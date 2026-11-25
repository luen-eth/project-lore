//! SQLite storage: entries, full-text index, and embedding blobs.

use std::{
    collections::HashMap,
    path::Path,
    sync::{Arc, Mutex},
};

use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension, params, params_from_iter, types::Value};

pub const KINDS: &[&str] = &["update", "decision", "bug", "note", "todo"];

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS entries (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    project    TEXT NOT NULL,
    kind       TEXT NOT NULL,
    title      TEXT NOT NULL,
    body       TEXT NOT NULL,
    tags       TEXT NOT NULL DEFAULT '',
    files      TEXT NOT NULL DEFAULT '',
    agent      TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at TEXT,
    embedding  BLOB,
    path        TEXT NOT NULL DEFAULT '',
    repo        TEXT NOT NULL DEFAULT '',
    commit_hash TEXT NOT NULL DEFAULT '',
    branch      TEXT NOT NULL DEFAULT '',
    dirty       INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS entries_project_created ON entries (project, created_at DESC);

CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS agents (
    name       TEXT PRIMARY KEY,
    client     TEXT NOT NULL DEFAULT '',
    first_seen TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    last_seen  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    requests   INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS activity (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    agent    TEXT NOT NULL,
    tool     TEXT NOT NULL,
    project  TEXT NOT NULL DEFAULT '',
    entry_id INTEGER,
    targets  TEXT NOT NULL DEFAULT '',
    summary  TEXT NOT NULL DEFAULT ''
);

CREATE VIRTUAL TABLE IF NOT EXISTS entries_fts USING fts5 (
    title, body, tags, files,
    content = 'entries', content_rowid = 'id',
    tokenize = 'unicode61 remove_diacritics 2'
);

CREATE TRIGGER IF NOT EXISTS entries_ai AFTER INSERT ON entries BEGIN
    INSERT INTO entries_fts (rowid, title, body, tags, files)
    VALUES (new.id, new.title, new.body, new.tags, new.files);
END;
CREATE TRIGGER IF NOT EXISTS entries_ad AFTER DELETE ON entries BEGIN
    INSERT INTO entries_fts (entries_fts, rowid, title, body, tags, files)
    VALUES ('delete', old.id, old.title, old.body, old.tags, old.files);
END;
CREATE TRIGGER IF NOT EXISTS entries_au AFTER UPDATE OF title, body, tags, files ON entries BEGIN
    INSERT INTO entries_fts (entries_fts, rowid, title, body, tags, files)
    VALUES ('delete', old.id, old.title, old.body, old.tags, old.files);
    INSERT INTO entries_fts (rowid, title, body, tags, files)
    VALUES (new.id, new.title, new.body, new.tags, new.files);
END;
"#;

const COLUMNS: &str = "id, project, kind, title, body, tags, files, agent, created_at, updated_at, \
                       path, repo, commit_hash, branch, dirty";

/// Columns added after the first release, as (name, definition).
const ADDED_COLUMNS: &[(&str, &str)] = &[
    ("path", "TEXT NOT NULL DEFAULT ''"),
    ("repo", "TEXT NOT NULL DEFAULT ''"),
    ("commit_hash", "TEXT NOT NULL DEFAULT ''"),
    ("branch", "TEXT NOT NULL DEFAULT ''"),
    ("dirty", "INTEGER NOT NULL DEFAULT 0"),
];

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Entry {
    pub id: i64,
    pub project: String,
    pub kind: String,
    pub title: String,
    pub body: String,
    pub tags: String,
    pub files: String,
    pub agent: String,
    pub created_at: String,
    #[serde(default)]
    pub updated_at: Option<String>,
    /// Working directory the agent was in when it logged the entry.
    #[serde(default)]
    pub path: String,
    /// Git remote of that directory, or empty when it is not a repository.
    #[serde(default)]
    pub repo: String,
    /// HEAD commit at the time of logging, or empty.
    #[serde(default)]
    pub commit: String,
    #[serde(default)]
    pub branch: String,
    /// True when the working tree had uncommitted changes.
    #[serde(default)]
    pub dirty: bool,
}

impl Entry {
    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get(0)?,
            project: row.get(1)?,
            kind: row.get(2)?,
            title: row.get(3)?,
            body: row.get(4)?,
            tags: row.get(5)?,
            files: row.get(6)?,
            agent: row.get(7)?,
            created_at: row.get(8)?,
            updated_at: row.get(9)?,
            path: row.get(10)?,
            repo: row.get(11)?,
            commit: row.get(12)?,
            branch: row.get(13)?,
            dirty: row.get(14)?,
        })
    }

    /// The text that gets embedded for semantic search.
    pub fn embedding_text(&self) -> String {
        let mut text = format!("{}\n{}", self.title, self.body);
        if !self.tags.is_empty() {
            text.push_str("\ntags: ");
            text.push_str(&self.tags);
        }
        text
    }
}

#[derive(Debug, Default)]
pub struct NewEntry {
    pub project: String,
    pub kind: String,
    pub title: String,
    pub body: String,
    pub tags: String,
    pub files: String,
    pub agent: String,
    pub path: String,
    pub repo: String,
    pub commit: String,
    pub branch: String,
    pub dirty: bool,
}

#[derive(Debug, Default)]
pub struct Patch {
    pub kind: Option<String>,
    pub title: Option<String>,
    pub body: Option<String>,
    pub tags: Option<String>,
    pub files: Option<String>,
}

#[derive(Debug)]
pub struct ProjectSummary {
    pub project: String,
    pub entries: i64,
    pub last_activity: String,
    /// Where each agent last was in this project, newest first.
    pub heads: Vec<AgentHead>,
}

/// The commit an agent most recently logged against in a project.
#[derive(Debug)]
pub struct AgentHead {
    pub agent: String,
    pub commit: String,
    pub branch: String,
    pub dirty: bool,
    pub at: String,
    pub entry_id: i64,
}

/// One tool call made by an agent, as shown in the admin activity feed.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Activity {
    pub id: i64,
    pub at: String,
    pub agent: String,
    /// The MCP tool that was called: recall, log, recent, ...
    pub tool: String,
    pub project: String,
    /// The entry the call created, changed, read or removed.
    pub entry_id: Option<i64>,
    /// Entries the call returned (search results), for highlighting.
    pub targets: Vec<i64>,
    pub summary: String,
}

pub const BACKUP_FORMAT: &str = "project-lore-backup";

/// Everything in the store: entries, their embedding vectors, the activity
/// log and the agent records. Restoring it reproduces the store exactly.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct Backup {
    pub format: String,
    pub version: u32,
    pub exported_at: String,
    pub entries: Vec<Entry>,
    #[serde(default)]
    pub activity: Vec<Activity>,
    #[serde(default)]
    pub agents: Vec<BackupAgent>,
    /// The model that produced `embeddings`. Vectors from another model are
    /// not comparable, so they are only reused when this matches.
    #[serde(default)]
    pub embedding_model: Option<String>,
    /// Entry id to its vector: little-endian f32 values, base64 encoded.
    #[serde(default)]
    pub embeddings: std::collections::BTreeMap<i64, String>,
}

/// Backup versions this build can read. Version 1 had no embeddings.
const BACKUP_VERSIONS: std::ops::RangeInclusive<u32> = 1..=2;

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct BackupAgent {
    pub name: String,
    #[serde(default)]
    pub client: String,
    pub first_seen: String,
    pub last_seen: String,
    #[serde(default)]
    pub requests: i64,
}

/// Activity rows kept; older ones are dropped.
const ACTIVITY_KEPT: i64 = 2000;

/// A connected agent, as shown in the admin view.
#[derive(Debug, serde::Serialize)]
pub struct AgentSummary {
    pub name: String,
    /// The HTTP client the agent last connected with.
    pub client: String,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    pub seconds_since_seen: Option<i64>,
    pub requests: i64,
    pub entries: i64,
}

/// An entry as drawn in the admin graph (no body).
#[derive(Debug, serde::Serialize)]
pub struct Neuron {
    pub id: i64,
    pub project: String,
    pub kind: String,
    pub title: String,
    pub tags: String,
    pub agent: String,
    pub created_at: String,
}

/// A semantic connection between two entries.
#[derive(Debug, serde::Serialize)]
pub struct Synapse {
    pub source: i64,
    pub target: i64,
    pub similarity: f32,
}

#[derive(Debug, serde::Serialize)]
pub struct Brain {
    pub total_entries: i64,
    pub neurons: Vec<Neuron>,
    pub synapses: Vec<Synapse>,
    /// Entries logged per day, oldest first, for the last 30 days.
    pub activity: Vec<(String, i64)>,
}

#[derive(Debug)]
pub struct Hit {
    pub entry: Entry,
    /// How the entry was found: "text", "semantic" or "text+semantic".
    pub matched: &'static str,
    /// Cosine similarity to the query, when the semantic index matched.
    pub similarity: Option<f32>,
}

#[derive(Clone)]
pub struct Db {
    conn: Arc<Mutex<Connection>>,
}

impl Db {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        let conn = Connection::open(path).with_context(|| format!("opening {}", path.display()))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "busy_timeout", 5000)?;
        conn.execute_batch(SCHEMA)?;
        add_missing_columns(&conn)?;
        migrate_fts(&conn)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn insert(&self, new: &NewEntry) -> Result<Entry> {
        let conn = self.lock();
        conn.execute(
            "INSERT INTO entries (project, kind, title, body, tags, files, agent,
                                  path, repo, commit_hash, branch, dirty)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                new.project,
                new.kind,
                new.title,
                new.body,
                new.tags,
                new.files,
                new.agent,
                new.path,
                new.repo,
                new.commit,
                new.branch,
                new.dirty
            ],
        )?;
        let id = conn.last_insert_rowid();
        Ok(get_entry(&conn, id)?.context("entry vanished after insert")?)
    }

    pub fn get(&self, id: i64) -> Result<Option<Entry>> {
        get_entry(&self.lock(), id)
    }

    /// Applies a patch and clears the stored embedding so it gets recomputed.
    pub fn amend(&self, id: i64, patch: &Patch) -> Result<Option<Entry>> {
        let conn = self.lock();
        let changed = conn.execute(
            "UPDATE entries SET
                kind  = COALESCE(?2, kind),
                title = COALESCE(?3, title),
                body  = COALESCE(?4, body),
                tags  = COALESCE(?5, tags),
                files = COALESCE(?6, files),
                updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now'),
                embedding = NULL
             WHERE id = ?1",
            params![
                id,
                patch.kind,
                patch.title,
                patch.body,
                patch.tags,
                patch.files
            ],
        )?;
        if changed == 0 {
            return Ok(None);
        }
        get_entry(&conn, id)
    }

    pub fn delete(&self, id: i64) -> Result<bool> {
        Ok(self
            .lock()
            .execute("DELETE FROM entries WHERE id = ?1", params![id])?
            > 0)
    }

    pub fn recent(
        &self,
        project: Option<&str>,
        kind: Option<&str>,
        limit: usize,
    ) -> Result<Vec<Entry>> {
        let conn = self.lock();
        let (filter, mut args) = filter_sql(project, kind);
        args.push(Value::Integer(limit as i64));
        let sql = format!(
            "SELECT {COLUMNS} FROM entries WHERE 1=1 {filter}
             ORDER BY created_at DESC, id DESC LIMIT ?"
        );
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(params_from_iter(args), Entry::from_row)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn projects(&self) -> Result<Vec<ProjectSummary>> {
        let conn = self.lock();
        let mut heads: HashMap<String, Vec<AgentHead>> = HashMap::new();
        {
            // The newest entry with a commit, per project and agent.
            let mut stmt = conn.prepare(
                "SELECT project, agent, commit_hash, branch, dirty, created_at, id
                 FROM entries e
                 WHERE commit_hash != '' AND id = (
                     SELECT MAX(id) FROM entries
                     WHERE project = e.project AND agent = e.agent AND commit_hash != ''
                 )
                 ORDER BY id DESC",
            )?;
            let rows = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    AgentHead {
                        agent: row.get(1)?,
                        commit: row.get(2)?,
                        branch: row.get(3)?,
                        dirty: row.get(4)?,
                        at: row.get(5)?,
                        entry_id: row.get(6)?,
                    },
                ))
            })?;
            for row in rows {
                let (project, head) = row?;
                heads.entry(project).or_default().push(head);
            }
        }
        let mut stmt = conn.prepare(
            "SELECT project, COUNT(*), MAX(created_at) FROM entries
             GROUP BY project ORDER BY MAX(created_at) DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get(1)?, row.get(2)?))
        })?;
        let mut projects = Vec::new();
        for row in rows {
            let (project, entries, last_activity) = row?;
            projects.push(ProjectSummary {
                heads: heads.remove(&project).unwrap_or_default(),
                project,
                entries,
                last_activity,
            });
        }
        Ok(projects)
    }

    /// A complete copy of the store.
    pub fn export(&self) -> Result<Backup> {
        let conn = self.lock();
        let exported_at: String =
            conn.query_row("SELECT strftime('%Y-%m-%dT%H:%M:%SZ', 'now')", [], |r| {
                r.get(0)
            })?;
        let entries = {
            let sql = format!("SELECT {COLUMNS} FROM entries ORDER BY id");
            let mut stmt = conn.prepare(&sql)?;
            let rows = stmt.query_map([], Entry::from_row)?;
            rows.collect::<rusqlite::Result<Vec<_>>>()?
        };
        let agents = {
            let mut stmt = conn.prepare(
                "SELECT name, client, first_seen, last_seen, requests FROM agents ORDER BY name",
            )?;
            let rows = stmt.query_map([], |row| {
                Ok(BackupAgent {
                    name: row.get(0)?,
                    client: row.get(1)?,
                    first_seen: row.get(2)?,
                    last_seen: row.get(3)?,
                    requests: row.get(4)?,
                })
            })?;
            rows.collect::<rusqlite::Result<Vec<_>>>()?
        };
        let embedding_model: Option<String> = conn
            .query_row(
                "SELECT value FROM meta WHERE key = 'embedding_model'",
                [],
                |row| row.get(0),
            )
            .optional()?;
        let embeddings = {
            use base64::Engine;
            let mut stmt =
                conn.prepare("SELECT id, embedding FROM entries WHERE embedding IS NOT NULL")?;
            let rows = stmt.query_map([], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))
            })?;
            let mut map = std::collections::BTreeMap::new();
            for row in rows {
                let (id, blob) = row?;
                map.insert(id, base64::engine::general_purpose::STANDARD.encode(blob));
            }
            map
        };
        drop(conn);
        let mut activity = self.activity(1_000_000)?;
        activity.reverse();
        Ok(Backup {
            format: BACKUP_FORMAT.to_string(),
            version: 2,
            exported_at,
            entries,
            activity,
            agents,
            embedding_model,
            embeddings,
        })
    }

    /// Replaces the whole store with a backup, keeping entry ids. All or
    /// nothing: on any error the previous contents stay in place.
    pub fn restore(&self, backup: &Backup) -> Result<usize> {
        validate_backup(backup)?;
        let mut conn = self.lock();
        let tx = conn.transaction()?;
        let reusable = reusable_vectors(&tx, backup)?;
        tx.execute_batch(
            "DELETE FROM entries; DELETE FROM activity; DELETE FROM agents;
             DELETE FROM sqlite_sequence WHERE name IN ('entries', 'activity');",
        )?;
        for entry in &backup.entries {
            tx.execute(
                "INSERT INTO entries (id, project, kind, title, body, tags, files, agent,
                                      created_at, updated_at, path, repo, commit_hash, branch, dirty)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
                params![
                    entry.id,
                    entry.project,
                    entry.kind,
                    entry.title,
                    entry.body,
                    entry.tags,
                    entry.files,
                    entry.agent,
                    entry.created_at,
                    entry.updated_at,
                    entry.path,
                    entry.repo,
                    entry.commit,
                    entry.branch,
                    entry.dirty
                ],
            )?;
            if let Some(vector) = reusable.get(&entry.id) {
                tx.execute(
                    "UPDATE entries SET embedding = ?2 WHERE id = ?1",
                    params![entry.id, vector],
                )?;
            }
        }
        for activity in &backup.activity {
            let targets = activity
                .targets
                .iter()
                .map(|id| id.to_string())
                .collect::<Vec<_>>()
                .join(",");
            tx.execute(
                "INSERT INTO activity (id, at, agent, tool, project, entry_id, targets, summary)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    activity.id,
                    activity.at,
                    activity.agent,
                    activity.tool,
                    activity.project,
                    activity.entry_id,
                    targets,
                    activity.summary
                ],
            )?;
        }
        for agent in &backup.agents {
            tx.execute(
                "INSERT INTO agents (name, client, first_seen, last_seen, requests)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    agent.name,
                    agent.client,
                    agent.first_seen,
                    agent.last_seen,
                    agent.requests
                ],
            )?;
        }
        tx.commit()?;
        Ok(backup.entries.len())
    }

    /// Adds the backup's entries that are not here yet, under new ids.
    /// An entry counts as present when project, title, body and creation time
    /// all match. Returns (added, already present).
    pub fn merge(&self, backup: &Backup) -> Result<(usize, usize)> {
        validate_backup(backup)?;
        let mut conn = self.lock();
        let tx = conn.transaction()?;
        let reusable = reusable_vectors(&tx, backup)?;
        let (mut added, mut present) = (0, 0);
        for entry in &backup.entries {
            let exists: bool = tx.query_row(
                "SELECT EXISTS (SELECT 1 FROM entries
                 WHERE project = ?1 AND title = ?2 AND body = ?3 AND created_at = ?4)",
                params![entry.project, entry.title, entry.body, entry.created_at],
                |row| row.get(0),
            )?;
            if exists {
                present += 1;
                continue;
            }
            tx.execute(
                "INSERT INTO entries (project, kind, title, body, tags, files, agent,
                                      created_at, updated_at, path, repo, commit_hash, branch, dirty)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
                params![
                    entry.project,
                    entry.kind,
                    entry.title,
                    entry.body,
                    entry.tags,
                    entry.files,
                    entry.agent,
                    entry.created_at,
                    entry.updated_at,
                    entry.path,
                    entry.repo,
                    entry.commit,
                    entry.branch,
                    entry.dirty
                ],
            )?;
            if let Some(vector) = reusable.get(&entry.id) {
                tx.execute(
                    "UPDATE entries SET embedding = ?2 WHERE id = ?1",
                    params![tx.last_insert_rowid(), vector],
                )?;
            }
            added += 1;
        }
        tx.commit()?;
        Ok((added, present))
    }

    /// Stores one agent action and returns it as recorded.
    pub fn record_activity(
        &self,
        agent: &str,
        tool: &str,
        project: &str,
        entry_id: Option<i64>,
        targets: &[i64],
        summary: &str,
    ) -> Result<Activity> {
        let conn = self.lock();
        let joined = targets
            .iter()
            .map(|id| id.to_string())
            .collect::<Vec<_>>()
            .join(",");
        conn.execute(
            "INSERT INTO activity (agent, tool, project, entry_id, targets, summary)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![agent, tool, project, entry_id, joined, summary],
        )?;
        let id = conn.last_insert_rowid();
        if id % 200 == 0 {
            conn.execute(
                "DELETE FROM activity WHERE id <= ?1",
                params![id - ACTIVITY_KEPT],
            )?;
        }
        let at: String =
            conn.query_row("SELECT at FROM activity WHERE id = ?1", params![id], |r| {
                r.get(0)
            })?;
        Ok(Activity {
            id,
            at,
            agent: agent.to_string(),
            tool: tool.to_string(),
            project: project.to_string(),
            entry_id,
            targets: targets.to_vec(),
            summary: summary.to_string(),
        })
    }

    /// The newest `limit` actions, newest first.
    pub fn activity(&self, limit: usize) -> Result<Vec<Activity>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT id, at, agent, tool, project, entry_id, targets, summary
             FROM activity ORDER BY id DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit as i64], |row| {
            let targets: String = row.get(6)?;
            Ok(Activity {
                id: row.get(0)?,
                at: row.get(1)?,
                agent: row.get(2)?,
                tool: row.get(3)?,
                project: row.get(4)?,
                entry_id: row.get(5)?,
                targets: targets
                    .split(',')
                    .filter_map(|id| id.parse().ok())
                    .collect(),
                summary: row.get(7)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Changes whenever an entry is added, amended or removed.
    pub fn version(&self) -> Result<String> {
        Ok(self.lock().query_row(
            "SELECT COUNT(*) || ':' || COALESCE(MAX(id), 0) || ':' || COALESCE(MAX(updated_at), '')
                    || ':' || COUNT(embedding) FROM entries",
            [],
            |row| row.get(0),
        )?)
    }

    /// Notes that an agent just made an authenticated request.
    pub fn touch_agent(&self, name: &str, client: &str) -> Result<()> {
        self.lock().execute(
            "INSERT INTO agents (name, client, requests) VALUES (?1, ?2, 1)
             ON CONFLICT (name) DO UPDATE SET
                client = CASE WHEN excluded.client = '' THEN client ELSE excluded.client END,
                last_seen = strftime('%Y-%m-%dT%H:%M:%SZ', 'now'),
                requests = requests + 1",
            params![name, client],
        )?;
        Ok(())
    }

    /// Every configured agent, plus any that wrote entries in the past,
    /// most recently seen first.
    pub fn agents(&self, configured: &[String]) -> Result<Vec<AgentSummary>> {
        let conn = self.lock();
        let mut written: HashMap<String, i64> = HashMap::new();
        {
            let mut stmt = conn
                .prepare("SELECT agent, COUNT(*) FROM entries WHERE agent != '' GROUP BY agent")?;
            let rows = stmt.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get(1)?)))?;
            for row in rows {
                let (agent, count) = row?;
                written.insert(agent, count);
            }
        }
        let mut agents: Vec<AgentSummary> = Vec::new();
        {
            let mut stmt = conn.prepare(
                "SELECT name, client, first_seen, last_seen, requests,
                        CAST(strftime('%s', 'now') AS INTEGER) - CAST(strftime('%s', last_seen) AS INTEGER)
                 FROM agents",
            )?;
            let rows = stmt.query_map([], |row| {
                Ok(AgentSummary {
                    name: row.get(0)?,
                    client: row.get(1)?,
                    first_seen: row.get(2)?,
                    last_seen: row.get(3)?,
                    requests: row.get(4)?,
                    seconds_since_seen: row.get(5)?,
                    entries: 0,
                })
            })?;
            for row in rows {
                agents.push(row?);
            }
        }
        let known: Vec<String> = agents.iter().map(|a| a.name.clone()).collect();
        for name in configured.iter().chain(written.keys()) {
            if !known.contains(name) && !agents.iter().any(|a| &a.name == name) {
                agents.push(AgentSummary {
                    name: name.clone(),
                    client: String::new(),
                    first_seen: None,
                    last_seen: None,
                    seconds_since_seen: None,
                    requests: 0,
                    entries: 0,
                });
            }
        }
        for agent in &mut agents {
            agent.entries = written.get(&agent.name).copied().unwrap_or(0);
        }
        agents.sort_by_key(|a| (a.seconds_since_seen.unwrap_or(i64::MAX), a.name.clone()));
        Ok(agents)
    }

    /// The newest `limit` entries and the semantic links between them: each
    /// entry is connected to its `neighbours` most similar entries above
    /// `min_similarity`.
    pub fn brain(&self, limit: usize, neighbours: usize, min_similarity: f32) -> Result<Brain> {
        let conn = self.lock();
        let total_entries: i64 =
            conn.query_row("SELECT COUNT(*) FROM entries", [], |r| r.get(0))?;

        let mut neurons = Vec::new();
        let mut vectors: Vec<(i64, Vec<f32>)> = Vec::new();
        {
            let mut stmt = conn.prepare(
                "SELECT id, project, kind, title, tags, agent, created_at, embedding
                 FROM entries ORDER BY id DESC LIMIT ?1",
            )?;
            let mut rows = stmt.query(params![limit as i64])?;
            while let Some(row) = rows.next()? {
                let id: i64 = row.get(0)?;
                neurons.push(Neuron {
                    id,
                    project: row.get(1)?,
                    kind: row.get(2)?,
                    title: row.get(3)?,
                    tags: row.get(4)?,
                    agent: row.get(5)?,
                    created_at: row.get(6)?,
                });
                if let Some(blob) = row.get::<_, Option<Vec<u8>>>(7)? {
                    vectors.push((id, decode_vector(&blob)));
                }
            }
        }

        let mut activity = Vec::new();
        {
            let mut stmt = conn.prepare(
                "SELECT substr(created_at, 1, 10), COUNT(*) FROM entries
                 WHERE created_at >= strftime('%Y-%m-%dT00:00:00Z', 'now', '-29 days')
                 GROUP BY 1 ORDER BY 1",
            )?;
            let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
            for row in rows {
                activity.push(row?);
            }
        }
        drop(conn);

        let mut synapses: Vec<Synapse> = Vec::new();
        let mut seen: std::collections::HashSet<(i64, i64)> = std::collections::HashSet::new();
        for (i, (id, vector)) in vectors.iter().enumerate() {
            let mut scored: Vec<(i64, f32)> = vectors
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, (other, other_vector))| (*other, dot(vector, other_vector)))
                .filter(|(_, similarity)| *similarity >= min_similarity)
                .collect();
            scored.sort_by(|a, b| b.1.total_cmp(&a.1));
            for (other, similarity) in scored.into_iter().take(neighbours) {
                let pair = (*id.min(&other), *id.max(&other));
                if seen.insert(pair) {
                    synapses.push(Synapse {
                        source: pair.0,
                        target: pair.1,
                        similarity,
                    });
                }
            }
        }

        Ok(Brain {
            total_entries,
            neurons,
            synapses,
            activity,
        })
    }

    /// Records which model produced the stored vectors. Vectors from a
    /// different model are not comparable, so they are dropped and recomputed.
    pub fn use_embedding_model(&self, name: &str) -> Result<()> {
        let conn = self.lock();
        let current: Option<String> = conn
            .query_row(
                "SELECT value FROM meta WHERE key = 'embedding_model'",
                [],
                |row| row.get(0),
            )
            .optional()?;
        if current.as_deref() != Some(name) {
            conn.execute("UPDATE entries SET embedding = NULL", [])?;
            conn.execute(
                "INSERT INTO meta (key, value) VALUES ('embedding_model', ?1)
                 ON CONFLICT (key) DO UPDATE SET value = excluded.value",
                params![name],
            )?;
        }
        Ok(())
    }

    pub fn set_embedding(&self, id: i64, vector: &[f32]) -> Result<()> {
        self.lock().execute(
            "UPDATE entries SET embedding = ?2 WHERE id = ?1",
            params![id, encode_vector(vector)],
        )?;
        Ok(())
    }

    /// Entries that still need an embedding, oldest first.
    pub fn missing_embeddings(&self, limit: usize) -> Result<Vec<Entry>> {
        let conn = self.lock();
        let sql =
            format!("SELECT {COLUMNS} FROM entries WHERE embedding IS NULL ORDER BY id LIMIT ?1");
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(params![limit as i64], Entry::from_row)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Hybrid search: full-text plus cosine similarity over stored
    /// embeddings, merged with reciprocal rank fusion.
    pub fn search(
        &self,
        query: &str,
        query_vector: Option<&[f32]>,
        project: Option<&str>,
        kind: Option<&str>,
        limit: usize,
        min_similarity: f32,
    ) -> Result<Vec<Hit>> {
        const POOL: usize = 40;
        const RRF_K: f64 = 60.0;

        let conn = self.lock();
        let (filter, filter_args) = filter_sql(project, kind);

        let mut text_ranked: Vec<i64> = Vec::new();
        if let Some(fts_query) = build_fts_query(query) {
            let sql = format!(
                "SELECT e.id FROM entries_fts
                 JOIN entries e ON e.id = entries_fts.rowid
                 WHERE entries_fts MATCH ? {filter}
                 ORDER BY bm25(entries_fts, 8.0, 1.0, 4.0, 2.0) LIMIT {POOL}"
            );
            let mut args = vec![Value::Text(fts_query)];
            args.extend(filter_args.iter().cloned());
            let mut stmt = conn.prepare(&sql)?;
            let rows = stmt.query_map(params_from_iter(args), |row| row.get::<_, i64>(0))?;
            text_ranked = rows.collect::<rusqlite::Result<_>>()?;
        }

        let mut semantic_ranked: Vec<i64> = Vec::new();
        let mut similarities: HashMap<i64, f32> = HashMap::new();
        if let Some(query_vector) = query_vector {
            let sql =
                format!("SELECT id, embedding FROM entries WHERE embedding IS NOT NULL {filter}");
            let mut stmt = conn.prepare(&sql)?;
            let rows = stmt.query_map(params_from_iter(filter_args.iter().cloned()), |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))
            })?;
            let mut scored: Vec<(i64, f32)> = Vec::new();
            for row in rows {
                let (id, blob) = row?;
                let score = dot(query_vector, &decode_vector(&blob));
                similarities.insert(id, score);
                if score >= min_similarity {
                    scored.push((id, score));
                }
            }
            scored.sort_by(|a, b| b.1.total_cmp(&a.1));
            semantic_ranked = scored.into_iter().take(POOL).map(|(id, _)| id).collect();
        }

        let mut fused: HashMap<i64, (f64, bool, bool)> = HashMap::new();
        for (rank, id) in text_ranked.iter().enumerate() {
            let slot = fused.entry(*id).or_default();
            slot.0 += 1.0 / (RRF_K + rank as f64 + 1.0);
            slot.1 = true;
        }
        for (rank, id) in semantic_ranked.iter().enumerate() {
            let slot = fused.entry(*id).or_default();
            slot.0 += 1.0 / (RRF_K + rank as f64 + 1.0);
            slot.2 = true;
        }

        let mut ordered: Vec<(i64, (f64, bool, bool))> = fused.into_iter().collect();
        let similarity = |id: &i64| similarities.get(id).copied().unwrap_or(0.0);
        ordered.sort_by(|a, b| {
            b.1.0
                .total_cmp(&a.1.0)
                .then(similarity(&b.0).total_cmp(&similarity(&a.0)))
                .then(b.0.cmp(&a.0))
        });

        let mut hits = Vec::new();
        for (id, (_, by_text, by_semantic)) in ordered.into_iter().take(limit) {
            if let Some(entry) = get_entry(&conn, id)? {
                let matched = match (by_text, by_semantic) {
                    (true, true) => "text+semantic",
                    (true, false) => "text",
                    _ => "semantic",
                };
                hits.push(Hit {
                    entry,
                    matched,
                    similarity: similarities.get(&id).copied(),
                });
            }
        }
        Ok(hits)
    }
}

/// The backup's vectors, decoded, if they came from the model in use here.
/// Entries without a reusable vector are embedded again after the import.
fn reusable_vectors(conn: &Connection, backup: &Backup) -> Result<HashMap<i64, Vec<u8>>> {
    use base64::Engine;
    let current: Option<String> = conn
        .query_row(
            "SELECT value FROM meta WHERE key = 'embedding_model'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    let mut vectors = HashMap::new();
    if backup.embedding_model.is_none() || backup.embedding_model != current {
        return Ok(vectors);
    }
    for (id, encoded) in &backup.embeddings {
        let blob = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|_| anyhow::anyhow!("the embedding of entry #{id} is not valid base64"))?;
        if blob.is_empty() || blob.len() % 4 != 0 {
            anyhow::bail!("the embedding of entry #{id} has an invalid length");
        }
        vectors.insert(*id, blob);
    }
    Ok(vectors)
}

fn validate_backup(backup: &Backup) -> Result<()> {
    if backup.format != BACKUP_FORMAT {
        anyhow::bail!("this file is not a project-lore backup");
    }
    if !BACKUP_VERSIONS.contains(&backup.version) {
        anyhow::bail!("backup version {} is not supported", backup.version);
    }
    for entry in &backup.entries {
        if entry.project.trim().is_empty() || entry.title.trim().is_empty() {
            anyhow::bail!("entry #{} has no project or title", entry.id);
        }
        if !KINDS.contains(&entry.kind.as_str()) {
            anyhow::bail!("entry #{} has an unknown kind \"{}\"", entry.id, entry.kind);
        }
    }
    Ok(())
}

/// Adds columns introduced after a database was first created.
fn add_missing_columns(conn: &Connection) -> Result<()> {
    let existing: Vec<String> = conn
        .prepare("SELECT name FROM pragma_table_info('entries')")?
        .query_map([], |row| row.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    for (name, definition) in ADDED_COLUMNS {
        if !existing.iter().any(|column| column == name) {
            conn.execute_batch(&format!(
                "ALTER TABLE entries ADD COLUMN {name} {definition};"
            ))?;
        }
    }
    Ok(())
}

/// Rebuilds the full-text index when it was created by an older version
/// with a different tokenizer.
fn migrate_fts(conn: &Connection) -> Result<()> {
    const FTS_VERSION: &str = "unicode61-prefix-1";
    let current: Option<String> = conn
        .query_row("SELECT value FROM meta WHERE key = 'fts'", [], |row| {
            row.get(0)
        })
        .optional()?;
    if current.as_deref() == Some(FTS_VERSION) {
        return Ok(());
    }
    if current.is_some()
        || conn.query_row("SELECT COUNT(*) FROM entries", [], |r| r.get::<_, i64>(0))? > 0
    {
        conn.execute_batch("DROP TABLE IF EXISTS entries_fts;")?;
        conn.execute_batch(SCHEMA)?;
        conn.execute(
            "INSERT INTO entries_fts (entries_fts) VALUES ('rebuild')",
            [],
        )?;
    }
    conn.execute(
        "INSERT INTO meta (key, value) VALUES ('fts', ?1)
         ON CONFLICT (key) DO UPDATE SET value = excluded.value",
        params![FTS_VERSION],
    )?;
    Ok(())
}

fn get_entry(conn: &Connection, id: i64) -> Result<Option<Entry>> {
    let sql = format!("SELECT {COLUMNS} FROM entries WHERE id = ?1");
    Ok(conn
        .query_row(&sql, params![id], Entry::from_row)
        .optional()?)
}

fn filter_sql(project: Option<&str>, kind: Option<&str>) -> (String, Vec<Value>) {
    let mut sql = String::new();
    let mut args = Vec::new();
    if let Some(project) = project {
        sql.push_str(" AND project = ?");
        args.push(Value::Text(project.to_string()));
    }
    if let Some(kind) = kind {
        sql.push_str(" AND kind = ?");
        args.push(Value::Text(kind.to_string()));
    }
    (sql, args)
}

/// Words too common to say anything about a topic (English and Turkish).
const STOPWORDS: &[&str] = &[
    "about", "after", "all", "also", "and", "any", "are", "been", "before", "between", "but",
    "can", "could", "did", "does", "done", "for", "from", "had", "has", "have", "here", "how",
    "into", "its", "just", "like", "more", "much", "need", "not", "only", "our", "over", "should",
    "some", "such", "than", "that", "the", "their", "them", "then", "there", "these", "they",
    "this", "those", "was", "what", "when", "where", "which", "while", "who", "why", "will",
    "with", "would", "you", "your", "ama", "bana", "ben", "bile", "bir", "biz", "bunu", "çok",
    "daha", "değil", "diye", "gibi", "hangi", "için", "ile", "kadar", "nasıl", "neden", "nedir",
    "olan", "olarak", "oldu", "sonra", "şey", "var", "veya", "yok",
];

/// Turns free text into an FTS5 query: every meaningful word becomes a prefix
/// match, OR-ed together. Long words also contribute a shortened stem, so
/// inflected forms still match (useful for agglutinative languages:
/// "güncelleme" also finds "güncelledim").
fn build_fts_query(query: &str) -> Option<String> {
    let mut terms: Vec<String> = Vec::new();
    for word in query.split(|c: char| !(c.is_alphanumeric() || c == '_')) {
        let chars: Vec<char> = word.chars().collect();
        let has_digit = chars.iter().any(|c| c.is_ascii_digit());
        if chars.len() < 2 || (chars.len() == 2 && !has_digit) {
            continue;
        }
        if STOPWORDS.contains(&word.to_lowercase().as_str()) {
            continue;
        }
        let mut push = |term: String| {
            let quoted = format!("\"{term}\"*");
            if !terms.contains(&quoted) {
                terms.push(quoted);
            }
        };
        push(word.to_string());
        if chars.len() >= 7 {
            let stem_len = (chars.len() * 2 / 3).max(5);
            push(chars[..stem_len].iter().collect());
        }
    }
    if terms.is_empty() {
        None
    } else {
        Some(terms.join(" OR "))
    }
}

fn encode_vector(vector: &[f32]) -> Vec<u8> {
    vector.iter().flat_map(|v| v.to_le_bytes()).collect()
}

fn decode_vector(blob: &[u8]) -> Vec<f32> {
    blob.chunks_exact(4)
        .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect()
}

/// Dot product; vectors are stored L2-normalised, so this is cosine similarity.
fn dot(a: &[f32], b: &[f32]) -> f32 {
    a.iter().zip(b).map(|(x, y)| x * y).sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_db() -> Db {
        let dir = std::env::temp_dir().join(format!(
            "lore-test-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        Db::open(&dir.join("lore.db")).unwrap()
    }

    fn entry(project: &str, title: &str, body: &str) -> NewEntry {
        NewEntry {
            project: project.into(),
            kind: "update".into(),
            title: title.into(),
            body: body.into(),
            ..Default::default()
        }
    }

    #[test]
    fn text_search_finds_inflected_and_filters_by_project() {
        let db = temp_db();
        db.insert(&entry(
            "shop",
            "Ödeme akışını güncelledim",
            "Stripe webhook imzası doğrulanıyor",
        ))
        .unwrap();
        db.insert(&entry("blog", "RSS feed added", "Atom and RSS endpoints"))
            .unwrap();

        let hits = db.search("güncelleme", None, None, None, 5, 0.8).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].entry.project, "shop");

        assert!(
            db.search("webhook", None, Some("blog"), None, 5, 0.8)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            db.search("webhook", None, Some("shop"), None, 5, 0.8)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn amend_reindexes_and_delete_removes() {
        let db = temp_db();
        let e = db.insert(&entry("p", "first title", "alpha body")).unwrap();
        db.amend(
            e.id,
            &Patch {
                body: Some("completely different zebra".into()),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(
            db.search("alpha", None, None, None, 5, 0.8)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            db.search("zebra", None, None, None, 5, 0.8).unwrap().len(),
            1
        );
        assert!(db.delete(e.id).unwrap());
        assert!(
            db.search("zebra", None, None, None, 5, 0.8)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn brain_links_similar_entries_and_lists_agents() {
        let db = temp_db();
        let a = db.insert(&entry("p", "one", "x")).unwrap();
        let b = db.insert(&entry("p", "two", "y")).unwrap();
        let c = db.insert(&entry("q", "three", "z")).unwrap();
        db.set_embedding(a.id, &[1.0, 0.0]).unwrap();
        db.set_embedding(b.id, &[0.98, 0.2]).unwrap();
        db.set_embedding(c.id, &[0.0, 1.0]).unwrap();
        let brain = db.brain(100, 3, 0.9).unwrap();
        assert_eq!(brain.neurons.len(), 3);
        assert_eq!(brain.synapses.len(), 1);
        assert_eq!(
            (brain.synapses[0].source, brain.synapses[0].target),
            (a.id, b.id)
        );

        db.touch_agent("claude", "claude-code/2").unwrap();
        db.touch_agent("claude", "").unwrap();
        let agents = db.agents(&["claude".into(), "codex".into()]).unwrap();
        assert_eq!(agents.len(), 2);
        assert_eq!((agents[0].name.as_str(), agents[0].requests), ("claude", 2));
        assert_eq!(agents[0].client, "claude-code/2");
        assert!(agents[1].last_seen.is_none());
    }

    #[test]
    fn projects_report_each_agents_latest_commit() {
        let db = temp_db();
        let at = |agent: &str, commit: &str, dirty: bool| NewEntry {
            agent: agent.into(),
            commit: commit.into(),
            branch: "main".into(),
            dirty,
            ..entry("shop", "t", "b")
        };
        db.insert(&at("claude", "aaaaaaa", false)).unwrap();
        db.insert(&at("codex", "bbbbbbb", false)).unwrap();
        db.insert(&at("claude", "ccccccc", true)).unwrap();
        db.insert(&at("claude", "", false)).unwrap();
        let projects = db.projects().unwrap();
        assert_eq!(projects.len(), 1);
        let heads: Vec<_> = projects[0]
            .heads
            .iter()
            .map(|h| (h.agent.as_str(), h.commit.as_str(), h.dirty))
            .collect();
        assert_eq!(
            heads,
            [("claude", "ccccccc", true), ("codex", "bbbbbbb", false)]
        );
    }

    #[test]
    fn old_databases_gain_the_new_columns() {
        let dir = std::env::temp_dir().join(format!("lore-migrate-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("lore.db");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE entries (id INTEGER PRIMARY KEY AUTOINCREMENT, project TEXT NOT NULL,
                 kind TEXT NOT NULL, title TEXT NOT NULL, body TEXT NOT NULL,
                 tags TEXT NOT NULL DEFAULT '', files TEXT NOT NULL DEFAULT '',
                 agent TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL DEFAULT 'x',
                 updated_at TEXT, embedding BLOB);
                 INSERT INTO entries (project, kind, title, body) VALUES ('p', 'note', 'old', 'entry');",
            )
            .unwrap();
        }
        let db = Db::open(&path).unwrap();
        let old = db.get(1).unwrap().unwrap();
        assert_eq!(
            (old.title.as_str(), old.commit.as_str(), old.dirty),
            ("old", "", false)
        );
        assert_eq!(
            db.search("entry", None, None, None, 5, 0.8).unwrap().len(),
            1
        );
    }

    #[test]
    fn activity_is_recorded_newest_first() {
        let db = temp_db();
        db.record_activity("claude", "log", "shop", Some(1), &[], "Added refunds")
            .unwrap();
        let second = db
            .record_activity("codex", "recall", "", None, &[1, 4], "refunds")
            .unwrap();
        assert_eq!(second.targets, [1, 4]);
        let feed = db.activity(10).unwrap();
        assert_eq!(feed.len(), 2);
        assert_eq!(
            (feed[0].agent.as_str(), feed[0].tool.as_str()),
            ("codex", "recall")
        );
        assert_eq!(feed[0].targets, [1, 4]);
        assert_eq!(feed[1].entry_id, Some(1));
    }

    #[test]
    fn backup_round_trips_and_merge_skips_what_exists() {
        let db = temp_db();
        let first = db
            .insert(&entry("shop", "Refunds", "refund endpoint"))
            .unwrap();
        db.insert(&entry("blog", "Feeds", "rss and atom")).unwrap();
        db.use_embedding_model("test-model").unwrap();
        db.set_embedding(first.id, &[1.0, 0.0]).unwrap();
        db.touch_agent("claude", "claude-code/2").unwrap();
        db.record_activity("claude", "log", "shop", Some(first.id), &[], "Refunds")
            .unwrap();

        let json = serde_json::to_string(&db.export().unwrap()).unwrap();
        let backup: Backup = serde_json::from_str(&json).unwrap();
        assert_eq!(
            (
                backup.entries.len(),
                backup.activity.len(),
                backup.agents.len()
            ),
            (2, 1, 1)
        );
        assert_eq!(backup.embeddings.len(), 1);
        assert_eq!(backup.embedding_model.as_deref(), Some("test-model"));

        // Merging a backup into the store it came from adds nothing.
        assert_eq!(db.merge(&backup).unwrap(), (0, 2));

        // Diverge, then restore: the store is exactly the backup again.
        db.delete(first.id).unwrap();
        db.insert(&entry("temp", "Scratch", "to be discarded"))
            .unwrap();
        assert_eq!(db.restore(&backup).unwrap(), 2);
        assert_eq!(db.get(first.id).unwrap().unwrap().title, "Refunds");
        assert!(
            db.search("discarded", None, None, None, 5, 0.8)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            db.search("refund", None, None, None, 5, 0.8).unwrap().len(),
            1
        );
        // The one vector that existed came back with its entry; the entry
        // that never had one is still waiting to be embedded.
        let missing: Vec<i64> = db
            .missing_embeddings(10)
            .unwrap()
            .iter()
            .map(|e| e.id)
            .collect();
        assert_eq!(missing.len(), 1);
        assert!(!missing.contains(&first.id));
        let hits = db
            .search("zz", Some(&[1.0, 0.0]), None, None, 5, 0.8)
            .unwrap();
        assert_eq!(hits[0].entry.id, first.id);
        assert_eq!(db.activity(10).unwrap().len(), 1);

        // Vectors from a different model are not reused.
        db.use_embedding_model("other-model").unwrap();
        db.restore(&backup).unwrap();
        assert_eq!(db.missing_embeddings(10).unwrap().len(), 2);
        db.use_embedding_model("test-model").unwrap();
        db.restore(&backup).unwrap();

        // A file that is not a backup changes nothing.
        let bogus = Backup {
            format: "something-else".into(),
            ..db.export().unwrap()
        };
        assert!(db.restore(&bogus).is_err());
        assert_eq!(db.export().unwrap().entries.len(), 2);
    }

    #[test]
    fn fts_query_drops_noise_words() {
        assert_eq!(
            build_fts_query("what is the plan"),
            Some("\"plan\"*".into())
        );
        assert_eq!(
            build_fts_query("JWT ile auth"),
            Some("\"JWT\"* OR \"auth\"*".into())
        );
        assert_eq!(build_fts_query("the of is"), None);
    }

    #[test]
    fn semantic_ranking_uses_vectors() {
        let db = temp_db();
        let a = db.insert(&entry("p", "one", "x")).unwrap();
        let b = db.insert(&entry("p", "two", "y")).unwrap();
        db.set_embedding(a.id, &[1.0, 0.0]).unwrap();
        db.set_embedding(b.id, &[0.0, 1.0]).unwrap();
        let hits = db
            .search("zz", Some(&[0.0, 1.0]), None, None, 5, 0.8)
            .unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].entry.id, b.id);
        assert_eq!(hits[0].matched, "semantic");
    }
}
