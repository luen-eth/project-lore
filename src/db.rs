//! SQLite storage: entries, chat sessions, the user profile and rules, the
//! full-text index, and embedding blobs.

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
    dirty       INTEGER NOT NULL DEFAULT 0,
    session_id  TEXT
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
    summary  TEXT NOT NULL DEFAULT '',
    session_id TEXT
);

CREATE TABLE IF NOT EXISTS sessions (
    id           TEXT PRIMARY KEY,
    agent        TEXT NOT NULL,
    project      TEXT NOT NULL,
    path         TEXT NOT NULL DEFAULT '',
    repo         TEXT NOT NULL DEFAULT '',
    commit_hash  TEXT NOT NULL DEFAULT '',
    branch       TEXT NOT NULL DEFAULT '',
    title        TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'open',
    summary      TEXT NOT NULL DEFAULT '',
    started_at   TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    ended_at     TEXT
);

CREATE TABLE IF NOT EXISTS session_updates (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    at         TEXT NOT NULL,
    body       TEXT NOT NULL,
    commit_hash TEXT NOT NULL DEFAULT '',
    branch     TEXT NOT NULL DEFAULT '',
    dirty      INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS agent_profiles (
    agent   TEXT PRIMARY KEY,
    address TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS rules (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    scope      TEXT NOT NULL,
    target     TEXT NOT NULL DEFAULT '',
    body       TEXT NOT NULL,
    enabled    INTEGER NOT NULL DEFAULT 1,
    position   INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
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
                       path, repo, commit_hash, branch, dirty, session_id";

/// The columns of a session row, in the order `Session::from_row` reads them.
const SESSION_COLUMNS: &str = "id, agent, project, path, repo, commit_hash, branch, \
                                title, status, summary, started_at, last_seen_at, ended_at";

const RULE_COLUMNS: &str = "id, scope, target, body, enabled, position, created_at, updated_at";

/// Rule listing order: global rules, then agent rules, then project rules,
/// each by position and id.
const RULE_ORDER: &str =
    "ORDER BY CASE scope WHEN 'global' THEN 0 WHEN 'agent' THEN 1 ELSE 2 END, position, id";

/// Longest rule body accepted.
const RULE_BODY_MAX_CHARS: usize = 2000;

/// Columns added after the first release, as (table, name, definition).
const ADDED_COLUMNS: &[(&str, &str, &str)] = &[
    ("entries", "path", "TEXT NOT NULL DEFAULT ''"),
    ("entries", "repo", "TEXT NOT NULL DEFAULT ''"),
    ("entries", "commit_hash", "TEXT NOT NULL DEFAULT ''"),
    ("entries", "branch", "TEXT NOT NULL DEFAULT ''"),
    ("entries", "dirty", "INTEGER NOT NULL DEFAULT 0"),
    ("entries", "session_id", "TEXT"),
    ("activity", "session_id", "TEXT"),
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
    /// The chat session this entry was logged in, when known.
    #[serde(default)]
    pub session_id: Option<String>,
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
            session_id: row.get(15)?,
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
    /// The chat session the entry is logged in, when there is one.
    pub session_id: Option<String>,
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
    /// The chat session the call was made in, when there is one.
    #[serde(default)]
    pub session_id: Option<String>,
}

pub const BACKUP_FORMAT: &str = "project-lore-backup";

/// The scopes a rule can have: everywhere, one agent or one project.
pub const RULE_SCOPES: &[&str] = &["global", "agent", "project"];

/// One chat an agent registered with `hello`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Session {
    /// "s_" plus 24 random hex characters.
    pub id: String,
    pub agent: String,
    pub project: String,
    /// Working directory the chat started in.
    pub path: String,
    /// Git remote of that directory, or empty when it is not a repository.
    pub repo: String,
    /// HEAD commit when the chat started, or empty.
    pub commit: String,
    pub branch: String,
    /// What the chat is about, one line.
    pub title: String,
    /// `open` or `closed`.
    pub status: String,
    /// Written by `bye`, or "closed after inactivity".
    pub summary: String,
    pub started_at: String,
    pub last_seen_at: String,
    /// Set when the session was closed.
    #[serde(default)]
    pub ended_at: Option<String>,
    /// How many check-ins the session has.
    #[serde(default)]
    pub updates: u32,
}

impl Session {
    /// Reads a session row followed by its check-in count.
    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get(0)?,
            agent: row.get(1)?,
            project: row.get(2)?,
            path: row.get(3)?,
            repo: row.get(4)?,
            commit: row.get(5)?,
            branch: row.get(6)?,
            title: row.get(7)?,
            status: row.get(8)?,
            summary: row.get(9)?,
            started_at: row.get(10)?,
            last_seen_at: row.get(11)?,
            ended_at: row.get(12)?,
            updates: row.get(13)?,
        })
    }
}

/// A session as `hello` opens it; the id and the times are assigned here.
#[derive(Debug, Default)]
pub struct NewSession {
    pub agent: String,
    pub project: String,
    pub path: String,
    pub repo: String,
    pub commit: String,
    pub branch: String,
    pub title: String,
}

/// One `checkin` on a session.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SessionUpdate {
    pub id: i64,
    pub session_id: String,
    pub at: String,
    /// What happened in the chat since the last check-in.
    pub body: String,
    /// HEAD commit at the time of the check-in, or empty.
    pub commit: String,
    pub branch: String,
    /// True when the working tree had uncommitted changes.
    pub dirty: bool,
}

impl SessionUpdate {
    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get(0)?,
            session_id: row.get(1)?,
            at: row.get(2)?,
            body: row.get(3)?,
            commit: row.get(4)?,
            branch: row.get(5)?,
            dirty: row.get(6)?,
        })
    }
}

/// How the user wants to be addressed, and in which language replies should
/// be, globally and per agent.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct Profile {
    /// Default form of address; may be empty.
    #[serde(default)]
    pub address: String,
    /// Language the user wants replies in; may be empty.
    #[serde(default)]
    pub language: String,
    /// Agents with their own form of address, overriding the default.
    #[serde(default)]
    pub agents: Vec<AgentAddress>,
}

/// One agent's own form of address, overriding the default.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AgentAddress {
    pub agent: String,
    #[serde(default)]
    pub address: String,
}

/// What the admin page saves for the profile.
#[derive(Debug, Default)]
pub struct ProfileInput {
    pub address: String,
    pub language: String,
    pub agents: Vec<AgentAddress>,
}

/// A rule the user wants agents to follow.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Rule {
    pub id: i64,
    /// One of: global, agent, project.
    pub scope: String,
    /// Agent or project name; empty for a global rule.
    pub target: String,
    pub body: String,
    pub enabled: bool,
    /// Manual ordering within a scope, smaller first.
    pub position: i64,
    pub created_at: String,
    pub updated_at: String,
}

impl Rule {
    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get(0)?,
            scope: row.get(1)?,
            target: row.get(2)?,
            body: row.get(3)?,
            enabled: row.get(4)?,
            position: row.get(5)?,
            created_at: row.get(6)?,
            updated_at: row.get(7)?,
        })
    }
}

/// A rule as the admin page creates or edits it.
#[derive(Debug)]
pub struct RuleInput {
    pub scope: String,
    pub target: String,
    pub body: String,
    pub enabled: bool,
    pub position: i64,
}

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
    /// The chats agents registered, with their check-in counts.
    #[serde(default)]
    pub sessions: Vec<Session>,
    /// Every check-in, in order.
    #[serde(default)]
    pub session_updates: Vec<SessionUpdate>,
    /// The profile as it was exported.
    #[serde(default)]
    pub profile: Profile,
    /// The rules the user wants followed.
    #[serde(default)]
    pub rules: Vec<Rule>,
}

/// Backup versions this build can read. Version 1 had no embeddings; version
/// 2 had no sessions, profile or rules.
const BACKUP_VERSIONS: std::ops::RangeInclusive<u32> = 1..=3;

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
                                  path, repo, commit_hash, branch, dirty, session_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
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
                new.dirty,
                new.session_id
            ],
        )?;
        let id = conn.last_insert_rowid();
        get_entry(&conn, id)?.context("entry vanished after insert")
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
        let sessions = self.sessions(None, None, 1_000_000)?;
        let session_updates = {
            let conn = self.lock();
            let mut stmt = conn.prepare(
                "SELECT id, session_id, at, body, commit_hash, branch, dirty
                 FROM session_updates ORDER BY id",
            )?;
            let rows = stmt.query_map([], SessionUpdate::from_row)?;
            rows.collect::<rusqlite::Result<_>>()?
        };
        let profile = self.profile()?;
        let rules = self.rules()?;
        Ok(Backup {
            format: BACKUP_FORMAT.to_string(),
            version: 3,
            exported_at,
            entries,
            activity,
            agents,
            embedding_model,
            embeddings,
            sessions,
            session_updates,
            profile,
            rules,
        })
    }

    /// Replaces the whole store with a backup, keeping entry ids. All or
    /// nothing: on any error the previous contents stay in place. A backup
    /// older than version 3 leaves the sessions, the profile and the rules
    /// as they are, since it has none to put in their place.
    pub fn restore(&self, backup: &Backup) -> Result<usize> {
        validate_backup(backup)?;
        let mut conn = self.lock();
        let tx = conn.transaction()?;
        let reusable = reusable_vectors(&tx, backup)?;
        tx.execute_batch(
            "DELETE FROM entries; DELETE FROM activity; DELETE FROM agents;
             DELETE FROM sqlite_sequence WHERE name IN ('entries', 'activity');",
        )?;
        // Backups older than version 3 know nothing of sessions, the profile
        // or rules. Restoring one must not wipe what was set up since, so
        // those tables are only replaced by a backup that carries them.
        let replaces_sessions = backup.version >= 3;
        if replaces_sessions {
            tx.execute_batch(
                "DELETE FROM sessions; DELETE FROM session_updates;
                 DELETE FROM agent_profiles; DELETE FROM rules;
                 DELETE FROM sqlite_sequence WHERE name IN ('session_updates', 'rules');",
            )?;
        }
        for entry in &backup.entries {
            tx.execute(
                "INSERT INTO entries (id, project, kind, title, body, tags, files, agent,
                                      created_at, updated_at, path, repo, commit_hash, branch,
                                      dirty, session_id)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
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
                    entry.dirty,
                    entry.session_id
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
                "INSERT INTO activity (id, at, agent, tool, project, entry_id, targets, summary, session_id)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    activity.id,
                    activity.at,
                    activity.agent,
                    activity.tool,
                    activity.project,
                    activity.entry_id,
                    targets,
                    activity.summary,
                    activity.session_id
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
        for session in &backup.sessions {
            tx.execute(
                "INSERT INTO sessions (id, agent, project, path, repo, commit_hash, branch,
                                       title, status, summary, started_at, last_seen_at, ended_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                params![
                    session.id,
                    session.agent,
                    session.project,
                    session.path,
                    session.repo,
                    session.commit,
                    session.branch,
                    session.title,
                    session.status,
                    session.summary,
                    session.started_at,
                    session.last_seen_at,
                    session.ended_at
                ],
            )?;
        }
        for update in &backup.session_updates {
            tx.execute(
                "INSERT INTO session_updates (id, session_id, at, body, commit_hash, branch, dirty)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    update.id,
                    update.session_id,
                    update.at,
                    update.body,
                    update.commit,
                    update.branch,
                    update.dirty
                ],
            )?;
        }
        if !replaces_sessions {
            tx.commit()?;
            return Ok(backup.entries.len());
        }
        set_meta(&tx, "profile.address", backup.profile.address.trim())?;
        set_meta(&tx, "profile.language", backup.profile.language.trim())?;
        for agent in &backup.profile.agents {
            let address = agent.address.trim();
            if agent.agent.trim().is_empty() || address.is_empty() {
                continue;
            }
            tx.execute(
                "INSERT OR REPLACE INTO agent_profiles (agent, address) VALUES (?1, ?2)",
                params![agent.agent.trim().to_lowercase(), address],
            )?;
        }
        for rule in &backup.rules {
            let (scope, target, body) = normalize_rule(&rule.scope, &rule.target, &rule.body)?;
            tx.execute(
                "INSERT INTO rules (id, scope, target, body, enabled, position, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    rule.id,
                    scope,
                    target,
                    body,
                    rule.enabled,
                    rule.position,
                    rule.created_at,
                    rule.updated_at
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
                                      created_at, updated_at, path, repo, commit_hash, branch,
                                      dirty, session_id)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
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
                    entry.dirty,
                    entry.session_id
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
        // Sessions come along with their check-ins; the profile stays as it
        // is here, and rules that already exist word for word are skipped.
        let mut arrived: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for session in &backup.sessions {
            let exists: bool = tx.query_row(
                "SELECT EXISTS (SELECT 1 FROM sessions WHERE id = ?1)",
                params![session.id],
                |row| row.get(0),
            )?;
            if exists {
                continue;
            }
            tx.execute(
                "INSERT INTO sessions (id, agent, project, path, repo, commit_hash, branch,
                                       title, status, summary, started_at, last_seen_at, ended_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                params![
                    session.id,
                    session.agent,
                    session.project,
                    session.path,
                    session.repo,
                    session.commit,
                    session.branch,
                    session.title,
                    session.status,
                    session.summary,
                    session.started_at,
                    session.last_seen_at,
                    session.ended_at
                ],
            )?;
            arrived.insert(session.id.as_str());
        }
        for update in &backup.session_updates {
            if !arrived.contains(update.session_id.as_str()) {
                continue;
            }
            tx.execute(
                "INSERT INTO session_updates (session_id, at, body, commit_hash, branch, dirty)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    update.session_id,
                    update.at,
                    update.body,
                    update.commit,
                    update.branch,
                    update.dirty
                ],
            )?;
        }
        for rule in &backup.rules {
            let (scope, target, body) = normalize_rule(&rule.scope, &rule.target, &rule.body)?;
            let exists: bool = tx.query_row(
                "SELECT EXISTS (SELECT 1 FROM rules
                 WHERE scope = ?1 AND target = ?2 AND body = ?3)",
                params![scope, target, body],
                |row| row.get(0),
            )?;
            if exists {
                continue;
            }
            tx.execute(
                "INSERT INTO rules (scope, target, body, enabled, position, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    scope,
                    target,
                    body,
                    rule.enabled,
                    rule.position,
                    rule.created_at,
                    rule.updated_at
                ],
            )?;
        }
        tx.commit()?;
        Ok((added, present))
    }

    /// Stores one agent action and returns it as recorded.
    #[expect(
        clippy::too_many_arguments,
        reason = "one argument per column of the activity row"
    )]
    pub fn record_activity(
        &self,
        agent: &str,
        tool: &str,
        project: &str,
        session_id: Option<&str>,
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
            "INSERT INTO activity (agent, tool, project, entry_id, targets, summary, session_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![agent, tool, project, entry_id, joined, summary, session_id],
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
            session_id: session_id.map(str::to_string),
        })
    }

    /// The newest `limit` actions, newest first.
    pub fn activity(&self, limit: usize) -> Result<Vec<Activity>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT id, at, agent, tool, project, entry_id, targets, summary, session_id
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
                session_id: row.get(8)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Opens the session for a new chat and returns it. The id is "s_" plus
    /// 24 random hex characters.
    pub fn open_session(&self, new: &NewSession) -> Result<Session> {
        let conn = self.lock();
        let id = new_session_id()?;
        conn.execute(
            "INSERT INTO sessions (id, agent, project, path, repo, commit_hash, branch,
                                    title, status, summary, started_at, last_seen_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'open', '',
                     strftime('%Y-%m-%dT%H:%M:%SZ', 'now'),
                     strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))",
            params![
                id,
                new.agent,
                new.project,
                new.path,
                new.repo,
                new.commit,
                new.branch,
                new.title
            ],
        )?;
        get_session(&conn, &id)?.context("session vanished after insert")
    }

    /// One session by its id.
    pub fn session(&self, id: &str) -> Result<Option<Session>> {
        get_session(&self.lock(), id)
    }

    /// Marks the session as seen right now and returns it, after checking it
    /// is still open and belongs to this agent. A session idle for longer
    /// than `idle_hours` is closed first and then refused; a session reached
    /// with the shared token may belong to any agent.
    pub fn touch_session(
        &self,
        id: &str,
        agent: &str,
        shared: bool,
        idle_hours: u32,
    ) -> Result<Session> {
        let conn = self.lock();
        let sql = format!(
            "SELECT {SESSION_COLUMNS}, \
                    (SELECT COUNT(*) FROM session_updates u WHERE u.session_id = s.id), \
                    COALESCE(CAST(strftime('%s', 'now') AS INTEGER) \
                             - CAST(strftime('%s', s.last_seen_at) AS INTEGER), 0)
             FROM sessions s WHERE s.id = ?1"
        );
        let found: Option<(Session, i64)> = conn
            .query_row(&sql, params![id], |row| {
                Ok((Session::from_row(row)?, row.get(14)?))
            })
            .optional()?;
        let Some((session, idle_seconds)) = found else {
            anyhow::bail!("there is no session with this id");
        };
        if session.status == "open" && idle_seconds >= idle_hours as i64 * 3600 {
            conn.execute(
                "UPDATE sessions SET status = 'closed', summary = 'closed after inactivity',
                     ended_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
                 WHERE id = ?1",
                params![id],
            )?;
            anyhow::bail!("it had been idle for more than {idle_hours} hours, so it was closed");
        }
        if session.status != "open" {
            anyhow::bail!("it is closed");
        }
        if !shared && session.agent != agent {
            anyhow::bail!(
                "it belongs to agent {}",
                if session.agent.is_empty() {
                    "someone else"
                } else {
                    &session.agent
                }
            );
        }
        conn.execute(
            "UPDATE sessions SET last_seen_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
             WHERE id = ?1",
            params![id],
        )?;
        get_session(&conn, id)?.context("session vanished after touch")
    }

    /// Stores one check-in on a session.
    pub fn add_session_update(
        &self,
        session_id: &str,
        body: &str,
        commit: &str,
        branch: &str,
        dirty: bool,
    ) -> Result<SessionUpdate> {
        let conn = self.lock();
        conn.execute(
            "INSERT INTO session_updates (session_id, at, body, commit_hash, branch, dirty)
             VALUES (?1, strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), ?2, ?3, ?4, ?5)",
            params![session_id, body, commit, branch, dirty],
        )?;
        let id = conn.last_insert_rowid();
        conn.query_row(
            "SELECT id, session_id, at, body, commit_hash, branch, dirty
             FROM session_updates WHERE id = ?1",
            params![id],
            SessionUpdate::from_row,
        )
        .context("session update vanished after insert")
    }

    /// Records where a chat stands: the commit it is at now, and the branch
    /// when one is given.
    pub fn set_session_head(
        &self,
        session_id: &str,
        commit: &str,
        branch: Option<&str>,
    ) -> Result<()> {
        let conn = self.lock();
        match branch {
            Some(branch) => conn.execute(
                "UPDATE sessions SET commit_hash = ?2, branch = ?3 WHERE id = ?1",
                params![session_id, commit, branch],
            )?,
            None => conn.execute(
                "UPDATE sessions SET commit_hash = ?2 WHERE id = ?1",
                params![session_id, commit],
            )?,
        };
        Ok(())
    }

    /// Closes a session with its final summary.
    pub fn close_session(&self, id: &str, summary: &str) -> Result<Session> {
        let conn = self.lock();
        let changed = conn.execute(
            "UPDATE sessions SET status = 'closed', summary = ?2,
                 ended_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now'),
                 last_seen_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
             WHERE id = ?1",
            params![id, summary],
        )?;
        if changed == 0 {
            anyhow::bail!("there is no session with this id");
        }
        get_session(&conn, id)?.context("session vanished after close")
    }

    /// Sessions, newest activity first, each with its check-in count.
    pub fn sessions(
        &self,
        status: Option<&str>,
        project: Option<&str>,
        limit: usize,
    ) -> Result<Vec<Session>> {
        let conn = self.lock();
        let mut sql = format!(
            "SELECT {SESSION_COLUMNS}, \
                    (SELECT COUNT(*) FROM session_updates u WHERE u.session_id = s.id)
             FROM sessions s WHERE 1=1"
        );
        let mut args: Vec<Value> = Vec::new();
        if let Some(status) = status {
            sql.push_str(" AND s.status = ?");
            args.push(Value::Text(status.to_string()));
        }
        if let Some(project) = project {
            sql.push_str(" AND s.project = ?");
            args.push(Value::Text(project.to_string()));
        }
        sql.push_str(" ORDER BY s.last_seen_at DESC, s.id DESC LIMIT ?");
        args.push(Value::Integer(limit as i64));
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(params_from_iter(args), Session::from_row)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// A session's check-ins, oldest first.
    pub fn session_updates(&self, session_id: &str) -> Result<Vec<SessionUpdate>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT id, session_id, at, body, commit_hash, branch, dirty
             FROM session_updates WHERE session_id = ?1 ORDER BY id",
        )?;
        let rows = stmt.query_map(params![session_id], SessionUpdate::from_row)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// The body of a session's latest check-in, if it has one.
    pub fn latest_session_update(&self, session_id: &str) -> Result<Option<String>> {
        let conn = self.lock();
        Ok(conn
            .query_row(
                "SELECT body FROM session_updates WHERE session_id = ?1
                 ORDER BY id DESC LIMIT 1",
                params![session_id],
                |row| row.get(0),
            )
            .optional()?)
    }

    /// Closes every open session idle for longer than `idle_hours` and
    /// returns how many were closed.
    pub fn close_idle_sessions(&self, idle_hours: u32) -> Result<usize> {
        Ok(self.lock().execute(
            "UPDATE sessions SET status = 'closed', summary = 'closed after inactivity',
                     ended_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
                 WHERE status = 'open'
                   AND COALESCE(CAST(strftime('%s', 'now') AS INTEGER)
                                - CAST(strftime('%s', last_seen_at) AS INTEGER), 0)
                       >= ?1 * 3600",
            params![idle_hours as i64],
        )?)
    }

    /// How many sessions are open right now.
    pub fn open_session_count(&self) -> Result<i64> {
        Ok(self.lock().query_row(
            "SELECT COUNT(*) FROM sessions WHERE status = 'open'",
            [],
            |row| row.get(0),
        )?)
    }

    /// The user's profile: the default form of address, the reply language
    /// and each agent's own form of address.
    pub fn profile(&self) -> Result<Profile> {
        let conn = self.lock();
        let address = meta_value(&conn, "profile.address")?;
        let language = meta_value(&conn, "profile.language")?;
        let agents = {
            let mut stmt =
                conn.prepare("SELECT agent, address FROM agent_profiles ORDER BY agent")?;
            let rows = stmt.query_map([], |row| {
                Ok(AgentAddress {
                    agent: row.get(0)?,
                    address: row.get(1)?,
                })
            })?;
            rows.collect::<rusqlite::Result<_>>()?
        };
        Ok(Profile {
            address,
            language,
            agents,
        })
    }

    /// Replaces the profile. Agent rows with an empty address are dropped:
    /// those agents use the default form of address.
    pub fn set_profile(&self, input: &ProfileInput) -> Result<()> {
        let mut conn = self.lock();
        let tx = conn.transaction()?;
        set_meta(&tx, "profile.address", input.address.trim())?;
        set_meta(&tx, "profile.language", input.language.trim())?;
        tx.execute("DELETE FROM agent_profiles", [])?;
        {
            let mut stmt =
                tx.prepare("INSERT INTO agent_profiles (agent, address) VALUES (?1, ?2)")?;
            for agent in &input.agents {
                let address = agent.address.trim();
                let name = agent.agent.trim().to_lowercase();
                if name.is_empty() || address.is_empty() {
                    continue;
                }
                stmt.execute(params![name, address])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Every rule, global ones first, then agent ones, then project ones.
    pub fn rules(&self) -> Result<Vec<Rule>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(&format!("SELECT {RULE_COLUMNS} FROM rules {RULE_ORDER}"))?;
        let rows = stmt.query_map([], Rule::from_row)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Adds a rule after validating its shape.
    pub fn add_rule(&self, input: &RuleInput) -> Result<Rule> {
        let (scope, target, body) = normalize_rule(&input.scope, &input.target, &input.body)?;
        let conn = self.lock();
        conn.execute(
            "INSERT INTO rules (scope, target, body, enabled, position,
                                 created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, strftime('%Y-%m-%dT%H:%M:%SZ', 'now'),
                     strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))",
            params![scope, target, body, input.enabled, input.position],
        )?;
        let id = conn.last_insert_rowid();
        get_rule(&conn, id)?.context("rule vanished after insert")
    }

    /// Applies a full edit of one rule. `None` when the id does not exist.
    pub fn update_rule(&self, id: i64, input: &RuleInput) -> Result<Option<Rule>> {
        let (scope, target, body) = normalize_rule(&input.scope, &input.target, &input.body)?;
        let conn = self.lock();
        let changed = conn.execute(
            "UPDATE rules SET scope = ?2, target = ?3, body = ?4, enabled = ?5,
                     position = ?6, updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
             WHERE id = ?1",
            params![id, scope, target, body, input.enabled, input.position],
        )?;
        if changed == 0 {
            return Ok(None);
        }
        get_rule(&conn, id)
    }

    /// Removes one rule. False when the id did not exist.
    pub fn delete_rule(&self, id: i64) -> Result<bool> {
        Ok(self
            .lock()
            .execute("DELETE FROM rules WHERE id = ?1", params![id])?
            > 0)
    }

    /// The enabled rules that apply to one agent on one project: the global
    /// ones, that agent's own and the project's.
    pub fn briefing_rules(&self, agent: &str, project: &str) -> Result<Vec<Rule>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(&format!(
            "SELECT {RULE_COLUMNS} FROM rules
             WHERE enabled = 1 AND (scope = 'global'
                   OR (scope = 'agent' AND target = ?1)
                   OR (scope = 'project' AND target = ?2))
             {RULE_ORDER}"
        ))?;
        let rows = stmt.query_map(params![agent, project], Rule::from_row)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// The form of address one agent should use: its own if set, otherwise
    /// the default one.
    pub fn address_for(&self, agent: &str) -> Result<String> {
        let conn = self.lock();
        let own: Option<String> = conn
            .query_row(
                "SELECT address FROM agent_profiles WHERE agent = ?1",
                params![agent],
                |row| row.get(0),
            )
            .optional()?;
        let default = meta_value(&conn, "profile.address")?;
        Ok(own.filter(|address| !address.is_empty()).unwrap_or(default))
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
    for session in &backup.sessions {
        if session.id.trim().is_empty() || session.started_at.trim().is_empty() {
            anyhow::bail!("a session in the backup has no id or start time");
        }
        if !["open", "closed"].contains(&session.status.as_str()) {
            anyhow::bail!(
                "session \"{}\" has an unknown status \"{}\"",
                session.id,
                session.status
            );
        }
    }
    let session_ids: std::collections::HashSet<&str> =
        backup.sessions.iter().map(|s| s.id.as_str()).collect();
    for update in &backup.session_updates {
        if !session_ids.contains(update.session_id.as_str()) {
            anyhow::bail!(
                "a check-in refers to session \"{}\", which is not in the backup",
                update.session_id
            );
        }
    }
    for rule in &backup.rules {
        normalize_rule(&rule.scope, &rule.target, &rule.body)
            .with_context(|| format!("rule #{} is not valid", rule.id))?;
    }
    Ok(())
}

/// Adds columns introduced after a database was first created.
fn add_missing_columns(conn: &Connection) -> Result<()> {
    for (table, name, definition) in ADDED_COLUMNS {
        let existing: Vec<String> = conn
            .prepare(&format!("SELECT name FROM pragma_table_info('{table}')"))?
            .query_map([], |row| row.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        if !existing.iter().any(|column| column == name) {
            conn.execute_batch(&format!(
                "ALTER TABLE {table} ADD COLUMN {name} {definition};"
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

/// One session row plus its check-in count.
fn get_session(conn: &Connection, id: &str) -> Result<Option<Session>> {
    let sql = format!(
        "SELECT {SESSION_COLUMNS}, \
                (SELECT COUNT(*) FROM session_updates u WHERE u.session_id = s.id)
         FROM sessions s WHERE s.id = ?1"
    );
    Ok(conn
        .query_row(&sql, params![id], Session::from_row)
        .optional()?)
}

fn get_rule(conn: &Connection, id: i64) -> Result<Option<Rule>> {
    let sql = format!("SELECT {RULE_COLUMNS} FROM rules WHERE id = ?1");
    Ok(conn
        .query_row(&sql, params![id], Rule::from_row)
        .optional()?)
}

/// "s_" plus 24 random hex characters.
fn new_session_id() -> Result<String> {
    let mut bytes = [0u8; 12];
    getrandom::fill(&mut bytes)?;
    Ok(format!(
        "s_{}",
        bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
    ))
}

/// Checks and normalises a rule's scope, target and body.
fn normalize_rule(scope: &str, target: &str, body: &str) -> Result<(String, String, String)> {
    let scope = scope.trim().to_lowercase();
    if !RULE_SCOPES.contains(&scope.as_str()) {
        anyhow::bail!("scope must be one of: {}", RULE_SCOPES.join(", "));
    }
    let mut target = target.trim().to_string();
    match scope.as_str() {
        "global" => {
            if !target.is_empty() {
                anyhow::bail!("a global rule must not name a target");
            }
        }
        "agent" => {
            if target.is_empty() {
                anyhow::bail!("an agent rule must name its agent");
            }
            // Agent names are lowercase everywhere else (tokens, sessions).
            target = target.to_lowercase();
        }
        _ => {
            if target.is_empty() {
                anyhow::bail!("a project rule must name its project");
            }
            target = target.to_lowercase();
        }
    }
    let body = body.trim();
    if body.is_empty() {
        anyhow::bail!("the rule body must not be empty");
    }
    if body.chars().count() > RULE_BODY_MAX_CHARS {
        anyhow::bail!("the rule body must be at most {RULE_BODY_MAX_CHARS} characters");
    }
    Ok((scope, target, body.to_string()))
}

/// Writes one `meta` key.
fn set_meta(conn: &Connection, key: &str, value: &str) -> Result<()> {
    conn.execute(
        "INSERT INTO meta (key, value) VALUES (?1, ?2)
         ON CONFLICT (key) DO UPDATE SET value = excluded.value",
        params![key, value],
    )?;
    Ok(())
}

/// Reads one `meta` key, or an empty string when it is not set.
fn meta_value(conn: &Connection, key: &str) -> Result<String> {
    Ok(conn
        .query_row(
            "SELECT value FROM meta WHERE key = ?1",
            params![key],
            |row| row.get(0),
        )
        .optional()?
        .unwrap_or_default())
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
    blob.as_chunks::<4>()
        .0
        .iter()
        .map(|chunk| f32::from_le_bytes(*chunk))
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
                 INSERT INTO entries (project, kind, title, body) VALUES ('p', 'note', 'old', 'entry');
                 CREATE TABLE activity (id INTEGER PRIMARY KEY AUTOINCREMENT,
                 at TEXT NOT NULL DEFAULT 'x', agent TEXT NOT NULL, tool TEXT NOT NULL,
                 project TEXT NOT NULL DEFAULT '', entry_id INTEGER,
                 targets TEXT NOT NULL DEFAULT '', summary TEXT NOT NULL DEFAULT '');
                 INSERT INTO activity (agent, tool, summary) VALUES ('claude', 'log', 'kept');
                 CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                 INSERT INTO meta (key, value) VALUES ('embedding_model', 'kept-model');",
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
        assert!(old.session_id.is_none());
        // The activity log and meta keep their rows and gain the session column.
        let feed = db.activity(10).unwrap();
        assert_eq!((feed.len(), feed[0].summary.as_str()), (1, "kept"));
        assert!(feed[0].session_id.is_none());
        db.record_activity("claude", "hello", "p", Some("s_x"), None, &[], "t")
            .unwrap();
        assert_eq!(
            db.export().unwrap().embedding_model.as_deref(),
            Some("kept-model")
        );
        // Opening it again changes nothing.
        drop(db);
        let db = Db::open(&path).unwrap();
        assert_eq!(db.activity(10).unwrap().len(), 2);
        assert_eq!(db.get(1).unwrap().unwrap().title, "old");
    }

    #[test]
    fn activity_is_recorded_newest_first() {
        let db = temp_db();
        db.record_activity("claude", "log", "shop", None, Some(1), &[], "Added refunds")
            .unwrap();
        let second = db
            .record_activity("codex", "recall", "", Some("s_x"), None, &[1, 4], "refunds")
            .unwrap();
        assert_eq!(second.targets, [1, 4]);
        assert_eq!(second.session_id.as_deref(), Some("s_x"));
        let feed = db.activity(10).unwrap();
        assert_eq!(feed.len(), 2);
        assert_eq!(
            (feed[0].agent.as_str(), feed[0].tool.as_str()),
            ("codex", "recall")
        );
        assert_eq!(feed[0].targets, [1, 4]);
        assert_eq!(feed[1].entry_id, Some(1));
        assert!(feed[1].session_id.is_none());
    }

    fn session(agent: &str, project: &str, title: &str) -> NewSession {
        NewSession {
            agent: agent.into(),
            project: project.into(),
            title: title.into(),
            ..Default::default()
        }
    }

    /// Backdates every session so it looks `hours` idle.
    fn backdate(db: &Db, hours: i64) {
        db.lock()
            .execute(
                &format!(
                    "UPDATE sessions SET last_seen_at = \
                     strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-{hours} hours')"
                ),
                [],
            )
            .unwrap();
    }

    #[test]
    fn sessions_open_update_and_close() {
        let db = temp_db();
        let opened = db
            .open_session(&session("claude", "shop", "Fix the checkout flow"))
            .unwrap();
        assert!(opened.id.starts_with("s_") && opened.id.len() == 26);
        assert_eq!(opened.status, "open");
        assert_eq!(opened.updates, 0);

        let touched = db.touch_session(&opened.id, "claude", false, 12).unwrap();
        assert_eq!(touched.id, opened.id);

        let update = db
            .add_session_update(&opened.id, "wrote the tests", "abc1234", "main", false)
            .unwrap();
        assert_eq!(update.body, "wrote the tests");
        assert_eq!(
            db.latest_session_update(&opened.id).unwrap().as_deref(),
            Some("wrote the tests")
        );

        let listed = db.sessions(Some("open"), Some("shop"), 10).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].updates, 1);

        let closed = db.close_session(&opened.id, "checkout tests pass").unwrap();
        assert_eq!(closed.status, "closed");
        assert_eq!(closed.summary, "checkout tests pass");
        assert!(closed.ended_at.is_some());

        // A closed session refuses further work, but keeps its timeline.
        assert!(db.touch_session(&opened.id, "claude", false, 12).is_err());
        assert_eq!(db.session_updates(&opened.id).unwrap().len(), 1);
        assert_eq!(db.open_session_count().unwrap(), 0);
        assert!(db.session("s_nope").unwrap().is_none());
    }

    #[test]
    fn a_session_of_another_agent_is_refused_unless_shared() {
        let db = temp_db();
        let opened = db.open_session(&session("claude", "shop", "t")).unwrap();
        let error = db
            .touch_session(&opened.id, "codex", false, 12)
            .unwrap_err()
            .to_string();
        assert!(error.contains("belongs to"), "unexpected error: {error}");
        // The shared token may touch any agent's session.
        db.touch_session(&opened.id, "codex", true, 12).unwrap();
    }

    #[test]
    fn idle_sessions_close_and_are_refused() {
        let db = temp_db();
        let opened = db.open_session(&session("claude", "shop", "t")).unwrap();
        backdate(&db, 25);

        let error = db
            .touch_session(&opened.id, "claude", false, 12)
            .unwrap_err()
            .to_string();
        assert!(error.contains("idle"), "unexpected error: {error}");
        let closed = db.session(&opened.id).unwrap().unwrap();
        assert_eq!(closed.status, "closed");
        assert_eq!(closed.summary, "closed after inactivity");
        assert!(closed.ended_at.is_some());

        // close_idle_sessions sweeps the rest and leaves fresh ones alone.
        let second = db.open_session(&session("codex", "blog", "t")).unwrap();
        db.touch_session(&second.id, "codex", false, 12).unwrap();
        assert_eq!(db.close_idle_sessions(12).unwrap(), 0);
        backdate(&db, 30);
        assert_eq!(db.close_idle_sessions(12).unwrap(), 1);
        assert_eq!(db.session(&second.id).unwrap().unwrap().status, "closed");
        let third = db.open_session(&session("codex", "blog", "t2")).unwrap();
        db.touch_session(&third.id, "codex", false, 12).unwrap();
        assert_eq!(db.close_idle_sessions(12).unwrap(), 0);
        assert_eq!(db.session(&third.id).unwrap().unwrap().status, "open");
    }

    #[test]
    fn rules_validate_and_brief_by_scope() {
        let db = temp_db();
        let rule = |scope: &str, target: &str, body: &str| RuleInput {
            scope: scope.into(),
            target: target.into(),
            body: body.into(),
            enabled: true,
            position: 0,
        };
        assert!(db.add_rule(&rule("world", "", "b")).is_err());
        assert!(db.add_rule(&rule("global", "claude", "b")).is_err());
        assert!(db.add_rule(&rule("agent", "", "b")).is_err());
        assert!(db.add_rule(&rule("project", "", "b")).is_err());
        assert!(db.add_rule(&rule("global", "", "")).is_err());
        assert!(db.add_rule(&rule("global", "", &"x".repeat(2001))).is_err());

        // Project targets are stored lowercase.
        let project = db
            .add_rule(&rule("project", "Shop", "run the linter"))
            .unwrap();
        assert_eq!(project.target, "shop");
        db.add_rule(&rule("global", "", "log in English")).unwrap();
        // Agent targets are lowercase too, like every agent name.
        let agent_rule = db
            .add_rule(&rule("agent", "Claude", "ask before deleting"))
            .unwrap();
        assert_eq!(agent_rule.target, "claude");
        let mut disabled = rule("agent", "claude", "never delete anything");
        disabled.enabled = false;
        db.add_rule(&disabled).unwrap();

        let briefing = db.briefing_rules("claude", "shop").unwrap();
        assert_eq!(
            briefing.iter().map(|r| r.body.as_str()).collect::<Vec<_>>(),
            ["log in English", "ask before deleting", "run the linter"]
        );
        // Other agents see only the global and project rules.
        assert_eq!(db.briefing_rules("codex", "shop").unwrap().len(), 2);
        assert_eq!(db.briefing_rules("claude", "blog").unwrap().len(), 2);

        // The listing groups by scope and can be edited.
        let all = db.rules().unwrap();
        assert_eq!(all.len(), 4);
        assert_eq!(
            all.iter().map(|r| r.scope.as_str()).collect::<Vec<_>>(),
            ["global", "agent", "agent", "project"]
        );
        let mut edited = rule("project", "shop", "run the linter twice");
        edited.position = 3;
        let saved = db.update_rule(project.id, &edited).unwrap().unwrap();
        assert_eq!(saved.body, "run the linter twice");
        assert!(db.update_rule(9999, &edited).unwrap().is_none());
        assert!(db.delete_rule(project.id).unwrap());
        assert!(!db.delete_rule(project.id).unwrap());
        assert_eq!(db.rules().unwrap().len(), 3);

        // Rules from a backup are normalised the same way, so a hand-edited
        // file neither duplicates a rule nor hides it from the briefing.
        let mut backup = db.export().unwrap();
        backup.rules[1].scope = " Agent ".into();
        backup.rules[1].target = "CLAUDE".into();
        db.merge(&backup).unwrap();
        assert_eq!(db.rules().unwrap().len(), 3);
        db.restore(&backup).unwrap();
        assert_eq!(db.briefing_rules("claude", "shop").unwrap().len(), 2);
    }

    #[test]
    fn address_for_falls_back_to_the_default() {
        let db = temp_db();
        assert_eq!(db.address_for("claude").unwrap(), "");
        db.set_profile(&ProfileInput {
            address: "Boss".into(),
            language: "English".into(),
            agents: vec![
                AgentAddress {
                    agent: "Codex".into(),
                    address: "Captain".into(),
                },
                // An empty address is dropped: that agent uses the default.
                AgentAddress {
                    agent: "codex".into(),
                    address: "  ".into(),
                },
            ],
        })
        .unwrap();
        let profile = db.profile().unwrap();
        assert_eq!(profile.address, "Boss");
        assert_eq!(profile.language, "English");
        assert_eq!(profile.agents.len(), 1);
        assert_eq!(profile.agents[0].agent, "codex");
        assert_eq!(db.address_for("codex").unwrap(), "Captain");
        assert_eq!(db.address_for("claude").unwrap(), "Boss");
    }

    #[test]
    fn backup_v3_round_trips_and_a_v2_file_still_restores() {
        let db = temp_db();
        let opened = db
            .open_session(&session("claude", "shop", "Refactor payments"))
            .unwrap();
        db.add_session_update(&opened.id, "first step", "abc1234", "main", true)
            .unwrap();
        db.set_profile(&ProfileInput {
            address: "Boss".into(),
            language: "English".into(),
            agents: vec![AgentAddress {
                agent: "codex".into(),
                address: "Captain".into(),
            }],
        })
        .unwrap();
        db.add_rule(&RuleInput {
            scope: "global".into(),
            target: String::new(),
            body: "be kind".into(),
            enabled: true,
            position: 0,
        })
        .unwrap();
        let entry = db
            .insert(&NewEntry {
                project: "shop".into(),
                kind: "update".into(),
                title: "Payments".into(),
                body: "split the charger".into(),
                session_id: Some(opened.id.clone()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(entry.session_id.as_deref(), Some(opened.id.as_str()));

        let json = serde_json::to_string(&db.export().unwrap()).unwrap();
        let backup: Backup = serde_json::from_str(&json).unwrap();
        assert_eq!(backup.version, 3);
        assert_eq!(backup.sessions.len(), 1);
        assert_eq!(backup.session_updates.len(), 1);
        assert_eq!(backup.rules.len(), 1);
        assert_eq!(backup.profile.address, "Boss");
        assert_eq!(
            backup.entries[0].session_id.as_deref(),
            Some(opened.id.as_str())
        );

        // Restore reproduces the sessions, the rules and the profile exactly.
        assert_eq!(db.restore(&backup).unwrap(), 1);
        let restored = db.session(&opened.id).unwrap().unwrap();
        assert_eq!(restored.updates, 1);
        assert_eq!(restored.title, "Refactor payments");
        assert_eq!(
            db.session_updates(&opened.id).unwrap()[0].body,
            "first step"
        );
        assert_eq!(db.address_for("codex").unwrap(), "Captain");
        assert_eq!(db.rules().unwrap()[0].body, "be kind");

        // A version 2 file, without the new sections, still restores; it
        // replaces the entries but keeps the sessions, profile and rules it
        // knows nothing about.
        let mut value = serde_json::to_value(db.export().unwrap()).unwrap();
        let object = value.as_object_mut().unwrap();
        for key in ["sessions", "session_updates", "profile", "rules"] {
            object.remove(key);
        }
        object.insert("version".into(), serde_json::json!(2));
        for entry in object.get_mut("entries").unwrap().as_array_mut().unwrap() {
            entry.as_object_mut().unwrap().remove("session_id");
        }
        for activity in object.get_mut("activity").unwrap().as_array_mut().unwrap() {
            activity.as_object_mut().unwrap().remove("session_id");
        }
        let v2: Backup = serde_json::from_value(value).unwrap();
        assert_eq!(v2.version, 2);
        assert!(v2.sessions.is_empty() && v2.rules.is_empty());
        db.restore(&v2).unwrap();
        assert!(db.get(entry.id).unwrap().unwrap().session_id.is_none());
        assert_eq!(db.session(&opened.id).unwrap().unwrap().updates, 1);
        assert_eq!(db.rules().unwrap().len(), 1);
        assert_eq!(db.address_for("codex").unwrap(), "Captain");

        // Clear the new tables by hand to exercise merge from scratch.
        db.lock()
            .execute_batch(
                "DELETE FROM sessions; DELETE FROM session_updates;
                 DELETE FROM agent_profiles; DELETE FROM rules;",
            )
            .unwrap();

        // Merging adds the missing session with its updates and the missing
        // rule, and leaves the profile alone. Merging again adds nothing.
        db.merge(&backup).unwrap();
        assert_eq!(
            db.session(&opened.id).unwrap().unwrap().title,
            "Refactor payments"
        );
        assert_eq!(db.session_updates(&opened.id).unwrap().len(), 1);
        assert_eq!(db.rules().unwrap().len(), 1);
        assert_eq!(db.address_for("codex").unwrap(), "Boss");
        let (added, present) = db.merge(&backup).unwrap();
        assert_eq!((added, present), (0, 1));
        assert_eq!(db.session_updates(&opened.id).unwrap().len(), 1);
        assert_eq!(db.rules().unwrap().len(), 1);
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
        db.record_activity(
            "claude",
            "log",
            "shop",
            None,
            Some(first.id),
            &[],
            "Refunds",
        )
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
