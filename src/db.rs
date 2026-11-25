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
    embedding  BLOB
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

const COLUMNS: &str = "id, project, kind, title, body, tags, files, agent, created_at, updated_at";

#[derive(Debug, Clone, serde::Serialize)]
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
    pub updated_at: Option<String>,
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
}

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
            "INSERT INTO entries (project, kind, title, body, tags, files, agent)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                new.project,
                new.kind,
                new.title,
                new.body,
                new.tags,
                new.files,
                new.agent
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
        let mut stmt = conn.prepare(
            "SELECT project, COUNT(*), MAX(created_at) FROM entries
             GROUP BY project ORDER BY MAX(created_at) DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(ProjectSummary {
                project: row.get(0)?,
                entries: row.get(1)?,
                last_activity: row.get(2)?,
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
