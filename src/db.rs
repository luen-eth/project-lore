//! SQLite storage: entries, chat sessions, the user profile and rules, the
//! shared board of tasks and messages, the full-text index, and embedding
//! blobs.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension, params, params_from_iter, types::Value};

use crate::users::Perms;

mod agents;
pub use agents::*;
mod builtin;
pub use builtin::*;
mod rename;
pub use rename::*;

pub const KINDS: &[&str] = &["update", "decision", "bug", "note", "todo"];

/// Held while a note-style to-do is checked and moved to the board (the
/// tool and the page), so two moves at once cannot both add a task.
pub static MOVE_TO_BOARD: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The line a note-style to-do gets when it is moved to the board.
pub fn moved_to_board_line(task_id: i64) -> String {
    format!("Moved to the board as task #{task_id}.")
}

/// The task a note-style to-do was already moved to, read from the line
/// `moved_to_board_line` wrote.
pub fn moved_to_board(body: &str) -> Option<i64> {
    body.lines().rev().find_map(|line| {
        line.trim()
            .strip_prefix("Moved to the board as task #")?
            .strip_suffix('.')?
            .parse()
            .ok()
    })
}

/// The project a to-do without one is filed under (`todo_add`, the page's
/// To-do view). Like any task, one there is taken by a built-in agent only
/// with a repository of its own or one recorded for the project.
pub const GENERAL_PROJECT: &str = "general";

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
    ended_at     TEXT,
    implicit     INTEGER NOT NULL DEFAULT 0
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

CREATE TABLE IF NOT EXISTS tasks (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    project     TEXT NOT NULL,
    title       TEXT NOT NULL,
    body        TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL DEFAULT 'open',
    assignee    TEXT NOT NULL DEFAULT '',
    created_by  TEXT NOT NULL,
    claimed_by  TEXT NOT NULL DEFAULT '',
    done_by     TEXT NOT NULL DEFAULT '',
    done_commit TEXT NOT NULL DEFAULT '',
    note        TEXT NOT NULL DEFAULT '',
    session_id  TEXT,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    done_at     TEXT
);
CREATE INDEX IF NOT EXISTS tasks_project_status ON tasks (project, status);

-- Notes the owner (a signed-in user) leaves on a task (schema 9), in order;
-- the task's own `note` stays the latest status note agents and lore write.
-- `task_created` is the task's own created_at when the note was written: a
-- note shows only with the task whose created_at still matches, so a row
-- left behind can never attach to another task that reuses the id.
CREATE TABLE IF NOT EXISTS task_notes (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id      INTEGER NOT NULL,
    author       TEXT NOT NULL,
    body         TEXT NOT NULL,
    created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    task_created TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS task_notes_task ON task_notes (task_id, id);

CREATE TABLE IF NOT EXISTS messages (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    kind         TEXT NOT NULL,
    project      TEXT NOT NULL DEFAULT '',
    from_agent   TEXT NOT NULL,
    to_agent     TEXT NOT NULL DEFAULT '',
    body         TEXT NOT NULL,
    session_id   TEXT,
    created_at   TEXT NOT NULL,
    delivered_to TEXT NOT NULL DEFAULT '',
    delivered_session TEXT,
    delivered_at TEXT
);
CREATE TABLE IF NOT EXISTS message_reads (
    message_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    agent      TEXT NOT NULL,
    read_at    TEXT NOT NULL,
    PRIMARY KEY (message_id, agent)
);

CREATE TABLE IF NOT EXISTS files (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    project     TEXT NOT NULL,
    path        TEXT NOT NULL,
    version     INTEGER NOT NULL,
    kind        TEXT NOT NULL DEFAULT 'other',
    description TEXT NOT NULL,
    encoding    TEXT NOT NULL DEFAULT 'utf8',
    content     BLOB NOT NULL,
    size        INTEGER NOT NULL,
    sha256      TEXT NOT NULL,
    entry_id    INTEGER,
    agent       TEXT NOT NULL,
    session_id  TEXT,
    created_at  TEXT NOT NULL,
    embedding   BLOB,
    UNIQUE (project, path, version)
);
CREATE INDEX IF NOT EXISTS files_project_path ON files (project, path, version DESC);

CREATE TABLE IF NOT EXISTS vault (
    provider   TEXT PRIMARY KEY,            -- cloudflare | github | github_org | gitlab | dokploy | mail
    base_url   TEXT NOT NULL DEFAULT '',    -- gitlab and dokploy only
    nonce      BLOB NOT NULL,
    secret     BLOB NOT NULL,               -- ciphertext
    hint       TEXT NOT NULL DEFAULT '',    -- last 4 characters of the credential
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ops_permissions (
    agent    TEXT NOT NULL,
    provider TEXT NOT NULL,
    level    TEXT NOT NULL,                 -- off | read | full
    PRIMARY KEY (agent, provider)
);
CREATE TABLE IF NOT EXISTS ops_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    agent      TEXT NOT NULL,               -- agent name, or 'admin' for a test call
    session_id TEXT,
    provider   TEXT NOT NULL,
    method     TEXT NOT NULL,
    path       TEXT NOT NULL,               -- path only: no query string, no body
    status     INTEGER NOT NULL,            -- upstream HTTP status; 0 = no response
    outcome    TEXT NOT NULL,               -- ok | denied | error
    detail     TEXT NOT NULL DEFAULT '',    -- short reason for denied / error
    duration_ms INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ops_log_created ON ops_log (created_at DESC);

-- Users who sign in to the admin view besides the two built-in ones. Never
-- part of the JSON backup; the full database backup carries them.
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE,     -- lowercase
    email         TEXT UNIQUE,              -- lowercase; NULL when not given
    password_hash TEXT NOT NULL,            -- Argon2id PHC string
    permissions   TEXT NOT NULL DEFAULT '[]', -- JSON array of permission ids
    disabled      INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    last_login_at TEXT,
    created_by    TEXT NOT NULL DEFAULT ''
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
                                title, status, summary, started_at, last_seen_at, ended_at, \
                                implicit";

const RULE_COLUMNS: &str = "id, scope, target, body, enabled, position, created_at, updated_at";

/// Rule listing order: global rules, then agent rules, then project rules,
/// each by position and id.
const RULE_ORDER: &str =
    "ORDER BY CASE scope WHEN 'global' THEN 0 WHEN 'agent' THEN 1 ELSE 2 END, position, id";

/// Longest rule body accepted.
const RULE_BODY_MAX_CHARS: usize = 2000;

/// The columns of a task row, in the order `Task::from_row` reads them.
const TASK_COLUMNS: &str = "id, project, title, body, status, assignee, created_by, \
                            claimed_by, done_by, done_commit, note, session_id, \
                            created_at, updated_at, done_at, repo, dokploy_project_id, \
                            cloudflare_zone, manual, manual_by";

/// The columns of a message row, in the order `Message::from_row` reads them.
const MESSAGE_COLUMNS: &str = "id, kind, project, from_agent, to_agent, body, session_id, \
                               created_at, delivered_to, delivered_session, delivered_at";

/// Task statuses: open, claimed, done or cancelled.
pub const TASK_STATUSES: &[&str] = &["open", "claimed", "done", "cancelled"];

/// The actions a task update can take.
pub const TASK_ACTIONS: &[&str] = &["claim", "release", "done", "cancel", "reopen"];

/// Message kinds: a message to agents, or a handoff note for a project.
pub const MESSAGE_KINDS: &[&str] = &["message", "handoff"];

/// Longest task title accepted.
pub const TASK_TITLE_MAX_CHARS: usize = 200;
/// Longest task or message body accepted.
pub const BODY_MAX_CHARS: usize = 4000;
/// Longest task status note accepted.
pub const NOTE_MAX_CHARS: usize = 1000;

/// The columns of a file row without its content and vector, in the order
/// `FileInfo::from_row` reads them.
const FILE_COLUMNS: &str = "id, project, path, version, kind, description, encoding, size, \
                            sha256, entry_id, agent, session_id, created_at";

/// What a kept file is: the ideas a project is built on, a design note, a
/// data file, a configuration file, or something else.
pub const FILE_KINDS: &[&str] = &["idea", "doc", "data", "config", "other"];
/// How file content is exchanged: as text, or as base64 for binary files.
pub const FILE_ENCODINGS: &[&str] = &["utf8", "base64"];
/// Largest file accepted, in raw bytes.
pub const FILE_MAX_BYTES: usize = 2 * 1024 * 1024;
/// Longest file description accepted.
pub const FILE_DESCRIPTION_MAX_CHARS: usize = 1000;
/// Longest file path accepted.
pub const FILE_PATH_MAX_CHARS: usize = 300;

/// The services whose credentials lore can keep, with fixed ids.
pub const PROVIDERS: &[&str] = &["cloudflare", "github", "github_org", "gitlab", "dokploy"];

/// What an agent may do with a provider: off, read or full. No permission
/// row means full.
pub const OPS_LEVELS: &[&str] = &["off", "read", "full"];

/// The mailbox: kept in the vault and in the level table like the
/// services, but not one of `PROVIDERS` (it is not an HTTP API), with its
/// own levels and its own default.
pub const MAIL_PROVIDER: &str = "mail";

/// What an agent may do with the mailbox: nothing, or look. `full` is
/// accepted and stored as `read`; there is nothing more to grant.
pub const MAIL_LEVELS: &[&str] = &["off", "read"];

/// The mailbox level without a permission row: unlike the services, an
/// agent sees the mailbox only after someone grants it.
pub const MAIL_DEFAULT_LEVEL: &str = "off";

/// How a provider call went: it answered, it was refused, or it failed.
pub const OPS_OUTCOMES: &[&str] = &["ok", "denied", "error"];

/// Ops log rows kept; older ones are dropped.
const OPS_LOG_KEPT: i64 = 5000;

/// The schema this build creates and understands, kept in `meta` as
/// `schema_version`. A database without the key predates it (0). Raise it
/// whenever a table or column is added, so a full backup from a newer build
/// is recognised and refused instead of loaded half-understood.
///
/// 1: users. 2: the agent registry and the OAuth tables. 3: the mailbox
/// columns of `vault` (host, port, account). 4: the built-in agents
/// (`builtin_agents`, `agent_runs`, `agent_run_events`). 5: the task
/// runner's task columns (`repo`, `dokploy_project_id`, `cloudflare_zone`,
/// `auto_attempts`, `auto_last_at`) and run columns. 6: help for other
/// agents (`delegations`; `agent_runs.requested_by`, `conversation`).
/// 7: run hardening (`tasks.author`, `touches`, `auto_seen`;
/// `sessions.token_agent`; `builtin_agents.read_other_services`;
/// `agent_runs.output_bytes`). 8: run confirmation and provenance
/// (`agent_run_refs`, `run_writes`; `agent_runs.base_head`). 9: an
/// agent's display name (`agent_registry.display_name`), and per built-in
/// agent the services of its terminals and the order and fallback of
/// Claude's credentials (`builtin_agents.terminal_services`,
/// `claude_priority`, `claude_fallback`; the last two unused since Claude
/// Code is signed in with the subscription only), a task's manual flag
/// (`tasks.manual`, `tasks.manual_by`) and the owner's notes on tasks
/// (`task_notes`, each bound to its task's `created_at`); the
/// columns nullable, NULL being the behaviour before them.
pub const SCHEMA_VERSION: i64 = 9;

/// Columns every database lore ever created has in `entries`: a full
/// backup without them is not a lore database.
const OLDEST_ENTRY_COLUMNS: &[&str] = &[
    "id",
    "project",
    "kind",
    "title",
    "body",
    "tags",
    "files",
    "agent",
    "created_at",
    "updated_at",
    "embedding",
];

/// Prefix of the temporary files the full backup and restore write next to
/// the database; leftovers from an interrupted run are removed at start-up.
const TEMP_PREFIX: &str = ".lore-tmp-";

/// Prefix of the safety copies a full restore writes before it replaces
/// the database.
pub const SNAPSHOT_PREFIX: &str = "pre-restore-";

/// Safety copies kept; older ones are removed.
const SNAPSHOTS_KEPT: usize = 3;

/// Columns added after the first release, as (table, name, definition).
const ADDED_COLUMNS: &[(&str, &str, &str)] = &[
    ("entries", "path", "TEXT NOT NULL DEFAULT ''"),
    ("entries", "repo", "TEXT NOT NULL DEFAULT ''"),
    ("entries", "commit_hash", "TEXT NOT NULL DEFAULT ''"),
    ("entries", "branch", "TEXT NOT NULL DEFAULT ''"),
    ("entries", "dirty", "INTEGER NOT NULL DEFAULT 0"),
    ("entries", "session_id", "TEXT"),
    ("activity", "session_id", "TEXT"),
    ("sessions", "implicit", "INTEGER NOT NULL DEFAULT 0"),
    // The mailbox's server and login, in clear: they are sealed into the
    // stored password as associated data. Empty for the HTTP services.
    ("vault", "host", "TEXT NOT NULL DEFAULT ''"),
    ("vault", "port", "INTEGER NOT NULL DEFAULT 0"),
    ("vault", "account", "TEXT NOT NULL DEFAULT ''"),
    // The task runner (schema 5): where a task's work goes, and what the
    // runner did with it. `repo` empty means "the latest repository lore
    // recorded for the project".
    ("tasks", "repo", "TEXT NOT NULL DEFAULT ''"),
    ("tasks", "dokploy_project_id", "TEXT NOT NULL DEFAULT ''"),
    ("tasks", "cloudflare_zone", "TEXT NOT NULL DEFAULT ''"),
    ("tasks", "auto_attempts", "INTEGER NOT NULL DEFAULT 0"),
    // When the runner last took or skipped the task: it waits until the
    // task is touched again (`updated_at` moves past this).
    ("tasks", "auto_last_at", "TEXT"),
    ("agent_runs", "model", "TEXT NOT NULL DEFAULT ''"),
    ("agent_runs", "task_title", "TEXT NOT NULL DEFAULT ''"),
    ("agent_runs", "pushed", "INTEGER NOT NULL DEFAULT 0"),
    ("agent_runs", "work_free_bytes", "INTEGER"),
    ("agent_runs", "cli_session", "TEXT NOT NULL DEFAULT ''"),
    ("agent_runs", "output_lines", "INTEGER NOT NULL DEFAULT 0"),
    // Help for other agents (schema 6): who asked for a run (`delegate`,
    // `ask`), and the conversation a chat run belongs to.
    ("agent_runs", "requested_by", "TEXT NOT NULL DEFAULT ''"),
    ("agent_runs", "conversation", "TEXT NOT NULL DEFAULT ''"),
    // Run hardening (schema 7): the verified identity that added a task,
    // the touches that re-queue it (by a signed-in user or its author) and
    // the touch count the runner last saw; the token agent of a session;
    // the owner's per-agent "may read other services during runs"; the
    // bytes of a run's stored output.
    ("tasks", "author", "TEXT NOT NULL DEFAULT ''"),
    ("tasks", "touches", "INTEGER NOT NULL DEFAULT 0"),
    ("tasks", "auto_seen", "INTEGER"),
    ("sessions", "token_agent", "TEXT NOT NULL DEFAULT ''"),
    (
        "builtin_agents",
        "read_other_services",
        "INTEGER NOT NULL DEFAULT 0",
    ),
    ("agent_runs", "output_bytes", "INTEGER NOT NULL DEFAULT 0"),
    // Run confirmation (schema 8): the default branch's head lore read
    // itself before the run started.
    ("agent_runs", "base_head", "TEXT NOT NULL DEFAULT ''"),
    // Display names (schema 9): what the page shows for an agent, which
    // the owner may change; NULL shows the technical name, which stays the
    // agent's identity everywhere.
    ("agent_registry", "display_name", "TEXT"),
    // Built-in agents (schema 9): what a terminal's CLI may do with the
    // services (NULL: what the agent may; `read`; `off`), and which Claude
    // credential comes first (NULL: the subscription; `api_key`) and
    // whether to fall back to the other (NULL or 0: no). The last two are
    // no longer read (Claude Code is signed in with the subscription only)
    // but stay: columns are never dropped.
    ("builtin_agents", "terminal_services", "TEXT"),
    ("builtin_agents", "claude_priority", "TEXT"),
    ("builtin_agents", "claude_fallback", "INTEGER"),
    // Tasks (schema 9): manual, never assigned to a built-in agent by lore
    // itself (NULL or 0: automatic, as before).
    ("tasks", "manual", "INTEGER"),
    // Who set it (schema 9): `user:<name>` or `agent:<name>`.
    ("tasks", "manual_by", "TEXT"),
    // The task's created_at a note was written for (schema 9).
    ("task_notes", "task_created", "TEXT NOT NULL DEFAULT ''"),
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
    /// Old names of this project (aliases left by renames).
    pub aliases: Vec<String>,
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
    /// True when lore opened the session itself, for a client whose tool
    /// list predates sessions and so never called `hello`.
    #[serde(default)]
    pub implicit: bool,
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
            implicit: row.get(13)?,
            updates: row.get(14)?,
        })
    }
}

/// A session as `hello` opens it; the id and the times are assigned here.
#[derive(Debug, Default, Clone)]
pub struct NewSession {
    pub agent: String,
    pub project: String,
    pub path: String,
    pub repo: String,
    pub commit: String,
    pub branch: String,
    pub title: String,
    /// True when lore opens the session itself for a client whose tool
    /// list predates sessions.
    pub implicit: bool,
}

/// What `Db::implicit_session` found or did.
#[derive(Debug)]
pub enum Implicit {
    /// The agent's open implicit session, reused.
    Reused(Session),
    /// A new implicit session, opened by this call.
    Opened(Session),
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

/// One task on the shared to-do list of a project.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Task {
    pub id: i64,
    pub project: String,
    pub title: String,
    #[serde(default)]
    pub body: String,
    /// One of: open, claimed, done, cancelled.
    pub status: String,
    /// The agent the task is meant for; empty for anyone.
    #[serde(default)]
    pub assignee: String,
    /// The agent that added it, or "admin".
    pub created_by: String,
    #[serde(default)]
    pub claimed_by: String,
    #[serde(default)]
    pub done_by: String,
    /// The commit the work was finished at, when there was one.
    #[serde(default)]
    pub done_commit: String,
    /// The latest status note.
    #[serde(default)]
    pub note: String,
    /// The session that created it, when there was one.
    #[serde(default)]
    pub session_id: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    /// Set when the task was marked done.
    #[serde(default)]
    pub done_at: Option<String>,
    /// The repository the work goes to (`github.com/<owner>/<repo>`);
    /// empty for the latest one lore recorded for the project.
    #[serde(default)]
    pub repo: String,
    /// A Dokploy project the work may change; empty for read-only.
    #[serde(default)]
    pub dokploy_project_id: String,
    /// A Cloudflare zone id the work may change; empty for read-only.
    #[serde(default)]
    pub cloudflare_zone: String,
    /// Manual (schema 9): lore never assigns it to a built-in agent by
    /// itself (the idle rule skips it); anything else is as for any task.
    #[serde(default)]
    pub manual: bool,
    /// Who made it manual (schema 9): `user:<name>` or `agent:<name>`;
    /// empty when it is not manual or nobody was recorded.
    #[serde(default)]
    pub manual_by: String,
}

impl Task {
    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get(0)?,
            project: row.get(1)?,
            title: row.get(2)?,
            body: row.get(3)?,
            status: row.get(4)?,
            assignee: row.get(5)?,
            created_by: row.get(6)?,
            claimed_by: row.get(7)?,
            done_by: row.get(8)?,
            done_commit: row.get(9)?,
            note: row.get(10)?,
            session_id: row.get(11)?,
            created_at: row.get(12)?,
            updated_at: row.get(13)?,
            done_at: row.get(14)?,
            repo: row.get(15)?,
            dokploy_project_id: row.get(16)?,
            cloudflare_zone: row.get(17)?,
            manual: row.get::<_, Option<bool>>(18)?.unwrap_or(false),
            manual_by: row.get::<_, Option<String>>(19)?.unwrap_or_default(),
        })
    }
}

/// A note the owner (a signed-in user) left on a task.
#[derive(Debug, Clone, serde::Serialize)]
pub struct TaskNote {
    pub id: i64,
    pub task_id: i64,
    /// The user name.
    pub author: String,
    pub body: String,
    pub created_at: String,
}

impl TaskNote {
    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get(0)?,
            task_id: row.get(1)?,
            author: row.get(2)?,
            body: row.get(3)?,
            created_at: row.get(4)?,
        })
    }
}

/// A task as it is created; the id and the times are assigned here.
#[derive(Debug, Default)]
pub struct NewTask {
    pub project: String,
    pub title: String,
    pub body: String,
    /// The agent the task is meant for; empty for anyone.
    pub assignee: String,
    /// The agent that adds it, or "admin".
    pub created_by: String,
    /// The chat session it was added in, when there is one.
    pub session_id: Option<String>,
    /// Where the work goes and what it may change (see `Task`); checked
    /// by `normalize_task_targets`.
    pub targets: TaskTargets,
    /// Manual: never assigned to a built-in agent by lore itself.
    pub manual: bool,
    /// Who made it manual (`user:<name>` or `agent:<name>`).
    pub manual_by: String,
}

/// The optional fields that say where a task's work goes: the repository,
/// and the Dokploy project and Cloudflare zone a built-in agent may change
/// for it. Empty is "not set".
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TaskTargets {
    pub repo: String,
    pub dokploy_project_id: String,
    pub cloudflare_zone: String,
}

/// Longest value of a task target field.
const TARGET_MAX_CHARS: usize = 200;

/// Checks the target fields: a repository is a `github.com/<owner>/<repo>`
/// address (any of the forms `parse_github_repo` reads, kept as given);
/// a Dokploy project id and a Cloudflare zone id are plain ids.
pub fn normalize_task_targets(targets: &TaskTargets) -> Result<TaskTargets> {
    let repo = targets.repo.trim().to_string();
    if !repo.is_empty() && parse_github_repo(&repo).is_none() {
        anyhow::bail!(
            "repo must be a GitHub repository such as github.com/owner/name or \
             https://github.com/owner/name.git"
        );
    }
    let plain_id = |name: &str, value: &str| -> Result<String> {
        let value = value.trim();
        if value.chars().count() > TARGET_MAX_CHARS
            || !value
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        {
            anyhow::bail!("{name} must be a plain id (letters, digits, `-`, `_`, `.`)");
        }
        Ok(value.to_string())
    };
    Ok(TaskTargets {
        repo,
        dokploy_project_id: plain_id("dokploy_project_id", &targets.dokploy_project_id)?,
        cloudflare_zone: plain_id("cloudflare_zone", &targets.cloudflare_zone)?,
    })
}

/// The GitHub address of a repository named by lore's own git proxy
/// (`http(s)://<lore host>/git/github/<o>/<r>(.git)`, or `github-org`):
/// what a built-in agent's checkout reports when git expands its remote.
/// `https://github.com/<o>/<r>`, or `None` for anything else.
pub fn lore_proxy_repo(address: &str) -> Option<String> {
    let address = address.trim();
    let rest = address
        .strip_prefix("https://")
        .or_else(|| address.strip_prefix("http://"))?;
    let (_host, path) = rest.split_once('/')?;
    let mut parts = path.trim_end_matches('/').split('/');
    if parts.next()? != "git" || !matches!(parts.next()?, "github" | "github-org") {
        return None;
    }
    let (owner, repo) = (parts.next()?, parts.next()?);
    if parts.next().is_some() {
        return None;
    }
    let repo = repo.strip_suffix(".git").unwrap_or(repo);
    let github = format!("https://github.com/{owner}/{repo}");
    // Only what the plain GitHub form accepts.
    parse_github_repo(&github).map(|_| github)
}

/// `(owner, repo)` of a GitHub repository address: `github.com/o/r`,
/// `https://github.com/o/r(.git)`, `git@github.com:o/r(.git)` or
/// `ssh://git@github.com/o/r(.git)`. Anything else, another host
/// included, is `None`.
pub fn parse_github_repo(address: &str) -> Option<(String, String)> {
    if let Some(github) = lore_proxy_repo(address) {
        return parse_github_repo(&github);
    }
    let address = address.trim();
    let rest = address
        .strip_prefix("https://")
        .or_else(|| address.strip_prefix("http://"))
        .or_else(|| address.strip_prefix("ssh://git@"))
        .or_else(|| address.strip_prefix("git@"))
        .unwrap_or(address);
    let rest = rest
        .strip_prefix("www.")
        .unwrap_or(rest)
        .strip_prefix("github.com")?;
    let rest = rest.strip_prefix('/').or_else(|| rest.strip_prefix(':'))?;
    let rest = rest.trim_end_matches('/');
    let rest = rest.strip_suffix(".git").unwrap_or(rest);
    let (owner, repo) = rest.split_once('/')?;
    let plain = |part: &str| {
        !part.is_empty()
            && part.len() <= 100
            && part != "."
            && part != ".."
            && part
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    };
    (plain(owner) && plain(repo)).then(|| (owner.to_string(), repo.to_string()))
}

/// One message between agents, or one handoff note for a project.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Message {
    pub id: i64,
    /// One of: message, handoff.
    pub kind: String,
    /// Required for a handoff; optional for a message.
    #[serde(default)]
    pub project: String,
    /// The agent that wrote it, or "admin".
    pub from_agent: String,
    /// Empty for a message to everyone; always empty for a handoff.
    #[serde(default)]
    pub to_agent: String,
    pub body: String,
    /// The session that wrote it, when there was one.
    #[serde(default)]
    pub session_id: Option<String>,
    pub created_at: String,
    /// Handoff only: the agent that received it.
    #[serde(default)]
    pub delivered_to: String,
    /// Handoff only: the session that received it.
    #[serde(default)]
    pub delivered_session: Option<String>,
    /// Handoff only: when it was delivered.
    #[serde(default)]
    pub delivered_at: Option<String>,
}

impl Message {
    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get(0)?,
            kind: row.get(1)?,
            project: row.get(2)?,
            from_agent: row.get(3)?,
            to_agent: row.get(4)?,
            body: row.get(5)?,
            session_id: row.get(6)?,
            created_at: row.get(7)?,
            delivered_to: row.get(8)?,
            delivered_session: row.get(9)?,
            delivered_at: row.get(10)?,
        })
    }
}

/// A message as it is written; the id and the time are assigned here.
#[derive(Debug, Default)]
pub struct NewMessage {
    /// One of: message, handoff.
    pub kind: String,
    pub project: String,
    pub from_agent: String,
    /// Empty for a message to everyone; always empty for a handoff.
    pub to_agent: String,
    pub body: String,
    /// The chat session it was written in, when there is one.
    pub session_id: Option<String>,
}

/// Who has read one message.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MessageRead {
    pub message_id: i64,
    pub agent: String,
    pub read_at: String,
}

/// A message as the admin board draws it: the row and its readers.
#[derive(Debug, serde::Serialize)]
pub struct BoardMessage {
    #[serde(flatten)]
    pub message: Message,
    /// The agents that have read it; empty for a handoff.
    pub read_by: Vec<String>,
}

/// The board totals the admin stats show.
#[derive(Debug, serde::Serialize)]
pub struct BoardCounts {
    pub open_tasks: i64,
    pub claimed_tasks: i64,
}

/// One version of a file kept for a project, without its content.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FileInfo {
    pub id: i64,
    pub project: String,
    /// Name or relative path, with forward slashes, e.g. `docs/ideas.md`.
    pub path: String,
    /// 1, 2, 3 … per project and path.
    pub version: i64,
    /// One of: idea, doc, data, config, other.
    pub kind: String,
    /// Why the file matters to the project.
    pub description: String,
    /// How agents exchange it: utf8 or base64.
    pub encoding: String,
    /// Raw size in bytes.
    pub size: i64,
    /// Hex SHA-256 of the raw bytes.
    pub sha256: String,
    /// The memory entry the file belongs to, when it was given one.
    #[serde(default)]
    pub entry_id: Option<i64>,
    /// The agent that saved this version, or "admin".
    pub agent: String,
    /// The session it was saved in, when there was one.
    #[serde(default)]
    pub session_id: Option<String>,
    pub created_at: String,
}

impl FileInfo {
    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get(0)?,
            project: row.get(1)?,
            path: row.get(2)?,
            version: row.get(3)?,
            kind: row.get(4)?,
            description: row.get(5)?,
            encoding: row.get(6)?,
            size: row.get(7)?,
            sha256: row.get(8)?,
            entry_id: row.get(9)?,
            agent: row.get(10)?,
            session_id: row.get(11)?,
            created_at: row.get(12)?,
        })
    }

    /// The text that gets embedded for semantic search.
    pub fn embedding_text(&self) -> String {
        format!("{} {} {}", self.path, self.kind, self.description)
    }
}

/// One version of a file with its raw bytes.
#[derive(Debug, Clone)]
pub struct StoredFile {
    pub info: FileInfo,
    pub content: Vec<u8>,
}

/// A file as an agent or the admin saves it; the version, the size, the
/// hash and the time are worked out here.
#[derive(Debug, Default)]
pub struct NewFile {
    pub project: String,
    pub path: String,
    /// One of `FILE_KINDS`; empty keeps the kind of the latest version,
    /// or means "other" for a new path.
    pub kind: String,
    pub description: String,
    /// One of `FILE_ENCODINGS`; empty means "utf8".
    pub encoding: String,
    /// The text itself, or the base64 of the raw bytes.
    pub content: String,
    pub entry_id: Option<i64>,
    /// The agent that saves it, or "admin".
    pub agent: String,
    pub session_id: Option<String>,
}

/// What `save_file` did.
#[derive(Debug)]
pub struct SavedFile {
    pub file: FileInfo,
    /// True when the content matched the latest version, so no new version
    /// was made.
    pub unchanged: bool,
    /// True when a new row was written, or the kind or the description of
    /// the latest one changed, so its vector needs computing.
    pub needs_embedding: bool,
}

/// A file found by `search_files`.
#[derive(Debug)]
pub struct FileHit {
    pub file: FileInfo,
    /// How the file was found: "text", "semantic" or "text+semantic".
    pub matched: &'static str,
    /// Cosine similarity to the query, when a vector was given.
    pub similarity: Option<f32>,
}

/// The file totals the admin page shows.
#[derive(Debug, serde::Serialize)]
pub struct FileCounts {
    /// Distinct project and path pairs.
    pub files: i64,
    /// Every stored version.
    pub versions: i64,
    /// Raw bytes over every version.
    pub bytes: i64,
}

/// A stored credential, exactly as the store keeps it: encrypted, with its
/// nonce beside it. Only the vault key ever reads the secret field, on
/// its way to one call.
#[derive(Debug, Clone)]
pub struct StoredVault {
    pub provider: String,
    /// The admin-entered server URL; gitlab and dokploy only.
    pub base_url: String,
    /// An XChaCha20-Poly1305 nonce, 24 random bytes per write.
    pub nonce: Vec<u8>,
    /// The credential, encrypted with the provider id as associated data.
    pub secret: Vec<u8>,
    pub hint: String,
    pub updated_at: String,
}

/// One provider's credential as the admin page shows it: never the nonce
/// and never the secret.
#[derive(Debug, serde::Serialize)]
pub struct VaultStatus {
    pub provider: String,
    /// True when a credential is stored.
    pub configured: bool,
    /// The admin-entered server URL, gitlab and dokploy only.
    pub base_url: String,
    /// The last four characters of the credential.
    pub hint: String,
    pub updated_at: String,
}

/// The stored mailbox: where it is and whose it is, in clear, and the
/// password, encrypted with all three as associated data. `Debug` leaves
/// the ciphertext and the nonce out.
#[derive(Clone)]
pub struct StoredMail {
    pub host: String,
    pub port: u16,
    pub account: String,
    pub nonce: Vec<u8>,
    pub secret: Vec<u8>,
    pub updated_at: String,
}

impl std::fmt::Debug for StoredMail {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StoredMail")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("account", &self.account)
            .field("secret", &"[redacted]")
            .finish()
    }
}

/// The leak scan switches (see `Db::leak_scan_settings`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeakScanSettings {
    /// Scan writes to public GitHub repositories (default on).
    pub scan: bool,
    /// Agents may create public repositories or make one public (default
    /// off).
    pub allow_public: bool,
}

/// One agent's permission on one provider: off, read or full.
#[derive(Debug, serde::Serialize)]
pub struct OpsPermission {
    pub agent: String,
    pub provider: String,
    pub level: String,
}

/// One provider call in the operations log: who called what, and how it
/// went. Never a query string, a body or a credential.
#[derive(Debug, serde::Serialize)]
pub struct OpLog {
    pub id: i64,
    /// An agent name, or "admin" for a test call from the admin page.
    pub agent: String,
    pub session_id: Option<String>,
    pub provider: String,
    pub method: String,
    pub path: String,
    /// The upstream HTTP status; 0 when there was no response.
    pub status: i64,
    /// One of: ok, denied, error.
    pub outcome: String,
    /// A short reason for a denied or failed call.
    pub detail: String,
    pub duration_ms: i64,
    pub created_at: String,
}

/// One file version as a backup carries it.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BackupFile {
    #[serde(flatten)]
    pub info: FileInfo,
    /// The raw bytes, base64 encoded.
    pub content: String,
    /// Its vector: little-endian f32 values, base64 encoded. Only reused
    /// when the backup's `embedding_model` matches the one in use.
    #[serde(default)]
    pub embedding: Option<String>,
}

/// Everything in the store: entries, their embedding vectors, the activity
/// log and the agent records. Restoring it reproduces the store exactly.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
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
    /// The shared to-do list.
    #[serde(default)]
    pub tasks: Vec<Task>,
    /// The messages and handoff notes.
    #[serde(default)]
    pub messages: Vec<Message>,
    /// Who has read which message.
    #[serde(default)]
    pub message_reads: Vec<MessageRead>,
    /// Every version of every file kept for a project.
    #[serde(default)]
    pub files: Vec<BackupFile>,
    /// The task runner's fields of the tasks (author, re-queue touches,
    /// automatic attempts), by task id.
    #[serde(default)]
    pub task_runner: Vec<builtin::TaskRunnerState>,
    /// Tasks handed to a built-in agent with `delegate`.
    #[serde(default)]
    pub delegations: Vec<builtin::Delegation>,
    /// Old project names and the project each now stands for (renames).
    /// A restore replaces the aliases with these (none when a backup has
    /// none: its rows are under the names it had); a merge leaves the
    /// aliases here as they are and files incoming rows under them.
    #[serde(default)]
    pub project_aliases: std::collections::BTreeMap<String, String>,
    /// The old names among `project_aliases` that came from a merge (no
    /// undo).
    #[serde(default)]
    pub project_alias_merges: Vec<String>,
}

/// The backup version this build writes.
const BACKUP_VERSION: u32 = 5;

/// Backup versions this build can read. Version 1 had no embeddings; version
/// 2 had no sessions, profile or rules; version 3 had no board; version 4
/// had no files.
const BACKUP_VERSIONS: std::ops::RangeInclusive<u32> = 1..=BACKUP_VERSION;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
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
    /// The avatar id the page shows for the agent.
    pub avatar: String,
    /// The name the page shows, when the owner gave one.
    pub display_name: Option<String>,
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
    /// The database file; its directory holds the temporary files and the
    /// safety copies of the full backup and restore.
    path: Arc<PathBuf>,
    /// Tests only: makes `load_full_backup` fail right after the pages
    /// were replaced.
    #[cfg(test)]
    pub fail_after_load: Arc<std::sync::atomic::AtomicBool>,
}

/// A stored user as the admin view lists it: no password hash.
#[derive(Debug, Clone, serde::Serialize)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub email: Option<String>,
    pub permissions: Vec<String>,
    pub disabled: bool,
    pub created_at: String,
    pub updated_at: String,
    pub last_login_at: Option<String>,
    pub created_by: String,
}

impl User {
    pub fn perms(&self) -> Perms {
        Perms::parse(&self.permissions).unwrap_or_default()
    }
}

/// A stored user with the hash a sign-in is checked against.
pub struct UserLogin {
    pub user: User,
    pub password_hash: String,
}

impl std::fmt::Debug for UserLogin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UserLogin")
            .field("user", &self.user)
            .field("password_hash", &"[redacted]")
            .finish()
    }
}

/// A user to add. Every field is already validated.
pub struct NewUser {
    pub username: String,
    pub email: Option<String>,
    pub password_hash: String,
    pub permissions: Perms,
    pub created_by: String,
}

impl std::fmt::Debug for NewUser {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewUser")
            .field("username", &self.username)
            .field("email", &self.email)
            .field("password_hash", &"[redacted]")
            .field("permissions", &self.permissions)
            .finish()
    }
}

/// A change to a user; `None` leaves the field as it is.
#[derive(Default)]
pub struct UserPatch {
    /// `Some(None)` removes the address.
    pub email: Option<Option<String>>,
    pub permissions: Option<Perms>,
    pub disabled: Option<bool>,
    pub password_hash: Option<String>,
}

impl std::fmt::Debug for UserPatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UserPatch")
            .field("email", &self.email)
            .field("permissions", &self.permissions)
            .field("disabled", &self.disabled)
            .field(
                "password_hash",
                &self.password_hash.as_ref().map(|_| "[redacted]"),
            )
            .finish()
    }
}

const USER_COLUMNS: &str = "id, username, email, permissions, disabled, created_at, updated_at, \
                            last_login_at, created_by";

impl User {
    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        let permissions: String = row.get(3)?;
        Ok(Self {
            id: row.get(0)?,
            username: row.get(1)?,
            email: row.get(2)?,
            permissions: Perms::from_json(&permissions)
                .ids()
                .into_iter()
                .map(String::from)
                .collect(),
            disabled: row.get(4)?,
            created_at: row.get(5)?,
            updated_at: row.get(6)?,
            last_login_at: row.get(7)?,
            created_by: row.get(8)?,
        })
    }
}

/// Why a full database restore was refused: the check that failed, and a
/// sentence for the page. Nothing was changed when this is returned.
#[derive(Debug)]
pub struct Refusal {
    pub check: &'static str,
    pub message: String,
}

impl Refusal {
    fn new(check: &'static str, message: impl Into<String>) -> Self {
        Self {
            check,
            message: message.into(),
        }
    }
}

/// Why loading a full backup failed, and whether the live database had
/// already been replaced when it did.
#[derive(Debug)]
pub enum LoadError {
    /// Nothing was changed.
    Unchanged(anyhow::Error),
    /// The backup's pages replaced the live database, then a later step
    /// (the migration, the counts) failed.
    Replaced(anyhow::Error),
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
        migrate(&conn)?;
        let db = Self {
            conn: Arc::new(Mutex::new(conn)),
            path: Arc::new(path.to_path_buf()),
            #[cfg(test)]
            fail_after_load: Arc::default(),
        };
        db.remove_stale_temp_files();
        Ok(db)
    }

    /// The directory the database file lives in.
    pub fn data_dir(&self) -> PathBuf {
        self.path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."))
    }

    /// A fresh path for a temporary database file next to the database.
    pub fn temp_path(&self, label: &str) -> Result<PathBuf> {
        self.temp_path_with(label, "sqlite")
    }

    /// A fresh path for a temporary file with this extension next to the
    /// database; whatever an interrupted run leaves there is removed at
    /// the next start.
    pub fn temp_path_with(&self, label: &str, extension: &str) -> Result<PathBuf> {
        let mut bytes = [0u8; 8];
        getrandom::fill(&mut bytes).map_err(|error| anyhow::anyhow!("no randomness: {error}"))?;
        let random: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        Ok(self
            .data_dir()
            .join(format!("{TEMP_PREFIX}{label}-{random}.{extension}")))
    }

    /// Removes what an interrupted full backup or restore left behind.
    fn remove_stale_temp_files(&self) {
        let Ok(dir) = std::fs::read_dir(self.data_dir()) else {
            return;
        };
        for item in dir.flatten() {
            if item.file_name().to_string_lossy().starts_with(TEMP_PREFIX) {
                let _ = std::fs::remove_file(item.path());
            }
        }
    }

    /// The periodic sweep (every ten minutes): removes lore's own
    /// temporary files ([`is_temp_name`]: spooled pushes, full backups and
    /// restores, safety copies being written, and their SQLite journals)
    /// older than [`TEMP_MAX_AGE`], and keeps only the newest three safety
    /// copies. A file a live operation still has open loses only its name
    /// (Linux keeps it readable until it is closed); none lives that long.
    /// Nothing else in the data directory can match: not the database, its
    /// `-wal`/`-shm`, a backup the owner asked for, or a stored file.
    /// Answers how many files went.
    pub fn sweep_leftovers(&self) -> usize {
        let dir = self.data_dir();
        let removed = sweep_temp_files(&dir, TEMP_MAX_AGE);
        if let Err(error) = prune_snapshots(&dir, SNAPSHOTS_KEPT) {
            tracing::warn!(%error, "old safety copies could not be removed");
        }
        if removed > 0 {
            tracing::info!(removed, "removed leftover temporary files");
        }
        removed
    }

    /// Copies the whole database, consistently, to `dest` with the SQLite
    /// online backup API. The connection is held only while the pages are
    /// copied. The copy uses a rollback journal, so it is one
    /// self-contained file.
    pub fn snapshot_to(&self, dest: &Path) -> Result<()> {
        let mut out = Connection::open(dest)
            .with_context(|| format!("creating the snapshot {}", dest.display()))?;
        {
            let conn = self.lock();
            let backup = rusqlite::backup::Backup::new(&conn, &mut out)?;
            run_backup(&backup)?;
        }
        out.pragma_update(None, "journal_mode", "DELETE")?;
        Ok(())
    }

    /// Writes a safety copy of the database as
    /// `pre-restore-YYYYMMDD-HHMMSS.sqlite` in the data directory and keeps
    /// only the newest three. Returns the file name.
    pub fn write_safety_snapshot(&self) -> Result<String> {
        let dir = self.data_dir();
        let stamp = utc_stamp();
        let mut name = format!("{SNAPSHOT_PREFIX}{stamp}.sqlite");
        let mut counter = 1;
        while dir.join(&name).exists() {
            counter += 1;
            name = format!("{SNAPSHOT_PREFIX}{stamp}-{counter}.sqlite");
        }
        // Written under a temporary name first, so a half-written copy is
        // never mistaken for a safety copy.
        let temp = self.temp_path("snapshot")?;
        let written = self
            .snapshot_to(&temp)
            .and_then(|()| Ok(std::fs::rename(&temp, dir.join(&name))?));
        if let Err(error) = written {
            remove_database_files(&temp);
            return Err(error);
        }
        prune_snapshots(&dir, SNAPSHOTS_KEPT)?;
        Ok(name)
    }

    /// Replaces the live database with a prepared full backup through the
    /// SQLite online backup API, all or nothing, then runs the start-up
    /// migration and returns the row count of every table. The error says
    /// whether the live pages were already replaced when it happened.
    pub fn load_full_backup(
        &self,
        source: &Path,
    ) -> std::result::Result<Vec<(String, i64)>, LoadError> {
        let src = Connection::open_with_flags(
            source,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .and_then(|conn| harden(&conn).map(|()| conn))
        .map_err(|error| LoadError::Unchanged(error.into()))?;
        let mut conn = self.lock();
        {
            let backup = rusqlite::backup::Backup::new(&src, &mut conn)
                .map_err(|error| LoadError::Unchanged(error.into()))?;
            run_backup(&backup).map_err(LoadError::Unchanged)?;
        }
        #[cfg(test)]
        if self
            .fail_after_load
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err(LoadError::Replaced(anyhow::anyhow!(
                "a failure injected by a test"
            )));
        }
        migrate(&conn).map_err(LoadError::Replaced)?;
        table_counts(&conn).map_err(LoadError::Replaced)
    }

    /// The row count of every table, by name.
    #[cfg(test)]
    pub fn table_counts(&self) -> Result<Vec<(String, i64)>> {
        table_counts(&self.lock())
    }

    /// Every stored user, by name.
    pub fn users(&self) -> Result<Vec<User>> {
        let conn = self.lock();
        let sql = format!("SELECT {USER_COLUMNS} FROM users ORDER BY username");
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map([], User::from_row)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn user(&self, id: i64) -> Result<Option<User>> {
        get_user(&self.lock(), id)
    }

    /// The user a sign-in names, by user name or, when it holds an `@`, by
    /// e-mail address, with the hash to check the password against.
    pub fn user_login(&self, name: &str) -> Result<Option<UserLogin>> {
        let name = name.trim().to_lowercase();
        let column = if name.contains('@') {
            "email"
        } else {
            "username"
        };
        let sql = format!("SELECT {USER_COLUMNS}, password_hash FROM users WHERE {column} = ?1");
        Ok(self
            .lock()
            .query_row(&sql, params![name], |row| {
                Ok(UserLogin {
                    user: User::from_row(row)?,
                    password_hash: row.get(9)?,
                })
            })
            .optional()?)
    }

    /// The stored hash of one user, to check their current password.
    pub fn user_password_hash(&self, id: i64) -> Result<Option<String>> {
        Ok(self
            .lock()
            .query_row(
                "SELECT password_hash FROM users WHERE id = ?1",
                params![id],
                |row| row.get(0),
            )
            .optional()?)
    }

    pub fn add_user(&self, new: &NewUser) -> Result<User> {
        let conn = self.lock();
        refuse_taken(&conn, None, Some(&new.username), new.email.as_deref())?;
        conn.execute(
            "INSERT INTO users (username, email, password_hash, permissions, disabled,
                                created_at, updated_at, created_by)
             VALUES (?1, ?2, ?3, ?4, 0, strftime('%Y-%m-%dT%H:%M:%SZ', 'now'),
                     strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), ?5)",
            params![
                new.username,
                new.email,
                new.password_hash,
                new.permissions.to_json(),
                new.created_by
            ],
        )?;
        let id = conn.last_insert_rowid();
        get_user(&conn, id)?.context("user vanished after insert")
    }

    /// Applies a change to one user. `None` when there is no such user.
    pub fn update_user(&self, id: i64, patch: &UserPatch) -> Result<Option<User>> {
        let conn = self.lock();
        if get_user(&conn, id)?.is_none() {
            return Ok(None);
        }
        if let Some(Some(email)) = &patch.email {
            refuse_taken(&conn, Some(id), None, Some(email))?;
        }
        conn.execute(
            "UPDATE users SET
                email = CASE WHEN ?2 THEN ?3 ELSE email END,
                permissions = COALESCE(?4, permissions),
                disabled = COALESCE(?5, disabled),
                password_hash = COALESCE(?6, password_hash),
                updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
             WHERE id = ?1",
            params![
                id,
                patch.email.is_some(),
                patch.email.clone().flatten(),
                patch.permissions.map(Perms::to_json),
                patch.disabled,
                patch.password_hash
            ],
        )?;
        get_user(&conn, id)
    }

    /// Removes one user; returns it, or `None` when there was none.
    pub fn delete_user(&self, id: i64) -> Result<Option<User>> {
        let conn = self.lock();
        let Some(user) = get_user(&conn, id)? else {
            return Ok(None);
        };
        conn.execute("DELETE FROM users WHERE id = ?1", params![id])?;
        Ok(Some(user))
    }

    /// Notes a successful sign-in.
    pub fn touch_user_login(&self, id: i64) -> Result<()> {
        self.lock().execute(
            "UPDATE users SET last_login_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now') WHERE id = ?1",
            params![id],
        )?;
        Ok(())
    }

    /// Runs raw SQL, for tests that need to break the database on purpose.
    #[cfg(test)]
    pub(crate) fn execute_for_test(&self, sql: &str) {
        self.lock().execute_batch(sql).unwrap();
    }

    /// Moves everything in the write-ahead log into the database file and
    /// empties the log, what a clean close does, for a process that is
    /// about to exit; without ever waiting long. The connection is waited
    /// for at most `patience` (a backup download or a restore holds it for
    /// a whole copy), and the checkpoint itself never waits on another
    /// process's lock: when a reader is in the way it copies what it can
    /// (`PASSIVE`) and says so. Either way the log is crash-safe: what is
    /// not checkpointed now is replayed at the next start.
    pub fn checkpoint_within(&self, patience: std::time::Duration) -> Result<()> {
        let deadline = std::time::Instant::now() + patience;
        let conn = loop {
            match self.conn.try_lock() {
                Ok(conn) => break conn,
                Err(std::sync::TryLockError::Poisoned(poisoned)) => break poisoned.into_inner(),
                Err(std::sync::TryLockError::WouldBlock) => {
                    if std::time::Instant::now() >= deadline {
                        anyhow::bail!(
                            "the database connection stayed busy (a backup or a restore in \
                             progress?); not checkpointed"
                        );
                    }
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
            }
        };
        conn.busy_timeout(std::time::Duration::ZERO)?;
        let attempt = (|| -> Result<()> {
            let busy: i64 =
                conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| row.get(0))?;
            if busy == 0 {
                return Ok(());
            }
            let (_, log, done): (i64, i64, i64) =
                conn.query_row("PRAGMA wal_checkpoint(PASSIVE)", [], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?))
                })?;
            anyhow::bail!(
                "another process is reading the database; {done} of {log} log pages were \
                 checkpointed"
            )
        })();
        conn.busy_timeout(std::time::Duration::from_millis(5000))?;
        attempt
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn insert(&self, new: &NewEntry) -> Result<Entry> {
        let conn = self.lock();
        // A renamed project's old name lands on the new one.
        let project = rename::resolve_alias(&conn, &new.project)?;
        conn.execute(
            "INSERT INTO entries (project, kind, title, body, tags, files, agent,
                                  path, repo, commit_hash, branch, dirty, session_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                project,
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
        let mut aliases: HashMap<String, Vec<String>> = HashMap::new();
        for (old, project) in rename::all_aliases(&conn)? {
            aliases.entry(project).or_default().push(old);
        }
        let mut projects = Vec::new();
        for row in rows {
            let (project, entries, last_activity) = row?;
            projects.push(ProjectSummary {
                heads: heads.remove(&project).unwrap_or_default(),
                aliases: aliases.remove(&project).unwrap_or_default(),
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
        let tasks = {
            let conn = self.lock();
            let sql = format!("SELECT {TASK_COLUMNS} FROM tasks ORDER BY id");
            let mut stmt = conn.prepare(&sql)?;
            let rows = stmt.query_map([], Task::from_row)?;
            rows.collect::<rusqlite::Result<_>>()?
        };
        // Messages and their read marks are read under one lock: a mark for
        // a message written in between would make the backup fail its own
        // validation on restore.
        let (messages, message_reads) = {
            let conn = self.lock();
            let sql = format!("SELECT {MESSAGE_COLUMNS} FROM messages ORDER BY id");
            let mut stmt = conn.prepare(&sql)?;
            let rows = stmt.query_map([], Message::from_row)?;
            let messages: Vec<Message> = rows.collect::<rusqlite::Result<_>>()?;
            let mut stmt = conn.prepare(
                "SELECT message_id, agent, read_at FROM message_reads ORDER BY message_id, agent",
            )?;
            let rows = stmt.query_map([], |row| {
                Ok(MessageRead {
                    message_id: row.get(0)?,
                    agent: row.get(1)?,
                    read_at: row.get(2)?,
                })
            })?;
            let message_reads: Vec<MessageRead> = rows.collect::<rusqlite::Result<_>>()?;
            (messages, message_reads)
        };
        let files = {
            use base64::Engine;
            let conn = self.lock();
            let sql = format!("SELECT {FILE_COLUMNS}, content, embedding FROM files ORDER BY id");
            let mut stmt = conn.prepare(&sql)?;
            let rows = stmt.query_map([], |row| {
                let content: Vec<u8> = row.get(13)?;
                let embedding: Option<Vec<u8>> = row.get(14)?;
                Ok(BackupFile {
                    info: FileInfo::from_row(row)?,
                    content: base64::engine::general_purpose::STANDARD.encode(content),
                    embedding: embedding
                        .map(|blob| base64::engine::general_purpose::STANDARD.encode(blob)),
                })
            })?;
            rows.collect::<rusqlite::Result<_>>()?
        };
        let task_runner = self.task_runner_states()?;
        let delegations = self.delegations()?;
        let project_aliases = self.project_aliases()?.into_iter().collect();
        let project_alias_merges = self.merged_project_aliases()?;
        Ok(Backup {
            format: BACKUP_FORMAT.to_string(),
            version: BACKUP_VERSION,
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
            tasks,
            messages,
            message_reads,
            files,
            task_runner,
            delegations,
            project_aliases,
            project_alias_merges,
        })
    }

    /// Replaces the whole store with a backup, keeping entry ids. All or
    /// nothing: on any error the previous contents stay in place. A backup
    /// older than version 3 leaves the sessions, the profile and the rules
    /// as they are; one older than version 4 also leaves the tasks, the
    /// messages and the read marks; one older than version 5 also leaves the
    /// files, since it has none to put in their place.
    pub fn restore(&self, backup: &Backup) -> Result<usize> {
        validate_backup(backup)?;
        rename::validate_backup_aliases(backup)?;
        let mut conn = self.lock();
        let tx = conn.transaction()?;
        let reusable = reusable_vectors(&tx, backup)?;
        tx.execute_batch(
            "DELETE FROM entries; DELETE FROM activity; DELETE FROM agents;
             DELETE FROM run_writes WHERE kind = 'entry';
             DELETE FROM sqlite_sequence WHERE name IN ('entries', 'activity');",
        )?;
        // The aliases go with the rows they were made for (checked
        // above).
        rename::delete_all_aliases(&tx)?;
        for (old, project) in &backup.project_aliases {
            let merged = backup.project_alias_merges.contains(old);
            rename::set_alias(&tx, old, project, merged)?;
        }
        // Backups older than version 3 know nothing of sessions, the profile
        // or rules, and ones older than version 4 know nothing of the board.
        // Restoring one must not wipe what was set up since, so those tables
        // are only replaced by a backup that carries them.
        let replaces_sessions = backup.version >= 3;
        if replaces_sessions {
            tx.execute_batch(
                "DELETE FROM sessions; DELETE FROM session_updates;
                 DELETE FROM agent_profiles; DELETE FROM rules;
                 DELETE FROM sqlite_sequence WHERE name IN ('session_updates', 'rules');",
            )?;
        }
        let replaces_board = backup.version >= 4;
        if replaces_board {
            tx.execute_batch(
                "DELETE FROM message_reads; DELETE FROM messages; DELETE FROM tasks;
                 DELETE FROM task_notes;
                 DELETE FROM delegations; DELETE FROM run_writes WHERE kind = 'message';
                 DELETE FROM sqlite_sequence WHERE name IN ('tasks', 'messages', 'task_notes');",
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
                                       title, status, summary, started_at, last_seen_at, ended_at,
                                       implicit)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
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
                    session.ended_at,
                    session.implicit
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
        if !replaces_board {
            tx.commit()?;
            return Ok(backup.entries.len());
        }
        for task in &backup.tasks {
            tx.execute(
                "INSERT INTO tasks (id, project, title, body, status, assignee, created_by,
                                      claimed_by, done_by, done_commit, note, session_id,
                                      created_at, updated_at, done_at, repo,
                                      dokploy_project_id, cloudflare_zone, manual, manual_by)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15,
                         ?16, ?17, ?18, ?19, ?20)",
                params![
                    task.id,
                    task.project,
                    task.title,
                    task.body,
                    task.status,
                    task.assignee,
                    task.created_by,
                    task.claimed_by,
                    task.done_by,
                    task.done_commit,
                    task.note,
                    task.session_id,
                    task.created_at,
                    task.updated_at,
                    task.done_at,
                    task.repo,
                    task.dokploy_project_id,
                    task.cloudflare_zone,
                    task.manual.then_some(true),
                    (task.manual && !task.manual_by.is_empty()).then_some(task.manual_by.as_str())
                ],
            )?;
        }
        // The task runner's fields and the delegations ride along by task
        // id; rows for tasks the backup does not hold are dropped.
        for state in &backup.task_runner {
            tx.execute(
                "UPDATE tasks SET author = ?2, touches = ?3, auto_seen = ?4, auto_attempts = ?5,
                     auto_last_at = ?6
                 WHERE id = ?1",
                params![
                    state.task_id,
                    state.author,
                    state.touches,
                    state.auto_seen,
                    state.auto_attempts,
                    state.auto_last_at
                ],
            )?;
        }
        for delegation in &backup.delegations {
            tx.execute(
                "INSERT OR REPLACE INTO delegations (task_id, agent, requested_by, via, created_at)
                 SELECT ?1, ?2, ?3, ?4, ?5 WHERE EXISTS (SELECT 1 FROM tasks WHERE id = ?1)",
                params![
                    delegation.task_id,
                    delegation.agent,
                    delegation.requested_by,
                    delegation.via,
                    delegation.created_at
                ],
            )?;
        }
        for message in &backup.messages {
            tx.execute(
                "INSERT INTO messages (id, kind, project, from_agent, to_agent, body,
                                         session_id, created_at, delivered_to,
                                         delivered_session, delivered_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    message.id,
                    message.kind,
                    message.project,
                    message.from_agent,
                    message.to_agent,
                    message.body,
                    message.session_id,
                    message.created_at,
                    message.delivered_to,
                    message.delivered_session,
                    message.delivered_at
                ],
            )?;
        }
        for read in &backup.message_reads {
            tx.execute(
                "INSERT OR IGNORE INTO message_reads (message_id, agent, read_at)
                 VALUES (?1, ?2, ?3)",
                params![read.message_id, read.agent, read.read_at],
            )?;
        }
        // Backups older than version 5 know nothing of files, so the files
        // kept here stay as they are.
        if backup.version >= 5 {
            let same_model = same_embedding_model(&tx, backup)?;
            tx.execute_batch(
                "DELETE FROM files; DELETE FROM sqlite_sequence WHERE name = 'files';",
            )?;
            for file in &backup.files {
                let (content, embedding) = decode_backup_file(file, same_model)?;
                insert_backup_file(
                    &tx,
                    Some(file.info.id),
                    &file.info,
                    file.info.version,
                    &content,
                )?;
                if let Some(vector) = embedding {
                    tx.execute(
                        "UPDATE files SET embedding = ?2 WHERE id = ?1",
                        params![file.info.id, vector],
                    )?;
                }
            }
        }
        tx.commit()?;
        Ok(backup.entries.len())
    }

    /// Adds the backup's entries that are not here yet, under new ids.
    /// An entry counts as present when project, title, body and creation time
    /// all match. Returns (added, already present).
    pub fn merge(&self, backup: &Backup) -> Result<(usize, usize)> {
        validate_backup(backup)?;
        // Rows under a renamed project's old name are filed under the new
        // one, and counted as present when they are there already.
        let aliases: HashMap<String, String> = self.project_aliases()?.into_iter().collect();
        let remapped;
        let backup = if aliases.is_empty() {
            backup
        } else {
            remapped = rename::remap_backup(backup, &aliases);
            &remapped
        };
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
                                       title, status, summary, started_at, last_seen_at, ended_at,
                                       implicit)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
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
                    session.ended_at,
                    session.implicit
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
        // The board comes along the same way: a task counts as present when
        // the same writer added the same title at the same time, and a
        // message when the same body arrived from the same agent at the same
        // time. Read marks are carried over to the new message ids.
        for task in &backup.tasks {
            let exists: bool = tx.query_row(
                "SELECT EXISTS (SELECT 1 FROM tasks
                 WHERE project = ?1 AND title = ?2 AND created_by = ?3 AND created_at = ?4)",
                params![task.project, task.title, task.created_by, task.created_at],
                |row| row.get(0),
            )?;
            if exists {
                continue;
            }
            tx.execute(
                "INSERT INTO tasks (project, title, body, status, assignee, created_by,
                                      claimed_by, done_by, done_commit, note, session_id,
                                      created_at, updated_at, done_at, repo,
                                      dokploy_project_id, cloudflare_zone, manual, manual_by)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15,
                         ?16, ?17, ?18, ?19)",
                params![
                    task.project,
                    task.title,
                    task.body,
                    task.status,
                    task.assignee,
                    task.created_by,
                    task.claimed_by,
                    task.done_by,
                    task.done_commit,
                    task.note,
                    task.session_id,
                    task.created_at,
                    task.updated_at,
                    task.done_at,
                    task.repo,
                    task.dokploy_project_id,
                    task.cloudflare_zone,
                    task.manual.then_some(true),
                    (task.manual && !task.manual_by.is_empty()).then_some(task.manual_by.as_str())
                ],
            )?;
        }
        let mut arrived_messages: HashMap<i64, i64> = HashMap::new();
        for message in &backup.messages {
            let exists: bool = tx.query_row(
                "SELECT EXISTS (SELECT 1 FROM messages
                 WHERE kind = ?1 AND from_agent = ?2 AND body = ?3 AND created_at = ?4)",
                params![
                    message.kind,
                    message.from_agent,
                    message.body,
                    message.created_at
                ],
                |row| row.get(0),
            )?;
            if exists {
                continue;
            }
            tx.execute(
                "INSERT INTO messages (kind, project, from_agent, to_agent, body,
                                         session_id, created_at, delivered_to,
                                         delivered_session, delivered_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    message.kind,
                    message.project,
                    message.from_agent,
                    message.to_agent,
                    message.body,
                    message.session_id,
                    message.created_at,
                    message.delivered_to,
                    message.delivered_session,
                    message.delivered_at
                ],
            )?;
            arrived_messages.insert(message.id, tx.last_insert_rowid());
        }
        for read in &backup.message_reads {
            let Some(new_id) = arrived_messages.get(&read.message_id) else {
                continue;
            };
            tx.execute(
                "INSERT OR IGNORE INTO message_reads (message_id, agent, read_at)
                 VALUES (?1, ?2, ?3)",
                params![new_id, read.agent, read.read_at],
            )?;
        }
        // A file version counts as present when the same project and path
        // already hold the same bytes; anything else becomes the next free
        // version of that path. Nothing here is replaced or removed.
        let same_model = same_embedding_model(&tx, backup)?;
        for file in &backup.files {
            let exists: bool = tx.query_row(
                "SELECT EXISTS (SELECT 1 FROM files
                 WHERE project = ?1 AND path = ?2 AND sha256 = ?3)",
                params![file.info.project, file.info.path, file.info.sha256],
                |row| row.get(0),
            )?;
            if exists {
                continue;
            }
            let (content, embedding) = decode_backup_file(file, same_model)?;
            let version: i64 = tx.query_row(
                "SELECT COALESCE(MAX(version), 0) + 1 FROM files WHERE project = ?1 AND path = ?2",
                params![file.info.project, file.info.path],
                |row| row.get(0),
            )?;
            // Entry ids differ between stores: the link follows the entry
            // it named, found the way merging finds entries, or is dropped.
            let mut info = file.info.clone();
            info.entry_id = match file.info.entry_id {
                None => None,
                Some(old) => match backup.entries.iter().find(|entry| entry.id == old) {
                    None => None,
                    Some(entry) => tx
                        .query_row(
                            "SELECT id FROM entries
                             WHERE project = ?1 AND title = ?2 AND body = ?3 AND created_at = ?4
                             ORDER BY id LIMIT 1",
                            params![entry.project, entry.title, entry.body, entry.created_at],
                            |row| row.get(0),
                        )
                        .optional()?,
                },
            };
            insert_backup_file(&tx, None, &info, version, &content)?;
            if let Some(vector) = embedding {
                tx.execute(
                    "UPDATE files SET embedding = ?2 WHERE id = ?1",
                    params![tx.last_insert_rowid(), vector],
                )?;
            }
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
        let project = &rename::resolve_alias(&conn, project)?;
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
        insert_session(&self.lock(), new)
    }

    /// The agent's open implicit session, or a new one opened from `new`
    /// when it has none. Lookup and insert happen under one lock, so two
    /// calls at the same moment cannot open two sessions for one agent. An
    /// implicit session idle for longer than `idle_hours` is closed first
    /// and never reused.
    pub fn implicit_session(&self, new: &NewSession, idle_hours: u32) -> Result<Implicit> {
        let conn = self.lock();
        conn.execute(
            "UPDATE sessions SET status = 'closed', summary = 'closed after inactivity',
                     ended_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
                 WHERE status = 'open' AND implicit = 1 AND agent = ?1
                   AND COALESCE(CAST(strftime('%s', 'now') AS INTEGER)
                                - CAST(strftime('%s', last_seen_at) AS INTEGER), 0)
                       >= ?2 * 3600",
            params![new.agent, idle_hours as i64],
        )?;
        let existing: Option<String> = conn
            .query_row(
                "SELECT id FROM sessions
                 WHERE status = 'open' AND implicit = 1 AND agent = ?1
                 ORDER BY last_seen_at DESC, id DESC LIMIT 1",
                params![new.agent],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(id) = existing {
            let session = get_session(&conn, &id)?.context("session vanished after lookup")?;
            return Ok(Implicit::Reused(session));
        }
        let new = NewSession {
            implicit: true,
            ..new.clone()
        };
        Ok(Implicit::Opened(insert_session(&conn, &new)?))
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
                Ok((Session::from_row(row)?, row.get(15)?))
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

    /// Adds a task to a project's shared to-do list.
    /// Adds the owner's note to a task (any status), in order.
    pub fn add_task_note(
        &self,
        task_id: i64,
        author: &str,
        body: &str,
    ) -> Result<Option<TaskNote>> {
        let body = body.trim();
        if body.is_empty() {
            anyhow::bail!("the note is empty");
        }
        if body.chars().count() > BODY_MAX_CHARS {
            anyhow::bail!("the note must be at most {BODY_MAX_CHARS} characters");
        }
        let conn = self.lock();
        let Some(task) = get_task(&conn, task_id)? else {
            return Ok(None);
        };
        conn.execute(
            "INSERT INTO task_notes (task_id, author, body, task_created) VALUES (?1, ?2, ?3, ?4)",
            params![task_id, author, body, task.created_at],
        )?;
        let id = conn.last_insert_rowid();
        Ok(Some(conn.query_row(
            "SELECT id, task_id, author, body, created_at FROM task_notes WHERE id = ?1",
            params![id],
            TaskNote::from_row,
        )?))
    }

    /// The owner's notes on these tasks, oldest first per task.
    pub fn task_notes(&self, task_ids: &[i64]) -> Result<HashMap<i64, Vec<TaskNote>>> {
        let mut out: HashMap<i64, Vec<TaskNote>> = HashMap::new();
        if task_ids.is_empty() {
            return Ok(out);
        }
        let conn = self.lock();
        // Only notes written for this very task (same id and created_at).
        let mut stmt = conn.prepare(
            "SELECT n.id, n.task_id, n.author, n.body, n.created_at
             FROM task_notes n JOIN tasks t ON t.id = n.task_id
             WHERE n.task_id = ?1 AND n.task_created = t.created_at
             ORDER BY n.id",
        )?;
        for id in task_ids {
            let notes = stmt
                .query_map(params![id], TaskNote::from_row)?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            if !notes.is_empty() {
                out.insert(*id, notes);
            }
        }
        Ok(out)
    }

    /// Puts a task on manual (lore never assigns it to a built-in agent by
    /// itself) or back to automatic, recording who did (`user:<name>` or
    /// `agent:<name>`; cleared with the flag).
    pub fn set_task_manual(&self, id: i64, manual: bool, by: &str) -> Result<Option<Task>> {
        let conn = self.lock();
        conn.execute(
            "UPDATE tasks SET manual = ?2, manual_by = ?3,
                 updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
             WHERE id = ?1",
            params![id, manual.then_some(true), manual.then_some(by)],
        )?;
        get_task(&conn, id)
    }

    pub fn add_task(&self, new: &NewTask) -> Result<Task> {
        let (project, title, body) = normalize_task(&new.project, &new.title, &new.body)?;
        let assignee = new.assignee.trim().to_lowercase();
        let created_by = new.created_by.trim().to_lowercase();
        let targets = normalize_task_targets(&new.targets)?;
        let conn = self.lock();
        let project = rename::resolve_alias(&conn, &project)?;
        conn.execute(
            "INSERT INTO tasks (project, title, body, assignee, created_by, session_id,
                                 created_at, updated_at, repo, dokploy_project_id,
                                 cloudflare_zone, manual, manual_by)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6,
                     strftime('%Y-%m-%dT%H:%M:%SZ', 'now'),
                     strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), ?7, ?8, ?9, ?10, ?11)",
            params![
                project,
                title,
                body,
                assignee,
                created_by,
                new.session_id,
                targets.repo,
                targets.dokploy_project_id,
                targets.cloudflare_zone,
                new.manual.then_some(true),
                new.manual.then_some(new.manual_by.as_str())
            ],
        )?;
        let id = conn.last_insert_rowid();
        get_task(&conn, id)?.context("task vanished after insert")
    }

    /// One task by its id.
    pub fn task(&self, id: i64) -> Result<Option<Task>> {
        get_task(&self.lock(), id)
    }

    /// Applies one task transition. `actor` is an agent name or "admin".
    /// A `None` note keeps the task's latest note. `None` when the id does
    /// not exist; an error, naming the task's current status, when the
    /// action does not apply to it.
    pub fn update_task(
        &self,
        id: i64,
        action: &str,
        actor: &str,
        note: Option<&str>,
        commit: Option<&str>,
    ) -> Result<Option<Task>> {
        let action = action.trim().to_lowercase();
        if !TASK_ACTIONS.contains(&action.as_str()) {
            anyhow::bail!("action must be one of: {}", TASK_ACTIONS.join(", "));
        }
        let actor = actor.trim().to_lowercase();
        let note = match note {
            None => None,
            Some(note) => {
                let note = note.trim();
                if note.chars().count() > NOTE_MAX_CHARS {
                    anyhow::bail!("the note must be at most {NOTE_MAX_CHARS} characters");
                }
                Some(note.to_string()).filter(|note| !note.is_empty())
            }
        };
        let commit = commit.unwrap_or("").trim().to_lowercase();
        let conn = self.lock();
        let Some(task) = get_task(&conn, id)? else {
            return Ok(None);
        };
        // The new value of every column the action touches; anything the
        // action leaves alone keeps its current value.
        let (status, claimed_by, done_by, done_commit, done) = match action.as_str() {
            "claim" => {
                if task.status == "claimed" {
                    if task.claimed_by != actor {
                        anyhow::bail!(
                            "task #{} is already claimed by {}",
                            task.id,
                            if task.claimed_by.is_empty() {
                                "someone else"
                            } else {
                                &task.claimed_by
                            }
                        );
                    }
                    // The claimer claiming again changes nothing.
                    (
                        task.status.clone(),
                        task.claimed_by.clone(),
                        String::new(),
                        String::new(),
                        false,
                    )
                } else if task.status != "open" {
                    anyhow::bail!("task #{} is {} and cannot be claimed", task.id, task.status);
                } else {
                    (
                        "claimed".into(),
                        actor.clone(),
                        String::new(),
                        String::new(),
                        false,
                    )
                }
            }
            "release" => {
                if task.status != "claimed" {
                    anyhow::bail!(
                        "task #{} is {} and cannot be released",
                        task.id,
                        task.status
                    );
                }
                if task.claimed_by != actor && actor != "admin" {
                    anyhow::bail!(
                        "task #{} is claimed by {}, and only they (or the admin) may release it",
                        task.id,
                        if task.claimed_by.is_empty() {
                            "someone else"
                        } else {
                            &task.claimed_by
                        }
                    );
                }
                (
                    "open".into(),
                    String::new(),
                    String::new(),
                    String::new(),
                    false,
                )
            }
            "done" => {
                if task.status != "open" && task.status != "claimed" {
                    anyhow::bail!(
                        "task #{} is {} and cannot be marked done",
                        task.id,
                        task.status
                    );
                }
                (
                    "done".into(),
                    task.claimed_by.clone(),
                    actor.clone(),
                    commit,
                    true,
                )
            }
            "cancel" => {
                if task.status != "open" && task.status != "claimed" {
                    anyhow::bail!(
                        "task #{} is {} and cannot be cancelled",
                        task.id,
                        task.status
                    );
                }
                (
                    "cancelled".into(),
                    task.claimed_by.clone(),
                    String::new(),
                    String::new(),
                    false,
                )
            }
            _ => {
                // reopen
                if task.status != "done" && task.status != "cancelled" {
                    anyhow::bail!(
                        "task #{} is {} and cannot be reopened",
                        task.id,
                        task.status
                    );
                }
                // Reopening clears the claim and the done fields.
                (
                    "open".into(),
                    String::new(),
                    String::new(),
                    String::new(),
                    false,
                )
            }
        };
        conn.execute(
            "UPDATE tasks SET status = ?2, claimed_by = ?3, done_by = ?4, done_commit = ?5,
                     note = COALESCE(?6, note),
                     updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now'),
                     done_at = CASE WHEN ?7 THEN strftime('%Y-%m-%dT%H:%M:%SZ', 'now') ELSE NULL END
             WHERE id = ?1",
            params![id, status, claimed_by, done_by, done_commit, note, done],
        )?;
        get_task(&conn, id)
    }

    /// Tasks on the board, claimed ones first, then open ones, then the
    /// rest, newest first within each status. An empty `statuses` list
    /// means every status.
    /// The projects that have notes (entries of kind `note`): how many and
    /// when the newest was written, most recent first.
    pub fn note_projects(&self) -> Result<Vec<(String, i64, String)>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT project, COUNT(*), MAX(created_at) FROM entries WHERE kind = 'note'
             GROUP BY project ORDER BY MAX(created_at) DESC",
        )?;
        let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn tasks(
        &self,
        project: Option<&str>,
        statuses: &[&str],
        limit: usize,
    ) -> Result<Vec<Task>> {
        let conn = self.lock();
        let mut sql = format!("SELECT {TASK_COLUMNS} FROM tasks WHERE 1=1");
        let mut args: Vec<Value> = Vec::new();
        if let Some(project) = project {
            sql.push_str(" AND project = ?");
            args.push(Value::Text(project.to_string()));
        }
        if !statuses.is_empty() {
            sql.push_str(&format!(
                " AND status IN ({})",
                placeholders(statuses.len())
            ));
            args.extend(
                statuses
                    .iter()
                    .map(|status| Value::Text(status.to_string())),
            );
        }
        sql.push_str(
            " ORDER BY CASE status WHEN 'claimed' THEN 0 WHEN 'open' THEN 1 ELSE 2 END, \
              created_at DESC, id DESC LIMIT ?",
        );
        args.push(Value::Integer(limit as i64));
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(params_from_iter(args), Task::from_row)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Adds a message between agents, or a handoff note for a project. A
    /// handoff needs its project and is never addressed to one agent.
    pub fn add_message(&self, new: &NewMessage) -> Result<Message> {
        let (kind, project, body) = normalize_message(&new.kind, &new.project, &new.body)?;
        let from_agent = new.from_agent.trim().to_lowercase();
        if from_agent.is_empty() {
            anyhow::bail!("from_agent must not be empty");
        }
        let to_agent = if kind == "handoff" {
            String::new()
        } else {
            new.to_agent.trim().to_lowercase()
        };
        let conn = self.lock();
        let project = rename::resolve_alias(&conn, &project)?;
        conn.execute(
            "INSERT INTO messages (kind, project, from_agent, to_agent, body, session_id,
                                     created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))",
            params![kind, project, from_agent, to_agent, body, new.session_id],
        )?;
        let id = conn.last_insert_rowid();
        get_message(&conn, id)?.context("message vanished after insert")
    }

    /// Messages agent X has not read yet, newest first: addressed to X or to
    /// everyone, and not written by X.
    pub fn unread_messages(
        &self,
        agent: &str,
        project: Option<&str>,
        limit: usize,
    ) -> Result<Vec<Message>> {
        self.messages_for(agent, project, limit, false)
    }

    /// The messages agent X has already read, newest first.
    pub fn read_messages(
        &self,
        agent: &str,
        project: Option<&str>,
        limit: usize,
    ) -> Result<Vec<Message>> {
        self.messages_for(agent, project, limit, true)
    }

    /// How many messages agent X has not read yet, across every project.
    pub fn unread_message_count(&self, agent: &str) -> Result<i64> {
        Ok(self.lock().query_row(
            "SELECT COUNT(*) FROM messages m
             WHERE m.kind = 'message' AND m.from_agent != ?1
               AND (m.to_agent = '' OR m.to_agent = ?1)
               AND NOT EXISTS (SELECT 1 FROM message_reads r
                               WHERE r.message_id = m.id AND r.agent = ?1)",
            params![agent],
            |row| row.get(0),
        )?)
    }

    /// The read or the unread messages of one agent, newest first.
    fn messages_for(
        &self,
        agent: &str,
        project: Option<&str>,
        limit: usize,
        read: bool,
    ) -> Result<Vec<Message>> {
        let conn = self.lock();
        let reads = if read { "EXISTS" } else { "NOT EXISTS" };
        let mut sql = format!(
            "SELECT {MESSAGE_COLUMNS} FROM messages m
             WHERE m.kind = 'message' AND m.from_agent != ?1
               AND (m.to_agent = '' OR m.to_agent = ?1)
               AND {reads} (SELECT 1 FROM message_reads r
                            WHERE r.message_id = m.id AND r.agent = ?1)"
        );
        let mut args: Vec<Value> = vec![Value::Text(agent.to_string())];
        if let Some(project) = project {
            sql.push_str(" AND m.project = ?");
            args.push(Value::Text(project.to_string()));
        }
        sql.push_str(" ORDER BY m.created_at DESC, m.id DESC LIMIT ?");
        args.push(Value::Integer(limit as i64));
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(params_from_iter(args), Message::from_row)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Marks messages read for one agent, and returns the ids this call
    /// marked. Ids that are gone, or already read, are skipped, so two
    /// sessions of the same agent never both get to show one message as new.
    pub fn mark_read(&self, agent: &str, ids: &[i64]) -> Result<Vec<i64>> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let conn = self.lock();
        // Inserting from the messages table itself leaves out ids that do
        // not exist, instead of tripping over their foreign key.
        let sql = format!(
            "INSERT OR IGNORE INTO message_reads (message_id, agent, read_at)
             SELECT id, ?1, strftime('%Y-%m-%dT%H:%M:%SZ', 'now') FROM messages
             WHERE id IN ({})
             RETURNING message_id",
            placeholders(ids.len())
        );
        let mut args: Vec<Value> = vec![Value::Text(agent.to_string())];
        args.extend(ids.iter().map(|id| Value::Integer(*id)));
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(params_from_iter(args), |row| row.get(0))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// The handoff notes of one project waiting for its next session:
    /// undelivered, and not written by that session, oldest first.
    pub fn pending_handoffs(&self, project: &str, session_id: &str) -> Result<Vec<Message>> {
        let conn = self.lock();
        let sql = format!(
            "SELECT {MESSAGE_COLUMNS} FROM messages
             WHERE kind = 'handoff' AND project = ?1 AND delivered_at IS NULL
               AND (session_id IS NULL OR session_id != ?2)
             ORDER BY id"
        );
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(params![project, session_id], Message::from_row)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Delivers handoff notes to one agent's session, and returns the ids
    /// this call delivered; only those may be shown. A note is delivered
    /// exactly once and never to the session that wrote it: ids already
    /// delivered, or written by `session_id`, are left alone. The check and
    /// the update are one statement, so two sessions opening at the same
    /// moment cannot both receive the same note.
    pub fn deliver_handoffs(&self, ids: &[i64], agent: &str, session_id: &str) -> Result<Vec<i64>> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let conn = self.lock();
        let sql = format!(
            "UPDATE messages SET delivered_to = ?1, delivered_session = ?2,
                     delivered_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
             WHERE kind = 'handoff' AND delivered_at IS NULL
               AND (session_id IS NULL OR session_id != ?2)
               AND id IN ({})
             RETURNING id",
            placeholders(ids.len())
        );
        let mut args: Vec<Value> = vec![
            Value::Text(agent.to_string()),
            Value::Text(session_id.to_string()),
        ];
        args.extend(ids.iter().map(|id| Value::Integer(*id)));
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(params_from_iter(args), |row| row.get(0))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Every message and handoff note on the board, newest first, each with
    /// the agents that have read it.
    pub fn messages(&self, project: Option<&str>, limit: usize) -> Result<Vec<BoardMessage>> {
        let conn = self.lock();
        let mut sql = format!("SELECT {MESSAGE_COLUMNS} FROM messages WHERE 1=1");
        let mut args: Vec<Value> = Vec::new();
        if let Some(project) = project {
            sql.push_str(" AND project = ?");
            args.push(Value::Text(project.to_string()));
        }
        sql.push_str(" ORDER BY created_at DESC, id DESC LIMIT ?");
        args.push(Value::Integer(limit as i64));
        let list: Vec<Message> = {
            let mut stmt = conn.prepare(&sql)?;
            let rows = stmt.query_map(params_from_iter(args), Message::from_row)?;
            rows.collect::<rusqlite::Result<_>>()?
        };
        let mut reads: HashMap<i64, Vec<String>> = HashMap::new();
        if !list.is_empty() {
            let ids: Vec<i64> = list.iter().map(|message| message.id).collect();
            let mut stmt = conn.prepare(&format!(
                "SELECT message_id, agent FROM message_reads
                 WHERE message_id IN ({}) ORDER BY message_id, agent",
                placeholders(ids.len())
            ))?;
            let rows = stmt.query_map(params_from_iter(ids), |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })?;
            for row in rows {
                let (message_id, agent) = row?;
                reads.entry(message_id).or_default().push(agent);
            }
        }
        Ok(list
            .into_iter()
            .map(|message| BoardMessage {
                read_by: reads.remove(&message.id).unwrap_or_default(),
                message,
            })
            .collect())
    }

    /// How many tasks are open and claimed right now.
    pub fn board_counts(&self) -> Result<BoardCounts> {
        let conn = self.lock();
        let (open_tasks, claimed_tasks): (i64, i64) = conn.query_row(
            "SELECT COUNT(*) FILTER (WHERE status = 'open'),
                    COUNT(*) FILTER (WHERE status = 'claimed') FROM tasks",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        Ok(BoardCounts {
            open_tasks,
            claimed_tasks,
        })
    }

    /// Saves a file for a project. When the latest version of that path
    /// holds the same bytes, no new version is made: its kind and
    /// description are updated if they changed, and it comes back with
    /// `unchanged` set. Otherwise the file is stored as the next version.
    /// Reading the latest version and writing the next one happen in one
    /// transaction under the store's lock, so two saves of the same path
    /// can never claim the same version.
    pub fn save_file(&self, new: &NewFile) -> Result<SavedFile> {
        let project = normalize_file_project(&new.project)?;
        let path = normalize_file_path(&new.path)?;
        refuse_secret_path(&path)?;
        let kind = normalize_file_kind(&new.kind)?;
        let encoding = normalize_file_encoding(&new.encoding)?;
        let description = normalize_file_description(&new.description)?;
        let content = decode_file_content(&encoding, &new.content)?;
        refuse_secret_content(&content)?;
        let agent = new.agent.trim().to_lowercase();
        if agent.is_empty() {
            anyhow::bail!("the agent saving the file must be named");
        }
        let sha256 = sha256_hex(&content);

        let mut conn = self.lock();
        let tx = conn.transaction()?;
        let project = rename::resolve_alias(&tx, &project)?;
        if let Some(entry_id) = new.entry_id {
            let exists: bool = tx.query_row(
                "SELECT EXISTS (SELECT 1 FROM entries WHERE id = ?1)",
                params![entry_id],
                |row| row.get(0),
            )?;
            if !exists {
                anyhow::bail!("there is no entry #{entry_id} to link the file to");
            }
        }
        let latest: Option<(i64, i64, String, String, String)> = tx
            .query_row(
                "SELECT id, version, sha256, kind, description FROM files
                 WHERE project = ?1 AND path = ?2 ORDER BY version DESC LIMIT 1",
                params![project, path],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()?;
        // A save that names no kind keeps the kind the path already has,
        // instead of turning an `idea` back into `other`.
        let kind = match &latest {
            Some((_, _, _, latest_kind, _)) if new.kind.trim().is_empty() => latest_kind.clone(),
            _ => kind,
        };
        if let Some((id, _, latest_sha, latest_kind, latest_description)) = &latest
            && *latest_sha == sha256
        {
            let changed = *latest_kind != kind || *latest_description != description;
            if changed {
                // A new description means a new vector.
                tx.execute(
                    "UPDATE files SET kind = ?2, description = ?3, embedding = NULL WHERE id = ?1",
                    params![id, kind, description],
                )?;
            }
            let file = get_file_info(&tx, *id)?.context("file vanished after update")?;
            tx.commit()?;
            return Ok(SavedFile {
                file,
                unchanged: true,
                needs_embedding: changed,
            });
        }
        let version = latest.map(|(_, version, ..)| version + 1).unwrap_or(1);
        tx.execute(
            "INSERT INTO files (project, path, version, kind, description, encoding, content,
                                size, sha256, entry_id, agent, session_id, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                     strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))",
            params![
                project,
                path,
                version,
                kind,
                description,
                encoding,
                content,
                content.len() as i64,
                sha256,
                new.entry_id,
                agent,
                new.session_id
            ],
        )?;
        let id = tx.last_insert_rowid();
        let file = get_file_info(&tx, id)?.context("file vanished after insert")?;
        tx.commit()?;
        Ok(SavedFile {
            file,
            unchanged: false,
            needs_embedding: true,
        })
    }

    /// One file version with its bytes, by id.
    pub fn file(&self, id: i64) -> Result<Option<StoredFile>> {
        let conn = self.lock();
        let sql = format!("SELECT {FILE_COLUMNS}, content FROM files WHERE id = ?1");
        Ok(conn
            .query_row(&sql, params![id], stored_file_from_row)
            .optional()?)
    }

    /// One version of a project's file with its bytes: the given version,
    /// or the latest one.
    pub fn file_at(
        &self,
        project: &str,
        path: &str,
        version: Option<i64>,
    ) -> Result<Option<StoredFile>> {
        let project = normalize_file_project(project)?;
        let path = normalize_file_path(path)?;
        let conn = self.lock();
        let sql = format!(
            "SELECT {FILE_COLUMNS}, content FROM files
             WHERE project = ?1 AND path = ?2 AND (?3 IS NULL OR version = ?3)
             ORDER BY version DESC LIMIT 1"
        );
        Ok(conn
            .query_row(&sql, params![project, path, version], stored_file_from_row)
            .optional()?)
    }

    /// Every version of one project's file, newest first, without content.
    pub fn file_versions(&self, project: &str, path: &str) -> Result<Vec<FileInfo>> {
        let project = normalize_file_project(project)?;
        let path = normalize_file_path(path)?;
        let conn = self.lock();
        let sql = format!(
            "SELECT {FILE_COLUMNS} FROM files WHERE project = ?1 AND path = ?2
             ORDER BY version DESC"
        );
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(params![project, path], FileInfo::from_row)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// The latest version of each file, newest first, without content.
    pub fn files(&self, project: Option<&str>, limit: usize) -> Result<Vec<FileInfo>> {
        let conn = self.lock();
        let mut sql = format!(
            "SELECT {FILE_COLUMNS} FROM files f
             WHERE version = (SELECT MAX(version) FROM files g
                              WHERE g.project = f.project AND g.path = f.path)"
        );
        let mut args: Vec<Value> = Vec::new();
        if let Some(project) = project {
            sql.push_str(" AND project = ?");
            args.push(Value::Text(project.to_string()));
        }
        sql.push_str(" ORDER BY created_at DESC, id DESC LIMIT ?");
        args.push(Value::Integer(limit as i64));
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(params_from_iter(args), FileInfo::from_row)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Finds files by their latest version: a case-insensitive substring
    /// match of the query's words on the path and the description, plus
    /// cosine similarity over the stored vectors when a query vector is
    /// given. Text matches come first, then meaning-only matches by
    /// similarity.
    pub fn search_files(
        &self,
        query: &str,
        project: Option<&str>,
        vector: Option<&[f32]>,
        min_similarity: f32,
        limit: usize,
    ) -> Result<Vec<FileHit>> {
        let terms = file_search_terms(query);
        let mut candidates: Vec<(FileInfo, Option<Vec<u8>>)> = Vec::new();
        {
            let conn = self.lock();
            let mut sql = format!(
                "SELECT {FILE_COLUMNS}, embedding FROM files f
                 WHERE version = (SELECT MAX(version) FROM files g
                                  WHERE g.project = f.project AND g.path = f.path)"
            );
            let mut args: Vec<Value> = Vec::new();
            if let Some(project) = project {
                sql.push_str(" AND project = ?");
                args.push(Value::Text(project.to_string()));
            }
            let mut stmt = conn.prepare(&sql)?;
            let rows = stmt.query_map(params_from_iter(args), |row| {
                Ok((FileInfo::from_row(row)?, row.get::<_, Option<Vec<u8>>>(13)?))
            })?;
            for row in rows {
                candidates.push(row?);
            }
        }
        // (text score, similarity, hit)
        let mut scored: Vec<(usize, f32, FileHit)> = Vec::new();
        for (file, blob) in candidates {
            let haystack = format!("{}\n{}", file.path, file.description).to_lowercase();
            let text = terms
                .iter()
                .filter(|term| haystack.contains(term.as_str()))
                .count();
            let similarity = match (vector, &blob) {
                (Some(vector), Some(blob)) => Some(dot(vector, &decode_vector(blob))),
                _ => None,
            };
            let semantic = similarity.is_some_and(|s| s >= min_similarity);
            if text == 0 && !semantic {
                continue;
            }
            let matched = match (text > 0, semantic) {
                (true, true) => "text+semantic",
                (true, false) => "text",
                _ => "semantic",
            };
            scored.push((
                text,
                similarity.unwrap_or(0.0),
                FileHit {
                    file,
                    matched,
                    similarity,
                },
            ));
        }
        scored.sort_by(|a, b| {
            b.0.cmp(&a.0)
                .then(b.1.total_cmp(&a.1))
                .then(b.2.file.id.cmp(&a.2.file.id))
        });
        Ok(scored
            .into_iter()
            .take(limit)
            .map(|(_, _, hit)| hit)
            .collect())
    }

    /// Removes one file version and returns it as it was.
    pub fn delete_file(&self, id: i64) -> Result<Option<FileInfo>> {
        let conn = self.lock();
        let Some(file) = get_file_info(&conn, id)? else {
            return Ok(None);
        };
        conn.execute("DELETE FROM files WHERE id = ?1", params![id])?;
        Ok(Some(file))
    }

    /// Removes every version of one project's file and returns how many
    /// there were.
    pub fn delete_file_path(&self, project: &str, path: &str) -> Result<usize> {
        let project = normalize_file_project(project)?;
        let path = normalize_file_path(path)?;
        Ok(self.lock().execute(
            "DELETE FROM files WHERE project = ?1 AND path = ?2",
            params![project, path],
        )?)
    }

    pub fn set_file_embedding(&self, id: i64, vector: &[f32]) -> Result<()> {
        self.lock().execute(
            "UPDATE files SET embedding = ?2 WHERE id = ?1",
            params![id, encode_vector(vector)],
        )?;
        Ok(())
    }

    /// File versions that still need an embedding, oldest first.
    pub fn files_missing_embeddings(&self, limit: usize) -> Result<Vec<FileInfo>> {
        let conn = self.lock();
        let sql = format!(
            "SELECT {FILE_COLUMNS} FROM files WHERE embedding IS NULL ORDER BY id LIMIT ?1"
        );
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(params![limit as i64], FileInfo::from_row)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// How many files, versions and bytes are kept.
    pub fn file_counts(&self) -> Result<FileCounts> {
        let conn = self.lock();
        let (files, versions, bytes): (i64, i64, i64) = conn.query_row(
            "SELECT (SELECT COUNT(*) FROM (SELECT 1 FROM files GROUP BY project, path)),
                    COUNT(*), COALESCE(SUM(size), 0) FROM files",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        Ok(FileCounts {
            files,
            versions,
            bytes,
        })
    }

    /// How many distinct files one project keeps.
    pub fn project_file_count(&self, project: &str) -> Result<i64> {
        Ok(self.lock().query_row(
            "SELECT COUNT(*) FROM (SELECT 1 FROM files WHERE project = ?1 GROUP BY path)",
            params![project],
            |row| row.get(0),
        )?)
    }

    /// Stores one provider's credential. The secret arrives already
    /// encrypted, with its nonce; the hint is the last four characters of
    /// the credential, and the base URL is the admin-entered server URL
    /// for gitlab and dokploy.
    pub fn set_vault(
        &self,
        provider: &str,
        base_url: &str,
        nonce: &[u8],
        secret: &[u8],
        hint: &str,
    ) -> Result<()> {
        let provider = normalize_provider(provider)?;
        let conn = self.lock();
        conn.execute(
            "INSERT INTO vault (provider, base_url, nonce, secret, hint, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
             ON CONFLICT (provider) DO UPDATE SET
                base_url = excluded.base_url, nonce = excluded.nonce,
                secret = excluded.secret, hint = excluded.hint,
                updated_at = excluded.updated_at",
            params![provider, base_url.trim(), nonce, secret, hint],
        )?;
        Ok(())
    }

    /// One provider's stored credential, still encrypted. The only reader
    /// is the vault key, on its way to a call.
    pub fn vault(&self, provider: &str) -> Result<Option<StoredVault>> {
        let provider = normalize_provider(provider)?;
        Ok(self
            .lock()
            .query_row(
                "SELECT provider, base_url, nonce, secret, hint, updated_at
                 FROM vault WHERE provider = ?1",
                params![provider],
                |row| {
                    Ok(StoredVault {
                        provider: row.get(0)?,
                        base_url: row.get(1)?,
                        nonce: row.get(2)?,
                        secret: row.get(3)?,
                        hint: row.get(4)?,
                        updated_at: row.get(5)?,
                    })
                },
            )
            .optional()?)
    }

    /// Every provider's credential as the admin page shows it, in the
    /// fixed provider order: configured, the server URL, the hint and the
    /// time. Never the nonce and never the secret.
    pub fn vault_status(&self) -> Result<Vec<VaultStatus>> {
        let conn = self.lock();
        let mut stored: HashMap<String, StoredVault> = HashMap::new();
        {
            let mut stmt = conn
                .prepare("SELECT provider, base_url, nonce, secret, hint, updated_at FROM vault")?;
            let rows = stmt.query_map([], |row| {
                Ok(StoredVault {
                    provider: row.get(0)?,
                    base_url: row.get(1)?,
                    nonce: row.get(2)?,
                    secret: row.get(3)?,
                    hint: row.get(4)?,
                    updated_at: row.get(5)?,
                })
            })?;
            for row in rows {
                let stored_row = row?;
                stored.insert(stored_row.provider.clone(), stored_row);
            }
        }
        let mut list = Vec::new();
        for id in PROVIDERS {
            let row = stored.remove(*id);
            list.push(VaultStatus {
                provider: (*id).to_string(),
                configured: row.is_some(),
                base_url: row
                    .as_ref()
                    .map(|row| row.base_url.clone())
                    .unwrap_or_default(),
                hint: row.as_ref().map(|row| row.hint.clone()).unwrap_or_default(),
                updated_at: row.map(|row| row.updated_at).unwrap_or_default(),
            });
        }
        Ok(list)
    }

    /// Removes one provider's credential. False when none was stored.
    pub fn delete_vault(&self, provider: &str) -> Result<bool> {
        let provider = normalize_level_provider(provider)?;
        Ok(self
            .lock()
            .execute("DELETE FROM vault WHERE provider = ?1", params![provider])?
            > 0)
    }

    /// Stores the mailbox: host, port and account in clear, the password
    /// already encrypted (with those three as associated data), and the
    /// hint (the page shows none for a password, so it is empty).
    pub fn set_mail_vault(
        &self,
        host: &str,
        port: u16,
        account: &str,
        nonce: &[u8],
        secret: &[u8],
        hint: &str,
    ) -> Result<()> {
        self.lock().execute(
            "INSERT INTO vault (provider, base_url, nonce, secret, hint, updated_at,
                                host, port, account)
             VALUES (?1, '', ?2, ?3, ?4, strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), ?5, ?6, ?7)
             ON CONFLICT (provider) DO UPDATE SET
                base_url = '', nonce = excluded.nonce, secret = excluded.secret,
                hint = excluded.hint, updated_at = excluded.updated_at,
                host = excluded.host, port = excluded.port, account = excluded.account",
            params![MAIL_PROVIDER, nonce, secret, hint, host, port, account],
        )?;
        Ok(())
    }

    /// The stored mailbox, the password still encrypted; `None` when none
    /// is stored.
    pub fn mail_vault(&self) -> Result<Option<StoredMail>> {
        Ok(self
            .lock()
            .query_row(
                "SELECT host, port, account, nonce, secret, updated_at
                 FROM vault WHERE provider = ?1",
                params![MAIL_PROVIDER],
                |row| {
                    let port: i64 = row.get(1)?;
                    Ok(StoredMail {
                        host: row.get(0)?,
                        port: u16::try_from(port).unwrap_or(0),
                        account: row.get(2)?,
                        nonce: row.get(3)?,
                        secret: row.get(4)?,
                        updated_at: row.get(5)?,
                    })
                },
            )
            .optional()?)
    }

    /// One agent's level on one provider: off, read or full. No row means
    /// full, so a fresh store grants everything and the admin only ever
    /// restricts.
    pub fn ops_level(&self, agent: &str, provider: &str) -> Result<String> {
        let agent = agent.trim().to_lowercase();
        let provider = normalize_level_provider(provider)?;
        let level: Option<String> = self
            .lock()
            .query_row(
                "SELECT level FROM ops_permissions WHERE agent = ?1 AND provider = ?2",
                params![agent, provider],
                |row| row.get(0),
            )
            .optional()?;
        if provider == MAIL_PROVIDER {
            // The mailbox only knows off and read: a row that says `full`
            // means read, and no row means off.
            return Ok(match level.as_deref() {
                Some("read" | "full") => "read".into(),
                _ => MAIL_DEFAULT_LEVEL.into(),
            });
        }
        Ok(level.unwrap_or_else(|| "full".into()))
    }

    /// Sets one agent's level on one provider. Level `full` deletes the
    /// row, keeping the default out of the store.
    pub fn set_ops_level(&self, agent: &str, provider: &str, level: &str) -> Result<()> {
        let agent = agent.trim().to_lowercase();
        if agent.is_empty() {
            anyhow::bail!("the agent must be named");
        }
        let provider = normalize_level_provider(provider)?;
        let mut level = level.trim().to_lowercase();
        if !OPS_LEVELS.contains(&level.as_str()) {
            anyhow::bail!("level must be one of: {}", OPS_LEVELS.join(", "));
        }
        let conn = self.lock();
        if provider == MAIL_PROVIDER {
            // `full` is read for the mailbox, and the default is off: only
            // a grant is stored.
            if level == "full" {
                level = "read".into();
            }
            if level == MAIL_DEFAULT_LEVEL {
                conn.execute(
                    "DELETE FROM ops_permissions WHERE agent = ?1 AND provider = ?2",
                    params![agent, provider],
                )?;
            } else {
                conn.execute(
                    "INSERT INTO ops_permissions (agent, provider, level) VALUES (?1, ?2, ?3)
                     ON CONFLICT (agent, provider) DO UPDATE SET level = excluded.level",
                    params![agent, provider, level],
                )?;
            }
            return Ok(());
        }
        if level == "full" {
            conn.execute(
                "DELETE FROM ops_permissions WHERE agent = ?1 AND provider = ?2",
                params![agent, provider],
            )?;
        } else {
            conn.execute(
                "INSERT INTO ops_permissions (agent, provider, level) VALUES (?1, ?2, ?3)
                 ON CONFLICT (agent, provider) DO UPDATE SET level = excluded.level",
                params![agent, provider, level],
            )?;
        }
        Ok(())
    }

    /// Every permission row, by agent then provider.
    pub fn ops_permissions(&self) -> Result<Vec<OpsPermission>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT agent, provider, level FROM ops_permissions ORDER BY agent, provider",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(OpsPermission {
                agent: row.get(0)?,
                provider: row.get(1)?,
                level: row.get(2)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// The operations kill switch: the `meta` key `ops.enabled`, missing
    /// meaning enabled.
    pub fn ops_enabled(&self) -> Result<bool> {
        let conn = self.lock();
        let value: Option<String> = conn
            .query_row(
                "SELECT value FROM meta WHERE key = 'ops.enabled'",
                [],
                |row| row.get(0),
            )
            .optional()?;
        // Missing means on; anything but "1" (a damaged value) means off.
        Ok(matches!(value.as_deref(), None | Some("1")))
    }

    /// Sets the operations kill switch.
    pub fn set_ops_enabled(&self, enabled: bool) -> Result<()> {
        let conn = self.lock();
        set_meta(&conn, "ops.enabled", if enabled { "1" } else { "0" })
    }

    /// The two leak scan switches: `meta` keys `leakscan.enabled` (missing
    /// means on; only "0" turns it off, so a damaged value keeps the scan)
    /// and `leakscan.allow_public` (only "1" allows; missing or damaged
    /// refuses public repositories).
    pub fn leak_scan_settings(&self) -> Result<LeakScanSettings> {
        let conn = self.lock();
        Ok(LeakScanSettings {
            scan: meta_value(&conn, "leakscan.enabled")? != "0",
            allow_public: meta_value(&conn, "leakscan.allow_public")? == "1",
        })
    }

    /// The owner's switch that lets built-in agents' runs add, change or
    /// remove CI definitions (`.github/workflows/`, `.gitlab-ci.yml`, …):
    /// `meta` key `runs.ci_changes`, only "1" allows (off by default).
    pub fn runs_may_change_ci(&self) -> Result<bool> {
        let conn = self.lock();
        Ok(meta_value(&conn, "runs.ci_changes")? == "1")
    }

    pub fn set_runs_may_change_ci(&self, allow: bool) -> Result<()> {
        let conn = self.lock();
        set_meta(&conn, "runs.ci_changes", if allow { "1" } else { "0" })
    }

    /// Records the token agent a session was opened with: the identity lore
    /// verified, which the session's free-text name may not be.
    pub fn set_session_token_agent(&self, id: &str, token_agent: &str) -> Result<()> {
        self.lock().execute(
            "UPDATE sessions SET token_agent = ?2 WHERE id = ?1 AND token_agent = ''",
            params![id, token_agent.trim().to_lowercase()],
        )?;
        Ok(())
    }

    /// Sets either leak scan switch; `None` leaves it as it is.
    pub fn set_leak_scan_settings(
        &self,
        scan: Option<bool>,
        allow_public: Option<bool>,
    ) -> Result<()> {
        let conn = self.lock();
        if let Some(scan) = scan {
            set_meta(&conn, "leakscan.enabled", if scan { "1" } else { "0" })?;
        }
        if let Some(allow) = allow_public {
            set_meta(
                &conn,
                "leakscan.allow_public",
                if allow { "1" } else { "0" },
            )?;
        }
        Ok(())
    }

    /// Records one provider call — allowed or refused — and keeps the log
    /// bounded to its newest rows. `agent` is an agent name, or "admin"
    /// for a test call from the admin page.
    #[expect(
        clippy::too_many_arguments,
        reason = "one argument per column of the ops_log row"
    )]
    pub fn log_op(
        &self,
        agent: &str,
        session_id: Option<&str>,
        provider: &str,
        method: &str,
        path: &str,
        status: i64,
        outcome: &str,
        detail: &str,
        duration_ms: i64,
    ) -> Result<OpLog> {
        let agent = agent.trim().to_lowercase();
        let provider = normalize_level_provider(provider)?;
        let outcome = outcome.trim().to_lowercase();
        if !OPS_OUTCOMES.contains(&outcome.as_str()) {
            anyhow::bail!("outcome must be one of: {}", OPS_OUTCOMES.join(", "));
        }
        let conn = self.lock();
        conn.execute(
            "INSERT INTO ops_log (agent, session_id, provider, method, path, status,
                                  outcome, detail, duration_ms, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9,
                     strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))",
            params![
                agent,
                session_id,
                provider,
                method,
                path,
                status,
                outcome,
                detail,
                duration_ms
            ],
        )?;
        let id = conn.last_insert_rowid();
        // The newest rows are the newest ids: rows only ever leave from
        // the old end, so one statement keeps the log bounded.
        conn.execute(
            "DELETE FROM ops_log WHERE id <= ?1",
            params![id - OPS_LOG_KEPT],
        )?;
        conn.query_row(
            "SELECT id, agent, session_id, provider, method, path, status, outcome,
                    detail, duration_ms, created_at
             FROM ops_log WHERE id = ?1",
            params![id],
            op_log_from_row,
        )
        .context("the ops log row vanished after insert")
    }

    /// The newest `limit` provider calls, newest first.
    pub fn ops_log(&self, limit: usize) -> Result<Vec<OpLog>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT id, agent, session_id, provider, method, path, status, outcome,
                    detail, duration_ms, created_at
             FROM ops_log ORDER BY id DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit as i64], op_log_from_row)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
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
        let target = rule_target(&conn, &scope, target)?;
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
        let target = rule_target(&conn, &scope, target)?;
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
                    avatar: String::new(),
                    display_name: None,
                })
            })?;
            for row in rows {
                agents.push(row?);
            }
        }
        // Every registry row too, so an OAuth agent approved but not yet
        // connected can have its service levels lowered.
        let avatars: HashMap<String, String> = {
            let mut stmt = conn.prepare("SELECT name, avatar FROM agent_registry")?;
            let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
            rows.collect::<rusqlite::Result<_>>()?
        };
        let display_names: HashMap<String, String> = {
            let mut stmt = conn.prepare(
                "SELECT name, display_name FROM agent_registry WHERE display_name IS NOT NULL",
            )?;
            let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
            rows.collect::<rusqlite::Result<_>>()?
        };
        let known: Vec<String> = agents.iter().map(|a| a.name.clone()).collect();
        for name in configured
            .iter()
            .chain(written.keys())
            .chain(avatars.keys())
        {
            if !known.contains(name) && !agents.iter().any(|a| &a.name == name) {
                agents.push(AgentSummary {
                    name: name.clone(),
                    client: String::new(),
                    first_seen: None,
                    last_seen: None,
                    seconds_since_seen: None,
                    requests: 0,
                    entries: 0,
                    avatar: String::new(),
                    display_name: None,
                });
            }
        }
        for agent in &mut agents {
            agent.entries = written.get(&agent.name).copied().unwrap_or(0);
            let chosen = avatars.get(&agent.name).map(String::as_str).unwrap_or("");
            agent.avatar = crate::avatars::effective(&agent.name, chosen).to_string();
            agent.display_name = display_names.get(&agent.name).cloned();
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

        // Every pair's similarity once (the matrix is symmetric), spread
        // over up to four cores: this is most of what the page's first
        // load waits for (about 1.4 billion multiplications for 1200
        // entries of 1024 dimensions).
        let similar = similar_pairs(&vectors, min_similarity)?;
        let mut synapses: Vec<Synapse> = Vec::new();
        let mut seen: std::collections::HashSet<(i64, i64)> = std::collections::HashSet::new();
        for (i, (id, _)) in vectors.iter().enumerate() {
            let mut scored: Vec<(i64, f32)> = similar[i]
                .iter()
                .map(|&(j, similarity)| (vectors[j].0, similarity))
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
            conn.execute("UPDATE files SET embedding = NULL", [])?;
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
    for task in &backup.tasks {
        if task.project.trim().is_empty() || task.title.trim().is_empty() {
            anyhow::bail!("task #{} has no project or title", task.id);
        }
        if !TASK_STATUSES.contains(&task.status.as_str()) {
            anyhow::bail!(
                "task #{} has an unknown status \"{}\"",
                task.id,
                task.status
            );
        }
    }
    for message in &backup.messages {
        if !MESSAGE_KINDS.contains(&message.kind.as_str()) {
            anyhow::bail!(
                "message #{} has an unknown kind \"{}\"",
                message.id,
                message.kind
            );
        }
        if message.kind == "handoff" && message.project.trim().is_empty() {
            anyhow::bail!("handoff note #{} has no project", message.id);
        }
        if message.body.trim().is_empty() {
            anyhow::bail!("message #{} has an empty body", message.id);
        }
    }
    let message_ids: std::collections::HashSet<i64> =
        backup.messages.iter().map(|message| message.id).collect();
    for read in &backup.message_reads {
        if !message_ids.contains(&read.message_id) {
            anyhow::bail!(
                "a read mark refers to message #{}, which is not in the backup",
                read.message_id
            );
        }
    }
    let mut versions: std::collections::HashSet<(&str, &str, i64)> =
        std::collections::HashSet::new();
    for file in &backup.files {
        let info = &file.info;
        if info.project.trim().is_empty() || info.project != info.project.trim().to_lowercase() {
            anyhow::bail!("file #{} has no project, or one not in lowercase", info.id);
        }
        if normalize_file_path(&info.path).ok().as_deref() != Some(info.path.as_str()) {
            anyhow::bail!("file #{} has an invalid path \"{}\"", info.id, info.path);
        }
        if info.version < 1 || !versions.insert((&info.project, &info.path, info.version)) {
            anyhow::bail!("file #{} has an invalid or repeated version", info.id);
        }
        if !FILE_KINDS.contains(&info.kind.as_str()) {
            anyhow::bail!("file #{} has an unknown kind \"{}\"", info.id, info.kind);
        }
        if !FILE_ENCODINGS.contains(&info.encoding.as_str()) {
            anyhow::bail!(
                "file #{} has an unknown encoding \"{}\"",
                info.id,
                info.encoding
            );
        }
    }
    Ok(())
}

/// The start-up migration: creates missing tables, indexes and triggers,
/// adds missing columns, rebuilds an outdated full-text index and records
/// the schema version. Additive only, and safe to run again.
fn migrate(conn: &Connection) -> Result<()> {
    conn.execute_batch(SCHEMA)?;
    conn.execute_batch(agents::SCHEMA)?;
    conn.execute_batch(builtin::SCHEMA)?;
    add_missing_columns(conn)?;
    migrate_fts(conn)?;
    // A database from before the registry: every agent it has seen gets a
    // registry row, once, so it can have an avatar and be disabled.
    if schema_version(conn)? < 2 {
        agents::backfill_registry(conn)?;
    }
    // Never lowered: a database a newer build wrote keeps its number.
    if schema_version(conn)? < SCHEMA_VERSION {
        set_meta(conn, "schema_version", &SCHEMA_VERSION.to_string())?;
    }
    Ok(())
}

/// The `schema_version` a database records; 0 when it has none.
fn schema_version(conn: &Connection) -> Result<i64> {
    let has_meta: bool = conn.query_row(
        "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type = 'table' AND name = 'meta'",
        [],
        |row| row.get(0),
    )?;
    if !has_meta {
        return Ok(0);
    }
    Ok(meta_value(conn, "schema_version")?
        .trim()
        .parse()
        .unwrap_or(0))
}

/// Copies every page in one step: the connection lock is held anyway, and
/// rusqlite's own loop sleeps between small steps.
fn run_backup(backup: &rusqlite::backup::Backup<'_, '_>) -> Result<()> {
    use rusqlite::backup::StepResult;
    loop {
        match backup.step(-1)? {
            StepResult::Done => return Ok(()),
            StepResult::More => continue,
            StepResult::Busy | StepResult::Locked => {
                anyhow::bail!("the database is busy; try again")
            }
            _ => anyhow::bail!("the backup stopped unexpectedly"),
        }
    }
}

fn table_counts(conn: &Connection) -> Result<Vec<(String, i64)>> {
    let names: Vec<String> = conn
        .prepare(
            "SELECT name FROM sqlite_master WHERE type = 'table'
               AND name NOT LIKE 'sqlite_%' AND name NOT LIKE 'entries_fts%'
             ORDER BY name",
        )?
        .query_map([], |row| row.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    let mut counts = Vec::with_capacity(names.len());
    for name in names {
        let count: i64 = conn.query_row(
            &format!("SELECT COUNT(*) FROM \"{}\"", name.replace('"', "\"\"")),
            [],
            |row| row.get(0),
        )?;
        counts.push((name, count));
    }
    Ok(counts)
}

/// Checks an uploaded full backup without changing it: the SQLite header,
/// that it opens read-only, `PRAGMA integrity_check`, the `entries` table
/// with the columns the oldest schema has, and a schema no newer than this
/// build understands.
pub fn check_full_backup(path: &Path) -> std::result::Result<(), Refusal> {
    use std::io::Read;
    let mut header = [0u8; 16];
    let read = std::fs::File::open(path).and_then(|mut file| file.read_exact(&mut header));
    if read.is_err() || &header != b"SQLite format 3\0" {
        return Err(Refusal::new(
            "header",
            "the file is not a SQLite database (its header is wrong)",
        ));
    }
    let conn = Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .and_then(|conn| harden(&conn).map(|()| conn))
    .map_err(|_| Refusal::new("open", "the file cannot be opened as a SQLite database"))?;
    let integrity: std::result::Result<Vec<String>, rusqlite::Error> =
        conn.prepare("PRAGMA integrity_check").and_then(|mut stmt| {
            stmt.query_map([], |row| row.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()
        });
    match integrity {
        Ok(rows) if rows == ["ok"] => {}
        Ok(rows) => {
            return Err(Refusal::new(
                "integrity",
                format!(
                    "the database is damaged: integrity_check reported {}",
                    rows.first()
                        .map(|row| row.chars().take(160).collect::<String>())
                        .unwrap_or_else(|| "nothing".into())
                ),
            ));
        }
        Err(_) => {
            return Err(Refusal::new(
                "integrity",
                "the database is damaged: integrity_check could not run",
            ));
        }
    }
    let columns: Vec<String> = conn
        .prepare("SELECT name FROM pragma_table_info('entries')")
        .and_then(|mut stmt| {
            stmt.query_map([], |row| row.get(0))?
                .collect::<rusqlite::Result<_>>()
        })
        .map_err(|_| Refusal::new("schema", "the database schema cannot be read"))?;
    if columns.is_empty() {
        return Err(Refusal::new(
            "schema",
            "the database has no entries table, so it is not a lore database",
        ));
    }
    if let Some(missing) = OLDEST_ENTRY_COLUMNS
        .iter()
        .find(|name| !columns.iter().any(|column| column == *name))
    {
        return Err(Refusal::new(
            "schema",
            format!("the entries table has no {missing} column, so it is not a lore database"),
        ));
    }
    let version = schema_version(&conn)
        .map_err(|_| Refusal::new("schema", "the database schema cannot be read"))?;
    if version > SCHEMA_VERSION {
        return Err(Refusal::new(
            "version",
            format!(
                "the backup comes from a newer lore (schema {version}); this build understands \
                 schema {SCHEMA_VERSION}. Update lore first."
            ),
        ));
    }
    check_schema_objects(&conn)?;
    Ok(())
}

/// The FTS5 shadow tables of `entries_fts`. Lore's index keeps its content
/// in `entries`, so `_content` never exists; it is accepted all the same,
/// since it holds nothing that could run.
const FTS_SHADOW_TABLES: &[&str] = &[
    "entries_fts_data",
    "entries_fts_idx",
    "entries_fts_content",
    "entries_fts_docsize",
    "entries_fts_config",
];

/// Makes a connection to a database lore did not write safe to read and
/// migrate: SQL in its schema may call only innocuous functions and
/// virtual tables (`trusted_schema` off), and the schema itself cannot be
/// tampered with through the connection (the defensive flag).
fn harden(conn: &Connection) -> rusqlite::Result<()> {
    use rusqlite::config::DbConfig;
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)?;
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA, false)?;
    conn.pragma_update(None, "trusted_schema", false)?;
    Ok(())
}

/// Every schema object a fresh, migrated empty database holds: (type,
/// name) with its SQL.
fn expected_objects() -> Result<HashMap<(String, String), Option<String>>> {
    let conn = Connection::open_in_memory()?;
    migrate(&conn)?;
    let mut stmt = conn.prepare("SELECT type, name, sql FROM sqlite_master")?;
    let rows = stmt.query_map([], |row| Ok(((row.get(0)?, row.get(1)?), row.get(2)?)))?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// Refuses a backup whose schema holds anything lore's own schema does not
/// create: a view, a trigger other than the full-text index's own (with
/// the SQL lore writes), a table or an index lore does not have, or a
/// virtual table other than the full-text index. Restoring such a file
/// would plant objects that run SQL inside the live database. SQLite's
/// own objects (`sqlite_sequence`, the statistics tables, the automatic
/// indexes of lore's tables) and the full-text index's shadow tables pass.
fn check_schema_objects(conn: &Connection) -> std::result::Result<(), Refusal> {
    let unreadable = || Refusal::new("schema", "the database schema cannot be read");
    let expected = expected_objects().map_err(|_| unreadable())?;
    let lore_tables: Vec<&str> = expected
        .keys()
        .filter(|(kind, _)| kind == "table")
        .map(|(_, name)| name.as_str())
        .collect();
    let found: Vec<(String, String, String, Option<String>)> = conn
        .prepare("SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY rowid")
        .and_then(|mut stmt| {
            stmt.query_map([], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })?
            .collect::<rusqlite::Result<_>>()
        })
        .map_err(|_| unreadable())?;
    for (kind, name, table, sql) in found {
        let shown: String = name.chars().take(80).collect();
        let foreign = |what: &str| {
            Refusal::new(
                "objects",
                format!(
                    "the database holds the {what} \"{shown}\", which lore's schema does not \
                     create; a full backup made by lore never has one, so it is refused"
                ),
            )
        };
        let known = expected.get(&(kind.clone(), name.clone()));
        let virtual_table = sql.as_deref().is_some_and(|sql| {
            sql.trim_start()
                .to_ascii_uppercase()
                .starts_with("CREATE VIRTUAL")
        });
        match kind.as_str() {
            "view" => return Err(foreign("view")),
            "trigger" => {
                if known.is_none_or(|lore_sql| *lore_sql != sql) {
                    return Err(foreign("trigger"));
                }
            }
            "table" => {
                let internal = matches!(
                    name.as_str(),
                    "sqlite_sequence" | "sqlite_stat1" | "sqlite_stat4"
                );
                let shadow = FTS_SHADOW_TABLES.contains(&name.as_str());
                if !(known.is_some() || internal || shadow) {
                    return Err(foreign("table"));
                }
                // Only the full-text index is a virtual table, and only an
                // FTS5 one.
                let fts5 = sql.as_deref().is_some_and(|sql| {
                    sql.to_ascii_lowercase()
                        .split_whitespace()
                        .collect::<Vec<_>>()
                        .windows(2)
                        .any(|pair| pair[0] == "using" && pair[1].starts_with("fts5"))
                });
                if virtual_table && !(name == "entries_fts" && fts5) {
                    return Err(foreign("virtual table"));
                }
            }
            "index" => {
                let automatic = name.starts_with("sqlite_autoindex_")
                    && sql.is_none()
                    && (lore_tables.contains(&table.as_str())
                        || FTS_SHADOW_TABLES.contains(&table.as_str()));
                if !(known.is_some() || automatic) {
                    return Err(foreign("index"));
                }
            }
            _ => return Err(foreign(&kind)),
        }
    }
    Ok(())
}

/// Brings a checked full backup up to this build's schema in place, so an
/// older backup gains the newer tables and columns before it replaces
/// anything, and rebuilds its full-text index.
pub fn prepare_full_backup(path: &Path) -> std::result::Result<(), Refusal> {
    let prepared = (|| -> Result<()> {
        let conn = Connection::open(path)?;
        harden(&conn)?;
        conn.pragma_update(None, "busy_timeout", 5000)?;
        // The full-text index and its triggers are always lore's own: they
        // are dropped here and created again from lore's schema below, so
        // nothing the file defined for them survives.
        conn.execute_batch(
            "DROP TRIGGER IF EXISTS entries_ai; DROP TRIGGER IF EXISTS entries_ad;
             DROP TRIGGER IF EXISTS entries_au; DROP TABLE IF EXISTS entries_fts;",
        )?;
        migrate(&conn)?;
        conn.execute(
            "INSERT INTO entries_fts (entries_fts) VALUES ('rebuild')",
            [],
        )?;
        Ok(())
    })();
    prepared.map_err(|error| {
        Refusal::new(
            "migrate",
            format!("the backup could not be brought up to this build's schema: {error}"),
        )
    })
}

/// Removes a database file and the journal files SQLite may keep next to
/// it.
pub fn remove_database_files(path: &Path) {
    let _ = std::fs::remove_file(path);
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut name = path.as_os_str().to_owned();
        name.push(suffix);
        let _ = std::fs::remove_file(PathBuf::from(name));
    }
}

/// How old one of lore's temporary files must be before the periodic
/// sweep removes it.
pub const TEMP_MAX_AGE: std::time::Duration = std::time::Duration::from_secs(60 * 60);

/// Whether a file name is one of lore's temporary files, exactly as
/// [`Db::temp_path_with`] makes them: `.lore-tmp-<label>-<16 hex>.<ext>`
/// (label: lower-case letters and `-`; ext: lower-case letters), or one of
/// SQLite's companions of such a file (`-journal`, `-wal`, `-shm`).
pub fn is_temp_name(name: &str) -> bool {
    let Some(rest) = name.strip_prefix(TEMP_PREFIX) else {
        return false;
    };
    let rest = ["-journal", "-wal", "-shm"]
        .iter()
        .find_map(|suffix| rest.strip_suffix(suffix))
        .unwrap_or(rest);
    let Some((stem, extension)) = rest.rsplit_once('.') else {
        return false;
    };
    let Some((label, random)) = stem.rsplit_once('-') else {
        return false;
    };
    !label.is_empty()
        && label.chars().all(|c| c.is_ascii_lowercase() || c == '-')
        && random.len() == 16
        && random.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f'))
        && !extension.is_empty()
        && extension.chars().all(|c| c.is_ascii_lowercase())
}

/// Removes lore's temporary files in `dir` older than `age` (regular files
/// only; a link is never followed). Answers how many went.
fn sweep_temp_files(dir: &Path, age: std::time::Duration) -> usize {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    let mut removed = 0;
    for item in entries.flatten() {
        let name = item.file_name().to_string_lossy().into_owned();
        if !is_temp_name(&name) {
            continue;
        }
        let Ok(meta) = std::fs::symlink_metadata(item.path()) else {
            continue;
        };
        let old = meta
            .modified()
            .ok()
            .and_then(|modified| modified.elapsed().ok())
            .is_some_and(|elapsed| elapsed > age);
        if meta.is_file() && old && std::fs::remove_file(item.path()).is_ok() {
            removed += 1;
        }
    }
    removed
}

/// Keeps the newest `keep` safety copies in `dir`, by the time each was
/// written, then by name.
fn prune_snapshots(dir: &Path, keep: usize) -> Result<()> {
    let mut found: Vec<(std::time::SystemTime, String)> = std::fs::read_dir(dir)?
        .flatten()
        .filter_map(|item| {
            let name = item.file_name().to_string_lossy().into_owned();
            if !(name.starts_with(SNAPSHOT_PREFIX) && name.ends_with(".sqlite")) {
                return None;
            }
            let written = item.metadata().and_then(|meta| meta.modified()).ok()?;
            Some((written, name))
        })
        .collect();
    found.sort();
    let excess = found.len().saturating_sub(keep);
    for (_, name) in &found[..excess] {
        std::fs::remove_file(dir.join(name))
            .with_context(|| format!("removing the old safety copy {name}"))?;
    }
    Ok(())
}

/// The current UTC time as `YYYYMMDD-HHMMSS`, for file names.
pub fn utc_stamp() -> String {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0);
    let (days, rest) = (seconds.div_euclid(86_400), seconds.rem_euclid(86_400));
    // Howard Hinnant's days-to-civil conversion.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}{month:02}{day:02}-{:02}{:02}{:02}",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    )
}

fn get_user(conn: &Connection, id: i64) -> Result<Option<User>> {
    let sql = format!("SELECT {USER_COLUMNS} FROM users WHERE id = ?1");
    Ok(conn
        .query_row(&sql, params![id], User::from_row)
        .optional()?)
}

/// Refuses a user name or e-mail address another user already has.
fn refuse_taken(
    conn: &Connection,
    except: Option<i64>,
    username: Option<&str>,
    email: Option<&str>,
) -> Result<()> {
    let except = except.unwrap_or(-1);
    if let Some(username) = username {
        let taken: bool = conn.query_row(
            "SELECT COUNT(*) > 0 FROM users WHERE username = ?1 AND id != ?2",
            params![username, except],
            |row| row.get(0),
        )?;
        if taken {
            anyhow::bail!("the user name \"{username}\" is taken");
        }
    }
    if let Some(email) = email {
        let taken: bool = conn.query_row(
            "SELECT COUNT(*) > 0 FROM users WHERE email = ?1 AND id != ?2",
            params![email, except],
            |row| row.get(0),
        )?;
        if taken {
            anyhow::bail!("another user has that e-mail address");
        }
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

/// Inserts a new open session and returns it. The id is "s_" plus 24
/// random hex characters.
fn insert_session(conn: &Connection, new: &NewSession) -> Result<Session> {
    let id = new_session_id()?;
    let project = rename::resolve_alias(conn, &new.project)?;
    conn.execute(
        "INSERT INTO sessions (id, agent, project, path, repo, commit_hash, branch,
                                title, status, summary, started_at, last_seen_at,
                                implicit)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'open', '',
                 strftime('%Y-%m-%dT%H:%M:%SZ', 'now'),
                 strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), ?9)",
        params![
            id,
            new.agent,
            project,
            new.path,
            new.repo,
            new.commit,
            new.branch,
            new.title,
            new.implicit
        ],
    )?;
    get_session(conn, &id)?.context("session vanished after insert")
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

fn get_task(conn: &Connection, id: i64) -> Result<Option<Task>> {
    let sql = format!("SELECT {TASK_COLUMNS} FROM tasks WHERE id = ?1");
    Ok(conn
        .query_row(&sql, params![id], Task::from_row)
        .optional()?)
}

fn get_message(conn: &Connection, id: i64) -> Result<Option<Message>> {
    let sql = format!("SELECT {MESSAGE_COLUMNS} FROM messages WHERE id = ?1");
    Ok(conn
        .query_row(&sql, params![id], Message::from_row)
        .optional()?)
}

/// `?, ?, ?` for an IN list of `count` values.
fn placeholders(count: usize) -> String {
    vec!["?"; count].join(", ")
}

/// Checks and normalises a task's project, title and body. Agent and
/// project names are lowercase everywhere else, so they are here too.
fn normalize_task(project: &str, title: &str, body: &str) -> Result<(String, String, String)> {
    let project = normalize_project(project)?;
    let title = title.trim();
    if title.is_empty() {
        anyhow::bail!("the task title must not be empty");
    }
    if title.chars().count() > TASK_TITLE_MAX_CHARS {
        anyhow::bail!("the task title must be at most {TASK_TITLE_MAX_CHARS} characters");
    }
    let body = body.trim();
    if body.chars().count() > BODY_MAX_CHARS {
        anyhow::bail!("the task body must be at most {BODY_MAX_CHARS} characters");
    }
    Ok((project, title.to_string(), body.to_string()))
}

/// Checks and normalises a message: its kind, its project and its body.
fn normalize_message(kind: &str, project: &str, body: &str) -> Result<(String, String, String)> {
    let kind = kind.trim().to_lowercase();
    if !MESSAGE_KINDS.contains(&kind.as_str()) {
        anyhow::bail!("kind must be one of: {}", MESSAGE_KINDS.join(", "));
    }
    let project = project.trim().to_lowercase();
    if kind == "handoff" && project.is_empty() {
        anyhow::bail!("a handoff note must name its project");
    }
    let body = body.trim();
    if body.is_empty() {
        anyhow::bail!("the message body must not be empty");
    }
    if body.chars().count() > BODY_MAX_CHARS {
        anyhow::bail!("the message body must be at most {BODY_MAX_CHARS} characters");
    }
    Ok((kind, project, body.to_string()))
}

/// A file's project: lowercase and not empty, like every project name.
fn normalize_file_project(project: &str) -> Result<String> {
    normalize_project(project)
}

/// One of `PROVIDERS` or the mailbox, lowercased: what the level table,
/// the operations log and removing a vault row accept. Reading and
/// writing a service credential stays with `normalize_provider`, so the
/// HTTP path can never pick up the mailbox's row.
fn normalize_level_provider(provider: &str) -> Result<String> {
    let provider = provider.trim().to_lowercase();
    if provider == MAIL_PROVIDER {
        Ok(provider)
    } else {
        normalize_provider(&provider).map_err(|_| {
            anyhow::anyhow!(
                "provider must be one of: {}, {MAIL_PROVIDER}",
                PROVIDERS.join(", ")
            )
        })
    }
}

/// One of `PROVIDERS`, lowercased: the fixed list everywhere a provider
/// is named.
fn normalize_provider(provider: &str) -> Result<String> {
    let provider = provider.trim().to_lowercase();
    if PROVIDERS.contains(&provider.as_str()) {
        Ok(provider)
    } else {
        anyhow::bail!("provider must be one of: {}", PROVIDERS.join(", "));
    }
}

/// A file's name or relative path: forward slashes, no leading slash, no
/// empty, `.` or `..` segments, no control characters, at most
/// `FILE_PATH_MAX_CHARS` characters.
pub fn normalize_file_path(path: &str) -> Result<String> {
    let path = path.trim().replace('\\', "/");
    if path.chars().any(char::is_control) {
        anyhow::bail!("the file path must not contain control characters");
    }
    let mut segments = Vec::new();
    for segment in path.split('/') {
        // Each segment is trimmed as it is kept, so `keys/server.pem /`
        // cannot hide a key file's name behind a space.
        match segment.trim() {
            "" | "." => {}
            ".." => anyhow::bail!("the file path must not contain a `..` segment"),
            segment => segments.push(segment),
        }
    }
    let path = segments.join("/");
    if path.is_empty() {
        anyhow::bail!("the file path must not be empty");
    }
    if path.chars().count() > FILE_PATH_MAX_CHARS {
        anyhow::bail!("the file path must be at most {FILE_PATH_MAX_CHARS} characters");
    }
    Ok(path)
}

/// The refusal every secret gets, whatever gave it away.
const SECRET_REFUSAL: &str = "lore does not store secrets";

/// Refuses paths that name an environment file or a private key.
fn refuse_secret_path(path: &str) -> Result<()> {
    let name = path.rsplit('/').next().unwrap_or(path).to_lowercase();
    let secret = name == ".env"
        || name.starts_with(".env.")
        || [".pem", ".key", "id_rsa", "id_ed25519"]
            .iter()
            .any(|suffix| name.ends_with(suffix));
    if secret {
        anyhow::bail!("{SECRET_REFUSAL}: `{path}` looks like an environment file or a key");
    }
    Ok(())
}

/// Refuses content that holds a private key: a PEM header, that is
/// `-----BEGIN `, then only uppercase letters, digits and spaces (`RSA `,
/// `OPENSSH `, `ENCRYPTED `, or nothing), then `PRIVATE KEY-----`. Text that
/// merely mentions the two markers apart is fine. The raw bytes are checked,
/// so a key sent as base64 is refused too.
fn refuse_secret_content(content: &[u8]) -> Result<()> {
    const BEGIN: &[u8] = b"-----BEGIN ";
    const END: &[u8] = b"PRIVATE KEY-----";
    let mut rest = content;
    while let Some(start) = find_bytes(rest, BEGIN) {
        let after = &rest[start + BEGIN.len()..];
        let label = after
            .iter()
            .take_while(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || **byte == b' ')
            .count();
        // `PRIVATE KEY` is itself made of label characters, so the run of
        // them swallows it; a header is a run that ends in it, right before
        // the closing dashes.
        let words = END.len() - "-----".len();
        if label >= words && after[label - words..].starts_with(END) {
            anyhow::bail!("{SECRET_REFUSAL}: the content holds a private key");
        }
        rest = after;
    }
    Ok(())
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// One of `FILE_KINDS`; empty means "other".
fn normalize_file_kind(kind: &str) -> Result<String> {
    let kind = kind.trim().to_lowercase();
    if kind.is_empty() {
        return Ok("other".into());
    }
    if !FILE_KINDS.contains(&kind.as_str()) {
        anyhow::bail!("kind must be one of: {}", FILE_KINDS.join(", "));
    }
    Ok(kind)
}

/// One of `FILE_ENCODINGS`; empty means "utf8".
fn normalize_file_encoding(encoding: &str) -> Result<String> {
    let encoding = encoding.trim().to_lowercase();
    match encoding.as_str() {
        "" | "utf8" | "utf-8" | "text" => Ok("utf8".into()),
        "base64" => Ok(encoding),
        _ => anyhow::bail!("encoding must be one of: {}", FILE_ENCODINGS.join(", ")),
    }
}

fn normalize_file_description(description: &str) -> Result<String> {
    let description = description.trim();
    if description.is_empty() {
        anyhow::bail!("the description must say why the file matters");
    }
    if description.chars().count() > FILE_DESCRIPTION_MAX_CHARS {
        anyhow::bail!("the description must be at most {FILE_DESCRIPTION_MAX_CHARS} characters");
    }
    Ok(description.to_string())
}

/// The raw bytes of a file as it was sent: the text itself, or the
/// decoded base64. At most `FILE_MAX_BYTES`.
fn decode_file_content(encoding: &str, content: &str) -> Result<Vec<u8>> {
    let too_big = || {
        anyhow::anyhow!(
            "the file is larger than {} MiB; lore keeps small files that matter, not large ones",
            FILE_MAX_BYTES / (1024 * 1024)
        )
    };
    let bytes = if encoding == "base64" {
        use base64::Engine;
        // Whitespace from line-wrapped base64 is dropped first.
        let compact: String = content.split_whitespace().collect();
        if compact.len() > FILE_MAX_BYTES.div_ceil(3) * 4 {
            return Err(too_big());
        }
        base64::engine::general_purpose::STANDARD
            .decode(compact.as_bytes())
            .map_err(|_| anyhow::anyhow!("the content is not valid base64"))?
    } else {
        // Text arrives as a string, so it is valid UTF-8 already.
        content.as_bytes().to_vec()
    };
    if bytes.len() > FILE_MAX_BYTES {
        return Err(too_big());
    }
    if encoding != "base64" && std::str::from_utf8(&bytes).is_err() {
        anyhow::bail!("utf8 content must be valid UTF-8; send binary files as base64");
    }
    Ok(bytes)
}

/// Lowercase hex SHA-256 of the raw bytes.
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The lowercase words of a file search: the same words the full-text
/// query keeps, plus the whole query when it is more than one word or
/// looks like a path.
fn file_search_terms(query: &str) -> Vec<String> {
    let mut terms: Vec<String> = Vec::new();
    for word in query.split(|c: char| !(c.is_alphanumeric() || c == '_')) {
        let chars = word.chars().count();
        let has_digit = word.chars().any(|c| c.is_ascii_digit());
        if chars < 2 || (chars == 2 && !has_digit) {
            continue;
        }
        let word = word.to_lowercase();
        if STOPWORDS.contains(&word.as_str()) || terms.contains(&word) {
            continue;
        }
        terms.push(word);
    }
    let whole = query.trim().to_lowercase();
    if whole.chars().count() >= 3 && !terms.contains(&whole) {
        terms.push(whole);
    }
    terms
}

fn get_file_info(conn: &Connection, id: i64) -> Result<Option<FileInfo>> {
    let sql = format!("SELECT {FILE_COLUMNS} FROM files WHERE id = ?1");
    Ok(conn
        .query_row(&sql, params![id], FileInfo::from_row)
        .optional()?)
}

/// Reads one operations log row.
fn op_log_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<OpLog> {
    Ok(OpLog {
        id: row.get(0)?,
        agent: row.get(1)?,
        session_id: row.get(2)?,
        provider: row.get(3)?,
        method: row.get(4)?,
        path: row.get(5)?,
        status: row.get(6)?,
        outcome: row.get(7)?,
        detail: row.get(8)?,
        duration_ms: row.get(9)?,
        created_at: row.get(10)?,
    })
}

/// Reads `FILE_COLUMNS` followed by `content`.
fn stored_file_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredFile> {
    Ok(StoredFile {
        info: FileInfo::from_row(row)?,
        content: row.get(13)?,
    })
}

/// True when the backup's vectors came from the model in use here.
fn same_embedding_model(conn: &Connection, backup: &Backup) -> Result<bool> {
    let current: Option<String> = conn
        .query_row(
            "SELECT value FROM meta WHERE key = 'embedding_model'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    Ok(backup.embedding_model.is_some() && backup.embedding_model == current)
}

/// A backup file's raw bytes, checked against its size and hash, and its
/// vector when that can be reused.
fn decode_backup_file(file: &BackupFile, same_model: bool) -> Result<(Vec<u8>, Option<Vec<u8>>)> {
    use base64::Engine;
    let id = file.info.id;
    let content = base64::engine::general_purpose::STANDARD
        .decode(&file.content)
        .map_err(|_| anyhow::anyhow!("the content of file #{id} is not valid base64"))?;
    if content.len() as i64 != file.info.size || sha256_hex(&content) != file.info.sha256 {
        anyhow::bail!("the content of file #{id} does not match its size and hash");
    }
    let embedding = match (&file.embedding, same_model) {
        (Some(encoded), true) => {
            let blob = base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .map_err(|_| anyhow::anyhow!("the embedding of file #{id} is not valid base64"))?;
            if blob.is_empty() || blob.len() % 4 != 0 {
                anyhow::bail!("the embedding of file #{id} has an invalid length");
            }
            Some(blob)
        }
        _ => None,
    };
    Ok((content, embedding))
}

/// Writes one file row from a backup: under its own id for a restore, or
/// under a new one for a merge.
fn insert_backup_file(
    conn: &Connection,
    id: Option<i64>,
    info: &FileInfo,
    version: i64,
    content: &[u8],
) -> Result<()> {
    conn.execute(
        "INSERT INTO files (id, project, path, version, kind, description, encoding, content,
                            size, sha256, entry_id, agent, session_id, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
        params![
            id,
            info.project,
            info.path,
            version,
            info.kind,
            info.description,
            info.encoding,
            content,
            content.len() as i64,
            info.sha256,
            info.entry_id,
            info.agent,
            info.session_id,
            info.created_at
        ],
    )?;
    Ok(())
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

/// A project rule's target through the aliases: a rule written for a
/// renamed project's old name applies to the new one.
fn rule_target(conn: &Connection, scope: &str, target: String) -> Result<String> {
    if scope == "project" {
        rename::resolve_alias(conn, &target)
    } else {
        Ok(target)
    }
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
/// For each vector, the others at least `min_similarity` alike, by index
/// and in index order, as one pass over every pair would find them. Each
/// pair is computed once, on as many threads as the machine offers (at
/// most 4). A worker that panics fails the whole answer rather than leave
/// links out.
fn similar_pairs(
    vectors: &[(i64, Vec<f32>)],
    min_similarity: f32,
) -> Result<Vec<Vec<(usize, f32)>>> {
    let n = vectors.len();
    let threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .clamp(1, 4)
        .min(n.max(1));
    // Rows are dealt round-robin, so the long first rows and the short last
    // ones (only j > i is computed) share out evenly.
    let upper: Vec<Vec<(usize, usize, f32)>> = std::thread::scope(|scope| -> Result<_> {
        let handles: Vec<_> = (0..threads)
            .map(|t| {
                scope.spawn(move || {
                    let mut found = Vec::new();
                    for i in (t..n).step_by(threads) {
                        for j in i + 1..n {
                            let similarity = dot(&vectors[i].1, &vectors[j].1);
                            if similarity >= min_similarity {
                                found.push((i, j, similarity));
                            }
                        }
                    }
                    found
                })
            })
            .collect();
        // Every worker is joined before any failure is answered.
        let joined: Vec<_> = handles.into_iter().map(|handle| handle.join()).collect();
        joined
            .into_iter()
            .map(|result| {
                result.map_err(|_| {
                    tracing::error!("a worker computing the graph's links panicked");
                    anyhow::anyhow!("computing the graph's links failed")
                })
            })
            .collect()
    })?;
    let mut rows: Vec<Vec<(usize, f32)>> = vec![Vec::new(); n];
    for (i, j, similarity) in upper.into_iter().flatten() {
        rows[i].push((j, similarity));
        rows[j].push((i, similarity));
    }
    for row in &mut rows {
        row.sort_by_key(|&(j, _)| j);
    }
    Ok(rows)
}

fn dot(a: &[f32], b: &[f32]) -> f32 {
    a.iter().zip(b).map(|(x, y)| x * y).sum()
}

#[cfg(test)]
mod tests {
    /// The owner's notes belong to one task: a board restore drops them,
    /// and a row left behind (an older binary's restore) never attaches to
    /// a new task that reuses the id.
    #[test]
    fn owner_notes_never_attach_to_another_task_with_the_same_id() {
        let dir = std::env::temp_dir().join(format!("lore-db-notes-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let db = super::Db::open(&dir.join("lore.db")).unwrap();
        let backup = db.export().unwrap();
        let new = |title: &str| super::NewTask {
            project: "shop".into(),
            title: title.into(),
            created_by: "admin".into(),
            ..Default::default()
        };
        let task = db.add_task(&new("old task")).unwrap();
        db.add_task_note(task.id, "luis", "only for the old task")
            .unwrap();
        assert_eq!(db.task_notes(&[task.id]).unwrap()[&task.id].len(), 1);
        db.restore(&backup).unwrap();
        // The restore dropped the notes and restarted the ids.
        db.execute_for_test(&format!(
            "INSERT INTO task_notes (task_id, author, body, task_created)
             VALUES ({}, 'luis', 'left behind', '1999-01-01T00:00:00Z')",
            task.id
        ));
        let reused = db.add_task(&new("new task")).unwrap();
        assert_eq!(reused.id, task.id, "the id is reused");
        assert!(db.task_notes(&[reused.id]).unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The parallel, once-per-pair similarity pass finds exactly what the
    /// plain pass over every ordered pair finds, in the same order.
    #[test]
    fn similar_pairs_match_the_plain_pass() {
        let mut seed = 7u64;
        let mut next = || {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            ((seed >> 33) as f32 / u32::MAX as f32) - 0.25
        };
        let vectors: Vec<(i64, Vec<f32>)> = (0..97)
            .map(|id| (id * 3, (0..16).map(|_| next()).collect()))
            .collect();
        for min in [-1.0, 0.0, 0.05, 0.2] {
            let fast = super::similar_pairs(&vectors, min).unwrap();
            for (i, (_, a)) in vectors.iter().enumerate() {
                let plain: Vec<(usize, f32)> = vectors
                    .iter()
                    .enumerate()
                    .filter(|(j, _)| *j != i)
                    .map(|(j, (_, b))| (j, super::dot(a, b)))
                    .filter(|(_, s)| *s >= min)
                    .collect();
                assert_eq!(fast[i], plain, "row {i} at {min}");
            }
        }
    }

    #[test]
    fn lore_s_git_proxy_addresses_stand_for_their_github_repository() {
        for address in [
            "http://lore:8081/git/github/me/shop.git",
            "https://lore.example/git/github-org/me/shop",
            "http://172.31.250.2:8081/git/github/me/shop/",
        ] {
            assert_eq!(
                lore_proxy_repo(address).as_deref(),
                Some("https://github.com/me/shop"),
                "{address}"
            );
            assert_eq!(
                parse_github_repo(address),
                Some(("me".into(), "shop".into())),
                "{address}"
            );
        }
        for other in [
            "http://lore:8081/git/gitlab/me/shop.git",
            "http://lore:8081/git/github/../shop.git",
            "http://lore:8081/git/github/me/shop/extra",
            "https://evil.example/me/shop",
        ] {
            assert_eq!(lore_proxy_repo(other), None, "{other}");
        }
    }

    use super::*;

    fn temp_db_named(name: &str) -> Db {
        let dir = std::env::temp_dir().join(format!("lore-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        Db::open(&dir.join("lore.db")).unwrap()
    }

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

    /// The implicit session `implicit_session` hands out, and whether it
    /// opened it.
    fn implicit(db: &Db, agent: &str) -> (Session, bool) {
        let new = NewSession {
            implicit: true,
            ..session(agent, "unknown", "Implicit")
        };
        match db.implicit_session(&new, 12).unwrap() {
            Implicit::Opened(session) => (session, true),
            Implicit::Reused(session) => (session, false),
        }
    }

    #[test]
    fn an_implicit_session_is_reused_per_agent_and_closed_when_idle() {
        let db = temp_db();
        let (first, opened) = implicit(&db, "claude");
        assert!(opened && first.implicit);
        let (again, opened) = implicit(&db, "claude");
        assert!(!opened);
        assert_eq!(again.id, first.id);
        // Another agent gets its own; a real session is never reused.
        let (other, opened) = implicit(&db, "codex");
        assert!(opened && other.id != first.id);
        let real = db.open_session(&session("gemini", "shop", "Real")).unwrap();
        assert!(!real.implicit);
        let (gemini, opened) = implicit(&db, "gemini");
        assert!(opened && gemini.id != real.id);
        // An idle one is closed, not reused.
        backdate(&db, 13);
        let (fresh, opened) = implicit(&db, "claude");
        assert!(opened && fresh.id != first.id);
        let stale = db.session(&first.id).unwrap().unwrap();
        assert_eq!(stale.status, "closed");
        // A real session of the same agent leaves the implicit one alone,
        // and it keeps being reused.
        let hello = db.open_session(&session("claude", "shop", "Real")).unwrap();
        let (same, opened) = implicit(&db, "claude");
        assert!(!opened && same.id == fresh.id && same.id != hello.id);
    }

    #[test]
    fn concurrent_implicit_calls_open_one_session() {
        let db = temp_db();
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let db = db.clone();
                std::thread::spawn(move || implicit(&db, "claude"))
            })
            .collect();
        let results: Vec<(Session, bool)> =
            handles.into_iter().map(|h| h.join().unwrap()).collect();
        assert_eq!(results.iter().filter(|(_, opened)| *opened).count(), 1);
        assert!(results.iter().all(|(s, _)| s.id == results[0].0.id));
        assert_eq!(db.sessions(Some("open"), None, 10).unwrap().len(), 1);
    }

    #[test]
    fn the_implicit_flag_survives_backups_and_old_backups_restore() {
        let db = temp_db();
        let (implicit, _) = implicit(&db, "claude");
        let real = db.open_session(&session("codex", "shop", "Real")).unwrap();
        let backup = db.export().unwrap();
        assert_eq!(backup.version, BACKUP_VERSION);
        db.restore(&backup).unwrap();
        assert!(db.session(&implicit.id).unwrap().unwrap().implicit);
        assert!(!db.session(&real.id).unwrap().unwrap().implicit);

        // A backup written before the flag existed has no `implicit` key:
        // it restores, and merges into an empty database, as not implicit.
        let mut value = serde_json::to_value(&backup).unwrap();
        for session in value["sessions"].as_array_mut().unwrap() {
            assert!(
                session
                    .as_object_mut()
                    .unwrap()
                    .remove("implicit")
                    .is_some()
            );
        }
        let old: Backup = serde_json::from_value(value).unwrap();
        db.restore(&old).unwrap();
        assert!(!db.session(&implicit.id).unwrap().unwrap().implicit);
        assert_eq!(db.sessions(None, None, 10).unwrap().len(), 2);

        let other = temp_db_named("implicit-merge");
        other.merge(&backup).unwrap();
        assert!(other.session(&implicit.id).unwrap().unwrap().implicit);
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
    fn backup_v4_round_trips_and_a_v2_file_still_restores() {
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
        assert_eq!(backup.version, BACKUP_VERSION);
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

    fn task(project: &str, title: &str) -> NewTask {
        NewTask {
            project: project.into(),
            title: title.into(),
            created_by: "claude".into(),
            ..Default::default()
        }
    }

    fn message(kind: &str, from: &str, to: &str, body: &str) -> NewMessage {
        NewMessage {
            kind: kind.into(),
            from_agent: from.into(),
            to_agent: to.into(),
            body: body.into(),
            ..Default::default()
        }
    }

    #[test]
    fn tasks_move_through_their_states() {
        let db = temp_db();
        let added = db
            .add_task(&NewTask {
                assignee: "Codex".into(),
                ..task("Shop", "Fix the checkout flow")
            })
            .unwrap();
        // Project and agent names are trimmed and lowercased.
        assert_eq!(
            (
                added.project.as_str(),
                added.assignee.as_str(),
                added.status.as_str()
            ),
            ("shop", "codex", "open")
        );
        assert!(
            db.add_task(&NewTask {
                title: "x".repeat(201),
                ..task("p", "t")
            })
            .is_err()
        );
        assert!(
            db.add_task(&NewTask {
                body: "x".repeat(4001),
                ..task("p", "t")
            })
            .is_err()
        );
        assert!(db.add_task(&task("", "t")).is_err());
        assert!(db.add_task(&task("p", "  ")).is_err());

        // A task is claimed, and only the claimer may release it.
        let claimed = db
            .update_task(added.id, "claim", "codex", None, None)
            .unwrap()
            .unwrap();
        assert_eq!(
            (claimed.status.as_str(), claimed.claimed_by.as_str()),
            ("claimed", "codex")
        );
        let error = db
            .update_task(added.id, "claim", "claude", None, None)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("already claimed"),
            "unexpected error: {error}"
        );
        // The claimer claiming again changes nothing.
        assert!(
            db.update_task(added.id, "claim", "codex", None, None)
                .unwrap()
                .is_some()
        );
        let error = db
            .update_task(added.id, "release", "claude", None, None)
            .unwrap_err()
            .to_string();
        assert!(error.contains("may release"), "unexpected error: {error}");
        let released = db
            .update_task(added.id, "release", "codex", None, None)
            .unwrap()
            .unwrap();
        assert_eq!(
            (released.status.as_str(), released.claimed_by.as_str()),
            ("open", "")
        );
        // The admin may release any task.
        db.update_task(added.id, "claim", "codex", None, None)
            .unwrap();
        assert!(
            db.update_task(added.id, "release", "admin", None, None)
                .unwrap()
                .is_some()
        );

        // Done, with a commit and a note.
        let done = db
            .update_task(added.id, "done", "claude", Some("shipped"), Some("abc1234"))
            .unwrap()
            .unwrap();
        assert_eq!(done.status, "done");
        assert_eq!(done.done_by, "claude");
        assert!(done.done_at.is_some());
        assert_eq!(done.done_commit, "abc1234");
        assert_eq!(done.note, "shipped");
        // A done task refuses everything but reopening.
        for action in ["claim", "release", "done", "cancel"] {
            let error = db
                .update_task(added.id, action, "claude", None, None)
                .unwrap_err()
                .to_string();
            assert!(error.contains("is done"), "unexpected error: {error}");
        }
        // Reopening clears the claim and the done fields, keeps the note.
        let reopened = db
            .update_task(added.id, "reopen", "admin", None, None)
            .unwrap()
            .unwrap();
        assert_eq!(reopened.status, "open");
        assert_eq!(
            (
                reopened.claimed_by.as_str(),
                reopened.done_by.as_str(),
                reopened.done_commit.as_str()
            ),
            ("", "", "")
        );
        assert!(reopened.done_at.is_none());
        assert_eq!(reopened.note, "shipped");

        // Cancel from open, then reopen from cancelled.
        let cancelled = db
            .update_task(added.id, "cancel", "claude", None, None)
            .unwrap()
            .unwrap();
        assert_eq!(cancelled.status, "cancelled");
        let error = db
            .update_task(added.id, "cancel", "claude", None, None)
            .unwrap_err()
            .to_string();
        assert!(error.contains("is cancelled"), "unexpected error: {error}");
        assert_eq!(
            db.update_task(added.id, "reopen", "claude", None, None)
                .unwrap()
                .unwrap()
                .status,
            "open"
        );

        // Unknown ids and actions, and a note that is too long.
        assert!(
            db.update_task(999, "claim", "claude", None, None)
                .unwrap()
                .is_none()
        );
        assert!(
            db.update_task(added.id, "ship", "claude", None, None)
                .is_err()
        );
        assert!(
            db.update_task(added.id, "done", "claude", Some(&"x".repeat(1001)), None)
                .is_err()
        );
        assert_eq!(
            db.task(added.id).unwrap().unwrap().title,
            "Fix the checkout flow"
        );
    }

    #[test]
    fn tasks_list_claimed_first_then_open_then_the_rest() {
        let db = temp_db();
        let first = db.add_task(&task("shop", "first")).unwrap();
        let second = db.add_task(&task("shop", "second")).unwrap();
        let third = db.add_task(&task("shop", "third")).unwrap();
        db.add_task(&task("blog", "other project")).unwrap();
        db.update_task(second.id, "claim", "codex", None, None)
            .unwrap();
        db.update_task(third.id, "done", "codex", None, None)
            .unwrap();

        // Newest first within a status; claimed before open before the rest.
        let listed = db
            .tasks(Some("shop"), &["open", "claimed", "done"], 10)
            .unwrap();
        let ids: Vec<i64> = listed.iter().map(|task| task.id).collect();
        assert_eq!(ids, [second.id, first.id, third.id]);
        assert_eq!(db.tasks(Some("shop"), &["open"], 10).unwrap().len(), 1);
        assert_eq!(db.tasks(None, &[], 10).unwrap().len(), 4);
        let counts = db.board_counts().unwrap();
        assert_eq!((counts.open_tasks, counts.claimed_tasks), (2, 1));
    }

    #[test]
    fn messages_reach_their_reader_once() {
        let db = temp_db();
        let direct = db
            .add_message(&NewMessage {
                project: "shop".into(),
                to_agent: "codex".into(),
                ..message("message", "claude", "", "look at the webhook")
            })
            .unwrap();
        let broadcast = db
            .add_message(&message("message", "admin", "", "standup at ten"))
            .unwrap();
        // The author never sees their own message as unread.
        db.add_message(&NewMessage {
            to_agent: "codex".into(),
            ..message("message", "codex", "", "note to self")
        })
        .unwrap();
        // A handoff is never in an inbox, and needs its project.
        let handoff = db
            .add_message(&NewMessage {
                project: "shop".into(),
                ..message("handoff", "claude", "", "the migration is half done")
            })
            .unwrap();
        assert!(
            db.add_message(&message("handoff", "claude", "", "no project"))
                .is_err()
        );
        assert!(
            db.add_message(&message("letter", "claude", "", "no such kind"))
                .is_err()
        );

        // Codex sees the direct message and the broadcast, newest first.
        let ids: Vec<i64> = db
            .unread_messages("codex", None, 10)
            .unwrap()
            .iter()
            .map(|message| message.id)
            .collect();
        assert_eq!(ids, [broadcast.id, direct.id]);
        assert_eq!(db.unread_message_count("codex").unwrap(), 2);
        // Claude sees only the broadcast.
        let ids: Vec<i64> = db
            .unread_messages("claude", None, 10)
            .unwrap()
            .iter()
            .map(|message| message.id)
            .collect();
        assert_eq!(ids, [broadcast.id]);
        // The project filter only matches messages that carry it.
        assert!(
            db.unread_messages("codex", Some("blog"), 10)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            db.unread_messages("codex", Some("shop"), 10).unwrap().len(),
            1
        );

        // Reading marks exactly the given ids, once.
        assert_eq!(
            db.mark_read("codex", &[direct.id, 999]).unwrap(),
            [direct.id]
        );
        let ids: Vec<i64> = db
            .unread_messages("codex", None, 10)
            .unwrap()
            .iter()
            .map(|message| message.id)
            .collect();
        assert_eq!(ids, [broadcast.id]);
        assert_eq!(db.unread_message_count("codex").unwrap(), 1);
        let ids: Vec<i64> = db
            .read_messages("codex", None, 20)
            .unwrap()
            .iter()
            .map(|message| message.id)
            .collect();
        assert_eq!(ids, [direct.id]);
        // A second marking (another session of the same agent) gets nothing
        // back, so it has nothing to show as new.
        assert!(db.mark_read("codex", &[direct.id]).unwrap().is_empty());
        assert_eq!(db.read_messages("codex", None, 20).unwrap().len(), 1);

        // The board lists newest first, with the readers of each message.
        let board = db.messages(None, 10).unwrap();
        assert_eq!(board.len(), 4);
        assert_eq!(board[0].message.id, handoff.id);
        assert_eq!(
            board
                .iter()
                .find(|row| row.message.id == direct.id)
                .unwrap()
                .read_by,
            ["codex"]
        );
        assert!(
            board
                .iter()
                .find(|row| row.message.kind == "handoff")
                .unwrap()
                .read_by
                .is_empty()
        );
    }

    #[test]
    fn handoffs_are_delivered_once_and_not_to_their_writer() {
        let db = temp_db();
        let writer = db
            .open_session(&session("claude", "shop", "writing"))
            .unwrap();
        let note = db
            .add_message(&NewMessage {
                project: "shop".into(),
                session_id: Some(writer.id.clone()),
                ..message("handoff", "claude", "", "the migration is half done")
            })
            .unwrap();

        // The session that wrote it is not handed its own note, and other
        // projects see nothing of it.
        assert!(db.pending_handoffs("shop", &writer.id).unwrap().is_empty());
        assert!(db.pending_handoffs("blog", &writer.id).unwrap().is_empty());

        // The next session on the project gets it, exactly once.
        let reader = db
            .open_session(&session("codex", "shop", "reading"))
            .unwrap();
        let pending = db.pending_handoffs("shop", &reader.id).unwrap();
        let ids: Vec<i64> = pending.iter().map(|message| message.id).collect();
        assert_eq!(ids, [note.id]);
        // Delivering to the writing session itself is refused even when the
        // caller passes its id.
        assert!(
            db.deliver_handoffs(&ids, "claude", &writer.id)
                .unwrap()
                .is_empty()
        );
        // Two sessions that both saw it pending: only the first receives it.
        let racer = db
            .open_session(&session("gemini", "shop", "racing"))
            .unwrap();
        assert_eq!(db.pending_handoffs("shop", &racer.id).unwrap().len(), 1);
        assert_eq!(
            db.deliver_handoffs(&ids, "codex", &reader.id).unwrap(),
            [note.id]
        );
        assert!(
            db.deliver_handoffs(&ids, "gemini", &racer.id)
                .unwrap()
                .is_empty()
        );
        assert!(db.pending_handoffs("shop", &reader.id).unwrap().is_empty());
        let third = db
            .open_session(&session("claude", "shop", "third"))
            .unwrap();
        assert!(db.pending_handoffs("shop", &third.id).unwrap().is_empty());
        assert!(
            db.deliver_handoffs(&ids, "codex", &reader.id)
                .unwrap()
                .is_empty()
        );

        let delivered = &db.messages(Some("shop"), 10).unwrap()[0];
        assert_eq!(delivered.message.delivered_to, "codex");
        assert_eq!(
            delivered.message.delivered_session.as_deref(),
            Some(reader.id.as_str())
        );
        assert!(delivered.message.delivered_at.is_some());
        assert!(delivered.read_by.is_empty());
    }

    #[test]
    fn backup_v4_round_trips_the_board() {
        let db = temp_db();
        let task = db
            .add_task(&NewTask {
                project: "shop".into(),
                title: "Fix the checkout flow".into(),
                body: "see the failing tests".into(),
                assignee: "codex".into(),
                created_by: "claude".into(),
                session_id: Some("s_1".into()),
                ..Default::default()
            })
            .unwrap();
        db.update_task(task.id, "claim", "codex", Some("on it"), None)
            .unwrap();
        let direct = db
            .add_message(&NewMessage {
                project: "shop".into(),
                to_agent: "codex".into(),
                ..message("message", "admin", "", "check the claims")
            })
            .unwrap();
        db.mark_read("codex", &[direct.id]).unwrap();
        let note = db
            .add_message(&NewMessage {
                project: "shop".into(),
                ..message("handoff", "claude", "", "the migration is half done")
            })
            .unwrap();
        db.deliver_handoffs(&[note.id], "codex", "s_9").unwrap();

        let json = serde_json::to_string(&db.export().unwrap()).unwrap();
        let backup: Backup = serde_json::from_str(&json).unwrap();
        assert_eq!(backup.version, BACKUP_VERSION);
        assert_eq!(backup.tasks.len(), 1);
        assert_eq!(backup.messages.len(), 2);
        assert_eq!(backup.message_reads.len(), 1);

        // Diverge, then restore: the board is exactly the backup again.
        db.add_task(&NewTask {
            project: "blog".into(),
            title: "Discarded".into(),
            created_by: "admin".into(),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(db.restore(&backup).unwrap(), 0);
        let tasks = db.tasks(None, &[], 10).unwrap();
        assert_eq!(tasks.len(), 1);
        assert_eq!(tasks[0].id, task.id);
        assert_eq!(
            (
                tasks[0].status.as_str(),
                tasks[0].claimed_by.as_str(),
                tasks[0].note.as_str()
            ),
            ("claimed", "codex", "on it")
        );
        assert_eq!(tasks[0].session_id.as_deref(), Some("s_1"));
        let board = db.messages(Some("shop"), 10).unwrap();
        assert_eq!(board.len(), 2);
        assert_eq!(
            board
                .iter()
                .find(|row| row.message.kind == "handoff")
                .unwrap()
                .message
                .delivered_to,
            "codex"
        );
        assert_eq!(
            board
                .iter()
                .find(|row| row.message.id == direct.id)
                .unwrap()
                .read_by,
            ["codex"]
        );
        assert_eq!(db.unread_message_count("codex").unwrap(), 0);

        // Merging the same backup adds nothing; a changed copy adds only
        // what is new, with its read marks under the new ids.
        assert_eq!(db.merge(&backup).unwrap(), (0, 0));
        let mut diverged: Backup = serde_json::from_str(&json).unwrap();
        diverged.tasks[0].title = "A different title".into();
        diverged.messages.push(Message {
            id: 999,
            kind: "message".into(),
            project: String::new(),
            from_agent: "claude".into(),
            to_agent: String::new(),
            body: "extra".into(),
            session_id: None,
            created_at: "2026-11-25T12:00:00Z".into(),
            delivered_to: String::new(),
            delivered_session: None,
            delivered_at: None,
        });
        diverged.message_reads.push(MessageRead {
            message_id: 999,
            agent: "codex".into(),
            read_at: "2026-11-25T12:01:00Z".into(),
        });
        db.merge(&diverged).unwrap();
        assert_eq!(db.tasks(None, &[], 10).unwrap().len(), 2);
        assert_eq!(db.messages(None, 100).unwrap().len(), 3);
        let read = db.read_messages("codex", None, 20).unwrap();
        assert!(read.iter().any(|message| message.body == "extra"));
    }

    #[test]
    fn a_v3_backup_leaves_the_board_in_place() {
        let db = temp_db();
        let kept = db.add_task(&task("shop", "kept")).unwrap();
        let sent = db
            .add_message(&message("message", "claude", "", "kept too"))
            .unwrap();

        // A version 3 file: the same store without the board sections.
        let mut value = serde_json::to_value(db.export().unwrap()).unwrap();
        let object = value.as_object_mut().unwrap();
        for key in ["tasks", "messages", "message_reads"] {
            object.remove(key);
        }
        object.insert("version".into(), serde_json::json!(3));
        let v3: Backup = serde_json::from_value(value).unwrap();
        assert!(v3.tasks.is_empty() && v3.messages.is_empty());

        // The board moves on after the export; restoring the older file
        // replaces the entries but leaves the board alone.
        db.add_task(&task("shop", "added later")).unwrap();
        db.update_task(kept.id, "done", "claude", None, None)
            .unwrap();
        db.mark_read("codex", &[sent.id]).unwrap();
        db.restore(&v3).unwrap();
        let tasks = db.tasks(None, &[], 10).unwrap();
        assert_eq!(tasks.len(), 2);
        assert!(
            tasks
                .iter()
                .any(|task| task.id == kept.id && task.status == "done")
        );
        let board = db.messages(None, 10).unwrap();
        assert_eq!(board.len(), 1);
        assert_eq!(board[0].read_by, ["codex"]);
    }

    #[test]
    fn an_old_database_gains_the_board_tables() {
        let dir = std::env::temp_dir().join(format!("lore-board-migrate-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("lore.db");
        {
            // A Phase 1 database: sessions and entries, no board tables.
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE entries (id INTEGER PRIMARY KEY AUTOINCREMENT, project TEXT NOT NULL,
                 kind TEXT NOT NULL, title TEXT NOT NULL, body TEXT NOT NULL,
                 tags TEXT NOT NULL DEFAULT '', files TEXT NOT NULL DEFAULT '',
                 agent TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL DEFAULT 'x',
                 updated_at TEXT, embedding BLOB);
                 INSERT INTO entries (project, kind, title, body) VALUES ('p', 'note', 'old', 'entry');
                 CREATE TABLE sessions (id TEXT PRIMARY KEY, agent TEXT NOT NULL,
                 project TEXT NOT NULL, path TEXT NOT NULL DEFAULT '', repo TEXT NOT NULL DEFAULT '',
                 commit_hash TEXT NOT NULL DEFAULT '', branch TEXT NOT NULL DEFAULT '',
                 title TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open',
                 summary TEXT NOT NULL DEFAULT '', started_at TEXT NOT NULL, last_seen_at TEXT NOT NULL,
                 ended_at TEXT);
                 INSERT INTO sessions (id, agent, project, title, started_at, last_seen_at)
                 VALUES ('s_old', 'claude', 'shop', 'old chat', 'x', 'x');
                 CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                 INSERT INTO meta (key, value) VALUES ('embedding_model', 'kept-model');",
            )
            .unwrap();
        }
        let db = Db::open(&path).unwrap();
        // Nothing was lost, and the board works right away.
        assert_eq!(db.get(1).unwrap().unwrap().title, "old");
        let old = db.session("s_old").unwrap().unwrap();
        assert_eq!(old.agent, "claude");
        // The session gained the implicit flag, unset.
        assert!(!old.implicit);
        assert_eq!(db.sessions(None, None, 10).unwrap().len(), 1);
        db.add_task(&task("shop", "fresh")).unwrap();
        let sent = db
            .add_message(&message("message", "claude", "", "fresh too"))
            .unwrap();
        db.mark_read("codex", &[sent.id]).unwrap();
        assert_eq!(db.tasks(Some("shop"), &["open"], 10).unwrap().len(), 1);
        assert_eq!(db.unread_messages("codex", None, 10).unwrap().len(), 0);
        assert_eq!(db.board_counts().unwrap().open_tasks, 1);
        // Opening it again changes nothing.
        drop(db);
        let db = Db::open(&path).unwrap();
        assert_eq!(db.tasks(None, &[], 10).unwrap().len(), 1);
        assert_eq!(db.get(1).unwrap().unwrap().title, "old");
    }

    fn new_file(project: &str, path: &str, content: &str) -> NewFile {
        NewFile {
            project: project.into(),
            path: path.into(),
            kind: "doc".into(),
            description: "why it matters".into(),
            content: content.into(),
            agent: "claude".into(),
            ..Default::default()
        }
    }

    #[test]
    fn files_get_a_new_version_only_when_the_content_changes() {
        let db = temp_db();
        let first = db
            .save_file(&new_file("Shop", "docs/ideas.md", "one"))
            .unwrap();
        assert!(!first.unchanged && first.needs_embedding);
        assert_eq!(
            (
                first.file.project.as_str(),
                first.file.version,
                first.file.size
            ),
            ("shop", 1, 3)
        );
        assert_eq!(first.file.sha256, sha256_hex(b"one"));
        assert_eq!(first.file.encoding, "utf8");

        let second = db
            .save_file(&new_file("shop", "docs/ideas.md", "two"))
            .unwrap();
        assert!(!second.unchanged);
        assert_eq!(second.file.version, 2);

        // The same bytes again make no new version; a new description is
        // taken over, and the file needs a new vector for it.
        let same = db
            .save_file(&NewFile {
                description: "a better reason".into(),
                kind: "idea".into(),
                ..new_file("shop", "docs/ideas.md", "two")
            })
            .unwrap();
        assert!(same.unchanged && same.needs_embedding);
        assert_eq!(same.file.id, second.file.id);
        assert_eq!(
            (same.file.kind.as_str(), same.file.description.as_str()),
            ("idea", "a better reason")
        );
        let again = db
            .save_file(&NewFile {
                description: "a better reason".into(),
                kind: "idea".into(),
                ..new_file("shop", "docs/ideas.md", "two")
            })
            .unwrap();
        assert!(again.unchanged && !again.needs_embedding);
        assert_eq!(db.file_versions("shop", "docs/ideas.md").unwrap().len(), 2);

        // Going back to older content is a change too.
        let third = db
            .save_file(&new_file("shop", "docs/ideas.md", "one"))
            .unwrap();
        assert_eq!(third.file.version, 3);

        // A link to an entry must name one that exists.
        let linked = NewFile {
            entry_id: Some(999),
            ..new_file("shop", "a.md", "x")
        };
        assert!(db.save_file(&linked).is_err());
        let entry = db.insert(&entry("shop", "t", "b")).unwrap();
        let linked = NewFile {
            entry_id: Some(entry.id),
            ..new_file("shop", "a.md", "x")
        };
        assert_eq!(db.save_file(&linked).unwrap().file.entry_id, Some(entry.id));
    }

    #[test]
    fn file_paths_are_normalised_and_checked() {
        assert_eq!(
            normalize_file_path("  /docs\\ideas.md ").unwrap(),
            "docs/ideas.md"
        );
        assert_eq!(
            normalize_file_path("./a//b/./c.json").unwrap(),
            "a/b/c.json"
        );
        for bad in ["", "/", " ./ ", "../x", "a/../b", "a/..", "a\nb"] {
            assert!(normalize_file_path(bad).is_err(), "{bad:?} was accepted");
        }
        assert!(normalize_file_path(&"x".repeat(300)).is_ok());
        assert!(normalize_file_path(&"x".repeat(301)).is_err());

        let db = temp_db();
        let saved = db
            .save_file(&new_file("shop", "/docs/./schema.json", "{}"))
            .unwrap();
        assert_eq!(saved.file.path, "docs/schema.json");
        assert!(
            db.file_at("shop", "docs//schema.json", None)
                .unwrap()
                .is_some()
        );
        for (field, file) in [
            ("project", new_file(" ", "a.md", "x")),
            (
                "kind",
                NewFile {
                    kind: "secret".into(),
                    ..new_file("p", "a.md", "x")
                },
            ),
            (
                "encoding",
                NewFile {
                    encoding: "hex".into(),
                    ..new_file("p", "a.md", "x")
                },
            ),
            (
                "description",
                NewFile {
                    description: " ".into(),
                    ..new_file("p", "a.md", "x")
                },
            ),
            (
                "long description",
                NewFile {
                    description: "d".repeat(1001),
                    ..new_file("p", "a.md", "x")
                },
            ),
            (
                "agent",
                NewFile {
                    agent: String::new(),
                    ..new_file("p", "a.md", "x")
                },
            ),
        ] {
            assert!(db.save_file(&file).is_err(), "a bad {field} was accepted");
        }
        // An empty kind and encoding fall back to other and utf8.
        let plain = db
            .save_file(&NewFile {
                kind: String::new(),
                ..new_file("p", "plain.txt", "x")
            })
            .unwrap();
        assert_eq!(
            (plain.file.kind.as_str(), plain.file.encoding.as_str()),
            ("other", "utf8")
        );
    }

    #[test]
    fn secrets_are_refused() {
        use base64::Engine;
        let db = temp_db();
        for path in [
            ".env",
            "deploy/.env.production",
            "certs/server.PEM",
            "deploy.key",
            ".ssh/id_rsa",
            "keys/id_ed25519",
        ] {
            let error = db
                .save_file(&new_file("shop", path, "x"))
                .unwrap_err()
                .to_string();
            assert!(
                error.contains("lore does not store secrets"),
                "{path}: {error}"
            );
        }
        let key =
            "notes\n-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----\n"; // lore:allow-secret
        let error = db
            .save_file(&new_file("shop", "notes.md", key))
            .unwrap_err()
            .to_string();
        assert!(error.contains("lore does not store secrets"), "{error}");
        // The same key sent as base64 is refused too.
        let encoded = NewFile {
            encoding: "base64".into(),
            ..new_file(
                "shop",
                "notes.bin",
                &base64::engine::general_purpose::STANDARD.encode(key),
            )
        };
        assert!(db.save_file(&encoded).is_err());
        // Names that only look similar, and a public key, are fine.
        db.save_file(&new_file("shop", ".envrc.md", "x")).unwrap();
        db.save_file(&new_file(
            "shop",
            "docs/keys.md",
            "-----BEGIN PUBLIC KEY-----",
        ))
        .unwrap();
        assert!(db.files(None, 10).unwrap().len() == 2);
    }

    #[test]
    fn only_real_pem_private_key_headers_are_refused() {
        for header in [
            "-----BEGIN PRIVATE KEY-----",           // lore:allow-secret
            "-----BEGIN RSA PRIVATE KEY-----",       // lore:allow-secret
            "-----BEGIN OPENSSH PRIVATE KEY-----",   // lore:allow-secret
            "-----BEGIN EC PRIVATE KEY-----",        // lore:allow-secret
            "-----BEGIN ENCRYPTED PRIVATE KEY-----", // lore:allow-secret
            "-----BEGIN DSA2 PRIVATE KEY-----",      // lore:allow-secret
            "text before -----BEGIN RSA PRIVATE KEY----- text after", // lore:allow-secret
        ] {
            let content = format!("notes\n{header}\nMIIEabc\n");
            assert!(
                refuse_secret_content(content.as_bytes()).is_err(),
                "{header}"
            );
        }
        for text in [
            // Documentation that names the markers is fine.
            "A key starts with `-----BEGIN ` followed by `PRIVATE KEY-----`.",
            "-----BEGIN PUBLIC KEY-----",
            "-----BEGIN CERTIFICATE-----\nPRIVATE KEY-----",
            "-----BEGIN rsa PRIVATE KEY-----",
            "-----BEGIN PRIVATE KEY",
            "-----BEGIN PRIVATE KEY----",
            "PRIVATE KEY----- before -----BEGIN ",
        ] {
            assert!(refuse_secret_content(text.as_bytes()).is_ok(), "{text}");
        }
        // The documentation sentence is stored, also when sent as base64.
        use base64::Engine;
        let db = temp_db();
        let doc = "A PEM key starts with `-----BEGIN ` followed by `PRIVATE KEY-----`.\n";
        db.save_file(&new_file("shop", "docs/spec.md", doc))
            .unwrap();
        db.save_file(&NewFile {
            encoding: "base64".into(),
            ..new_file(
                "shop",
                "docs/spec.bin",
                &base64::engine::general_purpose::STANDARD.encode(doc),
            )
        })
        .unwrap();
    }

    #[test]
    fn files_over_two_mebibytes_are_refused() {
        use base64::Engine;
        let db = temp_db();
        let exact = "a".repeat(FILE_MAX_BYTES);
        assert_eq!(
            db.save_file(&new_file("p", "big.txt", &exact))
                .unwrap()
                .file
                .size,
            FILE_MAX_BYTES as i64
        );
        let over = "a".repeat(FILE_MAX_BYTES + 1);
        assert!(db.save_file(&new_file("p", "bigger.txt", &over)).is_err());
        let encoded = NewFile {
            encoding: "base64".into(),
            ..new_file(
                "p",
                "bigger.bin",
                &base64::engine::general_purpose::STANDARD.encode(vec![7u8; FILE_MAX_BYTES + 1]),
            )
        };
        assert!(db.save_file(&encoded).is_err());
        let invalid = NewFile {
            encoding: "base64".into(),
            ..new_file("p", "broken.bin", "not base64 at all!")
        };
        assert!(db.save_file(&invalid).is_err());
    }

    #[test]
    fn binary_files_round_trip_as_base64() {
        use base64::Engine;
        let db = temp_db();
        let bytes: Vec<u8> = (0..=255u8).cycle().take(1000).collect();
        let encoded = base64::engine::general_purpose::STANDARD.encode(&bytes);
        // Line-wrapped base64 is accepted too.
        let wrapped = encoded
            .as_bytes()
            .chunks(76)
            .map(|line| std::str::from_utf8(line).unwrap())
            .collect::<Vec<_>>()
            .join("\n");
        let saved = db
            .save_file(&NewFile {
                encoding: "base64".into(),
                kind: "data".into(),
                ..new_file("p", "assets/logo.png", &wrapped)
            })
            .unwrap();
        assert_eq!(saved.file.encoding, "base64");
        assert_eq!(saved.file.size, 1000);
        let stored = db.file(saved.file.id).unwrap().unwrap();
        assert_eq!(stored.content, bytes);
        assert_eq!(stored.info.sha256, sha256_hex(&bytes));
        // Binary content is not valid UTF-8, so it cannot be sent as text,
        // but text bytes may be sent as base64.
        let text = NewFile {
            encoding: "base64".into(),
            ..new_file(
                "p",
                "hello.txt",
                &base64::engine::general_purpose::STANDARD.encode("hello"),
            )
        };
        assert_eq!(db.save_file(&text).unwrap().file.size, 5);
    }

    #[test]
    fn files_list_only_the_latest_versions() {
        let db = temp_db();
        db.save_file(&new_file("shop", "a.md", "1")).unwrap();
        db.save_file(&new_file("shop", "a.md", "2")).unwrap();
        let b = db.save_file(&new_file("shop", "b.md", "1")).unwrap();
        db.save_file(&new_file("blog", "a.md", "1")).unwrap();

        let all = db.files(None, 10).unwrap();
        assert_eq!(all.len(), 3);
        let shop = db.files(Some("shop"), 10).unwrap();
        assert_eq!(
            shop.iter()
                .map(|f| (f.path.as_str(), f.version))
                .collect::<Vec<_>>(),
            [("b.md", 1), ("a.md", 2)]
        );
        assert_eq!(db.files(Some("shop"), 1).unwrap().len(), 1);

        let versions = db.file_versions("shop", "a.md").unwrap();
        assert_eq!(
            versions.iter().map(|f| f.version).collect::<Vec<_>>(),
            [2, 1]
        );
        assert_eq!(
            db.file_at("shop", "a.md", None).unwrap().unwrap().content,
            b"2"
        );
        assert_eq!(
            db.file_at("shop", "a.md", Some(1))
                .unwrap()
                .unwrap()
                .content,
            b"1"
        );
        assert!(db.file_at("shop", "a.md", Some(9)).unwrap().is_none());

        let counts = db.file_counts().unwrap();
        assert_eq!((counts.files, counts.versions, counts.bytes), (3, 4, 4));
        assert_eq!(db.project_file_count("shop").unwrap(), 2);

        // Deleting the latest version brings the previous one back to the
        // list; deleting the path removes every version.
        let deleted = db.delete_file(versions[0].id).unwrap().unwrap();
        assert_eq!(deleted.version, 2);
        assert!(db.delete_file(versions[0].id).unwrap().is_none());
        assert_eq!(
            db.files(Some("shop"), 10)
                .unwrap()
                .iter()
                .find(|f| f.path == "a.md")
                .unwrap()
                .version,
            1
        );
        assert_eq!(db.delete_file_path("shop", "a.md").unwrap(), 1);
        assert_eq!(db.delete_file_path("shop", "a.md").unwrap(), 0);
        let left = db.files(None, 10).unwrap();
        assert_eq!(left.len(), 2);
        assert!(left.iter().any(|f| f.id == b.file.id));
    }

    #[test]
    fn files_are_found_by_text_and_by_vector() {
        let db = temp_db();
        let ideas = db
            .save_file(&NewFile {
                description: "The principles the checkout is built on".into(),
                ..new_file("shop", "docs/ideas.md", "x")
            })
            .unwrap()
            .file;
        let schema = db
            .save_file(&NewFile {
                description: "Database layout".into(),
                ..new_file("shop", "schema.sql", "y")
            })
            .unwrap()
            .file;
        let other = db
            .save_file(&NewFile {
                description: "Checkout settings for the blog".into(),
                ..new_file("blog", "config.json", "z")
            })
            .unwrap()
            .file;
        db.set_file_embedding(ideas.id, &[1.0, 0.0]).unwrap();
        db.set_file_embedding(schema.id, &[0.0, 1.0]).unwrap();

        // Words match the path or the description, whatever their case.
        let hits = db.search_files("CHECKOUT", None, None, 0.8, 10).unwrap();
        assert_eq!(hits.len(), 2);
        assert!(hits.iter().all(|hit| hit.matched == "text"));
        let hits = db.search_files("ideas.md", None, None, 0.8, 10).unwrap();
        assert_eq!(hits[0].file.id, ideas.id);
        let hits = db
            .search_files("checkout", Some("blog"), None, 0.8, 10)
            .unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].file.id, other.id);
        assert!(
            db.search_files("the of", None, None, 0.8, 10)
                .unwrap()
                .is_empty()
        );

        // A vector finds by meaning; text matches still come first.
        let hits = db
            .search_files("zzz", None, Some(&[0.0, 1.0]), 0.8, 10)
            .unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!((hits[0].file.id, hits[0].matched), (schema.id, "semantic"));
        let hits = db
            .search_files("checkout", None, Some(&[0.0, 1.0]), 0.8, 10)
            .unwrap();
        assert_eq!(hits.len(), 3);
        assert!(hits[..2].iter().all(|hit| hit.matched == "text"));
        assert_eq!((hits[2].file.id, hits[2].matched), (schema.id, "semantic"));

        // Only the latest version is searched.
        db.save_file(&NewFile {
            description: "Database layout, now with refunds".into(),
            ..new_file("shop", "schema.sql", "y2")
        })
        .unwrap();
        let hits = db.search_files("layout", None, None, 0.8, 10).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].file.version, 2);

        // A new model drops file vectors along with entry vectors.
        assert_eq!(db.files_missing_embeddings(10).unwrap().len(), 2);
        db.use_embedding_model("another-model").unwrap();
        assert_eq!(db.files_missing_embeddings(10).unwrap().len(), 4);
    }

    #[test]
    fn backup_v5_round_trips_the_files() {
        use base64::Engine;
        let db = temp_db();
        db.use_embedding_model("test-model").unwrap();
        let entry = db
            .insert(&entry("shop", "Ideas", "where they live"))
            .unwrap();
        let v1 = db
            .save_file(&NewFile {
                entry_id: Some(entry.id),
                ..new_file("shop", "docs/ideas.md", "first")
            })
            .unwrap()
            .file;
        let v2 = db
            .save_file(&new_file("shop", "docs/ideas.md", "second"))
            .unwrap()
            .file;
        let bytes = vec![0u8, 159, 146, 150];
        let binary = db
            .save_file(&NewFile {
                encoding: "base64".into(),
                ..new_file(
                    "shop",
                    "logo.bin",
                    &base64::engine::general_purpose::STANDARD.encode(&bytes),
                )
            })
            .unwrap()
            .file;
        db.set_file_embedding(v2.id, &[1.0, 0.0]).unwrap();

        let json = serde_json::to_string(&db.export().unwrap()).unwrap();
        let backup: Backup = serde_json::from_str(&json).unwrap();
        assert_eq!(backup.version, 5);
        assert_eq!(backup.files.len(), 3);
        assert!(backup.files.iter().any(|file| file.embedding.is_some()));

        // Diverge, then restore: the files are exactly the backup again,
        // under their ids, with the vector that existed.
        db.delete_file(v1.id).unwrap();
        db.save_file(&new_file("shop", "scratch.md", "discard me"))
            .unwrap();
        db.restore(&backup).unwrap();
        let restored = db.file(v1.id).unwrap().unwrap();
        assert_eq!(restored.content, b"first");
        assert_eq!(restored.info.entry_id, Some(entry.id));
        assert_eq!(db.file(binary.id).unwrap().unwrap().content, bytes);
        assert!(db.file_at("shop", "scratch.md", None).unwrap().is_none());
        let missing: Vec<i64> = db
            .files_missing_embeddings(10)
            .unwrap()
            .iter()
            .map(|file| file.id)
            .collect();
        assert_eq!(missing, [v1.id, binary.id]);
        // A new save continues the version count.
        assert_eq!(
            db.save_file(&new_file("shop", "docs/ideas.md", "third"))
                .unwrap()
                .file
                .version,
            3
        );

        // Merging the backup back adds nothing: every version is present.
        let before = db.file_counts().unwrap().versions;
        db.merge(&backup).unwrap();
        assert_eq!(db.file_counts().unwrap().versions, before);

        // Into a store without them, merging adds each missing version as
        // the next free version of its path, and never removes anything.
        db.delete_file(v1.id).unwrap();
        db.save_file(&new_file("shop", "kept.md", "stays")).unwrap();
        db.merge(&backup).unwrap();
        let versions = db.file_versions("shop", "docs/ideas.md").unwrap();
        assert_eq!(
            versions.iter().map(|f| f.version).collect::<Vec<_>>(),
            [4, 3, 2]
        );
        assert_eq!(db.file(versions[0].id).unwrap().unwrap().content, b"first");
        assert!(db.file_at("shop", "kept.md", None).unwrap().is_some());

        // A backup whose content does not match its hash changes nothing.
        let mut broken: Backup = serde_json::from_str(&json).unwrap();
        broken.files[0].content = base64::engine::general_purpose::STANDARD.encode("tampered");
        broken.files[0].info.sha256 = sha256_hex(b"something else");
        let count = db.file_counts().unwrap().versions;
        assert!(db.restore(&broken).is_err());
        assert!(db.merge(&broken).is_err());
        assert_eq!(db.file_counts().unwrap().versions, count);
        assert!(db.file_at("shop", "kept.md", None).unwrap().is_some());
    }

    #[test]
    fn a_v4_backup_leaves_the_files_in_place() {
        let db = temp_db();
        db.insert(&entry("shop", "Old", "entry")).unwrap();
        let kept = db
            .save_file(&new_file("shop", "docs/ideas.md", "kept"))
            .unwrap()
            .file;

        // A version 4 file: the same store without the files section.
        let mut value = serde_json::to_value(db.export().unwrap()).unwrap();
        let object = value.as_object_mut().unwrap();
        object.remove("files");
        object.insert("version".into(), serde_json::json!(4));
        let v4: Backup = serde_json::from_value(value).unwrap();
        assert!(v4.files.is_empty());

        // Files saved after the export survive restoring the older file.
        let later = db
            .save_file(&new_file("shop", "docs/ideas.md", "later"))
            .unwrap()
            .file;
        db.restore(&v4).unwrap();
        assert!(db.file(kept.id).unwrap().is_some());
        assert_eq!(db.file(later.id).unwrap().unwrap().content, b"later");
        assert_eq!(db.file_counts().unwrap().versions, 2);
        // Versions 1 to 3 still load.
        for version in 1..=3 {
            let mut older = serde_json::to_value(&v4).unwrap();
            older
                .as_object_mut()
                .unwrap()
                .insert("version".into(), serde_json::json!(version));
            let older: Backup = serde_json::from_value(older).unwrap();
            db.restore(&older).unwrap();
            db.merge(&older).unwrap();
        }
        assert_eq!(db.file_counts().unwrap().versions, 2);
        // Version 6 does not exist yet.
        let mut newer = serde_json::to_value(&v4).unwrap();
        newer
            .as_object_mut()
            .unwrap()
            .insert("version".into(), serde_json::json!(6));
        let newer: Backup = serde_json::from_value(newer).unwrap();
        assert!(db.restore(&newer).is_err());
    }

    #[test]
    fn a_current_database_gains_the_files_table() {
        let dir = std::env::temp_dir().join(format!("lore-files-migrate-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("lore.db");
        let (entry_id, session_id) = {
            // Everything the store held before files existed.
            let db = Db::open(&path).unwrap();
            let entry = db.insert(&entry("shop", "old", "entry")).unwrap();
            db.set_embedding(entry.id, &[1.0, 0.0]).unwrap();
            let opened = db.open_session(&session("claude", "shop", "chat")).unwrap();
            db.add_session_update(&opened.id, "step", "", "", false)
                .unwrap();
            db.add_rule(&RuleInput {
                scope: "global".into(),
                target: String::new(),
                body: "be kind".into(),
                enabled: true,
                position: 0,
            })
            .unwrap();
            db.add_task(&task("shop", "kept task")).unwrap();
            db.add_message(&message("message", "claude", "", "kept message"))
                .unwrap();
            db.lock()
                .execute_batch("DROP INDEX files_project_path; DROP TABLE files;")
                .unwrap();
            (entry.id, opened.id)
        };
        let db = Db::open(&path).unwrap();
        assert_eq!(db.get(entry_id).unwrap().unwrap().title, "old");
        assert!(db.missing_embeddings(10).unwrap().is_empty());
        assert_eq!(db.session_updates(&session_id).unwrap().len(), 1);
        assert_eq!(db.rules().unwrap().len(), 1);
        assert_eq!(db.tasks(None, &[], 10).unwrap().len(), 1);
        assert_eq!(db.messages(None, 10).unwrap().len(), 1);
        assert_eq!(db.file_counts().unwrap().versions, 0);
        db.save_file(&new_file("shop", "docs/ideas.md", "new"))
            .unwrap();
        // Opening it again changes nothing.
        drop(db);
        let db = Db::open(&path).unwrap();
        assert_eq!(db.files(None, 10).unwrap().len(), 1);
        assert_eq!(db.get(entry_id).unwrap().unwrap().title, "old");
        assert_eq!(db.export().unwrap().entries.len(), 1);
    }

    #[test]
    fn padded_path_segments_cannot_hide_a_secret_name() {
        assert_eq!(
            normalize_file_path("docs /ideas.md ").unwrap(),
            "docs/ideas.md"
        );
        assert_eq!(
            normalize_file_path("keys/server.pem /").unwrap(),
            "keys/server.pem"
        );
        let db = temp_db();
        for path in ["keys/server.pem /", "deploy/.env /", "x/ id_rsa /"] {
            let error = db
                .save_file(&new_file("shop", path, "x"))
                .unwrap_err()
                .to_string();
            assert!(
                error.contains("lore does not store secrets"),
                "{path}: {error}"
            );
        }
    }

    #[test]
    fn a_save_without_a_kind_keeps_the_kind_of_the_path() {
        let db = temp_db();
        let first = db
            .save_file(&NewFile {
                kind: "idea".into(),
                ..new_file("shop", "docs/ideas.md", "one")
            })
            .unwrap();
        assert_eq!(first.file.kind, "idea");
        // The same bytes without a kind change nothing.
        let same = db
            .save_file(&NewFile {
                kind: String::new(),
                ..new_file("shop", "docs/ideas.md", "one")
            })
            .unwrap();
        assert!(same.unchanged && !same.needs_embedding);
        assert_eq!(same.file.kind, "idea");
        // A new version without a kind stays an idea; a named kind wins.
        let second = db
            .save_file(&NewFile {
                kind: String::new(),
                ..new_file("shop", "docs/ideas.md", "two")
            })
            .unwrap();
        assert_eq!(
            (second.file.version, second.file.kind.as_str()),
            (2, "idea")
        );
        let third = db
            .save_file(&NewFile {
                kind: "doc".into(),
                ..new_file("shop", "docs/ideas.md", "three")
            })
            .unwrap();
        assert_eq!(third.file.kind, "doc");
    }

    // ---- The credential vault and the operations log ----

    fn vault_key() -> crate::vault::VaultKey {
        crate::vault::VaultKey::from_env_value(&"ab".repeat(32))
            .unwrap()
            .unwrap()
    }

    /// A database that already holds a `github` credential and its
    /// levels opens with the organization provider added and nothing
    /// changed: same rows, same schema version, the credential still
    /// decrypts, and `github_org` is simply not configured.
    #[test]
    fn a_stored_github_credential_survives_the_organization_provider() {
        let dir = std::env::temp_dir().join(format!("lore-github-org-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("lore.db");
        let key = vault_key();
        let dump = |db: &Db| -> (i64, Vec<String>) {
            let conn = db.lock();
            let version = schema_version(&conn).unwrap();
            let mut rows: Vec<String> = Vec::new();
            for sql in [
                "SELECT provider || '|' || base_url || '|' || hex(nonce) || '|' || hex(secret) \
                 || '|' || hint || '|' || updated_at FROM vault ORDER BY provider",
                "SELECT agent || '|' || provider || '|' || level FROM ops_permissions \
                 ORDER BY agent, provider",
            ] {
                let mut stmt = conn.prepare(sql).unwrap();
                let found = stmt.query_map([], |row| row.get::<_, String>(0)).unwrap();
                rows.extend(found.map(Result::unwrap));
            }
            (version, rows)
        };
        let before = {
            let db = Db::open(&path).unwrap();
            let (nonce, secret) = key.encrypt("github", "", "ghp_personal-token-42");
            db.set_vault("github", "", &nonce, &secret, "n-42").unwrap();
            db.set_ops_level("claude", "github", "off").unwrap();
            db.set_ops_level("codex", "github", "read").unwrap();
            dump(&db)
        };
        let db = Db::open(&path).unwrap();
        assert_eq!(dump(&db), before);
        let stored = db.vault("github").unwrap().unwrap();
        assert_eq!(
            key.decrypt("github", "", &stored.nonce, &stored.secret)
                .unwrap()
                .expose(),
            "ghp_personal-token-42"
        );
        assert_eq!(db.ops_level("claude", "github").unwrap(), "off");
        assert_eq!(db.ops_level("codex", "github").unwrap(), "read");
        // The organization account starts unconfigured with the default
        // level, and its rows are its own.
        assert!(db.vault("github_org").unwrap().is_none());
        let status = db.vault_status().unwrap();
        let org = status
            .iter()
            .find(|row| row.provider == "github_org")
            .unwrap();
        assert!(!org.configured);
        assert_eq!(db.ops_level("claude", "github_org").unwrap(), "full");
        db.set_ops_level("claude", "github_org", "read").unwrap();
        assert_eq!(db.ops_level("claude", "github").unwrap(), "off");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn vault_rows_round_trip_and_delete() {
        let db = temp_db();
        let key = vault_key();
        assert!(db.vault("github").unwrap().is_none());

        let (nonce, secret) = key.encrypt("github", "", "ghp_test-token-42");
        // Provider ids are validated and lowercased.
        db.set_vault(" GitHub ", "", &nonce, &secret, "d-42")
            .unwrap();
        let stored = db.vault("github").unwrap().unwrap();
        assert_eq!(stored.base_url, "");
        assert_eq!(stored.hint, "d-42");
        assert!(!stored.nonce.is_empty());
        // The store holds the credential encrypted, never as written.
        assert_ne!(stored.secret, b"ghp_test-token-42".as_slice());
        assert_eq!(
            key.decrypt("github", "", &stored.nonce, &stored.secret)
                .unwrap()
                .expose(),
            "ghp_test-token-42"
        );
        for bad in ["", "shop", "cloudflare2"] {
            assert!(
                db.set_vault(bad, "", &nonce, &secret, "x").is_err(),
                "{bad:?}"
            );
            assert!(db.vault(bad).is_err(), "{bad:?}");
            assert!(db.delete_vault(bad).is_err(), "{bad:?}");
        }

        // The status lists every provider, in the fixed order, and never
        // carries a nonce or a secret. The organization account has no
        // row and is simply not configured.
        let status = db.vault_status().unwrap();
        let ids: Vec<&str> = status.iter().map(|row| row.provider.as_str()).collect();
        assert_eq!(
            ids,
            ["cloudflare", "github", "github_org", "gitlab", "dokploy"]
        );
        let github = &status[1];
        assert!(github.configured && github.hint == "d-42");
        assert!(status[0].hint.is_empty() && !status[0].configured);
        assert!(!status[2].configured && status[2].hint.is_empty());

        // gitlab keeps the admin-entered server URL.
        let (nonce, secret) = key.encrypt("gitlab", "https://git.example.com", "glpat-1234");
        db.set_vault("gitlab", "https://git.example.com", &nonce, &secret, "1234")
            .unwrap();
        assert_eq!(
            db.vault_status().unwrap()[3].base_url,
            "https://git.example.com"
        );

        assert!(db.delete_vault("github").unwrap());
        assert!(!db.delete_vault("github").unwrap());
        assert!(db.vault("github").unwrap().is_none());
    }

    #[test]
    fn ops_levels_default_to_full_and_can_be_restricted() {
        let db = temp_db();
        // No row means full.
        assert_eq!(db.ops_level("Claude", "GitHub").unwrap(), "full");
        assert!(db.ops_level("claude", "shop").is_err());
        db.set_ops_level("Claude", "GitHub", "READ").unwrap();
        assert_eq!(db.ops_level("claude", "github").unwrap(), "read");
        assert_eq!(db.ops_permissions().unwrap().len(), 1);
        // `full` deletes the row again.
        db.set_ops_level("claude", "github", "full").unwrap();
        assert_eq!(db.ops_level("claude", "github").unwrap(), "full");
        assert!(db.ops_permissions().unwrap().is_empty());
        db.set_ops_level("claude", "dokploy", "off").unwrap();
        assert!(
            db.ops_permissions()
                .unwrap()
                .iter()
                .any(|row| row.agent == "claude" && row.provider == "dokploy")
        );
        for (agent, provider, level) in [
            ("", "github", "off"),
            ("claude", "nope", "off"),
            ("claude", "github", "sometimes"),
        ] {
            assert!(db.set_ops_level(agent, provider, level).is_err());
        }

        // The kill switch: missing means enabled.
        assert!(db.ops_enabled().unwrap());
        db.set_ops_enabled(false).unwrap();
        assert!(!db.ops_enabled().unwrap());
        db.set_ops_enabled(true).unwrap();
        assert!(db.ops_enabled().unwrap());
        // A damaged value fails closed.
        set_meta(&db.lock(), "ops.enabled", "yes please").unwrap();
        assert!(!db.ops_enabled().unwrap());

        // The leak scan: on by default, public repositories refused by
        // default, and a damaged value keeps both on the safe side.
        let defaults = LeakScanSettings {
            scan: true,
            allow_public: false,
        };
        assert_eq!(db.leak_scan_settings().unwrap(), defaults);
        db.set_leak_scan_settings(Some(false), None).unwrap();
        assert!(!db.leak_scan_settings().unwrap().scan);
        db.set_leak_scan_settings(None, Some(true)).unwrap();
        assert_eq!(
            db.leak_scan_settings().unwrap(),
            LeakScanSettings {
                scan: false,
                allow_public: true
            }
        );
        set_meta(&db.lock(), "leakscan.enabled", "nope").unwrap();
        set_meta(&db.lock(), "leakscan.allow_public", "yes").unwrap();
        assert_eq!(db.leak_scan_settings().unwrap(), defaults);
    }

    #[test]
    fn the_ops_log_is_newest_first_and_bounded() {
        let db = temp_db();
        let row = db
            .log_op(
                "Claude",
                Some("s_1"),
                "GitHub",
                "GET",
                "/user",
                200,
                "ok",
                "",
                3,
            )
            .unwrap();
        // Agent names are trimmed and lowercased like everywhere else.
        assert_eq!((row.agent.as_str(), row.method.as_str()), ("claude", "GET"));
        assert_eq!(row.status, 200);
        assert!(row.created_at.contains('T'));
        db.log_op(
            "claude",
            None,
            "github",
            "POST",
            "/x",
            0,
            "denied",
            "no access",
            1,
        )
        .unwrap();
        let log = db.ops_log(10).unwrap();
        assert_eq!(log.len(), 2);
        assert_eq!(log[0].path, "/x");
        assert_eq!(log[0].outcome, "denied");
        assert_eq!(log[0].detail, "no access");
        assert_eq!(log[1].session_id.as_deref(), Some("s_1"));
        assert!(
            db.log_op("claude", None, "github", "GET", "/", 0, "later", "", 0)
                .is_err()
        );
        assert!(
            db.log_op("claude", None, "shop", "GET", "/", 0, "ok", "", 0)
                .is_err()
        );

        // The log keeps at most its newest 5000 rows.
        for i in 0..5_005 {
            db.log_op(
                &format!("agent{i}"),
                None,
                "github",
                "GET",
                &format!("/p{i}"),
                200,
                "ok",
                "",
                i,
            )
            .unwrap();
        }
        let all = db.ops_log(10_000).unwrap();
        assert_eq!(all.len(), OPS_LOG_KEPT as usize);
        assert_eq!(all[0].path, "/p5004");
        assert_eq!(all[0].agent, "agent5004");
        // The oldest five went, the rest stayed in order.
        assert_eq!(all[all.len() - 1].path, "/p5");
    }

    #[test]
    fn backups_do_not_carry_the_vault_the_permissions_or_the_log() {
        let db = temp_db();
        let key = vault_key();
        let (nonce, secret) = key.encrypt("github", "", "ghp_test-token-42");
        db.set_vault("github", "", &nonce, &secret, "d-42").unwrap();
        db.set_ops_level("claude", "github", "read").unwrap();
        db.log_op("claude", None, "github", "GET", "/user", 200, "ok", "", 2)
            .unwrap();
        db.insert(&entry("shop", "Payments", "the credential vault arrived"))
            .unwrap();

        let json = serde_json::to_string(&db.export().unwrap()).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        let keys: Vec<&str> = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert!(!keys.contains(&"vault"));
        assert!(!keys.contains(&"ops_permissions"));
        assert!(!keys.contains(&"ops_log"));
        assert!(!json.contains("ghp_test-token-42"));

        // The store moves on after the export, then a restore replaces the
        // entries and leaves all three tables exactly as they are.
        let backup: Backup = serde_json::from_str(&json).unwrap();
        db.set_ops_level("claude", "github", "off").unwrap();
        db.log_op(
            "codex",
            None,
            "dokploy",
            "POST",
            "/application.deploy",
            201,
            "ok",
            "",
            9,
        )
        .unwrap();
        db.insert(&entry("temp", "Scratch", "discarded by the restore"))
            .unwrap();
        db.restore(&backup).unwrap();
        assert!(
            db.search("discarded", None, None, None, 5, 0.8)
                .unwrap()
                .is_empty()
        );
        assert_eq!(db.ops_level("claude", "github").unwrap(), "off");
        let log = db.ops_log(10).unwrap();
        assert_eq!(log.len(), 2);
        assert_eq!(log[0].provider, "dokploy");
        let stored = db.vault("github").unwrap().unwrap();
        assert_eq!(stored.hint, "d-42");
        assert_eq!(
            key.decrypt("github", "", &stored.nonce, &stored.secret)
                .unwrap()
                .expose(),
            "ghp_test-token-42"
        );

        // Merging a backup adds nothing to them either.
        db.merge(&backup).unwrap();
        assert_eq!(db.ops_log(10).unwrap().len(), 2);
        assert_eq!(db.ops_level("claude", "github").unwrap(), "off");
        assert!(db.vault("github").unwrap().is_some());
    }

    #[test]
    fn an_old_database_gains_the_vault_tables() {
        let dir = std::env::temp_dir().join(format!("lore-vault-migrate-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("lore.db");
        {
            // The schema before the vault: entries and meta, nothing more.
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE entries (id INTEGER PRIMARY KEY AUTOINCREMENT, project TEXT NOT NULL,
                 kind TEXT NOT NULL, title TEXT NOT NULL, body TEXT NOT NULL,
                 tags TEXT NOT NULL DEFAULT '', files TEXT NOT NULL DEFAULT '',
                 agent TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL DEFAULT 'x',
                 updated_at TEXT, embedding BLOB);
                 INSERT INTO entries (project, kind, title, body) VALUES ('p', 'note', 'old', 'entry');
                 CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);",
            )
            .unwrap();
        }
        let db = Db::open(&path).unwrap();
        // Nothing was lost, and the vault works right away.
        assert_eq!(db.get(1).unwrap().unwrap().title, "old");
        let key = vault_key();
        let (nonce, secret) = key.encrypt("dokploy", "http://localhost:3000", "dky_test-1234");
        db.set_vault("dokploy", "http://localhost:3000", &nonce, &secret, "1234")
            .unwrap();
        db.set_ops_level("claude", "dokploy", "read").unwrap();
        assert_eq!(db.ops_level("claude", "dokploy").unwrap(), "read");
        assert!(db.vault_status().unwrap()[4].configured);
        db.log_op(
            "claude",
            None,
            "dokploy",
            "GET",
            "/project.all",
            200,
            "ok",
            "",
            1,
        )
        .unwrap();
        assert_eq!(db.ops_log(10).unwrap().len(), 1);
        // Opening it again changes nothing.
        drop(db);
        let db = Db::open(&path).unwrap();
        assert_eq!(db.get(1).unwrap().unwrap().title, "old");
        assert_eq!(db.ops_log(10).unwrap().len(), 1);
        assert!(db.vault("dokploy").unwrap().is_some());
    }

    /// A database from before the mailbox (schema 2: the vault without
    /// host, port and account) opens with every row, its credentials still
    /// decrypt, and it gains the columns and the mailbox.
    #[test]
    fn a_vault_from_before_the_mailbox_keeps_its_rows() {
        let dir = test_dir("mail-migrate");
        let path = dir.join("lore.db");
        let key = vault_key();
        let (nonce, secret) = key.encrypt("gitlab", "https://git.example.com", "glpat-old-1");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE entries (id INTEGER PRIMARY KEY AUTOINCREMENT, project TEXT NOT NULL,
                 kind TEXT NOT NULL, title TEXT NOT NULL, body TEXT NOT NULL,
                 tags TEXT NOT NULL DEFAULT '', files TEXT NOT NULL DEFAULT '',
                 agent TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL DEFAULT 'x',
                 updated_at TEXT, embedding BLOB);
                 INSERT INTO entries (project, kind, title, body) VALUES ('p', 'note', 'old', 'entry');
                 CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                 INSERT INTO meta (key, value) VALUES ('schema_version', '2');
                 CREATE TABLE vault (provider TEXT PRIMARY KEY, base_url TEXT NOT NULL DEFAULT '',
                 nonce BLOB NOT NULL, secret BLOB NOT NULL, hint TEXT NOT NULL DEFAULT '',
                 updated_at TEXT NOT NULL);
                 CREATE TABLE ops_permissions (agent TEXT NOT NULL, provider TEXT NOT NULL,
                 level TEXT NOT NULL, PRIMARY KEY (agent, provider));
                 INSERT INTO ops_permissions VALUES ('claude', 'gitlab', 'read');",
            )
            .unwrap();
            conn.execute(
                "INSERT INTO vault (provider, base_url, nonce, secret, hint, updated_at)
                 VALUES ('gitlab', 'https://git.example.com', ?1, ?2, 'ld-1', 'then')",
                params![nonce, secret],
            )
            .unwrap();
        }
        let db = Db::open(&path).unwrap();
        assert_eq!(schema_version(&db.lock()).unwrap(), SCHEMA_VERSION);
        assert_eq!(db.get(1).unwrap().unwrap().title, "old");
        let stored = db.vault("gitlab").unwrap().unwrap();
        assert_eq!(
            (
                stored.base_url.as_str(),
                stored.hint.as_str(),
                stored.updated_at.as_str()
            ),
            ("https://git.example.com", "ld-1", "then")
        );
        assert_eq!(
            key.decrypt("gitlab", &stored.base_url, &stored.nonce, &stored.secret)
                .unwrap()
                .expose(),
            "glpat-old-1"
        );
        assert_eq!(db.ops_level("claude", "gitlab").unwrap(), "read");
        // No mailbox yet, and it is off for everyone.
        assert!(db.mail_vault().unwrap().is_none());
        assert_eq!(db.ops_level("claude", "mail").unwrap(), "off");
        let columns: Vec<String> = db
            .lock()
            .prepare("SELECT name FROM pragma_table_info('vault')")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        for column in ["host", "port", "account"] {
            assert!(columns.iter().any(|name| name == column), "{column}");
        }
        db.set_mail_vault("imap.example.com", 993, "me@example.com", b"n", b"s", "")
            .unwrap();
        // Opening it again changes nothing.
        drop(db);
        let db = Db::open(&path).unwrap();
        assert!(db.vault("gitlab").unwrap().is_some());
        assert_eq!(db.mail_vault().unwrap().unwrap().account, "me@example.com");
        assert_eq!(db.vault_status().unwrap().len(), PROVIDERS.len());
    }

    /// A fresh, empty directory for one test.
    fn test_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("lore-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn user_fixture(name: &str, email: Option<&str>, perms: &[&str]) -> NewUser {
        NewUser {
            username: name.into(),
            email: email.map(String::from),
            password_hash: "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA".into(),
            permissions: Perms::parse(perms).unwrap(),
            created_by: "admin".into(),
        }
    }

    /// Entries, a file in two versions, a task, a user and a vault row.
    fn populate(db: &Db) {
        db.insert(&entry("shop", "Checkout", "Stripe webhooks verified"))
            .unwrap();
        db.insert(&entry("blog", "Feed", "RSS and Atom")).unwrap();
        for content in ["first", "second"] {
            db.save_file(&NewFile {
                project: "shop".into(),
                path: "docs/plan.md".into(),
                kind: "doc".into(),
                description: "the plan".into(),
                encoding: "utf8".into(),
                content: content.into(),
                entry_id: None,
                agent: "claude".into(),
                session_id: None,
            })
            .unwrap();
        }
        db.add_task(&NewTask {
            project: "shop".into(),
            title: "Ship it".into(),
            body: String::new(),
            assignee: String::new(),
            created_by: "admin".into(),
            session_id: None,
            ..Default::default()
        })
        .unwrap();
        db.add_user(&user_fixture("luis", Some("luis@example.com"), &["write"]))
            .unwrap();
        db.set_vault("github", "", b"nonce-bytes-24", b"ciphertext", "1234")
            .unwrap();
    }

    /// A hash over every row of a table, in id order.
    fn table_hash(db: &Db, table: &str, columns: &str) -> String {
        let conn = db.lock();
        let mut stmt = conn
            .prepare(&format!("SELECT {columns} FROM {table} ORDER BY id"))
            .unwrap();
        let count = stmt.column_count();
        let mut bytes = Vec::new();
        let mut rows = stmt.query([]).unwrap();
        while let Some(row) = rows.next().unwrap() {
            for i in 0..count {
                let value: Value = row.get(i).unwrap();
                bytes.extend(format!("{value:?}|").into_bytes());
            }
            bytes.push(b'\n');
        }
        sha256_hex(&bytes)
    }

    #[test]
    fn users_are_stored_unique_and_lowercase() {
        let db = temp_db_named("users");
        let user = db
            .add_user(&user_fixture(
                "luis",
                Some("luis@example.com"),
                &["users", "write"],
            ))
            .unwrap();
        assert_eq!(user.permissions, ["write", "users"]);
        assert!(!user.disabled && user.last_login_at.is_none());
        assert!(db.add_user(&user_fixture("luis", None, &[])).is_err());
        assert!(
            db.add_user(&user_fixture("other", Some("luis@example.com"), &[]))
                .is_err()
        );
        // Two users without an address are fine.
        db.add_user(&user_fixture("a1", None, &[])).unwrap();
        db.add_user(&user_fixture("a2", None, &[])).unwrap();
        assert_eq!(db.user_login("LUIS").unwrap().unwrap().user.id, user.id);
        assert_eq!(
            db.user_login("Luis@Example.com").unwrap().unwrap().user.id,
            user.id
        );
        assert!(db.user_login("nobody").unwrap().is_none());
        let login = db.user_login("luis").unwrap().unwrap();
        assert!(
            !format!("{login:?}").contains("argon2"),
            "the hash leaked into Debug"
        );

        let changed = db
            .update_user(
                user.id,
                &UserPatch {
                    email: Some(None),
                    permissions: Some(Perms::parse(&["backup"]).unwrap()),
                    disabled: Some(true),
                    password_hash: Some("$argon2id$new".into()),
                },
            )
            .unwrap()
            .unwrap();
        assert_eq!(
            (changed.email, changed.permissions, changed.disabled),
            (None, vec!["backup".to_string()], true)
        );
        assert_eq!(
            db.user_password_hash(user.id).unwrap().as_deref(),
            Some("$argon2id$new")
        );
        // An empty patch changes nothing.
        let same = db
            .update_user(user.id, &UserPatch::default())
            .unwrap()
            .unwrap();
        assert!(same.disabled);
        assert!(
            db.update_user(999, &UserPatch::default())
                .unwrap()
                .is_none()
        );
        db.touch_user_login(user.id).unwrap();
        assert!(db.user(user.id).unwrap().unwrap().last_login_at.is_some());
        assert_eq!(db.delete_user(user.id).unwrap().unwrap().username, "luis");
        assert!(db.delete_user(user.id).unwrap().is_none());
        assert_eq!(db.users().unwrap().len(), 2);
    }

    #[test]
    fn json_backups_leave_the_users_alone() {
        let db = temp_db_named("json-users");
        populate(&db);
        let backup = db.export().unwrap();
        assert!(
            !serde_json::to_string(&backup)
                .unwrap()
                .contains("luis@example.com"),
            "a user reached the JSON backup"
        );
        db.add_user(&user_fixture("later", None, &[])).unwrap();
        db.restore(&backup).unwrap();
        db.merge(&backup).unwrap();
        let names: Vec<String> = db
            .users()
            .unwrap()
            .into_iter()
            .map(|u| u.username)
            .collect();
        assert_eq!(names, ["later", "luis"]);
    }

    #[test]
    fn a_database_from_before_users_opens_and_keeps_its_rows() {
        let dir = test_dir("pre-users");
        let path = dir.join("lore.db");
        {
            let db = Db::open(&path).unwrap();
            populate(&db);
        }
        // Turn it back into what the previous release wrote: no users
        // table and no schema version.
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch("DROP TABLE users; DELETE FROM meta WHERE key = 'schema_version';")
                .unwrap();
        }
        let db = Db::open(&path).unwrap();
        let counts: HashMap<String, i64> = db.table_counts().unwrap().into_iter().collect();
        assert_eq!(counts["entries"], 2);
        assert_eq!(counts["files"], 2);
        assert_eq!(counts["tasks"], 1);
        assert_eq!(counts["vault"], 1);
        assert_eq!(counts["users"], 0);
        assert_eq!(schema_version(&db.lock()).unwrap(), SCHEMA_VERSION);
        assert_eq!(
            db.search("webhooks", None, None, None, 5, 0.8)
                .unwrap()
                .len(),
            1
        );
        // A newer build's number is never lowered.
        set_meta(&db.lock(), "schema_version", "99").unwrap();
        drop(db);
        let db = Db::open(&path).unwrap();
        assert_eq!(schema_version(&db.lock()).unwrap(), 99);
    }

    #[test]
    fn a_full_backup_restores_into_another_database_exactly() {
        let dir = test_dir("full-roundtrip");
        let source = Db::open(&dir.join("a/lore.db")).unwrap();
        populate(&source);
        let file = dir.join("full.sqlite");
        source.snapshot_to(&file).unwrap();
        check_full_backup(&file).unwrap();
        prepare_full_backup(&file).unwrap();

        let target = Db::open(&dir.join("b/lore.db")).unwrap();
        target
            .insert(&entry("old", "Replaced", "gone after the restore"))
            .unwrap();
        let counts = target.load_full_backup(&file).unwrap();
        assert_eq!(counts, source.table_counts().unwrap());
        let entries = "id, project, kind, title, body, tags, files, agent, created_at, updated_at";
        let files = "id, project, path, version, content, sha256, created_at";
        assert_eq!(
            table_hash(&target, "entries", entries),
            table_hash(&source, "entries", entries)
        );
        assert_eq!(
            table_hash(&target, "files", files),
            table_hash(&source, "files", files)
        );
        assert_eq!(target.users().unwrap()[0].username, "luis");
        assert!(target.vault("github").unwrap().is_some());
        assert_eq!(
            target
                .search("webhooks", None, None, None, 5, 0.8)
                .unwrap()
                .len(),
            1
        );
        assert!(
            target
                .search("Replaced", None, None, None, 5, 0.8)
                .unwrap()
                .is_empty()
        );
        // The target keeps working on its own file.
        target
            .insert(&entry("new", "After", "written after"))
            .unwrap();
        drop(target);
        let reopened = Db::open(&dir.join("b/lore.db")).unwrap();
        assert_eq!(reopened.recent(None, None, 10).unwrap().len(), 3);
    }

    #[test]
    fn bad_full_backups_are_refused_and_change_nothing() {
        let dir = test_dir("full-bad");
        let live = Db::open(&dir.join("live/lore.db")).unwrap();
        populate(&live);
        let before = live.table_counts().unwrap();

        let text = dir.join("text.sqlite");
        std::fs::write(&text, b"this is not a database at all, just text").unwrap();
        assert_eq!(check_full_backup(&text).unwrap_err().check, "header");

        let foreign = dir.join("foreign.sqlite");
        Connection::open(&foreign)
            .unwrap()
            .execute_batch("CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT);")
            .unwrap();
        assert_eq!(check_full_backup(&foreign).unwrap_err().check, "schema");

        let partial = dir.join("partial.sqlite");
        Connection::open(&partial)
            .unwrap()
            .execute_batch("CREATE TABLE entries (id INTEGER PRIMARY KEY, project TEXT);")
            .unwrap();
        assert_eq!(check_full_backup(&partial).unwrap_err().check, "schema");

        let newer = dir.join("newer.sqlite");
        live.snapshot_to(&newer).unwrap();
        Connection::open(&newer)
            .unwrap()
            .execute_batch("UPDATE meta SET value = '999' WHERE key = 'schema_version';")
            .unwrap();
        assert_eq!(check_full_backup(&newer).unwrap_err().check, "version");

        // A real database with pages overwritten in the middle.
        let corrupt = dir.join("corrupt.sqlite");
        live.snapshot_to(&corrupt).unwrap();
        let mut bytes = std::fs::read(&corrupt).unwrap();
        assert!(bytes.len() > 4096 * 4);
        for byte in &mut bytes[4096 + 100..4096 * 3] {
            *byte = 0xA5;
        }
        std::fs::write(&corrupt, &bytes).unwrap();
        let refusal = check_full_backup(&corrupt).unwrap_err();
        assert!(
            matches!(refusal.check, "integrity" | "open" | "schema"),
            "{refusal:?}"
        );

        assert_eq!(live.table_counts().unwrap(), before);
        assert_eq!(live.recent(None, None, 10).unwrap().len(), 2);
    }

    #[test]
    fn full_backups_with_objects_lore_does_not_create_are_refused() {
        let dir = test_dir("full-objects");
        let live = Db::open(&dir.join("live/lore.db")).unwrap();
        populate(&live);
        let clean = dir.join("clean.sqlite");
        live.snapshot_to(&clean).unwrap();
        check_full_backup(&clean).unwrap();
        let planted = [
            (
                "steal",
                "CREATE TRIGGER steal AFTER INSERT ON users BEGIN \
                 UPDATE users SET permissions = '[\"users\"]'; END;",
            ),
            (
                "peek",
                "CREATE VIEW peek AS SELECT password_hash FROM users;",
            ),
            ("extra", "CREATE TABLE extra (id INTEGER PRIMARY KEY);"),
            (
                "users_hash",
                "CREATE INDEX users_hash ON users (password_hash);",
            ),
            (
                "notes_fts",
                "CREATE VIRTUAL TABLE notes_fts USING fts5 (body);",
            ),
            // A trigger with lore's name and other SQL.
            (
                "entries_ai",
                "DROP TRIGGER entries_ai; CREATE TRIGGER entries_ai AFTER INSERT ON entries \
                 BEGIN DELETE FROM users; END;",
            ),
        ];
        for (index, (name, sql)) in planted.iter().enumerate() {
            let file = dir.join(format!("planted-{index}.sqlite"));
            live.snapshot_to(&file).unwrap();
            Connection::open(&file).unwrap().execute_batch(sql).unwrap();
            let refusal = check_full_backup(&file).unwrap_err();
            assert_eq!(refusal.check, "objects", "{name}: {refusal:?}");
            assert!(refusal.message.contains(name), "{refusal:?}");
        }
        // The objects SQLite makes itself pass: statistics, automatic indexes.
        let analyzed = dir.join("analyzed.sqlite");
        live.snapshot_to(&analyzed).unwrap();
        Connection::open(&analyzed)
            .unwrap()
            .execute_batch("ANALYZE;")
            .unwrap();
        check_full_backup(&analyzed).unwrap();
    }

    #[test]
    fn an_uploaded_database_is_opened_without_trusting_its_schema() {
        let conn = Connection::open_in_memory().unwrap();
        harden(&conn).unwrap();
        let trusted: bool = conn
            .query_row("PRAGMA trusted_schema", [], |row| row.get(0))
            .unwrap();
        assert!(!trusted);
        use rusqlite::config::DbConfig;
        assert!(conn.db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE).unwrap());
        assert!(
            !conn
                .db_config(DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA)
                .unwrap()
        );
        // Defensive: the schema cannot be written through the connection.
        conn.execute_batch("CREATE TABLE t (id INTEGER);").unwrap();
        assert!(
            conn.execute_batch("PRAGMA writable_schema = ON; DELETE FROM sqlite_master;")
                .is_err()
        );
        // A prepared backup keeps lore's own full-text triggers and index.
        let dir = test_dir("full-harden");
        let live = Db::open(&dir.join("live/lore.db")).unwrap();
        populate(&live);
        let file = dir.join("prepared.sqlite");
        live.snapshot_to(&file).unwrap();
        check_full_backup(&file).unwrap();
        prepare_full_backup(&file).unwrap();
        check_full_backup(&file).unwrap();
        let target = Db::open(&dir.join("target/lore.db")).unwrap();
        target.load_full_backup(&file).unwrap();
        assert_eq!(
            target
                .search("stripe", None, None, None, 5, 0.8)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn the_periodic_sweep_removes_only_old_temporary_files() {
        let dir = test_dir("sweep");
        let db = Db::open(&dir.join("lore.db")).unwrap();
        let old_time = std::time::SystemTime::now() - std::time::Duration::from_secs(2 * 3600);
        let age = |name: &str| {
            let path = dir.join(name);
            std::fs::write(&path, "x").unwrap();
            std::fs::File::options()
                .write(true)
                .open(&path)
                .unwrap()
                .set_modified(old_time)
                .unwrap();
        };
        // Old spool and backup leftovers go.
        age(".lore-tmp-push-0123456789abcdef.pack");
        age(".lore-tmp-backup-0123456789abcdef.sqlite-journal");
        // A fresh spool stays; so does everything that is not lore's
        // temporary file, however old.
        std::fs::write(dir.join(".lore-tmp-push-fedcba9876543210.pack"), "x").unwrap();
        let companions: Vec<&str> = ["lore.db-wal", "lore.db-shm"]
            .into_iter()
            .filter(|name| dir.join(name).exists())
            .collect();
        for keep in [
            "my-backup.sqlite",
            ".lore-tmp-notes.txt",
            ".lore-tmp-push-0123456789ABCDEF.pack",
            ".lore-tmp-push-0123.pack",
        ] {
            age(keep);
        }
        assert_eq!(db.sweep_leftovers(), 2);
        let left: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|item| item.file_name().to_string_lossy().into_owned())
            .collect();
        assert!(left.contains(&"lore.db".to_string()));
        assert!(left.contains(&".lore-tmp-push-fedcba9876543210.pack".to_string()));
        for keep in ["my-backup.sqlite", ".lore-tmp-notes.txt"]
            .into_iter()
            .chain(companions)
        {
            assert!(left.contains(&keep.to_string()), "{keep} was removed");
        }
        assert!(!left.iter().any(|name| name.contains("0123456789abcdef")));
        assert!(is_temp_name(
            ".lore-tmp-upload-source-0123456789abcdef.sqlite"
        ));
        assert!(!is_temp_name("lore.db"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn safety_snapshots_are_written_and_pruned() {
        let dir = test_dir("snapshots");
        let db = Db::open(&dir.join("lore.db")).unwrap();
        populate(&db);
        let mut names = Vec::new();
        for _ in 0..5 {
            names.push(db.write_safety_snapshot().unwrap());
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let mut kept: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|item| item.file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with(SNAPSHOT_PREFIX))
            .collect();
        kept.sort();
        let mut newest = names[2..].to_vec();
        newest.sort();
        assert_eq!(kept, newest);
        assert!(names[0].starts_with(SNAPSHOT_PREFIX) && names[0].ends_with(".sqlite"));
        // Each copy is a complete database of its own.
        check_full_backup(&dir.join(&names[4])).unwrap();
        // No temporary file is left behind.
        assert!(
            std::fs::read_dir(&dir)
                .unwrap()
                .flatten()
                .all(|item| !item.file_name().to_string_lossy().starts_with(TEMP_PREFIX))
        );
        assert_eq!(utc_stamp().len(), "YYYYMMDD-HHMMSS".len());
    }

    #[test]
    fn an_older_full_backup_gains_the_new_tables() {
        let dir = test_dir("full-old");
        let old = dir.join("old.sqlite");
        Connection::open(&old)
            .unwrap()
            .execute_batch(
                "CREATE TABLE entries (id INTEGER PRIMARY KEY AUTOINCREMENT, project TEXT NOT NULL,
                 kind TEXT NOT NULL, title TEXT NOT NULL, body TEXT NOT NULL,
                 tags TEXT NOT NULL DEFAULT '', files TEXT NOT NULL DEFAULT '',
                 agent TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL DEFAULT 'x',
                 updated_at TEXT, embedding BLOB);
                 INSERT INTO entries (project, kind, title, body) VALUES ('p', 'note', 'old', 'entry');
                 CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);",
            )
            .unwrap();
        check_full_backup(&old).unwrap();
        prepare_full_backup(&old).unwrap();
        let db = Db::open(&dir.join("live/lore.db")).unwrap();
        populate(&db);
        let counts: HashMap<String, i64> = db.load_full_backup(&old).unwrap().into_iter().collect();
        assert_eq!(counts["entries"], 1);
        for table in ["users", "files", "tasks", "vault", "ops_log", "sessions"] {
            assert_eq!(counts.get(table), Some(&0), "{table}");
        }
        assert_eq!(db.get(1).unwrap().unwrap().title, "old");
        assert_eq!(
            db.search("entry", None, None, None, 5, 0.8).unwrap().len(),
            1
        );
        db.add_user(&user_fixture("fresh", None, &[])).unwrap();
    }
}
