//! The built-in coding agents: their settings (model, enabled, available
//! for help, daily cap, active hours), the last state their runners
//! reported, and the tables runs will use (part 6b).
//!
//! No credential is ever stored here: sign-in tokens, `auth.json` files and
//! API keys live only in each agent's own volume. None of these tables is
//! part of the JSON backup; the full database backup carries them.

use anyhow::{Context, Result};
use rusqlite::{OptionalExtension, params};

use super::Db;

/// Tables added for the built-in agents. Created by the start-up
/// migration; additive only.
pub(super) const SCHEMA: &str = r#"
-- One row per built-in agent named in LORE_RUNNER_TOKENS. The owner's
-- settings, and what its runner last reported (never a credential).
CREATE TABLE IF NOT EXISTS builtin_agents (
    name           TEXT PRIMARY KEY,
    kind           TEXT NOT NULL DEFAULT '',     -- claude | codex | opencode; '' until reported
    provider       TEXT NOT NULL DEFAULT '',
    model          TEXT NOT NULL DEFAULT '',     -- '' = the CLI's default
    enabled        INTEGER NOT NULL DEFAULT 0,
    available      INTEGER NOT NULL DEFAULT 0,   -- may other agents ask it for help
    daily_cap      INTEGER NOT NULL DEFAULT 5,   -- board tasks a day, at most
    active_hours   TEXT NOT NULL DEFAULT '',     -- '' = always, else HH:MM-HH:MM (UTC)
    connected      INTEGER NOT NULL DEFAULT 0,
    connected_at   TEXT,
    last_seen_at   TEXT,
    runner_version TEXT NOT NULL DEFAULT '',
    cli_version    TEXT NOT NULL DEFAULT '',
    signed_in      INTEGER NOT NULL DEFAULT 0,
    login_method   TEXT NOT NULL DEFAULT '',
    login_ends     TEXT,
    status_detail  TEXT NOT NULL DEFAULT '',
    status_at      TEXT,
    created_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_by     TEXT NOT NULL DEFAULT ''
);
-- One run of a built-in agent (part 6b): a board task, help for another
-- agent, or a chat. The run token is kept only as its SHA-256 hash.
CREATE TABLE IF NOT EXISTS agent_runs (
    id               TEXT PRIMARY KEY,
    agent            TEXT NOT NULL,
    task_id          INTEGER,
    kind             TEXT NOT NULL,              -- task | help | chat
    project          TEXT NOT NULL DEFAULT '',
    repo             TEXT NOT NULL DEFAULT '',
    provider         TEXT NOT NULL DEFAULT '',
    status           TEXT NOT NULL DEFAULT 'queued',
    started_at       TEXT,
    ended_at         TEXT,
    exit_code        INTEGER,
    summary          TEXT NOT NULL DEFAULT '',
    commit_hash      TEXT NOT NULL DEFAULT '',
    token_hash       TEXT,
    token_expires_at INTEGER,
    scope            TEXT NOT NULL DEFAULT '{}', -- JSON: provider, owner/repo, dokploy project
    created_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
CREATE INDEX IF NOT EXISTS agent_runs_agent ON agent_runs (agent, created_at DESC);
-- A bounded, redacted log of each run's output (part 6b).
CREATE TABLE IF NOT EXISTS agent_run_events (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    seq    INTEGER NOT NULL,
    at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    stream TEXT NOT NULL DEFAULT 'text',
    body   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS agent_run_events_run ON agent_run_events (run_id, seq);
"#;

/// Board tasks a built-in agent may take a day, at most.
pub const MAX_DAILY_CAP: i64 = 100;

/// One built-in agent as stored.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct BuiltinAgent {
    pub name: String,
    pub kind: String,
    pub provider: String,
    pub model: String,
    pub enabled: bool,
    pub available: bool,
    pub daily_cap: i64,
    pub active_hours: String,
    pub connected: bool,
    pub connected_at: Option<String>,
    pub last_seen_at: Option<String>,
    pub runner_version: String,
    pub cli_version: String,
    pub signed_in: bool,
    pub login_method: String,
    pub login_ends: Option<String>,
    pub status_detail: String,
    pub status_at: Option<String>,
    pub updated_at: String,
    pub updated_by: String,
}

const BUILTIN_COLUMNS: &str = "name, kind, provider, model, enabled, available, daily_cap, \
     active_hours, connected, connected_at, last_seen_at, runner_version, cli_version, \
     signed_in, login_method, login_ends, status_detail, status_at, updated_at, updated_by";

impl BuiltinAgent {
    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            name: row.get(0)?,
            kind: row.get(1)?,
            provider: row.get(2)?,
            model: row.get(3)?,
            enabled: row.get(4)?,
            available: row.get(5)?,
            daily_cap: row.get(6)?,
            active_hours: row.get(7)?,
            connected: row.get(8)?,
            connected_at: row.get(9)?,
            last_seen_at: row.get(10)?,
            runner_version: row.get(11)?,
            cli_version: row.get(12)?,
            signed_in: row.get(13)?,
            login_method: row.get(14)?,
            login_ends: row.get(15)?,
            status_detail: row.get(16)?,
            status_at: row.get(17)?,
            updated_at: row.get(18)?,
            updated_by: row.get(19)?,
        })
    }
}

/// A change to a built-in agent's settings; `None` leaves a field. Every
/// value is already validated.
#[derive(Debug, Default)]
pub struct BuiltinSettings {
    pub model: Option<String>,
    pub enabled: Option<bool>,
    pub available: Option<bool>,
    pub daily_cap: Option<i64>,
    pub active_hours: Option<String>,
}

/// What a runner reported about its sign-in.
#[derive(Debug, Default)]
pub struct BuiltinStatus {
    pub signed_in: bool,
    pub login_method: String,
    pub login_ends: Option<String>,
    pub detail: String,
    pub cli_version: Option<String>,
}

impl Db {
    /// Gives every built-in agent named in `LORE_RUNNER_TOKENS` its row and
    /// a registry row of kind `builtin` with `avatar`, and marks every one
    /// disconnected (a runner that is still up connects again). Refuses a
    /// name an agent of another kind already has.
    pub fn register_builtin_agents(&self, agents: &[(String, String, &str)]) -> Result<()> {
        let mut conn = self.lock();
        let tx = conn.transaction()?;
        for (name, kind, avatar) in agents {
            let existing: Option<String> = tx
                .query_row(
                    "SELECT kind FROM agent_registry WHERE name = ?1",
                    params![name],
                    |row| row.get(0),
                )
                .optional()?;
            match existing.as_deref() {
                None => {
                    tx.execute(
                        "INSERT INTO agent_registry (name, kind, avatar, note, created_by)
                         VALUES (?1, 'builtin', ?2, 'built-in coding agent', 'environment')",
                        params![name, avatar],
                    )?;
                }
                Some("builtin") => {}
                Some(other) => anyhow::bail!(
                    "LORE_RUNNER_TOKENS names \"{name}\", but an agent of kind {other} already has \
                     that name; give the built-in agent another name (LORE_RUNNER_AGENT on its \
                     container and the same name in LORE_RUNNER_TOKENS)"
                ),
            }
            tx.execute(
                "INSERT OR IGNORE INTO builtin_agents (name, kind) VALUES (?1, ?2)",
                params![name, kind],
            )?;
        }
        tx.execute("UPDATE builtin_agents SET connected = 0", [])?;
        tx.commit()?;
        Ok(())
    }

    pub fn builtin_agent(&self, name: &str) -> Result<Option<BuiltinAgent>> {
        let sql = format!("SELECT {BUILTIN_COLUMNS} FROM builtin_agents WHERE name = ?1");
        Ok(self
            .lock()
            .query_row(&sql, params![name], BuiltinAgent::from_row)
            .optional()?)
    }

    /// Applies the owner's settings.
    pub fn update_builtin_settings(
        &self,
        name: &str,
        settings: &BuiltinSettings,
        by: &str,
    ) -> Result<BuiltinAgent> {
        {
            let conn = self.lock();
            conn.execute(
                "UPDATE builtin_agents SET
                    model = COALESCE(?2, model),
                    enabled = COALESCE(?3, enabled),
                    available = COALESCE(?4, available),
                    daily_cap = COALESCE(?5, daily_cap),
                    active_hours = COALESCE(?6, active_hours),
                    updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now'),
                    updated_by = ?7
                 WHERE name = ?1",
                params![
                    name,
                    settings.model,
                    settings.enabled,
                    settings.available,
                    settings.daily_cap,
                    settings.active_hours,
                    by
                ],
            )?;
        }
        self.builtin_agent(name)?
            .context("there is no built-in agent by that name")
    }

    /// Notes that a runner connected, as what.
    pub fn builtin_connected(
        &self,
        name: &str,
        kind: &str,
        provider: &str,
        runner_version: &str,
        cli_version: Option<&str>,
    ) -> Result<()> {
        self.lock().execute(
            "UPDATE builtin_agents SET connected = 1, kind = ?2, provider = ?3,
                 runner_version = ?4, cli_version = COALESCE(?5, cli_version),
                 connected_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now'),
                 last_seen_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
             WHERE name = ?1",
            params![name, kind, provider, runner_version, cli_version],
        )?;
        Ok(())
    }

    /// Notes that a runner's link closed.
    pub fn builtin_disconnected(&self, name: &str) -> Result<()> {
        self.lock().execute(
            "UPDATE builtin_agents SET connected = 0,
                 last_seen_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
             WHERE name = ?1",
            params![name],
        )?;
        Ok(())
    }

    /// Records the sign-in state a runner reported.
    pub fn builtin_status(&self, name: &str, status: &BuiltinStatus) -> Result<()> {
        self.lock().execute(
            "UPDATE builtin_agents SET signed_in = ?2, login_method = ?3, login_ends = ?4,
                 status_detail = ?5, cli_version = COALESCE(?6, cli_version),
                 status_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now'),
                 last_seen_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
             WHERE name = ?1",
            params![
                name,
                status.signed_in,
                status.login_method,
                status.login_ends,
                status.detail,
                status.cli_version
            ],
        )?;
        Ok(())
    }
}

/// Whether a database already has the built-in agent tables (for tests of
/// older databases).
#[cfg(test)]
pub(super) fn has_builtin_tables(conn: &rusqlite::Connection) -> Result<bool> {
    Ok(conn.query_row(
        "SELECT COUNT(*) = 3 FROM sqlite_master WHERE type = 'table'
           AND name IN ('builtin_agents', 'agent_runs', 'agent_run_events')",
        [],
        |row| row.get(0),
    )?)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn temp_db(label: &str) -> (Db, std::path::PathBuf) {
        let dir =
            std::env::temp_dir().join(format!("lore-builtin-test-{label}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("lore.db");
        (Db::open(&path).unwrap(), path)
    }

    #[test]
    fn a_database_from_the_previous_schema_opens_unchanged_and_gains_the_tables() {
        let (db, path) = temp_db("old");
        // What a database of schema 3 looks like: no built-in tables.
        db.execute_for_test(
            "DROP TABLE builtin_agents; DROP TABLE agent_runs; DROP TABLE agent_run_events;
             UPDATE meta SET value = '3' WHERE key = 'schema_version';
             INSERT INTO entries (project, kind, title, body, agent)
               VALUES ('lore', 'note', 'kept', 'body', 'claude');
             INSERT INTO agent_registry (name, kind, avatar, note) VALUES ('claude', 'token', 'nova', 'n');
             INSERT INTO tasks (project, title, created_by, created_at, updated_at)
               VALUES ('lore', 'a task', 'claude', 'x', 'x');",
        );
        assert!(!has_builtin_tables(&db.lock()).unwrap());
        let before: HashMap<String, i64> = db.table_counts().unwrap().into_iter().collect();
        drop(db);
        let db = Db::open(&path).unwrap();
        assert!(has_builtin_tables(&db.lock()).unwrap());
        let after: HashMap<String, i64> = db.table_counts().unwrap().into_iter().collect();
        for (table, count) in &before {
            assert_eq!(after.get(table), Some(count), "{table}");
        }
        assert_eq!(after["builtin_agents"], 0);
        assert_eq!(
            super::super::schema_version(&db.lock()).unwrap(),
            super::super::SCHEMA_VERSION
        );
        let claude = db.registry_agent("claude").unwrap().unwrap();
        assert_eq!(
            (claude.kind.as_str(), claude.avatar.as_str()),
            ("token", "nova")
        );
        // Without LORE_RUNNER_TOKENS nothing else is written.
        assert!(db.builtin_agent("claude").unwrap().is_none());
    }

    #[test]
    fn built_in_agents_are_registered_and_keep_their_settings() {
        let (db, _) = temp_db("register");
        let agents = vec![
            ("claude-builtin".to_string(), "claude".to_string(), "ember"),
            (
                "deepseek-builtin".to_string(),
                "opencode".to_string(),
                "wave",
            ),
        ];
        db.register_builtin_agents(&agents).unwrap();
        let registry = db.registry_agent("claude-builtin").unwrap().unwrap();
        assert_eq!(
            (registry.kind.as_str(), registry.avatar.as_str()),
            ("builtin", "ember")
        );
        let changed = db
            .update_builtin_settings(
                "claude-builtin",
                &BuiltinSettings {
                    model: Some("sonnet".into()),
                    enabled: Some(true),
                    daily_cap: Some(3),
                    active_hours: Some("08:00-20:00".into()),
                    ..BuiltinSettings::default()
                },
                "admin",
            )
            .unwrap();
        assert_eq!(changed.model, "sonnet");
        assert!(changed.enabled && !changed.available);
        db.builtin_connected(
            "claude-builtin",
            "claude",
            "anthropic",
            "0.1.0",
            Some("2.1"),
        )
        .unwrap();
        db.builtin_status(
            "claude-builtin",
            &BuiltinStatus {
                signed_in: true,
                login_method: "setup-token".into(),
                login_ends: Some("2027-11-26T00:00:00Z".into()),
                detail: "ok".into(),
                cli_version: None,
            },
        )
        .unwrap();
        let agent = db.builtin_agent("claude-builtin").unwrap().unwrap();
        assert!(agent.connected && agent.signed_in);
        assert_eq!(agent.cli_version, "2.1");
        // Registering again (a restart) keeps the settings, marks it
        // disconnected, and leaves a changed avatar alone.
        db.set_agent_details("claude-builtin", Some("nova"), None, "admin")
            .unwrap();
        db.register_builtin_agents(&agents).unwrap();
        let agent = db.builtin_agent("claude-builtin").unwrap().unwrap();
        assert!(!agent.connected && agent.signed_in);
        assert_eq!((agent.model.as_str(), agent.daily_cap), ("sonnet", 3));
        assert_eq!(
            db.registry_agent("claude-builtin").unwrap().unwrap().avatar,
            "nova"
        );
        // A name another kind of agent has is refused.
        db.register_token_agents(&["codex".into()]).unwrap();
        assert!(
            db.register_builtin_agents(&[("codex".into(), "codex".into(), "prism")])
                .is_err()
        );
        assert!(db.builtin_agent("codex").unwrap().is_none());
        // An OAuth agent cannot be re-authorized under a built-in name.
        assert!(db.oauth_agents().unwrap().is_empty());
    }
}
