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
-- A board task another agent handed to a built-in agent (`delegate`,
-- schema 6): who asked, through which token, and for which agent. The
-- task itself is an ordinary board task.
CREATE TABLE IF NOT EXISTS delegations (
    task_id      INTEGER PRIMARY KEY,
    agent        TEXT NOT NULL,
    requested_by TEXT NOT NULL,
    via          TEXT NOT NULL DEFAULT '',
    created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
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

/// Lines of output kept per run; later ones are counted, not stored.
pub const RUN_EVENTS_KEPT: i64 = 2000;

/// Runs whose output is kept; older runs keep their row, not their lines.
const RUNS_WITH_EVENTS: i64 = 200;

/// The columns of a run row, in the order `Run::from_row` reads them.
const RUN_COLUMNS: &str = "id, agent, task_id, kind, project, repo, provider, status, \
     started_at, ended_at, exit_code, summary, commit_hash, model, task_title, pushed, \
     work_free_bytes, output_lines, created_at, scope, requested_by, conversation";

/// One run of a built-in agent, as the admin page and the runner see it.
/// The token is never part of it, not even hashed.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct Run {
    pub id: String,
    pub agent: String,
    pub task_id: Option<i64>,
    pub kind: String,
    pub project: String,
    pub repo: String,
    pub provider: String,
    /// starting | running | done | pushed | failed | stopped | timeout |
    /// interrupted
    pub status: String,
    pub started_at: Option<String>,
    pub ended_at: Option<String>,
    pub exit_code: Option<i64>,
    pub summary: String,
    #[serde(rename = "commit")]
    pub commit_hash: String,
    pub model: String,
    pub task_title: String,
    pub pushed: bool,
    pub work_free_bytes: Option<i64>,
    pub output_lines: i64,
    pub created_at: String,
    /// The JSON scope (provider, repository, Dokploy project, zone).
    #[serde(skip)]
    pub scope: String,
    /// The agent that delegated the task or asked the question; empty for
    /// the scheduler's own board runs.
    pub requested_by: String,
    /// The conversation a chat run belongs to; empty for other runs.
    pub conversation: String,
}

impl Run {
    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get(0)?,
            agent: row.get(1)?,
            task_id: row.get(2)?,
            kind: row.get(3)?,
            project: row.get(4)?,
            repo: row.get(5)?,
            provider: row.get(6)?,
            status: row.get(7)?,
            started_at: row.get(8)?,
            ended_at: row.get(9)?,
            exit_code: row.get(10)?,
            summary: row.get(11)?,
            commit_hash: row.get(12)?,
            model: row.get(13)?,
            task_title: row.get(14)?,
            pushed: row.get(15)?,
            work_free_bytes: row.get(16)?,
            output_lines: row.get(17)?,
            created_at: row.get(18)?,
            scope: row.get(19)?,
            requested_by: row.get(20)?,
            conversation: row.get(21)?,
        })
    }
}

/// A run as it starts. The token is given only as its hash.
#[derive(Debug, Default)]
pub struct NewRun {
    pub id: String,
    pub agent: String,
    pub task_id: Option<i64>,
    pub kind: String,
    pub project: String,
    pub repo: String,
    pub provider: String,
    pub model: String,
    pub task_title: String,
    pub token_hash: String,
    pub token_expires_at: i64,
    pub scope: String,
    pub requested_by: String,
    pub conversation: String,
}

/// A task another agent delegated to a built-in agent.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Delegation {
    pub task_id: i64,
    pub agent: String,
    /// The agent that delegated it (its session's name).
    pub requested_by: String,
    /// The token it called with, when that names another agent.
    pub via: String,
    pub created_at: String,
}

/// The latest run of a conversation, for a follow-up `ask`.
#[derive(Debug, Clone)]
pub struct ConversationRun {
    pub run: Run,
    /// The CLI's own session id, when the runner reported one.
    pub cli_session: String,
    /// Seconds since the run ended (or started, while it runs).
    pub age_secs: i64,
}

/// How a run ended.
#[derive(Debug, Default)]
pub struct RunEnd {
    pub status: String,
    pub exit_code: Option<i64>,
    pub summary: String,
    pub commit: String,
    pub pushed: bool,
    pub work_free_bytes: Option<i64>,
}

/// One stored line of a run's output (already redacted).
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct RunEvent {
    pub seq: i64,
    pub at: String,
    pub stream: String,
    pub body: String,
}

/// An open, unclaimed task as the task runner sees it.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AutoTask {
    #[serde(flatten)]
    pub task: super::Task,
    /// Not touched for the idle threshold.
    pub idle: bool,
    /// Taken or skipped by the runner since it was last touched.
    pub waiting: bool,
    pub auto_attempts: i64,
}

impl Db {
    /// Sets a task's target fields (repository, Dokploy project,
    /// Cloudflare zone). Touches the task, so the runner looks at it
    /// again. `None` when there is no such task.
    pub fn set_task_targets(
        &self,
        id: i64,
        targets: &super::TaskTargets,
    ) -> Result<Option<super::Task>> {
        let targets = super::normalize_task_targets(targets)?;
        let conn = self.lock();
        let changed = conn.execute(
            "UPDATE tasks SET repo = ?2, dokploy_project_id = ?3, cloudflare_zone = ?4,
                 updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
             WHERE id = ?1",
            params![
                id,
                targets.repo,
                targets.dokploy_project_id,
                targets.cloudflare_zone
            ],
        )?;
        if changed == 0 {
            return Ok(None);
        }
        super::get_task(&conn, id)
    }

    /// The repository lore recorded most recently for a project: the
    /// newest `repo` of an entry or a session, whatever its host. Empty
    /// values and "none" are not repositories.
    pub fn latest_project_repo(&self, project: &str) -> Result<Option<String>> {
        Ok(self
            .lock()
            .query_row(
                "SELECT repo FROM (
                     SELECT repo, created_at AS at FROM entries
                      WHERE project = ?1 AND repo != '' AND lower(repo) != 'none'
                     UNION ALL
                     SELECT repo, started_at AS at FROM sessions
                      WHERE project = ?1 AND repo != '' AND lower(repo) != 'none'
                 ) ORDER BY at DESC LIMIT 1",
                params![project],
                |row| row.get(0),
            )
            .optional()?)
    }

    /// Every open, unclaimed task, oldest first, with whether it is idle
    /// (not updated for `idle_minutes`) and whether the runner already
    /// took or skipped it since it was last touched.
    pub fn auto_tasks(&self, idle_minutes: i64, limit: usize) -> Result<Vec<AutoTask>> {
        let conn = self.lock();
        let sql = format!(
            "SELECT {}, updated_at <= strftime('%Y-%m-%dT%H:%M:%SZ', 'now', ?1),
                    auto_last_at IS NOT NULL AND auto_last_at >= updated_at, auto_attempts
             FROM tasks WHERE status = 'open' AND claimed_by = ''
             ORDER BY created_at, id LIMIT ?2",
            super::TASK_COLUMNS
        );
        let mut stmt = conn.prepare(&sql)?;
        let offset = format!("-{} minutes", idle_minutes.max(0));
        let rows = stmt.query_map(params![offset, limit as i64], |row| {
            Ok(AutoTask {
                task: super::Task::from_row(row)?,
                idle: row.get(18)?,
                waiting: row.get(19)?,
                auto_attempts: row.get(20)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Notes on a task why the runner skipped it, without touching it: it
    /// waits until someone does.
    pub fn note_task_skip(&self, id: i64, note: &str) -> Result<()> {
        let note: String = note.chars().take(super::NOTE_MAX_CHARS).collect();
        self.lock().execute(
            "UPDATE tasks SET note = ?2, auto_last_at = updated_at WHERE id = ?1",
            params![id, note],
        )?;
        Ok(())
    }

    /// Records that the runner took a task (counted) or left it (not
    /// counted): either way it waits until it is touched again.
    pub fn mark_task_auto(&self, id: i64, attempt: bool) -> Result<()> {
        self.lock().execute(
            "UPDATE tasks SET auto_attempts = auto_attempts + ?2, auto_last_at = updated_at
             WHERE id = ?1",
            params![id, i64::from(attempt)],
        )?;
        Ok(())
    }

    /// A new run. Its token is stored only as `token_hash`.
    pub fn insert_run(&self, new: &NewRun) -> Result<Run> {
        let conn = self.lock();
        conn.execute(
            "INSERT INTO agent_runs (id, agent, task_id, kind, project, repo, provider, status,
                                     started_at, token_hash, token_expires_at, scope, model,
                                     task_title, requested_by, conversation)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'starting',
                     strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            params![
                new.id,
                new.agent,
                new.task_id,
                new.kind,
                new.project,
                new.repo,
                new.provider,
                new.token_hash,
                new.token_expires_at,
                new.scope,
                new.model,
                new.task_title,
                new.requested_by,
                new.conversation
            ],
        )?;
        get_run(&conn, &new.id)?.context("run vanished after insert")
    }

    pub fn run(&self, id: &str) -> Result<Option<Run>> {
        get_run(&self.lock(), id)
    }

    /// The runner started the CLI: the run is running.
    pub fn run_running(&self, id: &str, cli_session: Option<&str>) -> Result<()> {
        self.lock().execute(
            "UPDATE agent_runs SET status = CASE WHEN status = 'starting' THEN 'running'
                                                ELSE status END,
                 cli_session = COALESCE(?2, cli_session)
             WHERE id = ?1",
            params![id, cli_session],
        )?;
        Ok(())
    }

    /// The run ended: its outcome is kept, its token is gone.
    pub fn finish_run(&self, id: &str, end: &RunEnd) -> Result<Option<Run>> {
        let conn = self.lock();
        conn.execute(
            "UPDATE agent_runs SET status = ?2, exit_code = ?3, summary = ?4, commit_hash = ?5,
                 pushed = ?6, work_free_bytes = COALESCE(?7, work_free_bytes),
                 ended_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now'),
                 token_hash = NULL, token_expires_at = NULL
             WHERE id = ?1",
            params![
                id,
                end.status,
                end.exit_code,
                end.summary.chars().take(1000).collect::<String>(),
                end.commit,
                end.pushed,
                end.work_free_bytes
            ],
        )?;
        get_run(&conn, id)
    }

    /// Revokes a run's token at once (a stop, the hard limit), before the
    /// run's end is known.
    pub fn revoke_run_token(&self, id: &str) -> Result<()> {
        self.lock().execute(
            "UPDATE agent_runs SET token_hash = NULL, token_expires_at = NULL WHERE id = ?1",
            params![id],
        )?;
        Ok(())
    }

    /// The open run a token hash belongs to, while the token is valid:
    /// the run has not ended, the token was not revoked, and `now` (unix
    /// seconds) is before its hard limit. Answers `(run id, agent, scope)`.
    pub fn run_for_token(&self, hash: &str, now: i64) -> Result<Option<(String, String, String)>> {
        Ok(self
            .lock()
            .query_row(
                "SELECT id, agent, scope FROM agent_runs
                 WHERE token_hash = ?1 AND token_expires_at > ?2
                   AND status IN ('starting', 'running')",
                params![hash, now],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?)
    }

    /// The newest runs, open ones first.
    pub fn runs(&self, limit: usize) -> Result<Vec<Run>> {
        let conn = self.lock();
        let sql = format!(
            "SELECT {RUN_COLUMNS} FROM agent_runs
             ORDER BY status IN ('starting', 'running') DESC, created_at DESC, rowid DESC
             LIMIT ?1"
        );
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(params![limit as i64], Run::from_row)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Runs that have not ended.
    pub fn open_runs(&self) -> Result<Vec<Run>> {
        let conn = self.lock();
        let sql = format!(
            "SELECT {RUN_COLUMNS} FROM agent_runs WHERE status IN ('starting', 'running')
             ORDER BY created_at"
        );
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map([], Run::from_row)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Task runs an agent started since midnight UTC, for its daily cap.
    pub fn task_runs_today(&self, agent: &str) -> Result<i64> {
        Ok(self.lock().query_row(
            "SELECT COUNT(*) FROM agent_runs
             WHERE agent = ?1 AND kind = 'task'
               AND created_at >= strftime('%Y-%m-%dT00:00:00Z', 'now')",
            params![agent],
            |row| row.get(0),
        )?)
    }

    /// Stores one line of a run's (already redacted) output. Past
    /// `RUN_EVENTS_KEPT` lines only the count grows.
    pub fn add_run_event(&self, run_id: &str, seq: i64, stream: &str, body: &str) -> Result<()> {
        let conn = self.lock();
        let lines: i64 = conn
            .query_row(
                "SELECT output_lines FROM agent_runs WHERE id = ?1",
                params![run_id],
                |row| row.get(0),
            )
            .optional()?
            .unwrap_or(0);
        if lines < RUN_EVENTS_KEPT {
            conn.execute(
                "INSERT INTO agent_run_events (run_id, seq, stream, body) VALUES (?1, ?2, ?3, ?4)",
                params![run_id, seq, stream, body],
            )?;
        }
        conn.execute(
            "UPDATE agent_runs SET output_lines = output_lines + 1 WHERE id = ?1",
            params![run_id],
        )?;
        Ok(())
    }

    /// A run's stored output after `after` (a `seq`), oldest first.
    pub fn run_events(&self, run_id: &str, after: i64, limit: usize) -> Result<Vec<RunEvent>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT seq, at, stream, body FROM agent_run_events
             WHERE run_id = ?1 AND seq > ?2 ORDER BY seq LIMIT ?3",
        )?;
        let rows = stmt.query_map(params![run_id, after, limit as i64], |row| {
            Ok(RunEvent {
                seq: row.get(0)?,
                at: row.get(1)?,
                stream: row.get(2)?,
                body: row.get(3)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Records that `requested_by` (through the token of `via`) handed
    /// task `task_id` to the built-in agent `agent`.
    pub fn add_delegation(
        &self,
        task_id: i64,
        agent: &str,
        requested_by: &str,
        via: &str,
    ) -> Result<()> {
        self.lock().execute(
            "INSERT OR REPLACE INTO delegations (task_id, agent, requested_by, via)
             VALUES (?1, ?2, ?3, ?4)",
            params![task_id, agent, requested_by, via],
        )?;
        Ok(())
    }

    /// The delegation of a task, when it was delegated.
    pub fn delegation(&self, task_id: i64) -> Result<Option<Delegation>> {
        Ok(self
            .lock()
            .query_row(
                "SELECT task_id, agent, requested_by, via, created_at FROM delegations
                 WHERE task_id = ?1",
                params![task_id],
                delegation_row,
            )
            .optional()?)
    }

    /// Delegated tasks that wait for their agent: open, unclaimed, and
    /// not taken or skipped since they were last touched. Oldest first.
    pub fn waiting_delegations(&self) -> Result<Vec<(super::Task, Delegation)>> {
        let conn = self.lock();
        let columns: Vec<String> = super::TASK_COLUMNS
            .split(',')
            .map(|column| format!("t.{}", column.trim()))
            .collect();
        let sql = format!(
            "SELECT {}, d.task_id, d.agent, d.requested_by, d.via, d.created_at
             FROM delegations d JOIN tasks t ON t.id = d.task_id
             WHERE t.status = 'open' AND t.claimed_by = ''
               AND (t.auto_last_at IS NULL OR t.auto_last_at < t.updated_at)
             ORDER BY d.created_at, t.id",
            columns.join(", ")
        );
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map([], |row| {
            Ok((
                super::Task::from_row(row)?,
                Delegation {
                    task_id: row.get(18)?,
                    agent: row.get(19)?,
                    requested_by: row.get(20)?,
                    via: row.get(21)?,
                    created_at: row.get(22)?,
                },
            ))
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// The latest run of a conversation.
    pub fn conversation_run(&self, conversation: &str) -> Result<Option<ConversationRun>> {
        let sql = format!(
            "SELECT {RUN_COLUMNS}, cli_session,
                    CAST(strftime('%s', 'now') - strftime('%s', COALESCE(ended_at, started_at,
                         created_at)) AS INTEGER)
             FROM agent_runs WHERE conversation = ?1 AND conversation != ''
             ORDER BY created_at DESC, rowid DESC LIMIT 1"
        );
        Ok(self
            .lock()
            .query_row(&sql, params![conversation], |row| {
                Ok(ConversationRun {
                    run: Run::from_row(row)?,
                    cli_session: row.get(22)?,
                    age_secs: row.get::<_, Option<i64>>(23)?.unwrap_or(i64::MAX),
                })
            })
            .optional()?)
    }

    /// Drops the output of all but the newest runs.
    pub fn prune_run_events(&self) -> Result<()> {
        self.lock().execute(
            "DELETE FROM agent_run_events WHERE run_id NOT IN (
                 SELECT id FROM agent_runs ORDER BY created_at DESC, rowid DESC LIMIT ?1)",
            params![RUNS_WITH_EVENTS],
        )?;
        Ok(())
    }
}

#[cfg(test)]
impl Db {
    /// A run's token hash, for tests that check it was revoked.
    pub fn run_token_hash(&self, id: &str) -> Result<Option<String>> {
        Ok(self.lock().query_row(
            "SELECT token_hash FROM agent_runs WHERE id = ?1",
            params![id],
            |row| row.get(0),
        )?)
    }
}

fn delegation_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Delegation> {
    Ok(Delegation {
        task_id: row.get(0)?,
        agent: row.get(1)?,
        requested_by: row.get(2)?,
        via: row.get(3)?,
        created_at: row.get(4)?,
    })
}

fn get_run(conn: &rusqlite::Connection, id: &str) -> Result<Option<Run>> {
    let sql = format!("SELECT {RUN_COLUMNS} FROM agent_runs WHERE id = ?1");
    Ok(conn
        .query_row(&sql, params![id], Run::from_row)
        .optional()?)
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
    fn a_database_of_schema_4_opens_with_every_row_and_gains_the_runner_columns() {
        let (db, path) = temp_db("schema4");
        // What a database of schema 4 looks like: the built-in tables, but
        // none of the task runner's columns.
        db.execute_for_test(
            "ALTER TABLE tasks DROP COLUMN repo;
             ALTER TABLE tasks DROP COLUMN dokploy_project_id;
             ALTER TABLE tasks DROP COLUMN cloudflare_zone;
             ALTER TABLE tasks DROP COLUMN auto_attempts;
             ALTER TABLE tasks DROP COLUMN auto_last_at;
             ALTER TABLE agent_runs DROP COLUMN model;
             ALTER TABLE agent_runs DROP COLUMN task_title;
             ALTER TABLE agent_runs DROP COLUMN pushed;
             ALTER TABLE agent_runs DROP COLUMN work_free_bytes;
             ALTER TABLE agent_runs DROP COLUMN cli_session;
             ALTER TABLE agent_runs DROP COLUMN output_lines;
             UPDATE meta SET value = '4' WHERE key = 'schema_version';
             INSERT INTO entries (project, kind, title, body, agent)
               VALUES ('lore', 'note', 'kept', 'body', 'claude');
             INSERT INTO tasks (project, title, body, status, created_by, note, created_at, updated_at)
               VALUES ('lore', 'a task', 'details', 'open', 'claude', 'a note', '2025-01-01T00:00:00Z', '2025-01-02T00:00:00Z');
             INSERT INTO builtin_agents (name, kind, model, enabled) VALUES ('claude-builtin', 'claude', 'opus', 1);
             INSERT INTO agent_runs (id, agent, kind, status) VALUES ('old-run', 'claude-builtin', 'task', 'done');",
        );
        let before: HashMap<String, i64> = db.table_counts().unwrap().into_iter().collect();
        drop(db);
        let db = Db::open(&path).unwrap();
        let after: HashMap<String, i64> = db.table_counts().unwrap().into_iter().collect();
        for (table, count) in &before {
            assert_eq!(after.get(table), Some(count), "{table}");
        }
        assert_eq!(
            super::super::schema_version(&db.lock()).unwrap(),
            super::super::SCHEMA_VERSION
        );
        let task = &db.tasks(None, &[], 10).unwrap()[0];
        assert_eq!(
            (task.title.as_str(), task.body.as_str(), task.note.as_str()),
            ("a task", "details", "a note")
        );
        assert_eq!(task.updated_at, "2025-01-02T00:00:00Z");
        assert!(task.repo.is_empty() && task.dokploy_project_id.is_empty());
        let auto = &db.auto_tasks(120, 10).unwrap()[0];
        assert!(auto.idle && !auto.waiting && auto.auto_attempts == 0);
        let run = db.run("old-run").unwrap().unwrap();
        assert_eq!((run.status.as_str(), run.pushed), ("done", false));
        assert_eq!(
            db.builtin_agent("claude-builtin").unwrap().unwrap().model,
            "opus"
        );
    }

    #[test]
    fn a_database_of_schema_5_opens_with_every_row_and_gains_the_help_fields() {
        let (db, path) = temp_db("schema5");
        // What a database of schema 5 looks like: the task runner's columns,
        // but no delegations and no help columns on the runs.
        db.execute_for_test(
            "DROP TABLE delegations;
             ALTER TABLE agent_runs DROP COLUMN requested_by;
             ALTER TABLE agent_runs DROP COLUMN conversation;
             UPDATE meta SET value = '5' WHERE key = 'schema_version';
             INSERT INTO entries (project, kind, title, body, agent)
               VALUES ('lore', 'note', 'kept', 'body', 'claude');
             INSERT INTO tasks (project, title, body, status, created_by, repo, created_at, updated_at)
               VALUES ('shop', 'a task', 'details', 'open', 'codex', 'github.com/me/shop',
                       '2025-01-01T00:00:00Z', '2025-01-02T00:00:00Z');
             INSERT INTO builtin_agents (name, kind, model, available) VALUES ('claude-builtin', 'claude', 'opus', 1);
             INSERT INTO agent_runs (id, agent, kind, status, summary, commit_hash, pushed, cli_session)
               VALUES ('old-run', 'claude-builtin', 'task', 'pushed', 'it went', 'abc1234', 1, 'sess-9');",
        );
        let before: HashMap<String, i64> = db.table_counts().unwrap().into_iter().collect();
        drop(db);
        let db = Db::open(&path).unwrap();
        let after: HashMap<String, i64> = db.table_counts().unwrap().into_iter().collect();
        for (table, count) in &before {
            assert_eq!(after.get(table), Some(count), "{table}");
        }
        assert_eq!(after["delegations"], 0);
        assert_eq!(
            super::super::schema_version(&db.lock()).unwrap(),
            super::super::SCHEMA_VERSION
        );
        let run = db.run("old-run").unwrap().unwrap();
        assert_eq!(
            (
                run.status.as_str(),
                run.summary.as_str(),
                run.commit_hash.as_str(),
                run.pushed
            ),
            ("pushed", "it went", "abc1234", true)
        );
        assert!(run.requested_by.is_empty() && run.conversation.is_empty());
        let task = &db.tasks(None, &[], 10).unwrap()[0];
        assert_eq!(
            (task.title.as_str(), task.repo.as_str()),
            ("a task", "github.com/me/shop")
        );
        assert!(db.delegation(task.id).unwrap().is_none());
        assert!(
            db.builtin_agent("claude-builtin")
                .unwrap()
                .unwrap()
                .available
        );
        // The new fields work on the old rows.
        db.add_delegation(task.id, "claude-builtin", "codex", "")
            .unwrap();
        let waiting = db.waiting_delegations().unwrap();
        assert_eq!(waiting.len(), 1);
        assert_eq!(waiting[0].1.requested_by, "codex");
        assert_eq!(waiting[0].0.id, task.id);
        assert!(db.conversation_run("").unwrap().is_none());
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
