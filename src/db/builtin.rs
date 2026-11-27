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
-- Every ref update lore let a run make (schema 8): a push through the git
-- proxy (`via` push) or a `repo_commit` (`via` repo_commit). `old` is
-- empty or zeros for a branch the run created. A task is marked done only
-- when its default branch points at a `new` recorded here for the run.
CREATE TABLE IF NOT EXISTS agent_run_refs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id     TEXT NOT NULL,
    ref        TEXT NOT NULL,
    old        TEXT NOT NULL DEFAULT '',
    new        TEXT NOT NULL,
    via        TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
CREATE INDEX IF NOT EXISTS agent_run_refs_run ON agent_run_refs (run_id);
-- What a built-in agent's run wrote to the shared memory and the board
-- (schema 8): `kind` entry or message, the row's id, and the run. lore
-- sets it itself, so briefings and `recall` can mark such text as written
-- by a built-in run.
CREATE TABLE IF NOT EXISTS run_writes (
    kind       TEXT NOT NULL,
    item_id    INTEGER NOT NULL,
    run_id     TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    PRIMARY KEY (kind, item_id)
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
    /// The owner's per-agent switch "may read other services during runs"
    /// (schema 7, off by default): a board run then also reads the services
    /// its task's author may read, beyond the task's own targets.
    pub read_other_services: bool,
    /// What a terminal's CLI may do with the services (schema 9): `None`
    /// what the agent may, `read`, or `off`.
    pub terminal_services: Option<String>,
    /// Claude: the credential used first when both are stored (schema 9):
    /// `None` the subscription, or `api_key`.
    pub claude_priority: Option<String>,
    /// Claude: fall back to the other credential when the first cannot be
    /// used (schema 9); `None` is off.
    pub claude_fallback: Option<bool>,
}

const BUILTIN_COLUMNS: &str = "name, kind, provider, model, enabled, available, daily_cap, \
     active_hours, connected, connected_at, last_seen_at, runner_version, cli_version, \
     signed_in, login_method, login_ends, status_detail, status_at, updated_at, updated_by, \
     read_other_services, terminal_services, claude_priority, claude_fallback";

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
            read_other_services: row.get(20)?,
            terminal_services: row.get(21)?,
            claude_priority: row.get(22)?,
            claude_fallback: row.get(23)?,
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
        // A model is handed to the CLI as an argument: one that starts with
        // `-` would be read as an option.
        if let Some(model) = &settings.model
            && !valid_model(model)
        {
            anyhow::bail!(
                "the model must be a plain name (letters, digits, `-`, `_`, `.`, `:`, `/`, `@`, \
                 `[`, `]`), not starting with `-`"
            );
        }
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

    /// The owner's switch "may read other services during runs" for one
    /// built-in agent.
    pub fn set_builtin_read_other_services(&self, name: &str, on: bool, by: &str) -> Result<()> {
        let changed = self.lock().execute(
            "UPDATE builtin_agents SET read_other_services = ?2,
                 updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), updated_by = ?3
             WHERE name = ?1",
            params![name, on, by],
        )?;
        if changed == 0 {
            anyhow::bail!("there is no built-in agent by that name");
        }
        Ok(())
    }

    /// What a terminal's CLI may do with the services: `None` (what the
    /// agent may), `read` or `off`.
    pub fn set_builtin_terminal_services(
        &self,
        name: &str,
        services: Option<&str>,
        by: &str,
    ) -> Result<()> {
        if services.is_some_and(|value| !matches!(value, "read" | "off")) {
            anyhow::bail!("the terminal's services are `same`, `read` or `off`");
        }
        let changed = self.lock().execute(
            "UPDATE builtin_agents SET terminal_services = ?2,
                 updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), updated_by = ?3
             WHERE name = ?1",
            params![name, services, by],
        )?;
        if changed == 0 {
            anyhow::bail!("there is no built-in agent by that name");
        }
        Ok(())
    }

    /// Claude's credentials: which comes first (`None` the subscription,
    /// or `api_key`) and whether to fall back to the other.
    pub fn set_builtin_claude_credentials(
        &self,
        name: &str,
        priority: Option<&str>,
        fallback: bool,
        by: &str,
    ) -> Result<()> {
        if priority.is_some_and(|value| value != "api_key") {
            anyhow::bail!("the first credential is `subscription` or `api_key`");
        }
        let changed = self.lock().execute(
            "UPDATE builtin_agents SET claude_priority = ?2, claude_fallback = ?3,
                 updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), updated_by = ?4
             WHERE name = ?1",
            params![name, priority, fallback.then_some(true), by],
        )?;
        if changed == 0 {
            anyhow::bail!("there is no built-in agent by that name");
        }
        Ok(())
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

    /// Notes why lore refused a runner (another protocol version, another
    /// CLI than the agent was set up with), where the admin page shows the
    /// sign-in detail.
    pub fn builtin_refused(&self, name: &str, reason: &str) -> Result<()> {
        let reason: String = reason
            .chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .take(300)
            .collect();
        self.lock().execute(
            "UPDATE builtin_agents SET status_detail = ?2,
                 status_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
             WHERE name = ?1",
            params![name, format!("lore refused this agent's runner: {reason}")],
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

/// Whether a model name may be handed to a CLI: non-empty is checked by
/// the caller; empty means the CLI's default. Never an option (`-x`).
pub fn valid_model(model: &str) -> bool {
    let model = model.trim();
    model.is_empty()
        || (model.len() <= 200
            && !model.starts_with('-')
            && model.chars().all(|c| {
                c.is_ascii_alphanumeric()
                    || matches!(c, '-' | '_' | '.' | ':' | '/' | '@' | '[' | ']')
            }))
}

/// Lines of output kept per run; later ones are counted, not stored.
pub const RUN_EVENTS_KEPT: i64 = 2000;

/// Bytes of output kept per run; past them lines are counted, not stored.
pub const RUN_EVENT_BYTES_KEPT: i64 = 1024 * 1024;

/// Runs whose output is kept; older runs keep their row, not their lines.
const RUNS_WITH_EVENTS: i64 = 200;

/// Bytes of stored output across every run; the oldest runs' lines go
/// first when there is more.
pub const RUN_EVENT_BYTES_TOTAL: i64 = 64 * 1024 * 1024;

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
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
    /// Taken or skipped by the runner since it was last re-queued (a touch
    /// by a signed-in user or by the task's author).
    pub waiting: bool,
    pub auto_attempts: i64,
    /// The verified identity that added the task (schema 7): a token's
    /// agent, `user:<id>` / `user:admin` for the admin page, `run:<agent>`
    /// for a built-in agent's run; empty when unknown (older tasks).
    pub author: String,
}

/// The task runner's own fields of a task, for the JSON backup.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TaskRunnerState {
    pub task_id: i64,
    #[serde(default)]
    pub author: String,
    #[serde(default)]
    pub touches: i64,
    #[serde(default)]
    pub auto_seen: Option<i64>,
    #[serde(default)]
    pub auto_attempts: i64,
    #[serde(default)]
    pub auto_last_at: Option<String>,
}

/// The SQL that says a task waits: the runner took or skipped it since its
/// last re-queueing touch.
const WAITING_SQL: &str = "(auto_seen IS NOT NULL AND auto_seen >= touches)";

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

    /// Records who added a task: the identity lore verified (see
    /// `AutoTask::author`).
    pub fn set_task_author(&self, id: i64, author: &str) -> Result<()> {
        self.lock().execute(
            "UPDATE tasks SET author = ?2 WHERE id = ?1",
            params![id, author.trim()],
        )?;
        Ok(())
    }

    /// Who added a task, as lore verified it; empty when unknown.
    pub fn task_author(&self, id: i64) -> Result<String> {
        Ok(self
            .lock()
            .query_row(
                "SELECT author FROM tasks WHERE id = ?1",
                params![id],
                |row| row.get(0),
            )
            .optional()?
            .unwrap_or_default())
    }

    /// A touch that re-queues a task for the runner: by a signed-in user
    /// (`reset`: the automatic attempts start over) or by the task's
    /// author (the attempts keep counting toward their maximum).
    pub fn requeue_task(&self, id: i64, reset: bool) -> Result<()> {
        self.lock().execute(
            "UPDATE tasks SET touches = touches + 1,
                 auto_attempts = CASE WHEN ?2 THEN 0 ELSE auto_attempts END
             WHERE id = ?1",
            params![id, reset],
        )?;
        Ok(())
    }

    /// The repositories lore recorded for a project, newest first, each
    /// with the token agent of the session that wrote it (schema 7; empty
    /// for records written before lore kept it). Empty values and "none"
    /// are not repositories.
    pub fn project_repo_records(
        &self,
        project: &str,
        limit: usize,
    ) -> Result<Vec<(String, String)>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT repo, token_agent FROM (
                 SELECT e.repo AS repo, COALESCE(s.token_agent, '') AS token_agent,
                        e.created_at AS at
                   FROM entries e LEFT JOIN sessions s ON s.id = e.session_id
                  WHERE e.project = ?1 AND e.repo != '' AND lower(e.repo) != 'none'
                 UNION ALL
                 SELECT repo, token_agent, started_at AS at FROM sessions
                  WHERE project = ?1 AND repo != '' AND lower(repo) != 'none'
             ) ORDER BY at DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![project, limit as i64], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
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

    /// One open, unclaimed task as the scheduler sees it, for a hand-off
    /// the owner asked for (manual or not).
    pub fn auto_task(&self, id: i64) -> Result<Option<AutoTask>> {
        Ok(self
            .auto_tasks_where(0, 1, &format!("AND id = {id}"))?
            .into_iter()
            .next())
    }

    /// Every open, unclaimed task, oldest first, with whether it is idle
    /// (not updated for `idle_minutes`) and whether the runner already
    /// took or skipped it since it was last re-queued.
    pub fn auto_tasks(&self, idle_minutes: i64, limit: usize) -> Result<Vec<AutoTask>> {
        self.auto_tasks_where(idle_minutes, limit, "")
    }

    /// The tasks the scheduler may take now, oldest first: open,
    /// unclaimed, idle, not waiting, under `max_attempts` automatic
    /// attempts, not delegated (a delegated task waits for its own agent)
    /// and not manual (lore never assigns a manual task by itself). Filtered here, before the limit, so skipped tasks never
    /// crowd out eligible ones.
    pub fn eligible_auto_tasks(
        &self,
        idle_minutes: i64,
        max_attempts: i64,
        limit: usize,
    ) -> Result<Vec<AutoTask>> {
        let filter = format!(
            "AND updated_at <= strftime('%Y-%m-%dT%H:%M:%SZ', 'now', ?1)
             AND NOT {WAITING_SQL} AND auto_attempts < {}
             AND id NOT IN (SELECT task_id FROM delegations)
             AND COALESCE(manual, 0) = 0",
            max_attempts.max(0)
        );
        self.auto_tasks_where(idle_minutes, limit, &filter)
    }

    fn auto_tasks_where(
        &self,
        idle_minutes: i64,
        limit: usize,
        filter: &str,
    ) -> Result<Vec<AutoTask>> {
        let conn = self.lock();
        let sql = format!(
            "SELECT {}, updated_at <= strftime('%Y-%m-%dT%H:%M:%SZ', 'now', ?1),
                    {WAITING_SQL}, auto_attempts, author
             FROM tasks WHERE status = 'open' AND claimed_by = '' {filter}
             ORDER BY created_at, id LIMIT ?2",
            super::TASK_COLUMNS
        );
        let mut stmt = conn.prepare(&sql)?;
        let offset = format!("-{} minutes", idle_minutes.max(0));
        let rows = stmt.query_map(params![offset, limit as i64], |row| {
            Ok(AutoTask {
                task: super::Task::from_row(row)?,
                idle: row.get(20)?,
                waiting: row.get(21)?,
                auto_attempts: row.get(22)?,
                author: row.get(23)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Notes on a task why the runner skipped it, without touching it: it
    /// waits until it is re-queued.
    pub fn note_task_skip(&self, id: i64, note: &str) -> Result<()> {
        let note: String = note.chars().take(super::NOTE_MAX_CHARS).collect();
        self.lock().execute(
            "UPDATE tasks SET note = ?2, auto_seen = touches,
                 auto_last_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
             WHERE id = ?1",
            params![id, note],
        )?;
        Ok(())
    }

    /// Records that the runner took a task (counted) or left it (not
    /// counted): either way it waits until it is re-queued.
    pub fn mark_task_auto(&self, id: i64, attempt: bool) -> Result<()> {
        self.lock().execute(
            "UPDATE tasks SET auto_attempts = auto_attempts + ?2, auto_seen = touches,
                 auto_last_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
             WHERE id = ?1",
            params![id, i64::from(attempt)],
        )?;
        Ok(())
    }

    /// A task the runner took but whose agent's container was only busy
    /// (`busy: …`): it goes back exactly as it was before it was taken
    /// (open, unclaimed, its old `updated_at`, the attempt not counted, not
    /// waiting), so the scheduler tries it again on a later tick. Only a
    /// claim by `agent` is undone.
    pub fn give_back_task(&self, id: i64, agent: &str, updated_at: &str) -> Result<bool> {
        let changed = self.lock().execute(
            "UPDATE tasks SET status = 'open', claimed_by = '', updated_at = ?3,
                 auto_attempts = MAX(auto_attempts - 1, 0), auto_seen = NULL
             WHERE id = ?1 AND status = 'claimed' AND claimed_by = ?2",
            params![id, agent, updated_at],
        )?;
        Ok(changed > 0)
    }

    /// The task runner's fields of every task, for the JSON backup.
    pub fn task_runner_states(&self) -> Result<Vec<TaskRunnerState>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT id, author, touches, auto_seen, auto_attempts, auto_last_at FROM tasks
             WHERE author != '' OR touches != 0 OR auto_seen IS NOT NULL OR auto_attempts != 0
                   OR auto_last_at IS NOT NULL
             ORDER BY id",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(TaskRunnerState {
                task_id: row.get(0)?,
                author: row.get(1)?,
                touches: row.get(2)?,
                auto_seen: row.get(3)?,
                auto_attempts: row.get(4)?,
                auto_last_at: row.get(5)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Every delegation, for the JSON backup.
    pub fn delegations(&self) -> Result<Vec<Delegation>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT task_id, agent, requested_by, via, created_at FROM delegations
             ORDER BY task_id",
        )?;
        let rows = stmt.query_map([], delegation_row)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// A new run. Its token is stored only as `token_hash`.
    pub fn insert_run(&self, new: &NewRun) -> Result<Run> {
        let conn = self.lock();
        let project = super::rename::resolve_alias(&conn, &new.project)?;
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
                project,
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
    /// `RUN_EVENTS_KEPT` lines or `RUN_EVENT_BYTES_KEPT` bytes only the
    /// count grows.
    pub fn add_run_event(&self, run_id: &str, seq: i64, stream: &str, body: &str) -> Result<()> {
        let conn = self.lock();
        let (lines, bytes): (i64, i64) = conn
            .query_row(
                "SELECT output_lines, output_bytes FROM agent_runs WHERE id = ?1",
                params![run_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?
            .unwrap_or((0, 0));
        let size = body.len() as i64;
        let keep = lines < RUN_EVENTS_KEPT && bytes + size <= RUN_EVENT_BYTES_KEPT;
        if keep {
            conn.execute(
                "INSERT INTO agent_run_events (run_id, seq, stream, body) VALUES (?1, ?2, ?3, ?4)",
                params![run_id, seq, stream, body],
            )?;
        }
        conn.execute(
            "UPDATE agent_runs SET output_lines = output_lines + 1,
                 output_bytes = output_bytes + ?2
             WHERE id = ?1",
            params![run_id, if keep { size } else { 0 }],
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

    /// Records who asked for a run that lore did not start by itself
    /// (`user:<name>` for the owner's hand-off on the page).
    pub fn set_run_requested_by(&self, run_id: &str, by: &str) -> Result<()> {
        self.lock().execute(
            "UPDATE agent_runs SET requested_by = ?2 WHERE id = ?1",
            params![run_id, by],
        )?;
        Ok(())
    }

    /// Whether the task runner ever started a run for a task, or a
    /// delegation hands it to a built-in agent: such a task is finished
    /// only on lore's own commit proof, never from a terminal.
    pub fn task_belongs_to_runs(&self, task_id: i64) -> Result<bool> {
        Ok(self.lock().query_row(
            "SELECT EXISTS (SELECT 1 FROM agent_runs WHERE task_id = ?1)
                 OR EXISTS (SELECT 1 FROM delegations WHERE task_id = ?1)",
            params![task_id],
            |row| row.get(0),
        )?)
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
               AND NOT (t.auto_seen IS NOT NULL AND t.auto_seen >= t.touches)
             ORDER BY d.created_at, t.id",
            columns.join(", ")
        );
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map([], |row| {
            Ok((
                super::Task::from_row(row)?,
                Delegation {
                    task_id: row.get(20)?,
                    agent: row.get(21)?,
                    requested_by: row.get(22)?,
                    via: row.get(23)?,
                    created_at: row.get(24)?,
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

    /// Drops the output of all but the newest runs, then the oldest runs'
    /// output while all of it is more than `RUN_EVENT_BYTES_TOTAL` bytes.
    pub fn prune_run_events(&self) -> Result<()> {
        self.prune_run_events_to(RUN_EVENT_BYTES_TOTAL)
    }

    fn prune_run_events_to(&self, total: i64) -> Result<()> {
        let conn = self.lock();
        conn.execute(
            "DELETE FROM agent_run_events WHERE run_id NOT IN (
                 SELECT id FROM agent_runs ORDER BY created_at DESC, rowid DESC LIMIT ?1)",
            params![RUNS_WITH_EVENTS],
        )?;
        loop {
            let stored: i64 = conn.query_row(
                "SELECT COALESCE(SUM(length(CAST(body AS BLOB))), 0) FROM agent_run_events",
                [],
                |row| row.get(0),
            )?;
            if stored <= total {
                return Ok(());
            }
            let oldest: Option<String> = conn
                .query_row(
                    "SELECT r.id FROM agent_runs r
                      WHERE EXISTS (SELECT 1 FROM agent_run_events e WHERE e.run_id = r.id)
                      ORDER BY r.created_at, r.rowid LIMIT 1",
                    [],
                    |row| row.get(0),
                )
                .optional()?;
            let Some(oldest) = oldest else {
                return Ok(());
            };
            conn.execute(
                "DELETE FROM agent_run_events WHERE run_id = ?1",
                params![oldest],
            )?;
        }
    }
}

/// One ref update lore let a run make.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct RunRef {
    #[serde(rename = "ref")]
    pub name: String,
    pub old: String,
    pub new: String,
    pub via: String,
    pub created_at: String,
}

impl RunRef {
    /// Whether the update created the branch.
    pub fn created(&self) -> bool {
        self.old.bytes().all(|byte| byte == b'0')
    }

    /// Whether this update credits its run with `sha` on `name` (a full
    /// ref): it moved the ref (old differs from new) to that commit, and
    /// the commit is the run's own: it came in the run's own pack
    /// (`push`) or `repo_commit` made it. A push that only pointed the ref
    /// at a commit that was already there (`push-existing`) credits
    /// nothing.
    pub fn credits(&self, name: &str, sha: &str) -> bool {
        self.name == name && self.new == sha && self.moved() && self.brought_its_commit()
    }

    fn moved(&self) -> bool {
        self.old != self.new
    }

    /// Whether the new commit is the run's own: it came in this update's
    /// pack (`push`) or `repo_commit` made it.
    fn brought_its_commit(&self) -> bool {
        matches!(self.via.as_str(), "push" | "repo_commit")
    }
}

/// Whether a run's recorded ref updates (oldest first, as
/// [`Db::run_refs`] answers them) credit it with `sha` on `name` (a full
/// ref). Either one update credits it on its own ([`RunRef::credits`]),
/// or an update moved `name` to `sha` without sending it
/// (`push-existing`) after an earlier update of the same run brought
/// `sha` itself (a `push` whose pack carried it, or a `repo_commit`), on
/// any branch: a run that pushes a feature branch and then fast-forwards
/// the default branch to it sends an empty pack the second time, and the
/// commit is still its own. A run is bound to one repository, so every
/// update of it is to that one. Pointing a branch at a commit the run
/// never sent credits nothing.
pub fn run_credited(refs: &[RunRef], name: &str, sha: &str) -> bool {
    refs.iter().enumerate().any(|(at, update)| {
        update.credits(name, sha)
            || (update.name == name
                && update.new == sha
                && update.moved()
                && update.via == "push-existing"
                && refs[..at].iter().any(|earlier| {
                    earlier.new == sha && earlier.moved() && earlier.brought_its_commit()
                }))
    })
}

impl Db {
    /// Records a ref update lore let run `run_id` make (`via` push,
    /// push-existing or repo_commit). `old` empty or zeros: the run created the branch.
    pub fn record_run_ref(
        &self,
        run_id: &str,
        name: &str,
        old: &str,
        new: &str,
        via: &str,
    ) -> Result<()> {
        self.lock().execute(
            "INSERT INTO agent_run_refs (run_id, ref, old, new, via) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                run_id,
                name,
                old.to_ascii_lowercase(),
                new.to_ascii_lowercase(),
                via
            ],
        )?;
        Ok(())
    }

    /// The ref updates of a run, oldest first.
    pub fn run_refs(&self, run_id: &str) -> Result<Vec<RunRef>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT ref, old, new, via, created_at FROM agent_run_refs WHERE run_id = ?1
             ORDER BY id",
        )?;
        let rows = stmt.query_map(params![run_id], |row| {
            Ok(RunRef {
                name: row.get(0)?,
                old: row.get(1)?,
                new: row.get(2)?,
                via: row.get(3)?,
                created_at: row.get(4)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// The branches a run created (short names), in the order it created
    /// them.
    pub fn run_created_branches(&self, run_id: &str) -> Result<Vec<String>> {
        let mut out: Vec<String> = Vec::new();
        for update in self.run_refs(run_id)? {
            if update.created()
                && let Some(branch) = update.name.strip_prefix("refs/heads/")
                && !out.iter().any(|known| known == branch)
            {
                out.push(branch.to_string());
            }
        }
        Ok(out)
    }

    /// The default branch's head lore read with its own credential before
    /// the run started (schema 8).
    pub fn set_run_base_head(&self, run_id: &str, head: &str) -> Result<()> {
        self.lock().execute(
            "UPDATE agent_runs SET base_head = ?2 WHERE id = ?1",
            params![run_id, head.to_ascii_lowercase()],
        )?;
        Ok(())
    }

    /// The base head recorded for a run; empty when none was read.
    #[cfg(test)]
    pub fn run_base_head(&self, run_id: &str) -> Result<String> {
        Ok(self
            .lock()
            .query_row(
                "SELECT base_head FROM agent_runs WHERE id = ?1",
                params![run_id],
                |row| row.get(0),
            )
            .optional()?
            .unwrap_or_default())
    }

    /// Marks an entry or a message (`kind`) as written by run `run_id`.
    pub fn mark_run_write(&self, kind: &str, item_id: i64, run_id: &str) -> Result<()> {
        self.lock().execute(
            "INSERT OR REPLACE INTO run_writes (kind, item_id, run_id) VALUES (?1, ?2, ?3)",
            params![kind, item_id, run_id],
        )?;
        Ok(())
    }

    /// Which of `ids` (entries or messages, by `kind`) a run wrote: id →
    /// run id.
    pub fn run_writes(
        &self,
        kind: &str,
        ids: &[i64],
    ) -> Result<std::collections::HashMap<i64, String>> {
        let mut out = std::collections::HashMap::new();
        if ids.is_empty() {
            return Ok(out);
        }
        let conn = self.lock();
        let mut stmt =
            conn.prepare("SELECT run_id FROM run_writes WHERE kind = ?1 AND item_id = ?2")?;
        for id in ids {
            if let Some(run) = stmt
                .query_row(params![kind, id], |row| row.get::<_, String>(0))
                .optional()?
            {
                out.insert(*id, run);
            }
        }
        Ok(out)
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

    /// F2: only an update that moved the branch to a commit of the run's
    /// own (its pack, or `repo_commit`) credits the run; a no-op, or a
    /// push that only pointed the branch at a commit someone else made,
    /// does not. Every recorded creation still counts as created.
    #[test]
    fn only_a_run_s_own_commit_credits_it() {
        let (db, _) = temp_db("credits");
        let (zero, base, mine, theirs) = (
            "0".repeat(40),
            "a".repeat(40),
            "b".repeat(40),
            "e".repeat(40),
        );
        let main = "refs/heads/main";
        db.record_run_ref("r1", main, &base, &mine, "push").unwrap();
        db.record_run_ref("r2", main, &base, &mine, "repo_commit")
            .unwrap();
        db.record_run_ref("r3", main, &base, &theirs, "push-existing")
            .unwrap();
        db.record_run_ref("r4", main, &theirs, &theirs, "push")
            .unwrap();
        db.record_run_ref("r5", "refs/heads/side", &zero, &theirs, "push-existing")
            .unwrap();
        let credited = |run: &str, sha: &str| {
            db.run_refs(run)
                .unwrap()
                .iter()
                .any(|update| update.credits(main, sha))
        };
        assert!(credited("r1", &mine));
        assert!(credited("r2", &mine));
        assert!(!credited("r3", &theirs));
        assert!(!credited("r4", &theirs));
        assert!(!credited("r1", &theirs));
        assert_eq!(db.run_created_branches("r5").unwrap(), vec!["side"]);
    }

    /// A run that pushes a feature branch (its commit comes in that pack)
    /// and then fast-forwards the default branch to the same commit (an
    /// empty pack: `push-existing`) is credited; pointing the default
    /// branch at a commit the run never sent is not, nor is a commit the
    /// run only sent after pointing the branch at it.
    #[test]
    fn a_fast_forward_to_the_run_s_own_earlier_push_credits_it() {
        let (db, _) = temp_db("credits-ff");
        let (zero, base, mine, theirs) = (
            "0".repeat(40),
            "a".repeat(40),
            "b".repeat(40),
            "e".repeat(40),
        );
        let (main, feature) = ("refs/heads/main", "refs/heads/feature");
        let credited = |run: &str, sha: &str| run_credited(&db.run_refs(run).unwrap(), main, sha);

        // Feature branch first, then main fast-forwarded to it.
        db.record_run_ref("ff", feature, &zero, &mine, "push")
            .unwrap();
        db.record_run_ref("ff", main, &base, &mine, "push-existing")
            .unwrap();
        assert!(credited("ff", &mine));

        // The same with a commit `repo_commit` made on the feature branch.
        db.record_run_ref("rc", feature, &base, &mine, "repo_commit")
            .unwrap();
        db.record_run_ref("rc", main, &base, &mine, "push-existing")
            .unwrap();
        assert!(credited("rc", &mine));

        // The run's own pack carried another commit; main points at one
        // that was upstream before the run.
        db.record_run_ref("other", feature, &zero, &mine, "push")
            .unwrap();
        db.record_run_ref("other", main, &base, &theirs, "push-existing")
            .unwrap();
        assert!(!credited("other", &theirs));

        // Only someone else's commit, on both branches.
        db.record_run_ref("theirs", feature, &zero, &theirs, "push-existing")
            .unwrap();
        db.record_run_ref("theirs", main, &base, &theirs, "push-existing")
            .unwrap();
        assert!(!credited("theirs", &theirs));

        // The commit "arrives" only after main was pointed at it.
        db.record_run_ref("late", main, &base, &mine, "push-existing")
            .unwrap();
        db.record_run_ref("late", feature, &zero, &mine, "push")
            .unwrap();
        assert!(!credited("late", &mine));

        // Another run's push of the commit does not make it this run's.
        db.record_run_ref("elsewhere", main, &base, &mine, "push-existing")
            .unwrap();
        assert!(!credited("elsewhere", &mine));
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

    /// E10: the eligible tasks are filtered before the limit, so waiting,
    /// over-tried and delegated tasks never crowd out the next one.
    #[test]
    fn eligible_tasks_are_filtered_before_the_limit() {
        let (db, _) = temp_db("eligible");
        let add = |title: &str| {
            db.add_task(&super::super::NewTask {
                project: "shop".into(),
                title: title.into(),
                created_by: "codex".into(),
                ..Default::default()
            })
            .unwrap()
        };
        for index in 0..5 {
            let task = add(&format!("waiting {index}"));
            db.mark_task_auto(task.id, false).unwrap();
        }
        let tried = add("tried twice");
        db.mark_task_auto(tried.id, true).unwrap();
        db.requeue_task(tried.id, false).unwrap();
        db.mark_task_auto(tried.id, true).unwrap();
        db.requeue_task(tried.id, false).unwrap();
        let delegated = add("delegated");
        db.add_delegation(delegated.id, "claude-builtin", "codex", "")
            .unwrap();
        let next = add("next");
        db.execute_for_test("UPDATE tasks SET updated_at = '2020-01-01T00:00:00Z'");
        let eligible = db.eligible_auto_tasks(120, 2, 3).unwrap();
        assert_eq!(eligible.len(), 1, "{eligible:?}");
        assert_eq!(eligible[0].task.id, next.id);
        // The queue view still lists them all.
        assert_eq!(db.auto_tasks(120, 50).unwrap().len(), 8);
    }

    /// E12 and E15: a re-queueing touch is counted, so one in the same
    /// second as the runner's mark is not lost; the author's touches keep
    /// the attempts, a signed-in user's start them over.
    #[test]
    fn touches_re_queue_and_attempts_have_a_maximum() {
        let (db, _) = temp_db("touches");
        let task = db
            .add_task(&super::super::NewTask {
                project: "shop".into(),
                title: "t".into(),
                created_by: "codex".into(),
                ..Default::default()
            })
            .unwrap();
        db.execute_for_test("UPDATE tasks SET updated_at = '2020-01-01T00:00:00Z'");
        let eligible = |db: &Db| db.eligible_auto_tasks(120, 2, 10).unwrap().len();
        assert_eq!(eligible(&db), 1);
        db.mark_task_auto(task.id, true).unwrap();
        assert_eq!(eligible(&db), 0);
        // Any other change (a claim and release by someone else) does not
        // re-queue it.
        db.update_task(task.id, "claim", "someone", None, None)
            .unwrap();
        db.update_task(task.id, "release", "someone", None, None)
            .unwrap();
        db.execute_for_test("UPDATE tasks SET updated_at = '2020-01-01T00:00:00Z'");
        assert_eq!(eligible(&db), 0);
        // The author's touch, in the same second as the mark: re-queued.
        db.requeue_task(task.id, false).unwrap();
        assert_eq!(eligible(&db), 1);
        db.mark_task_auto(task.id, true).unwrap();
        db.requeue_task(task.id, false).unwrap();
        // Two attempts: the maximum, whatever the author does.
        assert_eq!(eligible(&db), 0);
        // A signed-in user's touch starts the count over.
        db.requeue_task(task.id, true).unwrap();
        assert_eq!(eligible(&db), 1);
    }

    /// E14: the JSON backup carries the task runner's fields and the
    /// delegations; a replacing restore leaves no delegation behind.
    #[test]
    fn the_backup_carries_the_task_runner_fields_and_delegations() {
        let (db, _) = temp_db("backup");
        let task = db
            .add_task(&super::super::NewTask {
                project: "shop".into(),
                title: "t".into(),
                created_by: "codex".into(),
                ..Default::default()
            })
            .unwrap();
        db.set_task_author(task.id, "codex").unwrap();
        db.mark_task_auto(task.id, true).unwrap();
        db.add_delegation(task.id, "claude-builtin", "codex", "")
            .unwrap();
        let backup = db.export().unwrap();
        assert_eq!(backup.delegations.len(), 1);
        assert_eq!(backup.task_runner[0].author, "codex");
        // Another store with a delegation on the same id.
        let (other, _) = temp_db("backup-other");
        let stale = other
            .add_task(&super::super::NewTask {
                project: "x".into(),
                title: "stale".into(),
                created_by: "a".into(),
                ..Default::default()
            })
            .unwrap();
        other
            .add_delegation(stale.id, "codex-builtin", "a", "")
            .unwrap();
        let mut without = db.export().unwrap();
        without.delegations.clear();
        other.restore(&without).unwrap();
        assert!(other.delegations().unwrap().is_empty());
        other.restore(&backup).unwrap();
        assert_eq!(other.delegations().unwrap(), db.delegations().unwrap());
        assert_eq!(other.task_author(task.id).unwrap(), "codex");
        assert_eq!(
            other.task_runner_states().unwrap(),
            db.task_runner_states().unwrap()
        );
    }

    /// F13: a run's stored output is capped in bytes, and so is all of it.
    #[test]
    fn stored_run_output_is_capped_in_bytes() {
        let (db, _) = temp_db("bytes");
        db.register_builtin_agents(&[("claude-builtin".into(), "claude".into(), "ember")])
            .unwrap();
        for id in ["run-a", "run-b"] {
            db.insert_run(&NewRun {
                id: id.into(),
                agent: "claude-builtin".into(),
                kind: "task".into(),
                token_hash: format!("h-{id}"),
                token_expires_at: super::super::unix_now() + 60,
                scope: "{}".into(),
                ..NewRun::default()
            })
            .unwrap();
        }
        let line = "x".repeat(100_000);
        for seq in 0..20 {
            db.add_run_event("run-a", seq, "text", &line).unwrap();
        }
        let kept = db.run_events("run-a", -1, 100).unwrap();
        assert_eq!(kept.len() as i64, RUN_EVENT_BYTES_KEPT / 100_000);
        assert_eq!(db.run("run-a").unwrap().unwrap().output_lines, 20);
        db.add_run_event("run-b", 0, "text", "later").unwrap();
        // The oldest run's lines go first past the total.
        db.prune_run_events_to(10).unwrap();
        assert!(db.run_events("run-a", -1, 100).unwrap().is_empty());
        assert_eq!(db.run_events("run-b", -1, 100).unwrap().len(), 1);
    }

    /// F14: a model that would be read as an option is refused.
    #[test]
    fn a_model_never_starts_with_a_dash() {
        let (db, _) = temp_db("model");
        db.register_builtin_agents(&[("claude-builtin".into(), "claude".into(), "ember")])
            .unwrap();
        for model in ["--dangerously-skip-permissions", "-m", "a b"] {
            assert!(
                db.update_builtin_settings(
                    "claude-builtin",
                    &BuiltinSettings {
                        model: Some(model.into()),
                        ..BuiltinSettings::default()
                    },
                    "admin",
                )
                .is_err(),
                "{model}"
            );
        }
        assert!(valid_model("deepseek/deepseek-v4-pro") && valid_model("opus") && valid_model(""));
        // The per-agent read switch.
        assert!(
            !db.builtin_agent("claude-builtin")
                .unwrap()
                .unwrap()
                .read_other_services
        );
        db.set_builtin_read_other_services("claude-builtin", true, "admin")
            .unwrap();
        assert!(
            db.builtin_agent("claude-builtin")
                .unwrap()
                .unwrap()
                .read_other_services
        );
    }

    /// The trusted repository records: each with the token agent of the
    /// session that wrote it, empty for records from before.
    #[test]
    fn repository_records_carry_their_token_agent() {
        let (db, _) = temp_db("records");
        db.execute_for_test(
            "INSERT INTO sessions (id, agent, project, repo, title, started_at, last_seen_at, token_agent)
               VALUES ('s1', 'claude', 'shop', 'github.com/me/shop', 't', '2024-01-01T00:00:00Z', 'x', 'claude');
             INSERT INTO entries (project, kind, title, body, agent, repo, session_id, created_at)
               VALUES ('shop', 'note', 'n', 'b', 'claude', 'github.com/me/other', 's1', '2025-01-01T00:00:00Z'),
                      ('shop', 'note', 'n', 'b', 'x', 'github.com/evil/repo', NULL, '2026-01-01T00:00:00Z');",
        );
        let records = db.project_repo_records("shop", 10).unwrap();
        assert_eq!(
            records,
            vec![
                ("github.com/evil/repo".to_string(), String::new()),
                ("github.com/me/other".to_string(), "claude".to_string()),
                ("github.com/me/shop".to_string(), "claude".to_string()),
            ]
        );
    }

    /// A database file `main`'s build wrote (pass its path in
    /// `LORE_MAIN_DB`; the test copies it) opens with this build, gains
    /// the new tables and columns, and keeps every row. Skipped without it.
    #[test]
    fn a_database_main_wrote_opens_with_every_row() {
        let Ok(source) = std::env::var("LORE_MAIN_DB") else {
            return;
        };
        let (_, path) = temp_db("from-main");
        std::fs::copy(&source, &path).unwrap();
        let before: HashMap<String, i64> = {
            let conn = rusqlite::Connection::open(&path).unwrap();
            let names: Vec<String> = conn
                .prepare(
                    "SELECT name FROM sqlite_master WHERE type = 'table'
                       AND name NOT LIKE 'sqlite_%' AND name NOT LIKE 'entries_fts%'",
                )
                .unwrap()
                .query_map([], |row| row.get(0))
                .unwrap()
                .collect::<rusqlite::Result<_>>()
                .unwrap();
            names
                .into_iter()
                .map(|name| {
                    let count = conn
                        .query_row(&format!("SELECT COUNT(*) FROM \"{name}\""), [], |row| {
                            row.get(0)
                        })
                        .unwrap();
                    (name, count)
                })
                .collect()
        };
        let db = Db::open(&path).unwrap();
        let after: HashMap<String, i64> = db.table_counts().unwrap().into_iter().collect();
        for (table, count) in &before {
            if let Some(now) = after.get(table) {
                assert_eq!(now, count, "{table}");
            }
        }
        assert!(before.values().sum::<i64>() > 0, "the fixture holds rows");
        assert_eq!(
            super::super::schema_version(&db.lock()).unwrap(),
            super::super::SCHEMA_VERSION
        );
        for task in db.tasks(None, &[], 100).unwrap() {
            assert!(db.task_author(task.id).unwrap().is_empty());
        }
        assert!(!db.runs_may_change_ci().unwrap());
        let backup = db.export().unwrap();
        assert_eq!(backup.tasks.len() as i64, before["tasks"]);
        assert_eq!(backup.entries.len() as i64, before["entries"]);
    }
}
