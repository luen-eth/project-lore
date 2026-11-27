//! The agent registry and the OAuth tables: who the agents are (kind,
//! avatar, note, disabled), the clients that registered themselves, the
//! grants an approval creates, and the codes and tokens of those grants.
//!
//! None of it is part of the JSON backup and a JSON restore leaves it
//! untouched; the full database backup carries it by construction. Codes
//! and tokens are stored only as SHA-256 hashes. Times of the OAuth tables
//! are Unix seconds.

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension, params};

use super::Db;
use crate::avatars;

/// Tables added by the agent registry and OAuth. Created by the start-up
/// migration; additive only.
pub(super) const SCHEMA: &str = r#"
-- Every agent lore knows by name: env-token agents get a row at start-up
-- and when first seen, OAuth agents when they are approved. The older
-- `agents` table keeps when each was seen; it is part of the JSON backup,
-- this one is not.
CREATE TABLE IF NOT EXISTS agent_registry (
    name       TEXT PRIMARY KEY,
    kind       TEXT NOT NULL DEFAULT 'token',   -- token | oauth
    avatar     TEXT NOT NULL DEFAULT '',        -- avatar id; '' = derived from the name
    note       TEXT NOT NULL DEFAULT '',
    disabled   INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    created_by TEXT NOT NULL DEFAULT ''
);
-- OAuth clients that registered themselves (RFC 7591, public clients).
CREATE TABLE IF NOT EXISTS oauth_clients (
    client_id     TEXT PRIMARY KEY,
    client_name   TEXT NOT NULL DEFAULT '',
    redirect_uris TEXT NOT NULL,               -- JSON array
    created_at    INTEGER NOT NULL,
    authorized_at INTEGER                      -- first approval; NULL = never
);
-- One approval: an agent, the client it was given to, who approved it.
CREATE TABLE IF NOT EXISTS oauth_grants (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    agent         TEXT NOT NULL,
    client_id     TEXT NOT NULL,
    client_name   TEXT NOT NULL DEFAULT '',
    redirect_uri  TEXT NOT NULL,
    authorized_by TEXT NOT NULL,
    created_at    INTEGER NOT NULL,
    last_used_at  INTEGER,
    revoked_at    INTEGER
);
CREATE INDEX IF NOT EXISTS oauth_grants_agent ON oauth_grants (agent);
CREATE TABLE IF NOT EXISTS oauth_codes (
    code_hash      TEXT PRIMARY KEY,           -- SHA-256 hex
    grant_id       INTEGER NOT NULL,
    client_id      TEXT NOT NULL,
    redirect_uri   TEXT NOT NULL,
    code_challenge TEXT NOT NULL,              -- S256
    expires_at     INTEGER NOT NULL,
    used           INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS oauth_tokens (
    token_hash   TEXT PRIMARY KEY,             -- SHA-256 hex
    kind         TEXT NOT NULL,                -- access | refresh
    grant_id     INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL,
    created_at   INTEGER NOT NULL,
    last_used_at INTEGER,
    used         INTEGER NOT NULL DEFAULT 0,   -- a refresh token already exchanged
    revoked      INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS oauth_tokens_grant ON oauth_tokens (grant_id);
"#;

/// Every table and column that records an agent's name in its history:
/// a new OAuth agent may not take a name found in any of them.
const AGENT_HISTORY: &[(&str, &str)] = &[
    ("agents", "name"),
    ("entries", "agent"),
    ("sessions", "agent"),
    ("activity", "agent"),
    ("files", "agent"),
    ("tasks", "created_by"),
    ("tasks", "claimed_by"),
    ("tasks", "done_by"),
    ("messages", "from_agent"),
    ("message_reads", "agent"),
    ("ops_log", "agent"),
];

/// Registered clients kept at most; the oldest never-authorized ones go
/// first.
pub const MAX_OAUTH_CLIENTS: i64 = 200;
/// A client never authorized within this many seconds of registering is
/// removed at the next registration.
const UNAUTHORIZED_CLIENT_TTL_SECS: i64 = 60 * 60;
/// Seconds between two `last_used_at` writes for one token.
const TOUCH_EVERY: i64 = 60;

/// The current time in Unix seconds.
pub fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0)
}

/// A registered OAuth client.
#[derive(Debug, Clone, serde::Serialize)]
pub struct OAuthClient {
    pub client_id: String,
    pub client_name: String,
    pub redirect_uris: Vec<String>,
}

/// Longest display name, in characters.
pub const DISPLAY_NAME_MAX_CHARS: usize = 40;

/// A display name as the owner typed it: trimmed, runs of spaces made
/// one, 1 to 40 characters. Refused: control characters (newlines
/// included), Unicode format characters (bidi overrides and isolates,
/// zero-width characters, the byte order mark, tags...), every space but
/// the plain one, and the characters that draw nothing (fillers, the blank
/// braille pattern). Empty clears it (`None`).
pub fn clean_display_name(raw: &str) -> Result<Option<String>, String> {
    if raw
        .chars()
        .any(|c| c.is_control() || invisible(c) || (c.is_whitespace() && c != ' '))
    {
        return Err(
            "a display name is one line of visible characters: no control, format or \
             invisible characters, and no spaces but the plain one"
                .into(),
        );
    }
    let collapsed = raw
        .split(' ')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    if collapsed.is_empty() {
        return Ok(None);
    }
    if collapsed.chars().count() > DISPLAY_NAME_MAX_CHARS {
        return Err(format!(
            "a display name is at most {DISPLAY_NAME_MAX_CHARS} characters"
        ));
    }
    Ok(Some(collapsed))
}

/// Unicode format characters (category Cf) and characters that show
/// nothing although they are not spaces.
fn invisible(c: char) -> bool {
    matches!(
        c as u32,
        0x00AD
            | 0x034F
            | 0x0600..=0x0605
            | 0x061C
            | 0x06DD
            | 0x070F
            | 0x0890..=0x0891
            | 0x08E2
            | 0x115F..=0x1160
            | 0x17B4..=0x17B5
            | 0x180B..=0x180F
            | 0x200B..=0x200F
            | 0x202A..=0x202E
            | 0x2060..=0x206F
            | 0x2800
            | 0x3164
            | 0xFE00..=0xFE0F
            | 0xFEFF
            | 0xFFA0
            | 0xFFF9..=0xFFFB
            | 0x110BD
            | 0x110CD
            | 0x13430..=0x1343F
            | 0x1BCA0..=0x1BCA3
            | 0x1D173..=0x1D17A
            | 0xE0000..=0xE0FFF
    )
}

/// One registry row.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RegistryAgent {
    pub name: String,
    pub kind: String,
    pub avatar: String,
    pub note: String,
    /// The name the page shows instead of `name`, when the owner set one.
    /// `name` stays the agent's identity everywhere.
    pub display_name: Option<String>,
    pub disabled: bool,
    pub created_at: String,
    pub created_by: String,
}

/// What an approval writes: the agent (new or existing), the grant and the
/// authorization code. Every field is already validated.
pub struct Approval {
    pub agent: String,
    /// True for a new agent; false re-authorizes an existing OAuth agent.
    pub new_agent: bool,
    /// An avatar id, or empty to keep (or derive) it.
    pub avatar: String,
    pub client_id: String,
    pub client_name: String,
    pub redirect_uri: String,
    pub authorized_by: String,
    /// Names no new agent may take: the env-token agents.
    pub reserved: Vec<String>,
    /// The approver lacks `integrations`: the agent gets level `off` on
    /// every HTTP provider it has no level for yet, so approving cannot
    /// hand out the stored service credentials.
    pub services_off: bool,
    pub code_hash: String,
    pub code_challenge: String,
    pub code_expires_at: i64,
}

impl std::fmt::Debug for Approval {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Approval")
            .field("agent", &self.agent)
            .field("new_agent", &self.new_agent)
            .field("client_id", &self.client_id)
            .field("redirect_uri", &self.redirect_uri)
            .field("authorized_by", &self.authorized_by)
            .field("services_off", &self.services_off)
            .field("code_hash", &"[redacted]")
            .finish()
    }
}

/// A code taken for an exchange.
#[derive(Debug)]
pub enum CodeLookup {
    /// No such code.
    Missing,
    /// The code was already exchanged once; its grant is now revoked.
    Reused,
    /// The code, now marked used.
    Taken(TakenCode),
}

#[derive(Debug)]
pub struct TakenCode {
    pub grant_id: i64,
    pub client_id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub expires_at: i64,
}

/// How a refresh token exchange went.
#[derive(Debug, PartialEq, Eq)]
pub enum RefreshLookup {
    /// Unknown, expired, revoked, for another client, or its agent is
    /// disabled.
    Invalid,
    /// Already exchanged once: the whole grant is now revoked.
    Reused,
    /// Valid and now used up; new tokens go to this grant.
    Rotated { grant_id: i64 },
}

/// A refresh token with what decides whether it may be exchanged.
struct RefreshRow {
    grant_id: i64,
    expires_at: i64,
    used: bool,
    revoked: bool,
    client_id: String,
    disabled: bool,
    grant_revoked: bool,
}

/// The agent an access token was issued to.
#[derive(Debug, PartialEq, Eq)]
pub struct AccessAgent {
    pub agent: String,
    pub disabled: bool,
}

/// One authorization of an OAuth agent, as the agents panel lists it.
#[derive(Debug, serde::Serialize)]
pub struct Authorization {
    pub id: i64,
    pub client_id: String,
    pub client_name: String,
    pub redirect_uri: String,
    pub authorized_by: String,
    pub authorized_at: String,
    pub last_used_at: Option<String>,
    pub revoked: bool,
}

/// Service calls of one agent to one provider with one outcome.
#[derive(Debug, serde::Serialize, PartialEq, Eq)]
pub struct ServiceCalls {
    pub provider: String,
    pub outcome: String,
    pub count: i64,
}

/// What an agent did, counted.
#[derive(Debug, Default, serde::Serialize)]
pub struct AgentStats {
    pub memories: i64,
    pub memories_by_kind: BTreeMap<String, i64>,
    pub sessions: i64,
    pub open_sessions: i64,
    /// Tool calls from the activity feed, which keeps its newest rows only.
    pub tool_calls_24h: i64,
    pub tool_calls_7d: i64,
    pub tool_calls_30d: i64,
    pub service_calls: Vec<ServiceCalls>,
    pub tasks_done: i64,
    pub files_saved: i64,
}

/// One agent as the agents panel shows it.
#[derive(Debug, serde::Serialize)]
pub struct AgentRecord {
    pub name: String,
    /// `token` or `oauth`; an agent known only from what it wrote is
    /// `token` (it came in through a token).
    pub kind: String,
    /// A token in the environment names this agent right now.
    pub env_token: bool,
    /// The avatar shown: the chosen one or the one derived from the name.
    pub avatar: String,
    pub avatar_chosen: bool,
    pub note: String,
    pub display_name: Option<String>,
    pub disabled: bool,
    pub registered_at: Option<String>,
    pub registered_by: String,
    pub client: String,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    pub requests: i64,
    pub authorizations: Vec<Authorization>,
    pub stats: AgentStats,
}

impl Db {
    /// Gives every env-token agent a registry row, at start-up. Existing
    /// rows are left as they are.
    pub fn register_token_agents(&self, names: &[String]) -> Result<()> {
        let conn = self.lock();
        for name in names {
            conn.execute(
                "INSERT OR IGNORE INTO agent_registry (name, kind, created_by)
                 VALUES (?1, 'token', 'environment')",
                params![name],
            )?;
        }
        Ok(())
    }

    /// Whether an env-token agent is disabled; gives it a registry row the
    /// first time it is seen.
    pub fn token_agent_disabled(&self, name: &str) -> Result<bool> {
        let conn = self.lock();
        let disabled: Option<bool> = conn
            .query_row(
                "SELECT disabled FROM agent_registry WHERE name = ?1",
                params![name],
                |row| row.get(0),
            )
            .optional()?;
        match disabled {
            Some(disabled) => Ok(disabled),
            None => {
                conn.execute(
                    "INSERT OR IGNORE INTO agent_registry (name, kind, created_by)
                     VALUES (?1, 'token', 'environment')",
                    params![name],
                )?;
                Ok(false)
            }
        }
    }

    pub fn registry_agent(&self, name: &str) -> Result<Option<RegistryAgent>> {
        get_registry_agent(&self.lock(), name)
    }

    /// The OAuth agents, by name: those a consent page may re-authorize.
    pub fn oauth_agents(&self) -> Result<Vec<RegistryAgent>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT name, kind, avatar, note, disabled, created_at, created_by, display_name
             FROM agent_registry WHERE kind = 'oauth' ORDER BY name",
        )?;
        let rows = stmt.query_map([], registry_from_row)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Changes an agent's avatar and note; `None` leaves a field. Gives an
    /// agent that has no row yet (one known only from what it wrote) a
    /// `token` row.
    pub fn set_agent_details(
        &self,
        name: &str,
        avatar: Option<&str>,
        note: Option<&str>,
        by: &str,
    ) -> Result<RegistryAgent> {
        let conn = self.lock();
        conn.execute(
            "INSERT OR IGNORE INTO agent_registry (name, kind, created_by) VALUES (?1, 'token', ?2)",
            params![name, by],
        )?;
        conn.execute(
            "UPDATE agent_registry SET avatar = COALESCE(?2, avatar), note = COALESCE(?3, note)
             WHERE name = ?1",
            params![name, avatar, note],
        )?;
        get_registry_agent(&conn, name)?.context("agent vanished after update")
    }

    /// Sets (or with `None` clears) the name the page shows for an agent;
    /// `display` must already be checked (`clean_display_name`). Refuses a
    /// display name that is another agent's technical name. Gives an agent
    /// without a row a `token` row, like `set_agent_details`.
    pub fn set_agent_display_name(
        &self,
        name: &str,
        display: Option<&str>,
        by: &str,
    ) -> Result<RegistryAgent> {
        let conn = self.lock();
        if let Some(display) = display {
            let lowered = display.to_lowercase();
            if lowered != name {
                for (table, column) in AGENT_HISTORY
                    .iter()
                    .copied()
                    .chain([("agent_registry", "name")])
                {
                    let taken: bool = conn.query_row(
                        &format!("SELECT COUNT(*) > 0 FROM {table} WHERE lower({column}) = ?1"),
                        params![lowered],
                        |row| row.get(0),
                    )?;
                    if taken {
                        anyhow::bail!(
                            "\"{display}\" is another agent's name; pick a display name that is not"
                        );
                    }
                }
            }
        }
        conn.execute(
            "INSERT OR IGNORE INTO agent_registry (name, kind, created_by) VALUES (?1, 'token', ?2)",
            params![name, by],
        )?;
        conn.execute(
            "UPDATE agent_registry SET display_name = ?2 WHERE name = ?1",
            params![name, display],
        )?;
        get_registry_agent(&conn, name)?.context("agent vanished after update")
    }

    /// Disables or enables an agent. Disabling closes its open sessions;
    /// returns how many were closed.
    pub fn set_agent_disabled(&self, name: &str, disabled: bool, by: &str) -> Result<usize> {
        let conn = self.lock();
        conn.execute(
            "INSERT OR IGNORE INTO agent_registry (name, kind, created_by) VALUES (?1, 'token', ?2)",
            params![name, by],
        )?;
        conn.execute(
            "UPDATE agent_registry SET disabled = ?2 WHERE name = ?1",
            params![name, disabled],
        )?;
        if !disabled {
            return Ok(0);
        }
        Ok(conn.execute(
            "UPDATE sessions SET status = 'closed', summary = 'closed: the agent was disabled',
                 ended_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
             WHERE agent = ?1 AND status = 'open'",
            params![name],
        )?)
    }

    /// Revokes every grant of an agent and every token and code of those
    /// grants. Returns how many grants were live.
    pub fn revoke_agent(&self, name: &str) -> Result<usize> {
        let conn = self.lock();
        let now = unix_now();
        let live = conn.execute(
            "UPDATE oauth_grants SET revoked_at = ?2 WHERE agent = ?1 AND revoked_at IS NULL",
            params![name, now],
        )?;
        conn.execute(
            "UPDATE oauth_tokens SET revoked = 1
             WHERE grant_id IN (SELECT id FROM oauth_grants WHERE agent = ?1)",
            params![name],
        )?;
        conn.execute(
            "DELETE FROM oauth_codes WHERE grant_id IN (SELECT id FROM oauth_grants WHERE agent = ?1)",
            params![name],
        )?;
        Ok(live)
    }

    /// Removes an OAuth agent's authorization entirely: its grants, codes
    /// and tokens, and its registry row. What it wrote stays. Refuses an
    /// agent that is not an OAuth agent.
    pub fn delete_oauth_agent(&self, name: &str) -> Result<bool> {
        let mut conn = self.lock();
        let tx = conn.transaction()?;
        let kind: Option<String> = tx
            .query_row(
                "SELECT kind FROM agent_registry WHERE name = ?1",
                params![name],
                |row| row.get(0),
            )
            .optional()?;
        match kind.as_deref() {
            None => return Ok(false),
            Some("oauth") => {}
            Some(_) => anyhow::bail!("only an OAuth agent's authorization can be deleted"),
        }
        tx.execute(
            "DELETE FROM oauth_tokens WHERE grant_id IN (SELECT id FROM oauth_grants WHERE agent = ?1)",
            params![name],
        )?;
        tx.execute(
            "DELETE FROM oauth_codes WHERE grant_id IN (SELECT id FROM oauth_grants WHERE agent = ?1)",
            params![name],
        )?;
        tx.execute("DELETE FROM oauth_grants WHERE agent = ?1", params![name])?;
        tx.execute("DELETE FROM agent_registry WHERE name = ?1", params![name])?;
        tx.commit()?;
        Ok(true)
    }

    /// Stores a newly registered client. Clients never authorized within
    /// an hour of registering are removed first. At most
    /// `MAX_OAUTH_CLIENTS` are kept: the oldest never-authorized ones are
    /// removed to make room, and when every client was authorized the
    /// registration is refused.
    pub fn register_oauth_client(&self, client: &OAuthClient) -> Result<()> {
        let conn = self.lock();
        conn.execute(
            "DELETE FROM oauth_clients WHERE authorized_at IS NULL AND created_at < ?1",
            params![unix_now() - UNAUTHORIZED_CLIENT_TTL_SECS],
        )?;
        let count: i64 =
            conn.query_row("SELECT COUNT(*) FROM oauth_clients", [], |row| row.get(0))?;
        if count >= MAX_OAUTH_CLIENTS {
            conn.execute(
                "DELETE FROM oauth_clients WHERE client_id IN (
                     SELECT client_id FROM oauth_clients WHERE authorized_at IS NULL
                     ORDER BY created_at, rowid LIMIT ?1)",
                params![count - MAX_OAUTH_CLIENTS + 1],
            )?;
            let left: i64 =
                conn.query_row("SELECT COUNT(*) FROM oauth_clients", [], |row| row.get(0))?;
            if left >= MAX_OAUTH_CLIENTS {
                anyhow::bail!("too many registered clients");
            }
        }
        conn.execute(
            "INSERT INTO oauth_clients (client_id, client_name, redirect_uris, created_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                client.client_id,
                client.client_name,
                serde_json::to_string(&client.redirect_uris)?,
                unix_now()
            ],
        )?;
        Ok(())
    }

    pub fn oauth_client(&self, client_id: &str) -> Result<Option<OAuthClient>> {
        let conn = self.lock();
        let row: Option<(String, String, String)> = conn
            .query_row(
                "SELECT client_id, client_name, redirect_uris FROM oauth_clients WHERE client_id = ?1",
                params![client_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        Ok(row.map(|(client_id, client_name, uris)| OAuthClient {
            client_id,
            client_name,
            redirect_uris: serde_json::from_str(&uris).unwrap_or_default(),
        }))
    }

    /// Records an approval in one transaction: the agent's registry row,
    /// the grant and the authorization code. Refuses a new agent whose
    /// name is taken, and re-authorizing an agent that is not an enabled
    /// OAuth agent. Returns the grant id.
    pub fn approve(&self, approval: &Approval) -> Result<i64> {
        let mut conn = self.lock();
        let tx = conn.transaction()?;
        let existing = get_registry_agent(&tx, &approval.agent)?;
        if approval.new_agent {
            // A name that wrote or did anything before belongs to someone:
            // a new OAuth agent under it would inherit its history and its
            // levels.
            let mut seen = false;
            for (table, column) in AGENT_HISTORY {
                seen |= tx.query_row(
                    &format!("SELECT EXISTS (SELECT 1 FROM {table} WHERE lower({column}) = ?1)"),
                    params![approval.agent.to_lowercase()],
                    |row| row.get::<_, bool>(0),
                )?;
            }
            if approval.reserved.contains(&approval.agent) {
                anyhow::bail!(
                    "\"{}\" belongs to an agent with a token in the environment",
                    approval.agent
                );
            }
            if existing.is_some() || seen {
                anyhow::bail!(
                    "an agent named \"{}\" already exists; pick another name or re-authorize it",
                    approval.agent
                );
            }
            tx.execute(
                "INSERT INTO agent_registry (name, kind, avatar, created_by)
                 VALUES (?1, 'oauth', ?2, ?3)",
                params![approval.agent, approval.avatar, approval.authorized_by],
            )?;
        } else {
            match existing {
                Some(agent) if agent.kind == "oauth" => {
                    if agent.disabled {
                        anyhow::bail!(
                            "\"{}\" is disabled; enable it in the agents panel first",
                            agent.name
                        );
                    }
                    if !approval.avatar.is_empty() {
                        tx.execute(
                            "UPDATE agent_registry SET avatar = ?2 WHERE name = ?1",
                            params![approval.agent, approval.avatar],
                        )?;
                    }
                }
                _ => anyhow::bail!("there is no OAuth agent named \"{}\"", approval.agent),
            }
        }
        if approval.services_off {
            for provider in super::PROVIDERS {
                tx.execute(
                    "INSERT OR IGNORE INTO ops_permissions (agent, provider, level)
                     VALUES (?1, ?2, 'off')",
                    params![approval.agent.to_lowercase(), provider],
                )?;
            }
        }
        let now = unix_now();
        tx.execute(
            "INSERT INTO oauth_grants (agent, client_id, client_name, redirect_uri, authorized_by,
                                       created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                approval.agent,
                approval.client_id,
                approval.client_name,
                approval.redirect_uri,
                approval.authorized_by,
                now
            ],
        )?;
        let grant_id = tx.last_insert_rowid();
        tx.execute(
            "UPDATE oauth_clients SET authorized_at = COALESCE(authorized_at, ?2)
             WHERE client_id = ?1",
            params![approval.client_id, now],
        )?;
        tx.execute(
            "INSERT INTO oauth_codes (code_hash, grant_id, client_id, redirect_uri, code_challenge,
                                      expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                approval.code_hash,
                grant_id,
                approval.client_id,
                approval.redirect_uri,
                approval.code_challenge,
                approval.code_expires_at
            ],
        )?;
        tx.commit()?;
        Ok(grant_id)
    }

    /// Takes an authorization code for an exchange: marks it used. A code
    /// presented a second time revokes the grant it created (RFC 6749
    /// section 4.1.2).
    pub fn take_code(&self, code_hash: &str) -> Result<CodeLookup> {
        let conn = self.lock();
        let row: Option<(TakenCode, bool)> = conn
            .query_row(
                "SELECT grant_id, client_id, redirect_uri, code_challenge, expires_at, used
                 FROM oauth_codes WHERE code_hash = ?1",
                params![code_hash],
                |row| {
                    Ok((
                        TakenCode {
                            grant_id: row.get(0)?,
                            client_id: row.get(1)?,
                            redirect_uri: row.get(2)?,
                            code_challenge: row.get(3)?,
                            expires_at: row.get(4)?,
                        },
                        row.get(5)?,
                    ))
                },
            )
            .optional()?;
        let Some((code, used)) = row else {
            return Ok(CodeLookup::Missing);
        };
        if used {
            revoke_grant(&conn, code.grant_id)?;
            return Ok(CodeLookup::Reused);
        }
        conn.execute(
            "UPDATE oauth_codes SET used = 1 WHERE code_hash = ?1",
            params![code_hash],
        )?;
        Ok(CodeLookup::Taken(code))
    }

    /// Whether a grant can still receive tokens: not revoked, and its agent
    /// exists and is enabled.
    pub fn grant_usable(&self, grant_id: i64) -> Result<bool> {
        Ok(self.lock().query_row(
            "SELECT COUNT(*) > 0 FROM oauth_grants g
               JOIN agent_registry r ON r.name = g.agent
             WHERE g.id = ?1 AND g.revoked_at IS NULL AND r.disabled = 0",
            params![grant_id],
            |row| row.get(0),
        )?)
    }

    /// Stores a fresh access and refresh token for a grant.
    pub fn issue_tokens(
        &self,
        grant_id: i64,
        access_hash: &str,
        access_expires_at: i64,
        refresh_hash: &str,
        refresh_expires_at: i64,
    ) -> Result<()> {
        let conn = self.lock();
        let now = unix_now();
        conn.execute(
            "INSERT INTO oauth_tokens (token_hash, kind, grant_id, expires_at, created_at)
             VALUES (?1, 'access', ?2, ?3, ?4), (?5, 'refresh', ?2, ?6, ?4)",
            params![
                access_hash,
                grant_id,
                access_expires_at,
                now,
                refresh_hash,
                refresh_expires_at
            ],
        )?;
        // Expired tokens are of no use to anyone.
        conn.execute(
            "DELETE FROM oauth_tokens WHERE expires_at < ?1",
            params![now - 86_400],
        )?;
        Ok(())
    }

    /// Exchanges a refresh token: valid ones are used up (the caller issues
    /// the new pair), one presented a second time revokes its whole grant.
    pub fn take_refresh_token(&self, token_hash: &str, client_id: &str) -> Result<RefreshLookup> {
        let conn = self.lock();
        let row: Option<RefreshRow> = conn
            .query_row(
                "SELECT t.grant_id, t.expires_at, t.used, t.revoked, g.client_id,
                        COALESCE(r.disabled, 1), g.revoked_at IS NOT NULL
                 FROM oauth_tokens t
                   JOIN oauth_grants g ON g.id = t.grant_id
                   LEFT JOIN agent_registry r ON r.name = g.agent
                 WHERE t.token_hash = ?1 AND t.kind = 'refresh'",
                params![token_hash],
                |row| {
                    Ok(RefreshRow {
                        grant_id: row.get(0)?,
                        expires_at: row.get(1)?,
                        used: row.get(2)?,
                        revoked: row.get(3)?,
                        client_id: row.get(4)?,
                        disabled: row.get(5)?,
                        grant_revoked: row.get(6)?,
                    })
                },
            )
            .optional()?;
        let Some(RefreshRow {
            grant_id,
            expires_at,
            used,
            revoked,
            client_id: owner,
            disabled,
            grant_revoked,
        }) = row
        else {
            return Ok(RefreshLookup::Invalid);
        };
        if owner != client_id {
            return Ok(RefreshLookup::Invalid);
        }
        if used {
            revoke_grant(&conn, grant_id)?;
            return Ok(RefreshLookup::Reused);
        }
        if revoked || grant_revoked || disabled || expires_at <= unix_now() {
            return Ok(RefreshLookup::Invalid);
        }
        conn.execute(
            "UPDATE oauth_tokens SET used = 1 WHERE token_hash = ?1",
            params![token_hash],
        )?;
        Ok(RefreshLookup::Rotated { grant_id })
    }

    /// The agent an unexpired, unrevoked access token belongs to, and
    /// whether that agent is disabled. Notes the use at most once a minute
    /// per token.
    pub fn access_token_agent(&self, token_hash: &str) -> Result<Option<AccessAgent>> {
        let conn = self.lock();
        let now = unix_now();
        let row: Option<(String, bool, i64)> = conn
            .query_row(
                "SELECT g.agent, COALESCE(r.disabled, 1), g.id
                 FROM oauth_tokens t
                   JOIN oauth_grants g ON g.id = t.grant_id
                   LEFT JOIN agent_registry r ON r.name = g.agent
                 WHERE t.token_hash = ?1 AND t.kind = 'access' AND t.revoked = 0
                   AND t.expires_at > ?2 AND g.revoked_at IS NULL",
                params![token_hash, now],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let Some((agent, disabled, grant_id)) = row else {
            return Ok(None);
        };
        if !disabled {
            let touched = conn.execute(
                "UPDATE oauth_tokens SET last_used_at = ?2
                 WHERE token_hash = ?1 AND (last_used_at IS NULL OR last_used_at <= ?2 - ?3)",
                params![token_hash, now, TOUCH_EVERY],
            )?;
            if touched > 0 {
                conn.execute(
                    "UPDATE oauth_grants SET last_used_at = ?2 WHERE id = ?1",
                    params![grant_id, now],
                )?;
            }
        }
        Ok(Some(AccessAgent { agent, disabled }))
    }

    /// Revokes one token (RFC 7009). A refresh token takes its whole grant
    /// with it. A token of another client, or an unknown one, changes
    /// nothing. Returns whether anything was revoked.
    pub fn revoke_token(&self, token_hash: &str, client_id: Option<&str>) -> Result<bool> {
        let conn = self.lock();
        let row: Option<(String, i64, String)> = conn
            .query_row(
                "SELECT t.kind, t.grant_id, g.client_id FROM oauth_tokens t
                   JOIN oauth_grants g ON g.id = t.grant_id
                 WHERE t.token_hash = ?1",
                params![token_hash],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let Some((kind, grant_id, owner)) = row else {
            return Ok(false);
        };
        if client_id.is_some_and(|id| id != owner) {
            return Ok(false);
        }
        if kind == "refresh" {
            revoke_grant(&conn, grant_id)?;
        } else {
            conn.execute(
                "UPDATE oauth_tokens SET revoked = 1 WHERE token_hash = ?1",
                params![token_hash],
            )?;
        }
        Ok(true)
    }

    /// Every agent lore knows, with how it is connected and what it did:
    /// registry rows, agents that were seen, the env-token agents
    /// (`configured`) and authors of entries.
    pub fn agent_records(&self, configured: &[String]) -> Result<Vec<AgentRecord>> {
        let conn = self.lock();
        let mut records: BTreeMap<String, AgentRecord> = BTreeMap::new();
        let blank = |name: &str| AgentRecord {
            name: name.to_string(),
            kind: "token".into(),
            env_token: configured.iter().any(|c| c == name),
            avatar: avatars::default_for(name).to_string(),
            avatar_chosen: false,
            note: String::new(),
            display_name: None,
            disabled: false,
            registered_at: None,
            registered_by: String::new(),
            client: String::new(),
            first_seen: None,
            last_seen: None,
            requests: 0,
            authorizations: Vec::new(),
            stats: AgentStats::default(),
        };
        for name in configured {
            records.insert(name.clone(), blank(name));
        }
        {
            let mut stmt = conn.prepare(
                "SELECT name, kind, avatar, note, disabled, created_at, created_by, display_name
                 FROM agent_registry",
            )?;
            for row in stmt.query_map([], registry_from_row)? {
                let row = row?;
                let record = records
                    .entry(row.name.clone())
                    .or_insert_with(|| blank(&row.name));
                record.kind = row.kind;
                record.avatar = avatars::effective(&row.name, &row.avatar).to_string();
                record.avatar_chosen = avatars::is_known(&row.avatar);
                record.note = row.note;
                record.display_name = row.display_name;
                record.disabled = row.disabled;
                record.registered_at = Some(row.created_at);
                record.registered_by = row.created_by;
            }
        }
        {
            let mut stmt =
                conn.prepare("SELECT name, client, first_seen, last_seen, requests FROM agents")?;
            let rows = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            })?;
            for row in rows {
                let (name, client, first_seen, last_seen, requests) = row?;
                let record = records.entry(name.clone()).or_insert_with(|| blank(&name));
                record.client = client;
                record.first_seen = Some(first_seen);
                record.last_seen = Some(last_seen);
                record.requests = requests;
            }
        }
        // What each agent did, one grouped query per kind of thing.
        let grouped = |sql: &str| -> Result<Vec<(String, String, i64)>> {
            let mut stmt = conn.prepare(sql)?;
            let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?;
            Ok(rows.collect::<rusqlite::Result<_>>()?)
        };
        for (agent, kind, count) in grouped(
            "SELECT agent, kind, COUNT(*) FROM entries WHERE agent != '' GROUP BY agent, kind",
        )? {
            let record = records
                .entry(agent.clone())
                .or_insert_with(|| blank(&agent));
            record.stats.memories += count;
            record.stats.memories_by_kind.insert(kind, count);
        }
        for (agent, status, count) in
            grouped("SELECT agent, status, COUNT(*) FROM sessions GROUP BY agent, status")?
        {
            if let Some(record) = records.get_mut(&agent) {
                record.stats.sessions += count;
                if status == "open" {
                    record.stats.open_sessions += count;
                }
            }
        }
        for (agent, window, count) in grouped(
            "SELECT agent, '24h', COUNT(*) FROM activity
               WHERE at >= strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-1 day') GROUP BY agent
             UNION ALL
             SELECT agent, '7d', COUNT(*) FROM activity
               WHERE at >= strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-7 days') GROUP BY agent
             UNION ALL
             SELECT agent, '30d', COUNT(*) FROM activity
               WHERE at >= strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-30 days') GROUP BY agent",
        )? {
            if let Some(record) = records.get_mut(&agent) {
                match window.as_str() {
                    "24h" => record.stats.tool_calls_24h = count,
                    "7d" => record.stats.tool_calls_7d = count,
                    _ => record.stats.tool_calls_30d = count,
                }
            }
        }
        {
            let mut stmt = conn.prepare(
                "SELECT agent, provider, outcome, COUNT(*) FROM ops_log
                 GROUP BY agent, provider, outcome ORDER BY agent, provider, outcome",
            )?;
            let rows = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    ServiceCalls {
                        provider: row.get(1)?,
                        outcome: row.get(2)?,
                        count: row.get(3)?,
                    },
                ))
            })?;
            for row in rows {
                let (agent, calls) = row?;
                if let Some(record) = records.get_mut(&agent) {
                    record.stats.service_calls.push(calls);
                }
            }
        }
        for (agent, _, count) in grouped(
            "SELECT done_by, '', COUNT(*) FROM tasks
             WHERE status = 'done' AND done_by != '' GROUP BY done_by",
        )? {
            if let Some(record) = records.get_mut(&agent) {
                record.stats.tasks_done = count;
            }
        }
        for (agent, _, count) in grouped("SELECT agent, '', COUNT(*) FROM files GROUP BY agent")? {
            if let Some(record) = records.get_mut(&agent) {
                record.stats.files_saved = count;
            }
        }
        {
            let mut stmt = conn.prepare(
                "SELECT id, agent, client_id, client_name, redirect_uri, authorized_by,
                        strftime('%Y-%m-%dT%H:%M:%SZ', created_at, 'unixepoch'),
                        strftime('%Y-%m-%dT%H:%M:%SZ', last_used_at, 'unixepoch'),
                        revoked_at IS NOT NULL
                 FROM oauth_grants ORDER BY created_at DESC, id DESC",
            )?;
            let rows = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(1)?,
                    Authorization {
                        id: row.get(0)?,
                        client_id: row.get(2)?,
                        client_name: row.get(3)?,
                        redirect_uri: row.get(4)?,
                        authorized_by: row.get(5)?,
                        authorized_at: row.get(6)?,
                        last_used_at: row.get(7)?,
                        revoked: row.get(8)?,
                    },
                ))
            })?;
            for row in rows {
                let (agent, authorization) = row?;
                if let Some(record) = records.get_mut(&agent) {
                    record.authorizations.push(authorization);
                }
            }
        }
        // The names lore itself uses in the activity feed are no agents.
        records.remove("admin");
        Ok(records.into_values().collect())
    }
}

/// Gives every agent the `agents` table has seen a registry row, keeping
/// when it was first seen. Run once, when a database from before the
/// registry is opened.
pub(super) fn backfill_registry(conn: &Connection) -> Result<()> {
    conn.execute(
        "INSERT OR IGNORE INTO agent_registry (name, kind, created_at, created_by)
         SELECT name, 'token', first_seen, 'environment' FROM agents",
        [],
    )?;
    Ok(())
}

/// Revokes a grant and every token and code of it.
fn revoke_grant(conn: &Connection, grant_id: i64) -> Result<()> {
    conn.execute(
        "UPDATE oauth_grants SET revoked_at = COALESCE(revoked_at, ?2) WHERE id = ?1",
        params![grant_id, unix_now()],
    )?;
    conn.execute(
        "UPDATE oauth_tokens SET revoked = 1 WHERE grant_id = ?1",
        params![grant_id],
    )?;
    conn.execute(
        "DELETE FROM oauth_codes WHERE grant_id = ?1 AND used = 0",
        params![grant_id],
    )?;
    Ok(())
}

fn get_registry_agent(conn: &Connection, name: &str) -> Result<Option<RegistryAgent>> {
    Ok(conn
        .query_row(
            "SELECT name, kind, avatar, note, disabled, created_at, created_by, display_name
             FROM agent_registry WHERE name = ?1",
            params![name],
            registry_from_row,
        )
        .optional()?)
}

fn registry_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RegistryAgent> {
    Ok(RegistryAgent {
        name: row.get(0)?,
        kind: row.get(1)?,
        avatar: row.get(2)?,
        note: row.get(3)?,
        disabled: row.get(4)?,
        created_at: row.get(5)?,
        created_by: row.get(6)?,
        display_name: row.get(7)?,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn temp_db(label: &str) -> (Db, std::path::PathBuf) {
        static COUNT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "lore-registry-test-{label}-{}-{}",
            std::process::id(),
            COUNT.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("lore.db");
        (Db::open(&path).unwrap(), path)
    }

    #[test]
    fn a_display_name_is_one_short_line_and_empty_clears_it() {
        assert_eq!(clean_display_name("  Claude  "), Ok(Some("Claude".into())));
        assert_eq!(clean_display_name("   "), Ok(None));
        assert_eq!(clean_display_name(""), Ok(None));
        assert!(clean_display_name("two\nlines").is_err());
        assert!(clean_display_name("tab\there").is_err());
        assert!(clean_display_name("bell\u{7}").is_err());
        assert_eq!(
            clean_display_name(&"é".repeat(40)),
            Ok(Some("é".repeat(40)))
        );
        assert!(clean_display_name(&"x".repeat(41)).is_err());
        assert_eq!(
            clean_display_name("  Big   Claude  "),
            Ok(Some("Big Claude".into()))
        );
        for bad in [
            "evil\u{202E}txt",
            "a\u{2066}b",
            "zero\u{200B}width",
            "joiner\u{200D}",
            "bom\u{FEFF}",
            "nbsp\u{00A0}x",
            "em\u{2003}space",
            "line\u{2028}sep",
            "filler\u{3164}",
            "braille\u{2800}",
            "tag\u{E0041}",
            "soft\u{00AD}hyphen",
        ] {
            assert!(clean_display_name(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_display_name_never_takes_another_agent_s_name_and_never_renames() {
        let (db, _) = temp_db("display");
        db.register_token_agents(&["claude-builtin".into(), "codex".into()])
            .unwrap();
        let row = db
            .set_agent_display_name("claude-builtin", Some("Claude <b>"), "admin")
            .unwrap();
        assert_eq!(row.name, "claude-builtin");
        assert_eq!(row.display_name.as_deref(), Some("Claude <b>"));
        // Another agent's technical name, in any case, is refused; its own
        // is allowed.
        assert!(
            db.set_agent_display_name("claude-builtin", Some("Codex"), "admin")
                .is_err()
        );
        assert!(
            db.set_agent_display_name("claude-builtin", Some("Claude-Builtin"), "admin")
                .is_ok()
        );
        let records = db.agent_records(&[]).unwrap();
        let record = records.iter().find(|r| r.name == "claude-builtin").unwrap();
        assert_eq!(record.display_name.as_deref(), Some("Claude-Builtin"));
        assert!(records.iter().all(|r| r.name != "Claude-Builtin"));
        let summary = db.agents(&[]).unwrap();
        assert_eq!(
            summary
                .iter()
                .find(|a| a.name == "claude-builtin")
                .unwrap()
                .display_name
                .as_deref(),
            Some("Claude-Builtin")
        );
        // Cleared: the technical name shows again.
        let row = db
            .set_agent_display_name("claude-builtin", None, "admin")
            .unwrap();
        assert_eq!(row.display_name, None);
    }

    /// Schema 9 adds a nullable column and nothing else: a database of
    /// schema 8 with rows keeps every row, gets the column (NULL), and a
    /// second start changes nothing.
    #[test]
    fn schema_nine_adds_the_display_name_to_a_schema_eight_database() {
        let (db, path) = temp_db("schema9");
        db.register_token_agents(&["alpha".into(), "beta".into()])
            .unwrap();
        db.set_agent_details("alpha", Some("nova"), Some("a note"), "admin")
            .unwrap();
        {
            let conn = db.lock();
            conn.execute_batch(
                "ALTER TABLE agent_registry DROP COLUMN display_name;
                 ALTER TABLE builtin_agents DROP COLUMN terminal_services;
                 ALTER TABLE builtin_agents DROP COLUMN claude_priority;
                 ALTER TABLE builtin_agents DROP COLUMN claude_fallback;
                 UPDATE meta SET value = '8' WHERE key = 'schema_version';",
            )
            .unwrap();
        }
        drop(db);
        for _ in 0..2 {
            let db = Db::open(&path).unwrap();
            let conn = db.lock();
            let version: String = conn
                .query_row(
                    "SELECT value FROM meta WHERE key = 'schema_version'",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(version, crate::db::SCHEMA_VERSION.to_string());
            const { assert!(crate::db::SCHEMA_VERSION >= 9) };
            let rows: Vec<(String, String, String, Option<String>)> = conn
                .prepare(
                    "SELECT name, avatar, note, display_name FROM agent_registry ORDER BY name",
                )
                .unwrap()
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
                .unwrap()
                .collect::<rusqlite::Result<_>>()
                .unwrap();
            assert_eq!(
                rows,
                vec![
                    ("alpha".into(), "nova".into(), "a note".into(), None),
                    ("beta".into(), "".into(), "".into(), None),
                ]
            );
            let columns: Vec<String> = conn
                .prepare("SELECT name FROM pragma_table_info('builtin_agents')")
                .unwrap()
                .query_map([], |r| r.get(0))
                .unwrap()
                .collect::<rusqlite::Result<_>>()
                .unwrap();
            for column in ["terminal_services", "claude_priority", "claude_fallback"] {
                assert!(columns.iter().any(|c| c == column), "{column}");
            }
        }
    }

    fn client(db: &Db, id: &str) {
        db.register_oauth_client(&OAuthClient {
            client_id: id.into(),
            client_name: "Test Client".into(),
            redirect_uris: vec!["http://127.0.0.1:9/cb".into()],
        })
        .unwrap();
    }

    fn approval(agent: &str, new_agent: bool, code: &str) -> Approval {
        Approval {
            agent: agent.into(),
            new_agent,
            avatar: "nova".into(),
            client_id: "client-1".into(),
            client_name: "Test Client".into(),
            redirect_uri: "http://127.0.0.1:9/cb".into(),
            authorized_by: "admin".into(),
            reserved: vec!["claude".into()],
            services_off: false,
            code_hash: code.into(),
            code_challenge: "c".repeat(43),
            code_expires_at: unix_now() + 300,
        }
    }

    #[test]
    fn a_database_from_before_the_registry_gains_it_and_keeps_its_rows() {
        let (db, path) = temp_db("old");
        // What a database of the previous build looks like: no registry,
        // no OAuth tables, schema version 1, agents seen and entries.
        db.execute_for_test(
            "DROP TABLE agent_registry; DROP TABLE oauth_clients; DROP TABLE oauth_grants;
             DROP TABLE oauth_codes; DROP TABLE oauth_tokens;
             UPDATE meta SET value = '1' WHERE key = 'schema_version';
             INSERT INTO agents (name, client, first_seen, last_seen, requests)
               VALUES ('claude', 'claude-code/2', '2026-01-02T03:04:05Z', '2026-01-03T00:00:00Z', 7);
             INSERT INTO entries (project, kind, title, body, agent)
               VALUES ('lore', 'note', 'kept', 'body', 'claude');",
        );
        drop(db);
        let db = Db::open(&path).unwrap();
        let counts: HashMap<String, i64> = db.table_counts().unwrap().into_iter().collect();
        for table in [
            "agent_registry",
            "oauth_clients",
            "oauth_grants",
            "oauth_codes",
            "oauth_tokens",
        ] {
            assert!(counts.contains_key(table), "{table} missing");
        }
        assert_eq!(counts["entries"], 1);
        assert_eq!(counts["agents"], 1);
        let claude = db.registry_agent("claude").unwrap().unwrap();
        assert_eq!(
            (claude.kind.as_str(), claude.created_at.as_str()),
            ("token", "2026-01-02T03:04:05Z")
        );
        assert!(!claude.disabled);
        // Env-token agents get a row at start-up and when first seen.
        db.register_token_agents(&["codex".into()]).unwrap();
        assert!(db.registry_agent("codex").unwrap().is_some());
        assert!(!db.token_agent_disabled("gemini").unwrap());
        assert_eq!(db.registry_agent("gemini").unwrap().unwrap().kind, "token");
        // The backfill runs once: a deleted row is not brought back.
        db.execute_for_test("DELETE FROM agent_registry WHERE name = 'claude'");
        drop(db);
        let db = Db::open(&path).unwrap();
        assert!(db.registry_agent("claude").unwrap().is_none());
    }

    #[test]
    fn an_approver_without_integrations_grants_no_service() {
        let (db, _) = temp_db("services-off");
        client(&db, "client-1");
        // Approved by someone with `integrations`: the default, full.
        db.approve(&approval("trusted", true, "t1")).unwrap();
        for provider in crate::db::PROVIDERS {
            assert_eq!(db.ops_level("trusted", provider).unwrap(), "full");
        }
        // Approved with `agents` alone: off on every service, mail too.
        let restricted = Approval {
            services_off: true,
            ..approval("cursor", true, "c1")
        };
        db.approve(&restricted).unwrap();
        for provider in crate::db::PROVIDERS {
            assert_eq!(
                db.ops_level("cursor", provider).unwrap(),
                "off",
                "{provider}"
            );
        }
        assert_eq!(db.ops_level("cursor", "mail").unwrap(), "off");
        // Re-authorizing keeps the levels someone already set and turns the
        // rest off.
        db.set_ops_level("trusted", "github", "read").unwrap();
        db.set_ops_level("trusted", "dokploy", "full").unwrap();
        db.approve(&Approval {
            services_off: true,
            ..approval("trusted", false, "t2")
        })
        .unwrap();
        assert_eq!(db.ops_level("trusted", "github").unwrap(), "read");
        assert_eq!(db.ops_level("trusted", "cloudflare").unwrap(), "off");
        // Level `full` keeps no row, so it is off now as well: the
        // approver could not have granted it.
        assert_eq!(db.ops_level("trusted", "dokploy").unwrap(), "off");
    }

    #[test]
    fn never_authorized_clients_expire_after_an_hour() {
        let (db, _) = temp_db("client-age");
        client(&db, "stale");
        client(&db, "used");
        client(&db, "recent");
        db.approve(&Approval {
            client_id: "used".into(),
            ..approval("cursor", true, "u1")
        })
        .unwrap();
        db.execute_for_test(&format!(
            "UPDATE oauth_clients SET created_at = {} WHERE client_id IN ('stale', 'used')",
            unix_now() - 2 * 60 * 60
        ));
        client(&db, "new");
        assert!(db.oauth_client("stale").unwrap().is_none());
        for kept in ["used", "recent", "new"] {
            assert!(db.oauth_client(kept).unwrap().is_some(), "{kept}");
        }
    }

    #[test]
    fn a_new_agent_cannot_take_a_name_from_the_history() {
        let (db, _) = temp_db("history-names");
        client(&db, "client-1");
        db.execute_for_test(
            "INSERT INTO entries (project, kind, title, body, agent)
               VALUES ('p', 'note', 't', 'b', 'Writer');
             INSERT INTO sessions (id, agent, project, title, started_at, last_seen_at)
               VALUES ('s1', 'sessioner', 'p', 't', 'x', 'x');
             INSERT INTO ops_log (agent, provider, method, path, status, outcome, created_at)
               VALUES ('caller', 'github', 'GET', '/user', 200, 'ok', 'x');
             INSERT INTO tasks (project, title, created_by, created_at, updated_at)
               VALUES ('p', 't', 'planner', 'x', 'x');",
        );
        for name in ["writer", "sessioner", "caller", "planner"] {
            let refused = db.approve(&approval(name, true, &format!("c-{name}")));
            assert!(refused.is_err(), "{name}");
            assert!(db.registry_agent(name).unwrap().is_none());
        }
        db.approve(&approval("fresh", true, "c-fresh")).unwrap();
        // The OAuth agent's own history does not stop its re-authorization.
        db.execute_for_test(
            "INSERT INTO entries (project, kind, title, body, agent)
               VALUES ('p', 'note', 't', 'b', 'fresh');",
        );
        db.approve(&approval("fresh", false, "c-fresh-2")).unwrap();
    }

    #[test]
    fn approval_codes_and_tokens_follow_the_rules() {
        let (db, _) = temp_db("oauth");
        client(&db, "client-1");
        // A new agent may not take an env-token name or an existing one.
        assert!(db.approve(&approval("claude", true, "h0")).is_err());
        let grant = db.approve(&approval("cursor", true, "h1")).unwrap();
        assert!(db.approve(&approval("cursor", true, "h2")).is_err());
        assert_eq!(db.registry_agent("cursor").unwrap().unwrap().kind, "oauth");
        // Re-authorizing needs an existing OAuth agent.
        assert!(db.approve(&approval("ghost", false, "h3")).is_err());
        let again = db.approve(&approval("cursor", false, "h4")).unwrap();
        assert_ne!(grant, again);

        // A code is taken once; the second time revokes its grant.
        let CodeLookup::Taken(code) = db.take_code("h1").unwrap() else {
            panic!("the code was not taken");
        };
        assert_eq!(code.grant_id, grant);
        db.issue_tokens(grant, "a1", unix_now() + 60, "r1", unix_now() + 600)
            .unwrap();
        assert_eq!(
            db.access_token_agent("a1").unwrap(),
            Some(AccessAgent {
                agent: "cursor".into(),
                disabled: false
            })
        );
        assert!(matches!(db.take_code("h1").unwrap(), CodeLookup::Reused));
        assert!(matches!(db.take_code("nope").unwrap(), CodeLookup::Missing));
        assert_eq!(db.access_token_agent("a1").unwrap(), None);
        assert!(!db.grant_usable(grant).unwrap());

        // Refresh tokens rotate; a reused one revokes the grant.
        db.issue_tokens(again, "a2", unix_now() + 60, "r2", unix_now() + 600)
            .unwrap();
        assert_eq!(
            db.take_refresh_token("r2", "other-client").unwrap(),
            RefreshLookup::Invalid
        );
        assert_eq!(
            db.take_refresh_token("r2", "client-1").unwrap(),
            RefreshLookup::Rotated { grant_id: again }
        );
        db.issue_tokens(again, "a3", unix_now() + 60, "r3", unix_now() + 600)
            .unwrap();
        assert_eq!(
            db.take_refresh_token("r2", "client-1").unwrap(),
            RefreshLookup::Reused
        );
        assert_eq!(db.access_token_agent("a3").unwrap(), None);
        assert_eq!(
            db.take_refresh_token("r3", "client-1").unwrap(),
            RefreshLookup::Invalid
        );

        // Expired access tokens are refused; revocation of one token.
        let third = db.approve(&approval("cursor", false, "h5")).unwrap();
        db.issue_tokens(third, "a4", unix_now() - 1, "r4", unix_now() + 600)
            .unwrap();
        assert_eq!(db.access_token_agent("a4").unwrap(), None);
        db.issue_tokens(third, "a5", unix_now() + 60, "r5", unix_now() + 600)
            .unwrap();
        assert!(!db.revoke_token("a5", Some("other-client")).unwrap());
        assert!(db.access_token_agent("a5").unwrap().is_some());
        assert!(db.revoke_token("a5", Some("client-1")).unwrap());
        assert_eq!(db.access_token_agent("a5").unwrap(), None);
        assert!(!db.revoke_token("unknown", None).unwrap());

        // Disabling shows on the token; revoking the agent ends it all.
        db.issue_tokens(third, "a6", unix_now() + 60, "r6", unix_now() + 600)
            .unwrap();
        db.set_agent_disabled("cursor", true, "admin").unwrap();
        assert_eq!(
            db.access_token_agent("a6").unwrap(),
            Some(AccessAgent {
                agent: "cursor".into(),
                disabled: true
            })
        );
        assert!(db.approve(&approval("cursor", false, "h6")).is_err());
        db.set_agent_disabled("cursor", false, "admin").unwrap();
        // Only the third grant was still live.
        assert_eq!(db.revoke_agent("cursor").unwrap(), 1);
        assert_eq!(db.access_token_agent("a6").unwrap(), None);
        assert!(db.delete_oauth_agent("cursor").unwrap());
        assert!(db.registry_agent("cursor").unwrap().is_none());
        db.register_token_agents(&["claude".into()]).unwrap();
        assert!(db.delete_oauth_agent("claude").is_err());
    }

    #[test]
    fn clients_are_capped_and_the_never_authorized_go_first() {
        let (db, _) = temp_db("clients");
        for n in 0..MAX_OAUTH_CLIENTS {
            client(&db, &format!("c{n}"));
        }
        // The first one is authorized, so it stays.
        db.execute_for_test("UPDATE oauth_clients SET authorized_at = 1 WHERE client_id = 'c0'");
        client(&db, "newest");
        assert!(db.oauth_client("c0").unwrap().is_some());
        assert!(db.oauth_client("c1").unwrap().is_none());
        assert!(db.oauth_client("newest").unwrap().is_some());
        db.execute_for_test("UPDATE oauth_clients SET authorized_at = 1");
        assert!(
            db.register_oauth_client(&OAuthClient {
                client_id: "refused".into(),
                client_name: String::new(),
                redirect_uris: vec!["https://x.example/cb".into()],
            })
            .is_err()
        );
    }

    #[test]
    fn statistics_count_what_each_agent_did() {
        let (db, _) = temp_db("stats");
        db.execute_for_test(
            "INSERT INTO entries (project, kind, title, body, agent) VALUES
               ('p', 'note', 'a', 'b', 'claude'), ('p', 'note', 'a', 'b', 'claude'),
               ('p', 'bug', 'a', 'b', 'claude'), ('p', 'note', 'a', 'b', 'codex');
             INSERT INTO sessions (id, agent, project, title, status, started_at, last_seen_at) VALUES
               ('s1', 'claude', 'p', 't', 'open', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z'),
               ('s2', 'claude', 'p', 't', 'closed', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z');
             INSERT INTO activity (at, agent, tool) VALUES
               (strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-1 hour'), 'claude', 'recall'),
               (strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-3 days'), 'claude', 'log'),
               (strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-20 days'), 'claude', 'log'),
               (strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-40 days'), 'claude', 'log');
             INSERT INTO ops_log (agent, provider, method, path, status, outcome, created_at) VALUES
               ('claude', 'github', 'GET', '/user', 200, 'ok', '2026-01-01T00:00:00Z'),
               ('claude', 'github', 'GET', '/user', 200, 'ok', '2026-01-01T00:00:00Z'),
               ('claude', 'github', 'POST', '/x', 0, 'denied', '2026-01-01T00:00:00Z');
             INSERT INTO tasks (project, title, status, created_by, done_by, created_at, updated_at) VALUES
               ('p', 't', 'done', 'admin', 'claude', 'x', 'x'),
               ('p', 't', 'open', 'admin', '', 'x', 'x');
             INSERT INTO files (project, path, version, description, content, size, sha256, agent,
                                created_at) VALUES
               ('p', 'a.md', 1, 'd', x'00', 1, 'h', 'claude', 'x'),
               ('p', 'a.md', 2, 'd', x'00', 1, 'h', 'claude', 'x');",
        );
        db.touch_agent("claude", "claude-code/2").unwrap();
        db.set_agent_details("claude", Some("ember"), Some("laptop"), "admin")
            .unwrap();
        let records = db.agent_records(&["claude".into(), "idle".into()]).unwrap();
        let claude = records.iter().find(|r| r.name == "claude").unwrap();
        let stats = &claude.stats;
        assert_eq!(stats.memories, 3);
        assert_eq!(stats.memories_by_kind.get("note"), Some(&2));
        assert_eq!(stats.memories_by_kind.get("bug"), Some(&1));
        assert_eq!((stats.sessions, stats.open_sessions), (2, 1));
        assert_eq!(
            (
                stats.tool_calls_24h,
                stats.tool_calls_7d,
                stats.tool_calls_30d
            ),
            (1, 2, 3)
        );
        assert_eq!(
            stats.service_calls,
            vec![
                ServiceCalls {
                    provider: "github".into(),
                    outcome: "denied".into(),
                    count: 1
                },
                ServiceCalls {
                    provider: "github".into(),
                    outcome: "ok".into(),
                    count: 2
                },
            ]
        );
        assert_eq!((stats.tasks_done, stats.files_saved), (1, 2));
        assert_eq!(
            (claude.avatar.as_str(), claude.avatar_chosen),
            ("ember", true)
        );
        assert_eq!(claude.note, "laptop");
        assert!(claude.env_token);
        assert_eq!(claude.requests, 1);
        let codex = records.iter().find(|r| r.name == "codex").unwrap();
        assert_eq!(codex.stats.memories, 1);
        assert!(!codex.env_token);
        assert_eq!(codex.avatar, avatars::default_for("codex"));
        let idle = records.iter().find(|r| r.name == "idle").unwrap();
        assert!(idle.first_seen.is_none() && idle.stats.memories == 0);
        // Disabling closes the open sessions.
        assert_eq!(db.set_agent_disabled("claude", true, "admin").unwrap(), 1);
        assert_eq!(db.set_agent_disabled("claude", true, "admin").unwrap(), 0);
    }
}
