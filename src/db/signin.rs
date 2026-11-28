//! Sign-in security: passwords of the built-in users set on the page,
//! passkeys (WebAuthn credentials), authenticator-app (TOTP) secrets,
//! recovery codes and the sign-in audit trail.
//!
//! An *account key* names whose credential a row is: `user:<users.id>` for
//! a stored user, `admin` or `viewer` for the built-in users. User ids are
//! never reused, so a key never moves to another user.
//!
//! None of these tables is part of the JSON backup; the full database
//! backup carries them. An older lore binary ignores them, which means it
//! does not enforce second factors and lets the environment passwords of
//! the built-in users sign in again.

use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension, params};

use super::Db;

/// Tables added for sign-in security (schema 10). Created by the start-up
/// migration; additive only.
pub(super) const SCHEMA: &str = r#"
-- Passwords of the built-in users set on the admin page. When a row exists
-- it wins over LORE_ADMIN_PASSWORD / LORE_VIEWER_PASSWORD (except under
-- LORE_ADMIN_BREAK_GLASS, admin only). The environment variable still
-- decides whether the user exists at all.
CREATE TABLE IF NOT EXISTS builtin_passwords (
    username      TEXT PRIMARY KEY CHECK (username IN ('admin', 'viewer')),
    password_hash TEXT NOT NULL,
    changed_at    TEXT NOT NULL,
    changed_by    TEXT NOT NULL DEFAULT ''
);
-- The WebAuthn user handle of an account: 32 random bytes, no personal data.
CREATE TABLE IF NOT EXISTS webauthn_users (
    account     TEXT PRIMARY KEY,
    user_handle BLOB NOT NULL UNIQUE,
    created_at  TEXT NOT NULL
);
-- Registered passkeys and security keys.
CREATE TABLE IF NOT EXISTS webauthn_credentials (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    account         TEXT NOT NULL,
    credential_id   BLOB NOT NULL UNIQUE,
    rp_id           TEXT NOT NULL,
    public_key      BLOB NOT NULL,
    alg             INTEGER NOT NULL,
    sign_count      INTEGER NOT NULL DEFAULT 0,
    uv_initialized  INTEGER NOT NULL DEFAULT 0,
    backup_eligible INTEGER NOT NULL DEFAULT 0,
    backup_state    INTEGER NOT NULL DEFAULT 0,
    discoverable    INTEGER,
    transports      TEXT NOT NULL DEFAULT '[]',
    aaguid          BLOB,
    attestation_fmt TEXT NOT NULL DEFAULT 'none',
    name            TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    last_used_at    TEXT
);
CREATE INDEX IF NOT EXISTS webauthn_credentials_account ON webauthn_credentials (account);
-- Confirmed authenticator-app secrets, encrypted with LORE_VAULT_KEY
-- (associated data "totp\n<account>"). Unconfirmed ones live in memory.
CREATE TABLE IF NOT EXISTS totp_secrets (
    account      TEXT PRIMARY KEY,
    nonce        BLOB NOT NULL,
    secret       BLOB NOT NULL,
    last_step    INTEGER NOT NULL,
    confirmed_at TEXT NOT NULL
);
-- Single-use recovery codes, as SHA-256 hex of "<account>:<code>".
CREATE TABLE IF NOT EXISTS recovery_codes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    account    TEXT NOT NULL,
    code_hash  TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    used_at    TEXT
);
CREATE INDEX IF NOT EXISTS recovery_codes_account ON recovery_codes (account);
-- Sign-in and credential audit trail; the newest 5000 rows are kept.
CREATE TABLE IF NOT EXISTS auth_events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    account    TEXT NOT NULL DEFAULT '',
    actor      TEXT NOT NULL DEFAULT '',
    event      TEXT NOT NULL,
    ip         TEXT NOT NULL DEFAULT '',
    detail     TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS auth_events_account ON auth_events (account, id DESC);
"#;

/// Sign-in log rows kept of each kind (noise, and the rest); older ones
/// are dropped.
const AUTH_EVENTS_KEPT: i64 = 5000;

/// Events anyone can cause without an account or a right password: they
/// have their own budget, so a flood of them never erases the others.
const NOISE_EVENTS: &[&str] = &[
    "signin.fail.password",
    "signin.fail.passkey",
    "signin.fail.second_factor",
    "signin.limited",
    "signin.pending",
    "reauth.fail",
];

const NOW: &str = "strftime('%Y-%m-%dT%H:%M:%SZ', 'now')";

/// The account key of a stored user.
pub fn user_account(id: i64) -> String {
    format!("user:{id}")
}

/// A built-in user's password set on the page.
#[derive(Debug, Clone)]
pub struct BuiltinPassword {
    pub password_hash: String,
    pub changed_at: String,
}

/// A registered passkey, as stored.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Credential {
    pub id: i64,
    pub account: String,
    #[serde(skip)]
    pub credential_id: Vec<u8>,
    pub rp_id: String,
    #[serde(skip)]
    pub public_key: Vec<u8>,
    #[serde(skip)]
    pub alg: i64,
    #[serde(skip)]
    pub sign_count: u32,
    pub uv_initialized: bool,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub discoverable: Option<bool>,
    pub transports: Vec<String>,
    pub name: String,
    pub created_at: String,
    pub last_used_at: Option<String>,
}

const CREDENTIAL_COLUMNS: &str = "id, account, credential_id, rp_id, public_key, alg, sign_count, \
     uv_initialized, backup_eligible, backup_state, discoverable, transports, name, created_at, \
     last_used_at";

impl Credential {
    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        let transports: String = row.get(11)?;
        Ok(Self {
            id: row.get(0)?,
            account: row.get(1)?,
            credential_id: row.get(2)?,
            rp_id: row.get(3)?,
            public_key: row.get(4)?,
            alg: row.get(5)?,
            sign_count: u32::try_from(row.get::<_, i64>(6)?).unwrap_or(u32::MAX),
            uv_initialized: row.get(7)?,
            backup_eligible: row.get(8)?,
            backup_state: row.get(9)?,
            discoverable: row.get(10)?,
            transports: serde_json::from_str(&transports).unwrap_or_default(),
            name: row.get(12)?,
            created_at: row.get(13)?,
            last_used_at: row.get(14)?,
        })
    }
}

/// A passkey to store after a verified registration.
#[derive(Debug, Clone)]
pub struct NewCredential {
    pub account: String,
    pub credential_id: Vec<u8>,
    pub rp_id: String,
    pub public_key: Vec<u8>,
    pub alg: i64,
    pub sign_count: u32,
    pub uv_initialized: bool,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub discoverable: Option<bool>,
    pub transports: Vec<String>,
    pub aaguid: Vec<u8>,
    pub attestation_fmt: String,
    pub name: String,
}

/// A confirmed authenticator-app secret, still encrypted.
#[derive(Debug, Clone)]
pub struct TotpRow {
    pub nonce: Vec<u8>,
    pub secret: Vec<u8>,
    pub confirmed_at: String,
}

/// What second factors an account has, for the users panel.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct SecondFactorSummary {
    pub passkeys: i64,
    pub totp: bool,
    pub recovery_left: i64,
}

impl SecondFactorSummary {
    pub fn any(&self) -> bool {
        self.passkeys > 0 || self.totp || self.recovery_left > 0
    }
}

/// One row of the sign-in log.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AuthEvent {
    pub id: i64,
    pub created_at: String,
    pub account: String,
    pub actor: String,
    pub event: String,
    pub ip: String,
    pub detail: String,
}

/// Whether the account a key names still exists in the database: a stored
/// user's row; the built-in users always (their environment variable is
/// checked elsewhere). Rows of a user an older binary deleted are ignored
/// this way, never deleted behind the owner's back.
fn account_exists(conn: &Connection, account: &str) -> Result<bool> {
    match account.strip_prefix("user:") {
        Some(id) => {
            let Ok(id) = id.parse::<i64>() else {
                return Ok(false);
            };
            Ok(conn
                .query_row("SELECT 1 FROM users WHERE id = ?1", params![id], |_| Ok(()))
                .optional()?
                .is_some())
        }
        None => Ok(account == "admin" || account == "viewer"),
    }
}

/// Deletes every second factor of an account inside an open transaction.
fn delete_second_factors(conn: &Connection, account: &str) -> Result<()> {
    conn.execute(
        "DELETE FROM webauthn_credentials WHERE account = ?1",
        params![account],
    )?;
    conn.execute(
        "DELETE FROM totp_secrets WHERE account = ?1",
        params![account],
    )?;
    conn.execute(
        "DELETE FROM recovery_codes WHERE account = ?1",
        params![account],
    )?;
    Ok(())
}

/// Deletes a stored user's sign-in rows; called inside `delete_user`'s
/// transaction.
pub(super) fn delete_user_credentials(conn: &Connection, id: i64) -> Result<()> {
    let account = user_account(id);
    delete_second_factors(conn, &account)?;
    conn.execute(
        "DELETE FROM webauthn_users WHERE account = ?1",
        params![account],
    )?;
    Ok(())
}

impl Db {
    /// A built-in user's page password, if one was set.
    pub fn builtin_password(&self, username: &str) -> Result<Option<BuiltinPassword>> {
        Ok(self
            .lock()
            .query_row(
                "SELECT password_hash, changed_at FROM builtin_passwords WHERE username = ?1",
                params![username],
                |row| {
                    Ok(BuiltinPassword {
                        password_hash: row.get(0)?,
                        changed_at: row.get(1)?,
                    })
                },
            )
            .optional()?)
    }

    pub fn set_builtin_password(&self, username: &str, hash: &str, changed_by: &str) -> Result<()> {
        self.lock().execute(
            &format!(
                "INSERT INTO builtin_passwords (username, password_hash, changed_at, changed_by)
                 VALUES (?1, ?2, {NOW}, ?3)
                 ON CONFLICT (username) DO UPDATE SET password_hash = excluded.password_hash,
                     changed_at = excluded.changed_at, changed_by = excluded.changed_by"
            ),
            params![username, hash, changed_by],
        )?;
        Ok(())
    }

    /// Removes a built-in user's page password; true when there was one.
    pub fn clear_builtin_password(&self, username: &str) -> Result<bool> {
        Ok(self.lock().execute(
            "DELETE FROM builtin_passwords WHERE username = ?1",
            params![username],
        )? > 0)
    }

    /// The account's WebAuthn user handle, made (32 random bytes) when it
    /// has none yet.
    pub fn webauthn_user_handle(&self, account: &str) -> Result<Vec<u8>> {
        let conn = self.lock();
        if let Some(handle) = conn
            .query_row(
                "SELECT user_handle FROM webauthn_users WHERE account = ?1",
                params![account],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?
        {
            return Ok(handle);
        }
        let mut handle = vec![0u8; 32];
        getrandom::fill(&mut handle).map_err(|error| anyhow::anyhow!("no randomness: {error}"))?;
        conn.execute(
            &format!(
                "INSERT INTO webauthn_users (account, user_handle, created_at) VALUES (?1, ?2, {NOW})"
            ),
            params![account, handle],
        )?;
        Ok(handle)
    }

    /// The account's user handle, without making one.
    pub fn existing_user_handle(&self, account: &str) -> Result<Option<Vec<u8>>> {
        Ok(self
            .lock()
            .query_row(
                "SELECT user_handle FROM webauthn_users WHERE account = ?1",
                params![account],
                |row| row.get(0),
            )
            .optional()?)
    }

    /// Stores a verified passkey. Fails when its credential id is taken.
    pub fn add_credential(&self, new: &NewCredential) -> Result<Credential> {
        let conn = self.lock();
        conn.execute(
            &format!(
                "INSERT INTO webauthn_credentials (account, credential_id, rp_id, public_key, alg,
                     sign_count, uv_initialized, backup_eligible, backup_state, discoverable,
                     transports, aaguid, attestation_fmt, name, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, {NOW})"
            ),
            params![
                new.account,
                new.credential_id,
                new.rp_id,
                new.public_key,
                new.alg,
                i64::from(new.sign_count),
                new.uv_initialized,
                new.backup_eligible,
                new.backup_state,
                new.discoverable,
                serde_json::to_string(&new.transports)?,
                new.aaguid,
                new.attestation_fmt,
                new.name,
            ],
        )?;
        let id = conn.last_insert_rowid();
        conn.query_row(
            &format!("SELECT {CREDENTIAL_COLUMNS} FROM webauthn_credentials WHERE id = ?1"),
            params![id],
            Credential::from_row,
        )
        .context("passkey vanished after insert")
    }

    /// Whether any account holds this credential id.
    pub fn credential_id_taken(&self, raw: &[u8]) -> Result<bool> {
        Ok(self
            .lock()
            .query_row(
                "SELECT 1 FROM webauthn_credentials WHERE credential_id = ?1",
                params![raw],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    /// An account's passkeys, oldest first.
    pub fn credentials(&self, account: &str) -> Result<Vec<Credential>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(&format!(
            "SELECT {CREDENTIAL_COLUMNS} FROM webauthn_credentials WHERE account = ?1 ORDER BY id"
        ))?;
        let rows = stmt.query_map(params![account], Credential::from_row)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// The passkey with this raw credential id, when its account still
    /// exists.
    pub fn credential_by_id(&self, raw: &[u8]) -> Result<Option<Credential>> {
        let conn = self.lock();
        let found = conn
            .query_row(
                &format!(
                    "SELECT {CREDENTIAL_COLUMNS} FROM webauthn_credentials WHERE credential_id = ?1"
                ),
                params![raw],
                Credential::from_row,
            )
            .optional()?;
        match found {
            Some(credential) if account_exists(&conn, &credential.account)? => Ok(Some(credential)),
            _ => Ok(None),
        }
    }

    /// The account a user handle belongs to.
    pub fn account_by_user_handle(&self, handle: &[u8]) -> Result<Option<String>> {
        Ok(self
            .lock()
            .query_row(
                "SELECT account FROM webauthn_users WHERE user_handle = ?1",
                params![handle],
                |row| row.get(0),
            )
            .optional()?)
    }

    /// Renames one of an account's passkeys; `None` when it has no such one.
    pub fn rename_credential(
        &self,
        account: &str,
        id: i64,
        name: &str,
    ) -> Result<Option<Credential>> {
        let conn = self.lock();
        let changed = conn.execute(
            "UPDATE webauthn_credentials SET name = ?3 WHERE account = ?1 AND id = ?2",
            params![account, id, name],
        )?;
        if changed == 0 {
            return Ok(None);
        }
        Ok(conn
            .query_row(
                &format!("SELECT {CREDENTIAL_COLUMNS} FROM webauthn_credentials WHERE id = ?1"),
                params![id],
                Credential::from_row,
            )
            .optional()?)
    }

    /// Removes one of an account's passkeys and returns its name. When it
    /// was the account's last second factor, the recovery codes go too.
    pub fn delete_credential(&self, account: &str, id: i64) -> Result<Option<String>> {
        let mut conn = self.lock();
        let tx = conn.transaction()?;
        let name: Option<String> = tx
            .query_row(
                "SELECT name FROM webauthn_credentials WHERE account = ?1 AND id = ?2",
                params![account, id],
                |row| row.get(0),
            )
            .optional()?;
        if name.is_some() {
            tx.execute(
                "DELETE FROM webauthn_credentials WHERE account = ?1 AND id = ?2",
                params![account, id],
            )?;
            drop_recovery_without_factor(&tx, account)?;
        }
        tx.commit()?;
        Ok(name)
    }

    /// Records a verified use of a passkey.
    pub fn touch_credential(
        &self,
        id: i64,
        sign_count: u32,
        backup_state: bool,
        uv: bool,
    ) -> Result<()> {
        self.lock().execute(
            &format!(
                "UPDATE webauthn_credentials SET sign_count = ?2, backup_state = ?3,
                     uv_initialized = CASE WHEN ?4 THEN 1 ELSE uv_initialized END,
                     last_used_at = {NOW}
                 WHERE id = ?1"
            ),
            params![id, i64::from(sign_count), backup_state, uv],
        )?;
        Ok(())
    }

    /// The account's confirmed authenticator-app secret, still encrypted.
    pub fn totp(&self, account: &str) -> Result<Option<TotpRow>> {
        Ok(self
            .lock()
            .query_row(
                "SELECT nonce, secret, confirmed_at FROM totp_secrets WHERE account = ?1",
                params![account],
                |row| {
                    Ok(TotpRow {
                        nonce: row.get(0)?,
                        secret: row.get(1)?,
                        confirmed_at: row.get(2)?,
                    })
                },
            )
            .optional()?)
    }

    /// Stores a confirmed secret, with the step of the confirming code as
    /// the last one used, so that code cannot sign in.
    pub fn set_totp(
        &self,
        account: &str,
        nonce: &[u8],
        secret: &[u8],
        last_step: i64,
    ) -> Result<()> {
        self.lock().execute(
            &format!(
                "INSERT INTO totp_secrets (account, nonce, secret, last_step, confirmed_at)
                 VALUES (?1, ?2, ?3, ?4, {NOW})
                 ON CONFLICT (account) DO UPDATE SET nonce = excluded.nonce,
                     secret = excluded.secret, last_step = excluded.last_step,
                     confirmed_at = excluded.confirmed_at"
            ),
            params![account, nonce, secret, last_step],
        )?;
        Ok(())
    }

    /// Accepts a time step only when it is later than every step used
    /// before: true when it was. Atomic, so one code never works twice,
    /// also under concurrent requests.
    pub fn advance_totp_step(&self, account: &str, step: i64) -> Result<bool> {
        Ok(self.lock().execute(
            "UPDATE totp_secrets SET last_step = ?2 WHERE account = ?1 AND last_step < ?2",
            params![account, step],
        )? == 1)
    }

    /// Removes the account's authenticator app; true when it had one. When
    /// it was the last second factor, the recovery codes go too.
    pub fn delete_totp(&self, account: &str) -> Result<bool> {
        let mut conn = self.lock();
        let tx = conn.transaction()?;
        let removed = tx.execute(
            "DELETE FROM totp_secrets WHERE account = ?1",
            params![account],
        )? > 0;
        if removed {
            drop_recovery_without_factor(&tx, account)?;
        }
        tx.commit()?;
        Ok(removed)
    }

    /// Replaces every recovery code of the account (used or not) with new
    /// hashes, in one transaction.
    pub fn replace_recovery_codes(&self, account: &str, hashes: &[String]) -> Result<()> {
        let mut conn = self.lock();
        let tx = conn.transaction()?;
        tx.execute(
            "DELETE FROM recovery_codes WHERE account = ?1",
            params![account],
        )?;
        for hash in hashes {
            tx.execute(
                &format!(
                    "INSERT INTO recovery_codes (account, code_hash, created_at) VALUES (?1, ?2, {NOW})"
                ),
                params![account, hash],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Uses one recovery code: `Some(codes left)` when it was unused and
    /// is now spent, `None` otherwise.
    pub fn use_recovery_code(&self, account: &str, hash: &str) -> Result<Option<i64>> {
        let conn = self.lock();
        let changed = conn.execute(
            &format!(
                "UPDATE recovery_codes SET used_at = {NOW}
                 WHERE account = ?1 AND code_hash = ?2 AND used_at IS NULL"
            ),
            params![account, hash],
        )?;
        if changed == 0 {
            return Ok(None);
        }
        Ok(Some(recovery_left(&conn, account)?))
    }

    /// Unused and total recovery codes of the account.
    pub fn recovery_remaining(&self, account: &str) -> Result<(i64, i64)> {
        let conn = self.lock();
        let total: i64 = conn.query_row(
            "SELECT COUNT(*) FROM recovery_codes WHERE account = ?1",
            params![account],
            |row| row.get(0),
        )?;
        Ok((recovery_left(&conn, account)?, total))
    }

    /// Removes every passkey, the authenticator app and the recovery codes
    /// of an account, in one transaction.
    pub fn reset_second_factors(&self, account: &str) -> Result<()> {
        let mut conn = self.lock();
        let tx = conn.transaction()?;
        delete_second_factors(&tx, account)?;
        tx.commit()?;
        Ok(())
    }

    /// Counts of the account's second factors (passkeys of every host).
    pub fn second_factor_summary(&self, account: &str) -> Result<SecondFactorSummary> {
        let conn = self.lock();
        let passkeys: i64 = conn.query_row(
            "SELECT COUNT(*) FROM webauthn_credentials WHERE account = ?1",
            params![account],
            |row| row.get(0),
        )?;
        let totp: bool = conn.query_row(
            "SELECT COUNT(*) > 0 FROM totp_secrets WHERE account = ?1",
            params![account],
            |row| row.get(0),
        )?;
        Ok(SecondFactorSummary {
            passkeys,
            totp,
            recovery_left: recovery_left(&conn, account)?,
        })
    }

    /// Notes one sign-in or credential event; keeps the newest rows only.
    /// `detail` must never hold a secret, a code or a password.
    pub fn record_auth_event(
        &self,
        account: &str,
        actor: &str,
        event: &str,
        ip: &str,
        detail: &str,
    ) -> Result<()> {
        let conn = self.lock();
        conn.execute(
            &format!(
                "INSERT INTO auth_events (created_at, account, actor, event, ip, detail)
                 VALUES ({NOW}, ?1, ?2, ?3, ?4, ?5)"
            ),
            params![account, actor, event, ip, detail],
        )?;
        // Two budgets: what anyone can cause without an account (refused
        // attempts, limits, pending sign-ins) never pushes out what only a
        // signed-in or right-password action writes (sign-ins, break-glass,
        // password and second-step changes, resets).
        let noise = NOISE_EVENTS.contains(&event);
        let placeholders = NOISE_EVENTS
            .iter()
            .map(|kind| format!("'{kind}'"))
            .collect::<Vec<_>>()
            .join(", ");
        let filter = if noise { "IN" } else { "NOT IN" };
        conn.execute(
            &format!(
                "DELETE FROM auth_events WHERE event {filter} ({placeholders}) AND id < (
                     SELECT id FROM auth_events WHERE event {filter} ({placeholders})
                     ORDER BY id DESC LIMIT 1 OFFSET ?1)"
            ),
            params![AUTH_EVENTS_KEPT - 1],
        )?;
        Ok(())
    }

    /// The newest events, of one account or (empty) of every account.
    pub fn auth_events(&self, account: Option<&str>, limit: i64) -> Result<Vec<AuthEvent>> {
        let conn = self.lock();
        let map = |row: &rusqlite::Row<'_>| {
            Ok(AuthEvent {
                id: row.get(0)?,
                created_at: row.get(1)?,
                account: row.get(2)?,
                actor: row.get(3)?,
                event: row.get(4)?,
                ip: row.get(5)?,
                detail: row.get(6)?,
            })
        };
        let columns = "id, created_at, account, actor, event, ip, detail";
        let rows = match account {
            Some(account) => {
                let mut stmt = conn.prepare(&format!(
                    "SELECT {columns} FROM auth_events WHERE account = ?1 ORDER BY id DESC LIMIT ?2"
                ))?;
                stmt.query_map(params![account, limit], map)?
                    .collect::<rusqlite::Result<Vec<_>>>()?
            }
            None => {
                let mut stmt = conn.prepare(&format!(
                    "SELECT {columns} FROM auth_events ORDER BY id DESC LIMIT ?1"
                ))?;
                stmt.query_map(params![limit], map)?
                    .collect::<rusqlite::Result<Vec<_>>>()?
            }
        };
        Ok(rows)
    }
}

fn recovery_left(conn: &Connection, account: &str) -> Result<i64> {
    Ok(conn.query_row(
        "SELECT COUNT(*) FROM recovery_codes WHERE account = ?1 AND used_at IS NULL",
        params![account],
        |row| row.get(0),
    )?)
}

/// Recovery codes are a second factor only next to a passkey or an app:
/// without either, they go.
fn drop_recovery_without_factor(conn: &Connection, account: &str) -> Result<()> {
    let factors: i64 = conn.query_row(
        "SELECT (SELECT COUNT(*) FROM webauthn_credentials WHERE account = ?1)
              + (SELECT COUNT(*) FROM totp_secrets WHERE account = ?1)",
        params![account],
        |row| row.get(0),
    )?;
    if factors == 0 {
        conn.execute(
            "DELETE FROM recovery_codes WHERE account = ?1",
            params![account],
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{NewUser, Perms};

    fn temp_db(name: &str) -> (std::path::PathBuf, Db) {
        let dir = std::env::temp_dir().join(format!("lore-signin-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = Db::open(&dir.join("lore.db")).unwrap();
        (dir, db)
    }

    fn credential(account: &str, raw: &[u8]) -> NewCredential {
        NewCredential {
            account: account.into(),
            credential_id: raw.to_vec(),
            rp_id: "example.org".into(),
            public_key: vec![1, 2, 3],
            alg: -7,
            sign_count: 0,
            uv_initialized: true,
            backup_eligible: false,
            backup_state: false,
            discoverable: Some(true),
            transports: vec!["internal".into()],
            aaguid: vec![0; 16],
            attestation_fmt: "none".into(),
            name: "laptop".into(),
        }
    }

    #[test]
    fn totp_steps_only_move_forward() {
        let (dir, db) = temp_db("totp");
        db.set_totp("admin", &[0; 24], &[1, 2], 100).unwrap();
        assert!(!db.advance_totp_step("admin", 100).unwrap());
        assert!(!db.advance_totp_step("admin", 99).unwrap());
        assert!(db.advance_totp_step("admin", 101).unwrap());
        assert!(!db.advance_totp_step("admin", 101).unwrap());
        assert!(!db.advance_totp_step("viewer", 500).unwrap());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn recovery_codes_are_single_use_and_follow_the_factors() {
        let (dir, db) = temp_db("recovery");
        db.add_credential(&credential("admin", &[7; 16])).unwrap();
        db.replace_recovery_codes("admin", &["a".into(), "b".into()])
            .unwrap();
        assert_eq!(db.recovery_remaining("admin").unwrap(), (2, 2));
        assert_eq!(db.use_recovery_code("admin", "a").unwrap(), Some(1));
        assert_eq!(db.use_recovery_code("admin", "a").unwrap(), None);
        assert_eq!(db.use_recovery_code("viewer", "b").unwrap(), None);
        db.replace_recovery_codes("admin", &["c".into()]).unwrap();
        assert_eq!(db.use_recovery_code("admin", "b").unwrap(), None);
        assert_eq!(db.recovery_remaining("admin").unwrap(), (1, 1));
        // The last passkey goes, and the codes with it.
        let id = db.credentials("admin").unwrap()[0].id;
        assert_eq!(
            db.delete_credential("admin", id).unwrap().as_deref(),
            Some("laptop")
        );
        assert_eq!(db.recovery_remaining("admin").unwrap(), (0, 0));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn deleting_a_user_removes_their_sign_in_rows_and_keeps_others() {
        let (dir, db) = temp_db("delete");
        let user = db
            .add_user(&NewUser {
                username: "luis".into(),
                email: None,
                password_hash: "x".into(),
                permissions: Perms::none(),
                created_by: "admin".into(),
            })
            .unwrap();
        let account = user_account(user.id);
        db.webauthn_user_handle(&account).unwrap();
        db.add_credential(&credential(&account, &[1; 16])).unwrap();
        db.add_credential(&credential("admin", &[2; 16])).unwrap();
        db.set_totp(&account, &[0; 24], &[1], 1).unwrap();
        db.replace_recovery_codes(&account, &["h".into()]).unwrap();
        assert!(db.credential_by_id(&[1; 16]).unwrap().is_some());
        db.delete_user(user.id).unwrap();
        assert!(db.credentials(&account).unwrap().is_empty());
        assert!(db.totp(&account).unwrap().is_none());
        assert_eq!(db.recovery_remaining(&account).unwrap(), (0, 0));
        assert!(db.existing_user_handle(&account).unwrap().is_none());
        assert_eq!(db.credentials("admin").unwrap().len(), 1);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn rows_of_a_user_deleted_elsewhere_are_ignored() {
        let (dir, db) = temp_db("orphan");
        // As an older binary leaves them: a credential of a user that is gone.
        db.add_credential(&credential("user:999", &[3; 16]))
            .unwrap();
        assert!(db.credential_by_id(&[3; 16]).unwrap().is_none());
        assert!(db.credential_id_taken(&[3; 16]).unwrap());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn noise_never_pushes_out_the_events_that_matter() {
        let (dir, db) = temp_db("noise");
        db.record_auth_event("admin", "admin", "signin.break_glass", "1.2.3.4", "")
            .unwrap();
        for _ in 0..(AUTH_EVENTS_KEPT + 50) {
            db.record_auth_event("", "", "signin.fail.passkey", "5.6.7.8", "x")
                .unwrap();
        }
        let all = db.auth_events(None, 20_000).unwrap();
        assert!(all.iter().any(|event| event.event == "signin.break_glass"));
        let noise = all
            .iter()
            .filter(|e| e.event == "signin.fail.passkey")
            .count();
        assert_eq!(noise as i64, AUTH_EVENTS_KEPT);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn the_sign_in_log_keeps_the_newest_rows() {
        let (dir, db) = temp_db("events");
        for n in 0..(AUTH_EVENTS_KEPT + 5) {
            db.record_auth_event("admin", "admin", "signin.ok", "127.0.0.1", &n.to_string())
                .unwrap();
        }
        let count: i64 = db
            .lock()
            .query_row("SELECT COUNT(*) FROM auth_events", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, AUTH_EVENTS_KEPT);
        let newest = db.auth_events(Some("admin"), 1).unwrap();
        assert_eq!(newest[0].detail, (AUTH_EVENTS_KEPT + 4).to_string());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn builtin_passwords_are_set_and_cleared() {
        let (dir, db) = temp_db("builtin");
        assert!(db.builtin_password("admin").unwrap().is_none());
        db.set_builtin_password("admin", "$argon2id$x", "admin")
            .unwrap();
        assert_eq!(
            db.builtin_password("admin").unwrap().unwrap().password_hash,
            "$argon2id$x"
        );
        assert!(db.set_builtin_password("luis", "h", "admin").is_err());
        assert!(db.clear_builtin_password("admin").unwrap());
        assert!(!db.clear_builtin_password("admin").unwrap());
        let _ = std::fs::remove_dir_all(dir);
    }
    #[test]
    fn a_schema_9_database_gains_the_tables_and_keeps_its_rows() {
        let (dir, db) = temp_db("migrate");
        db.add_user(&NewUser {
            username: "kept".into(),
            email: None,
            password_hash: "x".into(),
            permissions: Perms::none(),
            created_by: "admin".into(),
        })
        .unwrap();
        {
            // What a schema-9 build leaves behind.
            let conn = db.lock();
            conn.execute_batch(
                "DROP TABLE builtin_passwords; DROP TABLE webauthn_users;
                 DROP TABLE webauthn_credentials; DROP TABLE totp_secrets;
                 DROP TABLE recovery_codes; DROP TABLE auth_events;",
            )
            .unwrap();
            super::super::set_meta(&conn, "schema_version", "9").unwrap();
        }
        let before = super::super::table_counts(&db.lock()).unwrap();
        drop(db);
        let db = Db::open(&dir.join("lore.db")).unwrap();
        let conn = db.lock();
        assert_eq!(
            super::super::schema_version(&conn).unwrap(),
            super::super::SCHEMA_VERSION
        );
        let after = super::super::table_counts(&conn).unwrap();
        for (table, count) in &before {
            assert!(after.contains(&(table.clone(), *count)), "{table} changed");
        }
        for table in [
            "builtin_passwords",
            "webauthn_users",
            "webauthn_credentials",
            "totp_secrets",
            "recovery_codes",
            "auth_events",
        ] {
            assert!(after.contains(&(table.to_string(), 0)), "{table} missing");
        }
        drop(conn);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn the_json_backup_holds_none_of_the_sign_in_tables() {
        let (dir, db) = temp_db("export");
        db.set_builtin_password("admin", "$argon2id$secret-hash", "admin")
            .unwrap();
        db.webauthn_user_handle("admin").unwrap();
        let mut new = credential("admin", &[0xab; 16]);
        new.public_key = b"public-key-bytes".to_vec();
        db.add_credential(&new).unwrap();
        db.set_totp("admin", &[9; 24], b"totp-ciphertext", 5)
            .unwrap();
        db.replace_recovery_codes("admin", &["recovery-hash-1".into()])
            .unwrap();
        db.record_auth_event("admin", "admin", "signin.ok", "10.1.2.3", "password")
            .unwrap();
        let json = serde_json::to_string(&db.export().unwrap()).unwrap();
        for needle in [
            "credential_id",
            "public_key",
            "public-key-bytes",
            "totp",
            "recovery",
            "auth_events",
            "signin.ok",
            "10.1.2.3",
            "password_hash",
            "argon2id",
            "user_handle",
        ] {
            assert!(!json.contains(needle), "the JSON backup holds {needle}");
        }
        let _ = std::fs::remove_dir_all(dir);
    }
}
