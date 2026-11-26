//! Signing in to the admin view: the permissions a user can hold, the rules
//! for user names, e-mail addresses and passwords, and password hashing.
//!
//! Two users are built in and never stored: `admin` (every permission,
//! `LORE_ADMIN_PASSWORD`) and `viewer` (reading only, `LORE_VIEWER_PASSWORD`).
//! Every other user lives in the `users` table with an Argon2id hash.

use std::sync::OnceLock;

use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
};

/// The built-in user with every permission.
pub const ADMIN_USER: &str = "admin";
/// The built-in watch-only user.
pub const VIEWER_USER: &str = "viewer";

pub const MIN_PASSWORD_CHARS: usize = 10;
pub const MAX_PASSWORD_CHARS: usize = 256;
const MAX_EMAIL_CHARS: usize = 254;

/// One thing a signed-in user may do beyond reading. Every signed-in user
/// reads what the viewer reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Perm {
    /// Add and change board tasks and messages, add and delete files.
    Write,
    /// Download backups.
    Backup,
    /// Restore backups.
    Restore,
    /// The profile and the rules.
    Settings,
    /// Service credentials, the per-agent service levels, the kill switch.
    Integrations,
    /// Manage the agents.
    Agents,
    /// Manage the users.
    Users,
}

impl Perm {
    pub const ALL: [Perm; 7] = [
        Perm::Write,
        Perm::Backup,
        Perm::Restore,
        Perm::Settings,
        Perm::Integrations,
        Perm::Agents,
        Perm::Users,
    ];

    pub fn id(self) -> &'static str {
        match self {
            Perm::Write => "write",
            Perm::Backup => "backup",
            Perm::Restore => "restore",
            Perm::Settings => "settings",
            Perm::Integrations => "integrations",
            Perm::Agents => "agents",
            Perm::Users => "users",
        }
    }

    /// One line for the page's permission checkboxes.
    pub fn explanation(self) -> &'static str {
        match self {
            Perm::Write => "Add and change board tasks and messages; add and delete project files.",
            Perm::Backup => "Download backups (JSON and the full database).",
            Perm::Restore => {
                "Import and restore backups (JSON and the full database), replacing what is here."
            }
            Perm::Settings => "Edit the profile and the rules every agent is told.",
            Perm::Integrations => {
                "Store, test and remove service credentials, set agent service levels and the kill switch."
            }
            Perm::Agents => "Manage the agents and their authorizations.",
            Perm::Users => "Add, change and delete users.",
        }
    }

    pub fn parse(id: &str) -> Option<Perm> {
        Perm::ALL.into_iter().find(|perm| perm.id() == id)
    }

    fn bit(self) -> u16 {
        1 << (self as u16)
    }
}

/// A set of permissions.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Perms(u16);

impl Perms {
    pub fn all() -> Self {
        Perm::ALL.into_iter().collect()
    }

    pub fn none() -> Self {
        Self(0)
    }

    pub fn contains(self, perm: Perm) -> bool {
        self.0 & perm.bit() != 0
    }

    pub fn is_all(self) -> bool {
        self == Self::all()
    }

    /// True when every permission here is also in `other`.
    pub fn is_subset_of(self, other: Self) -> bool {
        self.0 & !other.0 == 0
    }

    /// The permissions here that `other` lacks.
    pub fn without(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }

    pub fn ids(self) -> Vec<&'static str> {
        Perm::ALL
            .into_iter()
            .filter(|perm| self.contains(*perm))
            .map(Perm::id)
            .collect()
    }

    /// Reads ids, refusing any that is not known. Order and repeats do not
    /// matter.
    pub fn parse<S: AsRef<str>>(ids: &[S]) -> Result<Self, String> {
        let mut perms = Self::none();
        for id in ids {
            let id = id.as_ref().trim().to_lowercase();
            match Perm::parse(&id) {
                Some(perm) => perms.0 |= perm.bit(),
                None => {
                    return Err(format!(
                        "unknown permission \"{}\"; known: {}",
                        id.chars().take(40).collect::<String>(),
                        Perm::ALL.map(Perm::id).join(", ")
                    ));
                }
            }
        }
        Ok(perms)
    }

    /// Reads the JSON array stored in the `users` table. Unknown ids, which
    /// a newer build may have written, are skipped rather than granted.
    pub fn from_json(text: &str) -> Self {
        let ids: Vec<String> = serde_json::from_str(text).unwrap_or_default();
        ids.iter().filter_map(|id| Perm::parse(id)).collect()
    }

    pub fn to_json(self) -> String {
        serde_json::to_string(&self.ids()).unwrap_or_else(|_| "[]".into())
    }
}

impl FromIterator<Perm> for Perms {
    fn from_iter<I: IntoIterator<Item = Perm>>(iter: I) -> Self {
        Self(iter.into_iter().fold(0, |bits, perm| bits | perm.bit()))
    }
}

/// Lowercases and checks a user name: `[a-z0-9][a-z0-9._-]{1,31}`, and not
/// one of the built-in names.
pub fn normalize_username(name: &str) -> Result<String, String> {
    let name = name.trim().to_lowercase();
    let mut chars = name.chars();
    let first_ok = chars
        .next()
        .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
    let rest_ok = chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "._-".contains(c));
    if !first_ok || !rest_ok || !(2..=32).contains(&name.len()) {
        return Err(
            "the user name must be 2 to 32 characters of a-z, 0-9, dot, underscore or dash, \
             starting with a letter or digit"
                .into(),
        );
    }
    if name == ADMIN_USER || name == VIEWER_USER {
        return Err(format!("the user name \"{name}\" is reserved"));
    }
    Ok(name)
}

/// Lowercases and checks an optional e-mail address. Empty means none.
pub fn normalize_email(email: &str) -> Result<Option<String>, String> {
    let email = email.trim().to_lowercase();
    if email.is_empty() {
        return Ok(None);
    }
    let valid = email.chars().count() <= MAX_EMAIL_CHARS
        && !email.chars().any(|c| c.is_whitespace() || c.is_control())
        && email.split_once('@').is_some_and(|(local, domain)| {
            !local.is_empty() && !domain.is_empty() && !domain.contains('@')
        });
    if valid {
        Ok(Some(email))
    } else {
        Err("the e-mail address does not look like name@example.com".into())
    }
}

/// Checks a new password's length. The password itself never appears in
/// the message.
pub fn check_password(password: &str) -> Result<(), String> {
    let count = password.chars().count();
    if count < MIN_PASSWORD_CHARS {
        return Err(format!(
            "the password must be at least {MIN_PASSWORD_CHARS} characters"
        ));
    }
    if count > MAX_PASSWORD_CHARS {
        return Err(format!(
            "the password must be at most {MAX_PASSWORD_CHARS} characters"
        ));
    }
    Ok(())
}

/// An Argon2id hash (default parameters) as a PHC string, with a salt from
/// the OS random number generator. Slow on purpose: call it off the async
/// executor.
pub fn hash_password(password: &str) -> anyhow::Result<String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|error| anyhow::anyhow!("no randomness: {error}"))?;
    let salt = SaltString::encode_b64(&bytes)
        .map_err(|error| anyhow::anyhow!("encoding the salt failed: {error}"))?;
    Ok(Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|error| anyhow::anyhow!("hashing failed: {error}"))?
        .to_string())
}

/// Whether a password matches a stored PHC string. The comparison inside
/// is constant time. Slow on purpose: call it off the async executor.
pub fn verify_password(password: &str, hash: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

/// A hash no password is known for. A sign-in for a user that does not
/// exist is verified against it, so it takes as long as one that does and
/// user names cannot be told apart by timing.
pub fn dummy_hash() -> &'static str {
    static DUMMY: OnceLock<String> = OnceLock::new();
    DUMMY.get_or_init(|| {
        let mut bytes = [0u8; 32];
        let _ = getrandom::fill(&mut bytes);
        let password: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        hash_password(&password).unwrap_or_else(|_| {
            // Without randomness the salt is fixed; the hash still costs the
            // same to verify, which is all it is for.
            let salt = SaltString::encode_b64(b"lore-dummy-salt!").expect("a valid salt");
            Argon2::default()
                .hash_password(password.as_bytes(), &salt)
                .expect("hashing a fixed password")
                .to_string()
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permissions_round_trip_and_refuse_unknown_ids() {
        let perms = Perms::parse(&["Backup", "write", "write"]).unwrap();
        assert!(perms.contains(Perm::Write) && perms.contains(Perm::Backup));
        assert!(!perms.contains(Perm::Users));
        assert_eq!(perms.ids(), ["write", "backup"]);
        assert_eq!(Perms::from_json(&perms.to_json()), perms);
        assert!(Perms::parse(&["root"]).is_err());
        assert_eq!(Perms::from_json(r#"["write","future"]"#).ids(), ["write"]);
        assert_eq!(Perms::from_json("not json"), Perms::none());
        assert!(Perms::all().is_all());
        assert_eq!(Perms::all().ids().len(), 7);
    }

    #[test]
    fn user_names_are_checked() {
        assert_eq!(normalize_username(" Luis.E-2 ").unwrap(), "luis.e-2");
        for bad in [
            "",
            "a",
            "admin",
            "Viewer",
            "-lead",
            ".dot",
            "has space",
            "émile",
            "x@y",
            &"a".repeat(33),
        ] {
            assert!(normalize_username(bad).is_err(), "{bad:?} was accepted");
        }
        assert!(normalize_username(&"a".repeat(32)).is_ok());
    }

    #[test]
    fn emails_and_passwords_are_checked() {
        assert_eq!(normalize_email("").unwrap(), None);
        assert_eq!(
            normalize_email(" Me@Example.COM ").unwrap().as_deref(),
            Some("me@example.com")
        );
        for bad in ["me", "@example.com", "me@", "a b@c.d", "a@b@c"] {
            assert!(normalize_email(bad).is_err(), "{bad:?} was accepted");
        }
        assert!(check_password("short").is_err());
        assert!(check_password(&"x".repeat(10)).is_ok());
        assert!(check_password(&"x".repeat(257)).is_err());
    }

    #[test]
    fn hashes_verify_only_their_password() {
        let hash = hash_password("correct horse battery").unwrap();
        assert!(hash.starts_with("$argon2id$"));
        assert!(verify_password("correct horse battery", &hash));
        assert!(!verify_password("correct horse battery!", &hash));
        assert!(!verify_password("anything", "not a hash"));
        assert!(!verify_password("anything", dummy_hash()));
    }
}
