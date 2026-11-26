//! The credential vault: the key that encrypts service credentials, and
//! the wrapper a decrypted credential travels in. A credential is stored
//! only as ciphertext; a decrypted one is never printed, serialized or
//! logged — `Debug` for it says `[redacted]`.

use anyhow::{Context, Result, bail};
use chacha20poly1305::{
    Key, KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};

/// `LORE_VAULT_KEY`: exactly 64 hex characters, 32 bytes.
const KEY_HEX_CHARS: usize = 64;
/// An XChaCha20-Poly1305 nonce: 24 random bytes per write.
const NONCE_LEN: usize = 24;

/// A decrypted credential. It has no `Serialize` and a manual `Debug`; the
/// only way out is `expose`, for the one place that sends it upstream.
pub struct Secret(String);

impl Secret {
    /// Wraps a credential that was just decrypted.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "decryption builds one directly; only the tests spell one out"
        )
    )]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// The credential itself.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("[redacted]")
    }
}

/// The key the vault encrypts credentials with, from `LORE_VAULT_KEY`.
/// It is never printed and never serialized either.
#[derive(Clone)]
pub struct VaultKey([u8; 32]);

impl std::fmt::Debug for VaultKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("VaultKey([redacted])")
    }
}

impl VaultKey {
    /// Reads one env value: empty disables the vault (`None`); anything
    /// else must be exactly 64 hex characters. The error names the
    /// variable and how to generate a key, and never echoes the value.
    pub fn from_env_value(value: &str) -> Result<Option<Self>> {
        let value = value.trim();
        if value.is_empty() {
            return Ok(None);
        }
        Ok(Some(Self::parse(value)?))
    }

    /// 64 hex characters, parsed into 32 bytes.
    fn parse(value: &str) -> Result<Self> {
        if value.len() != KEY_HEX_CHARS || !value.chars().all(|c| c.is_ascii_hexdigit()) {
            bail!(
                "LORE_VAULT_KEY must be exactly 64 hex characters (32 bytes). \
                 Generate one with: openssl rand -hex 32"
            );
        }
        let mut key = [0u8; 32];
        for (index, slot) in key.iter_mut().enumerate() {
            let pair = &value[index * 2..index * 2 + 2];
            *slot = u8::from_str_radix(pair, 16)
                .with_context(|| "LORE_VAULT_KEY must be exactly 64 hex characters")?;
        }
        Ok(Self(key))
    }

    /// Encrypts one provider's credential: a fresh 24-byte nonce every
    /// write, and the provider id plus the server URL as associated data,
    /// so a row moved to another provider, or pointed at another server,
    /// no longer decrypts.
    pub fn encrypt(&self, provider: &str, base_url: &str, secret: &str) -> (Vec<u8>, Vec<u8>) {
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce).expect("reading the system random source");
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&self.0));
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: secret.as_bytes(),
                    aad: associated_data(provider, base_url).as_bytes(),
                },
            )
            .expect("encrypting a secret in memory cannot fail");
        (nonce.to_vec(), ciphertext)
    }

    /// Decrypts one provider's credential. A wrong key, a row moved to
    /// another provider or another server URL, or a damaged row fails with
    /// a clear error and never panics.
    pub fn decrypt(
        &self,
        provider: &str,
        base_url: &str,
        nonce: &[u8],
        ciphertext: &[u8],
    ) -> Result<Secret> {
        if nonce.len() != NONCE_LEN {
            bail!("the stored credential is damaged: its nonce has the wrong length");
        }
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&self.0));
        let plain = cipher
            .decrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad: associated_data(provider, base_url).as_bytes(),
                },
            )
            .map_err(|_| {
                anyhow::anyhow!(
                    "the stored credential could not be decrypted: it was written with a \
                     different LORE_VAULT_KEY, or for another provider or server URL"
                )
            })?;
        let text = String::from_utf8(plain)
            .map_err(|_| anyhow::anyhow!("the stored credential is not valid UTF-8"))?;
        Ok(Secret(text))
    }
}

/// The associated data a credential is sealed with: the provider id and
/// the server URL, so neither can be changed without the credential.
fn associated_data(provider: &str, base_url: &str) -> String {
    format!("{provider}\n{base_url}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key_from(hex: &str) -> VaultKey {
        VaultKey::from_env_value(hex).unwrap().unwrap()
    }

    #[test]
    fn the_key_is_parsed_from_the_environment_value() {
        // Empty input (blank counts) disables the vault.
        assert!(VaultKey::from_env_value("").unwrap().is_none());
        assert!(VaultKey::from_env_value("   ").unwrap().is_none());
        for bad in [
            "xyz",
            &"g".repeat(63),
            &"g".repeat(65),
            &"zz".repeat(32),
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg",
        ] {
            let error = VaultKey::from_env_value(bad).unwrap_err().to_string();
            assert!(error.contains("LORE_VAULT_KEY"), "{error}");
            assert!(error.contains("openssl rand -hex 32"), "{error}");
            // The value itself is never echoed back.
            assert!(!error.contains(bad), "the error echoed the key: {error}");
        }
        assert!(key_from(&"ab".repeat(32)).0.len() == 32);
    }

    #[test]
    fn secrets_round_trip_and_never_debug() {
        let key = key_from(&"ab".repeat(32));
        let (nonce, secret) = key.encrypt("github", "", "ghp_a-secret-token");
        assert_eq!(nonce.len(), 24);
        // A fresh nonce every write.
        let (other_nonce, _) = key.encrypt("github", "", "ghp_a-secret-token");
        assert_ne!(nonce, other_nonce);
        // The ciphertext is not the credential.
        assert_ne!(secret, b"ghp_a-secret-token".as_slice());

        let back = key.decrypt("github", "", &nonce, &secret).unwrap();
        assert_eq!(back.expose(), "ghp_a-secret-token");
        // Debug never shows the credential, or the key.
        assert_eq!(format!("{back:?}"), "[redacted]");
        assert_eq!(format!("{key:?}"), "VaultKey([redacted])");
    }

    #[test]
    fn a_wrong_key_or_provider_fails_cleanly() {
        let one = key_from(&"11".repeat(32));
        let two = key_from(&"22".repeat(32));
        let (nonce, secret) = one.encrypt("github", "", "ghp_a-secret-token");

        let error = two
            .decrypt("github", "", &nonce, &secret)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("different LORE_VAULT_KEY"),
            "unexpected error: {error}"
        );
        // A row moved to another provider no longer decrypts: the provider
        // id is the associated data.
        let error = one
            .decrypt("gitlab", "", &nonce, &secret)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("another provider"),
            "unexpected error: {error}"
        );
        // Damaged rows fail with a clear error and never panic.
        // Pointing the row at another server URL breaks it as well: the
        // URL is part of the associated data.
        let (nonce_at, sealed_at) = one.encrypt("gitlab", "https://git.example.com", "glpat-x1");
        assert_eq!(
            one.decrypt("gitlab", "https://git.example.com", &nonce_at, &sealed_at)
                .unwrap()
                .expose(),
            "glpat-x1"
        );
        let error = one
            .decrypt("gitlab", "https://attacker.example", &nonce_at, &sealed_at)
            .unwrap_err()
            .to_string();
        assert!(error.contains("server URL"), "unexpected error: {error}");
        let error = one
            .decrypt("github", "", &[], &secret)
            .unwrap_err()
            .to_string();
        assert!(error.contains("damaged"), "unexpected error: {error}");
        assert!(one.decrypt("github", "", &nonce, &[]).is_err());
        assert!(one.decrypt("github", "", &[0u8; 24], &secret).is_err());
    }
}
