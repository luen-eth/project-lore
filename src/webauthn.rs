//! A small WebAuthn relying-party verifier (Web Authentication Level 3,
//! §7.1 registration and §7.2 assertion), for passkeys and security keys.
//!
//! The profile is deliberately narrow: attestation conveyance `none` (any
//! `fmt` is accepted and only recorded; `attStmt` is never verified, which
//! L3 allows for self attestation and `none`), and the algorithms EdDSA
//! (-8), ES256 (-7) and RS256 (-257). Signatures are checked with `ring`,
//! CBOR is read with `ciborium`. Parsing never panics: every length is
//! checked and every size capped.

use base64::{
    Engine, alphabet,
    engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig},
};
use ciborium::Value;
use ring::signature;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// COSE algorithm ids lore accepts, in the order the options list them.
pub const ALG_EDDSA: i64 = -8;
pub const ALG_ES256: i64 = -7;
pub const ALG_RS256: i64 = -257;
pub const ALGORITHMS: [i64; 3] = [ALG_EDDSA, ALG_ES256, ALG_RS256];

/// Longest and shortest credential id accepted (L3 §5.1: at most 1023).
const MAX_CREDENTIAL_ID: usize = 1023;
const MIN_CREDENTIAL_ID: usize = 16;
/// Largest clientDataJSON accepted.
const MAX_CLIENT_DATA: usize = 4 * 1024;
/// Largest attestationObject accepted.
const MAX_ATTESTATION_OBJECT: usize = 16 * 1024;
/// Largest authenticatorData of an assertion accepted.
const MAX_AUTHENTICATOR_DATA: usize = 1024 + 37;
/// Largest signature accepted.
const MAX_SIGNATURE: usize = 1024;

const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;
const FLAG_BE: u8 = 0x08;
const FLAG_BS: u8 = 0x10;
const FLAG_AT: u8 = 0x40;
const FLAG_ED: u8 = 0x80;

/// The transports lore keeps from `getTransports()`.
const KNOWN_TRANSPORTS: &[&str] = &["usb", "nfc", "ble", "smart-card", "hybrid", "internal"];

/// base64url as browsers send it: no padding, padding tolerated.
const B64URL: GeneralPurpose = GeneralPurpose::new(
    &alphabet::URL_SAFE,
    GeneralPurposeConfig::new()
        .with_encode_padding(false)
        .with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

pub fn b64url_encode(bytes: &[u8]) -> String {
    B64URL.encode(bytes)
}

pub fn b64url_decode(text: &str) -> Option<Vec<u8>> {
    B64URL.decode(text).ok()
}

/// Why a ceremony was refused. The reason goes to the sign-in log, never
/// to the browser in detail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Malformed(&'static str),
    Type,
    Challenge,
    Origin,
    CrossOrigin,
    RpIdHash,
    UserPresence,
    UserVerification,
    BackupFlags,
    UnsupportedAlgorithm,
    CredentialId,
    Signature,
    CounterRegression,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Malformed(what) => write!(f, "malformed: {what}"),
            Error::Type => f.write_str("wrong clientData type"),
            Error::Challenge => f.write_str("wrong challenge"),
            Error::Origin => f.write_str("wrong origin"),
            Error::CrossOrigin => f.write_str("cross-origin or top-origin"),
            Error::RpIdHash => f.write_str("wrong relying party id"),
            Error::UserPresence => f.write_str("user presence missing"),
            Error::UserVerification => f.write_str("user verification missing"),
            Error::BackupFlags => f.write_str("inconsistent backup flags"),
            Error::UnsupportedAlgorithm => f.write_str("algorithm not accepted"),
            Error::CredentialId => f.write_str("credential id mismatch"),
            Error::Signature => f.write_str("bad signature"),
            Error::CounterRegression => f.write_str("signature counter went backwards"),
        }
    }
}

/// What a ceremony must match: the challenge the server issued, the origin
/// and relying-party id it was issued for, and whether user verification
/// is required.
#[derive(Debug, Clone, Copy)]
pub struct Expected<'a> {
    pub challenge: &'a [u8],
    pub origin: &'a str,
    pub rp_id: &'a str,
    pub user_verification: bool,
}

/// `RegistrationResponseJSON` as the page sends it.
#[derive(Deserialize, Debug, Clone)]
pub struct RegistrationJson {
    pub id: String,
    #[serde(rename = "rawId")]
    pub raw_id: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub response: RegistrationResponse,
    #[serde(default, rename = "clientExtensionResults")]
    pub extensions: serde_json::Value,
}

#[derive(Deserialize, Debug, Clone)]
pub struct RegistrationResponse {
    #[serde(rename = "clientDataJSON")]
    pub client_data: String,
    #[serde(rename = "attestationObject")]
    pub attestation_object: String,
    #[serde(default)]
    pub transports: Vec<String>,
}

/// `AuthenticationResponseJSON` as the page sends it.
#[derive(Deserialize, Debug, Clone)]
pub struct AssertionJson {
    pub id: String,
    #[serde(rename = "rawId")]
    pub raw_id: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub response: AssertionResponse,
}

#[derive(Deserialize, Debug, Clone)]
pub struct AssertionResponse {
    #[serde(rename = "clientDataJSON")]
    pub client_data: String,
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: String,
    pub signature: String,
    #[serde(default, rename = "userHandle")]
    pub user_handle: Option<String>,
}

/// A verified registration: the credential record to store.
#[derive(Debug, Clone)]
pub struct Registration {
    pub credential_id: Vec<u8>,
    /// The COSE_Key exactly as received.
    pub public_key: Vec<u8>,
    pub alg: i64,
    pub sign_count: u32,
    pub user_verified: bool,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub aaguid: Vec<u8>,
    pub fmt: String,
    /// `credProps.rk`, when the client reported it.
    pub discoverable: Option<bool>,
    pub transports: Vec<String>,
}

/// The stored credential an assertion is checked against.
#[derive(Debug, Clone, Copy)]
pub struct StoredCredential<'a> {
    pub public_key: &'a [u8],
    pub sign_count: u32,
    pub backup_eligible: bool,
}

/// A verified assertion: what to update in the record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Assertion {
    pub sign_count: u32,
    pub user_verified: bool,
    pub backup_state: bool,
}

/// The raw credential id of a response, checking that `id` is its
/// base64url form and that its length is acceptable.
pub fn raw_id(id: &str, raw_id: &str, kind: &str) -> Result<Vec<u8>, Error> {
    if kind != "public-key" {
        return Err(Error::Malformed("type is not public-key"));
    }
    let raw = b64url_decode(raw_id).ok_or(Error::Malformed("rawId is not base64url"))?;
    if !(MIN_CREDENTIAL_ID..=MAX_CREDENTIAL_ID).contains(&raw.len()) {
        return Err(Error::CredentialId);
    }
    if b64url_decode(id).as_deref() != Some(raw.as_slice()) {
        return Err(Error::CredentialId);
    }
    Ok(raw)
}

/// Checks clientDataJSON (L3 §7.1 steps 5–12, §7.2 steps 10–15) and
/// returns its SHA-256 hash.
fn check_client_data(
    encoded: &str,
    kind: &str,
    expected: &Expected<'_>,
) -> Result<[u8; 32], Error> {
    let bytes =
        b64url_decode(encoded).ok_or(Error::Malformed("clientDataJSON is not base64url"))?;
    if bytes.len() > MAX_CLIENT_DATA {
        return Err(Error::Malformed("clientDataJSON too large"));
    }
    let text = bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(&bytes);
    let data: serde_json::Value =
        serde_json::from_slice(text).map_err(|_| Error::Malformed("clientDataJSON is not JSON"))?;
    if data.get("type").and_then(|v| v.as_str()) != Some(kind) {
        return Err(Error::Type);
    }
    let challenge = data
        .get("challenge")
        .and_then(|v| v.as_str())
        .and_then(b64url_decode)
        .ok_or(Error::Challenge)?;
    if challenge.len() != expected.challenge.len()
        || !bool::from(challenge.ct_eq(expected.challenge))
    {
        return Err(Error::Challenge);
    }
    if data.get("origin").and_then(|v| v.as_str()) != Some(expected.origin) {
        return Err(Error::Origin);
    }
    match data.get("crossOrigin") {
        None | Some(serde_json::Value::Bool(false)) => {}
        Some(_) => return Err(Error::CrossOrigin),
    }
    if data.get("topOrigin").is_some() {
        return Err(Error::CrossOrigin);
    }
    Ok(Sha256::digest(&bytes).into())
}

/// The parts of authenticator data lore uses.
struct AuthData {
    flags: u8,
    sign_count: u32,
    /// For a registration: aaguid, credential id and the COSE key bytes.
    attested: Option<(Vec<u8>, Vec<u8>, Vec<u8>)>,
}

/// Decodes exactly one CBOR item from the start of `bytes`; returns it and
/// the bytes it took.
fn one_cbor_item(bytes: &[u8]) -> Result<(Value, usize), Error> {
    let mut cursor = std::io::Cursor::new(bytes);
    let value: Value =
        ciborium::de::from_reader(&mut cursor).map_err(|_| Error::Malformed("bad CBOR"))?;
    let used = usize::try_from(cursor.position()).map_err(|_| Error::Malformed("bad CBOR"))?;
    Ok((value, used))
}

/// Parses authenticator data (L3 §6.1): rpIdHash, flags, counter, attested
/// credential data when AT is set, extensions only when ED is set, and
/// nothing after.
fn parse_auth_data(bytes: &[u8], rp_id: &str) -> Result<AuthData, Error> {
    if bytes.len() < 37 {
        return Err(Error::Malformed("authenticator data too short"));
    }
    let rp_hash: [u8; 32] = Sha256::digest(rp_id.as_bytes()).into();
    if !bool::from(bytes[..32].ct_eq(&rp_hash)) {
        return Err(Error::RpIdHash);
    }
    let flags = bytes[32];
    let sign_count = u32::from_be_bytes([bytes[33], bytes[34], bytes[35], bytes[36]]);
    let mut rest = &bytes[37..];
    let mut attested = None;
    if flags & FLAG_AT != 0 {
        if rest.len() < 18 {
            return Err(Error::Malformed("attested credential data too short"));
        }
        let aaguid = rest[..16].to_vec();
        let id_len = usize::from(u16::from_be_bytes([rest[16], rest[17]]));
        if id_len > MAX_CREDENTIAL_ID {
            return Err(Error::CredentialId);
        }
        rest = &rest[18..];
        if rest.len() < id_len {
            return Err(Error::Malformed("credential id cut short"));
        }
        let credential_id = rest[..id_len].to_vec();
        rest = &rest[id_len..];
        let (_, used) = one_cbor_item(rest)?;
        let key = rest[..used].to_vec();
        rest = &rest[used..];
        attested = Some((aaguid, credential_id, key));
    }
    if flags & FLAG_ED != 0 {
        let (value, used) = one_cbor_item(rest)?;
        if !matches!(value, Value::Map(_)) || used != rest.len() {
            return Err(Error::Malformed("extension data is not one CBOR map"));
        }
    } else if !rest.is_empty() {
        return Err(Error::Malformed("trailing bytes after authenticator data"));
    }
    Ok(AuthData {
        flags,
        sign_count,
        attested,
    })
}

/// The flag checks every ceremony makes: UP set, UV when required, BS
/// only with BE.
fn check_flags(flags: u8, user_verification: bool) -> Result<(), Error> {
    if flags & FLAG_UP == 0 {
        return Err(Error::UserPresence);
    }
    if user_verification && flags & FLAG_UV == 0 {
        return Err(Error::UserVerification);
    }
    if flags & FLAG_BS != 0 && flags & FLAG_BE == 0 {
        return Err(Error::BackupFlags);
    }
    Ok(())
}

/// A public key ready for `ring`.
enum PublicKey {
    Ed25519(Vec<u8>),
    Es256(Vec<u8>),
    Rs256 { n: Vec<u8>, e: Vec<u8> },
}

fn int_of(value: &Value) -> Option<i128> {
    match value {
        Value::Integer(int) => Some(i128::from(*int)),
        _ => None,
    }
}

/// Reads a COSE_Key (RFC 9052/9053, RFC 8230) of one of the accepted
/// algorithms; returns its algorithm and key.
fn parse_cose_key(bytes: &[u8]) -> Result<(i64, PublicKey), Error> {
    let (value, used) = one_cbor_item(bytes)?;
    if used != bytes.len() {
        return Err(Error::Malformed("trailing bytes after the public key"));
    }
    let Value::Map(entries) = value else {
        return Err(Error::Malformed("the public key is not a map"));
    };
    let get = |label: i128| {
        entries
            .iter()
            .find(|(key, _)| int_of(key) == Some(label))
            .map(|(_, value)| value)
    };
    let int = |label: i128| get(label).and_then(int_of);
    let bytes_of = |label: i128| match get(label) {
        Some(Value::Bytes(bytes)) => Some(bytes.clone()),
        _ => None,
    };
    match (int(1), int(3)) {
        (Some(1), Some(-8)) => {
            let x = bytes_of(-2).filter(|x| x.len() == 32);
            match (int(-1), x) {
                (Some(6), Some(x)) => Ok((ALG_EDDSA, PublicKey::Ed25519(x))),
                _ => Err(Error::UnsupportedAlgorithm),
            }
        }
        (Some(2), Some(-7)) => {
            let x = bytes_of(-2).filter(|x| x.len() == 32);
            let y = bytes_of(-3).filter(|y| y.len() == 32);
            match (int(-1), x, y) {
                (Some(1), Some(x), Some(y)) => {
                    let mut point = Vec::with_capacity(65);
                    point.push(0x04);
                    point.extend_from_slice(&x);
                    point.extend_from_slice(&y);
                    Ok((ALG_ES256, PublicKey::Es256(point)))
                }
                _ => Err(Error::UnsupportedAlgorithm),
            }
        }
        (Some(3), Some(-257)) => {
            let n = bytes_of(-1).filter(|n| (256..=1024).contains(&n.len()));
            let e = bytes_of(-2).filter(|e| (1..=8).contains(&e.len()));
            match (n, e) {
                (Some(n), Some(e)) => Ok((ALG_RS256, PublicKey::Rs256 { n, e })),
                _ => Err(Error::UnsupportedAlgorithm),
            }
        }
        _ => Err(Error::UnsupportedAlgorithm),
    }
}

fn strip_leading_zeros(bytes: &[u8]) -> &[u8] {
    let first = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
    &bytes[first..]
}

fn verify_signature(key: &PublicKey, message: &[u8], sig: &[u8]) -> Result<(), Error> {
    let verified = match key {
        PublicKey::Ed25519(x) => {
            signature::UnparsedPublicKey::new(&signature::ED25519, x).verify(message, sig)
        }
        PublicKey::Es256(point) => {
            signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, point)
                .verify(message, sig)
        }
        PublicKey::Rs256 { n, e } => signature::RsaPublicKeyComponents {
            n: strip_leading_zeros(n),
            e: strip_leading_zeros(e),
        }
        .verify(&signature::RSA_PKCS1_2048_8192_SHA256, message, sig),
    };
    verified.map_err(|_| Error::Signature)
}

/// Verifies a registration (L3 §7.1, attestation `none` profile). The
/// caller has already matched the ceremony and still checks that the
/// credential id is not registered yet.
pub fn verify_registration(
    response: &RegistrationJson,
    expected: &Expected<'_>,
) -> Result<Registration, Error> {
    let raw = raw_id(&response.id, &response.raw_id, &response.kind)?;
    check_client_data(&response.response.client_data, "webauthn.create", expected)?;
    let object = b64url_decode(&response.response.attestation_object)
        .ok_or(Error::Malformed("attestationObject is not base64url"))?;
    if object.len() > MAX_ATTESTATION_OBJECT {
        return Err(Error::Malformed("attestationObject too large"));
    }
    let (value, used) = one_cbor_item(&object)?;
    if used != object.len() {
        return Err(Error::Malformed(
            "trailing bytes after the attestationObject",
        ));
    }
    let Value::Map(entries) = value else {
        return Err(Error::Malformed("attestationObject is not a map"));
    };
    let field = |name: &str| {
        entries
            .iter()
            .find(|(key, _)| matches!(key, Value::Text(text) if text == name))
            .map(|(_, value)| value)
    };
    let fmt = match field("fmt") {
        Some(Value::Text(fmt)) if fmt.len() <= 32 => fmt.clone(),
        _ => return Err(Error::Malformed("fmt missing")),
    };
    if !matches!(field("attStmt"), Some(Value::Map(_))) {
        return Err(Error::Malformed("attStmt missing"));
    }
    let Some(Value::Bytes(auth_data)) = field("authData") else {
        return Err(Error::Malformed("authData missing"));
    };
    let parsed = parse_auth_data(auth_data, expected.rp_id)?;
    check_flags(parsed.flags, expected.user_verification)?;
    let Some((aaguid, credential_id, public_key)) = parsed.attested else {
        return Err(Error::Malformed("no attested credential data"));
    };
    if credential_id != raw {
        return Err(Error::CredentialId);
    }
    let (alg, _) = parse_cose_key(&public_key)?;
    let discoverable = response
        .extensions
        .get("credProps")
        .and_then(|props| props.get("rk"))
        .and_then(serde_json::Value::as_bool);
    let mut transports: Vec<String> = response
        .response
        .transports
        .iter()
        .filter(|t| KNOWN_TRANSPORTS.contains(&t.as_str()))
        .cloned()
        .collect();
    transports.sort();
    transports.dedup();
    Ok(Registration {
        credential_id,
        public_key,
        alg,
        sign_count: parsed.sign_count,
        user_verified: parsed.flags & FLAG_UV != 0,
        backup_eligible: parsed.flags & FLAG_BE != 0,
        backup_state: parsed.flags & FLAG_BS != 0,
        aaguid,
        fmt,
        discoverable,
        transports,
    })
}

/// Verifies an assertion against its stored credential (L3 §7.2, steps 10
/// on). The caller has matched the ceremony, the credential and the user
/// handle.
pub fn verify_assertion(
    response: &AssertionJson,
    expected: &Expected<'_>,
    stored: &StoredCredential<'_>,
) -> Result<Assertion, Error> {
    raw_id(&response.id, &response.raw_id, &response.kind)?;
    let client_hash = check_client_data(&response.response.client_data, "webauthn.get", expected)?;
    let auth_data = b64url_decode(&response.response.authenticator_data)
        .ok_or(Error::Malformed("authenticatorData is not base64url"))?;
    if auth_data.len() > MAX_AUTHENTICATOR_DATA {
        return Err(Error::Malformed("authenticatorData too large"));
    }
    let parsed = parse_auth_data(&auth_data, expected.rp_id)?;
    if parsed.attested.is_some() {
        return Err(Error::Malformed("attested data in an assertion"));
    }
    check_flags(parsed.flags, expected.user_verification)?;
    if (parsed.flags & FLAG_BE != 0) != stored.backup_eligible {
        return Err(Error::BackupFlags);
    }
    let sig = b64url_decode(&response.response.signature)
        .ok_or(Error::Malformed("signature is not base64url"))?;
    if sig.is_empty() || sig.len() > MAX_SIGNATURE {
        return Err(Error::Malformed("signature size"));
    }
    let (_, key) = parse_cose_key(stored.public_key)?;
    let mut message = auth_data.clone();
    message.extend_from_slice(&client_hash);
    verify_signature(&key, &message, &sig)?;
    if (parsed.sign_count != 0 || stored.sign_count != 0) && parsed.sign_count <= stored.sign_count
    {
        return Err(Error::CounterRegression);
    }
    Ok(Assertion {
        sign_count: parsed.sign_count,
        user_verified: parsed.flags & FLAG_UV != 0,
        backup_state: parsed.flags & FLAG_BS != 0,
    })
}

/// The user handle of an assertion, when the authenticator returned one.
pub fn user_handle(response: &AssertionJson) -> Result<Option<Vec<u8>>, Error> {
    match response.response.user_handle.as_deref() {
        None | Some("") => Ok(None),
        Some(text) => b64url_decode(text)
            .filter(|handle| handle.len() <= 64)
            .map(Some)
            .ok_or(Error::Malformed("userHandle is not base64url")),
    }
}

/// A software authenticator for the tests: ES256 or Ed25519 keys from
/// `ring`, `none` attestation, chosen flags and counter. It answers like a
/// browser does, with the JSON the page sends.
#[cfg(test)]
pub mod soft {
    use super::*;
    use ring::{
        rand::SystemRandom,
        signature::{EcdsaKeyPair, Ed25519KeyPair, KeyPair},
    };

    pub enum Key {
        Es256(EcdsaKeyPair),
        Ed25519(Ed25519KeyPair),
    }

    #[derive(Clone, Copy, Debug)]
    pub struct Flags {
        pub up: bool,
        pub uv: bool,
        pub be: bool,
        pub bs: bool,
    }

    impl Flags {
        pub const UP_UV: Flags = Flags {
            up: true,
            uv: true,
            be: false,
            bs: false,
        };
        pub const UP: Flags = Flags {
            up: true,
            uv: false,
            be: false,
            bs: false,
        };

        pub fn byte(self) -> u8 {
            (u8::from(self.up) * FLAG_UP)
                | (u8::from(self.uv) * FLAG_UV)
                | (u8::from(self.be) * FLAG_BE)
                | (u8::from(self.bs) * FLAG_BS)
        }
    }

    pub struct Authenticator {
        pub key: Key,
        pub credential_id: Vec<u8>,
        pub counter: u32,
        /// The user handle a discoverable credential returns.
        pub user_handle: Option<Vec<u8>>,
    }

    impl Authenticator {
        pub fn es256() -> Self {
            let rng = SystemRandom::new();
            let pkcs8 =
                EcdsaKeyPair::generate_pkcs8(&signature::ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
                    .unwrap();
            let key = EcdsaKeyPair::from_pkcs8(
                &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
                pkcs8.as_ref(),
                &rng,
            )
            .unwrap();
            Self::with_key(Key::Es256(key))
        }

        pub fn ed25519() -> Self {
            let rng = SystemRandom::new();
            let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
            Self::with_key(Key::Ed25519(
                Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap(),
            ))
        }

        fn with_key(key: Key) -> Self {
            let mut credential_id = vec![0u8; 32];
            getrandom::fill(&mut credential_id).unwrap();
            Self {
                key,
                credential_id,
                counter: 0,
                user_handle: None,
            }
        }

        pub fn cose_key(&self) -> Vec<u8> {
            let int = |n: i64| Value::Integer(n.into());
            let map = match &self.key {
                Key::Es256(key) => {
                    let point = key.public_key().as_ref();
                    vec![
                        (int(1), int(2)),
                        (int(3), int(-7)),
                        (int(-1), int(1)),
                        (int(-2), Value::Bytes(point[1..33].to_vec())),
                        (int(-3), Value::Bytes(point[33..65].to_vec())),
                    ]
                }
                Key::Ed25519(key) => vec![
                    (int(1), int(1)),
                    (int(3), int(-8)),
                    (int(-1), int(6)),
                    (int(-2), Value::Bytes(key.public_key().as_ref().to_vec())),
                ],
            };
            let mut out = Vec::new();
            ciborium::ser::into_writer(&Value::Map(map), &mut out).unwrap();
            out
        }

        pub fn sign(&self, message: &[u8]) -> Vec<u8> {
            match &self.key {
                Key::Es256(key) => key
                    .sign(&SystemRandom::new(), message)
                    .unwrap()
                    .as_ref()
                    .to_vec(),
                Key::Ed25519(key) => key.sign(message).as_ref().to_vec(),
            }
        }

        pub fn client_data(kind: &str, challenge: &[u8], origin: &str) -> Vec<u8> {
            serde_json::json!({
                "type": kind,
                "challenge": b64url_encode(challenge),
                "origin": origin,
                "crossOrigin": false,
            })
            .to_string()
            .into_bytes()
        }

        pub fn auth_data(&self, rp_id: &str, flags: u8, counter: u32, attested: bool) -> Vec<u8> {
            let mut data = Sha256::digest(rp_id.as_bytes()).to_vec();
            data.push(flags | if attested { FLAG_AT } else { 0 });
            data.extend_from_slice(&counter.to_be_bytes());
            if attested {
                data.extend_from_slice(&[0u8; 16]);
                data.extend_from_slice(&(self.credential_id.len() as u16).to_be_bytes());
                data.extend_from_slice(&self.credential_id);
                data.extend_from_slice(&self.cose_key());
            }
            data
        }

        /// `RegistrationResponseJSON` for a creation request.
        pub fn register(
            &self,
            challenge: &[u8],
            origin: &str,
            rp_id: &str,
            flags: Flags,
        ) -> serde_json::Value {
            let client_data = Self::client_data("webauthn.create", challenge, origin);
            let auth_data = self.auth_data(rp_id, flags.byte(), self.counter, true);
            Self::registration_json(&self.credential_id, &client_data, &auth_data)
        }

        pub fn registration_json(
            credential_id: &[u8],
            client_data: &[u8],
            auth_data: &[u8],
        ) -> serde_json::Value {
            let object = Value::Map(vec![
                (Value::Text("fmt".into()), Value::Text("none".into())),
                (Value::Text("attStmt".into()), Value::Map(vec![])),
                (
                    Value::Text("authData".into()),
                    Value::Bytes(auth_data.to_vec()),
                ),
            ]);
            let mut encoded = Vec::new();
            ciborium::ser::into_writer(&object, &mut encoded).unwrap();
            serde_json::json!({
                "id": b64url_encode(credential_id),
                "rawId": b64url_encode(credential_id),
                "type": "public-key",
                "authenticatorAttachment": "platform",
                "response": {
                    "clientDataJSON": b64url_encode(client_data),
                    "attestationObject": b64url_encode(&encoded),
                    "transports": ["internal"],
                },
                "clientExtensionResults": { "credProps": { "rk": true } },
            })
        }

        /// `AuthenticationResponseJSON` for a request; the counter goes up
        /// first unless it is held at 0 (as synced passkeys do).
        pub fn assert(
            &mut self,
            challenge: &[u8],
            origin: &str,
            rp_id: &str,
            flags: Flags,
        ) -> serde_json::Value {
            if self.counter != 0 {
                self.counter += 1;
            }
            let client_data = Self::client_data("webauthn.get", challenge, origin);
            let auth_data = self.auth_data(rp_id, flags.byte(), self.counter, false);
            self.assertion_json(&client_data, &auth_data)
        }

        /// Signs and wraps chosen client data and authenticator data.
        pub fn assertion_json(&self, client_data: &[u8], auth_data: &[u8]) -> serde_json::Value {
            let mut message = auth_data.to_vec();
            message.extend_from_slice(&Sha256::digest(client_data));
            let signature = self.sign(&message);
            serde_json::json!({
                "id": b64url_encode(&self.credential_id),
                "rawId": b64url_encode(&self.credential_id),
                "type": "public-key",
                "response": {
                    "clientDataJSON": b64url_encode(client_data),
                    "authenticatorData": b64url_encode(auth_data),
                    "signature": b64url_encode(&signature),
                    "userHandle": self.user_handle.as_deref().map(b64url_encode),
                },
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::soft::{Authenticator, Flags};
    use super::*;

    const RP_ID: &str = "example.org";
    const ORIGIN: &str = "https://example.org";
    const VECTORS: &str = include_str!("testdata/webauthn-l3-vectors.json");

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    fn vector(name: &str, part: &str, field: &str) -> Vec<u8> {
        let all: serde_json::Value = serde_json::from_str(VECTORS).unwrap();
        hex(all[name][part][field]
            .as_str()
            .unwrap_or_else(|| panic!("{name}.{part}.{field}")))
    }

    fn expected(challenge: &[u8], uv: bool) -> Expected<'_> {
        Expected {
            challenge,
            origin: ORIGIN,
            rp_id: RP_ID,
            user_verification: uv,
        }
    }

    fn registration_of(name: &str) -> RegistrationJson {
        let id = vector(name, "reg", "credential_id");
        serde_json::from_value(serde_json::json!({
            "id": b64url_encode(&id),
            "rawId": b64url_encode(&id),
            "type": "public-key",
            "response": {
                "clientDataJSON": b64url_encode(&vector(name, "reg", "clientDataJSON")),
                "attestationObject": b64url_encode(&vector(name, "reg", "attestationObject")),
            },
            "clientExtensionResults": {},
        }))
        .unwrap()
    }

    fn assertion_of(name: &str) -> AssertionJson {
        let id = vector(name, "reg", "credential_id");
        serde_json::from_value(serde_json::json!({
            "id": b64url_encode(&id),
            "rawId": b64url_encode(&id),
            "type": "public-key",
            "response": {
                "clientDataJSON": b64url_encode(&vector(name, "auth", "clientDataJSON")),
                "authenticatorData": b64url_encode(&vector(name, "auth", "authenticatorData")),
                "signature": b64url_encode(&vector(name, "auth", "signature")),
            },
        }))
        .unwrap()
    }

    /// Registers and authenticates with a published vector.
    fn round_trip(name: &str) -> Result<(Registration, Assertion), Error> {
        let reg_challenge = vector(name, "reg", "challenge");
        let registration =
            verify_registration(&registration_of(name), &expected(&reg_challenge, false))?;
        let auth_challenge = vector(name, "auth", "challenge");
        let assertion = verify_assertion(
            &assertion_of(name),
            &expected(&auth_challenge, false),
            &StoredCredential {
                public_key: &registration.public_key,
                sign_count: registration.sign_count,
                backup_eligible: registration.backup_eligible,
            },
        )?;
        Ok((registration, assertion))
    }

    #[test]
    fn the_l3_vectors_lore_supports_register_and_authenticate() {
        for (name, alg, fmt) in [
            ("none-es256", ALG_ES256, "none"),
            ("packed-self-es256", ALG_ES256, "packed"),
            ("packed-es256", ALG_ES256, "packed"),
            ("none-es256-long-credential-id", ALG_ES256, "none"),
            ("packed-rs256", ALG_RS256, "packed"),
            ("packed-eddsa", ALG_EDDSA, "packed"),
        ] {
            let (registration, _) = round_trip(name).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(registration.alg, alg, "{name}");
            assert_eq!(registration.fmt, fmt, "{name}");
            assert_eq!(registration.aaguid, vector(name, "reg", "aaguid"), "{name}");
        }
        let (long, _) = round_trip("none-es256-long-credential-id").unwrap();
        assert_eq!(long.credential_id.len(), 1023);
    }

    #[test]
    fn the_l3_vectors_lore_refuses_are_refused() {
        // crossOrigin: true and topOrigin, in registration and assertion.
        for name in ["none-es256-crossOrigin", "none-es256-topOrigin"] {
            let challenge = vector(name, "reg", "challenge");
            assert_eq!(
                verify_registration(&registration_of(name), &expected(&challenge, false))
                    .unwrap_err(),
                Error::CrossOrigin,
                "{name}"
            );
        }
        // Algorithms lore does not offer: ES384, ES512, Ed448.
        for name in ["packed-es384", "packed-es512", "packed-ed448"] {
            let challenge = vector(name, "reg", "challenge");
            assert_eq!(
                verify_registration(&registration_of(name), &expected(&challenge, false))
                    .unwrap_err(),
                Error::UnsupportedAlgorithm,
                "{name}"
            );
        }
    }

    #[test]
    fn a_mutated_l3_vector_is_refused() {
        let name = "none-es256";
        let reg_challenge = vector(name, "reg", "challenge");
        let registration =
            verify_registration(&registration_of(name), &expected(&reg_challenge, false)).unwrap();
        let challenge = vector(name, "auth", "challenge");
        let stored = StoredCredential {
            public_key: &registration.public_key,
            sign_count: 0,
            backup_eligible: registration.backup_eligible,
        };
        let check =
            |assertion: &AssertionJson, expected: &Expected<'_>, stored: &StoredCredential<'_>| {
                verify_assertion(assertion, expected, stored)
            };
        let good = assertion_of(name);
        assert!(check(&good, &expected(&challenge, false), &stored).is_ok());
        // Another challenge, origin or relying party.
        let mut wrong = challenge.clone();
        wrong[0] ^= 1;
        assert_eq!(
            check(&good, &expected(&wrong, false), &stored).unwrap_err(),
            Error::Challenge
        );
        let other_origin = Expected {
            origin: "https://example.com",
            ..expected(&challenge, false)
        };
        assert_eq!(
            check(&good, &other_origin, &stored).unwrap_err(),
            Error::Origin
        );
        let other_rp = Expected {
            rp_id: "example.com",
            ..expected(&challenge, false)
        };
        assert_eq!(
            check(&good, &other_rp, &stored).unwrap_err(),
            Error::RpIdHash
        );
        // UV required but not given (this vector's flags have no UV).
        let flags = vector(name, "auth", "authenticatorData")[32];
        assert_eq!(flags & FLAG_UV, 0);
        assert_eq!(
            check(&good, &expected(&challenge, true), &stored).unwrap_err(),
            Error::UserVerification
        );
        // The backup-eligible flag cannot change.
        let flipped = StoredCredential {
            backup_eligible: !stored.backup_eligible,
            ..stored
        };
        assert_eq!(
            check(&good, &expected(&challenge, false), &flipped).unwrap_err(),
            Error::BackupFlags
        );
        // One bit of the signature.
        let mut bad_sig = good.clone();
        let mut sig = b64url_decode(&bad_sig.response.signature).unwrap();
        let last = sig.len() - 1;
        sig[last] ^= 1;
        bad_sig.response.signature = b64url_encode(&sig);
        assert!(check(&bad_sig, &expected(&challenge, false), &stored).is_err());
        // A trailing byte after the authenticator data, without ED.
        let mut trailing = good.clone();
        let mut data = b64url_decode(&trailing.response.authenticator_data).unwrap();
        data.push(0);
        trailing.response.authenticator_data = b64url_encode(&data);
        assert!(matches!(
            check(&trailing, &expected(&challenge, false), &stored).unwrap_err(),
            Error::Malformed(_)
        ));
        // id and rawId disagree.
        let mut mismatch = good.clone();
        mismatch.id = b64url_encode(&[1u8; 32]);
        assert_eq!(
            check(&mismatch, &expected(&challenge, false), &stored).unwrap_err(),
            Error::CredentialId
        );
        // A registration answered with clientData of type webauthn.get.
        let mut swapped = registration_of(name);
        swapped.response.client_data = good.response.client_data.clone();
        assert_eq!(
            verify_registration(&swapped, &expected(&challenge, false)).unwrap_err(),
            Error::Type
        );
    }

    #[test]
    fn the_software_authenticator_passes_and_every_tampering_fails() {
        for mut device in [Authenticator::es256(), Authenticator::ed25519()] {
            let challenge = [7u8; 32];
            let response: RegistrationJson =
                serde_json::from_value(device.register(&challenge, ORIGIN, RP_ID, Flags::UP_UV))
                    .unwrap();
            let registration = verify_registration(&response, &expected(&challenge, true)).unwrap();
            assert_eq!(registration.discoverable, Some(true));
            assert_eq!(registration.transports, ["internal"]);
            assert!(registration.user_verified);
            device.counter = 5;
            let stored = StoredCredential {
                public_key: &registration.public_key,
                sign_count: 5,
                backup_eligible: false,
            };
            let challenge = [9u8; 32];
            let ok: AssertionJson =
                serde_json::from_value(device.assert(&challenge, ORIGIN, RP_ID, Flags::UP_UV))
                    .unwrap();
            let assertion = verify_assertion(&ok, &expected(&challenge, true), &stored).unwrap();
            assert_eq!(assertion.sign_count, 6);
            // The counter going backwards (a cloned key) is refused.
            let stored_later = StoredCredential {
                sign_count: 6,
                ..stored
            };
            assert_eq!(
                verify_assertion(&ok, &expected(&challenge, true), &stored_later).unwrap_err(),
                Error::CounterRegression
            );
            // User presence cleared.
            let no_up = Flags {
                up: false,
                ..Flags::UP_UV
            };
            let client_data = Authenticator::client_data("webauthn.get", &challenge, ORIGIN);
            let auth_data = device.auth_data(RP_ID, no_up.byte(), 9, false);
            let response: AssertionJson =
                serde_json::from_value(device.assertion_json(&client_data, &auth_data)).unwrap();
            assert_eq!(
                verify_assertion(&response, &expected(&challenge, false), &stored).unwrap_err(),
                Error::UserPresence
            );
            // BS without BE.
            let bs_only = Flags {
                bs: true,
                ..Flags::UP_UV
            };
            let auth_data = device.auth_data(RP_ID, bs_only.byte(), 10, false);
            let response: AssertionJson =
                serde_json::from_value(device.assertion_json(&client_data, &auth_data)).unwrap();
            assert_eq!(
                verify_assertion(&response, &expected(&challenge, false), &stored).unwrap_err(),
                Error::BackupFlags
            );
            // Signed by another key.
            let other = Authenticator::es256();
            let auth_data = device.auth_data(RP_ID, Flags::UP_UV.byte(), 11, false);
            let mut forged: AssertionJson =
                serde_json::from_value(other.assertion_json(&client_data, &auth_data)).unwrap();
            forged.id = ok.id.clone();
            forged.raw_id = ok.raw_id.clone();
            assert_eq!(
                verify_assertion(&forged, &expected(&challenge, false), &stored).unwrap_err(),
                Error::Signature
            );
        }
    }

    #[test]
    fn synced_passkeys_with_a_zero_counter_pass() {
        let mut device = Authenticator::es256();
        let challenge = [1u8; 32];
        let flags = Flags {
            be: true,
            bs: true,
            ..Flags::UP_UV
        };
        let response: RegistrationJson =
            serde_json::from_value(device.register(&challenge, ORIGIN, RP_ID, flags)).unwrap();
        let registration = verify_registration(&response, &expected(&challenge, true)).unwrap();
        assert!(registration.backup_eligible && registration.backup_state);
        let stored = StoredCredential {
            public_key: &registration.public_key,
            sign_count: 0,
            backup_eligible: true,
        };
        for _ in 0..2 {
            let response: AssertionJson =
                serde_json::from_value(device.assert(&challenge, ORIGIN, RP_ID, flags)).unwrap();
            assert_eq!(
                verify_assertion(&response, &expected(&challenge, true), &stored)
                    .unwrap()
                    .sign_count,
                0
            );
        }
    }

    #[test]
    fn a_credential_id_longer_than_1023_bytes_is_refused() {
        let mut device = Authenticator::es256();
        device.credential_id = vec![5u8; 1024];
        let challenge = [3u8; 32];
        let response: RegistrationJson =
            serde_json::from_value(device.register(&challenge, ORIGIN, RP_ID, Flags::UP)).unwrap();
        assert_eq!(
            verify_registration(&response, &expected(&challenge, false)).unwrap_err(),
            Error::CredentialId
        );
        // And the authenticator data alone, with a length field over the cap.
        device.credential_id = vec![5u8; 1024];
        let data = device.auth_data(RP_ID, FLAG_UP, 0, true);
        assert_eq!(
            parse_auth_data(&data, RP_ID).err(),
            Some(Error::CredentialId)
        );
    }

    #[test]
    fn parsers_never_panic_on_garbage() {
        let device = Authenticator::es256();
        let auth_data = device.auth_data(RP_ID, FLAG_UP | FLAG_UV, 1, true);
        let cose = device.cose_key();
        let mut seed: u32 = 0x1234_5678;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            seed
        };
        for cut in 0..auth_data.len() {
            let _ = parse_auth_data(&auth_data[..cut], RP_ID);
        }
        for cut in 0..cose.len() {
            let _ = parse_cose_key(&cose[..cut]);
        }
        for _ in 0..2000 {
            let len = (next() % 300) as usize;
            let mut bytes: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            let _ = parse_cose_key(&bytes);
            let _ = one_cbor_item(&bytes);
            // Keep the rpIdHash right so the parser goes past it.
            if bytes.len() > 40 {
                bytes[..32].copy_from_slice(&Sha256::digest(RP_ID.as_bytes()));
                bytes[32] |= FLAG_AT;
            }
            let _ = parse_auth_data(&bytes, RP_ID);
            let mut mutated = auth_data.clone();
            let at = (next() as usize) % mutated.len();
            mutated[at] = next() as u8;
            let _ = parse_auth_data(&mutated, RP_ID);
        }
    }
}
