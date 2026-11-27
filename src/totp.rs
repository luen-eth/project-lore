//! The authenticator app (TOTP, RFC 6238 over HOTP, RFC 4226) and the
//! recovery codes: generation, checking and the setup QR code.
//!
//! TOTP here is SHA-1, 6 digits, a 30-second period and T0 = 0: what
//! Google Authenticator and every other app assume. HMAC-SHA1 comes from
//! `ring`, base32 from `data-encoding`; both were already built for TLS
//! and WebSockets.

use data_encoding::BASE32_NOPAD;
use ring::hmac;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Digits of a code.
pub const DIGITS: u32 = 6;
/// Seconds one code is valid for.
pub const PERIOD: u64 = 30;
/// Bytes of a secret: 160 bits (RFC 4226 §4, R6).
const SECRET_BYTES: usize = 20;
/// Recovery codes made at once.
pub const RECOVERY_CODES: usize = 10;
/// Bytes of one recovery code: 80 bits, 16 base32 characters.
const RECOVERY_BYTES: usize = 10;

/// HOTP (RFC 4226 §5): HMAC-SHA1 of the counter, dynamic truncation, the
/// last `digits` decimal digits, zero-padded.
pub fn hotp(key: &[u8], counter: u64, digits: u32) -> String {
    let tag = hmac::sign(
        &hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, key),
        &counter.to_be_bytes(),
    );
    let mac = tag.as_ref();
    let offset = usize::from(mac[mac.len() - 1] & 0x0f);
    let binary = (u32::from(mac[offset] & 0x7f) << 24)
        | (u32::from(mac[offset + 1]) << 16)
        | (u32::from(mac[offset + 2]) << 8)
        | u32::from(mac[offset + 3]);
    let value = u64::from(binary) % 10u64.pow(digits);
    format!("{value:0width$}", width = digits as usize)
}

/// The time step of a Unix time.
pub fn step_at(unix_seconds: u64) -> i64 {
    i64::try_from(unix_seconds / PERIOD).unwrap_or(i64::MAX)
}

/// The current Unix time in seconds.
pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// A typed code, spaces removed, when it is exactly six ASCII digits.
pub fn normalize_code(code: &str) -> Option<String> {
    let code: String = code.chars().filter(|c| !c.is_whitespace()).collect();
    (code.len() == DIGITS as usize && code.bytes().all(|b| b.is_ascii_digit())).then_some(code)
}

/// The time step a code matches, from one step before `unix_seconds` to
/// one after. All three codes are computed and compared in constant time
/// every time. The caller still has to make sure the step is later than
/// every step used before (`Db::advance_totp_step`).
pub fn matching_step(key: &[u8], code: &str, unix_seconds: u64) -> Option<i64> {
    let code = normalize_code(code)?;
    let now = step_at(unix_seconds);
    let mut found = None;
    for step in [now - 1, now, now + 1] {
        let Ok(counter) = u64::try_from(step) else {
            continue;
        };
        let expected = hotp(key, counter, DIGITS);
        if bool::from(expected.as_bytes().ct_eq(code.as_bytes())) && found.is_none() {
            found = Some(step);
        }
    }
    found
}

/// A new random secret, as base32 without padding (32 characters).
pub fn new_secret() -> anyhow::Result<String> {
    let mut bytes = [0u8; SECRET_BYTES];
    getrandom::fill(&mut bytes).map_err(|error| anyhow::anyhow!("no randomness: {error}"))?;
    Ok(BASE32_NOPAD.encode(&bytes))
}

/// The key bytes of a base32 secret.
pub fn decode_secret(secret: &str) -> Option<Vec<u8>> {
    let cleaned: String = secret
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_ascii_uppercase();
    BASE32_NOPAD.decode(cleaned.as_bytes()).ok()
}

/// A secret grouped by four characters for typing by hand.
pub fn group_secret(secret: &str) -> String {
    secret
        .as_bytes()
        .chunks(4)
        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
        .collect::<Vec<_>>()
        .join(" ")
}

/// Percent-encodes everything but the RFC 3986 unreserved characters.
fn percent_encode(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// The `otpauth://` URI an authenticator app reads (Google Authenticator
/// Key URI format): issuer in the label and as a parameter, both
/// percent-encoded, the defaults spelled out.
pub fn otpauth_uri(issuer: &str, account: &str, secret: &str) -> String {
    let issuer = percent_encode(issuer);
    format!(
        "otpauth://totp/{issuer}:{account}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits={DIGITS}&period={PERIOD}",
        account = percent_encode(account),
    )
}

/// The QR code of a URI as an SVG `data:` URL, for an `<img>`: the SVG has
/// attributes only (no `style`), and the page's CSP allows `data:` images.
pub fn qr_data_url(uri: &str) -> anyhow::Result<String> {
    use base64::Engine;
    use qrcode::{EcLevel, QrCode, render::svg};
    let code = QrCode::with_error_correction_level(uri.as_bytes(), EcLevel::M)
        .map_err(|error| anyhow::anyhow!("making the QR code failed: {error}"))?;
    let image = code
        .render::<svg::Color<'_>>()
        .min_dimensions(240, 240)
        .quiet_zone(true)
        .dark_color(svg::Color("#000000"))
        .light_color(svg::Color("#ffffff"))
        .build();
    Ok(format!(
        "data:image/svg+xml;base64,{}",
        base64::engine::general_purpose::STANDARD.encode(image)
    ))
}

/// New recovery codes: `RECOVERY_CODES` of 80 random bits each, as shown
/// once (`xxxx-xxxx-xxxx-xxxx`), with the hashes to store for `account`.
pub fn new_recovery_codes(account: &str) -> anyhow::Result<(Vec<String>, Vec<String>)> {
    let mut shown = Vec::with_capacity(RECOVERY_CODES);
    let mut hashes = Vec::with_capacity(RECOVERY_CODES);
    for _ in 0..RECOVERY_CODES {
        let mut bytes = [0u8; RECOVERY_BYTES];
        getrandom::fill(&mut bytes).map_err(|error| anyhow::anyhow!("no randomness: {error}"))?;
        let plain = BASE32_NOPAD.encode(&bytes).to_ascii_lowercase();
        hashes.push(recovery_hash(account, &plain));
        let groups: Vec<&str> = (0..4).map(|i| &plain[i * 4..i * 4 + 4]).collect();
        shown.push(groups.join("-"));
    }
    Ok((shown, hashes))
}

/// A typed recovery code made comparable: lowercase, spaces and dashes
/// removed; `None` unless 16 base32 characters remain.
pub fn normalize_recovery(code: &str) -> Option<String> {
    let code: String = code
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect::<String>()
        .to_ascii_lowercase();
    (code.len() == 16
        && code
            .bytes()
            .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b)))
    .then_some(code)
}

/// What is stored for a recovery code: SHA-256 hex of
/// `<account>:<normalized code>`, so a code of one account never works for
/// another.
pub fn recovery_hash(account: &str, normalized: &str) -> String {
    let digest = Sha256::digest(format!("{account}:{normalized}").as_bytes());
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const RFC_SECRET: &[u8] = b"12345678901234567890";

    #[test]
    fn hotp_matches_rfc_4226_appendix_d() {
        let expected = [
            "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583",
            "399871", "520489",
        ];
        for (counter, code) in expected.iter().enumerate() {
            assert_eq!(hotp(RFC_SECRET, counter as u64, 6), *code);
        }
    }

    #[test]
    fn totp_matches_rfc_6238_appendix_b_sha1() {
        for (time, code) in [
            (59u64, "94287082"),
            (1_111_111_109, "07081804"),
            (1_111_111_111, "14050471"),
            (1_234_567_890, "89005924"),
            (2_000_000_000, "69279037"),
            (20_000_000_000, "65353130"),
        ] {
            assert_eq!(hotp(RFC_SECRET, time / PERIOD, 8), code, "T = {time}");
        }
    }

    #[test]
    fn one_step_either_side_is_accepted_two_are_not() {
        let now = 1_700_000_000u64;
        let step = now / PERIOD;
        for (offset, accepted) in [(-2i64, false), (-1, true), (0, true), (1, true), (2, false)] {
            let counter = (step as i64 + offset) as u64;
            let code = hotp(RFC_SECRET, counter, 6);
            assert_eq!(
                matching_step(RFC_SECRET, &code, now),
                accepted.then_some(counter as i64),
                "offset {offset}"
            );
        }
        let code = hotp(RFC_SECRET, step, 6);
        let spaced = format!("{} {}", &code[..3], &code[3..]);
        assert_eq!(matching_step(RFC_SECRET, &spaced, now), Some(step as i64));
    }

    #[test]
    fn malformed_codes_never_match() {
        let now = 1_700_000_000u64;
        for bad in ["", "12345", "1234567", "12a456", "１２３４５６", "-12345"] {
            assert_eq!(matching_step(RFC_SECRET, bad, now), None, "{bad:?}");
        }
    }

    #[test]
    fn secrets_round_trip_through_base32() {
        let secret = new_secret().unwrap();
        assert_eq!(secret.len(), 32);
        assert!(!secret.contains('='));
        assert_eq!(decode_secret(&secret).unwrap().len(), SECRET_BYTES);
        let grouped = group_secret(&secret);
        assert_eq!(grouped.split(' ').count(), 8);
        assert_eq!(
            decode_secret(&grouped.to_lowercase()),
            decode_secret(&secret)
        );
        assert_eq!(
            BASE32_NOPAD.encode(RFC_SECRET),
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        );
    }

    #[test]
    fn the_otpauth_uri_is_encoded() {
        assert_eq!(
            otpauth_uri("lore (data.example.com)", "luis@example.com", "ABC"),
            "otpauth://totp/lore%20%28data.example.com%29:luis%40example.com?secret=ABC&\
             issuer=lore%20%28data.example.com%29&algorithm=SHA1&digits=6&period=30"
        );
        assert!(otpauth_uri("a:b", "c", "X").starts_with("otpauth://totp/a%3Ab:c?"));
    }

    #[test]
    fn the_qr_code_is_an_svg_without_style() {
        use base64::Engine;
        let url = qr_data_url(&otpauth_uri("lore (x)", "admin", &new_secret().unwrap())).unwrap();
        let encoded = url.strip_prefix("data:image/svg+xml;base64,").unwrap();
        let svg = String::from_utf8(
            base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .unwrap(),
        )
        .unwrap();
        assert!(svg.contains("<svg") && svg.contains("fill=\"#000000\""));
        assert!(!svg.contains("style"));
        assert!(!svg.contains("<script"));
    }

    #[test]
    fn recovery_codes_are_formatted_normalized_and_bound_to_the_account() {
        let (shown, hashes) = new_recovery_codes("user:1").unwrap();
        assert_eq!(shown.len(), RECOVERY_CODES);
        assert_eq!(hashes.len(), RECOVERY_CODES);
        let code = &shown[0];
        assert_eq!(code.len(), 19);
        assert_eq!(code.matches('-').count(), 3);
        let normalized = normalize_recovery(&format!(" {} ", code.to_uppercase())).unwrap();
        assert_eq!(recovery_hash("user:1", &normalized), hashes[0]);
        let spaced = code.replace('-', " ");
        assert_eq!(
            normalize_recovery(&spaced).as_deref(),
            Some(normalized.as_str())
        );
        assert_ne!(recovery_hash("user:2", &normalized), hashes[0]);
        for bad in [
            "",
            "abcd-efgh",
            "abcd-efgh-ijkl-mnop-q",
            "abcd-efgh-ijkl-mno1",
        ] {
            assert!(normalize_recovery(bad).is_none(), "{bad:?}");
        }
        let unique: std::collections::HashSet<_> = shown.iter().collect();
        assert_eq!(unique.len(), RECOVERY_CODES);
    }
}
