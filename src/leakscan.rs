//! The leak scan: what keeps a secret lore can recognise out of a public
//! GitHub repository written to through lore — the `github` and
//! `github_org` tools (REST) and pushes through the git proxy.
//!
//! `Scanner` is pure: bytes (and a file path) in, findings out. A finding
//! names the rule and where it fired (a file path, a JSON field, a line
//! number), never the matched text. It recognises every secret lore holds
//! (its own start-up secrets and every stored credential, in the forms
//! `ops::Guard` redacts), a set of high-confidence credential formats, and
//! file names that must never be public. A line holding `ALLOW_MARKER` is
//! skipped by the format rules (never by the known-secret rule).
//!
//! `Visibility` answers whether a GitHub repository is public, cached for a
//! minute and failing closed: anything but a clear "private" counts as
//! public. `check_rest` is the decision for one REST write.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant},
};

use base64::Engine;
use regex::bytes::{Captures, Regex, RegexBuilder};
use serde_json::Value;

use crate::{
    ops::{self, Guard, Provider},
    vault::Secret,
};

/// A line holding this text is skipped by the format rules, so
/// documentation and tests can carry fake tokens. A value lore actually
/// holds is refused even on such a line.
pub const ALLOW_MARKER: &str = "lore:allow-secret";
/// The rule for a value lore itself holds.
pub const KNOWN_SECRET: &str = "known-secret";
/// At most this many findings are collected per scan; one is enough to
/// refuse, a few help the agent fix them all at once.
const MAX_FINDINGS: usize = 50;
/// How many findings a refusal sentence names.
const NAMED_FINDINGS: usize = 5;
/// A file path or key longer than this is shortened in a location.
const MAX_LABEL_CHARS: usize = 200;
/// How long a repository's visibility is trusted.
const VISIBILITY_TTL: Duration = Duration::from_secs(60);
/// The repository answer is read up to this size.
const MAX_REPO_ANSWER_BYTES: usize = 1024 * 1024;

/// One thing the scan found: the rule and where, never the secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub rule: &'static str,
    /// Where it is: a file path, a JSON field, a line number. Built only
    /// from names that do not themselves look like a secret.
    pub location: String,
}

impl std::fmt::Display for Finding {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{} in {}", self.rule, self.location)
    }
}

/// A rule that fired on a line of some content (1-based).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hit {
    pub rule: &'static str,
    pub line: usize,
}

/// A rule's second look at a match, on the whole line it is on: the
/// regular expression finds a candidate, this rejects placeholders and
/// look-alikes.
type Check = fn(&[u8], &Captures) -> bool;

/// One credential format. The patterns never match a line break, so a
/// match always lies on one line.
struct Rule {
    name: &'static str,
    pattern: &'static str,
    check: Check,
}

const RULES: &[Rule] = &[
    Rule {
        name: "private-key",
        pattern: r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----",
        check: always,
    },
    Rule {
        name: "github-token",
        pattern: r"(?-u:\b)(?:gh[pousr]_[A-Za-z0-9]{36,251}|github_pat_[A-Za-z0-9_]{50,251})(?-u:\b)",
        check: token,
    },
    Rule {
        name: "gitlab-token",
        pattern: r"(?-u:\b)glpat-[A-Za-z0-9_\-]{20,64}",
        check: token,
    },
    Rule {
        name: "aws-access-key-id",
        pattern: r"(?-u:\b)(?:AKIA|ASIA)[A-Z0-9]{16}(?-u:\b)",
        check: token,
    },
    Rule {
        name: "google-api-key",
        pattern: r"(?-u:\b)AIza[0-9A-Za-z_\-]{35}",
        check: token,
    },
    Rule {
        name: "slack-token",
        pattern: r"(?-u:\b)xox[abprs]-[A-Za-z0-9\-]{10,250}",
        check: slack,
    },
    Rule {
        name: "stripe-live-key",
        pattern: r"(?-u:\b)(?:sk|rk)_live_[A-Za-z0-9]{20,250}",
        check: token,
    },
    Rule {
        name: "anthropic-key",
        pattern: r"(?-u:\b)sk-ant-[A-Za-z0-9_\-]{32,250}",
        check: token,
    },
    Rule {
        name: "openai-key",
        pattern: r"(?-u:\b)sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{32,250}",
        check: openai,
    },
    Rule {
        name: "telegram-bot-token",
        pattern: r"(?-u:\b)[0-9]{8,10}:AA[A-Za-z0-9_\-]{33}",
        check: telegram,
    },
    Rule {
        name: "npm-token",
        pattern: r"(?-u:\b)npm_[A-Za-z0-9]{36}(?-u:\b)",
        check: token,
    },
    Rule {
        name: "sendgrid-key",
        pattern: r"(?-u:\b)SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}",
        check: token,
    },
    Rule {
        name: "jwt",
        pattern: r"(?-u:\b)eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{20,}",
        check: jwt,
    },
    Rule {
        name: "hex-private-key",
        pattern: r#"(?i)[a-z0-9_]*(?:private_?key|privkey|secret_?key)[a-z0-9_]*["']?[ \t]*(?::=|=>|=|:)[ \t]*["']?(?:0x)?([0-9a-f]{64})(?-u:\b)"#,
        check: hex_key,
    },
    Rule {
        name: "seed-phrase",
        pattern: r#"(?i)[a-z0-9_]*(?:mnemonic|seed_?phrase|recovery_?phrase|seed_?words|private_?key|secret_?key)[a-z0-9_]*["']?[ \t]*(?::=|=>|=|:)[ \t]*["']([a-z]{3,8}(?: [a-z]{3,8}){11,23})["']"#,
        check: seed_phrase,
    },
    Rule {
        name: "url-credentials",
        pattern: r#"(?i)(?-u:\b)[a-z][a-z0-9+.\-]{1,20}://[^\s:/@"'<>`]{1,100}:([^\s/@"'<>`]{6,200})@[a-z0-9\[]"#,
        check: url_password,
    },
    Rule {
        name: "secret-assignment",
        pattern: r#"(?i)([a-z0-9_.\-]*(?:password|passwd|secret|token|api_?key|apikey)[a-z0-9_.\-]*)["']?[ \t]*(?::=|=>|=|:)[ \t]*(?:"([^"\n]{8,200})"|'([^'\n]{8,200})')"#,
        check: assignment,
    },
];

/// The rules compiled once: one expression that finds candidate lines,
/// and each rule on its own to judge them.
struct Compiled {
    any: Regex,
    rules: Vec<(&'static str, Regex, Check)>,
}

fn compiled() -> &'static Compiled {
    static COMPILED: OnceLock<Compiled> = OnceLock::new();
    COMPILED.get_or_init(|| {
        let any = RULES
            .iter()
            .map(|rule| format!("(?:{})", rule.pattern))
            .collect::<Vec<_>>()
            .join("|");
        Compiled {
            any: RegexBuilder::new(&any)
                .size_limit(64 << 20)
                .build()
                .expect("the leak scan rules compile"),
            rules: RULES
                .iter()
                .map(|rule| {
                    (
                        rule.name,
                        Regex::new(rule.pattern).expect("a leak scan rule compiles"),
                        rule.check,
                    )
                })
                .collect(),
        }
    })
}

/// The scanner for one call or one push: the format rules plus every
/// secret lore knows, in every form the guard redacts. `Debug` never
/// prints them.
#[derive(Clone, Default)]
pub struct Scanner {
    known: Option<Arc<Regex>>,
}

impl std::fmt::Debug for Scanner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Scanner([redacted])")
    }
}

impl Scanner {
    /// The scanner for every form of every secret `guard` knows: build the
    /// guard with `Guard::with_secrets(&ops::stored_secrets(..))` first, as
    /// the redaction does, so every stored credential is in it.
    pub fn new(guard: &Guard) -> Self {
        let forms = guard.known_forms();
        if forms.is_empty() {
            return Self { known: None };
        }
        let pattern = forms
            .iter()
            .map(|form| regex::escape(form))
            .collect::<Vec<_>>()
            .join("|");
        let known = RegexBuilder::new(&pattern)
            .unicode(false)
            .size_limit(256 << 20)
            .build()
            .ok()
            .map(Arc::new);
        Self { known }
    }

    /// Every rule that fires on `data`, with its line. The known secrets
    /// are looked for everywhere; the format rules skip a line that holds
    /// `ALLOW_MARKER`.
    pub fn hits(&self, data: &[u8]) -> Vec<Hit> {
        let mut out: Vec<Hit> = Vec::new();
        if let Some(known) = &self.known {
            let mut lines = LineCounter::default();
            for found in known.find_iter(data) {
                push_hit(&mut out, KNOWN_SECRET, lines.at(data, found.start()));
                if out.len() >= MAX_FINDINGS {
                    return out;
                }
            }
        }
        let rules = compiled();
        let mut lines = LineCounter::default();
        let mut last_line = usize::MAX;
        for candidate in rules.any.find_iter(data) {
            let (start, end) = line_bounds(data, candidate.start());
            if start == last_line {
                continue;
            }
            last_line = start;
            let line = &data[start..end];
            if contains(line, ALLOW_MARKER.as_bytes()) {
                continue;
            }
            let number = lines.at(data, start);
            for (name, regex, check) in &rules.rules {
                if regex.captures_iter(line).any(|caps| check(line, &caps)) {
                    push_hit(&mut out, name, number);
                }
            }
            if out.len() >= MAX_FINDINGS {
                break;
            }
        }
        out
    }

    /// `hits`, each with `label` (a file or a field) and its line.
    pub fn scan_content(&self, data: &[u8], label: &str) -> Vec<Finding> {
        self.hits(data)
            .into_iter()
            .map(|hit| Finding {
                rule: hit.rule,
                location: format!("{label}, line {}", hit.line),
            })
            .collect()
    }

    /// A file: its name (see `name_rule`) and its content. The REST and
    /// pack scans name files themselves; this is the whole-file form the
    /// tests (and lore's check of its own files) use.
    #[cfg(test)]
    pub fn scan_file(&self, data: &[u8], path: &str) -> Vec<Finding> {
        let label = self.label(path);
        let mut out = Vec::new();
        if let Some(rule) = name_rule(path) {
            out.push(Finding {
                rule,
                location: label.clone(),
            });
        }
        out.extend(self.scan_content(data, &label));
        out
    }

    /// A name (a file path, a key) as a location may show it: quoted, cut
    /// to a readable length, control characters replaced — or a stand-in
    /// when the name itself looks like a secret.
    pub fn label(&self, name: &str) -> String {
        if !self.hits(name.as_bytes()).is_empty() {
            return "[a name that itself looks like a secret]".into();
        }
        let mut clean: String = name
            .chars()
            .take(MAX_LABEL_CHARS)
            .map(|c| if c.is_control() || c == '`' { '?' } else { c })
            .collect();
        if name.chars().count() > MAX_LABEL_CHARS {
            clean.push('…');
        }
        format!("`{clean}`")
    }

    /// A JSON request body: every string value at any depth (object keys
    /// too), the base64-decoded value of every `content` field (the
    /// Contents and Blobs APIs), and the name rules for every file the body
    /// adds — a tree entry (`path` with `content` or `sha`), a gist file
    /// (a key under `files`, or a `filename`). `file` is the file the body
    /// writes when the URL names it (`/contents/{path}`).
    pub fn scan_json(&self, body: &Value, file: Option<&str>) -> Vec<Finding> {
        let mut out = Vec::new();
        self.walk(body, None, "", file, &mut out);
        dedup(out)
    }

    fn walk(
        &self,
        value: &Value,
        key: Option<&str>,
        field: &str,
        file: Option<&str>,
        out: &mut Vec<Finding>,
    ) {
        if out.len() >= MAX_FINDINGS {
            return;
        }
        let field_name = if field.is_empty() { "body" } else { field };
        match value {
            Value::String(text) => {
                let place = match file {
                    Some(file) => format!("{} (field `{field_name}`)", self.label(file)),
                    None => format!("field `{field_name}`"),
                };
                out.extend(self.scan_content(text.as_bytes(), &place));
                if key == Some("content")
                    && let Some(decoded) = decode_base64(text)
                {
                    out.extend(self.scan_content(&decoded, &format!("{place}, base64-decoded")));
                }
            }
            Value::Array(items) => {
                for (index, item) in items.iter().enumerate() {
                    self.walk(item, key, &format!("{field_name}[{index}]"), file, out);
                }
            }
            Value::Object(map) => {
                let named = map
                    .get("path")
                    .and_then(Value::as_str)
                    .filter(|_| adds_content(map));
                let renamed = map.get("filename").and_then(Value::as_str);
                for name in [named, renamed].into_iter().flatten() {
                    if let Some(rule) = name_rule(name) {
                        out.push(Finding {
                            rule,
                            location: self.label(name),
                        });
                    }
                }
                let own = map
                    .get("path")
                    .or_else(|| map.get("filename"))
                    .and_then(Value::as_str)
                    .or(file);
                for (child_key, child) in map {
                    for hit in self.hits(child_key.as_bytes()) {
                        out.push(Finding {
                            rule: hit.rule,
                            location: format!("an object key in field `{field_name}`"),
                        });
                    }
                    let child_field = if field.is_empty() {
                        field_segment(child_key)
                    } else {
                        format!("{field}.{}", field_segment(child_key))
                    };
                    // A gist's files are keyed by their names.
                    let child_file = if key == Some("files") {
                        if !child.is_null()
                            && let Some(rule) = name_rule(child_key)
                        {
                            out.push(Finding {
                                rule,
                                location: self.label(child_key),
                            });
                        }
                        Some(child_key.as_str())
                    } else {
                        own
                    };
                    self.walk(child, Some(child_key), &child_field, child_file, out);
                }
            }
            Value::Number(_) | Value::Bool(_) | Value::Null => {}
        }
    }
}

/// True for a tree entry that puts content under its `path`: it carries
/// `content` or a blob `sha`, and is not a directory.
fn adds_content(map: &serde_json::Map<String, Value>) -> bool {
    let carries = map.get("content").is_some_and(|value| !value.is_null())
        || map.get("sha").is_some_and(Value::is_string);
    let directory = map.get("type").and_then(Value::as_str) == Some("tree")
        || map.get("mode").and_then(Value::as_str) == Some("040000");
    carries && !directory
}

/// A JSON key as a field path shows it: plain keys as they are, anything
/// else as `…`.
fn field_segment(key: &str) -> String {
    if !key.is_empty()
        && key.len() <= 40
        && key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
    {
        key.to_string()
    } else {
        "…".into()
    }
}

/// The bytes a `content` field carries when it is base64 (line breaks
/// allowed, as the Contents API sends them), or `None`.
fn decode_base64(text: &str) -> Option<Vec<u8>> {
    let compact: String = text.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    if compact.len() < 8 {
        return None;
    }
    base64::engine::general_purpose::STANDARD
        .decode(&compact)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(&compact))
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(&compact))
        .ok()
        .filter(|bytes| !bytes.is_empty() && bytes.as_slice() != compact.as_bytes())
}

/// The rule for a file that must not be public whatever it holds, or
/// `None`: environment files (not their `.example`, `.sample`,
/// `.template` or `.dist` siblings), SSH private keys, key stores and
/// certificates with keys, credential files, SQLite databases (lore's own
/// backups among them) and SQL dumps.
pub fn name_rule(path: &str) -> Option<&'static str> {
    let name = path
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(path)
        .trim()
        .to_ascii_lowercase();
    if name.is_empty() {
        return None;
    }
    let extension = name.rsplit_once('.').map(|(_, ext)| ext).unwrap_or("");
    if name == ".env" || name.ends_with(".env") {
        return Some("env-file");
    }
    if let Some(variant) = name.strip_prefix(".env.") {
        return (!matches!(variant, "example" | "sample" | "template" | "dist"))
            .then_some("env-file");
    }
    if matches!(
        name.as_str(),
        "id_rsa" | "id_dsa" | "id_ecdsa" | "id_ed25519" | "id_ecdsa_sk" | "id_ed25519_sk"
    ) {
        return Some("ssh-key-file");
    }
    if matches!(
        extension,
        "pem" | "key" | "p12" | "pfx" | "keystore" | "jks" | "ppk"
    ) {
        return Some("key-file");
    }
    if matches!(
        name.as_str(),
        ".netrc" | "_netrc" | ".pgpass" | ".git-credentials"
    ) {
        return Some("credentials-file");
    }
    if matches!(extension, "sqlite" | "sqlite3" | "db") {
        return Some("database-file");
    }
    if extension == "sql" && (name.contains("dump") || name.starts_with("backup")) {
        return Some("database-dump");
    }
    None
}

// ---------- The rules' second look ----------

fn always(_: &[u8], _: &Captures) -> bool {
    true
}

/// The matched text, or group 1 when there is one.
fn matched<'a>(caps: &Captures<'a>) -> &'a [u8] {
    caps.get(1)
        .or_else(|| caps.get(0))
        .map(|found| found.as_bytes())
        .unwrap_or_default()
}

/// Text that is obviously a placeholder or an example.
fn placeholder(text: &[u8]) -> bool {
    const WORDS: &[&str] = &[
        "example",
        "xxxx",
        "****",
        "....",
        "placeholder",
        "your_",
        "your-",
        "yourtoken",
        "yourkey",
        "yoursecret",
        "yourpassword",
        "changeme",
        "change_me",
        "change-me",
        "dummy",
        "fake",
        "not-real",
        "notreal",
        "redacted",
        "replace",
        "insert",
        "todo",
        "fixme",
        "0000000000",
        "1234567890",
        "abcdefgh",
        "<",
        ">",
        "${",
        "{{",
        "}}",
        "%s",
        "%(",
        "$(",
    ];
    let lower = text.to_ascii_lowercase();
    WORDS.iter().any(|word| contains(&lower, word.as_bytes()))
}

/// A token-shaped match: not a placeholder, and varied enough to be
/// random rather than a repeated character or a word.
fn token(_: &[u8], caps: &Captures) -> bool {
    let text = matched(caps);
    !placeholder(text) && distinct(text) >= 8
}

fn slack(line: &[u8], caps: &Captures) -> bool {
    token(line, caps) && matched(caps).iter().any(u8::is_ascii_digit)
}

/// OpenAI keys are mixed-case base62 with digits; `sk-ant-` is Anthropic's.
fn openai(line: &[u8], caps: &Captures) -> bool {
    let text = matched(caps);
    if text.starts_with(b"sk-ant-") {
        return false;
    }
    let tail = &text[3..];
    token(line, caps)
        && tail.iter().any(u8::is_ascii_uppercase)
        && tail.iter().any(u8::is_ascii_lowercase)
        && tail.iter().any(u8::is_ascii_digit)
}

/// A bot token is exactly 35 characters after the colon: one more token
/// character means it is something else.
fn telegram(line: &[u8], caps: &Captures) -> bool {
    let Some(found) = caps.get(0) else {
        return false;
    };
    let next = line.get(found.end()).copied();
    !next.is_some_and(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
        && token(line, caps)
}

/// A JWT: the header and the payload decode to JSON objects, and the
/// header names an algorithm.
fn jwt(_: &[u8], caps: &Captures) -> bool {
    let text = matched(caps);
    let mut parts = text.split(|byte| *byte == b'.');
    let (Some(header), Some(payload)) = (parts.next(), parts.next()) else {
        return false;
    };
    let decode = |part: &[u8]| -> Option<Value> {
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(part)
            .ok()?;
        serde_json::from_slice::<Value>(&bytes)
            .ok()
            .filter(Value::is_object)
    };
    decode(header).is_some_and(|header| header.get("alg").is_some()) && decode(payload).is_some()
}

fn hex_key(_: &[u8], caps: &Captures) -> bool {
    let text = matched(caps);
    !placeholder(text) && distinct(text) >= 8
}

/// A BIP-39 sized phrase (12, 15, 18, 21 or 24 words) of mostly distinct
/// words.
fn seed_phrase(_: &[u8], caps: &Captures) -> bool {
    let text = matched(caps).to_ascii_lowercase();
    let words: Vec<&[u8]> = text.split(|byte| *byte == b' ').collect();
    let mut unique = words.clone();
    unique.sort();
    unique.dedup();
    matches!(words.len(), 12 | 15 | 18 | 21 | 24)
        && unique.len() + 2 >= words.len()
        && !placeholder(&text)
}

/// The password part of `scheme://user:password@host`.
fn url_password(_: &[u8], caps: &Captures) -> bool {
    let password = matched(caps);
    let lower = password.to_ascii_lowercase();
    let generic = [
        "password", "passwd", "pass", "secret", "token", "pwd", "pat", "apikey",
    ];
    !placeholder(password)
        && !generic.iter().any(|word| lower == word.as_bytes())
        && !["password", "secret", "token"]
            .iter()
            .any(|word| contains(&lower, word.as_bytes()))
        && !matches!(password.first(), Some(b'$' | b'{' | b'%' | b'*' | b':'))
}

/// `password = "…"` and its kin: a quoted value of 8 characters or more
/// that is no placeholder, no environment lookup, no path or URL and no
/// prose, and has a digit or a symbol in it — what a secret looks like,
/// not a setting's name.
fn assignment(_: &[u8], caps: &Captures) -> bool {
    let name = caps
        .get(1)
        .map(|found| found.as_bytes().to_ascii_lowercase())
        .unwrap_or_default();
    let Some(value) = caps
        .get(2)
        .or_else(|| caps.get(3))
        .map(|found| found.as_bytes())
    else {
        return false;
    };
    const NOT_SECRET_NAMES: &[&str] = &[
        "url",
        "uri",
        "endpoint",
        "path",
        "file",
        "type",
        "name",
        "_id",
        "hint",
        "label",
        "placeholder",
        "header",
        "field",
        "prompt",
        "env",
        "hash",
        "pattern",
        "regex",
        "format",
        "length",
        "expire",
        "kind",
        "mode",
        "scope",
        "prefix",
        "suffix",
        "message",
        "error",
        "reason",
        "text",
        "description",
        "help",
        "title",
        "count",
        "limit",
    ];
    if NOT_SECRET_NAMES
        .iter()
        .any(|word| contains(&name, word.as_bytes()))
    {
        return false;
    }
    let lower = value.to_ascii_lowercase();
    const SELF_DESCRIBING: &[&str] = &["password", "passwd", "secret", "token"];
    const LOOKUPS: &[&str] = &[
        "env(", "env.", "env[", "env!", "getenv", "environ", "process.", "vault(", "secrets.",
    ];
    let symbol =
        |byte: &u8| byte.is_ascii_punctuation() && !matches!(byte, b'-' | b'_' | b'.' | b'/');
    !value.iter().any(u8::is_ascii_whitespace)
        && !placeholder(value)
        && !SELF_DESCRIBING
            .iter()
            .any(|word| contains(&lower, word.as_bytes()))
        && !LOOKUPS.iter().any(|word| contains(&lower, word.as_bytes()))
        && !matches!(value.first(), Some(b'$' | b'/' | b'~' | b'@' | b'#' | b'%'))
        && !value.starts_with(b"./")
        && !contains(value, b"://")
        && (value.iter().any(u8::is_ascii_digit) || value.iter().any(symbol))
        && distinct(value) >= 5
}

// ---------- Small helpers ----------

fn distinct(text: &[u8]) -> usize {
    let mut seen = [false; 256];
    let mut count = 0;
    for byte in text {
        if !seen[*byte as usize] {
            seen[*byte as usize] = true;
            count += 1;
        }
    }
    count
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack.len() >= needle.len()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

/// The start and end (exclusive, without the line break) of the line
/// holding `offset`.
fn line_bounds(data: &[u8], offset: usize) -> (usize, usize) {
    let start = data[..offset]
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map_or(0, |position| position + 1);
    let end = data[offset..]
        .iter()
        .position(|byte| *byte == b'\n')
        .map_or(data.len(), |position| offset + position);
    (start, end)
}

/// Line numbers for offsets asked in ascending order, counted once.
#[derive(Default)]
struct LineCounter {
    offset: usize,
    breaks: usize,
}

impl LineCounter {
    fn at(&mut self, data: &[u8], offset: usize) -> usize {
        if offset >= self.offset {
            self.breaks += data[self.offset..offset]
                .iter()
                .filter(|byte| **byte == b'\n')
                .count();
            self.offset = offset;
        }
        self.breaks + 1
    }
}

fn push_hit(out: &mut Vec<Hit>, rule: &'static str, line: usize) {
    let hit = Hit { rule, line };
    if !out.contains(&hit) {
        out.push(hit);
    }
}

/// The findings without repeats, in the order found.
pub fn dedup(findings: Vec<Finding>) -> Vec<Finding> {
    let mut out: Vec<Finding> = Vec::with_capacity(findings.len());
    for finding in findings {
        if !out.contains(&finding) {
            out.push(finding);
        }
    }
    out
}

/// The first few findings as one line, for a refusal or a log row.
pub fn summarize(findings: &[Finding]) -> String {
    let mut text = findings
        .iter()
        .take(NAMED_FINDINGS)
        .map(Finding::to_string)
        .collect::<Vec<_>>()
        .join("; ");
    if findings.len() > NAMED_FINDINGS {
        text.push_str(&format!("; and {} more", findings.len() - NAMED_FINDINGS));
    }
    text
}

// ---------- Repository visibility ----------

/// Which GitHub repositories are public, as far as lore knows: one answer
/// per (API base, provider, repository), trusted for 60 seconds. Only a
/// clear answer is kept; anything else is asked again next time.
#[derive(Default)]
pub struct Visibility {
    known: Mutex<HashMap<String, (Instant, bool)>>,
}

/// The one cache the REST tools and the git proxy share, so a repository
/// made public through one is asked about again by the other.
pub fn visibility() -> &'static Visibility {
    static VISIBILITY: OnceLock<Visibility> = OnceLock::new();
    VISIBILITY.get_or_init(Visibility::default)
}

/// A GitHub owner or repository name lore will put in a URL.
fn plain_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 100
        && name != "."
        && name != ".."
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

impl Visibility {
    fn key(api_base: &str, provider: &Provider, owner: &str, repo: &str) -> String {
        format!(
            "{}\n{}\n{}/{}",
            api_base.trim_end_matches('/'),
            provider.id,
            owner.to_ascii_lowercase(),
            repo.to_ascii_lowercase()
        )
    }

    /// True unless GitHub clearly says the repository is private:
    /// `GET /repos/{owner}/{repo}` with the provider's own credential, its
    /// `private` field. A network error, a 404 (the token cannot see it), a
    /// redirect or anything unexpected counts as public.
    pub async fn is_public(
        &self,
        client: &reqwest::Client,
        api_base: &str,
        provider: &Provider,
        secret: &Secret,
        owner: &str,
        repo: &str,
    ) -> bool {
        let repo = repo.strip_suffix(".git").unwrap_or(repo);
        if !plain_name(owner) || !plain_name(repo) {
            return true;
        }
        let key = Self::key(api_base, provider, owner, repo);
        if let Some((at, public)) = self.known.lock().expect("visibility cache").get(&key)
            && at.elapsed() < VISIBILITY_TTL
        {
            return *public;
        }
        let Some(private) = fetch_private(client, api_base, secret, owner, repo).await else {
            return true;
        };
        let mut known = self.known.lock().expect("visibility cache");
        if known.len() > 1000 {
            known.retain(|_, (at, _)| at.elapsed() < VISIBILITY_TTL);
        }
        known.insert(key, (Instant::now(), !private));
        !private
    }

    /// Forgets every answer about one repository, through any provider:
    /// called when lore lets a call make it public.
    pub fn forget(&self, owner: &str, repo: &str) {
        let suffix = format!(
            "\n{}/{}",
            owner.to_ascii_lowercase(),
            repo.trim_end_matches(".git").to_ascii_lowercase()
        );
        self.known
            .lock()
            .expect("visibility cache")
            .retain(|key, _| !key.ends_with(&suffix));
    }
}

/// The repository's `private` field, or `None` when the answer is not a
/// clear 200 with it. `visibility: "public"` wins over a `private` field
/// that says otherwise.
async fn fetch_private(
    client: &reqwest::Client,
    api_base: &str,
    secret: &Secret,
    owner: &str,
    repo: &str,
) -> Option<bool> {
    let url = format!("{}/repos/{owner}/{repo}", api_base.trim_end_matches('/'));
    let authorization = ops::sensitive_header(&format!("Bearer {}", secret.expose())).ok()?;
    let mut response = client
        .get(url)
        .header("authorization", authorization)
        .header("accept", "application/vnd.github+json")
        .header("x-github-api-version", "2022-11-28")
        .header("user-agent", ops::USER_AGENT)
        .timeout(Duration::from_secs(20))
        .send()
        .await
        .ok()?;
    if response.status() != reqwest::StatusCode::OK {
        return None;
    }
    let mut bytes: Vec<u8> = Vec::new();
    while let Some(chunk) = response.chunk().await.ok()? {
        if bytes.len() + chunk.len() > MAX_REPO_ANSWER_BYTES {
            return None;
        }
        bytes.extend_from_slice(&chunk);
    }
    let value: Value = serde_json::from_slice(&bytes).ok()?;
    if value.get("visibility").and_then(Value::as_str) == Some("public") {
        return Some(false);
    }
    value.get("private")?.as_bool()
}

// ---------- REST writes ----------

/// What a GitHub REST write touches, as far as the leak scan cares.
#[derive(Debug, PartialEq, Eq)]
pub enum RestTarget {
    /// Nothing the scan looks at.
    Other,
    /// A write under `/repos/{owner}/{repo}`: scanned when the repository
    /// is public. `file` is the path of `PUT …/contents/{path}`;
    /// `makes_public` is a `PATCH` of the repository that makes it public.
    Repo {
        owner: String,
        repo: String,
        file: Option<String>,
        makes_public: bool,
    },
    /// A write under `/gists`; `public` is true when the body says so or
    /// does not say.
    Gist { public: bool },
    /// `POST /user/repos`, `POST /orgs/{org}/repos` or a repository made
    /// from a template; `public` unless the body asks for a private one.
    CreatesRepo { public: bool },
}

/// One percent-decoded path segment.
fn decode_segment(segment: &str) -> String {
    let bytes = segment.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%'
            && index + 2 < bytes.len()
            && let Some(byte) = std::str::from_utf8(&bytes[index + 1..index + 3])
                .ok()
                .and_then(|hex| u8::from_str_radix(hex, 16).ok())
        {
            out.push(byte);
            index += 3;
            continue;
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// True when a body that creates a repository leaves it public: no
/// `visibility` of `private` or `internal`, and no `private: true`.
fn creates_public(body: Option<&Value>) -> bool {
    let body = body.unwrap_or(&Value::Null);
    match body.get("visibility").and_then(Value::as_str) {
        Some(visibility) if visibility.eq_ignore_ascii_case("public") => true,
        Some(visibility)
            if visibility.eq_ignore_ascii_case("private")
                || visibility.eq_ignore_ascii_case("internal") =>
        {
            false
        }
        _ => body.get("private").and_then(Value::as_bool) != Some(true),
    }
}

/// What a GitHub REST call touches. `method` is normalised and `path` is
/// the path as the service sees it (see `ops::validate`).
pub fn rest_target(method: &str, path: &str, body: Option<&Value>) -> RestTarget {
    if method == "GET" {
        return RestTarget::Other;
    }
    let segments: Vec<String> = path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .map(decode_segment)
        .collect();
    let lower: Vec<String> = segments.iter().map(|s| s.to_ascii_lowercase()).collect();
    let parts: Vec<&str> = lower.iter().map(String::as_str).collect();
    match parts.as_slice() {
        ["user", "repos"] | ["orgs", _, "repos"] if method == "POST" => RestTarget::CreatesRepo {
            public: creates_public(body),
        },
        ["repos", _, _, "generate"] if method == "POST" => RestTarget::CreatesRepo {
            public: creates_public(body),
        },
        ["repos", _, _, rest @ ..] => {
            let makes_public = rest.is_empty()
                && method == "PATCH"
                && body.is_some_and(|body| {
                    body.get("private").and_then(Value::as_bool) == Some(false)
                        || body
                            .get("visibility")
                            .and_then(Value::as_str)
                            .is_some_and(|v| v.eq_ignore_ascii_case("public"))
                });
            let file = (method == "PUT" && rest.len() > 1 && rest[0] == "contents")
                .then(|| segments[4..].join("/"));
            RestTarget::Repo {
                owner: segments[1].clone(),
                repo: segments[2].clone(),
                file,
                makes_public,
            }
        }
        ["gists", ..] => RestTarget::Gist {
            public: body
                .and_then(|body| body.get("public"))
                .and_then(Value::as_bool)
                != Some(false),
        },
        _ => RestTarget::Other,
    }
}

/// Why a REST write was refused: the sentence for the agent and the
/// detail for the operations log. Neither carries a secret.
#[derive(Debug)]
pub struct Refusal {
    pub message: String,
    pub detail: String,
}

impl Refusal {
    fn secrets(target: &str, findings: &[Finding]) -> Self {
        let list = summarize(findings);
        Self {
            message: format!(
                "lore refused this call: it would put a secret or a private file into a public \
                 {target} ({list}). lore does not let secrets or private files reach a public \
                 repository: remove it, or ask the user."
            ),
            detail: format!("leak scan: {list}"),
        }
    }

    fn goes_public(what: &str) -> Self {
        Self {
            message: format!(
                "lore refused this call: it would {what}, and the administrator has not allowed \
                 agents to create public repositories or make one public. Keep it private \
                 (`\"private\": true`), or ask the user."
            ),
            detail: format!("leak scan: would {what}; public repositories are not allowed"),
        }
    }
}

/// Everything `check_rest` needs about the call.
pub struct RestCall<'a> {
    pub client: &'a reqwest::Client,
    /// The provider's API base, where `/repos/{owner}/{repo}` is asked.
    pub api_base: &'a str,
    pub provider: &'a Provider,
    pub secret: &'a Secret,
    pub scanner: &'a Scanner,
    /// The admin switch: agents may create public repositories or make
    /// one public.
    pub allow_public: bool,
    pub method: &'a str,
    /// The path as the service sees it.
    pub path: &'a str,
    pub body: Option<&'a Value>,
}

/// The leak scan's decision for one GitHub REST write, before anything is
/// sent: `Err` refuses it.
pub async fn check_rest(call: &RestCall<'_>) -> Result<(), Refusal> {
    match rest_target(call.method, call.path, call.body) {
        RestTarget::Other => Ok(()),
        RestTarget::CreatesRepo { public: false } => Ok(()),
        RestTarget::CreatesRepo { public: true } => {
            if call.allow_public {
                Ok(())
            } else {
                Err(Refusal::goes_public("create a public repository"))
            }
        }
        RestTarget::Gist { public: false } => Ok(()),
        RestTarget::Gist { public: true } => {
            let findings = call
                .body
                .map(|body| call.scanner.scan_json(body, None))
                .unwrap_or_default();
            if findings.is_empty() {
                Ok(())
            } else {
                Err(Refusal::secrets("gist", &findings))
            }
        }
        RestTarget::Repo {
            owner,
            repo,
            file,
            makes_public,
        } => {
            if makes_public {
                if !call.allow_public {
                    return Err(Refusal::goes_public("make a repository public"));
                }
                visibility().forget(&owner, &repo);
            }
            if call.body.is_none() && file.is_none() {
                return Ok(());
            }
            let public = visibility()
                .is_public(
                    call.client,
                    call.api_base,
                    call.provider,
                    call.secret,
                    &owner,
                    &repo,
                )
                .await;
            if !public {
                return Ok(());
            }
            let mut findings = Vec::new();
            if let Some(file) = file.as_deref()
                && let Some(rule) = name_rule(file)
            {
                findings.push(Finding {
                    rule,
                    location: call.scanner.label(file),
                });
            }
            if let Some(body) = call.body {
                findings.extend(call.scanner.scan_json(body, file.as_deref()));
            }
            let findings = dedup(findings);
            if findings.is_empty() {
                Ok(())
            } else {
                Err(Refusal::secrets("GitHub repository", &findings))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, extract::State, http::StatusCode, routing::get};

    /// Deterministic random-looking text over `alphabet`: test tokens are
    /// built at run time, so this file holds none for the scan to find.
    fn tail(len: usize, alphabet: &str, seed: u32) -> String {
        let alphabet = alphabet.as_bytes();
        let mut state = seed.max(1);
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                alphabet[(state % alphabet.len() as u32) as usize] as char
            })
            .collect()
    }

    const BASE62: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    fn b62(len: usize, seed: u32) -> String {
        tail(len, BASE62, seed)
    }

    fn b64url(text: &str) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(text)
    }

    /// One line per rule that must fire, built from pieces.
    fn firing_samples() -> Vec<(&'static str, String)> {
        let words = [
            "orbit", "velvet", "canyon", "pepper", "almond", "glide", "harbor", "nickel", "tundra",
            "quiver", "saddle", "breeze",
        ]
        .join(" ");
        vec![
            (
                "private-key",
                ["-----BEGIN OPENSSH ", "PRIVATE KEY-----"].concat(),
            ),
            (
                "private-key",
                ["-----BEGIN RSA ", "PRIVATE KEY-----"].concat(),
            ),
            ("private-key", ["-----BEGIN ", "PRIVATE KEY-----"].concat()),
            (
                "private-key",
                ["-----BEGIN PGP ", "PRIVATE KEY BLOCK-----"].concat(),
            ),
            ("github-token", format!("token: {}p_{}", "gh", b62(36, 1))),
            (
                "github-token",
                format!("x = {}", ["gh", "s_", &b62(36, 2)].concat()),
            ),
            (
                "github-token",
                ["github", "_pat_", &b62(22, 3), "_", &b62(59, 4)].concat(),
            ),
            ("gitlab-token", ["gl", "pat-", &b62(20, 5)].concat()),
            (
                "aws-access-key-id",
                ["AK", "IA", &tail(16, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 6)].concat(),
            ),
            ("google-api-key", ["AI", "za", &b62(35, 7)].concat()),
            (
                "slack-token",
                ["xo", "xb-", &tail(12, "0123456789", 8), "-", &b62(24, 9)].concat(),
            ),
            ("stripe-live-key", ["sk", "_live_", &b62(24, 10)].concat()),
            (
                "anthropic-key",
                ["sk", "-ant-api03-", &b62(80, 11)].concat(),
            ),
            ("openai-key", ["sk", "-proj-", &b62(64, 12)].concat()),
            (
                "telegram-bot-token",
                format!(
                    "bot = {}:{}",
                    tail(9, "123456789", 13),
                    ["AA", &b62(33, 14)].concat()
                ),
            ),
            ("npm-token", ["np", "m_", &b62(36, 15)].concat()),
            (
                "sendgrid-key",
                ["S", "G.", &b62(22, 16), ".", &b62(43, 17)].concat(),
            ),
            (
                "jwt",
                format!(
                    "Authorization: Bearer {}.{}.{}",
                    b64url(r#"{"alg":"HS256","typ":"JWT"}"#),
                    b64url(r#"{"sub":"42","name":"someone"}"#),
                    b62(43, 18)
                ),
            ),
            (
                "hex-private-key",
                format!("PRIVATE_KEY=0x{}", tail(64, "0123456789abcdef", 19)),
            ),
            (
                "hex-private-key",
                format!("\"privkey\": \"{}\"", tail(64, "0123456789abcdef", 20)),
            ),
            ("seed-phrase", format!("mnemonic = \"{words}\"")),
            (
                "url-credentials",
                format!(
                    "DATABASE_URL=postgres://app:{}@db.internal:5432/app",
                    b62(16, 21)
                ),
            ),
            (
                "secret-assignment",
                format!("db_password = \"Xy7!{}\"", b62(10, 22)),
            ),
            (
                "secret-assignment",
                format!("{{\"api_key\": \"{}\"}}", b62(32, 23)),
            ),
        ]
    }

    #[test]
    fn every_rule_fires_on_its_format() {
        let scanner = Scanner::default();
        for (rule, line) in firing_samples() {
            let hits = scanner.hits(line.as_bytes());
            assert!(
                hits.iter().any(|hit| hit.rule == rule),
                "{rule} did not fire on {line:?}: {hits:?}"
            );
            // On a later line, with the line number.
            let text = format!("first line\nsecond line\n{line}\n");
            assert!(
                scanner
                    .hits(text.as_bytes())
                    .iter()
                    .any(|hit| hit.rule == rule && hit.line == 3)
            );
        }
        // Every rule is tested.
        for rule in RULES {
            assert!(
                firing_samples().iter().any(|(name, _)| *name == rule.name),
                "{} has no sample",
                rule.name
            );
        }
    }

    #[test]
    fn findings_never_carry_the_secret() {
        let scanner = Scanner::default();
        for (_, line) in firing_samples() {
            for finding in scanner.scan_file(line.as_bytes(), "src/settings.py") {
                assert_eq!(finding.location, "`src/settings.py`, line 1");
                assert!(!line.contains(&finding.location));
            }
        }
        // A file name that is itself a token is not repeated either.
        let token = ["gh", "p_", &b62(36, 30)].concat();
        let label = scanner.label(&format!("notes/{token}.txt"));
        assert!(!label.contains(&token), "{label}");
    }

    #[test]
    fn placeholders_and_look_alikes_do_not_fire() {
        let scanner = Scanner::default();
        let quiet = [
            "password = \"changeme123\"".to_string(),
            "token: \"${GITHUB_TOKEN}\"".into(),
            "api_key = \"<your api key>\"".into(),
            "secret = \"your_secret_here_42\"".into(),
            "password = \"\"".into(),
            "password = os.environ[\"DB_PASSWORD\"]".into(),
            "password: \"process.env.DB_PASSWORD1\"".into(),
            "\"token\": \"the token is missing 1\"".into(),
            "user = \"x-access-token\"".into(),
            "token_url = \"https://example.com/oauth/token1\"".into(),
            "secret_name = \"Prod-Db-Credentials-2\"".into(),
            "password_hash = \"$argon2id$v=19$m=19456\"".into(),
            ["gh", "p_", &"x".repeat(36)].concat(),
            ["AK", "IAIOSFODNN7", "EXAMPLE"].concat(),
            "sk-learn-preprocessing-pipeline-utilities-module".into(),
            format!(
                "{}.{}.{}",
                b64url(r#"{"typ":"JWT"}"#),
                b64url(r#"{"sub":"1"}"#),
                b62(30, 31)
            ),
            format!("PRIVATE_KEY={}", "0".repeat(64)),
            format!("public_key = \"{}\"", tail(64, "0123456789abcdef", 32)),
            "mnemonic = \"abandon abandon abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon about\""
                .into(),
            "https://user:password@example.com/".into(),
            "git clone https://lore:${LORE_TOKEN}@lore.example.com/git/x.git".into(),
            "-----BEGIN CERTIFICATE-----".into(),
            "-----BEGIN PUBLIC KEY-----".into(),
            "-----BEGIN rsa PRIVATE KEY".into(),
        ];
        for line in quiet {
            assert!(
                scanner.hits(line.as_bytes()).is_empty(),
                "fired on {line:?}: {:?}",
                scanner.hits(line.as_bytes())
            );
        }
    }

    #[test]
    fn the_allow_marker_skips_a_line_but_never_a_known_secret() {
        let scanner = Scanner::default();
        let token = ["gh", "p_", &b62(36, 40)].concat();
        let marked = format!("const FAKE: &str = \"{token}\"; // {ALLOW_MARKER}");
        assert!(scanner.hits(marked.as_bytes()).is_empty());
        // Only that line.
        let text = format!("{marked}\nlet real = \"{token}\";\n");
        assert_eq!(
            scanner.hits(text.as_bytes()),
            vec![Hit {
                rule: "github-token",
                line: 2
            }]
        );

        let own = "lore-own-agent-token-Qw8Zx2";
        let scanner = Scanner::new(&Guard::new([own], Vec::new()));
        let marked = format!("{own} {ALLOW_MARKER}");
        assert_eq!(
            scanner.hits(marked.as_bytes()),
            vec![Hit {
                rule: KNOWN_SECRET,
                line: 1
            }]
        );
    }

    #[test]
    fn known_secrets_are_found_in_every_form() {
        use crate::vault::Secret;
        let own = "lore-own/agent+token-Qw8Zx2";
        let stored = "a-stored-credential-9Kq";
        let guard = Guard::new([own], Vec::new()).with_secrets(&[Secret::new(stored)]);
        let scanner = Scanner::new(&guard);
        let base64 = base64::engine::general_purpose::STANDARD.encode(stored);
        for text in [
            format!("x = {own}"),
            format!("stored: {stored}"),
            format!("encoded: {base64}"),
            format!("escaped: {}", own.replace('/', "%2F").replace('+', "%2B")),
            format!("json: {}", serde_json::to_string(own).unwrap()),
        ] {
            let hits = scanner.hits(text.as_bytes());
            assert!(
                hits.iter().any(|hit| hit.rule == KNOWN_SECRET),
                "{text}: {hits:?}"
            );
        }
        assert!(scanner.hits(b"nothing to see").is_empty());
        assert_eq!(format!("{scanner:?}"), "Scanner([redacted])");
    }

    #[test]
    fn file_names_that_must_not_be_public() {
        for (path, rule) in [
            (".env", "env-file"),
            ("deploy/.env.production", "env-file"),
            ("config/prod.env", "env-file"),
            ("home/.ssh/id_rsa", "ssh-key-file"),
            ("id_ed25519", "ssh-key-file"),
            ("certs/server.pem", "key-file"),
            ("tls.key", "key-file"),
            ("store.p12", "key-file"),
            ("a.pfx", "key-file"),
            ("release.keystore", "key-file"),
            ("app.jks", "key-file"),
            (".netrc", "credentials-file"),
            ("data/lore.db", "database-file"),
            ("lore-full-20260101-120000.sqlite", "database-file"),
            ("pre-restore-20260101-120000.sqlite", "database-file"),
            ("cache.sqlite3", "database-file"),
            ("dump.sql", "database-dump"),
            ("db/backup-2026.sql", "database-dump"),
        ] {
            assert_eq!(name_rule(path), Some(rule), "{path}");
        }
        for path in [
            ".env.example",
            "x/.env.sample",
            ".env.template",
            "src/db.rs",
            "id_rsa.pub",
            "schema.sql",
            "README.md",
            "keys.rs",
            "environment.ts",
        ] {
            assert_eq!(name_rule(path), None, "{path}");
        }
    }

    #[test]
    fn json_bodies_are_scanned_at_every_depth() {
        let scanner = Scanner::default();
        let token = ["gh", "p_", &b62(36, 50)].concat();
        let file = format!("API = \"{token}\"\n");
        let encoded = base64::engine::general_purpose::STANDARD.encode(&file);

        // The Contents API: the content is base64.
        let body = serde_json::json!({ "message": "add config", "content": encoded });
        let found = scanner.scan_json(&body, Some("src/config.py"));
        assert_eq!(
            found,
            vec![Finding {
                rule: "github-token",
                location: "`src/config.py` (field `content`), base64-decoded, line 1".into(),
            }]
        );
        // A tree: the name and the content of each entry.
        let body = serde_json::json!({ "tree": [
            { "path": "keys/id_rsa", "mode": "100644", "type": "blob", "content": "x" },
            { "path": "app.py", "mode": "100644", "type": "blob", "content": file },
            { "path": ".env", "mode": "100644", "type": "blob", "sha": null },
        ]});
        let found = scanner.scan_json(&body, None);
        assert_eq!(found.len(), 2, "{found:?}");
        assert_eq!(found[0].rule, "ssh-key-file");
        assert_eq!(found[0].location, "`keys/id_rsa`");
        assert_eq!(found[1].rule, "github-token");
        assert_eq!(
            found[1].location,
            "`app.py` (field `tree[1].content`), line 1"
        );
        // A gist: its files are keyed by name; a removed file is fine.
        let body = serde_json::json!({ "public": true, "files": {
            ".env": { "content": "A=1" },
            "old.env": null,
            "notes.md": { "content": format!("deep\n{token}") },
        }});
        let found = scanner.scan_json(&body, None);
        let rules: Vec<&str> = found.iter().map(|finding| finding.rule).collect();
        assert_eq!(rules, vec!["env-file", "github-token"], "{found:?}");
        assert_eq!(
            found[1].location,
            "`notes.md` (field `files.notes.md.content`), line 2"
        );
        for finding in found {
            assert!(!finding.location.contains(&token));
        }
        // Clean bodies find nothing.
        let body = serde_json::json!({ "title": "Fix", "body": "plain text", "draft": false });
        assert!(scanner.scan_json(&body, None).is_empty());
    }

    #[test]
    fn rest_targets_are_recognised() {
        use serde_json::json;
        assert_eq!(
            rest_target("GET", "/repos/o/r/contents/.env", None),
            RestTarget::Other
        );
        assert_eq!(
            rest_target(
                "PUT",
                "/repos/Me/Shop/contents/src/a%20b.py",
                Some(&json!({}))
            ),
            RestTarget::Repo {
                owner: "Me".into(),
                repo: "Shop".into(),
                file: Some("src/a b.py".into()),
                makes_public: false,
            }
        );
        assert_eq!(
            rest_target("PATCH", "/repos/o/r", Some(&json!({ "private": false }))),
            RestTarget::Repo {
                owner: "o".into(),
                repo: "r".into(),
                file: None,
                makes_public: true,
            }
        );
        assert_eq!(
            rest_target(
                "PATCH",
                "/repos/o/r",
                Some(&json!({ "visibility": "PUBLIC" }))
            ),
            RestTarget::Repo {
                owner: "o".into(),
                repo: "r".into(),
                file: None,
                makes_public: true,
            }
        );
        for (path, body, public) in [
            ("/user/repos", None, true),
            ("/user/repos", Some(json!({ "name": "x" })), true),
            ("/user/repos", Some(json!({ "private": false })), true),
            ("/user/repos", Some(json!({ "private": true })), false),
            (
                "/orgs/acme/repos",
                Some(json!({ "visibility": "internal" })),
                false,
            ),
            (
                "/orgs/acme/repos",
                Some(json!({ "visibility": "public", "private": true })),
                true,
            ),
            (
                "/repos/acme/template/generate",
                Some(json!({ "name": "x" })),
                true,
            ),
        ] {
            assert_eq!(
                rest_target("POST", path, body.as_ref()),
                RestTarget::CreatesRepo { public },
                "{path} {body:?}"
            );
        }
        assert_eq!(
            rest_target("POST", "/gists", Some(&json!({ "files": {} }))),
            RestTarget::Gist { public: true }
        );
        assert_eq!(
            rest_target("PATCH", "/gists/abc", Some(&json!({ "public": false }))),
            RestTarget::Gist { public: false }
        );
        assert_eq!(rest_target("POST", "/user/emails", None), RestTarget::Other);
    }

    type Asked = Arc<Mutex<Vec<String>>>;

    /// A mock of `GET /repos/{owner}/{repo}`: `public*` is public,
    /// `private*` private, `missing*` 404, `odd*` an answer without the
    /// field, anything else 500. A local mock, never GitHub.
    async fn repo_api() -> (String, Asked) {
        let asked: Asked = Arc::new(Mutex::new(Vec::new()));
        let router = Router::new()
            .route(
                "/repos/{owner}/{repo}",
                get(
                    |State(asked): State<Asked>,
                     axum::extract::Path((_, repo)): axum::extract::Path<(String, String)>| async move {
                        asked.lock().unwrap().push(repo.clone());
                        if repo.starts_with("public") {
                            (StatusCode::OK, r#"{"private":false}"#.to_string())
                        } else if repo.starts_with("private") {
                            (StatusCode::OK, r#"{"private":true}"#.to_string())
                        } else if repo.starts_with("missing") {
                            (StatusCode::NOT_FOUND, "{}".to_string())
                        } else if repo.starts_with("odd") {
                            (StatusCode::OK, r#"{"name":"odd"}"#.to_string())
                        } else {
                            (StatusCode::INTERNAL_SERVER_ERROR, String::new())
                        }
                    },
                ),
            )
            .with_state(asked.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            axum::serve(listener, router.into_make_service())
                .await
                .unwrap();
        });
        (base, asked)
    }

    #[tokio::test]
    async fn visibility_is_cached_and_fails_closed() {
        let (base, asked) = repo_api().await;
        let client = ops::client();
        let secret = Secret::new("visibility-test-credential");
        let cache = Visibility::default();
        let public = |repo: &'static str| {
            let (cache, client, secret, base) = (&cache, &client, &secret, &base);
            async move {
                cache
                    .is_public(client, base, &ops::GITHUB, secret, "owner", repo)
                    .await
            }
        };
        assert!(public("public-site").await);
        assert!(!public("private-shop").await);
        // Cached: asked once each.
        assert!(public("public-site").await);
        assert!(!public("private-shop.git").await);
        assert_eq!(asked.lock().unwrap().len(), 2);
        // Anything unclear is public, and asked again next time.
        for repo in ["missing-one", "odd-one", "failing-one"] {
            assert!(public(repo).await, "{repo}");
            assert!(public(repo).await, "{repo}");
        }
        assert_eq!(asked.lock().unwrap().len(), 8);
        // A name lore would not put in a URL is public without asking.
        assert!(public("bad name").await);
        assert_eq!(asked.lock().unwrap().len(), 8);
        // The other account has its own entry; forgetting drops both.
        assert!(
            !cache
                .is_public(
                    &client,
                    &base,
                    &ops::GITHUB_ORG,
                    &secret,
                    "owner",
                    "private-shop"
                )
                .await
        );
        assert_eq!(asked.lock().unwrap().len(), 9);
        cache.forget("Owner", "private-shop");
        assert!(!public("private-shop").await);
        assert_eq!(asked.lock().unwrap().len(), 10);
        // An API that cannot be reached: public.
        assert!(
            cache
                .is_public(
                    &client,
                    "http://127.0.0.1:1",
                    &ops::GITHUB,
                    &secret,
                    "owner",
                    "private-shop"
                )
                .await
        );
    }

    /// lore's own repository: no rule fires on any file it tracks (or is
    /// about to track), so the scan does not stand in the way of pushing
    /// lore itself. Skipped where git or the checkout is not available.
    #[test]
    fn lore_s_own_files_hold_no_finding() {
        let root = env!("CARGO_MANIFEST_DIR");
        let Ok(listed) = std::process::Command::new("git")
            .args([
                "ls-files",
                "-z",
                "--cached",
                "--others",
                "--exclude-standard",
            ])
            .current_dir(root)
            .output()
        else {
            return;
        };
        if !listed.status.success() {
            return;
        }
        let scanner = Scanner::default();
        let mut found = Vec::new();
        let mut files = 0;
        for path in listed.stdout.split(|byte| *byte == 0) {
            let path = String::from_utf8_lossy(path).into_owned();
            if path.is_empty() {
                continue;
            }
            let Ok(bytes) = std::fs::read(std::path::Path::new(root).join(&path)) else {
                continue;
            };
            files += 1;
            found.extend(scanner.scan_file(&bytes, &path));
        }
        assert!(files > 10, "only {files} files were listed");
        assert!(found.is_empty(), "{found:#?}");
    }
}
