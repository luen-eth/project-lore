//! Reading and changing a GitHub repository without a checkout:
//! `repo_tree`, `repo_read`, `repo_search` and `repo_commit`. They are
//! conveniences over the GitHub REST API for clients that have no shell,
//! such as chat web apps, and go through exactly the gates of the `github`
//! and `github_org` tools: a real session, the vault, the kill switch, the
//! agent's level (`read` for the three read tools, `full` for
//! `repo_commit`), the credential added here on the server side, every
//! stored secret redacted from the answer, one `ops_log` row and one
//! activity note per tool call. Every upstream request goes through
//! `ops::call_with_limit`.
//!
//! `repo_commit` writes through the Git Data API. When the repository is
//! public (or its visibility cannot be read) every change is scanned by the
//! leak scan before anything is sent, and one finding refuses the whole
//! commit. The blobs and the tree it creates afterwards carry only what was
//! scanned, so they are not scanned a second time.

use std::{collections::HashMap, time::Instant};

use axum::http::request::Parts;
use base64::Engine;
use rmcp::schemars;
use serde::Deserialize;
use serde_json::{Value, json};

use super::{Lore, agent_of, blocking, internal, session_agent};
use crate::{auth::SHARED_AGENT, leakscan, ops};

/// The longest path `repo_tree`, `repo_read` and `repo_commit` accept.
const MAX_PATH_CHARS: usize = 4096;
/// The longest ref name accepted.
const MAX_REF_CHARS: usize = 255;
/// `repo_tree`'s depth: default and maximum.
const TREE_DEPTH: (usize, usize) = (2, 10);
/// `repo_tree`'s entry limit: default and maximum.
const TREE_LIMIT: (usize, usize) = (300, 2000);
/// How many tree listings `repo_tree` makes when GitHub cannot list the
/// whole tree in one answer.
const MAX_TREE_CALLS: usize = 60;
/// How many files one `repo_read` call reads.
const MAX_READ_PATHS: usize = 10;
/// Files larger than this are reported by size only.
const MAX_READ_BYTES: u64 = 1024 * 1024;
/// `repo_search`'s result limit: default and maximum.
const SEARCH_LIMIT: (usize, usize) = (20, 50);
/// GitHub's own limit on a code search query.
const MAX_QUERY_CHARS: usize = 256;
/// How many changes one commit carries.
const MAX_CHANGES: usize = 50;
/// The longest commit message.
const MAX_MESSAGE_CHARS: usize = 2000;
/// The most content one commit carries, all files together.
const MAX_COMMIT_BYTES: usize = 8 * 1024 * 1024;
/// Where GitHub shows a repository; the compare link points there.
const GITHUB_WEB: &str = "https://github.com";

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RepoTreeArgs {
    /// Session id returned by `hello` for this chat.
    pub session_id: String,
    /// The repository as `owner/name`, e.g. `octocat/hello-world`.
    pub repo: String,
    /// Which GitHub credential to use: `personal` (the default) or
    /// `organization`.
    pub account: Option<String>,
    /// Branch, tag or commit sha. Omit for the default branch.
    pub r#ref: Option<String>,
    /// The directory to list, e.g. `src/server`. Omit for the root.
    pub path: Option<String>,
    /// How many levels below `path` to list (default 2, at most 10).
    pub depth: Option<u32>,
    /// The most entries to list (default 300, at most 2000).
    pub limit: Option<u32>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RepoReadArgs {
    /// Session id returned by `hello` for this chat.
    pub session_id: String,
    /// The repository as `owner/name`, e.g. `octocat/hello-world`.
    pub repo: String,
    /// Which GitHub credential to use: `personal` (the default) or
    /// `organization`.
    pub account: Option<String>,
    /// The files to read: 1 to 10 paths from the repository root, e.g.
    /// ["src/main.rs", "Cargo.toml"].
    pub paths: Vec<String>,
    /// Branch, tag or commit sha. Omit for the default branch.
    pub r#ref: Option<String>,
    /// With a single path: the first line to show (1-based).
    pub start_line: Option<u32>,
    /// With a single path: the last line to show.
    pub end_line: Option<u32>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RepoSearchArgs {
    /// Session id returned by `hello` for this chat.
    pub session_id: String,
    /// The repository as `owner/name`, e.g. `octocat/hello-world`.
    pub repo: String,
    /// Which GitHub credential to use: `personal` (the default) or
    /// `organization`.
    pub account: Option<String>,
    /// What to look for: words or an identifier, in GitHub code search
    /// syntax. The repository is added by lore.
    pub query: String,
    /// Only files under this directory, e.g. `src`.
    pub path: Option<String>,
    /// Only files with this extension, e.g. `rs`.
    pub extension: Option<String>,
    /// The most results to list (default 20, at most 50).
    pub limit: Option<u32>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RepoCommitArgs {
    /// Session id returned by `hello` for this chat.
    pub session_id: String,
    /// The repository as `owner/name`, e.g. `octocat/hello-world`.
    pub repo: String,
    /// Which GitHub credential to use: `personal` (the default) or
    /// `organization`.
    pub account: Option<String>,
    /// The branch to commit to. It must exist, unless `create_from` is
    /// given; the commit lands on it directly.
    pub branch: String,
    /// The commit message (1 to 2000 characters).
    pub message: String,
    /// 1 to 50 changes, all in one commit. Each is {"path", "content"}
    /// (text, written as is), {"path", "content_base64"} (bytes) or
    /// {"path", "delete": true}.
    pub changes: Vec<FileChange>,
    /// Creates `branch` from this branch, tag or commit; the branch must
    /// not exist yet.
    pub create_from: Option<String>,
    /// The commit sha you expect the branch to be at (from `repo_tree` or
    /// `repo_read`). When the branch has moved, nothing is written.
    pub expected_head: Option<String>,
}

/// One change of a `repo_commit`.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct FileChange {
    /// The file's path from the repository root, e.g. `src/main.rs`.
    pub path: String,
    /// The new text of the file, written as is.
    pub content: Option<String>,
    /// The new bytes of the file, base64-encoded.
    pub content_base64: Option<String>,
    /// True to delete the file.
    pub delete: Option<bool>,
}

/// One call of the four tools, as the server hands it over.
pub enum RepoCall {
    Tree(RepoTreeArgs),
    Read(RepoReadArgs),
    Search(RepoSearchArgs),
    Commit(RepoCommitArgs),
}

impl RepoCall {
    fn method(&self) -> &'static str {
        match self {
            RepoCall::Commit(_) => "POST",
            _ => "GET",
        }
    }

    fn common(&self) -> (&str, &str, Option<&str>) {
        let (session, repo, account) = match self {
            RepoCall::Tree(args) => (&args.session_id, &args.repo, &args.account),
            RepoCall::Read(args) => (&args.session_id, &args.repo, &args.account),
            RepoCall::Search(args) => (&args.session_id, &args.repo, &args.account),
            RepoCall::Commit(args) => (&args.session_id, &args.repo, &args.account),
        };
        (session.trim(), repo.trim(), account.as_deref())
    }

    /// The readable form the operations log keeps, e.g.
    /// `repo_read owner/x:src/main.rs@main`. Never a search query or any
    /// file content.
    fn log_path(&self) -> String {
        let (_, repo, _) = self.common();
        let at = |reference: &Option<String>| match reference {
            Some(reference) => format!("@{}", reference.trim()),
            None => String::new(),
        };
        match self {
            RepoCall::Tree(args) => format!(
                "repo_tree {repo}:{}{}",
                args.path.as_deref().unwrap_or("").trim(),
                at(&args.r#ref)
            ),
            RepoCall::Read(args) => {
                format!(
                    "repo_read {repo}:{}{}",
                    args.paths.join(","),
                    at(&args.r#ref)
                )
            }
            RepoCall::Search(args) => {
                let mut path = format!("repo_search {repo}");
                if let Some(prefix) = &args.path {
                    path.push_str(&format!(" path:{}", prefix.trim()));
                }
                if let Some(extension) = &args.extension {
                    path.push_str(&format!(" extension:{}", extension.trim()));
                }
                path
            }
            RepoCall::Commit(args) => format!(
                "repo_commit {repo}@{} ({} change{})",
                args.branch.trim(),
                args.changes.len(),
                if args.changes.len() == 1 { "" } else { "s" }
            ),
        }
    }

    /// The checked arguments, or why they are not valid.
    fn plan(self) -> Result<Plan, String> {
        match self {
            RepoCall::Tree(args) => Ok(Plan::Tree {
                reference: optional_ref("ref", args.r#ref.as_deref())?,
                path: directory(args.path.as_deref())?,
                depth: bounded("depth", args.depth, TREE_DEPTH)?,
                limit: bounded("limit", args.limit, TREE_LIMIT)?,
            }),
            RepoCall::Read(args) => {
                if args.paths.is_empty() || args.paths.len() > MAX_READ_PATHS {
                    return Err(format!(
                        "paths must name 1 to {MAX_READ_PATHS} files (got {})",
                        args.paths.len()
                    ));
                }
                let paths = args
                    .paths
                    .iter()
                    .map(|path| file_path(path))
                    .collect::<Result<Vec<_>, _>>()?;
                let lines = match (args.start_line, args.end_line) {
                    (None, None) => None,
                    _ if paths.len() > 1 => {
                        return Err("start_line and end_line need a single path".into());
                    }
                    (start, end) => {
                        let start = start.unwrap_or(1).max(1) as usize;
                        let end = end.map(|end| end as usize);
                        if end.is_some_and(|end| end < start) {
                            return Err("end_line must not be before start_line".into());
                        }
                        Some((start, end))
                    }
                };
                Ok(Plan::Read {
                    reference: optional_ref("ref", args.r#ref.as_deref())?,
                    paths,
                    lines,
                })
            }
            RepoCall::Search(args) => {
                let query = args.query.trim().to_string();
                if query.is_empty() {
                    return Err("query must not be empty".into());
                }
                if query.chars().count() > MAX_QUERY_CHARS || query.chars().any(char::is_control) {
                    return Err(format!(
                        "query must be one line of at most {MAX_QUERY_CHARS} characters"
                    ));
                }
                let path = match args.path.as_deref() {
                    Some(path) => Some(directory(Some(path))?).filter(|path| !path.is_empty()),
                    None => None,
                };
                let extension = match args.extension.as_deref().map(str::trim) {
                    None | Some("") => None,
                    Some(extension) => {
                        let extension = extension.trim_start_matches('.');
                        if extension.is_empty()
                            || extension.len() > 32
                            || !extension
                                .chars()
                                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'))
                        {
                            return Err("extension must be letters and digits, e.g. `rs`".into());
                        }
                        Some(extension.to_string())
                    }
                };
                Ok(Plan::Search {
                    query,
                    path,
                    extension,
                    limit: bounded("limit", args.limit, SEARCH_LIMIT)?,
                })
            }
            RepoCall::Commit(args) => Ok(Plan::Commit(commit_plan(args)?)),
        }
    }
}

/// The checked arguments of one call.
enum Plan {
    Tree {
        reference: Option<String>,
        path: String,
        depth: usize,
        limit: usize,
    },
    Read {
        reference: Option<String>,
        paths: Vec<String>,
        lines: Option<(usize, Option<usize>)>,
    },
    Search {
        query: String,
        path: Option<String>,
        extension: Option<String>,
        limit: usize,
    },
    Commit(CommitPlan),
}

struct CommitPlan {
    branch: String,
    message: String,
    /// Path and new bytes; `None` deletes the file.
    changes: Vec<(String, Option<Vec<u8>>)>,
    create_from: Option<String>,
    expected_head: Option<String>,
}

fn commit_plan(args: RepoCommitArgs) -> Result<CommitPlan, String> {
    let branch = git_ref("branch", &args.branch)?;
    let message = args.message.trim_end().to_string();
    if message.trim().is_empty() || message.chars().count() > MAX_MESSAGE_CHARS {
        return Err(format!(
            "message must be 1 to {MAX_MESSAGE_CHARS} characters"
        ));
    }
    if args.changes.is_empty() || args.changes.len() > MAX_CHANGES {
        return Err(format!(
            "changes must hold 1 to {MAX_CHANGES} changes (got {})",
            args.changes.len()
        ));
    }
    let mut changes: Vec<(String, Option<Vec<u8>>)> = Vec::new();
    let mut total = 0usize;
    for change in args.changes {
        let path = file_path(&change.path)?;
        if changes.iter().any(|(seen, _)| *seen == path) {
            return Err(format!("`{path}` is changed twice; give each path once"));
        }
        let delete = change.delete.unwrap_or(false);
        let bytes = match (change.content, change.content_base64, delete) {
            (Some(text), None, false) => Some(text.into_bytes()),
            (None, Some(encoded), false) => {
                let compact: String = encoded
                    .chars()
                    .filter(|c| !c.is_ascii_whitespace())
                    .collect();
                Some(
                    base64::engine::general_purpose::STANDARD
                        .decode(compact)
                        .map_err(|_| format!("content_base64 of `{path}` is not valid base64"))?,
                )
            }
            (None, None, true) => None,
            _ => {
                return Err(format!(
                    "the change to `{path}` must have exactly one of `content`, \
                     `content_base64` or `delete: true`"
                ));
            }
        };
        total += bytes.as_ref().map_or(0, Vec::len);
        if total > MAX_COMMIT_BYTES {
            return Err("the changes hold more than 8 MiB of content; split the commit".into());
        }
        changes.push((path, bytes));
    }
    let expected_head = match args.expected_head.as_deref().map(str::trim) {
        None | Some("") => None,
        Some(sha) => {
            let sha = sha.to_ascii_lowercase();
            if !(7..=64).contains(&sha.len()) || !sha.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err("expected_head must be a commit sha (7 to 40 hex digits)".into());
            }
            Some(sha)
        }
    };
    Ok(CommitPlan {
        branch,
        message,
        changes,
        create_from: optional_ref("create_from", args.create_from.as_deref())?,
        expected_head,
    })
}

/// `owner/name`, also from `https://github.com/owner/name(.git)`.
fn repository(repo: &str) -> Result<(String, String), String> {
    let trimmed = repo.trim().trim_end_matches('/');
    let trimmed = trimmed
        .strip_prefix("https://github.com/")
        .unwrap_or(trimmed);
    let trimmed = trimmed.strip_suffix(".git").unwrap_or(trimmed);
    let plain = |name: &str| {
        !name.is_empty()
            && name.len() <= 100
            && name != "."
            && name != ".."
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    };
    match trimmed.split_once('/') {
        Some((owner, name)) if plain(owner) && plain(name) => {
            Ok((owner.to_string(), name.to_string()))
        }
        _ => Err("repo must be `owner/name`, e.g. `octocat/hello-world`".into()),
    }
}

/// The provider an `account` names, and whether it was named.
fn account(account: Option<&str>) -> Result<(ops::Provider, bool), String> {
    match account
        .map(|value| value.trim().to_ascii_lowercase())
        .as_deref()
    {
        None | Some("") => Ok((ops::GITHUB, false)),
        Some("personal" | "github") => Ok((ops::GITHUB, true)),
        Some("organization" | "organisation" | "org" | "github_org") => Ok((ops::GITHUB_ORG, true)),
        Some(_) => Err("account must be `personal` or `organization`".into()),
    }
}

/// A value between 1 and `max`, `default` when omitted.
fn bounded(
    name: &str,
    value: Option<u32>,
    (default, max): (usize, usize),
) -> Result<usize, String> {
    match value {
        None => Ok(default),
        Some(value) if value >= 1 && value as usize <= max => Ok(value as usize),
        Some(_) => Err(format!("{name} must be between 1 and {max}")),
    }
}

/// A file path from the repository root: no leading `/`, no `.`, `..` or
/// empty segment, no `.git` segment, no backslash or control character, at
/// most 4096 characters.
fn file_path(path: &str) -> Result<String, String> {
    if path.is_empty() {
        return Err("a path must not be empty".into());
    }
    if path.chars().count() > MAX_PATH_CHARS {
        return Err(format!(
            "a path must be at most {MAX_PATH_CHARS} characters"
        ));
    }
    let shown: String = path.chars().take(200).collect();
    if path.starts_with('/') {
        return Err(format!(
            "`{shown}` starts with `/`; give the path from the repository root"
        ));
    }
    if path.contains('\\') || path.chars().any(char::is_control) {
        return Err(format!(
            "`{shown}` holds a backslash or a control character"
        ));
    }
    for segment in path.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err(format!("`{shown}` has an empty, `.` or `..` segment"));
        }
        if segment.eq_ignore_ascii_case(".git") {
            return Err(format!("`{shown}` reaches into `.git`"));
        }
    }
    Ok(path.to_string())
}

/// A directory: `""` (or `/`, or nothing) for the root, else a file path
/// with any trailing `/` removed.
fn directory(path: Option<&str>) -> Result<String, String> {
    let path = path.unwrap_or("").trim();
    let path = path.trim_end_matches('/');
    if path.is_empty() {
        return Ok(String::new());
    }
    file_path(path)
}

/// A branch, tag or commit name as git allows it.
fn git_ref(name: &str, value: &str) -> Result<String, String> {
    let value = value.trim();
    let valid = !value.is_empty()
        && value.chars().count() <= MAX_REF_CHARS
        && !value.chars().any(|c| {
            c.is_whitespace()
                || c.is_control()
                || matches!(c, '~' | '^' | ':' | '?' | '*' | '[' | '\\')
        })
        && !value.contains("..")
        && !value.contains("@{")
        && !value.contains("//")
        && !value.starts_with(['/', '-', '.'])
        && !value.ends_with(['/', '.'])
        && !value.ends_with(".lock");
    if valid {
        Ok(value.to_string())
    } else {
        Err(format!(
            "{name} must be a branch, tag or commit name as git allows it"
        ))
    }
}

fn optional_ref(name: &str, value: Option<&str>) -> Result<Option<String>, String> {
    match value.map(str::trim) {
        None | Some("") => Ok(None),
        Some(value) => git_ref(name, value).map(Some),
    }
}

/// A path for a URL: every segment percent-encoded except the unreserved
/// characters, the `/` between them kept.
fn encode_path(path: &str) -> String {
    path.split('/')
        .map(|segment| {
            let mut out = String::with_capacity(segment.len());
            for byte in segment.bytes() {
                if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
                    out.push(byte as char);
                } else {
                    out.push_str(&format!("%{byte:02X}"));
                }
            }
            out
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// Why a call failed: the sentence for the agent (and the log), and
/// whether GitHub answered 404, which may mean the credential cannot see
/// the repository.
#[derive(Debug)]
struct Failure {
    message: String,
    not_found: bool,
    /// The upstream HTTP status when GitHub refused the call, 0 otherwise.
    status: u16,
    /// GitHub's own short reason (its `message`), for the log row.
    reason: String,
}

impl Failure {
    fn plain(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            not_found: false,
            status: 0,
            reason: String::new(),
        }
    }

    /// GitHub's `message`, one line and short, already redacted.
    fn reason_of(answer: &Value) -> String {
        answer
            .get("message")
            .and_then(Value::as_str)
            .map(|message| super::clip(&super::log_text(message, 200), 200))
            .unwrap_or_default()
    }

    /// GitHub's refusal in plain words, with its own message (already
    /// redacted) when it gave one.
    fn http(status: u16, answer: &Value, what: &str, provider: &ops::Provider) -> Self {
        let said = answer
            .get("message")
            .and_then(Value::as_str)
            .map(|message| super::clip(&super::log_text(message, 300), 300))
            .unwrap_or_default();
        let said = if said.is_empty() {
            String::new()
        } else {
            format!(": {said}")
        };
        let label = provider.label;
        let message = match status {
            401 => format!(
                "GitHub did not accept the {label} credential (HTTP 401{said}); the \
                 administrator must check it"
            ),
            403 => format!(
                "GitHub refused {what} (HTTP 403{said}). The {label} credential may lack \
                 permission for it, the branch may be protected, or a rate limit was hit"
            ),
            404 => format!(
                "GitHub answered 404 for {what}: it does not exist, or the {label} \
                 credential cannot see it"
            ),
            409 => format!("GitHub refused {what} (HTTP 409{said})"),
            422 => format!("GitHub refused {what} (HTTP 422{said})"),
            _ => format!("GitHub answered HTTP {status} for {what}{said}"),
        };
        Self {
            message,
            not_found: status == 404,
            status,
            reason: Self::reason_of(answer),
        }
    }
}

/// One entry of a git tree.
#[derive(Debug, Clone)]
struct TreeEntry {
    path: String,
    mode: String,
    kind: String,
    size: Option<u64>,
    sha: String,
}

/// A ref resolved to its commit.
struct Resolved {
    /// The name asked for, or the default branch.
    name: String,
    commit: String,
    tree: String,
}

/// The upstream side of one tool call: where to send, with which
/// credential, and the redaction for every answer.
struct Upstream<'a> {
    http: &'a reqwest::Client,
    base: String,
    granted: ops::Authorized,
    guard: ops::Guard,
    provider: ops::Provider,
    owner: String,
    name: String,
    /// The status of the last answer, for the log row.
    status: u16,
    /// The start of the last refused answer (redacted, one line), for the
    /// log row when GitHub gave no `message`.
    excerpt: String,
    /// Which step of `repo_commit` is running, for the log row.
    step: &'static str,
}

impl Upstream<'_> {
    fn repo_path(&self, rest: &str) -> String {
        format!("/repos/{}/{}{rest}", self.owner, self.name)
    }

    /// One request through `ops::call_with_limit`: the status, the answer
    /// as JSON (`Null` when it is not JSON or was cut), and whether it was
    /// read whole.
    async fn send(
        &mut self,
        method: &str,
        path: String,
        query: &[(&str, String)],
        body: Option<Value>,
    ) -> Result<(u16, Value, bool), Failure> {
        let query = (!query.is_empty()).then(|| {
            query
                .iter()
                .map(|(key, value)| ((*key).to_string(), Value::from(value.clone())))
                .collect()
        });
        let request = ops::OpsRequest {
            provider: self.provider,
            method: method.into(),
            path,
            query,
            body,
        };
        let response = ops::call_with_limit(
            self.http,
            &self.base,
            &self.granted.secret,
            &self.guard,
            &request,
            ops::MAX_RESPONSE_BYTES,
        )
        .await
        .map_err(|error| match error {
            ops::OpsError::Invalid(reason) => Failure::plain(reason),
            ops::OpsError::Transport(reason) => Failure::plain(format!(
                "{} could not be reached: {reason}",
                self.provider.label
            )),
        })?;
        self.status = response.status;
        self.excerpt = if (200..300).contains(&response.status) {
            String::new()
        } else {
            super::clip(&super::log_text(&response.body, 200), 200)
        };
        let value = if response.truncated {
            Value::Null
        } else {
            serde_json::from_str(&response.body).unwrap_or(Value::Null)
        };
        Ok((response.status, value, !response.truncated))
    }

    /// `send`, and a 2xx JSON answer or the failure.
    async fn json(
        &mut self,
        method: &str,
        path: String,
        query: &[(&str, String)],
        body: Option<Value>,
        what: &str,
    ) -> Result<Value, Failure> {
        let (status, value, whole) = self.send(method, path, query, body).await?;
        if !(200..300).contains(&status) {
            return Err(Failure::http(status, &value, what, &self.provider));
        }
        if !whole || value.is_null() {
            return Err(Failure::plain(format!(
                "GitHub's answer for {what} was too large or not JSON"
            )));
        }
        Ok(value)
    }

    /// A branch, tag or commit (the default branch when `None`) resolved
    /// to its commit and tree.
    async fn resolve(&mut self, reference: Option<&str>) -> Result<Resolved, Failure> {
        let name = match reference {
            Some(name) => name.to_string(),
            None => {
                let repo = self
                    .json("GET", self.repo_path(""), &[], None, "the repository")
                    .await?;
                repo.get("default_branch")
                    .and_then(Value::as_str)
                    .map(str::to_string)
                    .ok_or_else(|| Failure::plain("GitHub named no default branch"))?
            }
        };
        let (status, value, _) = self
            .send(
                "GET",
                self.repo_path("/commits"),
                &[("sha", name.clone()), ("per_page", "1".into())],
                None,
            )
            .await?;
        let what = format!("ref `{name}`");
        match status {
            200..=299 => {}
            409 => {
                return Err(Failure::plain(
                    "the repository is empty: it has no commit yet",
                ));
            }
            404 | 422 => {
                return Err(Failure {
                    message: format!(
                        "GitHub found no commit for {what}: it does not exist, or the {} \
                         credential cannot see the repository",
                        self.provider.label
                    ),
                    not_found: status == 404,
                    status,
                    reason: Failure::reason_of(&value),
                });
            }
            _ => return Err(Failure::http(status, &value, &what, &self.provider)),
        }
        let first = value
            .get(0)
            .ok_or_else(|| Failure::plain(format!("GitHub found no commit at {what}")))?;
        let commit = first.get("sha").and_then(Value::as_str);
        let tree = first.pointer("/commit/tree/sha").and_then(Value::as_str);
        match (commit, tree) {
            (Some(commit), Some(tree)) => Ok(Resolved {
                name,
                commit: commit.to_string(),
                tree: tree.to_string(),
            }),
            _ => Err(Failure::plain(format!(
                "GitHub's answer for {what} named no commit"
            ))),
        }
    }

    /// The entries of one tree, recursively or one level, and whether the
    /// list is whole (GitHub cuts very large trees; lore reads 2 MiB).
    async fn tree(
        &mut self,
        sha: &str,
        recursive: bool,
    ) -> Result<(Vec<TreeEntry>, bool), Failure> {
        let query: Vec<(&str, String)> = if recursive {
            vec![("recursive", "1".into())]
        } else {
            Vec::new()
        };
        let (status, value, whole) = self
            .send(
                "GET",
                self.repo_path(&format!("/git/trees/{}", encode_path(sha))),
                &query,
                None,
            )
            .await?;
        if !(200..300).contains(&status) {
            return Err(Failure::http(status, &value, "the tree", &self.provider));
        }
        let Some(items) = value.get("tree").and_then(Value::as_array) else {
            return Ok((Vec::new(), false));
        };
        let entries = items
            .iter()
            .filter_map(|item| {
                Some(TreeEntry {
                    path: item.get("path")?.as_str()?.to_string(),
                    mode: item.get("mode")?.as_str()?.to_string(),
                    kind: item.get("type")?.as_str()?.to_string(),
                    size: item.get("size").and_then(Value::as_u64),
                    sha: item.get("sha")?.as_str()?.to_string(),
                })
            })
            .collect();
        let truncated = value.get("truncated").and_then(Value::as_bool) == Some(true);
        Ok((entries, whole && !truncated))
    }
}

impl Lore {
    /// One call of the four repository tools end to end: the session, the
    /// arguments, the access check, the upstream calls, the log row and
    /// the activity note. `Ok` is the answer; `Err` is why it did not
    /// happen.
    pub(super) async fn repo_tool(&self, parts: &Parts, call: RepoCall) -> Result<String, String> {
        let agent = agent_of(parts);
        let shared = agent == SHARED_AGENT;
        let method = call.method();
        let log_path = call.log_path();
        let this = self.clone();
        let token_agent = agent.clone();
        let refused_path = log_path.clone();
        let prepared = blocking(move || {
            let log_path = refused_path;
            let (session_id, repo, account_name) = call.common();
            let session = this.require_session(session_id, &token_agent, shared)?;
            let actor = session_agent(&token_agent, &session).to_string();
            let label = ops::acting_as(&token_agent, &actor);
            let checked = account(account_name).and_then(|(provider, named)| {
                let (owner, name) = repository(repo)?;
                Ok((provider, named, owner, name))
            });
            let provider = checked.as_ref().map_or(ops::GITHUB, |checked| checked.0);
            let ready = checked.and_then(|checked| Ok((checked, call.plan()?)));
            let ((provider, named, owner, name), plan) = match ready {
                Ok(ready) => ready,
                Err(error) => {
                    this.log_op_call(
                        &label,
                        &actor,
                        Some(&session.id),
                        provider,
                        method,
                        &log_path,
                        "error",
                        &error,
                        0,
                        0,
                    );
                    return Err(error);
                }
            };
            match ops::authorize(
                &this.db,
                this.vault.as_ref(),
                &token_agent,
                &actor,
                provider,
                method,
            ) {
                Ok(granted) => {
                    let guard = match this.vault.as_ref() {
                        Some(key) => this
                            .guard
                            .with_secrets(&ops::stored_secrets(&this.db, key).map_err(internal)?),
                        None => this.guard.clone(),
                    };
                    let scan =
                        method != "GET" && this.db.leak_scan_settings().map_err(internal)?.scan;
                    Ok(Prepared {
                        session_id: session.id,
                        actor,
                        label,
                        provider,
                        named,
                        owner,
                        name,
                        plan,
                        granted,
                        guard,
                        scan,
                    })
                }
                Err(denied) => {
                    this.log_op_call(
                        &label,
                        &actor,
                        Some(&session.id),
                        provider,
                        method,
                        &log_path,
                        "denied",
                        &denied.reason,
                        0,
                        0,
                    );
                    Err(denied.reason)
                }
            }
        })
        .await?;

        let Prepared {
            session_id,
            actor,
            label,
            provider,
            named,
            owner,
            name,
            plan,
            granted,
            guard,
            scan,
        } = prepared;
        let base = match &self.github_api_base {
            Some(base) => base.clone(),
            None => granted.api_base.clone(),
        };
        let mut upstream = Upstream {
            http: &self.http,
            base,
            granted,
            guard,
            provider,
            owner,
            name,
            status: 0,
            excerpt: String::new(),
            step: "",
        };
        let started = Instant::now();
        let outcome = match plan {
            Plan::Tree {
                reference,
                path,
                depth,
                limit,
            } => repo_tree(&mut upstream, reference.as_deref(), &path, depth, limit).await,
            Plan::Read {
                reference,
                paths,
                lines,
            } => repo_read(&mut upstream, reference.as_deref(), &paths, lines).await,
            Plan::Search {
                query,
                path,
                extension,
                limit,
            } => {
                repo_search(
                    &mut upstream,
                    &query,
                    path.as_deref(),
                    extension.as_deref(),
                    limit,
                )
                .await
            }
            Plan::Commit(plan) => match self.leak_check(&upstream, &plan, scan).await {
                Ok(()) => repo_commit(&mut upstream, &plan).await,
                Err(refusal) => {
                    let this = self.clone();
                    let (session_id, actor, label, path) = (
                        session_id.clone(),
                        actor.clone(),
                        label.clone(),
                        log_path.clone(),
                    );
                    let _ = blocking(move || {
                        this.log_op_call(
                            &label,
                            &actor,
                            Some(&session_id),
                            provider,
                            method,
                            &path,
                            "denied",
                            &refusal.detail,
                            0,
                            0,
                        );
                        Ok(())
                    })
                    .await;
                    return Err(refusal.message);
                }
            },
        };
        let outcome = match outcome {
            Err(mut failure) if failure.not_found => {
                let mut hint = None;
                if !named && provider.id == ops::GITHUB.id {
                    hint = self
                        .organization_hint(&mut upstream, &agent, &actor, &label, &session_id)
                        .await;
                }
                // Otherwise, which owners the account covers, when the
                // repository's owner is not one of them.
                if hint.is_none() {
                    let caller = super::accounts::Caller {
                        token_agent: &agent,
                        actor: &actor,
                        label: &label,
                        session_id: Some(&session_id),
                    };
                    hint = self
                        .owner_hint(
                            provider,
                            &upstream.owner,
                            &caller,
                            super::accounts::Style::Repo,
                        )
                        .await
                        .map(|hint| format!(" {hint}"));
                }
                if let Some(hint) = hint {
                    failure.message.push_str(&hint);
                }
                Err(failure)
            }
            other => other,
        };
        let mut status = upstream.status as i64;
        let (went, detail) = match &outcome {
            Ok(_) => ("ok", String::new()),
            // Refused upstream: the status and GitHub's short reason (and
            // the step of `repo_commit`), so the log tells a 403 from a 422.
            Err(failure) if failure.status != 0 => {
                status = failure.status as i64;
                let mut reason = [&failure.reason, &upstream.excerpt]
                    .into_iter()
                    .find(|reason| !reason.is_empty())
                    .cloned()
                    .unwrap_or_else(|| "no reason given".into());
                if !upstream.step.is_empty() {
                    reason.push_str(&format!(" (step: {})", upstream.step));
                }
                ("error", reason)
            }
            Err(failure) => ("error", failure.message.clone()),
        };
        let this = self.clone();
        let _ = blocking(move || {
            this.log_op_call(
                &label,
                &actor,
                Some(&session_id),
                provider,
                method,
                &log_path,
                went,
                &detail,
                status,
                started.elapsed().as_millis() as i64,
            );
            Ok(())
        })
        .await;
        outcome.map_err(|failure| failure.message)
    }

    /// When the personal credential cannot see the repository but the
    /// organization's can, the sentence that says so; lore never switches
    /// accounts by itself. The organization's credential is used only
    /// when this agent may read through it, and that look is logged.
    async fn organization_hint(
        &self,
        upstream: &mut Upstream<'_>,
        agent: &str,
        actor: &str,
        label: &str,
        session_id: &str,
    ) -> Option<String> {
        let status = upstream.status;
        let (seen, _, _) = upstream
            .send("GET", upstream.repo_path(""), &[], None)
            .await
            .ok()?;
        upstream.status = status;
        if seen != 404 {
            return None;
        }
        let this = self.clone();
        let (token_agent, session_actor) = (agent.to_string(), actor.to_string());
        let granted = blocking(move || {
            Ok(ops::authorize(
                &this.db,
                this.vault.as_ref(),
                &token_agent,
                &session_actor,
                ops::GITHUB_ORG,
                "GET",
            )
            .ok())
        })
        .await
        .ok()??;
        let base = match &self.github_api_base {
            Some(base) => base.clone(),
            None => granted.api_base.clone(),
        };
        let path = upstream.repo_path("");
        let request = ops::OpsRequest {
            provider: ops::GITHUB_ORG,
            method: "GET".into(),
            path,
            query: None,
            body: None,
        };
        let started = Instant::now();
        let answer = ops::call(
            &self.http,
            &base,
            &granted.secret,
            &upstream.guard,
            &request,
        )
        .await;
        let org_status = answer.as_ref().map_or(0, |response| response.status);
        let this = self.clone();
        let (actor, label, session_id) =
            (actor.to_string(), label.to_string(), session_id.to_string());
        let log_path = format!("repo_access {}/{}", upstream.owner, upstream.name);
        let _ = blocking(move || {
            this.log_op_call(
                &label,
                &actor,
                Some(&session_id),
                ops::GITHUB_ORG,
                "GET",
                &log_path,
                if org_status == 0 { "error" } else { "ok" },
                "",
                org_status as i64,
                started.elapsed().as_millis() as i64,
            );
            Ok(())
        })
        .await;
        (org_status == 200).then(|| {
            " The organization account's credential can see this repository: call again with \
             `account: \"organization\"`."
                .to_string()
        })
    }

    /// The leak scan for one commit, before anything is written: when the
    /// repository is public (or its visibility cannot be read), every
    /// written file's name and content, the message and the branch name.
    async fn leak_check(
        &self,
        upstream: &Upstream<'_>,
        plan: &CommitPlan,
        scan: bool,
    ) -> Result<(), leakscan::Refusal> {
        if !scan {
            return Ok(());
        }
        let public = leakscan::visibility()
            .is_public(
                upstream.http,
                &upstream.base,
                &upstream.provider,
                &upstream.granted.secret,
                &upstream.owner,
                &upstream.name,
            )
            .await;
        if !public {
            return Ok(());
        }
        let scanner = leakscan::Scanner::new(&upstream.guard);
        let findings = commit_findings(&scanner, plan);
        if findings.is_empty() {
            return Ok(());
        }
        let list = leakscan::summarize(&findings);
        Err(leakscan::Refusal {
            message: format!(
                "lore refused this commit: it would put a secret or a private file into a \
                 public GitHub repository ({list}). lore does not let secrets or private files \
                 reach a public repository: remove it, or ask the user. Nothing was written."
            ),
            detail: format!("leak scan: {list}"),
        })
    }
}

/// What the leak scan finds in a commit: the name rules and the content
/// rules for every file it writes, and the content rules for the message
/// and the branch name. Deletions publish nothing.
fn commit_findings(scanner: &leakscan::Scanner, plan: &CommitPlan) -> Vec<leakscan::Finding> {
    let mut findings = Vec::new();
    for (path, bytes) in &plan.changes {
        let Some(bytes) = bytes else {
            continue;
        };
        let label = scanner.label(path);
        if let Some(rule) = leakscan::name_rule(path) {
            findings.push(leakscan::Finding {
                rule,
                location: label.clone(),
            });
        }
        findings.extend(scanner.scan_content(bytes, &label));
    }
    findings.extend(scanner.scan_content(plan.message.as_bytes(), "the commit message"));
    findings.extend(scanner.scan_content(plan.branch.as_bytes(), "the branch name"));
    leakscan::dedup(findings)
}

/// What the blocking part of a call hands the async part.
struct Prepared {
    session_id: String,
    actor: String,
    label: String,
    provider: ops::Provider,
    named: bool,
    owner: String,
    name: String,
    plan: Plan,
    granted: ops::Authorized,
    guard: ops::Guard,
    scan: bool,
}

async fn repo_tree(
    upstream: &mut Upstream<'_>,
    reference: Option<&str>,
    path: &str,
    depth: usize,
    limit: usize,
) -> Result<String, Failure> {
    let resolved = upstream.resolve(reference).await?;
    let (mut entries, whole) = upstream.tree(&resolved.tree, true).await?;
    let prefix = if path.is_empty() {
        String::new()
    } else {
        format!("{path}/")
    };
    if !whole {
        entries = walk_tree(upstream, &resolved.tree, path, depth, limit).await?;
    } else if !path.is_empty() {
        match entries.iter().find(|entry| entry.path == path) {
            Some(entry) if entry.kind == "tree" => {}
            Some(_) => {
                return Err(Failure::plain(format!(
                    "`{path}` is a file, not a directory: read it with `repo_read`"
                )));
            }
            None => {
                return Err(Failure::plain(format!(
                    "there is no directory `{path}` at {}",
                    resolved.name
                )));
            }
        }
    }
    let mut shown: Vec<&TreeEntry> = entries
        .iter()
        .filter(|entry| {
            entry.path.starts_with(&prefix)
                && entry.path.len() > prefix.len()
                && entry.path[prefix.len()..].split('/').count() <= depth
        })
        .collect();
    shown.sort_by(|a, b| a.path.cmp(&b.path));
    let total = shown.len();
    let mut out = format!(
        "{}/{} @ {} (commit {})\n",
        upstream.owner, upstream.name, resolved.name, resolved.commit
    );
    out.push_str(&format!(
        "{}, depth {depth}: {total} entr{}\n",
        if path.is_empty() {
            "/".to_string()
        } else {
            format!("{path}/")
        },
        if total == 1 { "y" } else { "ies" }
    ));
    for entry in shown.iter().take(limit) {
        let line = match entry.kind.as_str() {
            "tree" => format!("{}/", entry.path),
            "commit" => format!("{}  (submodule)", entry.path),
            _ if entry.mode == "120000" => format!("{}  (symlink)", entry.path),
            _ => format!("{}  {}", entry.path, entry.size.unwrap_or(0)),
        };
        out.push_str(&line);
        out.push('\n');
    }
    if total > limit {
        out.push_str(&format!(
            "(truncated: {} more entries not shown; raise `limit` (at most {}), narrow `path` \
             or lower `depth`)\n",
            total - limit,
            TREE_LIMIT.1
        ));
    }
    if total == 0 {
        out.push_str("(empty)\n");
    }
    Ok(cap(out))
}

/// The tree below `path` to `depth` levels, one listing per directory,
/// for a repository too large for one recursive listing. Stops after
/// `MAX_TREE_CALLS` listings or once more than `limit` entries are known.
async fn walk_tree(
    upstream: &mut Upstream<'_>,
    root: &str,
    path: &str,
    depth: usize,
    limit: usize,
) -> Result<Vec<TreeEntry>, Failure> {
    let mut calls = 0;
    let mut sha = root.to_string();
    let mut walked = String::new();
    if !path.is_empty() {
        for segment in path.split('/') {
            let (entries, _) = upstream.tree(&sha, false).await?;
            calls += 1;
            let next = if walked.is_empty() {
                segment.to_string()
            } else {
                format!("{walked}/{segment}")
            };
            match entries.into_iter().find(|entry| entry.path == segment) {
                Some(entry) if entry.kind == "tree" => sha = entry.sha,
                Some(_) => {
                    return Err(Failure::plain(format!(
                        "`{next}` is a file, not a directory: read it with `repo_read`"
                    )));
                }
                None => {
                    return Err(Failure::plain(format!("there is no directory `{next}`")));
                }
            }
            walked = next;
        }
    }
    let mut out: Vec<TreeEntry> = Vec::new();
    let mut level: Vec<(String, String)> = vec![(walked, sha)];
    for _ in 0..depth {
        let mut next_level = Vec::new();
        for (dir, sha) in level {
            if calls >= MAX_TREE_CALLS || out.len() > limit {
                return Ok(out);
            }
            let (entries, _) = upstream.tree(&sha, false).await?;
            calls += 1;
            for mut entry in entries {
                entry.path = if dir.is_empty() {
                    entry.path
                } else {
                    format!("{dir}/{}", entry.path)
                };
                if entry.kind == "tree" {
                    next_level.push((entry.path.clone(), entry.sha.clone()));
                }
                out.push(entry);
            }
        }
        level = next_level;
    }
    Ok(out)
}

async fn repo_read(
    upstream: &mut Upstream<'_>,
    reference: Option<&str>,
    paths: &[String],
    lines: Option<(usize, Option<usize>)>,
) -> Result<String, Failure> {
    let resolved = upstream.resolve(reference).await?;
    let mut out = format!(
        "{}/{} @ {} (commit {})\n",
        upstream.owner, upstream.name, resolved.name, resolved.commit
    );
    let mut cut: Vec<String> = Vec::new();
    for path in paths {
        if out.chars().count() >= ops::MAX_BODY_CHARS {
            cut.push(format!("{path} (not shown)"));
            continue;
        }
        let section = read_one(upstream, &resolved.commit, path, lines).await?;
        let room = ops::MAX_BODY_CHARS - out.chars().count();
        if section.chars().count() <= room {
            out.push_str(&section);
            continue;
        }
        // Cut at the last whole line that fits.
        let mut kept = String::new();
        let mut last_line = None;
        for line in section.split_inclusive('\n') {
            if kept.chars().count() + line.chars().count() > room {
                break;
            }
            kept.push_str(line);
            last_line = line
                .split_whitespace()
                .next()
                .and_then(|number| number.parse::<usize>().ok())
                .or(last_line);
        }
        out.push_str(&kept);
        cut.push(match last_line {
            Some(line) => format!("{path} (shown up to line {line})"),
            None => format!("{path} (not shown)"),
        });
    }
    if !cut.is_empty() {
        out.push_str(&format!(
            "\n(cut to fit the output limit of {} characters: {}. Read the rest with \
             start_line and end_line, one file at a time.)\n",
            ops::MAX_BODY_CHARS,
            cut.join(", ")
        ));
    }
    Ok(out)
}

/// One file of `repo_read` as its section: a header line, then the text
/// with line numbers, or what the file is when it is not shown.
async fn read_one(
    upstream: &mut Upstream<'_>,
    commit: &str,
    path: &str,
    lines: Option<(usize, Option<usize>)>,
) -> Result<String, Failure> {
    let (status, value, whole) = upstream
        .send(
            "GET",
            upstream.repo_path(&format!("/contents/{}", encode_path(path))),
            &[("ref", commit.to_string())],
            None,
        )
        .await?;
    match status {
        200..=299 => {}
        404 => return Ok(format!("\n== {path} ==\n(not found at this commit)\n")),
        _ => {
            return Err(Failure::http(
                status,
                &value,
                &format!("`{path}`"),
                &upstream.provider,
            ));
        }
    }
    if !whole {
        return Ok(format!(
            "\n== {path} ==\n(too large to show: files over 1 MiB are not read)\n"
        ));
    }
    if value.is_array() {
        return Ok(format!(
            "\n== {path} ==\n(a directory: list it with `repo_tree`)\n"
        ));
    }
    let size = value.get("size").and_then(Value::as_u64).unwrap_or(0);
    let sha = value.get("sha").and_then(Value::as_str).unwrap_or("");
    let kind = value.get("type").and_then(Value::as_str).unwrap_or("");
    let header = format!("\n== {path} ({size} bytes, sha {sha}) ==\n");
    match kind {
        "file" => {}
        "symlink" => {
            let target = value.get("target").and_then(Value::as_str).unwrap_or("?");
            return Ok(format!("{header}(a symlink to `{target}`)\n"));
        }
        "submodule" => return Ok(format!("{header}(a submodule)\n")),
        other => return Ok(format!("{header}(a {other}, not a file)\n")),
    }
    let encoding = value.get("encoding").and_then(Value::as_str).unwrap_or("");
    if size > MAX_READ_BYTES || encoding != "base64" {
        return Ok(format!(
            "{header}(too large to show: files over 1 MiB are not read)\n"
        ));
    }
    let content: String = value
        .get("content")
        .and_then(Value::as_str)
        .unwrap_or("")
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(content) else {
        return Ok(format!("{header}(the content could not be decoded)\n"));
    };
    let text = match std::str::from_utf8(&bytes) {
        Ok(text) if !bytes[..bytes.len().min(8000)].contains(&0) => text,
        _ => {
            let extension = path
                .rsplit('/')
                .next()
                .and_then(|name| name.rsplit_once('.'))
                .map(|(_, extension)| extension.to_ascii_lowercase())
                .filter(|extension| !extension.is_empty() && extension.len() <= 16);
            return Ok(format!(
                "{header}(binary file{}, {} bytes: not shown)\n",
                extension.map(|e| format!(", .{e}")).unwrap_or_default(),
                bytes.len()
            ));
        }
    };
    // Every stored secret goes, as in every other answer.
    let text = upstream
        .guard
        .redact(text, upstream.granted.secret.expose());
    let all: Vec<&str> = text.lines().collect();
    let (start, end) = match lines {
        None => (1, all.len()),
        Some((start, end)) => (start, end.unwrap_or(all.len()).min(all.len())),
    };
    if all.is_empty() {
        return Ok(format!("{header}(empty)\n"));
    }
    if start > all.len() {
        return Ok(format!(
            "{header}(the file has {} lines; start_line {start} is past its end)\n",
            all.len()
        ));
    }
    let width = end.to_string().len();
    let mut out = header;
    if lines.is_some() {
        out.push_str(&format!("(lines {start}-{end} of {})\n", all.len()));
    }
    for (index, line) in all[start - 1..end].iter().enumerate() {
        out.push_str(&format!("{:>width$}  {line}\n", start + index));
    }
    Ok(out)
}

async fn repo_search(
    upstream: &mut Upstream<'_>,
    query: &str,
    path: Option<&str>,
    extension: Option<&str>,
    limit: usize,
) -> Result<String, Failure> {
    let mut q = format!("{query} repo:{}/{}", upstream.owner, upstream.name);
    if let Some(path) = path {
        if path.contains(' ') {
            q.push_str(&format!(" path:\"{path}\""));
        } else {
            q.push_str(&format!(" path:{path}"));
        }
    }
    if let Some(extension) = extension {
        q.push_str(&format!(" extension:{extension}"));
    }
    let value = upstream
        .json(
            "GET",
            "/search/code".into(),
            &[("q", q), ("per_page", limit.to_string())],
            None,
            "the code search",
        )
        .await?;
    let total = value
        .get("total_count")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let items = value
        .get("items")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut out = format!(
        "{total} file{} in {}/{} (GitHub code search covers the default branch only and may \
         lag behind recent pushes)\n",
        if total == 1 { "" } else { "s" },
        upstream.owner,
        upstream.name
    );
    if value.get("incomplete_results").and_then(Value::as_bool) == Some(true) {
        out.push_str("(GitHub says these results may be incomplete)\n");
    }
    for item in items.iter().take(limit) {
        let Some(path) = item.get("path").and_then(Value::as_str) else {
            continue;
        };
        out.push_str(&format!("- {path}\n"));
        for fragment in item
            .get("text_matches")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|matched| matched.get("fragment").and_then(Value::as_str))
        {
            for line in fragment.lines() {
                out.push_str(&format!("    {line}\n"));
            }
            out.push_str("    …\n");
        }
    }
    if (items.len() as u64) < total {
        out.push_str(&format!(
            "({} shown; narrow the query, `path` or `extension`, or raise `limit` (at most {}))\n",
            items.len().min(limit),
            SEARCH_LIMIT.1
        ));
    }
    Ok(cap(out))
}

/// One commit through the Git Data API: the branch's head, its tree, one
/// blob per written file, one tree on top of the head's, one commit, and
/// the branch moved to it without force (or created at it).
async fn repo_commit(upstream: &mut Upstream<'_>, plan: &CommitPlan) -> Result<String, Failure> {
    let branch_ref = format!("/git/ref/heads/{}", encode_path(&plan.branch));
    upstream.step = "ref";
    let (status, value, _) = upstream
        .send("GET", upstream.repo_path(&branch_ref), &[], None)
        .await?;
    let (head, created) = match status {
        200..=299 => {
            if plan.create_from.is_some() {
                return Err(Failure::plain(format!(
                    "the branch `{}` already exists: leave out `create_from` to commit to it",
                    plan.branch
                )));
            }
            let head = value
                .pointer("/object/sha")
                .and_then(Value::as_str)
                .ok_or_else(|| Failure::plain("GitHub's answer for the branch named no commit"))?;
            (head.to_string(), None)
        }
        404 => match &plan.create_from {
            Some(base) => {
                let resolved = upstream.resolve(Some(base)).await?;
                (resolved.commit, Some(base.clone()))
            }
            None => {
                return Err(Failure {
                    message: format!(
                        "GitHub found no branch `{}` in {}/{}: pass `create_from` (a branch, tag \
                         or commit) to create it, or check the name",
                        plan.branch, upstream.owner, upstream.name
                    ),
                    not_found: true,
                    status,
                    reason: Failure::reason_of(&value),
                });
            }
        },
        _ => {
            return Err(Failure::http(
                status,
                &value,
                &format!("the branch `{}`", plan.branch),
                &upstream.provider,
            ));
        }
    };
    if let Some(expected) = &plan.expected_head
        && !head.to_ascii_lowercase().starts_with(expected.as_str())
    {
        return Err(Failure::plain(format!(
            "the branch `{}` is at {head}, not at the expected_head {expected}: someone else \
             changed it. Nothing was written. Read the branch again and retry with its new head.",
            plan.branch
        )));
    }
    let commit = upstream
        .json(
            "GET",
            upstream.repo_path(&format!("/git/commits/{head}")),
            &[],
            None,
            "the head commit",
        )
        .await?;
    let base_tree = commit
        .pointer("/tree/sha")
        .and_then(Value::as_str)
        .ok_or_else(|| Failure::plain("GitHub's answer for the head commit named no tree"))?
        .to_string();
    // The current entries keep a file's mode (executable, symlink) and
    // catch a path that is a directory or a deletion of nothing.
    upstream.step = "tree";
    let (entries, whole) = upstream.tree(&base_tree, true).await?;
    let known: HashMap<&str, &TreeEntry> = entries
        .iter()
        .map(|entry| (entry.path.as_str(), entry))
        .collect();
    let mut tree = Vec::new();
    let mut changed = Vec::new();
    for (path, bytes) in &plan.changes {
        let existing = known.get(path.as_str());
        if existing.is_some_and(|entry| entry.kind == "tree") {
            return Err(Failure::plain(format!(
                "`{path}` is a directory; nothing was written"
            )));
        }
        let mode = existing
            .filter(|entry| entry.kind == "blob")
            .map_or("100644", |entry| entry.mode.as_str())
            .to_string();
        match bytes {
            None => {
                if whole && existing.is_none() {
                    return Err(Failure::plain(format!(
                        "`{path}` does not exist on `{}`, so it cannot be deleted; nothing was \
                         written",
                        plan.branch
                    )));
                }
                tree.push(json!({ "path": path, "mode": mode, "type": "blob", "sha": null }));
                changed.push(format!("deleted  {path}"));
            }
            Some(bytes) => {
                upstream.step = "blob";
                let blob = upstream
                    .json(
                        "POST",
                        upstream.repo_path("/git/blobs"),
                        &[],
                        Some(json!({
                            "content": base64::engine::general_purpose::STANDARD.encode(bytes),
                            "encoding": "base64",
                        })),
                        &format!("the content of `{path}`"),
                    )
                    .await?;
                let sha = blob
                    .get("sha")
                    .and_then(Value::as_str)
                    .ok_or_else(|| Failure::plain("GitHub's answer for a blob named no sha"))?;
                tree.push(json!({ "path": path, "mode": mode, "type": "blob", "sha": sha }));
                changed.push(format!(
                    "{}  {path}",
                    if existing.is_some() {
                        "changed"
                    } else {
                        "added  "
                    }
                ));
            }
        }
    }
    upstream.step = "tree";
    let new_tree = upstream
        .json(
            "POST",
            upstream.repo_path("/git/trees"),
            &[],
            Some(json!({ "base_tree": base_tree, "tree": tree })),
            "the new tree",
        )
        .await?;
    let new_tree = new_tree
        .get("sha")
        .and_then(Value::as_str)
        .ok_or_else(|| Failure::plain("GitHub's answer for the tree named no sha"))?
        .to_string();
    upstream.step = "commit";
    let new_commit = upstream
        .json(
            "POST",
            upstream.repo_path("/git/commits"),
            &[],
            Some(json!({ "message": plan.message, "tree": new_tree, "parents": [head] })),
            "the commit",
        )
        .await?;
    let new_commit = new_commit
        .get("sha")
        .and_then(Value::as_str)
        .ok_or_else(|| Failure::plain("GitHub's answer for the commit named no sha"))?
        .to_string();
    upstream.step = "update";
    let (status, value, _) = match &created {
        Some(_) => {
            upstream
                .send(
                    "POST",
                    upstream.repo_path("/git/refs"),
                    &[],
                    Some(
                        json!({ "ref": format!("refs/heads/{}", plan.branch), "sha": new_commit }),
                    ),
                )
                .await?
        }
        None => {
            upstream
                .send(
                    "PATCH",
                    upstream.repo_path(&format!("/git/refs/heads/{}", encode_path(&plan.branch))),
                    &[],
                    Some(json!({ "sha": new_commit, "force": false })),
                )
                .await?
        }
    };
    if !(200..300).contains(&status) {
        let said = value.get("message").and_then(Value::as_str).unwrap_or("");
        let mut failure = Failure::http(
            status,
            &value,
            &format!("moving the branch `{}`", plan.branch),
            &upstream.provider,
        );
        if status == 422 && said.to_ascii_lowercase().contains("fast forward") {
            failure.message = format!(
                "the branch `{}` moved while lore was committing, so it was left as it is (the \
                 new commit {new_commit} is on no branch). Read the branch again and retry.",
                plan.branch
            );
        } else if status == 422 && said.to_ascii_lowercase().contains("already exists") {
            failure.message = format!(
                "the branch `{}` was created by someone else meanwhile, so it was left as it is. \
                 Retry without `create_from`.",
                plan.branch
            );
        }
        failure.message.push_str(" Nothing on the branch changed.");
        return Err(failure);
    }
    let mut out = format!(
        "Committed {} change{} to {}/{} as one commit.\ncommit: {new_commit}\n",
        plan.changes.len(),
        if plan.changes.len() == 1 { "" } else { "s" },
        upstream.owner,
        upstream.name
    );
    match &created {
        Some(base) => out.push_str(&format!(
            "branch: {} (created from {base} at {head})\n",
            plan.branch
        )),
        None => out.push_str(&format!("branch: {} (was at {head})\n", plan.branch)),
    }
    out.push_str(&format!(
        "compare: {GITHUB_WEB}/{}/{}/compare/{head}...{new_commit}\nchanged:\n",
        upstream.owner, upstream.name
    ));
    for line in changed {
        out.push_str(&format!("- {line}\n"));
    }
    Ok(out)
}

/// An answer cut to the output limit every provider tool has.
fn cap(text: String) -> String {
    if text.chars().count() <= ops::MAX_BODY_CHARS {
        return text;
    }
    let mut out: String = text.chars().take(ops::MAX_BODY_CHARS).collect();
    out.push_str(&format!(
        "\n(truncated: the first {} characters)\n",
        ops::MAX_BODY_CHARS
    ));
    out
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use axum::{
        Router,
        extract::{Request, State},
        http::StatusCode,
        response::{IntoResponse, Response},
        routing::any,
    };
    use rmcp::handler::server::{common::Extension, wrapper::Parameters};
    use serde::de::DeserializeOwned;

    use super::*;
    use crate::{
        auth::Agent,
        db::{Db, NewSession},
        embed::Embedder,
        events::Events,
        vault::VaultKey,
    };

    /// The stored test credentials; not real, and not in any token format.
    const PERSONAL: &str = "test-personal-credential-value";
    const ORGANIZATION: &str = "test-organization-credential-value";
    const HEAD: &str = "1111111111111111111111111111111111111111";
    const TREE: &str = "2222222222222222222222222222222222222222";
    const NEW_TREE: &str = "3333333333333333333333333333333333333333";
    const NEW_COMMIT: &str = "4444444444444444444444444444444444444444";
    const TAGGED: &str = "5555555555555555555555555555555555555555";

    /// One request the mock GitHub received.
    #[derive(Debug, Clone)]
    struct Seen {
        method: String,
        path: String,
        query: String,
        auth: String,
        body: String,
    }

    impl Seen {
        /// `METHOD /path?query`, the query's pairs sorted.
        fn line(&self) -> String {
            if self.query.is_empty() {
                format!("{} {}", self.method, self.path)
            } else {
                let mut pairs: Vec<&str> = self.query.split('&').collect();
                pairs.sort();
                format!("{} {}?{}", self.method, self.path, pairs.join("&"))
            }
        }

        fn json(&self) -> Value {
            serde_json::from_str(&self.body).unwrap()
        }
    }

    type Log = Arc<Mutex<Vec<Seen>>>;

    fn reply(status: u16, value: Value) -> Response {
        (StatusCode::from_u16(status).unwrap(), value.to_string()).into_response()
    }

    /// A file as the Contents API answers it: base64 in lines of 60.
    fn file(path: &str, bytes: &[u8]) -> Value {
        let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
        let wrapped: Vec<String> = encoded
            .as_bytes()
            .chunks(60)
            .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
            .collect();
        json!({
            "type": "file", "path": path, "size": bytes.len(), "sha": "blobsha",
            "encoding": "base64", "content": wrapped.join("\n"),
        })
    }

    fn tree_entries() -> Value {
        let blob = |path: &str, mode: &str, size: u64| json!({"path": path, "mode": mode, "type": "blob", "sha": "b", "size": size});
        let dir = |path: &str| json!({"path": path, "mode": "040000", "type": "tree", "sha": "t"});
        json!([
            blob("README.md", "100644", 31),
            dir("bin"),
            blob("bin/run.sh", "100755", 10),
            blob("logo.png", "100644", 6),
            dir("src"),
            blob("src/main.rs", "100644", 40),
            blob("src/lib.rs", "100644", 7),
            dir("src/deep"),
            dir("src/deep/a"),
            blob("src/deep/a/b.rs", "100644", 3),
        ])
    }

    /// The mock GitHub: repositories named `public…` are public, `hidden…`
    /// are visible to the organization's credential only, `racy…` and
    /// `guarded…` refuse moving a branch. Every request is recorded. A
    /// local mock, never GitHub.
    async fn github(State(log): State<Log>, request: Request) -> Response {
        let (parts, body) = request.into_parts();
        let body = axum::body::to_bytes(body, 64 << 20)
            .await
            .unwrap_or_default();
        let seen = Seen {
            method: parts.method.to_string(),
            path: parts.uri.path().to_string(),
            query: parts.uri.query().unwrap_or("").to_string(),
            auth: parts
                .headers
                .get("authorization")
                .and_then(|value| value.to_str().ok())
                .unwrap_or("")
                .to_string(),
            body: String::from_utf8_lossy(&body).into_owned(),
        };
        let blobs = {
            let mut log = log.lock().unwrap();
            log.push(seen.clone());
            log.iter()
                .filter(|s| s.path.ends_with("/git/blobs"))
                .count()
        };
        let org = seen.auth == format!("Bearer {ORGANIZATION}");
        let path = seen.path.clone();
        let segments: Vec<&str> = path.trim_start_matches('/').split('/').collect();
        if segments == ["search", "code"] {
            return reply(
                200,
                json!({"total_count": 3, "incomplete_results": false, "items": [
                    {"path": "src/main.rs", "text_matches": [{"fragment": "fn main() {}"}]},
                    {"path": "src/lib.rs"},
                ]}),
            );
        }
        if segments.len() < 3 || segments[0] != "repos" {
            return reply(404, json!({"message": "Not Found"}));
        }
        let repo = segments[2];
        if repo.starts_with("hidden") && !org {
            return reply(404, json!({"message": "Not Found"}));
        }
        let rest = &segments[3..];
        match (seen.method.as_str(), rest) {
            ("GET", []) => reply(
                200,
                json!({"private": !repo.starts_with("public"), "default_branch": "main"}),
            ),
            ("GET", ["commits"]) => {
                if seen.query.contains("sha=nope") {
                    return reply(422, json!({"message": "No commit found for SHA: nope"}));
                }
                let sha = if seen.query.contains("sha=v1") {
                    TAGGED
                } else {
                    HEAD
                };
                reply(
                    200,
                    json!([{"sha": sha, "commit": {"tree": {"sha": TREE}}}]),
                )
            }
            ("GET", ["git", "trees", _]) => reply(
                200,
                json!({"sha": TREE, "truncated": false, "tree": tree_entries()}),
            ),
            ("GET", ["contents", file_path @ ..]) => {
                let name = file_path.join("/");
                match name.as_str() {
                    "README.md" => reply(200, file(&name, b"# Demo\nsecond line\nthird line\n")),
                    "src/main.rs" => reply(
                        200,
                        file(&name, format!("fn main() {{}}\n// {PERSONAL}\n").as_bytes()),
                    ),
                    "logo.png" => reply(200, file(&name, &[0x89, b'P', b'N', b'G', 0, 1])),
                    "big.bin" => reply(
                        200,
                        json!({"type": "file", "size": 2_000_000, "sha": "s",
                               "encoding": "none", "content": ""}),
                    ),
                    "long.txt" => {
                        let text: String =
                            (0..20_000).map(|n| format!("line number {n}\n")).collect();
                        reply(200, file(&name, text.as_bytes()))
                    }
                    "src" => reply(200, json!([{"name": "main.rs", "type": "file"}])),
                    _ => reply(404, json!({"message": "Not Found"})),
                }
            }
            ("GET", ["git", "ref", "heads", branch @ ..]) => {
                if branch.join("/") == "main" {
                    reply(
                        200,
                        json!({"ref": "refs/heads/main", "object": {"sha": HEAD}}),
                    )
                } else {
                    reply(404, json!({"message": "Not Found"}))
                }
            }
            ("GET", ["git", "commits", sha]) => {
                reply(200, json!({"sha": sha, "tree": {"sha": TREE}}))
            }
            ("POST", ["git", "blobs"]) => reply(201, json!({"sha": format!("blob{blobs}")})),
            ("POST", ["git", "trees"]) => reply(201, json!({"sha": NEW_TREE})),
            ("POST", ["git", "commits"]) => reply(201, json!({"sha": NEW_COMMIT})),
            ("PATCH", ["git", "refs", "heads", ..]) if repo.starts_with("racy") => {
                reply(422, json!({"message": "Update is not a fast forward"}))
            }
            ("PATCH", ["git", "refs", "heads", ..]) if repo.starts_with("guarded") => reply(
                422,
                json!({"message": "Protected branch update failed for refs/heads/main."}),
            ),
            ("PATCH", ["git", "refs", "heads", ..]) => {
                reply(200, json!({"object": {"sha": NEW_COMMIT}}))
            }
            ("POST", ["git", "refs"]) => reply(201, json!({"object": {"sha": NEW_COMMIT}})),
            _ => reply(404, json!({"message": "Not Found"})),
        }
    }

    async fn serve(log: Log) -> String {
        let router = Router::new().route("/{*rest}", any(github)).with_state(log);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            axum::serve(listener, router.into_make_service())
                .await
                .unwrap();
        });
        base
    }

    /// A lore with both GitHub credentials stored, pointed at the mock,
    /// and an open session of `claude`.
    async fn setup(name: &str) -> (Lore, Log, String) {
        let dir =
            std::env::temp_dir().join(format!("lore-repotools-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let db = Db::open(&dir.join("lore.db")).unwrap();
        let mut lore = Lore::new(
            db,
            Embedder::disabled(),
            0.5,
            Events::new(),
            12,
            None,
            ops::Guard::default(),
        );
        let key = VaultKey::from_env_value(&"9a".repeat(32)).unwrap().unwrap();
        for (provider, credential) in [("github", PERSONAL), ("github_org", ORGANIZATION)] {
            let (nonce, secret) = key.encrypt(provider, "", credential);
            lore.db
                .set_vault(provider, "", &nonce, &secret, "alue")
                .unwrap();
        }
        lore.vault = Some(key);
        let log: Log = Arc::default();
        lore.github_api_base = Some(serve(log.clone()).await);
        let session = lore
            .db
            .open_session(&NewSession {
                agent: "claude".into(),
                project: "shop".into(),
                path: "/work/shop".into(),
                repo: String::new(),
                commit: String::new(),
                branch: String::new(),
                title: "web chat".into(),
                implicit: false,
            })
            .unwrap()
            .id;
        (lore, log, session)
    }

    fn claude() -> Extension<Parts> {
        let mut parts = axum::http::Request::builder()
            .body(())
            .unwrap()
            .into_parts()
            .0;
        parts.extensions.insert(Agent("claude".into()));
        Extension(parts)
    }

    fn args<T: DeserializeOwned>(session: &str, mut value: Value) -> Parameters<T> {
        value["session_id"] = Value::from(session);
        Parameters(serde_json::from_value(value).unwrap())
    }

    fn lines(log: &Log) -> Vec<String> {
        log.lock().unwrap().iter().map(Seen::line).collect()
    }

    /// Every request carried the credential of `account`; no answer, log
    /// row or activity note repeats either credential.
    fn credential_kept(lore: &Lore, log: &Log, credential: &str, answers: &[&str]) {
        for seen in log.lock().unwrap().iter() {
            assert_eq!(seen.auth, format!("Bearer {credential}"), "{}", seen.line());
        }
        let kept = format!(
            "{answers:?}{:?}{:?}",
            lore.db.ops_log(100).unwrap(),
            lore.db.activity(100).unwrap()
        );
        assert!(!kept.contains(PERSONAL) && !kept.contains(ORGANIZATION));
    }

    fn last_row(lore: &Lore) -> crate::db::OpLog {
        lore.db.ops_log(1).unwrap().remove(0)
    }

    fn decoded_query(query: &str) -> Vec<(String, String)> {
        reqwest::Url::parse(&format!("http://mock/?{query}"))
            .unwrap()
            .query_pairs()
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect()
    }

    #[tokio::test]
    async fn repo_tree_lists_the_default_branch() {
        let (lore, log, session) = setup("tree").await;
        let answer = lore
            .repo_tree(args(&session, json!({"repo": "me/shop"})), claude())
            .await
            .unwrap();
        assert_eq!(
            lines(&log),
            [
                "GET /repos/me/shop".to_string(),
                "GET /repos/me/shop/commits?per_page=1&sha=main".into(),
                format!("GET /repos/me/shop/git/trees/{TREE}?recursive=1"),
            ]
        );
        assert_eq!(
            answer,
            format!(
                "me/shop @ main (commit {HEAD})\n/, depth 2: 8 entries\nREADME.md  31\nbin/\n\
                 bin/run.sh  10\nlogo.png  6\nsrc/\nsrc/deep/\nsrc/lib.rs  7\nsrc/main.rs  40\n"
            )
        );
        credential_kept(&lore, &log, PERSONAL, &[&answer]);
        let row = last_row(&lore);
        assert_eq!(
            (
                row.provider.as_str(),
                row.method.as_str(),
                row.path.as_str(),
                row.outcome.as_str(),
                row.status
            ),
            ("github", "GET", "repo_tree me/shop:", "ok", 200)
        );
        let note = &lore.db.activity(1).unwrap()[0];
        assert_eq!(note.tool, "github");

        // One directory, one level, a ref, a limit.
        let answer = lore
            .repo_tree(
                args(
                    &session,
                    json!({"repo": "me/shop", "path": "src/", "depth": 1, "ref": "main", "limit": 2}),
                ),
                claude(),
            )
            .await
            .unwrap();
        assert!(
            answer.ends_with(
                "src/, depth 1: 3 entries\nsrc/deep/\nsrc/lib.rs  7\n(truncated: 1 more entries \
                 not shown; raise `limit` (at most 2000), narrow `path` or lower `depth`)\n"
            ),
            "{answer}"
        );
        let refused = lore
            .repo_tree(
                args(&session, json!({"repo": "me/shop", "path": "README.md"})),
                claude(),
            )
            .await
            .unwrap_err();
        assert!(refused.contains("is a file"), "{refused}");
        let refused = lore
            .repo_tree(
                args(&session, json!({"repo": "me/shop", "ref": "nope"})),
                claude(),
            )
            .await
            .unwrap_err();
        assert!(
            refused.contains("GitHub found no commit for ref `nope`"),
            "{refused}"
        );
        for bad in [
            json!({"repo": "me/shop", "depth": 11}),
            json!({"repo": "nope"}),
        ] {
            assert!(lore.repo_tree(args(&session, bad), claude()).await.is_err());
        }
    }

    #[tokio::test]
    async fn repo_read_shows_text_and_describes_the_rest() {
        let (lore, log, session) = setup("read").await;
        let answer = lore
            .repo_read(
                args(
                    &session,
                    json!({"repo": "me/shop", "ref": "main", "paths": [
                        "README.md", "src/main.rs", "logo.png", "big.bin", "src", "gone.txt"
                    ]}),
                ),
                claude(),
            )
            .await
            .unwrap();
        let mut expected = vec!["GET /repos/me/shop/commits?per_page=1&sha=main".to_string()];
        for path in [
            "README.md",
            "src/main.rs",
            "logo.png",
            "big.bin",
            "src",
            "gone.txt",
        ] {
            expected.push(format!("GET /repos/me/shop/contents/{path}?ref={HEAD}"));
        }
        assert_eq!(lines(&log), expected);
        assert!(answer.starts_with(&format!("me/shop @ main (commit {HEAD})\n")));
        assert!(
            answer.contains(
                "== README.md (30 bytes, sha blobsha) ==\n1  # Demo\n2  second line\n3  third line\n"
            ),
            "{answer}"
        );
        // The stored credential the file holds is redacted.
        assert!(answer.contains("2  // [redacted]\n"), "{answer}");
        assert!(answer.contains("(binary file, .png, 6 bytes: not shown)"));
        assert!(answer.contains("== big.bin (2000000 bytes, sha s) ==\n(too large to show"));
        assert!(answer.contains("== src ==\n(a directory: list it with `repo_tree`)"));
        assert!(answer.contains("== gone.txt ==\n(not found at this commit)"));
        credential_kept(&lore, &log, PERSONAL, &[&answer]);
        assert_eq!(
            last_row(&lore).path,
            "repo_read me/shop:README.md,src/main.rs,logo.png,big.bin,src,gone.txt@main"
        );

        // A range of one file.
        let answer = lore
            .repo_read(
                args(
                    &session,
                    json!({"repo": "me/shop", "paths": ["README.md"], "start_line": 2, "end_line": 3}),
                ),
                claude(),
            )
            .await
            .unwrap();
        assert!(
            answer.ends_with("(lines 2-3 of 3)\n2  second line\n3  third line\n"),
            "{answer}"
        );
        // Ranges need one path; at most ten paths.
        let refused = lore
            .repo_read(
                args(
                    &session,
                    json!({"repo": "me/shop", "paths": ["a", "b"], "start_line": 2}),
                ),
                claude(),
            )
            .await
            .unwrap_err();
        assert_eq!(refused, "start_line and end_line need a single path");
        let eleven: Vec<String> = (0..11).map(|n| format!("f{n}")).collect();
        assert!(
            lore.repo_read(
                args(&session, json!({"repo": "me/shop", "paths": eleven})),
                claude()
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn repo_read_is_cut_to_the_output_limit() {
        let (lore, _log, session) = setup("read-cap").await;
        let answer = lore
            .repo_read(
                args(
                    &session,
                    json!({"repo": "me/shop", "paths": ["long.txt", "README.md"]}),
                ),
                claude(),
            )
            .await
            .unwrap();
        assert!(answer.chars().count() < ops::MAX_BODY_CHARS + 500);
        assert!(
            answer.contains(
                "(cut to fit the output limit of 100000 characters: long.txt (shown up to line "
            ) && answer.contains("README.md (not shown)"),
            "{}",
            &answer[answer.len() - 400..]
        );
        // One part of it reads whole.
        let answer = lore
            .repo_read(
                args(
                    &session,
                    json!({"repo": "me/shop", "paths": ["long.txt"], "start_line": 19999}),
                ),
                claude(),
            )
            .await
            .unwrap();
        assert!(
            answer.ends_with("19999  line number 19998\n20000  line number 19999\n"),
            "{answer}"
        );
    }

    #[tokio::test]
    async fn repo_search_is_scoped_to_the_repository() {
        let (lore, log, session) = setup("search").await;
        let answer = lore
            .repo_search(
                args(
                    &session,
                    json!({"repo": "me/shop", "query": "fn main", "path": "src", "extension": ".rs"}),
                ),
                claude(),
            )
            .await
            .unwrap();
        let seen = log.lock().unwrap().clone();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].path, "/search/code");
        let mut query = decoded_query(&seen[0].query);
        query.sort();
        assert_eq!(
            query,
            [
                ("per_page".to_string(), "20".to_string()),
                (
                    "q".into(),
                    "fn main repo:me/shop path:src extension:rs".into()
                ),
            ]
        );
        assert!(
            answer.starts_with("3 files in me/shop (GitHub code search covers the default branch")
                && answer.contains("- src/main.rs\n    fn main() {}\n    …\n- src/lib.rs\n")
                && answer.contains("(2 shown;"),
            "{answer}"
        );
        credential_kept(&lore, &log, PERSONAL, &[&answer]);
        // The query is not logged.
        assert_eq!(
            last_row(&lore).path,
            "repo_search me/shop path:src extension:.rs"
        );
    }

    #[tokio::test]
    async fn repo_commit_makes_one_commit_of_many_changes() {
        let (lore, log, session) = setup("commit").await;
        let answer = lore
            .repo_commit(
                args(
                    &session,
                    json!({
                        "repo": "me/shop", "branch": "main", "message": "Update docs",
                        "expected_head": &HEAD[..12],
                        "changes": [
                            {"path": "src/main.rs", "content": "fn main() {}\n"},
                            {"path": "docs/new file.md",
                             "content_base64": base64::engine::general_purpose::STANDARD.encode("hi\n")},
                            {"path": "bin/run.sh", "content": "#!/bin/sh\n"},
                            {"path": "README.md", "delete": true},
                        ]
                    }),
                ),
                claude(),
            )
            .await
            .unwrap();
        assert_eq!(
            lines(&log),
            [
                "GET /repos/me/shop".to_string(),
                "GET /repos/me/shop/git/ref/heads/main".into(),
                format!("GET /repos/me/shop/git/commits/{HEAD}"),
                format!("GET /repos/me/shop/git/trees/{TREE}?recursive=1"),
                "POST /repos/me/shop/git/blobs".into(),
                "POST /repos/me/shop/git/blobs".into(),
                "POST /repos/me/shop/git/blobs".into(),
                "POST /repos/me/shop/git/trees".into(),
                "POST /repos/me/shop/git/commits".into(),
                "PATCH /repos/me/shop/git/refs/heads/main".into(),
            ]
        );
        let seen = log.lock().unwrap().clone();
        assert_eq!(
            seen[4].json(),
            json!({"content": base64::engine::general_purpose::STANDARD.encode("fn main() {}\n"),
                   "encoding": "base64"})
        );
        assert_eq!(
            seen[7].json(),
            json!({"base_tree": TREE, "tree": [
                {"path": "src/main.rs", "mode": "100644", "type": "blob", "sha": "blob1"},
                {"path": "docs/new file.md", "mode": "100644", "type": "blob", "sha": "blob2"},
                {"path": "bin/run.sh", "mode": "100755", "type": "blob", "sha": "blob3"},
                {"path": "README.md", "mode": "100644", "type": "blob", "sha": null},
            ]})
        );
        assert_eq!(
            seen[8].json(),
            json!({"message": "Update docs", "tree": NEW_TREE, "parents": [HEAD]})
        );
        assert_eq!(seen[9].json(), json!({"sha": NEW_COMMIT, "force": false}));
        assert_eq!(
            answer,
            format!(
                "Committed 4 changes to me/shop as one commit.\ncommit: {NEW_COMMIT}\n\
                 branch: main (was at {HEAD})\n\
                 compare: https://github.com/me/shop/compare/{HEAD}...{NEW_COMMIT}\nchanged:\n\
                 - changed  src/main.rs\n- added    docs/new file.md\n- changed  bin/run.sh\n\
                 - deleted  README.md\n"
            )
        );
        credential_kept(&lore, &log, PERSONAL, &[&answer]);
        let row = last_row(&lore);
        assert_eq!(
            (
                row.method.as_str(),
                row.path.as_str(),
                row.outcome.as_str(),
                row.status
            ),
            ("POST", "repo_commit me/shop@main (4 changes)", "ok", 200)
        );
    }

    #[tokio::test]
    async fn repo_commit_creates_a_branch_and_checks_the_head() {
        let (lore, log, session) = setup("branch").await;
        let commit = |value: Value| lore.repo_commit(args(&session, value), claude());
        let answer = commit(json!({
            "repo": "me/shop", "branch": "feature/x", "create_from": "v1",
            "message": "Start", "changes": [{"path": "a.txt", "content": "a\n"}]
        }))
        .await
        .unwrap();
        assert_eq!(
            lines(&log),
            [
                "GET /repos/me/shop".to_string(),
                "GET /repos/me/shop/git/ref/heads/feature/x".into(),
                "GET /repos/me/shop/commits?per_page=1&sha=v1".into(),
                format!("GET /repos/me/shop/git/commits/{TAGGED}"),
                format!("GET /repos/me/shop/git/trees/{TREE}?recursive=1"),
                "POST /repos/me/shop/git/blobs".into(),
                "POST /repos/me/shop/git/trees".into(),
                "POST /repos/me/shop/git/commits".into(),
                "POST /repos/me/shop/git/refs".into(),
            ]
        );
        assert_eq!(
            log.lock().unwrap()[8].json(),
            json!({"ref": "refs/heads/feature/x", "sha": NEW_COMMIT})
        );
        assert!(
            answer.contains(&format!("branch: feature/x (created from v1 at {TAGGED})")),
            "{answer}"
        );

        // A missing branch without create_from, an existing one with it, a
        // head that moved, a deletion of nothing: refused, nothing written.
        log.lock().unwrap().clear();
        for (value, wanted) in [
            (
                json!({"repo": "me/shop", "branch": "nope", "message": "m",
                       "changes": [{"path": "a", "content": "a"}]}),
                "GitHub found no branch `nope` in me/shop: pass `create_from`",
            ),
            (
                json!({"repo": "me/shop", "branch": "main", "create_from": "main",
                       "message": "m", "changes": [{"path": "a", "content": "a"}]}),
                "the branch `main` already exists",
            ),
            (
                json!({"repo": "me/shop", "branch": "main", "expected_head": "abcdef1",
                       "message": "m", "changes": [{"path": "a", "content": "a"}]}),
                "not at the expected_head abcdef1: someone else changed it. Nothing was written.",
            ),
            (
                json!({"repo": "me/shop", "branch": "main", "message": "m",
                       "changes": [{"path": "gone.txt", "delete": true}]}),
                "`gone.txt` does not exist on `main`",
            ),
            (
                json!({"repo": "me/shop", "branch": "main", "message": "m",
                       "changes": [{"path": "src", "content": "x"}]}),
                "`src` is a directory",
            ),
        ] {
            let refused = commit(value).await.unwrap_err();
            assert!(refused.contains(wanted), "{refused}");
        }
        assert!(
            lines(&log).iter().all(|line| line.starts_with("GET ")),
            "{:?}",
            lines(&log)
        );

        // GitHub's refusals in plain words; the branch is never forced.
        for (repo, wanted) in [
            (
                "racy-shop",
                "the branch `main` moved while lore was committing",
            ),
            (
                "guarded-shop",
                "Protected branch update failed for refs/heads/main.",
            ),
        ] {
            let refused = commit(json!({
                "repo": format!("me/{repo}"), "branch": "main", "message": "m",
                "changes": [{"path": "a", "content": "a"}]
            }))
            .await
            .unwrap_err();
            assert!(
                refused.contains(wanted) && refused.ends_with("Nothing on the branch changed."),
                "{refused}"
            );
        }
        assert!(
            log.lock()
                .unwrap()
                .iter()
                .filter(|seen| seen.method == "PATCH")
                .all(|seen| seen.json()["force"] == false)
        );
    }

    #[tokio::test]
    async fn repo_commit_validates_every_path_before_sending() {
        let (lore, log, session) = setup("paths").await;
        let change = |change: Value| json!({"repo": "me/shop", "branch": "main", "message": "m", "changes": [change]});
        for (value, wanted) in [
            (
                change(json!({"path": "../x", "content": "a"})),
                "`..` segment",
            ),
            (
                change(json!({"path": "/etc/x", "content": "a"})),
                "starts with `/`",
            ),
            (
                change(json!({"path": ".git/config", "content": "a"})),
                "reaches into `.git`",
            ),
            (
                change(json!({"path": "src/.GIT/hooks/x", "content": "a"})),
                "reaches into `.git`",
            ),
            (change(json!({"path": "a//b", "content": "a"})), "empty"),
            (change(json!({"path": "a\\b", "content": "a"})), "backslash"),
            (
                change(json!({"path": "x".repeat(4097), "content": "a"})),
                "at most 4096",
            ),
            (change(json!({"path": "a"})), "exactly one of"),
            (
                change(json!({"path": "a", "content": "a", "delete": true})),
                "exactly one of",
            ),
            (
                change(json!({"path": "a", "content_base64": "!!"})),
                "not valid base64",
            ),
            (
                json!({"repo": "me/shop", "branch": "main", "message": "m", "changes": [
                    {"path": "a", "content": "1"}, {"path": "a", "content": "2"}]}),
                "changed twice",
            ),
            (
                json!({"repo": "me/shop", "branch": "main", "message": "m", "changes": []}),
                "1 to 50 changes",
            ),
            (
                json!({"repo": "me/shop", "branch": "main", "message": " ",
                       "changes": [{"path": "a", "content": "a"}]}),
                "message must be",
            ),
            (
                json!({"repo": "me/shop", "branch": "a..b", "message": "m",
                       "changes": [{"path": "a", "content": "a"}]}),
                "branch must be",
            ),
            (
                json!({"repo": "me/shop", "branch": "main", "message": "m",
                       "changes": [{"path": "a", "content": "x".repeat(MAX_COMMIT_BYTES + 1)}]}),
                "more than 8 MiB",
            ),
        ] {
            let refused = lore
                .repo_commit(args(&session, value), claude())
                .await
                .unwrap_err();
            assert!(refused.contains(wanted), "{wanted}: {refused}");
            assert_eq!(last_row(&lore).outcome, "error");
        }
        assert!(log.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn secrets_never_reach_a_public_repository() {
        let (lore, log, session) = setup("leak").await;
        let token = ["gh", "p_", "Zq8Lm2Xv9Rt4Wp6Ky3Nb7Hc5Jd1Fg0Ts8QeA"].concat(); // lore:allow-secret
        let commit = |repo: &str, changes: Value, message: &str| {
            lore.repo_commit(
                args(
                    &session,
                    json!({"repo": repo, "branch": "main", "message": message, "changes": changes}),
                ),
                claude(),
            )
        };
        let leak = json!([
            {"path": "README.md", "content": "fine\n"},
            {"path": "config.py", "content": format!("KEY = '{token}'\n")},
        ]);

        // A public repository: refused whole, nothing but the visibility
        // question sent, logged as denied.
        let refused = commit("me/public-site", leak.clone(), "m")
            .await
            .unwrap_err();
        assert_eq!(
            refused,
            "lore refused this commit: it would put a secret or a private file into a public \
             GitHub repository (github-token in `config.py`, line 1). lore does not let secrets \
             or private files reach a public repository: remove it, or ask the user. Nothing \
             was written."
        );
        assert_eq!(lines(&log), ["GET /repos/me/public-site"]);
        let row = last_row(&lore);
        assert_eq!(
            (
                row.method.as_str(),
                row.outcome.as_str(),
                row.detail.as_str()
            ),
            (
                "POST",
                "denied",
                "leak scan: github-token in `config.py`, line 1"
            )
        );

        // The same in base64, a private file by its name, a secret in the
        // message: refused too.
        let encoded = base64::engine::general_purpose::STANDARD.encode(format!("t={token}\n"));
        for (changes, message, wanted) in [
            (
                json!([{"path": "x.txt", "content_base64": encoded}]),
                "m",
                "github-token in `x.txt`, line 1",
            ),
            (
                json!([{"path": "deploy/.env", "content": "A=1\n"}]),
                "m",
                "env-file in `deploy/.env`",
            ),
            (
                json!([{"path": "a.txt", "content": "a\n"}]),
                &format!("add {token}") as &str,
                "github-token in the commit message, line 1",
            ),
        ] {
            let refused = commit("me/public-site", changes, message)
                .await
                .unwrap_err();
            assert!(refused.contains(wanted), "{refused}");
        }
        // A repository whose visibility cannot be read counts as public.
        let refused = commit("me/hidden-site", leak.clone(), "m")
            .await
            .unwrap_err();
        assert!(refused.contains("github-token in `config.py`"), "{refused}");
        assert!(
            lines(&log)
                .iter()
                .all(|line| line.starts_with("GET /repos/me/") && !line.contains("/git/")),
            "{:?}",
            lines(&log)
        );

        // A clean change to a public repository, and the same secret to a
        // private one, go through: the blobs and the tree are not scanned a
        // second time.
        commit(
            "me/public-site",
            json!([{"path": "a.txt", "content": "a\n"}]),
            "m",
        )
        .await
        .unwrap();
        log.lock().unwrap().clear();
        commit("me/private-shop", leak, "m").await.unwrap();
        let sent: Vec<String> = log
            .lock()
            .unwrap()
            .iter()
            .filter(|seen| seen.path.ends_with("/git/blobs"))
            .map(Seen::json)
            .map(|body| body["content"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(sent.len(), 2);
        assert!(
            String::from_utf8(
                base64::engine::general_purpose::STANDARD
                    .decode(&sent[1])
                    .unwrap()
            )
            .unwrap()
            .contains(&token)
        );

        // The token is in no log row and no activity note.
        let kept = format!(
            "{:?}{:?}",
            lore.db.ops_log(100).unwrap(),
            lore.db.activity(100).unwrap()
        );
        assert!(!kept.contains(&token));
    }

    #[tokio::test]
    async fn levels_and_the_kill_switch_hold() {
        let (lore, log, session) = setup("levels").await;
        let tree = || lore.repo_tree(args(&session, json!({"repo": "me/shop"})), claude());
        let commit = || {
            lore.repo_commit(
                args(
                    &session,
                    json!({"repo": "me/shop", "branch": "main", "message": "m",
                           "changes": [{"path": "a", "content": "a"}]}),
                ),
                claude(),
            )
        };
        // read: reading works, committing does not.
        lore.db.set_ops_level("claude", "github", "read").unwrap();
        tree().await.unwrap();
        log.lock().unwrap().clear();
        assert_eq!(
            commit().await.unwrap_err(),
            "you have read-only access to github"
        );
        let row = last_row(&lore);
        assert_eq!(
            (row.method.as_str(), row.outcome.as_str()),
            ("POST", "denied")
        );
        // off: not even reading.
        lore.db.set_ops_level("claude", "github", "off").unwrap();
        assert_eq!(tree().await.unwrap_err(), "you have no access to github");
        assert_eq!(last_row(&lore).outcome, "denied");
        // The organization's level is its own.
        lore.repo_tree(
            args(
                &session,
                json!({"repo": "me/shop", "account": "organization"}),
            ),
            claude(),
        )
        .await
        .unwrap();
        // The kill switch stops everything.
        lore.db.set_ops_level("claude", "github", "full").unwrap();
        lore.db.set_ops_enabled(false).unwrap();
        log.lock().unwrap().clear();
        for refused in [tree().await.unwrap_err(), commit().await.unwrap_err()] {
            assert_eq!(refused, "operations are switched off by the administrator");
        }
        assert!(log.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn the_account_is_chosen_and_never_switched_silently() {
        let (lore, log, session) = setup("account").await;
        let tree = |value: Value| lore.repo_tree(args(&session, value), claude());
        let refused = tree(json!({"repo": "me/hidden-shop"})).await.unwrap_err();
        assert!(
            refused.starts_with("GitHub answered 404 for the repository"),
            "{refused}"
        );
        assert!(
            refused.ends_with(
                "The organization account's credential can see this repository: call again \
                 with `account: \"organization\"`."
            ),
            "{refused}"
        );
        // The look through the organization's credential is logged under
        // it; the call itself under the personal account.
        let rows = lore.db.ops_log(2).unwrap();
        assert_eq!(
            (rows[0].provider.as_str(), rows[0].outcome.as_str()),
            ("github", "error")
        );
        assert_eq!(
            (
                rows[1].provider.as_str(),
                rows[1].path.as_str(),
                rows[1].status
            ),
            ("github_org", "repo_access me/hidden-shop", 200)
        );
        // Named, the personal account gives no hint.
        let refused = tree(json!({"repo": "me/hidden-shop", "account": "personal"}))
            .await
            .unwrap_err();
        assert!(!refused.contains("organization"), "{refused}");
        // Without access to the organization's account, no look and no hint.
        lore.db
            .set_ops_level("claude", "github_org", "off")
            .unwrap();
        log.lock().unwrap().clear();
        let refused = tree(json!({"repo": "me/hidden-shop"})).await.unwrap_err();
        assert!(!refused.contains("organization"), "{refused}");
        assert!(
            log.lock()
                .unwrap()
                .iter()
                .all(|seen| seen.auth == format!("Bearer {PERSONAL}"))
        );
        // With the organization's account it works, with its credential.
        lore.db
            .set_ops_level("claude", "github_org", "read")
            .unwrap();
        log.lock().unwrap().clear();
        let answer = tree(json!({"repo": "me/hidden-shop", "account": "organization"}))
            .await
            .unwrap();
        assert!(answer.starts_with("me/hidden-shop @ main"), "{answer}");
        credential_kept(&lore, &log, ORGANIZATION, &[&answer]);
        assert_eq!(last_row(&lore).provider, "github_org");
        let refused = tree(json!({"repo": "me/shop", "account": "bogus"}))
            .await
            .unwrap_err();
        assert_eq!(refused, "account must be `personal` or `organization`");
    }

    #[tokio::test]
    async fn the_tools_need_a_real_session() {
        let (lore, log, _session) = setup("session").await;
        // No session id at all does not even parse: no implicit session.
        assert!(serde_json::from_value::<RepoTreeArgs>(json!({"repo": "me/shop"})).is_err());
        assert!(
            serde_json::from_value::<RepoCommitArgs>(json!({
                "repo": "me/shop", "branch": "main", "message": "m", "changes": []
            }))
            .is_err()
        );
        for id in ["", "s_nope"] {
            let refused = lore
                .repo_read(
                    args(id, json!({"repo": "me/shop", "paths": ["README.md"]})),
                    claude(),
                )
                .await
                .unwrap_err();
            assert!(refused.starts_with("no open session"), "{refused}");
        }
        assert!(log.lock().unwrap().is_empty());
        assert!(lore.db.ops_log(10).unwrap().is_empty());
        // Every tool's schema requires it.
        let router = Lore::tool_router();
        for name in ["repo_tree", "repo_read", "repo_search", "repo_commit"] {
            let schema = &router.get(name).unwrap().input_schema;
            let required = schema.get("required").and_then(|r| r.as_array()).unwrap();
            assert!(required.iter().any(|field| field == "session_id"), "{name}");
            assert!(required.iter().any(|field| field == "repo"), "{name}");
        }
    }

    #[test]
    fn paths_and_refs_are_checked_and_encoded() {
        assert_eq!(encode_path("docs/new file.md"), "docs/new%20file.md");
        assert_eq!(encode_path("a/ü?#.rs"), "a/%C3%BC%3F%23.rs");
        assert_eq!(directory(Some("/")).unwrap(), "");
        assert_eq!(directory(Some("src/")).unwrap(), "src");
        assert!(file_path("src/.gitignore").is_ok());
        for good in ["main", "feature/x", "v1.2.3", "abc1234"] {
            assert!(git_ref("ref", good).is_ok(), "{good}");
        }
        for bad in [
            "", "a b", "a..b", "-x", "/x", "x/", "x.lock", "a:b", "a~1", "x@{1}",
        ] {
            assert!(git_ref("ref", bad).is_err(), "{bad:?}");
        }
        assert_eq!(
            repository("https://github.com/me/shop.git").unwrap(),
            ("me".to_string(), "shop".to_string())
        );
        for bad in ["me", "me/shop/x", "../x", "me/sh op"] {
            assert!(repository(bad).is_err(), "{bad}");
        }
    }
}
