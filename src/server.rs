//! The MCP surface: tool definitions and their text rendering.

use std::time::Instant;

use axum::http::request::Parts;
use rmcp::{
    ServerHandler,
    handler::server::{common::Extension, router::tool::ToolRouter, wrapper::Parameters},
    model::{Implementation, ServerCapabilities, ServerConfig},
    schemars, tool, tool_handler, tool_router,
};
use serde::Deserialize;

use crate::{
    auth::{Agent, SHARED_AGENT},
    db::{
        BODY_MAX_CHARS, Db, Entry, FileInfo, Implicit, KINDS, Message, NOTE_MAX_CHARS, NewEntry,
        NewFile, NewMessage, NewSession, NewTask, Patch, Rule, Session, TASK_ACTIONS,
        TASK_TITLE_MAX_CHARS, Task,
    },
    embed::Embedder,
    events::Events,
    ops,
    vault::VaultKey,
};

const INSTRUCTIONS: &str = "\
Lore is the user's shared long-term memory across coding agents and sessions.

Every new chat must begin with `hello`, before any other lore tool. It opens a session \
for this chat and returns the briefing: how to address the user, the language to reply \
in, and the rules the user wants followed. Follow the briefing for the whole chat; it \
is given once per chat and is not repeated on later calls.

Pass the `session_id` that `hello` returns to every other lore tool in this chat. Keep \
the session current: call `checkin` each time you finish a meaningful step, and `bye` \
with a short summary before the chat ends.

Before starting work on a topic, call `recall` with a short description of what you are \
about to do, to find out whether it was done, decided or tried before. Use `recent` to see \
where a project was left off.

After any meaningful change, decision, bug fix or discovery, call `log` so future sessions \
can find it. Write entries for a reader with no context: say what changed, why, and where \
(files, commands, versions). One entry per topic; do not log trivia or secrets.

Every `log` call must say where the work stands: `path` (the project directory), `repo` \
(`git remote get-url origin`) and `commit` (`git rev-parse HEAD`), read fresh right before \
logging. Commit your work first when you can; otherwise set `dirty` to true. This is how \
agents tell who is ahead and who is behind: `projects` lists the last commit each agent \
logged per project, so compare it with your own HEAD before building on someone's work.

`project` is the repository or folder name in lowercase (for example `project-lore`). \
If an earlier entry is wrong or outdated, fix it with `amend` rather than adding a \
contradicting one.

The board is how agents work together. Before starting on something that may already \
be on the list, check it with `tasks`, and use `task_update` to claim a task before \
working on it and to mark it `done` (with the commit) when you finish it. Leave a `handoff` note \
when you stop in the middle of something, and use `send` for anything another agent \
must know.

When a file matters to a project beyond its code (the ideas it is built on, a design \
note, a schema, an important JSON or config file), keep it with `file_save` so other \
agents can find it with `files` and read it with `file_get`. Saving the same path again \
makes a new version. Do not store source code that lives in git, and never store secrets.

When the briefing lists services you can operate, call them through their tools — \
`cloudflare`, `github` for the personal GitHub account, `github_org` for the GitHub \
organization account, `git_server` for the self-hosted GitLab, `dokploy` — and check \
`integrations` first to see what you may do and how to address each one. The \
credentials are stored by the administrator and added by lore on the server side: \
never ask the user for one, and never send one yourself.";

/// The tools that existed before sessions. A client whose tool list
/// predates sessions may call them without `session_id`; lore then serves
/// the call through an implicit session.
const LEGACY_TOOLS: [&str; 7] = [
    "recall", "log", "recent", "projects", "get", "amend", "forget",
];

/// The title of a session lore opens itself for such a client.
const IMPLICIT_TITLE: &str = "Implicit session (client with an outdated tool list)";

/// Longest body returned inline by `recall` and `recent`; `get` returns everything.
const PREVIEW_CHARS: usize = 700;

/// Longest file text `file_get` returns; longer text is cut and says so.
const FILE_TEXT_CHARS: usize = 200_000;

#[derive(Clone)]
pub struct Lore {
    db: Db,
    embedder: Embedder,
    min_similarity: f32,
    /// Hours after which an open session is closed as inactive.
    idle_hours: u32,
    events: Events,
    /// The vault key, when the administrator set one. Without it no
    /// credential exists and the provider tools say so.
    vault: Option<VaultKey>,
    /// lore's own secrets and protected Dokploy ids, built at start-up.
    guard: ops::Guard,
    /// The HTTP client provider calls go through: no redirects, so a
    /// credential is never forwarded to another host.
    http: reqwest::Client,
    /// The tools this server offers; the notice for clients with an
    /// outdated tool list names them.
    tool_router: ToolRouter<Self>,
}

/// Keeps `session_id` listed as required in the schema of a legacy tool
/// whose `session_id` deserializes when missing (`#[serde(default)]`,
/// which schemars would otherwise mark optional), so new clients still
/// always send it.
fn require_session_id(schema: &mut schemars::Schema) {
    if let Some(object) = schema.as_object_mut() {
        let required = object
            .entry("required")
            .or_insert_with(|| serde_json::Value::Array(Vec::new()));
        if let Some(list) = required.as_array_mut()
            && !list.iter().any(|name| name == "session_id")
        {
            list.insert(0, "session_id".into());
        }
    }
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[schemars(transform = require_session_id)]
pub struct RecallArgs {
    /// Session id returned by `hello` for this chat.
    #[serde(default)]
    pub session_id: String,
    /// What you want to know, in natural language or keywords. Any language.
    pub query: String,
    /// Restrict to one project. Omit to search every project.
    pub project: Option<String>,
    /// Restrict to one kind: update, decision, bug, note or todo.
    pub kind: Option<String>,
    /// Maximum number of entries to return (default 8, max 25).
    pub limit: Option<u32>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[schemars(transform = require_session_id)]
pub struct LogArgs {
    /// Session id returned by `hello` for this chat.
    #[serde(default)]
    pub session_id: String,
    /// Repository or folder name in lowercase, e.g. `project-lore`.
    pub project: String,
    /// One of: update (a change you made), decision (a choice and its reason),
    /// bug (a problem and its fix), note (a fact worth keeping), todo (work left open).
    pub kind: String,
    /// One line that says what this entry is about.
    pub title: String,
    /// The details: what changed, why, and how. Written for a reader with no context.
    pub body: String,
    /// Absolute path of the project directory you are working in.
    pub path: String,
    /// Git remote of the project (output of `git remote get-url origin`).
    /// Pass "none" if the directory is not a git repository or has no remote.
    pub repo: String,
    /// Current HEAD commit hash (output of `git rev-parse HEAD`), read right
    /// before logging. Pass "none" only if the directory is not a git repository.
    pub commit: String,
    /// Current branch (output of `git branch --show-current`).
    pub branch: Option<String>,
    /// True if the working tree has uncommitted changes, i.e. the work this
    /// entry describes is not fully contained in `commit`.
    pub dirty: Option<bool>,
    /// Short topic tags, e.g. ["auth", "docker"].
    pub tags: Option<Vec<String>>,
    /// Paths of the files this entry is about.
    pub files: Option<Vec<String>>,
    /// The agent writing the entry, e.g. `claude-code`, `codex`, `opencode`.
    /// Ignored when the server identifies the agent from its token.
    pub agent: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[schemars(transform = require_session_id)]
pub struct RecentArgs {
    /// Session id returned by `hello` for this chat.
    #[serde(default)]
    pub session_id: String,
    /// Restrict to one project. Omit for every project.
    pub project: Option<String>,
    /// Restrict to one kind: update, decision, bug, note or todo.
    pub kind: Option<String>,
    /// Maximum number of entries to return (default 10, max 50).
    pub limit: Option<u32>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[schemars(transform = require_session_id)]
pub struct ProjectsArgs {
    /// Session id returned by `hello` for this chat.
    #[serde(default)]
    pub session_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[schemars(transform = require_session_id)]
pub struct IdArgs {
    /// Session id returned by `hello` for this chat.
    #[serde(default)]
    pub session_id: String,
    /// Entry id, as shown in `recall` and `recent` results.
    pub id: i64,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[schemars(transform = require_session_id)]
pub struct AmendArgs {
    /// Session id returned by `hello` for this chat.
    #[serde(default)]
    pub session_id: String,
    /// Id of the entry to change.
    pub id: i64,
    /// New kind. Omit to keep the current one.
    pub kind: Option<String>,
    /// New title. Omit to keep the current one.
    pub title: Option<String>,
    /// New body, replacing the old one. Omit to keep the current one.
    pub body: Option<String>,
    /// New tag list, replacing the old one. Omit to keep the current one.
    pub tags: Option<Vec<String>>,
    /// New file list, replacing the old one. Omit to keep the current one.
    pub files: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct HelloArgs {
    /// Repository or folder name in lowercase, e.g. `project-lore`.
    pub project: String,
    /// Absolute path of the project directory you are working in.
    pub path: String,
    /// Git remote of the project (output of `git remote get-url origin`).
    /// Pass "none" if the directory is not a git repository or has no remote.
    pub repo: String,
    /// Current HEAD commit hash (output of `git rev-parse HEAD`), read right
    /// before this call. Pass "none" if the directory is not a git repository.
    pub commit: String,
    /// Current branch (output of `git branch --show-current`).
    pub branch: Option<String>,
    /// One line that says what this chat is about.
    pub title: String,
    /// The agent starting the chat, e.g. `claude-code`, `codex`, `opencode`.
    /// Ignored when the server identifies the agent from its token.
    pub agent: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CheckinArgs {
    /// Session id returned by `hello` for this chat.
    pub session_id: String,
    /// What happened in this chat since the last check-in.
    pub note: String,
    /// Current HEAD commit hash (output of `git rev-parse HEAD`). Omit when
    /// it has not moved since the last check-in.
    pub commit: Option<String>,
    /// Current branch, when it has moved.
    pub branch: Option<String>,
    /// True if the working tree has uncommitted changes.
    pub dirty: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ByeArgs {
    /// Session id returned by `hello` for this chat.
    pub session_id: String,
    /// A short summary of what this chat accomplished.
    pub summary: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct TaskAddArgs {
    /// Session id returned by `hello` for this chat.
    pub session_id: String,
    /// Repository or folder name in lowercase, e.g. `project-lore`.
    pub project: String,
    /// One line that says what needs doing.
    pub title: String,
    /// The details: what exactly the task involves, links, constraints.
    pub body: Option<String>,
    /// The agent the task is meant for. Omit for anyone.
    pub assignee: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct TaskUpdateArgs {
    /// Session id returned by `hello` for this chat.
    pub session_id: String,
    /// Id of the task, as shown by `tasks`.
    pub id: i64,
    /// One of: claim (take the task), release (give it back), done
    /// (finished), cancel (no longer needed), reopen.
    pub action: String,
    /// Short status note: what changed, or why the task was closed.
    pub note: Option<String>,
    /// The HEAD commit the work was finished at, with `done`.
    pub commit: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct TasksArgs {
    /// Session id returned by `hello` for this chat.
    pub session_id: String,
    /// Restrict to one project. Omit for every project.
    pub project: Option<String>,
    /// One of: open (open + claimed, the default), done, cancelled, all.
    pub status: Option<String>,
    /// Maximum number of tasks to return (default 20, max 100).
    pub limit: Option<u32>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SendArgs {
    /// Session id returned by `hello` for this chat.
    pub session_id: String,
    /// What the other agent must know.
    pub body: String,
    /// One agent, or omit to tell every agent.
    pub to: Option<String>,
    /// The project the message is about, when it is about one.
    pub project: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct HandoffArgs {
    /// Session id returned by `hello` for this chat.
    pub session_id: String,
    /// The repository or folder name the note is about, in lowercase.
    pub project: String,
    /// Where the work stands and what is left, for whoever continues.
    pub body: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct InboxArgs {
    /// Session id returned by `hello` for this chat.
    pub session_id: String,
    /// Restrict to one project. Omit for every project.
    pub project: Option<String>,
    /// Also list the 20 latest messages you have already read.
    pub include_read: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct FileSaveArgs {
    /// Session id returned by `hello` for this chat.
    pub session_id: String,
    /// Repository or folder name in lowercase, e.g. `project-lore`.
    pub project: String,
    /// The file's name or path relative to the project, e.g. `docs/ideas.md`.
    /// Saving the same path again makes a new version.
    pub path: String,
    /// The whole file: its text, or its bytes as base64 with `encoding` set
    /// to `base64`. At most 2 MiB.
    pub content: String,
    /// Why the file matters to the project, in one or two sentences.
    pub description: String,
    /// One of: idea, doc, data, config, other. Omit it to keep the kind of
    /// the earlier versions (other for a new file).
    pub kind: Option<String>,
    /// utf8 (the default) for text, base64 for binary files.
    pub encoding: Option<String>,
    /// The id of a memory entry this file belongs to, if any.
    pub entry_id: Option<i64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct FileGetArgs {
    /// Session id returned by `hello` for this chat.
    pub session_id: String,
    /// File id, as shown by `files` and `recall`. Or give `project` and `path`.
    pub id: Option<i64>,
    /// The project the file belongs to, with `path`.
    pub project: Option<String>,
    /// The file's path within the project, with `project`.
    pub path: Option<String>,
    /// One version, with `project` and `path`. Omit for the latest.
    pub version: Option<i64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct FilesArgs {
    /// Session id returned by `hello` for this chat.
    pub session_id: String,
    /// Restrict to one project. Omit for every project.
    pub project: Option<String>,
    /// Search the paths and descriptions instead of listing the newest files.
    pub query: Option<String>,
    /// Maximum number of files to return (default 20, max 100).
    pub limit: Option<u32>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct FileDeleteArgs {
    /// Session id returned by `hello` for this chat.
    pub session_id: String,
    /// Id of the file version to delete, as shown by `files` and `file_get`.
    pub id: i64,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct IntegrationsArgs {
    /// Session id returned by `hello` for this chat.
    pub session_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct OpsArgs {
    /// Session id returned by `hello` for this chat.
    pub session_id: String,
    /// One of: GET, POST, PUT, PATCH, DELETE.
    pub method: String,
    /// The path after the provider's API base, starting with `/`, e.g.
    /// `/zones`. Query parameters go in `query`, never in the path.
    pub path: String,
    /// Query parameters, e.g. {"per_page": 1}. Values are strings,
    /// numbers or booleans.
    pub query: Option<serde_json::Map<String, serde_json::Value>>,
    /// The JSON body of the request. Not allowed with GET.
    pub body: Option<serde_json::Value>,
}

/// Where a legacy tool call says it comes from, for the implicit session it
/// may open: the call's `project`, and from `log` also the directory, the
/// git state and the agent name the call gives itself.
#[derive(Debug, Default)]
struct CallPlace {
    project: Option<String>,
    /// The agent the call says it is (`log`'s `agent`); only used with the
    /// shared token, which does not name one.
    declared: Option<String>,
    path: String,
    repo: String,
    commit: String,
    branch: String,
}

impl CallPlace {
    fn project(project: Option<&str>) -> Self {
        Self {
            project: project.map(str::to_string),
            ..Self::default()
        }
    }
}

/// A self-declared agent name usable for an implicit session: lowercase
/// letters, digits, `-`, `_` and `.`, at most 64 characters, and not one of
/// the names lore uses itself.
fn declared_agent(name: &str) -> Option<String> {
    let name = name.trim().to_lowercase();
    let valid = !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        && name != SHARED_AGENT
        && name != "admin";
    valid.then_some(name)
}

/// A legacy tool's result with the implicit-session text in front of it,
/// on success and on failure alike, so a briefing is never lost.
fn with_preface(preface: String, result: Result<String, String>) -> Result<String, String> {
    if preface.is_empty() {
        return result;
    }
    match result {
        Ok(text) => Ok(preface + &text),
        Err(error) => Err(preface + &error),
    }
}

#[tool_router]
impl Lore {
    pub fn new(
        db: Db,
        embedder: Embedder,
        min_similarity: f32,
        events: Events,
        idle_hours: u32,
        vault: Option<VaultKey>,
        guard: ops::Guard,
    ) -> Self {
        Self {
            db,
            embedder,
            min_similarity,
            idle_hours,
            events,
            vault,
            guard,
            http: ops::client(),
            tool_router: Self::tool_router(),
        }
    }

    /// Verifies the chat's session is open, current and this agent's, or tells
    /// the agent how to get one.
    fn require_session(&self, id: &str, agent: &str, shared: bool) -> Result<Session, String> {
        self.db
            .touch_session(id, agent, shared, self.idle_hours)
            .map_err(|error| {
                format!(
                    "no open session `{id}`: call `hello` first (once per chat) and pass \
                     the `session_id` it returns. {error}"
                )
            })
    }

    /// The session a call to one of the seven legacy tools runs in, and the
    /// text to put before its result. With a `session_id` this is exactly
    /// `require_session` and the text is empty, except that a closed
    /// implicit session of the caller is replaced by a fresh one. Without
    /// one, the agent's open implicit session is reused or a new one is
    /// opened from `place`; the text is then the notice about the outdated
    /// tool list, preceded by the `hello` briefing when this call opened
    /// the session.
    fn legacy_session(
        &self,
        given: &str,
        agent: &str,
        shared: bool,
        place: CallPlace,
    ) -> Result<(Session, String), String> {
        let given = given.trim();
        let mut replaced = None;
        if !given.is_empty() {
            match self.require_session(given, agent, shared) {
                Ok(session) => return Ok((session, String::new())),
                Err(error) => {
                    // An implicit session that has closed since (a `hello`,
                    // `bye` or inactivity) must not lock out a client that
                    // cannot call `hello`: it continues in a fresh one. Real
                    // sessions and unknown ids keep the error.
                    let replaceable = self
                        .db
                        .session(given)
                        .map_err(internal)?
                        .is_some_and(|row| row.implicit && (shared || row.agent == agent));
                    if !replaceable {
                        return Err(error);
                    }
                    replaced = Some(given.to_string());
                }
            }
        }
        // A per-agent token names the agent; with the shared token the
        // session goes by the name the call gives itself, if any.
        let owner = if shared {
            place
                .declared
                .as_deref()
                .and_then(declared_agent)
                .unwrap_or_else(|| SHARED_AGENT.to_string())
        } else {
            agent.to_string()
        };
        let new = NewSession {
            agent: owner,
            project: normalize_project_filter(place.project).unwrap_or_else(|| "unknown".into()),
            path: place.path.trim().to_string(),
            repo: optional_ref(&place.repo),
            commit: normalize_commit(&place.commit).unwrap_or_default(),
            branch: place.branch.trim().to_string(),
            title: IMPLICIT_TITLE.to_string(),
            implicit: true,
        };
        let (session, opened) = match self
            .db
            .implicit_session(&new, self.idle_hours)
            .map_err(internal)?
        {
            Implicit::Reused(session) => (session, false),
            Implicit::Opened(session) => (session, true),
        };
        let id = session.id.clone();
        let answer = (|| {
            let session = self.require_session(&id, agent, shared)?;
            let mut preface = String::new();
            if let Some(old) = &replaced {
                preface.push_str(&format!(
                    "Session {old} has closed, so lore continues in {}.\n\n",
                    session.id
                ));
            }
            if opened {
                // Stale sessions never show as open in the briefing.
                self.db
                    .close_idle_sessions(self.idle_hours)
                    .map_err(internal)?;
                preface.push_str(&format!(
                    "You called lore without a session, so lore opened one for you: {}.\n\n",
                    session.id
                ));
                preface.push_str(&self.open_briefing(&session, agent, false)?);
                preface.push_str("\n\n");
            }
            preface.push_str(&self.outdated_notice(&session.id));
            preface.push_str("\n\n");
            Ok((session, preface))
        })();
        // A session whose briefing could not be built is closed, so the
        // next call opens a fresh one and gets the briefing after all.
        if opened
            && answer.is_err()
            && let Err(error) = self
                .db
                .close_session(&id, "closed: the briefing could not be built")
        {
            tracing::warn!(%error, "closing an implicit session failed");
        }
        answer
    }

    /// The paragraph that tells a client with an outdated tool list what it
    /// is missing and how to get it. The tool names come from the router,
    /// so the list stays current.
    fn outdated_notice(&self, session_id: &str) -> String {
        let names: Vec<String> = self
            .tool_router
            .list_all()
            .into_iter()
            .map(|tool| tool.name.to_string())
            .filter(|name| !LEGACY_TOOLS.contains(&name.as_str()))
            .collect();
        format!(
            "This call came without a `session_id`, so lore used the implicit session \
             {session_id}. If your tool list has `hello`, call it once for this chat and pass \
             the `session_id` it returns. If it does not, your client holds an outdated lore \
             tool list; lore now also has: {}. Start a new chat or restart the MCP client to \
             load them. Until then pass \"session_id\": \"{session_id}\" on every lore call.",
            names.join(", ")
        )
    }

    #[tool(
        description = "Search the shared memory for past work, decisions, bugs and notes related to a topic. Call this before starting work to learn what was already done. Combines keyword and semantic search."
    )]
    async fn recall(
        &self,
        Parameters(args): Parameters<RecallArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<String, String> {
        let agent = agent_of(&parts);
        let shared = agent == SHARED_AGENT;
        let session_id = args.session_id.trim().to_string();
        let this = self.clone();
        blocking(move || {
            let (session, preface) = this.legacy_session(
                &session_id,
                &agent,
                shared,
                CallPlace::project(args.project.as_deref()),
            )?;
            let result = (|| {
                let query = args.query.trim().to_string();
                if query.is_empty() {
                    return Err("query must not be empty".into());
                }
                let project = normalize_project_filter(args.project);
                let kind = normalize_kind_filter(args.kind)?;
                let limit = args.limit.unwrap_or(8).clamp(1, 25) as usize;
                let vector = this.embedder.embed_query(&query).unwrap_or_else(|error| {
                    tracing::warn!(%error, "query embedding failed");
                    None
                });
                let hits = this
                    .db
                    .search(
                        &query,
                        vector.as_deref(),
                        project.as_deref(),
                        kind.as_deref(),
                        limit,
                        this.min_similarity,
                    )
                    .map_err(internal)?;
                let found: Vec<i64> = hits.iter().map(|hit| hit.entry.id).collect();
                this.note(
                    &agent,
                    "recall",
                    project.as_deref().unwrap_or(""),
                    Some(&session.id),
                    None,
                    &found,
                    &format!("\"{}\" → {} found", clip(&query, 90), found.len()),
                );
                // Files the query matches come after the entries; a failure here
                // only costs the hint.
                let related = this
                    .db
                    .search_files(
                        &query,
                        project.as_deref(),
                        vector.as_deref(),
                        this.min_similarity,
                        3,
                    )
                    .unwrap_or_else(|error| {
                        tracing::warn!(%error, "file search failed");
                        Vec::new()
                    });
                let mut related_text = String::new();
                if !related.is_empty() {
                    related_text.push_str("\nRelated files:\n");
                    for hit in &related {
                        related_text.push_str(&format!(
                            "- #{} {}/{} v{} — {}\n",
                            hit.file.id,
                            hit.file.project,
                            hit.file.path,
                            hit.file.version,
                            clip(&hit.file.description, 160)
                        ));
                    }
                    related_text.push_str("Read one with `file_get`.\n");
                }
                if hits.is_empty() {
                    let scope = project
                        .map(|p| format!(" in project `{p}`"))
                        .unwrap_or_default();
                    let mut out = format!("No entries found for \"{query}\"{scope}.");
                    out.push_str(&related_text);
                    return Ok(out);
                }
                let mut out = format!("{} entries for \"{query}\":\n", hits.len());
                for hit in &hits {
                    out.push('\n');
                    let matched = match hit.similarity {
                        Some(similarity) => format!("{} ({similarity:.2})", hit.matched),
                        None => hit.matched.to_string(),
                    };
                    out.push_str(&render(&hit.entry, Some(&matched), true));
                }
                out.push_str(&related_text);
                if !this.embedder.is_ready() {
                    out.push_str(
                        "\n(Semantic search is still warming up; results are keyword-only.)\n",
                    );
                }
                Ok(out)
            })();
            with_preface(preface, result)
        })
        .await
    }

    #[tool(
        description = "Record a change, decision, bug fix, note or open todo in the shared memory so future sessions and other agents can find it. Call this after any meaningful piece of work. Always include the project directory, its git remote and the current HEAD commit."
    )]
    async fn log(
        &self,
        Parameters(args): Parameters<LogArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<String, String> {
        // A per-agent token identifies the writer; only the shared token
        // falls back to what the model says it is.
        let actor = agent_of(&parts);
        let shared = actor == SHARED_AGENT;
        let session_id = args.session_id.trim().to_string();
        let declared = args.agent.clone();
        let agent = match parts.extensions.get::<Agent>() {
            Some(Agent(name)) if name != SHARED_AGENT => name.clone(),
            _ => args.agent.unwrap_or_default().trim().to_lowercase(),
        };
        let this = self.clone();
        blocking(move || {
            let (session, preface) = this.legacy_session(
                &session_id,
                &actor,
                shared,
                CallPlace {
                    project: Some(args.project.clone()),
                    declared,
                    path: args.path.clone(),
                    repo: args.repo.clone(),
                    commit: args.commit.clone(),
                    branch: args.branch.clone().unwrap_or_default(),
                },
            )?;
            let result = (|| {
                let new = NewEntry {
                    project: normalize_project(&args.project)?,
                    kind: normalize_kind(&args.kind)?,
                    title: required("title", &args.title)?,
                    body: required("body", &args.body)?,
                    tags: join_list(args.tags),
                    files: join_list(args.files),
                    agent,
                    path: required("path", &args.path)?,
                    repo: optional_ref(&args.repo),
                    commit: normalize_commit(&args.commit)?,
                    branch: args.branch.unwrap_or_default().trim().to_string(),
                    dirty: args.dirty.unwrap_or(false),
                    session_id: Some(session.id.clone()),
                };
                let entry = this.db.insert(&new).map_err(internal)?;
                this.embed_entry(&entry);
                let actor = if entry.agent.is_empty() {
                    &actor
                } else {
                    &entry.agent
                };
                this.note(
                    actor,
                    "log",
                    &entry.project,
                    Some(&session.id),
                    Some(entry.id),
                    &[],
                    &format!("[{}] {}", entry.kind, entry.title),
                );
                let at = if entry.commit.is_empty() {
                    " (no commit recorded)".to_string()
                } else {
                    format!(" at {}", describe_commit(&entry))
                };
                Ok(format!(
                    "Logged #{} in `{}` ({}){at}: {}",
                    entry.id, entry.project, entry.kind, entry.title
                ))
            })();
            with_preface(preface, result)
        })
        .await
    }

    #[tool(
        description = "List the most recent entries, newest first. Use it to see where a project was left off."
    )]
    async fn recent(
        &self,
        Parameters(args): Parameters<RecentArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<String, String> {
        let agent = agent_of(&parts);
        let shared = agent == SHARED_AGENT;
        let session_id = args.session_id.trim().to_string();
        let this = self.clone();
        blocking(move || {
            let (session, preface) = this.legacy_session(
                &session_id,
                &agent,
                shared,
                CallPlace::project(args.project.as_deref()),
            )?;
            let result = (|| {
                let project = normalize_project_filter(args.project);
                let kind = normalize_kind_filter(args.kind)?;
                let limit = args.limit.unwrap_or(10).clamp(1, 50) as usize;
                let entries = this
                    .db
                    .recent(project.as_deref(), kind.as_deref(), limit)
                    .map_err(internal)?;
                let seen: Vec<i64> = entries.iter().map(|entry| entry.id).collect();
                this.note(
                    &agent,
                    "recent",
                    project.as_deref().unwrap_or(""),
                    Some(&session.id),
                    None,
                    &seen,
                    &format!("{} newest entries", seen.len()),
                );
                if entries.is_empty() {
                    return Ok("No entries yet.".to_string());
                }
                let mut out = format!("{} most recent entries:\n", entries.len());
                for entry in &entries {
                    out.push('\n');
                    out.push_str(&render(entry, None, true));
                }
                Ok(out)
            })();
            with_preface(preface, result)
        })
        .await
    }

    #[tool(
        description = "List every project in the shared memory with its entry count, last activity, and the commit each agent last logged at. Compare those commits with your own HEAD to see who is ahead or behind."
    )]
    async fn projects(
        &self,
        Parameters(args): Parameters<ProjectsArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<String, String> {
        let agent = agent_of(&parts);
        let shared = agent == SHARED_AGENT;
        let session_id = args.session_id.trim().to_string();
        let this = self.clone();
        blocking(move || {
            let (session, preface) =
                this.legacy_session(&session_id, &agent, shared, CallPlace::default())?;
            let result = (|| {
                let projects = this.db.projects().map_err(internal)?;
                this.note(
                    &agent,
                    "projects",
                    "",
                    Some(&session.id),
                    None,
                    &[],
                    &format!("{} projects", projects.len()),
                );
                if projects.is_empty() {
                    return Ok("No projects yet.".to_string());
                }
                let mut out = String::from("Projects (most recently active first):\n");
                for p in projects {
                    out.push_str(&format!(
                        "- `{}`: {} entries, last activity {}\n",
                        p.project, p.entries, p.last_activity
                    ));
                    for head in &p.heads {
                        let agent = if head.agent.is_empty() {
                            "unknown agent"
                        } else {
                            &head.agent
                        };
                        let branch = if head.branch.is_empty() {
                            String::new()
                        } else {
                            format!(" on {}", head.branch)
                        };
                        let dirty = if head.dirty {
                            ", with uncommitted changes"
                        } else {
                            ""
                        };
                        out.push_str(&format!(
                            "    {agent} last logged at commit {}{branch}{dirty} ({}, entry #{})\n",
                            short(&head.commit),
                            head.at,
                            head.entry_id
                        ));
                    }
                }
                Ok(out)
            })();
            with_preface(preface, result)
        })
        .await
    }

    #[tool(
        description = "Fetch one entry in full by id. Use it when a recall result was truncated."
    )]
    async fn get(
        &self,
        Parameters(args): Parameters<IdArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<String, String> {
        let agent = agent_of(&parts);
        let shared = agent == SHARED_AGENT;
        let session_id = args.session_id.trim().to_string();
        let this = self.clone();
        blocking(move || {
            let (session, preface) =
                this.legacy_session(&session_id, &agent, shared, CallPlace::default())?;
            let result = (|| match this.db.get(args.id).map_err(internal)? {
                Some(entry) => {
                    this.note(
                        &agent,
                        "get",
                        &entry.project,
                        Some(&session.id),
                        Some(entry.id),
                        &[],
                        &entry.title,
                    );
                    Ok(render(&entry, None, false))
                }
                None => Err(format!("No entry with id {}.", args.id)),
            })();
            with_preface(preface, result)
        })
        .await
    }

    #[tool(
        description = "Correct or update an existing entry. Only the fields you pass are changed. Prefer this over logging a contradicting entry."
    )]
    async fn amend(
        &self,
        Parameters(args): Parameters<AmendArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<String, String> {
        let agent = agent_of(&parts);
        let shared = agent == SHARED_AGENT;
        let session_id = args.session_id.trim().to_string();
        let this = self.clone();
        blocking(move || {
            let (session, preface) =
                this.legacy_session(&session_id, &agent, shared, CallPlace::default())?;
            let result = (|| {
                let patch = Patch {
                    kind: args.kind.as_deref().map(normalize_kind).transpose()?,
                    title: args
                        .title
                        .as_deref()
                        .map(|t| required("title", t))
                        .transpose()?,
                    body: args
                        .body
                        .as_deref()
                        .map(|b| required("body", b))
                        .transpose()?,
                    tags: args.tags.map(|t| join_list(Some(t))),
                    files: args.files.map(|f| join_list(Some(f))),
                };
                match this.db.amend(args.id, &patch).map_err(internal)? {
                    Some(entry) => {
                        this.embed_entry(&entry);
                        this.note(
                            &agent,
                            "amend",
                            &entry.project,
                            Some(&session.id),
                            Some(entry.id),
                            &[],
                            &entry.title,
                        );
                        Ok(format!("Updated #{}: {}", entry.id, entry.title))
                    }
                    None => Err(format!("No entry with id {}.", args.id)),
                }
            })();
            with_preface(preface, result)
        })
        .await
    }

    #[tool(
        description = "Permanently delete an entry by id. Use only for entries that are wrong or were logged by mistake."
    )]
    async fn forget(
        &self,
        Parameters(args): Parameters<IdArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<String, String> {
        let agent = agent_of(&parts);
        let shared = agent == SHARED_AGENT;
        let session_id = args.session_id.trim().to_string();
        let this = self.clone();
        blocking(move || {
            let (session, preface) =
                this.legacy_session(&session_id, &agent, shared, CallPlace::default())?;
            let result = (|| {
                let existing = this.db.get(args.id).map_err(internal)?;
                if this.db.delete(args.id).map_err(internal)? {
                    let (project, title) = existing
                        .map(|entry| (entry.project, entry.title))
                        .unwrap_or_default();
                    this.note(
                        &agent,
                        "forget",
                        &project,
                        Some(&session.id),
                        Some(args.id),
                        &[],
                        &title,
                    );
                    Ok(format!("Deleted #{}.", args.id))
                } else {
                    Err(format!("No entry with id {}.", args.id))
                }
            })();
            with_preface(preface, result)
        })
        .await
    }

    #[tool(
        description = "Open the session for this chat and get the briefing: how to address the user, the language to reply in, the rules the user wants followed, notes left for whoever works on the project next, your unread messages, the open tasks, the files kept for the project, other open sessions, and where the project was left off. Call this once at the very start of every new chat, before any other lore tool."
    )]
    async fn hello(
        &self,
        Parameters(args): Parameters<HelloArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<String, String> {
        // A per-agent token identifies the agent; only the shared token
        // falls back to what the model says it is.
        let actor = agent_of(&parts);
        let agent = match parts.extensions.get::<Agent>() {
            Some(Agent(name)) if name != SHARED_AGENT => name.clone(),
            _ => args.agent.unwrap_or_default().trim().to_lowercase(),
        };
        let this = self.clone();
        blocking(move || {
            let new = NewSession {
                agent,
                project: normalize_project(&args.project)?,
                path: required("path", &args.path)?,
                repo: optional_ref(&args.repo),
                commit: normalize_commit(&args.commit)?,
                branch: args.branch.unwrap_or_default().trim().to_string(),
                title: one_line("title", &args.title)?,
                implicit: false,
            };
            // Stale sessions never show as open in the briefing.
            this.db
                .close_idle_sessions(this.idle_hours)
                .map_err(internal)?;
            // Implicit sessions are left alone: one may still serve another
            // chat of this agent whose client cannot call `hello`. They end
            // with `bye` or after inactivity.
            let session = this.db.open_session(&new).map_err(internal)?;
            this.open_briefing(&session, &actor, true)
        })
        .await
    }

    #[tool(
        description = "Record what happened in this chat since the last check-in, keeping the session current. Call it after every meaningful step."
    )]
    async fn checkin(
        &self,
        Parameters(args): Parameters<CheckinArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<String, String> {
        let agent = agent_of(&parts);
        let shared = agent == SHARED_AGENT;
        let session_id = args.session_id.trim().to_string();
        let this = self.clone();
        blocking(move || {
            let session = this.require_session(&session_id, &agent, shared)?;
            let note = required("note", &args.note)?;
            let commit = match args.commit.as_deref() {
                None => None,
                Some(commit) => Some(normalize_commit(commit)?),
            };
            let branch = args
                .branch
                .as_deref()
                .map(str::trim)
                .filter(|branch| !branch.is_empty());
            if let Some(commit) = &commit {
                this.db
                    .set_session_head(&session.id, commit, branch)
                    .map_err(internal)?;
            }
            let update = this
                .db
                .add_session_update(
                    &session.id,
                    &note,
                    commit.as_deref().unwrap_or(""),
                    branch.unwrap_or(""),
                    args.dirty.unwrap_or(false),
                )
                .map_err(internal)?;
            let clipped = clip(&note, 90);
            this.note(
                &agent,
                "checkin",
                &session.project,
                Some(&session.id),
                None,
                &[],
                &clipped,
            );
            let mut out = format!("Checked in on {}: {}", update.session_id, clipped);
            // Only a hint, so the agent knows to look: reading them is what
            // `inbox` is for.
            let actor = session_agent(&agent, &session);
            let unread = this.db.unread_message_count(actor).map_err(internal)?;
            if unread > 0 {
                out.push_str(&format!(
                    "\nYou have {unread} unread message(s): call `inbox`."
                ));
            }
            Ok(out)
        })
        .await
    }

    #[tool(
        description = "Close the session with a short summary of what this chat accomplished. Call it before the chat ends."
    )]
    async fn bye(
        &self,
        Parameters(args): Parameters<ByeArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<String, String> {
        let agent = agent_of(&parts);
        let shared = agent == SHARED_AGENT;
        let session_id = args.session_id.trim().to_string();
        let this = self.clone();
        blocking(move || {
            let session = this.require_session(&session_id, &agent, shared)?;
            let summary = required("summary", &args.summary)?;
            let closed = this
                .db
                .close_session(&session.id, &summary)
                .map_err(internal)?;
            let clipped = clip(&summary, 90);
            this.note(
                &agent,
                "bye",
                &closed.project,
                Some(&closed.id),
                None,
                &[],
                &clipped,
            );
            Ok(format!("Session {} closed: {}", closed.id, clipped))
        })
        .await
    }

    #[tool(
        description = "Add a task to the shared to-do list of a project: work that should not be forgotten, or that another agent could pick up. Say exactly what needs doing."
    )]
    async fn task_add(
        &self,
        Parameters(args): Parameters<TaskAddArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<String, String> {
        let agent = agent_of(&parts);
        let shared = agent == SHARED_AGENT;
        let session_id = args.session_id.trim().to_string();
        let this = self.clone();
        blocking(move || {
            let session = this.require_session(&session_id, &agent, shared)?;
            let actor = session_agent(&agent, &session);
            let new = NewTask {
                project: normalize_project(&args.project)?,
                title: short_line("title", &args.title, TASK_TITLE_MAX_CHARS)?,
                body: capped("body", args.body.as_deref(), BODY_MAX_CHARS)?,
                assignee: args
                    .assignee
                    .as_deref()
                    .map(|a| a.trim().to_lowercase())
                    .unwrap_or_default(),
                created_by: actor.to_string(),
                session_id: Some(session.id.clone()),
            };
            let task = this.db.add_task(&new).map_err(internal)?;
            this.note(
                actor,
                "task_add",
                &task.project,
                Some(&session.id),
                None,
                &[],
                &format!("task #{}: {}", task.id, task.title),
            );
            Ok(format!(
                "Task #{} added to `{}`: {}",
                task.id, task.project, task.title
            ))
        })
        .await
    }

    #[tool(
        description = "Update a task on the shared to-do list. Call `tasks` to see the ids. Claim a task with `claim` before you start working on it, and mark it `done` (with the commit) when you finish. Also: `release` a task you are giving up, `cancel` one that is no longer needed, `reopen` one that was closed by mistake."
    )]
    async fn task_update(
        &self,
        Parameters(args): Parameters<TaskUpdateArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<String, String> {
        let agent = agent_of(&parts);
        let shared = agent == SHARED_AGENT;
        let session_id = args.session_id.trim().to_string();
        let this = self.clone();
        blocking(move || {
            let session = this.require_session(&session_id, &agent, shared)?;
            let actor = session_agent(&agent, &session);
            let action = args.action.trim().to_lowercase();
            if !TASK_ACTIONS.contains(&action.as_str()) {
                return Err(format!(
                    "action must be one of: {}",
                    TASK_ACTIONS.join(", ")
                ));
            }
            let note = args
                .note
                .as_deref()
                .map(|note| capped("note", Some(note), NOTE_MAX_CHARS))
                .transpose()?
                .filter(|note| !note.is_empty());
            let commit = match args.commit.as_deref() {
                None => None,
                Some(commit) => Some(normalize_commit(commit)?),
            };
            let task = match this.db.update_task(
                args.id,
                &action,
                actor,
                note.as_deref(),
                commit.as_deref(),
            ) {
                Ok(Some(task)) => task,
                Ok(None) => return Err(format!("No task with id {}.", args.id)),
                // A refused transition is an answer to the agent, not a
                // server fault: it names the task's current status.
                Err(error) => {
                    tracing::warn!(%error, id = args.id, "task update refused");
                    return Err(error.to_string());
                }
            };
            let effect = match action.as_str() {
                "claim" => "claimed".to_string(),
                "release" => "released".to_string(),
                "done" => {
                    if task.done_commit.is_empty() {
                        "marked done".to_string()
                    } else {
                        format!("marked done at {}", short(&task.done_commit))
                    }
                }
                "cancel" => "cancelled".to_string(),
                _ => "reopened".to_string(),
            };
            this.note(
                actor,
                "task_update",
                &task.project,
                Some(&session.id),
                None,
                &[],
                &format!("task #{} {effect}", task.id),
            );
            Ok(format!("Task #{} {effect}.", task.id))
        })
        .await
    }

    #[tool(
        description = "List the tasks on the shared to-do list: open and claimed ones by default, or done, cancelled or all of them. Check this before starting work that may already be on the list."
    )]
    async fn tasks(
        &self,
        Parameters(args): Parameters<TasksArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<String, String> {
        let agent = agent_of(&parts);
        let shared = agent == SHARED_AGENT;
        let session_id = args.session_id.trim().to_string();
        let this = self.clone();
        blocking(move || {
            let session = this.require_session(&session_id, &agent, shared)?;
            let actor = session_agent(&agent, &session);
            let status = args.status.as_deref().map(|s| s.trim().to_lowercase());
            let statuses: &[&str] = match status.as_deref() {
                None | Some("") | Some("open") => &["open", "claimed"],
                Some("done") => &["done"],
                Some("cancelled") => &["cancelled"],
                Some("all") => &[],
                Some(other) => {
                    return Err(format!(
                        "status must be open, done, cancelled or all, not \"{other}\""
                    ));
                }
            };
            let word = match statuses {
                ["open", "claimed"] => " open",
                ["done"] => " done",
                ["cancelled"] => " cancelled",
                _ => "",
            };
            let limit = args.limit.unwrap_or(20).clamp(1, 100) as usize;
            let project = normalize_project_filter(args.project);
            let list = this
                .db
                .tasks(project.as_deref(), statuses, limit)
                .map_err(internal)?;
            this.note(
                actor,
                "tasks",
                project.as_deref().unwrap_or(""),
                Some(&session.id),
                None,
                &[],
                &format!("{} tasks", list.len()),
            );
            if list.is_empty() {
                let scope = project.map(|p| format!(" on `{p}`")).unwrap_or_default();
                return Ok(format!("No{word} tasks{scope}."));
            }
            let scope = project.map(|p| format!(" on `{p}`")).unwrap_or_default();
            let mut out = format!("{}{} tasks{scope}:\n", list.len(), word);
            for task in &list {
                out.push('\n');
                out.push_str(&render_task(task));
            }
            Ok(out)
        })
        .await
    }

    #[tool(
        description = "Send a message to one other agent, or to every agent when `to` is omitted. Use it for anything another agent must know, even in a later session: they read their unread messages in `hello` and `inbox`."
    )]
    async fn send(
        &self,
        Parameters(args): Parameters<SendArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<String, String> {
        let agent = agent_of(&parts);
        let shared = agent == SHARED_AGENT;
        let session_id = args.session_id.trim().to_string();
        let this = self.clone();
        blocking(move || {
            let session = this.require_session(&session_id, &agent, shared)?;
            let actor = session_agent(&agent, &session);
            let to = args
                .to
                .as_deref()
                .map(|to| to.trim().to_lowercase())
                .filter(|to| !to.is_empty());
            let project = normalize_project_filter(args.project);
            let message = this
                .db
                .add_message(&NewMessage {
                    kind: "message".to_string(),
                    project: project.clone().unwrap_or_default(),
                    from_agent: actor.to_string(),
                    to_agent: to.clone().unwrap_or_default(),
                    body: long_text("body", &args.body, BODY_MAX_CHARS)?,
                    session_id: Some(session.id.clone()),
                })
                .map_err(internal)?;
            this.note(
                actor,
                "send",
                &message.project,
                Some(&session.id),
                None,
                &[],
                &format!("message #{}: {}", message.id, clip(&message.body, 90)),
            );
            Ok(match to {
                Some(to) => format!("Message #{} sent to {}.", message.id, to),
                None => format!("Message #{} sent to everyone.", message.id),
            })
        })
        .await
    }

    #[tool(
        description = "Leave a handoff note for whoever works on this project next: where the work stands, what is done, what is left. It is delivered exactly once, to the next session on the project that is not this one."
    )]
    async fn handoff(
        &self,
        Parameters(args): Parameters<HandoffArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<String, String> {
        let agent = agent_of(&parts);
        let shared = agent == SHARED_AGENT;
        let session_id = args.session_id.trim().to_string();
        let this = self.clone();
        blocking(move || {
            let session = this.require_session(&session_id, &agent, shared)?;
            let actor = session_agent(&agent, &session);
            let project = normalize_project(&args.project)?;
            let message = this
                .db
                .add_message(&NewMessage {
                    kind: "handoff".to_string(),
                    project: project.clone(),
                    from_agent: actor.to_string(),
                    to_agent: String::new(),
                    body: long_text("body", &args.body, BODY_MAX_CHARS)?,
                    session_id: Some(session.id.clone()),
                })
                .map_err(internal)?;
            this.note(
                actor,
                "handoff",
                &message.project,
                Some(&session.id),
                None,
                &[],
                &clip(&message.body, 90),
            );
            Ok(format!(
                "Handoff note #{} left for the next session on `{}`.",
                message.id, message.project
            ))
        })
        .await
    }

    #[tool(
        description = "Read the messages other agents sent you: the ones addressed to you and the ones sent to everyone. Returns up to 30 unread messages, newest first, and marks them read. With include_read it also lists the 20 latest ones you have already read."
    )]
    async fn inbox(
        &self,
        Parameters(args): Parameters<InboxArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<String, String> {
        let agent = agent_of(&parts);
        let shared = agent == SHARED_AGENT;
        let session_id = args.session_id.trim().to_string();
        let this = self.clone();
        blocking(move || {
            let session = this.require_session(&session_id, &agent, shared)?;
            let actor = session_agent(&agent, &session);
            let project = normalize_project_filter(args.project);
            // The already-read list is taken before this call marks
            // anything, so it holds only what was read earlier.
            let mut read = Vec::new();
            if args.include_read.unwrap_or(false) {
                read = this
                    .db
                    .read_messages(actor, project.as_deref(), 20)
                    .map_err(internal)?;
            }
            let mut unread = this
                .db
                .unread_messages(actor, project.as_deref(), 30)
                .map_err(internal)?;
            // Only what this call marked is shown as unread, so another
            // session of the same agent reading at the same moment does not
            // get the same messages as new too.
            let ids: Vec<i64> = unread.iter().map(|message| message.id).collect();
            let marked = this.db.mark_read(actor, &ids).map_err(internal)?;
            unread.retain(|message| marked.contains(&message.id));
            let scope = project
                .as_deref()
                .map(|p| format!(" about `{p}`"))
                .unwrap_or_default();
            let mut out = if unread.is_empty() {
                format!("No unread messages{scope}.")
            } else {
                let mut out = format!("{} unread messages{scope}:\n", unread.len());
                for message in &unread {
                    out.push('\n');
                    out.push_str(&render_message(message, BODY_MAX_CHARS));
                }
                out
            };
            if !read.is_empty() {
                out.push_str("\n\nAlready read, newest first:\n");
                for message in &read {
                    out.push('\n');
                    out.push_str(&render_message(message, BODY_MAX_CHARS));
                }
            }
            this.note(
                actor,
                "inbox",
                project.as_deref().unwrap_or(""),
                Some(&session.id),
                None,
                &[],
                &format!("{} unread, {} read", unread.len(), read.len()),
            );
            Ok(out)
        })
        .await
    }

    #[tool(
        description = "Keep a file that matters to a project so future agents can find and read it: the ideas the project is built on, a design note, a schema, an important JSON or config file. Not source code that lives in git, and never secrets (keys, tokens, passwords, .env files). Saving the same path again stores a new version; identical content is not stored twice. Text is sent as is; binary files as base64 with encoding `base64`. At most 2 MiB."
    )]
    async fn file_save(
        &self,
        Parameters(args): Parameters<FileSaveArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<String, String> {
        let agent = agent_of(&parts);
        let shared = agent == SHARED_AGENT;
        let session_id = args.session_id.trim().to_string();
        let this = self.clone();
        blocking(move || {
            let session = this.require_session(&session_id, &agent, shared)?;
            let actor = session_agent(&agent, &session);
            let new = NewFile {
                project: normalize_project(&args.project)?,
                path: args.path,
                kind: args.kind.unwrap_or_default(),
                description: args.description,
                encoding: args.encoding.unwrap_or_default(),
                content: args.content,
                entry_id: args.entry_id,
                agent: actor.to_string(),
                session_id: Some(session.id.clone()),
            };
            // A refused file is an answer to the agent, not a server fault:
            // it says what was wrong with it.
            let saved = this.db.save_file(&new).map_err(|error| {
                tracing::warn!(%error, "file save refused");
                error.to_string()
            })?;
            if saved.needs_embedding {
                this.embed_file(&saved.file);
            }
            let file = &saved.file;
            this.note(
                actor,
                "file_save",
                &file.project,
                Some(&session.id),
                None,
                &[],
                &format!(
                    "{} v{}{}",
                    file.path,
                    file.version,
                    if saved.unchanged { " (unchanged)" } else { "" }
                ),
            );
            Ok(if saved.unchanged {
                format!(
                    "{} is unchanged (v{}, file #{}).",
                    file.path, file.version, file.id
                )
            } else {
                format!(
                    "Saved {} v{} in {} ({}, file #{}).",
                    file.path,
                    file.version,
                    file.project,
                    human_size(file.size),
                    file.id
                )
            })
        })
        .await
    }

    #[tool(
        description = "Read a file kept in lore: by `id`, or by `project` and `path` (the latest version unless `version` is given). Returns what the file is and why it matters, its other versions, and its content."
    )]
    async fn file_get(
        &self,
        Parameters(args): Parameters<FileGetArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<String, String> {
        let agent = agent_of(&parts);
        let shared = agent == SHARED_AGENT;
        let session_id = args.session_id.trim().to_string();
        let this = self.clone();
        blocking(move || {
            let session = this.require_session(&session_id, &agent, shared)?;
            let actor = session_agent(&agent, &session);
            let found = match (args.id, args.project.as_deref(), args.path.as_deref()) {
                (Some(id), _, _) => this.db.file(id).map_err(internal)?,
                (None, Some(project), Some(path)) => this
                    .db
                    .file_at(project, path, args.version)
                    .map_err(|error| error.to_string())?,
                _ => return Err("give the file's `id`, or its `project` and `path`".into()),
            };
            let Some(file) = found else {
                return Err(match args.id {
                    Some(id) => format!("No file with id {id}."),
                    None => "No such file (or no such version of it).".to_string(),
                });
            };
            let info = &file.info;
            let versions = this
                .db
                .file_versions(&info.project, &info.path)
                .map_err(internal)?;
            this.note(
                actor,
                "file_get",
                &info.project,
                Some(&session.id),
                None,
                &[],
                &format!("{} v{}", info.path, info.version),
            );
            let mut out = format!(
                "#{} {}/{} v{} · {} · {} · sha256 {} · saved by {} at {}\n",
                info.id,
                info.project,
                info.path,
                info.version,
                info.kind,
                human_size(info.size),
                &info.sha256[..info.sha256.len().min(12)],
                info.agent,
                info.created_at
            );
            out.push_str(&format!("Why it matters: {}\n", info.description));
            if let Some(entry_id) = info.entry_id {
                out.push_str(&format!("Belongs to entry #{entry_id}.\n"));
            }
            let others: Vec<String> = versions
                .iter()
                .filter(|other| other.id != info.id)
                .map(|other| format!("v{} (#{})", other.version, other.id))
                .collect();
            if others.is_empty() {
                out.push_str("No other versions.\n");
            } else {
                out.push_str(&format!("Other versions: {}.\n", others.join(", ")));
            }
            out.push('\n');
            if info.encoding == "base64" {
                use base64::Engine;
                out.push_str(
                    "Binary file, shown as base64 (decode it to get the raw bytes):\n",
                );
                out.push_str(&base64::engine::general_purpose::STANDARD.encode(&file.content));
                out.push('\n');
            } else {
                let text = String::from_utf8_lossy(&file.content);
                let total = text.chars().count();
                if total > FILE_TEXT_CHARS {
                    let cut: String = text.chars().take(FILE_TEXT_CHARS).collect();
                    out.push_str(&cut);
                    out.push_str(&format!(
                        "\n… (truncated: this shows the first {FILE_TEXT_CHARS} of {total} characters)\n"
                    ));
                } else {
                    out.push_str(&text);
                    if !text.ends_with('\n') {
                        out.push('\n');
                    }
                }
            }
            Ok(out)
        })
        .await
    }

    #[tool(
        description = "List the files kept in lore, newest first, or search their paths and descriptions with `query`. Read one with `file_get`."
    )]
    async fn files(
        &self,
        Parameters(args): Parameters<FilesArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<String, String> {
        let agent = agent_of(&parts);
        let shared = agent == SHARED_AGENT;
        let session_id = args.session_id.trim().to_string();
        let this = self.clone();
        blocking(move || {
            let session = this.require_session(&session_id, &agent, shared)?;
            let actor = session_agent(&agent, &session);
            let project = normalize_project_filter(args.project);
            let query = args
                .query
                .as_deref()
                .map(str::trim)
                .filter(|query| !query.is_empty())
                .map(str::to_string);
            let limit = args.limit.unwrap_or(20).clamp(1, 100) as usize;
            // Each file with how a search found it, when this is a search.
            let list: Vec<(FileInfo, Option<String>)> = match &query {
                None => this
                    .db
                    .files(project.as_deref(), limit)
                    .map_err(internal)?
                    .into_iter()
                    .map(|file| (file, None))
                    .collect(),
                Some(query) => {
                    let vector = this.embedder.embed_query(query).unwrap_or_else(|error| {
                        tracing::warn!(%error, "query embedding failed");
                        None
                    });
                    this.db
                        .search_files(
                            query,
                            project.as_deref(),
                            vector.as_deref(),
                            this.min_similarity,
                            limit,
                        )
                        .map_err(internal)?
                        .into_iter()
                        .map(|hit| {
                            let matched = match hit.similarity {
                                Some(similarity) => format!("{} ({similarity:.2})", hit.matched),
                                None => hit.matched.to_string(),
                            };
                            (hit.file, Some(matched))
                        })
                        .collect()
                }
            };
            this.note(
                actor,
                "files",
                project.as_deref().unwrap_or(""),
                Some(&session.id),
                None,
                &[],
                &match &query {
                    Some(query) => format!("\"{}\" → {} found", clip(query, 90), list.len()),
                    None => format!("{} files", list.len()),
                },
            );
            let scope = project
                .as_deref()
                .map(|p| format!(" in `{p}`"))
                .unwrap_or_default();
            if list.is_empty() {
                return Ok(match &query {
                    Some(query) => format!("No files found for \"{query}\"{scope}."),
                    None => format!("No files kept{scope} yet."),
                });
            }
            let mut out = match &query {
                Some(query) => format!("{} files for \"{query}\"{scope}:\n", list.len()),
                None => format!("{} newest files{scope}:\n", list.len()),
            };
            for (file, matched) in &list {
                let matched = matched
                    .as_deref()
                    .map(|matched| format!(" · match: {matched}"))
                    .unwrap_or_default();
                out.push_str(&format!(
                    "\n#{} {}/{} v{} [{}] {} · {} · {}{matched}\n{}\n",
                    file.id,
                    file.project,
                    file.path,
                    file.version,
                    file.kind,
                    human_size(file.size),
                    file.agent,
                    file.created_at,
                    file.description
                ));
            }
            Ok(out)
        })
        .await
    }

    #[tool(
        description = "Delete one version of a file kept in lore, by id. Use only for a version saved by mistake or one that must not be kept."
    )]
    async fn file_delete(
        &self,
        Parameters(args): Parameters<FileDeleteArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<String, String> {
        let agent = agent_of(&parts);
        let shared = agent == SHARED_AGENT;
        let session_id = args.session_id.trim().to_string();
        let this = self.clone();
        blocking(move || {
            let session = this.require_session(&session_id, &agent, shared)?;
            let actor = session_agent(&agent, &session);
            let Some(file) = this.db.delete_file(args.id).map_err(internal)? else {
                return Err(format!("No file with id {}.", args.id));
            };
            this.note(
                actor,
                "file_delete",
                &file.project,
                Some(&session.id),
                None,
                &[],
                &format!("{} v{}", file.path, file.version),
            );
            Ok(format!(
                "Deleted {} v{} in {} (file #{}).",
                file.path, file.version, file.project, file.id
            ))
        })
        .await
    }

    #[tool(
        description = "List the services you may operate through lore — Cloudflare, GitHub (the personal account and the organization account), a self-hosted GitLab, Dokploy — with your access level on each, the API base to address them and a link to each API reference. The credentials are stored by the administrator and added by lore on the server side; you never see them."
    )]
    async fn integrations(
        &self,
        Parameters(args): Parameters<IntegrationsArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<String, String> {
        let agent = agent_of(&parts);
        let shared = agent == SHARED_AGENT;
        let session_id = args.session_id.trim().to_string();
        let host = public_host(&parts);
        let this = self.clone();
        blocking(move || {
            let session = this.require_session(&session_id, &agent, shared)?;
            let actor = session_agent(&agent, &session);
            let enabled = this.db.ops_enabled().map_err(internal)?;
            let status = this.db.vault_status().map_err(internal)?;
            let mut out = String::new();
            if this.vault.is_none() {
                out.push_str(
                    "The vault is not enabled on this server, so no credential is stored.\n",
                );
            } else if !enabled {
                out.push_str("Operations are switched off by the administrator right now.\n");
            }
            out.push_str("Services you can call through lore:\n");
            let mut usable = 0;
            for (provider, row) in ops::ALL.iter().zip(status.iter()) {
                let level =
                    ops::effective_level(&this.db, &agent, actor, provider.id).map_err(internal)?;
                let line = if !row.configured {
                    format!("- {} — not configured yet", provider.label)
                } else {
                    let access = match level {
                        "off" => "no access".to_string(),
                        "read" => "read-only".to_string(),
                        _ => {
                            usable += 1;
                            "full access".to_string()
                        }
                    };
                    // Named whenever the label alone does not say which
                    // tool it is: the two GitHub accounts, GitLab.
                    let called_as = if provider.tool != provider.label.to_lowercase() {
                        format!(" (called with `{}`)", provider.tool)
                    } else {
                        String::new()
                    };
                    format!(
                        "- {} ({access}) — API base {} — API reference: {}{called_as}",
                        provider.label,
                        provider.api_base(&row.base_url),
                        provider.api_docs
                    )
                };
                out.push_str(&line);
                out.push('\n');
                // The git providers the agent may use also say how to
                // clone through lore: the URL pattern, with the request's
                // public origin or the placeholder in it, and which token
                // is the password. The code knows no public origin, so
                // the placeholder stands in for it.
                if let Some(route) = provider.git_route()
                    && row.configured
                    && level != "off"
                {
                    let depth = if provider.service() == "github" {
                        "<owner>/<repo>"
                    } else {
                        "<group>/<sub>/<repo>"
                    };
                    out.push_str(&format!(
                        "  git clone https://lore:<your lore token>@{host}/git/{route}/{depth}.git\n"
                    ));
                    out.push_str(
                        "  Use your own lore token as the password; never print it. `read` \
                         lets you clone and fetch, `full` lets you push.\n",
                    );
                }
            }
            out.push_str(
                "\nThe credential is added by lore on the server side: never ask the user \
                 for one, and never send one yourself.",
            );
            this.note(
                actor,
                "integrations",
                "",
                Some(&session.id),
                None,
                &[],
                &format!("{usable} of {} services usable", ops::ALL.len()),
            );
            Ok(out)
        })
        .await
    }

    #[tool(
        description = "Operate Cloudflare through lore: zones, DNS records and anything else the account's token allows. Examples: `GET /zones` lists the zones; `POST /zones/{zone_id}/dns_records` with body {\"type\":\"A\",\"name\":\"sub.example.com\",\"content\":\"203.0.113.10\"} creates a DNS record. The Cloudflare credential is added by lore on the server side: never ask the user for it, and never send one yourself."
    )]
    async fn cloudflare(
        &self,
        Parameters(args): Parameters<OpsArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<String, String> {
        self.operate(&parts, ops::CLOUDFLARE, args).await
    }

    #[tool(
        description = "Call the GitHub REST API through lore with the user's personal GitHub account: repositories, pull requests, issues and anything else the personal account's token allows. For repositories that belong to the GitHub organization, use `github_org` instead. Examples: `GET /user/repos?per_page=10` lists your repositories; `POST /repos/{owner}/{repo}/pulls` with body {\"title\":\"Add refunds\",\"head\":\"feature/refunds\",\"base\":\"main\"} opens a pull request. The GitHub credential is added by lore on the server side: never ask the user for it, and never send one yourself."
    )]
    async fn github(
        &self,
        Parameters(args): Parameters<OpsArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<String, String> {
        self.operate(&parts, ops::GITHUB, args).await
    }

    #[tool(
        description = "Call the GitHub REST API through lore with the GitHub organization account's token (kept apart from the personal account). Prefer it for repositories, pull requests, issues, teams and settings that belong to the organization; use `github` for the user's personal repositories. Same arguments as `github`. Examples: `GET /orgs/{org}/repos?per_page=10` lists the organization's repositories; `POST /repos/{org}/{repo}/pulls` with body {\"title\":\"Add refunds\",\"head\":\"feature/refunds\",\"base\":\"main\"} opens a pull request. The credential is added by lore on the server side: never ask the user for it, and never send one yourself."
    )]
    async fn github_org(
        &self,
        Parameters(args): Parameters<OpsArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<String, String> {
        self.operate(&parts, ops::GITHUB_ORG, args).await
    }

    #[tool(
        description = "Call the REST API of the user's self-hosted GitLab server through lore: projects, merge requests, issues and anything else the account's token allows. Examples: `GET /projects?membership=true` lists your projects; `POST /projects/{id}/merge_requests` with body {\"title\":\"Add refunds\",\"source_branch\":\"feature/refunds\",\"target_branch\":\"main\"} opens a merge request. The GitLab credential is added by lore on the server side: never ask the user for it, and never send one yourself."
    )]
    async fn git_server(
        &self,
        Parameters(args): Parameters<OpsArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<String, String> {
        self.operate(&parts, ops::GITLAB, args).await
    }

    #[tool(
        description = "Operate the user's Dokploy server through lore: projects, applications, deployments and anything else the API key allows. Examples: `GET /project.all` lists the projects; `POST /application.deploy` with body {\"applicationId\":\"...\"} deploys an application. The Dokploy credential is added by lore on the server side: never ask the user for it, and never send one yourself."
    )]
    async fn dokploy(
        &self,
        Parameters(args): Parameters<OpsArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<String, String> {
        self.operate(&parts, ops::DOKPLOY, args).await
    }

    /// One provider call end to end: the session, the request checks, the
    /// access check, the call, the log row and the activity note. `Ok` is
    /// the answer to show the agent; `Err` is why it did not happen.
    async fn operate(
        &self,
        parts: &Parts,
        provider: ops::Provider,
        args: OpsArgs,
    ) -> Result<String, String> {
        let agent = agent_of(parts);
        let shared = agent == SHARED_AGENT;
        let session_id = args.session_id.trim().to_string();
        let request = ops::OpsRequest {
            provider,
            method: args.method,
            path: args.path,
            query: args.query,
            body: args.body,
        };
        let this = self.clone();
        // The session, the request shape and the access check run off the
        // async runtime; a refused call is logged right there and its
        // credential is never even decrypted. Every row of this call is
        // logged under the same name: the session's agent, with the token's
        // agent added when they differ.
        let (session, label, method, path, granted) = {
            let (agent, session_id, request) = (agent.clone(), session_id.clone(), request.clone());
            blocking(move || {
                let session = this.require_session(&session_id, &agent, shared)?;
                let actor = session_agent(&agent, &session).to_string();
                let label = ops::acting_as(&agent, &actor);
                // The request is checked before the credential is touched.
                let method = match ops::normalize_method(&request.method) {
                    Ok(method) => method,
                    Err(error) => {
                        this.log_op_call(
                            &label,
                            &actor,
                            Some(&session.id),
                            provider,
                            &request.method,
                            &request.path,
                            "error",
                            error.message(),
                            0,
                            0,
                        );
                        return Err(error.message().to_string());
                    }
                };
                // A write naming lore's own Dokploy deployment is refused
                // here, and logged the way a denylisted path is.
                let checked = ops::validate(&request)
                    .and_then(|path| this.guard.check(&request).map(|()| path));
                let path = match checked {
                    Ok(path) => path,
                    Err(error) => {
                        this.log_op_call(
                            &label,
                            &actor,
                            Some(&session.id),
                            provider,
                            &method,
                            &request.path,
                            "error",
                            error.message(),
                            0,
                            0,
                        );
                        return Err(error.message().to_string());
                    }
                };
                match ops::authorize(
                    &this.db,
                    this.vault.as_ref(),
                    &agent,
                    &actor,
                    provider,
                    &method,
                ) {
                    Ok(granted) => Ok((session, label, method, path, granted)),
                    Err(denied) => {
                        this.log_op_call(
                            &label,
                            &actor,
                            Some(&session.id),
                            provider,
                            &method,
                            &path,
                            "denied",
                            &denied.reason,
                            0,
                            0,
                        );
                        Err(denied.reason)
                    }
                }
            })
            .await?
        };
        let actor = session_agent(&agent, &session).to_string();
        let started = Instant::now();
        let outcome = ops::call(
            &self.http,
            &granted.api_base,
            &granted.secret,
            &self.guard,
            &request,
        )
        .await;
        let (status, went, detail, answer) = match outcome {
            Ok(response) => (
                response.status as i64,
                "ok",
                String::new(),
                Ok(render_ops_response(&response)),
            ),
            Err(error) => {
                let message = match &error {
                    ops::OpsError::Invalid(reason) => reason.clone(),
                    ops::OpsError::Transport(reason) => {
                        format!("{} could not be reached: {reason}", provider.label)
                    }
                };
                (0, "error", error.message().to_string(), Err(message))
            }
        };
        let this = self.clone();
        let session_id = session.id.clone();
        let log = blocking(move || {
            let duration = started.elapsed().as_millis() as i64;
            this.log_op_call(
                &label,
                &actor,
                Some(&session_id),
                provider,
                &method,
                &path,
                went,
                &detail,
                status,
                duration,
            );
            Ok(())
        });
        let _ = log.await;
        answer
    }

    /// Writes one operations log row and the activity note for a provider
    /// call. Bookkeeping only: a failure here never fails the call, and
    /// the note is one line — method, path, how it went — never a query, a
    /// body or a response.
    #[expect(
        clippy::too_many_arguments,
        reason = "one argument per column of the ops_log row"
    )]
    fn log_op_call(
        &self,
        label: &str,
        actor: &str,
        session_id: Option<&str>,
        provider: ops::Provider,
        method: &str,
        path: &str,
        outcome: &str,
        detail: &str,
        status: i64,
        duration_ms: i64,
    ) {
        // What the agent sent may be anything: the log keeps a bounded,
        // single-line copy.
        let method = log_text(method, 10);
        let path = log_text(path, 1000);
        if let Err(error) = self.db.log_op(
            label,
            session_id,
            provider.id,
            &method,
            &path,
            status,
            outcome,
            detail,
            duration_ms,
        ) {
            tracing::warn!(%error, "writing the ops log failed");
        }
        let went = if outcome == "ok" {
            status.to_string()
        } else {
            outcome.to_string()
        };
        self.note(
            actor,
            provider.tool,
            "",
            session_id,
            None,
            &[],
            &format!("{method} {path} → {went}"),
        );
    }

    /// The briefing for a session that was just opened: the profile, the
    /// rules, the board, the other open sessions and where the project was
    /// left off. With `deliver` (a session from `hello`) it marks the
    /// listed messages read and delivers the handoff notes, so it is built
    /// once per session; an implicit session only shows them, and they
    /// stay waiting for the next `hello`. `actor` is the agent the token
    /// names.
    fn open_briefing(
        &self,
        session: &Session,
        actor: &str,
        deliver: bool,
    ) -> Result<String, String> {
        let address = self.db.address_for(&session.agent).map_err(internal)?;
        let language = self.db.profile().map_err(internal)?.language;
        let rules = self
            .db
            .briefing_rules(&session.agent, &session.project)
            .map_err(internal)?;
        let mut others = self
            .db
            .sessions(Some("open"), Some(&session.project), 9)
            .map_err(internal)?;
        others.retain(|other| other.id != session.id);
        let mut other_rows = Vec::new();
        for other in others {
            let latest = self.db.latest_session_update(&other.id).map_err(internal)?;
            other_rows.push((other, latest));
        }
        let entries = self
            .db
            .recent(Some(&session.project), None, 5)
            .map_err(internal)?;
        let feed_agent = if session.agent.is_empty() {
            actor
        } else {
            &session.agent
        };
        // The open tasks show what is waiting; tasks meant for this
        // agent come first.
        let mut open_tasks = self
            .db
            .tasks(Some(&session.project), &["open", "claimed"], 100)
            .map_err(internal)?;
        open_tasks.sort_by_key(|task| task.assignee.as_str() != feed_agent);
        open_tasks.truncate(10);
        // The files kept for the project: how many, and the newest three.
        let file_count = self
            .db
            .project_file_count(&session.project)
            .map_err(internal)?;
        let latest_files = if file_count > 0 {
            self.db.files(Some(&session.project), 3).map_err(internal)?
        } else {
            Vec::new()
        };
        // The services this agent may operate, named when there is one.
        let services = self.usable_services(actor, feed_agent)?;
        // Up to ten unread messages are listed and marked read, and
        // handoff notes for whoever works on this project next arrive
        // here, exactly once. Only what this call marked or delivered
        // is shown, so a session opening at the same moment cannot show
        // it too. Handoffs go last, with nothing that can fail after
        // them: a delivered note cannot be fetched again, while a
        // message marked read still shows in `inbox` with include_read.
        let mut unread = self
            .db
            .unread_messages(feed_agent, None, 10)
            .map_err(internal)?;
        let mut handoffs = self
            .db
            .pending_handoffs(&session.project, &session.id)
            .map_err(internal)?;
        let unread_more = if deliver {
            let ids: Vec<i64> = unread.iter().map(|message| message.id).collect();
            let marked = self.db.mark_read(feed_agent, &ids).map_err(internal)?;
            unread.retain(|message| marked.contains(&message.id));
            self.db.unread_message_count(feed_agent).map_err(internal)?
        } else {
            self.db.unread_message_count(feed_agent).map_err(internal)? - unread.len() as i64
        };
        if deliver {
            let ids: Vec<i64> = handoffs.iter().map(|message| message.id).collect();
            let delivered = self
                .db
                .deliver_handoffs(&ids, feed_agent, &session.id)
                .map_err(internal)?;
            handoffs.retain(|message| delivered.contains(&message.id));
        }
        self.note(
            feed_agent,
            "hello",
            &session.project,
            Some(&session.id),
            None,
            &[],
            &clip(&session.title, 90),
        );
        Ok(briefing(
            session,
            &address,
            &language,
            &rules,
            &BriefingBoard {
                handoffs: &handoffs,
                unread: &unread,
                unread_more: unread_more.max(0) as usize,
                agent: feed_agent,
                open_tasks: &open_tasks,
                file_count: file_count.max(0) as usize,
                latest_files: &latest_files,
                services: &services,
                held: !deliver,
            },
            &other_rows,
            &entries,
        ))
    }

    /// The services this agent may operate, as the briefing names them:
    /// `cloudflare (full), github (read)`. Empty when there are none, so
    /// the briefing leaves the line out.
    fn usable_services(&self, token_agent: &str, agent: &str) -> Result<String, String> {
        if self.vault.is_none() {
            return Ok(String::new());
        }
        if !self.db.ops_enabled().map_err(internal)? {
            return Ok(String::new());
        }
        let status = self.db.vault_status().map_err(internal)?;
        let mut usable = Vec::new();
        for (provider, row) in ops::ALL.iter().zip(status.iter()) {
            if !row.configured {
                continue;
            }
            let level = ops::effective_level(&self.db, token_agent, agent, provider.id)
                .map_err(internal)?;
            if level == "off" {
                continue;
            }
            usable.push(format!("{} ({})", provider.id, level));
        }
        Ok(usable.join(", "))
    }

    /// Records what an agent just did and pushes it to open admin pages.
    /// Bookkeeping only: a failure here never fails the tool call.
    #[expect(
        clippy::too_many_arguments,
        reason = "one argument per column of the activity row"
    )]
    fn note(
        &self,
        agent: &str,
        tool: &str,
        project: &str,
        session_id: Option<&str>,
        entry_id: Option<i64>,
        targets: &[i64],
        summary: &str,
    ) {
        match self
            .db
            .record_activity(agent, tool, project, session_id, entry_id, targets, summary)
        {
            Ok(activity) => self.events.publish(activity),
            Err(error) => tracing::warn!(%error, "recording activity failed"),
        }
    }

    /// Stores the embedding for an entry; a failure only costs semantic recall
    /// for that entry until the next startup backfill.
    fn embed_entry(&self, entry: &Entry) {
        match self.embedder.embed_passage(&entry.embedding_text()) {
            Ok(Some(vector)) => {
                if let Err(error) = self.db.set_embedding(entry.id, &vector) {
                    tracing::warn!(%error, id = entry.id, "storing embedding failed");
                }
            }
            Ok(None) => {}
            Err(error) => tracing::warn!(%error, id = entry.id, "embedding failed"),
        }
    }

    /// Stores the embedding of a file's path, kind and description; a
    /// failure only costs semantic search for that file until the next
    /// startup backfill.
    fn embed_file(&self, file: &FileInfo) {
        match self.embedder.embed_passage(&file.embedding_text()) {
            Ok(Some(vector)) => {
                if let Err(error) = self.db.set_file_embedding(file.id, &vector) {
                    tracing::warn!(%error, id = file.id, "storing file embedding failed");
                }
            }
            Ok(None) => {}
            Err(error) => tracing::warn!(%error, id = file.id, "file embedding failed"),
        }
    }
}

#[tool_handler]
impl ServerHandler for Lore {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new(
                "project-lore",
                env!("CARGO_PKG_VERSION"),
            ))
            .with_instructions(INSTRUCTIONS)
    }
}

/// Runs database work on the blocking pool, where every SQLite call of
/// this server happens.
async fn blocking<F, T>(work: F) -> Result<T, String>
where
    F: FnOnce() -> Result<T, String> + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|error| format!("internal error: {error}"))?
}

/// Agent-supplied text as the log keeps it: one line, at most `max`
/// characters.
fn log_text(text: &str, max: usize) -> String {
    text.chars()
        .take(max)
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

/// The host agents reach lore at, for the clone URL: the request's `Host`
/// header when it is a plain host name, else a placeholder.
fn public_host(parts: &Parts) -> String {
    parts
        .headers
        .get(axum::http::header::HOST)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|host| {
            !host.is_empty()
                && host.len() <= 255
                && host
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']'))
        })
        .map(str::to_string)
        .unwrap_or_else(|| "<this lore host>".to_string())
}

/// One provider answer as the tools return it: `HTTP <status>` on the
/// first line, then the body, with a note when it was cut.
fn render_ops_response(response: &ops::OpsResponse) -> String {
    let mut out = format!("HTTP {}", response.status);
    if response.truncated {
        out.push_str(&format!(
            "\n(truncated: the first {} characters of a longer response)",
            ops::MAX_BODY_CHARS
        ));
    }
    out.push('\n');
    out.push_str(&response.body);
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out
}

/// The agent the request was authenticated as.
fn agent_of(parts: &Parts) -> String {
    parts
        .extensions
        .get::<Agent>()
        .map(|agent| agent.0.clone())
        .unwrap_or_else(|| SHARED_AGENT.to_string())
}

fn clip(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        text.to_string()
    } else {
        text.chars().take(max).collect::<String>() + "…"
    }
}

fn internal(error: anyhow::Error) -> String {
    tracing::error!(%error, "tool failed");
    format!("internal error: {error}")
}

fn required(name: &str, value: &str) -> Result<String, String> {
    let value = value.trim();
    if value.is_empty() {
        Err(format!("{name} must not be empty"))
    } else {
        Ok(value.to_string())
    }
}

/// Required text, flattened to a single line.
fn one_line(name: &str, value: &str) -> Result<String, String> {
    let flat: String = value.split_whitespace().collect::<Vec<_>>().join(" ");
    required(name, &flat)
}

/// The agent a session acts as: the one that opened it, or the token's
/// agent when the session carries no name.
fn session_agent<'a>(token_agent: &'a str, session: &'a Session) -> &'a str {
    if session.agent.is_empty() {
        token_agent
    } else {
        &session.agent
    }
}

/// Required text with a length cap, flattened to a single line.
fn short_line(name: &str, value: &str, max: usize) -> Result<String, String> {
    let flat = one_line(name, value)?;
    if flat.chars().count() > max {
        return Err(format!("{name} must be at most {max} characters"));
    }
    Ok(flat)
}

/// Required text with a length cap, trimmed but otherwise as written.
fn long_text(name: &str, value: &str, max: usize) -> Result<String, String> {
    let value = required(name, value)?;
    if value.chars().count() > max {
        return Err(format!("{name} must be at most {max} characters"));
    }
    Ok(value)
}

/// Optional text with a length cap, trimmed; empty stays empty.
fn capped(name: &str, value: Option<&str>, max: usize) -> Result<String, String> {
    let value = value.unwrap_or("").trim();
    if value.chars().count() > max {
        return Err(format!("{name} must be at most {max} characters"));
    }
    Ok(value.to_string())
}

/// One task as `tasks` lists it: the id, the status, the title, the project
/// and the creator, who holds or finished it where that applies, then the
/// body and the latest note.
fn render_task(task: &Task) -> String {
    let mut out = format!(
        "#{} [{}] {} · {} · by {}",
        task.id, task.status, task.title, task.project, task.created_by
    );
    if !task.claimed_by.is_empty() {
        out.push_str(&format!(" → claimed by {}", task.claimed_by));
    }
    if !task.assignee.is_empty() {
        out.push_str(&format!(" → for {}", task.assignee));
    }
    if !task.done_by.is_empty() {
        out.push_str(&format!(" → done by {}", task.done_by));
        if !task.done_commit.is_empty() {
            out.push_str(&format!(" at {}", short(&task.done_commit)));
        }
    }
    out.push('\n');
    if !task.body.is_empty() {
        out.push_str(&clip(&task.body, 300));
        out.push('\n');
    }
    if !task.note.is_empty() {
        out.push_str(&format!("note: {}", task.note));
        out.push('\n');
    }
    out
}

/// One message as `inbox` lists it. `body_clip` caps the body.
fn render_message(message: &Message, body_clip: usize) -> String {
    let addressed = if message.to_agent.is_empty() {
        "to everyone"
    } else {
        "to you"
    };
    let mut line = format!("#{} from {} [{addressed}]", message.id, message.from_agent);
    if !message.project.is_empty() {
        line.push_str(&format!(" · {}", message.project));
    }
    line.push_str(&format!(" · {}:", message.created_at));
    let mut out = line;
    out.push('\n');
    out.push_str(&clip(&message.body, body_clip));
    out.push('\n');
    out
}

/// The board sections of the `hello` briefing: the handoff notes delivered
/// with it, the messages it marks read, the open tasks of the project, and
/// the files kept for it.
struct BriefingBoard<'a> {
    handoffs: &'a [Message],
    unread: &'a [Message],
    /// Unread messages beyond the ten listed.
    unread_more: usize,
    /// The agent the briefing is for, to mark the tasks meant for it.
    agent: &'a str,
    open_tasks: &'a [Task],
    /// How many distinct files the project keeps.
    file_count: usize,
    /// The newest of them, newest first.
    latest_files: &'a [FileInfo],
    /// The services this agent can operate, as `integrations` names them.
    services: &'a str,
    /// True for an implicit session: the handoff notes and messages are
    /// shown but left waiting for the next session opened with `hello`.
    held: bool,
}

/// The text `hello` returns: the session, the profile, the rules, the board,
/// the other open sessions and where the project was left off. A section
/// that has nothing to say is left out entirely.
fn briefing(
    session: &Session,
    address: &str,
    language: &str,
    rules: &[Rule],
    board: &BriefingBoard<'_>,
    others: &[(Session, Option<String>)],
    entries: &[Entry],
) -> String {
    let agent = if session.agent.is_empty() {
        "unknown agent"
    } else {
        &session.agent
    };
    let mut sections = vec![format!(
        "Session {} opened for {} on {}.\nPass `session_id` with this value to every \
         other lore tool in this chat.",
        session.id, agent, session.project
    )];
    let mut profile = Vec::new();
    if !address.is_empty() {
        profile.push(format!("How to address the user: {address}"));
    }
    if !language.is_empty() {
        profile.push(format!("Reply to the user in: {language}"));
    }
    if !profile.is_empty() {
        sections.push(profile.join("\n"));
    }
    if !rules.is_empty() {
        let mut lines = vec!["Rules the user wants followed:".to_string()];
        for (index, rule) in rules.iter().enumerate() {
            lines.push(format!("{}. {}", index + 1, rule.body));
        }
        sections.push(lines.join("\n"));
    }
    if !board.handoffs.is_empty() {
        let mut lines = vec![format!(
            "Notes left for whoever works on {} next:",
            session.project
        )];
        if board.held {
            lines.push(
                "(Shown only: they are delivered when a session is opened with `hello`.)".into(),
            );
        }
        for note in board.handoffs {
            lines.push(format!(
                "- from {} · {}: {}",
                note.from_agent, note.created_at, note.body
            ));
        }
        sections.push(lines.join("\n"));
    }
    if !board.unread.is_empty() {
        let mut lines = vec!["Unread messages:".to_string()];
        if board.held {
            lines.push(
                "(Left unread: they are marked read when a session is opened with `hello`.)".into(),
            );
        }
        for message in board.unread {
            let addressed = if message.to_agent.is_empty() {
                "to everyone"
            } else {
                "to you"
            };
            let mut line = format!(
                "- #{} from {} [{addressed}]",
                message.id, message.from_agent
            );
            if !message.project.is_empty() {
                line.push_str(&format!(" · {}", message.project));
            }
            line.push_str(&format!(
                " · {}: {}",
                message.created_at,
                clip(&message.body, 400)
            ));
            lines.push(line);
        }
        if board.unread_more > 0 {
            lines.push(format!(
                "  (… and {} more: call `inbox`)",
                board.unread_more
            ));
        }
        sections.push(lines.join("\n"));
    }
    if !board.open_tasks.is_empty() {
        let mut lines = vec![format!("Open tasks on {}:", session.project)];
        for task in board.open_tasks {
            let status = if task.status == "claimed" {
                format!("claimed by {}", task.claimed_by)
            } else {
                "open".to_string()
            };
            let mut line = format!("- #{} [{}] {}", task.id, status, task.title);
            if !board.agent.is_empty() && task.assignee == board.agent {
                line.push_str(" (for you)");
            }
            lines.push(line);
        }
        sections.push(lines.join("\n"));
    }
    if board.file_count > 0 {
        let latest = board
            .latest_files
            .iter()
            .map(|file| file.path.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        sections.push(format!(
            "Files kept for {}: {} (latest: {latest}). List them with `files`, read one with \
             `file_get`.",
            session.project, board.file_count
        ));
    }
    if !board.services.is_empty() {
        sections.push(format!(
            "Services you can operate through lore: {}. See `integrations`.",
            board.services
        ));
    }
    if !others.is_empty() {
        let mut lines = vec![format!("Other open sessions on {}:", session.project)];
        for (other, latest) in others {
            let agent = if other.agent.is_empty() {
                "unknown agent"
            } else {
                &other.agent
            };
            let mut line = format!(
                "- {} · started {} · {}",
                agent, other.started_at, other.title
            );
            if let Some(latest) = latest {
                line.push_str(&format!(" (last update: {})", clip(latest, 160)));
            }
            lines.push(line);
        }
        sections.push(lines.join("\n"));
    }
    if !entries.is_empty() {
        let mut lines = vec![format!("Where {} was left off:", session.project)];
        for entry in entries {
            let agent = if entry.agent.is_empty() {
                String::new()
            } else {
                format!(" · {}", entry.agent)
            };
            lines.push(format!(
                "- #{} [{}] {}{} · {}",
                entry.id, entry.kind, entry.title, agent, entry.created_at
            ));
        }
        sections.push(lines.join("\n"));
    }
    sections.push(
        "Keep this session current: call `checkin` when you finish a meaningful step, and \
         `bye` with a short summary before the chat ends. Use `tasks`/`task_update` for the \
         shared to-do list, `send` to talk to other agents, and `handoff` to leave a note for \
         the next one. This briefing is given once per chat; it is not repeated on later calls."
            .to_string(),
    );
    sections.join("\n\n")
}

fn normalize_project(project: &str) -> Result<String, String> {
    let project = project.trim().to_lowercase();
    if project.is_empty() {
        return Err("project must not be empty".into());
    }
    Ok(project)
}

fn normalize_project_filter(project: Option<String>) -> Option<String> {
    project
        .map(|p| p.trim().to_lowercase())
        .filter(|p| !p.is_empty())
}

fn normalize_kind(kind: &str) -> Result<String, String> {
    let kind = kind.trim().to_lowercase();
    if KINDS.contains(&kind.as_str()) {
        Ok(kind)
    } else {
        Err(format!("kind must be one of: {}", KINDS.join(", ")))
    }
}

fn normalize_kind_filter(kind: Option<String>) -> Result<Option<String>, String> {
    match kind.as_deref().map(str::trim) {
        None | Some("") => Ok(None),
        Some(kind) => normalize_kind(kind).map(Some),
    }
}

/// Empty for "none"-like values, otherwise the trimmed text.
fn optional_ref(value: &str) -> String {
    let value = value.trim();
    match value.to_lowercase().as_str() {
        "" | "none" | "n/a" | "null" | "-" => String::new(),
        _ => value.to_string(),
    }
}

/// Accepts a full or abbreviated git hash, or "none".
fn normalize_commit(commit: &str) -> Result<String, String> {
    let commit = optional_ref(commit).to_lowercase();
    if commit.is_empty() {
        return Ok(commit);
    }
    if (7..=64).contains(&commit.len()) && commit.chars().all(|c| c.is_ascii_hexdigit()) {
        Ok(commit)
    } else {
        Err("commit must be the hash printed by `git rev-parse HEAD`, or \"none\" outside a git repository".into())
    }
}

/// A byte count as people read it: 812 B, 1.2 KB, 1.8 MB.
fn human_size(bytes: i64) -> String {
    let bytes = bytes.max(0) as f64;
    if bytes < 1024.0 {
        format!("{bytes} B")
    } else if bytes < 1024.0 * 1024.0 {
        format!("{:.1} KB", bytes / 1024.0)
    } else {
        format!("{:.1} MB", bytes / (1024.0 * 1024.0))
    }
}

fn short(commit: &str) -> &str {
    &commit[..commit.len().min(10)]
}

fn describe_commit(entry: &Entry) -> String {
    let mut text = short(&entry.commit).to_string();
    if !entry.branch.is_empty() {
        text.push_str(&format!(" ({})", entry.branch));
    }
    if entry.dirty {
        text.push_str(" + uncommitted changes");
    }
    text
}

fn join_list(items: Option<Vec<String>>) -> String {
    items
        .unwrap_or_default()
        .iter()
        .map(|item| item.trim())
        .filter(|item| !item.is_empty())
        .collect::<Vec<_>>()
        .join(", ")
}

fn render(entry: &Entry, matched: Option<&str>, preview: bool) -> String {
    let mut out = format!(
        "#{} [{}] {} · {} · {}",
        entry.id, entry.kind, entry.project, entry.created_at, entry.title
    );
    out.push('\n');
    let mut meta = Vec::new();
    if !entry.agent.is_empty() {
        meta.push(format!("agent: {}", entry.agent));
    }
    if !entry.tags.is_empty() {
        meta.push(format!("tags: {}", entry.tags));
    }
    if !entry.files.is_empty() {
        meta.push(format!("files: {}", entry.files));
    }
    if !entry.commit.is_empty() {
        meta.push(format!("commit: {}", describe_commit(entry)));
    }
    if !entry.repo.is_empty() {
        meta.push(format!("repo: {}", entry.repo));
    }
    if !entry.path.is_empty() {
        meta.push(format!("path: {}", entry.path));
    }
    if let Some(updated) = &entry.updated_at {
        meta.push(format!("amended: {updated}"));
    }
    if let Some(matched) = matched {
        meta.push(format!("match: {matched}"));
    }
    if !meta.is_empty() {
        out.push_str(&meta.join(" | "));
        out.push('\n');
    }
    let total = entry.body.chars().count();
    if preview && total > PREVIEW_CHARS {
        let cut: String = entry.body.chars().take(PREVIEW_CHARS).collect();
        out.push_str(&cut);
        out.push_str(&format!(
            "…\n(truncated, {total} chars; call get with id {} for the rest)",
            entry.id
        ));
    } else {
        out.push_str(&entry.body);
    }
    out.push('\n');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::de::DeserializeOwned;
    use serde_json::json;

    fn test_lore(name: &str) -> Lore {
        let dir =
            std::env::temp_dir().join(format!("lore-server-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let db = Db::open(&dir.join("lore.db")).unwrap();
        db.set_profile(&crate::db::ProfileInput {
            address: "Boss".into(),
            language: "English".into(),
            agents: Vec::new(),
        })
        .unwrap();
        Lore::new(
            db,
            Embedder::disabled(),
            0.5,
            Events::new(),
            12,
            None,
            ops::Guard::default(),
        )
    }

    /// A request authenticated as `agent`, or with the shared token.
    fn as_agent(agent: Option<&str>) -> Extension<Parts> {
        let mut parts = axum::http::Request::builder()
            .body(())
            .unwrap()
            .into_parts()
            .0;
        if let Some(agent) = agent {
            parts.extensions.insert(Agent(agent.to_string()));
        }
        Extension(parts)
    }

    fn args<T: DeserializeOwned>(value: serde_json::Value) -> Parameters<T> {
        Parameters(serde_json::from_value(value).unwrap())
    }

    const OPENED: &str = "You called lore without a session, so lore opened one for you: ";
    const OUTDATED: &str =
        "This call came without a `session_id`, so lore used the implicit session";

    /// The session id an implicit answer names in its notice.
    fn notice_id(text: &str) -> String {
        let marker = "pass \"session_id\": \"";
        let start = text.find(marker).unwrap() + marker.len();
        text[start..].split('"').next().unwrap().to_string()
    }

    #[tokio::test]
    async fn the_seven_tools_work_without_a_session_id() {
        let lore = test_lore("seven");
        let claude = || as_agent(Some("claude"));
        let first = lore
            .log(
                args(json!({
                    "project": "Shop", "kind": "note", "title": "t", "body": "b",
                    "path": "/work/shop", "repo": "none", "commit": "abc1234",
                    "branch": "main"
                })),
                claude(),
            )
            .await
            .unwrap();
        // The first call carries the briefing, then the notice, then the result.
        assert!(first.starts_with(OPENED), "{first}");
        assert!(first.contains("Reply to the user in: English"), "{first}");
        assert!(first.contains("How to address the user: Boss"), "{first}");
        assert!(first.contains(OUTDATED));
        assert!(first.trim_end().ends_with(": t"), "{first}");
        let id = notice_id(&first);
        assert!(first.contains(&format!("{OPENED}{id}.")));
        let session = lore.db.session(&id).unwrap().unwrap();
        assert!(session.implicit);
        assert_eq!(
            (
                session.agent.as_str(),
                session.project.as_str(),
                session.path.as_str(),
                session.commit.as_str(),
                session.branch.as_str(),
                session.title.as_str()
            ),
            (
                "claude",
                "shop",
                "/work/shop",
                "abc1234",
                "main",
                IMPLICIT_TITLE
            )
        );
        let entry = lore.db.recent(None, None, 1).unwrap().remove(0);
        assert_eq!(entry.session_id.as_deref(), Some(id.as_str()));

        let later = [
            lore.recent(args(json!({})), claude()).await,
            lore.recall(args(json!({"query": "t"})), claude()).await,
            lore.projects(args(json!({})), claude()).await,
            lore.get(args(json!({"id": entry.id})), claude()).await,
            lore.amend(args(json!({"id": entry.id, "title": "t2"})), claude())
                .await,
            lore.forget(args(json!({"id": entry.id, "session_id": "  "})), claude())
                .await,
        ];
        for answer in later {
            let answer = answer.unwrap();
            assert!(answer.starts_with(OUTDATED), "{answer}");
            assert!(!answer.contains(OPENED) && !answer.contains("Reply to the user"));
            assert_eq!(notice_id(&answer), id);
            // Exactly one paragraph, then a blank line, then the result.
            assert_eq!(answer.matches(OUTDATED).count(), 1);
            assert!(!answer.split("\n\n").next().unwrap().contains('\n'));
        }
        // Every call ran in the implicit session.
        let activity = lore.db.activity(20).unwrap();
        assert!(
            activity
                .iter()
                .filter(|a| a.tool != "hello")
                .all(|a| a.session_id.as_deref() == Some(id.as_str())),
        );
        // A failing call still carries the notice.
        let failed = lore
            .get(args(json!({"id": 999_999})), claude())
            .await
            .unwrap_err();
        assert!(failed.starts_with(OUTDATED) && failed.ends_with("No entry with id 999999."));
    }

    #[tokio::test]
    async fn the_notice_lists_the_new_tools_only() {
        let lore = test_lore("notice");
        let notice = lore.outdated_notice("s_x");
        let list = notice
            .split("lore now also has: ")
            .nth(1)
            .unwrap()
            .split(". Start")
            .next()
            .unwrap();
        let names: Vec<&str> = list.split(", ").collect();
        for wanted in [
            "hello",
            "checkin",
            "bye",
            "tasks",
            "task_add",
            "file_save",
            "files",
        ] {
            assert!(names.contains(&wanted), "{wanted} missing from {list}");
        }
        for legacy in LEGACY_TOOLS {
            assert!(!names.contains(&legacy), "{legacy} listed in {list}");
        }
        assert_eq!(names.len(), Lore::tool_router().list_all().len() - 7);
        assert!(notice.ends_with("pass \"session_id\": \"s_x\" on every lore call."));
    }

    #[tokio::test]
    async fn agents_get_their_own_implicit_session_and_hello_leaves_it() {
        let lore = test_lore("agents");
        let claude = notice_id(
            &lore
                .recent(args(json!({})), as_agent(Some("claude")))
                .await
                .unwrap(),
        );
        let codex = notice_id(
            &lore
                .recent(args(json!({})), as_agent(Some("codex")))
                .await
                .unwrap(),
        );
        assert_ne!(claude, codex);
        // The shared token gets one too, with the same access as before.
        let shared = lore
            .recent(args(json!({"project": "shop"})), as_agent(None))
            .await
            .unwrap();
        assert!(shared.starts_with(OPENED));
        let shared = notice_id(&shared);
        assert_eq!(
            lore.db.session(&shared).unwrap().unwrap().agent,
            SHARED_AGENT
        );
        assert_eq!(lore.db.session(&shared).unwrap().unwrap().project, "shop");

        let hello = lore
            .hello(
                args(json!({
                    "project": "shop", "path": "/work", "repo": "none",
                    "commit": "none", "title": "real chat"
                })),
                as_agent(Some("claude")),
            )
            .await
            .unwrap();
        let real = hello.split_whitespace().nth(1).unwrap().to_string();
        // `hello` closes no implicit session: one may still serve another
        // chat of this agent whose client cannot call `hello`.
        for id in [&claude, &codex, &shared] {
            assert_eq!(lore.db.session(id).unwrap().unwrap().status, "open");
        }

        // With a real session id the tools answer exactly as before.
        let plain = lore
            .recent(args(json!({"session_id": real})), as_agent(Some("claude")))
            .await
            .unwrap();
        assert_eq!(plain, "No entries yet.");
        // Without one, the call still runs in the implicit session, and
        // the notice tells a current client to call `hello`.
        let forgot = lore
            .recent(args(json!({})), as_agent(Some("claude")))
            .await
            .unwrap();
        assert!(
            forgot.starts_with(OUTDATED) && !forgot.contains(OPENED),
            "{forgot}"
        );
        assert!(forgot.contains("If your tool list has `hello`, call it once for this chat"));
        assert_eq!(notice_id(&forgot), claude);

        // A `hello` through the shared token leaves it open as well.
        lore.hello(
            args(json!({
                "project": "shop", "path": "/work", "repo": "none",
                "commit": "none", "title": "shared chat", "agent": "gemini"
            })),
            as_agent(None),
        )
        .await
        .unwrap();
        assert_eq!(lore.db.session(&shared).unwrap().unwrap().status, "open");
    }

    #[tokio::test]
    async fn a_write_to_lore_s_own_dokploy_deployment_is_refused_and_logged() {
        let mut lore = test_lore("protected");
        lore.guard = ops::Guard::new(
            Vec::<String>::new(),
            ops::parse_protected("lore-app_Xk29fQ").unwrap(),
        );
        let first = lore
            .recent(args(json!({})), as_agent(Some("claude")))
            .await
            .unwrap();
        let session = notice_id(&first);
        let refused = lore
            .dokploy(
                args(json!({
                    "session_id": session, "method": "POST",
                    "path": "/application.saveEnvironment",
                    "body": {"applicationId": "lore-app_Xk29fQ", "env": "X=1"}
                })),
                as_agent(Some("claude")),
            )
            .await
            .unwrap_err();
        assert_eq!(
            refused,
            "lore does not let agents change its own Dokploy deployment (lore-app_Xk29fQ). \
             Ask the user to do this themselves."
        );
        let row = &lore.db.ops_log(1).unwrap()[0];
        assert_eq!(row.provider, "dokploy");
        assert_eq!(row.method, "POST");
        assert_eq!(row.path, "/application.saveEnvironment");
        assert_eq!(row.outcome, "error");
        assert_eq!(row.detail, refused);
    }

    /// The organization account is a tool and a service of its own:
    /// listed by `integrations` with its own clone URL, named in the
    /// briefing, and logged under its own provider id.
    #[tokio::test]
    async fn the_github_organization_account_is_its_own_service() {
        let mut lore = test_lore("github-org");
        let key = VaultKey::from_env_value(&"cd".repeat(32)).unwrap().unwrap();
        for (provider, credential) in [
            ("github", "ghp_personal-credential"),
            ("github_org", "ghp_organization-credential"),
        ] {
            let (nonce, secret) = key.encrypt(provider, "", credential);
            lore.db
                .set_vault(provider, "", &nonce, &secret, "tial")
                .unwrap();
        }
        lore.vault = Some(key);
        let tools: Vec<String> = Lore::tool_router()
            .list_all()
            .into_iter()
            .map(|tool| tool.name.to_string())
            .collect();
        assert!(tools.iter().any(|name| name == "github"));
        assert!(tools.iter().any(|name| name == "github_org"));

        let first = lore
            .recent(args(json!({})), as_agent(Some("claude")))
            .await
            .unwrap();
        let session = notice_id(&first);
        lore.db
            .set_ops_level("claude", "github_org", "read")
            .unwrap();
        let listed = lore
            .integrations(
                args(json!({ "session_id": session })),
                as_agent(Some("claude")),
            )
            .await
            .unwrap();
        assert!(
            listed.contains("- GitHub (personal) (full access)")
                && listed.contains("(called with `github`)"),
            "{listed}"
        );
        assert!(
            listed.contains("- GitHub (organization) (read-only)")
                && listed.contains("(called with `github_org`)"),
            "{listed}"
        );
        assert!(
            listed.contains("/git/github/<owner>/<repo>.git"),
            "{listed}"
        );
        assert!(
            listed.contains("/git/github-org/<owner>/<repo>.git"),
            "{listed}"
        );
        assert_eq!(
            lore.usable_services("claude", "claude").unwrap(),
            "github (full), github_org (read)"
        );

        // A refused call is logged under the organization provider, and
        // the GitHub denylist applies to it.
        let refused = lore
            .github_org(
                args(json!({
                    "session_id": session, "method": "POST", "path": "/user/keys"
                })),
                as_agent(Some("claude")),
            )
            .await
            .unwrap_err();
        assert!(
            refused.contains("creates, rotates or reveals credentials"),
            "{refused}"
        );
        let row = &lore.db.ops_log(1).unwrap()[0];
        assert_eq!(row.provider, "github_org");
        assert_eq!(row.outcome, "error");
        // The read-only level holds for writes, and only there.
        let denied = lore
            .github_org(
                args(json!({
                    "session_id": session, "method": "POST", "path": "/orgs/acme/repos"
                })),
                as_agent(Some("claude")),
            )
            .await
            .unwrap_err();
        assert_eq!(denied, "you have read-only access to github_org");
        let row = &lore.db.ops_log(1).unwrap()[0];
        assert_eq!(
            (row.provider.as_str(), row.outcome.as_str()),
            ("github_org", "denied")
        );
    }

    #[tokio::test]
    async fn a_closed_implicit_session_is_replaced_not_refused() {
        let lore = test_lore("replace");
        let first = lore
            .recent(args(json!({})), as_agent(Some("claude")))
            .await
            .unwrap();
        let old = notice_id(&first);
        lore.db.close_session(&old, "done").unwrap();
        let answer = lore
            .recent(args(json!({"session_id": old})), as_agent(Some("claude")))
            .await
            .unwrap();
        let fresh = notice_id(&answer);
        assert_ne!(fresh, old);
        assert!(
            answer.starts_with(&format!(
                "Session {old} has closed, so lore continues in {fresh}."
            )),
            "{answer}"
        );
        assert!(answer.contains(OPENED) && answer.contains(OUTDATED));
        assert!(lore.db.session(&fresh).unwrap().unwrap().implicit);

        // Another agent cannot take it over, and a closed real session or
        // an unknown id still fails.
        lore.db.close_session(&fresh, "done").unwrap();
        let error = lore
            .recent(args(json!({"session_id": fresh})), as_agent(Some("codex")))
            .await
            .unwrap_err();
        assert!(error.starts_with("no open session"), "{error}");
        let real = lore
            .db
            .open_session(&NewSession {
                agent: "codex".into(),
                project: "shop".into(),
                title: "real".into(),
                ..NewSession::default()
            })
            .unwrap();
        lore.db.close_session(&real.id, "done").unwrap();
        let error = lore
            .recent(
                args(json!({"session_id": real.id})),
                as_agent(Some("codex")),
            )
            .await
            .unwrap_err();
        assert!(
            error.contains("it is closed") && !error.contains(OUTDATED),
            "{error}"
        );

        // The shared token may replace any closed implicit session.
        let answer = lore
            .recent(args(json!({"session_id": fresh})), as_agent(None))
            .await
            .unwrap();
        assert!(
            answer.starts_with(&format!("Session {fresh} has closed")),
            "{answer}"
        );
    }

    #[tokio::test]
    async fn the_shared_token_names_the_implicit_session_after_the_caller() {
        let lore = test_lore("declared");
        let log = |agent: &str| {
            args::<LogArgs>(json!({
                "project": "shop", "kind": "note", "title": "t", "body": "b",
                "path": "/work/shop", "repo": "none", "commit": "none", "agent": agent
            }))
        };
        let codex = lore.log(log(" Codex "), as_agent(None)).await.unwrap();
        assert!(codex.contains("opened for codex on shop"), "{codex}");
        let codex_id = notice_id(&codex);
        assert_eq!(lore.db.session(&codex_id).unwrap().unwrap().agent, "codex");
        // The same name reuses it; a different one gets its own.
        let again = lore.log(log("codex"), as_agent(None)).await.unwrap();
        assert_eq!(notice_id(&again), codex_id);
        assert!(!again.contains(OPENED));
        let gemini = notice_id(&lore.log(log("gemini"), as_agent(None)).await.unwrap());
        assert_ne!(gemini, codex_id);
        // A name lore cannot use, or none, falls back to `shared`.
        for bad in ["bad name!", "admin", "shared", ""] {
            let answer = lore.log(log(bad), as_agent(None)).await.unwrap();
            let id = notice_id(&answer);
            assert_eq!(lore.db.session(&id).unwrap().unwrap().agent, SHARED_AGENT);
        }
        // A per-agent token ignores the name the call gives.
        let claude = notice_id(
            &lore
                .log(log("codex"), as_agent(Some("claude")))
                .await
                .unwrap(),
        );
        assert_eq!(lore.db.session(&claude).unwrap().unwrap().agent, "claude");
    }

    #[tokio::test]
    async fn an_implicit_briefing_leaves_handoffs_and_messages_waiting() {
        let lore = test_lore("held");
        let note = |kind: &str, to: &str, body: &str| NewMessage {
            kind: kind.into(),
            project: "shop".into(),
            from_agent: "codex".into(),
            to_agent: to.into(),
            body: body.into(),
            session_id: None,
        };
        lore.db
            .add_message(&note("handoff", "", "finish the checkout"))
            .unwrap();
        lore.db
            .add_message(&note("message", "claude", "look at #3"))
            .unwrap();
        let answer = lore
            .recent(args(json!({"project": "shop"})), as_agent(Some("claude")))
            .await
            .unwrap();
        assert!(answer.contains("finish the checkout") && answer.contains("look at #3"));
        assert!(answer.contains("(Shown only: they are delivered when a session is opened"));
        assert!(answer.contains("(Left unread: they are marked read when a session is opened"));
        assert_eq!(lore.db.pending_handoffs("shop", "s_none").unwrap().len(), 1);
        assert_eq!(lore.db.unread_message_count("claude").unwrap(), 1);

        // The next `hello` gets them, and delivers them.
        let hello = lore
            .hello(
                args(json!({
                    "project": "shop", "path": "/work", "repo": "none",
                    "commit": "none", "title": "real chat"
                })),
                as_agent(Some("claude")),
            )
            .await
            .unwrap();
        assert!(hello.contains("finish the checkout") && hello.contains("look at #3"));
        assert!(!hello.contains("Shown only") && !hello.contains("Left unread"));
        assert!(
            lore.db
                .pending_handoffs("shop", "s_none")
                .unwrap()
                .is_empty()
        );
        assert_eq!(lore.db.unread_message_count("claude").unwrap(), 0);
    }

    #[tokio::test]
    async fn an_implicit_session_without_its_briefing_is_closed() {
        let lore = test_lore("broken");
        // Break the briefing: the agent addresses live in this table.
        lore.db.execute_for_test("DROP TABLE agent_profiles;");
        let error = lore
            .recent(args(json!({})), as_agent(Some("claude")))
            .await
            .unwrap_err();
        assert!(!error.contains(OUTDATED), "{error}");
        let sessions = lore.db.sessions(None, None, 10).unwrap();
        assert_eq!(sessions.len(), 1);
        assert_eq!(
            (sessions[0].status.as_str(), sessions[0].summary.as_str()),
            ("closed", "closed: the briefing could not be built")
        );
    }

    #[tokio::test]
    async fn unknown_sessions_and_newer_tools_still_fail() {
        let lore = test_lore("refuse");
        let error = lore
            .recent(
                args(json!({"session_id": "s_nope"})),
                as_agent(Some("claude")),
            )
            .await
            .unwrap_err();
        assert!(
            error.starts_with("no open session `s_nope`: call `hello` first"),
            "{error}"
        );
        assert!(!error.contains(OUTDATED));
        // Tools that came with sessions still need the field.
        for missing in [
            serde_json::from_value::<TasksArgs>(json!({})).is_err(),
            serde_json::from_value::<CheckinArgs>(json!({"note": "x"})).is_err(),
            serde_json::from_value::<FileSaveArgs>(json!({})).is_err(),
            serde_json::from_value::<IntegrationsArgs>(json!({})).is_err(),
            serde_json::from_value::<OpsArgs>(json!({"method": "GET", "path": "/"})).is_err(),
        ] {
            assert!(missing);
        }
        assert!(lore.db.sessions(None, None, 10).unwrap().is_empty());
    }

    #[test]
    fn the_schema_still_requires_a_session_id() {
        let router = Lore::tool_router();
        for name in LEGACY_TOOLS {
            let schema = &router.get(name).unwrap().input_schema;
            let required = schema.get("required").and_then(|r| r.as_array()).unwrap();
            assert!(
                required.iter().any(|field| field == "session_id"),
                "{name}: {required:?}"
            );
            let doc = &schema["properties"]["session_id"]["description"];
            assert_eq!(doc, "Session id returned by `hello` for this chat.");
        }
    }

    #[test]
    fn logged_agent_text_is_one_bounded_line() {
        assert_eq!(log_text("GET", 10), "GET");
        assert_eq!(log_text(&"X".repeat(5000), 10).chars().count(), 10);
        assert_eq!(log_text("/a\nb\r\u{7}", 1000), "/a?b??");
    }

    #[test]
    fn the_clone_host_comes_from_a_plain_host_header() {
        let parts = |host: Option<&str>| {
            let mut request = axum::http::Request::builder();
            if let Some(host) = host {
                request = request.header(axum::http::header::HOST, host);
            }
            request.body(()).unwrap().into_parts().0
        };
        assert_eq!(
            public_host(&parts(Some("lore.example.com"))),
            "lore.example.com"
        );
        assert_eq!(
            public_host(&parts(Some("localhost:8080"))),
            "localhost:8080"
        );
        for odd in [None, Some("evil.example/x"), Some("a b"), Some("")] {
            assert_eq!(public_host(&parts(odd)), "<this lore host>", "{odd:?}");
        }
    }
}
