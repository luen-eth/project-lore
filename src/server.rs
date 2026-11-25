//! The MCP surface: tool definitions and their text rendering.

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
    db::{Db, Entry, KINDS, NewEntry, Patch},
    embed::Embedder,
    events::Events,
};

const INSTRUCTIONS: &str = "\
Lore is the user's shared long-term memory across coding agents and sessions.

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
contradicting one.";

/// Longest body returned inline by `recall` and `recent`; `get` returns everything.
const PREVIEW_CHARS: usize = 700;

#[derive(Clone)]
pub struct Lore {
    db: Db,
    embedder: Embedder,
    min_similarity: f32,
    events: Events,
    #[expect(dead_code, reason = "read by the tool_handler macro")]
    tool_router: ToolRouter<Self>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RecallArgs {
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
pub struct LogArgs {
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
pub struct RecentArgs {
    /// Restrict to one project. Omit for every project.
    pub project: Option<String>,
    /// Restrict to one kind: update, decision, bug, note or todo.
    pub kind: Option<String>,
    /// Maximum number of entries to return (default 10, max 50).
    pub limit: Option<u32>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct IdArgs {
    /// Entry id, as shown in `recall` and `recent` results.
    pub id: i64,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct AmendArgs {
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

#[tool_router]
impl Lore {
    pub fn new(db: Db, embedder: Embedder, min_similarity: f32, events: Events) -> Self {
        Self {
            db,
            embedder,
            min_similarity,
            events,
            tool_router: Self::tool_router(),
        }
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
        let query = args.query.trim().to_string();
        if query.is_empty() {
            return Err("query must not be empty".into());
        }
        let project = normalize_project_filter(args.project);
        let kind = normalize_kind_filter(args.kind)?;
        let limit = args.limit.unwrap_or(8).clamp(1, 25) as usize;
        let this = self.clone();
        blocking(move || {
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
                None,
                &found,
                &format!("\"{}\" → {} found", clip(&query, 90), found.len()),
            );
            if hits.is_empty() {
                let scope = project
                    .map(|p| format!(" in project `{p}`"))
                    .unwrap_or_default();
                return Ok(format!("No entries found for \"{query}\"{scope}."));
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
            if !this.embedder.is_ready() {
                out.push_str(
                    "\n(Semantic search is still warming up; results are keyword-only.)\n",
                );
            }
            Ok(out)
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
        let agent = match parts.extensions.get::<Agent>() {
            Some(Agent(name)) if name != SHARED_AGENT => name.clone(),
            _ => args.agent.unwrap_or_default().trim().to_lowercase(),
        };
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
        };
        let this = self.clone();
        blocking(move || {
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
        let project = normalize_project_filter(args.project);
        let kind = normalize_kind_filter(args.kind)?;
        let limit = args.limit.unwrap_or(10).clamp(1, 50) as usize;
        let this = self.clone();
        blocking(move || {
            let entries = this
                .db
                .recent(project.as_deref(), kind.as_deref(), limit)
                .map_err(internal)?;
            let seen: Vec<i64> = entries.iter().map(|entry| entry.id).collect();
            this.note(
                &agent,
                "recent",
                project.as_deref().unwrap_or(""),
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
        })
        .await
    }

    #[tool(
        description = "List every project in the shared memory with its entry count, last activity, and the commit each agent last logged at. Compare those commits with your own HEAD to see who is ahead or behind."
    )]
    async fn projects(&self, Extension(parts): Extension<Parts>) -> Result<String, String> {
        let agent = agent_of(&parts);
        let this = self.clone();
        blocking(move || {
            let projects = this.db.projects().map_err(internal)?;
            this.note(
                &agent,
                "projects",
                "",
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
        let this = self.clone();
        blocking(move || match this.db.get(args.id).map_err(internal)? {
            Some(entry) => {
                this.note(
                    &agent,
                    "get",
                    &entry.project,
                    Some(entry.id),
                    &[],
                    &entry.title,
                );
                Ok(render(&entry, None, false))
            }
            None => Err(format!("No entry with id {}.", args.id)),
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
        let this = self.clone();
        blocking(
            move || match this.db.amend(args.id, &patch).map_err(internal)? {
                Some(entry) => {
                    this.embed_entry(&entry);
                    this.note(
                        &agent,
                        "amend",
                        &entry.project,
                        Some(entry.id),
                        &[],
                        &entry.title,
                    );
                    Ok(format!("Updated #{}: {}", entry.id, entry.title))
                }
                None => Err(format!("No entry with id {}.", args.id)),
            },
        )
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
        let this = self.clone();
        blocking(move || {
            let existing = this.db.get(args.id).map_err(internal)?;
            if this.db.delete(args.id).map_err(internal)? {
                let (project, title) = existing
                    .map(|entry| (entry.project, entry.title))
                    .unwrap_or_default();
                this.note(&agent, "forget", &project, Some(args.id), &[], &title);
                Ok(format!("Deleted #{}.", args.id))
            } else {
                Err(format!("No entry with id {}.", args.id))
            }
        })
        .await
    }

    /// Records what an agent just did and pushes it to open admin pages.
    /// Bookkeeping only: a failure here never fails the tool call.
    fn note(
        &self,
        agent: &str,
        tool: &str,
        project: &str,
        entry_id: Option<i64>,
        targets: &[i64],
        summary: &str,
    ) {
        match self
            .db
            .record_activity(agent, tool, project, entry_id, targets, summary)
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

async fn blocking<F>(work: F) -> Result<String, String>
where
    F: FnOnce() -> Result<String, String> + Send + 'static,
{
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|error| format!("internal error: {error}"))?
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
