//! What a built-in agent may change while it works on one task: the
//! scope a run-scoped token carries. lore mints the token when a run
//! starts (`taskrunner`), keeps only its hash, and accepts it on `/mcp`
//! and the git proxy, on the internal runner listener only, until the run
//! ends or its hard limit passes.
//!
//! The scope is enforced in one place per surface, all of them here:
//! - lore's own tools ask `check_tool` before every call: one allowlist,
//!   narrower for a conversation than for a task run;
//! - the git proxy asks `check_push` before a push (fetching is allowed
//!   from any repository the run may read), and `check_ref_update` for
//!   every ref the push names (no deletion, no tag, no other branch than
//!   the default one or a new one, fast-forward only);
//! - the provider tools ask `check_call` before every call (GET is
//!   allowed where the run may read; the existing levels, the denylist,
//!   the leak scan and `LORE_DOKPLOY_PROTECTED` still apply on top), then
//!   `check_github_request` for a GitHub write (refs, trees) and
//!   `check_dokploy` for a Dokploy write, with the resource ids the task's
//!   project holds;
//! - the repository tools (`repo_tree`, `repo_read`, `repo_search`,
//!   `repo_commit`) ask `check_repository_tool`: reading like GET, a
//!   commit only to the run's own repository through its own provider,
//!   and never touching a CI definition (`ci_path`);
//! - `mail` and the git proxy's fetch ask `check_read`.
//!
//! A run reads only what `readable` lists: a board run its task's GitHub
//! account and the services its task names (more only when the owner
//! allowed it for the agent); a run another agent asked for (`delegate`,
//! `ask`) never more than that agent may read; a conversation (`ask`) is
//! `read_only` everywhere.
//!
//! Outside a run a built-in agent has no lore credential at all: its
//! runner's link secret reaches only the internal runner listener.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::ops::{self, Provider};

/// The prefix of every run token, so `/mcp` and the git proxy send only
/// such strings to the database.
pub const TOKEN_PREFIX: &str = "lore_run_";

/// The scope format this build writes. A stored scope of an older format
/// (without the read limits and the allowlists) is refused like an
/// unknown token, so a run started by an older build never gets the old,
/// wider rights.
pub const SCOPE_VERSION: u32 = 2;

/// A run token: the prefix and 32 random bytes as 64 hex characters.
pub fn new_token() -> Result<String, getrandom::Error> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes)?;
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    Ok(format!("{TOKEN_PREFIX}{hex}"))
}

/// Whether a bearer value has the shape of a run token.
pub fn looks_like_token(value: &str) -> bool {
    value.strip_prefix(TOKEN_PREFIX).is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

/// The scope of one run.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunScope {
    /// The scope format (`SCOPE_VERSION`); 0 for a scope an older build
    /// stored.
    #[serde(default)]
    pub version: u32,
    /// The run the token belongs to.
    #[serde(default)]
    pub run_id: String,
    /// The built-in agent the run belongs to.
    #[serde(default)]
    pub agent: String,
    /// The board task of a task run; none for a conversation.
    #[serde(default)]
    pub task_id: Option<i64>,
    /// `github` or `github_org`: the credential that may push.
    pub provider: String,
    pub owner: String,
    pub repo: String,
    /// The repository's default branch: the one existing branch a run may
    /// move.
    #[serde(default)]
    pub branch: String,
    /// A Dokploy project the run may change; none for read-only.
    #[serde(default)]
    pub dokploy_project_id: Option<String>,
    /// A Cloudflare zone id the run may change; none for read-only.
    #[serde(default)]
    pub cloudflare_zone: Option<String>,
    /// Whether the owner lets runs add, change or remove CI definitions
    /// (taken from the Integrations switch when the run starts).
    #[serde(default)]
    pub ci_allowed: bool,
    /// A conversation (`ask`): no write rights anywhere, whatever the
    /// fields above say. No push, no non-GET call, no `repo_commit`.
    #[serde(default)]
    pub read_only: bool,
    /// The services the run may read at all (provider ids, and `mail`);
    /// `None` for every one (only a scope of an older format has none).
    #[serde(default)]
    pub readable: Option<Vec<String>>,
    /// The agent that delegated the task or asked the question; empty
    /// for the scheduler's own board runs.
    #[serde(default)]
    pub requested_by: String,
    /// The token agent `requested_by` called with: the identity lore
    /// verified (a shared-token session can name itself anything).
    #[serde(default)]
    pub requested_via: String,
}

/// What `check_call` decided.
#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny(String),
    /// A Dokploy write: allowed only when its procedure is on the list and
    /// every id it names belongs to this Dokploy project; the caller reads
    /// the project's ids and asks `check_dokploy`.
    DokployProject(String),
}

/// lore's tools a run may call whatever its kind: reading lore and the
/// services (the service tools check the scope themselves).
const RUN_READ_TOOLS: &[&str] = &[
    "recall",
    "recent",
    "projects",
    "get",
    "tasks",
    "files",
    "file_get",
    "integrations",
    "repo_tree",
    "repo_read",
    "repo_search",
    "github",
    "github_org",
    "git_server",
    "cloudflare",
    "dokploy",
    "mail",
];

/// What a task run may call besides the read tools.
const TASK_RUN_TOOLS: &[&str] = &["hello", "checkin", "bye", "log", "handoff", "repo_commit"];

/// What a conversation may call besides the read tools.
const CHAT_RUN_TOOLS: &[&str] = &["hello", "bye"];

/// The task actions a task run may take, on its own task only.
const TASK_RUN_ACTIONS: &[&str] = &["done", "release"];

/// The CI definitions a run may not add, change or remove unless the
/// owner allows it: directories (everything below them) and root files.
pub const CI_DIRECTORIES: &[&str] = &[".github/workflows", ".github/actions", ".circleci"];
pub const CI_FILES: &[&str] = &[".gitlab-ci.yml", "azure-pipelines.yml", "Jenkinsfile"];

/// The CI definition a repository path is, is below, or holds (a
/// directory on the way to one, such as `.github`): the name to report,
/// or `None`. Compared without case, `/`-separated, leading `/` ignored.
pub fn ci_path(path: &str) -> Option<&'static str> {
    let path = path.trim().trim_matches('/').to_ascii_lowercase();
    if path.is_empty() {
        return None;
    }
    for dir in CI_DIRECTORIES {
        let lower = dir.to_ascii_lowercase();
        if path == lower
            || path.starts_with(&format!("{lower}/"))
            || lower.starts_with(&format!("{path}/"))
        {
            return Some(dir);
        }
    }
    CI_FILES
        .iter()
        .find(|file| path == file.to_ascii_lowercase())
        .copied()
}

/// The refusal of a CI change.
pub fn ci_refusal(what: &str) -> String {
    format!(
        "this run may not add, change or remove CI definitions ({what}): a CI file runs with \
         the repository's secrets. The owner can allow it in the Integrations settings \
         (\"runs may change CI definitions\")"
    )
}

/// The Dokploy procedures a run may call to change its task's project,
/// each with the id key(s) that name its target (exactly one of them must
/// be given). From Dokploy's API reference (docs.dokploy.com/docs/api);
/// everything else, `project.remove` and every global procedure included,
/// is refused.
const DOKPLOY_PROCEDURES: &[(&str, &[&str])] = &[
    ("application.create", &["environmentId"]),
    ("application.update", &["applicationId"]),
    ("application.delete", &["applicationId"]),
    ("application.deploy", &["applicationId"]),
    ("application.redeploy", &["applicationId"]),
    ("application.start", &["applicationId"]),
    ("application.stop", &["applicationId"]),
    ("application.reload", &["applicationId"]),
    ("application.saveEnvironment", &["applicationId"]),
    ("application.saveBuildType", &["applicationId"]),
    ("application.saveDockerProvider", &["applicationId"]),
    ("application.saveGithubProvider", &["applicationId"]),
    ("application.saveGitlabProvider", &["applicationId"]),
    ("application.saveBitbucketProvider", &["applicationId"]),
    ("application.saveGiteaProvider", &["applicationId"]),
    ("application.saveGitProvider", &["applicationId"]),
    ("application.disconnectGitProvider", &["applicationId"]),
    ("application.cleanQueues", &["applicationId"]),
    ("application.clearDeployments", &["applicationId"]),
    ("application.killBuild", &["applicationId"]),
    ("application.updateTraefikConfig", &["applicationId"]),
    ("compose.create", &["environmentId"]),
    ("compose.update", &["composeId"]),
    ("compose.delete", &["composeId"]),
    ("compose.deploy", &["composeId"]),
    ("compose.redeploy", &["composeId"]),
    ("compose.start", &["composeId"]),
    ("compose.stop", &["composeId"]),
    ("compose.cleanQueues", &["composeId"]),
    ("compose.killBuild", &["composeId"]),
    ("compose.cancelDeployment", &["composeId"]),
    ("compose.randomizeCompose", &["composeId"]),
    ("compose.isolatedDeployment", &["composeId"]),
    ("compose.fetchSourceType", &["composeId"]),
    ("compose.disconnectGitProvider", &["composeId"]),
    ("compose.move", &["composeId"]),
    ("domain.create", &["applicationId", "composeId"]),
    ("domain.update", &["domainId"]),
    ("domain.delete", &["domainId"]),
    ("mounts.create", &["serviceId"]),
    ("mounts.update", &["mountId"]),
    ("mounts.remove", &["mountId"]),
    ("port.create", &["applicationId"]),
    ("port.update", &["portId"]),
    ("port.delete", &["portId"]),
    ("redirects.create", &["applicationId"]),
    ("redirects.update", &["redirectId"]),
    ("redirects.delete", &["redirectId"]),
    ("security.create", &["applicationId"]),
    ("security.update", &["securityId"]),
    ("security.delete", &["securityId"]),
    ("environment.create", &["projectId"]),
    ("environment.update", &["environmentId"]),
    ("environment.remove", &["environmentId"]),
    ("environment.duplicate", &["environmentId"]),
];

/// The database kinds, whose procedures all take `<kind>Id`.
const DOKPLOY_DATABASES: &[&str] = &["postgres", "mysql", "mariadb", "mongo", "redis"];
const DOKPLOY_DATABASE_ACTIONS: &[&str] = &[
    "update",
    "remove",
    "deploy",
    "start",
    "stop",
    "reload",
    "rebuild",
    "saveEnvironment",
    "saveExternalPort",
    "changeStatus",
    "move",
];

/// The keys of a Dokploy project tree (`project.one`) that name the
/// project's own resources. Shared things a project merely refers to
/// (`organizationId`, `serverId`, `registryId`, `githubId`,
/// `customGitSSHKeyId`, `destinationId`, …) are not among them.
const DOKPLOY_RESOURCE_KEYS: &[&str] = &[
    "projectId",
    "environmentId",
    "applicationId",
    "composeId",
    "postgresId",
    "mysqlId",
    "mariadbId",
    "mongoId",
    "redisId",
    "domainId",
    "mountId",
    "portId",
    "redirectId",
    "securityId",
    "backupId",
];

/// The id key(s) a Dokploy procedure names its target with, when a run
/// may call it.
fn dokploy_target(procedure: &str) -> Option<Vec<String>> {
    if let Some((_, keys)) = DOKPLOY_PROCEDURES
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(procedure))
    {
        return Some(keys.iter().map(|key| key.to_string()).collect());
    }
    let (kind, action) = procedure.split_once('.')?;
    let kind = DOKPLOY_DATABASES
        .iter()
        .find(|db| db.eq_ignore_ascii_case(kind))?;
    if action.eq_ignore_ascii_case("create") {
        return Some(vec!["environmentId".into()]);
    }
    DOKPLOY_DATABASE_ACTIONS
        .iter()
        .any(|known| known.eq_ignore_ascii_case(action))
        .then(|| vec![format!("{kind}Id")])
}

/// The GitHub endpoint classes a run may write under its own repository
/// (`/repos/{owner}/{repo}/<class>/…`).
const GITHUB_WRITE_CLASSES: &[&str] = &[
    "contents",
    "git",
    "pulls",
    "issues",
    "comments",
    "labels",
    "milestones",
    "statuses",
    "check-runs",
    "check-suites",
    "merges",
    "releases",
    "commits",
];

/// The Git Data API kinds a run may write.
const GITHUB_GIT_KINDS: &[&str] = &["blobs", "trees", "commits", "refs", "tags"];

impl RunScope {
    /// `owner/repo`, as the task names it.
    pub fn repository(&self) -> String {
        format!("{}/{}", self.owner, self.repo)
    }

    /// Whether `repo_path` (as the git proxy parsed it, with or without
    /// `.git`) is this run's repository through this run's provider.
    fn is_own_repository(&self, provider: &Provider, owner: &str, repo: &str) -> bool {
        let repo = repo.strip_suffix(".git").unwrap_or(repo);
        !self.owner.is_empty()
            && provider.id == self.provider
            && owner.eq_ignore_ascii_case(&self.owner)
            && repo.eq_ignore_ascii_case(&self.repo)
    }

    /// Whether the run may read `service` (a provider id, or `mail`) at
    /// all. Every read surface asks this: the provider tools, the
    /// repository tools, `mail` and the git proxy's fetch.
    pub fn check_read(&self, service: &str) -> Result<(), String> {
        match &self.readable {
            Some(allowed) if !allowed.iter().any(|id| id == service) => {
                Err(if self.requested_by.is_empty() {
                    format!(
                        "this run may not read {service}: a built-in agent's run reads only its \
                     task's GitHub account and the services its task names (the owner can let \
                     an agent read more during runs)"
                    )
                } else {
                    format!(
                        "this run may not read {service}: {} asked for it and has no access to \
                     {service} itself, and a built-in agent never does more for another agent \
                     than that agent could do",
                        self.requested_by
                    )
                })
            }
            _ => Ok(()),
        }
    }

    /// The one allowlist of lore's own tools for a run token: the read
    /// tools for every run; for a task run also `hello`, `checkin`, `bye`,
    /// `log`, `handoff`, `repo_commit` and `task_update` (its own task,
    /// `done` or `release`); for a conversation `hello` and `bye`.
    pub fn check_tool(&self, tool: &str, args: Option<&Map<String, Value>>) -> Result<(), String> {
        if RUN_READ_TOOLS.contains(&tool) {
            return Ok(());
        }
        if self.read_only {
            if CHAT_RUN_TOOLS.contains(&tool) {
                return Ok(());
            }
            return Err(format!(
                "a built-in agent answering a question may only read: lore refuses `{tool}` in a \
                 conversation (it may call `hello`, `bye` and lore's read tools)"
            ));
        }
        if TASK_RUN_TOOLS.contains(&tool) {
            return Ok(());
        }
        if tool == "task_update" {
            let id = args.and_then(|args| args.get("id")).and_then(Value::as_i64);
            let action = args
                .and_then(|args| args.get("action"))
                .and_then(Value::as_str)
                .map(|action| action.trim().to_ascii_lowercase())
                .unwrap_or_default();
            let Some(own) = self.task_id else {
                return Err("this run has no task, so it may not change any".into());
            };
            if id != Some(own) {
                return Err(format!(
                    "this run works on task #{own} only and may not change another task"
                ));
            }
            if !TASK_RUN_ACTIONS.contains(&action.as_str()) {
                return Err(format!(
                    "this run may only mark its task `done` or `release` it (with a note), not \
                     `{action}`"
                ));
            }
            return Ok(());
        }
        Err(format!(
            "a built-in agent's run may not call `{tool}`: it may read lore, call `hello`, \
             `checkin`, `bye`, `log`, `handoff`, `repo_commit`, and `task_update` on its own task"
        ))
    }

    /// The refusal of any write in a conversation.
    fn read_only_refusal(&self) -> String {
        "this run is a conversation and may only read: a built-in agent answering a question \
         changes nothing (no push, no commit, no write call on any service)"
            .to_string()
    }

    /// The repository tools' check before a call (`repo_tree`,
    /// `repo_read`, `repo_search` read like GET; `repo_commit` writes):
    /// reading anywhere the run may read, a commit only to the run's own
    /// repository through the run's own provider.
    pub fn check_repository_tool(
        &self,
        provider: &Provider,
        write: bool,
        owner: &str,
        repo: &str,
    ) -> Result<(), String> {
        self.check_read(provider.id)?;
        if !write {
            return Ok(());
        }
        if self.read_only {
            return Err(self.read_only_refusal());
        }
        if self.is_own_repository(provider, owner, repo) {
            Ok(())
        } else {
            Err(format!(
                "this run may commit only to {} through `{}`: it works on one task, and that \
                 task's repository is the only one it may change",
                self.repository(),
                self.provider
            ))
        }
    }

    /// The paths of a commit a run makes (`repo_commit`): none may be a CI
    /// definition unless the owner allows it.
    pub fn check_commit_paths<'a>(
        &self,
        paths: impl IntoIterator<Item = &'a str>,
    ) -> Result<(), String> {
        if self.ci_allowed {
            return Ok(());
        }
        for path in paths {
            if let Some(what) = ci_path(path) {
                return Err(ci_refusal(&format!("{what} through `{path}`")));
            }
        }
        Ok(())
    }

    /// The branch of a commit a run makes (`repo_commit`): the default
    /// branch, or a new branch it creates.
    pub fn check_commit_branch(&self, branch: &str, creates: bool) -> Result<(), String> {
        if creates || (!self.branch.is_empty() && branch == self.branch) {
            Ok(())
        } else {
            Err(format!(
                "this run may commit only to the default branch `{}` or to a new branch, not to \
                 the existing branch `{branch}`",
                self.branch
            ))
        }
    }

    /// The git proxy's check before a push (`git-receive-pack`, either
    /// half): only to the run's repository, through the run's provider.
    pub fn check_push(&self, provider: &Provider, repo_path: &str) -> Result<(), String> {
        if self.read_only {
            return Err(self.read_only_refusal());
        }
        let mut parts = repo_path.split('/');
        let (owner, repo, rest) = (parts.next(), parts.next(), parts.next());
        match (owner, repo, rest) {
            (Some(owner), Some(repo), None) if self.is_own_repository(provider, owner, repo) => {
                Ok(())
            }
            _ => Err(format!(
                "this run may push only to {} through {}: it works on one task, and that \
                 task's repository is the only one it may change",
                self.repository(),
                self.provider
            )),
        }
    }

    /// One ref of a push (`old new ref` from the command list), before
    /// the ancestry is looked at: never a deletion, only branches, and an
    /// existing branch only when it is the default one. Answers whether
    /// the update must be proved a fast-forward (an existing branch).
    pub fn check_ref_update(&self, old: &str, new: &str, name: &str) -> Result<bool, String> {
        let zero = |id: &str| id.bytes().all(|byte| byte == b'0');
        if zero(new) {
            return Err(format!(
                "this run may not delete {name}: a built-in agent never deletes a branch or a tag"
            ));
        }
        let Some(branch) = name.strip_prefix("refs/heads/") else {
            return Err(format!(
                "this run may push only branches, not {name} (no tags, no other refs)"
            ));
        };
        if zero(old) {
            return Ok(false);
        }
        if self.branch.is_empty() || branch != self.branch {
            return Err(format!(
                "this run may update only the default branch `{}` or create new branches, not \
                 the existing branch `{branch}`",
                self.branch
            ));
        }
        Ok(true)
    }

    /// The provider tools' check before a call. `method` is normalised
    /// and `path` is the path the service will see (`ops::validate`).
    pub fn check_call(&self, provider: &Provider, method: &str, path: &str) -> Decision {
        if let Err(reason) = self.check_read(provider.id) {
            return Decision::Deny(reason);
        }
        if method == "GET" {
            return Decision::Allow;
        }
        if self.read_only {
            return Decision::Deny(self.read_only_refusal());
        }
        let decoded = ops::decode_for_match(path);
        let segments: Vec<&str> = decoded
            .split('/')
            .filter(|segment| !segment.is_empty())
            .collect();
        let refuse = |why: String| Decision::Deny(why);
        match provider.service() {
            "github" => {
                let own = segments.len() >= 4
                    && segments[0] == "repos"
                    && self.is_own_repository(provider, segments[1], segments[2]);
                if !own {
                    return refuse(format!(
                        "this run may change only {} through `{}` (paths under \
                         /repos/{}/…); everything else is read-only for it",
                        self.repository(),
                        self.provider,
                        self.repository()
                    ));
                }
                match self.github_class(&segments[3..]) {
                    Ok(()) => Decision::Allow,
                    Err(why) => refuse(why),
                }
            }
            "cloudflare" => match &self.cloudflare_zone {
                Some(zone)
                    if segments.len() >= 3
                        && segments[0] == "zones"
                        && segments[1] == zone.to_ascii_lowercase()
                        && segments[2] == "dns_records" =>
                {
                    Decision::Allow
                }
                Some(zone) => refuse(format!(
                    "this run may change Cloudflare only under /zones/{zone}/dns_records (DNS \
                     records of its task's zone); everything else is read-only for it"
                )),
                None => refuse(
                    "this run may only read Cloudflare: its task names no Cloudflare zone".into(),
                ),
            },
            "dokploy" => match &self.dokploy_project_id {
                Some(project) => Decision::DokployProject(project.clone()),
                None => refuse(
                    "this run may only read Dokploy: its task names no Dokploy project".into(),
                ),
            },
            _ => refuse(format!(
                "this run may only read {}: a built-in agent changes nothing outside its task",
                provider.label
            )),
        }
    }

    /// The endpoint class of a GitHub write under the run's repository
    /// (`rest` is what follows `/repos/{owner}/{repo}`, decoded and
    /// lowercased): on the allowlist, and a Contents path that is no CI
    /// definition.
    fn github_class(&self, rest: &[&str]) -> Result<(), String> {
        let class = rest.first().copied().unwrap_or_default();
        let refused = |class: &str| {
            format!(
                "this run may not call {} endpoints (`/repos/{}/{class}…`): a built-in agent may \
                 write only contents, git data, pulls, issues and their comments, labels, \
                 milestones, statuses and check runs, merges and releases of its repository",
                if class.is_empty() { "these" } else { class },
                self.repository()
            )
        };
        if rest.iter().any(|segment| segment.contains("%2f")) {
            return Err(refused(class));
        }
        if !GITHUB_WRITE_CLASSES.contains(&class) {
            return Err(refused(class));
        }
        match class {
            "git" => {
                let kind = rest.get(1).copied().unwrap_or_default();
                if !GITHUB_GIT_KINDS.contains(&kind) {
                    return Err(refused(&format!("git/{kind}")));
                }
            }
            // Only comments on a commit.
            "commits" => {
                if !(rest.len() == 3 && rest[2] == "comments") {
                    return Err(refused("commits"));
                }
            }
            "contents" if !self.ci_allowed => {
                let path = rest[1..].join("/");
                if let Some(what) = ci_path(&path) {
                    return Err(ci_refusal(&format!("{what} through the Contents API")));
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// A GitHub write the path check allowed, looked at with its body:
    /// refs may not be deleted, forced, or move another existing branch
    /// than the default one, and no tag ref is written; a tree may not
    /// hold a CI definition (unless the owner allows it). `path` is the
    /// validated path.
    pub fn check_github_request(
        &self,
        method: &str,
        path: &str,
        body: Option<&Value>,
    ) -> Result<(), String> {
        let decoded = ops::decode_for_match(path);
        let segments: Vec<&str> = decoded
            .split('/')
            .filter(|segment| !segment.is_empty())
            .collect();
        if segments.len() < 5 || segments[3] != "git" {
            return Ok(());
        }
        match segments[4] {
            "refs" => {
                let name = segments[5..].join("/");
                if method == "DELETE" {
                    return Err(format!(
                        "this run may not delete refs/{name}: a built-in agent never deletes a \
                         branch or a tag"
                    ));
                }
                if method == "POST" {
                    let created = body
                        .and_then(|body| body.get("ref"))
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    if !created.starts_with("refs/heads/") {
                        return Err(format!(
                            "this run may create only branches (refs/heads/…), not `{created}`"
                        ));
                    }
                    return Ok(());
                }
                // An update of an existing ref.
                if body
                    .and_then(|body| body.get("force"))
                    .is_some_and(|force| force != &Value::Bool(false))
                {
                    return Err(
                        "this run may not force a ref update: a built-in agent only moves a \
                         branch forward"
                            .into(),
                    );
                }
                // The original spelling of the branch, for the comparison.
                let original: Vec<&str> = path
                    .split('/')
                    .filter(|segment| !segment.is_empty())
                    .collect();
                let branch = original.get(6..).map(|rest| rest.join("/"));
                match (segments.get(5).copied(), branch) {
                    (Some("heads"), Some(branch))
                        if !self.branch.is_empty() && branch == self.branch =>
                    {
                        Ok(())
                    }
                    _ => Err(format!(
                        "this run may update only the default branch `{}`, not refs/{name}",
                        self.branch
                    )),
                }
            }
            "trees" if method == "POST" && !self.ci_allowed => {
                let entries = body
                    .and_then(|body| body.get("tree"))
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                for entry in &entries {
                    let path = entry
                        .get("path")
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    if let Some(what) = ci_path(path) {
                        return Err(ci_refusal(&format!(
                            "{what} through a Git Data tree entry `{path}`"
                        )));
                    }
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    /// A Dokploy write in a run whose task names a project: its procedure
    /// is on the list, the id key that names its target is given as a
    /// string, and every id the request names (each value under a key
    /// ending in `Id`, in the body or the query) is a string and one of
    /// the project's own resource ids (`project_ids`, from
    /// `dokploy_tree_ids`).
    pub fn check_dokploy(
        &self,
        req: &ops::OpsRequest,
        project_ids: &[String],
    ) -> Result<(), String> {
        let project = self.dokploy_project_id.as_deref().unwrap_or_default();
        let procedure = req.path.trim().trim_start_matches('/');
        let Some(targets) = dokploy_target(procedure) else {
            return Err(format!(
                "this run may not call the Dokploy procedure `{procedure}`: inside its task's \
                 project {project} it may only deploy, start, stop, update and configure the \
                 project's applications, compose services, databases, domains, mounts, ports, \
                 redirects, security rules and environments"
            ));
        };
        let mut named: Vec<(String, String)> = Vec::new();
        if let Some(body) = &req.body {
            collect_named(body, &mut named)?;
        }
        if let Some(query) = &req.query {
            collect_named(&Value::Object(query.clone()), &mut named)?;
        }
        let given: Vec<&(String, String)> = named
            .iter()
            .filter(|(key, _)| targets.iter().any(|target| target == key))
            .collect();
        if given.len() != 1 {
            return Err(format!(
                "this run may call `{procedure}` only with exactly one {} naming a resource of the \
                 project {project}",
                targets.join(" or ")
            ));
        }
        for (key, id) in &named {
            if id != project && !project_ids.iter().any(|known| known == id) {
                return Err(format!(
                    "this run may change Dokploy only inside the project {project}; {key} {id} is \
                     not one of its resources"
                ));
            }
        }
        Ok(())
    }
}

fn is_id_key(key: &str) -> bool {
    key.ends_with("Id") || key.ends_with("ID") || key == "id"
}

fn is_ids_key(key: &str) -> bool {
    key.ends_with("Ids") || key.ends_with("IDs") || key == "ids"
}

/// Every id a Dokploy request names, as `(key, id)`, at any depth. An id
/// that is not a string (a number, an array, an object) is refused, and
/// so is a list of ids.
fn collect_named(value: &Value, out: &mut Vec<(String, String)>) -> Result<(), String> {
    match value {
        Value::Object(map) => {
            for (key, item) in map {
                if is_ids_key(key) {
                    return Err(format!(
                        "this run may not name Dokploy resources in a list (`{key}`)"
                    ));
                }
                if is_id_key(key) {
                    match item {
                        Value::String(text) => out.push((key.clone(), text.trim().to_string())),
                        Value::Null => {}
                        _ => {
                            return Err(format!(
                                "this run may name a Dokploy resource only with a string id \
                                 (`{key}`)"
                            ));
                        }
                    }
                } else {
                    collect_named(item, out)?;
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_named(item, out)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// The resource ids a Dokploy project's tree holds (`project.one`): the
/// string under every resource key (`DOKPLOY_RESOURCE_KEYS`) at any
/// depth. Ids of shared things the project refers to are left out.
pub fn dokploy_tree_ids(answer: &str) -> Vec<String> {
    fn walk(value: &Value, out: &mut Vec<String>) {
        match value {
            Value::Object(map) => {
                for (key, item) in map {
                    match item {
                        Value::String(text) if DOKPLOY_RESOURCE_KEYS.contains(&key.as_str()) => {
                            out.push(text.trim().to_string())
                        }
                        _ => walk(item, out),
                    }
                }
            }
            Value::Array(items) => items.iter().for_each(|item| walk(item, out)),
            _ => {}
        }
    }
    let mut ids = Vec::new();
    if let Ok(value) = serde_json::from_str::<Value>(answer) {
        walk(&value, &mut ids);
    }
    ids.retain(|id| !id.is_empty());
    ids.sort();
    ids.dedup();
    ids
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope() -> RunScope {
        RunScope {
            version: SCOPE_VERSION,
            run_id: "r1".into(),
            agent: "claude-builtin".into(),
            task_id: Some(7),
            provider: "github".into(),
            owner: "Luen-Eth".into(),
            repo: "shop".into(),
            branch: "main".into(),
            readable: Some(vec!["github".into(), "dokploy".into(), "cloudflare".into()]),
            ..RunScope::default()
        }
    }

    fn denied(decision: Decision) -> String {
        match decision {
            Decision::Deny(why) => why,
            other => panic!("not denied: {other:?}"),
        }
    }

    #[test]
    fn repository_tools_commit_only_to_the_task_s_repository() {
        let scope = scope();
        assert!(
            scope
                .check_repository_tool(&ops::GITHUB, true, "LUEN-ETH", "Shop")
                .is_ok()
        );
        for (provider, owner, repo) in [
            (ops::GITHUB, "luen-eth", "other"),
            (ops::GITHUB, "someone", "shop"),
            (ops::GITHUB_ORG, "luen-eth", "shop"),
        ] {
            let refused = scope
                .check_repository_tool(&provider, true, owner, repo)
                .unwrap_err();
            assert!(
                refused.contains("may commit only to Luen-Eth/shop")
                    || refused.contains("may not read github_org"),
                "{refused}"
            );
        }
        // Reading is like GET: anywhere the run may read.
        assert!(
            scope
                .check_repository_tool(&ops::GITHUB, false, "someone", "else")
                .is_ok()
        );
        // A commit: the default branch or a new one, never a CI file.
        assert!(scope.check_commit_branch("main", false).is_ok());
        assert!(scope.check_commit_branch("feature", true).is_ok());
        assert!(scope.check_commit_branch("release", false).is_err());
        assert!(
            scope
                .check_commit_paths(["src/main.rs", "README.md"])
                .is_ok()
        );
        for path in [
            ".github/workflows/ci.yml",
            "/.GitHub/Workflows/x.yaml",
            ".github/actions/setup/action.yml",
            ".gitlab-ci.yml",
            "Jenkinsfile",
            ".circleci/config.yml",
            "azure-pipelines.yml",
        ] {
            let refused = scope.check_commit_paths([path]).unwrap_err();
            assert!(refused.contains("CI definitions"), "{path}: {refused}");
        }
        let allowed = RunScope {
            ci_allowed: true,
            ..scope.clone()
        };
        assert!(
            allowed
                .check_commit_paths([".github/workflows/ci.yml"])
                .is_ok()
        );
    }

    #[test]
    fn a_conversation_writes_nowhere_and_reads_only_what_its_asker_may() {
        let scope = RunScope {
            read_only: true,
            readable: Some(vec!["github".into()]),
            requested_by: "codex".into(),
            ..scope()
        };
        assert!(scope.check_push(&ops::GITHUB, "luen-eth/shop").is_err());
        assert!(
            scope
                .check_repository_tool(&ops::GITHUB, true, "luen-eth", "shop")
                .is_err()
        );
        assert!(matches!(
            scope.check_call(&ops::GITHUB, "POST", "/repos/luen-eth/shop/pulls"),
            Decision::Deny(_)
        ));
        assert_eq!(
            scope.check_call(&ops::GITHUB, "GET", "/repos/x/y"),
            Decision::Allow
        );
        for provider in [ops::GITHUB_ORG, ops::DOKPLOY, ops::CLOUDFLARE] {
            let why = denied(scope.check_call(&provider, "GET", "/x"));
            assert!(why.contains("codex asked for it"), "{why}");
        }
        assert!(scope.check_read("mail").is_err());
        assert!(scope.check_read("github").is_ok());
    }

    /// E2: one allowlist of lore's own tools for run tokens.
    #[test]
    fn a_run_calls_only_the_tools_on_its_allowlist() {
        let task = scope();
        let args = |value: Value| value.as_object().cloned();
        for tool in [
            "recall", "tasks", "file_get", "files", "github", "dokploy", "hello",
        ] {
            assert!(task.check_tool(tool, None).is_ok(), "{tool}");
        }
        for tool in ["checkin", "bye", "log", "handoff", "repo_commit"] {
            assert!(task.check_tool(tool, None).is_ok(), "{tool}");
        }
        for tool in [
            "amend",
            "forget",
            "task_add",
            "send",
            "file_save",
            "file_delete",
            "inbox",
            "delegate",
            "ask",
            "assistants",
        ] {
            let why = task.check_tool(tool, None).unwrap_err();
            assert!(why.contains(&format!("`{tool}`")), "{tool}: {why}");
        }
        assert!(
            task.check_tool(
                "task_update",
                args(json!({"id": 7, "action": "done"})).as_ref()
            )
            .is_ok()
        );
        assert!(
            task.check_tool(
                "task_update",
                args(json!({"id": 7, "action": "Release"})).as_ref()
            )
            .is_ok()
        );
        for (id, action) in [(8, "done"), (7, "cancel"), (7, "claim"), (7, "reopen")] {
            assert!(
                task.check_tool(
                    "task_update",
                    args(json!({"id": id, "action": action})).as_ref()
                )
                .is_err(),
                "{id} {action}"
            );
        }
        assert!(task.check_tool("task_update", None).is_err());
        let chat = RunScope {
            read_only: true,
            task_id: None,
            ..scope()
        };
        for tool in ["recall", "get", "hello", "bye"] {
            assert!(chat.check_tool(tool, None).is_ok(), "{tool}");
        }
        for tool in [
            "checkin",
            "log",
            "handoff",
            "task_update",
            "task_add",
            "repo_commit",
        ] {
            assert!(chat.check_tool(tool, None).is_err(), "{tool}");
        }
    }

    #[test]
    fn tokens_have_one_shape() {
        let token = new_token().unwrap();
        assert!(looks_like_token(&token));
        assert_ne!(token, new_token().unwrap());
        assert!(!looks_like_token("lore_run_xyz"));
        assert!(!looks_like_token(&token.to_uppercase()));
        assert!(!looks_like_token(&token[TOKEN_PREFIX.len()..]));
    }

    #[test]
    fn a_push_goes_only_to_the_task_s_repository() {
        let scope = scope();
        assert!(scope.check_push(&ops::GITHUB, "luen-eth/shop").is_ok());
        assert!(scope.check_push(&ops::GITHUB, "Luen-Eth/shop.git").is_ok());
        for (provider, path) in [
            (ops::GITHUB, "luen-eth/other"),
            (ops::GITHUB, "someone/shop"),
            (ops::GITHUB_ORG, "luen-eth/shop"),
            (ops::GITLAB, "luen-eth/shop"),
            (ops::GITHUB, "luen-eth/shop/extra"),
            (ops::GITHUB, "luen-eth"),
        ] {
            assert!(scope.check_push(&provider, path).is_err(), "{path}");
        }
    }

    /// C5: no deletion, no tag, only the default branch or a new one.
    #[test]
    fn a_push_never_deletes_tags_or_moves_another_branch() {
        let scope = scope();
        let (zero, a, b) = ("0".repeat(40), "a".repeat(40), "b".repeat(40));
        assert_eq!(scope.check_ref_update(&a, &b, "refs/heads/main"), Ok(true));
        assert_eq!(
            scope.check_ref_update(&zero, &b, "refs/heads/feature"),
            Ok(false)
        );
        for (old, new, name, word) in [
            (&a, &zero, "refs/heads/main", "delete"),
            (&a, &zero, "refs/heads/feature", "delete"),
            (&a, &zero, "refs/tags/v1", "delete"),
            (&zero, &b, "refs/tags/v1", "only branches"),
            (&a, &b, "refs/notes/commits", "only branches"),
            (&a, &b, "refs/heads/release", "only the default branch"),
        ] {
            let why = scope.check_ref_update(old, new, name).unwrap_err();
            assert!(why.contains(word), "{name}: {why}");
        }
    }

    /// C2: only the endpoint classes a coding task needs.
    #[test]
    fn github_writes_stay_on_the_allowlist_under_the_repository() {
        let scope = scope();
        let allow = |provider: &Provider, method: &str, path: &str| {
            scope.check_call(provider, method, path) == Decision::Allow
        };
        for (method, path) in [
            ("POST", "/repos/luen-eth/shop/pulls"),
            ("PUT", "/repos/luen-eth/shop/pulls/3/merge"),
            ("PATCH", "/repos/LUEN-ETH/SHOP/issues/3"),
            ("POST", "/repos/luen-eth/shop/issues/3/comments"),
            ("PUT", "/repos/luen-eth/shop/contents/src/main.rs"),
            ("POST", "/repos/luen-eth/shop/git/trees"),
            ("PATCH", "/repos/luen-eth/shop/git/refs/heads/main"),
            ("POST", "/repos/luen-eth/shop/labels"),
            ("POST", "/repos/luen-eth/shop/statuses/abc"),
            ("POST", "/repos/luen-eth/shop/check-runs"),
            ("POST", "/repos/luen-eth/shop/merges"),
            ("POST", "/repos/luen-eth/shop/releases"),
            ("POST", "/repos/luen-eth/shop/commits/abc/comments"),
        ] {
            assert!(allow(&ops::GITHUB, method, path), "{method} {path}");
        }
        assert!(allow(&ops::GITHUB, "GET", "/repos/other/thing"));
        for (provider, method, path, class) in [
            (
                ops::GITHUB,
                "PUT",
                "/repos/luen-eth/shop/transfer",
                "transfer",
            ),
            (
                ops::GITHUB,
                "PUT",
                "/repos/luen-eth/shop/collaborators/x",
                "collaborators",
            ),
            (ops::GITHUB, "POST", "/repos/luen-eth/shop/forks", "forks"),
            (
                ops::GITHUB,
                "POST",
                "/repos/luen-eth/shop/generate",
                "generate",
            ),
            (ops::GITHUB, "POST", "/repos/luen-eth/shop/pages", "pages"),
            (ops::GITHUB, "POST", "/repos/luen-eth/shop/hooks", "hooks"),
            (
                ops::GITHUB,
                "PUT",
                "/repos/luen-eth/shop/branches/main/protection",
                "branches",
            ),
            (
                ops::GITHUB,
                "POST",
                "/repos/luen-eth/shop/rulesets",
                "rulesets",
            ),
            (
                ops::GITHUB,
                "PUT",
                "/repos/luen-eth/shop/actions/secrets/X",
                "actions",
            ),
            (
                ops::GITHUB,
                "PUT",
                "/repos/luen-eth/shop/environments/prod",
                "environments",
            ),
            (
                ops::GITHUB,
                "POST",
                "/repos/luen-eth/shop/dispatches",
                "dispatches",
            ),
            (ops::GITHUB, "POST", "/repos/luen-eth/shop/%68ooks", "hooks"),
            (
                ops::GITHUB,
                "POST",
                "/repos/luen-eth/shop/git/notes",
                "git/notes",
            ),
            (
                ops::GITHUB,
                "POST",
                "/repos/luen-eth/shop/commits/abc",
                "commits",
            ),
        ] {
            let why = denied(scope.check_call(&provider, method, path));
            assert!(why.contains(class), "{method} {path}: {why}");
        }
        for (provider, method, path) in [
            (ops::GITHUB, "POST", "/repos/luen-eth/other/pulls"),
            (ops::GITHUB, "DELETE", "/repos/luen-eth/shop"),
            (ops::GITHUB, "PATCH", "/repos/luen-eth/shop"),
            (ops::GITHUB, "POST", "/user/repos"),
            (ops::GITHUB, "POST", "/graphql"),
            (ops::GITHUB_ORG, "POST", "/repos/luen-eth/shop/pulls"),
            (ops::GITLAB, "POST", "/projects/1/issues"),
        ] {
            assert!(
                matches!(scope.check_call(&provider, method, path), Decision::Deny(_)),
                "{method} {path}"
            );
        }
    }

    /// C3 and C5 through the REST API: CI paths, ref deletion, force,
    /// tags and other branches.
    #[test]
    fn github_bodies_keep_ci_files_and_branches_safe() {
        let scope = scope();
        let why = denied(scope.check_call(
            &ops::GITHUB,
            "PUT",
            "/repos/luen-eth/shop/contents/.github/workflows/ci.yml",
        ));
        assert!(why.contains("CI definitions"), "{why}");
        let check = |method: &str, path: &str, body: Value| {
            scope.check_github_request(method, path, Some(&body))
        };
        assert!(
            check(
                "POST",
                "/repos/luen-eth/shop/git/trees",
                json!({"tree": [{"path": "src/a.rs"}]})
            )
            .is_ok()
        );
        for entry in [
            ".github",
            ".github/workflows/x.yml",
            "Jenkinsfile",
            ".circleci",
        ] {
            let why = check(
                "POST",
                "/repos/luen-eth/shop/git/trees",
                json!({"base_tree": "abc", "tree": [{"path": entry, "type": "tree", "sha": "1"}]}),
            )
            .unwrap_err();
            assert!(why.contains("CI definitions"), "{entry}: {why}");
        }
        assert!(
            check(
                "PATCH",
                "/repos/luen-eth/shop/git/refs/heads/main",
                json!({"sha": "x"})
            )
            .is_ok()
        );
        assert!(
            check(
                "POST",
                "/repos/luen-eth/shop/git/refs",
                json!({"ref": "refs/heads/new", "sha": "x"})
            )
            .is_ok()
        );
        for (method, path, body, word) in [
            (
                "PATCH",
                "/repos/luen-eth/shop/git/refs/heads/main",
                json!({"sha": "x", "force": true}),
                "force",
            ),
            (
                "PATCH",
                "/repos/luen-eth/shop/git/refs/heads/release",
                json!({"sha": "x"}),
                "only the default branch",
            ),
            (
                "PATCH",
                "/repos/luen-eth/shop/git/refs/tags/v1",
                json!({"sha": "x"}),
                "only the default branch",
            ),
            (
                "DELETE",
                "/repos/luen-eth/shop/git/refs/heads/old",
                json!({}),
                "delete",
            ),
            (
                "POST",
                "/repos/luen-eth/shop/git/refs",
                json!({"ref": "refs/tags/v9", "sha": "x"}),
                "only branches",
            ),
        ] {
            let why = check(method, path, body).unwrap_err();
            assert!(why.contains(word), "{method} {path}: {why}");
        }
        let allowed = RunScope {
            ci_allowed: true,
            ..scope.clone()
        };
        assert_eq!(
            allowed.check_call(
                &ops::GITHUB,
                "PUT",
                "/repos/luen-eth/shop/contents/.github/workflows/ci.yml"
            ),
            Decision::Allow
        );
    }

    /// C7, C1, E4: Cloudflare DNS records only; Dokploy procedures on the
    /// list with their target inside the project's own resources.
    #[test]
    fn dokploy_and_cloudflare_writes_stay_inside_the_task_s_targets() {
        let mut scope = scope();
        assert!(matches!(
            scope.check_call(&ops::DOKPLOY, "POST", "/application.deploy"),
            Decision::Deny(_)
        ));
        assert!(matches!(
            scope.check_call(&ops::CLOUDFLARE, "POST", "/zones/abc/dns_records"),
            Decision::Deny(_)
        ));
        scope.dokploy_project_id = Some("proj-1234".into());
        scope.cloudflare_zone = Some("zone-abc".into());
        assert_eq!(
            scope.check_call(&ops::DOKPLOY, "POST", "/application.deploy"),
            Decision::DokployProject("proj-1234".into())
        );
        assert_eq!(
            scope.check_call(&ops::CLOUDFLARE, "POST", "/zones/zone-abc/dns_records"),
            Decision::Allow
        );
        assert_eq!(
            scope.check_call(&ops::CLOUDFLARE, "PATCH", "/zones/zone-abc/dns_records/r1"),
            Decision::Allow
        );
        for path in [
            "/zones/zone-abc",
            "/zones/zone-abc/settings/ssl",
            "/zones/zone-abc/pagerules",
            "/zones/zone-abc/workers/routes",
            "/zones/other/dns_records",
            "/accounts/x",
        ] {
            assert!(
                matches!(
                    scope.check_call(&ops::CLOUDFLARE, "PATCH", path),
                    Decision::Deny(_)
                ),
                "{path}"
            );
        }
        // Only the project's own resources: shared ids are not in the set.
        let tree = dokploy_tree_ids(
            r#"{"projectId":"proj-1234","organizationId":"org-1","environments":[{"environmentId":"env-1",
                "applications":[{"applicationId":"app-1","serverId":"srv-1","registryId":"reg-1",
                "githubId":"gh-1","domains":[{"domainId":"dom-1"}]}],
                "postgres":[{"postgresId":"pg-1"}]}]}"#,
        );
        assert_eq!(tree, vec!["app-1", "dom-1", "env-1", "pg-1", "proj-1234"]);
        let request = |path: &str, body: Value| ops::OpsRequest {
            provider: ops::DOKPLOY,
            method: "POST".into(),
            path: path.into(),
            query: None,
            body: Some(body),
        };
        for (path, body) in [
            ("/application.deploy", json!({"applicationId": "app-1"})),
            (
                "/application.saveEnvironment",
                json!({"applicationId": "app-1", "env": "A=1"}),
            ),
            (
                "/application.create",
                json!({"name": "x", "environmentId": "env-1"}),
            ),
            (
                "/domain.update",
                json!({"domainId": "dom-1", "host": "a.example"}),
            ),
            (
                "/domain.create",
                json!({"host": "b.example", "applicationId": "app-1"}),
            ),
            ("/postgres.deploy", json!({"postgresId": "pg-1"})),
            (
                "/environment.create",
                json!({"projectId": "proj-1234", "name": "e"}),
            ),
        ] {
            assert!(
                scope
                    .check_dokploy(&request(path, body.clone()), &tree)
                    .is_ok(),
                "{path} {body}"
            );
        }
        for (path, body, word) in [
            // A global procedure, with the project's id added.
            (
                "/settings.updateServer",
                json!({"projectId": "proj-1234"}),
                "procedure",
            ),
            (
                "/sshKey.create",
                json!({"projectId": "proj-1234"}),
                "procedure",
            ),
            (
                "/registry.create",
                json!({"projectId": "proj-1234"}),
                "procedure",
            ),
            (
                "/project.remove",
                json!({"projectId": "proj-1234"}),
                "procedure",
            ),
            (
                "/user.update",
                json!({"projectId": "proj-1234"}),
                "procedure",
            ),
            (
                "/application.refreshToken",
                json!({"applicationId": "app-1"}),
                "procedure",
            ),
            // The target outside the project, or not named.
            (
                "/application.deploy",
                json!({"applicationId": "app-elsewhere"}),
                "not one of",
            ),
            (
                "/application.deploy",
                json!({"projectId": "proj-1234"}),
                "exactly one",
            ),
            (
                "/application.deploy",
                json!({"name": "no id"}),
                "exactly one",
            ),
            // A shared id from the tree, or one smuggled in.
            (
                "/application.update",
                json!({"applicationId": "app-1", "serverId": "srv-1"}),
                "not one of",
            ),
            (
                "/application.update",
                json!({"applicationId": "app-1", "githubId": "gh-1"}),
                "not one of",
            ),
            (
                "/application.create",
                json!({"environmentId": "env-1", "organizationId": "org-1"}),
                "not one of",
            ),
            // Lists and numbers under id keys.
            (
                "/application.deploy",
                json!({"applicationId": ["app-1", "app-x"]}),
                "string id",
            ),
            (
                "/application.deploy",
                json!({"applicationId": 5}),
                "string id",
            ),
            (
                "/application.update",
                json!({"applicationId": "app-1", "networkIds": ["n"]}),
                "list",
            ),
            (
                "/domain.create",
                json!({"host": "x", "applicationId": "app-1", "composeId": "c"}),
                "exactly one",
            ),
        ] {
            let why = scope
                .check_dokploy(&request(path, body.clone()), &tree)
                .unwrap_err();
            assert!(why.contains(word), "{path} {body}: {why}");
        }
        // A number in the query is refused too.
        let mut query = Map::new();
        query.insert("applicationId".into(), json!(5));
        let numeric = ops::OpsRequest {
            query: Some(query),
            body: None,
            ..request("/application.deploy", json!({}))
        };
        assert!(scope.check_dokploy(&numeric, &tree).is_err());
    }

    #[test]
    fn ci_paths_cover_the_directories_on_the_way() {
        for (path, found) in [
            (".github", Some(".github/workflows")),
            (".github/workflows", Some(".github/workflows")),
            (".github/dependabot.yml", None),
            ("src/.github/workflows/x", None),
            ("docs/Jenkinsfile", None),
            ("Jenkinsfile", Some("Jenkinsfile")),
            ("", None),
        ] {
            assert_eq!(ci_path(path), found, "{path}");
        }
    }

    use serde_json::json;
}
