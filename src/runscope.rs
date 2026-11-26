//! What a built-in agent may change while it works on one task: the
//! scope a run-scoped token carries. lore mints the token when a run
//! starts (`taskrunner`), keeps only its hash, and accepts it on `/mcp`
//! and the git proxy until the run ends or its hard limit passes.
//!
//! The scope is enforced in one place per surface, both here:
//! - the git proxy asks `check_push` before a push (fetching is allowed
//!   from any repository the provider credential can read);
//! - the provider tools ask `check_call` before every call (GET is
//!   allowed anywhere; the existing levels, the denylist, the leak scan
//!   and `LORE_DOKPLOY_PROTECTED` still apply on top), and for a Dokploy
//!   write `check_dokploy` with the ids the task's project holds;
//! - the repository tools (`repo_tree`, `repo_read`, `repo_search`,
//!   `repo_commit`) ask `check_repository_tool`: reading like GET, a
//!   commit only to the run's own repository through its own provider;
//! - `mail` and the git proxy's fetch ask `check_read`.
//!
//! A run another agent asked for (`delegate`, `ask`) carries what that
//! agent may do: `readable` lists the services it may read, and a
//! conversation (`ask`) is `read_only` everywhere.
//!
//! Outside a run a built-in agent has no lore credential at all: its
//! runner's link secret reaches only the internal runner listener.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::ops::{self, Provider};

/// The prefix of every run token, so `/mcp` and the git proxy send only
/// such strings to the database.
pub const TOKEN_PREFIX: &str = "lore_run_";

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
    /// The run the token belongs to.
    #[serde(default)]
    pub run_id: String,
    /// The built-in agent the run belongs to.
    #[serde(default)]
    pub agent: String,
    /// `github` or `github_org`: the credential that may push.
    pub provider: String,
    pub owner: String,
    pub repo: String,
    /// A Dokploy project the run may change; none for read-only.
    #[serde(default)]
    pub dokploy_project_id: Option<String>,
    /// A Cloudflare zone id the run may change; none for read-only.
    #[serde(default)]
    pub cloudflare_zone: Option<String>,
    /// A conversation (`ask`): no write rights anywhere, whatever the
    /// fields above say. No push, no non-GET call, no `repo_commit`.
    #[serde(default)]
    pub read_only: bool,
    /// The services the run may read at all (provider ids, and `mail`);
    /// `None` for every one. A run another agent asked for may read no
    /// more than that agent could read itself.
    #[serde(default)]
    pub readable: Option<Vec<String>>,
    /// The agent that delegated the task or asked the question; empty
    /// for the scheduler's own board runs.
    #[serde(default)]
    pub requested_by: String,
}

/// What `check_call` decided.
#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny(String),
    /// A Dokploy write: allowed only when every id it names belongs to
    /// this Dokploy project; the caller reads the project's ids and asks
    /// `check_dokploy`.
    DokployProject(String),
}

impl RunScope {
    /// `owner/repo`, as the task names it.
    pub fn repository(&self) -> String {
        format!("{}/{}", self.owner, self.repo)
    }

    /// Whether `repo_path` (as the git proxy parsed it, with or without
    /// `.git`) is this run's repository through this run's provider.
    fn is_own_repository(&self, provider: &Provider, owner: &str, repo: &str) -> bool {
        let repo = repo.strip_suffix(".git").unwrap_or(repo);
        provider.id == self.provider
            && owner.eq_ignore_ascii_case(&self.owner)
            && repo.eq_ignore_ascii_case(&self.repo)
    }

    /// Whether the run may read `service` (a provider id, or `mail`) at
    /// all. Every read surface asks this: the provider tools, the
    /// repository tools, `mail` and the git proxy's fetch.
    pub fn check_read(&self, service: &str) -> Result<(), String> {
        match &self.readable {
            Some(allowed) if !allowed.iter().any(|id| id == service) => Err(format!(
                "this run may not read {service}: {} asked for it and has no access to {service} \
                 itself, and a built-in agent never does more for another agent than that agent \
                 could do",
                if self.requested_by.is_empty() {
                    "the agent that"
                } else {
                    self.requested_by.as_str()
                }
            )),
            _ => Ok(()),
        }
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
        let segments: Vec<String> = path
            .split('/')
            .filter(|segment| !segment.is_empty())
            .map(|segment| segment.to_ascii_lowercase())
            .collect();
        let refuse = |why: String| Decision::Deny(why);
        match provider.service() {
            "github" => {
                // Under the repository, not the repository itself: its
                // settings, its name and its deletion stay with the owner.
                let own = segments.len() >= 4
                    && segments[0] == "repos"
                    && self.is_own_repository(provider, &segments[1], &segments[2]);
                if own {
                    Decision::Allow
                } else {
                    refuse(format!(
                        "this run may change only {} through `{}` (paths under \
                         /repos/{}/…); everything else is read-only for it",
                        self.repository(),
                        self.provider,
                        self.repository()
                    ))
                }
            }
            "cloudflare" => match &self.cloudflare_zone {
                Some(zone)
                    if segments.len() >= 3
                        && segments[0] == "zones"
                        && segments[1] == zone.to_ascii_lowercase() =>
                {
                    Decision::Allow
                }
                Some(zone) => refuse(format!(
                    "this run may change Cloudflare only under /zones/{zone}/…"
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

    /// A Dokploy write in a run whose task names a project: every id the
    /// request names (each string value under a key ending in `Id`, in
    /// the body or the query) must be the project's own or one of the
    /// ids its project tree holds (`project_ids`), and it must name one.
    pub fn check_dokploy(
        &self,
        req: &ops::OpsRequest,
        project_ids: &[String],
    ) -> Result<(), String> {
        let mut named: Vec<String> = Vec::new();
        if let Some(body) = &req.body {
            collect_ids(body, &mut named);
        }
        if let Some(query) = &req.query {
            for (key, value) in query {
                if is_id_key(key)
                    && let Some(text) = value.as_str()
                {
                    named.push(text.trim().to_string());
                }
            }
        }
        let project = self.dokploy_project_id.as_deref().unwrap_or_default();
        if named.is_empty() {
            return Err(format!(
                "this run may change Dokploy only inside the project {project}: name the \
                 project's or one of its resources' ids"
            ));
        }
        for id in &named {
            if id != project && !project_ids.iter().any(|known| known == id) {
                return Err(format!(
                    "this run may change Dokploy only inside the project {project}; {id} is \
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

/// Every string under a key ending in `Id`, at any depth.
fn collect_ids(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, item) in map {
                match item {
                    Value::String(text) if is_id_key(key) => out.push(text.trim().to_string()),
                    Value::Number(number) if is_id_key(key) => out.push(number.to_string()),
                    _ => collect_ids(item, out),
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_ids(item, out);
            }
        }
        _ => {}
    }
}

/// The ids a Dokploy project's tree holds (`project.one`): every string
/// under a key ending in `Id`.
pub fn dokploy_tree_ids(answer: &str) -> Vec<String> {
    let mut ids = Vec::new();
    if let Ok(value) = serde_json::from_str::<Value>(answer) {
        collect_ids(&value, &mut ids);
    }
    ids.sort();
    ids.dedup();
    ids
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope() -> RunScope {
        RunScope {
            run_id: "r1".into(),
            agent: "claude-builtin".into(),
            provider: "github".into(),
            owner: "Luen-Eth".into(),
            repo: "shop".into(),
            dokploy_project_id: None,
            cloudflare_zone: None,
            read_only: false,
            readable: None,
            requested_by: String::new(),
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
                refused.contains("may commit only to Luen-Eth/shop"),
                "{refused}"
            );
            // Reading is like GET: anywhere.
            assert!(
                scope
                    .check_repository_tool(&provider, false, owner, repo)
                    .is_ok()
            );
        }
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
        // Services the asker cannot read are closed even for GET.
        for provider in [ops::GITHUB_ORG, ops::DOKPLOY, ops::CLOUDFLARE] {
            let Decision::Deny(why) = scope.check_call(&provider, "GET", "/x") else {
                panic!("{}", provider.id)
            };
            assert!(why.contains("codex asked for it"), "{why}");
        }
        assert!(scope.check_read("mail").is_err());
        assert!(scope.check_read("github").is_ok());
        // An old scope (no new fields) reads everywhere and writes as before.
        let old: RunScope =
            serde_json::from_str(r#"{"provider":"github","owner":"me","repo":"shop"}"#).unwrap();
        assert!(!old.read_only && old.readable.is_none());
        assert!(old.check_push(&ops::GITHUB, "me/shop").is_ok());
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

    #[test]
    fn github_writes_stay_under_the_repository() {
        let scope = scope();
        let allow = |provider: &Provider, method: &str, path: &str| {
            scope.check_call(provider, method, path) == Decision::Allow
        };
        assert!(allow(&ops::GITHUB, "POST", "/repos/luen-eth/shop/pulls"));
        assert!(allow(
            &ops::GITHUB,
            "PATCH",
            "/repos/LUEN-ETH/SHOP/issues/3"
        ));
        // GET anywhere, through either account.
        assert!(allow(&ops::GITHUB, "GET", "/repos/other/thing"));
        assert!(allow(&ops::GITHUB_ORG, "GET", "/orgs/x/repos"));
        assert!(allow(&ops::GITLAB, "GET", "/projects"));
        for (provider, method, path) in [
            (ops::GITHUB, "POST", "/repos/luen-eth/other/pulls"),
            (ops::GITHUB, "DELETE", "/repos/luen-eth/shop"),
            (ops::GITHUB, "PATCH", "/repos/luen-eth/shop"),
            (ops::GITHUB, "POST", "/user/repos"),
            (ops::GITHUB, "POST", "/graphql"),
            (ops::GITHUB, "PUT", "/repos/luen-eth"),
            (ops::GITHUB_ORG, "POST", "/repos/luen-eth/shop/pulls"),
            (ops::GITLAB, "POST", "/projects/1/issues"),
        ] {
            assert!(
                matches!(scope.check_call(&provider, method, path), Decision::Deny(_)),
                "{method} {path}"
            );
        }
    }

    #[test]
    fn dokploy_and_cloudflare_writes_need_the_task_s_field() {
        let mut scope = scope();
        assert!(matches!(
            scope.check_call(&ops::DOKPLOY, "POST", "/application.deploy"),
            Decision::Deny(_)
        ));
        assert!(matches!(
            scope.check_call(&ops::CLOUDFLARE, "POST", "/zones/abc/dns_records"),
            Decision::Deny(_)
        ));
        assert_eq!(
            scope.check_call(&ops::CLOUDFLARE, "GET", "/zones"),
            Decision::Allow
        );
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
        for path in ["/zones/zone-abc", "/zones/other/dns_records", "/accounts/x"] {
            assert!(
                matches!(
                    scope.check_call(&ops::CLOUDFLARE, "DELETE", path),
                    Decision::Deny(_)
                ),
                "{path}"
            );
        }
        let request = |body: Value| ops::OpsRequest {
            provider: ops::DOKPLOY,
            method: "POST".into(),
            path: "/application.deploy".into(),
            query: None,
            body: Some(body),
        };
        let tree = dokploy_tree_ids(
            r#"{"projectId":"proj-1234","environments":[{"environmentId":"env-1",
                "applications":[{"applicationId":"app-1","name":"web"}]}]}"#,
        );
        assert_eq!(tree, vec!["app-1", "env-1", "proj-1234"]);
        assert!(
            scope
                .check_dokploy(
                    &request(serde_json::json!({"applicationId": "app-1"})),
                    &tree
                )
                .is_ok()
        );
        assert!(
            scope
                .check_dokploy(
                    &request(serde_json::json!({"name": "x", "projectId": "proj-1234"})),
                    &tree
                )
                .is_ok()
        );
        for body in [
            serde_json::json!({"applicationId": "app-elsewhere"}),
            serde_json::json!({"applicationId": "app-1", "serverId": "srv-9"}),
            serde_json::json!({"name": "no id"}),
        ] {
            assert!(
                scope.check_dokploy(&request(body.clone()), &tree).is_err(),
                "{body}"
            );
        }
    }
}
