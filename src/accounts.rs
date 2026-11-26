//! Which owners each GitHub account covers: the login of the user its
//! token belongs to (`GET /user`) and the organizations that user is a
//! member of (`GET /user/orgs`). `integrations` lists them under each
//! account, the `hello` briefing names them when they are known, and a 404
//! under `/repos/{owner}/{repo}` for an owner the account does not cover
//! gets a short hint saying which account does. The hint is advice only:
//! lore never switches accounts or retries by itself.
//!
//! The owners are learnt with the stored credential through `ops::call`
//! (redaction, no redirects, timeouts), one `ops_log` row per lookup, and
//! kept in memory only, for ten minutes, per provider and per stored
//! credential: the cache is keyed by the credential row's nonce, which is
//! fresh on every save, so saving or removing a credential invalidates it
//! at once. A lookup that fails leaves the owners unknown, never an error.
//! An agent sees an account's owners only when its level on that account
//! is at least `read`.

use std::{
    collections::HashMap,
    sync::{Arc, LazyLock, Mutex},
    time::{Duration, Instant},
};

use serde_json::Value;

use super::{Lore, blocking, internal};
use crate::ops;

/// How long learnt owners are kept.
const FRESH: Duration = Duration::from_secs(600);
/// How long a failed lookup is remembered before the next one.
const RETRY: Duration = Duration::from_secs(60);
/// How long a caller outside the async runtime waits for a lookup.
const WAIT: Duration = Duration::from_secs(20);
/// The path a lookup is logged under.
const LOG_PATH: &str = "account owners";
/// The longest owner name accepted from GitHub.
const MAX_LOGIN_CHARS: usize = 100;

/// The owners one GitHub account covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Owners {
    /// The login of the user the token belongs to.
    pub user: String,
    /// The organizations that user is a member of.
    pub organizations: Vec<String>,
}

impl Owners {
    /// True when `owner` is the user or one of the organizations (GitHub
    /// names are case-insensitive).
    fn covers(&self, owner: &str) -> bool {
        self.user.eq_ignore_ascii_case(owner)
            || self
                .organizations
                .iter()
                .any(|organization| organization.eq_ignore_ascii_case(owner))
    }

    /// `luen-eth (user), acme (organization)`.
    fn listed(&self) -> String {
        let mut names = vec![format!("{} (user)", self.user)];
        names.extend(
            self.organizations
                .iter()
                .map(|organization| format!("{organization} (organization)")),
        );
        names.join(", ")
    }

    /// The line `integrations` shows under the account.
    fn line(&self) -> String {
        let addressed = match self.organizations.as_slice() {
            [] => String::new(),
            [only] => format!(" — its repositories are addressed as {only}/<repo>"),
            [first, ..] => format!(
                " — an organization's repositories are addressed as <organization>/<repo>, \
                 e.g. {first}/<repo>"
            ),
        };
        format!("  owners: {}{addressed}\n", self.listed())
    }

    /// The names alone, for the briefing: `someuser, acme`.
    fn names(&self) -> String {
        let mut names = vec![self.user.as_str()];
        names.extend(self.organizations.iter().map(String::as_str));
        names.join(", ")
    }
}

/// Who a lookup or a hint is for: the token's agent, the session's agent,
/// the name the log rows carry and the session, when there is one.
pub(super) struct Caller<'a> {
    pub token_agent: &'a str,
    pub actor: &'a str,
    pub label: &'a str,
    pub session_id: Option<&'a str>,
}

/// How a hint names the account to use instead.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Style {
    /// The `github` and `github_org` tools: by tool name.
    Tool,
    /// The `repo_*` tools: by their `account` argument.
    Repo,
}

/// The cache key: the provider, the API base and the stored credential's
/// nonce (fresh on every save).
type Fingerprint = (&'static str, String, Vec<u8>);

struct Cached {
    owners: Option<Arc<Owners>>,
    at: Instant,
}

impl Cached {
    fn fresh(&self) -> bool {
        let keep = if self.owners.is_some() { FRESH } else { RETRY };
        self.at.elapsed() < keep
    }
}

static CACHE: LazyLock<Mutex<HashMap<Fingerprint, Cached>>> = LazyLock::new(Mutex::default);
/// One lookup at a time per credential: concurrent callers wait for it.
static FILLS: LazyLock<Mutex<HashMap<Fingerprint, Arc<tokio::sync::Mutex<()>>>>> =
    LazyLock::new(Mutex::default);

/// `Some(owners)` when a fresh entry exists (`owners` may be unknown).
fn lookup(fingerprint: &Fingerprint) -> Option<Option<Arc<Owners>>> {
    let cache = CACHE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    cache
        .get(fingerprint)
        .filter(|cached| cached.fresh())
        .map(|cached| cached.owners.clone())
}

fn store(fingerprint: Fingerprint, owners: Option<Arc<Owners>>) {
    let mut cache = CACHE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    cache.retain(|_, cached| cached.at.elapsed() < FRESH);
    cache.insert(
        fingerprint,
        Cached {
            owners,
            at: Instant::now(),
        },
    );
}

fn fill_gate(fingerprint: &Fingerprint) -> Arc<tokio::sync::Mutex<()>> {
    let mut fills = FILLS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    fills.retain(|_, gate| Arc::strong_count(gate) > 1);
    fills.entry(fingerprint.clone()).or_default().clone()
}

/// A GitHub login as lore repeats it: letters, digits, `-`, `_`, `.`.
fn login(value: &Value) -> Option<String> {
    let name = value.get("login")?.as_str()?;
    let valid = !name.is_empty()
        && name.chars().count() <= MAX_LOGIN_CHARS
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
    valid.then(|| name.to_string())
}

/// The `{owner}` of a path under `/repos/{owner}/{repo}`.
fn repo_owner(path: &str) -> Option<&str> {
    let mut segments = path.split('?').next()?.split('/');
    let (Some(""), Some("repos"), Some(owner), Some(repo)) = (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    ) else {
        return None;
    };
    (!owner.is_empty() && !repo.is_empty()).then_some(owner)
}

/// The short reason the log row of a provider call keeps when the service
/// refused it (HTTP 400 and above): the answer's `message` (GitHub,
/// Dokploy) or first `errors[].message` (Cloudflare), else the start of the
/// answer, one line and at most 200 characters. The answer is already
/// redacted. Empty for any other status, so those rows stay as they were.
pub(super) fn upstream_reason(response: &ops::OpsResponse) -> String {
    if response.status < 400 {
        return String::new();
    }
    let value = serde_json::from_str::<Value>(&response.body).unwrap_or(Value::Null);
    let message = value
        .get("message")
        .and_then(Value::as_str)
        .or_else(|| value.pointer("/errors/0/message").and_then(Value::as_str))
        .unwrap_or(&response.body);
    let reason = super::clip(&super::log_text(message.trim(), 200), 200);
    if reason.is_empty() {
        "no reason given".into()
    } else {
        reason
    }
}

fn is_github(provider: ops::Provider) -> bool {
    provider.service() == ops::GITHUB.id
}

fn other_account(provider: ops::Provider) -> ops::Provider {
    if provider.id == ops::GITHUB.id {
        ops::GITHUB_ORG
    } else {
        ops::GITHUB
    }
}

impl Lore {
    /// Where the owners are asked for. The tests never reach GitHub: a
    /// lore without a mock learns nothing there.
    fn owners_base(&self) -> Option<String> {
        match &self.github_api_base {
            Some(base) => Some(base.clone()),
            None if cfg!(test) => None,
            None => Some(ops::GITHUB.fixed_base.to_string()),
        }
    }

    /// The cache key of the provider's stored credential; `None` when
    /// there is none to use (no vault, operations off, nothing stored).
    fn owners_fingerprint(&self, provider: ops::Provider) -> Result<Option<Fingerprint>, String> {
        if self.vault.is_none()
            || !is_github(provider)
            || !self.db.ops_enabled().map_err(internal)?
        {
            return Ok(None);
        }
        let Some(stored) = self.db.vault(provider.id).map_err(internal)? else {
            return Ok(None);
        };
        Ok(self
            .owners_base()
            .map(|base| (provider.id, base, stored.nonce)))
    }

    /// The owners when they are cached; never contacts GitHub.
    fn cached_owners(&self, provider: ops::Provider) -> Option<Arc<Owners>> {
        let fingerprint = self.owners_fingerprint(provider).ok()??;
        lookup(&fingerprint).flatten()
    }

    /// The owners, from the cache or learnt now (one lookup, logged).
    async fn account_owners(
        &self,
        provider: ops::Provider,
        caller: &Caller<'_>,
    ) -> Option<Arc<Owners>> {
        let this = self.clone();
        let fingerprint = blocking(move || this.owners_fingerprint(provider))
            .await
            .ok()??;
        if let Some(found) = lookup(&fingerprint) {
            return found;
        }
        let gate = fill_gate(&fingerprint);
        let _filling = gate.lock().await;
        if let Some(found) = lookup(&fingerprint) {
            return found;
        }
        let owners = self
            .fetch_owners(provider, &fingerprint, caller)
            .await?
            .map(Arc::new);
        store(fingerprint, owners.clone());
        owners
    }

    /// Asks GitHub. `None` when the credential changed meanwhile (nothing
    /// is cached then); `Some(None)` when the owners stay unknown.
    async fn fetch_owners(
        &self,
        provider: ops::Provider,
        fingerprint: &Fingerprint,
        caller: &Caller<'_>,
    ) -> Option<Option<Owners>> {
        let this = self.clone();
        let nonce = fingerprint.2.clone();
        let (secret, guard) = blocking(move || {
            let Some(key) = this.vault.as_ref() else {
                return Ok(None);
            };
            let Some(stored) = this.db.vault(provider.id).map_err(internal)? else {
                return Ok(None);
            };
            if stored.nonce != nonce {
                return Ok(None);
            }
            let Ok(secret) =
                key.decrypt(provider.id, &stored.base_url, &stored.nonce, &stored.secret)
            else {
                return Ok(None);
            };
            let guard = this
                .guard
                .with_secrets(&ops::stored_secrets(&this.db, key).map_err(internal)?);
            Ok(Some((secret, guard)))
        })
        .await
        .ok()??;
        let started = Instant::now();
        let mut status = 0;
        let mut ask = async |path: &str, query: Option<serde_json::Map<String, Value>>| {
            let request = ops::OpsRequest {
                provider,
                method: "GET".into(),
                path: path.into(),
                query,
                body: None,
            };
            let response = ops::call_with_limit(
                &self.http,
                &fingerprint.1,
                &secret,
                &guard,
                &request,
                ops::MAX_RESPONSE_BYTES,
            )
            .await
            .map_err(|error| error.message().to_string())?;
            status = response.status;
            if !(200..300).contains(&response.status) || response.truncated {
                return Err(format!(
                    "GitHub answered HTTP {} for {path}",
                    response.status
                ));
            }
            serde_json::from_str::<Value>(&response.body)
                .map_err(|_| format!("GitHub's answer for {path} was not JSON"))
        };
        let learnt = async {
            let user = login(&ask("/user", None).await?)
                .ok_or_else(|| "GitHub's answer for /user named no login".to_string())?;
            let mut query = serde_json::Map::new();
            query.insert("per_page".into(), Value::from(100));
            let organizations = ask("/user/orgs", Some(query))
                .await?
                .as_array()
                .ok_or_else(|| "GitHub's answer for /user/orgs was not a list".to_string())?
                .iter()
                .filter_map(login)
                .collect();
            Ok::<_, String>(Owners {
                user,
                organizations,
            })
        }
        .await;
        let (outcome, detail) = match &learnt {
            Ok(_) => ("ok", String::new()),
            Err(reason) => ("error", reason.clone()),
        };
        let this = self.clone();
        let (label, actor) = (caller.label.to_string(), caller.actor.to_string());
        let session_id = caller.session_id.map(str::to_string);
        let _ = blocking(move || {
            this.log_op_call(
                &label,
                &actor,
                session_id.as_deref(),
                provider,
                "GET",
                LOG_PATH,
                outcome,
                &detail,
                status as i64,
                started.elapsed().as_millis() as i64,
            );
            Ok(())
        })
        .await;
        Some(learnt.ok())
    }

    /// `account_owners` for a caller outside the async runtime (inside
    /// `blocking`): runs it on the runtime and waits a bounded time.
    fn owners_now(&self, provider: ops::Provider, caller: &Caller<'_>) -> Option<Arc<Owners>> {
        if let Some(owners) = self.cached_owners(provider) {
            return Some(owners);
        }
        let handle = tokio::runtime::Handle::try_current().ok()?;
        let (sender, receiver) = std::sync::mpsc::channel();
        let this = self.clone();
        let (token_agent, actor, label) = (
            caller.token_agent.to_string(),
            caller.actor.to_string(),
            caller.label.to_string(),
        );
        let session_id = caller.session_id.map(str::to_string);
        handle.spawn(async move {
            let caller = Caller {
                token_agent: &token_agent,
                actor: &actor,
                label: &label,
                session_id: session_id.as_deref(),
            };
            let _ = sender.send(this.account_owners(provider, &caller).await);
        });
        receiver.recv_timeout(WAIT).ok().flatten()
    }

    /// Starts a lookup in the background when the owners are not cached;
    /// returns at once.
    fn prefetch_owners(&self, provider: ops::Provider, token_agent: &str, agent: &str) {
        if self.cached_owners(provider).is_some() {
            return;
        }
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let this = self.clone();
        let (token_agent, actor) = (token_agent.to_string(), agent.to_string());
        let label = ops::acting_as(&token_agent, &actor);
        handle.spawn(async move {
            let caller = Caller {
                token_agent: &token_agent,
                actor: &actor,
                label: &label,
                session_id: None,
            };
            this.account_owners(provider, &caller).await;
        });
    }

    /// The `owners:` line `integrations` shows under a configured GitHub
    /// account the agent may use (`read` or `full`); `None` otherwise or
    /// when the owners are unknown. Call from inside `blocking`.
    pub(super) fn owners_line(
        &self,
        provider: ops::Provider,
        configured: bool,
        level: &str,
        caller: &Caller<'_>,
    ) -> Option<String> {
        if !is_github(provider) || !configured || !matches!(level, "read" | "full") {
            return None;
        }
        self.owners_now(provider, caller)
            .map(|owners| owners.line())
    }

    /// What the briefing adds after a GitHub account's level: `; owners:
    /// a, b` when they are cached, and empty otherwise (never contacts
    /// GitHub; see `prefetch_briefing_owners`). The caller lists only
    /// accounts the agent may use.
    pub(super) fn briefing_owners(&self, provider: ops::Provider) -> String {
        match self.cached_owners(provider) {
            Some(owners) if is_github(provider) => format!("; owners: {}", owners.names()),
            _ => String::new(),
        }
    }

    /// For a `hello`: starts, in the background, the lookup of the owners
    /// of each GitHub account the agent may use that are not cached yet,
    /// so the next briefing and `integrations` can name them. Returns at
    /// once: `hello` never waits for GitHub.
    pub(super) fn prefetch_briefing_owners(&self, token_agent: &str, agent: &str) {
        for provider in [ops::GITHUB, ops::GITHUB_ORG] {
            if ops::effective_level(&self.db, token_agent, agent, provider.id)
                .is_ok_and(|level| level != "off")
            {
                self.prefetch_owners(provider, token_agent, agent);
            }
        }
    }

    /// The hint for a 404 under `/repos/{owner}/{repo}` when `owner` is not
    /// one the account covers: which owners it covers and, when the other
    /// GitHub account (that the agent may read) covers `owner`, to use
    /// that one. `None` when the owners are unknown or cover `owner`.
    pub(super) async fn owner_hint(
        &self,
        provider: ops::Provider,
        owner: &str,
        caller: &Caller<'_>,
        style: Style,
    ) -> Option<String> {
        if !is_github(provider) {
            return None;
        }
        let owners = self.account_owners(provider, caller).await?;
        if owners.covers(owner) {
            return None;
        }
        let named = match style {
            Style::Tool => format!("{} account (`{}`)", provider.label, provider.tool),
            Style::Repo => format!("{} account", provider.label),
        };
        let mut hint = format!(
            "lore: `{owner}` is not among the owners the {named} covers: {}.",
            owners.listed()
        );
        let other = other_account(provider);
        let this = self.clone();
        let (token_agent, actor) = (caller.token_agent.to_string(), caller.actor.to_string());
        let level = blocking(move || {
            ops::effective_level(&this.db, &token_agent, &actor, other.id).map_err(internal)
        })
        .await
        .unwrap_or("off");
        if level != "off"
            && let Some(others) = self.account_owners(other, caller).await
            && others.covers(owner)
        {
            let instead = match (style, other.id == ops::GITHUB.id) {
                (Style::Tool, _) => format!("call `{}` instead", other.tool),
                (Style::Repo, true) => "call again with `account: \"personal\"`".to_string(),
                (Style::Repo, false) => "call again with `account: \"organization\"`".to_string(),
            };
            hint.push_str(&format!(
                " `{owner}` is covered by the {} account: {instead}.",
                other.label
            ));
        }
        Some(hint)
    }

    /// `answer` with the owner hint appended when a `github` or
    /// `github_org` call answered 404 under `/repos/{owner}/{repo}`;
    /// anything else is returned as it is.
    pub(super) async fn with_owner_hint(
        &self,
        provider: ops::Provider,
        path: &str,
        status: i64,
        answer: Result<String, String>,
        caller: Caller<'_>,
    ) -> Result<String, String> {
        let owner = match (&answer, repo_owner(path)) {
            (Ok(_), Some(owner)) if status == 404 && is_github(provider) => owner,
            _ => return answer,
        };
        match self.owner_hint(provider, owner, &caller, Style::Tool).await {
            Some(hint) => answer.map(|text| format!("{text}{hint}\n")),
            None => answer,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use axum::{
        Router,
        extract::{Request, State},
        http::StatusCode,
        response::{IntoResponse, Response},
        routing::any,
    };
    use rmcp::handler::server::{common::Extension, wrapper::Parameters};
    use serde::de::DeserializeOwned;
    use serde_json::json;

    use super::*;
    use crate::{
        auth::Agent,
        db::{Db, NewSession},
        embed::Embedder,
        events::Events,
        vault::VaultKey,
    };

    /// The stored test credentials; not real, and not in any token format.
    const PERSONAL: &str = "test-personal-owners-credential";
    const ORGANIZATION: &str = "test-organization-owners-credential";

    /// What the mock GitHub received and how it behaves.
    #[derive(Default)]
    struct Mock {
        /// `/user` and `/user/orgs` requests, as `<account> <path>`.
        lookups: Mutex<Vec<String>>,
        /// Requests under `/repos/`.
        repos: AtomicUsize,
        /// Answer the lookups with 500.
        broken: std::sync::atomic::AtomicBool,
        /// Wait this many milliseconds before answering a lookup.
        slow_ms: AtomicUsize,
    }

    fn reply(status: u16, value: Value) -> Response {
        (StatusCode::from_u16(status).unwrap(), value.to_string()).into_response()
    }

    /// The mock GitHub: the personal credential is the user `luen-eth`,
    /// in no organization; the organization's is `someuser`, a member of
    /// `userl-private-repos`. `luen-eth/traffic-escape` is seen by the
    /// personal credential, `userl-private-repos/traffic-escape` by the
    /// organization's; every other repository is 404. A local mock, never
    /// GitHub.
    async fn github(State(mock): State<Arc<Mock>>, request: Request) -> Response {
        let auth = request
            .headers()
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .to_string();
        let account = if auth == format!("Bearer {PERSONAL}") {
            "personal"
        } else if auth == format!("Bearer {ORGANIZATION}") {
            "organization"
        } else {
            return reply(401, json!({"message": "Bad credentials"}));
        };
        let method = request.method().to_string();
        let path = request.uri().path().to_string();
        if path.starts_with("/user") {
            mock.lookups
                .lock()
                .unwrap()
                .push(format!("{account} {path}"));
            let slow = mock.slow_ms.load(Ordering::SeqCst);
            if slow > 0 {
                tokio::time::sleep(Duration::from_millis(slow as u64)).await;
            }
            if mock.broken.load(Ordering::SeqCst) {
                return reply(500, json!({"message": "Server Error"}));
            }
            return match (account, path.as_str()) {
                ("personal", "/user") => reply(200, json!({"login": "luen-eth"})),
                ("personal", "/user/orgs") => reply(200, json!([])),
                ("organization", "/user") => reply(200, json!({"login": "someuser"})),
                ("organization", "/user/orgs") => {
                    reply(200, json!([{"login": "userl-private-repos", "id": 7}]))
                }
                _ => reply(404, json!({"message": "Not Found"})),
            };
        }
        mock.repos.fetch_add(1, Ordering::SeqCst);
        let segments: Vec<&str> = path.trim_start_matches('/').split('/').collect();
        let visible = matches!(
            (account, segments.as_slice()),
            (
                "personal",
                [
                    "repos",
                    "luen-eth",
                    "traffic-escape" | "readonly" | "racy" | "plain",
                    ..
                ],
            ) | (
                "organization",
                ["repos", "userl-private-repos", "traffic-escape", ..]
            )
        );
        let repo = segments.get(2).copied().unwrap_or("");
        let rest = segments.get(3..).unwrap_or(&[]);
        match (visible, method.as_str(), rest) {
            (true, "GET", ["git", "ref", "heads", "main"]) => {
                return reply(
                    200,
                    json!({"object": {"sha": "1111111111111111111111111111111111111111"}}),
                );
            }
            (true, "GET", ["git", "commits", _]) => {
                return reply(
                    200,
                    json!({"tree": {"sha": "2222222222222222222222222222222222222222"}}),
                );
            }
            (true, "POST", ["git", "blobs"]) if repo == "readonly" => {
                return reply(
                    403,
                    json!({"message": "Resource not accessible by personal access token",
                           "documentation_url": "https://docs.github.com/rest"}),
                );
            }
            (true, "POST", ["git", "blobs"]) => return reply(201, json!({"sha": "blob1"})),
            (true, "POST", ["git", "trees"]) => return reply(201, json!({"sha": "3333"})),
            (true, "POST", ["git", "commits"]) => return reply(201, json!({"sha": "4444"})),
            (true, "PATCH", ["git", "refs", "heads", "main"]) if repo == "racy" => {
                return reply(422, json!({"message": "Update is not a fast forward"}));
            }
            (true, "PATCH", ["git", "refs", "heads", "main"]) => {
                return reply(200, json!({"object": {"sha": "4444"}}));
            }
            _ => {}
        }
        match (visible, segments.get(3)) {
            (true, None) => reply(200, json!({"private": true, "default_branch": "main"})),
            (true, Some(&"commits")) => reply(
                200,
                json!([{"sha": "1111111111111111111111111111111111111111",
                        "commit": {"tree": {"sha": "2222222222222222222222222222222222222222"}}}]),
            ),
            (true, Some(&"git")) => reply(
                200,
                json!({"sha": "2222222222222222222222222222222222222222", "truncated": false,
                       "tree": [{"path": "README.md", "mode": "100644", "type": "blob",
                                 "sha": "b", "size": 3}]}),
            ),
            _ => reply(404, json!({"message": "Not Found"})),
        }
    }

    async fn serve(mock: Arc<Mock>) -> String {
        let router = Router::new()
            .route("/{*rest}", any(github))
            .with_state(mock);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            axum::serve(listener, router.into_make_service())
                .await
                .unwrap();
        });
        base
    }

    fn store_credential(lore: &Lore, provider: &str, credential: &str) {
        let (nonce, secret) = lore
            .vault
            .as_ref()
            .unwrap()
            .encrypt(provider, "", credential);
        lore.db
            .set_vault(provider, "", &nonce, &secret, "tial")
            .unwrap();
    }

    /// A lore with both GitHub credentials stored, pointed at the mock,
    /// and an open session of `claude`.
    async fn setup(name: &str) -> (Lore, Arc<Mock>, String) {
        let dir = std::env::temp_dir().join(format!("lore-accounts-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let db = Db::open(&dir.join("lore.db")).unwrap();
        db.set_profile(&crate::db::ProfileInput {
            address: "Boss".into(),
            language: "English".into(),
            agents: Vec::new(),
        })
        .unwrap();
        let mut lore = Lore::new(
            db,
            Embedder::disabled(),
            0.5,
            Events::new(),
            12,
            None,
            ops::Guard::default(),
        );
        lore.vault = Some(VaultKey::from_env_value(&"5c".repeat(32)).unwrap().unwrap());
        store_credential(&lore, "github", PERSONAL);
        store_credential(&lore, "github_org", ORGANIZATION);
        let mock = Arc::new(Mock::default());
        lore.github_api_base = Some(serve(mock.clone()).await);
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
        (lore, mock, session)
    }

    fn claude() -> Extension<axum::http::request::Parts> {
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

    fn get(session: &str, path: &str) -> Parameters<super::super::OpsArgs> {
        args(session, json!({"method": "GET", "path": path}))
    }

    fn lookups(mock: &Mock) -> Vec<String> {
        mock.lookups.lock().unwrap().clone()
    }

    /// No answer, log row or activity note repeats either credential.
    fn credentials_kept(lore: &Lore, answers: &[&str]) {
        let kept = format!(
            "{answers:?}{:?}{:?}",
            lore.db.ops_log(200).unwrap(),
            lore.db.activity(200).unwrap()
        );
        assert!(!kept.contains(PERSONAL) && !kept.contains(ORGANIZATION));
    }

    const ORG_HINT: &str = "lore: `luen-eth` is not among the owners the GitHub \
        (organization) account (`github_org`) covers: someuser (user), userl-private-repos \
        (organization). `luen-eth` is covered by the GitHub (personal) account: call `github` \
        instead.\n";

    #[tokio::test]
    async fn owners_are_learnt_once_and_listed_per_level() {
        let (lore, mock, session) = setup("listed").await;
        let listed = lore
            .integrations(args(&session, json!({})), claude())
            .await
            .unwrap();
        assert!(
            listed.contains("(called with `github`)\n  owners: luen-eth (user)\n"),
            "{listed}"
        );
        assert!(
            listed.contains(
                "(called with `github_org`)\n  owners: someuser (user), userl-private-repos \
                 (organization) — its repositories are addressed as \
                 userl-private-repos/<repo>\n"
            ),
            "{listed}"
        );
        assert_eq!(
            lookups(&mock),
            [
                "personal /user",
                "personal /user/orgs",
                "organization /user",
                "organization /user/orgs"
            ]
        );
        // One log row per lookup, under a readable path.
        let rows = lore.db.ops_log(10).unwrap();
        let owners: Vec<(&str, &str, &str, i64)> = rows
            .iter()
            .filter(|row| row.path == LOG_PATH)
            .map(|row| {
                (
                    row.provider.as_str(),
                    row.method.as_str(),
                    row.outcome.as_str(),
                    row.status,
                )
            })
            .collect();
        assert_eq!(
            owners,
            [
                ("github_org", "GET", "ok", 200),
                ("github", "GET", "ok", 200)
            ]
        );

        // Cached: the next calls ask GitHub nothing.
        let again = lore
            .integrations(args(&session, json!({})), claude())
            .await
            .unwrap();
        assert_eq!(again, listed);
        let hinted = lore
            .github_org(get(&session, "/repos/luen-eth/traffic-escape"), claude())
            .await
            .unwrap();
        assert!(hinted.ends_with(ORG_HINT), "{hinted}");
        assert_eq!(lookups(&mock).len(), 4);
        assert_eq!(
            lore.db
                .ops_log(100)
                .unwrap()
                .iter()
                .filter(|row| row.path == LOG_PATH)
                .count(),
            2
        );

        // Off on an account: its owners are not shown; read is enough.
        lore.db
            .set_ops_level("claude", "github_org", "off")
            .unwrap();
        lore.db.set_ops_level("claude", "github", "read").unwrap();
        let listed = lore
            .integrations(args(&session, json!({})), claude())
            .await
            .unwrap();
        assert!(listed.contains("  owners: luen-eth (user)\n"), "{listed}");
        assert!(!listed.contains("someuser"), "{listed}");
        assert!(!listed.contains("userl-private-repos"), "{listed}");
        credentials_kept(&lore, &[&listed, &hinted]);
    }

    #[tokio::test]
    async fn saving_or_removing_a_credential_forgets_its_owners() {
        let (lore, mock, session) = setup("invalidate").await;
        let caller = Caller {
            token_agent: "claude",
            actor: "claude",
            label: "claude",
            session_id: Some(&session),
        };
        assert_eq!(
            lore.account_owners(ops::GITHUB, &caller)
                .await
                .unwrap()
                .user,
            "luen-eth"
        );
        lore.account_owners(ops::GITHUB, &caller).await.unwrap();
        assert_eq!(lookups(&mock).len(), 2);
        // Saved again (even the same value): learnt again.
        store_credential(&lore, "github", PERSONAL);
        assert!(lore.cached_owners(ops::GITHUB).is_none());
        lore.account_owners(ops::GITHUB, &caller).await.unwrap();
        assert_eq!(lookups(&mock).len(), 4);
        // Replaced by another account's credential: its owners now.
        store_credential(&lore, "github", ORGANIZATION);
        assert_eq!(
            lore.account_owners(ops::GITHUB, &caller)
                .await
                .unwrap()
                .user,
            "someuser"
        );
        // Removed: nothing is known and nothing is asked.
        assert!(lore.db.delete_vault("github").unwrap());
        let before = lookups(&mock).len();
        assert!(lore.account_owners(ops::GITHUB, &caller).await.is_none());
        assert!(lore.cached_owners(ops::GITHUB).is_none());
        assert_eq!(lookups(&mock).len(), before);
        // The kill switch: no lookup either.
        lore.db.set_ops_enabled(false).unwrap();
        assert!(
            lore.account_owners(ops::GITHUB_ORG, &caller)
                .await
                .is_none()
        );
        assert_eq!(lookups(&mock).len(), before);
    }

    #[tokio::test]
    async fn a_wrong_owner_gets_a_hint_on_either_account() {
        let (lore, mock, session) = setup("hint").await;
        // The production case: the organization's account, the user's name.
        let answer = lore
            .github_org(get(&session, "/repos/luen-eth/traffic-escape"), claude())
            .await
            .unwrap();
        assert_eq!(
            answer,
            format!("HTTP 404\n{{\"message\":\"Not Found\"}}\n{ORG_HINT}")
        );
        // The other way round.
        let answer = lore
            .github(
                get(&session, "/repos/userl-private-repos/traffic-escape/pulls"),
                claude(),
            )
            .await
            .unwrap();
        assert!(
            answer.ends_with(
                "lore: `userl-private-repos` is not among the owners the GitHub (personal) \
                 account (`github`) covers: luen-eth (user). `userl-private-repos` is covered \
                 by the GitHub (organization) account: call `github_org` instead.\n"
            ),
            "{answer}"
        );
        // An owner neither account covers: only what this one covers.
        let answer = lore
            .github(get(&session, "/repos/stranger/x"), claude())
            .await
            .unwrap();
        assert!(
            answer.ends_with(
                "lore: `stranger` is not among the owners the GitHub (personal) account \
                 (`github`) covers: luen-eth (user).\n"
            ),
            "{answer}"
        );
        // Without access to the other account, it is never named.
        lore.db.set_ops_level("claude", "github", "off").unwrap();
        let answer = lore
            .github_org(get(&session, "/repos/luen-eth/traffic-escape"), claude())
            .await
            .unwrap();
        assert!(
            answer.ends_with(
                "lore: `luen-eth` is not among the owners the GitHub (organization) account \
                 (`github_org`) covers: someuser (user), userl-private-repos (organization).\n"
            ),
            "{answer}"
        );
        // The hint never made a call of its own beyond the lookups.
        assert_eq!(mock.repos.load(Ordering::SeqCst), 4);
        assert_eq!(lookups(&mock).len(), 4);
        credentials_kept(&lore, &[&answer]);
    }

    #[tokio::test]
    async fn the_right_owner_or_another_answer_is_left_as_it_is() {
        let (lore, mock, session) = setup("unchanged").await;
        // A known owner's 404: byte for byte what GitHub said.
        let answer = lore
            .github_org(
                get(&session, "/repos/userl-private-repos/missing"),
                claude(),
            )
            .await
            .unwrap();
        assert_eq!(answer, "HTTP 404\n{\"message\":\"Not Found\"}\n");
        let answer = lore
            .github(get(&session, "/repos/LUEN-ETH/missing"), claude())
            .await
            .unwrap();
        assert_eq!(answer, "HTTP 404\n{\"message\":\"Not Found\"}\n");
        // A success, and a 404 outside `/repos/`, are never looked at.
        let before = lookups(&mock).len();
        let answer = lore
            .github(get(&session, "/repos/luen-eth/traffic-escape"), claude())
            .await
            .unwrap();
        assert_eq!(
            answer,
            "HTTP 200\n{\"default_branch\":\"main\",\"private\":true}\n"
        );
        let answer = lore
            .github(get(&session, "/gists/nothing"), claude())
            .await
            .unwrap();
        assert_eq!(answer, "HTTP 404\n{\"message\":\"Not Found\"}\n");
        assert_eq!(lookups(&mock).len(), before);
    }

    #[tokio::test]
    async fn a_failed_lookup_changes_nothing() {
        let (lore, mock, session) = setup("broken").await;
        mock.broken.store(true, Ordering::SeqCst);
        let answer = lore
            .github_org(get(&session, "/repos/luen-eth/traffic-escape"), claude())
            .await
            .unwrap();
        assert_eq!(answer, "HTTP 404\n{\"message\":\"Not Found\"}\n");
        let listed = lore
            .integrations(args(&session, json!({})), claude())
            .await
            .unwrap();
        assert!(!listed.contains("owners:"), "{listed}");
        let refused = lore
            .repo_tree(
                args(
                    &session,
                    json!({"repo": "luen-eth/traffic-escape", "account": "organization"}),
                ),
                claude(),
            )
            .await
            .unwrap_err();
        assert_eq!(
            refused,
            "GitHub answered 404 for the repository: it does not exist, or the GitHub \
             (organization) credential cannot see it"
        );
        // The failure is logged, once per lookup, and remembered a while.
        let failed: Vec<String> = lore
            .db
            .ops_log(100)
            .unwrap()
            .iter()
            .filter(|row| row.path == LOG_PATH)
            .map(|row| format!("{} {} {}", row.provider, row.outcome, row.detail))
            .collect();
        assert_eq!(
            failed,
            [
                "github error GitHub answered HTTP 500 for /user",
                "github_org error GitHub answered HTTP 500 for /user"
            ]
        );
        assert_eq!(lookups(&mock), ["organization /user", "personal /user"]);
    }

    #[tokio::test]
    async fn the_repository_tools_give_the_same_hint() {
        let (lore, _mock, session) = setup("repo").await;
        let refused = lore
            .repo_tree(
                args(
                    &session,
                    json!({"repo": "luen-eth/traffic-escape", "account": "organization"}),
                ),
                claude(),
            )
            .await
            .unwrap_err();
        assert_eq!(
            refused,
            "GitHub answered 404 for the repository: it does not exist, or the GitHub \
             (organization) credential cannot see it lore: `luen-eth` is not among the owners \
             the GitHub (organization) account covers: someuser (user), userl-private-repos \
             (organization). `luen-eth` is covered by the GitHub (personal) account: call \
             again with `account: \"personal\"`."
        );
        let refused = lore
            .repo_read(
                args(
                    &session,
                    json!({"repo": "userl-private-repos/traffic-escape", "paths": ["README.md"],
                           "account": "personal"}),
                ),
                claude(),
            )
            .await
            .unwrap_err();
        assert!(
            refused.ends_with(
                "`userl-private-repos` is covered by the GitHub (organization) account: call \
                 again with `account: \"organization\"`."
            ),
            "{refused}"
        );
        // The right owner: no hint.
        let answer = lore
            .repo_tree(
                args(
                    &session,
                    json!({"repo": "userl-private-repos/traffic-escape",
                           "account": "organization"}),
                ),
                claude(),
            )
            .await
            .unwrap();
        assert!(answer.contains("README.md"), "{answer}");
        // Without access to the other account, it is not named.
        lore.db.set_ops_level("claude", "github", "off").unwrap();
        let refused = lore
            .repo_tree(
                args(
                    &session,
                    json!({"repo": "luen-eth/traffic-escape", "account": "organization"}),
                ),
                claude(),
            )
            .await
            .unwrap_err();
        assert!(
            refused.ends_with("someuser (user), userl-private-repos (organization)."),
            "{refused}"
        );
    }

    #[tokio::test]
    async fn hello_does_not_wait_for_github() {
        let (lore, mock, _session) = setup("hello").await;
        mock.slow_ms.store(3000, Ordering::SeqCst);
        let started = Instant::now();
        let hello = lore
            .hello(
                args(
                    "",
                    json!({"project": "shop", "path": "/work", "repo": "none",
                           "commit": "none", "title": "chat"}),
                ),
                claude(),
            )
            .await
            .unwrap();
        assert!(started.elapsed() < Duration::from_millis(2500));
        assert!(
            hello.contains(
                "Services you can operate through lore: github (full), github_org (full). \
                 See `integrations`."
            ),
            "{hello}"
        );
        // The lookups started in the background; once done, the briefing
        // names the owners.
        for _ in 0..100 {
            if lore.cached_owners(ops::GITHUB).is_some()
                && lore.cached_owners(ops::GITHUB_ORG).is_some()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert_eq!(
            lore.usable_services("claude", "claude").unwrap(),
            "github (full; owners: luen-eth), github_org (full; owners: someuser, \
             userl-private-repos)"
        );
        // The background lookups were logged, without a session.
        let rows = lore.db.ops_log(100).unwrap();
        assert_eq!(
            rows.iter()
                .filter(|row| row.path == LOG_PATH && row.outcome == "ok")
                .count(),
            2
        );
    }

    /// A call refused upstream leaves its status and GitHub's reason (and
    /// the step of `repo_commit`) in the log row and the activity line;
    /// a successful row stays as it was.
    #[tokio::test]
    async fn refused_calls_say_why_in_the_log() {
        let (lore, _mock, session) = setup("legible").await;
        let commit = |repo: &str| {
            lore.repo_commit(
                args(
                    &session,
                    json!({"repo": repo, "branch": "main", "message": "m",
                           "changes": [{"path": "a.txt", "content": "a"}]}),
                ),
                claude(),
            )
        };
        let last = |lore: &Lore| {
            let row = lore.db.ops_log(1).unwrap().remove(0);
            let note = lore.db.activity(1).unwrap().remove(0);
            (
                row.status,
                row.outcome,
                row.detail,
                format!("{} {}", note.tool, note.summary),
            )
        };
        // 403 on the blob: the token lacks Contents write.
        let refused = commit("luen-eth/readonly").await.unwrap_err();
        assert!(refused.contains("HTTP 403"), "{refused}");
        assert_eq!(
            last(&lore),
            (
                403,
                "error".to_string(),
                "Resource not accessible by personal access token (step: blob)".to_string(),
                "github POST repo_commit luen-eth/readonly@main (1 change) → 403 Resource \
                 not accessible by personal access token (step: blob)"
                    .to_string()
            )
        );
        // 422 when moving the branch.
        let refused = commit("luen-eth/racy").await.unwrap_err();
        assert!(
            refused.contains("moved while lore was committing"),
            "{refused}"
        );
        let (status, outcome, detail, _) = last(&lore);
        assert_eq!(
            (status, outcome.as_str(), detail.as_str()),
            (422, "error", "Update is not a fast forward (step: update)")
        );
        // A success: the row as before.
        commit("luen-eth/plain").await.unwrap();
        let (status, outcome, detail, note) = last(&lore);
        assert_eq!((status, outcome.as_str(), detail.as_str()), (200, "ok", ""));
        assert!(note.ends_with("→ 200"), "{note}");
        // 404 in repo_read.
        let refused = lore
            .repo_read(
                args(
                    &session,
                    json!({"repo": "luen-eth/gone", "paths": ["README.md"], "account": "personal"}),
                ),
                claude(),
            )
            .await
            .unwrap_err();
        assert!(refused.starts_with("GitHub answered 404"), "{refused}");
        assert_eq!(
            last(&lore),
            (
                404,
                "error".to_string(),
                "Not Found".to_string(),
                "github GET repo_read luen-eth/gone:README.md → 404 Not Found".to_string()
            )
        );
        // The `github` tool: a 403 answer keeps its reason in the row.
        lore.github(
            args(
                &session,
                json!({"method": "POST", "path": "/repos/luen-eth/readonly/git/blobs",
                       "body": {"content": "x"}}),
            ),
            claude(),
        )
        .await
        .unwrap();
        let (status, outcome, detail, note) = last(&lore);
        assert_eq!(
            (status, outcome.as_str(), detail.as_str()),
            (
                403,
                "ok",
                "Resource not accessible by personal access token"
            )
        );
        assert!(
            note.ends_with("→ 403 Resource not accessible by personal access token"),
            "{note}"
        );
        credentials_kept(&lore, &[&refused]);
    }

    #[test]
    fn repository_paths_name_their_owner() {
        assert_eq!(repo_owner("/repos/acme/shop"), Some("acme"));
        assert_eq!(repo_owner("/repos/acme/shop/pulls/1"), Some("acme"));
        assert_eq!(repo_owner("/repos/acme"), None);
        assert_eq!(repo_owner("/repos//shop"), None);
        assert_eq!(repo_owner("/orgs/acme/repos"), None);
        assert_eq!(login(&json!({"login": "a b"})), None);
        assert_eq!(login(&json!({"login": "ok-name"})), Some("ok-name".into()));
    }
}
