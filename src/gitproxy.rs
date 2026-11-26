//! The git proxy: clone, fetch and push through lore. An agent runs plain
//! `git` against `/git/<provider>/<owner>/<repo>.git` (`github`,
//! `github-org` for the organization account's credential, or `gitlab`),
//! authenticates with its own lore token (the password of a Basic header,
//! or a Bearer token), and lore forwards the smart-HTTP request upstream with the stored
//! credential. The credential never reaches the agent's machine, and the
//! agent's lore token never travels upstream.

use std::{
    net::SocketAddr,
    path::PathBuf,
    pin::Pin,
    sync::{Arc, OnceLock},
    task::{Context, Poll},
    time::{Duration, Instant},
};

use axum::{
    RequestExt, Router,
    body::Body,
    extract::{ConnectInfo, DefaultBodyLimit, Request, State},
    http::{HeaderMap, Method, StatusCode, header},
    response::{IntoResponse, Response},
    routing::any,
};
use base64::Engine;
use tokio::io::{AsyncRead, AsyncWriteExt};

use crate::{
    auth::{McpAuth, Refused, client_ip, too_many_requests},
    db::Db,
    events::Events,
    leakscan,
    ops::{self, transport_reason},
    packscan::{self, Verdict},
    runscope::CiState,
    vault::{Secret, VaultKey},
};

/// GitHub's web base, where its git smart-HTTP endpoint lives. Held in the
/// proxy state so the tests can point it at a local mock.
pub const GITHUB_WEB_BASE: &str = "https://github.com";
/// One request body may be at most 2 GiB. Pushes can be hundreds of MB, so
/// the git routes lift the default limit to exactly this and apply it by
/// hand: the pack streams through and is never buffered whole.
const MAX_BODY_BYTES: usize = 2 * 1024 * 1024 * 1024;
/// The longest repository path accepted.
const MAX_REPO_CHARS: usize = 300;
/// 30 seconds to connect upstream.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// An idle read is dropped after 2 minutes. There is no overall timeout:
/// a clone may take minutes.
const IDLE_READ_TIMEOUT: Duration = Duration::from_secs(120);
/// The request headers forwarded upstream, and nothing else: never the
/// incoming `Authorization`, `Cookie` or `Host`.
const FORWARDED_HEADERS: [&str; 6] = [
    "content-type",
    "content-encoding",
    "accept",
    "accept-encoding",
    "git-protocol",
    "user-agent",
];
/// The upstream response headers passed back to the agent. Everything else
/// — `Set-Cookie`, `WWW-Authenticate`, `Location`, … — is dropped.
const PASSED_HEADERS: [&str; 5] = [
    "content-type",
    "content-encoding",
    "cache-control",
    "expires",
    "pragma",
];
/// The Basic realm git is told about when the lore token is missing.
const REALM: &str = r#"Basic realm="lore git""#;
/// GitHub's REST API, where the leak scan asks whether a repository is
/// public. Held in the proxy state so the tests can point it at a mock.
pub const GITHUB_API_BASE: &str = "https://api.github.com";
/// How long a push to a public repository waits for its turn to be
/// checked before it is refused as busy.
const SCAN_WAIT: Duration = Duration::from_secs(120);

/// The git proxy state: the tokens and the throttling it shares with the
/// `/mcp` middleware, the vault key, and the upstream client.
pub struct GitProxy {
    /// The token table, the failed-login throttling and the store, shared
    /// with the `/mcp` middleware.
    pub auth: Arc<McpAuth>,
    /// The vault key; without it no credential exists and every request
    /// is refused with the vault's own sentence.
    pub vault: Option<VaultKey>,
    /// GitHub's web base; overridable so the tests can point it at a
    /// local mock instead of the real GitHub.
    pub github_web_base: String,
    /// The upstream client: no redirects, no overall timeout.
    pub http: reqwest::Client,
    /// Fan-out of the activity notes to open admin pages.
    pub events: Events,
    /// lore's own secrets, which the leak scan keeps out of a public
    /// repository together with every stored credential.
    pub guard: ops::Guard,
    /// GitHub's REST API base for the visibility check; overridable so
    /// the tests can point it at a local mock.
    pub github_api_base: String,
    /// The largest push to a public repository that is checked; a larger
    /// one is refused. 256 MiB; the tests lower it.
    pub max_scanned_push: usize,
}

impl GitProxy {
    /// The state as `main` builds it: the real GitHub base, the shared
    /// `/mcp` authentication, and the vault key.
    pub fn new(
        auth: Arc<McpAuth>,
        vault: Option<VaultKey>,
        events: Events,
        guard: ops::Guard,
    ) -> Self {
        Self {
            auth,
            vault,
            github_web_base: GITHUB_WEB_BASE.to_string(),
            http: client(),
            events,
            guard,
            github_api_base: GITHUB_API_BASE.to_string(),
            max_scanned_push: packscan::LIMITS.max_request,
        }
    }
}

/// The upstream client every git request goes through: it follows no
/// redirect (so a credential is never forwarded to another host), takes no
/// proxy from the environment, connects
/// within 30 s, reads idly for at most 120 s, and has no overall timeout —
/// a clone may take minutes.
pub fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .connect_timeout(CONNECT_TIMEOUT)
        .read_timeout(IDLE_READ_TIMEOUT)
        .build()
        .expect("building the git proxy client")
}

/// Mounts `/git`: the three smart-HTTP requests, with the request body
/// capped at 2 GiB instead of the default limit.
pub fn router(state: Arc<GitProxy>) -> Router {
    Router::new()
        .route(
            "/git/{*rest}",
            any(proxy).layer(DefaultBodyLimit::max(MAX_BODY_BYTES)),
        )
        .with_state(state)
}

/// One of the three git smart-HTTP requests the proxy answers. Anything
/// else under `/git/` is not a request that exists and answers 404.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Endpoint {
    /// `GET …/info/refs?service=…`: the ref advertisement.
    InfoRefs,
    /// `POST …/git-upload-pack`: fetch / clone.
    UploadPack,
    /// `POST …/git-receive-pack`: push.
    ReceivePack,
}

impl Endpoint {
    /// The method this endpoint answers; any other method is a 404.
    fn method(self) -> Method {
        match self {
            Endpoint::InfoRefs => Method::GET,
            _ => Method::POST,
        }
    }

    /// The path tail as it travels upstream.
    fn tail(self) -> &'static str {
        match self {
            Endpoint::InfoRefs => "info/refs",
            Endpoint::UploadPack => "git-upload-pack",
            Endpoint::ReceivePack => "git-receive-pack",
        }
    }

    /// The tail of the ops log path: the row reads `git:<repo>:<this>`.
    fn log_tag(self) -> &'static str {
        match self {
            Endpoint::InfoRefs => "info-refs",
            Endpoint::UploadPack => "upload-pack",
            Endpoint::ReceivePack => "receive-pack",
        }
    }

    /// True for the two pack POSTs, which also earn an activity note.
    fn is_pack_post(self) -> bool {
        !matches!(self, Endpoint::InfoRefs)
    }
}

/// One parsed `/git/…` request: the provider, the repository path as the
/// agent asked for it (no `.git` added), and the endpoint.
#[derive(Clone)]
struct GitRequest {
    /// github, github_org or gitlab; `parse` lets nothing else through.
    provider: ops::Provider,
    repo: String,
    endpoint: Endpoint,
}

/// Splits the path after `/git/` into provider, repository path and
/// endpoint. `None` when this is not one of the three requests — a
/// provider other than github, github-org or gitlab, a path that ends in
/// anything but the three tails, or a method that does not belong to the
/// shape: the caller answers 404, because no such request exists. The
/// repository path rules are checked later, once the agent is
/// authenticated.
fn parse(rest: &str, method: &Method) -> Option<GitRequest> {
    let segments: Vec<&str> = rest.split('/').collect();
    let count = segments.len();
    // `info/refs` ends the path with two segments; the packs with one.
    let (endpoint, repo_len) =
        if count >= 2 && segments[count - 2] == "info" && segments[count - 1] == "refs" {
            (Endpoint::InfoRefs, count - 2)
        } else if segments[count - 1] == "git-upload-pack" {
            (Endpoint::UploadPack, count - 1)
        } else if segments[count - 1] == "git-receive-pack" {
            (Endpoint::ReceivePack, count - 1)
        } else {
            return None;
        };
    // Only these providers exist; nothing else is a request. The
    // organization account's segment is `github-org`, its provider id
    // `github_org`.
    let provider = *ops::ALL
        .iter()
        .find(|provider| provider.git_route() == Some(segments[0]))?;
    if method != endpoint.method() {
        return None;
    }
    Some(GitRequest {
        provider,
        repo: segments[1..repo_len].join("/"),
        endpoint,
    })
}

/// The repository path rules: one segment at least, every segment plain
/// letters, digits, `.`, `_` or `-` and never `.` or `..`, the count the
/// provider allows (two for GitHub, two to ten for GitLab), and at most
/// 300 characters in all. Broken paths are answered before any credential
/// is touched.
fn validate_repo(provider: &ops::Provider, repo: &str) -> Result<(), String> {
    if repo.is_empty() {
        return Err("the repository path is missing".into());
    }
    if repo.chars().count() > MAX_REPO_CHARS {
        return Err(format!(
            "the repository path must be at most {MAX_REPO_CHARS} characters"
        ));
    }
    for segment in repo.split('/') {
        if segment == "." || segment == ".." {
            return Err("the repository path must not contain a `.` or `..` segment".into());
        }
        if segment.is_empty()
            || !segment
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        {
            return Err(
                "each repository path segment may contain only letters, digits, `.`, `_` and `-`"
                    .into(),
            );
        }
    }
    let count = repo.split('/').count();
    match provider.service() {
        "github" if count != 2 => {
            Err("a github repository path is <owner>/<repo>, exactly two segments".into())
        }
        "gitlab" if !(2..=10).contains(&count) => Err(
            "a gitlab repository path is <group>/<project> or deeper, two to ten segments".into(),
        ),
        _ => Ok(()),
    }
}

/// `info/refs` accepts only `service=git-upload-pack` or
/// `service=git-receive-pack`; dumb HTTP is not supported.
fn validate_service(endpoint: Endpoint, query: Option<&str>) -> Result<(), String> {
    if endpoint != Endpoint::InfoRefs {
        return Ok(());
    }
    match query {
        Some("service=git-upload-pack") | Some("service=git-receive-pack") => Ok(()),
        _ => Err(
            "the query must be service=git-upload-pack or service=git-receive-pack \
             (dumb HTTP is not supported)"
                .into(),
        ),
    }
}

/// True when the request belongs to the push pair, which needs `full`;
/// the fetch pair is covered by `read`.
fn is_push(endpoint: Endpoint, query: Option<&str>) -> bool {
    match endpoint {
        Endpoint::ReceivePack => true,
        Endpoint::InfoRefs => query == Some("service=git-receive-pack"),
        Endpoint::UploadPack => false,
    }
}

/// The repository path with `.git` on the last segment when the agent did
/// not write it: added once, never twice.
fn with_git(repo: &str) -> String {
    match repo.rsplit('/').next() {
        Some(last) if last.ends_with(".git") => repo.to_string(),
        _ => format!("{repo}.git"),
    }
}

/// The lore token a git request presents: the password of a `Basic`
/// Authorization header — the user name is ignored; git sends
/// `lore:<token>` — or a Bearer token. Empty when there is nothing to
/// check, which the token match then refuses.
fn presented_token(headers: &HeaderMap) -> String {
    let Some(value) = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
    else {
        return String::new();
    };
    let Some((scheme, rest)) = value.split_once(' ') else {
        return String::new();
    };
    match scheme.to_ascii_lowercase().as_str() {
        "basic" => base64::engine::general_purpose::STANDARD
            .decode(rest.trim())
            .map(|bytes| {
                let text = String::from_utf8_lossy(&bytes).into_owned();
                match text.split_once(':') {
                    Some((_, password)) => password.to_string(),
                    None => text,
                }
            })
            .unwrap_or_default(),
        "bearer" => rest.trim().to_string(),
        _ => String::new(),
    }
}

/// `Authorization: Basic base64("<user>:<secret>")` for the upstream: the
/// GitHub credential rides as `x-access-token`, the GitLab one as
/// `oauth2`. The header is built here and goes nowhere else.
fn basic(user: &str, secret: &Secret) -> String {
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{user}:{}", secret.expose()))
    )
}

/// The one handler under `/git/`: parse, authenticate, check the path,
/// authorise, forward. Every failure answers with plain text, and the
/// request is logged — allowed, denied or broken — before the response.
async fn proxy(State(state): State<Arc<GitProxy>>, request: Request) -> Response {
    let started = Instant::now();
    // The body is consumed directly, so the route's 2 GiB limit is
    // applied by hand: `with_limited_body` wraps the stream that will
    // pass through, and nothing is buffered whole.
    let (parts, body) = request.with_limited_body().into_parts();

    // Routing: only three requests exist, everything else is a 404.
    let Some(rest) = parts.uri.path().strip_prefix("/git/") else {
        return not_found();
    };
    let Some(git) = parse(rest, &parts.method) else {
        return not_found();
    };

    // Authentication: the same token table and the same constant-time
    // comparison as `/mcp`, with the same throttling for failures.
    // An OAuth access token works as well, as on `/mcp`; a disabled
    // agent is refused either way.
    let presented = presented_token(&parts.headers);
    let internal = parts
        .extensions
        .get::<crate::auth::InternalListener>()
        .is_some();
    let (agent, scope) = match state.auth.authenticate_on(&presented, internal).await {
        Ok(found) => (found.agent().to_string(), found.scope().cloned()),
        Err(Refused::Disabled { agent, env: true }) => {
            return plain(
                StatusCode::FORBIDDEN,
                &format!("the agent \"{agent}\" is disabled in the lore admin view"),
            );
        }
        Err(Refused::Disabled { .. }) => return unauthorized(),
        Err(Refused::Invalid) => {
            let peer = parts
                .extensions
                .get::<ConnectInfo<SocketAddr>>()
                .map(|info| info.0);
            // On the internal listener the direct peer is the caller.
            let internal = parts
                .extensions
                .get::<crate::auth::InternalListener>()
                .is_some();
            let ip = client_ip(&parts.headers, peer, state.auth.trust_proxy && !internal);
            if let Some(retry_after) = state.auth.failures.hit(&ip) {
                tracing::warn!(%ip, "too many failed token attempts");
                return too_many_requests(retry_after);
            }
            return unauthorized();
        }
    };
    // The same per-agent request budget as `/mcp`, and the same record of
    // when the agent was last seen.
    if let Some(retry_after) = state.auth.requests.hit(&agent) {
        return too_many_requests(retry_after);
    }
    {
        let db = state.auth.db.clone();
        let (agent, client) = (
            agent.clone(),
            parts
                .headers
                .get(header::USER_AGENT)
                .and_then(|value| value.to_str().ok())
                .unwrap_or("")
                .chars()
                .take(120)
                .collect::<String>(),
        );
        tokio::task::spawn_blocking(move || {
            if let Err(error) = db.touch_agent(&agent, &client) {
                tracing::warn!(%error, "recording agent activity failed");
            }
        });
    }

    // The request shape: repository path, then the info/refs service.
    let query = parts.uri.query();
    if let Err(reason) = validate_repo(&git.provider, &git.repo) {
        conclude(
            &state,
            &agent,
            &git,
            0,
            "error",
            &reason,
            elapsed_ms(started),
        )
        .await;
        return plain(StatusCode::BAD_REQUEST, &reason);
    }
    if let Err(reason) = validate_service(git.endpoint, query) {
        conclude(
            &state,
            &agent,
            &git,
            0,
            "error",
            &reason,
            elapsed_ms(started),
        )
        .await;
        return plain(StatusCode::BAD_REQUEST, &reason);
    }

    // A built-in agent's run token pushes only to its task's repository,
    // through its task's provider; it fetches from anywhere the
    // credential can read. This is the one place the git proxy checks it.
    let scoped = scope.as_ref().and_then(|scope| {
        if is_push(git.endpoint, query) {
            scope.check_push(&git.provider, &git.repo).err()
        } else {
            // A run another agent asked for fetches only through the
            // accounts that agent may read itself.
            scope.check_read(git.provider.id).err()
        }
    });
    if let Some(reason) = scoped {
        conclude(
            &state,
            &agent,
            &git,
            0,
            "denied",
            &reason,
            elapsed_ms(started),
        )
        .await;
        return plain(StatusCode::FORBIDDEN, &reason);
    }

    // Authorisation: `read` covers the fetch pair, `full` is needed for
    // the push pair. The SQLite work runs on the blocking pool, like
    // every database call of this server.
    let authorized = {
        let db = state.auth.db.clone();
        let vault = state.vault.clone();
        let github_base = state.github_web_base.clone();
        let guard = state.guard.clone();
        let (agent, git, push) = (agent.clone(), git.clone(), is_push(git.endpoint, query));
        tokio::task::spawn_blocking(move || {
            // A git request has no MCP session: the token's agent is the
            // only name there is, and the effective level is its own.
            match ops::authorize(
                &db,
                vault.as_ref(),
                &agent,
                &agent,
                git.provider,
                if push { "POST" } else { "GET" },
            ) {
                Ok(granted) => {
                    // Where the git endpoint lives: GitHub's web base, or
                    // the stored server URL for GitLab, which authorize
                    // already checked is there.
                    let base = if git.provider.service() == "github" {
                        github_base
                    } else {
                        granted.server_url
                    };
                    // A push to GitHub may need the leak scan: its switch,
                    // and every secret lore knows to look for.
                    let leak = if git.endpoint == Endpoint::ReceivePack
                        && git.provider.service() == "github"
                    {
                        scan_guard(&db, vault.as_ref(), guard)
                            .map_err(|error| format!("internal error: {error}"))?
                    } else {
                        None
                    };
                    Ok((base, granted.secret, leak))
                }
                Err(denied) => Err(denied.reason),
            }
        })
        .await
    };
    let Ok(authorized) = authorized else {
        tracing::error!("the git access check panicked");
        return plain(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
    };
    let (base, secret, leak) = match authorized {
        Ok(granted) => granted,
        Err(reason) => {
            conclude(
                &state,
                &agent,
                &git,
                0,
                "denied",
                &reason,
                elapsed_ms(started),
            )
            .await;
            return plain(StatusCode::FORBIDDEN, &reason);
        }
    };

    // The leak scan: a push to a public GitHub repository is read whole
    // and checked before a byte of it goes upstream. A push to a private
    // repository streams through untouched.
    let mut spooled: Option<SpoolStream> = None;
    let mut run_pushed: Option<RunPushed> = None;
    let mut body = Some(body);
    let (owner, repo) = git.repo.split_once('/').unwrap_or((git.repo.as_str(), ""));
    let mut scan = None;
    if let Some(guard) = leak {
        let public = leakscan::visibility()
            .is_public(
                &state.http,
                &state.github_api_base,
                &git.provider,
                &secret,
                owner,
                repo,
            )
            .await;
        if public {
            scan = Some(guard);
        }
    }
    // A built-in agent's push is always read whole and checked: which refs
    // it moves and how, and what it changes in the CI definitions.
    let run = scope
        .as_ref()
        .filter(|_| git.endpoint == Endpoint::ReceivePack)
        .map(|scope| RunPush {
            scope,
            secret: &secret,
            provider: git.provider,
            owner: owner.strip_suffix(".git").unwrap_or(owner).to_string(),
            repo: repo.strip_suffix(".git").unwrap_or(repo).to_string(),
        });
    if scan.is_some() || run.is_some() {
        {
            let encoding = parts
                .headers
                .get(header::CONTENT_ENCODING)
                .and_then(|value| value.to_str().ok())
                .map(str::to_string);
            let taken = body.take().expect("the body is read once");
            match check_push(&state, taken, encoding, scan, run).await {
                Ok((stream, pushed)) => {
                    spooled = Some(stream);
                    run_pushed = pushed;
                }
                Err(refused) => {
                    conclude(
                        &state,
                        &agent,
                        &git,
                        0,
                        refused.outcome,
                        &refused.detail,
                        elapsed_ms(started),
                    )
                    .await;
                    return *refused.response;
                }
            }
        }
    }

    // Forwarding: the upstream URL, the credential as the upstream expects
    // it, the six harmless headers, and a body that streams through.
    let base = base.trim_end_matches('/');
    let mut url = format!("{}/{}/{}", base, with_git(&git.repo), git.endpoint.tail());
    if let Some(query) = query {
        url.push('?');
        url.push_str(query);
    }
    // The upstream is pinned: whatever the repository path, the request
    // goes to the base's scheme, host and port, below the base's path.
    if !same_origin_below(base, &url) {
        let reason = "the upstream URL is not below the configured server";
        conclude(
            &state,
            &agent,
            &git,
            0,
            "error",
            reason,
            elapsed_ms(started),
        )
        .await;
        return plain(StatusCode::BAD_REQUEST, reason);
    }
    let user = if git.provider.service() == "github" {
        "x-access-token"
    } else {
        "oauth2"
    };
    let credential = match ops::sensitive_header(&basic(user, &secret)) {
        Ok(value) => value,
        Err(error) => {
            conclude(
                &state,
                &agent,
                &git,
                0,
                "error",
                error.message(),
                elapsed_ms(started),
            )
            .await;
            return plain(StatusCode::BAD_GATEWAY, error.message());
        }
    };
    let mut forwarded = state
        .http
        .request(git.endpoint.method(), url)
        .header(header::AUTHORIZATION, credential);
    for name in FORWARDED_HEADERS {
        if let Some(value) = parts.headers.get(name) {
            forwarded = forwarded.header(name, value);
        }
    }
    if git.endpoint.method() == Method::POST {
        // The pack streams through in both directions; it is never
        // buffered whole. A checked push streams from its spool file,
        // byte for byte what the agent sent.
        forwarded = match (spooled, body) {
            (Some(stream), _) => forwarded.body(reqwest::Body::wrap_stream(stream)),
            (None, Some(body)) => {
                forwarded.body(reqwest::Body::wrap_stream(body.into_data_stream()))
            }
            (None, None) => forwarded,
        };
    }

    let sent = forwarded.send().await;
    let duration = elapsed_ms(started);
    let response = match sent {
        Ok(response) => response,
        Err(error) => {
            // A push over the 2 GiB cap fails while its body streams up.
            if over_body_limit(&error) {
                let reason = "the request body is larger than 2 GiB";
                conclude(&state, &agent, &git, 0, "error", reason, duration).await;
                return plain(StatusCode::PAYLOAD_TOO_LARGE, reason);
            }
            let reason = transport_reason(&error);
            // The URL carries no credential, but the error is printed
            // without it anyway.
            tracing::warn!(error = %error.without_url(), "the upstream git request failed");
            conclude(&state, &agent, &git, 0, "error", &reason, duration).await;
            return plain(
                StatusCode::BAD_GATEWAY,
                &format!("{} could not be reached: {reason}", git.provider.label),
            );
        }
    };

    // The status passes through, except where passing it through would
    // mislead: an upstream 401 or 403 would make git prompt the user for
    // a password and could be mistaken for a lore login failure, and a
    // redirect is never followed, so it is not an answer either.
    let status = response.status();
    if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
        let reason = format!(
            "the stored {} credential was refused upstream",
            git.provider.id
        );
        conclude(
            &state,
            &agent,
            &git,
            status.as_u16() as i64,
            "error",
            &reason,
            duration,
        )
        .await;
        return plain(StatusCode::BAD_GATEWAY, &reason);
    }
    if status.is_redirection() {
        let reason = "upstream answered with a redirect";
        conclude(
            &state,
            &agent,
            &git,
            status.as_u16() as i64,
            "error",
            reason,
            duration,
        )
        .await;
        return plain(StatusCode::BAD_GATEWAY, reason);
    }
    // The row is written once the headers are in: the duration is the
    // time to the response, and the body streams on without bookkeeping.
    conclude(
        &state,
        &agent,
        &git,
        status.as_u16() as i64,
        "ok",
        "",
        duration,
    )
    .await;

    let mut out = Response::builder().status(status);
    {
        let headers = out
            .headers_mut()
            .expect("a valid status has no conflict to report");
        for name in PASSED_HEADERS {
            if let Some(value) = response.headers().get(name) {
                headers.insert(name, value.clone());
            }
        }
    }
    // A built-in agent's push asks git for a full pack (`no-thin`), so
    // lore can read every tree it changes.
    if scope.is_some() && git.endpoint == Endpoint::InfoRefs && is_push(git.endpoint, query) {
        let mut advertisement = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = tokio_stream::StreamExt::next(&mut stream).await {
            let Ok(chunk) = chunk else {
                return plain(
                    StatusCode::BAD_GATEWAY,
                    "the ref advertisement could not be read",
                );
            };
            advertisement.extend_from_slice(&chunk);
            if advertisement.len() > MAX_ADVERTISEMENT {
                return plain(
                    StatusCode::BAD_GATEWAY,
                    "the ref advertisement is too large",
                );
            }
        }
        let advertisement = with_no_thin(&advertisement).unwrap_or(advertisement);
        if let Some(headers) = out.headers_mut() {
            headers.remove(header::CONTENT_LENGTH);
        }
        return out
            .body(Body::from(advertisement))
            .expect("a valid status and header values build a response");
    }
    // A built-in agent's push: the answer streams to git unchanged while
    // lore reads upstream's report from it, and records for the run only
    // the refs upstream reported `ok` (lore credits a task only with a
    // commit its own run pushed, and lets the run move again only branches
    // it created).
    if let Some(scope) = scope.as_ref().filter(|_| status.is_success())
        && let Some(pushed) = run_pushed.filter(|pushed| !pushed.updates.is_empty())
    {
        let body = recording_body(
            response,
            pushed,
            state.auth.db.clone(),
            scope.run_id.clone(),
        );
        return out
            .body(body)
            .expect("a valid status and header values build a response");
    }
    // A failure mid-stream is passed on without the upstream URL.
    let stream = tokio_stream::StreamExt::map(response.bytes_stream(), |chunk| {
        chunk.map_err(reqwest::Error::without_url)
    });
    out.body(Body::from_stream(stream))
        .expect("a valid status and header values build a response")
}

/// The largest ref advertisement lore rewrites for a built-in agent's push.
const MAX_ADVERTISEMENT: usize = 16 * 1024 * 1024;

/// A `git-receive-pack` ref advertisement with the `no-thin` capability
/// added to the first ref line (so git sends a full pack), or `None` when
/// it does not have the expected shape (it is then passed on as it is).
fn with_no_thin(body: &[u8]) -> Option<Vec<u8>> {
    let mut at = 0;
    let mut out = Vec::with_capacity(body.len() + 8);
    let mut done = false;
    while at + 4 <= body.len() {
        let len = usize::from_str_radix(std::str::from_utf8(&body[at..at + 4]).ok()?, 16).ok()?;
        if len == 0 {
            out.extend_from_slice(b"0000");
            at += 4;
            continue;
        }
        if len < 4 || at + len > body.len() {
            return None;
        }
        let payload = &body[at + 4..at + len];
        at += len;
        if !done && let Some(nul) = payload.iter().position(|byte| *byte == 0) {
            let (line, caps) = payload.split_at(nul);
            let caps = caps[1..].strip_suffix(b"\n").unwrap_or(&caps[1..]);
            let has = caps
                .split(|byte| *byte == b' ')
                .any(|cap| cap == b"no-thin");
            let mut new = line.to_vec();
            new.push(0);
            new.extend_from_slice(caps);
            if !has {
                new.extend_from_slice(b" no-thin");
            }
            new.push(b'\n');
            out.extend_from_slice(format!("{:04x}", new.len() + 4).as_bytes());
            out.extend_from_slice(&new);
            done = true;
            continue;
        }
        out.extend_from_slice(&body[at - len..at]);
    }
    (done && at == body.len()).then_some(out)
}

/// One ref update of a built-in agent's push that lore records for the
/// run once upstream reports it `ok`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RunUpdate {
    old: String,
    new: String,
    name: String,
    /// Whether the new commit came in the run's own pack (else the run
    /// only pointed the ref at a commit that was there already).
    own: bool,
}

/// What a built-in agent's checked push may record: its real updates
/// (`old` differs from `new`), and how upstream's answer is framed.
#[derive(Debug)]
struct RunPushed {
    updates: Vec<RunUpdate>,
    /// The client asked for a side band: the report comes in band 1.
    side_band: bool,
}

impl RunPushed {
    fn from_view(view: &packscan::PushView) -> Self {
        Self {
            updates: view
                .commands
                .updates
                .iter()
                .filter(|(old, new, _)| old != new)
                .map(|(old, new, name)| RunUpdate {
                    old: old.clone(),
                    new: new.clone(),
                    name: name.clone(),
                    own: view.commits.contains_key(new),
                })
                .collect(),
            side_band: view.commands.has("side-band-64k") || view.commands.has("side-band"),
        }
    }
}

/// How a run's pushed ref is recorded: `push` when its commit came in the
/// run's own pack (only such a push, or a `repo_commit`, credits a task),
/// `push-existing` when the run pointed the ref at a commit that was
/// already there.
fn push_via(update: &RunUpdate) -> &'static str {
    if update.own { "push" } else { "push-existing" }
}

/// Most bytes of upstream's report lore keeps while reading it (one line
/// per ref; far more than any push lore lets through has).
const MAX_REPORT: usize = 1024 * 1024;

/// Reads upstream's `report-status` from the bytes of a push's answer as
/// they pass by: band 1 when the client asked for a side band (band 2 is
/// progress and skipped, band 3 a fatal error), the whole answer
/// otherwise. Keeps at most one partial packet and [`MAX_REPORT`] bytes of
/// the report; past that, or on anything it cannot read, it gives up and
/// [`ReportReader::finish`] answers `None`.
#[derive(Debug, Default)]
struct ReportReader {
    side_band: bool,
    outer: Vec<u8>,
    report: Vec<u8>,
    broken: bool,
}

/// The length of a pkt-line from its four hex digits.
fn pkt_len(head: &[u8]) -> Option<usize> {
    let text = std::str::from_utf8(head).ok()?;
    if text.len() != 4 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    usize::from_str_radix(text, 16).ok()
}

impl ReportReader {
    fn new(side_band: bool) -> Self {
        Self {
            side_band,
            ..Self::default()
        }
    }

    fn keep(&mut self, bytes: &[u8]) {
        if self.report.len() + bytes.len() > MAX_REPORT {
            self.broken = true;
            self.report = Vec::new();
        } else {
            self.report.extend_from_slice(bytes);
        }
    }

    fn feed(&mut self, bytes: &[u8]) {
        if self.broken {
            return;
        }
        if !self.side_band {
            self.keep(bytes);
            return;
        }
        self.outer.extend_from_slice(bytes);
        let mut at = 0;
        while !self.broken && self.outer.len() - at >= 4 {
            let Some(len) = pkt_len(&self.outer[at..at + 4]) else {
                self.broken = true;
                break;
            };
            if len == 0 {
                at += 4;
                continue;
            }
            if !(5..=65520).contains(&len) {
                self.broken = true;
                break;
            }
            if self.outer.len() - at < len {
                break;
            }
            let band = self.outer[at + 4];
            let payload = self.outer[at + 5..at + len].to_vec();
            at += len;
            match band {
                1 => self.keep(&payload),
                2 => {}
                _ => self.broken = true,
            }
        }
        self.outer.drain(..at.min(self.outer.len()));
        if self.broken {
            self.outer = Vec::new();
        }
    }

    /// The refs upstream reported `ok`, when the report was read whole:
    /// `unpack ok`, then `ok <ref>` / `ng <ref> <why>` lines (and the
    /// `option` lines of report-status-v2), closed by a flush. `None`
    /// when it could not be read or the pack was not unpacked.
    fn finish(&self) -> Option<std::collections::HashSet<String>> {
        if self.broken {
            return None;
        }
        let body = &self.report;
        let mut at = 0;
        let mut ok = std::collections::HashSet::new();
        let mut unpacked = false;
        while at + 4 <= body.len() {
            let len = pkt_len(&body[at..at + 4])?;
            if len == 0 {
                return unpacked.then_some(ok);
            }
            if len < 4 || at + len > body.len() {
                return None;
            }
            let line = std::str::from_utf8(&body[at + 4..at + len]).ok()?;
            let line = line.strip_suffix('\n').unwrap_or(line);
            at += len;
            if !unpacked {
                if line != "unpack ok" {
                    return None;
                }
                unpacked = true;
            } else if let Some(name) = line.strip_prefix("ok ") {
                ok.insert(name.to_string());
            } else if !(line.starts_with("ng ") || line.starts_with("option ")) {
                return None;
            }
        }
        None
    }
}

/// The answer to a built-in agent's push: upstream's bytes pass to git
/// unchanged, while a [`ReportReader`] reads the report from them; once
/// upstream is done (and before git sees the end), the updates upstream
/// reported `ok` are recorded for the run. Nothing is recorded when the
/// report cannot be read.
fn recording_body(response: reqwest::Response, pushed: RunPushed, db: Db, run_id: String) -> Body {
    let (sender, receiver) = tokio::sync::mpsc::channel::<std::io::Result<axum::body::Bytes>>(8);
    tokio::spawn(async move {
        let mut reader = ReportReader::new(pushed.side_band);
        let mut stream = response.bytes_stream();
        let mut client_gone = false;
        while let Some(chunk) = tokio_stream::StreamExt::next(&mut stream).await {
            match chunk {
                Ok(bytes) => {
                    reader.feed(&bytes);
                    if !client_gone && sender.send(Ok(bytes)).await.is_err() {
                        // git went away: upstream is still read to the end,
                        // so what it did is recorded.
                        client_gone = true;
                    }
                }
                Err(error) => {
                    let error = std::io::Error::other(error.without_url());
                    if !client_gone {
                        let _ = sender.send(Err(error)).await;
                    }
                    break;
                }
            }
        }
        let Some(ok) = reader.finish() else {
            tracing::warn!(
                run = %run_id,
                "upstream's report of a run's push could not be read; nothing was recorded for it"
            );
            return;
        };
        let updates: Vec<RunUpdate> = pushed
            .updates
            .into_iter()
            .filter(|update| ok.contains(&update.name))
            .collect();
        if updates.is_empty() {
            return;
        }
        let recorded = tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
            for update in &updates {
                db.record_run_ref(
                    &run_id,
                    &update.name,
                    &update.old,
                    &update.new,
                    push_via(update),
                )?;
            }
            Ok(())
        })
        .await;
        if !matches!(recorded, Ok(Ok(()))) {
            tracing::error!("recording a run's pushed refs failed");
        }
        drop(sender);
    });
    Body::from_stream(tokio_stream::wrappers::ReceiverStream::new(receiver))
}

/// A short ref name as a path segment of GitHub's API: everything but
/// letters, digits, `.`, `_`, `-` and `/` percent-encoded.
fn ref_path(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for byte in name.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'/') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// What the checks of a built-in agent's push need.
struct RunPush<'a> {
    scope: &'a crate::runscope::RunScope,
    /// lore's credential for the repository, to ask GitHub what the pack
    /// does not carry.
    secret: &'a crate::vault::Secret,
    provider: ops::Provider,
    owner: String,
    repo: String,
}

impl RunPush<'_> {
    /// One GET on GitHub's API with lore's credential: the JSON, or why
    /// not.
    async fn get(&self, state: &GitProxy, path: String) -> Result<serde_json::Value, String> {
        let request = ops::OpsRequest {
            provider: self.provider,
            method: "GET".into(),
            path,
            query: None,
            body: None,
        };
        let answer = ops::call(
            &ops::client(),
            &state.github_api_base,
            self.secret,
            &state.guard,
            &request,
        )
        .await
        .map_err(|error| error.message().to_string())?;
        if answer.status != 200 || answer.truncated {
            return Err(format!("GitHub answered HTTP {}", answer.status));
        }
        serde_json::from_str(&answer.body).map_err(|_| "GitHub's answer is not JSON".to_string())
    }

    /// Whether `name` (a full ref) exists upstream, asked with lore's
    /// credential (`GET /repos/{o}/{r}/git/ref/<ref>`): 200 yes, 404 (or
    /// 409, an empty repository) no, anything else is not an answer.
    async fn ref_exists(&self, state: &GitProxy, name: &str) -> Result<bool, String> {
        if self.provider.service() != "github" {
            return Err(format!("{} cannot be asked", self.provider.label));
        }
        let short = name.strip_prefix("refs/").unwrap_or(name);
        let request = ops::OpsRequest {
            provider: self.provider,
            method: "GET".into(),
            path: format!(
                "/repos/{}/{}/git/ref/{}",
                self.owner,
                self.repo,
                ref_path(short)
            ),
            query: None,
            body: None,
        };
        let answer = ops::call(
            &ops::client(),
            &state.github_api_base,
            self.secret,
            &state.guard,
            &request,
        )
        .await
        .map_err(|error| error.message().to_string())?;
        match answer.status {
            200 => Ok(true),
            404 | 409 => Ok(false),
            status => Err(format!("GitHub answered HTTP {status}")),
        }
    }

    /// A commit's tree: from the pack, else from GitHub.
    async fn tree_of(
        &self,
        state: &GitProxy,
        view: &packscan::PushView,
        commit: &str,
    ) -> Result<String, String> {
        if let Some((tree, _)) = view.commits.get(commit) {
            return Ok(tree.clone());
        }
        let value = self
            .get(
                state,
                format!("/repos/{}/{}/git/commits/{commit}", self.owner, self.repo),
            )
            .await?;
        value["tree"]["sha"]
            .as_str()
            .map(str::to_ascii_lowercase)
            .ok_or_else(|| "GitHub did not name the commit's tree".into())
    }

    /// A tree's entries as `(name, id)`: from the pack, else from GitHub.
    async fn entries(
        &self,
        state: &GitProxy,
        view: &packscan::PushView,
        tree: &str,
    ) -> Result<Vec<(String, String)>, String> {
        if let Some(entries) = view.trees.get(tree) {
            return Ok(entries
                .iter()
                .map(|entry| (entry.name.clone(), entry.id.clone()))
                .collect());
        }
        let value = self
            .get(
                state,
                format!("/repos/{}/{}/git/trees/{tree}", self.owner, self.repo),
            )
            .await?;
        let items = value["tree"]
            .as_array()
            .ok_or_else(|| "GitHub did not list the tree".to_string())?;
        Ok(items
            .iter()
            .filter_map(|item| {
                Some((
                    item["path"].as_str()?.to_string(),
                    item["sha"].as_str()?.to_ascii_lowercase(),
                ))
            })
            .collect())
    }

    /// The CI definitions at a commit (`runscope::ci_state`).
    async fn ci_state(
        &self,
        state: &GitProxy,
        view: &packscan::PushView,
        commit: &str,
    ) -> Result<CiState, String> {
        let root = self.tree_of(state, view, commit).await?;
        let root = self.entries(state, view, &root).await?;
        let github = match root.iter().find(|(name, _)| name == ".github") {
            Some((_, tree)) => Some(self.entries(state, view, &tree.clone()).await?),
            None => None,
        };
        Ok(crate::runscope::ci_state(&root, github.as_deref()))
    }

    /// Whether `old` is an ancestor of `new`: through the commits the pack
    /// carries, then, from where the pack ends, by asking GitHub
    /// (`compare`). Anything lore cannot prove is no.
    async fn fast_forward(
        &self,
        state: &GitProxy,
        view: &packscan::PushView,
        old: &str,
        new: &str,
    ) -> bool {
        let mut seen = std::collections::HashSet::new();
        let mut queue = vec![new.to_string()];
        let mut edge: Vec<String> = Vec::new();
        while let Some(commit) = queue.pop() {
            if commit == old {
                return true;
            }
            if !seen.insert(commit.clone()) || seen.len() > 100_000 {
                continue;
            }
            match view.commits.get(&commit) {
                Some((_, parents)) => queue.extend(parents.iter().cloned()),
                None => edge.push(commit),
            }
        }
        for commit in edge.iter().take(8) {
            let compared = self
                .get(
                    state,
                    format!(
                        "/repos/{}/{}/compare/{old}...{commit}",
                        self.owner, self.repo
                    ),
                )
                .await;
            if let Ok(value) = compared
                && matches!(value["status"].as_str(), Some("ahead" | "identical"))
            {
                return true;
            }
        }
        false
    }

    /// The checks of a built-in agent's push, on what it carries: every
    /// ref (see `RunScope::check_ref_update`), fast-forward only for an
    /// existing branch, and no change to a CI definition against the ref's
    /// old commit (the default branch's head for a new branch) unless the
    /// owner allows it. The refusal, when there is one.
    async fn check(&self, state: &GitProxy, view: &packscan::PushView) -> Result<(), String> {
        // A commit git would read differently (a `parent` line after
        // `author`, …) could prove a fast-forward that is not one.
        if let Some(bad) = view.malformed_commits.first() {
            return Err(format!(
                "the push carries a commit whose header is not the shape git writes ({bad}); a \
                 built-in agent pushes only commits made by git"
            ));
        }
        for (old, new, name) in &view.commands.updates {
            let existing = self.scope.check_ref_update(old, new, name)?;
            // A command that changes nothing moves nothing, and is never
            // recorded for the run.
            if old == new {
                continue;
            }
            // A creation only creates: lore asks upstream itself whether
            // the branch is there already, and refuses when it is (or
            // when it cannot tell).
            if !existing {
                match self.ref_exists(state, name).await {
                    Ok(false) => {}
                    Ok(true) => {
                        return Err(format!(
                            "{name} already exists, so this push cannot create it: a built-in \
                             agent creates only new branches, and moves an existing one only \
                             when it is {}",
                            self.scope.movable()
                        ));
                    }
                    Err(why) => {
                        return Err(format!(
                            "lore could not check whether {name} already exists ({why}), so it \
                             refuses to let this push create it"
                        ));
                    }
                }
            }
            if existing && !self.fast_forward(state, view, old, new).await {
                return Err(format!(
                    "this run may only move {name} forward: lore could not prove that {} \
                     descends from {} (a built-in agent never rewrites a branch's history)",
                    &new[..new.len().min(12)],
                    &old[..old.len().min(12)]
                ));
            }
            if self.scope.ci_allowed {
                continue;
            }
            let base = if existing {
                old.clone()
            } else {
                let value = self
                    .get(
                        state,
                        format!(
                            "/repos/{}/{}/commits/{}",
                            self.owner, self.repo, self.scope.branch
                        ),
                    )
                    .await
                    .map_err(|why| {
                        format!(
                            "lore could not read the default branch to check the push's CI \
                             definitions ({why}), so it refuses the push"
                        )
                    })?;
                value["sha"].as_str().map(str::to_ascii_lowercase).ok_or(
                    "lore could not read the default branch's head, so it refuses the push",
                )?
            };
            let unreadable = |why: String| {
                format!(
                    "lore could not read the CI definitions of {name} ({why}), so it refuses the \
                     push{}",
                    if view.complete {
                        ""
                    } else {
                        "; push a full pack (lore asks for one with `no-thin`)"
                    }
                )
            };
            let before = self
                .ci_state(state, view, &base)
                .await
                .map_err(unreadable)?;
            let after = self.ci_state(state, view, new).await.map_err(unreadable)?;
            let changed = crate::runscope::ci_changes(&before, &after);
            if !changed.is_empty() {
                return Err(crate::runscope::ci_refusal(&format!(
                    "{} in {name}",
                    changed.join(", ")
                )));
            }
        }
        Ok(())
    }
}

/// True when `url` has the scheme, host and port of `base` and a path at
/// or below the base's path.
fn same_origin_below(base: &str, url: &str) -> bool {
    let (Ok(base), Ok(url)) = (reqwest::Url::parse(base), reqwest::Url::parse(url)) else {
        return false;
    };
    let base_path = base.path().trim_end_matches('/');
    base.scheme() == url.scheme()
        && base.host_str() == url.host_str()
        && base.port_or_known_default() == url.port_or_known_default()
        && url.path().starts_with(&format!("{base_path}/"))
}

/// True when a send failed because the request body passed the 2 GiB cap.
fn over_body_limit(error: &reqwest::Error) -> bool {
    let mut source: Option<&dyn std::error::Error> = Some(error);
    while let Some(current) = source {
        if current.to_string().contains("length limit exceeded") {
            return true;
        }
        source = current.source();
    }
    false
}

/// The guard the leak scan of a push uses — lore's own secrets plus every
/// stored credential — or `None` when the administrator switched the scan
/// off. Runs on the blocking pool.
fn scan_guard(
    db: &Db,
    vault: Option<&VaultKey>,
    guard: ops::Guard,
) -> anyhow::Result<Option<ops::Guard>> {
    if !db.leak_scan_settings()?.scan {
        return Ok(None);
    }
    Ok(Some(match vault {
        Some(key) => guard.with_secrets(&ops::stored_secrets(db, key)?),
        None => guard,
    }))
}

/// The pushes checked at once: one. Reading a pack holds up to 256 MiB in
/// memory plus the objects kept as delta bases.
fn scan_slots() -> Arc<tokio::sync::Semaphore> {
    static SLOTS: OnceLock<Arc<tokio::sync::Semaphore>> = OnceLock::new();
    SLOTS
        .get_or_init(|| Arc::new(tokio::sync::Semaphore::new(1)))
        .clone()
}

/// A spooled push on disk, removed when the last holder lets go.
struct Spool(PathBuf);

impl Drop for Spool {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// A checked push streaming upstream from its spool file. The file goes
/// with the stream.
struct SpoolStream {
    file: tokio::fs::File,
    buffer: Vec<u8>,
    _spool: Spool,
}

impl tokio_stream::Stream for SpoolStream {
    type Item = std::io::Result<axum::body::Bytes>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        let mut read = tokio::io::ReadBuf::new(&mut this.buffer);
        match Pin::new(&mut this.file).poll_read(cx, &mut read) {
            Poll::Ready(Ok(())) if read.filled().is_empty() => Poll::Ready(None),
            Poll::Ready(Ok(())) => {
                Poll::Ready(Some(Ok(axum::body::Bytes::copy_from_slice(read.filled()))))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Some(Err(error))),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// A push the leak scan refused: the answer for git, and the outcome and
/// detail of the log row (rule and location, never the secret).
struct PushRefused {
    response: Box<Response>,
    outcome: &'static str,
    detail: String,
}

impl PushRefused {
    fn plain(status: StatusCode, outcome: &'static str, text: &str, detail: &str) -> Self {
        Self {
            response: Box::new(plain(status, text)),
            outcome,
            detail: detail.to_string(),
        }
    }
}

/// The sentence every secret refusal ends with.
const KEEP_OUT: &str = "lore does not let secrets or private files reach a public repository. \
                        Remove them from the commits (rewrite the commits if needed), or ask \
                        the user.";

/// Reads a push to a public repository to the end, into a spool file in
/// the data directory (at most `max_scanned_push` bytes), checks it on the
/// blocking pool, and hands back a stream of exactly those bytes when
/// nothing was found. Anything else is refused, in the protocol when the
/// command list could be read (git then shows the reason under
/// `remote:` and marks the refs rejected), as a plain 403 otherwise.
async fn check_push(
    state: &GitProxy,
    body: Body,
    encoding: Option<String>,
    guard: Option<ops::Guard>,
    run: Option<RunPush<'_>>,
) -> Result<(SpoolStream, Option<RunPushed>), PushRefused> {
    let permit = match tokio::time::timeout(SCAN_WAIT, scan_slots().acquire_owned()).await {
        Ok(Ok(permit)) => permit,
        _ => {
            return Err(PushRefused::plain(
                StatusCode::SERVICE_UNAVAILABLE,
                "error",
                "lore is busy checking other pushes to public repositories for secrets; try again \
                 in a minute",
                "leak scan: busy",
            ));
        }
    };
    let internal = |error: &dyn std::fmt::Display| {
        tracing::error!(%error, "spooling a push failed");
        PushRefused::plain(
            StatusCode::INTERNAL_SERVER_ERROR,
            "error",
            "internal error: the push could not be checked for secrets",
            "leak scan: the push could not be spooled",
        )
    };
    let spool = Spool(
        state
            .auth
            .db
            .temp_path_with("push", "pack")
            .map_err(|error| internal(&error))?,
    );
    let cap = state.max_scanned_push;
    let mut written = 0usize;
    let mut over = false;
    {
        let mut file = tokio::fs::File::create(&spool.0)
            .await
            .map_err(|error| internal(&error))?;
        let mut stream = body.into_data_stream();
        while let Some(chunk) = tokio_stream::StreamExt::next(&mut stream).await {
            let chunk = match chunk {
                Ok(chunk) => chunk,
                Err(error) => {
                    let (status, reason) = if error.to_string().contains("length limit exceeded") {
                        (
                            StatusCode::PAYLOAD_TOO_LARGE,
                            "the request body is larger than 2 GiB",
                        )
                    } else {
                        (StatusCode::BAD_REQUEST, "the push could not be read")
                    };
                    return Err(PushRefused::plain(status, "error", reason, reason));
                }
            };
            // Past the cap the rest is read and dropped, so git gets the
            // answer instead of a broken connection.
            if over {
                continue;
            }
            let room = cap - written;
            let keep = chunk.len().min(room);
            file.write_all(&chunk[..keep])
                .await
                .map_err(|error| internal(&error))?;
            written += keep;
            over = chunk.len() > room;
        }
        file.flush().await.map_err(|error| internal(&error))?;
    }

    let path = spool.0.clone();
    let limits = packscan::Limits {
        max_request: cap,
        ..packscan::LIMITS
    };
    let wants_view = run.is_some();
    type Read = (
        packscan::Checked,
        Option<Result<packscan::PushView, String>>,
    );
    let checked = tokio::task::spawn_blocking(move || -> std::io::Result<Read> {
        let bytes = std::fs::read(&path)?;
        if over {
            return Ok((
                packscan::Checked {
                    commands: packscan::read_commands(&bytes).ok(),
                    verdict: Verdict::TooLarge,
                },
                None,
            ));
        }
        let view = wants_view.then(|| packscan::push_view(&bytes, encoding.as_deref(), &limits));
        let checked = match &guard {
            Some(guard) => {
                let scanner = leakscan::Scanner::new(guard);
                packscan::check_request(&bytes, encoding.as_deref(), &scanner, &limits)
            }
            None => packscan::Checked {
                commands: packscan::read_commands(&bytes).ok(),
                verdict: Verdict::Clean,
            },
        };
        Ok((checked, view))
    })
    .await;
    drop(permit);
    let (checked, view) = match checked {
        Ok(Ok(checked)) => checked,
        Ok(Err(error)) => return Err(internal(&error)),
        Err(error) => return Err(internal(&error)),
    };
    // A built-in agent's push: its refs and its CI definitions, refused in
    // the protocol when the command list could be read.
    let mut accepted: Option<RunPushed> = None;
    if let Some(run) = &run {
        if let Some(Ok(view)) = &view {
            accepted = Some(RunPushed::from_view(view));
        }
        let refusal = match &view {
            _ if over => Some(format!(
                "lore refused this push: it is larger than lore checks for a built-in agent's run \
                 ({} MiB)",
                cap / (1024 * 1024)
            )),
            Some(Ok(view)) => run.check(state, view).await.err(),
            Some(Err(why)) => Some(format!("the push could not be read ({why})")),
            None => Some("the push could not be read".to_string()),
        };
        if let Some(reason) = refusal {
            let lines = vec![format!("lore refused this push: {reason}")];
            let short = format!("lore: {}", reason.chars().take(200).collect::<String>());
            let report = checked
                .commands
                .as_ref()
                .and_then(|commands| packscan::refusal_report(commands, &lines, &short));
            let response = match report {
                Some(body) => (
                    StatusCode::OK,
                    [
                        (
                            header::CONTENT_TYPE,
                            "application/x-git-receive-pack-result",
                        ),
                        (header::CACHE_CONTROL, "no-cache"),
                    ],
                    body,
                )
                    .into_response(),
                None => plain(StatusCode::FORBIDDEN, &lines.join("\n")),
            };
            return Err(PushRefused {
                response: Box::new(response),
                outcome: "denied",
                detail: format!("run push: {}", reason.chars().take(300).collect::<String>()),
            });
        }
    }

    let limit = if cap >= 1024 * 1024 {
        format!("{} MiB", cap / (1024 * 1024))
    } else {
        format!("{cap} bytes")
    };
    let (lines, reason, detail) = match &checked.verdict {
        Verdict::Clean => {
            let file = tokio::fs::File::open(&spool.0)
                .await
                .map_err(|error| internal(&error))?;
            return Ok((
                SpoolStream {
                    file,
                    buffer: vec![0; 64 * 1024],
                    _spool: spool,
                },
                accepted,
            ));
        }
        Verdict::Found(findings) => {
            let mut lines = vec![
                "lore refused this push: it would put a secret or a private file into a public \
                 GitHub repository:"
                    .to_string(),
            ];
            for finding in findings.iter().take(10) {
                lines.push(format!("  - {finding}"));
            }
            if findings.len() > 10 {
                lines.push(format!("  - and {} more", findings.len() - 10));
            }
            lines.push(KEEP_OUT.to_string());
            (
                lines,
                format!("lore: secret or private file found ({})", findings[0]),
                format!("leak scan: {}", leakscan::summarize(findings)),
            )
        }
        Verdict::TooLarge if over => (
            vec![format!(
                "lore refused this push: it is larger than {limit}, too large to check for \
                 secrets before it reaches a public repository. Push it in smaller parts, or ask \
                 the user."
            )],
            format!("lore: push larger than {limit}, too large to check"),
            format!("leak scan: the push is larger than {limit}"),
        ),
        Verdict::TooLarge => (
            vec![
                "lore refused this push: it is too large to check for secrets (an object over \
                 32 MiB, or more than 1 GiB of content), and the repository is public. Push it \
                 in smaller parts, or ask the user."
                    .to_string(),
            ],
            "lore: too large to check for secrets".to_string(),
            "leak scan: too large to check".to_string(),
        ),
        Verdict::Malformed(why) => (
            vec![format!(
                "lore refused this push: it could not be read to check it for secrets ({why}), \
                 and the repository is public. Ask the user."
            )],
            "lore: the push could not be checked for secrets".to_string(),
            format!("leak scan: the push could not be read: {why}"),
        ),
    };
    let report = checked
        .commands
        .as_ref()
        .and_then(|commands| packscan::refusal_report(commands, &lines, &reason));
    let response = match report {
        Some(body) => (
            StatusCode::OK,
            [
                (
                    header::CONTENT_TYPE,
                    "application/x-git-receive-pack-result",
                ),
                (header::CACHE_CONTROL, "no-cache"),
            ],
            body,
        )
            .into_response(),
        None => plain(StatusCode::FORBIDDEN, &lines.join("\n")),
    };
    Err(PushRefused {
        response: Box::new(response),
        outcome: "denied",
        detail,
    })
}

/// Milliseconds since the request arrived, for the ops log row.
fn elapsed_ms(started: Instant) -> i64 {
    started.elapsed().as_millis() as i64
}

/// Writes the one ops log row every request earns — allowed, denied or
/// broken — plus the activity note a pack POST earns, on the blocking
/// pool. It waits, so a response (or a test) never beats the log row.
async fn conclude(
    state: &GitProxy,
    agent: &str,
    git: &GitRequest,
    status: i64,
    outcome: &str,
    detail: &str,
    duration_ms: i64,
) {
    let (db, events) = (state.auth.db.clone(), state.events.clone());
    let (agent, git) = (agent.to_string(), git.clone());
    let (outcome, detail) = (outcome.to_string(), detail.to_string());
    let _ = tokio::task::spawn_blocking(move || {
        record(
            &db,
            &events,
            &agent,
            &git,
            status,
            &outcome,
            &detail,
            duration_ms,
        );
    })
    .await;
}

/// The bookkeeping itself, already on the blocking pool. A failure is
/// logged and never fails the request, and neither row ever carries a
/// credential or the agent's lore token.
#[expect(
    clippy::too_many_arguments,
    reason = "one argument per column of the ops_log row"
)]
fn record(
    db: &Db,
    events: &Events,
    agent: &str,
    git: &GitRequest,
    status: i64,
    outcome: &str,
    detail: &str,
    duration_ms: i64,
) {
    // The repository path is the agent's text: the log keeps a bounded,
    // single-line copy even when it was refused for its shape.
    let repo: String = git
        .repo
        .chars()
        .take(MAX_REPO_CHARS)
        .map(|c| if c.is_control() { '?' } else { c })
        .collect();
    let path = format!("git:{repo}:{tag}", tag = git.endpoint.log_tag());
    if let Err(error) = db.log_op(
        agent,
        None,
        git.provider.id,
        git.endpoint.method().as_str(),
        &path,
        status,
        outcome,
        detail,
        duration_ms,
    ) {
        tracing::warn!(%error, "writing the ops log failed");
    }
    // The feed names the fetch and the push; info/refs is bookkeeping.
    if git.endpoint.is_pack_post() {
        let tool = if git.endpoint == Endpoint::UploadPack {
            "git_fetch"
        } else {
            "git_push"
        };
        let summary = format!("{} {}", git.provider.id, repo);
        match db.record_activity(agent, tool, "", None, None, &[], &summary) {
            Ok(activity) => events.publish(activity),
            Err(error) => tracing::warn!(%error, "recording activity failed"),
        }
    }
}

/// A short plain-text answer, as git clients read them.
fn plain(status: StatusCode, text: &str) -> Response {
    (status, format!("{text}\n")).into_response()
}

/// Everything under `/git/` that is not one of the three requests.
fn not_found() -> Response {
    plain(StatusCode::NOT_FOUND, "no such git request")
}

/// The 401 that tells git to use (or keep using) the token it has,
/// instead of prompting the user for a password.
fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, REALM)],
        "missing or invalid lore token\n",
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::load_tokens;
    use std::sync::Mutex;

    /// A lore token long enough for `load_tokens` to accept.
    const TOKEN: &str = "test-lore-token-0123456789abcdef";
    /// The stored credentials, as the upstream must receive them.
    const GITHUB_CREDENTIAL: &str = "ghp_test-upstream-credential";
    const GITLAB_CREDENTIAL: &str = "glpat-test-upstream-credential"; // lore:allow-secret

    /// One request the mock upstream saw.
    #[derive(Debug, Clone, Default)]
    struct Seen {
        method: String,
        path: String,
        query: String,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    }

    type Log = Arc<Mutex<Vec<Seen>>>;

    /// What the mock upstream records and what it answers.
    #[derive(Clone)]
    struct Mock {
        log: Log,
        status: StatusCode,
        headers: Vec<(&'static str, &'static str)>,
        body: Vec<u8>,
    }

    /// The headers worth checking, lowercased as HTTP names are.
    const WATCHED: [&str; 7] = [
        "authorization",
        "content-type",
        "git-protocol",
        "user-agent",
        "cookie",
        "host",
        "x-lore-token",
    ];

    /// Serves a router on a free local port. A local mock, never a real
    /// service.
    async fn serve(router: Router) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            axum::serve(listener, router.into_make_service())
                .await
                .unwrap();
        });
        base
    }

    /// The mock upstream: records every request, answers a fixed status,
    /// header set and body.
    fn mock_upstream(mock: &Mock) -> Router {
        Router::new().route(
            "/{*rest}",
            any(|State(mock): State<Mock>, request: Request| async move {
                let (parts, raw) = request.into_parts();
                // A few MiB must fit; a pack is larger than most limits.
                let body = axum::body::to_bytes(raw, 32 * 1024 * 1024)
                    .await
                    .unwrap_or_default();
                let mut seen = Seen {
                    method: parts.method.to_string(),
                    path: parts.uri.path().to_string(),
                    query: parts.uri.query().unwrap_or_default().to_string(),
                    body: body.to_vec(),
                    ..Default::default()
                };
                for name in WATCHED {
                    if let Some(value) = parts.headers.get(name) {
                        seen.headers
                            .push((name.to_string(), value.to_str().unwrap_or("").to_string()));
                    }
                }
                mock.log.lock().unwrap().push(seen);
                let mut response = (mock.status, mock.body.clone()).into_response();
                for (name, value) in &mock.headers {
                    response.headers_mut().insert(*name, value.parse().unwrap());
                }
                response
            })
            .with_state(mock.clone()),
        )
    }

    /// Serves the proxy itself, with the GitHub base pointed at the mock
    /// upstream and a gitlab row pointing at it too.
    async fn serve_proxy(upstream: &str, vault: Option<VaultKey>) -> (String, Db) {
        let (base, db, _) = serve_proxy_with(upstream, vault, usize::MAX).await;
        (base, db)
    }

    /// The mock GitHub API the leak scan asks about visibility: a
    /// repository whose name starts with `public` is public, one starting
    /// with `broken` answers 500, every other one is private. Every
    /// question is counted.
    async fn visibility_api() -> (String, Arc<Mutex<Vec<String>>>) {
        let asked: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let router = Router::new()
            // Which branches exist (a run's push may only create new ones):
            // `main` and `release` do, a name starting with `broken` gets a
            // 500, every other one is missing.
            .route(
                "/repos/{owner}/{repo}/git/ref/{*name}",
                any(
                    |State(asked): State<Arc<Mutex<Vec<String>>>>,
                     axum::extract::Path((_, _, name)): axum::extract::Path<(
                        String,
                        String,
                        String,
                    )>| async move {
                        asked.lock().unwrap().push(format!("ref {name}"));
                        match name.trim_start_matches("heads/") {
                            "main" | "release" => (
                                StatusCode::OK,
                                format!(
                                    r#"{{"ref":"refs/{name}","object":{{"sha":"{}"}}}}"#,
                                    "e".repeat(40)
                                ),
                            ),
                            other if other.starts_with("broken") => {
                                (StatusCode::INTERNAL_SERVER_ERROR, String::new())
                            }
                            _ => (
                                StatusCode::NOT_FOUND,
                                r#"{"message":"Not Found"}"#.to_string(),
                            ),
                        }
                    },
                ),
            )
            .route(
                "/repos/{owner}/{repo}",
                any(
                    |State(asked): State<Arc<Mutex<Vec<String>>>>,
                     axum::extract::Path((owner, repo)): axum::extract::Path<(String, String)>,
                     headers: HeaderMap| async move {
                        let authorized = headers
                            .get(header::AUTHORIZATION)
                            .and_then(|value| value.to_str().ok())
                            == Some(&format!("Bearer {GITHUB_CREDENTIAL}") as &str);
                        asked.lock().unwrap().push(format!("{owner}/{repo}"));
                        if !authorized || repo.starts_with("broken") {
                            return (StatusCode::INTERNAL_SERVER_ERROR, String::new());
                        }
                        let public = repo.starts_with("public");
                        (
                            StatusCode::OK,
                            format!(
                                "{{\"full_name\":\"{owner}/{repo}\",\"private\":{}}}",
                                !public
                            ),
                        )
                    },
                ),
            )
            .with_state(asked.clone());
        (serve(router).await, asked)
    }

    /// `serve_proxy` with the visibility API mocked, the push size cap
    /// set, and the questions the API was asked handed back.
    async fn serve_proxy_with(
        upstream: &str,
        vault: Option<VaultKey>,
        max_scanned_push: usize,
    ) -> (String, Db, Arc<Mutex<Vec<String>>>) {
        let dir = std::env::temp_dir().join(format!(
            "lore-gitproxy-test-{}-{:?}-{}",
            std::process::id(),
            std::thread::current().id(),
            upstream.rsplit(':').next().unwrap_or("")
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let db = Db::open(&dir.join("lore.db")).unwrap();
        if let Some(key) = vault.as_ref() {
            let (nonce, secret) = key.encrypt("github", "", GITHUB_CREDENTIAL);
            db.set_vault("github", "", &nonce, &secret, "-ial").unwrap();
            let (nonce, secret) = key.encrypt("gitlab", upstream, GITLAB_CREDENTIAL);
            db.set_vault("gitlab", upstream, &nonce, &secret, "-eam")
                .unwrap();
        }
        let auth = Arc::new(McpAuth::new(
            load_tokens("", &format!("claude:{TOKEN}")).unwrap(),
            db.clone(),
            false,
        ));
        let (api, asked) = visibility_api().await;
        let state = Arc::new(GitProxy {
            auth,
            vault,
            github_web_base: upstream.to_string(),
            http: client(),
            events: Events::new(),
            guard: ops::Guard::default(),
            github_api_base: api,
            max_scanned_push: max_scanned_push.min(packscan::LIMITS.max_request),
        });
        // Served as the internal listener serves it, where run tokens work.
        let base = serve(router(state).layer(axum::Extension(crate::auth::InternalListener))).await;
        (base, db, asked)
    }

    /// The fixture most tests start from: a working mock upstream, the
    /// vault on, both providers configured, `claude` at full access.
    async fn working_proxy() -> (String, Db, Log) {
        let log: Log = Arc::new(Mutex::new(Vec::new()));
        let mock = Mock {
            log: log.clone(),
            status: StatusCode::OK,
            headers: vec![],
            body: b"001e# service=git-upload-pack\n0000".to_vec(),
        };
        let upstream = serve(mock_upstream(&mock)).await;
        let (base, db) = serve_proxy(&upstream, Some(key())).await;
        (base, db, log)
    }

    fn key() -> VaultKey {
        VaultKey::from_env_value(&"ab".repeat(32)).unwrap().unwrap()
    }

    /// `Authorization: Basic base64("lore:<token>")`, as git sends it.
    fn basic_auth() -> String {
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("lore:{TOKEN}"))
        )
    }

    fn call(
        client: &reqwest::Client,
        base: &str,
        method: Method,
        path: &str,
    ) -> reqwest::RequestBuilder {
        client
            .request(method, format!("{base}{path}"))
            .header(header::AUTHORIZATION, basic_auth())
    }

    /// Deterministic pseudo-random bytes: the tests need volume, not
    /// randomness.
    fn noise(len: usize) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(len);
        let mut state = 0x1234_5678_u32;
        for _ in 0..len {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            bytes.push((state >> 24) as u8);
        }
        bytes
    }

    fn last(log: &Log) -> Seen {
        log.lock().unwrap().last().cloned().unwrap()
    }

    /// One raw HTTP request over a socket, read to the connection's end.
    /// The URL parser inside an HTTP client normalises `.` and `..`
    /// segments away before they are ever sent, and the proxy must still
    /// see and refuse them, so this writes the request by hand — on the
    /// blocking pool, where waiting for the answer holds nothing up.
    async fn raw_request(base: &str, path: &str) -> (u16, String) {
        let (base, path) = (base.to_string(), path.to_string());
        tokio::task::spawn_blocking(move || {
            use std::io::{Read, Write};
            let address: SocketAddr = base.trim_start_matches("http://").parse().unwrap();
            let mut stream = std::net::TcpStream::connect(address).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let request = format!(
                "GET {path} HTTP/1.1\r\nHost: {address}\r\nAuthorization: {}\r\n\
                 Connection: close\r\n\r\n",
                basic_auth()
            );
            stream.write_all(request.as_bytes()).unwrap();
            let mut response = String::new();
            stream.read_to_string(&mut response).unwrap();
            let status = response
                .split_whitespace()
                .nth(1)
                .and_then(|code| code.parse().ok())
                .unwrap_or(0);
            (status, response)
        })
        .await
        .expect("the raw request finished")
    }

    /// No header, a wrong token and a malformed Basic value: all 401, and
    /// the one header that makes git retry with what it has.
    #[tokio::test]
    async fn tokens_are_required_and_checked() {
        let (base, _db, log) = working_proxy().await;
        let client = reqwest::Client::new();
        let path = "/git/github/owner/repo.git/info/refs?service=git-upload-pack";

        let response = client.get(format!("{base}{path}")).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers().get(header::WWW_AUTHENTICATE).unwrap(),
            REALM
        );
        let body = response.text().await.unwrap();
        assert!(body.contains("lore token"), "{body}");

        for header in [
            format!("Bearer {}", "x".repeat(TOKEN.len())),
            "Basic not base64 at all".to_string(),
        ] {
            let response = client
                .get(format!("{base}{path}"))
                .header(header::AUTHORIZATION, &header)
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{header}");
        }
        // None of it ever reached the upstream.
        assert!(log.lock().unwrap().is_empty());

        // Basic and Bearer both work.
        for header in [basic_auth(), format!("Bearer {TOKEN}")] {
            let response = client
                .get(format!("{base}{path}"))
                .header(header::AUTHORIZATION, &header)
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{header}");
        }
        // The upstream saw the requests, with the stored credential in
        // them and never the lore token.
        for seen in log.lock().unwrap().iter() {
            for (_, value) in &seen.headers {
                assert!(!value.contains(TOKEN), "the lore token travelled: {value}");
            }
        }
    }

    /// The four requests against the levels: `off` refuses everything,
    /// `read` lets the fetch pair through and refuses the push pair,
    /// `full` lets all four through; the kill switch and a provider
    /// without a credential refuse with their own sentences.
    /// An OAuth access token for a new agent, written straight into the
    /// store the way an approval and a code exchange would.
    fn oauth_token(db: &Db, agent: &str) -> String {
        db.register_oauth_client(&crate::db::OAuthClient {
            client_id: format!("client-{agent}"),
            client_name: "Test".into(),
            redirect_uris: vec!["http://127.0.0.1:9/cb".into()],
        })
        .unwrap();
        let grant = db
            .approve(&crate::db::Approval {
                agent: agent.into(),
                new_agent: true,
                avatar: String::new(),
                client_id: format!("client-{agent}"),
                client_name: "Test".into(),
                redirect_uri: "http://127.0.0.1:9/cb".into(),
                authorized_by: "admin".into(),
                reserved: vec!["claude".into()],
                services_off: false,
                code_hash: format!("code-{agent}"),
                code_challenge: "c".repeat(43),
                code_expires_at: crate::db::unix_now() + 300,
            })
            .unwrap();
        let access = crate::oauth::random_token().unwrap();
        let now = crate::db::unix_now();
        db.issue_tokens(
            grant,
            &crate::oauth::token_hash(&access),
            now + 3600,
            &format!("refresh-{agent}"),
            now + 7200,
        )
        .unwrap();
        access
    }

    #[tokio::test]
    async fn oauth_tokens_work_and_disabled_agents_are_refused() {
        let (base, db, _log) = working_proxy().await;
        let client = reqwest::Client::new();
        let path = "/git/github/owner/repo.git/info/refs?service=git-upload-pack";
        let access = oauth_token(&db, "cursor");
        let with = |secret: &str| {
            client.get(format!("{base}{path}")).header(
                header::AUTHORIZATION,
                format!(
                    "Basic {}",
                    base64::engine::general_purpose::STANDARD.encode(format!("lore:{secret}"))
                ),
            )
        };
        // An OAuth access token is a lore token too; its agent's level
        // applies (no row: full).
        assert_eq!(with(&access).send().await.unwrap().status(), StatusCode::OK);

        // A disabled env-token agent: 403 with a sentence.
        db.set_agent_disabled("claude", true, "admin").unwrap();
        let response = with(TOKEN).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(
            response
                .text()
                .await
                .unwrap()
                .contains("\"claude\" is disabled")
        );
        // A disabled OAuth agent: its token no longer counts.
        db.set_agent_disabled("cursor", true, "admin").unwrap();
        let response = with(&access).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers().get(header::WWW_AUTHENTICATE).unwrap(),
            REALM
        );
        db.set_agent_disabled("claude", false, "admin").unwrap();
        assert_eq!(with(TOKEN).send().await.unwrap().status(), StatusCode::OK);
    }

    /// A run in the database for a built-in agent, scoped to `me/shop`
    /// through the personal account; answers the run token.
    fn run_token(db: &Db, run_id: &str) -> String {
        db.register_builtin_agents(&[("claude-builtin".into(), "claude".into(), "ember")])
            .unwrap();
        let token = crate::runscope::new_token().unwrap();
        let scope = crate::runscope::RunScope {
            version: crate::runscope::SCOPE_VERSION,
            run_id: run_id.into(),
            agent: "claude-builtin".into(),
            provider: "github".into(),
            owner: "me".into(),
            repo: "shop".into(),
            branch: "main".into(),
            readable: Some(vec!["github".into()]),
            ..Default::default()
        };
        db.insert_run(&crate::db::NewRun {
            id: run_id.into(),
            agent: "claude-builtin".into(),
            kind: "task".into(),
            token_hash: crate::oauth::token_hash(&token),
            token_expires_at: crate::db::unix_now() + 600,
            scope: serde_json::to_string(&scope).unwrap(),
            ..Default::default()
        })
        .unwrap();
        token
    }

    /// A run token pushes only to its task's repository, through its
    /// task's provider; it fetches from anywhere; it dies with its run,
    /// its revocation and its hard limit; and it is never logged.
    #[tokio::test]
    async fn a_run_token_pushes_only_to_its_task_s_repository() {
        let (base, db, log) = working_proxy().await;
        let client = reqwest::Client::new();
        let token = run_token(&db, "run-git-1");
        let with = |user: &str, token: &str| {
            format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode(format!("{user}:{token}"))
            )
        };
        let get = |path: &str, auth: String| {
            client
                .get(format!("{base}{path}"))
                .header(header::AUTHORIZATION, auth)
                .send()
        };
        let push_refs = |repo: &str| format!("/git/{repo}.git/info/refs?service=git-receive-pack");
        // Its own repository: both halves of a push go through.
        let response = get(&push_refs("github/me/shop"), with("lore", &token))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let response = client
            .post(format!("{base}/git/github/me/shop.git/git-receive-pack"))
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(b"0000".to_vec())
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let sent = log.lock().unwrap().len();
        // Another repository, another owner, the other account: refused
        // before anything goes upstream.
        for repo in [
            "github/me/other",
            "github/someone/shop",
            "github-org/me/shop",
        ] {
            let response = get(&push_refs(repo), with("lore", &token)).await.unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN, "{repo}");
            assert!(
                response
                    .text()
                    .await
                    .unwrap()
                    .contains("may push only to me/shop"),
                "{repo}"
            );
            let row = &db.ops_log(1).unwrap()[0];
            assert_eq!(row.outcome, "denied");
        }
        let response = client
            .post(format!("{base}/git/github/me/other.git/git-receive-pack"))
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(b"0000".to_vec())
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            log.lock().unwrap().len(),
            sent,
            "nothing refused went upstream"
        );
        // Fetching another repository is allowed.
        let response = get(
            "/git/github/someone/library.git/info/refs?service=git-upload-pack",
            with("lore", &token),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        // The user name in the Basic header changes nothing: the token's
        // agent is the one recorded.
        get(&push_refs("github/me/shop"), with("codex-builtin", &token))
            .await
            .unwrap();
        let row = &db.ops_log(1).unwrap()[0];
        assert_eq!(row.agent, "claude-builtin");
        // Never logged.
        let dump = format!(
            "{:?}{:?}",
            db.ops_log(100).unwrap(),
            db.activity(100).unwrap()
        );
        assert!(!dump.contains(&token));

        // Revoked: 401.
        db.revoke_run_token("run-git-1").unwrap();
        let response = get(&push_refs("github/me/shop"), with("lore", &token))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        // Past its hard limit: 401.
        let late = run_token(&db, "run-git-2");
        db.execute_for_test("UPDATE agent_runs SET token_expires_at = 1 WHERE id = 'run-git-2'");
        let response = get(&push_refs("github/me/shop"), with("lore", &late))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        // Its run ended: 401.
        let ended = run_token(&db, "run-git-3");
        assert_eq!(
            get(&push_refs("github/me/shop"), with("lore", &ended))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        db.finish_run(
            "run-git-3",
            &crate::db::RunEnd {
                status: "failed".into(),
                ..Default::default()
            },
        )
        .unwrap();
        let response = get(&push_refs("github/me/shop"), with("lore", &ended))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        // A disabled built-in agent's run token: refused too.
        let live = run_token(&db, "run-git-4");
        db.set_agent_disabled("claude-builtin", true, "admin")
            .unwrap();
        let response = get(&push_refs("github/me/shop"), with("lore", &live))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn the_levels_gate_fetch_and_push() {
        let (base, db, _log) = working_proxy().await;
        let client = reqwest::Client::new();
        let cases: [(Method, &str); 4] = [
            (
                Method::GET,
                "/git/github/owner/repo.git/info/refs?service=git-upload-pack",
            ),
            (
                Method::GET,
                "/git/github/owner/repo.git/info/refs?service=git-receive-pack",
            ),
            (Method::POST, "/git/github/owner/repo.git/git-upload-pack"),
            (Method::POST, "/git/github/owner/repo.git/git-receive-pack"),
        ];

        db.set_ops_level("claude", "github", "off").unwrap();
        for (method, path) in cases.iter() {
            let response = call(&client, &base, method.clone(), path)
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN, "{path}");
            let body = response.text().await.unwrap();
            assert!(body.contains("you have no access to github"), "{body}");
        }

        db.set_ops_level("claude", "github", "read").unwrap();
        let response = call(
            &client,
            &base,
            Method::GET,
            "/git/github/owner/repo.git/info/refs?service=git-upload-pack",
        )
        .send()
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let response = call(
            &client,
            &base,
            Method::POST,
            "/git/github/owner/repo.git/git-upload-pack",
        )
        .body("00aawant 0000")
        .send()
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        for path in [
            "/git/github/owner/repo.git/info/refs?service=git-receive-pack",
            "/git/github/owner/repo.git/git-receive-pack",
        ] {
            let method = if path.contains("info/refs") {
                Method::GET
            } else {
                Method::POST
            };
            let response = call(&client, &base, method, path).send().await.unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN, "{path}");
            let body = response.text().await.unwrap();
            assert!(
                body.contains("you have read-only access to github"),
                "{body}"
            );
        }

        db.set_ops_level("claude", "github", "full").unwrap();
        for (method, path) in cases.iter() {
            let response = call(&client, &base, method.clone(), path)
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{path}");
        }

        // The kill switch refuses everything, configured or not.
        db.set_ops_enabled(false).unwrap();
        let response = call(
            &client,
            &base,
            Method::GET,
            "/git/github/owner/repo.git/info/refs?service=git-upload-pack",
        )
        .send()
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = response.text().await.unwrap();
        assert!(
            body.contains("operations are switched off by the administrator"),
            "{body}"
        );
        db.set_ops_enabled(true).unwrap();

        // A provider with no stored credential says so, in its own words.
        db.delete_vault("gitlab").unwrap();
        let response = call(
            &client,
            &base,
            Method::GET,
            "/git/gitlab/group/sub/project.git/info/refs?service=git-upload-pack",
        )
        .send()
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = response.text().await.unwrap();
        assert!(body.contains("no gitlab credential is stored"), "{body}");
    }

    /// The path rules: `..`, a wrong segment count for GitHub, a bad
    /// provider, a wrong or missing service, and shapes that are not
    /// requests at all.
    #[tokio::test]
    async fn paths_and_services_are_checked() {
        let (base, _db, _log) = working_proxy().await;
        let client = reqwest::Client::new();

        // `.` and `..` and an empty segment: an HTTP client would iron
        // them out of the URL before sending, so these go over a raw
        // socket, exactly as written.
        for (name, path) in [
            (
                "dots",
                "/git/github/owner/../repo.git/info/refs?service=git-upload-pack",
            ),
            (
                "dot",
                "/git/github/owner/./repo.git/info/refs?service=git-upload-pack",
            ),
            (
                "empty segment",
                "/git/github//repo.git/info/refs?service=git-upload-pack",
            ),
        ] {
            let (status, response) = raw_request(&base, path).await;
            assert_eq!(status, 400, "{name}: {path}\n{response}");
            assert!(response.contains("400"), "{name}: {response}");
        }

        let cases: [(&str, &str, StatusCode); 9] = [
            // Wrong segment counts.
            (
                "github with one segment",
                "/git/github/owner/info/refs?service=git-upload-pack",
                StatusCode::BAD_REQUEST,
            ),
            (
                "github with three segments",
                "/git/github/owner/repo/extra/info/refs?service=git-upload-pack",
                StatusCode::BAD_REQUEST,
            ),
            (
                "gitlab with one segment",
                "/git/gitlab/group/info/refs?service=git-upload-pack",
                StatusCode::BAD_REQUEST,
            ),
            (
                "gitlab with eleven segments",
                &format!(
                    "/git/gitlab/{}/project.git/info/refs?service=git-upload-pack",
                    ["g"; 10].join("/")
                ),
                StatusCode::BAD_REQUEST,
            ),
            (
                "too long",
                &format!(
                    "/git/github/owner/{}.git/info/refs?service=git-upload-pack",
                    "x".repeat(300)
                ),
                StatusCode::BAD_REQUEST,
            ),
            // A character outside the allowed set.
            (
                "percent escape",
                "/git/github/owner/repo%2egit/info/refs?service=git-upload-pack",
                StatusCode::BAD_REQUEST,
            ),
            // A wrong or missing service.
            (
                "wrong service",
                "/git/github/owner/repo.git/info/refs?service=git-http-upload-pack",
                StatusCode::BAD_REQUEST,
            ),
            (
                "no service",
                "/git/github/owner/repo.git/info/refs",
                StatusCode::BAD_REQUEST,
            ),
            // A bad provider is not a request that exists.
            (
                "bad provider",
                "/git/bitbucket/owner/repo.git/info/refs?service=git-upload-pack",
                StatusCode::NOT_FOUND,
            ),
        ];
        for (name, path, expected) in cases {
            let response = call(&client, &base, Method::GET, path)
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), expected, "{name}: {path}");
            if expected == StatusCode::BAD_REQUEST {
                let body = response.text().await.unwrap();
                assert!(!body.is_empty() && body.ends_with('\n'), "{name}: {body}");
            }
        }

        // Shapes that are not one of the three requests are 404s.
        for (method, path) in [
            (Method::GET, "/git/github/owner/repo.git/objects/abcd"),
            (
                Method::POST,
                "/git/github/owner/repo.git/info/refs?service=git-upload-pack",
            ),
            (Method::GET, "/git/github/owner/repo.git/git-upload-pack"),
            (Method::GET, "/git/"),
        ] {
            let response = call(&client, &base, method, path).send().await.unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
        }

        // GitLab takes a deep path: two to ten segments.
        let response = call(
            &client,
            &base,
            Method::GET,
            "/git/gitlab/group/sub/team/project/info/refs?service=git-upload-pack",
        )
        .send()
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    /// The request travels upstream with the stored credential, the six
    /// forwarded headers and the agent's token nowhere in it; the body of
    /// a POST arrives byte-identical and the answer comes back the same
    /// way, with only the allow-listed headers.
    #[tokio::test]
    async fn both_directions_stream_byte_identical() {
        let answer = noise(2 * 1024 * 1024);
        let log: Log = Arc::new(Mutex::new(Vec::new()));
        let mock = Mock {
            log: log.clone(),
            status: StatusCode::OK,
            headers: vec![
                ("content-type", "application/x-git-upload-pack-result"),
                ("cache-control", "no-cache"),
                ("set-cookie", "upstream-session=1"),
            ],
            body: answer.clone(),
        };
        let upstream = serve(mock_upstream(&mock)).await;
        let (base, _db) = serve_proxy(&upstream, Some(key())).await;
        let client = reqwest::Client::new();

        // A repo path without `.git` gains it exactly once.
        let response = call(
            &client,
            &base,
            Method::GET,
            "/git/github/owner/repo/info/refs?service=git-upload-pack",
        )
        .header("git-protocol", "version=2")
        .header(header::USER_AGENT, "git/2.47.0")
        .header(header::COOKIE, "lore-leak=1")
        .send()
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let seen = last(&log);
        assert_eq!(seen.method, "GET");
        assert_eq!(seen.path, "/owner/repo.git/info/refs");
        assert_eq!(seen.query, "service=git-upload-pack");
        let header = |name: &str| {
            seen.headers
                .iter()
                .find(|(seen_name, _)| seen_name == name)
                .map(|(_, value)| value.clone())
        };
        assert_eq!(
            header("authorization").as_deref(),
            Some(
                format!(
                    "Basic {}",
                    base64::engine::general_purpose::STANDARD
                        .encode(format!("x-access-token:{GITHUB_CREDENTIAL}"))
                )
                .as_str()
            )
        );
        assert_eq!(header("git-protocol").as_deref(), Some("version=2"));
        assert_eq!(header("user-agent").as_deref(), Some("git/2.47.0"));
        assert_eq!(header("cookie"), None);

        // And with `.git` already written it is not added twice.
        call(
            &client,
            &base,
            Method::GET,
            "/git/github/owner/repo.git/info/refs?service=git-upload-pack",
        )
        .send()
        .await
        .unwrap();
        assert_eq!(last(&log).path, "/owner/repo.git/info/refs");

        // GitLab rides its own credential, off its stored server URL.
        let response = call(
            &client,
            &base,
            Method::GET,
            "/git/gitlab/group/sub/project.git/info/refs?service=git-receive-pack",
        )
        .send()
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let seen = last(&log);
        assert_eq!(seen.path, "/group/sub/project.git/info/refs");
        assert_eq!(
            seen.headers
                .iter()
                .find(|(seen_name, _)| seen_name == "authorization")
                .map(|(_, value)| value.clone()),
            Some(format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD
                    .encode(format!("oauth2:{GITLAB_CREDENTIAL}"))
            ))
        );

        // A few MiB of pack stream through unchanged, both ways.
        let pack = noise(4 * 1024 * 1024);
        let response = call(
            &client,
            &base,
            Method::POST,
            "/git/github/owner/repo/git-upload-pack",
        )
        .header(
            header::CONTENT_TYPE,
            "application/x-git-upload-pack-request",
        )
        .header("git-protocol", "version=2")
        .body(pack.clone())
        .send()
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("application/x-git-upload-pack-result")
        );
        assert_eq!(
            response
                .headers()
                .get(header::CACHE_CONTROL)
                .and_then(|value| value.to_str().ok()),
            Some("no-cache")
        );
        assert!(response.headers().get(header::SET_COOKIE).is_none());
        let bytes = response.bytes().await.unwrap();
        assert_eq!(bytes.as_ref(), answer.as_slice());
        let seen = last(&log);
        assert_eq!(seen.method, "POST");
        assert_eq!(seen.path, "/owner/repo.git/git-upload-pack");
        assert_eq!(
            seen.headers
                .iter()
                .find(|(seen_name, _)| seen_name == "content-type")
                .map(|(_, value)| value.clone()),
            Some("application/x-git-upload-pack-request".to_string())
        );
        assert_eq!(seen.body, pack);

        // The lore token is nowhere in anything the upstream saw.
        for seen in log.lock().unwrap().iter() {
            for (_, value) in &seen.headers {
                assert!(!value.contains(TOKEN), "the lore token travelled: {value}");
            }
            assert!(
                !String::from_utf8_lossy(&seen.body).contains(TOKEN),
                "the lore token travelled in a body"
            );
        }
    }

    /// An upstream that refuses the credential, one that redirects, and
    /// one that cannot be reached: all become 502, and the redirect is
    /// not followed.
    #[tokio::test]
    async fn refused_credentials_and_redirects_become_502() {
        let refused: Log = Arc::new(Mutex::new(Vec::new()));
        let mock = Mock {
            log: refused.clone(),
            status: StatusCode::UNAUTHORIZED,
            headers: vec![("set-cookie", "upstream-session=1")],
            body: b"bad credentials\n".to_vec(),
        };
        let upstream = serve(mock_upstream(&mock)).await;
        let (base, db) = serve_proxy(&upstream, Some(key())).await;
        let client = reqwest::Client::new();

        let response = call(
            &client,
            &base,
            Method::GET,
            "/git/github/owner/repo.git/info/refs?service=git-upload-pack",
        )
        .send()
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert!(response.headers().get(header::SET_COOKIE).is_none());
        let body = response.text().await.unwrap();
        assert_eq!(body, "the stored github credential was refused upstream\n");
        assert_eq!(refused.lock().unwrap().len(), 1);
        // The log says it failed, with the upstream status and the reason.
        let row = &db.ops_log(1).unwrap()[0];
        assert_eq!((row.status, row.outcome.as_str()), (401, "error"));
        assert!(row.detail.contains("refused upstream"), "{}", row.detail);

        // A redirect upstream: not followed, and not passed through either.
        let moved: Log = Arc::new(Mutex::new(Vec::new()));
        let mock = Mock {
            log: moved.clone(),
            status: StatusCode::FOUND,
            headers: vec![
                ("location", "https://elsewhere.example.com/repo"),
                ("set-cookie", "upstream-session=1"),
            ],
            body: b"moved\n".to_vec(),
        };
        let upstream = serve(mock_upstream(&mock)).await;
        let (base, moved_db) = serve_proxy(&upstream, Some(key())).await;
        let response = call(
            &client,
            &base,
            Method::GET,
            "/git/github/owner/repo.git/info/refs?service=git-upload-pack",
        )
        .send()
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert!(response.headers().get(header::LOCATION).is_none());
        assert!(response.headers().get(header::SET_COOKIE).is_none());
        let body = response.text().await.unwrap();
        assert_eq!(body, "upstream answered with a redirect\n");
        // Nothing was followed: the redirecting upstream saw one request.
        assert_eq!(moved.lock().unwrap().len(), 1);

        let row = &moved_db.ops_log(1).unwrap()[0];
        assert_eq!((row.status, row.outcome.as_str()), (302, "error"));

        // An unreachable upstream is a 502 with a short reason.
        let (base, _db) = serve_proxy("http://127.0.0.1:1", Some(key())).await;
        let response = call(
            &client,
            &base,
            Method::GET,
            "/git/github/owner/repo.git/info/refs?service=git-upload-pack",
        )
        .send()
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        let body = response.text().await.unwrap();
        assert!(body.contains("could not be reached"), "{body}");
        assert!(!body.contains("127.0.0.1"), "{body}");
    }

    /// One ops log row per request, and the activity note only for the
    /// pack POSTs; neither ever carries the lore token or the credential.
    #[tokio::test]
    async fn requests_are_logged_without_secrets() {
        let (base, db, _log) = working_proxy().await;
        let client = reqwest::Client::new();

        // An allowed fetch pair: two rows, one activity note.
        let response = call(
            &client,
            &base,
            Method::GET,
            "/git/github/owner/repo.git/info/refs?service=git-upload-pack",
        )
        .send()
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let response = call(
            &client,
            &base,
            Method::POST,
            "/git/github/owner/repo.git/git-upload-pack",
        )
        .body("00aawant 0000")
        .send()
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let rows = db.ops_log(10).unwrap();
        assert_eq!(rows.len(), 2, "{rows:?}");
        assert_eq!(rows[1].agent, "claude");
        assert_eq!(rows[1].provider, "github");
        assert_eq!(rows[1].method, "GET");
        assert_eq!(rows[1].path, "git:owner/repo.git:info-refs");
        assert_eq!(rows[1].status, 200);
        assert_eq!(rows[1].outcome, "ok");
        assert_eq!(rows[0].method, "POST");
        assert_eq!(rows[0].path, "git:owner/repo.git:upload-pack");
        assert_eq!(rows[0].status, 200);
        assert_eq!(rows[0].outcome, "ok");
        let activity = db.activity(10).unwrap();
        assert_eq!(activity.len(), 1, "{activity:?}");
        assert_eq!(activity[0].tool, "git_fetch");
        assert_eq!(activity[0].summary, "github owner/repo.git");
        assert_eq!(activity[0].agent, "claude");

        // A denied request is logged too, with its sentence.
        db.set_ops_level("claude", "github", "read").unwrap();
        let response = call(
            &client,
            &base,
            Method::POST,
            "/git/github/owner/repo.git/git-receive-pack",
        )
        .body("0000")
        .send()
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let rows = db.ops_log(10).unwrap();
        assert_eq!(rows.len(), 3, "{rows:?}");
        assert_eq!(rows[0].outcome, "denied");
        assert_eq!(rows[0].status, 0);
        assert_eq!(rows[0].path, "git:owner/repo.git:receive-pack");
        assert_eq!(rows[0].detail, "you have read-only access to github");
        let activity = db.activity(10).unwrap();
        assert_eq!(activity.len(), 2, "{activity:?}");
        assert_eq!(activity[0].tool, "git_push");
        assert_eq!(activity[0].summary, "github owner/repo.git");

        // Neither the log nor the feed carries a secret, ever.
        let all = format!("{rows:?}{activity:?}");
        assert!(!all.contains(TOKEN), "the lore token was logged");
        assert!(
            !all.contains(GITHUB_CREDENTIAL),
            "the credential was logged"
        );
    }

    /// `/git/github-org/…` rides the organization account's credential
    /// and level, `/git/github/…` the personal one, and neither ever
    /// carries the other's credential.
    #[tokio::test]
    async fn the_organization_route_uses_its_own_credential_and_level() {
        const ORG_CREDENTIAL: &str = "ghp_test-organization-credential";
        let (base, db, log) = working_proxy().await;
        let client = reqwest::Client::new();
        let org_path = "/git/github-org/acme/repo.git/info/refs?service=git-upload-pack";
        let personal_path = "/git/github/owner/repo.git/info/refs?service=git-upload-pack";
        let expected = |credential: &str| {
            format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD
                    .encode(format!("x-access-token:{credential}"))
            )
        };
        let authorization = |seen: &Seen| {
            seen.headers
                .iter()
                .find(|(name, _)| name == "authorization")
                .map(|(_, value)| value.clone())
                .unwrap()
        };

        // Not configured yet: refused, and nothing goes upstream.
        let response = call(&client, &base, Method::GET, org_path)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            response.text().await.unwrap(),
            "no github_org credential is stored\n"
        );
        assert!(log.lock().unwrap().is_empty());

        let key = key();
        let (nonce, secret) = key.encrypt("github_org", "", ORG_CREDENTIAL);
        db.set_vault("github_org", "", &nonce, &secret, "tial")
            .unwrap();
        let response = call(&client, &base, Method::GET, org_path)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let seen = last(&log);
        assert_eq!(seen.path, "/acme/repo.git/info/refs");
        assert_eq!(authorization(&seen), expected(ORG_CREDENTIAL));
        let response = call(&client, &base, Method::GET, personal_path)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(authorization(&last(&log)), expected(GITHUB_CREDENTIAL));

        // The organization path keeps GitHub's shape rules.
        let response = call(
            &client,
            &base,
            Method::GET,
            "/git/github-org/acme/repo/extra/info/refs?service=git-upload-pack",
        )
        .send()
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        // `github_org` is the provider id, not a route segment.
        let response = call(
            &client,
            &base,
            Method::GET,
            "/git/github_org/acme/repo.git/info/refs?service=git-upload-pack",
        )
        .send()
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        // The levels are independent.
        db.set_ops_level("claude", "github_org", "off").unwrap();
        let response = call(&client, &base, Method::GET, org_path)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            response.text().await.unwrap(),
            "you have no access to github_org\n"
        );
        let response = call(&client, &base, Method::GET, personal_path)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        db.set_ops_level("claude", "github_org", "full").unwrap();
        db.set_ops_level("claude", "github", "off").unwrap();
        let response = call(&client, &base, Method::GET, personal_path)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let response = call(&client, &base, Method::GET, org_path)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // Its own rows in the ops log, and neither credential in them.
        let rows = db.ops_log(20).unwrap();
        assert_eq!(rows[0].provider, "github_org");
        assert_eq!(rows[0].path, "git:acme/repo.git:info-refs");
        assert_eq!(rows[1].provider, "github");
        assert_eq!(rows[1].outcome, "denied");
        let all = format!("{rows:?}{:?}", db.activity(20).unwrap());
        assert!(!all.contains(ORG_CREDENTIAL) && !all.contains(GITHUB_CREDENTIAL));
        // Every upstream request carried exactly one of the two.
        for seen in log.lock().unwrap().iter() {
            let value = authorization(seen);
            assert!(
                value == expected(ORG_CREDENTIAL) || value == expected(GITHUB_CREDENTIAL),
                "{value}"
            );
        }
    }

    /// The token helper reads both schemes git may send.
    #[test]
    fn the_presented_token_comes_from_basic_or_bearer() {
        let mut headers = HeaderMap::new();
        assert_eq!(presented_token(&headers), "");

        headers.insert(
            header::AUTHORIZATION,
            format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode(format!("lore:{TOKEN}"))
            )
            .parse()
            .unwrap(),
        );
        assert_eq!(presented_token(&headers), TOKEN);

        headers.insert(
            header::AUTHORIZATION,
            format!("Bearer {TOKEN}").parse().unwrap(),
        );
        assert_eq!(presented_token(&headers), TOKEN);

        // A Basic value without a colon counts as the whole password.
        headers.insert(
            header::AUTHORIZATION,
            format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode(TOKEN)
            )
            .parse()
            .unwrap(),
        );
        assert_eq!(presented_token(&headers), TOKEN);

        headers.insert(header::AUTHORIZATION, "Digest abc".parse().unwrap());
        assert_eq!(presented_token(&headers), "");
    }

    /// The upstream URL never leaves the configured server.
    #[test]
    fn the_upstream_is_pinned_to_the_base() {
        assert!(same_origin_below(
            "https://github.com",
            "https://github.com/owner/repo.git/info/refs"
        ));
        assert!(same_origin_below(
            "https://git.example.com/team",
            "https://git.example.com/team/g/p.git/git-upload-pack"
        ));
        for url in [
            "https://evil.example/owner/repo.git/info/refs",
            "http://github.com/owner/repo.git/info/refs",
            "https://github.com:8443/owner/repo.git/info/refs",
        ] {
            assert!(!same_origin_below("https://github.com", url), "{url}");
        }
        assert!(!same_origin_below(
            "https://git.example.com/team",
            "https://git.example.com/other/p.git/info/refs"
        ));
    }

    /// The repository path rules, unit level.
    #[test]
    fn repo_paths_follow_the_rules() {
        assert!(validate_repo(&ops::GITHUB, "owner/repo").is_ok());
        assert!(validate_repo(&ops::GITHUB, "owner/repo.git").is_ok());
        assert!(validate_repo(&ops::GITLAB, "group/sub/project").is_ok());
        assert!(validate_repo(&ops::GITLAB, &["a"; 10].join("/")).is_ok());
        for (provider, repo) in [
            (&ops::GITHUB, ""),
            (&ops::GITHUB, "owner"),
            (&ops::GITHUB, "a/b/c"),
            (&ops::GITHUB, "own er/repo"),
            (&ops::GITHUB, "owner/../repo"),
            (&ops::GITHUB, "owner/./repo"),
            (&ops::GITHUB, "owner/repo%20"),
            (&ops::GITLAB, "one"),
            (&ops::GITLAB, &["a"; 11].join("/")),
            (&ops::GITLAB, &format!("a/{}", "x".repeat(300))),
        ] {
            assert!(
                validate_repo(provider, repo).is_err(),
                "{repo:?} was accepted"
            );
        }
        // `.git` is added once, on the last segment, never twice.
        assert_eq!(with_git("owner/repo"), "owner/repo.git");
        assert_eq!(with_git("owner/repo.git"), "owner/repo.git");
        assert_eq!(with_git("owner/repo"), "owner/repo.git");
    }

    // ---------- The leak scan of pushes ----------

    /// A mock GitHub that speaks just enough of receive-pack: an empty
    /// repository's ref advertisement, and `ok` for every push. It records
    /// what it is sent. A local mock, never GitHub.
    fn receive_pack_upstream(log: &Log) -> Router {
        Router::new().route(
            "/{*rest}",
            any(|State(log): State<Log>, request: Request| async move {
                let (parts, raw) = request.into_parts();
                let body = axum::body::to_bytes(raw, 64 * 1024 * 1024)
                    .await
                    .unwrap_or_default();
                log.lock().unwrap().push(Seen {
                    method: parts.method.to_string(),
                    path: parts.uri.path().to_string(),
                    query: parts.uri.query().unwrap_or_default().to_string(),
                    body: body.to_vec(),
                    ..Default::default()
                });
                let pkt = |text: &[u8]| {
                    let mut out = format!("{:04x}", text.len() + 4).into_bytes();
                    out.extend_from_slice(text);
                    out
                };
                if parts.uri.path().ends_with("/info/refs") {
                    let mut out = pkt(b"# service=git-receive-pack\n");
                    out.extend_from_slice(b"0000");
                    out.extend(pkt(
                        b"0000000000000000000000000000000000000000 capabilities^{}\0report-status \
                          report-status-v2 delete-refs side-band-64k quiet ofs-delta \
                          agent=git/mock\n",
                    ));
                    out.extend_from_slice(b"0000");
                    (
                        [(
                            header::CONTENT_TYPE,
                            "application/x-git-receive-pack-advertisement",
                        )],
                        out,
                    )
                        .into_response()
                } else {
                    let mut status = pkt(b"unpack ok\n");
                    status.extend(pkt(b"ok refs/heads/main\n"));
                    status.extend_from_slice(b"0000");
                    let mut band = vec![1u8];
                    band.extend_from_slice(&status);
                    let mut out = pkt(&band);
                    out.extend_from_slice(b"0000");
                    (
                        [(
                            header::CONTENT_TYPE,
                            "application/x-git-receive-pack-result",
                        )],
                        out,
                    )
                        .into_response()
                }
            })
            .with_state(log.clone()),
        )
    }

    /// Runs git with no user or system configuration, no prompts and a
    /// fixed identity.
    fn git(dir: &std::path::Path, args: &[&str]) -> std::process::Output {
        std::process::Command::new("git")
            .args([
                "-c",
                "user.name=lore test",
                "-c",
                "user.email=test@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "-c",
                "init.defaultBranch=main",
                "-c",
                "credential.helper=",
            ])
            .args(args)
            .current_dir(dir)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("HOME", dir)
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("LC_ALL", "C")
            .output()
            .expect("git runs")
    }

    fn git_available() -> bool {
        std::process::Command::new("git")
            .arg("--version")
            .output()
            .is_ok_and(|out| out.status.success())
    }

    /// A fresh repository with these files in one commit.
    fn work_repo(name: &str, files: &[(&str, String)]) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "lore-push-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert!(git(&dir, &["init", "-q"]).status.success());
        for (path, content) in files {
            let path = dir.join(path);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, content).unwrap();
        }
        assert!(git(&dir, &["add", "-A"]).status.success());
        assert!(git(&dir, &["commit", "-q", "-m", "work"]).status.success());
        dir
    }

    /// `git push <url> HEAD:refs/heads/main`, on the blocking pool so the
    /// servers keep running.
    async fn push(dir: &std::path::Path, url: String) -> std::process::Output {
        let dir = dir.to_path_buf();
        tokio::task::spawn_blocking(move || git(&dir, &["push", &url, "HEAD:refs/heads/main"]))
            .await
            .unwrap()
    }

    /// A GitHub-shaped token built at run time, so this file holds none.
    fn fake_token() -> String {
        ["gh", "p_", "Zq8Lm2Xv9Rt4Wp6Ky3Nb7Hc5Jd1Fg0Ts8QeA"].concat()
    }

    fn posts(log: &Log) -> Vec<Seen> {
        log.lock()
            .unwrap()
            .iter()
            .filter(|seen| seen.method == "POST")
            .cloned()
            .collect()
    }

    /// The request body git sends for a push of `files`, captured by
    /// pushing straight to the mock.
    async fn captured_push(name: &str, files: &[(&str, String)]) -> Vec<u8> {
        let log: Log = Arc::new(Mutex::new(Vec::new()));
        let upstream = serve(receive_pack_upstream(&log)).await;
        let dir = work_repo(name, files);
        let out = push(&dir, format!("{upstream}/owner/capture.git")).await;
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        posts(&log).pop().expect("git sent a pack").body
    }

    /// A real `git push` through the proxy: refused with the reason under
    /// `remote:` and the ref rejected when the public repository would get
    /// a secret; forwarded when the push is clean or the repository is
    /// private.
    #[tokio::test]
    async fn a_real_git_push_is_checked_when_the_repository_is_public() {
        if !git_available() {
            eprintln!("git is not installed; skipped");
            return;
        }
        let log: Log = Arc::new(Mutex::new(Vec::new()));
        let upstream = serve(receive_pack_upstream(&log)).await;
        let (base, db, asked) = serve_proxy_with(&upstream, Some(key()), usize::MAX).await;
        let url = |repo: &str| {
            format!(
                "http://lore:{TOKEN}@{}/git/github/owner/{repo}.git",
                base.trim_start_matches("http://")
            )
        };
        let leak = work_repo(
            "leak",
            &[
                ("README.md", "# Shop\n".to_string()),
                ("config/app.py", format!("GITHUB = '{}'\n", fake_token())),
            ],
        );

        let out = push(&leak, url("public-site")).await;
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        eprintln!("--- what git printed ---\n{stderr}--- end ---");
        assert!(!out.status.success());
        assert!(
            stderr.contains(
                "remote: lore refused this push: it would put a secret or a private file into a \
                 public GitHub repository:"
            ),
            "{stderr}"
        );
        assert!(
            stderr.contains("remote:   - github-token in `config/app.py`, line 1"),
            "{stderr}"
        );
        assert!(stderr.contains("[remote rejected]"), "{stderr}");
        assert!(!stderr.contains(&fake_token()));
        assert!(posts(&log).is_empty(), "the push reached the upstream");
        assert!(
            asked
                .lock()
                .unwrap()
                .contains(&"owner/public-site".to_string())
        );
        let row = &db.ops_log(1).unwrap()[0];
        assert_eq!(
            (row.outcome.as_str(), row.path.as_str()),
            ("denied", "git:owner/public-site.git:receive-pack")
        );
        assert_eq!(
            row.detail,
            "leak scan: github-token in `config/app.py`, line 1"
        );
        let all = format!(
            "{:?}{:?}",
            db.ops_log(100).unwrap(),
            db.activity(100).unwrap()
        );
        assert!(!all.contains(&fake_token()));

        // The same push to a private repository streams through.
        let out = push(&leak, url("repo")).await;
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(posts(&log).len(), 1);

        // A clean push to the public repository goes through, checked.
        let clean = work_repo("clean", &[("README.md", "# Shop\n".to_string())]);
        let out = push(&clean, url("public-site")).await;
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(posts(&log).len(), 2);
        assert_eq!(db.ops_log(1).unwrap()[0].outcome, "ok");
    }

    /// The bytes git sends reach the upstream unchanged: checked for a
    /// public repository, streamed for a private one. A stored credential
    /// is recognised as such.
    #[tokio::test]
    async fn checked_pushes_are_forwarded_byte_identical() {
        if !git_available() {
            eprintln!("git is not installed; skipped");
            return;
        }
        let leak = captured_push(
            "bytes-leak",
            &[("deploy/notes.txt", format!("use {GITLAB_CREDENTIAL}\n"))],
        )
        .await;
        let clean = captured_push("bytes-clean", &[("a.txt", "hello\n".to_string())]).await;

        let log: Log = Arc::new(Mutex::new(Vec::new()));
        let upstream = serve(receive_pack_upstream(&log)).await;
        let (base, _db, _) = serve_proxy_with(&upstream, Some(key()), usize::MAX).await;
        let client = reqwest::Client::new();
        let send = |repo: &str, body: Vec<u8>| {
            call(
                &client,
                &base,
                Method::POST,
                &format!("/git/github/owner/{repo}.git/git-receive-pack"),
            )
            .header(
                header::CONTENT_TYPE,
                "application/x-git-receive-pack-request",
            )
            .body(body)
            .send()
        };

        // A stored credential in a public repository: refused in the
        // protocol, nothing sent.
        let response = send("public-docs", leak.clone()).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/x-git-receive-pack-result"
        );
        let answer = String::from_utf8_lossy(&response.bytes().await.unwrap()).into_owned();
        assert!(
            answer.contains("known-secret in `deploy/notes.txt`, line 1"),
            "{answer}"
        );
        assert!(answer.contains("ng refs/heads/main lore: "), "{answer}");
        assert!(!answer.contains(GITLAB_CREDENTIAL));
        assert!(posts(&log).is_empty());

        // The same bytes to a private repository arrive unchanged.
        let response = send("repo", leak.clone()).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(posts(&log).last().unwrap().body, leak);

        // A clean push to a public repository arrives unchanged too.
        let response = send("public-docs", clean.clone()).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(posts(&log).last().unwrap().body, clean);
        assert_eq!(posts(&log).len(), 2);
    }

    /// A push that cannot be read, one over the size cap, and a repository
    /// whose visibility cannot be learned are refused; with the scan
    /// switched off, everything streams as before.
    #[tokio::test]
    async fn unreadable_oversized_and_unknown_pushes_fail_closed() {
        let log: Log = Arc::new(Mutex::new(Vec::new()));
        let upstream = serve(receive_pack_upstream(&log)).await;
        let (base, db, _) = serve_proxy_with(&upstream, Some(key()), 4096).await;
        let client = reqwest::Client::new();
        let send = |repo: &str, body: Vec<u8>| {
            call(
                &client,
                &base,
                Method::POST,
                &format!("/git/github/owner/{repo}.git/git-receive-pack"),
            )
            .body(body)
            .send()
        };
        let command = |pack: &[u8]| {
            let line = format!(
                "{} {} refs/heads/main\0report-status side-band-64k\n",
                "0".repeat(40),
                "1".repeat(40)
            );
            let mut body = format!("{:04x}", line.len() + 4).into_bytes();
            body.extend_from_slice(line.as_bytes());
            body.extend_from_slice(b"0000");
            body.extend_from_slice(pack);
            body
        };

        // A damaged pack: refused in the protocol.
        let response = send("public-x", command(b"PACK\0\0\0\x02junk"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let answer = String::from_utf8_lossy(&response.bytes().await.unwrap()).into_owned();
        assert!(answer.contains("could not be read to check it"), "{answer}");
        assert!(answer.contains("ng refs/heads/main"), "{answer}");
        // No command list at all: a plain 403.
        let response = send("public-x", b"garbage".to_vec()).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(
            response
                .text()
                .await
                .unwrap()
                .contains("could not be read to check it")
        );
        // Over the cap (4096 bytes here, 256 MiB in production).
        let big = command(&noise(10_000));
        let response = send("public-x", big.clone()).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let answer = String::from_utf8_lossy(&response.bytes().await.unwrap()).into_owned();
        assert!(
            answer.contains("larger than 4096 bytes, too large to check")
                && answer.contains("Push it in smaller parts, or ask the user."),
            "{answer}"
        );
        // A repository the API will not describe counts as public.
        let response = send("broken-x", big.clone()).await.unwrap();
        let answer = String::from_utf8_lossy(&response.bytes().await.unwrap()).into_owned();
        assert!(answer.contains("too large to check"), "{answer}");
        assert!(posts(&log).is_empty());
        let row = &db.ops_log(1).unwrap()[0];
        assert_eq!(row.outcome, "denied");
        assert_eq!(row.detail, "leak scan: the push is larger than 4096 bytes");
        // No spool file is left behind.
        let left: Vec<_> = std::fs::read_dir(db.data_dir())
            .unwrap()
            .flatten()
            .filter(|item| item.file_name().to_string_lossy().contains("push"))
            .collect();
        assert!(left.is_empty(), "{left:?}");

        // Switched off: nothing is checked, everything streams.
        db.set_leak_scan_settings(Some(false), None).unwrap();
        let response = send("public-x", big.clone()).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(posts(&log).last().unwrap().body, big);
    }

    #[test]
    fn the_receive_pack_advertisement_asks_for_a_full_pack() {
        let first = format!(
            "{} refs/heads/main\0report-status side-band-64k\n",
            "a".repeat(40)
        );
        let second = format!("{} refs/heads/dev\n", "b".repeat(40));
        let pkt = |text: &str| format!("{:04x}{text}", text.len() + 4);
        let body = format!(
            "{}0000{}{}0000",
            pkt("# service=git-receive-pack\n"),
            pkt(&first),
            pkt(&second)
        );
        let rewritten = String::from_utf8(with_no_thin(body.as_bytes()).unwrap()).unwrap();
        let expected = format!(
            "{}0000{}{}0000",
            pkt("# service=git-receive-pack\n"),
            pkt(&format!(
                "{} refs/heads/main\0report-status side-band-64k no-thin\n",
                "a".repeat(40)
            )),
            pkt(&second)
        );
        assert_eq!(rewritten, expected);
        // Already there: unchanged; not an advertisement: left alone.
        assert_eq!(
            with_no_thin(rewritten.as_bytes()).unwrap(),
            rewritten.as_bytes()
        );
        assert!(with_no_thin(b"garbage").is_none());
    }

    /// C5 and C3 on a built-in agent's push: no deletion, no tag, the
    /// default branch only fast-forward (proved from the pack, then by
    /// asking GitHub), new branches, and no CI change against the old head
    /// (or the default branch's head for a new branch).
    #[tokio::test]
    async fn a_run_push_moves_branches_forward_and_leaves_ci_alone() {
        let id = |c: char| c.to_string().repeat(40);
        let (a, b, c, d, e, f, x) = (
            id('a'),
            id('b'),
            id('c'),
            id('d'),
            id('e'),
            id('f'),
            id('9'),
        );
        let zero = "0".repeat(40);
        // What GitHub has: A on main, its tree, its `.github` tree.
        let api = Router::new()
            .route(
                "/repos/me/shop/commits/main",
                axum::routing::get({
                    let a = a.clone();
                    move || async move { format!(r#"{{"sha":"{a}"}}"#) }
                }),
            )
            .route(
                "/repos/me/shop/git/commits/{sha}",
                axum::routing::get({
                    let a = a.clone();
                    move |axum::extract::Path(sha): axum::extract::Path<String>| {
                        let a = a.clone();
                        async move {
                            if sha == a {
                                (StatusCode::OK, r#"{"tree":{"sha":"1111111111111111111111111111111111111111"}}"#.to_string())
                            } else {
                                (StatusCode::NOT_FOUND, "{}".to_string())
                            }
                        }
                    }
                }),
            )
            .route(
                "/repos/me/shop/git/trees/{sha}",
                axum::routing::get(|axum::extract::Path(sha): axum::extract::Path<String>| async move {
                    match sha.as_str() {
                        "1111111111111111111111111111111111111111" => (
                            StatusCode::OK,
                            r#"{"tree":[{"path":".github","sha":"2222222222222222222222222222222222222222","type":"tree"},
                                        {"path":"src","sha":"3333333333333333333333333333333333333333","type":"tree"}]}"#,
                        ),
                        "2222222222222222222222222222222222222222" => (
                            StatusCode::OK,
                            r#"{"tree":[{"path":"workflows","sha":"4444444444444444444444444444444444444444","type":"tree"}]}"#,
                        ),
                        _ => (StatusCode::NOT_FOUND, "{}"),
                    }
                }),
            )
            .route(
                "/repos/me/shop/compare/{spec}",
                axum::routing::get({
                    let ok = format!("{a}...{f}");
                    move |axum::extract::Path(spec): axum::extract::Path<String>| {
                        let ok = ok.clone();
                        async move {
                            if spec == ok {
                                r#"{"status":"ahead"}"#
                            } else {
                                r#"{"status":"diverged"}"#
                            }
                        }
                    }
                }),
            );
        let api = serve(api).await;
        let db = Db::open(&std::env::temp_dir().join(format!(
            "lore-gitproxy-runpush-{}/lore.db",
            std::process::id()
        )))
        .unwrap();
        let state = GitProxy {
            auth: Arc::new(McpAuth::new(
                load_tokens("", &format!("claude:{TOKEN}")).unwrap(),
                db,
                false,
            )),
            vault: None,
            github_web_base: String::new(),
            http: client(),
            events: Events::new(),
            guard: ops::Guard::default(),
            github_api_base: api,
            max_scanned_push: 1024,
        };
        let entry = |name: &str, id: &str| packscan::TreeEntry {
            mode: "40000".into(),
            name: name.into(),
            id: id.into(),
        };
        let same_ci = "5555555555555555555555555555555555555555".to_string();
        let new_ci = "6666666666666666666666666666666666666666".to_string();
        let new_github = "7777777777777777777777777777777777777777".to_string();
        let mut view = packscan::PushView {
            complete: true,
            ..packscan::PushView::default()
        };
        // B, E: the CI as it was. D: a changed workflow. C: from elsewhere.
        view.commits
            .insert(b.clone(), (same_ci.clone(), vec![a.clone()]));
        view.commits
            .insert(e.clone(), (same_ci.clone(), vec![f.clone()]));
        view.commits
            .insert(d.clone(), (new_ci.clone(), vec![a.clone()]));
        view.commits
            .insert(c.clone(), (same_ci.clone(), vec![x.clone()]));
        view.trees.insert(
            same_ci.clone(),
            vec![
                entry(".github", "2222222222222222222222222222222222222222"),
                entry("src", "8888888888888888888888888888888888888888"),
            ],
        );
        view.trees
            .insert(new_ci.clone(), vec![entry(".github", &new_github)]);
        view.trees.insert(
            new_github.clone(),
            vec![entry(
                "workflows",
                "9999999999999999999999999999999999999999",
            )],
        );
        let scope = crate::runscope::RunScope {
            version: crate::runscope::SCOPE_VERSION,
            provider: "github".into(),
            owner: "me".into(),
            repo: "shop".into(),
            branch: "main".into(),
            ..Default::default()
        };
        let secret = crate::vault::Secret::new("ghp_test-credential"); // lore:allow-secret
        async fn run_check(
            state: &GitProxy,
            base: &packscan::PushView,
            secret: &crate::vault::Secret,
            scope: &crate::runscope::RunScope,
            updates: Vec<(&str, &str, &str)>,
        ) -> Result<(), String> {
            let mut view = packscan::PushView {
                commits: base.commits.clone(),
                trees: base.trees.clone(),
                complete: true,
                ..packscan::PushView::default()
            };
            view.commands.updates = updates
                .into_iter()
                .map(|(o, n, r)| (o.to_string(), n.to_string(), r.to_string()))
                .collect();
            let run = RunPush {
                scope,
                secret,
                provider: ops::GITHUB,
                owner: "me".into(),
                repo: "shop".into(),
            };
            run.check(state, &view).await
        }
        let check = |scope, updates| run_check(&state, &view, &secret, scope, updates);
        // Allowed: forward on main (from the pack, and through GitHub's
        // compare where the pack ends), and a new branch.
        assert_eq!(
            check(&scope, vec![(&a, &b, "refs/heads/main")]).await,
            Ok(())
        );
        assert_eq!(
            check(&scope, vec![(&a, &e, "refs/heads/main")]).await,
            Ok(())
        );
        assert_eq!(
            check(&scope, vec![(&zero, &b, "refs/heads/feature")]).await,
            Ok(())
        );
        for (updates, word) in [
            (
                vec![(a.as_str(), zero.as_str(), "refs/heads/main")],
                "delete",
            ),
            (
                vec![(a.as_str(), zero.as_str(), "refs/heads/feature")],
                "delete",
            ),
            (
                vec![(zero.as_str(), b.as_str(), "refs/tags/v1")],
                "only branches",
            ),
            (
                vec![(a.as_str(), b.as_str(), "refs/heads/release")],
                "only the default branch",
            ),
            (
                vec![(a.as_str(), c.as_str(), "refs/heads/main")],
                "only move refs/heads/main forward",
            ),
            (
                vec![(a.as_str(), d.as_str(), "refs/heads/main")],
                "CI definitions",
            ),
            (
                vec![(zero.as_str(), d.as_str(), "refs/heads/sneaky")],
                "CI definitions",
            ),
        ] {
            let why = check(&scope, updates.clone()).await.unwrap_err();
            assert!(why.contains(word), "{updates:?}: {why}");
        }
        // The owner's switch lets CI changes through, never history rewrites.
        let allowed = crate::runscope::RunScope {
            ci_allowed: true,
            ..scope.clone()
        };
        assert_eq!(
            check(&allowed, vec![(&a, &d, "refs/heads/main")]).await,
            Ok(())
        );
        assert!(
            check(&allowed, vec![(&a, &c, "refs/heads/main")])
                .await
                .is_err()
        );
    }

    /// C5 end to end: a run token's push that deletes a branch is refused
    /// in the protocol, and nothing goes upstream.
    #[tokio::test]
    async fn a_run_token_never_deletes_a_branch() {
        let (base, db, log) = working_proxy().await;
        let token = run_token(&db, "run-git-delete");
        let line = format!(
            "{} {} refs/heads/main\0report-status\n",
            "a".repeat(40),
            "0".repeat(40)
        );
        let body = format!("{:04x}{line}0000", line.len() + 4);
        let sent = log.lock().unwrap().len();
        let response = reqwest::Client::new()
            .post(format!("{base}/git/github/me/shop.git/git-receive-pack"))
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(body)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let text = response.text().await.unwrap();
        assert!(text.contains("ng refs/heads/main"), "{text}");
        assert!(text.contains("delete"), "{text}");
        assert_eq!(log.lock().unwrap().len(), sent, "nothing went upstream");
        assert_eq!(db.ops_log(1).unwrap()[0].outcome, "denied");
    }

    /// A pkt-line.
    fn pkt(text: &[u8]) -> Vec<u8> {
        let mut out = format!("{:04x}", text.len() + 4).into_bytes();
        out.extend_from_slice(text);
        out
    }

    /// An upstream `report-status`: these lines, then a flush; in band 1
    /// (after a progress line in band 2) when `side_band`.
    fn report(lines: &[&str], side_band: bool) -> Vec<u8> {
        let mut status = Vec::new();
        for line in lines {
            status.extend(pkt(format!("{line}\n").as_bytes()));
        }
        status.extend_from_slice(b"0000");
        if !side_band {
            return status;
        }
        let mut out = pkt(b"\x02Resolving deltas: 100% (1/1)\n");
        for chunk in status.chunks(7) {
            let mut band = vec![1u8];
            band.extend_from_slice(chunk);
            out.extend(pkt(&band));
        }
        out.extend_from_slice(b"0000");
        out
    }

    /// The proxy in front of an upstream that answers every push with
    /// `answer`.
    async fn proxy_answering(answer: Vec<u8>) -> (String, Db, Log) {
        let log: Log = Arc::new(Mutex::new(Vec::new()));
        let mock = Mock {
            log: log.clone(),
            status: StatusCode::OK,
            headers: vec![("content-type", "application/x-git-receive-pack-result")],
            body: answer,
        };
        let upstream = serve(mock_upstream(&mock)).await;
        let (base, db) = serve_proxy(&upstream, Some(key())).await;
        (base, db, log)
    }

    /// A push of these command lines (no pack) with `token`; the status
    /// and the bytes of the answer.
    async fn push_lines(base: &str, token: &str, lines: &[String]) -> (StatusCode, Vec<u8>) {
        let mut body = Vec::new();
        for line in lines {
            body.extend(pkt(line.as_bytes()));
        }
        body.extend_from_slice(b"0000");
        let response = reqwest::Client::new()
            .post(format!("{base}/git/github/me/shop.git/git-receive-pack"))
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(body)
            .send()
            .await
            .unwrap();
        let status = response.status();
        (status, response.bytes().await.unwrap().to_vec())
    }

    /// Lets a run's pushes change CI, so a test needs no CI comparison
    /// upstream.
    fn allow_ci(db: &Db, run: &str) {
        db.execute_for_test(&format!(
            "UPDATE agent_runs SET scope = json_set(scope, '$.ci_allowed', json('true'))
             WHERE id = '{run}'"
        ));
    }

    /// G3 and G5: a run's push that upstream reports `ok` is recorded for
    /// the run, and a branch the run created is one it may move later
    /// (its token's scope learns it); a refused push records nothing.
    #[tokio::test]
    async fn a_run_s_accepted_pushes_are_recorded_for_it() {
        let answer = report(&["unpack ok", "ok refs/heads/feature"], false);
        let (base, db, _log) = proxy_answering(answer.clone()).await;
        let token = run_token(&db, "run-git-record");
        allow_ci(&db, "run-git-record");
        let (zero, new) = ("0".repeat(40), "c".repeat(40));
        let (status, bytes) = push_lines(
            &base,
            &token,
            &[format!("{zero} {new} refs/heads/feature\0report-status\n")],
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        // git gets upstream's answer byte for byte.
        assert_eq!(bytes, answer);
        let refs = db.run_refs("run-git-record").unwrap();
        assert_eq!(refs.len(), 1, "{refs:?}");
        // No pack came with it: the run pointed a new branch at a commit
        // that was there, which creates the branch and credits nothing.
        assert_eq!(
            (
                refs[0].name.as_str(),
                refs[0].new.as_str(),
                refs[0].via.as_str()
            ),
            ("refs/heads/feature", new.as_str(), "push-existing")
        );
        assert!(!refs[0].credits("refs/heads/feature", &new));
        assert_eq!(
            db.run_created_branches("run-git-record").unwrap(),
            vec!["feature"]
        );
        let auth = McpAuth::new(Vec::new(), db.clone(), false);
        let found = auth.authenticate_on(&token, true).await.unwrap();
        assert_eq!(found.scope().unwrap().created_branches, vec!["feature"]);
        // Another existing branch is still refused, and nothing recorded.
        let (_, bytes) = push_lines(
            &base,
            &token,
            &[format!(
                "{} {} refs/heads/release\0report-status\n",
                "a".repeat(40),
                "b".repeat(40)
            )],
        )
        .await;
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.contains("ng refs/heads/release"), "{text}");
        assert_eq!(db.run_refs("run-git-record").unwrap().len(), 1);
    }

    /// F2, the reviewer's probe: a no-op `H H refs/heads/main` (H someone
    /// else's commit) is not the run's update, and a "creation" of a
    /// branch that exists (`0 X refs/heads/release`, or `0 H main`) is
    /// refused by lore itself, so the run never gains `release` to move.
    #[tokio::test]
    async fn no_ops_and_creations_of_existing_branches_are_not_the_run_s() {
        let answer = report(
            &["unpack ok", "ok refs/heads/main", "ok refs/heads/release"],
            false,
        );
        let (base, db, log) = proxy_answering(answer).await;
        let token = run_token(&db, "run-probe");
        allow_ci(&db, "run-probe");
        let someone_elses = "e".repeat(40);
        let (status, _) = push_lines(
            &base,
            &token,
            &[format!(
                "{someone_elses} {someone_elses} refs/heads/main\0report-status\n"
            )],
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(db.run_refs("run-probe").unwrap().is_empty());
        for line in [
            format!(
                "{} {} refs/heads/release\0report-status\n",
                "0".repeat(40),
                "d".repeat(40)
            ),
            format!(
                "{} {someone_elses} refs/heads/main\0report-status\n",
                "0".repeat(40)
            ),
        ] {
            let sent = posts(&log).len();
            let (status, bytes) = push_lines(&base, &token, std::slice::from_ref(&line)).await;
            let text = String::from_utf8_lossy(&bytes);
            assert_eq!(status, StatusCode::OK);
            assert!(text.contains("already exists"), "{line}: {text}");
            assert!(text.contains("ng refs/heads/"), "{text}");
            assert_eq!(posts(&log).len(), sent, "nothing went upstream");
        }
        assert!(db.run_refs("run-probe").unwrap().is_empty());
        assert!(db.run_created_branches("run-probe").unwrap().is_empty());
        // When lore cannot tell whether the branch exists, it refuses.
        let (_, bytes) = push_lines(
            &base,
            &token,
            &[format!(
                "{} {} refs/heads/broken-lookup\0report-status\n",
                "0".repeat(40),
                "d".repeat(40)
            )],
        )
        .await;
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.contains("could not check whether"), "{text}");
        assert!(db.run_refs("run-probe").unwrap().is_empty());
    }

    /// F2: only the refs upstream reports `ok` are recorded; an `ng`, a
    /// failed unpack or a report lore cannot read records nothing, and git
    /// still gets upstream's bytes unchanged.
    #[tokio::test]
    async fn only_refs_upstream_reports_ok_are_recorded() {
        let (zero, new) = ("0".repeat(40), "c".repeat(40));
        let cases: Vec<(Vec<u8>, &str, Vec<&str>)> = vec![
            (
                report(
                    &[
                        "unpack ok",
                        "ng refs/heads/one failed to update ref",
                        "ok refs/heads/two",
                    ],
                    true,
                ),
                "report-status side-band-64k",
                vec!["refs/heads/two"],
            ),
            (
                report(
                    &[
                        "unpack ok",
                        "ok refs/heads/one",
                        "option refname refs/heads/one",
                        "ok refs/heads/two",
                    ],
                    false,
                ),
                "report-status-v2",
                vec!["refs/heads/one", "refs/heads/two"],
            ),
            (
                report(
                    &[
                        "unpack index-pack failed",
                        "ng refs/heads/one unpacker error",
                    ],
                    true,
                ),
                "report-status side-band-64k",
                vec![],
            ),
            (
                b"this is not a report at all".to_vec(),
                "report-status",
                vec![],
            ),
            // A report with no flush at its end was cut short.
            (
                pkt(b"unpack ok\n")
                    .into_iter()
                    .chain(pkt(b"ok refs/heads/one\n"))
                    .collect(),
                "report-status",
                vec![],
            ),
            // Side band asked for, but the answer is not framed in one.
            (
                report(&["unpack ok", "ok refs/heads/one"], false),
                "report-status side-band-64k",
                vec![],
            ),
        ];
        for (index, (answer, caps, wanted)) in cases.into_iter().enumerate() {
            let (base, db, _log) = proxy_answering(answer.clone()).await;
            let run = format!("run-report-{index}");
            let token = run_token(&db, &run);
            allow_ci(&db, &run);
            let (status, bytes) = push_lines(
                &base,
                &token,
                &[
                    format!("{zero} {new} refs/heads/one\0{caps}\n"),
                    format!("{zero} {new} refs/heads/two\n"),
                ],
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(bytes, answer, "case {index}");
            let recorded: Vec<String> = db
                .run_refs(&run)
                .unwrap()
                .into_iter()
                .map(|update| update.name)
                .collect();
            assert_eq!(recorded, wanted, "case {index}");
        }
        // A token that is not a run's: its push streams through as before,
        // whatever the answer, and nothing is recorded anywhere.
        let answer = b"this is not a report at all".to_vec();
        let (base, db, _log) = proxy_answering(answer.clone()).await;
        let (status, bytes) = push_lines(
            &base,
            TOKEN,
            &[format!("{zero} {new} refs/heads/one\0report-status\n")],
        )
        .await;
        assert_eq!((status, bytes), (StatusCode::OK, answer));
        let counts: std::collections::HashMap<String, i64> =
            db.table_counts().unwrap().into_iter().collect();
        assert_eq!(
            counts.get("agent_run_refs").copied().unwrap_or(0),
            0,
            "{counts:?}"
        );
    }

    /// F2: a real `git push` by a run, with its pack: upstream reports it
    /// `ok`, it is recorded as the run's own (`push`) and credits the run
    /// with its commit.
    #[tokio::test]
    async fn a_run_s_real_push_is_recorded_as_its_own_and_credited() {
        if !git_available() {
            eprintln!("git is not installed; skipped");
            return;
        }
        let log: Log = Arc::new(Mutex::new(Vec::new()));
        let capture = serve(receive_pack_upstream(&log)).await;
        let dir = work_repo("run-real", &[("README.md", "hello\n".to_string())]);
        // The capturing mock reports `main`, so git calls this push failed;
        // only the request body it sent is wanted.
        {
            let dir = dir.clone();
            let url = format!("{capture}/owner/capture.git");
            tokio::task::spawn_blocking(move || {
                git(&dir, &["push", &url, "HEAD:refs/heads/newwork"])
            })
            .await
            .unwrap();
        }
        let body = posts(&log).pop().expect("git sent a pack").body;
        let head = String::from_utf8(git(&dir, &["rev-parse", "HEAD"]).stdout).unwrap();
        let head = head.trim().to_string();
        let answer = report(&["unpack ok", "ok refs/heads/newwork"], true);
        let (base, db, _log) = proxy_answering(answer.clone()).await;
        let token = run_token(&db, "run-real");
        allow_ci(&db, "run-real");
        let response = reqwest::Client::new()
            .post(format!("{base}/git/github/me/shop.git/git-receive-pack"))
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(body)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.bytes().await.unwrap().to_vec(), answer);
        let refs = db.run_refs("run-real").unwrap();
        assert_eq!(refs.len(), 1, "{refs:?}");
        assert_eq!(refs[0].via, "push");
        assert_eq!(refs[0].new, head);
        assert!(refs[0].credits("refs/heads/newwork", &head));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The report reader on its own: fed byte by byte, bounded, strict.
    #[test]
    fn the_report_reader_reads_band_one_and_gives_up_on_anything_else() {
        let answer = report(
            &["unpack ok", "ok refs/heads/a", "ng refs/heads/b no"],
            true,
        );
        let mut reader = ReportReader::new(true);
        for byte in &answer {
            reader.feed(std::slice::from_ref(byte));
        }
        let ok = reader.finish().unwrap();
        assert_eq!(ok.len(), 1);
        assert!(ok.contains("refs/heads/a"));
        // Band 3 is a fatal error.
        let mut reader = ReportReader::new(true);
        reader.feed(&pkt(b"\x03remote error\n"));
        assert_eq!(reader.finish(), None);
        // Past the bound it gives up and keeps nothing.
        let mut reader = ReportReader::new(false);
        let line = pkt(format!("ok refs/heads/{}\n", "x".repeat(200)).as_bytes());
        reader.feed(&pkt(b"unpack ok\n"));
        for _ in 0..(MAX_REPORT / line.len() + 2) {
            reader.feed(&line);
        }
        assert!(reader.report.len() <= MAX_REPORT);
        assert_eq!(reader.finish(), None);
        // An unknown line makes the whole report unreadable.
        let mut reader = ReportReader::new(false);
        reader.feed(&report(&["unpack ok", "ok refs/heads/a", "weird"], false));
        assert_eq!(reader.finish(), None);
    }

    /// G1 end to end, with the re-review's crafted push: a commit whose
    /// `parent OLD` line comes after `committer` (git reads a root commit,
    /// a loose reader a fast-forward) is refused, and nothing goes up.
    #[tokio::test]
    async fn a_commit_with_a_misplaced_parent_is_refused() {
        let (base, db, log) = working_proxy().await;
        let token = run_token(&db, "run-git-misplaced");
        let body = include_bytes!("testdata/misplaced-parent.body").to_vec();
        let sent = log.lock().unwrap().len();
        let response = reqwest::Client::new()
            .post(format!("{base}/git/github/me/shop.git/git-receive-pack"))
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(body)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let text = response.text().await.unwrap();
        assert!(text.contains("ng refs/heads/main"), "{text}");
        assert!(text.contains("not the shape git writes"), "{text}");
        assert_eq!(log.lock().unwrap().len(), sent, "nothing went upstream");
        assert_eq!(db.ops_log(1).unwrap()[0].outcome, "denied");
    }
}
