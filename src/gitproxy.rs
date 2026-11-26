//! The git proxy: clone, fetch and push through lore. An agent runs plain
//! `git` against `/git/<provider>/<owner>/<repo>.git` (`github`,
//! `github-org` for the organization account's credential, or `gitlab`),
//! authenticates with its own lore token (the password of a Basic header,
//! or a Bearer token), and lore forwards the smart-HTTP request upstream with the stored
//! credential. The credential never reaches the agent's machine, and the
//! agent's lore token never travels upstream.

use std::{
    net::SocketAddr,
    sync::Arc,
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

use crate::{
    auth::{McpAuth, Refused, client_ip, too_many_requests},
    db::Db,
    events::Events,
    ops::{self, transport_reason},
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
}

impl GitProxy {
    /// The state as `main` builds it: the real GitHub base, the shared
    /// `/mcp` authentication, and the vault key.
    pub fn new(auth: Arc<McpAuth>, vault: Option<VaultKey>, events: Events) -> Self {
        Self {
            auth,
            vault,
            github_web_base: GITHUB_WEB_BASE.to_string(),
            http: client(),
            events,
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
    let agent = match state.auth.authenticate(&presented).await {
        Ok(found) => found.agent().to_string(),
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
            let ip = client_ip(&parts.headers, peer, state.auth.trust_proxy);
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

    // Authorisation: `read` covers the fetch pair, `full` is needed for
    // the push pair. The SQLite work runs on the blocking pool, like
    // every database call of this server.
    let authorized = {
        let db = state.auth.db.clone();
        let vault = state.vault.clone();
        let github_base = state.github_web_base.clone();
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
                    Ok((base, granted.secret))
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
    let (base, secret) = match authorized {
        Ok(pair) => pair,
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
        // buffered whole.
        forwarded = forwarded.body(reqwest::Body::wrap_stream(body.into_data_stream()));
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
    // A failure mid-stream is passed on without the upstream URL.
    let stream = tokio_stream::StreamExt::map(response.bytes_stream(), |chunk| {
        chunk.map_err(reqwest::Error::without_url)
    });
    out.body(Body::from_stream(stream))
        .expect("a valid status and header values build a response")
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
    const GITLAB_CREDENTIAL: &str = "glpat-test-upstream-credential";

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
        let dir = std::env::temp_dir().join(format!(
            "lore-gitproxy-test-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
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
        let state = Arc::new(GitProxy {
            auth,
            vault,
            github_web_base: upstream.to_string(),
            http: client(),
            events: Events::new(),
        });
        let base = serve(router(state)).await;
        (base, db)
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
}
