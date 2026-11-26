//! lore's own OAuth 2.1 authorization server, as the MCP authorization
//! specification (2025-06-18) asks of a server: protected resource
//! metadata (RFC 9728), authorization server metadata (RFC 8414), dynamic
//! client registration for public clients (RFC 7591), the authorization
//! code flow with PKCE S256 only, rotating refresh tokens and revocation
//! (RFC 7009).
//!
//! The consent page is served here at `/oauth/authorize`; signing in and
//! approving go through the admin view's session (its cookie lives under
//! `/admin`), so those two steps are admin routes with their own place in
//! the route permission table.
//!
//! Codes and tokens are 32 random bytes, URL-safe base64, and only their
//! SHA-256 hashes are stored. None of them is ever logged.

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use axum::{
    Json, Router,
    extract::{ConnectInfo, DefaultBodyLimit, Query, Request, State, rejection::FormRejection},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::Engine;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::{
    auth::{RateLimiter, client_ip, too_many_requests},
    db::{self, CodeLookup, Db, OAuthClient, RefreshLookup},
};

/// The only scope lore knows: everything an agent may do.
pub const SCOPE: &str = "lore";
/// Access tokens live one hour.
pub const ACCESS_TTL_SECS: i64 = 60 * 60;
/// Refresh tokens live 90 days from their last use (each use rotates).
pub const REFRESH_TTL_SECS: i64 = 90 * 24 * 60 * 60;
/// Authorization codes live five minutes.
pub const CODE_TTL_SECS: i64 = 5 * 60;
/// How long a consent page may stay open before it has to start again.
const PENDING_TTL: Duration = Duration::from_secs(15 * 60);
/// Consent requests kept at most. When full, the client with the most open
/// requests loses its oldest, so a flood from one client cannot push out
/// another's.
const MAX_PENDING: usize = 500;
/// Open consent requests one client may have; its oldest goes first.
const MAX_PENDING_PER_CLIENT: usize = 20;
/// Redirect URIs a client may register.
const MAX_REDIRECT_URIS: usize = 5;
const MAX_REDIRECT_URI_CHARS: usize = 2000;
/// A client name is shown, never trusted: this long at most.
const MAX_CLIENT_NAME_CHARS: usize = 100;
const MAX_REGISTRATION_BYTES: usize = 16 * 1024;
const MAX_FORM_BYTES: usize = 16 * 1024;
/// Names an OAuth agent may never take: lore's own users and the agent of
/// the shared token.
const RESERVED_AGENT_NAMES: &[&str] = &["admin", "viewer", "shared"];
/// Schemes that are never a redirect target, whatever a client registers:
/// ones that run code or read files, well-known web, file and network
/// schemes, and the handlers operating systems register for dangerous
/// things (installing apps, searching shares, opening archives).
const REFUSED_SCHEMES: &[&str] = &[
    "javascript",
    "jscript",
    "livescript",
    "data",
    "file",
    "vbscript",
    "about",
    "blob",
    "filesystem",
    "view-source",
    "ftp",
    "ftps",
    "sftp",
    "ws",
    "wss",
    "mailto",
    "tel",
    "sms",
    "callto",
    "gopher",
    "smb",
    "nfs",
    "ssh",
    "telnet",
    "ldap",
    "ldaps",
    "news",
    "nntp",
    "irc",
    "rtsp",
    "sip",
    "jar",
    "intent",
    "itms",
    "itms-apps",
    "itms-services",
    "search",
    "search-ms",
    "hcp",
    "its",
    "mk",
    "res",
    "shell",
    "chrome",
    "chrome-extension",
    "moz-extension",
    "resource",
];
/// Scheme prefixes refused like `REFUSED_SCHEMES`: Windows' `ms-*`
/// handlers (`ms-msdt`, `ms-officecmd`, …) and their `vnd.ms-` kin.
const REFUSED_SCHEME_PREFIXES: &[&str] = &["ms-", "vnd.ms-"];

const CONSENT_PAGE: &str = include_str!("../assets/consent.html");

/// The OAuth state: the store, how the public origin is derived, the
/// names no OAuth agent may take, and the consent requests in flight.
pub struct OAuth {
    pub db: Db,
    pub trust_proxy: bool,
    /// `LORE_ALLOWED_HOSTS`: the public origin must name one of them when
    /// set.
    pub allowed_hosts: Vec<String>,
    /// The env-token agents: no OAuth agent may take their names.
    pub env_agents: Vec<String>,
    pending: Mutex<HashMap<String, Pending>>,
    /// Registrations per client address.
    registrations: RateLimiter,
    /// Failed token requests per client address.
    failures: RateLimiter,
    /// Authorization requests (consent pages) per client address.
    authorizations: RateLimiter,
}

/// A validated authorization request waiting for the user's decision.
#[derive(Clone)]
pub struct Pending {
    pub client_id: String,
    pub client_name: String,
    pub redirect_uri: String,
    pub state: Option<String>,
    pub code_challenge: String,
    created: Instant,
    /// The one-time token the consent page must send back, and a hash of
    /// the admin session it was handed to.
    csrf: Option<(String, String)>,
}

impl std::fmt::Debug for Pending {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pending")
            .field("client_id", &self.client_id)
            .field("redirect_uri", &self.redirect_uri)
            .field("csrf", &self.csrf.as_ref().map(|_| "[redacted]"))
            .finish()
    }
}

impl OAuth {
    pub fn new(
        db: Db,
        trust_proxy: bool,
        allowed_hosts: Vec<String>,
        env_agents: Vec<String>,
    ) -> Self {
        Self {
            db,
            trust_proxy,
            allowed_hosts,
            env_agents,
            pending: Mutex::new(HashMap::new()),
            // Ten registrations per address in ten minutes.
            registrations: RateLimiter::new(10, Duration::from_secs(10 * 60)),
            // Thirty failed token requests per address in five minutes.
            failures: RateLimiter::new(30, Duration::from_secs(5 * 60)),
            // Thirty consent pages per address in ten minutes.
            authorizations: RateLimiter::new(30, Duration::from_secs(10 * 60)),
        }
    }

    fn pending(&self) -> std::sync::MutexGuard<'_, HashMap<String, Pending>> {
        let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        pending.retain(|_, request| request.created.elapsed() < PENDING_TTL);
        pending
    }

    /// Keeps a validated request and returns its id for the consent page.
    fn add_pending(&self, request: Pending) -> Option<String> {
        let id = random_token().ok()?;
        let mut pending = self.pending();
        // The oldest open request of one client.
        let oldest_of = |pending: &HashMap<String, Pending>, client: &str| {
            pending
                .iter()
                .filter(|(_, open)| open.client_id == client)
                .min_by_key(|(_, open)| open.created)
                .map(|(id, _)| id.clone())
        };
        while pending
            .values()
            .filter(|open| open.client_id == request.client_id)
            .count()
            >= MAX_PENDING_PER_CLIENT
        {
            let oldest = oldest_of(&pending, &request.client_id)?;
            pending.remove(&oldest);
        }
        while pending.len() >= MAX_PENDING {
            let mut counts: HashMap<&str, usize> = HashMap::new();
            for open in pending.values() {
                *counts.entry(open.client_id.as_str()).or_default() += 1;
            }
            let busiest = counts
                .into_iter()
                .max_by_key(|(_, count)| *count)
                .map(|(client, _)| client.to_string())?;
            let oldest = oldest_of(&pending, &busiest)?;
            pending.remove(&oldest);
        }
        pending.insert(id.clone(), request);
        Some(id)
    }

    /// A consent request that is still open.
    pub fn pending_request(&self, id: &str) -> Option<Pending> {
        self.pending().get(id).cloned()
    }

    /// Hands out the one-time token for a consent request, bound to the
    /// admin session that will send it back. A new one replaces the old.
    pub fn issue_csrf(&self, id: &str, session: &str) -> Option<String> {
        let token = random_token().ok()?;
        let mut pending = self.pending();
        let request = pending.get_mut(id)?;
        request.csrf = Some((token_hash(session), token.clone()));
        Some(token)
    }

    /// Checks the one-time token and the session it was bound to.
    pub fn check_csrf(&self, id: &str, session: &str, presented: &str) -> Option<Pending> {
        let pending = self.pending();
        let request = pending.get(id)?;
        let (bound, token) = request.csrf.as_ref()?;
        let session_ok: bool = token_hash(session)
            .as_bytes()
            .ct_eq(bound.as_bytes())
            .into();
        let token_ok: bool = presented.as_bytes().ct_eq(token.as_bytes()).into();
        (session_ok && token_ok).then(|| request.clone())
    }

    /// Ends a consent request: approved or denied, it cannot be used again.
    pub fn finish(&self, id: &str) {
        self.pending().remove(id);
    }

    /// Names no new OAuth agent may take.
    pub fn reserved_names(&self) -> Vec<String> {
        RESERVED_AGENT_NAMES
            .iter()
            .map(|name| name.to_string())
            .chain(self.env_agents.iter().cloned())
            .collect()
    }
}

/// The routes of the authorization server. None of them needs a sign-in:
/// the metadata, registration, the token and revocation endpoints are for
/// clients, and the consent page signs the user in itself.
pub fn router(oauth: Arc<OAuth>) -> Router {
    Router::new()
        .route(
            "/.well-known/oauth-protected-resource",
            get(resource_metadata),
        )
        .route(
            "/.well-known/oauth-protected-resource/mcp",
            get(resource_metadata),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            get(server_metadata),
        )
        .route(
            "/oauth/register",
            post(register).layer(DefaultBodyLimit::max(MAX_REGISTRATION_BYTES)),
        )
        .route("/oauth/authorize", get(authorize))
        .route(
            "/oauth/token",
            post(token).layer(DefaultBodyLimit::max(MAX_FORM_BYTES)),
        )
        .route(
            "/oauth/revoke",
            post(revoke).layer(DefaultBodyLimit::max(MAX_FORM_BYTES)),
        )
        .layer(middleware::from_fn(headers))
        .with_state(oauth)
}

/// Every answer is not to be stored or framed; pages get the admin view's
/// strict CSP.
async fn headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(crate::admin::CSP),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}

/// The origin clients reach lore at, from the request: the `Host` header
/// when it is a plain host name (and one of `LORE_ALLOWED_HOSTS` when that
/// is set), with `https` — or `http` for a loopback host. Behind a trusted
/// proxy `X-Forwarded-Proto` decides the scheme. `None` when the host is
/// not acceptable.
pub fn public_origin(
    headers: &HeaderMap,
    trust_proxy: bool,
    allowed_hosts: &[String],
) -> Option<String> {
    let host = headers
        .get(header::HOST)?
        .to_str()
        .ok()?
        .trim()
        .to_ascii_lowercase();
    let plain = !host.is_empty()
        && host.len() <= 255
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']'));
    if !plain {
        return None;
    }
    let (name, port) = split_host(&host);
    if !allowed_hosts.is_empty() {
        let allowed = allowed_hosts.iter().any(|allowed| {
            let allowed = allowed.trim().to_ascii_lowercase();
            let (allowed_name, allowed_port) = split_host(&allowed);
            allowed_name == name && (allowed_port.is_none() || allowed_port == port)
        });
        if !allowed {
            return None;
        }
    }
    let forwarded = trust_proxy
        .then(|| {
            headers
                .get("x-forwarded-proto")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.split(',').next())
                .map(|value| value.trim().to_ascii_lowercase())
        })
        .flatten()
        .filter(|proto| proto == "http" || proto == "https");
    let scheme = forwarded.unwrap_or_else(|| {
        if is_loopback_host(name) {
            "http".into()
        } else {
            "https".into()
        }
    });
    Some(format!("{scheme}://{host}"))
}

/// Splits `host[:port]`, IPv6 literals in brackets included.
fn split_host(host: &str) -> (&str, Option<&str>) {
    if let Some(rest) = host.strip_prefix('[') {
        return match rest.split_once(']') {
            Some((name, tail)) => (name, tail.strip_prefix(':')),
            None => (host, None),
        };
    }
    match host.rsplit_once(':') {
        Some((name, port)) if !name.contains(':') => (name, Some(port)),
        _ => (host, None),
    }
}

fn is_loopback_host(name: &str) -> bool {
    let name = name.trim_start_matches('[').trim_end_matches(']');
    name == "localhost"
        || name.ends_with(".localhost")
        || name.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// The resource this server protects.
fn resource_of(origin: &str) -> String {
    format!("{origin}/mcp")
}

fn unknown_host() -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({
            "error": "invalid_request",
            "error_description": "the Host header is not one this server answers to",
        })),
    )
        .into_response()
}

/// Metadata documents may be read from a browser-based client.
fn public_json(value: serde_json::Value) -> Response {
    ([(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")], Json(value)).into_response()
}

/// RFC 9728: what `/mcp` is and which authorization server issues its
/// tokens.
async fn resource_metadata(State(oauth): State<Arc<OAuth>>, headers: HeaderMap) -> Response {
    let Some(origin) = public_origin(&headers, oauth.trust_proxy, &oauth.allowed_hosts) else {
        return unknown_host();
    };
    public_json(json!({
        "resource": resource_of(&origin),
        "authorization_servers": [origin],
        "bearer_methods_supported": ["header"],
        "scopes_supported": [SCOPE],
        "resource_name": "project-lore",
    }))
}

/// RFC 8414: where the endpoints are and what they support.
async fn server_metadata(State(oauth): State<Arc<OAuth>>, headers: HeaderMap) -> Response {
    let Some(origin) = public_origin(&headers, oauth.trust_proxy, &oauth.allowed_hosts) else {
        return unknown_host();
    };
    public_json(json!({
        "issuer": origin,
        "authorization_endpoint": format!("{origin}/oauth/authorize"),
        "token_endpoint": format!("{origin}/oauth/token"),
        "registration_endpoint": format!("{origin}/oauth/register"),
        "revocation_endpoint": format!("{origin}/oauth/revoke"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "revocation_endpoint_auth_methods_supported": ["none"],
        "scopes_supported": [SCOPE],
    }))
}

/// An RFC 6749 / RFC 7591 error answer.
fn oauth_error(status: StatusCode, error: &str, description: &str) -> Response {
    (
        status,
        Json(json!({ "error": error, "error_description": description })),
    )
        .into_response()
}

/// Checks one redirect URI a client registers: `https://` with a host, or
/// `http://` on a loopback host (any port), or a private-use scheme such
/// as `cursor://`; never a fragment, user information, or a scheme that
/// can run code or read files.
pub fn check_redirect_uri(uri: &str) -> Result<(), String> {
    if uri.is_empty() || uri.chars().count() > MAX_REDIRECT_URI_CHARS {
        return Err(format!(
            "a redirect URI must be 1 to {MAX_REDIRECT_URI_CHARS} characters"
        ));
    }
    if uri.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err("a redirect URI must not contain spaces or control characters".into());
    }
    if uri.contains('#') {
        return Err("a redirect URI must not contain a fragment".into());
    }
    let url = reqwest::Url::parse(uri).map_err(|_| "a redirect URI must be an absolute URI")?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err("a redirect URI must not contain user information".into());
    }
    match url.scheme() {
        "https" => {
            if url.host_str().is_none_or(str::is_empty) {
                return Err("an https redirect URI needs a host".into());
            }
        }
        "http" => {
            if !url.host_str().is_some_and(is_loopback_host) {
                return Err(
                    "an http redirect URI is allowed only on a loopback host (localhost, \
                     127.0.0.1 or [::1]); use https otherwise"
                        .into(),
                );
            }
        }
        scheme => {
            let mut chars = scheme.chars();
            let shaped = chars.next().is_some_and(|c| c.is_ascii_lowercase())
                && chars.all(|c| {
                    c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '+' | '.' | '-')
                });
            if !shaped
                || scheme.len() < 2
                || REFUSED_SCHEMES.contains(&scheme)
                || REFUSED_SCHEME_PREFIXES
                    .iter()
                    .any(|prefix| scheme.starts_with(prefix))
            {
                return Err(format!("the scheme \"{scheme}\" is not a redirect target"));
            }
        }
    }
    Ok(())
}

/// A client name as lore keeps it: control characters removed, trimmed,
/// at most 100 characters. It is only ever shown as text.
pub fn clean_client_name(name: &str) -> String {
    name.chars()
        .filter(|c| !c.is_control())
        .collect::<String>()
        .trim()
        .chars()
        .take(MAX_CLIENT_NAME_CHARS)
        .collect()
}

#[derive(Deserialize)]
struct Registration {
    #[serde(default)]
    client_name: Option<String>,
    #[serde(default)]
    redirect_uris: Option<Vec<String>>,
    #[serde(default)]
    grant_types: Option<Vec<String>>,
    #[serde(default)]
    response_types: Option<Vec<String>>,
}

/// RFC 7591 for public clients: stores the name and the redirect URIs and
/// hands out a random `client_id`. No client secret exists.
async fn register(
    State(oauth): State<Arc<OAuth>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Result<Json<Registration>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let ip = client_ip(&headers, Some(peer), oauth.trust_proxy);
    if let Some(retry_after) = oauth.registrations.hit(&ip) {
        tracing::warn!(%ip, "too many client registrations");
        return too_many_requests(retry_after);
    }
    let Ok(Json(form)) = body else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_client_metadata",
            "the body must be a JSON object",
        );
    };
    let uris = form.redirect_uris.unwrap_or_default();
    if uris.is_empty() || uris.len() > MAX_REDIRECT_URIS {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_redirect_uri",
            &format!("register 1 to {MAX_REDIRECT_URIS} redirect URIs"),
        );
    }
    for uri in &uris {
        if let Err(reason) = check_redirect_uri(uri) {
            return oauth_error(StatusCode::BAD_REQUEST, "invalid_redirect_uri", &reason);
        }
    }
    if let Some(grants) = &form.grant_types
        && grants
            .iter()
            .any(|grant| grant != "authorization_code" && grant != "refresh_token")
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_client_metadata",
            "only the authorization_code and refresh_token grant types are supported",
        );
    }
    if let Some(types) = &form.response_types
        && types.iter().any(|kind| kind != "code")
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_client_metadata",
            "only the code response type is supported",
        );
    }
    let Ok(client_id) = random_token() else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let client = OAuthClient {
        client_id,
        client_name: clean_client_name(form.client_name.as_deref().unwrap_or("")),
        redirect_uris: uris,
    };
    let db = oauth.db.clone();
    let stored = client.clone();
    match tokio::task::spawn_blocking(move || db.register_oauth_client(&stored)).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            tracing::warn!(%error, "a client registration was refused");
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_client_metadata",
                "lore holds as many registered clients as it keeps; try again later",
            );
        }
        Err(error) => {
            tracing::error!(%error, "the registration task failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    }
    tracing::info!(%ip, client = %client.client_name, "an OAuth client registered");
    (
        StatusCode::CREATED,
        Json(json!({
            "client_id": client.client_id,
            "client_id_issued_at": db::unix_now(),
            "client_name": client.client_name,
            "redirect_uris": client.redirect_uris,
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
            "scope": SCOPE,
        })),
    )
        .into_response()
}

#[derive(Deserialize, Default)]
struct AuthorizeQuery {
    #[serde(default)]
    response_type: Option<String>,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    redirect_uri: Option<String>,
    #[serde(default)]
    code_challenge: Option<String>,
    #[serde(default)]
    code_challenge_method: Option<String>,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    resource: Option<String>,
}

/// A page that explains a refused authorization request. It never
/// redirects and repeats nothing from the request.
fn error_page(status: StatusCode, message: &str) -> Response {
    let page = format!(
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <meta name=\"robots\" content=\"noindex, nofollow\"><meta name=\"color-scheme\" content=\"dark\">\
         <title>project-lore: authorization refused</title>\
         <link rel=\"stylesheet\" href=\"/admin/app.css\"><link rel=\"stylesheet\" href=\"/admin/consent.css\">\
         </head><body class=\"consent-page\"><main class=\"consent\"><section class=\"login-card consent-card\">\
         <h1>Authorization refused</h1><p class=\"muted\">{}</p>\
         <p class=\"fine\">Nothing was sent back to the application. Close this window and connect again \
         from the client.</p></section></main></body></html>\n",
        escape_html(message)
    );
    (
        status,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        page,
    )
        .into_response()
}

fn escape_html(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Sends the user agent back to a validated redirect URI with the given
/// query parameters.
pub fn redirect_with(redirect_uri: &str, pairs: &[(&str, &str)]) -> Option<String> {
    let mut url = reqwest::Url::parse(redirect_uri).ok()?;
    {
        let mut query = url.query_pairs_mut();
        for (key, value) in pairs {
            query.append_pair(key, value);
        }
    }
    Some(url.to_string())
}

fn redirect_error(
    redirect_uri: &str,
    error: &str,
    description: &str,
    state: Option<&str>,
) -> Response {
    let mut pairs = vec![("error", error), ("error_description", description)];
    if let Some(state) = state {
        pairs.push(("state", state));
    }
    match redirect_with(redirect_uri, &pairs) {
        Some(location) => (StatusCode::SEE_OTHER, [(header::LOCATION, location)]).into_response(),
        None => error_page(StatusCode::BAD_REQUEST, "The redirect URI cannot be used."),
    }
}

/// Validates an authorization request and serves the consent page. An
/// unknown client or a redirect URI that does not match shows an error
/// page and never redirects; every other problem goes back to the client
/// as an OAuth error.
async fn authorize(
    State(oauth): State<Arc<OAuth>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    query: Result<Query<AuthorizeQuery>, axum::extract::rejection::QueryRejection>,
) -> Response {
    let ip = client_ip(&headers, Some(peer), oauth.trust_proxy);
    if let Some(retry_after) = oauth.authorizations.hit(&ip) {
        tracing::warn!(%ip, "too many authorization requests");
        return too_many_requests(retry_after);
    }
    let query = query.map(|Query(query)| query).unwrap_or_default();
    let Some(origin) = public_origin(&headers, oauth.trust_proxy, &oauth.allowed_hosts) else {
        return error_page(
            StatusCode::BAD_REQUEST,
            "This server does not answer to the host name the request used.",
        );
    };
    let client_id = query.client_id.unwrap_or_default();
    let client = if client_id.is_empty() || client_id.len() > 200 {
        None
    } else {
        let db = oauth.db.clone();
        match tokio::task::spawn_blocking(move || db.oauth_client(&client_id)).await {
            Ok(Ok(client)) => client,
            other => {
                tracing::error!(?other, "loading an OAuth client failed");
                return error_page(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "The request could not be checked.",
                );
            }
        }
    };
    let Some(client) = client else {
        return error_page(
            StatusCode::BAD_REQUEST,
            "The application is not registered with this lore server, or its registration \
             was removed.",
        );
    };
    let redirect_uri = match query.redirect_uri {
        Some(uri) if client.redirect_uris.contains(&uri) => uri,
        None if client.redirect_uris.len() == 1 => client.redirect_uris[0].clone(),
        _ => {
            return error_page(
                StatusCode::BAD_REQUEST,
                "The redirect URI does not match any the application registered.",
            );
        }
    };
    // From here on the redirect URI is trusted, so errors go back to it.
    let state = query
        .state
        .filter(|state| !state.is_empty() && state.len() <= 2000);
    let state = state.as_deref();
    if query.response_type.as_deref() != Some("code") {
        return redirect_error(
            &redirect_uri,
            "unsupported_response_type",
            "only response_type=code is supported",
            state,
        );
    }
    let challenge = query.code_challenge.unwrap_or_default();
    if query.code_challenge_method.as_deref() != Some("S256") || !is_challenge(&challenge) {
        return redirect_error(
            &redirect_uri,
            "invalid_request",
            "PKCE is required: send code_challenge with code_challenge_method=S256",
            state,
        );
    }
    if let Some(resource) = query.resource.as_deref()
        && !resource_matches(resource, &origin)
    {
        return redirect_error(
            &redirect_uri,
            "invalid_target",
            "the resource is not this server's MCP endpoint",
            state,
        );
    }
    let request = Pending {
        client_id: client.client_id.clone(),
        client_name: client.client_name.clone(),
        redirect_uri,
        state: state.map(str::to_string),
        code_challenge: challenge,
        created: Instant::now(),
        csrf: None,
    };
    let Some(id) = oauth.add_pending(request) else {
        return error_page(
            StatusCode::INTERNAL_SERVER_ERROR,
            "The request could not be kept.",
        );
    };
    // The id is URL-safe base64, so it goes into the page as it is.
    let page = CONSENT_PAGE.replace("{{REQUEST}}", &id);
    ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], page).into_response()
}

/// Whether a `resource` parameter names this server's MCP endpoint.
fn resource_matches(resource: &str, origin: &str) -> bool {
    let expected = resource_of(origin);
    resource == expected || resource.strip_suffix('/') == Some(expected.as_str())
}

/// The token endpoint's form, read as plain pairs so every problem can be
/// answered as an RFC 6749 error.
type FormPairs = HashMap<String, String>;

fn field<'a>(form: &'a FormPairs, name: &str) -> Option<&'a str> {
    form.get(name)
        .map(String::as_str)
        .filter(|value| !value.is_empty())
}

/// The token endpoint: an authorization code or a refresh token in, a new
/// access token and refresh token out.
async fn token(
    State(oauth): State<Arc<OAuth>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    form: Result<axum::Form<FormPairs>, FormRejection>,
) -> Response {
    let ip = client_ip(&headers, Some(peer), oauth.trust_proxy);
    if let Some(retry_after) = oauth.failures.blocked(&ip) {
        return too_many_requests(retry_after);
    }
    let Ok(axum::Form(form)) = form else {
        oauth.failures.hit(&ip);
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "the body must be application/x-www-form-urlencoded",
        );
    };
    let origin = public_origin(&headers, oauth.trust_proxy, &oauth.allowed_hosts);
    let answer = match field(&form, "grant_type") {
        Some("authorization_code") => exchange_code(&oauth, &form, origin.as_deref()).await,
        Some("refresh_token") => exchange_refresh(&oauth, &form).await,
        Some(_) => Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "grant_type must be authorization_code or refresh_token",
        )),
        None => Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "grant_type is missing",
        )),
    };
    match answer {
        Ok(response) => response,
        Err(response) => {
            oauth.failures.hit(&ip);
            response
        }
    }
}

fn invalid_grant(description: &str) -> Response {
    oauth_error(StatusCode::BAD_REQUEST, "invalid_grant", description)
}

/// Looks up the client a token request names. Public clients identify
/// themselves with `client_id` alone.
#[expect(
    clippy::result_large_err,
    reason = "the error is the HTTP answer itself, built once per token request"
)]
async fn known_client(oauth: &OAuth, form: &FormPairs) -> Result<OAuthClient, Response> {
    let Some(client_id) = field(form, "client_id").map(str::to_string) else {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "client_id is missing",
        ));
    };
    let db = oauth.db.clone();
    match tokio::task::spawn_blocking(move || db.oauth_client(&client_id)).await {
        Ok(Ok(Some(client))) => Ok(client),
        Ok(Ok(None)) => Err(oauth_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "the client is not registered",
        )),
        other => {
            tracing::error!(?other, "loading an OAuth client failed");
            Err(StatusCode::INTERNAL_SERVER_ERROR.into_response())
        }
    }
}

#[expect(
    clippy::result_large_err,
    reason = "the error is the HTTP answer itself, built once per token request"
)]
async fn exchange_code(
    oauth: &OAuth,
    form: &FormPairs,
    origin: Option<&str>,
) -> Result<Response, Response> {
    let client = known_client(oauth, form).await?;
    let (Some(code), Some(verifier)) = (field(form, "code"), field(form, "code_verifier")) else {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "code and code_verifier are required",
        ));
    };
    if let Some(resource) = field(form, "resource")
        && !origin.is_some_and(|origin| resource_matches(resource, origin))
    {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_target",
            "the resource is not this server's MCP endpoint",
        ));
    }
    let db = oauth.db.clone();
    let hash = token_hash(code);
    let taken = match tokio::task::spawn_blocking(move || db.take_code(&hash)).await {
        Ok(Ok(taken)) => taken,
        other => {
            tracing::error!(?other, "taking an authorization code failed");
            return Err(StatusCode::INTERNAL_SERVER_ERROR.into_response());
        }
    };
    let code = match taken {
        CodeLookup::Taken(code) => code,
        CodeLookup::Reused => {
            tracing::warn!(client = %client.client_id, "an authorization code was used twice; its grant is revoked");
            return Err(invalid_grant("the authorization code was already used"));
        }
        CodeLookup::Missing => return Err(invalid_grant("the authorization code is not valid")),
    };
    if code.client_id != client.client_id {
        return Err(invalid_grant("the code was issued to another client"));
    }
    if field(form, "redirect_uri").is_some_and(|uri| uri != code.redirect_uri) {
        return Err(invalid_grant(
            "redirect_uri does not match the authorization request",
        ));
    }
    if code.expires_at <= db::unix_now() {
        return Err(invalid_grant("the authorization code has expired"));
    }
    if !pkce_matches(verifier, &code.code_challenge) {
        return Err(invalid_grant(
            "the code_verifier does not match the code_challenge",
        ));
    }
    issue(oauth, code.grant_id).await
}

#[expect(
    clippy::result_large_err,
    reason = "the error is the HTTP answer itself, built once per token request"
)]
async fn exchange_refresh(oauth: &OAuth, form: &FormPairs) -> Result<Response, Response> {
    let client = known_client(oauth, form).await?;
    let Some(refresh) = field(form, "refresh_token") else {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "refresh_token is required",
        ));
    };
    let db = oauth.db.clone();
    let hash = token_hash(refresh);
    let client_id = client.client_id.clone();
    let lookup =
        match tokio::task::spawn_blocking(move || db.take_refresh_token(&hash, &client_id)).await {
            Ok(Ok(lookup)) => lookup,
            other => {
                tracing::error!(?other, "exchanging a refresh token failed");
                return Err(StatusCode::INTERNAL_SERVER_ERROR.into_response());
            }
        };
    match lookup {
        RefreshLookup::Rotated { grant_id } => issue(oauth, grant_id).await,
        RefreshLookup::Reused => {
            tracing::warn!(client = %client.client_id, "a refresh token was used twice; its grant is revoked");
            Err(invalid_grant(
                "the refresh token was already used; authorize again",
            ))
        }
        RefreshLookup::Invalid => Err(invalid_grant("the refresh token is not valid")),
    }
}

/// Issues an access token and a refresh token for a usable grant.
#[expect(
    clippy::result_large_err,
    reason = "the error is the HTTP answer itself, built once per token request"
)]
async fn issue(oauth: &OAuth, grant_id: i64) -> Result<Response, Response> {
    let (Ok(access), Ok(refresh)) = (random_token(), random_token()) else {
        return Err(StatusCode::INTERNAL_SERVER_ERROR.into_response());
    };
    let db = oauth.db.clone();
    let (access_hash, refresh_hash) = (token_hash(&access), token_hash(&refresh));
    let stored = tokio::task::spawn_blocking(move || -> anyhow::Result<bool> {
        if !db.grant_usable(grant_id)? {
            return Ok(false);
        }
        let now = db::unix_now();
        db.issue_tokens(
            grant_id,
            &access_hash,
            now + ACCESS_TTL_SECS,
            &refresh_hash,
            now + REFRESH_TTL_SECS,
        )?;
        Ok(true)
    })
    .await;
    match stored {
        Ok(Ok(true)) => Ok((
            [(header::CACHE_CONTROL, "no-store")],
            Json(json!({
                "access_token": access,
                "token_type": "Bearer",
                "expires_in": ACCESS_TTL_SECS,
                "refresh_token": refresh,
                "scope": SCOPE,
            })),
        )
            .into_response()),
        Ok(Ok(false)) => Err(invalid_grant(
            "the authorization was revoked or its agent is disabled",
        )),
        other => {
            tracing::error!(?other, "issuing tokens failed");
            Err(StatusCode::INTERNAL_SERVER_ERROR.into_response())
        }
    }
}

/// RFC 7009: revokes an access or refresh token. The answer is the same
/// whether or not the token was known.
async fn revoke(
    State(oauth): State<Arc<OAuth>>,
    form: Result<axum::Form<FormPairs>, FormRejection>,
) -> Response {
    let Ok(axum::Form(form)) = form else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "the body must be application/x-www-form-urlencoded",
        );
    };
    let Some(token) = field(&form, "token") else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "token is missing",
        );
    };
    let hash = token_hash(token);
    let client_id = field(&form, "client_id").map(str::to_string);
    let db = oauth.db.clone();
    match tokio::task::spawn_blocking(move || db.revoke_token(&hash, client_id.as_deref())).await {
        Ok(Ok(_)) => StatusCode::OK.into_response(),
        other => {
            tracing::error!(?other, "revoking a token failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// 32 random bytes from the OS, URL-safe base64 without padding (43
/// characters).
pub fn random_token() -> Result<String, getrandom::Error> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes)?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

/// The SHA-256 of a code or token, as stored.
pub fn token_hash(token: &str) -> String {
    Sha256::digest(token.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Whether a bearer value has the shape of a token lore issues, so other
/// strings never reach the database.
pub fn looks_like_token(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// An S256 code challenge: 43 characters of URL-safe base64.
fn is_challenge(value: &str) -> bool {
    looks_like_token(value)
}

/// PKCE S256 (RFC 7636): BASE64URL(SHA256(verifier)) equals the
/// challenge. The verifier must be 43 to 128 unreserved characters.
pub fn pkce_matches(verifier: &str, challenge: &str) -> bool {
    let shaped = (43..=128).contains(&verifier.len())
        && verifier
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b));
    if !shaped {
        return false;
    }
    let computed = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(Sha256::digest(verifier.as_bytes()));
    computed.as_bytes().ct_eq(challenge.as_bytes()).into()
}

/// Lowercases and checks an agent name: `[a-z0-9][a-z0-9_-]{1,31}`, and
/// none of the names lore reserves.
pub fn normalize_agent_name(name: &str, reserved: &[String]) -> Result<String, String> {
    let name = name.trim().to_lowercase();
    let mut chars = name.chars();
    let first_ok = chars
        .next()
        .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
    let rest_ok =
        chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-');
    if !first_ok || !rest_ok || !(2..=32).contains(&name.len()) {
        return Err(
            "the agent name must be 2 to 32 characters of a-z, 0-9, underscore or dash, \
             starting with a letter or digit"
                .into(),
        );
    }
    if reserved.contains(&name) {
        return Err(format!(
            "\"{name}\" is reserved: lore uses it, or an agent with a token in the environment has it"
        ));
    }
    Ok(name)
}

/// An agent name suggested from a client's name: lowercase, every other
/// character a dash, 2 to 32 characters; `taken` names get a number.
pub fn suggest_agent_name(client_name: &str, taken: &[String]) -> String {
    let mut base = String::new();
    for c in client_name.to_lowercase().chars() {
        if c.is_ascii_lowercase() || c.is_ascii_digit() {
            base.push(c);
        } else if !base.is_empty() && !base.ends_with('-') {
            base.push('-');
        }
    }
    let mut base: String = base.trim_matches('-').chars().take(28).collect();
    base = base.trim_end_matches('-').to_string();
    if base.len() < 2 {
        base = "agent".into();
    }
    if !taken.contains(&base) {
        return base;
    }
    (2..1000)
        .map(|n| format!("{base}-{n}"))
        .find(|name| !taken.contains(name))
        .unwrap_or(base)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, value.parse().unwrap());
        headers
    }

    #[test]
    fn the_origin_comes_from_a_checked_host() {
        assert_eq!(
            public_origin(&host("lore.example.com"), false, &[]).as_deref(),
            Some("https://lore.example.com")
        );
        assert_eq!(
            public_origin(&host("127.0.0.1:8080"), false, &[]).as_deref(),
            Some("http://127.0.0.1:8080")
        );
        assert_eq!(
            public_origin(&host("localhost:3000"), false, &[]).as_deref(),
            Some("http://localhost:3000")
        );
        assert!(public_origin(&host("evil.example/x"), false, &[]).is_none());
        assert!(public_origin(&HeaderMap::new(), false, &[]).is_none());
        let allowed = vec!["lore.example.com".to_string()];
        assert!(public_origin(&host("lore.example.com:443"), false, &allowed).is_some());
        assert!(public_origin(&host("other.example.com"), false, &allowed).is_none());
        let pinned = vec!["lore.example.com:8443".to_string()];
        assert!(public_origin(&host("lore.example.com:8443"), false, &pinned).is_some());
        assert!(public_origin(&host("lore.example.com"), false, &pinned).is_none());
        // The forwarded scheme counts only behind a trusted proxy.
        let mut forwarded = host("lore.example.com");
        forwarded.insert("x-forwarded-proto", "http".parse().unwrap());
        assert_eq!(
            public_origin(&forwarded, true, &[]).as_deref(),
            Some("http://lore.example.com")
        );
        assert_eq!(
            public_origin(&forwarded, false, &[]).as_deref(),
            Some("https://lore.example.com")
        );
        forwarded.insert("x-forwarded-proto", "gopher".parse().unwrap());
        assert_eq!(
            public_origin(&forwarded, true, &[]).as_deref(),
            Some("https://lore.example.com")
        );
    }

    fn test_oauth(label: &str) -> OAuth {
        let dir =
            std::env::temp_dir().join(format!("lore-oauth-test-{label}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        OAuth::new(
            Db::open(&dir.join("lore.db")).unwrap(),
            false,
            Vec::new(),
            Vec::new(),
        )
    }

    fn open_request(client: &str) -> Pending {
        Pending {
            client_id: client.into(),
            client_name: String::new(),
            redirect_uri: "http://127.0.0.1:9/cb".into(),
            state: None,
            code_challenge: "c".repeat(43),
            created: Instant::now(),
            csrf: None,
        }
    }

    #[test]
    fn a_flood_of_consent_requests_cannot_expire_another_clients() {
        let oauth = test_oauth("pending");
        let real = oauth.add_pending(open_request("real-client")).unwrap();
        // One client keeps at most its own share.
        let mut flood = Vec::new();
        for _ in 0..(MAX_PENDING_PER_CLIENT + 5) {
            flood.push(oauth.add_pending(open_request("flooder")).unwrap());
        }
        assert!(oauth.pending_request(&flood[0]).is_none());
        assert!(oauth.pending_request(flood.last().unwrap()).is_some());
        // Many clients filling every slot push out the busiest client's
        // oldest requests, never the one request of another.
        for client in 0..(MAX_PENDING / MAX_PENDING_PER_CLIENT + 2) {
            for _ in 0..MAX_PENDING_PER_CLIENT {
                oauth
                    .add_pending(open_request(&format!("flooder-{client}")))
                    .unwrap();
            }
        }
        assert!(oauth.pending().len() <= MAX_PENDING);
        assert!(oauth.pending_request(&real).is_some());
    }

    #[tokio::test]
    async fn authorization_requests_are_limited_per_address() {
        let oauth = Arc::new(test_oauth("authorize-limit"));
        let peer: SocketAddr = "203.0.113.7:5000".parse().unwrap();
        let mut statuses = Vec::new();
        for _ in 0..31 {
            let response = authorize(
                State(oauth.clone()),
                ConnectInfo(peer),
                host("lore.example.com"),
                Ok(Query(AuthorizeQuery::default())),
            )
            .await;
            statuses.push(response.status());
        }
        assert!(
            statuses[..30]
                .iter()
                .all(|status| *status == StatusCode::BAD_REQUEST)
        );
        assert_eq!(statuses[30], StatusCode::TOO_MANY_REQUESTS);
        // Another address is not affected.
        let response = authorize(
            State(oauth),
            ConnectInfo("203.0.113.8:5000".parse().unwrap()),
            host("lore.example.com"),
            Ok(Query(AuthorizeQuery::default())),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn redirect_uris_are_checked() {
        for good in [
            "https://client.example.com/callback",
            "http://localhost:33418/callback",
            "http://127.0.0.1:5000/cb",
            "http://[::1]:9999/",
            "cursor://anysphere.cursor-retrieval/oauth/callback",
            "vscode://vscode.github-authentication/did-authenticate",
            "com.example.app:/oauth2redirect",
            "my-client+v2://callback",
        ] {
            assert!(check_redirect_uri(good).is_ok(), "{good} was refused");
        }
        for bad in [
            "",
            "http://client.example.com/callback",
            "https://client.example.com/cb#frag",
            "javascript:alert(1)",
            "data:text/html,hi",
            "file:///etc/passwd",
            "relative/path",
            "https://user:pass@client.example.com/",
            "https://client.example.com/a b",
            "ms-msdt:/id",
            "ms-officecmd:x",
            "MS-SETTINGS:privacy",
            "search-ms:query=x&crumb=location:\\\\host\\share",
            "intent://scan/",
            "itms-services://?action=download-manifest&url=https://x/m.plist",
            "jar:https://example.com/a.jar!/x",
            "vnd.ms-excel:x",
            "smb://host/share",
            "ssh://host",
            "gopher://host/",
        ] {
            assert!(check_redirect_uri(bad).is_err(), "{bad:?} was accepted");
        }
    }

    #[test]
    fn pkce_s256_and_token_shapes() {
        // RFC 7636 appendix B.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert!(pkce_matches(verifier, challenge));
        assert!(!pkce_matches(&format!("{verifier}x"), challenge));
        assert!(!pkce_matches("short", challenge));
        assert!(is_challenge(challenge));
        let token = random_token().unwrap();
        assert!(looks_like_token(&token));
        assert_ne!(token, random_token().unwrap());
        assert!(!looks_like_token("x".repeat(64).as_str()));
        assert_eq!(token_hash("abc").len(), 64);
    }

    #[test]
    fn agent_names_are_checked_and_suggested() {
        let reserved: Vec<String> = ["admin", "viewer", "shared", "claude"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(
            normalize_agent_name(" Codex-2 ", &reserved).unwrap(),
            "codex-2"
        );
        for bad in [
            "",
            "a",
            "-x",
            "has space",
            "a.b",
            "admin",
            "claude",
            &"a".repeat(33),
        ] {
            assert!(normalize_agent_name(bad, &reserved).is_err(), "{bad:?}");
        }
        assert_eq!(suggest_agent_name("Claude Code", &[]), "claude-code");
        assert_eq!(
            suggest_agent_name("Claude Code", &["claude-code".to_string()]),
            "claude-code-2"
        );
        assert_eq!(suggest_agent_name("!!", &[]), "agent");
        assert_eq!(suggest_agent_name("Ünïcode ✓ Client", &[]), "n-code-client");
        assert!(suggest_agent_name(&"x".repeat(80), &[]).len() <= 32);
        assert_eq!(clean_client_name(" a\u{7}b\n "), "ab");
        assert_eq!(clean_client_name(&"y".repeat(500)).chars().count(), 100);
    }
}
