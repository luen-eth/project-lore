//! The admin view's side of the built-in agents: their state, their
//! settings, and the sign-in flows, which the page drives and the agents'
//! runners carry out. A pasted credential passes through here to the
//! runner and is dropped: it is never stored, logged or sent back.
//!
//! The terminal (part 6d) is a WebSocket between the page and one PTY in
//! an agent's container. Its bytes are relayed as they are, never stored
//! or logged; a terminal cannot be redacted reliably, so whoever may open
//! one (`agents`) has a shell in that container with its credentials.

use super::*;
use axum::extract::ws::{
    Message as WsMessage, WebSocket, WebSocketUpgrade, rejection::WebSocketUpgradeRejection,
};
use base64::Engine;

use crate::{
    avatars,
    builtin::{Hub, HubError, TerminalEvent},
    db::{BuiltinSettings, MAX_DAILY_CAP},
    runner::{
        drivers::{CLAUDE_MODELS, DEEPSEEK_MODELS, MAX_CREDENTIAL_BYTES},
        protocol::{CredentialKind, FromRunner, Kind, LoginMethod, Secret, TerminalMode, ToRunner},
    },
};

pub(super) const SCRIPT: &str = include_str!("../../assets/builtin.js");
pub(super) const STYLE: &str = include_str!("../../assets/builtin.css");

/// The terminal window: a document of its own, shown in a frame of the
/// admin page, so the style relaxation xterm.js needs stays out of the
/// admin page's policy.
pub(super) const TERMINAL_PAGE: &str = include_str!("../../assets/terminal.html");
pub(super) const TERMINAL_SCRIPT: &str = include_str!("../../assets/terminal.js");
pub(super) const TERMINAL_STYLE: &str = include_str!("../../assets/terminal.css");

/// xterm.js and its fit addon, vendored from npm (`@xterm/xterm` 6.0.0,
/// `@xterm/addon-fit` 0.11.0) with their licences. The version is in the
/// path, so they are cached for a year.
const XTERM_SCRIPT: &str = include_str!("../../assets/vendor/xterm-6.0.0/xterm.js");
const XTERM_STYLE: &str = include_str!("../../assets/vendor/xterm-6.0.0/xterm.css");
const XTERM_LICENSE: &str = include_str!("../../assets/vendor/xterm-6.0.0/LICENSE");
const FIT_SCRIPT: &str = include_str!("../../assets/vendor/addon-fit-0.11.0/addon-fit.js");
const FIT_LICENSE: &str = include_str!("../../assets/vendor/addon-fit-0.11.0/LICENSE");

/// The terminal document's policy: the admin page's, except that styles
/// may also be inline (xterm.js writes `<style>` elements and `style`
/// attributes as it draws; scripts stay `'self'` only) and that the admin
/// page may frame it.
pub(super) const TERMINAL_CSP: &str = "default-src 'none'; script-src 'self'; \
style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; \
base-uri 'none'; form-action 'none'; frame-ancestors 'self'";

/// Largest frame a terminal page may send (typed or pasted input).
const TERMINAL_FRAME_BYTES: usize = 64 * 1024;

/// How long the page has to say what to open.
const TERMINAL_OPEN_WAIT: Duration = Duration::from_secs(15);

/// The built-in agents' routes and who may reach them; `access` reads this
/// table after the main one.
pub(super) const ROUTES: &[(&str, &str, Access)] = &[
    ("GET", "/admin/builtin.js", Access::Public),
    ("GET", "/admin/builtin.css", Access::Public),
    ("GET", "/admin/terminal", Access::Public),
    ("GET", "/admin/terminal.js", Access::Public),
    ("GET", "/admin/terminal.css", Access::Public),
    ("GET", "/admin/vendor/xterm-6.0.0/{file}", Access::Public),
    (
        "GET",
        "/admin/vendor/addon-fit-0.11.0/{file}",
        Access::Public,
    ),
    (
        "GET",
        "/admin/api/builtin/{name}/terminal",
        Access::Needs(Perm::Agents),
    ),
    ("GET", "/admin/api/builtin", Access::SignedIn),
    // The task runner: anyone signed in may watch, only `agents` stops.
    ("GET", "/admin/api/builtin/runs", Access::SignedIn),
    ("GET", "/admin/api/builtin/active", Access::SignedIn),
    // A run's output can hold what redaction missed: `agents` only.
    (
        "GET",
        "/admin/api/builtin/runs/{id}/events",
        Access::Needs(Perm::Agents),
    ),
    (
        "POST",
        "/admin/api/builtin/{name}/stop",
        Access::Needs(Perm::Agents),
    ),
    (
        "PUT",
        "/admin/api/builtin/{name}",
        Access::Needs(Perm::Agents),
    ),
    (
        "POST",
        "/admin/api/builtin/{name}/refresh",
        Access::Needs(Perm::Agents),
    ),
    (
        "POST",
        "/admin/api/builtin/{name}/login",
        Access::Needs(Perm::Agents),
    ),
    (
        "POST",
        "/admin/api/builtin/{name}/login/code",
        Access::Needs(Perm::Agents),
    ),
    (
        "POST",
        "/admin/api/builtin/{name}/login/cancel",
        Access::Needs(Perm::Agents),
    ),
    (
        "POST",
        "/admin/api/builtin/{name}/credential",
        Access::Needs(Perm::Agents),
    ),
    (
        "POST",
        "/admin/api/builtin/{name}/logout",
        Access::Needs(Perm::Agents),
    ),
];

/// Longest model name accepted.
const MODEL_MAX_CHARS: usize = 100;

/// How long the page waits for each kind of answer.
const STATUS_WAIT: Duration = Duration::from_secs(90);
const MODELS_WAIT: Duration = Duration::from_secs(150);
const LOGIN_WAIT: Duration = Duration::from_secs(45);
const QUICK_WAIT: Duration = Duration::from_secs(30);

pub(super) fn routes() -> Router<Arc<Admin>> {
    Router::new()
        .route(
            "/admin/builtin.js",
            get(|| async { asset("text/javascript; charset=utf-8", SCRIPT) }),
        )
        .route(
            "/admin/builtin.css",
            get(|| async { asset("text/css; charset=utf-8", STYLE) }),
        )
        .route("/admin/api/builtin", get(list))
        .route("/admin/api/builtin/runs", get(runs))
        .route("/admin/api/builtin/active", get(active))
        .route("/admin/api/builtin/runs/{id}/events", get(run_events))
        .route("/admin/api/builtin/{name}/stop", post(stop))
        .route(
            "/admin/api/builtin/{name}",
            put(update).layer(DefaultBodyLimit::max(MAX_JSON_BYTES)),
        )
        .route("/admin/api/builtin/{name}/refresh", post(refresh))
        .route(
            "/admin/api/builtin/{name}/login",
            post(login_start).layer(DefaultBodyLimit::max(MAX_JSON_BYTES)),
        )
        .route(
            "/admin/api/builtin/{name}/login/code",
            post(login_code).layer(DefaultBodyLimit::max(MAX_JSON_BYTES)),
        )
        .route("/admin/api/builtin/{name}/login/cancel", post(login_cancel))
        .route(
            "/admin/api/builtin/{name}/credential",
            post(credential).layer(DefaultBodyLimit::max(2 * MAX_CREDENTIAL_BYTES)),
        )
        .route("/admin/api/builtin/{name}/logout", post(logout))
        .route("/admin/terminal", get(terminal_page))
        .route(
            "/admin/terminal.js",
            get(|| async { asset("text/javascript; charset=utf-8", TERMINAL_SCRIPT) }),
        )
        .route(
            "/admin/terminal.css",
            get(|| async { asset("text/css; charset=utf-8", TERMINAL_STYLE) }),
        )
        .route("/admin/vendor/xterm-6.0.0/{file}", get(xterm_file))
        .route("/admin/vendor/addon-fit-0.11.0/{file}", get(fit_file))
        .route("/admin/api/builtin/{name}/terminal", get(terminal))
        .route_layer(middleware::from_fn(json_only))
}

/// Every state-changing built-in route takes JSON only: a form another
/// site submits (even a sibling subdomain, which `SameSite` lets through)
/// cannot send `Content-Type: application/json` without the browser
/// asking first, and lore never says yes.
async fn json_only(request: Request, next: Next) -> Response {
    let changes = !matches!(
        *request.method(),
        axum::http::Method::GET | axum::http::Method::HEAD | axum::http::Method::OPTIONS
    );
    let json = request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"));
    if changes && !json {
        return (
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            Json(json!({ "error": "send JSON (Content-Type: application/json)" })),
        )
            .into_response();
    }
    next.run(request).await
}

/// `GET /admin/terminal`: the terminal window's document, with its own
/// policy (the security headers keep a policy a route set).
async fn terminal_page() -> Response {
    (
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CONTENT_SECURITY_POLICY, TERMINAL_CSP),
            (header::X_FRAME_OPTIONS, "SAMEORIGIN"),
        ],
        TERMINAL_PAGE,
    )
        .into_response()
}

fn vendored(content_type: &'static str, body: &'static str) -> Response {
    (
        [
            (header::CONTENT_TYPE, content_type),
            (header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
        ],
        body,
    )
        .into_response()
}

async fn xterm_file(Path(file): Path<String>) -> Response {
    match file.as_str() {
        "xterm.js" => vendored("text/javascript; charset=utf-8", XTERM_SCRIPT),
        "xterm.css" => vendored("text/css; charset=utf-8", XTERM_STYLE),
        "LICENSE" => vendored("text/plain; charset=utf-8", XTERM_LICENSE),
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn fit_file(Path(file): Path<String>) -> Response {
    match file.as_str() {
        "addon-fit.js" => vendored("text/javascript; charset=utf-8", FIT_SCRIPT),
        "LICENSE" => vendored("text/plain; charset=utf-8", FIT_LICENSE),
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}

/// Every state-changing admin route: a browser request from another site
/// is refused, a sibling subdomain (same site, other origin) included. A
/// browser says where a request comes from in `Sec-Fetch-Site` (only
/// `same-origin` and `none`, a typed address, pass) and in `Origin` (it
/// must be the request's own origin). A request with neither, from a
/// script or `curl`, carries no ambient cookie of a victim and passes on
/// to the usual checks.
pub(super) async fn same_origin_writes(request: Request, next: Next) -> Response {
    let changes = !matches!(
        *request.method(),
        axum::http::Method::GET | axum::http::Method::HEAD | axum::http::Method::OPTIONS
    );
    if changes && !written_here(request.headers()) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "this request came from another site and was refused" })),
        )
            .into_response();
    }
    next.run(request).await
}

/// Whether a state-changing request may be one this lore's page made.
fn written_here(headers: &HeaderMap) -> bool {
    if let Some(site) = headers
        .get("sec-fetch-site")
        .and_then(|value| value.to_str().ok())
        && !matches!(
            site.trim().to_ascii_lowercase().as_str(),
            "same-origin" | "none"
        )
    {
        return false;
    }
    !headers.contains_key(header::ORIGIN) || same_origin(headers)
}

/// Whether a request's `Origin` is the request's own origin: its host
/// (and port) is the `Host` the request was sent to. Browsers always send
/// `Origin` with a WebSocket, so a missing one is refused too.
fn same_origin(headers: &HeaderMap) -> bool {
    let header_text = |name| {
        headers
            .get(name)
            .and_then(|value: &HeaderValue| value.to_str().ok())
            .map(|value| value.trim().to_ascii_lowercase())
    };
    let (Some(origin), Some(host)) = (header_text(header::ORIGIN), header_text(header::HOST))
    else {
        return false;
    };
    let Some((scheme, authority)) = origin.split_once("://") else {
        return false;
    };
    let default_port = match scheme {
        "https" => ":443",
        "http" => ":80",
        _ => return false,
    };
    if authority.is_empty() || authority.contains(['/', '@', '?', '#']) {
        return false;
    }
    let plain = |value: &str| {
        value
            .strip_suffix(default_port)
            .unwrap_or(value)
            .to_string()
    };
    plain(authority) == plain(&host)
}

/// What the terminal page sends as text; typed bytes come as binary
/// frames.
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum PageFrame {
    Open {
        mode: TerminalMode,
        cols: u16,
        rows: u16,
    },
    Resize {
        cols: u16,
        rows: u16,
    },
    /// The page is shown: someone is looking, so the terminal is not idle.
    Alive,
    Close,
}

/// `GET /admin/api/builtin/{name}/terminal`: a WebSocket to a terminal in
/// the agent's container. The guard has already checked the session
/// cookie and the `agents` permission on the upgrade request; this checks
/// that the page asking is this lore's own.
async fn terminal(
    State(admin): State<Arc<Admin>>,
    Extension(me): Extension<SignedIn>,
    Path(name): Path<String>,
    headers: HeaderMap,
    upgrade: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
) -> Response {
    let (hub, name) = match target(&admin, &name) {
        Ok(found) => found,
        Err(status) => return status.into_response(),
    };
    if !same_origin(&headers) {
        tracing::warn!(agent = %name, user = %me.username, "a terminal request from another origin was refused");
        return forbidden("the terminal opens only from this lore's own admin page");
    }
    let upgrade = match upgrade {
        Ok(upgrade) => upgrade,
        Err(rejection) => return rejection.into_response(),
    };
    // The session this page is signed in with: looked at again while
    // the terminal is open. The guard has just accepted it.
    let Some(session) = super::cookie(&headers, super::COOKIE) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let state = admin.clone();
    let agent = name.clone();
    let model = tokio::task::spawn_blocking(move || state.db.builtin_agent(&agent))
        .await
        .ok()
        .and_then(Result::ok)
        .flatten()
        .map(|agent| agent.model)
        .filter(|model| !model.is_empty());
    upgrade
        .max_message_size(TERMINAL_FRAME_BYTES)
        .max_frame_size(TERMINAL_FRAME_BYTES)
        .on_upgrade(move |socket| relay(admin, hub, name, me.username, session, model, socket))
}

/// Sends one small JSON frame to the page.
async fn tell(socket: &mut WebSocket, value: serde_json::Value) -> bool {
    socket
        .send(WsMessage::text(value.to_string()))
        .await
        .is_ok()
}

/// One page and one terminal, from the page's `open` to either side's end.
/// While it is open, the page's session and its `agents` permission are
/// checked again every `terminal_recheck` (30 seconds): a terminal does
/// not outlive the sign-in or the permission it was opened with.
async fn relay(
    admin: Arc<Admin>,
    hub: Arc<Hub>,
    agent: String,
    who: String,
    session: String,
    model: Option<String>,
    mut socket: WebSocket,
) {
    let open = tokio::time::timeout(TERMINAL_OPEN_WAIT, async {
        while let Some(Ok(frame)) = socket.recv().await {
            match frame {
                WsMessage::Text(text) => {
                    return serde_json::from_str::<PageFrame>(text.as_str()).ok();
                }
                WsMessage::Close(_) => return None,
                _ => {}
            }
        }
        None
    })
    .await
    .ok()
    .flatten();
    let Some(PageFrame::Open { mode, cols, rows }) = open else {
        tell(
            &mut socket,
            json!({ "type": "error", "message": "the page did not say what to open" }),
        )
        .await;
        return;
    };
    let (term_id, mut events) = match hub.terminal_open(&agent, mode, cols, rows, model).await {
        Ok(opened) => opened,
        Err(error) => {
            tell(
                &mut socket,
                json!({ "type": "error", "message": error.to_string() }),
            )
            .await;
            return;
        }
    };
    let what = match mode {
        TerminalMode::Cli => "the CLI's terminal",
        TerminalMode::Shell => "a shell",
    };
    note_activity(
        &admin,
        "builtin",
        &format!("{who} opened {what} in {agent}"),
    );
    tracing::info!(%agent, user = %who, %term_id, ?mode, "a terminal opened");
    let mut ended = false;
    let mut recheck = tokio::time::interval_at(
        tokio::time::Instant::now() + admin.terminal_recheck,
        admin.terminal_recheck,
    );
    recheck.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    if tell(&mut socket, json!({ "type": "opened" })).await {
        loop {
            tokio::select! {
                _ = recheck.tick() => {
                    if let Err(why) = admin.terminal_access(&session) {
                        tracing::info!(%agent, user = %who, %term_id, "a terminal was closed: its session or permission is gone");
                        tell(&mut socket, json!({ "type": "exit", "code": null, "message": why })).await;
                        break;
                    }
                }
                frame = socket.recv() => {
                    let command = match frame {
                        Some(Ok(WsMessage::Binary(bytes))) => ToRunner::TerminalInput {
                            term_id: term_id.clone(),
                            data: base64::engine::general_purpose::STANDARD.encode(&bytes),
                        },
                        Some(Ok(WsMessage::Text(text))) => match serde_json::from_str::<PageFrame>(text.as_str()) {
                            Ok(PageFrame::Resize { cols, rows }) => ToRunner::TerminalResize {
                                term_id: term_id.clone(),
                                cols,
                                rows,
                            },
                            // An empty input types nothing and keeps the
                            // terminal from being closed as idle.
                            Ok(PageFrame::Alive) => ToRunner::TerminalInput {
                                term_id: term_id.clone(),
                                data: String::new(),
                            },
                            Ok(PageFrame::Close) => break,
                            Ok(PageFrame::Open { .. }) | Err(_) => continue,
                        },
                        Some(Ok(WsMessage::Close(_))) | Some(Err(_)) | None => break,
                        Some(Ok(_)) => continue,
                    };
                    if hub.terminal_send(&term_id, command).await.is_err() {
                        break;
                    }
                }
                event = events.recv() => match event {
                    Some(TerminalEvent::Output(bytes)) => {
                        if socket.send(WsMessage::Binary(bytes.into())).await.is_err() {
                            break;
                        }
                    }
                    Some(TerminalEvent::Exit { code, message }) => {
                        ended = true;
                        tell(&mut socket, json!({ "type": "exit", "code": code, "message": message })).await;
                        break;
                    }
                    None => {
                        ended = true;
                        tell(&mut socket, json!({
                            "type": "exit",
                            "code": null,
                            "message": "the terminal ended: the agent's container disconnected, or this page fell behind",
                        }))
                        .await;
                        break;
                    }
                },
            }
        }
    }
    if !ended {
        hub.terminal_close(&term_id).await;
    }
    let _ = socket.send(WsMessage::Close(None)).await;
    tracing::info!(%agent, %term_id, "a terminal's page closed");
}

/// The hub and a built-in agent's name from a path, or the answer to send.
fn target(admin: &Admin, name: &str) -> Result<(Arc<Hub>, String), StatusCode> {
    let Some(hub) = admin.builtin.clone() else {
        return Err(StatusCode::NOT_FOUND);
    };
    let name = name.trim().to_lowercase();
    if !hub.is_builtin(&name) {
        return Err(StatusCode::NOT_FOUND);
    }
    Ok((hub, name))
}

fn unreachable_runner(error: HubError) -> Response {
    (
        StatusCode::CONFLICT,
        Json(json!({ "error": error.to_string() })),
    )
        .into_response()
}

/// The kind of a built-in agent: what its runner said, else what was
/// stored, else what its name suggests.
fn kind_of(hub: &Hub, name: &str, stored: &str) -> Option<Kind> {
    hub.link(name)
        .map(|(kind, _)| kind)
        .or_else(|| Kind::parse(stored))
        .or_else(|| Kind::parse(crate::builtin::kind_and_avatar(name).0))
}

/// One built-in agent as the page shows it. The sign-in prompt goes only
/// to someone who may finish it.
fn agent_view(
    admin: &Admin,
    hub: &Hub,
    name: &str,
    manage: bool,
) -> anyhow::Result<serde_json::Value> {
    let stored = admin
        .db
        .builtin_agent(name)?
        .ok_or_else(|| anyhow::anyhow!("the built-in agent {name} has no row"))?;
    let registry = admin.db.registry_agent(name)?;
    let avatar = registry
        .as_ref()
        .map(|agent| avatars::effective(name, &agent.avatar).to_string())
        .unwrap_or_else(|| avatars::default_for(name).to_string());
    let display_name = registry.and_then(|agent| agent.display_name);
    let kind = kind_of(hub, name, &stored.kind);
    let link = hub.link(name);
    let provider = link
        .as_ref()
        .map(|(_, provider)| provider.clone())
        .unwrap_or_else(|| stored.provider.clone());
    let models = hub.models(name).map(|list| json!(list)).unwrap_or_else(|| {
        // Until the runner is asked: what is known without it.
        let known: Vec<&str> = match kind {
            Some(Kind::Claude) => CLAUDE_MODELS.to_vec(),
            Some(Kind::Opencode) if provider == "deepseek" || provider.is_empty() => {
                DEEPSEEK_MODELS.to_vec()
            }
            _ => Vec::new(),
        };
        json!({ "models": known, "source": "known" })
    });
    let methods: Vec<&str> = kind
        .map(|kind| kind.login_methods().iter().map(|m| m.id()).collect())
        .unwrap_or_default();
    let credentials: Vec<serde_json::Value> = kind
        .map(|kind| {
            kind.credentials()
                .iter()
                .map(|c| json!({ "id": c.id(), "label": c.label() }))
                .collect()
        })
        .unwrap_or_default();
    Ok(json!({
        "name": stored.name,
        // What the page shows; `name` stays the identity.
        "display_name": display_name,
        "kind": kind.map(Kind::id),
        "provider": provider,
        "avatar": avatar,
        "model": stored.model,
        "enabled": stored.enabled,
        "available": stored.available,
        "daily_cap": stored.daily_cap,
        "active_hours": stored.active_hours,
        "connected": link.is_some(),
        "connected_at": stored.connected_at,
        "last_seen_at": stored.last_seen_at,
        "runner_version": stored.runner_version,
        "cli_version": stored.cli_version,
        "signed_in": stored.signed_in,
        "login_method": stored.login_method,
        "login_ends": stored.login_ends,
        // What the CLI said may name the account (an e-mail address).
        "status_detail": if manage { Some(&stored.status_detail) } else { None },
        "read_other_services": stored.read_other_services,
        // NULL in the database: what the agent may.
        "terminal_services": stored.terminal_services.as_deref().unwrap_or("same"),
        "second_runner": if manage { hub.intrusion(name) } else { None },
        "status_at": stored.status_at,
        "updated_at": stored.updated_at,
        "updated_by": stored.updated_by,
        "models": models,
        "resources": hub.resources(name),
        "methods": methods,
        "credentials": credentials,
        "login": if manage { hub.login_state(name).map(|login| json!(login)) } else { None },
    }))
}

/// `GET /admin/api/builtin`: every built-in agent. Without
/// `LORE_RUNNER_TOKENS` the answer says none is configured and the page
/// shows nothing.
async fn list(State(admin): State<Arc<Admin>>, Extension(me): Extension<SignedIn>) -> Response {
    let Some(hub) = admin.builtin.clone() else {
        return Json(json!({ "configured": false, "agents": [] })).into_response();
    };
    let manage = me.perms.contains(Perm::Agents);
    let state = admin.clone();
    let result = tokio::task::spawn_blocking(move || -> anyhow::Result<serde_json::Value> {
        let agents = hub
            .agents()
            .iter()
            .map(|name| agent_view(&state, &hub, name, manage))
            .collect::<anyhow::Result<Vec<_>>>()?;
        Ok(json!({
            "configured": true,
            "manage": manage,
            "agents": agents,
            "claude_models": CLAUDE_MODELS,
            "max_daily_cap": MAX_DAILY_CAP,
        }))
    })
    .await;
    respond(result)
}

async fn one(admin: &Arc<Admin>, hub: Arc<Hub>, name: String) -> Response {
    let state = admin.clone();
    let result = tokio::task::spawn_blocking(move || -> anyhow::Result<serde_json::Value> {
        Ok(json!({ "agent": agent_view(&state, &hub, &name, true)? }))
    })
    .await;
    respond(result)
}

#[derive(Deserialize)]
struct SettingsForm {
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    available: Option<bool>,
    #[serde(default)]
    daily_cap: Option<i64>,
    #[serde(default)]
    active_hours: Option<String>,
    #[serde(default)]
    read_other_services: Option<bool>,
    /// `same`, `read` or `off`.
    #[serde(default)]
    terminal_services: Option<String>,
}

/// A model name: an alias or an id, no spaces, not starting with `-` (it
/// is a CLI argument). Empty is the CLI's default.
fn valid_model(model: &str) -> bool {
    !model.starts_with('-')
        && model.chars().count() <= MODEL_MAX_CHARS
        && model.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':' | '/' | '@' | '[' | ']')
        })
}

/// `HH:MM-HH:MM` (UTC), or empty for always.
pub(super) fn valid_hours(hours: &str) -> bool {
    if hours.is_empty() {
        return true;
    }
    let time = |text: &str| -> bool {
        let Some((h, m)) = text.split_once(':') else {
            return false;
        };
        h.len() == 2
            && m.len() == 2
            && h.parse::<u8>().is_ok_and(|h| h < 24)
            && m.parse::<u8>().is_ok_and(|m| m < 60)
    };
    match hours.split_once('-') {
        Some((from, to)) => time(from) && time(to) && from != to,
        None => false,
    }
}

/// `PUT /admin/api/builtin/{name}`: the owner's settings.
async fn update(
    State(admin): State<Arc<Admin>>,
    Extension(me): Extension<SignedIn>,
    Path(name): Path<String>,
    Json(form): Json<SettingsForm>,
) -> Response {
    let (hub, name) = match target(&admin, &name) {
        Ok(found) => found,
        Err(status) => return status.into_response(),
    };
    let model = form.model.map(|model| model.trim().to_string());
    if model.as_deref().is_some_and(|model| !valid_model(model)) {
        return bad_request(&format!(
            "the model must be a name or alias of at most {MODEL_MAX_CHARS} characters, without \
             spaces"
        ));
    }
    if form
        .daily_cap
        .is_some_and(|cap| !(0..=MAX_DAILY_CAP).contains(&cap))
    {
        return bad_request(&format!(
            "the daily cap must be between 0 and {MAX_DAILY_CAP}"
        ));
    }
    let active_hours = form.active_hours.map(|hours| hours.trim().to_string());
    if active_hours
        .as_deref()
        .is_some_and(|hours| !valid_hours(hours))
    {
        return bad_request(
            "active hours must look like 08:00-20:00 (UTC), or be empty for always",
        );
    }
    let settings = BuiltinSettings {
        model,
        enabled: form.enabled,
        available: form.available,
        daily_cap: form.daily_cap,
        active_hours,
    };
    let state = admin.clone();
    let (who, agent) = (me.username.clone(), name.clone());
    let read_other_services = form.read_other_services;
    let terminal_services = match form.terminal_services.as_deref().map(str::trim) {
        None => None,
        Some("same") => Some(None),
        Some(value @ ("read" | "off")) => Some(Some(value.to_string())),
        Some(_) => return bad_request("the terminal's services are same, read or off"),
    };
    let result = tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
        let before = state.db.builtin_agent(&agent)?;
        let mut after = state.db.update_builtin_settings(&agent, &settings, &who)?;
        if let Some(on) = read_other_services
            && on != after.read_other_services
        {
            state.db.set_builtin_read_other_services(&agent, on, &who)?;
            after.read_other_services = on;
        }
        if let Some(services) = terminal_services
            && services != after.terminal_services
        {
            state
                .db
                .set_builtin_terminal_services(&agent, services.as_deref(), &who)?;
            after.terminal_services = services;
        }
        if before.as_ref() != Some(&after) {
            let mut changes = Vec::new();
            if let Some(before) = &before {
                if before.model != after.model {
                    let model = if after.model.is_empty() {
                        "the default"
                    } else {
                        &after.model
                    };
                    changes.push(format!("model {model}"));
                }
                if before.enabled != after.enabled {
                    changes.push(if after.enabled { "enabled" } else { "disabled" }.to_string());
                }
                if before.available != after.available {
                    changes.push(
                        if after.available {
                            "available for help"
                        } else {
                            "not available for help"
                        }
                        .to_string(),
                    );
                }
                if before.daily_cap != after.daily_cap {
                    changes.push(format!("daily cap {}", after.daily_cap));
                }
                if before.read_other_services != after.read_other_services {
                    changes.push(
                        if after.read_other_services {
                            "may read other services during runs"
                        } else {
                            "reads only its task's services during runs"
                        }
                        .to_string(),
                    );
                }
                if before.terminal_services != after.terminal_services {
                    changes.push(format!(
                        "services in the terminal: {}",
                        match after.terminal_services.as_deref() {
                            Some("read") => "read only",
                            Some("off") => "off",
                            _ => "same as the agent",
                        }
                    ));
                }
                if before.active_hours != after.active_hours {
                    let hours = if after.active_hours.is_empty() {
                        "always"
                    } else {
                        &after.active_hours
                    };
                    changes.push(format!("active {hours}"));
                }
            }
            if !changes.is_empty() {
                note_activity(
                    &state,
                    "builtin",
                    &format!("{who} set {agent}: {}", changes.join(", ")),
                );
            }
        }
        Ok(())
    })
    .await;
    match result {
        Ok(Ok(())) => one(&admin, hub, name).await,
        Ok(Err(error)) => bad_request(&error.to_string()),
        Err(error) => {
            tracing::error!(%error, "saving a built-in agent failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// `POST /admin/api/builtin/{name}/refresh`: asks the runner for its
/// sign-in state and its models.
async fn refresh(State(admin): State<Arc<Admin>>, Path(name): Path<String>) -> Response {
    let (hub, name) = match target(&admin, &name) {
        Ok(found) => found,
        Err(status) => return status.into_response(),
    };
    let (status, models) = tokio::join!(
        hub.request(
            &name,
            |id| ToRunner::Status { id },
            STATUS_WAIT
        ),
        hub.request(&name, |id| ToRunner::ListModels { id }, MODELS_WAIT),
    );
    if let Err(error) = status.and(models) {
        return unreachable_runner(error);
    }
    one(&admin, hub, name).await
}

#[derive(Deserialize)]
struct LoginForm {
    method: LoginMethod,
}

/// `POST /admin/api/builtin/{name}/login`: starts an interactive sign-in
/// and answers with what the owner must do.
async fn login_start(
    State(admin): State<Arc<Admin>>,
    Extension(me): Extension<SignedIn>,
    Path(name): Path<String>,
    Json(form): Json<LoginForm>,
) -> Response {
    let (hub, name) = match target(&admin, &name) {
        Ok(found) => found,
        Err(status) => return status.into_response(),
    };
    let Some((kind, _)) = hub.link(&name) else {
        return unreachable_runner(HubError::NotConnected);
    };
    if !kind.login_methods().contains(&form.method) {
        return bad_request(&format!(
            "{} has no {} sign-in; paste a credential instead",
            kind.id(),
            form.method.id()
        ));
    }
    let mut started = 0;
    let answer = hub
        .request(
            &name,
            |id| {
                started = id;
                hub.login_started(&name, id, form.method.id());
                ToRunner::LoginStart {
                    id,
                    method: form.method,
                }
            },
            LOGIN_WAIT,
        )
        .await;
    match answer {
        Ok(FromRunner::LoginPrompt { .. }) => {
            note_activity(
                &admin,
                "builtin",
                &format!(
                    "{} started a {} sign-in of {name}",
                    me.username,
                    form.method.id()
                ),
            );
            one(&admin, hub, name).await
        }
        Ok(FromRunner::Error { message, .. }) => {
            hub.login_failed(&name, started, &message);
            bad_request(&message)
        }
        Ok(other) => {
            tracing::warn!(agent = %name, answer = ?other, "an unexpected answer to a sign-in");
            hub.login_failed(&name, started, "the runner answered something unexpected");
            StatusCode::BAD_GATEWAY.into_response()
        }
        Err(error) => {
            hub.login_failed(&name, started, &error.to_string());
            unreachable_runner(error)
        }
    }
}

#[derive(Deserialize, Debug)]
struct CodeForm {
    code: Secret,
}

/// `POST /admin/api/builtin/{name}/login/code`: the code the browser
/// showed, for `claude auth login`.
async fn login_code(
    State(admin): State<Arc<Admin>>,
    Path(name): Path<String>,
    Json(form): Json<CodeForm>,
) -> Response {
    let (hub, name) = match target(&admin, &name) {
        Ok(found) => found,
        Err(status) => return status.into_response(),
    };
    let code = Secret::new(form.code.expose().trim());
    if code.expose().is_empty() || code.expose().len() > 4096 {
        return bad_request("paste the code the sign-in page showed");
    }
    match hub
        .request(&name, |id| ToRunner::LoginCode { id, code }, QUICK_WAIT)
        .await
    {
        Ok(FromRunner::Done { .. }) => one(&admin, hub, name).await,
        Ok(FromRunner::Error { message, .. }) => bad_request(&message),
        Ok(_) => StatusCode::BAD_GATEWAY.into_response(),
        Err(error) => unreachable_runner(error),
    }
}

/// `POST /admin/api/builtin/{name}/login/cancel`.
async fn login_cancel(State(admin): State<Arc<Admin>>, Path(name): Path<String>) -> Response {
    let (hub, name) = match target(&admin, &name) {
        Ok(found) => found,
        Err(status) => return status.into_response(),
    };
    hub.clear_login(&name);
    if hub.link(&name).is_some()
        && let Err(error) = hub
            .request(&name, |id| ToRunner::LoginCancel { id }, QUICK_WAIT)
            .await
    {
        return unreachable_runner(error);
    }
    one(&admin, hub, name).await
}

#[derive(Deserialize, Debug)]
struct CredentialForm {
    credential: CredentialKind,
    value: Secret,
}

/// `POST /admin/api/builtin/{name}/credential`: a pasted token,
/// `auth.json` or API key, passed straight to the runner, which writes it
/// into the agent's volume. Never stored, logged or sent back here.
async fn credential(
    State(admin): State<Arc<Admin>>,
    Extension(me): Extension<SignedIn>,
    Path(name): Path<String>,
    Json(form): Json<CredentialForm>,
) -> Response {
    let (hub, name) = match target(&admin, &name) {
        Ok(found) => found,
        Err(status) => return status.into_response(),
    };
    let Some((kind, _)) = hub.link(&name) else {
        return unreachable_runner(HubError::NotConnected);
    };
    if !kind.credentials().contains(&form.credential) {
        return bad_request(&format!(
            "a {} cannot sign {} in",
            form.credential.label(),
            kind.id()
        ));
    }
    let value = form.value.expose().trim();
    if value.is_empty() {
        return bad_request(&format!("paste the {}", form.credential.label()));
    }
    if value.len() > MAX_CREDENTIAL_BYTES {
        return bad_request(&format!("the {} is too long", form.credential.label()));
    }
    let pasted = value.to_string();
    let value = Secret::new(value);
    let answer = hub
        .request(
            &name,
            |id| ToRunner::SetCredential {
                id,
                credential: form.credential,
                value,
            },
            STATUS_WAIT,
        )
        .await;
    match answer {
        Ok(FromRunner::Done { .. }) => {
            // The page shows the sign-in state the stored credential gives.
            let _ = hub
                .request(
                    &name,
                    |id| ToRunner::Status { id },
                    STATUS_WAIT,
                )
                .await;
            note_activity(
                &admin,
                "builtin",
                &format!(
                    "{} stored a {} in the volume of {name}",
                    me.username,
                    form.credential.label()
                ),
            );
            tracing::info!(agent = %name, credential = form.credential.id(), "a built-in agent's credential was stored in its volume");
            one(&admin, hub, name).await
        }
        Ok(FromRunner::Error { message, .. }) => {
            bad_request(&crate::runner::drivers::redact_with(&message, &[pasted]))
        }
        Ok(_) => StatusCode::BAD_GATEWAY.into_response(),
        Err(error) => unreachable_runner(error),
    }
}

/// `POST /admin/api/builtin/{name}/logout`: removes the stored sign-in
/// from the agent's volume.
async fn logout(
    State(admin): State<Arc<Admin>>,
    Extension(me): Extension<SignedIn>,
    Path(name): Path<String>,
) -> Response {
    let (hub, name) = match target(&admin, &name) {
        Ok(found) => found,
        Err(status) => return status.into_response(),
    };
    hub.clear_login(&name);
    match hub
        .request(&name, |id| ToRunner::Logout { id }, STATUS_WAIT)
        .await
    {
        Ok(FromRunner::Done { .. }) => {
            let _ = hub
                .request(
                    &name,
                    |id| ToRunner::Status { id },
                    STATUS_WAIT,
                )
                .await;
            note_activity(
                &admin,
                "builtin",
                &format!("{} signed {name} out", me.username),
            );
            one(&admin, hub, name).await
        }
        Ok(FromRunner::Error { message, .. }) => bad_request(&message),
        Ok(_) => StatusCode::BAD_GATEWAY.into_response(),
        Err(error) => unreachable_runner(error),
    }
}

/// `GET /admin/api/builtin/runs`: the task runner's queue, the runs going
/// on and the history. Output lines are read from `…/runs/{id}/events`
/// and arrive live as `run` events on the stream.
async fn runs(State(admin): State<Arc<Admin>>, Extension(me): Extension<SignedIn>) -> Response {
    let Some(runner) = admin.task_runner.clone() else {
        return Json(json!({ "configured": false })).into_response();
    };
    let manage = me.perms.contains(Perm::Agents);
    let result = async {
        let active = runner.active().await?;
        let queue = runner.queue().await?;
        let readiness = runner.readiness().await?;
        let db = admin.db.clone();
        let history = tokio::task::spawn_blocking(move || db.runs(40)).await??;
        let mut history = serde_json::to_value(history)?;
        let mut active = serde_json::to_value(active)?;
        if !manage {
            // What a run said (its summary may quote output) is for the
            // `agents` permission only.
            for list in [&mut history, &mut active] {
                if let Some(runs) = list.as_array_mut() {
                    for run in runs.iter_mut().filter_map(|run| run.as_object_mut()) {
                        for field in ["summary", "answer", "last_words", "last_text"] {
                            run.remove(field);
                        }
                    }
                }
            }
        }
        let settings = runner.settings();
        anyhow::Ok(json!({
            "configured": true,
            "manage": manage,
            "active": active,
            "queue": queue,
            "agents": readiness,
            "history": history,
            "settings": {
                "idle_minutes": settings.idle_minutes,
                "hard_limit_minutes": settings.hard_limit.as_secs() / 60,
                "wall_clock_minutes": settings.wall_clock.as_secs() / 60,
                "output_cap_bytes": settings.output_cap_bytes,
            },
        }))
    }
    .await;
    match result {
        Ok(value) => Json(value).into_response(),
        Err(error) => {
            tracing::error!(error = %format!("{error:#}"), "reading the task runner failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// `GET /admin/api/builtin/active`: the runs going on, for the graph when
/// the page loads. Empty without built-in agents.
async fn active(State(admin): State<Arc<Admin>>) -> Response {
    let Some(runner) = admin.task_runner.clone() else {
        return Json(json!({ "runs": [] })).into_response();
    };
    match runner.active().await {
        Ok(runs) => {
            let runs: Vec<serde_json::Value> = runs
                .into_iter()
                .map(|run| {
                    json!({
                        "run_id": run["id"],
                        "agent": run["agent"],
                        "avatar": run["avatar"],
                        "project": run["project"],
                    })
                })
                .collect();
            Json(json!({ "runs": runs })).into_response()
        }
        Err(error) => {
            tracing::error!(error = %format!("{error:#}"), "reading the active runs failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[derive(Deserialize)]
struct EventsQuery {
    #[serde(default)]
    after: Option<i64>,
}

/// `GET /admin/api/builtin/runs/{id}/events?after=N`: a run's stored
/// output, already redacted, read-only for everyone signed in.
async fn run_events(
    State(admin): State<Arc<Admin>>,
    Path(id): Path<String>,
    Query(query): Query<EventsQuery>,
) -> Response {
    if admin.task_runner.is_none() {
        return StatusCode::NOT_FOUND.into_response();
    }
    let db = admin.db.clone();
    let after = query.after.unwrap_or(0);
    let result =
        tokio::task::spawn_blocking(move || -> anyhow::Result<Option<serde_json::Value>> {
            let Some(run) = db.run(&id)? else {
                return Ok(None);
            };
            let events = db.run_events(&id, after, crate::db::RUN_EVENTS_KEPT as usize)?;
            Ok(Some(json!({ "run": run, "events": events })))
        })
        .await;
    match result {
        Ok(Ok(Some(value))) => Json(value).into_response(),
        Ok(Ok(None)) => StatusCode::NOT_FOUND.into_response(),
        _ => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// `POST /admin/api/builtin/{name}/stop`: stops the agent's run. Its token
/// dies at once; the runner interrupts the CLI and deletes the work.
async fn stop(
    State(admin): State<Arc<Admin>>,
    Extension(me): Extension<SignedIn>,
    Path(name): Path<String>,
) -> Response {
    let (_, name) = match target(&admin, &name) {
        Ok(found) => found,
        Err(status) => return status.into_response(),
    };
    let Some(runner) = admin.task_runner.clone() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    match runner.stop(&name).await {
        Ok(true) => {
            note_activity(
                &admin,
                "builtin",
                &format!("{} stopped the run of {name}", me.username),
            );
            Json(json!({ "stopped": true })).into_response()
        }
        Ok(false) => bad_request(&format!("{name} has no run going")),
        Err(error) => {
            tracing::error!(error = %format!("{error:#}"), "stopping a run failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_are_validated() {
        for ok in ["", "08:00-20:00", "22:00-06:30"] {
            assert!(valid_hours(ok), "{ok}");
        }
        for bad in ["8-20", "24:00-01:00", "08:00-08:00", "08:00", "08:60-09:00"] {
            assert!(!valid_hours(bad), "{bad}");
        }
        for ok in [
            "",
            "sonnet",
            "gpt-5.5",
            "deepseek-v4-pro",
            "claude-opus-4-1[1m]",
        ] {
            assert!(valid_model(ok), "{ok}");
        }
        for bad in ["two words", "x;rm", &"m".repeat(101), "-x", "--model=evil"] {
            assert!(!valid_model(bad), "{bad}");
        }
    }

    #[test]
    fn every_route_is_in_the_access_table() {
        for (method, path, _) in ROUTES {
            assert!(
                access(&method.parse().unwrap(), path).is_some(),
                "{method} {path}"
            );
        }
    }
}
