//! The admin view: password login with two roles (optionally guarded by
//! reCAPTCHA v3), a session cookie, and the JSON the brain visualisation draws.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use std::convert::Infallible;

use axum::{
    Json, Router,
    extract::{ConnectInfo, DefaultBodyLimit, Path, Query, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{
        IntoResponse, Response,
        sse::{Event, KeepAlive, Sse},
    },
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::json;
use subtle::ConstantTimeEq;
use tokio_stream::{Stream, StreamExt, wrappers::BroadcastStream};

use crate::{
    auth::{RateLimiter, client_ip, too_many_requests},
    db::{Backup, Db},
    embed::Embedder,
    events::Events,
};

const COOKIE: &str = "lore_session";
const SESSION_TTL: Duration = Duration::from_secs(12 * 60 * 60);
/// Newest entries drawn in the graph; older ones stay searchable over MCP.
const MAX_NEURONS: usize = 1200;
const NEIGHBOURS: usize = 3;
const RECAPTCHA_ACTION: &str = "login";
/// Actions shown in the feed when the page opens.
const FEED_LENGTH: usize = 60;
/// Largest backup file accepted for import.
const MAX_BACKUP_BYTES: usize = 512 * 1024 * 1024;
/// Name the feed shows for actions taken from this page.
const ADMIN_ACTOR: &str = "admin";
const ICON: &str = include_str!("../assets/icon.svg");
const BACKDROP: &[u8] = include_bytes!("../assets/backdrop.jpg");

const PAGE: &str = include_str!("../assets/admin.html");
const SCRIPT: &str = include_str!("../assets/admin.js");
const STYLE: &str = include_str!("../assets/admin.css");

const CSP: &str = "default-src 'none'; script-src 'self' https://www.google.com/recaptcha/ \
https://www.gstatic.com/recaptcha/; style-src 'self'; img-src 'self' data:; connect-src 'self'; \
frame-src https://www.google.com/recaptcha/ https://recaptcha.google.com/recaptcha/; \
base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

pub struct Recaptcha {
    pub site_key: String,
    pub secret: String,
    pub min_score: f64,
}

/// What a signed-in session may do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Role {
    /// Everything, including backup export, import and restore.
    Admin,
    /// Watch only: the graph, the activity feed and entries.
    Viewer,
}

impl Role {
    fn name(self) -> &'static str {
        match self {
            Role::Admin => "admin",
            Role::Viewer => "viewer",
        }
    }
}

pub struct Admin {
    pub db: Db,
    pub password: String,
    /// A second password that signs in with the watch-only role.
    pub viewer_password: Option<String>,
    pub recaptcha: Option<Recaptcha>,
    pub trust_proxy: bool,
    /// Agent names that hold a token, so idle ones are listed too.
    pub configured_agents: Vec<String>,
    pub embedding_model: Option<&'static str>,
    pub link_similarity: f32,
    pub events: Events,
    pub embedder: Embedder,
    sessions: Mutex<HashMap<String, (Instant, Role)>>,
    logins: RateLimiter,
    http: reqwest::Client,
}

impl Admin {
    pub fn new(
        db: Db,
        password: String,
        viewer_password: Option<String>,
        recaptcha: Option<Recaptcha>,
        trust_proxy: bool,
        configured_agents: Vec<String>,
        embedding_model: Option<&'static str>,
        link_similarity: f32,
        events: Events,
        embedder: Embedder,
    ) -> Self {
        Self {
            db,
            password,
            viewer_password,
            recaptcha,
            trust_proxy,
            configured_agents,
            embedding_model,
            link_similarity,
            events,
            embedder,
            sessions: Mutex::new(HashMap::new()),
            // Five wrong attempts lock the address out for fifteen minutes.
            logins: RateLimiter::new(5, Duration::from_secs(15 * 60)),
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(8))
                .build()
                .expect("building the HTTP client"),
        }
    }

    /// The role of the session a request carries, if it has a live one.
    fn session_role(&self, headers: &HeaderMap) -> Option<Role> {
        let token = cookie(headers, COOKIE)?;
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        sessions.retain(|_, (expires, _)| *expires > Instant::now());
        sessions.get(&token).map(|(_, role)| *role)
    }
}

pub fn router(admin: Arc<Admin>) -> Router {
    // Open to both roles.
    let private = Router::new()
        .route("/admin/api/brain", get(brain))
        .route("/admin/api/pulse", get(pulse))
        .route("/admin/api/events", get(events))
        .route("/admin/api/entries/{id}", get(entry))
        .layer(middleware::from_fn_with_state(
            admin.clone(),
            require_session,
        ));
    // Backups carry the whole store, so only the admin role reaches them.
    let admin_only = Router::new()
        .route("/admin/api/export", get(export))
        .route(
            "/admin/api/import",
            post(import).layer(DefaultBodyLimit::max(MAX_BACKUP_BYTES)),
        )
        .layer(middleware::from_fn_with_state(admin.clone(), require_admin));

    Router::new()
        .route(
            "/admin",
            get(|| async { asset("text/html; charset=utf-8", PAGE) }),
        )
        .route(
            "/admin/app.js",
            get(|| async { asset("text/javascript; charset=utf-8", SCRIPT) }),
        )
        .route(
            "/admin/app.css",
            get(|| async { asset("text/css; charset=utf-8", STYLE) }),
        )
        .route(
            "/admin/icon.svg",
            get(|| async { asset("image/svg+xml", ICON) }),
        )
        .route(
            "/admin/backdrop.jpg",
            get(|| async { ([(header::CONTENT_TYPE, "image/jpeg")], BACKDROP) }),
        )
        .route("/admin/api/session", get(session))
        .route("/admin/api/login", post(login))
        .route("/admin/api/logout", post(logout))
        .merge(private)
        .merge(admin_only)
        .layer(middleware::from_fn(security_headers))
        .with_state(admin)
}

fn asset(content_type: &'static str, body: &'static str) -> Response {
    ([(header::CONTENT_TYPE, content_type)], body).into_response()
}

async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CSP),
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
    response
}

async fn require_session(
    State(admin): State<Arc<Admin>>,
    request: Request,
    next: Next,
) -> Response {
    if admin.session_role(request.headers()).is_some() {
        next.run(request).await
    } else {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "sign in first" })),
        )
            .into_response()
    }
}

async fn require_admin(State(admin): State<Arc<Admin>>, request: Request, next: Next) -> Response {
    match admin.session_role(request.headers()) {
        Some(Role::Admin) => next.run(request).await,
        Some(Role::Viewer) => (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "this needs the admin password" })),
        )
            .into_response(),
        None => (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "sign in first" })),
        )
            .into_response(),
    }
}

/// Tells the page whether it is signed in and which reCAPTCHA key to load.
async fn session(State(admin): State<Arc<Admin>>, headers: HeaderMap) -> Json<serde_json::Value> {
    let role = admin.session_role(&headers);
    Json(json!({
        "authenticated": role.is_some(),
        "role": role.map(Role::name),
        "recaptcha_site_key": admin.recaptcha.as_ref().map(|r| r.site_key.as_str()),
    }))
}

#[derive(Deserialize)]
struct LoginForm {
    password: String,
    #[serde(default)]
    captcha: String,
}

async fn login(
    State(admin): State<Arc<Admin>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(form): Json<LoginForm>,
) -> Response {
    let ip = client_ip(&headers, Some(peer), admin.trust_proxy);
    if let Some(retry_after) = admin.logins.blocked(&ip) {
        return too_many_requests(retry_after);
    }

    if let Some(recaptcha) = &admin.recaptcha {
        if let Err(reason) = verify_captcha(&admin.http, recaptcha, &form.captcha, &ip).await {
            tracing::warn!(%ip, %reason, "admin login rejected by reCAPTCHA");
            admin.logins.hit(&ip);
            return (
                StatusCode::FORBIDDEN,
                Json(json!({ "error": "The request looked automated. Try again." })),
            )
                .into_response();
        }
    }

    // Check both passwords every time so timing does not tell them apart.
    let presented = form.password.as_bytes();
    let is_admin = bool::from(presented.ct_eq(admin.password.as_bytes()));
    let is_viewer = admin
        .viewer_password
        .as_ref()
        .is_some_and(|viewer| bool::from(presented.ct_eq(viewer.as_bytes())));
    let role = match (is_admin, is_viewer) {
        (true, _) => Some(Role::Admin),
        (false, true) => Some(Role::Viewer),
        (false, false) => None,
    };
    let Some(role) = role else {
        tracing::warn!(%ip, "admin login with a wrong password");
        admin.logins.hit(&ip);
        tokio::time::sleep(Duration::from_millis(400)).await;
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "Wrong password." })),
        )
            .into_response();
    };

    admin.logins.reset(&ip);
    let token = match random_token() {
        Ok(token) => token,
        Err(error) => {
            tracing::error!(%error, "no randomness for a session token");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    admin
        .sessions
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(token.clone(), (Instant::now() + SESSION_TTL, role));
    tracing::info!(%ip, role = role.name(), "signed in to the admin view");
    let cookie = format!(
        "{COOKIE}={token}; Path=/admin; HttpOnly; Secure; SameSite=Strict; Max-Age={}",
        SESSION_TTL.as_secs()
    );
    (
        [(header::SET_COOKIE, cookie)],
        Json(json!({ "ok": true, "role": role.name() })),
    )
        .into_response()
}

async fn logout(State(admin): State<Arc<Admin>>, headers: HeaderMap) -> Response {
    if let Some(token) = cookie(&headers, COOKIE) {
        admin
            .sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&token);
    }
    let expired = format!("{COOKIE}=; Path=/admin; HttpOnly; Secure; SameSite=Strict; Max-Age=0");
    ([(header::SET_COOKIE, expired)], Json(json!({ "ok": true }))).into_response()
}

/// Everything the visualisation draws.
async fn brain(State(admin): State<Arc<Admin>>) -> Response {
    let state = admin.clone();
    let result = tokio::task::spawn_blocking(move || -> anyhow::Result<serde_json::Value> {
        let brain = state
            .db
            .brain(MAX_NEURONS, NEIGHBOURS, state.link_similarity)?;
        Ok(json!({
            "version": state.db.version()?,
            "embedding_model": state.embedding_model,
            "agents": state.db.agents(&state.configured_agents)?,
            "activity": state.db.activity(FEED_LENGTH)?,
            "brain": brain,
        }))
    })
    .await;
    respond(result)
}

/// A cheap poll: the data version and who is connected.
async fn pulse(State(admin): State<Arc<Admin>>) -> Response {
    let state = admin.clone();
    let result = tokio::task::spawn_blocking(move || -> anyhow::Result<serde_json::Value> {
        Ok(json!({
            "version": state.db.version()?,
            "agents": state.db.agents(&state.configured_agents)?,
        }))
    })
    .await;
    respond(result)
}

/// Server-sent events: one `activity` event per agent action, as it happens.
async fn events(
    State(admin): State<Arc<Admin>>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let stream = BroadcastStream::new(admin.events.subscribe()).filter_map(|message| {
        // A listener that fell behind skips what it missed; the page's
        // periodic refresh catches up.
        let activity = message.ok()?;
        let event = Event::default()
            .event("activity")
            .json_data(&activity)
            .ok()?;
        Some(Ok(event))
    });
    Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(20)))
}

/// Downloads the whole store as one JSON file.
async fn export(State(admin): State<Arc<Admin>>) -> Response {
    let db = admin.db.clone();
    match tokio::task::spawn_blocking(move || db.export()).await {
        Ok(Ok(backup)) => {
            let stamp: String = backup
                .exported_at
                .chars()
                .filter(|c| c.is_ascii_digit())
                .collect();
            let name = format!("attachment; filename=\"project-lore-backup-{stamp}.json\"");
            match serde_json::to_vec(&backup) {
                Ok(body) => (
                    [
                        (header::CONTENT_TYPE, "application/json".to_string()),
                        (header::CONTENT_DISPOSITION, name),
                    ],
                    body,
                )
                    .into_response(),
                Err(error) => {
                    tracing::error!(%error, "serialising the backup failed");
                    StatusCode::INTERNAL_SERVER_ERROR.into_response()
                }
            }
        }
        other => {
            tracing::error!(?other, "export failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[derive(Deserialize)]
struct ImportOptions {
    /// `merge` adds missing entries; `replace` restores the backup exactly.
    mode: String,
}

/// Loads a backup: either merged into what is here or replacing it.
async fn import(
    State(admin): State<Arc<Admin>>,
    Query(options): Query<ImportOptions>,
    Json(backup): Json<Backup>,
) -> Response {
    let replace = match options.mode.as_str() {
        "replace" => true,
        "merge" => false,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "mode must be merge or replace" })),
            )
                .into_response();
        }
    };
    let state = admin.clone();
    let result = tokio::task::spawn_blocking(move || -> anyhow::Result<serde_json::Value> {
        let (added, present) = if replace {
            (state.db.restore(&backup)?, 0)
        } else {
            state.db.merge(&backup)?
        };
        let (tool, summary) = if replace {
            ("restore", format!("{added} entries restored"))
        } else {
            (
                "import",
                format!("{added} added, {present} already present"),
            )
        };
        tracing::info!(tool, added, present, "backup loaded from the admin view");
        if let Ok(activity) = state
            .db
            .record_activity(ADMIN_ACTOR, tool, "", None, &[], &summary)
        {
            state.events.publish(activity);
        }
        // Imported entries have no vectors yet; compute them in the background.
        let (db, embedder, events) = (
            state.db.clone(),
            state.embedder.clone(),
            state.events.clone(),
        );
        std::thread::spawn(move || {
            match embedder.backfill(&db) {
                // Tell open pages the links are back, so they redraw.
                Ok(count) if count > 0 => {
                    let summary = format!("{count} entries searchable by meaning again");
                    if let Ok(activity) =
                        db.record_activity(ADMIN_ACTOR, "reindex", "", None, &[], &summary)
                    {
                        events.publish(activity);
                    }
                }
                Ok(_) => {}
                Err(error) => tracing::warn!(%error, "embedding imported entries failed"),
            }
        });
        Ok(json!({ "added": added, "present": present, "replaced": replace }))
    })
    .await;
    match result {
        Ok(Ok(value)) => Json(value).into_response(),
        Ok(Err(error)) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": error.to_string() })),
        )
            .into_response(),
        Err(error) => {
            tracing::error!(%error, "import task failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn entry(State(admin): State<Arc<Admin>>, Path(id): Path<i64>) -> Response {
    let db = admin.db.clone();
    match tokio::task::spawn_blocking(move || db.get(id)).await {
        Ok(Ok(Some(entry))) => Json(entry).into_response(),
        Ok(Ok(None)) => StatusCode::NOT_FOUND.into_response(),
        other => {
            tracing::error!(?other, "loading an entry failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

fn respond(result: Result<anyhow::Result<serde_json::Value>, tokio::task::JoinError>) -> Response {
    match result {
        Ok(Ok(value)) => Json(value).into_response(),
        Ok(Err(error)) => {
            tracing::error!(%error, "admin query failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
        Err(error) => {
            tracing::error!(%error, "admin task failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[derive(Deserialize)]
struct CaptchaVerdict {
    success: bool,
    #[serde(default)]
    score: f64,
    #[serde(default)]
    action: String,
}

/// Checks a reCAPTCHA v3 token with Google. Fails closed: if Google cannot be
/// reached, the login is refused.
async fn verify_captcha(
    http: &reqwest::Client,
    recaptcha: &Recaptcha,
    token: &str,
    ip: &str,
) -> Result<(), String> {
    if token.is_empty() {
        return Err("no token".into());
    }
    let verdict: CaptchaVerdict = http
        .post("https://www.google.com/recaptcha/api/siteverify")
        .form(&[
            ("secret", recaptcha.secret.as_str()),
            ("response", token),
            ("remoteip", ip),
        ])
        .send()
        .await
        .map_err(|e| format!("verification request failed: {e}"))?
        .json()
        .await
        .map_err(|e| format!("unreadable verification response: {e}"))?;
    if !verdict.success {
        return Err("token rejected".into());
    }
    if verdict.action != RECAPTCHA_ACTION {
        return Err(format!("unexpected action \"{}\"", verdict.action));
    }
    if verdict.score < recaptcha.min_score {
        return Err(format!("score {:.1} below threshold", verdict.score));
    }
    Ok(())
}

fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(key, _)| *key == name)
        .map(|(_, value)| value.to_string())
        .filter(|value| !value.is_empty())
}

fn random_token() -> Result<String, getrandom::Error> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes)?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}
