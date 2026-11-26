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
    routing::{delete, get, post, put},
};
use serde::Deserialize;
use serde_json::json;
use subtle::ConstantTimeEq;
use tokio_stream::{Stream, StreamExt, wrappers::BroadcastStream};

use crate::{
    auth::{RateLimiter, client_ip, too_many_requests},
    db::{
        Backup, Db, FileInfo, Message, NewFile, NewMessage, NewTask, OPS_LEVELS, ProfileInput,
        Rule, RuleInput, Session, Task,
    },
    embed::Embedder,
    events::Events,
    ops,
    vault::{Secret, VaultKey},
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
/// Largest profile or rule edit accepted.
const MAX_JSON_BYTES: usize = 64 * 1024;
/// Largest file upload accepted: a 2 MiB file as base64, inside its JSON.
const MAX_FILE_UPLOAD_BYTES: usize = 4 * 1024 * 1024;
/// Longest file text the detail view returns; longer text is cut.
const FILE_TEXT_CHARS: usize = 200_000;
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
    /// Hours after which an open session is closed as inactive.
    pub idle_hours: u32,
    pub events: Events,
    pub embedder: Embedder,
    /// The vault key, when the administrator set one. Without it no
    /// credential can be stored, and the integrations panel says so.
    pub vault: Option<VaultKey>,
    sessions: Mutex<HashMap<String, (Instant, Role)>>,
    logins: RateLimiter,
    http: reqwest::Client,
    /// The client provider calls go through: no redirects, 60 s timeout.
    ops_http: reqwest::Client,
}

impl Admin {
    #[expect(
        clippy::too_many_arguments,
        reason = "the router wiring passes every option at once"
    )]
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
        idle_hours: u32,
        vault: Option<VaultKey>,
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
            idle_hours,
            events,
            embedder,
            vault,
            sessions: Mutex::new(HashMap::new()),
            // Five wrong attempts lock the address out for fifteen minutes.
            logins: RateLimiter::new(5, Duration::from_secs(15 * 60)),
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(8))
                .build()
                .expect("building the HTTP client"),
            ops_http: ops::client(),
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
        .route("/admin/api/profile", get(profile))
        .route("/admin/api/sessions", get(sessions))
        .route("/admin/api/sessions/{id}", get(session_detail))
        .route("/admin/api/board", get(board))
        .route("/admin/api/files", get(files))
        .route("/admin/api/files/{id}", get(file_detail))
        .route("/admin/api/files/{id}/download", get(download_file))
        .route("/admin/api/integrations", get(integrations))
        .layer(middleware::from_fn_with_state(
            admin.clone(),
            require_session,
        ));
    // Backups carry the whole store, profile edits change what every
    // agent is told, and board writes speak for the administrator, so only
    // the admin role reaches them.
    let admin_only = Router::new()
        .route("/admin/api/export", get(export))
        .route(
            "/admin/api/import",
            post(import).layer(DefaultBodyLimit::max(MAX_BACKUP_BYTES)),
        )
        .route(
            "/admin/api/profile",
            put(save_profile).layer(DefaultBodyLimit::max(MAX_JSON_BYTES)),
        )
        .route(
            "/admin/api/rules",
            post(add_rule).layer(DefaultBodyLimit::max(MAX_JSON_BYTES)),
        )
        .route(
            "/admin/api/rules/{id}",
            put(save_rule)
                .layer(DefaultBodyLimit::max(MAX_JSON_BYTES))
                .delete(delete_rule),
        )
        .route(
            "/admin/api/tasks",
            post(add_task).layer(DefaultBodyLimit::max(MAX_JSON_BYTES)),
        )
        .route(
            "/admin/api/tasks/{id}",
            put(update_task).layer(DefaultBodyLimit::max(MAX_JSON_BYTES)),
        )
        .route(
            "/admin/api/messages",
            post(add_message).layer(DefaultBodyLimit::max(MAX_JSON_BYTES)),
        )
        // Only the upload carries a whole file; every other route keeps the
        // small limit.
        .route(
            "/admin/api/files",
            post(upload_file).layer(DefaultBodyLimit::max(MAX_FILE_UPLOAD_BYTES)),
        )
        .route("/admin/api/files/{id}", delete(delete_file))
        // Credentials speak for the whole server, so only the admin role
        // reaches the integrations writes.
        .route(
            "/admin/api/integrations/{provider}",
            put(save_integration)
                .layer(DefaultBodyLimit::max(MAX_JSON_BYTES))
                .delete(delete_integration),
        )
        .route(
            "/admin/api/integrations/{provider}/test",
            post(test_integration),
        )
        .route(
            "/admin/api/integrations/permissions",
            put(save_permission).layer(DefaultBodyLimit::max(MAX_JSON_BYTES)),
        )
        .route(
            "/admin/api/integrations/enabled",
            put(set_integration_enabled).layer(DefaultBodyLimit::max(MAX_JSON_BYTES)),
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

/// Identifies the page assets compiled into this binary. An open page compares
/// it with the one it was loaded from and reloads itself after a deploy, so
/// nobody keeps working in an outdated page.
fn build_id() -> String {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    (PAGE, SCRIPT, STYLE).hash(&mut hasher);
    format!("{:016x}", hasher.finish())
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
        "build": build_id(),
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

    if let Some(recaptcha) = &admin.recaptcha
        && let Err(reason) = verify_captcha(&admin.http, recaptcha, &form.captcha, &ip).await
    {
        tracing::warn!(%ip, %reason, "admin login rejected by reCAPTCHA");
        admin.logins.hit(&ip);
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "The request looked automated. Try again." })),
        )
            .into_response();
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
        // Stale sessions never show as open.
        state.db.close_idle_sessions(state.idle_hours)?;
        Ok(json!({
            "version": state.db.version()?,
            "embedding_model": state.embedding_model,
            "agents": state.db.agents(&state.configured_agents)?,
            "activity": state.db.activity(FEED_LENGTH)?,
            "open_sessions": state.db.open_session_count()?,
            "open_tasks": state.db.board_counts()?.open_tasks,
            "files": state.db.file_counts()?.files,
            "brain": brain,
        }))
    })
    .await;
    respond(result)
}

/// A cheap poll: the data version, who is connected, how many chats are open.
async fn pulse(State(admin): State<Arc<Admin>>) -> Response {
    let state = admin.clone();
    let result = tokio::task::spawn_blocking(move || -> anyhow::Result<serde_json::Value> {
        state.db.close_idle_sessions(state.idle_hours)?;
        Ok(json!({
            "version": state.db.version()?,
            "agents": state.db.agents(&state.configured_agents)?,
            "open_sessions": state.db.open_session_count()?,
            "open_tasks": state.db.board_counts()?.open_tasks,
            "files": state.db.file_counts()?.files,
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
        if let Ok(activity) =
            state
                .db
                .record_activity(ADMIN_ACTOR, tool, "", None, None, &[], &summary)
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
                        db.record_activity(ADMIN_ACTOR, "reindex", "", None, None, &[], &summary)
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

/// The profile the admin page edits: the form of address, the reply language,
/// each agent's own address, the rules, and every agent a row can be made
/// for.
async fn profile(State(admin): State<Arc<Admin>>) -> Response {
    let state = admin.clone();
    let result = tokio::task::spawn_blocking(move || -> anyhow::Result<serde_json::Value> {
        let profile = state.db.profile()?;
        let rules = state.db.rules()?;
        let known_agents: Vec<String> = state
            .db
            .agents(&state.configured_agents)?
            .into_iter()
            .map(|agent| agent.name)
            .collect();
        Ok(json!({
            "address": profile.address,
            "language": profile.language,
            "agents": profile.agents,
            "rules": rules,
            "known_agents": known_agents,
        }))
    })
    .await;
    respond(result)
}

#[derive(Deserialize)]
struct ProfileForm {
    #[serde(default)]
    address: String,
    #[serde(default)]
    language: String,
    #[serde(default)]
    agents: Vec<AgentAddressForm>,
}

#[derive(Deserialize)]
struct AgentAddressForm {
    #[serde(default)]
    agent: String,
    #[serde(default)]
    address: String,
}

/// Saves the profile: the default form of address, the reply language and
/// each agent's own form of address. Rows with an empty address are dropped
/// on the store side.
async fn save_profile(State(admin): State<Arc<Admin>>, Json(form): Json<ProfileForm>) -> Response {
    let address = form.address.trim();
    if address.chars().count() > 80 {
        return bad_request("the form of address must be at most 80 characters");
    }
    let language = form.language.trim();
    if language.chars().count() > 40 {
        return bad_request("the reply language must be at most 40 characters");
    }
    let input = ProfileInput {
        address: address.to_string(),
        language: language.to_string(),
        agents: form
            .agents
            .into_iter()
            .map(|agent| crate::db::AgentAddress {
                agent: agent.agent.trim().to_lowercase(),
                address: agent.address.trim().to_string(),
            })
            .collect(),
    };
    let state = admin.clone();
    let result = tokio::task::spawn_blocking(move || -> anyhow::Result<serde_json::Value> {
        state.db.set_profile(&input)?;
        // Tell open pages what the agents are told has changed.
        if let Ok(activity) = state.db.record_activity(
            ADMIN_ACTOR,
            "profile",
            "",
            None,
            None,
            &[],
            "profile updated",
        ) {
            state.events.publish(activity);
        }
        Ok(json!({ "ok": true }))
    })
    .await;
    match result {
        Ok(Ok(value)) => Json(value).into_response(),
        Ok(Err(error)) => bad_request(&error.to_string()),
        Err(error) => {
            tracing::error!(%error, "saving the profile failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[derive(Deserialize)]
struct SessionsQuery {
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    project: Option<String>,
    #[serde(default)]
    limit: Option<u32>,
}

/// The chat sessions agents opened, newest activity first.
async fn sessions(State(admin): State<Arc<Admin>>, Query(query): Query<SessionsQuery>) -> Response {
    let status = match query.status.as_deref() {
        None | Some("") => None,
        Some("open") => Some("open"),
        Some("closed") => Some("closed"),
        Some(_) => return bad_request("status must be open or closed"),
    };
    let limit = query.limit.unwrap_or(50).clamp(1, 200) as usize;
    let state = admin.clone();
    let result = tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<Session>> {
        state.db.close_idle_sessions(state.idle_hours)?;
        state.db.sessions(status, query.project.as_deref(), limit)
    })
    .await;
    match result {
        Ok(Ok(list)) => Json(list).into_response(),
        Ok(Err(error)) => {
            tracing::error!(%error, "listing sessions failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
        Err(error) => {
            tracing::error!(%error, "sessions task failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// One session with its check-in timeline.
async fn session_detail(State(admin): State<Arc<Admin>>, Path(id): Path<String>) -> Response {
    let state = admin.clone();
    let result =
        tokio::task::spawn_blocking(move || -> anyhow::Result<Option<serde_json::Value>> {
            let Some(session) = state.db.session(&id)? else {
                return Ok(None);
            };
            let updates = state.db.session_updates(&id)?;
            let mut value = serde_json::to_value(session)?;
            if let Some(object) = value.as_object_mut() {
                object.insert("updates".into(), serde_json::to_value(updates)?);
            }
            Ok(Some(value))
        })
        .await;
    match result {
        Ok(Ok(Some(value))) => Json(value).into_response(),
        Ok(Ok(None)) => StatusCode::NOT_FOUND.into_response(),
        Ok(Err(error)) => {
            tracing::error!(%error, "loading a session failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
        Err(error) => {
            tracing::error!(%error, "session task failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[derive(Deserialize)]
struct BoardQuery {
    #[serde(default)]
    project: Option<String>,
    #[serde(default)]
    limit: Option<u32>,
}

/// The shared board: every task, the latest messages and the totals, for
/// the Board panel. Any signed-in role can read it.
async fn board(State(admin): State<Arc<Admin>>, Query(query): Query<BoardQuery>) -> Response {
    let project = query
        .project
        .as_deref()
        .map(str::trim)
        .filter(|project| !project.is_empty())
        .map(str::to_lowercase);
    let limit = query.limit.unwrap_or(100).clamp(1, 300) as usize;
    let state = admin.clone();
    let result = tokio::task::spawn_blocking(move || -> anyhow::Result<serde_json::Value> {
        let project = project.as_deref();
        let tasks = state.db.tasks(project, &[], limit)?;
        let messages = state.db.messages(project, 100)?;
        let counts = state.db.board_counts()?;
        Ok(json!({ "tasks": tasks, "messages": messages, "counts": counts }))
    })
    .await;
    respond(result)
}

#[derive(Deserialize)]
struct TaskForm {
    #[serde(default)]
    project: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    body: String,
    #[serde(default)]
    assignee: String,
}

/// Adds a task as the admin. The created task is returned.
async fn add_task(State(admin): State<Arc<Admin>>, Json(form): Json<TaskForm>) -> Response {
    let input = NewTask {
        project: form.project,
        title: form.title,
        body: form.body,
        assignee: form.assignee,
        created_by: ADMIN_ACTOR.into(),
        session_id: None,
    };
    let state = admin.clone();
    let result = tokio::task::spawn_blocking(move || -> anyhow::Result<Task> {
        let task = state.db.add_task(&input)?;
        let summary = format!("task #{}: {}", task.id, task.title);
        if let Ok(activity) = state.db.record_activity(
            ADMIN_ACTOR,
            "task_add",
            &task.project,
            None,
            None,
            &[],
            &summary,
        ) {
            state.events.publish(activity);
        }
        Ok(task)
    })
    .await;
    match result {
        Ok(Ok(task)) => Json(task).into_response(),
        Ok(Err(error)) => bad_request(&error.to_string()),
        Err(error) => {
            tracing::error!(%error, "adding a task failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[derive(Deserialize)]
struct TaskUpdateForm {
    #[serde(default)]
    action: String,
    #[serde(default)]
    note: String,
}

/// Moves one task along its life cycle as the admin, who may release or
/// reopen any task.
async fn update_task(
    State(admin): State<Arc<Admin>>,
    Path(id): Path<i64>,
    Json(form): Json<TaskUpdateForm>,
) -> Response {
    let state = admin.clone();
    let result = tokio::task::spawn_blocking(move || -> anyhow::Result<Option<Task>> {
        let note = form.note.trim();
        let note = (!note.is_empty()).then(|| note.to_string());
        let Some(task) =
            state
                .db
                .update_task(id, &form.action, ADMIN_ACTOR, note.as_deref(), None)?
        else {
            return Ok(None);
        };
        let summary = format!("task #{} {}", task.id, form.action);
        if let Ok(activity) = state.db.record_activity(
            ADMIN_ACTOR,
            "task_update",
            &task.project,
            None,
            None,
            &[],
            &summary,
        ) {
            state.events.publish(activity);
        }
        Ok(Some(task))
    })
    .await;
    match result {
        Ok(Ok(Some(task))) => Json(task).into_response(),
        Ok(Ok(None)) => StatusCode::NOT_FOUND.into_response(),
        Ok(Err(error)) => bad_request(&error.to_string()),
        Err(error) => {
            tracing::error!(%error, "updating a task failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[derive(Deserialize)]
struct MessageForm {
    #[serde(default)]
    kind: String,
    #[serde(default)]
    project: String,
    #[serde(default)]
    to: String,
    #[serde(default)]
    body: String,
}

/// Adds a message or a handoff note as the admin. The message that was
/// written is returned.
async fn add_message(State(admin): State<Arc<Admin>>, Json(form): Json<MessageForm>) -> Response {
    let input = NewMessage {
        kind: form.kind,
        project: form.project,
        from_agent: ADMIN_ACTOR.into(),
        to_agent: form.to,
        body: form.body,
        session_id: None,
    };
    let state = admin.clone();
    let result = tokio::task::spawn_blocking(move || -> anyhow::Result<Message> {
        let message = state.db.add_message(&input)?;
        let (tool, summary) = if message.kind == "handoff" {
            (
                "handoff",
                format!("handoff note #{} for {}", message.id, message.project),
            )
        } else {
            let to = if message.to_agent.is_empty() {
                "everyone"
            } else {
                &message.to_agent
            };
            ("send", format!("message #{} to {}", message.id, to))
        };
        if let Ok(activity) = state.db.record_activity(
            ADMIN_ACTOR,
            tool,
            &message.project,
            None,
            None,
            &[],
            &summary,
        ) {
            state.events.publish(activity);
        }
        Ok(message)
    })
    .await;
    match result {
        Ok(Ok(message)) => Json(message).into_response(),
        Ok(Err(error)) => bad_request(&error.to_string()),
        Err(error) => {
            tracing::error!(%error, "adding a message failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[derive(Deserialize)]
struct FilesQuery {
    #[serde(default)]
    project: Option<String>,
    #[serde(default)]
    q: Option<String>,
    #[serde(default)]
    limit: Option<u32>,
}

/// The latest version of each file, newest first, or the files a search
/// matches, with the totals. Any signed-in role can read it.
async fn files(State(admin): State<Arc<Admin>>, Query(query): Query<FilesQuery>) -> Response {
    let project = query
        .project
        .as_deref()
        .map(str::trim)
        .filter(|project| !project.is_empty())
        .map(str::to_lowercase);
    let search = query
        .q
        .as_deref()
        .map(str::trim)
        .filter(|q| !q.is_empty())
        .map(str::to_string);
    let limit = query.limit.unwrap_or(100).clamp(1, 300) as usize;
    let state = admin.clone();
    let result = tokio::task::spawn_blocking(move || -> anyhow::Result<serde_json::Value> {
        let project = project.as_deref();
        // The page searches by words in the path and the description.
        let list: Vec<FileInfo> = match &search {
            None => state.db.files(project, limit)?,
            Some(search) => state
                .db
                .search_files(search, project, None, 1.0, limit)?
                .into_iter()
                .map(|hit| hit.file)
                .collect(),
        };
        let counts = state.db.file_counts()?;
        Ok(json!({ "files": list, "counts": counts }))
    })
    .await;
    respond(result)
}

/// One file version: its metadata, every version of its path, and its text
/// when it is a text file, cut to `FILE_TEXT_CHARS`.
async fn file_detail(State(admin): State<Arc<Admin>>, Path(id): Path<i64>) -> Response {
    let state = admin.clone();
    let result =
        tokio::task::spawn_blocking(move || -> anyhow::Result<Option<serde_json::Value>> {
            let Some(file) = state.db.file(id)? else {
                return Ok(None);
            };
            let versions = state
                .db
                .file_versions(&file.info.project, &file.info.path)?;
            let (text, truncated) = if file.info.encoding == "base64" {
                (None, false)
            } else {
                let text = String::from_utf8_lossy(&file.content);
                if text.chars().count() > FILE_TEXT_CHARS {
                    (
                        Some(text.chars().take(FILE_TEXT_CHARS).collect::<String>()),
                        true,
                    )
                } else {
                    (Some(text.into_owned()), false)
                }
            };
            Ok(Some(json!({
                "file": file.info,
                "versions": versions,
                "text": text,
                "truncated": truncated,
            })))
        })
        .await;
    match result {
        Ok(Ok(Some(value))) => Json(value).into_response(),
        Ok(Ok(None)) => StatusCode::NOT_FOUND.into_response(),
        Ok(Err(error)) => {
            tracing::error!(%error, "loading a file failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
        Err(error) => {
            tracing::error!(%error, "file task failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// The raw bytes of one file version, always as a download: a stored HTML
/// or SVG file must never render inside the admin page's origin.
async fn download_file(State(admin): State<Arc<Admin>>, Path(id): Path<i64>) -> Response {
    let db = admin.db.clone();
    match tokio::task::spawn_blocking(move || db.file(id)).await {
        Ok(Ok(Some(file))) => {
            let disposition = format!(
                "attachment; filename=\"{}\"",
                download_name(&file.info.path)
            );
            (
                [
                    (header::CONTENT_TYPE, "application/octet-stream".to_string()),
                    (header::CONTENT_DISPOSITION, disposition),
                    (header::X_CONTENT_TYPE_OPTIONS, "nosniff".to_string()),
                ],
                file.content,
            )
                .into_response()
        }
        Ok(Ok(None)) => StatusCode::NOT_FOUND.into_response(),
        other => {
            tracing::error!(?other, "downloading a file failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// The last segment of a file path, with every character outside
/// `[A-Za-z0-9._-]` replaced, so it is safe inside a header.
fn download_name(path: &str) -> String {
    let base = path.rsplit('/').next().unwrap_or(path);
    let name: String = base
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    if name.trim_matches(['.', '_']).is_empty() {
        "file".to_string()
    } else {
        name
    }
}

#[derive(Deserialize)]
struct FileForm {
    #[serde(default)]
    project: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    kind: String,
    #[serde(default)]
    encoding: String,
    #[serde(default)]
    content: String,
}

/// Saves a file as the admin: a new version, or the latest one again when
/// the content is the same.
async fn upload_file(State(admin): State<Arc<Admin>>, Json(form): Json<FileForm>) -> Response {
    let input = NewFile {
        project: form.project,
        path: form.path,
        kind: form.kind,
        description: form.description,
        encoding: form.encoding,
        content: form.content,
        entry_id: None,
        agent: ADMIN_ACTOR.into(),
        session_id: None,
    };
    let state = admin.clone();
    let result = tokio::task::spawn_blocking(move || -> anyhow::Result<serde_json::Value> {
        let saved = state.db.save_file(&input)?;
        let file = &saved.file;
        if saved.needs_embedding {
            match state.embedder.embed_passage(&file.embedding_text()) {
                Ok(Some(vector)) => {
                    if let Err(error) = state.db.set_file_embedding(file.id, &vector) {
                        tracing::warn!(%error, id = file.id, "storing file embedding failed");
                    }
                }
                Ok(None) => {}
                Err(error) => tracing::warn!(%error, id = file.id, "file embedding failed"),
            }
        }
        let summary = format!(
            "{} v{}{}",
            file.path,
            file.version,
            if saved.unchanged { " (unchanged)" } else { "" }
        );
        if let Ok(activity) = state.db.record_activity(
            ADMIN_ACTOR,
            "file_save",
            &file.project,
            None,
            None,
            &[],
            &summary,
        ) {
            state.events.publish(activity);
        }
        Ok(json!({ "file": saved.file, "unchanged": saved.unchanged }))
    })
    .await;
    match result {
        Ok(Ok(value)) => Json(value).into_response(),
        Ok(Err(error)) => bad_request(&error.to_string()),
        Err(error) => {
            tracing::error!(%error, "saving a file failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[derive(Deserialize)]
struct DeleteFileOptions {
    /// True removes every version of the file's path, not just this one.
    #[serde(default)]
    all: bool,
}

/// Removes one file version, or every version of its path.
async fn delete_file(
    State(admin): State<Arc<Admin>>,
    Path(id): Path<i64>,
    Query(options): Query<DeleteFileOptions>,
) -> Response {
    let state = admin.clone();
    let result =
        tokio::task::spawn_blocking(move || -> anyhow::Result<Option<serde_json::Value>> {
            let (file, deleted) = if options.all {
                let Some(file) = state.db.file(id)? else {
                    return Ok(None);
                };
                let deleted = state
                    .db
                    .delete_file_path(&file.info.project, &file.info.path)?;
                (file.info, deleted)
            } else {
                let Some(file) = state.db.delete_file(id)? else {
                    return Ok(None);
                };
                (file, 1)
            };
            let summary = if options.all {
                format!("{} (all {deleted} versions)", file.path)
            } else {
                format!("{} v{}", file.path, file.version)
            };
            if let Ok(activity) = state.db.record_activity(
                ADMIN_ACTOR,
                "file_delete",
                &file.project,
                None,
                None,
                &[],
                &summary,
            ) {
                state.events.publish(activity);
            }
            Ok(Some(json!({ "ok": true, "deleted": deleted })))
        })
        .await;
    match result {
        Ok(Ok(Some(value))) => Json(value).into_response(),
        Ok(Ok(None)) => StatusCode::NOT_FOUND.into_response(),
        Ok(Err(error)) => bad_request(&error.to_string()),
        Err(error) => {
            tracing::error!(%error, "deleting a file failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[derive(Deserialize)]
struct RuleForm {
    #[serde(default)]
    scope: String,
    #[serde(default)]
    target: String,
    #[serde(default)]
    body: String,
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    position: i64,
}

impl RuleForm {
    fn input(&self) -> RuleInput {
        RuleInput {
            scope: self.scope.clone(),
            target: self.target.clone(),
            body: self.body.clone(),
            enabled: self.enabled.unwrap_or(true),
            position: self.position,
        }
    }
}

/// Everything the Integrations panel shows: the vault state, the kill
/// switch, the four providers, the agents with their permissions and the
/// latest operations. No credential in any of it.
async fn integrations(State(admin): State<Arc<Admin>>) -> Response {
    let state = admin.clone();
    let result = tokio::task::spawn_blocking(move || -> anyhow::Result<serde_json::Value> {
        let vault = state.db.vault_status()?;
        let enabled = state.db.ops_enabled()?;
        let agents: Vec<String> = state
            .db
            .agents(&state.configured_agents)?
            .into_iter()
            .map(|agent| agent.name)
            .collect();
        let permissions = state.db.ops_permissions()?;
        let log = state.db.ops_log(100)?;
        let mut providers: Vec<serde_json::Value> = Vec::new();
        for (provider, row) in ops::ALL.iter().zip(vault.iter()) {
            // Whether the current key still opens the stored credential: a
            // changed LORE_VAULT_KEY leaves rows nobody can use. Only the
            // yes or no leaves this block.
            let readable = match (row.configured, state.vault.as_ref()) {
                (true, Some(key)) => state.db.vault(provider.id)?.is_some_and(|stored| {
                    key.decrypt(provider.id, &stored.base_url, &stored.nonce, &stored.secret)
                        .is_ok()
                }),
                _ => false,
            };
            providers.push(json!({
                "id": provider.id,
                "label": provider.label,
                "needs_url": provider.needs_url,
                "configured": row.configured,
                "readable": readable,
                "base_url": row.base_url,
                "hint": row.hint,
                "updated_at": row.updated_at,
            }));
        }
        Ok(json!({
            "vault_enabled": state.vault.is_some(),
            "enabled": enabled,
            "providers": providers,
            "agents": agents,
            "permissions": permissions,
            "log": log,
        }))
    })
    .await;
    respond(result)
}

#[derive(Deserialize)]
struct IntegrationForm {
    #[serde(default)]
    secret: String,
    #[serde(default)]
    base_url: String,
}

/// Stores one provider's credential, or changes the server URL of one
/// already stored. The secret is encrypted before it is written; no
/// response, log line or activity summary ever carries it.
async fn save_integration(
    State(admin): State<Arc<Admin>>,
    Path(provider_id): Path<String>,
    Json(form): Json<IntegrationForm>,
) -> Response {
    let Some(provider) = ops::Provider::find(&provider_id) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(key) = admin.vault.clone() else {
        return bad_request(
            "the vault is not enabled: set LORE_VAULT_KEY on the server to store credentials",
        );
    };
    let secret = form.secret.trim().to_string();
    let url = form.base_url.trim().to_string();
    // Everything is validated before the secret is used, so no error
    // message can echo it back.
    if secret.is_empty() && !url.is_empty() {
        // The server URL is sealed into the credential: pointing a stored
        // credential at another server would send it there unseen.
        return bad_request("enter the credential again to change the server URL");
    }
    if secret.is_empty() {
        return bad_request("paste the credential");
    }
    if !(8..=4096).contains(&secret.chars().count()) {
        return bad_request("the credential must be between 8 and 4096 characters");
    }
    // It travels in an HTTP header: printable ASCII, no spaces.
    if !secret.bytes().all(|byte| (0x21..=0x7e).contains(&byte)) {
        return bad_request(
            "the credential must be printable ASCII without spaces; check what was pasted",
        );
    }
    if !provider.needs_url && !url.is_empty() {
        return bad_request(&format!(
            "{} does not take a server URL; its API base is fixed",
            provider.label
        ));
    }
    if provider.needs_url && url.is_empty() {
        return bad_request(&format!("{} needs the server URL as well", provider.id));
    }
    let url = if url.is_empty() {
        url
    } else {
        match ops::normalize_server_url(&url) {
            Ok(url) => url,
            Err(message) => return bad_request(&message),
        }
    };
    let state = admin.clone();
    let result = tokio::task::spawn_blocking(move || -> anyhow::Result<serde_json::Value> {
        let (nonce, ciphertext) = key.encrypt(provider.id, &url, &secret);
        let count = secret.chars().count();
        let hint: String = secret.chars().skip(count.saturating_sub(4)).collect();
        state
            .db
            .set_vault(provider.id, &url, &nonce, &ciphertext, &hint)?;
        let summary = format!("saved the {} credential", provider.id);
        if let Ok(activity) =
            state
                .db
                .record_activity(ADMIN_ACTOR, "integrations", "", None, None, &[], &summary)
        {
            state.events.publish(activity);
        }
        Ok(json!({ "ok": true }))
    })
    .await;
    match result {
        Ok(Ok(value)) => Json(value).into_response(),
        Ok(Err(error)) => bad_request(&error.to_string()),
        Err(error) => {
            tracing::error!(%error, "saving a credential failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// Removes one provider's credential.
async fn delete_integration(
    State(admin): State<Arc<Admin>>,
    Path(provider_id): Path<String>,
) -> Response {
    let Some(provider) = ops::Provider::find(&provider_id) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let state = admin.clone();
    let result =
        tokio::task::spawn_blocking(move || -> anyhow::Result<Option<serde_json::Value>> {
            if !state.db.delete_vault(provider.id)? {
                return Ok(None);
            }
            let summary = format!("removed the {} credential", provider.id);
            if let Ok(activity) =
                state
                    .db
                    .record_activity(ADMIN_ACTOR, "integrations", "", None, None, &[], &summary)
            {
                state.events.publish(activity);
            }
            Ok(Some(json!({ "ok": true })))
        })
        .await;
    match result {
        Ok(Ok(Some(value))) => Json(value).into_response(),
        Ok(Ok(None)) => StatusCode::NOT_FOUND.into_response(),
        Ok(Err(error)) => bad_request(&error.to_string()),
        Err(error) => {
            tracing::error!(%error, "removing a credential failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// Makes one harmless read through the very same call the agents use, so
/// the administrator sees whether a stored credential works. The answer is
/// one human sentence, never the response body.
async fn test_integration(
    State(admin): State<Arc<Admin>>,
    Path(provider_id): Path<String>,
) -> Response {
    let Some(provider) = ops::Provider::find(&provider_id) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    // The credential is read and decrypted off the async runtime; a
    // refusal writes its own log row and is answered without a call.
    let prepared = {
        let state = admin.clone();
        tokio::task::spawn_blocking(
            move || -> anyhow::Result<Result<(String, Secret), String>> {
                let request = provider.test_request();
                let Some(key) = state.vault.as_ref() else {
                    state.db.log_op(
                        ADMIN_ACTOR,
                        None,
                        provider.id,
                        "GET",
                        &request.path,
                        0,
                        "denied",
                        "the vault is not enabled",
                        0,
                    )?;
                    return Ok(Err(
                        "Set LORE_VAULT_KEY on the server to store credentials.".into(),
                    ));
                };
                let Some(row) = state.db.vault(provider.id)? else {
                    state.db.log_op(
                        ADMIN_ACTOR,
                        None,
                        provider.id,
                        "GET",
                        &request.path,
                        0,
                        "denied",
                        "no credential is stored",
                        0,
                    )?;
                    return Ok(Err(format!("No {} credential is stored.", provider.id)));
                };
                if provider.needs_url && row.base_url.trim().is_empty() {
                    state.db.log_op(
                        ADMIN_ACTOR,
                        None,
                        provider.id,
                        "GET",
                        &request.path,
                        0,
                        "denied",
                        "no server URL is stored",
                        0,
                    )?;
                    return Ok(Err(format!("No {} server URL is stored.", provider.id)));
                }
                let Ok(secret) = key.decrypt(provider.id, &row.base_url, &row.nonce, &row.secret)
                else {
                    state.db.log_op(
                        ADMIN_ACTOR,
                        None,
                        provider.id,
                        "GET",
                        &request.path,
                        0,
                        "denied",
                        "the stored credential cannot be decrypted",
                        0,
                    )?;
                    return Ok(Err(format!(
                        "The stored {} credential cannot be decrypted with the current \
                         LORE_VAULT_KEY; enter it again.",
                        provider.id
                    )));
                };
                Ok(Ok((provider.api_base(&row.base_url), secret)))
            },
        )
        .await
    };
    let (base, secret) = match prepared {
        Ok(Ok(Ok(pair))) => pair,
        Ok(Ok(Err(message))) => {
            return Json(json!({ "ok": false, "status": 0, "message": message })).into_response();
        }
        Ok(Err(error)) => {
            tracing::error!(%error, "reading the vault failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
        Err(error) => {
            tracing::error!(%error, "the vault task failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let request = provider.test_request();
    let started = Instant::now();
    let outcome = ops::call(&admin.ops_http, &base, &secret, &request).await;
    // What the test found, ready to answer and to log.
    let (ok, status, message, log_status, log_outcome, log_detail) = match &outcome {
        Ok(response) => {
            let status = response.status;
            let ok = (200..300).contains(&status);
            let message = if ok {
                format!(
                    "{} answered {status}: the credential works.",
                    provider.label
                )
            } else if status == 401 || status == 403 {
                format!("{} refused the credential ({status}).", provider.label)
            } else {
                format!("{} answered {status}.", provider.label)
            };
            (ok, status, message, status as i64, "ok", String::new())
        }
        Err(ops::OpsError::Transport(reason)) => (
            false,
            0,
            format!("{} could not be reached: {reason}.", provider.label),
            0,
            "error",
            reason.clone(),
        ),
        Err(ops::OpsError::Invalid(reason)) => {
            (false, 0, reason.clone(), 0, "error", reason.clone())
        }
    };
    let summary = format!(
        "tested {} ({})",
        provider.id,
        if ok { "ok" } else { "failed" }
    );
    let state = admin.clone();
    let log = tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
        let duration = started.elapsed().as_millis() as i64;
        state.db.log_op(
            ADMIN_ACTOR,
            None,
            provider.id,
            "GET",
            &request.path,
            log_status,
            log_outcome,
            &log_detail,
            duration,
        )?;
        if let Ok(activity) =
            state
                .db
                .record_activity(ADMIN_ACTOR, "integrations", "", None, None, &[], &summary)
        {
            state.events.publish(activity);
        }
        Ok(())
    })
    .await;
    if let Err(error) = log {
        tracing::warn!(%error, "writing the ops log failed");
    }
    Json(json!({ "ok": ok, "status": status, "message": message })).into_response()
}

#[derive(Deserialize)]
struct PermissionForm {
    #[serde(default)]
    agent: String,
    #[serde(default)]
    provider: String,
    #[serde(default)]
    level: String,
}

/// Sets one agent's level on one provider.
async fn save_permission(
    State(admin): State<Arc<Admin>>,
    Json(form): Json<PermissionForm>,
) -> Response {
    let agent = form.agent.trim().to_lowercase();
    if agent.is_empty() {
        return bad_request("agent must not be empty");
    }
    let Some(provider) = ops::Provider::find(&form.provider) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let level = form.level.trim().to_lowercase();
    if !OPS_LEVELS.contains(&level.as_str()) {
        return bad_request("level must be one of: off, read, full");
    }
    let state = admin.clone();
    let result = tokio::task::spawn_blocking(move || -> anyhow::Result<serde_json::Value> {
        state.db.set_ops_level(&agent, provider.id, &level)?;
        let summary = format!("{} → {}: {}", agent, provider.id, level);
        if let Ok(activity) =
            state
                .db
                .record_activity(ADMIN_ACTOR, "integrations", "", None, None, &[], &summary)
        {
            state.events.publish(activity);
        }
        Ok(json!({ "ok": true }))
    })
    .await;
    match result {
        Ok(Ok(value)) => Json(value).into_response(),
        Ok(Err(error)) => bad_request(&error.to_string()),
        Err(error) => {
            tracing::error!(%error, "saving a permission failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[derive(Deserialize)]
struct EnabledForm {
    #[serde(default)]
    enabled: Option<bool>,
}

/// Sets the kill switch: whether agents may operate the services at all.
async fn set_integration_enabled(
    State(admin): State<Arc<Admin>>,
    Json(form): Json<EnabledForm>,
) -> Response {
    let Some(enabled) = form.enabled else {
        return bad_request("enabled must be true or false");
    };
    let state = admin.clone();
    let result = tokio::task::spawn_blocking(move || -> anyhow::Result<serde_json::Value> {
        state.db.set_ops_enabled(enabled)?;
        let summary = if enabled {
            "switched agent operations on"
        } else {
            "switched agent operations off"
        };
        if let Ok(activity) =
            state
                .db
                .record_activity(ADMIN_ACTOR, "integrations", "", None, None, &[], summary)
        {
            state.events.publish(activity);
        }
        Ok(json!({ "ok": true }))
    })
    .await;
    match result {
        Ok(Ok(value)) => Json(value).into_response(),
        Ok(Err(error)) => bad_request(&error.to_string()),
        Err(error) => {
            tracing::error!(%error, "switching operations failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// Adds a rule. The created rule is returned.
async fn add_rule(State(admin): State<Arc<Admin>>, Json(form): Json<RuleForm>) -> Response {
    let input = form.input();
    let state = admin.clone();
    let result = tokio::task::spawn_blocking(move || -> anyhow::Result<Rule> {
        let rule = state.db.add_rule(&input)?;
        let summary = format!("rule #{} added", rule.id);
        if let Ok(activity) =
            state
                .db
                .record_activity(ADMIN_ACTOR, "rules", "", None, None, &[], &summary)
        {
            state.events.publish(activity);
        }
        Ok(rule)
    })
    .await;
    match result {
        Ok(Ok(rule)) => Json(rule).into_response(),
        Ok(Err(error)) => bad_request(&error.to_string()),
        Err(error) => {
            tracing::error!(%error, "adding a rule failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// Applies a full edit of one rule.
async fn save_rule(
    State(admin): State<Arc<Admin>>,
    Path(id): Path<i64>,
    Json(form): Json<RuleForm>,
) -> Response {
    let input = form.input();
    let state = admin.clone();
    let result = tokio::task::spawn_blocking(move || -> anyhow::Result<Option<Rule>> {
        let Some(rule) = state.db.update_rule(id, &input)? else {
            return Ok(None);
        };
        let summary = format!("rule #{} saved", rule.id);
        if let Ok(activity) =
            state
                .db
                .record_activity(ADMIN_ACTOR, "rules", "", None, None, &[], &summary)
        {
            state.events.publish(activity);
        }
        Ok(Some(rule))
    })
    .await;
    match result {
        Ok(Ok(Some(rule))) => Json(rule).into_response(),
        Ok(Ok(None)) => StatusCode::NOT_FOUND.into_response(),
        Ok(Err(error)) => bad_request(&error.to_string()),
        Err(error) => {
            tracing::error!(%error, "saving a rule failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// Removes one rule.
async fn delete_rule(State(admin): State<Arc<Admin>>, Path(id): Path<i64>) -> Response {
    let state = admin.clone();
    let result = tokio::task::spawn_blocking(move || -> anyhow::Result<bool> {
        let deleted = state.db.delete_rule(id)?;
        if deleted {
            let summary = format!("rule #{id} deleted");
            if let Ok(activity) =
                state
                    .db
                    .record_activity(ADMIN_ACTOR, "rules", "", None, None, &[], &summary)
            {
                state.events.publish(activity);
            }
        }
        Ok(deleted)
    })
    .await;
    match result {
        Ok(Ok(true)) => Json(json!({ "ok": true })).into_response(),
        Ok(Ok(false)) => StatusCode::NOT_FOUND.into_response(),
        Ok(Err(error)) => bad_request(&error.to_string()),
        Err(error) => {
            tracing::error!(%error, "deleting a rule failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// A validation failure the page can show next to the field it came from.
fn bad_request(message: &str) -> Response {
    (StatusCode::BAD_REQUEST, Json(json!({ "error": message }))).into_response()
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

#[cfg(test)]
mod tests {
    use super::*;

    fn test_vault_key() -> VaultKey {
        VaultKey::from_env_value(&"ab".repeat(32)).unwrap().unwrap()
    }

    /// Serves the admin router on a free local port with one admin and one
    /// viewer session already signed in.
    async fn serve_with(vault: Option<VaultKey>) -> (String, Arc<Admin>) {
        // The thread id keeps parallel tests off each other's database.
        let dir = std::env::temp_dir().join(format!(
            "lore-admin-test-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let db = Db::open(&dir.join("lore.db")).unwrap();
        let admin = Arc::new(Admin::new(
            db,
            "admin-password".into(),
            Some("viewer-password".into()),
            None,
            false,
            vec!["claude".into()],
            None,
            0.8,
            Events::new(),
            Embedder::disabled(),
            12,
            vault,
        ));
        {
            let mut sessions = admin.sessions.lock().unwrap();
            let expires = Instant::now() + Duration::from_secs(600);
            sessions.insert("admin-token".into(), (expires, Role::Admin));
            sessions.insert("viewer-token".into(), (expires, Role::Viewer));
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let app = router(admin.clone());
        tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });
        (base, admin)
    }

    async fn serve() -> (String, Arc<Admin>) {
        serve_with(Some(test_vault_key())).await
    }

    #[tokio::test]
    async fn profile_and_rule_edits_need_the_admin_role() {
        let (base, _admin) = serve().await;
        let client = reqwest::Client::new();
        let call = |method: reqwest::Method, path: &str, token: Option<&str>| {
            let mut request = client.request(method, format!("{base}{path}"));
            if let Some(token) = token {
                request = request.header(header::COOKIE, format!("{COOKIE}={token}"));
            }
            request
        };
        let rule = json!({ "scope": "global", "target": "", "body": "be brief" });
        let profile = json!({ "address": "Boss", "language": "English", "agents": [] });

        // Reads: any signed-in role, nobody else.
        for path in [
            "/admin/api/profile",
            "/admin/api/sessions",
            "/admin/api/sessions/s_x",
        ] {
            let status = call(reqwest::Method::GET, path, None)
                .send()
                .await
                .unwrap()
                .status();
            assert_eq!(status, 401, "{path} without a session");
        }
        let status = call(
            reqwest::Method::GET,
            "/admin/api/profile",
            Some("viewer-token"),
        )
        .send()
        .await
        .unwrap()
        .status();
        assert_eq!(status, 200);

        // Writes: the viewer is refused, the admin gets through.
        for token in [None, Some("viewer-token")] {
            let expected = if token.is_some() { 403 } else { 401 };
            let responses = [
                call(reqwest::Method::PUT, "/admin/api/profile", token).json(&profile),
                call(reqwest::Method::POST, "/admin/api/rules", token).json(&rule),
                call(reqwest::Method::PUT, "/admin/api/rules/1", token).json(&rule),
                call(reqwest::Method::DELETE, "/admin/api/rules/1", token),
            ];
            for request in responses {
                let status = request.send().await.unwrap().status();
                assert_eq!(status, expected);
            }
        }
        let response = call(
            reqwest::Method::PUT,
            "/admin/api/profile",
            Some("admin-token"),
        )
        .json(&profile)
        .send()
        .await
        .unwrap();
        assert_eq!(response.status(), 200);
        let response = call(
            reqwest::Method::POST,
            "/admin/api/rules",
            Some("admin-token"),
        )
        .json(&json!({ "scope": "global", "target": "x", "body": "b" }))
        .send()
        .await
        .unwrap();
        assert_eq!(response.status(), 400);
        let response = call(
            reqwest::Method::POST,
            "/admin/api/rules",
            Some("admin-token"),
        )
        .json(&rule)
        .send()
        .await
        .unwrap();
        assert_eq!(response.status(), 200);
        assert!(
            response
                .headers()
                .contains_key(header::CONTENT_SECURITY_POLICY)
        );
        let response = call(
            reqwest::Method::DELETE,
            "/admin/api/rules/1",
            Some("admin-token"),
        )
        .send()
        .await
        .unwrap();
        assert_eq!(response.status(), 200);

        // Bodies over 64 KB are refused.
        let huge = json!({ "address": "x".repeat(70 * 1024), "language": "", "agents": [] });
        let response = call(
            reqwest::Method::PUT,
            "/admin/api/profile",
            Some("admin-token"),
        )
        .json(&huge)
        .send()
        .await
        .unwrap();
        assert_eq!(response.status(), 413);
    }

    #[tokio::test]
    async fn board_reads_and_writes_follow_the_roles() {
        let (base, _admin) = serve().await;
        let client = reqwest::Client::new();
        let call = |method: reqwest::Method, path: String, token: Option<&str>| {
            let mut request = client.request(method, format!("{base}{path}"));
            if let Some(token) = token {
                request = request.header(header::COOKIE, format!("{COOKIE}={token}"));
            }
            request
        };
        let task =
            json!({ "project": "Shop", "title": "Fix checkout", "body": "b", "assignee": "" });
        let message = json!({ "kind": "message", "project": "shop", "to": "", "body": "hello" });
        let handoff = json!({ "kind": "handoff", "project": "shop", "body": "half done" });

        // Reads: any signed-in role, nobody else.
        let status = call(reqwest::Method::GET, "/admin/api/board".into(), None)
            .send()
            .await
            .unwrap()
            .status();
        assert_eq!(status, 401);
        let response = call(
            reqwest::Method::GET,
            "/admin/api/board".into(),
            Some("viewer-token"),
        )
        .send()
        .await
        .unwrap();
        assert_eq!(response.status(), 200);
        let board: serde_json::Value = response.json().await.unwrap();
        assert!(board["tasks"].as_array().unwrap().is_empty());
        assert!(board["messages"].as_array().unwrap().is_empty());
        assert_eq!(board["counts"]["open_tasks"], 0);

        // Writes: the viewer is refused, nobody else is not even signed in.
        for token in [None, Some("viewer-token")] {
            let expected = if token.is_some() { 403 } else { 401 };
            for request in [
                call(reqwest::Method::POST, "/admin/api/tasks".into(), token).json(&task),
                call(reqwest::Method::PUT, "/admin/api/tasks/1".into(), token)
                    .json(&json!({ "action": "done", "note": "" })),
                call(reqwest::Method::POST, "/admin/api/messages".into(), token).json(&message),
            ] {
                assert_eq!(request.send().await.unwrap().status(), expected);
            }
        }

        // The admin writes a task, and every write lands in the activity
        // feed under the admin's name.
        let response = call(
            reqwest::Method::POST,
            "/admin/api/tasks".into(),
            Some("admin-token"),
        )
        .json(&task)
        .send()
        .await
        .unwrap();
        assert_eq!(response.status(), 200);
        let created: serde_json::Value = response.json().await.unwrap();
        let id = created["id"].as_i64().unwrap();
        assert_eq!(created["status"], "open");
        assert_eq!(created["created_by"], "admin");
        assert_eq!(created["project"], "shop");

        // The admin moves the task along; ids that do not exist and
        // actions that do not apply are refused.
        let response = call(
            reqwest::Method::PUT,
            format!("/admin/api/tasks/{id}"),
            Some("admin-token"),
        )
        .json(&json!({ "action": "done", "note": "shipped" }))
        .send()
        .await
        .unwrap();
        assert_eq!(response.status(), 200);
        let done: serde_json::Value = response.json().await.unwrap();
        assert_eq!(done["status"], "done");
        assert_eq!(done["done_by"], "admin");
        assert_eq!(done["note"], "shipped");
        let response = call(
            reqwest::Method::PUT,
            format!("/admin/api/tasks/{id}"),
            Some("admin-token"),
        )
        .json(&json!({ "action": "done", "note": "" }))
        .send()
        .await
        .unwrap();
        assert_eq!(response.status(), 400);
        let response = call(
            reqwest::Method::PUT,
            format!("/admin/api/tasks/{id}"),
            Some("admin-token"),
        )
        .json(&json!({ "action": "reopen", "note": "" }))
        .send()
        .await
        .unwrap();
        assert_eq!(response.status(), 200);
        let response = call(
            reqwest::Method::PUT,
            format!("/admin/api/tasks/{id}"),
            Some("admin-token"),
        )
        .json(&json!({ "action": "fly", "note": "" }))
        .send()
        .await
        .unwrap();
        assert_eq!(response.status(), 400);
        let response = call(
            reqwest::Method::PUT,
            "/admin/api/tasks/999".into(),
            Some("admin-token"),
        )
        .json(&json!({ "action": "done", "note": "" }))
        .send()
        .await
        .unwrap();
        assert_eq!(response.status(), 404);

        // Messages: a handoff without a project is refused.
        let response = call(
            reqwest::Method::POST,
            "/admin/api/messages".into(),
            Some("admin-token"),
        )
        .json(&message)
        .send()
        .await
        .unwrap();
        assert_eq!(response.status(), 200);
        let sent: serde_json::Value = response.json().await.unwrap();
        assert_eq!(sent["from_agent"], "admin");
        let response = call(
            reqwest::Method::POST,
            "/admin/api/messages".into(),
            Some("admin-token"),
        )
        .json(&json!({ "kind": "handoff", "project": "", "body": "x" }))
        .send()
        .await
        .unwrap();
        assert_eq!(response.status(), 400);
        let response = call(
            reqwest::Method::POST,
            "/admin/api/messages".into(),
            Some("admin-token"),
        )
        .json(&handoff)
        .send()
        .await
        .unwrap();
        assert_eq!(response.status(), 200);

        // The viewer reads what the admin wrote, with the readers of each
        // message and the task totals.
        let response = call(
            reqwest::Method::GET,
            "/admin/api/board?project=shop".into(),
            Some("viewer-token"),
        )
        .send()
        .await
        .unwrap();
        assert_eq!(response.status(), 200);
        let board: serde_json::Value = response.json().await.unwrap();
        assert_eq!(board["tasks"].as_array().unwrap().len(), 1);
        assert_eq!(board["counts"]["open_tasks"], 1);
        let messages = board["messages"].as_array().unwrap();
        assert_eq!(messages.len(), 2);
        assert!(
            messages
                .iter()
                .all(|message| message["read_by"].as_array().is_some())
        );

        // The pulse payload carries the open task count too.
        let response = call(
            reqwest::Method::GET,
            "/admin/api/pulse".into(),
            Some("viewer-token"),
        )
        .send()
        .await
        .unwrap();
        let pulse: serde_json::Value = response.json().await.unwrap();
        assert_eq!(pulse["open_tasks"], 1);
    }

    #[tokio::test]
    async fn files_follow_the_roles_and_download_safely() {
        use base64::Engine;
        let (base, _admin) = serve().await;
        let client = reqwest::Client::new();
        let call = |method: reqwest::Method, path: String, token: Option<&str>| {
            let mut request = client.request(method, format!("{base}{path}"));
            if let Some(token) = token {
                request = request.header(header::COOKIE, format!("{COOKIE}={token}"));
            }
            request
        };
        let page = json!({
            "project": "Shop", "path": "docs/page.html", "description": "a page that must not render",
            "kind": "doc", "encoding": "utf8", "content": "<script>alert(1)</script>",
        });

        // Reads: any signed-in role, nobody else.
        for path in [
            "/admin/api/files",
            "/admin/api/files/1",
            "/admin/api/files/1/download",
        ] {
            let status = call(reqwest::Method::GET, path.into(), None)
                .send()
                .await
                .unwrap()
                .status();
            assert_eq!(status, 401, "{path} without a session");
        }
        let response = call(
            reqwest::Method::GET,
            "/admin/api/files".into(),
            Some("viewer-token"),
        )
        .send()
        .await
        .unwrap();
        assert_eq!(response.status(), 200);
        let listed: serde_json::Value = response.json().await.unwrap();
        assert!(listed["files"].as_array().unwrap().is_empty());
        assert_eq!(listed["counts"]["files"], 0);

        // Writes: the viewer is refused, nobody else is not even signed in.
        for token in [None, Some("viewer-token")] {
            let expected = if token.is_some() { 403 } else { 401 };
            for request in [
                call(reqwest::Method::POST, "/admin/api/files".into(), token).json(&page),
                call(reqwest::Method::DELETE, "/admin/api/files/1".into(), token),
                call(
                    reqwest::Method::DELETE,
                    "/admin/api/files/1?all=true".into(),
                    token,
                ),
            ] {
                assert_eq!(request.send().await.unwrap().status(), expected);
            }
        }

        // The admin saves a file; the same content again makes no new version.
        let response = call(
            reqwest::Method::POST,
            "/admin/api/files".into(),
            Some("admin-token"),
        )
        .json(&page)
        .send()
        .await
        .unwrap();
        assert_eq!(response.status(), 200);
        let saved: serde_json::Value = response.json().await.unwrap();
        let id = saved["file"]["id"].as_i64().unwrap();
        assert_eq!(saved["unchanged"], false);
        assert_eq!(saved["file"]["agent"], "admin");
        assert_eq!(saved["file"]["project"], "shop");
        let response = call(
            reqwest::Method::POST,
            "/admin/api/files".into(),
            Some("admin-token"),
        )
        .json(&page)
        .send()
        .await
        .unwrap();
        let again: serde_json::Value = response.json().await.unwrap();
        assert_eq!(
            (again["unchanged"].as_bool(), again["file"]["id"].as_i64()),
            (Some(true), Some(id))
        );

        // Validation errors are a 400 with a reason: secrets, bad paths.
        for bad in [
            json!({ "project": "shop", "path": ".env", "description": "d", "content": "A=1" }),
            json!({ "project": "shop", "path": "../x", "description": "d", "content": "x" }),
            json!({ "project": "shop", "path": "x.md", "description": "", "content": "x" }),
        ] {
            let response = call(
                reqwest::Method::POST,
                "/admin/api/files".into(),
                Some("admin-token"),
            )
            .json(&bad)
            .send()
            .await
            .unwrap();
            assert_eq!(response.status(), 400);
            let body: serde_json::Value = response.json().await.unwrap();
            assert!(body["error"].as_str().is_some_and(|e| !e.is_empty()));
        }

        // A binary file fits under the upload limit as base64; a body over
        // 4 MiB is refused before it is read.
        let bytes: Vec<u8> = (0..=255u8).cycle().take(2 * 1024 * 1024).collect();
        let binary = json!({
            "project": "shop", "path": "assets/blob.bin", "description": "binary",
            "kind": "data", "encoding": "base64",
            "content": base64::engine::general_purpose::STANDARD.encode(&bytes),
        });
        let response = call(
            reqwest::Method::POST,
            "/admin/api/files".into(),
            Some("admin-token"),
        )
        .json(&binary)
        .send()
        .await
        .unwrap();
        assert_eq!(response.status(), 200);
        let binary_id = response.json::<serde_json::Value>().await.unwrap()["file"]["id"]
            .as_i64()
            .unwrap();
        let huge = json!({ "project": "shop", "path": "huge.txt", "description": "d",
                           "content": "x".repeat(5 * 1024 * 1024) });
        let response = call(
            reqwest::Method::POST,
            "/admin/api/files".into(),
            Some("admin-token"),
        )
        .json(&huge)
        .send()
        .await
        .unwrap();
        assert_eq!(response.status(), 413);
        // Other JSON routes keep the small limit.
        let response = call(
            reqwest::Method::POST,
            "/admin/api/tasks".into(),
            Some("admin-token"),
        )
        .json(&json!({ "project": "shop", "title": "t", "body": "x".repeat(100 * 1024) }))
        .send()
        .await
        .unwrap();
        assert_eq!(response.status(), 413);

        // The viewer reads the detail: text for a text file, none for a
        // binary one.
        let response = call(
            reqwest::Method::GET,
            format!("/admin/api/files/{id}"),
            Some("viewer-token"),
        )
        .send()
        .await
        .unwrap();
        assert_eq!(response.status(), 200);
        let detail: serde_json::Value = response.json().await.unwrap();
        assert_eq!(detail["text"], "<script>alert(1)</script>");
        assert_eq!(detail["truncated"], false);
        assert_eq!(detail["versions"].as_array().unwrap().len(), 1);
        let response = call(
            reqwest::Method::GET,
            format!("/admin/api/files/{binary_id}"),
            Some("viewer-token"),
        )
        .send()
        .await
        .unwrap();
        let detail: serde_json::Value = response.json().await.unwrap();
        assert!(detail["text"].is_null());

        // Downloads are always attachments that cannot be sniffed into HTML.
        let response = call(
            reqwest::Method::GET,
            format!("/admin/api/files/{id}/download"),
            Some("viewer-token"),
        )
        .send()
        .await
        .unwrap();
        assert_eq!(response.status(), 200);
        let headers = response.headers().clone();
        assert_eq!(headers[header::CONTENT_TYPE], "application/octet-stream");
        assert_eq!(
            headers[header::CONTENT_DISPOSITION],
            "attachment; filename=\"page.html\""
        );
        assert_eq!(headers[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
        assert_eq!(
            response.bytes().await.unwrap().as_ref(),
            b"<script>alert(1)</script>"
        );
        let response = call(
            reqwest::Method::GET,
            format!("/admin/api/files/{binary_id}/download"),
            Some("admin-token"),
        )
        .send()
        .await
        .unwrap();
        assert_eq!(response.bytes().await.unwrap().as_ref(), bytes.as_slice());
        assert_eq!(download_name("a/b/we\"ird name;.txt"), "we_ird_name_.txt");
        assert_eq!(download_name(".."), "file");

        // The list, the search and the totals; the pulse carries the count.
        let response = call(
            reqwest::Method::GET,
            "/admin/api/files?project=shop&q=binary".into(),
            Some("viewer-token"),
        )
        .send()
        .await
        .unwrap();
        let found: serde_json::Value = response.json().await.unwrap();
        assert_eq!(found["files"].as_array().unwrap().len(), 1);
        assert_eq!(found["counts"]["files"], 2);
        let pulse: serde_json::Value = call(
            reqwest::Method::GET,
            "/admin/api/pulse".into(),
            Some("viewer-token"),
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
        assert_eq!(pulse["files"], 2);

        // Deleting: one version, then every version of a path; unknown
        // ids are a 404.
        let second = json!({ "project": "shop", "path": "docs/page.html",
                             "description": "d", "content": "v2" });
        call(
            reqwest::Method::POST,
            "/admin/api/files".into(),
            Some("admin-token"),
        )
        .json(&second)
        .send()
        .await
        .unwrap();
        let response = call(
            reqwest::Method::DELETE,
            format!("/admin/api/files/{id}"),
            Some("admin-token"),
        )
        .send()
        .await
        .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(
            response.json::<serde_json::Value>().await.unwrap()["deleted"],
            1
        );
        let response = call(
            reqwest::Method::DELETE,
            format!("/admin/api/files/{id}"),
            Some("admin-token"),
        )
        .send()
        .await
        .unwrap();
        assert_eq!(response.status(), 404);
        let response = call(
            reqwest::Method::DELETE,
            format!("/admin/api/files/{binary_id}?all=true"),
            Some("admin-token"),
        )
        .send()
        .await
        .unwrap();
        assert_eq!(response.status(), 200);
        let response = call(
            reqwest::Method::GET,
            "/admin/api/files".into(),
            Some("admin-token"),
        )
        .send()
        .await
        .unwrap();
        let listed: serde_json::Value = response.json().await.unwrap();
        assert_eq!(listed["files"].as_array().unwrap().len(), 1);
        assert_eq!(listed["files"][0]["version"], 2);
        assert_eq!(
            call(
                reqwest::Method::GET,
                "/admin/api/files/999".into(),
                Some("admin-token")
            )
            .send()
            .await
            .unwrap()
            .status(),
            404
        );
    }

    #[tokio::test]
    async fn integrations_reads_and_writes_follow_the_roles() {
        let (base, _admin) = serve().await;
        let client = reqwest::Client::new();
        let call = |method: reqwest::Method, path: String, token: Option<&str>| {
            let mut request = client.request(method, format!("{base}{path}"));
            if let Some(token) = token {
                request = request.header(header::COOKIE, format!("{COOKIE}={token}"));
            }
            request
        };

        // Reads: any signed-in role, nobody else.
        let status = call(reqwest::Method::GET, "/admin/api/integrations".into(), None)
            .send()
            .await
            .unwrap()
            .status();
        assert_eq!(status, 401);
        let response = call(
            reqwest::Method::GET,
            "/admin/api/integrations".into(),
            Some("viewer-token"),
        )
        .send()
        .await
        .unwrap();
        assert_eq!(response.status(), 200);
        let first: serde_json::Value = response.json().await.unwrap();
        assert_eq!(first["vault_enabled"], true);
        assert_eq!(first["enabled"], true);
        assert_eq!(first["providers"].as_array().unwrap().len(), 4);
        assert!(first["permissions"].as_array().unwrap().is_empty());
        assert!(first["log"].as_array().unwrap().is_empty());
        let names: Vec<&str> = first["agents"]
            .as_array()
            .unwrap()
            .iter()
            .map(|agent| agent.as_str().unwrap())
            .collect();
        assert!(names.contains(&"claude"));

        // Writes: the viewer is refused, nobody else is not even signed in.
        let credential = json!({ "secret": "ghp_not-a-real-token-9999", "base_url": "" });
        for token in [None, Some("viewer-token")] {
            let expected = if token.is_some() { 403 } else { 401 };
            for request in [
                call(
                    reqwest::Method::PUT,
                    "/admin/api/integrations/github".into(),
                    token,
                )
                .json(&credential),
                call(
                    reqwest::Method::DELETE,
                    "/admin/api/integrations/github".into(),
                    token,
                ),
                call(
                    reqwest::Method::POST,
                    "/admin/api/integrations/github/test".into(),
                    token,
                ),
                call(
                    reqwest::Method::PUT,
                    "/admin/api/integrations/permissions".into(),
                    token,
                )
                .json(&json!({ "agent": "claude", "provider": "github", "level": "read" })),
                call(
                    reqwest::Method::PUT,
                    "/admin/api/integrations/enabled".into(),
                    token,
                )
                .json(&json!({ "enabled": false })),
            ] {
                assert_eq!(request.send().await.unwrap().status(), expected);
            }
        }

        // The admin stores a GitHub credential.
        let response = call(
            reqwest::Method::PUT,
            "/admin/api/integrations/github".into(),
            Some("admin-token"),
        )
        .json(&credential)
        .send()
        .await
        .unwrap();
        assert_eq!(response.status(), 200);
        // The stored credential never appears in the integrations JSON.
        let response = call(
            reqwest::Method::GET,
            "/admin/api/integrations".into(),
            Some("viewer-token"),
        )
        .send()
        .await
        .unwrap();
        assert_eq!(response.status(), 200);
        let shown: serde_json::Value = response.json().await.unwrap();
        let raw = serde_json::to_string(&shown).unwrap();
        assert!(
            !raw.contains("not-a-real-token"),
            "the credential leaked into the panel JSON"
        );
        let github = shown["providers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|provider| provider["id"] == "github")
            .cloned()
            .unwrap();
        assert_eq!(github["configured"], true);
        assert_eq!(github["hint"], "9999");
        assert!(
            github["updated_at"]
                .as_str()
                .is_some_and(|at| !at.is_empty())
        );

        // A gitlab credential with its server URL; the pasted /api/v4 form
        // is accepted. The URL alone cannot move the stored credential to
        // another server: it is sealed with it, so it must be entered again.
        let gitlab = json!({
            "secret": "glpat_not-real-either-88",
            "base_url": "https://git.example.com/api/v4/",
        });
        let response = call(
            reqwest::Method::PUT,
            "/admin/api/integrations/gitlab".into(),
            Some("admin-token"),
        )
        .json(&gitlab)
        .send()
        .await
        .unwrap();
        assert_eq!(response.status(), 200);
        let response = call(
            reqwest::Method::PUT,
            "/admin/api/integrations/gitlab".into(),
            Some("admin-token"),
        )
        .json(&json!({ "secret": "", "base_url": "https://git.example.de/" }))
        .send()
        .await
        .unwrap();
        assert_eq!(response.status(), 400);
        let body: serde_json::Value = response.json().await.unwrap();
        assert!(
            body["error"]
                .as_str()
                .is_some_and(|error| error.contains("enter the credential again")),
            "{body}"
        );
        let response = call(
            reqwest::Method::PUT,
            "/admin/api/integrations/gitlab".into(),
            Some("admin-token"),
        )
        .json(
            &json!({ "secret": "glpat_not-real-either-88", "base_url": "https://git.example.de/" }),
        )
        .send()
        .await
        .unwrap();
        assert_eq!(response.status(), 200);
        let shown: serde_json::Value = call(
            reqwest::Method::GET,
            "/admin/api/integrations".into(),
            Some("admin-token"),
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
        let gitlab = shown["providers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|provider| provider["id"] == "gitlab")
            .cloned()
            .unwrap();
        assert_eq!(gitlab["base_url"], "https://git.example.de");
        assert_eq!(gitlab["readable"], true);
        assert!(
            !serde_json::to_string(&shown)
                .unwrap()
                .contains("not-real-either"),
            "the credential leaked into the panel JSON"
        );

        // Validation: no secret and no URL; a secret that is too short; a
        // URL on a provider with a fixed base; a URL that is not https.
        for bad in [
            json!({ "secret": "", "base_url": "" }),
            json!({ "secret": "short", "base_url": "" }),
            json!({ "secret": "has a space in it", "base_url": "" }),
            json!({ "secret": "non-ascii-é-secret", "base_url": "" }),
            json!({ "secret": "valid-length-secret", "base_url": "https://example.com" }),
            json!({ "secret": "valid-length-secret", "base_url": "http://git.example.com" }),
        ] {
            let response = call(
                reqwest::Method::PUT,
                "/admin/api/integrations/github".into(),
                Some("admin-token"),
            )
            .json(&bad)
            .send()
            .await
            .unwrap();
            assert_eq!(response.status(), 400);
            let body: serde_json::Value = response.json().await.unwrap();
            assert!(
                body["error"]
                    .as_str()
                    .is_some_and(|error| !error.is_empty())
            );
        }
        // An unknown provider is a 404, on every route.
        for request in [
            call(
                reqwest::Method::PUT,
                "/admin/api/integrations/shop".into(),
                Some("admin-token"),
            )
            .json(&credential),
            call(
                reqwest::Method::DELETE,
                "/admin/api/integrations/shop".into(),
                Some("admin-token"),
            ),
            call(
                reqwest::Method::POST,
                "/admin/api/integrations/shop/test".into(),
                Some("admin-token"),
            ),
        ] {
            assert_eq!(request.send().await.unwrap().status(), 404);
        }

        // The permissions and the kill switch, as the admin sets them.
        let response = call(
            reqwest::Method::PUT,
            "/admin/api/integrations/permissions".into(),
            Some("admin-token"),
        )
        .json(&json!({ "agent": "Claude", "provider": "GitHub", "level": "READ" }))
        .send()
        .await
        .unwrap();
        assert_eq!(response.status(), 200);
        let response = call(
            reqwest::Method::PUT,
            "/admin/api/integrations/enabled".into(),
            Some("admin-token"),
        )
        .json(&json!({ "enabled": false }))
        .send()
        .await
        .unwrap();
        assert_eq!(response.status(), 200);
        let shown: serde_json::Value = call(
            reqwest::Method::GET,
            "/admin/api/integrations".into(),
            Some("viewer-token"),
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
        assert_eq!(shown["enabled"], false);
        let rows = shown["permissions"].as_array().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(
            (
                rows[0]["agent"].as_str().unwrap(),
                rows[0]["provider"].as_str().unwrap(),
                rows[0]["level"].as_str().unwrap()
            ),
            ("claude", "github", "read")
        );
        for bad in [
            json!({ "agent": "", "provider": "github", "level": "read" }),
            json!({ "agent": "claude", "provider": "github", "level": "sometimes" }),
            json!({ "agent": "claude", "provider": "github" }),
        ] {
            let response = call(
                reqwest::Method::PUT,
                "/admin/api/integrations/permissions".into(),
                Some("admin-token"),
            )
            .json(&bad)
            .send()
            .await
            .unwrap();
            assert_eq!(response.status(), 400);
        }
        let response = call(
            reqwest::Method::PUT,
            "/admin/api/integrations/permissions".into(),
            Some("admin-token"),
        )
        .json(&json!({ "agent": "claude", "provider": "shop", "level": "read" }))
        .send()
        .await
        .unwrap();
        assert_eq!(response.status(), 404);
        let response = call(
            reqwest::Method::PUT,
            "/admin/api/integrations/enabled".into(),
            Some("admin-token"),
        )
        .json(&json!({}))
        .send()
        .await
        .unwrap();
        assert_eq!(response.status(), 400);
        // Switched back on.
        let response = call(
            reqwest::Method::PUT,
            "/admin/api/integrations/enabled".into(),
            Some("admin-token"),
        )
        .json(&json!({ "enabled": true }))
        .send()
        .await
        .unwrap();
        assert_eq!(response.status(), 200);

        // A test call against a provider with nothing stored says so, and
        // records itself in the log with the admin's name.
        let response = call(
            reqwest::Method::POST,
            "/admin/api/integrations/cloudflare/test".into(),
            Some("admin-token"),
        )
        .send()
        .await
        .unwrap();
        assert_eq!(response.status(), 200);
        let tested: serde_json::Value = response.json().await.unwrap();
        assert_eq!(tested["ok"], false);
        assert!(
            tested["message"]
                .as_str()
                .is_some_and(|message| message.contains("No cloudflare credential"))
        );

        // Deleting: once, then a 404.
        let response = call(
            reqwest::Method::DELETE,
            "/admin/api/integrations/github".into(),
            Some("admin-token"),
        )
        .send()
        .await
        .unwrap();
        assert_eq!(response.status(), 200);
        let shown: serde_json::Value = call(
            reqwest::Method::GET,
            "/admin/api/integrations".into(),
            Some("viewer-token"),
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
        let github = shown["providers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|provider| provider["id"] == "github")
            .cloned()
            .unwrap();
        assert_eq!(github["configured"], false);
        assert_eq!(github["hint"], "");
        assert_eq!(
            call(
                reqwest::Method::DELETE,
                "/admin/api/integrations/github".into(),
                Some("admin-token"),
            )
            .send()
            .await
            .unwrap()
            .status(),
            404
        );
        // The refused test call left its row, under the admin's name.
        let log = shown["log"].as_array().unwrap();
        assert!(
            log.iter()
                .any(|row| row["agent"] == "admin" && row["provider"] == "cloudflare"),
            "the refused test was not logged"
        );
    }

    #[tokio::test]
    async fn storing_a_credential_needs_the_vault() {
        let (base, _admin) = serve_with(None).await;
        let client = reqwest::Client::new();
        let response = client
            .put(format!("{base}/admin/api/integrations/github"))
            .header(header::COOKIE, format!("{COOKIE}=admin-token"))
            .json(&json!({ "secret": "valid-length-secret", "base_url": "" }))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 400);
        let body: serde_json::Value = response.json().await.unwrap();
        assert!(
            body["error"]
                .as_str()
                .is_some_and(|error| error.contains("LORE_VAULT_KEY")),
            "the error should name the variable: {body}"
        );
        // The panel says the vault is off.
        let shown: serde_json::Value = client
            .get(format!("{base}/admin/api/integrations"))
            .header(header::COOKIE, format!("{COOKIE}=viewer-token"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(shown["vault_enabled"], false);
    }
}
