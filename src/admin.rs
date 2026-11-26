//! The admin view: sign-in with a user name and password (optionally guarded
//! by reCAPTCHA v3), a session cookie that carries the user's permissions,
//! the users panel, JSON and full database backups, and the JSON the brain
//! visualisation draws.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use std::convert::Infallible;

mod agents;
mod builtin;

use axum::{
    Extension, Json, Router,
    body::{Body, Bytes},
    extract::{ConnectInfo, DefaultBodyLimit, MatchedPath, Path, Query, Request, State},
    handler::Handler,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{
        IntoResponse, Response,
        sse::{Event, KeepAlive, Sse},
    },
    routing::{get, post, put},
};
use serde::Deserialize;
use serde_json::json;
use subtle::ConstantTimeEq;
use tokio_stream::{
    Stream, StreamExt,
    wrappers::{BroadcastStream, ReceiverStream},
};

use crate::{
    auth::{RateLimiter, client_ip, too_many_requests},
    db::{
        self, Backup, Db, FileInfo, Message, NewFile, NewMessage, NewTask, NewUser, OPS_LEVELS,
        ProfileInput, Rule, RuleInput, Session, Task, UserPatch,
    },
    embed::Embedder,
    events::Events,
    mail,
    oauth::OAuth,
    ops,
    users::{self, ADMIN_USER, Perm, Perms, VIEWER_USER},
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
/// Largest full database backup accepted for restore: 2 GiB.
const MAX_FULL_RESTORE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
/// Largest profile or rule edit accepted.
const MAX_JSON_BYTES: usize = 64 * 1024;
/// Largest file upload accepted: a 2 MiB file as base64, inside its JSON.
const MAX_FILE_UPLOAD_BYTES: usize = 4 * 1024 * 1024;
/// Longest file text the detail view returns; longer text is cut.
const FILE_TEXT_CHARS: usize = 200_000;
/// Argon2 password checks that may run at the same time.
const ARGON_PERMITS: usize = 3;
/// Name the feed shows for actions taken from this page.
const ADMIN_ACTOR: &str = "admin";
const ICON: &str = include_str!("../assets/icon.svg");
const BACKDROP: &[u8] = include_bytes!("../assets/backdrop.jpg");

const PAGE: &str = include_str!("../assets/admin.html");
const SCRIPT: &str = include_str!("../assets/admin.js");
const STYLE: &str = include_str!("../assets/admin.css");
const CONSENT_SCRIPT: &str = include_str!("../assets/consent.js");
const CONSENT_STYLE: &str = include_str!("../assets/consent.css");

/// The page's Content Security Policy; the OAuth consent page uses it too.
pub(crate) const CSP: &str = "default-src 'none'; script-src 'self' https://www.google.com/recaptcha/ \
https://www.gstatic.com/recaptcha/; style-src 'self'; img-src 'self' data:; connect-src 'self'; \
frame-src https://www.google.com/recaptcha/ https://recaptcha.google.com/recaptcha/; \
base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

pub struct Recaptcha {
    pub site_key: String,
    pub secret: String,
    pub min_score: f64,
}

/// Who a signed-in session belongs to and what it may do, recorded at
/// sign-in. Every signed-in user reads what the viewer reads.
#[derive(Clone, Debug)]
pub struct SignedIn {
    pub username: String,
    /// The stored user's id; `None` for the built-in `admin` and `viewer`.
    pub user_id: Option<i64>,
    pub perms: Perms,
}

impl SignedIn {
    fn builtin_admin() -> Self {
        Self {
            username: ADMIN_USER.into(),
            user_id: None,
            perms: Perms::all(),
        }
    }

    fn builtin_viewer() -> Self {
        Self {
            username: VIEWER_USER.into(),
            user_id: None,
            perms: Perms::none(),
        }
    }

    /// The role older pages read: `admin` with every permission, else
    /// `viewer`.
    fn role(&self) -> &'static str {
        if self.perms.is_all() {
            "admin"
        } else {
            "viewer"
        }
    }
}

struct AdminSession {
    expires: Instant,
    user: SignedIn,
}

/// Who may reach a route.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Access {
    /// Anyone: the page, its assets, signing in and out.
    Public,
    /// Any signed-in user: everything the viewer reads.
    SignedIn,
    /// A signed-in user holding this permission.
    Needs(Perm),
    /// A signed-in user holding every permission: the built-in admin, or a
    /// stored user given all of them. Loading a whole database is as much
    /// as being the administrator.
    Everything,
}

/// Every route of the admin view and who may reach it. The guard looks a
/// request up here by its method and route pattern; a route missing from
/// this table answers 403 to everyone, so a new route stays closed until it
/// is listed. The README carries the same table.
const ROUTES: &[(&str, &str, Access)] = &[
    ("GET", "/admin", Access::Public),
    ("GET", "/admin/app.js", Access::Public),
    ("GET", "/admin/app.css", Access::Public),
    ("GET", "/admin/icon.svg", Access::Public),
    ("GET", "/admin/backdrop.jpg", Access::Public),
    ("GET", "/admin/consent.js", Access::Public),
    ("GET", "/admin/consent.css", Access::Public),
    ("GET", "/admin/avatars/{file}", Access::Public),
    ("GET", "/admin/api/session", Access::Public),
    ("POST", "/admin/api/login", Access::Public),
    ("POST", "/admin/api/logout", Access::Public),
    ("GET", "/admin/api/brain", Access::SignedIn),
    ("GET", "/admin/api/pulse", Access::SignedIn),
    ("GET", "/admin/api/events", Access::SignedIn),
    ("GET", "/admin/api/entries/{id}", Access::SignedIn),
    ("GET", "/admin/api/profile", Access::SignedIn),
    ("GET", "/admin/api/sessions", Access::SignedIn),
    ("GET", "/admin/api/sessions/{id}", Access::SignedIn),
    ("GET", "/admin/api/board", Access::SignedIn),
    ("GET", "/admin/api/files", Access::SignedIn),
    ("GET", "/admin/api/files/{id}", Access::SignedIn),
    ("GET", "/admin/api/files/{id}/download", Access::SignedIn),
    ("GET", "/admin/api/integrations", Access::SignedIn),
    ("GET", "/admin/api/agents", Access::SignedIn),
    ("PUT", "/admin/api/password", Access::SignedIn),
    // The consent page: anyone signed in sees the request (and is told
    // when they lack `agents`) and may deny it; approving needs `agents`.
    ("GET", "/admin/api/oauth/requests/{id}", Access::SignedIn),
    (
        "POST",
        "/admin/api/oauth/requests/{id}/deny",
        Access::SignedIn,
    ),
    (
        "POST",
        "/admin/api/oauth/requests/{id}/approve",
        Access::Needs(Perm::Agents),
    ),
    (
        "PUT",
        "/admin/api/agents/{name}",
        Access::Needs(Perm::Agents),
    ),
    (
        "DELETE",
        "/admin/api/agents/{name}",
        Access::Needs(Perm::Agents),
    ),
    (
        "POST",
        "/admin/api/agents/{name}/revoke",
        Access::Needs(Perm::Agents),
    ),
    ("POST", "/admin/api/tasks", Access::Needs(Perm::Write)),
    ("PUT", "/admin/api/tasks/{id}", Access::Needs(Perm::Write)),
    ("POST", "/admin/api/messages", Access::Needs(Perm::Write)),
    ("POST", "/admin/api/files", Access::Needs(Perm::Write)),
    (
        "DELETE",
        "/admin/api/files/{id}",
        Access::Needs(Perm::Write),
    ),
    ("GET", "/admin/api/export", Access::Needs(Perm::Backup)),
    ("GET", "/admin/api/backup/full", Access::Needs(Perm::Backup)),
    ("POST", "/admin/api/import", Access::Needs(Perm::Restore)),
    // A full database brings its own users, permissions, OAuth tokens and
    // credentials, so restoring one is as much as holding every permission.
    ("POST", "/admin/api/restore/full", Access::Everything),
    ("PUT", "/admin/api/profile", Access::Needs(Perm::Settings)),
    ("POST", "/admin/api/rules", Access::Needs(Perm::Settings)),
    (
        "PUT",
        "/admin/api/rules/{id}",
        Access::Needs(Perm::Settings),
    ),
    (
        "DELETE",
        "/admin/api/rules/{id}",
        Access::Needs(Perm::Settings),
    ),
    (
        "PUT",
        "/admin/api/integrations/{provider}",
        Access::Needs(Perm::Integrations),
    ),
    (
        "DELETE",
        "/admin/api/integrations/{provider}",
        Access::Needs(Perm::Integrations),
    ),
    (
        "POST",
        "/admin/api/integrations/{provider}/test",
        Access::Needs(Perm::Integrations),
    ),
    (
        "PUT",
        "/admin/api/integrations/permissions",
        Access::Needs(Perm::Integrations),
    ),
    (
        "PUT",
        "/admin/api/integrations/enabled",
        Access::Needs(Perm::Integrations),
    ),
    ("GET", "/admin/api/users", Access::Needs(Perm::Users)),
    ("POST", "/admin/api/users", Access::Needs(Perm::Users)),
    ("PUT", "/admin/api/users/{id}", Access::Needs(Perm::Users)),
    (
        "DELETE",
        "/admin/api/users/{id}",
        Access::Needs(Perm::Users),
    ),
];

/// Who may reach a route, or `None` when the table does not list it.
fn access(method: &axum::http::Method, pattern: &str) -> Option<Access> {
    // A HEAD request is answered by the GET handler, so it has its rights.
    let method = if method == axum::http::Method::HEAD {
        "GET"
    } else {
        method.as_str()
    };
    ROUTES
        .iter()
        .chain(builtin::ROUTES)
        .find(|(m, path, _)| *m == method && *path == pattern)
        .map(|(_, _, access)| *access)
}

pub struct Admin {
    pub db: Db,
    pub password: String,
    /// A second password that signs in as the watch-only `viewer`.
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
    /// lore's own secrets, redacted from the Test button's answer too.
    guard: ops::Guard,
    sessions: Mutex<HashMap<String, AdminSession>>,
    logins: RateLimiter,
    /// Argon2 verifications running at once, at most `ARGON_PERMITS`: each
    /// takes 19 MiB and a core, so a flood of sign-ins is answered 429
    /// rather than queued.
    argon: Arc<tokio::sync::Semaphore>,
    /// Set while a full backup is being written or a full restore runs:
    /// one at a time.
    busy: AtomicBool,
    http: reqwest::Client,
    /// The client provider calls go through: no redirects, 60 s timeout.
    ops_http: reqwest::Client,
    /// The OAuth authorization server, whose consent requests the page
    /// answers; `None` when it is not mounted.
    oauth: Option<Arc<OAuth>>,
    /// The built-in agents' runner links; `None` without
    /// `LORE_RUNNER_TOKENS`.
    builtin: Option<Arc<crate::builtin::Hub>>,
}

/// Clears `Admin::busy` when the work that set it ends, however it ends.
struct BusyGuard<'a>(&'a AtomicBool);

impl Drop for BusyGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
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
        guard: ops::Guard,
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
            guard,
            sessions: Mutex::new(HashMap::new()),
            // Five wrong attempts lock the address out for fifteen minutes.
            logins: RateLimiter::new(5, Duration::from_secs(15 * 60)),
            argon: Arc::new(tokio::sync::Semaphore::new(ARGON_PERMITS)),
            busy: AtomicBool::new(false),
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(8))
                .build()
                .expect("building the HTTP client"),
            ops_http: ops::client(),
            oauth: None,
            builtin: None,
        }
    }

    /// Lets the page show and sign in the built-in agents.
    pub fn with_builtin(mut self, hub: Arc<crate::builtin::Hub>) -> Self {
        self.builtin = Some(hub);
        self
    }

    /// Lets the page answer the consent requests of this authorization
    /// server.
    pub fn with_oauth(mut self, oauth: Arc<OAuth>) -> Self {
        self.oauth = Some(oauth);
        self
    }

    fn sessions(&self) -> std::sync::MutexGuard<'_, HashMap<String, AdminSession>> {
        self.sessions.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Who the session a request carries belongs to, if it is live.
    fn signed_in(&self, headers: &HeaderMap) -> Option<SignedIn> {
        let token = cookie(headers, COOKIE)?;
        let mut sessions = self.sessions();
        sessions.retain(|_, session| session.expires > Instant::now());
        sessions.get(&token).map(|session| session.user.clone())
    }

    /// Ends every session of a stored user except `keep` (the session
    /// making the change), whose permissions are brought up to date.
    fn end_sessions_of(&self, user_id: i64, keep: Option<&str>, perms: Option<Perms>) {
        let mut sessions = self.sessions();
        sessions.retain(|token, session| {
            session.user.user_id != Some(user_id) || Some(token.as_str()) == keep
        });
        if let (Some(keep), Some(perms)) = (keep, perms)
            && let Some(session) = sessions.get_mut(keep)
            && session.user.user_id == Some(user_id)
        {
            session.user.perms = perms;
        }
    }

    /// One full backup or restore at a time.
    fn try_busy(&self) -> Option<BusyGuard<'_>> {
        self.busy
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .ok()
            .map(|_| BusyGuard(&self.busy))
    }
}

pub fn router(admin: Arc<Admin>) -> Router {
    router_with(admin, Router::new())
}

/// The admin routes plus `extra`, all behind the access guard.
fn router_with(admin: Arc<Admin>, extra: Router<Arc<Admin>>) -> Router {
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
        .route(
            "/admin/consent.js",
            get(|| async { asset("text/javascript; charset=utf-8", CONSENT_SCRIPT) }),
        )
        .route(
            "/admin/consent.css",
            get(|| async { asset("text/css; charset=utf-8", CONSENT_STYLE) }),
        )
        .route("/admin/avatars/{file}", get(agents::avatar))
        .route("/admin/api/agents", get(agents::list_agents))
        .route(
            "/admin/api/agents/{name}",
            put(agents::update_agent)
                .layer(DefaultBodyLimit::max(MAX_JSON_BYTES))
                .delete(agents::delete_agent),
        )
        .route(
            "/admin/api/agents/{name}/revoke",
            post(agents::revoke_agent),
        )
        .route(
            "/admin/api/oauth/requests/{id}",
            get(agents::consent_request),
        )
        .route(
            "/admin/api/oauth/requests/{id}/approve",
            post(agents::consent_approve).layer(DefaultBodyLimit::max(MAX_JSON_BYTES)),
        )
        .route(
            "/admin/api/oauth/requests/{id}/deny",
            post(agents::consent_deny).layer(DefaultBodyLimit::max(MAX_JSON_BYTES)),
        )
        .route("/admin/api/session", get(session))
        .route("/admin/api/login", post(login))
        .route("/admin/api/logout", post(logout))
        // Reading: any signed-in user.
        .route("/admin/api/brain", get(brain))
        .route("/admin/api/pulse", get(pulse))
        .route("/admin/api/events", get(events))
        .route("/admin/api/entries/{id}", get(entry))
        .route("/admin/api/sessions", get(sessions))
        .route("/admin/api/sessions/{id}", get(session_detail))
        .route("/admin/api/board", get(board))
        .route("/admin/api/integrations", get(integrations))
        .route(
            "/admin/api/password",
            put(change_own_password).layer(DefaultBodyLimit::max(MAX_JSON_BYTES)),
        )
        // Backups carry the whole store.
        .route("/admin/api/export", get(export))
        .route(
            "/admin/api/import",
            post(import).layer(DefaultBodyLimit::max(MAX_BACKUP_BYTES)),
        )
        .route("/admin/api/backup/full", get(full_backup))
        // The upload is streamed to disk with its own cap.
        .route(
            "/admin/api/restore/full",
            post(full_restore).layer(DefaultBodyLimit::disable()),
        )
        .route(
            "/admin/api/profile",
            get(profile).put(save_profile.layer(DefaultBodyLimit::max(MAX_JSON_BYTES))),
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
            get(files).post(upload_file.layer(DefaultBodyLimit::max(MAX_FILE_UPLOAD_BYTES))),
        )
        .route(
            "/admin/api/files/{id}",
            get(file_detail).delete(delete_file),
        )
        .route("/admin/api/files/{id}/download", get(download_file))
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
        .route(
            "/admin/api/users",
            get(list_users).post(add_user.layer(DefaultBodyLimit::max(MAX_JSON_BYTES))),
        )
        .route(
            "/admin/api/users/{id}",
            put(update_user)
                .layer(DefaultBodyLimit::max(MAX_JSON_BYTES))
                .delete(delete_user),
        )
        .merge(builtin::routes())
        .merge(extra)
        .route_layer(middleware::from_fn_with_state(admin.clone(), guard))
        .layer(middleware::from_fn(security_headers))
        .with_state(admin)
}

/// Identifies the page assets compiled into this binary. An open page compares
/// it with the one it was loaded from and reloads itself after a deploy, so
/// nobody keeps working in an outdated page.
fn build_id() -> String {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    (PAGE, SCRIPT, STYLE, builtin::SCRIPT, builtin::STYLE).hash(&mut hasher);
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
    // Nothing is stored, except what says otherwise (the avatars).
    headers
        .entry(header::CACHE_CONTROL)
        .or_insert(HeaderValue::from_static("no-store"));
    response
}

/// Lets a request through only when `ROUTES` allows it: a signed-in user
/// for reads, the route's permission for everything else. The signed-in
/// user is handed to the handler as a request extension.
async fn guard(State(admin): State<Arc<Admin>>, mut request: Request, next: Next) -> Response {
    let pattern = request
        .extensions()
        .get::<MatchedPath>()
        .map(|path| path.as_str().to_string())
        .unwrap_or_default();
    let Some(access) = access(request.method(), &pattern) else {
        tracing::warn!(route = %pattern, "a route missing from the access table was refused");
        return forbidden("this route is not open to anyone");
    };
    if access == Access::Public {
        return next.run(request).await;
    }
    let Some(user) = admin.signed_in(request.headers()) else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "sign in first" })),
        )
            .into_response();
    };
    if let Access::Needs(perm) = access
        && !user.perms.contains(perm)
    {
        return forbidden(&format!("this needs the {} permission", perm.id()));
    }
    if access == Access::Everything && !user.perms.is_all() {
        return forbidden(
            "restoring a full database needs every permission: the file brings its own users, \
             permissions and tokens, so it is as much as being the administrator",
        );
    }
    request.extensions_mut().insert(user);
    next.run(request).await
}

fn forbidden(message: &str) -> Response {
    (StatusCode::FORBIDDEN, Json(json!({ "error": message }))).into_response()
}

/// Tells the page whether it is signed in, as whom, with which
/// permissions, and which reCAPTCHA key to load. `role` stays for pages
/// cached before permissions existed.
async fn session(State(admin): State<Arc<Admin>>, headers: HeaderMap) -> Json<serde_json::Value> {
    let user = admin.signed_in(&headers);
    Json(json!({
        "authenticated": user.is_some(),
        "build": build_id(),
        "role": user.as_ref().map(SignedIn::role),
        "username": user.as_ref().map(|user| user.username.as_str()),
        "permissions": user.as_ref().map(|user| user.perms.ids()),
        "stored": user.as_ref().is_some_and(|user| user.user_id.is_some()),
        "recaptcha_site_key": admin.recaptcha.as_ref().map(|r| r.site_key.as_str()),
    }))
}

#[derive(Deserialize)]
struct LoginForm {
    /// A user name or a stored user's e-mail address. Empty tries the
    /// built-in `admin`, then `viewer`, as before user names existed.
    #[serde(default)]
    username: String,
    password: String,
    #[serde(default)]
    captcha: String,
}

impl std::fmt::Debug for LoginForm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginForm")
            .field("username", &self.username)
            .field("password", &"[redacted]")
            .finish()
    }
}

/// How a sign-in attempt went.
enum LoginOutcome {
    Ok(SignedIn),
    Wrong,
    /// The password was right, but the user is disabled.
    Disabled,
    /// Every Argon2 slot is taken: nothing was checked.
    Busy,
}

/// Checks a user name and password. Built-in passwords are compared in
/// constant time; stored users are verified against their Argon2id hash,
/// and an unknown name against a dummy hash, so it takes as long.
async fn check_login(admin: &Arc<Admin>, username: &str, password: String) -> LoginOutcome {
    let presented = password.as_bytes();
    let is_admin = || bool::from(presented.ct_eq(admin.password.as_bytes()));
    let is_viewer = || {
        admin
            .viewer_password
            .as_ref()
            .is_some_and(|viewer| bool::from(presented.ct_eq(viewer.as_bytes())))
    };
    match username {
        "" => {
            // Check both passwords every time so timing does not tell them apart.
            match (is_admin(), is_viewer()) {
                (true, _) => LoginOutcome::Ok(SignedIn::builtin_admin()),
                (false, true) => LoginOutcome::Ok(SignedIn::builtin_viewer()),
                (false, false) => LoginOutcome::Wrong,
            }
        }
        ADMIN_USER if is_admin() => LoginOutcome::Ok(SignedIn::builtin_admin()),
        VIEWER_USER if is_viewer() => LoginOutcome::Ok(SignedIn::builtin_viewer()),
        ADMIN_USER | VIEWER_USER => LoginOutcome::Wrong,
        name => {
            // The slot moves into the blocking task, so it is held until
            // the hash is checked even when the request goes away.
            let Ok(permit) = admin.argon.clone().try_acquire_owned() else {
                return LoginOutcome::Busy;
            };
            let (state, name) = (admin.clone(), name.to_string());
            let checked = tokio::task::spawn_blocking(move || -> anyhow::Result<LoginOutcome> {
                let _permit = permit;
                let found = state.db.user_login(&name)?;
                let hash = found
                    .as_ref()
                    .map_or(users::dummy_hash(), |login| login.password_hash.as_str());
                let matches = users::verify_password(&password, hash);
                let Some(login) = found.filter(|_| matches) else {
                    return Ok(LoginOutcome::Wrong);
                };
                if login.user.disabled {
                    return Ok(LoginOutcome::Disabled);
                }
                state.db.touch_user_login(login.user.id)?;
                Ok(LoginOutcome::Ok(SignedIn {
                    perms: login.user.perms(),
                    username: login.user.username,
                    user_id: Some(login.user.id),
                }))
            })
            .await;
            match checked {
                Ok(Ok(outcome)) => outcome,
                Ok(Err(error)) => {
                    tracing::error!(%error, "checking a sign-in failed");
                    LoginOutcome::Wrong
                }
                Err(error) => {
                    tracing::error!(%error, "the sign-in task failed");
                    LoginOutcome::Wrong
                }
            }
        }
    }
}

async fn login(
    State(admin): State<Arc<Admin>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(form): Json<LoginForm>,
) -> Response {
    let ip = client_ip(&headers, Some(peer), admin.trust_proxy);
    // Every attempt counts before anything is checked, so parallel requests
    // cannot all slip under the limit; a successful sign-in clears it.
    if let Some(retry_after) = admin.logins.hit(&ip) {
        return too_many_requests(retry_after);
    }

    if let Some(recaptcha) = &admin.recaptcha
        && let Err(reason) = verify_captcha(&admin.http, recaptcha, &form.captcha, &ip).await
    {
        tracing::warn!(%ip, %reason, "admin login rejected by reCAPTCHA");
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "The request looked automated. Try again." })),
        )
            .into_response();
    }

    let username = form.username.trim().to_lowercase();
    let user = match check_login(&admin, &username, form.password).await {
        LoginOutcome::Ok(user) => user,
        LoginOutcome::Busy => {
            tracing::warn!(%ip, "sign-in refused: every password check slot is busy");
            return too_many_requests(2);
        }
        LoginOutcome::Wrong => {
            tracing::warn!(%ip, "admin login with a wrong user name or password");
            tokio::time::sleep(Duration::from_millis(400)).await;
            let message = if username.is_empty() {
                "Wrong password."
            } else {
                "Wrong user name or password."
            };
            return (StatusCode::UNAUTHORIZED, Json(json!({ "error": message }))).into_response();
        }
        LoginOutcome::Disabled => {
            tracing::warn!(%ip, "sign-in by a disabled user");
            return forbidden("This user is disabled.");
        }
    };

    let token = match random_token() {
        Ok(token) => token,
        Err(error) => {
            tracing::error!(%error, "no randomness for a session token");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    // The user may have been changed, disabled or deleted while the
    // password was checked: the session gets the state as it is now.
    let state = admin.clone();
    let session_token = token.clone();
    let started =
        tokio::task::spawn_blocking(move || start_session(&state, &session_token, user)).await;
    let user = match started {
        Ok(Ok(Some(user))) => user,
        Ok(Ok(None)) => {
            tracing::warn!(%ip, "a sign-in raced a change to its user and was refused");
            return forbidden("This user was changed or disabled while signing in.");
        }
        Ok(Err(error)) => {
            tracing::error!(%error, "starting a session failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
        Err(error) => {
            tracing::error!(%error, "the session task failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    admin.logins.reset(&ip);
    let body = json!({
        "ok": true,
        "role": user.role(),
        "username": user.username,
        "permissions": user.perms.ids(),
        "stored": user.user_id.is_some(),
    });
    tracing::info!(%ip, user = %user.username, "signed in to the admin view");
    let cookie = format!(
        "{COOKIE}={token}; Path=/admin; HttpOnly; Secure; SameSite=Strict; Max-Age={}",
        SESSION_TTL.as_secs()
    );
    ([(header::SET_COOKIE, cookie)], Json(body)).into_response()
}

/// Inserts the session for a checked sign-in. A stored user is read again
/// under the sessions lock: a change made while the password was being
/// checked (disabled, deleted, other permissions) either shows here or
/// ends this session right after, because `end_sessions_of` needs the same
/// lock. `None` when the user is gone or disabled.
fn start_session(
    admin: &Admin,
    token: &str,
    mut user: SignedIn,
) -> anyhow::Result<Option<SignedIn>> {
    let mut sessions = admin.sessions();
    if let Some(id) = user.user_id {
        match admin.db.user(id)? {
            Some(now) if !now.disabled && now.username == user.username => {
                user.perms = now.perms();
            }
            _ => return Ok(None),
        }
    }
    sessions.insert(
        token.to_string(),
        AdminSession {
            expires: Instant::now() + SESSION_TTL,
            user: user.clone(),
        },
    );
    Ok(Some(user))
}

async fn logout(State(admin): State<Arc<Admin>>, headers: HeaderMap) -> Response {
    if let Some(token) = cookie(&headers, COOKIE) {
        admin.sessions().remove(&token);
    }
    let expired = format!("{COOKIE}=; Path=/admin; HttpOnly; Secure; SameSite=Strict; Max-Age=0");
    ([(header::SET_COOKIE, expired)], Json(json!({ "ok": true }))).into_response()
}

/// Notes a change made from the page in the activity feed.
fn note_activity(admin: &Admin, tool: &str, summary: &str) {
    if let Ok(activity) = admin
        .db
        .record_activity(ADMIN_ACTOR, tool, "", None, None, &[], summary)
    {
        admin.events.publish(activity);
    }
}

/// The stored users, the built-in ones (which cannot be changed here) and
/// what each permission means.
async fn list_users(State(admin): State<Arc<Admin>>) -> Response {
    let state = admin.clone();
    let result = tokio::task::spawn_blocking(move || -> anyhow::Result<serde_json::Value> {
        let mut builtin =
            vec![json!({ "username": ADMIN_USER, "permissions": Perms::all().ids() })];
        if state.viewer_password.is_some() {
            builtin.push(json!({ "username": VIEWER_USER, "permissions": Perms::none().ids() }));
        }
        let permissions: Vec<serde_json::Value> = Perm::ALL
            .iter()
            .map(|perm| json!({ "id": perm.id(), "explanation": perm.explanation() }))
            .collect();
        Ok(json!({
            "users": state.db.users()?,
            "builtin": builtin,
            "permissions": permissions,
        }))
    })
    .await;
    respond(result)
}

#[derive(Deserialize)]
struct NewUserForm {
    #[serde(default)]
    username: String,
    #[serde(default)]
    email: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    permissions: Vec<String>,
}

async fn add_user(
    State(admin): State<Arc<Admin>>,
    Extension(me): Extension<SignedIn>,
    Json(form): Json<NewUserForm>,
) -> Response {
    let username = match users::normalize_username(&form.username) {
        Ok(name) => name,
        Err(message) => return bad_request(&message),
    };
    let email = match users::normalize_email(&form.email) {
        Ok(email) => email,
        Err(message) => return bad_request(&message),
    };
    if let Err(message) = users::check_password(&form.password) {
        return bad_request(&message);
    }
    let perms = match Perms::parse(&form.permissions) {
        Ok(perms) => perms,
        Err(message) => return bad_request(&message),
    };
    if let Err(message) = may_grant(&me, perms) {
        return forbidden(&message);
    }
    let state = admin.clone();
    let password = form.password;
    let result = tokio::task::spawn_blocking(move || -> anyhow::Result<db::User> {
        let user = state.db.add_user(&NewUser {
            username,
            email,
            password_hash: users::hash_password(&password)?,
            permissions: perms,
            created_by: me.username.clone(),
        })?;
        let summary = format!(
            "{} added the user {} ({})",
            me.username,
            user.username,
            describe_perms(perms)
        );
        note_activity(&state, "users", &summary);
        Ok(user)
    })
    .await;
    match result {
        Ok(Ok(user)) => Json(user).into_response(),
        Ok(Err(error)) => bad_request(&error.to_string()),
        Err(error) => {
            tracing::error!(%error, "adding a user failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// A user may grant only permissions they hold themselves; the built-in
/// admin holds every one.
fn may_grant(me: &SignedIn, perms: Perms) -> Result<(), String> {
    if perms.is_subset_of(me.perms) {
        Ok(())
    } else {
        Err(format!(
            "you can only grant permissions you hold yourself; you do not hold {}",
            perms.without(me.perms).ids().join(", ")
        ))
    }
}

/// A user may change, disable or delete (or set the password of) only a
/// stored user whose every permission they hold themselves.
fn may_manage(me: &SignedIn, user: &db::User) -> Result<(), String> {
    let missing = user.perms().without(me.perms);
    if missing == Perms::none() {
        Ok(())
    } else {
        Err(format!(
            "{} holds permissions you do not hold ({}), so you cannot change or delete them",
            user.username,
            missing.ids().join(", ")
        ))
    }
}

/// How a change to a stored user went, past the request checks.
enum UserChange<T> {
    Done(T),
    Missing,
    Forbidden(String),
}

/// Permission ids for an activity note.
fn describe_perms(perms: Perms) -> String {
    if perms == Perms::none() {
        "read only".into()
    } else {
        perms.ids().join(", ")
    }
}

#[derive(Deserialize)]
struct UserForm {
    /// Absent leaves it; empty removes it.
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    permissions: Option<Vec<String>>,
    #[serde(default)]
    disabled: Option<bool>,
    /// A new password; absent or empty leaves it.
    #[serde(default)]
    password: Option<String>,
}

/// Changes a stored user. A user cannot take `users` away from themselves
/// or disable themselves. A new password, other permissions or disabling
/// ends the user's sessions.
async fn update_user(
    State(admin): State<Arc<Admin>>,
    Extension(me): Extension<SignedIn>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(form): Json<UserForm>,
) -> Response {
    let myself = me.user_id == Some(id);
    let mut patch = UserPatch::default();
    if let Some(email) = &form.email {
        match users::normalize_email(email) {
            Ok(email) => patch.email = Some(email),
            Err(message) => return bad_request(&message),
        }
    }
    if let Some(ids) = &form.permissions {
        match Perms::parse(ids) {
            Ok(perms) => patch.permissions = Some(perms),
            Err(message) => return bad_request(&message),
        }
    }
    if myself
        && patch
            .permissions
            .is_some_and(|perms| !perms.contains(Perm::Users))
    {
        return bad_request("you cannot remove the users permission from yourself");
    }
    if myself && form.disabled == Some(true) {
        return bad_request("you cannot disable yourself");
    }
    if let Some(perms) = patch.permissions
        && let Err(message) = may_grant(&me, perms)
    {
        return forbidden(&message);
    }
    patch.disabled = form.disabled;
    let password = form.password.filter(|password| !password.is_empty());
    if let Some(password) = &password
        && let Err(message) = users::check_password(password)
    {
        return bad_request(&message);
    }
    let keep = cookie(&headers, COOKIE);
    let state = admin.clone();
    let result = tokio::task::spawn_blocking(move || -> anyhow::Result<UserChange<db::User>> {
        let Some(before) = state.db.user(id)? else {
            return Ok(UserChange::Missing);
        };
        if let Err(message) = may_manage(&me, &before) {
            return Ok(UserChange::Forbidden(message));
        }
        if let Some(password) = &password {
            patch.password_hash = Some(users::hash_password(password)?);
        }
        let Some(after) = state.db.update_user(id, &patch)? else {
            return Ok(UserChange::Missing);
        };
        let mut changes = Vec::new();
        if before.email != after.email {
            changes.push("e-mail".to_string());
        }
        let perms_changed = before.permissions != after.permissions;
        if perms_changed {
            changes.push(format!("permissions ({})", describe_perms(after.perms())));
        }
        if before.disabled != after.disabled {
            changes.push(
                if after.disabled {
                    "disabled"
                } else {
                    "enabled"
                }
                .to_string(),
            );
        }
        if password.is_some() {
            changes.push("password".to_string());
        }
        if password.is_some() || perms_changed || after.disabled {
            state.end_sessions_of(id, keep.as_deref(), Some(after.perms()));
        }
        if !changes.is_empty() {
            let summary = format!(
                "{} changed the user {}: {}",
                me.username,
                after.username,
                changes.join(", ")
            );
            note_activity(&state, "users", &summary);
        }
        Ok(UserChange::Done(after))
    })
    .await;
    match result {
        Ok(Ok(UserChange::Done(user))) => Json(user).into_response(),
        Ok(Ok(UserChange::Missing)) => StatusCode::NOT_FOUND.into_response(),
        Ok(Ok(UserChange::Forbidden(message))) => forbidden(&message),
        Ok(Err(error)) => bad_request(&error.to_string()),
        Err(error) => {
            tracing::error!(%error, "changing a user failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// Removes a stored user and ends their sessions. Nobody deletes themselves.
async fn delete_user(
    State(admin): State<Arc<Admin>>,
    Extension(me): Extension<SignedIn>,
    Path(id): Path<i64>,
) -> Response {
    if me.user_id == Some(id) {
        return bad_request("you cannot delete yourself");
    }
    let state = admin.clone();
    let result = tokio::task::spawn_blocking(move || -> anyhow::Result<UserChange<()>> {
        let Some(before) = state.db.user(id)? else {
            return Ok(UserChange::Missing);
        };
        if let Err(message) = may_manage(&me, &before) {
            return Ok(UserChange::Forbidden(message));
        }
        let Some(user) = state.db.delete_user(id)? else {
            return Ok(UserChange::Missing);
        };
        state.end_sessions_of(id, None, None);
        let summary = format!("{} deleted the user {}", me.username, user.username);
        note_activity(&state, "users", &summary);
        Ok(UserChange::Done(()))
    })
    .await;
    match result {
        Ok(Ok(UserChange::Done(()))) => Json(json!({ "ok": true })).into_response(),
        Ok(Ok(UserChange::Missing)) => StatusCode::NOT_FOUND.into_response(),
        Ok(Ok(UserChange::Forbidden(message))) => forbidden(&message),
        Ok(Err(error)) => bad_request(&error.to_string()),
        Err(error) => {
            tracing::error!(%error, "deleting a user failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[derive(Deserialize)]
struct PasswordForm {
    #[serde(default)]
    current: String,
    #[serde(default)]
    password: String,
}

impl std::fmt::Debug for PasswordForm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PasswordForm { [redacted] }")
    }
}

/// A stored user changes their own password; the current one is required.
/// Their other sessions end; this one stays.
async fn change_own_password(
    State(admin): State<Arc<Admin>>,
    Extension(me): Extension<SignedIn>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(form): Json<PasswordForm>,
) -> Response {
    let Some(id) = me.user_id else {
        return bad_request(
            "the built-in users' passwords are set in the server environment, not here",
        );
    };
    let ip = client_ip(&headers, Some(peer), admin.trust_proxy);
    if let Err(message) = users::check_password(&form.password) {
        return bad_request(&message);
    }
    // Like a sign-in: the attempt counts before the current password is
    // checked, and the check needs a free Argon2 slot.
    if let Some(retry_after) = admin.logins.hit(&ip) {
        return too_many_requests(retry_after);
    }
    let Ok(permit) = admin.argon.clone().try_acquire_owned() else {
        return too_many_requests(2);
    };
    let keep = cookie(&headers, COOKIE);
    let state = admin.clone();
    let result =
        tokio::task::spawn_blocking(move || -> anyhow::Result<Result<(), &'static str>> {
            let _permit = permit;
            let Some(hash) = state.db.user_password_hash(id)? else {
                return Ok(Err("your user no longer exists"));
            };
            if !users::verify_password(&form.current, &hash) {
                return Ok(Err("the current password is wrong"));
            }
            let patch = UserPatch {
                password_hash: Some(users::hash_password(&form.password)?),
                ..UserPatch::default()
            };
            state.db.update_user(id, &patch)?;
            state.end_sessions_of(id, keep.as_deref(), None);
            let summary = format!("{} changed their password", me.username);
            note_activity(&state, "users", &summary);
            Ok(Ok(()))
        })
        .await;
    match result {
        Ok(Ok(Ok(()))) => {
            admin.logins.reset(&ip);
            Json(json!({ "ok": true })).into_response()
        }
        Ok(Ok(Err(message))) => bad_request(message),
        Ok(Err(error)) => bad_request(&error.to_string()),
        Err(error) => {
            tracing::error!(%error, "changing a password failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// Downloads the whole SQLite database: a consistent snapshot made with the
/// online backup API into a temporary file, streamed from disk and removed
/// as soon as it is open. The connection is free while it streams.
async fn full_backup(State(admin): State<Arc<Admin>>) -> Response {
    let Some(busy) = admin.try_busy() else {
        return conflict();
    };
    let db = admin.db.clone();
    let snapshot = tokio::task::spawn_blocking(move || -> anyhow::Result<(std::fs::File, u64)> {
        let path = db.temp_path("backup")?;
        let opened = db.snapshot_to(&path).and_then(|()| {
            let file = std::fs::File::open(&path)?;
            let length = file.metadata()?.len();
            Ok((file, length))
        });
        // The open handle keeps the bytes readable; the name goes now, so
        // nothing is left behind whatever happens to the download.
        db::remove_database_files(&path);
        opened
    })
    .await;
    drop(busy);
    let (file, length) = match snapshot {
        Ok(Ok(pair)) => pair,
        Ok(Err(error)) => {
            tracing::error!(%error, "writing the full backup failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
        Err(error) => {
            tracing::error!(%error, "the full backup task failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let (sender, receiver) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(4);
    tokio::task::spawn_blocking(move || {
        use std::io::Read;
        let mut file = file;
        let mut buffer = vec![0u8; 256 * 1024];
        loop {
            match file.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => {
                    let chunk = Bytes::copy_from_slice(&buffer[..read]);
                    if sender.blocking_send(Ok(chunk)).is_err() {
                        break;
                    }
                }
                Err(error) => {
                    let _ = sender.blocking_send(Err(error));
                    break;
                }
            }
        }
    });
    tracing::info!(bytes = length, "full database backup downloaded");
    let name = format!(
        "attachment; filename=\"lore-full-{}.sqlite\"",
        db::utc_stamp()
    );
    (
        [
            (header::CONTENT_TYPE, "application/octet-stream".to_string()),
            (header::CONTENT_DISPOSITION, name),
            (header::CONTENT_LENGTH, length.to_string()),
        ],
        Body::from_stream(ReceiverStream::new(receiver)),
    )
        .into_response()
}

fn conflict() -> Response {
    (
        StatusCode::CONFLICT,
        Json(json!({ "error": "a full backup or restore is already running; try again shortly" })),
    )
        .into_response()
}

fn refused(check: &str, message: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({ "error": message, "check": check })),
    )
        .into_response()
}

/// Replaces the whole database with an uploaded `.sqlite` full backup.
/// The upload is streamed to a temporary file and checked before anything
/// is touched; a safety copy of the current database is written; then the
/// backup is loaded all or nothing. Any refusal leaves the live database
/// as it was and names the check that failed.
async fn full_restore(
    State(admin): State<Arc<Admin>>,
    Extension(me): Extension<SignedIn>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let declared = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok());
    if declared.is_some_and(|length| length > MAX_FULL_RESTORE_BYTES) {
        return too_large();
    }
    let Some(_busy) = admin.try_busy() else {
        return conflict();
    };
    // Owns the temporary file from before the first byte arrives: however
    // the request ends (refused, done, or dropped because the client went
    // away mid-upload), the file goes with it.
    let temp = match admin.db.temp_path("restore") {
        Ok(path) => TempFile(path),
        Err(error) => {
            tracing::error!(%error, "no temporary file for the restore");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let received = receive_upload(body, &temp.0).await;
    match received {
        Err(Upload::TooLarge) => too_large(),
        Err(Upload::Failed(reason)) => refused("upload", &reason),
        Ok(0) => refused("upload", "the upload was empty"),
        Ok(_) => {
            let state = admin.clone();
            // The blocking work owns the file now: if the client leaves
            // while it runs, the file is removed when it ends, not before.
            let outcome = tokio::task::spawn_blocking(move || {
                let temp = temp;
                restore_prepared(&state, &me, &temp.0)
            })
            .await;
            match outcome {
                Ok(Ok(value)) => Json(value).into_response(),
                Ok(Err(refusal)) if refusal.check == "after-load" => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": refusal.message, "check": refusal.check })),
                )
                    .into_response(),
                Ok(Err(refusal)) => {
                    tracing::warn!(check = refusal.check, reason = %refusal.message, "full restore refused");
                    refused(refusal.check, &refusal.message)
                }
                Err(error) => {
                    tracing::error!(%error, "the restore task failed");
                    StatusCode::INTERNAL_SERVER_ERROR.into_response()
                }
            }
        }
    }
}

/// A temporary database file, removed (with its journal files) when this
/// is dropped.
struct TempFile(std::path::PathBuf);

impl Drop for TempFile {
    fn drop(&mut self) {
        db::remove_database_files(&self.0);
    }
}

fn too_large() -> Response {
    (
        StatusCode::PAYLOAD_TOO_LARGE,
        Json(json!({ "error": "the file is larger than 2 GiB" })),
    )
        .into_response()
}

enum Upload {
    TooLarge,
    Failed(String),
}

/// Streams a request body to `path`, never holding more than one chunk in
/// memory. Returns the byte count.
async fn receive_upload(body: Body, path: &std::path::Path) -> Result<u64, Upload> {
    use tokio::io::AsyncWriteExt;
    let mut file = tokio::fs::File::create(path)
        .await
        .map_err(|error| Upload::Failed(format!("the upload could not be stored: {error}")))?;
    let mut stream = body.into_data_stream();
    let mut total: u64 = 0;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| Upload::Failed("the upload was interrupted".into()))?;
        total += chunk.len() as u64;
        if total > MAX_FULL_RESTORE_BYTES {
            return Err(Upload::TooLarge);
        }
        file.write_all(&chunk)
            .await
            .map_err(|error| Upload::Failed(format!("the upload could not be stored: {error}")))?;
    }
    file.flush()
        .await
        .map_err(|error| Upload::Failed(format!("the upload could not be stored: {error}")))?;
    file.sync_all()
        .await
        .map_err(|error| Upload::Failed(format!("the upload could not be stored: {error}")))?;
    Ok(total)
}

/// The blocking part of a full restore, once the upload is on disk.
fn restore_prepared(
    admin: &Arc<Admin>,
    me: &SignedIn,
    path: &std::path::Path,
) -> Result<serde_json::Value, db::Refusal> {
    db::check_full_backup(path)?;
    db::prepare_full_backup(path)?;
    let snapshot = admin
        .db
        .write_safety_snapshot()
        .map_err(|error| db::Refusal {
            check: "snapshot",
            message: format!(
                "the safety copy of the current database could not be written: {error}"
            ),
        })?;
    let counts = admin.db.load_full_backup(path).map_err(|error| match error {
        db::LoadError::Unchanged(error) => db::Refusal {
            check: "load",
            message: format!("the backup could not be loaded; nothing changed: {error}"),
        },
        db::LoadError::Replaced(error) => {
            tracing::error!(%error, snapshot = %snapshot, "a full restore failed after the database was replaced");
            // The sessions follow what the database now holds.
            keep_sessions_of_existing_users(admin);
            db::Refusal {
                check: "after-load",
                message: format!(
                    "the backup replaced the database, but a later step failed: {error}. The \
                     database may now be the backup without lore's latest schema changes; \
                     restart lore, which runs them again. The database as it was before the \
                     restore is in the safety copy {snapshot} in the data directory."
                ),
            }
        }
    })?;
    // Derived state: vectors from another model are dropped and computed
    // again in the background, like after a JSON restore.
    if let Some(model) = admin.embedding_model
        && let Err(error) = admin.db.use_embedding_model(model)
    {
        tracing::warn!(%error, "checking the embedding model after a restore failed");
    }
    let (db, embedder) = (admin.db.clone(), admin.embedder.clone());
    std::thread::spawn(move || {
        if let Err(error) = embedder.backfill(&db) {
            tracing::warn!(%error, "embedding restored entries failed");
        }
    });
    keep_sessions_of_existing_users(admin);
    let entries = counts
        .iter()
        .find(|(table, _)| table == "entries")
        .map_or(0, |(_, count)| *count);
    let summary = format!(
        "{} restored a full database backup ({entries} entries)",
        me.username
    );
    tracing::info!(entries, snapshot = %snapshot, "full database backup restored");
    note_activity(admin, "restore", &summary);
    let tables: serde_json::Map<String, serde_json::Value> = counts
        .into_iter()
        .map(|(table, count)| (table, json!(count)))
        .collect();
    Ok(json!({ "ok": true, "tables": tables, "snapshot": snapshot }))
}

/// After a full restore, a stored user's session stays only when the
/// restored database has that user, enabled, with the same permissions.
fn keep_sessions_of_existing_users(admin: &Admin) {
    let users: HashMap<i64, db::User> = match admin.db.users() {
        Ok(list) => list.into_iter().map(|user| (user.id, user)).collect(),
        Err(error) => {
            tracing::warn!(%error, "listing users after a restore failed; ending their sessions");
            HashMap::new()
        }
    };
    admin
        .sessions()
        .retain(|_, session| match session.user.user_id {
            None => true,
            Some(id) => users.get(&id).is_some_and(|user| {
                user.username == session.user.username
                    && !user.disabled
                    && user.perms() == session.user.perms
            }),
        });
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
/// switch, the HTTP providers and the mailbox (each with its own levels
/// and default level), the agents with their permissions and the latest
/// operations. No credential in any of it.
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
                "kind": "http",
                "levels": OPS_LEVELS,
                "default_level": "full",
            }));
        }
        // The mailbox: not an HTTP provider, read-only, off by default.
        let stored = state.db.mail_vault()?;
        let readable = match (&stored, state.vault.as_ref()) {
            (Some(stored), Some(key)) => mail::Mailbox::open(key, stored).is_ok(),
            _ => false,
        };
        providers.push(json!({
            "id": mail::ID,
            "label": mail::LABEL,
            "needs_url": false,
            "configured": stored.is_some(),
            "readable": readable,
            "base_url": "",
            "hint": "",
            "updated_at": stored.as_ref().map(|row| row.updated_at.clone()).unwrap_or_default(),
            "kind": "mail",
            "host": stored.as_ref().map(|row| row.host.clone()).unwrap_or_default(),
            "port": stored.as_ref().map_or(mail::DEFAULT_PORT, |row| row.port),
            "account": stored.as_ref().map(|row| row.account.clone()).unwrap_or_default(),
            "levels": db::MAIL_LEVELS,
            "default_level": db::MAIL_DEFAULT_LEVEL,
        }));
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
    /// The mailbox only: server host, port and account.
    #[serde(default)]
    host: String,
    #[serde(default)]
    port: Option<u32>,
    #[serde(default)]
    account: String,
}

/// Stores one provider's credential, or changes the server URL of one
/// already stored. The secret is encrypted before it is written; no
/// response, log line or activity summary ever carries it.
async fn save_integration(
    State(admin): State<Arc<Admin>>,
    Path(provider_id): Path<String>,
    Json(form): Json<IntegrationForm>,
) -> Response {
    if provider_id.trim().eq_ignore_ascii_case(mail::ID) {
        return save_mail(admin, form).await;
    }
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

/// Removes one provider's credential, or the mailbox.
async fn delete_integration(
    State(admin): State<Arc<Admin>>,
    Path(provider_id): Path<String>,
) -> Response {
    let id = if provider_id.trim().eq_ignore_ascii_case(mail::ID) {
        mail::ID
    } else {
        match ops::Provider::find(&provider_id) {
            Some(provider) => provider.id,
            None => return StatusCode::NOT_FOUND.into_response(),
        }
    };
    let state = admin.clone();
    let result =
        tokio::task::spawn_blocking(move || -> anyhow::Result<Option<serde_json::Value>> {
            if !state.db.delete_vault(id)? {
                return Ok(None);
            }
            let summary = format!("removed the {id} credential");
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
    if provider_id.trim().eq_ignore_ascii_case(mail::ID) {
        return test_mail(admin).await;
    }
    let Some(provider) = ops::Provider::find(&provider_id) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    // The credential is read and decrypted off the async runtime; a
    // refusal writes its own log row and is answered without a call.
    let prepared = {
        let state = admin.clone();
        tokio::task::spawn_blocking(
            move || -> anyhow::Result<Result<(String, Secret, ops::Guard), String>> {
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
                let guard = state
                    .guard
                    .with_secrets(&ops::stored_secrets(&state.db, key)?);
                Ok(Ok((provider.api_base(&row.base_url), secret, guard)))
            },
        )
        .await
    };
    let (base, secret, guard) = match prepared {
        Ok(Ok(Ok(prepared))) => prepared,
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
    let outcome = ops::call(&admin.ops_http, &base, &secret, &guard, &request).await;
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

/// Stores the mailbox: host, port and account in clear, the password
/// encrypted with all three sealed in as associated data, so it can never
/// be pointed at another server or account. The password is always
/// entered again, and no answer, log line or activity note carries it.
async fn save_mail(admin: Arc<Admin>, form: IntegrationForm) -> Response {
    let Some(key) = admin.vault.clone() else {
        return bad_request(
            "the vault is not enabled: set LORE_VAULT_KEY on the server to store credentials",
        );
    };
    if !form.base_url.trim().is_empty() {
        return bad_request("the mailbox takes a host and a port, not a URL");
    }
    let host = match mail::normalize_host(&form.host) {
        Ok(host) => host,
        Err(message) => return bad_request(&message),
    };
    let port = match mail::normalize_port(form.port) {
        Ok(port) => port,
        Err(message) => return bad_request(&message),
    };
    let account = match mail::normalize_account(&form.account) {
        Ok(account) => account,
        Err(message) => return bad_request(&message),
    };
    // The password is not trimmed: spaces may be part of it.
    let password = form.secret;
    if let Err(message) = mail::check_password(&password) {
        return bad_request(&message);
    }
    let state = admin.clone();
    let result = tokio::task::spawn_blocking(move || -> anyhow::Result<serde_json::Value> {
        let mailbox = mail::Mailbox {
            host,
            port,
            account,
        };
        let (nonce, ciphertext) = key.encrypt(mail::ID, &mailbox.sealed_with(), &password);
        // No hint: the end of a password is not shown anywhere.
        state.db.set_mail_vault(
            &mailbox.host,
            mailbox.port,
            &mailbox.account,
            &nonce,
            &ciphertext,
            "",
        )?;
        let summary = format!("saved the {} credential", mail::ID);
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
            tracing::error!(%error, "saving the mailbox failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// The mailbox's Test: log in and count the folders. Read-only like every
/// mailbox call; logged as a `folders` call by the administrator.
async fn test_mail(admin: Arc<Admin>) -> Response {
    let prepared = {
        let state = admin.clone();
        tokio::task::spawn_blocking(
            move || -> anyhow::Result<Result<(mail::Mailbox, Secret, ops::Guard), String>> {
                let refuse = |detail: &str| {
                    state.db.log_op(
                        ADMIN_ACTOR,
                        None,
                        mail::ID,
                        "folders",
                        "",
                        0,
                        "denied",
                        detail,
                        0,
                    )
                };
                let Some(key) = state.vault.as_ref() else {
                    refuse("the vault is not enabled")?;
                    return Ok(Err(
                        "Set LORE_VAULT_KEY on the server to store credentials.".into(),
                    ));
                };
                let Some(stored) = state.db.mail_vault()? else {
                    refuse("no credential is stored")?;
                    return Ok(Err("No mailbox is stored.".into()));
                };
                match mail::Mailbox::open(key, &stored) {
                    Ok((mailbox, password)) => {
                        let guard = state
                            .guard
                            .with_secrets(&ops::stored_secrets(&state.db, key)?);
                        Ok(Ok((mailbox, password, guard)))
                    }
                    Err(_) => {
                        refuse("the stored credential cannot be decrypted")?;
                        Ok(Err(
                            "The stored mailbox password cannot be decrypted with the \
                                current LORE_VAULT_KEY; enter it again."
                                .into(),
                        ))
                    }
                }
            },
        )
        .await
    };
    let (mailbox, password, guard) = match prepared {
        Ok(Ok(Ok(prepared))) => prepared,
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
    let started = Instant::now();
    let host = mailbox.host.clone();
    let outcome = mail::test(mailbox, password, guard).await;
    let (ok, message, log_outcome, detail) = match &outcome {
        Ok(count) => (
            true,
            format!(
                "Logged in to {host}: {count} folder{}.",
                if *count == 1 { "" } else { "s" }
            ),
            "ok",
            String::new(),
        ),
        // The page hears the server's words; the log keeps a fixed text.
        Err(failure) => (
            false,
            format!("{}.", failure.message),
            "error",
            failure.log.to_string(),
        ),
    };
    let summary = format!("tested {} ({})", mail::ID, if ok { "ok" } else { "failed" });
    let state = admin.clone();
    let log = tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
        let duration = started.elapsed().as_millis() as i64;
        state.db.log_op(
            ADMIN_ACTOR,
            None,
            mail::ID,
            "folders",
            "",
            0,
            log_outcome,
            &detail,
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
    Json(json!({ "ok": ok, "status": 0, "message": message })).into_response()
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
    let provider = if form.provider.trim().eq_ignore_ascii_case(mail::ID) {
        mail::ID
    } else {
        match ops::Provider::find(&form.provider) {
            Some(provider) => provider.id,
            None => return StatusCode::NOT_FOUND.into_response(),
        }
    };
    let mut level = form.level.trim().to_lowercase();
    if provider == mail::ID {
        // The mailbox is read-only: `full` means read.
        if level == "full" {
            level = "read".into();
        }
        if !db::MAIL_LEVELS.contains(&level.as_str()) {
            return bad_request("the mailbox level must be one of: off, read");
        }
    } else if !OPS_LEVELS.contains(&level.as_str()) {
        return bad_request("level must be one of: off, read, full");
    }
    let state = admin.clone();
    let result = tokio::task::spawn_blocking(move || -> anyhow::Result<serde_json::Value> {
        state.db.set_ops_level(&agent, provider, &level)?;
        let summary = format!("{agent} → {provider}: {level}");
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
        serve_router(vault, Router::new()).await
    }

    /// Like `serve_with`, with `extra` routes behind the same guard.
    async fn serve_router(
        vault: Option<VaultKey>,
        extra: Router<Arc<Admin>>,
    ) -> (String, Arc<Admin>) {
        // A counter keeps every server, even two in one test, on its own
        // database.
        static SERVERS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "lore-admin-test-{}-{}",
            std::process::id(),
            SERVERS.fetch_add(1, Ordering::SeqCst)
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
            ops::Guard::default(),
        ));
        sign_in(&admin, "admin-token", SignedIn::builtin_admin());
        sign_in(&admin, "viewer-token", SignedIn::builtin_viewer());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let app = router_with(admin.clone(), extra);
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

    /// Puts a live session for `user` under `token`.
    fn sign_in(admin: &Admin, token: &str, user: SignedIn) {
        admin.sessions().insert(
            token.into(),
            AdminSession {
                expires: Instant::now() + Duration::from_secs(600),
                user,
            },
        );
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
        // The five HTTP services, then the mailbox with its own levels
        // and its own default.
        let providers = first["providers"].as_array().unwrap();
        let ids: Vec<&str> = providers
            .iter()
            .map(|provider| provider["id"].as_str().unwrap())
            .collect();
        assert_eq!(
            ids,
            [
                "cloudflare",
                "github",
                "github_org",
                "gitlab",
                "dokploy",
                "mail"
            ]
        );
        assert_eq!(providers[1]["default_level"], "full");
        assert_eq!(providers[1]["levels"], json!(["off", "read", "full"]));
        assert_eq!(providers[5]["kind"], "mail");
        assert_eq!(providers[5]["default_level"], "off");
        assert_eq!(providers[5]["levels"], json!(["off", "read"]));
        assert_eq!(providers[5]["configured"], false);
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
        // The organization account is a provider of its own: not configured
        // by the personal credential, stored and removed on its own.
        let organization = |shown: &serde_json::Value| {
            shown["providers"]
                .as_array()
                .unwrap()
                .iter()
                .find(|provider| provider["id"] == "github_org")
                .cloned()
                .unwrap()
        };
        assert_eq!(organization(&shown)["configured"], false);
        assert_eq!(organization(&shown)["label"], "GitHub (organization)");
        assert_eq!(github["label"], "GitHub (personal)");
        let response = call(
            reqwest::Method::PUT,
            "/admin/api/integrations/github_org".into(),
            Some("admin-token"),
        )
        .json(&json!({ "secret": "ghp_organization-not-real-7777" }))
        .send()
        .await
        .unwrap();
        assert_eq!(response.status(), 200);
        let response = call(
            reqwest::Method::DELETE,
            "/admin/api/integrations/github_org".into(),
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
        assert!(
            !serde_json::to_string(&shown)
                .unwrap()
                .contains("organization-not-real")
        );
        assert_eq!(organization(&shown)["configured"], false);
        let still = shown["providers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|provider| provider["id"] == "github")
            .cloned()
            .unwrap();
        assert_eq!(still["configured"], true);
        assert_eq!(still["hint"], "9999");

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

    /// The mailbox goes through the same routes as the services, with its
    /// own form (host, port, account, password), its own levels and its
    /// own default; the password never comes back.
    #[tokio::test]
    async fn the_mailbox_is_stored_tested_and_granted_on_its_own_terms() {
        let (base, admin) = serve().await;
        let client = reqwest::Client::new();
        let call = |method: reqwest::Method, path: &str, token: &str| {
            client
                .request(method, format!("{base}{path}"))
                .header(header::COOKIE, format!("{COOKIE}={token}"))
        };
        // A port nothing listens on: the Test fails locally and never
        // reaches a real server.
        let closed = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.local_addr().unwrap().port()
        };
        let password = "mail app password 1";
        let good = json!({
            "host": "127.0.0.1", "port": closed, "account": "me@example.com", "secret": password
        });

        // The viewer may not store it.
        let response = call(
            reqwest::Method::PUT,
            "/admin/api/integrations/mail",
            "viewer-token",
        )
        .json(&good)
        .send()
        .await
        .unwrap();
        assert_eq!(response.status(), 403);
        for bad in [
            json!({ "host": "", "account": "me@example.com", "secret": password }),
            json!({ "host": "imaps://imap.example.com", "account": "me@example.com", "secret": password }),
            json!({ "host": "imap.example.com", "port": 0, "account": "me@example.com", "secret": password }),
            json!({ "host": "imap.example.com", "account": "", "secret": password }),
            json!({ "host": "imap.example.com", "account": "me@example.com", "secret": "" }),
            json!({ "host": "imap.example.com", "account": "me@example.com", "secret": "a\r\nb" }),
            json!({ "host": "imap.example.com", "account": "me@example.com", "secret": password, "base_url": "https://x.example" }),
        ] {
            let response = call(
                reqwest::Method::PUT,
                "/admin/api/integrations/mail",
                "admin-token",
            )
            .json(&bad)
            .send()
            .await
            .unwrap();
            assert_eq!(response.status(), 400, "{bad}");
            let text = response.text().await.unwrap();
            assert!(!text.contains(password), "{text}");
        }
        let response = call(
            reqwest::Method::PUT,
            "/admin/api/integrations/MAIL",
            "admin-token",
        )
        .json(&good)
        .send()
        .await
        .unwrap();
        assert_eq!(response.status(), 200);

        // Stored in the vault, sealed to host, port and account; the HTTP
        // path cannot read the row.
        let stored = admin.db.mail_vault().unwrap().unwrap();
        assert_eq!(
            (stored.host.as_str(), stored.port, stored.account.as_str()),
            ("127.0.0.1", closed, "me@example.com")
        );
        let (_, opened) = mail::Mailbox::open(&test_vault_key(), &stored).unwrap();
        assert_eq!(opened.expose(), password);
        assert!(admin.db.vault("mail").is_err());

        let shown = call(
            reqwest::Method::GET,
            "/admin/api/integrations",
            "viewer-token",
        )
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
        assert!(!shown.contains(password), "{shown}");
        let shown: serde_json::Value = serde_json::from_str(&shown).unwrap();
        let row = &shown["providers"][5];
        assert_eq!(row["id"], "mail");
        assert_eq!(row["configured"], true);
        assert_eq!(row["readable"], true);
        assert_eq!(row["host"], "127.0.0.1");
        assert_eq!(row["port"], closed);
        assert_eq!(row["account"], "me@example.com");
        assert_eq!(row["hint"], "");

        // Levels: off and read only; full is read.
        for (level, status) in [("full", 200), ("sometimes", 400)] {
            let response = call(
                reqwest::Method::PUT,
                "/admin/api/integrations/permissions",
                "admin-token",
            )
            .json(&json!({ "agent": "claude", "provider": "mail", "level": level }))
            .send()
            .await
            .unwrap();
            assert_eq!(response.status(), status, "{level}");
        }
        assert_eq!(admin.db.ops_level("claude", "mail").unwrap(), "read");
        let response = call(
            reqwest::Method::PUT,
            "/admin/api/integrations/permissions",
            "viewer-token",
        )
        .json(&json!({ "agent": "claude", "provider": "mail", "level": "off" }))
        .send()
        .await
        .unwrap();
        assert_eq!(response.status(), 403);
        assert_eq!(admin.db.ops_level("claude", "mail").unwrap(), "read");

        // Test: logs in (here: fails to connect) and says so, logged as a
        // `folders` call of the administrator.
        let tested: serde_json::Value = call(
            reqwest::Method::POST,
            "/admin/api/integrations/mail/test",
            "admin-token",
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
        assert_eq!(tested["ok"], false);
        // A loopback address is refused before anything connects, so Test
        // cannot be used to probe internal ports.
        assert!(
            tested["message"]
                .as_str()
                .unwrap()
                .contains("not a public one"),
            "{tested}"
        );
        let row = &admin.db.ops_log(1).unwrap()[0];
        assert_eq!(
            (
                row.provider.as_str(),
                row.method.as_str(),
                row.path.as_str()
            ),
            ("mail", "folders", "")
        );
        assert_eq!(row.outcome, "error");

        // Remove, then it is gone.
        for status in [200, 404] {
            let response = call(
                reqwest::Method::DELETE,
                "/admin/api/integrations/mail",
                "admin-token",
            )
            .send()
            .await
            .unwrap();
            assert_eq!(response.status(), status);
        }
        assert!(admin.db.mail_vault().unwrap().is_none());
        // The activity notes never carry the password.
        let activity = admin.db.activity(50).unwrap();
        assert!(activity.iter().all(|row| !row.summary.contains(password)));
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

    /// A stored user with a real hash, and a live session for them under
    /// `token`.
    fn stored_user(admin: &Admin, name: &str, perms: &[&str], token: &str) -> db::User {
        let user = admin
            .db
            .add_user(&NewUser {
                username: name.into(),
                email: Some(format!("{name}@example.com")),
                password_hash: users::hash_password("a-long-password").unwrap(),
                permissions: Perms::parse(perms).unwrap(),
                created_by: "admin".into(),
            })
            .unwrap();
        sign_in(
            admin,
            token,
            SignedIn {
                username: user.username.clone(),
                user_id: Some(user.id),
                perms: user.perms(),
            },
        );
        user
    }

    fn has_session(admin: &Admin, token: &str) -> bool {
        admin.sessions().contains_key(token)
    }

    async fn login(base: &str, body: serde_json::Value) -> reqwest::Response {
        reqwest::Client::new()
            .post(format!("{base}/admin/api/login"))
            .json(&body)
            .send()
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn sign_in_by_name_e_mail_or_password_alone() {
        let (base, admin) = serve().await;
        let user = stored_user(&admin, "luis", &["write"], "unused");
        stored_user(&admin, "gone", &[], "unused-2");
        admin
            .db
            .update_user(
                admin.db.user_login("gone").unwrap().unwrap().user.id,
                &UserPatch {
                    disabled: Some(true),
                    ..UserPatch::default()
                },
            )
            .unwrap();

        for (body, name, perms) in [
            (json!({ "password": "admin-password" }), "admin", 7),
            (json!({ "password": "viewer-password" }), "viewer", 0),
            (
                json!({ "username": "Admin", "password": "admin-password" }),
                "admin",
                7,
            ),
            (
                json!({ "username": "viewer", "password": "viewer-password" }),
                "viewer",
                0,
            ),
            (
                json!({ "username": "luis", "password": "a-long-password" }),
                "luis",
                1,
            ),
            (
                json!({ "username": "LUIS@example.com", "password": "a-long-password" }),
                "luis",
                1,
            ),
        ] {
            let response = login(&base, body.clone()).await;
            assert_eq!(response.status(), 200, "{body}");
            let cookie = response.headers()[header::SET_COOKIE]
                .to_str()
                .unwrap()
                .to_string();
            let answer: serde_json::Value = response.json().await.unwrap();
            assert_eq!(answer["username"], name);
            assert_eq!(answer["permissions"].as_array().unwrap().len(), perms);
            assert_eq!(answer["role"], if perms == 7 { "admin" } else { "viewer" });
            // The session endpoint says the same.
            let token = cookie.split(';').next().unwrap().to_string();
            let session: serde_json::Value = reqwest::Client::new()
                .get(format!("{base}/admin/api/session"))
                .header(header::COOKIE, token)
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            assert_eq!(session["authenticated"], true);
            assert_eq!(session["username"], name);
            assert_eq!(session["stored"], name == "luis");
        }
        assert!(
            admin
                .db
                .user(user.id)
                .unwrap()
                .unwrap()
                .last_login_at
                .is_some()
        );

        // Wrong passwords, the built-in names swapped, an unknown user and a
        // disabled one: four failures, under the lock-out limit of five.
        for (body, status) in [
            (
                json!({ "username": "luis", "password": "wrong-password" }),
                401,
            ),
            (
                json!({ "username": "admin", "password": "viewer-password" }),
                401,
            ),
            (
                json!({ "username": "nobody", "password": "a-long-password" }),
                401,
            ),
            (
                json!({ "username": "gone", "password": "a-long-password" }),
                403,
            ),
        ] {
            let response = login(&base, body.clone()).await;
            assert_eq!(response.status(), status, "{body}");
            assert!(response.headers().get(header::SET_COOKIE).is_none());
            let text = response.text().await.unwrap();
            assert!(!text.contains("password\":"), "{text}");
        }
    }

    #[tokio::test]
    async fn avatars_are_served_and_agents_are_managed_with_the_agents_permission() {
        let (base, admin) = serve().await;
        let client = reqwest::Client::new();
        let response = client
            .get(format!("{base}/admin/avatars/nova.svg"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.headers()[header::CONTENT_TYPE], "image/svg+xml");
        assert!(
            response.headers()[header::CACHE_CONTROL]
                .to_str()
                .unwrap()
                .contains("max-age=31536000")
        );
        assert!(response.text().await.unwrap().starts_with("<svg"));
        for missing in ["nope.svg", "nova", "nova.png", "..%2Fadmin.svg"] {
            let response = client
                .get(format!("{base}/admin/avatars/{missing}"))
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), 404, "{missing}");
        }
        // Other pages are still never cached.
        let response = client.get(format!("{base}/admin")).send().await.unwrap();
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");

        let call = |method: reqwest::Method, path: &str, token: &str| {
            client
                .request(method, format!("{base}{path}"))
                .header(header::COOKIE, format!("{COOKIE}={token}"))
        };
        admin.db.execute_for_test(
            "INSERT INTO sessions (id, agent, project, title, status, started_at, last_seen_at)
                 VALUES ('s1', 'claude', 'p', 't', 'open', '2026-01-01T00:00:00Z',
                         '2026-01-01T00:00:00Z');",
        );
        // Reading: any signed-in user.
        let list: serde_json::Value =
            call(reqwest::Method::GET, "/admin/api/agents", "viewer-token")
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
        assert_eq!(list["manage"], false);
        assert_eq!(list["avatars"].as_array().unwrap().len(), 10);
        let claude = &list["agents"][0];
        assert_eq!(claude["name"], "claude");
        assert_eq!(claude["env_token"], true);
        assert_eq!(claude["stats"]["open_sessions"], 1);
        // Changing: `agents` only.
        let change = json!({ "avatar": "wave", "note": "laptop", "disabled": true });
        let response = call(
            reqwest::Method::PUT,
            "/admin/api/agents/claude",
            "viewer-token",
        )
        .json(&change)
        .send()
        .await
        .unwrap();
        assert_eq!(response.status(), 403);
        for bad in [
            json!({ "avatar": "nope" }),
            json!({ "note": "x".repeat(301) }),
        ] {
            let response = call(
                reqwest::Method::PUT,
                "/admin/api/agents/claude",
                "admin-token",
            )
            .json(&bad)
            .send()
            .await
            .unwrap();
            assert_eq!(response.status(), 400, "{bad}");
        }
        let response = call(
            reqwest::Method::PUT,
            "/admin/api/agents/nobody",
            "admin-token",
        )
        .json(&change)
        .send()
        .await
        .unwrap();
        assert_eq!(response.status(), 404);
        let response = call(
            reqwest::Method::PUT,
            "/admin/api/agents/claude",
            "admin-token",
        )
        .json(&change)
        .send()
        .await
        .unwrap();
        assert_eq!(response.status(), 200);
        let row = admin.db.registry_agent("claude").unwrap().unwrap();
        assert_eq!(
            (row.avatar.as_str(), row.note.as_str(), row.disabled),
            ("wave", "laptop", true)
        );
        // Disabling closed the open session and left a note in the feed.
        let open = admin.db.sessions(Some("open"), None, 10).unwrap();
        assert!(open.is_empty());
        let feed = admin.db.activity(5).unwrap();
        assert!(
            feed.iter()
                .any(|a| a.tool == "disable" && a.summary.contains("disabled the agent claude"))
        );
        let response = call(
            reqwest::Method::PUT,
            "/admin/api/agents/claude",
            "admin-token",
        )
        .json(&json!({ "disabled": false }))
        .send()
        .await
        .unwrap();
        assert_eq!(response.status(), 200);
        assert!(
            admin
                .db
                .activity(5)
                .unwrap()
                .iter()
                .any(|a| a.tool == "enable")
        );
        // The brain's agent list carries the chosen avatar.
        let brain: serde_json::Value =
            call(reqwest::Method::GET, "/admin/api/pulse", "viewer-token")
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
        assert_eq!(brain["agents"][0]["avatar"], "wave");
        // An env-token agent has no OAuth authorization to delete.
        let response = call(
            reqwest::Method::DELETE,
            "/admin/api/agents/claude",
            "admin-token",
        )
        .send()
        .await
        .unwrap();
        assert_eq!(response.status(), 400);
        let response = call(
            reqwest::Method::POST,
            "/admin/api/agents/claude/revoke",
            "viewer-token",
        )
        .send()
        .await
        .unwrap();
        assert_eq!(response.status(), 403);
        let response = call(
            reqwest::Method::POST,
            "/admin/api/agents/claude/revoke",
            "admin-token",
        )
        .send()
        .await
        .unwrap();
        assert_eq!(response.status(), 200);
        assert!(
            admin
                .db
                .activity(5)
                .unwrap()
                .iter()
                .any(|a| a.tool == "revoke")
        );
    }

    #[tokio::test]
    async fn every_permission_guards_its_routes() {
        let extra = Router::new().route("/admin/api/unlisted", get(|| async { "open?" }));
        let (base, admin) = serve_router(Some(test_vault_key()), extra).await;
        for perm in Perm::ALL {
            stored_user(
                &admin,
                perm.id(),
                &[perm.id()],
                &format!("{}-token", perm.id()),
            );
        }
        stored_user(&admin, "reader", &[], "reader-token");
        let backup = admin.db.export().unwrap();
        let client = reqwest::Client::new();
        let call = |method: reqwest::Method, path: &str, token: &str| {
            client
                .request(method, format!("{base}{path}"))
                .header(header::COOKIE, format!("{COOKIE}={token}"))
        };
        let task = json!({ "project": "shop", "title": "t", "body": "", "assignee": "" });
        let profile = json!({ "address": "Boss", "language": "English", "agents": [] });
        let cases: Vec<(&str, reqwest::Method, &str, Option<serde_json::Value>)> = vec![
            (
                "write",
                reqwest::Method::POST,
                "/admin/api/tasks",
                Some(task),
            ),
            ("backup", reqwest::Method::GET, "/admin/api/export", None),
            (
                "restore",
                reqwest::Method::POST,
                "/admin/api/import?mode=merge",
                Some(serde_json::to_value(&backup).unwrap()),
            ),
            (
                "settings",
                reqwest::Method::PUT,
                "/admin/api/profile",
                Some(profile),
            ),
            (
                "integrations",
                reqwest::Method::PUT,
                "/admin/api/integrations/enabled",
                Some(json!({ "enabled": true })),
            ),
            ("users", reqwest::Method::GET, "/admin/api/users", None),
            (
                "agents",
                reqwest::Method::PUT,
                "/admin/api/agents/claude",
                Some(json!({ "note": "the laptop" })),
            ),
        ];
        for (perm, method, path, body) in &cases {
            for other in Perm::ALL.map(Perm::id).iter().chain(["reader"].iter()) {
                let mut request = call(method.clone(), path, &format!("{other}-token"));
                if let Some(body) = body {
                    request = request.json(body);
                }
                let status = request.send().await.unwrap().status();
                if other == perm {
                    assert_eq!(status, 200, "{perm} on {path}");
                } else {
                    assert_eq!(status, 403, "{other} on {path}");
                }
            }
        }
        // Reading needs only a session; the full backup needs `backup`.
        for path in [
            "/admin/api/brain",
            "/admin/api/board",
            "/admin/api/integrations",
        ] {
            assert_eq!(
                call(reqwest::Method::GET, path, "reader-token")
                    .send()
                    .await
                    .unwrap()
                    .status(),
                200
            );
        }
        assert_eq!(
            call(
                reqwest::Method::GET,
                "/admin/api/backup/full",
                "reader-token"
            )
            .send()
            .await
            .unwrap()
            .status(),
            403
        );
        assert_eq!(
            call(
                reqwest::Method::POST,
                "/admin/api/restore/full",
                "backup-token"
            )
            .body("x")
            .send()
            .await
            .unwrap()
            .status(),
            403
        );
        // A route nobody listed is closed, even to the built-in admin.
        let response = call(reqwest::Method::GET, "/admin/api/unlisted", "admin-token")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 403);
        assert_eq!(
            access(&axum::http::Method::GET, "/admin/api/unlisted"),
            None
        );
        assert_eq!(
            access(&axum::http::Method::HEAD, "/admin/api/export"),
            Some(Access::Needs(Perm::Backup))
        );
        // Every route the table lists is distinct.
        for (i, (method, path, _)) in ROUTES.iter().enumerate() {
            assert!(
                !ROUTES[i + 1..]
                    .iter()
                    .any(|(m, p, _)| m == method && p == path),
                "{method} {path} listed twice"
            );
        }
    }

    #[tokio::test]
    async fn users_are_managed_with_the_users_permission() {
        let (base, admin) = serve().await;
        let me = stored_user(&admin, "boss", &["users", "write", "backup"], "boss-token");
        let client = reqwest::Client::new();
        let call = |method: reqwest::Method, path: String, token: &str| {
            client
                .request(method, format!("{base}{path}"))
                .header(header::COOKIE, format!("{COOKIE}={token}"))
        };

        // Malformed and reserved names, short passwords, unknown permissions.
        for bad in [
            json!({ "username": "admin", "password": "a-long-password" }),
            json!({ "username": "Viewer", "password": "a-long-password" }),
            json!({ "username": "x", "password": "a-long-password" }),
            json!({ "username": "has space", "password": "a-long-password" }),
            json!({ "username": "-dash", "password": "a-long-password" }),
            json!({ "username": "fine", "password": "short" }),
            json!({ "username": "fine", "email": "nope", "password": "a-long-password" }),
            json!({ "username": "fine", "password": "a-long-password", "permissions": ["root"] }),
            json!({ "username": "boss", "password": "a-long-password" }),
        ] {
            let response = call(
                reqwest::Method::POST,
                "/admin/api/users".into(),
                "boss-token",
            )
            .json(&bad)
            .send()
            .await
            .unwrap();
            assert_eq!(response.status(), 400, "{bad}");
            let text = response.text().await.unwrap();
            assert!(!text.contains("a-long-password"), "{text}");
        }

        let response = call(
            reqwest::Method::POST,
            "/admin/api/users".into(),
            "boss-token",
        )
        .json(&json!({ "username": "Ana", "email": "Ana@Example.com",
                           "password": "ana-password-1", "permissions": ["write", "backup"] }))
        .send()
        .await
        .unwrap();
        assert_eq!(response.status(), 200);
        let ana: serde_json::Value = response.json().await.unwrap();
        assert_eq!(ana["username"], "ana");
        assert_eq!(ana["email"], "ana@example.com");
        assert_eq!(ana["created_by"], "boss");
        assert!(ana.get("password_hash").is_none());
        let ana_id = ana["id"].as_i64().unwrap();

        let listed: serde_json::Value = call(
            reqwest::Method::GET,
            "/admin/api/users".into(),
            "boss-token",
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
        let raw = listed.to_string();
        assert!(!raw.contains("argon2"), "a hash reached the page");
        assert_eq!(listed["users"].as_array().unwrap().len(), 2);
        assert_eq!(listed["builtin"].as_array().unwrap().len(), 2);
        assert_eq!(listed["permissions"].as_array().unwrap().len(), 7);

        // Sign Ana in twice; changing her permissions ends both sessions.
        for token in ["ana-1", "ana-2"] {
            sign_in(
                &admin,
                token,
                SignedIn {
                    username: "ana".into(),
                    user_id: Some(ana_id),
                    perms: Perms::parse(&["write", "backup"]).unwrap(),
                },
            );
        }
        let response = call(
            reqwest::Method::PUT,
            format!("/admin/api/users/{ana_id}"),
            "boss-token",
        )
        .json(&json!({ "permissions": ["write"] }))
        .send()
        .await
        .unwrap();
        assert_eq!(response.status(), 200);
        assert!(!has_session(&admin, "ana-1") && !has_session(&admin, "ana-2"));
        // An e-mail change alone keeps her sessions; a new password ends them.
        sign_in(
            &admin,
            "ana-3",
            SignedIn {
                username: "ana".into(),
                user_id: Some(ana_id),
                perms: Perms::parse(&["write"]).unwrap(),
            },
        );
        let response = call(
            reqwest::Method::PUT,
            format!("/admin/api/users/{ana_id}"),
            "boss-token",
        )
        .json(&json!({ "email": "" }))
        .send()
        .await
        .unwrap();
        assert_eq!(
            response.json::<serde_json::Value>().await.unwrap()["email"],
            serde_json::Value::Null
        );
        assert!(has_session(&admin, "ana-3"));
        let response = call(
            reqwest::Method::PUT,
            format!("/admin/api/users/{ana_id}"),
            "boss-token",
        )
        .json(&json!({ "password": "another-password" }))
        .send()
        .await
        .unwrap();
        assert_eq!(response.status(), 200);
        assert!(!has_session(&admin, "ana-3"));
        assert!(has_session(&admin, "boss-token"));
        let response = login(
            &base,
            json!({ "username": "ana", "password": "another-password" }),
        )
        .await;
        assert_eq!(response.status(), 200);

        // Self-lockout: boss cannot drop `users`, disable or delete himself.
        let mine = format!("/admin/api/users/{}", me.id);
        for body in [
            json!({ "permissions": ["write"] }),
            json!({ "disabled": true }),
        ] {
            let response = call(reqwest::Method::PUT, mine.clone(), "boss-token")
                .json(&body)
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), 400, "{body}");
        }
        let response = call(reqwest::Method::DELETE, mine.clone(), "boss-token")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 400);
        // Dropping another permission is fine, and his session follows.
        let response = call(reqwest::Method::PUT, mine.clone(), "boss-token")
            .json(&json!({ "permissions": ["users", "write"] }))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert!(
            admin
                .signed_in(&{
                    let mut headers = HeaderMap::new();
                    headers.insert(
                        header::COOKIE,
                        format!("{COOKIE}=boss-token").parse().unwrap(),
                    );
                    headers
                })
                .is_some_and(
                    |user| user.perms.contains(Perm::Write) && !user.perms.contains(Perm::Backup)
                )
        );

        // Disabling and deleting Ana end her sessions.
        sign_in(
            &admin,
            "ana-4",
            SignedIn {
                username: "ana".into(),
                user_id: Some(ana_id),
                perms: Perms::none(),
            },
        );
        let response = call(
            reqwest::Method::PUT,
            format!("/admin/api/users/{ana_id}"),
            "boss-token",
        )
        .json(&json!({ "disabled": true }))
        .send()
        .await
        .unwrap();
        assert_eq!(response.status(), 200);
        assert!(!has_session(&admin, "ana-4"));
        sign_in(
            &admin,
            "ana-5",
            SignedIn {
                username: "ana".into(),
                user_id: Some(ana_id),
                perms: Perms::none(),
            },
        );
        let response = call(
            reqwest::Method::DELETE,
            format!("/admin/api/users/{ana_id}"),
            "boss-token",
        )
        .send()
        .await
        .unwrap();
        assert_eq!(response.status(), 200);
        assert!(!has_session(&admin, "ana-5"));
        assert_eq!(
            call(
                reqwest::Method::DELETE,
                format!("/admin/api/users/{ana_id}"),
                "boss-token"
            )
            .send()
            .await
            .unwrap()
            .status(),
            404
        );
        // The feed says who did what, never a password.
        let feed = admin.db.activity(50).unwrap();
        let notes: Vec<&str> = feed
            .iter()
            .filter(|row| row.tool == "users")
            .map(|row| row.summary.as_str())
            .collect();
        assert!(
            notes
                .iter()
                .any(|note| note.contains("boss added the user ana"))
        );
        assert!(
            notes
                .iter()
                .any(|note| note.contains("boss deleted the user ana"))
        );
        assert!(notes.iter().all(|note| !note.contains("another-password")));
    }

    #[tokio::test]
    async fn users_cannot_grant_or_touch_permissions_they_lack() {
        let (base, admin) = serve().await;
        stored_user(&admin, "boss", &["users"], "boss-token");
        let chief = stored_user(&admin, "chief", &["users", "integrations"], "chief-token");
        let ann = stored_user(&admin, "ann", &[], "ann-token");
        let client = reqwest::Client::new();
        let call = |method: reqwest::Method, path: String, token: &str| {
            client
                .request(method, format!("{base}{path}"))
                .header(header::COOKIE, format!("{COOKIE}={token}"))
        };
        let boss_id = admin.db.user_login("boss").unwrap().unwrap().user.id;
        let chief_path = format!("/admin/api/users/{}", chief.id);
        let ann_path = format!("/admin/api/users/{}", ann.id);
        let refused: Vec<(reqwest::Method, String, serde_json::Value)> = vec![
            // Granting what boss does not hold: to a new user, to himself,
            // to someone weaker.
            (
                reqwest::Method::POST,
                "/admin/api/users".into(),
                json!({ "username": "mole", "password": "a-long-password",
                        "permissions": ["integrations"] }),
            ),
            (
                reqwest::Method::PUT,
                format!("/admin/api/users/{boss_id}"),
                json!({ "permissions": ["users", "restore"] }),
            ),
            (
                reqwest::Method::PUT,
                ann_path.clone(),
                json!({ "permissions": ["agents"] }),
            ),
            // Touching a stronger user in any way.
            (
                reqwest::Method::PUT,
                chief_path.clone(),
                json!({ "password": "taken-over-now" }),
            ),
            (
                reqwest::Method::PUT,
                chief_path.clone(),
                json!({ "disabled": true }),
            ),
            (
                reqwest::Method::PUT,
                chief_path.clone(),
                json!({ "email": "boss@example.org" }),
            ),
            (
                reqwest::Method::PUT,
                chief_path.clone(),
                json!({ "permissions": ["users"] }),
            ),
            (reqwest::Method::DELETE, chief_path.clone(), json!({})),
        ];
        for (method, path, body) in refused {
            let mut request = call(method.clone(), path.clone(), "boss-token");
            if method != reqwest::Method::DELETE {
                request = request.json(&body);
            }
            let response = request.send().await.unwrap();
            assert_eq!(response.status(), 403, "{method} {path} {body}");
        }
        // Nothing changed.
        assert!(admin.db.user_login("mole").unwrap().is_none());
        let after = admin.db.user(chief.id).unwrap().unwrap();
        assert_eq!(after.perms(), chief.perms());
        assert!(!after.disabled && after.email == chief.email);
        assert!(has_session(&admin, "chief-token"));
        assert_eq!(
            admin.db.user(boss_id).unwrap().unwrap().perms(),
            Perms::parse(&["users"]).unwrap()
        );
        assert_eq!(
            admin.db.user(ann.id).unwrap().unwrap().perms(),
            Perms::none()
        );
        assert_eq!(
            login(
                &base,
                json!({ "username": "chief", "password": "a-long-password" })
            )
            .await
            .status(),
            200
        );
        // What boss holds he may grant, and weaker users he may change.
        let response = call(reqwest::Method::PUT, ann_path.clone(), "boss-token")
            .json(&json!({ "permissions": ["users"], "password": "ann-new-password" }))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        // The built-in admin holds everything.
        let response = call(reqwest::Method::PUT, chief_path.clone(), "admin-token")
            .json(&json!({ "permissions": ["agents", "restore"] }))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let response = call(reqwest::Method::DELETE, chief_path, "admin-token")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
    }

    #[tokio::test]
    async fn parallel_sign_ins_are_counted_before_the_password_is_checked() {
        let (base, admin) = serve().await;
        stored_user(&admin, "luis", &[], "luis-token");
        // Rounds of as many parallel attempts as there are Argon2 slots, so
        // only the counting can turn one away: five are checked, no more.
        let mut statuses = Vec::new();
        for _ in 0..4 {
            let round: Vec<_> = (0..ARGON_PERMITS)
                .map(|_| {
                    let base = base.clone();
                    tokio::spawn(async move {
                        login(
                            &base,
                            json!({ "username": "luis", "password": "wrong-password" }),
                        )
                        .await
                        .status()
                        .as_u16()
                    })
                })
                .collect();
            for attempt in round {
                statuses.push(attempt.await.unwrap());
            }
        }
        let checked = statuses.iter().filter(|status| **status == 401).count();
        assert_eq!(checked, 5, "{statuses:?}");
        assert!(statuses.iter().all(|status| matches!(status, 401 | 429)));
        // Still locked out, even with the right password.
        let response = login(
            &base,
            json!({ "username": "luis", "password": "a-long-password" }),
        )
        .await;
        assert_eq!(response.status(), 429);
    }

    #[tokio::test]
    async fn password_checks_wait_for_no_free_argon2_slot() {
        let (base, admin) = serve().await;
        stored_user(&admin, "luis", &[], "luis-token");
        let held = admin
            .argon
            .clone()
            .try_acquire_many_owned(ARGON_PERMITS as u32)
            .unwrap();
        let response = login(
            &base,
            json!({ "username": "luis", "password": "a-long-password" }),
        )
        .await;
        assert_eq!(response.status(), 429);
        assert!(response.headers().get(header::SET_COOKIE).is_none());
        let response = reqwest::Client::new()
            .put(format!("{base}/admin/api/password"))
            .header(header::COOKIE, format!("{COOKIE}=luis-token"))
            .json(&json!({ "current": "a-long-password", "password": "new-password-1" }))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 429);
        // The built-in passwords need no Argon2 slot.
        let response = login(&base, json!({ "password": "admin-password" })).await;
        assert_eq!(response.status(), 200);
        drop(held);
        let response = login(
            &base,
            json!({ "username": "luis", "password": "a-long-password" }),
        )
        .await;
        assert_eq!(response.status(), 200);
    }

    #[test]
    fn a_session_starts_with_the_user_as_stored_now() {
        let dir = std::env::temp_dir().join(format!("lore-admin-race-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let admin = Admin::new(
            Db::open(&dir.join("lore.db")).unwrap(),
            "admin-password".into(),
            None,
            None,
            false,
            Vec::new(),
            None,
            0.8,
            Events::new(),
            Embedder::disabled(),
            12,
            None,
            ops::Guard::default(),
        );
        let user = admin
            .db
            .add_user(&NewUser {
                username: "luis".into(),
                email: None,
                password_hash: "x".into(),
                permissions: Perms::parse(&["write", "users"]).unwrap(),
                created_by: "admin".into(),
            })
            .unwrap();
        // What the password check saw before the user was changed.
        let checked = SignedIn {
            username: "luis".into(),
            user_id: Some(user.id),
            perms: user.perms(),
        };
        admin
            .db
            .update_user(
                user.id,
                &UserPatch {
                    permissions: Some(Perms::parse(&["write"]).unwrap()),
                    ..UserPatch::default()
                },
            )
            .unwrap();
        let started = start_session(&admin, "t1", checked.clone())
            .unwrap()
            .unwrap();
        assert_eq!(started.perms, Perms::parse(&["write"]).unwrap());
        assert_eq!(
            admin.sessions().get("t1").unwrap().user.perms,
            Perms::parse(&["write"]).unwrap()
        );
        admin
            .db
            .update_user(
                user.id,
                &UserPatch {
                    disabled: Some(true),
                    ..UserPatch::default()
                },
            )
            .unwrap();
        assert!(
            start_session(&admin, "t2", checked.clone())
                .unwrap()
                .is_none()
        );
        assert!(!admin.sessions().contains_key("t2"));
        admin.db.delete_user(user.id).unwrap();
        assert!(start_session(&admin, "t3", checked).unwrap().is_none());
        // The built-in users have nothing stored to re-read.
        assert!(
            start_session(&admin, "t4", SignedIn::builtin_admin())
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn a_restore_that_fails_after_the_load_says_so_and_names_the_safety_copy() {
        let (base, admin) = serve().await;
        let file = admin.db.temp_path("upload-source").unwrap();
        admin.db.snapshot_to(&file).unwrap();
        let bytes = std::fs::read(&file).unwrap();
        db::remove_database_files(&file);
        admin
            .db
            .fail_after_load
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let response = reqwest::Client::new()
            .post(format!("{base}/admin/api/restore/full"))
            .header(header::COOKIE, format!("{COOKIE}=admin-token"))
            .body(bytes)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 500);
        let answer: serde_json::Value = response.json().await.unwrap();
        assert_eq!(answer["check"], "after-load");
        let message = answer["error"].as_str().unwrap();
        assert!(!message.contains("nothing changed"), "{message}");
        let snapshot = std::fs::read_dir(admin.db.data_dir())
            .unwrap()
            .flatten()
            .map(|item| item.file_name().to_string_lossy().into_owned())
            .find(|name| name.starts_with("pre-restore-"))
            .unwrap();
        assert!(message.contains(&snapshot), "{message}");
    }

    #[tokio::test]
    async fn an_abandoned_full_restore_upload_leaves_no_file() {
        let (_base, admin) = serve().await;
        let dir = admin.db.data_dir();
        let temp_files = || {
            std::fs::read_dir(&dir)
                .unwrap()
                .flatten()
                .filter(|item| item.file_name().to_string_lossy().starts_with(".lore-tmp-"))
                .count()
        };
        // An upload that sends one chunk and then stalls, the way a client
        // that went away looks to the handler until it is dropped.
        let (sender, receiver) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(1);
        sender
            .send(Ok(Bytes::from(vec![b'x'; 64 * 1024])))
            .await
            .unwrap();
        let body = Body::from_stream(ReceiverStream::new(receiver));
        let handler = full_restore(
            State(admin.clone()),
            Extension(SignedIn::builtin_admin()),
            HeaderMap::new(),
            body,
        );
        // The request is dropped mid-upload, as axum drops it when the
        // connection goes away.
        let dropped = tokio::time::timeout(Duration::from_millis(300), handler).await;
        assert!(dropped.is_err(), "the stalled upload finished");
        assert_eq!(temp_files(), 0, "the temporary file stayed behind");
        drop(sender);
        // And the next restore is not blocked by it.
        assert!(admin.try_busy().is_some());
    }

    #[tokio::test]
    async fn own_password_changes_need_the_current_one() {
        let (base, admin) = serve().await;
        stored_user(&admin, "luis", &[], "luis-token");
        sign_in(
            &admin,
            "luis-other",
            admin
                .signed_in(&{
                    let mut headers = HeaderMap::new();
                    headers.insert(
                        header::COOKIE,
                        format!("{COOKIE}=luis-token").parse().unwrap(),
                    );
                    headers
                })
                .unwrap(),
        );
        let client = reqwest::Client::new();
        let change = |token: &str, body: serde_json::Value| {
            client
                .put(format!("{base}/admin/api/password"))
                .header(header::COOKIE, format!("{COOKIE}={token}"))
                .json(&body)
        };
        let response = change(
            "luis-token",
            json!({ "current": "wrong-one!!", "password": "new-password-1" }),
        )
        .send()
        .await
        .unwrap();
        assert_eq!(response.status(), 400);
        let response = change(
            "luis-token",
            json!({ "current": "a-long-password", "password": "short" }),
        )
        .send()
        .await
        .unwrap();
        assert_eq!(response.status(), 400);
        // The built-in users' passwords live in the environment.
        let response = change(
            "admin-token",
            json!({ "current": "admin-password", "password": "new-password-1" }),
        )
        .send()
        .await
        .unwrap();
        assert_eq!(response.status(), 400);
        let response = change(
            "luis-token",
            json!({ "current": "a-long-password", "password": "new-password-1" }),
        )
        .send()
        .await
        .unwrap();
        assert_eq!(response.status(), 200);
        assert!(has_session(&admin, "luis-token"));
        assert!(!has_session(&admin, "luis-other"));
        assert_eq!(
            login(
                &base,
                json!({ "username": "luis", "password": "new-password-1" })
            )
            .await
            .status(),
            200
        );
    }

    #[tokio::test]
    async fn a_full_backup_downloads_and_restores_over_http() {
        let (source, source_admin) = serve().await;
        source_admin
            .db
            .insert(&crate::db::NewEntry {
                project: "shop".into(),
                kind: "note".into(),
                title: "Kept".into(),
                body: "in the full backup".into(),
                ..Default::default()
            })
            .unwrap();
        stored_user(&source_admin, "carried", &["users"], "carried-token");
        let client = reqwest::Client::new();
        let response = client
            .get(format!("{source}/admin/api/backup/full"))
            .header(header::COOKIE, format!("{COOKIE}=admin-token"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let disposition = response.headers()[header::CONTENT_DISPOSITION]
            .to_str()
            .unwrap()
            .to_string();
        assert!(
            disposition.starts_with("attachment; filename=\"lore-full-")
                && disposition.ends_with(".sqlite\"")
        );
        let file = response.bytes().await.unwrap();
        assert!(file.starts_with(b"SQLite format 3\0"));
        // The temporary copy is gone.
        let dir = source_admin.db.data_dir();
        assert!(
            std::fs::read_dir(&dir)
                .unwrap()
                .flatten()
                .all(|item| { !item.file_name().to_string_lossy().starts_with(".lore-tmp-") })
        );

        let (target, target_admin) = serve().await;
        let gone = stored_user(
            &target_admin,
            "gone",
            &Perm::ALL.map(Perm::id),
            "gone-token",
        );
        stored_user(&target_admin, "restorer", &["restore"], "restorer-token");
        let upload = |token: &str, body: Vec<u8>| {
            client
                .post(format!("{target}/admin/api/restore/full"))
                .header(header::COOKIE, format!("{COOKIE}={token}"))
                .header(header::CONTENT_TYPE, "application/octet-stream")
                .body(body)
        };
        // Refused uploads name the check and change nothing.
        for (body, check) in [
            (b"definitely not sqlite".to_vec(), "header"),
            (Vec::new(), "upload"),
        ] {
            let response = upload("admin-token", body).send().await.unwrap();
            assert_eq!(response.status(), 400);
            assert_eq!(
                response.json::<serde_json::Value>().await.unwrap()["check"],
                check
            );
        }
        assert_eq!(target_admin.db.users().unwrap().len(), 2);
        // `restore` alone is not enough for a whole database: it carries its
        // own users and tokens.
        let response = upload("restorer-token", file.to_vec())
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 403);
        assert_eq!(target_admin.db.users().unwrap().len(), 2);

        let response = upload("gone-token", file.to_vec()).send().await.unwrap();
        assert_eq!(response.status(), 200);
        let result: serde_json::Value = response.json().await.unwrap();
        assert_eq!(result["tables"]["entries"], 1);
        assert_eq!(result["tables"]["users"], 1);
        assert!(
            result["snapshot"]
                .as_str()
                .unwrap()
                .starts_with("pre-restore-")
        );
        let target_dir = target_admin.db.data_dir();
        assert!(
            target_dir
                .join(result["snapshot"].as_str().unwrap())
                .exists()
        );
        assert_eq!(
            target_admin.db.recent(None, None, 5).unwrap()[0].title,
            "Kept"
        );
        // The restoring user no longer exists; the built-in sessions stay.
        assert!(!has_session(&target_admin, "gone-token"));
        assert!(has_session(&target_admin, "admin-token"));
        assert!(
            target_admin
                .db
                .user(gone.id)
                .unwrap()
                .is_none_or(|user| user.username != "gone")
        );
        assert!(
            std::fs::read_dir(&target_dir)
                .unwrap()
                .flatten()
                .all(|item| { !item.file_name().to_string_lossy().starts_with(".lore-tmp-") })
        );
    }
}
