//! The read-only admin view: password login (optionally guarded by
//! reCAPTCHA v3), a session cookie, and the JSON the brain visualisation draws.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use axum::{
    Json, Router,
    extract::{ConnectInfo, Path, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::json;
use subtle::ConstantTimeEq;

use crate::{
    auth::{RateLimiter, client_ip, too_many_requests},
    db::Db,
};

const COOKIE: &str = "lore_session";
const SESSION_TTL: Duration = Duration::from_secs(12 * 60 * 60);
/// Newest entries drawn in the graph; older ones stay searchable over MCP.
const MAX_NEURONS: usize = 1200;
const NEIGHBOURS: usize = 3;
const RECAPTCHA_ACTION: &str = "login";

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

pub struct Admin {
    pub db: Db,
    pub password: String,
    pub recaptcha: Option<Recaptcha>,
    pub trust_proxy: bool,
    /// Agent names that hold a token, so idle ones are listed too.
    pub configured_agents: Vec<String>,
    pub embedding_model: Option<&'static str>,
    pub link_similarity: f32,
    sessions: Mutex<HashMap<String, Instant>>,
    logins: RateLimiter,
    http: reqwest::Client,
}

impl Admin {
    pub fn new(
        db: Db,
        password: String,
        recaptcha: Option<Recaptcha>,
        trust_proxy: bool,
        configured_agents: Vec<String>,
        embedding_model: Option<&'static str>,
        link_similarity: f32,
    ) -> Self {
        Self {
            db,
            password,
            recaptcha,
            trust_proxy,
            configured_agents,
            embedding_model,
            link_similarity,
            sessions: Mutex::new(HashMap::new()),
            // Five wrong attempts lock the address out for fifteen minutes.
            logins: RateLimiter::new(5, Duration::from_secs(15 * 60)),
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(8))
                .build()
                .expect("building the HTTP client"),
        }
    }

    fn session_valid(&self, headers: &HeaderMap) -> bool {
        let Some(token) = cookie(headers, COOKIE) else {
            return false;
        };
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        sessions.retain(|_, expires| *expires > Instant::now());
        sessions.contains_key(&token)
    }
}

pub fn router(admin: Arc<Admin>) -> Router {
    let private = Router::new()
        .route("/admin/api/brain", get(brain))
        .route("/admin/api/pulse", get(pulse))
        .route("/admin/api/entries/{id}", get(entry))
        .layer(middleware::from_fn_with_state(
            admin.clone(),
            require_session,
        ));

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
        .route("/admin/api/session", get(session))
        .route("/admin/api/login", post(login))
        .route("/admin/api/logout", post(logout))
        .merge(private)
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
    if admin.session_valid(request.headers()) {
        next.run(request).await
    } else {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "sign in first" })),
        )
            .into_response()
    }
}

/// Tells the page whether it is signed in and which reCAPTCHA key to load.
async fn session(State(admin): State<Arc<Admin>>, headers: HeaderMap) -> Json<serde_json::Value> {
    Json(json!({
        "authenticated": admin.session_valid(&headers),
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

    let correct = bool::from(form.password.as_bytes().ct_eq(admin.password.as_bytes()));
    if !correct {
        tracing::warn!(%ip, "admin login with a wrong password");
        admin.logins.hit(&ip);
        tokio::time::sleep(Duration::from_millis(400)).await;
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "Wrong password." })),
        )
            .into_response();
    }

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
        .insert(token.clone(), Instant::now() + SESSION_TTL);
    tracing::info!(%ip, "admin signed in");
    let cookie = format!(
        "{COOKIE}={token}; Path=/admin; HttpOnly; Secure; SameSite=Strict; Max-Age={}",
        SESSION_TTL.as_secs()
    );
    ([(header::SET_COOKIE, cookie)], Json(json!({ "ok": true }))).into_response()
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
