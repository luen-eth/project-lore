//! project-lore: a shared second brain for coding agents, served over MCP.

mod admin;
mod auth;
mod avatars;
mod db;
mod embed;
mod events;
mod gitproxy;
mod leakscan;
mod mail;
mod oauth;
mod ops;
mod packscan;
mod server;
mod users;
mod vault;

use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use anyhow::{Context, Result, bail};
use axum::{Router, middleware, routing::get};
use rmcp::transport::streamable_http_server::{
    StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
};

use crate::{
    admin::{Admin, Recaptcha},
    auth::{McpAuth, SHARED_AGENT},
    db::Db,
    embed::{Embedder, Model},
    events::Events,
    gitproxy::GitProxy,
    oauth::OAuth,
    server::Lore,
    vault::VaultKey,
};

const MIN_ADMIN_PASSWORD_LEN: usize = 12;

#[tokio::main]
async fn main() -> Result<()> {
    if std::env::args().nth(1).as_deref() == Some("healthcheck") {
        return healthcheck();
    }
    // The IMAP client traces every command it sends, the mailbox's LOGIN
    // with its password included, and every answer, mail included: it is
    // silenced whatever RUST_LOG says.
    let mut filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "info,ort=warn,rmcp=warn".into());
    for directive in ["async_imap=off", "imap_proto=off"] {
        filter = filter.add_directive(directive.parse().expect("a fixed log directive"));
    }
    {
        use tracing_subscriber::util::SubscriberInitExt;
        log_subscriber(filter, std::io::stderr).init();
    }

    let tokens = auth::load_tokens(&env_or("LORE_TOKEN", ""), &env_or("LORE_TOKENS", ""))?;
    let data_dir = PathBuf::from(env_or("LORE_DATA_DIR", "./data"));
    let bind: SocketAddr = env_or("LORE_BIND", "0.0.0.0:8080")
        .parse()
        .context("LORE_BIND must be an address like 0.0.0.0:8080")?;
    let allowed_hosts: Vec<String> = env_or("LORE_ALLOWED_HOSTS", "")
        .split(',')
        .map(|h| h.trim().to_string())
        .filter(|h| !h.is_empty())
        .collect();
    let trust_proxy = flag("LORE_TRUST_PROXY", false);
    let model_name = env_or("LORE_EMBEDDING_MODEL", Model::default().name());
    let Some(model) = Model::parse(&model_name) else {
        bail!("LORE_EMBEDDING_MODEL must be one of: e5-small, e5-base, e5-large, bge-m3");
    };
    let min_similarity: f32 = match env_or("LORE_MIN_SIMILARITY", "").as_str() {
        "" => model.min_similarity(),
        value => value
            .parse()
            .context("LORE_MIN_SIMILARITY must be a number between 0 and 1")?,
    };
    let idle_hours: u32 = match env_or("LORE_SESSION_IDLE_HOURS", "12").parse() {
        Ok(hours) if (1..=720).contains(&hours) => hours,
        _ => bail!("LORE_SESSION_IDLE_HOURS must be a whole number between 1 and 720"),
    };
    let vault = VaultKey::from_env_value(&env_or("LORE_VAULT_KEY", ""))?;
    if vault.is_some() {
        tracing::info!("credential vault enabled (LORE_VAULT_KEY set)");
    } else {
        tracing::info!(
            "credential vault disabled: set LORE_VAULT_KEY (64 hex characters, \
             `openssl rand -hex 32`) to store service credentials"
        );
    }

    // lore's own secrets, redacted from every provider response (the env
    // of lore's own Dokploy application holds them all), and the Dokploy
    // ids of its own deployment, which no agent write may name. Built once
    // here; neither is ever logged.
    let dokploy_protected = ops::parse_protected(&env_or("LORE_DOKPLOY_PROTECTED", ""))?;
    let guard = {
        let own_secrets: Vec<String> = tokens
            .iter()
            .map(|token| token.secret().to_string())
            .chain(
                [
                    "LORE_ADMIN_PASSWORD",
                    "LORE_VIEWER_PASSWORD",
                    "LORE_RECAPTCHA_SECRET_KEY",
                    "LORE_VAULT_KEY",
                ]
                .map(|name| env_or(name, "")),
            )
            .collect();
        ops::Guard::new(&own_secrets, dokploy_protected)
    };
    if guard.protected_count() > 0 {
        tracing::info!(
            ids = guard.protected_count(),
            "agents may not change lore's own Dokploy deployment (LORE_DOKPLOY_PROTECTED)"
        );
    }

    let db = Db::open(&data_dir.join("lore.db"))?;
    let semantic = flag("LORE_EMBEDDINGS", true);
    let embedder = if semantic {
        db.use_embedding_model(model.name())?;
        Embedder::spawn(model, data_dir.join("models"), db.clone())
    } else {
        tracing::info!("semantic search disabled (LORE_EMBEDDINGS=off)");
        Embedder::disabled()
    };

    let configured_agents: Vec<String> = tokens
        .iter()
        .map(|t| t.agent.clone())
        .filter(|name| name != SHARED_AGENT)
        .collect();
    // Every env-token agent has a registry row, so it can be given an
    // avatar and a note, or be disabled, before it first connects.
    db.register_token_agents(&tokens.iter().map(|t| t.agent.clone()).collect::<Vec<_>>())?;
    let mut auth = McpAuth::new(tokens, db.clone(), trust_proxy);
    auth.allowed_hosts = allowed_hosts;

    let events = Events::new();
    let lore = Lore::new(
        db.clone(),
        embedder.clone(),
        min_similarity,
        events.clone(),
        idle_hours,
        vault.clone(),
        guard.clone(),
    );

    let admin = match admin_password()? {
        Some(password) => {
            let viewer_password = viewer_password(&password)?;
            if viewer_password.is_some() {
                tracing::info!("viewer password set: watch-only sign-in enabled");
            }
            let recaptcha = recaptcha()?;
            if recaptcha.is_none() {
                tracing::warn!("admin view runs without reCAPTCHA (keys not set)");
            }
            Some(Admin::new(
                db.clone(),
                password,
                viewer_password,
                recaptcha,
                trust_proxy,
                configured_agents,
                semantic.then(|| model.name()),
                model.link_similarity(),
                events.clone(),
                embedder.clone(),
                idle_hours,
                vault.clone(),
                guard.clone(),
            ))
        }
        None => {
            tracing::info!(
                "admin view and agent authorization (OAuth) disabled (LORE_ADMIN_PASSWORD not set)"
            );
            None
        }
    };
    if admin.is_some() {
        tracing::info!("admin view enabled at /admin; agents may also authorize through OAuth");
    }
    for warning in startup_warnings(
        &db,
        admin.is_some(),
        &auth.allowed_hosts,
        &auth
            .tokens
            .iter()
            .map(|token| token.agent.clone())
            .collect::<Vec<_>>(),
    )? {
        tracing::warn!("{warning}");
    }
    let app = app(auth, lore, vault, events, admin);

    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .with_context(|| format!("binding {bind}"))?;
    tracing::info!(%bind, data = %data_dir.display(), "project-lore listening");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown())
    .await?;
    Ok(())
}

/// Targets never logged, whatever `RUST_LOG` says: the IMAP client and its
/// parser trace the LOGIN command with the mailbox password and every
/// answer, mail included.
const SILENCED_TARGETS: &[&str] = &["async_imap", "imap_proto"];

/// True for an event or span from a silenced crate.
fn silenced(target: &str) -> bool {
    SILENCED_TARGETS
        .iter()
        .any(|prefix| target.starts_with(prefix))
}

/// The log subscriber: `filter` (from `RUST_LOG`) decides what is written,
/// and on top of it a filter that drops everything from the silenced
/// crates. That one does not depend on `filter`, so a more specific
/// directive such as `RUST_LOG=async_imap::imap_stream=trace` cannot turn
/// them back on.
fn log_subscriber<W>(
    filter: tracing_subscriber::EnvFilter,
    writer: W,
) -> impl tracing::Subscriber + Send + Sync
where
    W: for<'writer> tracing_subscriber::fmt::MakeWriter<'writer> + Send + Sync + 'static,
{
    use tracing_subscriber::layer::SubscriberExt;
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(writer)
        .finish()
        .with(tracing_subscriber::filter::filter_fn(|metadata| {
            !silenced(metadata.target())
        }))
}

/// What the start-up log warns about: OAuth mounted without
/// `LORE_ALLOWED_HOSTS` (its issuer and redirect origin then follow the
/// request's Host header), and an env-token agent whose name an OAuth agent
/// already has (the token then acts as that OAuth agent, with its levels
/// and history).
fn startup_warnings(
    db: &Db,
    oauth: bool,
    allowed_hosts: &[String],
    env_agents: &[String],
) -> Result<Vec<String>> {
    let mut warnings = Vec::new();
    if oauth && allowed_hosts.is_empty() {
        warnings.push(
            "OAuth is on but LORE_ALLOWED_HOSTS is not set: the issuer and the consent page's \
             origin follow whatever Host header a request carries. Set LORE_ALLOWED_HOSTS to the \
             public host name(s) lore is reached at."
                .to_string(),
        );
    }
    for name in env_agents {
        if db
            .registry_agent(name)?
            .is_some_and(|agent| agent.kind == "oauth")
        {
            warnings.push(format!(
                "the env token agent \"{name}\" has the name of an OAuth agent: that token acts as \
                 the OAuth agent, with its levels and history. Rename the token's agent in \
                 LORE_TOKENS, or delete the OAuth agent in the agents panel."
            ));
        }
    }
    Ok(warnings)
}

/// The HTTP routes: `/mcp` behind the bearer check, `/health`, the git
/// proxy, and — when the admin view is on — the admin view and the OAuth
/// authorization server, which needs it to sign users in.
fn app(
    mut auth: McpAuth,
    lore: Lore,
    vault: Option<VaultKey>,
    events: Events,
    admin: Option<Admin>,
) -> Router {
    let oauth = admin.as_ref().map(|_| {
        Arc::new(OAuth::new(
            auth.db.clone(),
            auth.trust_proxy,
            auth.allowed_hosts.clone(),
            auth.tokens
                .iter()
                .map(|token| token.agent.clone())
                .collect(),
        ))
    });
    auth.oauth = oauth.is_some();

    // Stateless JSON responses: nothing is lost when the container restarts,
    // and every request is authenticated on its own.
    let mut config = StreamableHttpServerConfig::default()
        .with_legacy_session_mode(false)
        .with_json_response(true);
    config = if auth.allowed_hosts.is_empty() {
        // Every request carries the bearer token, so DNS rebinding cannot reach
        // the tools; Host pinning is an optional extra.
        config.disable_allowed_hosts()
    } else {
        config.with_allowed_hosts(auth.allowed_hosts.clone())
    };
    // The git proxy's leak scan looks for lore's own secrets too.
    let guard = lore.guard();
    let mcp = StreamableHttpService::new(
        move || Ok(lore.clone()),
        Arc::new(LocalSessionManager::default()),
        config,
    );

    let auth = Arc::new(auth);
    let mut app = Router::new()
        .nest_service("/mcp", mcp)
        .layer(middleware::from_fn_with_state(
            auth.clone(),
            auth::require_token,
        ))
        .route("/health", get(|| async { "ok" }))
        // Plain `git` speaks to /git: lore authenticates the agent with
        // its own lore token and adds the stored credential upstream,
        // where the agent's machine never sees it.
        .merge(gitproxy::router(Arc::new(GitProxy::new(
            auth, vault, events, guard,
        ))));
    if let (Some(admin), Some(oauth)) = (admin, oauth) {
        app = app
            .merge(admin::router(Arc::new(admin.with_oauth(oauth.clone()))))
            .merge(oauth::router(oauth));
    }
    app
}

/// `lore healthcheck`: exits 0 when the local server answers `/health`.
/// Lets the container health check run without curl in the image.
fn healthcheck() -> Result<()> {
    use std::io::{Read, Write};
    let bind: SocketAddr = env_or("LORE_BIND", "0.0.0.0:8080").parse()?;
    let address = SocketAddr::from(([127, 0, 0, 1], bind.port()));
    let mut stream = std::net::TcpStream::connect_timeout(&address, Duration::from_secs(3))?;
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    stream.write_all(b"GET /health HTTP/1.0\r\nHost: localhost\r\n\r\n")?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    if response.starts_with("HTTP/1.0 200") || response.starts_with("HTTP/1.1 200") {
        Ok(())
    } else {
        bail!(
            "unhealthy: {}",
            response.lines().next().unwrap_or("no response")
        )
    }
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| default.to_string())
}

fn flag(key: &str, default: bool) -> bool {
    match env_or(key, "").to_lowercase().as_str() {
        "on" | "true" | "1" | "yes" => true,
        "off" | "false" | "0" | "no" => false,
        _ => default,
    }
}

fn admin_password() -> Result<Option<String>> {
    let password = env_or("LORE_ADMIN_PASSWORD", "");
    if password.is_empty() {
        return Ok(None);
    }
    if password.len() < MIN_ADMIN_PASSWORD_LEN {
        bail!("LORE_ADMIN_PASSWORD must be at least {MIN_ADMIN_PASSWORD_LEN} characters");
    }
    Ok(Some(password))
}

/// The optional watch-only password. It must differ from the admin password,
/// or signing in with it would silently grant the admin role.
fn viewer_password(admin: &str) -> Result<Option<String>> {
    let password = env_or("LORE_VIEWER_PASSWORD", "");
    if password.is_empty() {
        return Ok(None);
    }
    if password.len() < MIN_ADMIN_PASSWORD_LEN {
        bail!("LORE_VIEWER_PASSWORD must be at least {MIN_ADMIN_PASSWORD_LEN} characters");
    }
    if password == admin {
        bail!("LORE_VIEWER_PASSWORD must be different from LORE_ADMIN_PASSWORD");
    }
    Ok(Some(password))
}

fn recaptcha() -> Result<Option<Recaptcha>> {
    let site_key = env_or("LORE_RECAPTCHA_SITE_KEY", "");
    let secret = env_or("LORE_RECAPTCHA_SECRET_KEY", "");
    match (site_key.is_empty(), secret.is_empty()) {
        (true, true) => Ok(None),
        (false, false) => Ok(Some(Recaptcha {
            site_key,
            secret,
            min_score: env_or("LORE_RECAPTCHA_MIN_SCORE", "0.5")
                .parse()
                .context("LORE_RECAPTCHA_MIN_SCORE must be a number between 0 and 1")?,
        })),
        _ => bail!("set both LORE_RECAPTCHA_SITE_KEY and LORE_RECAPTCHA_SECRET_KEY, or neither"),
    }
}

async fn shutdown() {
    let ctrl_c = tokio::signal::ctrl_c();
    let mut terminate =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ok();
    tokio::select! {
        _ = ctrl_c => {}
        _ = async {
            match terminate.as_mut() {
                Some(signal) => { signal.recv().await; }
                None => std::future::pending::<()>().await,
            }
        } => {}
    }
    tracing::info!("shutting down");
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use axum::http::{StatusCode, header};
    use base64::Engine;
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::{
        db::NewUser,
        users::{self, Perms},
    };

    #[test]
    fn the_imap_crates_are_never_logged_whatever_rust_log_says() {
        #[derive(Clone, Default)]
        struct Captured(Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::io::Write for Captured {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let captured = Captured::default();
        let writer = captured.clone();
        // The directive that beat the old `async_imap=off`.
        let filter = tracing_subscriber::EnvFilter::new(
            "info,async_imap::imap_stream=trace,imap_proto=trace,async_imap=off",
        );
        let subscriber = log_subscriber(filter, move || writer.clone());
        tracing::subscriber::with_default(subscriber, || {
            tracing::trace!(target: "async_imap::imap_stream", "LOGIN me@example.com hunter2-secret");
            tracing::trace!(target: "async_imap", "LOGIN me@example.com hunter2-secret");
            tracing::trace!(target: "imap_proto::parser", "a parsed answer with mail");
            tracing::info!(target: "lore_check", "still logged");
        });
        let text = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
        assert!(text.contains("still logged"), "{text}");
        assert!(!text.contains("hunter2-secret"), "{text}");
        assert!(!text.contains("parsed answer"), "{text}");
        assert!(silenced("async_imap::imap_stream") && silenced("imap_proto"));
        assert!(!silenced("project_lore::mail"));
    }

    #[test]
    fn start_up_warns_about_an_open_host_and_a_shared_agent_name() {
        let dir = std::env::temp_dir().join(format!("lore-warnings-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let db = Db::open(&dir.join("lore.db")).unwrap();
        let agents = vec!["claude".to_string(), "cursor".to_string()];
        assert!(
            startup_warnings(&db, false, &[], &agents)
                .unwrap()
                .is_empty()
        );
        let open = startup_warnings(&db, true, &[], &agents).unwrap();
        assert_eq!(open.len(), 1);
        assert!(open[0].contains("LORE_ALLOWED_HOSTS"));
        let pinned = vec!["lore.example.com".to_string()];
        assert!(
            startup_warnings(&db, true, &pinned, &agents)
                .unwrap()
                .is_empty()
        );
        db.execute_for_test(
            "INSERT INTO agent_registry (name, kind, created_by) VALUES ('cursor', 'oauth', 'admin');",
        );
        let shared = startup_warnings(&db, true, &pinned, &agents).unwrap();
        assert_eq!(shared.len(), 1);
        assert!(shared[0].contains("\"cursor\""), "{shared:?}");
    }

    const ENV_TOKEN: &str = "claude-env-token-0123456789abcdef";
    const ADMIN_PASSWORD: &str = "admin-password-long";
    const REDIRECT: &str = "http://127.0.0.1:47123/callback";

    struct Server {
        base: String,
        db: Db,
        http: reqwest::Client,
    }

    /// The whole app as `main` builds it, on a free port, with one env
    /// token (`claude`) and the admin view on.
    async fn serve() -> Server {
        static SERVERS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "lore-app-test-{}-{}",
            std::process::id(),
            SERVERS.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let db = Db::open(&dir.join("lore.db")).unwrap();
        let tokens = auth::load_tokens("", &format!("claude:{ENV_TOKEN}")).unwrap();
        db.register_token_agents(&["claude".into()]).unwrap();
        let auth = McpAuth::new(tokens, db.clone(), false);
        let events = Events::new();
        let lore = Lore::new(
            db.clone(),
            Embedder::disabled(),
            0.8,
            events.clone(),
            12,
            None,
            ops::Guard::default(),
        );
        let admin = Admin::new(
            db.clone(),
            ADMIN_PASSWORD.into(),
            None,
            None,
            false,
            vec!["claude".into()],
            None,
            0.8,
            events.clone(),
            Embedder::disabled(),
            12,
            None,
            ops::Guard::default(),
        );
        let router = app(auth, lore, None, events, Some(admin));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            axum::serve(
                listener,
                router.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        Server { base, db, http }
    }

    /// Signs in and returns the session cookie.
    async fn login(server: &Server, username: &str, password: &str) -> String {
        let response = server
            .http
            .post(format!("{}/admin/api/login", server.base))
            .json(&json!({ "username": username, "password": password }))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200, "sign-in as {username}");
        let cookie = response.headers()[header::SET_COOKIE].to_str().unwrap();
        cookie.split(';').next().unwrap().to_string()
    }

    fn pkce() -> (String, String) {
        let verifier = oauth::random_token().unwrap();
        let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(Sha256::digest(verifier.as_bytes()));
        (verifier, challenge)
    }

    async fn register(server: &Server) -> String {
        let response = server
            .http
            .post(format!("{}/oauth/register", server.base))
            .json(&json!({
                "client_name": "Claude Code",
                "redirect_uris": [REDIRECT],
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
                "token_endpoint_auth_method": "none",
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 201);
        let body: Value = response.json().await.unwrap();
        assert_eq!(body["token_endpoint_auth_method"], "none");
        body["client_id"].as_str().unwrap().to_string()
    }

    fn authorize_url(server: &Server, client_id: &str, challenge: &str, redirect: &str) -> String {
        let mut url = reqwest::Url::parse(&format!("{}/oauth/authorize", server.base)).unwrap();
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", client_id)
            .append_pair("redirect_uri", redirect)
            .append_pair("code_challenge", challenge)
            .append_pair("code_challenge_method", "S256")
            .append_pair("state", "state-123")
            .append_pair("scope", "lore")
            .append_pair("resource", &format!("{}/mcp", server.base));
        url.to_string()
    }

    /// Opens the consent page and returns the request id it carries.
    async fn authorize(server: &Server, client_id: &str, challenge: &str) -> String {
        let response = server
            .http
            .get(authorize_url(server, client_id, challenge, REDIRECT))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(response.headers()[header::X_FRAME_OPTIONS], "DENY");
        let page = response.text().await.unwrap();
        let start = page.find(r#"name="lore-request" content=""#).unwrap() + 29;
        page[start..start + 43].to_string()
    }

    async fn consent(server: &Server, cookie: &str, id: &str) -> (StatusCode, Value) {
        let response = server
            .http
            .get(format!("{}/admin/api/oauth/requests/{id}", server.base))
            .header(header::COOKIE, cookie)
            .send()
            .await
            .unwrap();
        (
            response.status(),
            response.json().await.unwrap_or(Value::Null),
        )
    }

    async fn approve(server: &Server, cookie: &str, id: &str, body: Value) -> (StatusCode, Value) {
        let response = server
            .http
            .post(format!(
                "{}/admin/api/oauth/requests/{id}/approve",
                server.base
            ))
            .header(header::COOKIE, cookie)
            .json(&body)
            .send()
            .await
            .unwrap();
        (
            response.status(),
            response.json().await.unwrap_or(Value::Null),
        )
    }

    fn query_of(url: &str) -> HashMap<String, String> {
        reqwest::Url::parse(url)
            .unwrap()
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect()
    }

    async fn token(server: &Server, form: &[(&str, &str)]) -> (StatusCode, Value) {
        let response = server
            .http
            .post(format!("{}/oauth/token", server.base))
            .form(form)
            .send()
            .await
            .unwrap();
        let status = response.status();
        (status, response.json().await.unwrap_or(Value::Null))
    }

    /// Runs the flow up to the authorization code: register, authorize,
    /// sign in as admin, approve a new agent.
    async fn code_for(server: &Server, name: &str) -> (String, String, String) {
        let client_id = register(server).await;
        let (verifier, challenge) = pkce();
        let id = authorize(server, &client_id, &challenge).await;
        let cookie = login(server, "admin", ADMIN_PASSWORD).await;
        let (status, request) = consent(server, &cookie, &id).await;
        assert_eq!(status, 200, "{request}");
        let (status, approved) = approve(
            server,
            &cookie,
            &id,
            json!({ "csrf": request["csrf"], "mode": "new", "name": name, "avatar": "comet" }),
        )
        .await;
        assert_eq!(status, 200, "{approved}");
        let query = query_of(approved["redirect"].as_str().unwrap());
        assert_eq!(query["state"], "state-123");
        (client_id, verifier, query["code"].clone())
    }

    async fn exchange(
        server: &Server,
        client_id: &str,
        verifier: &str,
        code: &str,
    ) -> (StatusCode, Value) {
        let resource = format!("{}/mcp", server.base);
        token(
            server,
            &[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", REDIRECT),
                ("client_id", client_id),
                ("code_verifier", verifier),
                ("resource", &resource),
            ],
        )
        .await
    }

    /// `tools/list` on `/mcp` with a bearer token.
    async fn tools_list(server: &Server, bearer: &str) -> reqwest::Response {
        server
            .http
            .post(format!("{}/mcp", server.base))
            .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
            .header(header::ACCEPT, "application/json, text/event-stream")
            .header("MCP-Protocol-Version", "2025-06-18")
            .json(&json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {} }))
            .send()
            .await
            .unwrap()
    }

    /// Waits for the request counter the bearer check bumps on the side.
    async fn seen(db: &Db, agent: &str) -> bool {
        for _ in 0..50 {
            if db
                .agents(&[])
                .unwrap()
                .iter()
                .any(|a| a.name == agent && a.requests > 0)
            {
                return true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        false
    }

    #[tokio::test]
    async fn metadata_documents_and_the_401_challenge() {
        let server = serve().await;
        let get = |path: &str| server.http.get(format!("{}{path}", server.base)).send();
        for path in [
            "/.well-known/oauth-protected-resource",
            "/.well-known/oauth-protected-resource/mcp",
        ] {
            let body: Value = get(path).await.unwrap().json().await.unwrap();
            assert_eq!(body["resource"], format!("{}/mcp", server.base));
            assert_eq!(body["authorization_servers"], json!([server.base]));
            assert_eq!(body["bearer_methods_supported"], json!(["header"]));
        }
        let body: Value = get("/.well-known/oauth-authorization-server")
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(body["issuer"], server.base);
        for (key, path) in [
            ("authorization_endpoint", "/oauth/authorize"),
            ("token_endpoint", "/oauth/token"),
            ("registration_endpoint", "/oauth/register"),
            ("revocation_endpoint", "/oauth/revoke"),
        ] {
            assert_eq!(body[key], format!("{}{path}", server.base));
        }
        assert_eq!(body["code_challenge_methods_supported"], json!(["S256"]));
        assert_eq!(
            body["token_endpoint_auth_methods_supported"],
            json!(["none"])
        );
        assert_eq!(
            body["grant_types_supported"],
            json!(["authorization_code", "refresh_token"])
        );
        assert_eq!(body["response_types_supported"], json!(["code"]));
        assert_eq!(body["scopes_supported"], json!(["lore"]));

        let response = tools_list(&server, "").await;
        assert_eq!(response.status(), 401);
        assert_eq!(
            response.headers()[header::WWW_AUTHENTICATE],
            format!(
                "Bearer resource_metadata=\"{}/.well-known/oauth-protected-resource\"",
                server.base
            )
        );
        assert_eq!(
            response.text().await.unwrap(),
            "missing or invalid bearer token\n"
        );
    }

    #[tokio::test]
    async fn registration_refuses_bad_metadata() {
        let server = serve().await;
        let post = |body: Value| {
            server
                .http
                .post(format!("{}/oauth/register", server.base))
                .json(&body)
                .send()
        };
        for uris in [
            json!([]),
            json!(["http://evil.example.com/cb"]),
            json!(["https://ok.example.com/cb#fragment"]),
            json!(["javascript:alert(1)"]),
            json!(["not a uri"]),
            json!([
                "https://a.example/1",
                "https://a.example/2",
                "https://a.example/3",
                "https://a.example/4",
                "https://a.example/5",
                "https://a.example/6"
            ]),
        ] {
            let response = post(json!({ "client_name": "x", "redirect_uris": uris }))
                .await
                .unwrap();
            assert_eq!(response.status(), 400, "{uris}");
            let body: Value = response.json().await.unwrap();
            assert_eq!(body["error"], "invalid_redirect_uri", "{uris}");
        }
        let response = post(json!({
            "redirect_uris": ["https://ok.example.com/cb"],
            "grant_types": ["client_credentials"],
        }))
        .await
        .unwrap();
        assert_eq!(response.status(), 400);
        let response = server
            .http
            .post(format!("{}/oauth/register", server.base))
            .body("nope")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 400);
        // A hostile name is kept as plain, shortened text.
        let response = post(json!({
            "client_name": format!("<img src=x>\u{7}{}", "y".repeat(300)),
            "redirect_uris": ["cursor://anysphere.cursor-retrieval/oauth/callback"],
        }))
        .await
        .unwrap();
        assert_eq!(response.status(), 201);
        let body: Value = response.json().await.unwrap();
        let name = body["client_name"].as_str().unwrap();
        assert!(name.starts_with("<img src=x>y") && name.chars().count() == 100);
    }

    #[tokio::test]
    async fn the_code_flow_with_pkce_connects_the_approved_agent() {
        let server = serve().await;
        let (client_id, verifier, code) = code_for(&server, "cursor-laptop").await;
        let (status, tokens) = exchange(&server, &client_id, &verifier, &code).await;
        assert_eq!(status, 200, "{tokens}");
        assert_eq!(tokens["token_type"], "Bearer");
        assert_eq!(tokens["expires_in"], 3600);
        let access = tokens["access_token"].as_str().unwrap().to_string();
        let refresh = tokens["refresh_token"].as_str().unwrap().to_string();
        assert_eq!(access.len(), 43);
        // Only hashes are stored.
        let stored = format!("{:?}", server.db.table_counts().unwrap());
        assert!(!stored.contains(&access));

        let response = tools_list(&server, &access).await;
        assert_eq!(response.status(), 200);
        let text = response.text().await.unwrap();
        assert!(text.contains("\"hello\""), "{text}");
        assert!(seen(&server.db, "cursor-laptop").await);
        let registered = server.db.registry_agent("cursor-laptop").unwrap().unwrap();
        assert_eq!(
            (
                registered.kind.as_str(),
                registered.avatar.as_str(),
                registered.created_by.as_str()
            ),
            ("oauth", "comet", "admin")
        );

        // Refresh rotates; the old refresh token used again revokes all.
        let refreshed = |refresh: String| {
            let (server, client_id) = (&server, client_id.clone());
            async move {
                token(
                    server,
                    &[
                        ("grant_type", "refresh_token"),
                        ("refresh_token", &refresh),
                        ("client_id", &client_id),
                    ],
                )
                .await
            }
        };
        let (status, rotated) = refreshed(refresh.clone()).await;
        assert_eq!(status, 200, "{rotated}");
        let access2 = rotated["access_token"].as_str().unwrap().to_string();
        let refresh2 = rotated["refresh_token"].as_str().unwrap().to_string();
        assert_ne!(refresh, refresh2);
        assert_eq!(tools_list(&server, &access2).await.status(), 200);
        let (status, error) = refreshed(refresh.clone()).await;
        assert_eq!(
            (status, error["error"].as_str()),
            (StatusCode::BAD_REQUEST, Some("invalid_grant"))
        );
        assert_eq!(tools_list(&server, &access2).await.status(), 401);
        let (status, _) = refreshed(refresh2).await;
        assert_eq!(status, 400);

        // A new authorization; revoking its access token ends it.
        let (client_id, verifier, code) = code_for(&server, "codex-desk").await;
        let (_, tokens) = exchange(&server, &client_id, &verifier, &code).await;
        let access = tokens["access_token"].as_str().unwrap().to_string();
        assert_eq!(tools_list(&server, &access).await.status(), 200);
        let response = server
            .http
            .post(format!("{}/oauth/revoke", server.base))
            .form(&[
                ("token", access.as_str()),
                ("client_id", client_id.as_str()),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(tools_list(&server, &access).await.status(), 401);
        // An unknown token is answered the same way.
        let response = server
            .http
            .post(format!("{}/oauth/revoke", server.base))
            .form(&[("token", "unknown")])
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
    }

    #[tokio::test]
    async fn codes_are_single_use_bound_and_short_lived() {
        let server = serve().await;
        // Wrong verifier: refused, and the code is used up.
        let (client_id, _, code) = code_for(&server, "agent-one").await;
        let (_, other) = pkce();
        let (status, error) = exchange(&server, &client_id, &other, &code).await;
        assert_eq!(
            (status, error["error"].as_str()),
            (StatusCode::BAD_REQUEST, Some("invalid_grant"))
        );

        // Reused code: the second exchange fails and revokes the first.
        let (client_id, verifier, code) = code_for(&server, "agent-two").await;
        let (status, tokens) = exchange(&server, &client_id, &verifier, &code).await;
        assert_eq!(status, 200);
        let access = tokens["access_token"].as_str().unwrap().to_string();
        let (status, error) = exchange(&server, &client_id, &verifier, &code).await;
        assert_eq!(
            (status, error["error"].as_str()),
            (StatusCode::BAD_REQUEST, Some("invalid_grant"))
        );
        assert_eq!(tools_list(&server, &access).await.status(), 401);

        // Expired code.
        let (client_id, verifier, code) = code_for(&server, "agent-three").await;
        server
            .db
            .execute_for_test("UPDATE oauth_codes SET expires_at = 0");
        let (status, error) = exchange(&server, &client_id, &verifier, &code).await;
        assert_eq!(
            (status, error["error"].as_str()),
            (StatusCode::BAD_REQUEST, Some("invalid_grant"))
        );

        // A code is bound to its client.
        let (_, verifier, code) = code_for(&server, "agent-four").await;
        let stranger = register(&server).await;
        let (status, _) = exchange(&server, &stranger, &verifier, &code).await;
        assert_eq!(status, 400);
        let (status, error) = exchange(&server, "unknown-client", &verifier, "x").await;
        assert_eq!(
            (status, error["error"].as_str()),
            (StatusCode::UNAUTHORIZED, Some("invalid_client"))
        );

        // A redirect URI that does not match never redirects; nor does an
        // unknown client.
        let client_id = register(&server).await;
        let (_, challenge) = pkce();
        for url in [
            authorize_url(
                &server,
                &client_id,
                &challenge,
                "http://127.0.0.1:47123/other",
            ),
            authorize_url(&server, &client_id, &challenge, "https://evil.example/cb"),
            authorize_url(&server, "nobody", &challenge, REDIRECT),
        ] {
            let response = server.http.get(url).send().await.unwrap();
            assert_eq!(response.status(), 400);
            assert!(response.headers().get(header::LOCATION).is_none());
        }
        // Without PKCE the error goes back to the (valid) redirect URI.
        let url = authorize_url(&server, &client_id, "", REDIRECT)
            .replace("code_challenge_method=S256", "code_challenge_method=plain");
        let response = server.http.get(url).send().await.unwrap();
        assert_eq!(response.status(), 303);
        let location = response.headers()[header::LOCATION].to_str().unwrap();
        let query = query_of(location);
        assert_eq!(query["error"], "invalid_request");
        assert_eq!(query["state"], "state-123");
        assert!(location.starts_with(REDIRECT));
        // A resource that is not this server's MCP endpoint.
        let url =
            authorize_url(&server, &client_id, &challenge, REDIRECT).replace("%2Fmcp", "%2Fother");
        let response = server.http.get(url).send().await.unwrap();
        assert_eq!(
            query_of(response.headers()[header::LOCATION].to_str().unwrap())["error"],
            "invalid_target"
        );
    }

    #[tokio::test]
    async fn approving_needs_the_agents_permission_and_the_page_token() {
        let server = serve().await;
        server
            .db
            .add_user(&NewUser {
                username: "writer".into(),
                email: None,
                password_hash: users::hash_password("writer-password").unwrap(),
                permissions: Perms::parse(&["write"]).unwrap(),
                created_by: "admin".into(),
            })
            .unwrap();
        let client_id = register(&server).await;
        let (_, challenge) = pkce();
        let id = authorize(&server, &client_id, &challenge).await;

        // Not signed in: nothing.
        let (status, _) = consent(&server, "lore_session=none", &id).await;
        assert_eq!(status, 401);

        // Without `agents`: a clear refusal, and approving is refused.
        let writer = login(&server, "writer", "writer-password").await;
        let (status, body) = consent(&server, &writer, &id).await;
        assert_eq!(status, 403);
        assert_eq!(body["permission"], false);
        assert!(
            body["error"]
                .as_str()
                .unwrap()
                .contains("agents permission")
        );
        let (status, _) = approve(
            &server,
            &writer,
            &id,
            json!({ "csrf": body["csrf"], "mode": "new", "name": "sneaky", "avatar": "" }),
        )
        .await;
        assert_eq!(status, 403);
        assert!(server.db.registry_agent("sneaky").unwrap().is_none());

        // The page token is required and bound to the sign-in.
        let admin = login(&server, "admin", ADMIN_PASSWORD).await;
        let (_, request) = consent(&server, &admin, &id).await;
        assert_eq!(request["client_name"], "Claude Code");
        assert_eq!(request["redirect_uri"], REDIRECT);
        assert_eq!(request["suggested_name"], "claude-code");
        assert_eq!(request["avatars"].as_array().unwrap().len(), 10);
        let csrf = request["csrf"].as_str().unwrap().to_string();
        for bad in [json!(""), json!("wrong"), json!(null)] {
            let (status, _) = approve(
                &server,
                &admin,
                &id,
                json!({ "csrf": bad, "mode": "new", "name": "agent-x", "avatar": "" }),
            )
            .await;
            // A missing token is refused; one that is not a string does
            // not even parse.
            assert!(
                status == 403 || (bad.is_null() && status == 422),
                "{bad}: {status}"
            );
        }
        assert!(server.db.registry_agent("agent-x").unwrap().is_none());
        let other_admin = login(&server, "admin", ADMIN_PASSWORD).await;
        let (status, _) = approve(
            &server,
            &other_admin,
            &id,
            json!({ "csrf": csrf, "mode": "new", "name": "agent-x", "avatar": "" }),
        )
        .await;
        assert_eq!(status, 403);

        // Names that are not free are refused; the request stays open.
        for name in ["claude", "admin", "viewer", "shared", "Bad Name", "x"] {
            let (status, body) = approve(
                &server,
                &admin,
                &id,
                json!({ "csrf": csrf, "mode": "new", "name": name, "avatar": "" }),
            )
            .await;
            assert_eq!(status, 400, "{name}: {body}");
        }
        let (status, _) = approve(
            &server,
            &admin,
            &id,
            json!({ "csrf": csrf, "mode": "existing", "name": "claude", "avatar": "" }),
        )
        .await;
        assert_eq!(status, 400);

        // Deny sends the application `access_denied` and ends the request.
        let response = server
            .http
            .post(format!(
                "{}/admin/api/oauth/requests/{id}/deny",
                server.base
            ))
            .header(header::COOKIE, &admin)
            .json(&json!({ "csrf": csrf }))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let body: Value = response.json().await.unwrap();
        let query = query_of(body["redirect"].as_str().unwrap());
        assert_eq!(query["error"], "access_denied");
        assert_eq!(query["state"], "state-123");
        let (status, _) = approve(
            &server,
            &admin,
            &id,
            json!({ "csrf": csrf, "mode": "new", "name": "agent-x", "avatar": "" }),
        )
        .await;
        assert_eq!(status, 404);

        // An existing OAuth agent can be re-authorized; a new one with its
        // name cannot be made.
        code_for(&server, "agent-x").await;
        let id = authorize(&server, &client_id, &challenge).await;
        let (_, request) = consent(&server, &admin, &id).await;
        assert_eq!(request["existing"][0]["name"], "agent-x");
        assert_eq!(request["suggested_name"], "claude-code");
        let (status, _) = approve(
            &server,
            &admin,
            &id,
            json!({ "csrf": request["csrf"], "mode": "new", "name": "agent-x", "avatar": "" }),
        )
        .await;
        assert_eq!(status, 400);
        let (status, body) = approve(
            &server,
            &admin,
            &id,
            json!({ "csrf": request["csrf"], "mode": "existing", "name": "agent-x", "avatar": "" }),
        )
        .await;
        assert_eq!(status, 200, "{body}");
    }

    #[tokio::test]
    async fn disabled_agents_are_refused_and_env_tokens_keep_working() {
        let server = serve().await;
        // The env token works as before.
        assert_eq!(tools_list(&server, ENV_TOKEN).await.status(), 200);
        assert!(seen(&server.db, "claude").await);
        let (client_id, verifier, code) = code_for(&server, "cursor").await;
        let (_, tokens) = exchange(&server, &client_id, &verifier, &code).await;
        let access = tokens["access_token"].as_str().unwrap().to_string();
        assert_eq!(tools_list(&server, &access).await.status(), 200);

        server
            .db
            .set_agent_disabled("claude", true, "admin")
            .unwrap();
        let response = tools_list(&server, ENV_TOKEN).await;
        assert_eq!(response.status(), 403);
        assert!(
            response
                .text()
                .await
                .unwrap()
                .contains("\"claude\" is disabled")
        );
        server
            .db
            .set_agent_disabled("cursor", true, "admin")
            .unwrap();
        let response = tools_list(&server, &access).await;
        assert_eq!(response.status(), 401);
        assert!(response.headers().contains_key(header::WWW_AUTHENTICATE));
        // A disabled agent's refresh token is refused too.
        let refresh = tokens["refresh_token"].as_str().unwrap();
        let (status, _) = token(
            &server,
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh),
                ("client_id", &client_id),
            ],
        )
        .await;
        assert_eq!(status, 400);
        server
            .db
            .set_agent_disabled("claude", false, "admin")
            .unwrap();
        server
            .db
            .set_agent_disabled("cursor", false, "admin")
            .unwrap();
        assert_eq!(tools_list(&server, ENV_TOKEN).await.status(), 200);
        assert_eq!(tools_list(&server, &access).await.status(), 200);
    }
}
