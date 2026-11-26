//! project-lore: a shared second brain for coding agents, served over MCP.

mod admin;
mod auth;
mod db;
mod embed;
mod events;
mod gitproxy;
mod ops;
mod server;
mod vault;

use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use anyhow::{Context, Result, bail};
use axum::{Router, middleware, routing::get};
use rmcp::transport::streamable_http_server::{
    StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
};

use crate::{
    admin::{Admin, Recaptcha},
    auth::{McpAuth, RateLimiter, SHARED_AGENT},
    db::Db,
    embed::{Embedder, Model},
    events::Events,
    gitproxy::GitProxy,
    server::Lore,
    vault::VaultKey,
};

const MIN_ADMIN_PASSWORD_LEN: usize = 12;

#[tokio::main]
async fn main() -> Result<()> {
    if std::env::args().nth(1).as_deref() == Some("healthcheck") {
        return healthcheck();
    }
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,ort=warn,rmcp=warn".into()),
        )
        .init();

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

    // Stateless JSON responses: nothing is lost when the container restarts,
    // and every request is authenticated on its own.
    let mut config = StreamableHttpServerConfig::default()
        .with_legacy_session_mode(false)
        .with_json_response(true);
    config = if allowed_hosts.is_empty() {
        // Every request carries the bearer token, so DNS rebinding cannot reach
        // the tools; Host pinning is an optional extra.
        config.disable_allowed_hosts()
    } else {
        config.with_allowed_hosts(allowed_hosts)
    };

    let configured_agents: Vec<String> = tokens
        .iter()
        .map(|t| t.agent.clone())
        .filter(|name| name != SHARED_AGENT)
        .collect();
    let mcp_auth = Arc::new(McpAuth {
        tokens,
        db: db.clone(),
        trust_proxy,
        failures: RateLimiter::new(20, Duration::from_secs(5 * 60)),
        requests: RateLimiter::new(600, Duration::from_secs(60)),
    });

    let events = Events::new();
    let mcp = {
        let (db, embedder, events) = (db.clone(), embedder.clone(), events.clone());
        let (vault, guard) = (vault.clone(), guard.clone());
        StreamableHttpService::new(
            move || {
                Ok(Lore::new(
                    db.clone(),
                    embedder.clone(),
                    min_similarity,
                    events.clone(),
                    idle_hours,
                    vault.clone(),
                    guard.clone(),
                ))
            },
            Arc::new(LocalSessionManager::default()),
            config,
        )
    };

    let mut app = Router::new()
        .nest_service("/mcp", mcp)
        .layer(middleware::from_fn_with_state(
            mcp_auth.clone(),
            auth::require_token,
        ))
        .route("/health", get(|| async { "ok" }))
        // Plain `git` speaks to /git: lore authenticates the agent with
        // its own lore token and adds the stored credential upstream,
        // where the agent's machine never sees it.
        .merge(gitproxy::router(Arc::new(GitProxy::new(
            mcp_auth,
            vault.clone(),
            events.clone(),
        ))));

    match admin_password()? {
        Some(password) => {
            let viewer_password = viewer_password(&password)?;
            if viewer_password.is_some() {
                tracing::info!("viewer password set: watch-only sign-in enabled");
            }
            let recaptcha = recaptcha()?;
            if recaptcha.is_none() {
                tracing::warn!("admin view runs without reCAPTCHA (keys not set)");
            }
            let admin = Admin::new(
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
            );
            app = app.merge(admin::router(Arc::new(admin)));
            tracing::info!("admin view enabled at /admin");
        }
        None => tracing::info!("admin view disabled (LORE_ADMIN_PASSWORD not set)"),
    }

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
