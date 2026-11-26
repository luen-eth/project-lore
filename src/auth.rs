//! Bearer-token authentication for the MCP endpoint, plus rate limiting.

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::{Result, bail};
use axum::{
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use subtle::ConstantTimeEq;

use crate::db::Db;

const MIN_TOKEN_LEN: usize = 24;
/// Name recorded for requests made with the shared `LORE_TOKEN`.
pub const SHARED_AGENT: &str = "shared";

/// The agent a request was authenticated as. Read by the tool handlers.
#[derive(Clone, Debug)]
pub struct Agent(pub String);

/// A bearer token and the agent it was issued to.
pub struct Token {
    pub agent: String,
    secret: String,
}

impl Token {
    /// The token's secret, for the set of lore's own secrets that every
    /// provider response is redacted against. Never logged.
    pub fn secret(&self) -> &str {
        &self.secret
    }
}

/// Reads `LORE_TOKEN` (one shared secret) and `LORE_TOKENS`
/// (`agent:secret,agent:secret`, one secret per agent). Either or both may be set.
pub fn load_tokens(shared: &str, per_agent: &str) -> Result<Vec<Token>> {
    let mut tokens = Vec::new();
    if !shared.trim().is_empty() {
        tokens.push(Token {
            agent: SHARED_AGENT.to_string(),
            secret: shared.trim().to_string(),
        });
    }
    for pair in per_agent.split(',') {
        let pair = pair.trim();
        if pair.is_empty() {
            continue;
        }
        let Some((agent, secret)) = pair.split_once(':') else {
            bail!("LORE_TOKENS entries must look like agent:secret");
        };
        let agent = agent.trim().to_lowercase();
        if agent.is_empty() || agent == SHARED_AGENT {
            bail!("LORE_TOKENS agent names must be non-empty and not \"{SHARED_AGENT}\"");
        }
        if tokens.iter().any(|t: &Token| t.agent == agent) {
            bail!("LORE_TOKENS lists the agent \"{agent}\" twice");
        }
        tokens.push(Token {
            agent,
            secret: secret.trim().to_string(),
        });
    }
    if tokens.is_empty() {
        bail!(
            "set LORE_TOKEN, or LORE_TOKENS as agent:secret pairs \
             (generate a secret with: openssl rand -hex 32)"
        );
    }
    if let Some(short) = tokens.iter().find(|t| t.secret.len() < MIN_TOKEN_LEN) {
        bail!(
            "the token for \"{}\" is shorter than {MIN_TOKEN_LEN} characters",
            short.agent
        );
    }
    Ok(tokens)
}

/// Fixed-window counter keyed by an arbitrary string (an IP or an agent name).
pub struct RateLimiter {
    max: u32,
    window: Duration,
    hits: Mutex<HashMap<String, (u32, Instant)>>,
}

impl RateLimiter {
    pub fn new(max: u32, window: Duration) -> Self {
        Self {
            max,
            window,
            hits: Mutex::new(HashMap::new()),
        }
    }

    /// Seconds until `key` is allowed again, if it is over the limit right now.
    pub fn blocked(&self, key: &str) -> Option<u64> {
        let hits = self.hits.lock().unwrap_or_else(|e| e.into_inner());
        match hits.get(key) {
            Some((count, started)) if *count >= self.max && started.elapsed() < self.window => {
                Some((self.window - started.elapsed()).as_secs().max(1))
            }
            _ => None,
        }
    }

    /// Counts one event. Returns the retry delay if this event exceeded the limit.
    pub fn hit(&self, key: &str) -> Option<u64> {
        let mut hits = self.hits.lock().unwrap_or_else(|e| e.into_inner());
        if hits.len() > 10_000 {
            let window = self.window;
            hits.retain(|_, (_, started)| started.elapsed() < window);
        }
        let slot = hits.entry(key.to_string()).or_insert((0, Instant::now()));
        if slot.1.elapsed() >= self.window {
            *slot = (0, Instant::now());
        }
        slot.0 += 1;
        if slot.0 > self.max {
            Some((self.window - slot.1.elapsed()).as_secs().max(1))
        } else {
            None
        }
    }

    pub fn reset(&self, key: &str) {
        self.hits
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(key);
    }
}

/// The client address. Behind a reverse proxy the socket peer is the proxy, so
/// the last `X-Forwarded-For` hop (the one our proxy appended) is used instead.
pub fn client_ip(headers: &HeaderMap, peer: Option<SocketAddr>, trust_proxy: bool) -> String {
    if trust_proxy {
        let forwarded = headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.rsplit(',').next())
            .and_then(|v| v.trim().parse::<IpAddr>().ok());
        if let Some(ip) = forwarded {
            return ip.to_string();
        }
    }
    peer.map(|p| p.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

pub fn too_many_requests(retry_after: u64) -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        [(header::RETRY_AFTER, retry_after.to_string())],
        "too many requests, slow down\n",
    )
        .into_response()
}

pub struct McpAuth {
    pub tokens: Vec<Token>,
    pub db: Db,
    pub trust_proxy: bool,
    /// Wrong-token attempts per client address.
    pub failures: RateLimiter,
    /// Requests per authenticated agent, to contain runaway loops.
    pub requests: RateLimiter,
}

/// The token a presented secret matches, if any. Every token is compared
/// in constant time, so timing does not reveal which one matched. Shared
/// by the `/mcp` middleware and the git proxy.
pub fn match_token<'a>(tokens: &'a [Token], presented: &str) -> Option<&'a Token> {
    let mut matched = None;
    for token in tokens {
        if bool::from(presented.as_bytes().ct_eq(token.secret.as_bytes())) {
            matched = Some(token);
        }
    }
    matched
}

/// Rejects requests without a known `Authorization: Bearer <token>`, throttles
/// repeated failures per address, and tags the rest with the token's agent.
pub async fn require_token(
    State(auth): State<Arc<McpAuth>>,
    mut request: Request,
    next: Next,
) -> Response {
    let presented = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| {
            value
                .strip_prefix("Bearer ")
                .or_else(|| value.strip_prefix("bearer "))
        })
        .map(str::trim)
        .unwrap_or("");

    let Some(token) = match_token(&auth.tokens, presented) else {
        let peer = request
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|info| info.0);
        let ip = client_ip(request.headers(), peer, auth.trust_proxy);
        if let Some(retry_after) = auth.failures.hit(&ip) {
            tracing::warn!(%ip, "too many failed token attempts");
            return too_many_requests(retry_after);
        }
        return (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Bearer")],
            "missing or invalid bearer token\n",
        )
            .into_response();
    };

    if let Some(retry_after) = auth.requests.hit(&token.agent) {
        return too_many_requests(retry_after);
    }

    let client = request
        .headers()
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .chars()
        .take(120)
        .collect::<String>();
    let db = auth.db.clone();
    let agent = token.agent.clone();
    tokio::task::spawn_blocking(move || {
        if let Err(error) = db.touch_agent(&agent, &client) {
            tracing::warn!(%error, "recording agent activity failed");
        }
    });

    request.extensions_mut().insert(Agent(token.agent.clone()));
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limiter_blocks_after_max_and_resets() {
        let limiter = RateLimiter::new(2, Duration::from_secs(60));
        assert!(limiter.hit("a").is_none());
        assert!(limiter.blocked("a").is_none());
        assert!(limiter.hit("a").is_none());
        assert!(limiter.blocked("a").is_some());
        assert!(limiter.hit("a").is_some());
        assert!(limiter.hit("b").is_none());
        limiter.reset("a");
        assert!(limiter.blocked("a").is_none());
    }

    #[test]
    fn tokens_are_validated() {
        let long = "x".repeat(32);
        assert!(load_tokens("", "").is_err());
        assert!(load_tokens("short", "").is_err());
        assert!(load_tokens("", &format!("claude:{long},claude:{long}")).is_err());
        let tokens = load_tokens(&long, &format!("Claude:{long}, codex:{long}")).unwrap();
        let names: Vec<_> = tokens.iter().map(|t| t.agent.as_str()).collect();
        assert_eq!(names, ["shared", "claude", "codex"]);
    }

    #[test]
    fn forwarded_address_is_used_only_behind_a_proxy() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "9.9.9.9, 1.2.3.4".parse().unwrap());
        let peer = Some("10.0.0.1:5000".parse().unwrap());
        assert_eq!(client_ip(&headers, peer, true), "1.2.3.4");
        assert_eq!(client_ip(&headers, peer, false), "10.0.0.1");
    }
}
