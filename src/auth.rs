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

use crate::{db::Db, runscope::RunScope};

const MIN_TOKEN_LEN: usize = 24;
/// Name recorded for requests made with the shared `LORE_TOKEN`.
pub const SHARED_AGENT: &str = "shared";

/// The agent a request was authenticated as. Read by the tool handlers.
#[derive(Clone, Debug)]
pub struct Agent(pub String);

/// Marks a request that arrived through the internal runner listener
/// (`LORE_RUNNER_BIND`), the only place a built-in agent's run token is
/// accepted. `main` adds it, as a request extension, to the routes it
/// serves there; on the public listener a run token is refused like an
/// unknown one, so a token that leaks out of a run is useless from the
/// internet.
#[derive(Clone, Copy, Debug)]
pub struct InternalListener;

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

/// An address range: `10.0.1.0/24`, `fd00::/8`, or one address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    net: IpAddr,
    prefix: u8,
}

impl Cidr {
    pub fn new(net: IpAddr, prefix: u8) -> Self {
        Self { net, prefix }
    }

    pub fn parse(text: &str) -> Option<Self> {
        let text = text.trim();
        let (address, prefix) = match text.split_once('/') {
            Some((address, prefix)) => (address, Some(prefix.parse::<u8>().ok()?)),
            None => (text, None),
        };
        let net: IpAddr = address.parse().ok()?;
        let max = if net.is_ipv4() { 32 } else { 128 };
        let prefix = prefix.unwrap_or(max);
        (prefix <= max).then_some(Self { net, prefix })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = unmapped(ip);
        match (self.net, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = u32::MAX
                    .checked_shl(32 - u32::from(self.prefix))
                    .unwrap_or(0);
                u32::from(net) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.prefix))
                    .unwrap_or(0);
                u128::from(net) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }
}

/// An IPv4 address written as IPv6 (`::ffff:a.b.c.d`), as the IPv4 one.
fn unmapped(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    }
}

/// Which direct peers may say, in `X-Forwarded-For`, whom they forward
/// for (only with `LORE_TRUST_PROXY=on`).
#[derive(Debug, Clone)]
pub enum ProxyTrust {
    /// Every peer, as before `LORE_TRUSTED_PROXIES` existed: an instance
    /// without built-in agents and without the variable.
    Any,
    /// The ranges `LORE_TRUSTED_PROXIES` names and the addresses the
    /// names in `LORE_TRUSTED_PROXY_HOSTS` resolve to now, never the agent
    /// networks.
    Listed {
        trusted: Vec<Cidr>,
        hosts: Option<Arc<HostTrust>>,
        never: Vec<Cidr>,
    },
    /// With built-in agents and without the variable: private and loopback
    /// peers (a reverse proxy on a Docker network or the host), never the
    /// agent networks.
    Private { never: Vec<Cidr> },
}

static PROXY_TRUST: std::sync::OnceLock<ProxyTrust> = std::sync::OnceLock::new();

/// Sets, once at start-up, which peers' `X-Forwarded-For` is believed.
pub fn set_proxy_trust(trust: ProxyTrust) {
    let _ = PROXY_TRUST.set(trust);
}

/// Reads `LORE_TRUSTED_PROXIES`: address ranges, comma separated.
pub fn parse_trusted_proxies(value: &str) -> Result<Vec<Cidr>> {
    value
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(|entry| {
            Cidr::parse(entry).ok_or_else(|| {
                anyhow::anyhow!(
                    "LORE_TRUSTED_PROXIES must be address ranges such as 10.0.1.0/24, comma \
                     separated (\"{entry}\" is not one)"
                )
            })
        })
        .collect()
}

/// Reads `LORE_TRUSTED_PROXY_HOSTS`: host names, comma separated.
pub fn parse_trusted_proxy_hosts(value: &str) -> Result<Vec<String>> {
    let mut names: Vec<String> = Vec::new();
    for name in value
        .split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
    {
        let valid = name.len() <= 253
            && name.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
            });
        if !valid {
            bail!(
                "LORE_TRUSTED_PROXY_HOSTS must be host names such as dokploy-traefik, comma \
                 separated (\"{name}\" is not one)"
            );
        }
        let name = name.to_ascii_lowercase();
        if !names.contains(&name) {
            names.push(name);
        }
    }
    Ok(names)
}

/// How often the names of `LORE_TRUSTED_PROXY_HOSTS` are resolved again.
pub const PROXY_HOSTS_REFRESH: Duration = Duration::from_secs(30);

/// How long the last address of a name that no longer resolves stays
/// trusted: long enough to ride out a resolver hiccup or a quick restart of
/// the proxy (three refreshes), short enough that an address the proxy gave
/// up is not trusted for long once Docker may hand it to someone else.
pub const PROXY_HOSTS_STALE: Duration = Duration::from_secs(90);

/// The reverse proxy trusted by name (`LORE_TRUSTED_PROXY_HOSTS`): the
/// address its names resolve to, kept current by [`HostTrust::refresh`].
///
/// A name must resolve to one address per address family. A clean answer
/// replaces the name's old address at once (the old address stops being
/// trusted, which is the point: Docker hands a restarted container a new
/// one, and the old one to whoever comes next). An ambiguous answer (two
/// IPv4 or two IPv6 addresses: another container took the name as a
/// network alias) adds nothing: the name keeps only the address it already
/// had, and only while that address is still in the answer; otherwise
/// nothing is trusted for it. A name that stops resolving keeps its last
/// address for [`PROXY_HOSTS_STALE`], then loses it.
#[derive(Debug)]
pub struct HostTrust {
    names: Vec<String>,
    known: Mutex<HashMap<String, Known>>,
    /// The union of every name's addresses, swapped whole.
    current: std::sync::RwLock<Arc<Vec<IpAddr>>>,
}

#[derive(Debug, Clone)]
struct Known {
    /// Trusted now: at most one address per family.
    addresses: Vec<IpAddr>,
    /// When the trusted addresses were last seen in an answer.
    confirmed_at: Instant,
    /// What was last logged about this name, so that a state is logged
    /// once when it starts, not at every refresh.
    noted: String,
}

/// Whether an answer holds more than one address of a family.
fn ambiguous(addresses: &[IpAddr]) -> bool {
    addresses.iter().filter(|ip| ip.is_ipv4()).count() > 1
        || addresses.iter().filter(|ip| ip.is_ipv6()).count() > 1
}

fn shown_addresses(addresses: &[IpAddr]) -> String {
    addresses
        .iter()
        .map(IpAddr::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

impl HostTrust {
    pub fn new(names: Vec<String>) -> Self {
        Self {
            names,
            known: Mutex::new(HashMap::new()),
            current: std::sync::RwLock::new(Arc::new(Vec::new())),
        }
    }

    #[cfg(test)]
    pub fn names(&self) -> &[String] {
        &self.names
    }

    /// Whether `ip` is one of the addresses the names resolve to now.
    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = unmapped(ip);
        self.current
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .contains(&ip)
    }

    /// The addresses trusted now, sorted.
    #[cfg(test)]
    pub fn addresses(&self) -> Vec<IpAddr> {
        let mut addresses = self
            .current
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .to_vec();
        addresses.sort();
        addresses
    }

    /// Takes in one resolution of `name` made at `now`: its addresses, or
    /// why it failed (an empty answer is a failure too).
    pub fn apply(&self, name: &str, answer: std::io::Result<Vec<IpAddr>>, now: Instant) {
        let mut known = self.known.lock().unwrap_or_else(|e| e.into_inner());
        let entry = known.entry(name.to_string()).or_insert_with(|| Known {
            addresses: Vec::new(),
            confirmed_at: now,
            noted: String::new(),
        });
        let before = entry.addresses.clone();
        let answer = answer.and_then(|addresses| {
            let mut addresses: Vec<IpAddr> = addresses.into_iter().map(unmapped).collect();
            addresses.sort();
            addresses.dedup();
            if addresses.is_empty() {
                Err(std::io::Error::other("no address"))
            } else {
                Ok(addresses)
            }
        });
        let note = match answer {
            Ok(addresses) if !ambiguous(&addresses) => {
                entry.addresses = addresses;
                entry.confirmed_at = now;
                format!("clean {}", shown_addresses(&entry.addresses))
            }
            Ok(addresses) => {
                // Keep what was trusted only while it is still answered;
                // never take a new address from an ambiguous answer.
                entry.addresses.retain(|ip| addresses.contains(ip));
                if !entry.addresses.is_empty() {
                    entry.confirmed_at = now;
                }
                let note = format!(
                    "ambiguous {} keeping {}",
                    shown_addresses(&addresses),
                    shown_addresses(&entry.addresses)
                );
                if entry.noted != note {
                    tracing::warn!(
                        host = name,
                        answered = %shown_addresses(&addresses),
                        kept = %shown_addresses(&entry.addresses),
                        "a trusted proxy's name resolves to more than one address of a family \
                         (another container may have taken it as a network alias): no new \
                         address is trusted from it; only the one already trusted is kept, \
                         while it is still among them"
                    );
                }
                note
            }
            Err(error) => {
                if !entry.addresses.is_empty()
                    && now.duration_since(entry.confirmed_at) >= PROXY_HOSTS_STALE
                {
                    tracing::warn!(
                        host = name,
                        %error,
                        dropped = %shown_addresses(&entry.addresses),
                        "a trusted proxy's name has not resolved for {} seconds; its last \
                         address is no longer trusted",
                        PROXY_HOSTS_STALE.as_secs()
                    );
                    entry.addresses.clear();
                }
                let note = format!("failing {}", shown_addresses(&entry.addresses));
                if entry.noted != note && !entry.noted.starts_with("failing") {
                    if entry.addresses.is_empty() {
                        tracing::warn!(
                            host = name,
                            %error,
                            "a name in LORE_TRUSTED_PROXY_HOSTS does not resolve: nothing is \
                             trusted for it until it does"
                        );
                    } else {
                        tracing::warn!(
                            host = name,
                            %error,
                            kept = %shown_addresses(&entry.addresses),
                            "a trusted proxy's name did not resolve; its last address stays \
                             trusted for {} seconds",
                            PROXY_HOSTS_STALE.as_secs()
                        );
                    }
                }
                note
            }
        };
        if entry.addresses != before && note.starts_with("clean") {
            if before.is_empty() {
                tracing::info!(
                    host = name,
                    addresses = %shown_addresses(&entry.addresses),
                    "trusting X-Forwarded-For from this reverse proxy"
                );
            } else {
                tracing::info!(
                    host = name,
                    old = %shown_addresses(&before),
                    new = %shown_addresses(&entry.addresses),
                    "a trusted proxy's address changed; only the new one is trusted now"
                );
            }
        } else if note.starts_with("clean") && entry.noted != note && !entry.noted.is_empty() {
            tracing::info!(
                host = name,
                addresses = %shown_addresses(&entry.addresses),
                "a trusted proxy's name resolves cleanly again"
            );
        }
        entry.noted = note;
        let mut union: Vec<IpAddr> = known
            .values()
            .flat_map(|entry| entry.addresses.iter().copied())
            .collect();
        union.sort();
        union.dedup();
        *self.current.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(union);
    }

    /// Resolves every name once with `resolve` and takes the answers in.
    pub async fn refresh_with<F, Fut>(&self, resolve: F)
    where
        F: Fn(String) -> Fut,
        Fut: std::future::Future<Output = std::io::Result<Vec<IpAddr>>>,
    {
        for name in &self.names {
            let answer = resolve(name.clone()).await;
            self.apply(name, answer, Instant::now());
        }
    }

    /// Resolves every name once through the system resolver (in Docker,
    /// the embedded DNS: a container's name on a shared network).
    pub async fn refresh(&self) {
        self.refresh_with(system_resolve).await;
    }

    /// Keeps the addresses current: resolves every name again every
    /// [`PROXY_HOSTS_REFRESH`], for as long as lore runs.
    pub fn spawn_refresh(self: &Arc<Self>) {
        let this = self.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(PROXY_HOSTS_REFRESH);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            tick.tick().await;
            loop {
                tick.tick().await;
                this.refresh().await;
            }
        });
    }
}

/// One name through the system resolver, bounded to a few seconds.
async fn system_resolve(name: String) -> std::io::Result<Vec<IpAddr>> {
    let lookup = tokio::net::lookup_host((name.as_str(), 0));
    match tokio::time::timeout(Duration::from_secs(5), lookup).await {
        Ok(found) => Ok(found?.map(|addr| addr.ip()).collect()),
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "the resolver did not answer",
        )),
    }
}

/// Whether an address is private or loopback (RFC 1918, unique local,
/// loopback).
fn private_or_loopback(ip: IpAddr) -> bool {
    match unmapped(ip) {
        IpAddr::V4(v4) => v4.is_private() || v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback() || (v6.segments()[0] & 0xfe00) == 0xfc00,
    }
}

/// Whether `peer` may speak for someone else in `X-Forwarded-For`.
pub fn peer_may_forward(trust: &ProxyTrust, peer: Option<SocketAddr>) -> bool {
    let Some(ip) = peer.map(|peer| unmapped(peer.ip())) else {
        return false;
    };
    match trust {
        ProxyTrust::Any => true,
        ProxyTrust::Listed {
            trusted,
            hosts,
            never,
        } => {
            !never.iter().any(|net| net.contains(ip))
                && (trusted.iter().any(|net| net.contains(ip))
                    || hosts.as_ref().is_some_and(|hosts| hosts.contains(ip)))
        }
        ProxyTrust::Private { never } => {
            !never.iter().any(|net| net.contains(ip)) && private_or_loopback(ip)
        }
    }
}

/// The client address. Behind a reverse proxy the socket peer is the proxy, so
/// the last `X-Forwarded-For` hop (the one our proxy appended) is used instead,
/// when the peer is one that may forward ([`ProxyTrust`]).
pub fn client_ip(headers: &HeaderMap, peer: Option<SocketAddr>, trust_proxy: bool) -> String {
    let trusted_peer = peer_may_forward(PROXY_TRUST.get().unwrap_or(&ProxyTrust::Any), peer);
    if trust_proxy && trusted_peer {
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
    /// Whether lore's OAuth authorization server is mounted; a 401 then
    /// points the client at the protected resource metadata.
    pub oauth: bool,
    /// `LORE_ALLOWED_HOSTS`, which the public origin must match when set.
    pub allowed_hosts: Vec<String>,
    /// The built-in agents' runner links, which know the open terminals and
    /// their tokens; none without built-in agents.
    pub terminals: Option<Arc<crate::builtin::Hub>>,
}

/// Who a presented bearer token belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Authenticated {
    /// A token from `LORE_TOKEN` / `LORE_TOKENS`.
    Env(String),
    /// An OAuth access token lore issued.
    OAuth(String),
    /// A built-in agent's run-scoped token: valid while its run lasts, for
    /// what its scope allows (see `runscope`).
    Run(Box<RunScope>),
    /// A built-in agent's terminal token (`lore_term_…`): valid while
    /// that terminal is open, as the agent itself with the levels the
    /// administrator gave it, without a run's scope (whoever opened the
    /// terminal holds the `agents` permission).
    Terminal(String),
}

impl Authenticated {
    pub fn agent(&self) -> &str {
        match self {
            Authenticated::Env(agent)
            | Authenticated::OAuth(agent)
            | Authenticated::Terminal(agent) => agent,
            Authenticated::Run(scope) => &scope.agent,
        }
    }

    /// The run's scope, for a run-scoped token.
    pub fn scope(&self) -> Option<&RunScope> {
        match self {
            Authenticated::Run(scope) => Some(scope),
            _ => None,
        }
    }
}

/// Why a presented bearer token was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refused {
    /// Missing, unknown, expired or revoked.
    Invalid,
    /// The token is known, but its agent is disabled in the agents panel.
    Disabled { agent: String, env: bool },
}

impl McpAuth {
    /// The authentication as `main` builds it, with the standard limits:
    /// 20 failed attempts per address in 5 minutes, 600 requests per agent
    /// per minute.
    pub fn new(tokens: Vec<Token>, db: Db, trust_proxy: bool) -> Self {
        Self {
            tokens,
            db,
            trust_proxy,
            failures: RateLimiter::new(20, Duration::from_secs(5 * 60)),
            requests: RateLimiter::new(600, Duration::from_secs(60)),
            oauth: false,
            allowed_hosts: Vec::new(),
            terminals: None,
        }
    }

    /// Checks a presented bearer token as the public listener does: an
    /// env token first (constant time, as always), then an unexpired,
    /// unrevoked OAuth access token. Either way the agent must not be
    /// disabled. A run token is refused here (see `authenticate_on`).
    #[cfg(test)]
    pub async fn authenticate(&self, presented: &str) -> Result<Authenticated, Refused> {
        self.authenticate_on(presented, false).await
    }

    /// `authenticate`, for a request that came in through the internal
    /// runner listener (`internal`) or not: only there is a built-in
    /// agent's run token accepted. Shared by `/mcp` and the git proxy.
    pub async fn authenticate_on(
        &self,
        presented: &str,
        internal: bool,
    ) -> Result<Authenticated, Refused> {
        if presented.is_empty() {
            return Err(Refused::Invalid);
        }
        if let Some(token) = match_token(&self.tokens, presented) {
            let agent = token.agent.clone();
            let db = self.db.clone();
            let name = agent.clone();
            let disabled =
                tokio::task::spawn_blocking(move || db.token_agent_disabled(&name)).await;
            return match disabled {
                Ok(Ok(true)) => Err(Refused::Disabled { agent, env: true }),
                Ok(Ok(false)) => Ok(Authenticated::Env(agent)),
                // The env tokens worked before the registry existed; a
                // registry that cannot be read does not lock them out.
                other => {
                    tracing::warn!(?other, "reading the agent registry failed");
                    Ok(Authenticated::Env(agent))
                }
            };
        }
        if crate::runscope::looks_like_token(presented) {
            if !internal {
                return Err(Refused::Invalid);
            }
            return self.authenticate_run(presented).await;
        }
        if !crate::oauth::looks_like_token(presented) {
            return Err(Refused::Invalid);
        }
        let db = self.db.clone();
        let hash = crate::oauth::token_hash(presented);
        match tokio::task::spawn_blocking(move || db.access_token_agent(&hash)).await {
            Ok(Ok(Some(found))) if found.disabled => Err(Refused::Disabled {
                agent: found.agent,
                env: false,
            }),
            Ok(Ok(Some(found))) => Ok(Authenticated::OAuth(found.agent)),
            Ok(Ok(None)) => Err(Refused::Invalid),
            other => {
                tracing::error!(?other, "checking an OAuth token failed");
                Err(Refused::Invalid)
            }
        }
    }

    /// A terminal token: only on the internal listener, only while its
    /// terminal is open and only from the address the agent's runner is
    /// connected from; its agent must not be disabled. Not accepted by the
    /// git proxy, which only knows `authenticate_on`.
    pub async fn authenticate_terminal(
        &self,
        presented: &str,
        internal: bool,
        peer: Option<std::net::IpAddr>,
    ) -> Result<Authenticated, Refused> {
        let (true, Some(hub), Some(peer)) = (internal, self.terminals.as_ref(), peer) else {
            return Err(Refused::Invalid);
        };
        let Some(agent) = hub.terminal_token_agent(presented, peer) else {
            return Err(Refused::Invalid);
        };
        let db = self.db.clone();
        let name = agent.clone();
        match tokio::task::spawn_blocking(move || db.registry_agent(&name)).await {
            Ok(Ok(Some(found))) if found.disabled => Err(Refused::Disabled { agent, env: false }),
            Ok(Ok(_)) => Ok(Authenticated::Terminal(agent)),
            other => {
                tracing::error!(?other, "checking a terminal token failed");
                Err(Refused::Invalid)
            }
        }
    }

    /// A run-scoped token: its run has not ended, the token was not
    /// revoked, its hard limit has not passed, and its agent is not
    /// disabled. Anything else is an invalid token (401).
    async fn authenticate_run(&self, presented: &str) -> Result<Authenticated, Refused> {
        let db = self.db.clone();
        let hash = crate::oauth::token_hash(presented);
        let found = tokio::task::spawn_blocking(move || -> Result<Option<(RunScope, bool)>> {
            let Some((run_id, agent, scope)) = db.run_for_token(&hash, crate::db::unix_now())?
            else {
                return Ok(None);
            };
            let mut scope: RunScope = serde_json::from_str(&scope)?;
            // A scope an older build stored carries the old, wider rights:
            // its token is no longer accepted.
            if scope.version < crate::runscope::SCOPE_VERSION {
                return Ok(None);
            }
            // The row is the authority on whose run it is.
            // The branches it created so far, from lore's own record.
            scope.created_branches = db.run_created_branches(&run_id)?;
            scope.run_id = run_id;
            scope.agent = agent;
            let disabled = db
                .registry_agent(&scope.agent)?
                .is_some_and(|agent| agent.disabled);
            Ok(Some((scope, disabled)))
        })
        .await;
        match found {
            Ok(Ok(Some((scope, false)))) => Ok(Authenticated::Run(Box::new(scope))),
            Ok(Ok(Some((scope, true)))) => Err(Refused::Disabled {
                agent: scope.agent,
                env: false,
            }),
            Ok(Ok(None)) => Err(Refused::Invalid),
            other => {
                tracing::error!(?other, "checking a run token failed");
                Err(Refused::Invalid)
            }
        }
    }

    /// The `WWW-Authenticate` value of a 401: with OAuth mounted it names
    /// the protected resource metadata (RFC 9728), as the MCP
    /// authorization specification asks.
    pub fn challenge(&self, headers: &HeaderMap) -> String {
        if !self.oauth {
            return "Bearer".into();
        }
        match crate::oauth::public_origin(headers, self.trust_proxy, &self.allowed_hosts) {
            Some(origin) => format!(
                "Bearer resource_metadata=\"{origin}/.well-known/oauth-protected-resource\""
            ),
            None => "Bearer".into(),
        }
    }
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
/// A disabled env-token agent gets a 403 with a sentence; a disabled OAuth
/// agent's token is refused like an invalid one.
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
        .unwrap_or("")
        .to_string();

    let internal = request.extensions().get::<InternalListener>().is_some();
    let peer_ip = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|info| info.0.ip());
    let found = if crate::builtin::looks_like_terminal_token(&presented) {
        auth.authenticate_terminal(&presented, internal, peer_ip)
            .await
    } else {
        auth.authenticate_on(&presented, internal).await
    };
    let terminal = matches!(found, Ok(Authenticated::Terminal(_)));
    let (agent, scope) = match found {
        Ok(found) => (found.agent().to_string(), found.scope().cloned()),
        Err(Refused::Disabled { agent, env: true }) => {
            tracing::warn!(%agent, "a disabled agent was refused");
            return (
                StatusCode::FORBIDDEN,
                format!("the agent \"{agent}\" is disabled in the lore admin view\n"),
            )
                .into_response();
        }
        Err(refused) => {
            if let Refused::Disabled { agent, .. } = &refused {
                tracing::warn!(%agent, "a disabled OAuth agent was refused");
            } else {
                let peer = request
                    .extensions()
                    .get::<ConnectInfo<SocketAddr>>()
                    .map(|info| info.0);
                // On the internal listener the direct peer is the caller:
                // a container's `X-Forwarded-For` is never believed.
                let ip = client_ip(request.headers(), peer, auth.trust_proxy && !internal);
                if let Some(retry_after) = auth.failures.hit(&ip) {
                    tracing::warn!(%ip, "too many failed token attempts");
                    return too_many_requests(retry_after);
                }
            }
            return (
                StatusCode::UNAUTHORIZED,
                [(header::WWW_AUTHENTICATE, auth.challenge(request.headers()))],
                "missing or invalid bearer token\n",
            )
                .into_response();
        }
    };

    if let Some(retry_after) = auth.requests.hit(&agent) {
        return too_many_requests(retry_after);
    }

    let mut client = request
        .headers()
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .chars()
        .take(120)
        .collect::<String>();
    // The agents panel tells a terminal's CLI from a run by this.
    if terminal {
        client = format!("lore terminal · {client}")
            .chars()
            .take(120)
            .collect();
    }
    let db = auth.db.clone();
    let name = agent.clone();
    tokio::task::spawn_blocking(move || {
        if let Err(error) = db.touch_agent(&name, &client) {
            tracing::warn!(%error, "recording agent activity failed");
        }
    });

    request.extensions_mut().insert(Agent(agent));
    // A run token's scope travels with the request to the tools, which
    // check every provider call against it.
    if let Some(scope) = scope {
        request.extensions_mut().insert(scope);
    }
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

    #[tokio::test]
    async fn env_tokens_are_checked_before_oauth_tokens() {
        let dir = std::env::temp_dir().join(format!("lore-auth-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let db = Db::open(&dir.join("lore.db")).unwrap();
        // An env token shaped exactly like an OAuth token, and an OAuth
        // access token with the same value for another agent.
        let secret = crate::oauth::random_token().unwrap();
        let auth = McpAuth::new(
            load_tokens("", &format!("claude:{secret}")).unwrap(),
            db.clone(),
            false,
        );
        db.register_oauth_client(&crate::db::OAuthClient {
            client_id: "c".into(),
            client_name: String::new(),
            redirect_uris: vec!["http://127.0.0.1:9/cb".into()],
        })
        .unwrap();
        let grant = db
            .approve(&crate::db::Approval {
                agent: "cursor".into(),
                new_agent: true,
                avatar: String::new(),
                client_id: "c".into(),
                client_name: String::new(),
                redirect_uri: "http://127.0.0.1:9/cb".into(),
                authorized_by: "admin".into(),
                reserved: vec![],
                services_off: false,
                code_hash: "h".into(),
                code_challenge: "c".repeat(43),
                code_expires_at: crate::db::unix_now() + 300,
            })
            .unwrap();
        let now = crate::db::unix_now();
        db.issue_tokens(
            grant,
            &crate::oauth::token_hash(&secret),
            now + 60,
            "r",
            now + 60,
        )
        .unwrap();
        assert_eq!(
            auth.authenticate(&secret).await,
            Ok(Authenticated::Env("claude".into()))
        );
        assert_eq!(auth.authenticate("").await, Err(Refused::Invalid));
        assert_eq!(auth.authenticate("nope").await, Err(Refused::Invalid));
        // Without OAuth mounted the challenge stays plain.
        assert_eq!(auth.challenge(&HeaderMap::new()), "Bearer");
        db.set_agent_disabled("claude", true, "admin").unwrap();
        assert_eq!(
            auth.authenticate(&secret).await,
            Err(Refused::Disabled {
                agent: "claude".into(),
                env: true
            })
        );
    }

    #[test]
    fn forwarded_addresses_are_believed_only_from_trusted_peers() {
        let peer = |ip: &str| Some(SocketAddr::new(ip.parse().unwrap(), 4000));
        let agents = vec![Cidr::parse("172.31.250.0/28").unwrap()];
        let listed = ProxyTrust::Listed {
            trusted: parse_trusted_proxies("10.0.1.0/24, 127.0.0.1").unwrap(),
            hosts: None,
            never: agents.clone(),
        };
        assert!(peer_may_forward(&listed, peer("10.0.1.7")));
        assert!(peer_may_forward(&listed, peer("127.0.0.1")));
        assert!(!peer_may_forward(&listed, peer("10.0.2.7")));
        assert!(!peer_may_forward(&listed, peer("172.31.250.9")));
        let private = ProxyTrust::Private { never: agents };
        assert!(peer_may_forward(&private, peer("10.0.1.7")));
        assert!(peer_may_forward(&private, peer("::ffff:192.168.1.2")));
        assert!(!peer_may_forward(&private, peer("172.31.250.9")));
        assert!(!peer_may_forward(&private, peer("203.0.113.5")));
        assert!(peer_may_forward(&ProxyTrust::Any, peer("203.0.113.5")));
        assert!(parse_trusted_proxies("10.0.0.0/33").is_err());
        assert!(parse_trusted_proxies("lore").is_err());
        assert!(
            Cidr::parse("fd00::/8")
                .unwrap()
                .contains("fd12::1".parse().unwrap())
        );
    }

    /// `LORE_TRUSTED_PROXY_HOSTS`: the peer is trusted while it is what
    /// the name resolves to now; a new address replaces the old one at
    /// once; an ambiguous answer (an alias) never adds an address; a name
    /// that stops resolving keeps its last address for a while, then loses
    /// it; a name that never resolved trusts nothing; the agent networks
    /// are never trusted, whatever a name says.
    #[tokio::test]
    async fn a_proxy_trusted_by_name_follows_its_address() {
        let ip = |text: &str| -> IpAddr { text.parse().unwrap() };
        let peer = |text: &str| Some(SocketAddr::new(text.parse().unwrap(), 4000));
        let hosts = Arc::new(HostTrust::new(
            parse_trusted_proxy_hosts(" dokploy-traefik, other-proxy ,dokploy-traefik").unwrap(),
        ));
        assert_eq!(hosts.names(), ["dokploy-traefik", "other-proxy"]);
        let trust = ProxyTrust::Listed {
            trusted: Vec::new(),
            hosts: Some(hosts.clone()),
            never: vec![Cidr::parse("172.31.250.0/28").unwrap()],
        };
        // An injected resolver: what each name resolves to.
        let answers: Arc<Mutex<HashMap<String, std::io::Result<Vec<IpAddr>>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let set = |name: &str, answer: std::io::Result<Vec<IpAddr>>| {
            answers.lock().unwrap().insert(name.to_string(), answer);
        };
        let resolve = |name: String| {
            let answers = answers.clone();
            async move {
                match answers.lock().unwrap().get(&name) {
                    Some(Ok(found)) => Ok(found.clone()),
                    Some(Err(error)) => Err(std::io::Error::new(error.kind(), error.to_string())),
                    None => Err(std::io::Error::new(std::io::ErrorKind::NotFound, "unknown")),
                }
            }
        };

        // Nothing resolves at start-up: a warning, and nobody is trusted.
        hosts.refresh_with(resolve).await;
        assert!(hosts.addresses().is_empty());
        assert!(!peer_may_forward(&trust, peer("10.0.1.5")));

        // The proxy comes up.
        set("dokploy-traefik", Ok(vec![ip("10.0.1.5")]));
        hosts.refresh_with(resolve).await;
        assert!(peer_may_forward(&trust, peer("10.0.1.5")));
        assert!(peer_may_forward(&trust, peer("::ffff:10.0.1.5")));
        assert!(!peer_may_forward(&trust, peer("10.0.1.6")));

        // Docker restarts it with a new address: the old one is dropped.
        set("dokploy-traefik", Ok(vec![ip("10.0.1.9")]));
        hosts.refresh_with(resolve).await;
        assert!(peer_may_forward(&trust, peer("10.0.1.9")));
        assert!(!peer_may_forward(&trust, peer("10.0.1.5")));

        // Another container takes the name as a network alias: Docker's DNS
        // answers both. The address trusted already is kept; the alias's is
        // never trusted.
        set("dokploy-traefik", Ok(vec![ip("10.0.1.66"), ip("10.0.1.9")]));
        hosts.refresh_with(resolve).await;
        assert!(peer_may_forward(&trust, peer("10.0.1.9")));
        assert!(!peer_may_forward(&trust, peer("10.0.1.66")));
        // The proxy restarts with a new address while the alias is there:
        // nothing is trusted for the name (fail closed).
        set(
            "dokploy-traefik",
            Ok(vec![ip("10.0.1.20"), ip("10.0.1.66")]),
        );
        hosts.refresh_with(resolve).await;
        assert!(!peer_may_forward(&trust, peer("10.0.1.9")));
        assert!(!peer_may_forward(&trust, peer("10.0.1.20")));
        assert!(!peer_may_forward(&trust, peer("10.0.1.66")));
        assert!(hosts.addresses().is_empty());
        // The alias goes away: the name is clean again.
        set("dokploy-traefik", Ok(vec![ip("10.0.1.9")]));
        hosts.refresh_with(resolve).await;
        assert!(peer_may_forward(&trust, peer("10.0.1.9")));

        // An ambiguous answer at start-up trusts nothing.
        let fresh = HostTrust::new(vec!["dokploy-traefik".into()]);
        fresh.apply(
            "dokploy-traefik",
            Ok(vec![ip("10.0.1.9"), ip("10.0.1.66")]),
            Instant::now(),
        );
        assert!(fresh.addresses().is_empty());
        // One address per family is not ambiguous.
        fresh.apply(
            "dokploy-traefik",
            Ok(vec![ip("10.0.1.9"), ip("fd00::9")]),
            Instant::now(),
        );
        assert_eq!(fresh.addresses(), vec![ip("10.0.1.9"), ip("fd00::9")]);

        // The name stops resolving: the last address is kept a while...
        let start = Instant::now();
        hosts.apply(
            "dokploy-traefik",
            Err(std::io::Error::other("no such host")),
            start,
        );
        assert!(peer_may_forward(&trust, peer("10.0.1.9")));
        // ... an empty answer is a failure too ...
        hosts.apply(
            "dokploy-traefik",
            Ok(Vec::new()),
            start + PROXY_HOSTS_STALE / 2,
        );
        assert!(peer_may_forward(&trust, peer("10.0.1.9")));
        // ... and dropped once the failures last too long (counted from
        // the last success, which was before `start`).
        hosts.apply(
            "dokploy-traefik",
            Err(std::io::Error::other("no such host")),
            start + PROXY_HOSTS_STALE,
        );
        assert!(!peer_may_forward(&trust, peer("10.0.1.9")));
        assert!(hosts.addresses().is_empty());

        // Two names: the union; an agent-network address never counts.
        let now = Instant::now();
        hosts.apply("dokploy-traefik", Ok(vec![ip("10.0.1.9")]), now);
        hosts.apply(
            "other-proxy",
            Ok(vec![ip("172.31.250.3"), ip("fd00::7")]),
            now,
        );
        assert_eq!(
            hosts.addresses(),
            vec![ip("10.0.1.9"), ip("172.31.250.3"), ip("fd00::7")]
        );
        assert!(peer_may_forward(&trust, peer("fd00::7")));
        assert!(!peer_may_forward(&trust, peer("172.31.250.3")));

        // Together with ranges: either one trusts.
        let both = ProxyTrust::Listed {
            trusted: parse_trusted_proxies("127.0.0.1").unwrap(),
            hosts: Some(hosts.clone()),
            never: Vec::new(),
        };
        assert!(peer_may_forward(&both, peer("127.0.0.1")));
        assert!(peer_may_forward(&both, peer("10.0.1.9")));
        assert!(!peer_may_forward(&both, peer("10.0.1.5")));

        assert!(parse_trusted_proxy_hosts("").unwrap().is_empty());
        assert!(parse_trusted_proxy_hosts("10.0.1.0/24").is_err());
        assert!(parse_trusted_proxy_hosts("http://traefik").is_err());
        assert!(parse_trusted_proxy_hosts("-bad").is_err());
    }

    #[test]
    fn forwarded_address_is_used_only_behind_a_proxy() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "9.9.9.9, 1.2.3.4".parse().unwrap());
        let peer = Some("10.0.0.1:5000".parse().unwrap());
        assert_eq!(client_ip(&headers, peer, true), "1.2.3.4");
        assert_eq!(client_ip(&headers, peer, false), "10.0.0.1");
    }

    /// C8 and E5: a run token is accepted only through the internal
    /// listener, and only when its stored scope has the current format.
    #[tokio::test]
    async fn run_tokens_need_the_internal_listener_and_a_current_scope() {
        let dir = std::env::temp_dir().join(format!("lore-auth-run-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let db = Db::open(&dir.join("lore.db")).unwrap();
        db.register_builtin_agents(&[("claude-builtin".into(), "claude".into(), "ember")])
            .unwrap();
        let auth = McpAuth::new(
            load_tokens("", &format!("claude:{}", "x".repeat(32))).unwrap(),
            db.clone(),
            false,
        );
        let mint = |id: &str, scope: &str| {
            let token = crate::runscope::new_token().unwrap();
            db.insert_run(&crate::db::NewRun {
                id: id.into(),
                agent: "claude-builtin".into(),
                kind: "task".into(),
                token_hash: crate::oauth::token_hash(&token),
                token_expires_at: crate::db::unix_now() + 600,
                scope: scope.into(),
                ..Default::default()
            })
            .unwrap();
            token
        };
        let current = mint(
            "run-new",
            &format!(
                r#"{{"version":{},"provider":"github","owner":"me","repo":"shop","readable":["github"]}}"#,
                crate::runscope::SCOPE_VERSION
            ),
        );
        // A scope an older build stored: no version, no read limits.
        let old = mint(
            "run-old",
            r#"{"provider":"github","owner":"me","repo":"shop"}"#,
        );
        assert!(matches!(
            auth.authenticate_on(&current, true).await,
            Ok(Authenticated::Run(scope)) if scope.run_id == "run-new"
        ));
        assert_eq!(
            auth.authenticate_on(&current, false).await,
            Err(Refused::Invalid)
        );
        assert_eq!(auth.authenticate(&current).await, Err(Refused::Invalid));
        assert_eq!(
            auth.authenticate_on(&old, true).await,
            Err(Refused::Invalid)
        );
    }
}
