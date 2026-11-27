//! lore's side of the runner link: the built-in agents' runners dial in
//! to `/runner/ws` on a separate internal listener (`LORE_RUNNER_BIND`,
//! never published), authenticate with their runner secret from
//! `LORE_RUNNER_TOKENS`, and then take commands. The hub keeps one link
//! per agent, routes answers to whoever asked, and records what the
//! runners report (connection, CLI version, sign-in state) in
//! `builtin_agents`. It never stores or logs a credential: a pasted token
//! passes through it to the runner and is dropped. Terminal bytes (part
//! 6d) pass through it between a runner and one admin page, and are never
//! stored or logged either.
//!
//! Without `LORE_RUNNER_TOKENS` there is no hub, no listener and no route:
//! lore behaves as it did before built-in agents existed.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use anyhow::{Result, bail};
use axum::{
    Router,
    extract::{
        ConnectInfo, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use base64::Engine;
use serde::Serialize;
use subtle::ConstantTimeEq;
use tokio::sync::{mpsc, oneshot};

use crate::{
    auth::{RateLimiter, too_many_requests},
    db::{BuiltinStatus, Db},
    runner::{
        AGENT_HEADER,
        protocol::{self, FromRunner, Kind, PROTOCOL_VERSION, Resources, TerminalMode, ToRunner},
    },
};

/// lore pings each runner this often; a runner silent for three pings is
/// taken as gone.
const PING_EVERY: Duration = Duration::from_secs(30);
const SILENCE_LIMIT: Duration = Duration::from_secs(90);

/// Shortest runner secret accepted.
const MIN_SECRET_LEN: usize = 24;

/// Run events waiting for the task runner. Output lines past it are left
/// out (and counted, and said so in one line); a run's start and end
/// always wait for room.
const RUN_EVENTS_QUEUE: usize = 4096;

/// What one runner link may send: frames and bytes per second, with a
/// burst. A runner over either loses its link.
const FRAMES_PER_SECOND: f64 = 500.0;
const FRAMES_BURST: f64 = 5000.0;
const BYTES_PER_SECOND: f64 = 8.0 * 1024.0 * 1024.0;
const BYTES_BURST: f64 = 64.0 * 1024.0 * 1024.0;

/// How long a live link has to answer before a second runner of the same
/// agent may take its place.
const LIVE_PROBE: Duration = Duration::from_secs(3);

/// Terminals one built-in agent may have open at once (its runner keeps
/// the same limit).
pub const MAX_TERMINALS: usize = crate::runner::terminal::MAX_TERMINALS;

/// Output frames waiting for a page that does not read them; a page that
/// falls this far behind loses its terminal.
const TERMINAL_BACKLOG: usize = 1024;

/// A runner secret, the built-in agent it belongs to, and what that agent
/// is: its CLI and provider are fixed here, never taken from the runner.
pub struct RunnerToken {
    pub agent: String,
    pub kind: Kind,
    pub provider: String,
    secret: String,
}

impl RunnerToken {
    /// The secret, for the set of lore's own secrets every provider
    /// response is redacted against. Never logged.
    pub fn secret(&self) -> &str {
        &self.secret
    }
}

impl std::fmt::Debug for RunnerToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RunnerToken")
            .field("agent", &self.agent)
            .field("kind", &self.kind)
            .field("provider", &self.provider)
            .field("secret", &"[redacted]")
            .finish()
    }
}

/// The CLI and provider an agent's name implies: `claude…` is Claude
/// Code with Anthropic, `codex…` Codex with OpenAI, `deepseek…` opencode
/// with DeepSeek.
pub fn kind_of_name(name: &str) -> Option<(Kind, String)> {
    if name.starts_with("claude") {
        Some((Kind::Claude, "anthropic".into()))
    } else if name.starts_with("codex") {
        Some((Kind::Codex, "openai".into()))
    } else if name.starts_with("deepseek") {
        Some((Kind::Opencode, "deepseek".into()))
    } else {
        None
    }
}

/// Reads `LORE_RUNNER_TOKENS`: `agent:secret` entries, comma separated, for
/// example `claude-builtin:<hex>,codex-builtin:<hex>,deepseek-builtin:<hex>`.
/// An entry may name the agent's CLI (and provider) between the two:
/// `agent:kind:secret` or `agent:kind/provider:secret`, which an agent
/// whose name does not start with `claude`, `codex` or `deepseek` must.
/// A runner whose hello claims another CLI or provider is refused.
pub fn parse_runner_tokens(value: &str) -> Result<Vec<RunnerToken>> {
    let mut tokens: Vec<RunnerToken> = Vec::new();
    for pair in value.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        let parts: Vec<&str> = pair.splitn(3, ':').collect();
        let (agent, named, secret) = match parts.as_slice() {
            [agent, secret] => (*agent, None, *secret),
            [agent, kind, secret] => (*agent, Some(*kind), *secret),
            _ => bail!("LORE_RUNNER_TOKENS entries must look like agent:secret"),
        };
        let agent = agent.trim().to_lowercase();
        let plain = !agent.is_empty()
            && agent.len() <= 64
            && agent
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
        if !plain {
            bail!("LORE_RUNNER_TOKENS agent names must be plain names such as claude-builtin");
        }
        if tokens.iter().any(|t| t.agent == agent) {
            bail!("LORE_RUNNER_TOKENS lists the agent \"{agent}\" twice");
        }
        let (kind, provider) = match named {
            Some(named) => {
                let (kind, provider) = match named.trim().split_once('/') {
                    Some((kind, provider)) => (kind, Some(provider)),
                    None => (named.trim(), None),
                };
                let Some(kind) = Kind::parse(kind) else {
                    bail!(
                        "LORE_RUNNER_TOKENS: \"{agent}\" names the CLI \"{kind}\"; use claude, codex \
                         or opencode"
                    );
                };
                let provider = provider
                    .map(|p| p.trim().to_lowercase())
                    .filter(|p| !p.is_empty())
                    .unwrap_or_else(|| crate::runner::default_provider(kind).to_string());
                if !provider
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
                {
                    bail!("LORE_RUNNER_TOKENS: the provider of \"{agent}\" must be a plain id");
                }
                (kind, provider)
            }
            None => kind_of_name(&agent).ok_or_else(|| {
                anyhow::anyhow!(
                    "LORE_RUNNER_TOKENS: say which CLI \"{agent}\" runs, as \
                     {agent}:claude:<secret>, {agent}:codex:<secret> or \
                     {agent}:opencode/<provider>:<secret>"
                )
            })?,
        };
        let secret = secret.trim().to_string();
        if secret.len() < MIN_SECRET_LEN {
            bail!(
                "the runner secret for \"{agent}\" is shorter than {MIN_SECRET_LEN} characters \
                 (openssl rand -hex 32)"
            );
        }
        tokens.push(RunnerToken {
            agent,
            kind,
            provider,
            secret,
        });
    }
    Ok(tokens)
}

/// `LORE_RUNNER_BIND`: one address, or several, comma separated (one per
/// agent network, so the runner listener is on those networks only).
pub fn parse_runner_binds(value: &str) -> Result<Vec<SocketAddr>> {
    let binds = value
        .split(',')
        .map(str::trim)
        .filter(|bind| !bind.is_empty())
        .map(|bind| {
            bind.parse::<SocketAddr>().map_err(|_| {
                anyhow::anyhow!(
                    "LORE_RUNNER_BIND must be addresses like 172.30.1.2:8081, comma separated"
                )
            })
        })
        .collect::<Result<Vec<_>>>()?;
    if binds.is_empty() {
        bail!("LORE_RUNNER_BIND is empty");
    }
    Ok(binds)
}

/// The sign-in hosts each CLI's interactive sign-in may send the owner
/// to, from the CLIs' documentation.
pub fn sign_in_hosts(kind: Kind) -> &'static [&'static str] {
    match kind {
        Kind::Claude => &[
            "claude.ai",
            "claude.com",
            "console.anthropic.com",
            "platform.claude.com",
        ],
        Kind::Codex => &["auth.openai.com", "chatgpt.com"],
        Kind::Opencode => &[],
    }
}

/// A sign-in link a runner reported, checked: it parses, is `https`, has
/// no user name or password and no unusual port, and its host is one the
/// agent's CLI signs in at. Answers the link and its host, for the page
/// to show apart.
#[cfg(test)]
pub fn checked_sign_in_url(kind: Kind, url: &str) -> Option<(String, String)> {
    let hosts: Vec<String> = sign_in_hosts(kind).iter().map(|h| h.to_string()).collect();
    checked_sign_in_url_in(&hosts, url)
}

/// The sign-in hosts of each CLI: the built-in list, or the owner's own
/// from `LORE_SIGN_IN_HOSTS_CLAUDE` / `LORE_SIGN_IN_HOSTS_CODEX` /
/// `LORE_SIGN_IN_HOSTS_OPENCODE` (host names, comma separated), which
/// replaces it when a CLI moves its sign-in.
pub fn sign_in_hosts_from_env(kind: Kind) -> Result<Vec<String>> {
    let name = format!("LORE_SIGN_IN_HOSTS_{}", kind.id().to_ascii_uppercase());
    let value = std::env::var(&name).unwrap_or_default();
    if value.trim().is_empty() {
        return Ok(sign_in_hosts(kind).iter().map(|h| h.to_string()).collect());
    }
    value
        .split(',')
        .map(|host| host.trim().trim_end_matches('.').to_ascii_lowercase())
        .filter(|host| !host.is_empty())
        .map(|host| {
            let plain = host.contains('.')
                && host
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.'));
            if plain {
                Ok(host)
            } else {
                bail!("{name} must be host names such as claude.ai, comma separated")
            }
        })
        .collect()
}

/// [`checked_sign_in_url`] against a given host list.
pub fn checked_sign_in_url_in(hosts: &[String], url: &str) -> Option<(String, String)> {
    let parsed = reqwest::Url::parse(url.trim()).ok()?;
    if parsed.scheme() != "https"
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.port().is_some()
    {
        return None;
    }
    let host = parsed.host_str()?.to_ascii_lowercase();
    hosts.contains(&host).then(|| (parsed.to_string(), host))
}

/// What a runner said about a sign-in, with every link that is not at one
/// of `hosts` replaced: a refused link is never shown, not even as text.
pub fn hide_other_links(text: &str, hosts: &[String]) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find("http") {
        let (before, from) = rest.split_at(at);
        out.push_str(before);
        let end = from
            .find(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '<' | '>'))
            .unwrap_or(from.len());
        let (word, after) = from.split_at(end);
        let link = word.starts_with("http://") || word.starts_with("https://");
        if link && checked_sign_in_url_in(hosts, word).is_none() {
            out.push_str("[a link to another host, not shown]");
        } else {
            out.push_str(word);
        }
        rest = after;
    }
    out.push_str(rest);
    out
}

/// lore's public listener without the agent networks: a connection
/// accepted on one of lore's agent-network addresses (where the runner
/// listener lives) is closed at once, so an agent container never reaches
/// the admin page, the sign-in or OAuth, whatever it sends. Runs reach lore
/// on the runner listener only (`/mcp`, `/git`, `/runner/ws`).
pub struct PublicListener {
    inner: tokio::net::TcpListener,
    refused: Vec<std::net::IpAddr>,
}

impl PublicListener {
    pub fn new(inner: tokio::net::TcpListener, refused: Vec<std::net::IpAddr>) -> Self {
        Self { inner, refused }
    }

    /// Whether a connection accepted on `local` is refused.
    pub fn refuses(&self, local: SocketAddr) -> bool {
        let ip = match local.ip() {
            std::net::IpAddr::V6(v6) => {
                v6.to_ipv4_mapped().map_or(local.ip(), std::net::IpAddr::V4)
            }
            v4 => v4,
        };
        self.refused.contains(&ip)
    }
}

impl axum::serve::Listener for PublicListener {
    type Io = tokio::net::TcpStream;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let (io, peer) = axum::serve::Listener::accept(&mut self.inner).await;
            match io.local_addr() {
                Ok(local) if self.refuses(local) => {
                    tracing::debug!(%peer, "a connection from an agent network to the public listener was closed");
                    drop(io);
                }
                _ => return (io, peer),
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        self.inner.local_addr()
    }
}

/// The networks lore's runner listener addresses are on, from the
/// container's routing table (`/proc/net/route`): what lore must never
/// take an `X-Forwarded-For` from. An address with no matching route
/// stands for itself.
pub fn agent_networks(addresses: &[std::net::IpAddr]) -> Vec<crate::auth::Cidr> {
    let table = std::fs::read_to_string("/proc/net/route").unwrap_or_default();
    agent_networks_in(&table, addresses)
}

fn agent_networks_in(table: &str, addresses: &[std::net::IpAddr]) -> Vec<crate::auth::Cidr> {
    let routes: Vec<(u32, u32)> = table
        .lines()
        .skip(1)
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let destination = u32::from_str_radix(fields.get(1)?, 16).ok()?;
            let gateway = u32::from_str_radix(fields.get(2)?, 16).ok()?;
            let mask = u32::from_str_radix(fields.get(7)?, 16).ok()?;
            // The kernel writes the bytes in network order read as a
            // little-endian number.
            (gateway == 0 && mask != 0).then(|| (destination.swap_bytes(), mask.swap_bytes()))
        })
        .collect();
    addresses
        .iter()
        .map(|address| {
            let std::net::IpAddr::V4(v4) = address else {
                return crate::auth::Cidr::new(*address, 128);
            };
            let ip = u32::from(*v4);
            routes
                .iter()
                .filter(|(destination, mask)| ip & mask == *destination)
                .max_by_key(|(_, mask)| mask.count_ones())
                .map(|(destination, mask)| {
                    crate::auth::Cidr::new(
                        std::net::IpAddr::V4((*destination).into()),
                        mask.count_ones() as u8,
                    )
                })
                .unwrap_or_else(|| crate::auth::Cidr::new(*address, 32))
        })
        .collect()
}

/// Removes the proxy headers from a request on the runner listener: it is
/// reached straight from the agent networks, never through a proxy, so the
/// direct peer is always the caller.
pub async fn strip_forwarded(
    mut request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    for name in [
        "x-forwarded-for",
        "x-forwarded-host",
        "x-forwarded-proto",
        "forwarded",
        "x-real-ip",
    ] {
        request.headers_mut().remove(name);
    }
    next.run(request).await
}

/// The line that says how many output lines of a run were left out.
fn dropped_line(agent: &str, run_id: &str, count: u64, first: u64) -> HubEvent {
    HubEvent::Run {
        agent: agent.to_string(),
        message: FromRunner::RunOutput {
            run_id: run_id.to_string(),
            // The first left-out line's number, which nothing else has.
            seq: first,
            stream: "lore".into(),
            line: format!(
                "{count} output line(s) were left out here: they came faster than lore could \
                 store them"
            ),
        },
    }
}

/// A second runner that tried to connect for an agent whose link was live.
#[derive(Debug, Clone, Serialize)]
pub struct Intrusion {
    pub at: String,
    pub address: String,
    pub count: u64,
}

/// A token bucket for one link's frames or bytes.
struct Bucket {
    level: f64,
    rate: f64,
    burst: f64,
    at: tokio::time::Instant,
}

impl Bucket {
    fn new(rate: f64, burst: f64) -> Self {
        Self {
            level: burst,
            rate,
            burst,
            at: tokio::time::Instant::now(),
        }
    }

    /// Takes `amount`; false when the bucket is empty.
    fn take(&mut self, amount: f64) -> bool {
        let now = tokio::time::Instant::now();
        self.level =
            (self.level + now.duration_since(self.at).as_secs_f64() * self.rate).min(self.burst);
        self.at = now;
        self.level -= amount;
        self.level >= 0.0
    }
}

/// The kind a built-in agent's name suggests before its runner first
/// says, and the avatar it starts with.
pub fn kind_and_avatar(name: &str) -> (&'static str, &'static str) {
    if name.starts_with("claude") {
        ("claude", "ember")
    } else if name.starts_with("codex") {
        ("codex", "prism")
    } else if name.starts_with("deepseek") {
        ("opencode", "wave")
    } else {
        ("", crate::avatars::default_for(name))
    }
}

/// Why a command did not get an answer.
#[derive(Debug)]
pub enum HubError {
    /// The agent's runner is not connected.
    NotConnected,
    /// The runner did not answer in time.
    Timeout,
    /// The link closed before the answer came.
    Closed,
    /// The agent already has as many terminals open as it may.
    TooManyTerminals,
}

impl std::fmt::Display for HubError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            HubError::NotConnected => {
                "the agent's container is not connected to lore; start it \
                 (docker compose -f docker-compose.agents.yml up -d) and check its log"
            }
            HubError::Timeout => "the agent's container did not answer in time",
            HubError::Closed => "the link to the agent's container closed",
            HubError::TooManyTerminals => {
                "this agent already has two terminals open; close one first"
            }
        })
    }
}

/// An interactive sign-in as the page shows it. The URL and the code are
/// what the owner needs to finish it; neither is a lasting credential, and
/// both live only in memory.
#[derive(Debug, Clone, Serialize)]
pub struct LoginState {
    #[serde(skip)]
    pub id: u64,
    pub method: String,
    /// `starting`, `waiting`, `done` or `failed`.
    pub state: String,
    pub url: Option<String>,
    /// The sign-in link's host, which the page shows apart from the link.
    pub url_host: Option<String>,
    pub code: Option<String>,
    pub needs_code: bool,
    pub message: String,
}

/// The models a runner last reported.
#[derive(Debug, Clone, Serialize)]
pub struct ModelList {
    pub models: Vec<String>,
    pub source: String,
}

/// What a terminal's page hears from the runner.
#[derive(Debug, PartialEq, Eq)]
pub enum TerminalEvent {
    Output(Vec<u8>),
    Exit {
        code: Option<i32>,
        message: Option<String>,
    },
}

/// An open terminal: the agent it runs in and the page that shows it, and
/// for the CLI's interface the hash of its lore token (see
/// `terminal_token_agent`). Forgetting the terminal revokes the token.
struct Terminal {
    agent: String,
    tx: mpsc::Sender<TerminalEvent>,
    token_hash: Option<String>,
}

/// A connected runner, and the address it connected from (the agent's
/// container on its own network).
struct Link {
    generation: u64,
    tx: mpsc::Sender<ToRunner>,
    kind: Kind,
    provider: String,
    address: Option<std::net::IpAddr>,
}

/// The prefix of a terminal's lore token: 32 random bytes as 64 hex
/// characters follow.
pub const TERMINAL_TOKEN_PREFIX: &str = "lore_term_";

/// A new terminal token.
fn new_terminal_token() -> Result<String, getrandom::Error> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes)?;
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    Ok(format!("{TERMINAL_TOKEN_PREFIX}{hex}"))
}

/// Whether a bearer value has the shape of a terminal token.
pub fn looks_like_terminal_token(value: &str) -> bool {
    value
        .strip_prefix(TERMINAL_TOKEN_PREFIX)
        .is_some_and(|hex| {
            hex.len() == 64
                && hex
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
}

/// An address as one listener reports it: an IPv4-mapped IPv6 address is
/// the IPv4 address.
fn plain_ip(ip: std::net::IpAddr) -> std::net::IpAddr {
    match ip {
        std::net::IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map_or(std::net::IpAddr::V6(v6), std::net::IpAddr::V4),
        v4 => v4,
    }
}

#[derive(Default)]
struct Inner {
    links: HashMap<String, Link>,
    pending: HashMap<u64, (String, oneshot::Sender<FromRunner>)>,
    logins: HashMap<String, LoginState>,
    models: HashMap<String, ModelList>,
    resources: HashMap<String, Resources>,
    terminals: HashMap<String, Terminal>,
    intrusions: HashMap<String, Intrusion>,
    /// Output lines left out per run (the queue was full): how many, and
    /// the first one's sequence number, which the summary line takes.
    dropped: HashMap<String, (u64, u64)>,
}

/// What the hub hands the task runner: what a runner said about a run,
/// and that a runner's link closed.
#[derive(Debug)]
pub enum HubEvent {
    /// `run_started`, `run_output`, `run_exit`, or an `unsupported`
    /// answer to `run_start`.
    Run { agent: String, message: FromRunner },
    /// The agent's runner disconnected: its run, if any, is gone.
    Disconnected { agent: String },
}

/// Every built-in agent's runner link.
pub struct Hub {
    db: Db,
    tokens: Vec<RunnerToken>,
    /// Where each CLI signs in (`LORE_SIGN_IN_HOSTS_*` or the built-in
    /// lists).
    sign_in_hosts: Vec<(Kind, Vec<String>)>,
    inner: Mutex<Inner>,
    next_id: AtomicU64,
    /// Wrong runner secrets, by address: ten in fifteen minutes lock it out.
    failures: RateLimiter,
    /// Run events for the task runner, which takes the receiver once.
    /// Bounded: a runner that floods it loses its link.
    run_tx: mpsc::Sender<HubEvent>,
    run_rx: Mutex<Option<mpsc::Receiver<HubEvent>>>,
    /// lore's MCP endpoint as the agents reach it, for the terminals'
    /// CLIs (`with_mcp_url`); without it a terminal gets no MCP server.
    mcp_url: Option<String>,
}

impl Hub {
    pub fn new(db: Db, tokens: Vec<RunnerToken>) -> Self {
        let (run_tx, run_rx) = mpsc::channel(RUN_EVENTS_QUEUE);
        let sign_in_hosts = [Kind::Claude, Kind::Codex, Kind::Opencode]
            .into_iter()
            .map(|kind| {
                let hosts = sign_in_hosts_from_env(kind).unwrap_or_else(|error| {
                    tracing::warn!(%error, "using the built-in sign-in hosts");
                    sign_in_hosts(kind).iter().map(|h| h.to_string()).collect()
                });
                (kind, hosts)
            })
            .collect();
        Self {
            db,
            tokens,
            sign_in_hosts,
            inner: Mutex::default(),
            next_id: AtomicU64::new(1),
            failures: RateLimiter::new(10, Duration::from_secs(15 * 60)),
            run_tx,
            run_rx: Mutex::new(Some(run_rx)),
            mcp_url: None,
        }
    }

    /// Gives the terminals' CLIs lore's MCP server at `url` (lore's
    /// internal address, `LORE_RUNNER_LORE_URL` + `/mcp`).
    pub fn with_mcp_url(mut self, url: String) -> Self {
        self.mcp_url = Some(url);
        self
    }

    /// The run events, for the one task runner that listens.
    pub fn take_events(&self) -> Option<mpsc::Receiver<HubEvent>> {
        self.run_rx.lock().unwrap_or_else(|e| e.into_inner()).take()
    }

    /// Sends a command that has no answer (a run's start or stop).
    pub async fn send(&self, agent: &str, command: ToRunner) -> Result<(), HubError> {
        let tx = {
            let inner = self.inner();
            let Some(link) = inner.links.get(agent) else {
                return Err(HubError::NotConnected);
            };
            link.tx.clone()
        };
        tx.send(command).await.map_err(|_| HubError::Closed)
    }

    fn inner(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn next_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::SeqCst)
    }

    /// The built-in agents, in the order `LORE_RUNNER_TOKENS` lists them.
    pub fn agents(&self) -> Vec<String> {
        self.tokens.iter().map(|t| t.agent.clone()).collect()
    }

    pub fn is_builtin(&self, name: &str) -> bool {
        self.tokens.iter().any(|t| t.agent == name)
    }

    /// The kind and provider of a connected runner.
    pub fn link(&self, name: &str) -> Option<(Kind, String)> {
        self.inner()
            .links
            .get(name)
            .map(|link| (link.kind, link.provider.clone()))
    }

    pub fn login_state(&self, name: &str) -> Option<LoginState> {
        self.inner().logins.get(name).cloned()
    }

    pub fn clear_login(&self, name: &str) {
        self.inner().logins.remove(name);
    }

    pub fn models(&self, name: &str) -> Option<ModelList> {
        self.inner().models.get(name).cloned()
    }

    pub fn resources(&self, name: &str) -> Option<Resources> {
        self.inner().resources.get(name).cloned()
    }

    /// The last time a second runner tried to connect for this agent.
    pub fn intrusion(&self, name: &str) -> Option<Intrusion> {
        self.inner().intrusions.get(name).cloned()
    }

    fn token(&self, agent: &str) -> Option<&RunnerToken> {
        self.tokens.iter().find(|token| token.agent == agent)
    }

    /// Where the agent's CLI signs in.
    fn hosts_of(&self, agent: &str) -> Vec<String> {
        let Some(kind) = self.token(agent).map(|token| token.kind) else {
            return Vec::new();
        };
        self.sign_in_hosts
            .iter()
            .find(|(k, _)| *k == kind)
            .map(|(_, hosts)| hosts.clone())
            .unwrap_or_default()
    }

    /// Whether `presented` is the runner secret of `agent`. Every stored
    /// secret is compared, in constant time, whatever the agent.
    fn check_secret(&self, agent: &str, presented: &str) -> bool {
        let mut matched = false;
        for token in &self.tokens {
            let equal: bool = token.secret.as_bytes().ct_eq(presented.as_bytes()).into();
            matched |= equal && token.agent == agent;
        }
        matched
    }

    /// Sends a command built around a fresh id and waits for its answer.
    pub async fn request(
        &self,
        agent: &str,
        make: impl FnOnce(u64) -> ToRunner,
        wait: Duration,
    ) -> Result<FromRunner, HubError> {
        let id = self.next_id();
        let (answer_tx, answer_rx) = oneshot::channel();
        let tx = {
            let mut inner = self.inner();
            let Some(link) = inner.links.get(agent) else {
                return Err(HubError::NotConnected);
            };
            let tx = link.tx.clone();
            inner.pending.insert(id, (agent.to_string(), answer_tx));
            tx
        };
        if tx.send(make(id)).await.is_err() {
            self.inner().pending.remove(&id);
            return Err(HubError::Closed);
        }
        match tokio::time::timeout(wait, answer_rx).await {
            Ok(Ok(answer)) => Ok(answer),
            Ok(Err(_)) => Err(HubError::Closed),
            Err(_) => {
                self.inner().pending.remove(&id);
                Err(HubError::Timeout)
            }
        }
    }

    /// Opens a terminal in an agent's container for one page: answers the
    /// terminal's id and where its output and its end arrive. The channel
    /// closes without an `Exit` when the agent's container disconnects.
    pub async fn terminal_open(
        &self,
        agent: &str,
        mode: TerminalMode,
        cols: u16,
        rows: u16,
        model: Option<String>,
    ) -> Result<(String, mpsc::Receiver<TerminalEvent>), HubError> {
        let term_id = format!("t{}", self.next_id());
        let (tx, rx) = mpsc::channel(TERMINAL_BACKLOG);
        let link = {
            let mut inner = self.inner();
            let Some(link) = inner.links.get(agent) else {
                return Err(HubError::NotConnected);
            };
            let link = link.tx.clone();
            let open = inner
                .terminals
                .values()
                .filter(|terminal| terminal.agent == agent)
                .count();
            if open >= MAX_TERMINALS {
                return Err(HubError::TooManyTerminals);
            }
            // The CLI's interface gets lore's MCP server with a token of
            // its own; a shell does not.
            let token = match (mode, &self.mcp_url) {
                (TerminalMode::Cli, Some(url)) => match new_terminal_token() {
                    Ok(token) => Some((url.clone(), token)),
                    Err(error) => {
                        tracing::error!(%error, "no randomness for a terminal token");
                        None
                    }
                },
                _ => None,
            };
            inner.terminals.insert(
                term_id.clone(),
                Terminal {
                    agent: agent.to_string(),
                    tx,
                    token_hash: token
                        .as_ref()
                        .map(|(_, token)| crate::oauth::token_hash(token)),
                },
            );
            (link, token)
        };
        let (link, token) = link;
        let open = ToRunner::TerminalOpen {
            term_id: term_id.clone(),
            mode,
            cols,
            rows,
            model,
            mcp: token.map(|(url, token)| protocol::TerminalMcp {
                url,
                token: protocol::Secret::new(token),
            }),
        };
        if link.send(open).await.is_err() {
            self.inner().terminals.remove(&term_id);
            return Err(HubError::Closed);
        }
        Ok((term_id, rx))
    }

    /// Sends a terminal command (input, resize) to the runner of the agent
    /// the terminal runs in.
    pub async fn terminal_send(&self, term_id: &str, command: ToRunner) -> Result<(), HubError> {
        let link = {
            let inner = self.inner();
            let Some(terminal) = inner.terminals.get(term_id) else {
                return Err(HubError::Closed);
            };
            let Some(link) = inner.links.get(&terminal.agent) else {
                return Err(HubError::NotConnected);
            };
            link.tx.clone()
        };
        link.send(command).await.map_err(|_| HubError::Closed)
    }

    /// The page went: the terminal is forgotten and its runner told to
    /// close it.
    pub async fn terminal_close(&self, term_id: &str) {
        let link = {
            let mut inner = self.inner();
            let Some(terminal) = inner.terminals.remove(term_id) else {
                return;
            };
            inner.links.get(&terminal.agent).map(|link| link.tx.clone())
        };
        if let Some(link) = link {
            let _ = link
                .send(ToRunner::TerminalClose {
                    term_id: term_id.to_string(),
                })
                .await;
        }
    }

    /// How many terminals are open, in every agent.
    #[cfg(test)]
    pub fn terminal_count(&self) -> usize {
        self.inner().terminals.len()
    }

    /// The built-in agent a terminal token speaks for: the token belongs
    /// to a terminal open right now, and the request comes from the
    /// address that agent's runner is connected from (its container). A
    /// closed terminal, a dropped link or another address: none.
    pub fn terminal_token_agent(&self, presented: &str, peer: std::net::IpAddr) -> Option<String> {
        if !looks_like_terminal_token(presented) {
            return None;
        }
        let hash = crate::oauth::token_hash(presented);
        let inner = self.inner();
        let terminal = inner
            .terminals
            .values()
            .find(|terminal| terminal.token_hash.as_deref() == Some(hash.as_str()))?;
        let link = inner.links.get(&terminal.agent)?;
        (link.address == Some(plain_ip(peer))).then(|| terminal.agent.clone())
    }

    /// Terminal bytes from a runner, for the page that shows them. Only
    /// the runner the terminal was opened in may write to it.
    fn on_terminal_output(&self, agent: &str, term_id: &str, data: &str) {
        let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(data.as_bytes()) else {
            return;
        };
        let mut inner = self.inner();
        let Some(terminal) = inner.terminals.get(term_id) else {
            return;
        };
        if terminal.agent != agent {
            return;
        }
        if terminal.tx.try_send(TerminalEvent::Output(bytes)).is_err() {
            // The page does not keep up (or went): it loses the terminal
            // rather than holding up the agent's whole link.
            inner.terminals.remove(term_id);
            let link = inner.links.get(agent).map(|link| link.tx.clone());
            drop(inner);
            tracing::warn!(%agent, %term_id, "a terminal's page fell behind; closing it");
            if let Some(link) = link {
                let _ = link.try_send(ToRunner::TerminalClose {
                    term_id: term_id.to_string(),
                });
            }
        }
    }

    fn on_terminal_exit(
        &self,
        agent: &str,
        term_id: &str,
        code: Option<i32>,
        message: Option<String>,
    ) {
        let mut inner = self.inner();
        if inner
            .terminals
            .get(term_id)
            .is_some_and(|terminal| terminal.agent == agent)
            && let Some(terminal) = inner.terminals.remove(term_id)
        {
            let _ = terminal.tx.try_send(TerminalEvent::Exit { code, message });
        }
    }

    /// Notes a sign-in the page started, before its prompt arrives.
    pub fn login_started(&self, agent: &str, id: u64, method: &str) {
        self.inner().logins.insert(
            agent.to_string(),
            LoginState {
                id,
                method: method.to_string(),
                state: "starting".into(),
                url: None,
                url_host: None,
                code: None,
                needs_code: false,
                message: String::new(),
            },
        );
    }

    /// Notes a sign-in that failed before its prompt.
    pub fn login_failed(&self, agent: &str, id: u64, message: &str) {
        if let Some(login) = self.inner().logins.get_mut(agent)
            && login.id == id
        {
            login.state = "failed".into();
            login.message = message.to_string();
        }
    }

    /// Hands a run's start, end or refusal to the task runner: never left
    /// out, it waits for room when the queue is full (without holding up
    /// the link).
    fn run_event(&self, agent: &str, message: &FromRunner) {
        let mut events = Vec::new();
        // A run's end comes after the line saying what was left out.
        if let FromRunner::RunExit { run_id, .. } = message
            && let Some((count, first)) = self.inner().dropped.remove(run_id)
        {
            events.push(dropped_line(agent, run_id, count, first));
        }
        events.push(HubEvent::Run {
            agent: agent.to_string(),
            message: message.clone(),
        });
        let mut events = events.into_iter();
        while let Some(event) = events.next() {
            if let Err(mpsc::error::TrySendError::Full(event)) = self.run_tx.try_send(event) {
                let rest: Vec<HubEvent> = std::iter::once(event).chain(events).collect();
                let tx = self.run_tx.clone();
                tokio::spawn(async move {
                    for event in rest {
                        let _ = tx.send(event).await;
                    }
                });
                return;
            }
        }
    }

    /// One output line for the task runner. When the queue is full the line
    /// is left out and counted rather than the link closed (a legitimate
    /// run may print fast); once there is room again, one line says how
    /// many were left out.
    fn run_line(&self, agent: &str, run_id: &str, seq: u64, stream: &str, line: &str) {
        self.say_dropped(agent, run_id);
        if self.inner().dropped.contains_key(run_id) {
            self.note_dropped(run_id, seq);
            return;
        }
        let event = HubEvent::Run {
            agent: agent.to_string(),
            message: FromRunner::RunOutput {
                run_id: run_id.to_string(),
                seq,
                stream: stream.to_string(),
                line: line.to_string(),
            },
        };
        if self.run_tx.try_send(event).is_err() {
            self.note_dropped(run_id, seq);
        }
    }

    fn note_dropped(&self, run_id: &str, seq: u64) {
        let mut inner = self.inner();
        let entry = inner.dropped.entry(run_id.to_string()).or_insert((0, seq));
        entry.0 += 1;
    }

    /// Sends the "lines were left out" line for a run when there is room.
    fn say_dropped(&self, agent: &str, run_id: &str) {
        let Some((count, first)) = self.inner().dropped.get(run_id).copied() else {
            return;
        };
        if self
            .run_tx
            .try_send(dropped_line(agent, run_id, count, first))
            .is_ok()
        {
            self.inner().dropped.remove(run_id);
        }
    }

    /// What a runner said: answers go to whoever asked; reports update the
    /// stored state.
    fn on_message(&self, agent: &str, message: FromRunner) {
        match &message {
            FromRunner::Status {
                signed_in,
                method,
                login_ends,
                cli_version,
                detail,
                ..
            } => {
                let status = BuiltinStatus {
                    signed_in: *signed_in,
                    login_method: method.clone().unwrap_or_default(),
                    login_ends: login_ends.clone(),
                    detail: detail.chars().take(400).collect(),
                    cli_version: cli_version.clone(),
                };
                if let Err(error) = self.db.builtin_status(agent, &status) {
                    tracing::warn!(%agent, %error, "recording a runner's status failed");
                }
            }
            FromRunner::LoginPrompt {
                id,
                url,
                code,
                needs_code,
                message: said,
            } => {
                // Only a link to where the agent's CLI signs in is shown,
                // and a refused one appears nowhere, not even in the text.
                let hosts = self.hosts_of(agent);
                let checked = url
                    .as_deref()
                    .and_then(|url| checked_sign_in_url_in(&hosts, url));
                if url.is_some() && checked.is_none() {
                    tracing::warn!(%agent, "a sign-in link to an unexpected place was refused");
                }
                let said = hide_other_links(said, &hosts);
                if let Some(login) = self.inner().logins.get_mut(agent)
                    && login.id == *id
                {
                    login.state = "waiting".into();
                    login.message = said.clone();
                    if url.is_some() && checked.is_none() {
                        login.message = format!(
                            "The runner reported a sign-in link that is not at a host this CLI \
                             signs in at, so it is not shown (the owner may list the CLI's \
                             sign-in hosts in LORE_SIGN_IN_HOSTS_{}).\n{said}",
                            self.token(agent)
                                .map(|token| token.kind.id().to_ascii_uppercase())
                                .unwrap_or_default()
                        );
                    }
                    (login.url, login.url_host) = checked.unzip();
                    login.code = code.clone();
                    login.needs_code = *needs_code;
                }
            }
            FromRunner::LoginDone {
                id,
                ok,
                message: said,
            } => {
                if let Some(login) = self.inner().logins.get_mut(agent)
                    && login.id == *id
                {
                    login.state = if *ok { "done" } else { "failed" }.into();
                    login.url = None;
                    login.url_host = None;
                    login.code = None;
                    login.needs_code = false;
                    login.message = hide_other_links(said, &self.hosts_of(agent));
                }
                tracing::info!(%agent, ok, "an interactive sign-in ended");
            }
            FromRunner::Models { models, source, .. } => {
                self.inner().models.insert(
                    agent.to_string(),
                    ModelList {
                        models: models.iter().take(200).cloned().collect(),
                        source: source.clone(),
                    },
                );
            }
            FromRunner::Resources(reading) => {
                self.inner()
                    .resources
                    .insert(agent.to_string(), reading.clone());
            }
            FromRunner::Unsupported { command, .. } => {
                tracing::warn!(%agent, %command, "the runner does not support a command");
                if command == "run_start" {
                    self.run_event(agent, &message);
                }
            }
            FromRunner::RunStarted { .. } | FromRunner::RunExit { .. } => {
                self.run_event(agent, &message);
            }
            FromRunner::RunOutput {
                run_id,
                seq,
                stream,
                line,
            } => self.run_line(agent, run_id, *seq, stream, line),
            FromRunner::RunOutputs { run_id, lines } => {
                for line in lines {
                    self.run_line(agent, run_id, line.seq, &line.stream, &line.line);
                }
            }
            FromRunner::TerminalOutput { term_id, data } => {
                self.on_terminal_output(agent, term_id, data);
            }
            FromRunner::TerminalExit {
                term_id,
                code,
                message: said,
            } => self.on_terminal_exit(agent, term_id, *code, said.clone()),
            _ => {}
        }
        if let Some(id) = message.answers() {
            let waiting = {
                let mut inner = self.inner();
                match inner.pending.get(&id) {
                    Some((owner, _)) if owner == agent => inner.pending.remove(&id),
                    _ => None,
                }
            };
            if let Some((_, answer)) = waiting {
                let _ = answer.send(message);
            }
        }
    }

    /// Whether the agent's current link is alive: it answers a ping within
    /// [`LIVE_PROBE`].
    async fn link_is_live(&self, agent: &str) -> bool {
        if self.link(agent).is_none() {
            return false;
        }
        matches!(
            self.request(agent, |id| ToRunner::Ping { id }, LIVE_PROBE)
                .await,
            Ok(FromRunner::Pong { .. })
        )
    }

    /// Notes a second runner that tried to connect while the agent's link
    /// was live: shown with the agent and in the activity feed.
    fn note_intrusion(&self, agent: &str, address: &str) {
        let at = crate::runner::drivers::iso_from_unix(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0),
        );
        let count = {
            let mut inner = self.inner();
            let entry = inner
                .intrusions
                .entry(agent.to_string())
                .or_insert(Intrusion {
                    at: at.clone(),
                    address: address.to_string(),
                    count: 0,
                });
            entry.at = at;
            entry.address = address.to_string();
            entry.count += 1;
            entry.count
        };
        tracing::warn!(%agent, %address, count, "a second runner tried to connect while the agent's runner is connected; refused");
        let summary = format!(
            "a second runner tried to connect as {agent} from {address} while its runner was \
             connected; it was refused (its runner secret may have leaked)"
        );
        if let Err(error) =
            self.db
                .record_activity("lore", "builtin", "", None, None, &[], &summary)
        {
            tracing::warn!(%error, "recording a second runner failed");
        }
    }

    /// Keeps why a runner was refused where the admin page shows it.
    fn note_refusal(&self, agent: &str, reason: &str) {
        if let Err(error) = self.db.builtin_refused(agent, reason) {
            tracing::warn!(%agent, %error, "recording a runner's refusal failed");
        }
    }

    /// The internal router: only `/runner/ws`.
    pub fn router(self: Arc<Self>) -> Router {
        Router::new()
            .route("/runner/ws", get(runner_ws))
            .with_state(self)
    }

    /// One runner's link, from the hello to the close.
    async fn serve(self: Arc<Self>, agent: String, address: String, mut socket: WebSocket) {
        let hello = tokio::time::timeout(Duration::from_secs(15), async {
            while let Some(Ok(frame)) = socket.recv().await {
                if let Message::Text(text) = frame {
                    return protocol::decode::<FromRunner>(text.as_str()).ok();
                }
            }
            None
        })
        .await
        .ok()
        .flatten();
        let refuse = |reason: String| ToRunner::Refused { reason };
        let (kind, provider, runner_version, cli_version) = match hello {
            Some(FromRunner::Hello {
                protocol: version,
                agent: named,
                kind,
                provider,
                runner_version,
                cli_version,
            }) => {
                if version != PROTOCOL_VERSION {
                    let reason = format!(
                        "this lore speaks runner protocol {PROTOCOL_VERSION}, the runner {version}; \
                         build both from the same version"
                    );
                    tracing::warn!(%agent, %reason, "a runner was refused");
                    self.note_refusal(&agent, &reason);
                    let _ = socket
                        .send(Message::text(protocol::encode(&refuse(reason))))
                        .await;
                    return;
                }
                if named != agent {
                    let _ = socket
                        .send(Message::text(protocol::encode(&refuse(
                            "the hello names another agent than the header".into(),
                        ))))
                        .await;
                    return;
                }
                // What the agent is was fixed in LORE_RUNNER_TOKENS.
                let Some(token) = self.token(&agent) else {
                    return;
                };
                if kind != token.kind || provider.trim().to_lowercase() != token.provider {
                    let reason = format!(
                        "{agent} runs {} with {}; this runner says {} with {}",
                        token.kind.id(),
                        token.provider,
                        kind.id(),
                        provider
                            .chars()
                            .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
                            .take(40)
                            .collect::<String>()
                    );
                    tracing::warn!(%agent, %reason, "a runner was refused");
                    self.note_refusal(&agent, &reason);
                    let _ = socket
                        .send(Message::text(protocol::encode(&refuse(reason))))
                        .await;
                    return;
                }
                (kind, token.provider.clone(), runner_version, cli_version)
            }
            _ => {
                tracing::warn!(%agent, "a runner connected without a hello");
                return;
            }
        };
        let provider: String = provider
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
            .take(40)
            .collect();
        let shorten = |text: &str| text.chars().take(120).collect::<String>();
        // One live link per agent: a runner that dials again after its
        // link died replaces it; a second runner while the first answers
        // is refused and noted.
        if self.link_is_live(&agent).await {
            self.note_intrusion(&agent, &address);
            let _ = socket
                .send(Message::text(protocol::encode(&refuse(
                    "another runner is connected for this agent".into(),
                ))))
                .await;
            return;
        }
        let (tx, mut rx) = mpsc::channel::<ToRunner>(64);
        let generation = self.next_id();
        {
            let mut inner = self.inner();
            inner.links.insert(
                agent.clone(),
                Link {
                    generation,
                    tx,
                    kind,
                    provider: provider.clone(),
                    address: address.parse().ok().map(plain_ip),
                },
            );
        }
        if let Err(error) = self.db.builtin_connected(
            &agent,
            kind.id(),
            &provider,
            &shorten(&runner_version),
            cli_version.as_deref().map(shorten).as_deref(),
        ) {
            tracing::warn!(%agent, %error, "recording a runner's connection failed");
        }
        tracing::info!(%agent, kind = kind.id(), %provider, "a built-in agent's runner connected");
        let welcome = ToRunner::Welcome {
            protocol: PROTOCOL_VERSION,
        };
        if socket
            .send(Message::text(protocol::encode(&welcome)))
            .await
            .is_ok()
        {
            self.pump(&agent, &mut socket, &mut rx).await;
        }
        let current = {
            let mut inner = self.inner();
            let current = inner
                .links
                .get(&agent)
                .is_some_and(|link| link.generation == generation);
            if current {
                inner.links.remove(&agent);
                inner.resources.remove(&agent);
                // Its terminals' pages see their channel close.
                inner
                    .terminals
                    .retain(|_, terminal| terminal.agent != agent);
                // Whoever waits on this runner hears that it went.
                inner.pending.retain(|_, (owner, _)| owner != &agent);
                if let Some(login) = inner.logins.get_mut(&agent)
                    && matches!(login.state.as_str(), "starting" | "waiting")
                {
                    login.state = "failed".into();
                    login.url = None;
                    login.url_host = None;
                    login.code = None;
                    login.message = "the agent's container disconnected".into();
                }
            }
            current
        };
        if current {
            let _ = self
                .run_tx
                .send(HubEvent::Disconnected {
                    agent: agent.clone(),
                })
                .await;
            if let Err(error) = self.db.builtin_disconnected(&agent) {
                tracing::warn!(%agent, %error, "recording a runner's disconnection failed");
            }
            tracing::info!(%agent, "a built-in agent's runner disconnected");
        }
    }

    /// Moves frames both ways until the link closes or goes quiet.
    async fn pump(&self, agent: &str, socket: &mut WebSocket, rx: &mut mpsc::Receiver<ToRunner>) {
        let mut ping = tokio::time::interval(PING_EVERY);
        ping.tick().await;
        let mut last_heard = tokio::time::Instant::now();
        let mut frames = Bucket::new(FRAMES_PER_SECOND, FRAMES_BURST);
        let mut bytes = Bucket::new(BYTES_PER_SECOND, BYTES_BURST);
        loop {
            tokio::select! {
                frame = socket.recv() => {
                    let Some(Ok(frame)) = frame else { return };
                    last_heard = tokio::time::Instant::now();
                    let size = match &frame {
                        Message::Text(text) => text.len(),
                        Message::Binary(data) => data.len(),
                        _ => 0,
                    };
                    if !frames.take(1.0) || !bytes.take(size as f64) {
                        tracing::warn!(%agent, "a runner sent more than its link allows; closing it");
                        let _ = socket.send(Message::Close(None)).await;
                        return;
                    }
                    match frame {
                        Message::Text(text) => match protocol::decode::<FromRunner>(text.as_str()) {
                            Ok(message) => self.on_message(agent, message),
                            Err(error) => {
                                tracing::warn!(%agent, %error, "a runner message could not be read");
                            }
                        },
                        Message::Close(_) => return,
                        _ => {}
                    }
                }
                command = rx.recv() => {
                    let Some(command) = command else { return };
                    if socket.send(Message::text(protocol::encode(&command))).await.is_err() {
                        return;
                    }
                }
                _ = ping.tick() => {
                    if last_heard.elapsed() > SILENCE_LIMIT {
                        tracing::warn!(%agent, "a runner went quiet; closing its link");
                        return;
                    }
                    let ping = ToRunner::Ping { id: self.next_id() };
                    if socket.send(Message::text(protocol::encode(&ping))).await.is_err() {
                        return;
                    }
                }
            }
        }
    }
}

/// `GET /runner/ws`: a runner's WebSocket. Checked before the upgrade:
/// the request came straight over the internal network (no proxy headers),
/// it names a built-in agent, and it carries that agent's secret.
async fn runner_ws(
    State(hub): State<Arc<Hub>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    upgrade: Result<WebSocketUpgrade, axum::extract::ws::rejection::WebSocketUpgradeRejection>,
) -> Response {
    // The internal listener is never published; a request that passed a
    // reverse proxy is refused all the same.
    if [
        "x-forwarded-for",
        "x-forwarded-host",
        "forwarded",
        "x-real-ip",
    ]
    .iter()
    .any(|name| headers.contains_key(*name))
    {
        return (
            StatusCode::FORBIDDEN,
            "runners connect over the internal network\n",
        )
            .into_response();
    }
    let ip = peer.ip().to_string();
    if let Some(retry_after) = hub.failures.blocked(&ip) {
        return too_many_requests(retry_after);
    }
    let agent = headers
        .get(AGENT_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.trim().to_lowercase())
        .unwrap_or_default();
    let presented = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::trim)
        .unwrap_or_default();
    if !hub.check_secret(&agent, presented) {
        hub.failures.hit(&ip);
        tracing::warn!(%ip, "a runner connection with a wrong agent or secret was refused");
        return (StatusCode::UNAUTHORIZED, "wrong runner agent or secret\n").into_response();
    }
    hub.failures.reset(&ip);
    let upgrade = match upgrade {
        Ok(upgrade) => upgrade,
        Err(rejection) => return rejection.into_response(),
    };
    upgrade
        .max_message_size(protocol::MAX_FRAME_BYTES)
        .max_frame_size(protocol::MAX_FRAME_BYTES)
        .on_upgrade(move |socket| hub.serve(agent, ip, socket))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::{
        self, Config, End,
        drivers::{Driver, Settings},
        protocol::{CredentialKind, LoginMethod, RunLine, Secret},
    };

    const CLAUDE_SECRET: &str = "claude-runner-secret-0123456789abcdef";
    const CODEX_SECRET: &str = "codex-runner-secret-0123456789abcdef0";

    fn temp_dir(label: &str) -> std::path::PathBuf {
        static COUNT: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "lore-hub-{label}-{}-{}",
            std::process::id(),
            COUNT.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A fake CLI: a shell script that prints the documented shapes.
    fn fake_cli(dir: &std::path::Path, kind: Kind) -> std::path::PathBuf {
        let script = match kind {
            Kind::Claude => {
                r#"#!/bin/sh
case "$1 $2" in
  "--version ") echo "2.1.328 (Claude Code)" ;;
  "auth status")
    if [ -n "$CLAUDE_CODE_OAUTH_TOKEN" ]; then echo "Logged in with token $CLAUDE_CODE_OAUTH_TOKEN"; exit 0; fi
    echo "Not logged in"; exit 1 ;;
  "auth login")
    echo "Browser didn't open? Use the url below to sign in:"
    echo "https://claude.ai/oauth/authorize?code=true&client_id=x"
    echo "Paste code here if prompted >"
    read code
    if [ "$code" = "good-code" ]; then echo "Login successful"; exit 0; fi
    echo "Invalid code"; exit 1 ;;
  "auth logout") exit 0 ;;
esac
"#
            }
            Kind::Codex => {
                r#"#!/bin/sh
case "$1 $2" in
  "--version ") echo "WARNING: noise"; echo "codex-cli 0.166.0" ;;
  "login status")
    if [ -f "$CODEX_HOME/auth.json" ]; then echo "Logged in using ChatGPT"; exit 0; fi
    echo "Not logged in"; exit 1 ;;
  "login --device-auth")
    echo "Follow these steps to sign in with ChatGPT using device code authorization:"
    echo "1. Open this link in your browser and sign in to your account"
    printf '   \033[94mhttps://auth.openai.com/codex/device\033[0m\n'
    printf '2. Enter this one-time code \033[94mABCD-12XYZ\033[0m\n'
    sleep 1
    echo '{"tokens":{"access_token":"device-made-access-token-123456"}}' > "$CODEX_HOME/auth.json"
    echo "Successfully logged in"; exit 0 ;;
  "debug models") echo '{"models":[{"slug":"gpt-6-sol","visibility":"list"},{"slug":"internal","visibility":"hide"}]}' ;;
  "logout ") rm -f "$CODEX_HOME/auth.json" ;;
esac
"#
            }
            Kind::Opencode => {
                r#"#!/bin/sh
case "$1" in
  --version) echo "2.3.2" ;;
  models) echo "anthropic/x"; echo "deepseek/deepseek-v4-pro"; echo "deepseek/deepseek-flash" ;;
esac
"#
            }
        };
        let path = dir.join(kind.id());
        std::fs::write(&path, script).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        path
    }

    struct Pair {
        hub: Arc<Hub>,
        db: Db,
        url: String,
        dir: std::path::PathBuf,
    }

    /// lore's runner listener on a free port, with two built-in agents.
    async fn listen() -> Pair {
        let dir = temp_dir("pair");
        let db = Db::open(&dir.join("lore.db")).unwrap();
        let tokens = parse_runner_tokens(&format!(
            "claude-builtin:{CLAUDE_SECRET}, codex-builtin:{CODEX_SECRET},deepseek-builtin:{CODEX_SECRET}x"
        ))
        .unwrap();
        let named: Vec<(String, String, &str)> = tokens
            .iter()
            .map(|t| {
                let (kind, avatar) = kind_and_avatar(&t.agent);
                (t.agent.clone(), kind.to_string(), avatar)
            })
            .collect();
        db.register_builtin_agents(&named).unwrap();
        let hub =
            Arc::new(Hub::new(db.clone(), tokens).with_mcp_url("http://127.0.0.1:9/mcp".into()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}/runner/ws", listener.local_addr().unwrap());
        let router = hub.clone().router();
        tokio::spawn(async move {
            axum::serve(
                listener,
                router.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });
        Pair { hub, db, url, dir }
    }

    fn config(pair: &Pair, agent: &str, kind: Kind, secret: &str) -> Config {
        let home = pair.dir.join(format!("home-{agent}"));
        std::fs::create_dir_all(&home).unwrap();
        Config {
            url: pair.url.clone(),
            token: Secret::new(secret),
            agent: agent.into(),
            settings: Settings {
                kind,
                provider: runner::default_provider(kind).into(),
                home,
                program: fake_cli(&pair.dir, kind),
            },
            work: pair.dir.clone(),
            git: std::path::PathBuf::from("git"),
        }
    }

    async fn connected(hub: &Hub, agent: &str) {
        for _ in 0..200 {
            if hub.link(agent).is_some() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("{agent} never connected");
    }

    fn start(config: Config) -> tokio::task::JoinHandle<Result<End>> {
        let driver = Arc::new(Driver::new(config.settings.clone()));
        driver.prepare().unwrap();
        tokio::spawn(async move { runner::session(&config, driver, Default::default()).await })
    }

    const WAIT: Duration = Duration::from_secs(20);

    #[tokio::test]
    async fn a_runner_signs_in_with_a_pasted_token_that_lore_never_keeps() {
        let pair = listen().await;
        let config = config(&pair, "claude-builtin", Kind::Claude, CLAUDE_SECRET);
        let home = config.settings.home.clone();
        start(config);
        connected(&pair.hub, "claude-builtin").await;
        assert_eq!(
            pair.hub.link("claude-builtin"),
            Some((Kind::Claude, "anthropic".into()))
        );
        let status = pair
            .hub
            .request("claude-builtin", |id| ToRunner::Status { id }, WAIT)
            .await
            .unwrap();
        let FromRunner::Status { signed_in, .. } = status else {
            panic!("{status:?}")
        };
        assert!(!signed_in);

        let token = "sk-ant-oat01-a-very-secret-setup-token-value"; // lore:allow-secret (fake test value)
        let answer = pair
            .hub
            .request(
                "claude-builtin",
                |id| ToRunner::SetCredential {
                    id,
                    credential: CredentialKind::SetupToken,
                    value: Secret::new(token),
                },
                WAIT,
            )
            .await
            .unwrap();
        assert!(
            matches!(answer, FromRunner::Done { ok: true, .. }),
            "{answer:?}"
        );
        // Stored in the agent's volume, owner-only.
        let stored = home.join(".lore-runner/secrets.env");
        let text = std::fs::read_to_string(&stored).unwrap();
        assert!(text.contains(token));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&stored).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        // The fake CLI echoes the token in its status; the runner removes it.
        let status = pair
            .hub
            .request("claude-builtin", |id| ToRunner::Status { id }, WAIT)
            .await
            .unwrap();
        let FromRunner::Status {
            signed_in,
            method,
            login_ends,
            detail,
            ..
        } = status
        else {
            panic!()
        };
        assert!(signed_in);
        assert_eq!(method.as_deref(), Some("setup-token"));
        assert!(login_ends.is_some());
        assert!(
            !detail.contains(token) && detail.contains("[redacted]"),
            "{detail}"
        );
        // Nothing of it reached lore's database.
        let agent = pair.db.builtin_agent("claude-builtin").unwrap().unwrap();
        assert!(agent.connected && agent.signed_in);
        let dump = format!("{agent:?}");
        assert!(!dump.contains(token));
        let bytes = std::fs::read(pair.dir.join("lore.db")).unwrap_or_default();
        assert!(!String::from_utf8_lossy(&bytes).contains(token));

        // Claude's models are a fixed list.
        let models = pair
            .hub
            .request("claude-builtin", |id| ToRunner::ListModels { id }, WAIT)
            .await
            .unwrap();
        assert!(
            matches!(&models, FromRunner::Models { models, source, .. }
                if models.contains(&"sonnet".to_string()) && source == "fixed"),
            "{models:?}"
        );
        let pong = pair
            .hub
            .request("claude-builtin", |id| ToRunner::Ping { id }, WAIT)
            .await
            .unwrap();
        assert!(matches!(pong, FromRunner::Pong { .. }));

        // Interactive sign-in: the URL shows, the pasted code goes to stdin.
        let answer = pair
            .hub
            .request(
                "claude-builtin",
                |id| {
                    pair.hub.login_started("claude-builtin", id, "interactive");
                    ToRunner::LoginStart {
                        id,
                        method: LoginMethod::Interactive,
                    }
                },
                WAIT,
            )
            .await
            .unwrap();
        let FromRunner::LoginPrompt {
            url, needs_code, ..
        } = answer
        else {
            panic!("{answer:?}")
        };
        assert!(needs_code);
        assert!(
            url.unwrap()
                .starts_with("https://claude.ai/oauth/authorize")
        );
        let answer = pair
            .hub
            .request(
                "claude-builtin",
                |id| ToRunner::LoginCode {
                    id,
                    code: Secret::new("good-code"),
                },
                WAIT,
            )
            .await
            .unwrap();
        assert!(matches!(answer, FromRunner::Done { ok: true, .. }));
        for _ in 0..200 {
            if pair
                .hub
                .login_state("claude-builtin")
                .is_some_and(|login| login.state == "done")
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(
            pair.hub.login_state("claude-builtin").unwrap().state,
            "done"
        );
    }

    #[tokio::test]
    async fn codex_device_login_and_models_flow_through_the_link() {
        let pair = listen().await;
        let config = config(&pair, "codex-builtin", Kind::Codex, CODEX_SECRET);
        let home = config.settings.home.clone();
        start(config);
        connected(&pair.hub, "codex-builtin").await;
        // The runner set Codex up to keep its credentials in a file.
        let toml = std::fs::read_to_string(home.join(".codex/config.toml")).unwrap();
        assert!(toml.contains("cli_auth_credentials_store = \"file\""));
        let answer = pair
            .hub
            .request(
                "codex-builtin",
                |id| {
                    pair.hub.login_started("codex-builtin", id, "device");
                    ToRunner::LoginStart {
                        id,
                        method: LoginMethod::Device,
                    }
                },
                WAIT,
            )
            .await
            .unwrap();
        let FromRunner::LoginPrompt {
            url,
            code,
            needs_code,
            ..
        } = answer
        else {
            panic!("{answer:?}")
        };
        assert_eq!(url.as_deref(), Some("https://auth.openai.com/codex/device"));
        assert_eq!(code.as_deref(), Some("ABCD-12XYZ"));
        assert!(!needs_code);
        let mut done = false;
        for _ in 0..300 {
            if let Some(login) = pair.hub.login_state("codex-builtin")
                && login.state == "done"
            {
                done = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(done, "{:?}", pair.hub.login_state("codex-builtin"));
        for _ in 0..200 {
            if pair
                .db
                .builtin_agent("codex-builtin")
                .unwrap()
                .unwrap()
                .signed_in
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let agent = pair.db.builtin_agent("codex-builtin").unwrap().unwrap();
        assert!(agent.signed_in);
        assert_eq!(agent.login_method, "ChatGPT");
        assert_eq!(agent.cli_version, "codex-cli 0.166.0");
        let models = pair
            .hub
            .request("codex-builtin", |id| ToRunner::ListModels { id }, WAIT)
            .await
            .unwrap();
        assert!(
            matches!(&models, FromRunner::Models { models, source, .. }
                if models == &vec!["gpt-6-sol".to_string()] && source == "cli"),
            "{models:?}"
        );
        // A pasted auth.json that is not JSON is refused without echoing.
        let answer = pair
            .hub
            .request(
                "codex-builtin",
                |id| ToRunner::SetCredential {
                    id,
                    credential: CredentialKind::AuthJson,
                    value: Secret::new("not-json-but-secret-looking-value"),
                },
                WAIT,
            )
            .await
            .unwrap();
        let FromRunner::Error { message, .. } = answer else {
            panic!("{answer:?}")
        };
        assert!(!message.contains("secret-looking"), "{message}");
        // Signing out removes the stored file.
        let answer = pair
            .hub
            .request("codex-builtin", |id| ToRunner::Logout { id }, WAIT)
            .await
            .unwrap();
        assert!(matches!(answer, FromRunner::Done { ok: true, .. }));
        assert!(!home.join(".codex/auth.json").exists());
    }

    #[tokio::test]
    async fn deepseek_takes_an_api_key_and_lists_its_models() {
        let pair = listen().await;
        let mut config = config(
            &pair,
            "deepseek-builtin",
            Kind::Opencode,
            &format!("{CODEX_SECRET}x"),
        );
        config.settings.provider = "deepseek".into();
        let home = config.settings.home.clone();
        start(config);
        connected(&pair.hub, "deepseek-builtin").await;
        let answer = pair
            .hub
            .request(
                "deepseek-builtin",
                |id| ToRunner::SetCredential {
                    id,
                    credential: CredentialKind::ApiKey,
                    value: Secret::new("sk-deepseek-0123456789"),
                },
                WAIT,
            )
            .await
            .unwrap();
        assert!(
            matches!(answer, FromRunner::Done { ok: true, .. }),
            "{answer:?}"
        );
        let text = std::fs::read_to_string(home.join(".lore-runner/secrets.env")).unwrap();
        assert_eq!(text.trim(), "DEEPSEEK_API_KEY=sk-deepseek-0123456789");
        assert!(home.join(".config/opencode/opencode.json").exists());
        let models = pair
            .hub
            .request("deepseek-builtin", |id| ToRunner::ListModels { id }, WAIT)
            .await
            .unwrap();
        assert!(
            matches!(&models, FromRunner::Models { models, .. }
                if models == &vec!["deepseek-v4-pro".to_string(), "deepseek-flash".to_string()]),
            "{models:?}"
        );
        // A setup token is not a DeepSeek credential.
        let answer = pair
            .hub
            .request(
                "deepseek-builtin",
                |id| ToRunner::SetCredential {
                    id,
                    credential: CredentialKind::SetupToken,
                    value: Secret::new("whatever-token-value"),
                },
                WAIT,
            )
            .await
            .unwrap();
        assert!(matches!(answer, FromRunner::Error { .. }));
    }

    #[tokio::test]
    async fn wrong_secrets_names_and_versions_are_refused() {
        let pair = listen().await;
        // Another agent's secret.
        let wrong = config(&pair, "claude-builtin", Kind::Claude, CODEX_SECRET);
        let driver = Arc::new(Driver::new(wrong.settings.clone()));
        assert!(
            runner::session(&wrong, driver, Default::default())
                .await
                .is_err()
        );
        // An agent lore does not know.
        let unknown = config(&pair, "gemini-builtin", Kind::Claude, CLAUDE_SECRET);
        let driver = Arc::new(Driver::new(unknown.settings.clone()));
        assert!(
            runner::session(&unknown, driver, Default::default())
                .await
                .is_err()
        );
        assert!(pair.hub.link("claude-builtin").is_none());
        assert!(
            !pair
                .db
                .builtin_agent("claude-builtin")
                .unwrap()
                .unwrap()
                .connected
        );

        // A proxied request is refused before the secret is looked at.
        let response = reqwest::Client::new()
            .get(pair.url.replace("ws://", "http://"))
            .header("x-forwarded-for", "203.0.113.9")
            .header(AGENT_HEADER, "claude-builtin")
            .header(header::AUTHORIZATION, format!("Bearer {CLAUDE_SECRET}"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 403);

        // Another protocol version is refused with a reason.
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::{self, client::IntoClientRequest};
        let mut request = pair.url.as_str().into_client_request().unwrap();
        request.headers_mut().insert(
            header::AUTHORIZATION,
            format!("Bearer {CLAUDE_SECRET}").parse().unwrap(),
        );
        request
            .headers_mut()
            .insert(AGENT_HEADER, "claude-builtin".parse().unwrap());
        let (mut socket, _) = tokio_tungstenite::connect_async(request).await.unwrap();
        let hello = FromRunner::Hello {
            protocol: PROTOCOL_VERSION + 1,
            agent: "claude-builtin".into(),
            kind: Kind::Claude,
            provider: "anthropic".into(),
            runner_version: "9".into(),
            cli_version: None,
        };
        socket
            .send(tungstenite::Message::text(protocol::encode(&hello)))
            .await
            .unwrap();
        let reply = socket.next().await.unwrap().unwrap();
        let reply: ToRunner = protocol::decode(reply.to_text().unwrap()).unwrap();
        assert!(matches!(reply, ToRunner::Refused { .. }), "{reply:?}");
        assert!(pair.hub.link("claude-builtin").is_none());
        // The reason is where the admin page shows it, not only in the log.
        let detail = pair
            .db
            .builtin_agent("claude-builtin")
            .unwrap()
            .unwrap()
            .status_detail;
        assert!(detail.contains("runner protocol"), "{detail}");
        // Not connected: a clear error, at once.
        assert!(matches!(
            pair.hub
                .request("claude-builtin", |id| ToRunner::Status { id }, WAIT)
                .await,
            Err(HubError::NotConnected)
        ));
    }

    #[tokio::test]
    async fn a_closed_link_is_noticed_and_a_new_one_replaces_it() {
        let pair = listen().await;
        let first = start(config(&pair, "claude-builtin", Kind::Claude, CLAUDE_SECRET));
        connected(&pair.hub, "claude-builtin").await;
        first.abort();
        for _ in 0..200 {
            if pair.hub.link("claude-builtin").is_none() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(pair.hub.link("claude-builtin").is_none());
        assert!(
            !pair
                .db
                .builtin_agent("claude-builtin")
                .unwrap()
                .unwrap()
                .connected
        );
        start(config(&pair, "claude-builtin", Kind::Claude, CLAUDE_SECRET));
        connected(&pair.hub, "claude-builtin").await;
        assert!(
            pair.db
                .builtin_agent("claude-builtin")
                .unwrap()
                .unwrap()
                .connected
        );
    }

    /// The admin routes with this hub, on a free port.
    async fn admin_server(pair: &Pair) -> String {
        admin_server_with(pair, None).await
    }

    /// The same, with a shorter re-check of open terminals.
    async fn admin_server_with(pair: &Pair, recheck: Option<Duration>) -> String {
        let admin = crate::admin::Admin::new(
            pair.db.clone(),
            "admin-password-long".into(),
            None,
            None,
            false,
            Vec::new(),
            None,
            0.8,
            crate::events::Events::new(),
            crate::embed::Embedder::disabled(),
            12,
            None,
            crate::ops::Guard::default(),
        )
        .with_builtin(pair.hub.clone());
        let admin = match recheck {
            Some(every) => admin.with_terminal_recheck(every),
            None => admin,
        };
        let router = crate::admin::router(Arc::new(admin));
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
        base
    }

    async fn sign_in(http: &reqwest::Client, base: &str, user: &str, password: &str) -> String {
        let response = http
            .post(format!("{base}/admin/api/login"))
            .json(&serde_json::json!({ "username": user, "password": password }))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let cookie = response.headers()[header::SET_COOKIE].to_str().unwrap();
        cookie.split(';').next().unwrap().to_string()
    }

    #[tokio::test]
    async fn the_page_signs_an_agent_in_and_the_token_goes_only_to_its_volume() {
        let pair = listen().await;
        let base = admin_server(&pair).await;
        let config = config(&pair, "claude-builtin", Kind::Claude, CLAUDE_SECRET);
        let home = config.settings.home.clone();
        start(config);
        connected(&pair.hub, "claude-builtin").await;
        pair.db
            .add_user(&crate::db::NewUser {
                username: "writer".into(),
                email: None,
                password_hash: crate::users::hash_password("writer-password").unwrap(),
                permissions: crate::users::Perms::parse(&["write"]).unwrap(),
                created_by: "admin".into(),
            })
            .unwrap();
        let http = reqwest::Client::new();
        let admin = sign_in(&http, &base, "admin", "admin-password-long").await;
        let writer = sign_in(&http, &base, "writer", "writer-password").await;
        let token = "sk-ant-oat01-page-pasted-secret-token-value"; // lore:allow-secret (fake test value)

        // Reading needs a sign-in only; changing needs `agents`.
        let list: serde_json::Value = http
            .get(format!("{base}/admin/api/builtin"))
            .header(header::COOKIE, &writer)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(list["configured"], true);
        assert_eq!(list["manage"], false);
        assert_eq!(list["agents"][0]["name"], "claude-builtin");
        assert_eq!(list["agents"][0]["connected"], true);
        let refused = http
            .post(format!(
                "{base}/admin/api/builtin/claude-builtin/credential"
            ))
            .header(header::COOKIE, &writer)
            .json(&serde_json::json!({ "credential": "setup_token", "value": token }))
            .send()
            .await
            .unwrap();
        assert_eq!(refused.status(), 403);
        assert!(!home.join(".lore-runner/secrets.env").exists());

        // A credential the kind does not take is refused before it leaves.
        let wrong = http
            .post(format!(
                "{base}/admin/api/builtin/claude-builtin/credential"
            ))
            .header(header::COOKIE, &admin)
            .json(&serde_json::json!({ "credential": "auth_json", "value": token }))
            .send()
            .await
            .unwrap();
        assert_eq!(wrong.status(), 400);
        let text = wrong.text().await.unwrap();
        assert!(!text.contains(token), "{text}");

        let stored = http
            .post(format!(
                "{base}/admin/api/builtin/claude-builtin/credential"
            ))
            .header(header::COOKIE, &admin)
            .json(&serde_json::json!({ "credential": "setup_token", "value": token }))
            .send()
            .await
            .unwrap();
        assert_eq!(stored.status(), 200);
        let text = stored.text().await.unwrap();
        assert!(!text.contains(token), "{text}");
        assert!(
            std::fs::read_to_string(home.join(".lore-runner/secrets.env"))
                .unwrap()
                .contains(token)
        );
        // The activity feed says what happened, without the value.
        let feed = format!("{:?}", pair.db.activity(20).unwrap());
        assert!(feed.contains("stored a setup token"), "{feed}");
        assert!(!feed.contains(token));
        for _ in 0..200 {
            if pair
                .db
                .builtin_agent("claude-builtin")
                .unwrap()
                .unwrap()
                .signed_in
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let list: serde_json::Value = http
            .get(format!("{base}/admin/api/builtin"))
            .header(header::COOKIE, &admin)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(list["agents"][0]["signed_in"], true);
        assert_eq!(list["agents"][0]["login_method"], "setup-token");
        assert!(!list.to_string().contains(token));

        // Settings are validated and kept.
        let put = |body: serde_json::Value| {
            http.put(format!("{base}/admin/api/builtin/claude-builtin"))
                .header(header::COOKIE, &admin)
                .json(&body)
                .send()
        };
        assert_eq!(
            put(serde_json::json!({ "active_hours": "9-5" }))
                .await
                .unwrap()
                .status(),
            400
        );
        assert_eq!(
            put(serde_json::json!({ "daily_cap": 1000 }))
                .await
                .unwrap()
                .status(),
            400
        );
        let saved = put(serde_json::json!({ "model": "opus", "enabled": true, "daily_cap": 2 }))
            .await
            .unwrap();
        assert_eq!(saved.status(), 200);
        let agent = pair.db.builtin_agent("claude-builtin").unwrap().unwrap();
        assert_eq!(
            (agent.model.as_str(), agent.enabled, agent.daily_cap),
            ("opus", true, 2)
        );
        // An unknown agent is not found.
        let missing = http
            .post(format!("{base}/admin/api/builtin/gemini-builtin/refresh"))
            .header(header::COOKIE, &admin)
            .json(&serde_json::json!({}))
            .send()
            .await
            .unwrap();
        assert_eq!(missing.status(), 404);
        let bytes = std::fs::read(pair.dir.join("lore.db")).unwrap_or_default();
        let wal = std::fs::read(pair.dir.join("lore.db-wal")).unwrap_or_default();
        assert!(!String::from_utf8_lossy(&bytes).contains(token));
        assert!(!String::from_utf8_lossy(&wal).contains(token));
    }

    /// A WebSocket to the terminal route, with the given cookie and Origin.
    async fn terminal_socket(
        base: &str,
        cookie: Option<&str>,
        origin: Option<&str>,
    ) -> Result<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
        u16,
    > {
        use tokio_tungstenite::tungstenite::{self, client::IntoClientRequest};
        let url = format!(
            "{}/admin/api/builtin/claude-builtin/terminal",
            base.replace("http://", "ws://")
        );
        let mut request = url.into_client_request().unwrap();
        if let Some(cookie) = cookie {
            request
                .headers_mut()
                .insert(header::COOKIE, cookie.parse().unwrap());
        }
        if let Some(origin) = origin {
            request
                .headers_mut()
                .insert(header::ORIGIN, origin.parse().unwrap());
        }
        match tokio_tungstenite::connect_async(request).await {
            Ok((socket, _)) => Ok(socket),
            Err(tungstenite::Error::Http(response)) => Err(response.status().as_u16()),
            Err(error) => panic!("{error}"),
        }
    }

    /// A terminal of the CLI's interface gets its own lore token, which
    /// speaks for that agent only while the terminal is open, only on the
    /// internal listener and only from the agent runner's address; a shell
    /// gets none.
    #[tokio::test]
    async fn a_terminal_s_token_works_only_while_it_is_open_and_only_from_its_agent() {
        use crate::auth::{Authenticated, McpAuth, Refused};
        let pair = listen().await;
        let script = |name: &str| {
            let program = pair.dir.join(name);
            std::fs::write(
                &program,
                "#!/bin/sh\ncase \"$1\" in --version) echo \"1.0.0\"; exit 0;; \
                 auth|login) echo \"Not logged in\"; exit 1;; esac\n\
                 echo \"tok:${LORE_AGENT_TOKEN:-none}:\"; read line\n",
            )
            .unwrap();
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).unwrap();
            program
        };
        let mut claude = config(&pair, "claude-builtin", Kind::Claude, CLAUDE_SECRET);
        claude.settings.program = script("claude-tok");
        let mut codex = config(&pair, "codex-builtin", Kind::Codex, CODEX_SECRET);
        codex.settings.program = script("codex-tok");
        start(claude);
        start(codex);
        connected(&pair.hub, "claude-builtin").await;
        connected(&pair.hub, "codex-builtin").await;

        async fn token_of(hub: &Hub, agent: &str, mode: TerminalMode) -> (String, String) {
            let (term_id, mut rx) = hub.terminal_open(agent, mode, 80, 24, None).await.unwrap();
            if mode == TerminalMode::Shell {
                // The shell prints it when asked (split, so the echoed
                // command line does not match).
                let typed = "printf 'to%s\\n' \"k:${LORE_AGENT_TOKEN:-none}:\"\r";
                hub.terminal_send(
                    &term_id,
                    ToRunner::TerminalInput {
                        term_id: term_id.clone(),
                        data: base64::engine::general_purpose::STANDARD.encode(typed),
                    },
                )
                .await
                .unwrap();
            }
            let mut text = String::new();
            loop {
                let event = tokio::time::timeout(WAIT, rx.recv())
                    .await
                    .unwrap_or_else(|_| panic!("no token line in {text:?}"))
                    .expect("the terminal ended");
                if let TerminalEvent::Output(bytes) = event {
                    text.push_str(&String::from_utf8_lossy(&bytes));
                }
                if let Some(start) = text.find("tok:")
                    && let Some(end) = text[start + 4..].find(':')
                {
                    // Keep the receiver alive: the terminal stays open.
                    std::mem::forget(rx);
                    return (term_id, text[start + 4..start + 4 + end].to_string());
                }
            }
        }
        let (claude_term, token) = token_of(&pair.hub, "claude-builtin", TerminalMode::Cli).await;
        assert!(looks_like_terminal_token(&token), "{token}");
        let (codex_term, codex_token) =
            token_of(&pair.hub, "codex-builtin", TerminalMode::Cli).await;
        assert_ne!(token, codex_token);

        let mut auth = McpAuth::new(Vec::new(), pair.db.clone(), false);
        auth.terminals = Some(pair.hub.clone());
        let runner: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        let mapped: std::net::IpAddr = "::ffff:127.0.0.1".parse().unwrap();
        let elsewhere: std::net::IpAddr = "10.9.8.7".parse().unwrap();
        assert_eq!(
            auth.authenticate_terminal(&token, true, Some(runner)).await,
            Ok(Authenticated::Terminal("claude-builtin".into()))
        );
        assert_eq!(
            auth.authenticate_terminal(&token, true, Some(mapped)).await,
            Ok(Authenticated::Terminal("claude-builtin".into()))
        );
        // Each terminal's token speaks for its own agent only.
        assert_eq!(
            auth.authenticate_terminal(&codex_token, true, Some(runner))
                .await,
            Ok(Authenticated::Terminal("codex-builtin".into()))
        );
        // Not on the public listener, not from another address, not
        // without a known peer, not where only run and OAuth tokens count
        // (the git proxy), not with a changed character.
        assert_eq!(
            auth.authenticate_terminal(&token, false, Some(runner))
                .await,
            Err(Refused::Invalid)
        );
        assert_eq!(
            auth.authenticate_terminal(&token, true, Some(elsewhere))
                .await,
            Err(Refused::Invalid)
        );
        assert_eq!(
            auth.authenticate_terminal(&token, true, None).await,
            Err(Refused::Invalid)
        );
        assert_eq!(
            auth.authenticate_on(&token, true).await,
            Err(Refused::Invalid)
        );
        let mut forged = token.clone();
        forged.pop();
        forged.push(if token.ends_with('0') { '1' } else { '0' });
        assert_eq!(
            auth.authenticate_terminal(&forged, true, Some(runner))
                .await,
            Err(Refused::Invalid)
        );
        // A shell gets no token.
        let (shell_term, shell_token) =
            token_of(&pair.hub, "claude-builtin", TerminalMode::Shell).await;
        assert_eq!(shell_token, "none");
        pair.hub.terminal_close(&shell_term).await;

        // Closed: the token is gone; the other agent's still works.
        pair.hub.terminal_close(&claude_term).await;
        assert_eq!(
            auth.authenticate_terminal(&token, true, Some(runner)).await,
            Err(Refused::Invalid)
        );
        assert_eq!(
            auth.authenticate_terminal(&codex_token, true, Some(runner))
                .await,
            Ok(Authenticated::Terminal("codex-builtin".into()))
        );
        pair.hub.terminal_close(&codex_term).await;
        assert_eq!(
            auth.authenticate_terminal(&codex_token, true, Some(runner))
                .await,
            Err(Refused::Invalid)
        );
    }

    #[tokio::test]
    async fn the_page_opens_a_terminal_through_the_hub() {
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::Message as Ws;
        let pair = listen().await;
        let base = admin_server(&pair).await;
        let mut config = config(&pair, "claude-builtin", Kind::Claude, CLAUDE_SECRET);
        // A fake CLI whose interactive side prints its arguments and its
        // window size, echoes a line and exits 5.
        let program = pair.dir.join("claude-tui");
        std::fs::write(
            &program,
            "#!/bin/sh\ncase \"$1\" in --version) echo \"2.1.328 (Claude Code)\"; exit 0;; \
             auth) echo \"Not logged in\"; exit 1;; esac\n\
             echo \"args:$*\"; stty size; read line; echo \"got:$line\"; stty size; read more; exit 5\n",
        )
        .unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        config.settings.program = program;
        start(config);
        connected(&pair.hub, "claude-builtin").await;
        pair.db
            .add_user(&crate::db::NewUser {
                username: "writer".into(),
                email: None,
                password_hash: crate::users::hash_password("writer-password").unwrap(),
                permissions: crate::users::Perms::parse(&["write"]).unwrap(),
                created_by: "admin".into(),
            })
            .unwrap();
        let http = reqwest::Client::new();
        let admin = sign_in(&http, &base, "admin", "admin-password-long").await;
        let writer = sign_in(&http, &base, "writer", "writer-password").await;
        let saved = http
            .put(format!("{base}/admin/api/builtin/claude-builtin"))
            .header(header::COOKIE, &admin)
            .json(&serde_json::json!({ "model": "opus" }))
            .send()
            .await
            .unwrap();
        assert_eq!(saved.status(), 200);
        let origin = base.clone();

        // Refused: no session, no `agents`, another origin, no origin.
        assert_eq!(
            terminal_socket(&base, None, Some(&origin)).await.err(),
            Some(401)
        );
        assert_eq!(
            terminal_socket(&base, Some(&writer), Some(&origin))
                .await
                .err(),
            Some(403)
        );
        assert_eq!(
            terminal_socket(&base, Some(&admin), Some("https://evil.example"))
                .await
                .err(),
            Some(403)
        );
        let other_port = format!("{base}1");
        assert_eq!(
            terminal_socket(&base, Some(&admin), Some(&other_port))
                .await
                .err(),
            Some(403)
        );
        assert_eq!(
            terminal_socket(&base, Some(&admin), None).await.err(),
            Some(403)
        );
        assert_eq!(pair.hub.terminal_count(), 0);

        // The owner's page: open, see output, resize, type, see the end.
        let mut socket = terminal_socket(&base, Some(&admin), Some(&origin))
            .await
            .unwrap();
        socket
            .send(Ws::text(
                r#"{"type":"open","mode":"cli","cols":90,"rows":20}"#,
            ))
            .await
            .unwrap();
        async fn until(
            socket: &mut (
                     impl StreamExt<Item = Result<Ws, tokio_tungstenite::tungstenite::Error>> + Unpin
                 ),
            text: &mut String,
            wanted: &str,
        ) -> Option<serde_json::Value> {
            loop {
                let frame = tokio::time::timeout(Duration::from_secs(15), socket.next())
                    .await
                    .unwrap_or_else(|_| panic!("waited for {wanted:?}; got {text:?}"))
                    .unwrap()
                    .unwrap();
                match frame {
                    Ws::Binary(bytes) => {
                        text.push_str(&String::from_utf8_lossy(&bytes));
                        if !wanted.is_empty() && text.contains(wanted) {
                            return None;
                        }
                    }
                    Ws::Text(json) => {
                        let value: serde_json::Value = serde_json::from_str(json.as_str()).unwrap();
                        if value["type"] != "opened" || wanted == "opened" {
                            return Some(value);
                        }
                    }
                    _ => {}
                }
            }
        }
        let mut text = String::new();
        assert_eq!(
            until(&mut socket, &mut text, "opened").await.unwrap()["type"],
            "opened"
        );
        until(&mut socket, &mut text, "20 90").await;
        assert!(text.contains("args:--model opus"), "{text}");
        assert_eq!(pair.hub.terminal_count(), 1);
        socket
            .send(Ws::text(r#"{"type":"resize","cols":100,"rows":33}"#))
            .await
            .unwrap();
        socket.send(Ws::text(r#"{"type":"alive"}"#)).await.unwrap();
        socket
            .send(Ws::binary(b"typed-but-never-stored\r".to_vec()))
            .await
            .unwrap();
        until(&mut socket, &mut text, "33 100").await;
        assert!(text.contains("got:typed-but-never-stored"), "{text}");
        socket.send(Ws::binary(b"\r".to_vec())).await.unwrap();
        let exit = until(&mut socket, &mut text, "").await.unwrap();
        assert_eq!(exit["type"], "exit");
        assert_eq!(exit["code"], 5);
        assert_eq!(pair.hub.terminal_count(), 0);

        // A page that goes closes its terminal; two at most per agent.
        let mut first = terminal_socket(&base, Some(&admin), Some(&origin))
            .await
            .unwrap();
        let mut second = terminal_socket(&base, Some(&admin), Some(&origin))
            .await
            .unwrap();
        let mut third = terminal_socket(&base, Some(&admin), Some(&origin))
            .await
            .unwrap();
        for socket in [&mut first, &mut second] {
            socket
                .send(Ws::text(
                    r#"{"type":"open","mode":"cli","cols":80,"rows":24}"#,
                ))
                .await
                .unwrap();
            let mut text = String::new();
            until(socket, &mut text, "24 80").await;
        }
        third
            .send(Ws::text(
                r#"{"type":"open","mode":"cli","cols":80,"rows":24}"#,
            ))
            .await
            .unwrap();
        let refused = until(&mut third, &mut String::new(), "").await.unwrap();
        assert_eq!(refused["type"], "error");
        assert!(
            refused["message"]
                .as_str()
                .unwrap()
                .contains("two terminals")
        );
        assert_eq!(pair.hub.terminal_count(), 2);
        drop(first);
        second.close(None).await.unwrap();
        for _ in 0..250 {
            if pair.hub.terminal_count() == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(pair.hub.terminal_count(), 0);

        // Who opened it is noted; what was typed or shown is not kept.
        let feed = format!("{:?}", pair.db.activity(20).unwrap());
        assert!(
            feed.contains("opened the CLI's terminal in claude-builtin"),
            "{feed}"
        );
        for file in ["lore.db", "lore.db-wal"] {
            let bytes = std::fs::read(pair.dir.join(file)).unwrap_or_default();
            assert!(!String::from_utf8_lossy(&bytes).contains("typed-but-never-stored"));
        }
    }

    /// An open terminal does not outlive the sign-in or the permission it
    /// was opened with: lore looks again while it is open and closes it
    /// with a sentence saying why.
    #[tokio::test]
    async fn an_open_terminal_closes_when_the_session_or_the_permission_goes() {
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::Message as Ws;
        let pair = listen().await;
        let base = admin_server_with(&pair, Some(Duration::from_millis(150))).await;
        let mut config = config(&pair, "claude-builtin", Kind::Claude, CLAUDE_SECRET);
        let program = pair.dir.join("claude-waits");
        std::fs::write(
            &program,
            "#!/bin/sh\ncase \"$1\" in --version) echo \"2.1.328 (Claude Code)\"; exit 0;; \
             auth) echo \"Not logged in\"; exit 1;; esac\necho ready; read line; exit 0\n",
        )
        .unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        config.settings.program = program;
        start(config);
        connected(&pair.hub, "claude-builtin").await;
        let operator = pair
            .db
            .add_user(&crate::db::NewUser {
                username: "operator".into(),
                email: None,
                password_hash: crate::users::hash_password("operator-password").unwrap(),
                permissions: crate::users::Perms::parse(&["agents", "users"]).unwrap(),
                created_by: "admin".into(),
            })
            .unwrap();
        let http = reqwest::Client::new();
        let origin = base.clone();

        /// Opens a terminal and waits until the program in it has printed.
        async fn open(
            base: &str,
            cookie: &str,
            origin: &str,
        ) -> tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        > {
            let mut socket = terminal_socket(base, Some(cookie), Some(origin))
                .await
                .unwrap();
            socket
                .send(Ws::text(
                    r#"{"type":"open","mode":"cli","cols":80,"rows":24}"#,
                ))
                .await
                .unwrap();
            let mut text = String::new();
            while !text.contains("ready") {
                let frame = tokio::time::timeout(Duration::from_secs(15), socket.next())
                    .await
                    .expect("the terminal never printed")
                    .unwrap()
                    .unwrap();
                if let Ws::Binary(bytes) = frame {
                    text.push_str(&String::from_utf8_lossy(&bytes));
                }
            }
            socket
        }
        /// The `exit` frame lore sends, then the socket's end.
        async fn closed(
            socket: &mut tokio_tungstenite::WebSocketStream<
                tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
            >,
        ) -> serde_json::Value {
            let mut exit = None;
            loop {
                let frame = tokio::time::timeout(Duration::from_secs(15), socket.next())
                    .await
                    .expect("the terminal stayed open");
                match frame {
                    Some(Ok(Ws::Text(json))) => {
                        exit = Some(serde_json::from_str(json.as_str()).unwrap());
                    }
                    Some(Ok(Ws::Close(_))) | Some(Err(_)) | None => {
                        return exit.expect("the socket closed without a reason");
                    }
                    Some(Ok(_)) => {}
                }
            }
        }
        async fn none_left(hub: &Hub) {
            for _ in 0..250 {
                if hub.terminal_count() == 0 {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            panic!("the terminal was not closed in the container");
        }

        // Still signed in, still allowed: several checks pass, it stays.
        let admin = sign_in(&http, &base, "admin", "admin-password-long").await;
        let mut socket = open(&base, &admin, &origin).await;
        tokio::time::sleep(Duration::from_millis(600)).await;
        assert_eq!(pair.hub.terminal_count(), 1);
        // Signing out ends the session: the terminal goes with it.
        let out = http
            .post(format!("{base}/admin/api/logout"))
            .header(header::COOKIE, &admin)
            .send()
            .await
            .unwrap();
        assert_eq!(out.status(), 200);
        let exit = closed(&mut socket).await;
        assert_eq!(exit["type"], "exit");
        assert!(
            exit["message"]
                .as_str()
                .unwrap()
                .contains("your session has ended"),
            "{exit}"
        );
        none_left(&pair.hub).await;

        // The permission is removed while the session stays.
        let cookie = sign_in(&http, &base, "operator", "operator-password").await;
        let mut socket = open(&base, &cookie, &origin).await;
        assert_eq!(pair.hub.terminal_count(), 1);
        let changed = http
            .put(format!("{base}/admin/api/users/{}", operator.id))
            .header(header::COOKIE, &cookie)
            .json(&serde_json::json!({ "permissions": ["users"] }))
            .send()
            .await
            .unwrap();
        assert_eq!(changed.status(), 200, "{}", changed.text().await.unwrap());
        let exit = closed(&mut socket).await;
        assert!(
            exit["message"]
                .as_str()
                .unwrap()
                .contains("no longer has the agents permission"),
            "{exit}"
        );
        none_left(&pair.hub).await;
        // And it cannot be opened again.
        assert_eq!(
            terminal_socket(&base, Some(&cookie), Some(&origin))
                .await
                .err(),
            Some(403)
        );
    }

    #[test]
    fn runner_tokens_are_parsed_strictly() {
        let tokens = parse_runner_tokens(&format!(" Claude-Builtin:{CLAUDE_SECRET} ,")).unwrap();
        assert_eq!(tokens[0].agent, "claude-builtin");
        assert!(!format!("{tokens:?}").contains(CLAUDE_SECRET));
        assert!(parse_runner_tokens("").unwrap().is_empty());
        for bad in [
            "claude-builtin".to_string(),
            "claude-builtin:short".to_string(),
            format!("bad name:{CLAUDE_SECRET}"),
            format!("a:{CLAUDE_SECRET},a:{CODEX_SECRET}"),
        ] {
            assert!(parse_runner_tokens(&bad).is_err(), "{bad}");
        }
        assert_eq!(kind_and_avatar("deepseek-builtin"), ("opencode", "wave"));
    }

    /// What an agent is comes from LORE_RUNNER_TOKENS: from its name, or
    /// named in the entry, which a name that says nothing must do.
    #[test]
    fn an_agent_s_cli_and_provider_are_fixed_by_lore() {
        let tokens = parse_runner_tokens(&format!(
            "claude-builtin:{CLAUDE_SECRET},helper:opencode/qwen:{CODEX_SECRET},second:codex:{CODEX_SECRET}0"
        ))
        .unwrap();
        assert_eq!(
            (tokens[0].kind, tokens[0].provider.as_str()),
            (Kind::Claude, "anthropic")
        );
        assert_eq!(
            (tokens[1].kind, tokens[1].provider.as_str()),
            (Kind::Opencode, "qwen")
        );
        assert_eq!(
            (tokens[2].kind, tokens[2].provider.as_str()),
            (Kind::Codex, "openai")
        );
        assert_eq!(tokens[1].secret(), CODEX_SECRET);
        assert!(parse_runner_tokens(&format!("helper:{CLAUDE_SECRET}")).is_err());
        assert!(parse_runner_tokens(&format!("helper:gemini:{CLAUDE_SECRET}")).is_err());
        assert_eq!(
            parse_runner_binds("172.31.250.2:8081, 172.31.250.18:8081")
                .unwrap()
                .len(),
            2
        );
        assert!(parse_runner_binds("lore:8081").is_err());
        assert!(parse_runner_binds(" ").is_err());
    }

    /// A runner whose hello claims another CLI than the agent's is refused.
    #[tokio::test]
    async fn a_runner_claiming_another_cli_is_refused() {
        let pair = listen().await;
        let lying = config(&pair, "claude-builtin", Kind::Codex, CLAUDE_SECRET);
        let driver = Arc::new(Driver::new(lying.settings.clone()));
        let ended = runner::session(&lying, driver, Default::default())
            .await
            .unwrap();
        assert!(
            matches!(&ended, End::Refused(reason) if reason.contains("runs claude")),
            "{ended:?}"
        );
        assert!(pair.hub.link("claude-builtin").is_none());
    }

    /// While an agent's runner is connected and answers, a second runner
    /// with the same secret is refused (not swapped in) and noted for the
    /// page and the activity feed.
    #[tokio::test]
    async fn a_second_runner_never_replaces_a_live_one() {
        let pair = listen().await;
        start(config(&pair, "claude-builtin", Kind::Claude, CLAUDE_SECRET));
        connected(&pair.hub, "claude-builtin").await;
        let thief = config(&pair, "claude-builtin", Kind::Claude, CLAUDE_SECRET);
        let driver = Arc::new(Driver::new(thief.settings.clone()));
        let ended = runner::session(&thief, driver, Default::default())
            .await
            .unwrap();
        assert!(
            matches!(&ended, End::Refused(reason) if reason.contains("another runner")),
            "{ended:?}"
        );
        // The first one still answers.
        assert!(matches!(
            pair.hub
                .request("claude-builtin", |id| ToRunner::Ping { id }, WAIT)
                .await,
            Ok(FromRunner::Pong { .. })
        ));
        let seen = pair.hub.intrusion("claude-builtin").unwrap();
        assert_eq!((seen.count, seen.address.as_str()), (1, "127.0.0.1"));
        let feed = format!("{:?}", pair.db.activity(20).unwrap());
        assert!(feed.contains("a second runner tried to connect"), "{feed}");
    }

    /// Only a link to a host the agent's CLI signs in at is shown, and
    /// only over https, without user info.
    #[test]
    fn sign_in_links_are_checked_against_the_cli_s_hosts() {
        let ok = checked_sign_in_url(
            Kind::Claude,
            "https://claude.ai/oauth/authorize?code=true&client_id=x",
        )
        .unwrap();
        assert_eq!(ok.1, "claude.ai");
        assert_eq!(
            checked_sign_in_url(Kind::Codex, "https://auth.openai.com/codex/device")
                .unwrap()
                .1,
            "auth.openai.com"
        );
        for bad in [
            "https://evil.example/oauth",
            "http://claude.ai/oauth",
            "https://user:pw@claude.ai/oauth",
            "https://claude.ai.evil.example/",
            "https://claude.ai:8443/",
            "javascript:alert(1)",
            "https://auth.openai.com/",
        ] {
            assert!(checked_sign_in_url(Kind::Claude, bad).is_none(), "{bad}");
        }
    }

    #[tokio::test]
    async fn a_sign_in_link_to_elsewhere_is_not_shown() {
        let pair = listen().await;
        pair.hub.login_started("claude-builtin", 7, "interactive");
        pair.hub.on_message(
            "claude-builtin",
            FromRunner::LoginPrompt {
                id: 7,
                url: Some("https://phish.example/login".into()),
                code: None,
                needs_code: true,
                message: "open https://phish.example/login?next=1 to sign in".into(),
            },
        );
        let login = pair.hub.login_state("claude-builtin").unwrap();
        assert_eq!((login.url, login.url_host), (None, None));
        assert!(login.message.contains("not shown"), "{}", login.message);
        // H12: the refused link appears nowhere in what the page gets.
        assert!(
            !login.message.contains("phish.example"),
            "{}",
            login.message
        );
        pair.hub.on_message(
            "claude-builtin",
            FromRunner::LoginDone {
                id: 7,
                ok: false,
                message: "failed at https://phish.example/x".into(),
            },
        );
        let login = pair.hub.login_state("claude-builtin").unwrap();
        assert!(
            !login.message.contains("phish.example"),
            "{}",
            login.message
        );
        pair.hub.login_started("claude-builtin", 7, "interactive");
        pair.hub.on_message(
            "claude-builtin",
            FromRunner::LoginPrompt {
                id: 7,
                url: Some("https://claude.ai/oauth/authorize?x=1".into()),
                code: None,
                needs_code: true,
                message: String::new(),
            },
        );
        let login = pair.hub.login_state("claude-builtin").unwrap();
        assert_eq!(login.url_host.as_deref(), Some("claude.ai"));
    }

    /// H6: run events wait in a bounded queue. Output lines past it are
    /// left out and counted (one line says how many), the run's end still
    /// arrives, and the link stays; a link over its frame rate is closed.
    #[tokio::test]
    async fn a_flood_of_output_lines_is_summarised_not_fatal() {
        let pair = listen().await;
        let mut events = pair.hub.take_events().unwrap();
        let lines: Vec<RunLine> = (1..=(RUN_EVENTS_QUEUE as u64 + 500))
            .map(|seq| RunLine {
                seq,
                stream: "stderr".into(),
                line: format!("noise {seq}"),
            })
            .collect();
        for chunk in lines.chunks(200) {
            pair.hub.on_message(
                "claude-builtin",
                FromRunner::RunOutputs {
                    run_id: "r1".into(),
                    lines: chunk.to_vec(),
                },
            );
        }
        pair.hub.on_message(
            "claude-builtin",
            FromRunner::RunExit {
                run_id: "r1".into(),
                code: Some(0),
                pushed: false,
                head: None,
                work_free_bytes: None,
                reason: None,
                answer: None,
            },
        );
        let (mut kept, mut summary, mut exit) = (0, None, false);
        while let Ok(Some(event)) =
            tokio::time::timeout(Duration::from_secs(2), events.recv()).await
        {
            match event {
                HubEvent::Run {
                    message: FromRunner::RunOutput { stream, line, .. },
                    ..
                } if stream == "lore" => summary = Some(line),
                HubEvent::Run {
                    message: FromRunner::RunOutput { .. },
                    ..
                } => kept += 1,
                HubEvent::Run {
                    message: FromRunner::RunExit { .. },
                    ..
                } => {
                    exit = true;
                    break;
                }
                _ => {}
            }
        }
        assert_eq!(kept, RUN_EVENTS_QUEUE);
        assert!(exit, "the run's end was lost");
        let summary = summary.expect("no line said that lines were left out");
        assert!(summary.starts_with("500 output line(s)"), "{summary}");
        let mut bucket = Bucket::new(10.0, 20.0);
        assert!((0..20).all(|_| bucket.take(1.0)));
        assert!(!bucket.take(1.0));
    }

    /// H2: the agent networks come from the routing table; an address
    /// without a route stands for itself.
    #[test]
    fn agent_networks_are_read_from_the_routing_table() {
        let table = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
                     eth0\t00000000\t010012AC\t0003\t0\t0\t0\t00000000\t0\t0\t0\n\
                     eth0\t000012AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0\n\
                     eth1\t00FA1FAC\t00000000\t0001\t0\t0\t0\tF0FFFFFF\t0\t0\t0\n";
        let nets = agent_networks_in(
            table,
            &["172.31.250.2".parse().unwrap(), "10.9.9.9".parse().unwrap()],
        );
        assert_eq!(
            nets[0],
            crate::auth::Cidr::parse("172.31.250.0/28").unwrap()
        );
        assert_eq!(nets[1], crate::auth::Cidr::parse("10.9.9.9/32").unwrap());
        assert!(nets[0].contains("172.31.250.9".parse().unwrap()));
        assert!(!nets[0].contains("172.31.250.17".parse().unwrap()));
    }

    /// H2: a connection accepted on an agent-network address of lore never
    /// reaches the public router; one on another address does.
    #[tokio::test]
    async fn the_public_listener_closes_connections_from_agent_networks() {
        use axum::serve::ListenerExt;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let app = Router::new().route("/admin/api/session", get(|| async { "here" }));
        let serve_on = |refused: Vec<std::net::IpAddr>| {
            let app = app.clone();
            async move {
                let inner = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let port = inner.local_addr().unwrap().port();
                let listener = PublicListener::new(inner, refused).tap_io(|_| {});
                tokio::spawn(async move {
                    axum::serve(
                        listener,
                        app.into_make_service_with_connect_info::<SocketAddr>(),
                    )
                    .await
                });
                port
            }
        };
        let ask = |port: u16| async move {
            let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .unwrap();
            let _ = stream
                .write_all(
                    b"GET /admin/api/session HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
                )
                .await;
            let mut answer = Vec::new();
            let _ =
                tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut answer)).await;
            String::from_utf8_lossy(&answer).into_owned()
        };
        let open = serve_on(vec!["10.1.2.3".parse().unwrap()]).await;
        assert!(ask(open).await.contains("here"));
        let closed = serve_on(vec!["127.0.0.1".parse().unwrap()]).await;
        assert_eq!(ask(closed).await, "");
    }

    /// H12: the owner can list a CLI's sign-in hosts.
    #[test]
    fn the_owner_may_name_the_sign_in_hosts() {
        let hosts = vec!["login.example.org".to_string()];
        assert!(checked_sign_in_url_in(&hosts, "https://login.example.org/a").is_some());
        assert!(checked_sign_in_url_in(&hosts, "https://claude.ai/a").is_none());
        assert_eq!(
            hide_other_links(
                "go to https://evil.example/x now, or https://login.example.org/y",
                &hosts
            ),
            "go to [a link to another host, not shown] now, or https://login.example.org/y"
        );
        // SAFETY: a name no other test uses.
        unsafe {
            std::env::set_var(
                "LORE_SIGN_IN_HOSTS_OPENCODE",
                "auth.example.net, x.example.com",
            )
        };
        assert_eq!(
            sign_in_hosts_from_env(Kind::Opencode).unwrap(),
            vec!["auth.example.net".to_string(), "x.example.com".to_string()]
        );
        unsafe { std::env::set_var("LORE_SIGN_IN_HOSTS_OPENCODE", "https://x/") };
        assert!(sign_in_hosts_from_env(Kind::Opencode).is_err());
        unsafe { std::env::remove_var("LORE_SIGN_IN_HOSTS_OPENCODE") };
    }

    /// State-changing built-in routes take JSON only (a cross-site form
    /// cannot send it); a viewer sees neither what the CLI said about the
    /// sign-in nor any run's output.
    #[tokio::test]
    async fn forms_are_refused_and_viewers_see_less() {
        let pair = listen().await;
        let events = crate::events::Events::new();
        pair.db
            .builtin_status(
                "claude-builtin",
                &BuiltinStatus {
                    detail: "Logged in as owner@example.com".into(),
                    ..BuiltinStatus::default()
                },
            )
            .unwrap();
        let admin = crate::admin::Admin::new(
            pair.db.clone(),
            "admin-password-long".into(),
            Some("viewer-password-long".into()),
            None,
            false,
            Vec::new(),
            None,
            0.8,
            events.clone(),
            crate::embed::Embedder::disabled(),
            12,
            None,
            crate::ops::Guard::default(),
        )
        .with_builtin(pair.hub.clone());
        // G9: a finished run whose summary quotes what it said.
        pair.db
            .insert_run(&crate::db::NewRun {
                id: "r-summary".into(),
                agent: "claude-builtin".into(),
                kind: "task".into(),
                ..Default::default()
            })
            .unwrap();
        pair.db
            .finish_run(
                "r-summary",
                &crate::db::RunEnd {
                    status: "done".into(),
                    summary: "secret-ish summary of the run".into(),
                    ..Default::default()
                },
            )
            .unwrap();
        let runner = crate::taskrunner::start(
            pair.db.clone(),
            pair.hub.clone(),
            events.clone(),
            crate::ops::Guard::default(),
            None,
        )
        .unwrap();
        let admin = admin.with_task_runner(runner);
        let router = crate::admin::router(Arc::new(admin));
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
        let http = reqwest::Client::new();
        let owner = sign_in(&http, &base, "admin", "admin-password-long").await;
        let viewer = sign_in(&http, &base, "viewer", "viewer-password-long").await;
        let history = |cookie: String| {
            let http = http.clone();
            let base = base.clone();
            async move {
                http.get(format!("{base}/admin/api/builtin/runs"))
                    .header(header::COOKIE, cookie)
                    .send()
                    .await
                    .unwrap()
                    .text()
                    .await
                    .unwrap()
            }
        };
        let seen = history(viewer.clone()).await;
        assert!(seen.contains("r-summary"), "{seen}");
        assert!(!seen.contains("secret-ish summary"), "{seen}");
        assert!(history(owner.clone()).await.contains("secret-ish summary"));
        for path in ["logout", "refresh", "login/cancel", "stop"] {
            let form = http
                .post(format!("{base}/admin/api/builtin/claude-builtin/{path}"))
                .header(header::COOKIE, &owner)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body("x=1")
                .send()
                .await
                .unwrap();
            assert_eq!(form.status(), 415, "{path}");
        }
        let plain = http
            .put(format!("{base}/admin/api/builtin/claude-builtin"))
            .header(header::COOKIE, &owner)
            .header(header::CONTENT_TYPE, "text/plain")
            .body(r#"{"enabled":true}"#)
            .send()
            .await
            .unwrap();
        assert_eq!(plain.status(), 415);
        assert!(
            !pair
                .db
                .builtin_agent("claude-builtin")
                .unwrap()
                .unwrap()
                .enabled
        );
        // With JSON the same route works, and the new switch is kept.
        let saved = http
            .put(format!("{base}/admin/api/builtin/claude-builtin"))
            .header(header::COOKIE, &owner)
            .json(&serde_json::json!({ "read_other_services": true, "model": "-x" }))
            .send()
            .await
            .unwrap();
        assert_eq!(saved.status(), 400, "a model starting with - is refused");
        let saved: serde_json::Value = http
            .put(format!("{base}/admin/api/builtin/claude-builtin"))
            .header(header::COOKIE, &owner)
            .json(&serde_json::json!({ "read_other_services": true }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(saved["agent"]["read_other_services"], true);
        assert!(
            pair.db
                .builtin_agent("claude-builtin")
                .unwrap()
                .unwrap()
                .read_other_services
        );
        let list = |cookie: String| {
            let http = http.clone();
            let base = base.clone();
            async move {
                http.get(format!("{base}/admin/api/builtin"))
                    .header(header::COOKIE, cookie)
                    .send()
                    .await
                    .unwrap()
                    .json::<serde_json::Value>()
                    .await
                    .unwrap()
            }
        };
        let seen = list(viewer.clone()).await;
        assert!(seen["agents"][0]["status_detail"].is_null(), "{seen}");
        assert!(!seen.to_string().contains("owner@example.com"));
        let seen = list(owner.clone()).await;
        assert!(seen.to_string().contains("owner@example.com"));
        let output = http
            .get(format!("{base}/admin/api/builtin/runs/r1/events"))
            .header(header::COOKIE, &viewer)
            .send()
            .await
            .unwrap();
        assert_eq!(output.status(), 403);

        // The live stream: a viewer hears that a run started and ended,
        // never a line of its output or the summary of its end.
        let stream = |cookie: String| {
            let http = http.clone();
            let base = base.clone();
            async move {
                http.get(format!("{base}/admin/api/events"))
                    .header(header::COOKIE, cookie)
                    .send()
                    .await
                    .unwrap()
            }
        };
        let mut seen_by_viewer = stream(viewer).await;
        let mut seen_by_owner = stream(owner).await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        events.publish_run(serde_json::json!({
            "type": "output", "run_id": "r1", "agent": "claude-builtin",
            "seq": 1, "stream": "text", "line": "secret-looking output line",
        }));
        events.publish_run(serde_json::json!({
            "type": "ended", "run_id": "r1", "agent": "claude-builtin",
            "status": "failed", "summary": "the last words of the run",
        }));
        async fn read(response: &mut reqwest::Response) -> String {
            let mut text = String::new();
            while !text.contains("\"ended\"") {
                let chunk = tokio::time::timeout(WAIT, response.chunk())
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap();
                text.push_str(&String::from_utf8_lossy(&chunk));
            }
            text
        }
        let viewer_text = read(&mut seen_by_viewer).await;
        assert!(
            !viewer_text.contains("secret-looking output line"),
            "{viewer_text}"
        );
        assert!(
            !viewer_text.contains("the last words of the run"),
            "{viewer_text}"
        );
        let owner_text = read(&mut seen_by_owner).await;
        assert!(
            owner_text.contains("secret-looking output line"),
            "{owner_text}"
        );
        assert!(
            owner_text.contains("the last words of the run"),
            "{owner_text}"
        );
    }
}
