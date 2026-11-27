//! lore's side of the runner link: the built-in agents' runners dial in
//! to `/runner/ws` on a separate internal listener (`LORE_RUNNER_BIND`,
//! never published), authenticate with their runner secret from
//! `LORE_RUNNER_TOKENS`, and then take commands. The hub keeps one link
//! per agent, routes answers to whoever asked, and records what the
//! runners report (connection, CLI version, sign-in state) in
//! `builtin_agents`. It never stores or logs a credential: a pasted token
//! passes through it to the runner and is dropped. Terminal bytes (part
//! 6d) pass through it between a runner and the one admin window that
//! shows a session, and are never stored or logged either: the recent
//! screen of each running session is kept in memory only (`replay`), for
//! the next window that attaches, and dropped when the session ends.
//!
//! Without `LORE_RUNNER_TOKENS` there is no hub, no listener and no route:
//! lore behaves as it did before built-in agents existed.

mod replay;

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
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
/// falls this far behind is detached (the session goes on).
const TERMINAL_BACKLOG: usize = 1024;

/// A terminal session nobody looks at ends after this long without output
/// (`LORE_TERMINAL_IDLE_MINUTES`).
pub const TERMINAL_IDLE: Duration = Duration::from_secs(30 * 60);

/// A terminal session ends after this long whatever happens in it
/// (`LORE_TERMINAL_MAX_HOURS`): a program that keeps drawing, or a tab
/// left open, does not hold the container, its sign-in and its token
/// forever.
pub const TERMINAL_MAX_AGE: Duration = Duration::from_secs(12 * 3600);

/// The window showing a session says this long before its maximum age
/// when it will end.
const TERMINAL_AGE_WARNING: Duration = Duration::from_secs(10 * 60);

/// How often lore looks at every terminal session: the idle limit, and
/// whether the user who opened it may still have it.
const TERMINAL_WATCH: Duration = Duration::from_secs(30);

/// A page says every minute that it is shown; a viewer silent this long is
/// taken as not looking (a hidden tab, a sleeping laptop).
const TERMINAL_LOOKING: Duration = Duration::from_secs(150);

/// Between the two resizes that make a program draw its screen again
/// after a page attached: long enough for it to read the first size.
const TERMINAL_REDRAW_PAUSE: Duration = Duration::from_millis(400);

/// What the activity feed names lore's own notes by (as the admin page's).
const ACTIVITY_ACTOR: &str = "admin";

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
    /// The session the page meant to resume has ended (and no new one is
    /// started without the owner asking).
    Ended(EndedSession),
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
                "this agent already has two terminals open; end one first"
            }
            HubError::Ended(ended) => return write!(f, "the session ended: {}", ended.message),
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

/// What a terminal's page hears.
#[derive(Debug, PartialEq, Eq)]
pub enum TerminalEvent {
    Output(Vec<u8>),
    /// The session reaches its maximum age at this unix time.
    EndsSoon {
        at: i64,
    },
    /// The session ended.
    Exit {
        code: Option<i32>,
        message: Option<String>,
    },
    /// Another window attached to the session: this one no longer shows
    /// it.
    TakenOver {
        by: String,
    },
}

/// Who opened a terminal session. While it lives lore checks that this
/// user still exists, still has the `agents` permission and is not
/// disabled; the built-in `admin` always may.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opener {
    pub username: String,
    /// The stored user's id; `None` for the built-in `admin`.
    pub user_id: Option<i64>,
}

/// The one page that shows a session now.
struct Viewer {
    id: u64,
    user: String,
    tx: mpsc::Sender<TerminalEvent>,
    /// When the page last said it is shown (or typed, or attached).
    alive: Instant,
}

/// A terminal session: a PTY in an agent's container that lives on while
/// no page shows it. For the CLI's interface it holds the hash of its lore
/// token (see `terminal_token_agent`); forgetting the session revokes the
/// token.
struct Terminal {
    agent: String,
    mode: TerminalMode,
    token_hash: Option<String>,
    opener: Opener,
    /// Unix seconds.
    started_at: i64,
    /// For the maximum age.
    started: Instant,
    /// The window showing it was told when it ends.
    warned: bool,
    last_output_at: i64,
    /// The last output, or the last moment someone looked: the idle limit
    /// counts from here.
    quiet_since: Instant,
    /// The recent screen, in memory only.
    replay: replay::Replay,
    viewer: Option<Viewer>,
}

impl Terminal {
    /// When the session reaches the maximum age, in unix seconds.
    fn ends_at(&self, max_age: Duration) -> i64 {
        self.started_at + max_age.as_secs() as i64
    }
}

/// How a session ended, kept (in memory) until a new one of the same kind
/// starts, so the owner who comes back sees why and when.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EndedSession {
    pub mode: TerminalMode,
    /// Unix seconds.
    pub at: i64,
    pub message: String,
    /// A page has been told (it was attached then, or asked since).
    #[serde(skip)]
    seen: bool,
}

/// A running session as the page and the task runner see it.
#[derive(Debug, Clone, Serialize)]
pub struct SessionView {
    pub mode: TerminalMode,
    pub started_at: i64,
    pub last_output_at: i64,
    pub opened_by: String,
    /// Who shows it in a window now, if anyone.
    pub viewer: Option<String>,
}

/// What a page asks for when it opens a terminal window.
pub struct AttachRequest {
    pub agent: String,
    pub mode: TerminalMode,
    pub cols: u16,
    pub rows: u16,
    pub model: Option<String>,
    pub opener: Opener,
    /// Start a new session when none runs, even right after one ended.
    pub fresh: bool,
}

/// A page attached to a session.
pub struct Attached {
    pub term_id: String,
    pub viewer: u64,
    pub events: mpsc::Receiver<TerminalEvent>,
    /// A new session was started for this page.
    pub started: bool,
    /// For a session that was running: its recent screen.
    pub replay: Vec<u8>,
    pub started_at: i64,
    /// When it reaches the maximum age (unix seconds), and whether that
    /// is close enough to say so now.
    pub ends_at: i64,
    pub ends_soon: bool,
    pub opened_by: String,
    /// The window it was taken from, by user name.
    pub taken_from: Option<String>,
}

/// Where a page stands after its events stopped.
#[derive(Debug, PartialEq, Eq)]
pub enum ViewerState {
    /// It still shows the session.
    Current,
    /// The session runs; another window shows it (by this user), or none
    /// does (the page fell behind and was detached).
    Elsewhere(Option<String>),
    /// The session ended.
    Ended(Option<EndedSession>),
}

/// What lore calls each kind of terminal in the activity feed.
fn what(mode: TerminalMode) -> &'static str {
    match mode {
        TerminalMode::Cli => "the CLI's terminal",
        TerminalMode::Shell => "a shell",
    }
}

pub fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0)
}

/// `10:42 UTC`.
pub fn clock(unix: i64) -> String {
    let minute = unix.rem_euclid(86_400) / 60;
    format!("{:02}:{:02} UTC", minute / 60, minute % 60)
}

fn hours(duration: Duration) -> String {
    match duration.as_secs() / 3600 {
        0 => minutes(duration),
        1 => "1 hour".into(),
        hours => format!("{hours} hours"),
    }
}

fn minutes(duration: Duration) -> String {
    let minutes = duration.as_secs() / 60;
    match minutes {
        0 => format!("{} seconds", duration.as_secs()),
        1 => "1 minute".into(),
        _ => format!("{minutes} minutes"),
    }
}

/// What the opener check found.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Verdict {
    Allowed,
    /// Why the user may no longer have the session.
    Gone(String),
    /// The database could not be asked.
    Unknown,
}

/// Opener checks in a row that could not reach the database before the
/// sessions they could not check end (about 90 seconds).
const OPENER_CHECK_FAILURES: u32 = 3;

/// Whether the user who opened a session may still have it: the same user
/// (by id and by the name recorded at open, so a restored database with
/// another user at that id does not count), not disabled, with `agents`.
fn opener_gone(db: &Db, opener: &Opener) -> Verdict {
    let Some(id) = opener.user_id else {
        return if opener.username == crate::users::ADMIN_USER {
            Verdict::Allowed
        } else {
            Verdict::Gone(format!(
                "{} is not a user who may open a terminal",
                opener.username
            ))
        };
    };
    match db.user(id) {
        Ok(None) => Verdict::Gone(format!("{}, who opened it, was deleted", opener.username)),
        Ok(Some(user)) if user.username != opener.username => Verdict::Gone(format!(
            "{}, who opened it, is no longer that account (the database changed)",
            opener.username
        )),
        Ok(Some(user)) if user.disabled => {
            Verdict::Gone(format!("{}, who opened it, was disabled", opener.username))
        }
        Ok(Some(user)) if !user.perms().contains(crate::users::Perm::Agents) => {
            Verdict::Gone(format!(
                "{}, who opened it, no longer has the agents permission",
                opener.username
            ))
        }
        Ok(Some(_)) => Verdict::Allowed,
        Err(error) => {
            tracing::warn!(%error, "checking who opened a terminal failed; checked again shortly");
            Verdict::Unknown
        }
    }
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
    /// The last ended session per agent and kind.
    ended: HashMap<(String, TerminalMode), EndedSession>,
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
    /// A session nobody looks at ends after this long without output.
    terminal_idle: Duration,
    /// How often the sessions are looked at.
    terminal_watch: Duration,
    /// A session ends after this long, whatever happens in it.
    terminal_max_age: Duration,
    /// Opener checks in a row that could not reach the database.
    opener_failures: std::sync::atomic::AtomicU32,
    /// Makes the next look at the sessions panic, for a test.
    #[cfg(test)]
    watch_panics: AtomicBool,
    /// Set once the watch over the sessions runs.
    watching: AtomicBool,
    /// Where the activity feed's notes are published (the admin page's).
    events: OnceLock<crate::events::Events>,
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
            terminal_idle: TERMINAL_IDLE,
            terminal_watch: TERMINAL_WATCH,
            terminal_max_age: TERMINAL_MAX_AGE,
            opener_failures: std::sync::atomic::AtomicU32::new(0),
            #[cfg(test)]
            watch_panics: AtomicBool::new(false),
            watching: AtomicBool::new(false),
            events: OnceLock::new(),
        }
    }

    /// The idle limit of a terminal session nobody looks at.
    pub fn with_terminal_idle(mut self, idle: Duration) -> Self {
        self.terminal_idle = idle;
        self
    }

    /// The maximum age of a terminal session.
    pub fn with_terminal_max_age(mut self, max_age: Duration) -> Self {
        self.terminal_max_age = max_age;
        self
    }

    /// The maximum age of a terminal session, in whole hours (at least 1
    /// as the page says it).
    pub fn terminal_max_hours(&self) -> u64 {
        (self.terminal_max_age.as_secs() / 3600).max(1)
    }

    /// A shorter look at the sessions, for the tests.
    #[cfg(test)]
    pub fn with_terminal_watch(mut self, every: Duration) -> Self {
        self.terminal_watch = every;
        self
    }

    /// Publishes the activity feed's notes about terminals here.
    pub fn set_events(&self, events: crate::events::Events) {
        let _ = self.events.set(events);
    }

    /// One line in the activity feed. Never terminal content: who, which
    /// agent, which kind, what happened.
    fn note(&self, summary: &str) {
        match self
            .db
            .record_activity(ACTIVITY_ACTOR, "builtin", "", None, None, &[], summary)
        {
            Ok(activity) => {
                if let Some(events) = self.events.get() {
                    events.publish(activity);
                }
            }
            Err(error) => tracing::warn!(%error, "noting a terminal in the activity feed failed"),
        }
    }

    /// The message that tells a Claude runner the owner's order and
    /// fallback of its credentials (NULL: the subscription first, no
    /// fallback).
    fn claude_prefs(&self, agent: &str) -> Option<ToRunner> {
        let stored = self.db.builtin_agent(agent).ok().flatten()?;
        Some(ToRunner::ClaudeCredentials {
            priority: stored
                .claude_priority
                .unwrap_or_else(|| "subscription".into()),
            fallback: stored.claude_fallback.unwrap_or(false),
        })
    }

    /// Sends the agent's runner its Claude credential choice again, after
    /// the owner changed it: waits for room on the link rather than drop
    /// it (a runner that is not connected gets it when it connects).
    pub async fn send_claude_prefs(&self, agent: &str) {
        let Some(prefs) = self.claude_prefs(agent) else {
            return;
        };
        let link = self.inner().links.get(agent).map(|link| link.tx.clone());
        if let Some(link) = link
            && link.send(prefs).await.is_err()
        {
            tracing::warn!(%agent, "the runner's link closed before it heard the credential order");
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

    /// Starts the watch over the terminal sessions once: every
    /// `terminal_watch` it ends a session nobody looks at that printed
    /// nothing for `terminal_idle`, and one whose opener may no longer
    /// have it. It stops when the hub goes.
    fn watch_terminals(self: &Arc<Self>) {
        if self.watching.swap(true, Ordering::SeqCst) {
            return;
        }
        let hub = Arc::downgrade(self);
        let every = self.terminal_watch;
        tokio::spawn(async move {
            /// Lets the next attach start the watch again, however this
            /// one ends.
            struct Stopped(std::sync::Weak<Hub>);
            impl Drop for Stopped {
                fn drop(&mut self) {
                    if let Some(hub) = self.0.upgrade() {
                        hub.watching.store(false, Ordering::SeqCst);
                    }
                }
            }
            let _stopped = Stopped(hub.clone());
            loop {
                let weak = hub.clone();
                let run = tokio::spawn(async move {
                    let mut tick = tokio::time::interval(every);
                    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                    tick.tick().await;
                    loop {
                        tick.tick().await;
                        let Some(hub) = weak.upgrade() else {
                            return;
                        };
                        hub.check_terminals().await;
                    }
                });
                match run.await {
                    // The hub went.
                    Ok(()) => return,
                    Err(error) if error.is_panic() => {
                        tracing::error!(
                            "the watch over the terminal sessions (idle limit, maximum age, \
                             opener check) panicked; starting it again"
                        );
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        if hub.upgrade().is_none() {
                            return;
                        }
                    }
                    Err(_) => return,
                }
            }
        });
    }

    /// One look at every session: the maximum age and its warning, the
    /// idle limit, a keep-alive for older runners, then the openers.
    async fn check_terminals(&self) {
        #[cfg(test)]
        if self.watch_panics.swap(false, Ordering::SeqCst) {
            panic!("a panic the tests asked for");
        }
        let now = Instant::now();
        let mut idle = Vec::new();
        let mut old = Vec::new();
        let mut openers = Vec::new();
        let mut keep_alive = Vec::new();
        {
            let mut inner = self.inner();
            let links: HashMap<String, mpsc::Sender<ToRunner>> = inner
                .links
                .iter()
                .map(|(agent, link)| (agent.clone(), link.tx.clone()))
                .collect();
            for (id, terminal) in inner.terminals.iter_mut() {
                let age = now.duration_since(terminal.started);
                if age >= self.terminal_max_age {
                    old.push(id.clone());
                    continue;
                }
                if !terminal.warned
                    && age + TERMINAL_AGE_WARNING >= self.terminal_max_age
                    && let Some(viewer) = &terminal.viewer
                    && viewer
                        .tx
                        .try_send(TerminalEvent::EndsSoon {
                            at: terminal.ends_at(self.terminal_max_age),
                        })
                        .is_ok()
                {
                    terminal.warned = true;
                }
                let looking = terminal
                    .viewer
                    .as_ref()
                    .is_some_and(|viewer| now.duration_since(viewer.alive) < TERMINAL_LOOKING);
                if looking {
                    terminal.quiet_since = now;
                } else if now.duration_since(terminal.quiet_since) >= self.terminal_idle {
                    idle.push(id.clone());
                    continue;
                }
                openers.push((id.clone(), terminal.opener.clone()));
                // A runner built before lore kept the idle limit closes a
                // terminal after 15 minutes without input; an empty input
                // counts as input there and types nothing (in this runner
                // as in that one), so a session lore keeps stays.
                if let Some(link) = links.get(&terminal.agent) {
                    keep_alive.push((link.clone(), id.clone()));
                }
            }
        }
        for (link, term_id) in keep_alive {
            let _ = link.try_send(ToRunner::TerminalInput {
                term_id,
                data: String::new(),
            });
        }
        for id in old {
            self.end_terminal(
                &id,
                None,
                format!(
                    "it reached the maximum age of a terminal session, {}",
                    hours(self.terminal_max_age)
                ),
            );
        }
        for id in idle {
            self.end_terminal(
                &id,
                None,
                format!(
                    "it printed nothing for {} while nobody was looking",
                    minutes(self.terminal_idle)
                ),
            );
        }
        if openers.is_empty() {
            return;
        }
        let db = self.db.clone();
        let verdicts = tokio::task::spawn_blocking(move || {
            let mut checked: HashMap<(String, Option<i64>), Verdict> = HashMap::new();
            openers
                .into_iter()
                .map(|(id, opener)| {
                    let verdict = checked
                        .entry((opener.username.clone(), opener.user_id))
                        .or_insert_with(|| opener_gone(&db, &opener))
                        .clone();
                    (id, verdict)
                })
                .collect::<Vec<_>>()
        })
        .await
        .unwrap_or_default();
        let failed = verdicts
            .iter()
            .any(|(_, verdict)| matches!(verdict, Verdict::Unknown));
        let failures = if failed {
            self.opener_failures.fetch_add(1, Ordering::SeqCst) + 1
        } else {
            self.opener_failures.store(0, Ordering::SeqCst);
            0
        };
        for (id, verdict) in verdicts {
            match verdict {
                Verdict::Allowed => {}
                Verdict::Gone(why) => {
                    self.end_terminal(&id, None, why);
                }
                Verdict::Unknown if failures >= OPENER_CHECK_FAILURES => {
                    tracing::error!(
                        term_id = %id,
                        failures,
                        "lore could not check who opened a terminal session; ending it"
                    );
                    self.end_terminal(
                        &id,
                        None,
                        "lore could not check, several times in a row, that the user who opened \
                         it may still have it (a database error)"
                            .into(),
                    );
                }
                Verdict::Unknown => {}
            }
        }
    }

    /// Opens a terminal window for one page: attaches it to the agent's
    /// running session of that kind (taking it from another window), or
    /// starts one. A page that meant to resume (`fresh` false) a session
    /// that has ended since hears why and when, once, instead of getting a
    /// new one.
    pub async fn terminal_attach(
        self: &Arc<Self>,
        request: AttachRequest,
    ) -> Result<Attached, HubError> {
        self.watch_terminals();
        let AttachRequest {
            agent,
            mode,
            cols,
            rows,
            model,
            opener,
            fresh,
        } = request;
        let viewer_id = self.next_id();
        let (tx, rx) = mpsc::channel(TERMINAL_BACKLOG);
        let now = Instant::now();
        let viewer = Viewer {
            id: viewer_id,
            user: opener.username.clone(),
            tx,
            alive: now,
        };
        let (link, term_id, open, started_at) = {
            let mut inner = self.inner();
            let Some(link) = inner.links.get(&agent) else {
                return Err(HubError::NotConnected);
            };
            let link = link.tx.clone();
            if let Some((id, terminal)) = inner
                .terminals
                .iter_mut()
                .find(|(_, terminal)| terminal.agent == agent && terminal.mode == mode)
            {
                let taken_from = terminal.viewer.replace(viewer).map(|previous| {
                    let _ = previous.tx.try_send(TerminalEvent::TakenOver {
                        by: opener.username.clone(),
                    });
                    previous.user
                });
                terminal.quiet_since = now;
                let ends_soon = now.duration_since(terminal.started) + TERMINAL_AGE_WARNING
                    >= self.terminal_max_age;
                let attached = Attached {
                    term_id: id.clone(),
                    viewer: viewer_id,
                    events: rx,
                    started: false,
                    replay: terminal.replay.snapshot(),
                    started_at: terminal.started_at,
                    ends_at: terminal.ends_at(self.terminal_max_age),
                    ends_soon,
                    opened_by: terminal.opener.username.clone(),
                    taken_from,
                };
                drop(inner);
                self.note(&match &attached.taken_from {
                    Some(from) if *from != opener.username => format!(
                        "{} took over {} in {agent} from {from}",
                        opener.username,
                        what(mode)
                    ),
                    Some(_) => format!(
                        "{} moved {} in {agent} to another window",
                        opener.username,
                        what(mode)
                    ),
                    None => format!("{} resumed {} in {agent}", opener.username, what(mode)),
                });
                return Ok(attached);
            }
            let key = (agent.clone(), mode);
            if !fresh
                && let Some(ended) = inner.ended.get_mut(&key)
                && !ended.seen
            {
                ended.seen = true;
                return Err(HubError::Ended(ended.clone()));
            }
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
            let term_id = format!("t{}", self.next_id());
            let started_at = unix_now();
            inner.ended.remove(&key);
            inner.terminals.insert(
                term_id.clone(),
                Terminal {
                    agent: agent.clone(),
                    mode,
                    token_hash: token
                        .as_ref()
                        .map(|(_, token)| crate::oauth::token_hash(token)),
                    opener: opener.clone(),
                    started_at,
                    started: now,
                    warned: false,
                    last_output_at: started_at,
                    quiet_since: now,
                    replay: replay::Replay::default(),
                    viewer: Some(viewer),
                },
            );
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
            (link, term_id, open, started_at)
        };
        if link.send(open).await.is_err() {
            self.inner().terminals.remove(&term_id);
            return Err(HubError::Closed);
        }
        self.note(&format!(
            "{} opened {} in {agent}",
            opener.username,
            what(mode)
        ));
        Ok(Attached {
            term_id,
            viewer: viewer_id,
            events: rx,
            started: true,
            replay: Vec::new(),
            started_at,
            ends_at: started_at + self.terminal_max_age.as_secs() as i64,
            ends_soon: false,
            opened_by: opener.username,
            taken_from: None,
        })
    }

    /// The link of the session `term_id` when `viewer` is the page that
    /// shows it; `touch` marks that page as looking.
    fn viewer_link(
        &self,
        term_id: &str,
        viewer: u64,
        touch: bool,
    ) -> Result<mpsc::Sender<ToRunner>, HubError> {
        let mut inner = self.inner();
        let Some(terminal) = inner.terminals.get_mut(term_id) else {
            return Err(HubError::Closed);
        };
        let agent = terminal.agent.clone();
        match terminal.viewer.as_mut() {
            Some(current) if current.id == viewer => {
                if touch {
                    current.alive = Instant::now();
                    terminal.quiet_since = current.alive;
                }
            }
            _ => return Err(HubError::Closed),
        }
        inner
            .links
            .get(&agent)
            .map(|link| link.tx.clone())
            .ok_or(HubError::NotConnected)
    }

    /// Sends what the page showing a session typed or its new size to the
    /// runner. Only the page that shows the session now may.
    pub async fn terminal_send(
        &self,
        term_id: &str,
        viewer: u64,
        command: ToRunner,
    ) -> Result<(), HubError> {
        let link = self.viewer_link(term_id, viewer, true)?;
        link.send(command).await.map_err(|_| HubError::Closed)
    }

    /// Makes a program draw its whole screen again for a page that just
    /// attached: the size goes one column off and back, so the program
    /// gets a window change it cannot ignore even when the size is the
    /// one it had.
    pub async fn terminal_redraw(
        &self,
        term_id: &str,
        viewer: u64,
        cols: u16,
        rows: u16,
    ) -> Result<(), HubError> {
        let nudge = if cols > 20 { cols - 1 } else { cols + 1 };
        let resize = |cols| ToRunner::TerminalResize {
            term_id: term_id.to_string(),
            cols,
            rows,
        };
        self.terminal_send(term_id, viewer, resize(nudge)).await?;
        tokio::time::sleep(TERMINAL_REDRAW_PAUSE).await;
        self.terminal_send(term_id, viewer, resize(cols)).await
    }

    /// The page went (hidden, closed, reloaded, its connection dropped):
    /// the session goes on without it. Answers whether it was the page
    /// showing the session.
    pub fn terminal_detach(&self, term_id: &str, viewer: u64, why: &str) -> bool {
        let note = {
            let mut inner = self.inner();
            let Some(terminal) = inner.terminals.get_mut(term_id) else {
                return false;
            };
            if terminal
                .viewer
                .as_ref()
                .is_none_or(|current| current.id != viewer)
            {
                return false;
            }
            let gone = terminal.viewer.take();
            terminal.quiet_since = Instant::now();
            format!(
                "{} left {} in {} running{why}",
                gone.map(|viewer| viewer.user).unwrap_or_default(),
                what(terminal.mode),
                terminal.agent
            )
        };
        self.note(&note);
        true
    }

    /// Ends a session: forgets it (which revokes its token), keeps how it
    /// ended, tells its page and has the runner kill its whole session.
    /// With `viewer`, only the page that shows it may.
    pub fn end_terminal(&self, term_id: &str, viewer: Option<u64>, message: String) -> bool {
        let (link, note) = {
            let mut inner = self.inner();
            let Some(terminal) = inner.terminals.get(term_id) else {
                return false;
            };
            if let Some(viewer) = viewer
                && terminal
                    .viewer
                    .as_ref()
                    .is_none_or(|current| current.id != viewer)
            {
                return false;
            }
            let Some(terminal) = inner.terminals.remove(term_id) else {
                return false;
            };
            let link = inner.links.get(&terminal.agent).map(|link| link.tx.clone());
            let note = self.ended_locked(&mut inner, terminal, None, message);
            (link, note)
        };
        if let Some(link) = link {
            let close = ToRunner::TerminalClose {
                term_id: term_id.to_string(),
            };
            if let Err(mpsc::error::TrySendError::Full(close)) = link.try_send(close) {
                tokio::spawn(async move {
                    let _ = link.send(close).await;
                });
            }
        }
        self.note(&note);
        true
    }

    /// Keeps how a session that was just taken out of the map ended and
    /// tells its page; answers the activity note.
    fn ended_locked(
        &self,
        inner: &mut Inner,
        terminal: Terminal,
        code: Option<i32>,
        message: String,
    ) -> String {
        let at = unix_now();
        let seen = terminal.viewer.as_ref().is_some_and(|viewer| {
            viewer
                .tx
                .try_send(TerminalEvent::Exit {
                    code,
                    message: Some(message.clone()),
                })
                .is_ok()
        });
        let note = format!(
            "{} in {} ended: {message}",
            what(terminal.mode),
            terminal.agent
        );
        inner.ended.insert(
            (terminal.agent, terminal.mode),
            EndedSession {
                mode: terminal.mode,
                at,
                message,
                seen,
            },
        );
        let mut note = note;
        if let Some(first) = note.get(..1) {
            note = first.to_uppercase() + &note[1..];
        }
        note
    }

    /// Where a page stands whose events stopped coming.
    pub fn terminal_viewer_state(
        &self,
        term_id: &str,
        viewer: u64,
        agent: &str,
        mode: TerminalMode,
    ) -> ViewerState {
        let inner = self.inner();
        match inner.terminals.get(term_id) {
            Some(terminal) => match &terminal.viewer {
                Some(current) if current.id == viewer => ViewerState::Current,
                Some(other) => ViewerState::Elsewhere(Some(other.user.clone())),
                None => ViewerState::Elsewhere(None),
            },
            None => ViewerState::Ended(inner.ended.get(&(agent.to_string(), mode)).cloned()),
        }
    }

    /// The agent's running sessions.
    pub fn terminal_sessions(&self, agent: &str) -> Vec<SessionView> {
        let inner = self.inner();
        let mut sessions: Vec<SessionView> = inner
            .terminals
            .values()
            .filter(|terminal| terminal.agent == agent)
            .map(|terminal| SessionView {
                mode: terminal.mode,
                started_at: terminal.started_at,
                last_output_at: terminal.last_output_at,
                opened_by: terminal.opener.username.clone(),
                viewer: terminal.viewer.as_ref().map(|viewer| viewer.user.clone()),
            })
            .collect();
        sessions.sort_by_key(|session| session.started_at);
        sessions
    }

    /// How the agent's last sessions of each kind ended, while no new one
    /// of that kind runs.
    pub fn terminal_ended(&self, agent: &str) -> Vec<EndedSession> {
        let inner = self.inner();
        let mut ended: Vec<EndedSession> = inner
            .ended
            .iter()
            .filter(|((name, _), _)| name == agent)
            .map(|(_, ended)| ended.clone())
            .collect();
        ended.sort_by_key(|ended| ended.at);
        ended
    }

    /// Since when a terminal session holds the agent's container (the
    /// oldest one), or `None`: a run does not start while one is open.
    pub fn terminal_busy(&self, agent: &str) -> Option<i64> {
        self.inner()
            .terminals
            .values()
            .filter(|terminal| terminal.agent == agent)
            .map(|terminal| terminal.started_at)
            .min()
    }

    /// How many terminals are open, in every agent.
    #[cfg(test)]
    pub fn terminal_count(&self) -> usize {
        self.inner().terminals.len()
    }

    /// The built-in agent a terminal token speaks for: the token belongs
    /// to a session running right now (shown in a window or not), and the
    /// request comes from the address that agent's runner is connected
    /// from (its container). An ended session, a dropped link or another
    /// address: none.
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

    /// Terminal bytes from a runner: kept for the next page that attaches
    /// and passed to the page showing the session, if any. Only the runner
    /// the session was opened in may write to it.
    fn on_terminal_output(&self, agent: &str, term_id: &str, data: &str) {
        let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(data.as_bytes()) else {
            return;
        };
        let note = {
            let mut inner = self.inner();
            let Some(terminal) = inner.terminals.get_mut(term_id) else {
                return;
            };
            if terminal.agent != agent {
                return;
            }
            terminal.replay.push(&bytes);
            terminal.last_output_at = unix_now();
            terminal.quiet_since = Instant::now();
            let behind = terminal
                .viewer
                .as_ref()
                .is_some_and(|viewer| viewer.tx.try_send(TerminalEvent::Output(bytes)).is_err());
            if !behind {
                return;
            }
            // The page does not keep up (or went): it is detached rather
            // than holding up the agent's whole link; the session goes on.
            let gone = terminal.viewer.take();
            tracing::info!(%agent, %term_id, "a terminal's page fell behind; detached it");
            format!(
                "{} left {} in {agent} running (the window fell behind)",
                gone.map(|viewer| viewer.user).unwrap_or_default(),
                what(terminal.mode)
            )
        };
        self.note(&note);
    }

    /// A session ended in the container: the program exited, or it could
    /// not be started.
    fn on_terminal_exit(
        &self,
        agent: &str,
        term_id: &str,
        code: Option<i32>,
        message: Option<String>,
    ) {
        let note = {
            let mut inner = self.inner();
            if !inner
                .terminals
                .get(term_id)
                .is_some_and(|terminal| terminal.agent == agent)
            {
                return;
            }
            let Some(terminal) = inner.terminals.remove(term_id) else {
                return;
            };
            let message = message.unwrap_or_else(|| {
                let program = match terminal.mode {
                    TerminalMode::Cli => "the CLI",
                    TerminalMode::Shell => "the shell",
                };
                match code {
                    Some(code) => format!("{program} exited (exit code {code})"),
                    None => format!("{program} exited"),
                }
            });
            self.ended_locked(&mut inner, terminal, code, message)
        };
        self.note(&note);
    }

    /// Ends every session of an agent whose link went (replaced, or
    /// closed): their PTYs died with the runner's session, and their tokens
    /// must not outlive it.
    fn end_link_terminals(&self, inner: &mut Inner, agent: &str, message: &str) -> Vec<String> {
        let gone: Vec<String> = inner
            .terminals
            .iter()
            .filter(|(_, terminal)| terminal.agent == agent)
            .map(|(id, _)| id.clone())
            .collect();
        let mut notes = Vec::new();
        for id in gone {
            if let Some(terminal) = inner.terminals.remove(&id) {
                notes.push(self.ended_locked(inner, terminal, None, message.to_string()));
            }
        }
        notes
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
        let ended = {
            let mut inner = self.inner();
            // A replaced link takes its terminal sessions with it: their
            // PTYs died with the old runner session, and their tokens must
            // not outlive it. Their pages hear why.
            let ended = if inner.links.contains_key(&agent) {
                self.end_link_terminals(&mut inner, &agent, "the agent's runner reconnected")
            } else {
                Vec::new()
            };
            inner.links.insert(
                agent.clone(),
                Link {
                    generation,
                    tx: tx.clone(),
                    kind,
                    provider: provider.clone(),
                    address: address.parse().ok().map(plain_ip),
                },
            );
            // The owner's choice of Claude's credentials, before anything
            // else the runner hears.
            if kind == Kind::Claude
                && let Some(prefs) = self.claude_prefs(&agent)
            {
                let _ = tx.try_send(prefs);
            }
            ended
        };
        for note in ended {
            self.note(&note);
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
        let (current, ended) = {
            let mut inner = self.inner();
            let current = inner
                .links
                .get(&agent)
                .is_some_and(|link| link.generation == generation);
            let mut ended = Vec::new();
            if current {
                inner.links.remove(&agent);
                inner.resources.remove(&agent);
                // Its terminal sessions died with the runner's session.
                ended = self.end_link_terminals(
                    &mut inner,
                    &agent,
                    "the agent's container disconnected",
                );
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
            (current, ended)
        };
        for note in ended {
            self.note(&note);
        }
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
        listen_tuned(None).await
    }

    /// The same, with a short terminal idle limit and a quick watch.
    async fn listen_tuned(idle: Option<Duration>) -> Pair {
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
        let mut hub = Hub::new(db.clone(), tokens).with_mcp_url("http://127.0.0.1:9/mcp".into());
        if let Some(idle) = idle {
            hub = hub
                .with_terminal_idle(idle)
                .with_terminal_watch(Duration::from_millis(100));
        }
        let hub = Arc::new(hub);
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

    /// The built-in admin, as the one who opens a session.
    fn owner() -> Opener {
        Opener {
            username: "admin".into(),
            user_id: None,
        }
    }

    /// A new session straight through the hub, as the owner's page would
    /// open it.
    async fn open_session(hub: &Arc<Hub>, agent: &str, mode: TerminalMode) -> Attached {
        hub.terminal_attach(AttachRequest {
            agent: agent.into(),
            mode,
            cols: 80,
            rows: 24,
            model: None,
            opener: owner(),
            fresh: true,
        })
        .await
        .unwrap_or_else(|error| panic!("{error}"))
    }

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
            .request(
                "claude-builtin",
                |id| ToRunner::Status { id, check: false },
                WAIT,
            )
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
            .request(
                "claude-builtin",
                |id| ToRunner::Status { id, check: false },
                WAIT,
            )
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
                .request(
                    "claude-builtin",
                    |id| ToRunner::Status { id, check: false },
                    WAIT
                )
                .await,
            Err(HubError::NotConnected)
        ));
    }

    /// A runner that dials again while its old link still sits in the hub
    /// (dead, not yet noticed) replaces it, and the old link's terminals go
    /// with it: their pages hear why and their tokens stop working.
    #[tokio::test]
    async fn a_replaced_link_closes_its_terminals_and_their_tokens() {
        use crate::auth::{Authenticated, McpAuth, Refused};
        let pair = listen().await;
        let token = new_terminal_token().unwrap();
        let (page_tx, mut page_rx) = mpsc::channel(8);
        {
            let (dead_tx, dead_rx) = mpsc::channel(1);
            drop(dead_rx);
            let mut inner = pair.hub.inner();
            inner.links.insert(
                "claude-builtin".into(),
                Link {
                    generation: 0,
                    tx: dead_tx,
                    kind: Kind::Claude,
                    provider: "anthropic".into(),
                    address: Some("127.0.0.1".parse().unwrap()),
                },
            );
            inner.terminals.insert(
                "t-old".into(),
                Terminal {
                    agent: "claude-builtin".into(),
                    mode: TerminalMode::Cli,
                    token_hash: Some(crate::oauth::token_hash(&token)),
                    opener: owner(),
                    started_at: unix_now(),
                    started: Instant::now(),
                    warned: false,
                    last_output_at: unix_now(),
                    quiet_since: Instant::now(),
                    replay: replay::Replay::default(),
                    viewer: Some(Viewer {
                        id: 1,
                        user: "admin".into(),
                        tx: page_tx,
                        alive: Instant::now(),
                    }),
                },
            );
        }
        let mut auth = McpAuth::new(Vec::new(), pair.db.clone(), false);
        auth.terminals = Some(pair.hub.clone());
        let local: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        assert_eq!(
            auth.authenticate_terminal(&token, true, Some(local)).await,
            Ok(Authenticated::Terminal("claude-builtin".into()))
        );
        start(config(&pair, "claude-builtin", Kind::Claude, CLAUDE_SECRET));
        let exit = tokio::time::timeout(WAIT, page_rx.recv()).await.unwrap();
        assert!(
            matches!(&exit, Some(TerminalEvent::Exit { message: Some(why), .. }) if why.contains("reconnected")),
            "{exit:?}"
        );
        assert_eq!(pair.hub.terminal_count(), 0);
        assert_eq!(
            pair.hub.terminal_ended("claude-builtin")[0].message,
            "the agent's runner reconnected"
        );
        assert_eq!(
            auth.authenticate_terminal(&token, true, Some(local)).await,
            Err(Refused::Invalid)
        );
    }

    #[tokio::test]
    async fn a_closed_link_is_noticed_and_a_new_one_replaces_it() {
        let pair = listen().await;
        let first = start(config(&pair, "claude-builtin", Kind::Claude, CLAUDE_SECRET));
        connected(&pair.hub, "claude-builtin").await;
        // A terminal session dies with the link.
        let mut session = open_session(&pair.hub, "claude-builtin", TerminalMode::Shell).await;
        first.abort();
        let exit = tokio::time::timeout(WAIT, async {
            loop {
                match session.events.recv().await {
                    Some(TerminalEvent::Output(_)) => continue,
                    other => return other,
                }
            }
        })
        .await
        .unwrap();
        assert!(
            matches!(&exit, Some(TerminalEvent::Exit { message: Some(why), .. }) if why == "the agent's container disconnected"),
            "{exit:?}"
        );
        assert_eq!(pair.hub.terminal_count(), 0);
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

    /// The owner gives a built-in agent a display name with the `agents`
    /// permission; it is checked, shown by the page's APIs, and the
    /// technical name stays the identity everywhere.
    #[tokio::test]
    async fn a_built_in_agent_gets_a_display_name_and_keeps_its_name() {
        let pair = listen().await;
        let base = admin_server(&pair).await;
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
        let put = |cookie: &str, name: &str| {
            http.put(format!("{base}/admin/api/agents/claude-builtin"))
                .header(header::COOKIE, cookie.to_string())
                .json(&serde_json::json!({ "display_name": name }))
        };
        assert_eq!(put(&writer, "Claude").send().await.unwrap().status(), 403);
        for bad in [
            "two\nlines",
            &"x".repeat(41),
            "codex-builtin",
            "DEEPSEEK-BUILTIN",
        ] {
            assert_eq!(
                put(&admin, bad).send().await.unwrap().status(),
                400,
                "{bad:?}"
            );
        }
        assert_eq!(
            put(&admin, "  Claude  ").send().await.unwrap().status(),
            200
        );
        let builtin: serde_json::Value = http
            .get(format!("{base}/admin/api/builtin"))
            .header(header::COOKIE, &admin)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let claude = builtin["agents"]
            .as_array()
            .unwrap()
            .iter()
            .find(|agent| agent["display_name"] == "Claude")
            .expect("the display name is shown");
        assert_eq!(claude["name"], "claude-builtin");
        let agents: serde_json::Value = http
            .get(format!("{base}/admin/api/agents"))
            .header(header::COOKIE, &writer)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert!(agents["agents"].as_array().unwrap().iter().any(|agent| {
            agent["name"] == "claude-builtin" && agent["display_name"] == "Claude"
        }));
        // The identity: the hub, the built-in row, the registry row.
        assert!(
            pair.hub
                .agents()
                .iter()
                .any(|name| name == "claude-builtin")
        );
        assert!(pair.db.builtin_agent("claude-builtin").unwrap().is_some());
        assert!(pair.db.registry_agent("Claude").unwrap().is_none());
        assert_eq!(
            pair.db
                .registry_agent("claude-builtin")
                .unwrap()
                .unwrap()
                .kind,
            "builtin"
        );
        // Empty clears it.
        assert_eq!(put(&admin, "").send().await.unwrap().status(), 200);
        assert_eq!(
            pair.db
                .registry_agent("claude-builtin")
                .unwrap()
                .unwrap()
                .display_name,
            None
        );
    }

    /// The terminal's services and Claude's credential order are set on
    /// the card with the `agents` permission only, validated, stored as
    /// NULL for the defaults, and the order reaches the runner.
    #[tokio::test]
    async fn the_terminal_and_credential_settings_need_the_agents_permission() {
        let pair = listen().await;
        let base = admin_server(&pair).await;
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
        let put = |cookie: &str, body: serde_json::Value| {
            http.put(format!("{base}/admin/api/builtin/claude-builtin"))
                .header(header::COOKIE, cookie.to_string())
                .json(&body)
        };
        let row = || pair.db.builtin_agent("claude-builtin").unwrap().unwrap();
        assert_eq!(
            put(&writer, serde_json::json!({"terminal_services": "off"}))
                .send()
                .await
                .unwrap()
                .status(),
            403
        );
        assert_eq!(row().terminal_services, None);
        assert_eq!(
            put(&admin, serde_json::json!({"terminal_services": "full"}))
                .send()
                .await
                .unwrap()
                .status(),
            400
        );
        assert_eq!(
            put(&admin, serde_json::json!({"claude_priority": "both"}))
                .send()
                .await
                .unwrap()
                .status(),
            400
        );
        assert_eq!(
            put(&admin, serde_json::json!({"terminal_services": "read"}))
                .send()
                .await
                .unwrap()
                .status(),
            200
        );
        assert_eq!(row().terminal_services.as_deref(), Some("read"));
        assert_eq!(
            put(
                &admin,
                serde_json::json!({"claude_priority": "api_key", "claude_fallback": true})
            )
            .send()
            .await
            .unwrap()
            .status(),
            200
        );
        assert_eq!(
            (row().claude_priority.as_deref(), row().claude_fallback),
            (Some("api_key"), Some(true))
        );
        let shown: serde_json::Value = http
            .get(format!("{base}/admin/api/builtin"))
            .header(header::COOKIE, &admin)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let claude = shown["agents"]
            .as_array()
            .unwrap()
            .iter()
            .find(|a| a["name"] == "claude-builtin")
            .unwrap();
        assert_eq!(
            (
                claude["terminal_services"].as_str(),
                claude["claude_priority"].as_str()
            ),
            (Some("read"), Some("api_key"))
        );
        assert_eq!(claude["claude_fallback"], true);
        // Back to the defaults: NULL again.
        put(&admin, serde_json::json!({"terminal_services": "same", "claude_priority": "subscription", "claude_fallback": false}))
            .send()
            .await
            .unwrap();
        assert_eq!(
            (
                row().terminal_services,
                row().claude_priority,
                row().claude_fallback
            ),
            (None, None, None)
        );
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

        async fn token_of(
            hub: &Arc<Hub>,
            agent: &str,
            mode: TerminalMode,
        ) -> (String, u64, String) {
            let Attached {
                term_id,
                viewer,
                events: mut rx,
                ..
            } = open_session(hub, agent, mode).await;
            if mode == TerminalMode::Shell {
                // The shell prints it when asked (split, so the echoed
                // command line does not match).
                let typed = "printf 'to%s\\n' \"k:${LORE_AGENT_TOKEN:-none}:\"\r";
                hub.terminal_send(
                    &term_id,
                    viewer,
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
                    return (
                        term_id,
                        viewer,
                        text[start + 4..start + 4 + end].to_string(),
                    );
                }
            }
        }
        let (claude_term, claude_viewer, token) =
            token_of(&pair.hub, "claude-builtin", TerminalMode::Cli).await;
        assert!(looks_like_terminal_token(&token), "{token}");
        let (codex_term, _, codex_token) =
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
        let (shell_term, _, shell_token) =
            token_of(&pair.hub, "claude-builtin", TerminalMode::Shell).await;
        assert_eq!(shell_token, "none");
        pair.hub
            .end_terminal(&shell_term, None, "ended by the test".into());

        // The CLI exits by itself (its `read` gets a line): the session
        // ends and its token is gone; the other agent's still works.
        pair.hub
            .terminal_send(
                &claude_term,
                claude_viewer,
                ToRunner::TerminalInput {
                    term_id: claude_term.clone(),
                    data: base64::engine::general_purpose::STANDARD.encode("\r"),
                },
            )
            .await
            .unwrap();
        for _ in 0..250 {
            if pair.hub.terminal_sessions("claude-builtin").is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(pair.hub.terminal_sessions("claude-builtin").is_empty());
        let ended = pair.hub.terminal_ended("claude-builtin");
        assert!(
            ended.iter().any(|ended| ended.mode == TerminalMode::Cli
                && ended.message == "the CLI exited (exit code 0)"),
            "{ended:?}"
        );
        assert_eq!(
            auth.authenticate_terminal(&token, true, Some(runner)).await,
            Err(Refused::Invalid)
        );
        assert_eq!(
            auth.authenticate_terminal(&codex_token, true, Some(runner))
                .await,
            Ok(Authenticated::Terminal("codex-builtin".into()))
        );
        pair.hub
            .end_terminal(&codex_term, None, "ended by the test".into());
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

    type PageSocket = tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >;

    /// Reads a terminal page's socket: terminal bytes go into `text`
    /// until it holds `wanted` (answers `None`); a JSON frame whose type
    /// is in `stop` is answered (`closed` stands for the socket's end);
    /// other JSON frames are passed over.
    async fn page_read(
        socket: &mut PageSocket,
        text: &mut String,
        wanted: &str,
        stop: &[&str],
    ) -> Option<serde_json::Value> {
        use futures_util::StreamExt;
        use tokio_tungstenite::tungstenite::Message as Ws;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        loop {
            let frame = tokio::time::timeout_at(deadline, socket.next())
                .await
                .unwrap_or_else(|_| panic!("waited for {wanted:?} or {stop:?}; got {text:?}"));
            match frame {
                Some(Ok(Ws::Binary(bytes))) => {
                    text.push_str(&String::from_utf8_lossy(&bytes));
                    if !wanted.is_empty() && text.contains(wanted) {
                        return None;
                    }
                }
                Some(Ok(Ws::Text(json))) => {
                    let value: serde_json::Value = serde_json::from_str(json.as_str()).unwrap();
                    if stop.contains(&value["type"].as_str().unwrap_or("")) {
                        return Some(value);
                    }
                }
                Some(Ok(Ws::Close(_))) | Some(Err(_)) | None => {
                    if stop.contains(&"closed") {
                        return Some(serde_json::json!({ "type": "closed" }));
                    }
                    panic!(
                        "the socket closed while waiting for {wanted:?} or {stop:?}; got {text:?}"
                    );
                }
                Some(Ok(_)) => {}
            }
        }
    }

    /// A page's `open` frame.
    fn open_frame(mode: &str, cols: u16, rows: u16, fresh: bool) -> String {
        serde_json::json!({ "type": "open", "mode": mode, "cols": cols, "rows": rows, "fresh": fresh })
            .to_string()
    }

    async fn wait_for(what: &str, mut done: impl FnMut() -> bool) {
        for _ in 0..1200 {
            if done() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("waited in vain for {what}");
    }

    /// A user with these permissions, signed in.
    async fn user(
        pair: &Pair,
        http: &reqwest::Client,
        base: &str,
        name: &str,
        permissions: &[&str],
    ) -> (i64, String) {
        let password = format!("{name}-password");
        let added = pair
            .db
            .add_user(&crate::db::NewUser {
                username: name.into(),
                email: None,
                password_hash: crate::users::hash_password(&password).unwrap(),
                permissions: crate::users::Perms::parse(permissions).unwrap(),
                created_by: "admin".into(),
            })
            .unwrap();
        (added.id, sign_in(http, base, name, &password).await)
    }

    /// The owner's request: a session goes on when its window goes, and
    /// the next window resumes it (the recent screen first, then live
    /// output, redrawn at its size) instead of starting another. A second
    /// window takes it over; End session ends it. The feed says who did
    /// what, never what was shown or typed.
    #[tokio::test]
    async fn a_session_outlives_its_window_and_the_next_window_resumes_it() {
        use futures_util::SinkExt;
        use tokio_tungstenite::tungstenite::Message as Ws;
        let pair = listen().await;
        let base = admin_server(&pair).await;
        start(config(&pair, "claude-builtin", Kind::Claude, CLAUDE_SECRET));
        connected(&pair.hub, "claude-builtin").await;
        let http = reqwest::Client::new();
        let admin = sign_in(&http, &base, "admin", "admin-password-long").await;
        let (_, operator) = user(&pair, &http, &base, "operator", &["agents"]).await;
        let origin = base.clone();

        let mut first = terminal_socket(&base, Some(&admin), Some(&origin))
            .await
            .unwrap();
        first
            .send(Ws::text(open_frame("shell", 80, 24, false)))
            .await
            .unwrap();
        let mut text = String::new();
        let opened = page_read(&mut first, &mut text, "", &["opened"])
            .await
            .unwrap();
        assert_eq!(opened["opened_by"], "admin");
        first
            .send(Ws::binary(
                // In the foreground job (which a window change signals),
                // waiting so the trap runs at once.
                b"sh -c 'trap \"echo winch:\\$(stty size):\" WINCH; i=0; while :; do \
                  i=$((i+1)); echo \"count-$i.\"; sleep 0.2 & wait $!; done'\r"
                    .to_vec(),
            ))
            .await
            .unwrap();
        page_read(&mut first, &mut text, "count-3.", &[]).await;
        // The window goes: the session does not.
        drop(first);
        wait_for("the window to be detached", || {
            pair.hub
                .terminal_sessions("claude-builtin")
                .first()
                .is_some_and(|session| session.viewer.is_none())
        })
        .await;
        tokio::time::sleep(Duration::from_millis(600)).await;
        let sessions = pair.hub.terminal_sessions("claude-builtin");
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].opened_by, "admin");
        assert_eq!(sessions[0].mode, TerminalMode::Shell);

        // The next window resumes it at its own size.
        let mut second = terminal_socket(&base, Some(&admin), Some(&origin))
            .await
            .unwrap();
        second
            .send(Ws::text(open_frame("shell", 100, 30, false)))
            .await
            .unwrap();
        let mut replayed = String::new();
        let attached = page_read(&mut second, &mut replayed, "", &["attached", "opened"])
            .await
            .unwrap();
        assert_eq!(attached["type"], "attached", "{attached}");
        assert_eq!(attached["opened_by"], "admin");
        page_read(&mut second, &mut replayed, "", &["replayed"]).await;
        assert!(replayed.contains("count-1."), "{replayed}");
        let last = replayed
            .split("count-")
            .filter_map(|part| part.split('.').next()?.parse::<u32>().ok())
            .max()
            .unwrap();
        // Output went on while no window showed it: it is in the replay.
        assert!(last >= 6, "{replayed}");
        let mut live = String::new();
        // The program is made to redraw: one column off, then the size.
        page_read(&mut second, &mut live, "winch:30 100:", &[]).await;
        assert!(live.contains("winch:30 99:"), "{live}");
        page_read(&mut second, &mut live, &format!("count-{}.", last + 3), &[]).await;
        assert!(!live.contains("count-1."), "{live}");
        // Typing reaches it.
        second.send(Ws::binary(b"\x03".to_vec())).await.unwrap();
        second
            .send(Ws::binary(b"echo typed-$((6*7))\r".to_vec()))
            .await
            .unwrap();
        page_read(&mut second, &mut live, "typed-42", &[]).await;

        // Another window, another user with `agents`, takes it over.
        let mut third = terminal_socket(&base, Some(&operator), Some(&origin))
            .await
            .unwrap();
        third
            .send(Ws::text(open_frame("shell", 100, 30, false)))
            .await
            .unwrap();
        let mut seen = String::new();
        page_read(&mut third, &mut seen, "", &["attached"]).await;
        let taken = page_read(&mut second, &mut String::new(), "", &["taken"])
            .await
            .unwrap();
        assert_eq!(taken["by"], "operator");
        assert_eq!(
            page_read(&mut second, &mut String::new(), "", &["closed"])
                .await
                .unwrap()["type"],
            "closed"
        );
        // The window that lost it cannot type into it.
        assert_eq!(
            pair.hub.terminal_sessions("claude-builtin")[0]
                .viewer
                .as_deref(),
            Some("operator")
        );
        page_read(&mut third, &mut seen, "", &["replayed"]).await;
        assert!(seen.contains("typed-42"), "{seen}");

        // End session: it ends, the window says why, nothing is left.
        third.send(Ws::text(r#"{"type":"end"}"#)).await.unwrap();
        let exit = page_read(&mut third, &mut String::new(), "", &["exit"])
            .await
            .unwrap();
        assert_eq!(exit["message"], "operator ended it with End session");
        assert!(exit["at"].as_i64().unwrap() > 0);
        assert_eq!(pair.hub.terminal_count(), 0);
        // The window saw it end: opening again starts a new one.
        let mut fourth = terminal_socket(&base, Some(&admin), Some(&origin))
            .await
            .unwrap();
        fourth
            .send(Ws::text(open_frame("shell", 80, 24, false)))
            .await
            .unwrap();
        page_read(&mut fourth, &mut String::new(), "", &["opened"]).await;
        fourth.send(Ws::text(r#"{"type":"end"}"#)).await.unwrap();
        page_read(&mut fourth, &mut String::new(), "", &["exit"]).await;

        let feed: Vec<String> = pair
            .db
            .activity(40)
            .unwrap()
            .into_iter()
            .map(|activity| activity.summary)
            .collect();
        for line in [
            "admin opened a shell in claude-builtin",
            "admin left a shell in claude-builtin running",
            "admin resumed a shell in claude-builtin",
            "operator took over a shell in claude-builtin from admin",
            "A shell in claude-builtin ended: operator ended it with End session",
        ] {
            assert!(
                feed.iter().any(|summary| summary == line),
                "{line} in {feed:?}"
            );
        }
        for file in ["lore.db", "lore.db-wal"] {
            let bytes = std::fs::read(pair.dir.join(file)).unwrap_or_default();
            let bytes = String::from_utf8_lossy(&bytes);
            assert!(!bytes.contains("count-1.") && !bytes.contains("typed-42"));
        }
    }

    /// A fake CLI that prints its lore token, then a line every 200 ms
    /// for 4 s, then waits for input.
    fn chatty_cli(pair: &Pair) -> std::path::PathBuf {
        let program = pair.dir.join("claude-chatty");
        std::fs::write(
            &program,
            "#!/bin/sh\ncase \"$1\" in --version) echo \"2.1.328 (Claude Code)\"; exit 0;; \
             auth) echo \"Not logged in\"; exit 1;; esac\n\
             echo \"tok:${LORE_AGENT_TOKEN:-none}:\"\n\
             i=0; while [ $i -lt 20 ]; do sleep 0.2; i=$((i+1)); echo \"out-$i\"; done\n\
             echo ready; read line\n",
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).unwrap();
        program
    }

    fn token_in(text: &str) -> String {
        let start = text.find("tok:").unwrap() + 4;
        let end = text[start..].find(':').unwrap();
        text[start..start + end].to_string()
    }

    /// A session nobody looks at ends after the idle limit without
    /// output, never while output keeps coming nor while a window shows
    /// it. The owner who comes back hears why and when, and a new session
    /// starts only when asked.
    #[tokio::test]
    async fn an_idle_session_ends_and_the_window_says_why_instead_of_starting_another() {
        use crate::auth::{Authenticated, McpAuth, Refused};
        use futures_util::SinkExt;
        use tokio_tungstenite::tungstenite::Message as Ws;
        // Margins wide enough for a loaded machine: output every 0.2 s
        // for 4 s against a limit of 1.5 s.
        let pair = listen_tuned(Some(Duration::from_millis(1500))).await;
        let base = admin_server(&pair).await;
        let mut config = config(&pair, "claude-builtin", Kind::Claude, CLAUDE_SECRET);
        config.settings.program = chatty_cli(&pair);
        start(config);
        connected(&pair.hub, "claude-builtin").await;
        let http = reqwest::Client::new();
        let admin = sign_in(&http, &base, "admin", "admin-password-long").await;
        let origin = base.clone();
        let mut auth = McpAuth::new(Vec::new(), pair.db.clone(), false);
        auth.terminals = Some(pair.hub.clone());
        let runner: std::net::IpAddr = "127.0.0.1".parse().unwrap();

        let mut socket = terminal_socket(&base, Some(&admin), Some(&origin))
            .await
            .unwrap();
        socket
            .send(Ws::text(open_frame("cli", 80, 24, false)))
            .await
            .unwrap();
        let mut text = String::new();
        page_read(&mut socket, &mut text, "out-1", &[]).await;
        let token = token_in(&text);
        drop(socket);
        // Detached and printing: it lives, and so does its token.
        tokio::time::sleep(Duration::from_millis(2500)).await;
        assert_eq!(pair.hub.terminal_count(), 1);
        assert_eq!(
            auth.authenticate_terminal(&token, true, Some(runner)).await,
            Ok(Authenticated::Terminal("claude-builtin".into()))
        );
        // Silent and unseen past the limit: it ends, with its token.
        wait_for("the idle limit", || pair.hub.terminal_count() == 0).await;
        assert_eq!(
            auth.authenticate_terminal(&token, true, Some(runner)).await,
            Err(Refused::Invalid)
        );
        let ended = pair.hub.terminal_ended("claude-builtin");
        assert!(
            ended[0].message.contains("printed nothing") && ended[0].message.contains("nobody"),
            "{ended:?}"
        );

        // The owner comes back: the window says why and when; nothing new
        // starts.
        let mut socket = terminal_socket(&base, Some(&admin), Some(&origin))
            .await
            .unwrap();
        socket
            .send(Ws::text(open_frame("cli", 80, 24, false)))
            .await
            .unwrap();
        let said = page_read(
            &mut socket,
            &mut String::new(),
            "",
            &["ended", "opened", "attached"],
        )
        .await
        .unwrap();
        assert_eq!(said["type"], "ended", "{said}");
        assert!(
            said["message"]
                .as_str()
                .unwrap()
                .contains("printed nothing")
        );
        assert_eq!(said["at"].as_i64(), Some(ended[0].at));
        assert_eq!(pair.hub.terminal_count(), 0);

        // "New session" starts one; a window that shows it keeps it,
        // silent or not.
        let mut socket = terminal_socket(&base, Some(&admin), Some(&origin))
            .await
            .unwrap();
        socket
            .send(Ws::text(open_frame("cli", 80, 24, true)))
            .await
            .unwrap();
        let mut text = String::new();
        page_read(&mut socket, &mut text, "ready", &[]).await;
        tokio::time::sleep(Duration::from_millis(3000)).await;
        assert_eq!(pair.hub.terminal_count(), 1);
        // Hidden or closed: the limit counts again.
        socket.send(Ws::text(r#"{"type":"hide"}"#)).await.unwrap();
        wait_for("the idle limit after hiding", || {
            pair.hub.terminal_count() == 0
        })
        .await;
        let feed = format!("{:?}", pair.db.activity(40).unwrap());
        assert!(
            feed.contains("The CLI's terminal in claude-builtin ended: it printed nothing"),
            "{feed}"
        );
    }

    /// Signing out of one browser detaches that window and leaves the
    /// session; the session itself ends when the user who opened it loses
    /// the `agents` permission (or is deleted or disabled), shown in a
    /// window or not, and its token goes with it.
    #[tokio::test]
    async fn a_session_ends_when_its_opener_may_no_longer_have_it() {
        use crate::auth::{Authenticated, McpAuth, Refused};
        use futures_util::SinkExt;
        use tokio_tungstenite::tungstenite::Message as Ws;
        let pair = listen_tuned(Some(Duration::from_secs(3600))).await;
        let base = admin_server_with(&pair, Some(Duration::from_millis(150))).await;
        let mut config = config(&pair, "claude-builtin", Kind::Claude, CLAUDE_SECRET);
        config.settings.program = chatty_cli(&pair);
        start(config);
        connected(&pair.hub, "claude-builtin").await;
        let http = reqwest::Client::new();
        let origin = base.clone();
        let mut auth = McpAuth::new(Vec::new(), pair.db.clone(), false);
        auth.terminals = Some(pair.hub.clone());
        let runner: std::net::IpAddr = "127.0.0.1".parse().unwrap();

        // The admin signs out: the window is detached, the session stays.
        let admin = sign_in(&http, &base, "admin", "admin-password-long").await;
        let mut socket = terminal_socket(&base, Some(&admin), Some(&origin))
            .await
            .unwrap();
        socket
            .send(Ws::text(open_frame("cli", 80, 24, false)))
            .await
            .unwrap();
        page_read(&mut socket, &mut String::new(), "ready", &[]).await;
        tokio::time::sleep(Duration::from_millis(500)).await;
        let out = http
            .post(format!("{base}/admin/api/logout"))
            .header(header::COOKIE, &admin)
            .send()
            .await
            .unwrap();
        assert_eq!(out.status(), 200);
        let detached = page_read(&mut socket, &mut String::new(), "", &["detached"])
            .await
            .unwrap();
        assert!(
            detached["message"]
                .as_str()
                .unwrap()
                .contains("your sign-in has ended"),
            "{detached}"
        );
        tokio::time::sleep(Duration::from_millis(600)).await;
        assert_eq!(pair.hub.terminal_count(), 1);
        // Signed in again, the admin resumes it, then ends it.
        let admin = sign_in(&http, &base, "admin", "admin-password-long").await;
        let mut socket = terminal_socket(&base, Some(&admin), Some(&origin))
            .await
            .unwrap();
        socket
            .send(Ws::text(open_frame("cli", 80, 24, false)))
            .await
            .unwrap();
        let mut replayed = String::new();
        page_read(&mut socket, &mut replayed, "", &["replayed"]).await;
        assert!(replayed.contains("ready"), "{replayed}");
        socket.send(Ws::text(r#"{"type":"end"}"#)).await.unwrap();
        page_read(&mut socket, &mut String::new(), "", &["exit"]).await;
        assert_eq!(pair.hub.terminal_count(), 0);

        // An operator opens one and closes the window; then loses `agents`.
        let (operator_id, operator) =
            user(&pair, &http, &base, "operator", &["agents", "users"]).await;
        let mut socket = terminal_socket(&base, Some(&operator), Some(&origin))
            .await
            .unwrap();
        socket
            .send(Ws::text(open_frame("cli", 80, 24, true)))
            .await
            .unwrap();
        let mut text = String::new();
        page_read(&mut socket, &mut text, "out-1", &[]).await;
        let token = token_in(&text);
        drop(socket);
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert_eq!(pair.hub.terminal_count(), 1);
        assert_eq!(
            auth.authenticate_terminal(&token, true, Some(runner)).await,
            Ok(Authenticated::Terminal("claude-builtin".into()))
        );
        let changed = http
            .put(format!("{base}/admin/api/users/{operator_id}"))
            .header(header::COOKIE, &operator)
            .json(&serde_json::json!({ "permissions": ["users"] }))
            .send()
            .await
            .unwrap();
        assert_eq!(changed.status(), 200, "{}", changed.text().await.unwrap());
        wait_for("the opener check", || pair.hub.terminal_count() == 0).await;
        assert_eq!(
            auth.authenticate_terminal(&token, true, Some(runner)).await,
            Err(Refused::Invalid)
        );
        assert_eq!(
            pair.hub.terminal_ended("claude-builtin")[0].message,
            "operator, who opened it, no longer has the agents permission"
        );
        // And it cannot be opened again.
        assert_eq!(
            terminal_socket(&base, Some(&operator), Some(&origin))
                .await
                .err(),
            Some(403)
        );
    }

    /// A link for `agent` that the test holds the other end of, as if its
    /// runner were connected from 127.0.0.1.
    fn fake_link(hub: &Hub, agent: &str) -> mpsc::Receiver<ToRunner> {
        let (tx, rx) = mpsc::channel(256);
        hub.inner().links.insert(
            agent.into(),
            Link {
                generation: 0,
                tx,
                kind: Kind::Claude,
                provider: "anthropic".into(),
                address: Some("127.0.0.1".parse().unwrap()),
            },
        );
        rx
    }

    /// A session as `terminal_attach` would make it, shown in no window.
    fn fake_session(hub: &Hub, term_id: &str, agent: &str, opener: Opener) {
        hub.inner().terminals.insert(
            term_id.into(),
            Terminal {
                agent: agent.into(),
                mode: TerminalMode::Cli,
                token_hash: None,
                opener,
                started_at: unix_now(),
                started: Instant::now(),
                warned: false,
                last_output_at: unix_now(),
                quiet_since: Instant::now(),
                replay: replay::Replay::default(),
                viewer: None,
            },
        );
    }

    /// Waits for the first message the fake runner gets that `pick`
    /// takes.
    async fn runner_gets<T>(
        rx: &mut mpsc::Receiver<ToRunner>,
        mut pick: impl FnMut(&ToRunner) -> Option<T>,
    ) -> T {
        tokio::time::timeout(WAIT, async {
            loop {
                let message = rx.recv().await.expect("the link closed");
                if let Some(found) = pick(&message) {
                    return found;
                }
            }
        })
        .await
        .expect("the runner never got it")
    }

    /// A runner built before lore kept the idle limit closes a terminal
    /// after 15 minutes without input. lore keeps it from doing that to a
    /// session it keeps: the window's keep-alive goes on as an empty input,
    /// and the watch sends one for every session, shown or not. (This
    /// runner types nothing for an empty input:
    /// `runner::terminal::tests::a_terminal_without_input_stays_open`.)
    #[tokio::test]
    async fn sessions_are_kept_alive_in_an_older_runner() {
        use futures_util::SinkExt;
        use tokio_tungstenite::tungstenite::Message as Ws;
        let pair = listen_tuned(Some(Duration::from_secs(3600))).await;
        let mut runner = fake_link(&pair.hub, "claude-builtin");
        let base = admin_server(&pair).await;
        let http = reqwest::Client::new();
        let admin = sign_in(&http, &base, "admin", "admin-password-long").await;
        let mut socket = terminal_socket(&base, Some(&admin), Some(&base))
            .await
            .unwrap();
        socket
            .send(Ws::text(open_frame("shell", 80, 24, false)))
            .await
            .unwrap();
        let term_id = runner_gets(&mut runner, |message| match message {
            ToRunner::TerminalOpen { term_id, .. } => Some(term_id.clone()),
            _ => None,
        })
        .await;
        page_read(&mut socket, &mut String::new(), "", &["opened"]).await;
        // The window says it is shown: an empty input reaches the runner.
        socket.send(Ws::text(r#"{"type":"alive"}"#)).await.unwrap();
        let empty = |message: &ToRunner| match message {
            ToRunner::TerminalInput { term_id: id, data } if *id == term_id && data.is_empty() => {
                Some(())
            }
            _ => None,
        };
        runner_gets(&mut runner, empty).await;
        // No window: the watch sends them.
        drop(socket);
        wait_for("the window to go", || {
            pair.hub.terminal_sessions("claude-builtin")[0]
                .viewer
                .is_none()
        })
        .await;
        while runner.try_recv().is_ok() {}
        runner_gets(&mut runner, empty).await;
        runner_gets(&mut runner, empty).await;
        assert_eq!(pair.hub.terminal_count(), 1);
    }

    /// A session ends at its maximum age, whatever happens in it; the
    /// window showing it hears when, ahead, and why, at the end. Its token
    /// goes with it.
    #[tokio::test]
    async fn a_session_ends_at_its_maximum_age() {
        use futures_util::SinkExt;
        use tokio_tungstenite::tungstenite::Message as Ws;
        let pair = listen().await;
        let hub = Hub::new(
            pair.db.clone(),
            parse_runner_tokens(&format!("claude-builtin:{CLAUDE_SECRET}")).unwrap(),
        )
        .with_terminal_max_age(Duration::from_secs(3))
        .with_terminal_watch(Duration::from_millis(100));
        let hub = Arc::new(hub);
        let pair = Pair {
            hub,
            db: pair.db.clone(),
            url: pair.url.clone(),
            dir: pair.dir.clone(),
        };
        let mut runner = fake_link(&pair.hub, "claude-builtin");
        let base = admin_server(&pair).await;
        let http = reqwest::Client::new();
        let admin = sign_in(&http, &base, "admin", "admin-password-long").await;
        let mut socket = terminal_socket(&base, Some(&admin), Some(&base))
            .await
            .unwrap();
        socket
            .send(Ws::text(open_frame("shell", 80, 24, false)))
            .await
            .unwrap();
        let opened = page_read(&mut socket, &mut String::new(), "", &["opened"])
            .await
            .unwrap();
        let since = opened["since"].as_i64().unwrap();
        assert_eq!(opened["ends_at"].as_i64(), Some(since + 3));
        // Within ten minutes of the end (here at once): the window is told.
        let soon = page_read(&mut socket, &mut String::new(), "", &["ends_soon"])
            .await
            .unwrap();
        assert_eq!(soon["at"].as_i64(), Some(since + 3));
        // Kept busy and shown, it still ends at its age.
        for _ in 0..10 {
            socket.send(Ws::text(r#"{"type":"alive"}"#)).await.unwrap();
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
        let exit = page_read(&mut socket, &mut String::new(), "", &["exit"])
            .await
            .unwrap();
        assert!(
            exit["message"]
                .as_str()
                .unwrap()
                .contains("maximum age of a terminal session"),
            "{exit}"
        );
        assert_eq!(pair.hub.terminal_count(), 0);
        runner_gets(&mut runner, |message| {
            matches!(message, ToRunner::TerminalClose { .. }).then_some(())
        })
        .await;
    }

    /// The watch is started again when it panics; and the opener check
    /// fails closed: sessions it cannot check three times in a row end.
    #[tokio::test]
    async fn the_watch_survives_a_panic_and_the_opener_check_fails_closed() {
        let pair = listen().await;
        let hub = Arc::new(
            Hub::new(
                pair.db.clone(),
                parse_runner_tokens(&format!("claude-builtin:{CLAUDE_SECRET}")).unwrap(),
            )
            .with_terminal_watch(Duration::from_millis(100)),
        );
        let _runner = fake_link(&hub, "claude-builtin");
        let keeper = pair
            .db
            .add_user(&crate::db::NewUser {
                username: "keeper".into(),
                email: None,
                password_hash: "x".into(),
                permissions: crate::users::Perms::parse(&["agents"]).unwrap(),
                created_by: "admin".into(),
            })
            .unwrap();
        fake_session(
            &hub,
            "t-kept",
            "claude-builtin",
            Opener {
                username: "keeper".into(),
                user_id: Some(keeper.id),
            },
        );
        hub.watch_panics.store(true, Ordering::SeqCst);
        hub.watch_terminals();
        // The first look panics; the watch runs again and keeps it.
        tokio::time::sleep(Duration::from_millis(1600)).await;
        assert!(!hub.watch_panics.load(Ordering::SeqCst));
        assert!(hub.watching.load(Ordering::SeqCst));
        assert_eq!(hub.terminal_count(), 1);
        // The database cannot be asked: after three looks it ends.
        pair.db.execute_for_test("DROP TABLE users");
        wait_for("the opener check to fail closed", || {
            hub.terminal_count() == 0
        })
        .await;
        assert!(
            hub.terminal_ended("claude-builtin")[0]
                .message
                .contains("could not check")
        );
    }

    /// Deleted, disabled, without `agents`, or not a user at all: the
    /// opener check says why; the built-in admin always may.
    #[test]
    fn the_opener_check_names_every_reason() {
        let dir = temp_dir("opener");
        let db = Db::open(&dir.join("lore.db")).unwrap();
        let add = |name: &str, perms: &[&str]| {
            db.add_user(&crate::db::NewUser {
                username: name.into(),
                email: None,
                password_hash: "x".into(),
                permissions: crate::users::Perms::parse(perms).unwrap(),
                created_by: "admin".into(),
            })
            .unwrap()
        };
        let opener = |user: &crate::db::User| Opener {
            username: user.username.clone(),
            user_id: Some(user.id),
        };
        let why = |verdict: Verdict| match verdict {
            Verdict::Gone(why) => why,
            other => panic!("{other:?}"),
        };
        assert_eq!(opener_gone(&db, &owner()), Verdict::Allowed);
        why(opener_gone(
            &db,
            &Opener {
                username: "viewer".into(),
                user_id: None,
            },
        ));
        let keeper = add("keeper", &["agents"]);
        assert_eq!(opener_gone(&db, &opener(&keeper)), Verdict::Allowed);
        // Another user at the same id (a restored database): not the
        // one who opened it.
        assert!(
            why(opener_gone(
                &db,
                &Opener {
                    username: "someone-else".into(),
                    user_id: Some(keeper.id),
                },
            ))
            .contains("no longer that account")
        );
        let writer = add("writer", &["write"]);
        assert!(
            why(opener_gone(&db, &opener(&writer))).contains("no longer has the agents permission")
        );
        let disabled = add("sleeper", &["agents"]);
        db.update_user(
            disabled.id,
            &crate::db::UserPatch {
                disabled: Some(true),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(why(opener_gone(&db, &opener(&disabled))).contains("was disabled"));
        let gone = add("leaver", &["agents"]);
        db.delete_user(gone.id).unwrap();
        assert!(why(opener_gone(&db, &opener(&gone))).contains("was deleted"));
        // The database cannot be asked: not known, not allowed.
        db.execute_for_test("DROP TABLE users");
        assert_eq!(opener_gone(&db, &opener(&keeper)), Verdict::Unknown);
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
