//! `lore proxy`: the built-in agents' only way out to the internet.
//!
//! The agent containers sit on internal networks (no route out); the
//! stack runs this small forward proxy on those networks and on one that
//! reaches the internet. It speaks only `CONNECT host:443` (HTTPS
//! tunnels: the proxy never sees what goes through them), and only to the
//! host names on its allowlist: the model providers' API and sign-in hosts.
//! A name that resolves to a private, loopback, link-local or otherwise
//! non-public address is refused, so the allowlist cannot be turned into a
//! way to the host, the LAN, the cloud metadata service or the other
//! containers. Nothing else is proxied: no plain HTTP, no IP literals.
//!
//! Configuration, from the environment:
//! - `LORE_PROXY_BIND`: default `0.0.0.0:3128`.
//! - `LORE_PROXY_ALLOW`: comma-separated host names; `.example.com`
//!   allows every name under example.com. Default [`DEFAULT_ALLOW`].
//! - `LORE_PROXY_PORTS`: comma-separated ports; default `443`.

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Semaphore,
};

/// What each CLI needs, from their documentation: Claude Code
/// (`api.anthropic.com`; sign-in at `claude.ai`, `console.anthropic.com`,
/// `platform.claude.com`), Codex (`api.openai.com`; the ChatGPT sign-in
/// and its backend at `auth.openai.com` and `chatgpt.com`), opencode with
/// DeepSeek (`api.deepseek.com`, and `models.dev`, opencode's model
/// catalogue).
pub const DEFAULT_ALLOW: &str = "api.anthropic.com,claude.ai,console.anthropic.com,\
platform.claude.com,api.openai.com,auth.openai.com,chatgpt.com,api.deepseek.com,models.dev";

/// Largest request head read.
const HEAD_BYTES: usize = 8 * 1024;

/// How many tunnels the proxy holds, in all and for one client, and how
/// long one may last: one agent cannot take every tunnel, nor hold one for
/// ever.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Tunnels open at once, in all.
    pub total: usize,
    /// Tunnels open at once from one client address.
    pub per_source: usize,
    /// A tunnel through which nothing passed this long is closed.
    pub idle: Duration,
    /// A tunnel is closed after this long, whatever passes.
    pub lifetime: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            total: 256,
            per_source: 64,
            idle: Duration::from_secs(15 * 60),
            lifetime: Duration::from_secs(3 * 60 * 60),
        }
    }
}

/// What the proxy lets through.
#[derive(Debug, Clone)]
pub struct Policy {
    /// Exact names, and `.suffix` entries.
    pub allow: Vec<String>,
    pub ports: Vec<u16>,
    /// Only for the tests: let a name resolve to a local address.
    pub allow_private: bool,
}

impl Policy {
    pub fn parse(allow: &str, ports: &str) -> Result<Self> {
        let allow: Vec<String> = allow
            .split(',')
            .map(|host| host.trim().trim_end_matches('.').to_ascii_lowercase())
            .filter(|host| !host.is_empty())
            .collect();
        let ports = ports
            .split(',')
            .map(str::trim)
            .filter(|port| !port.is_empty())
            .map(|port| {
                port.parse::<u16>()
                    .context("LORE_PROXY_PORTS must be port numbers")
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            allow,
            ports,
            allow_private: false,
        })
    }

    /// Whether a host name (not an address) is on the allowlist.
    pub fn allows(&self, host: &str) -> bool {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        if host.is_empty()
            || host.parse::<IpAddr>().is_ok()
            || !host
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.'))
        {
            return false;
        }
        self.allow
            .iter()
            .any(|entry| match entry.strip_prefix('.') {
                Some(suffix) => host.ends_with(&format!(".{suffix}")),
                None => *entry == host,
            })
    }
}

/// Whether an address is on the public internet.
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => public_v4(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return public_v4(v4);
            }
            let first = v6.segments()[0];
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (first & 0xfe00) == 0xfc00 // unique local
                || (first & 0xffc0) == 0xfe80 // link-local
                || (first == 0x2001 && v6.segments()[1] == 0x0db8) // documentation
                || (first == 0x0064 && v6.segments()[1] == 0xff9b) // NAT64
                || v6 == Ipv6Addr::from(1u128))
        }
    }
}

fn public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_unspecified()
        || ip.is_multicast()
        || a == 0
        || (a == 100 && (64..128).contains(&b)) // shared address space
        || (a == 192 && b == 0 && c == 0)
        || (a == 198 && (b == 18 || b == 19)) // benchmarking
        || a >= 240)
}

/// `lore proxy`: serves for ever.
pub async fn main_from_env() -> Result<()> {
    let var = |name: &str, default: &str| {
        std::env::var(name)
            .ok()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| default.to_string())
    };
    let bind: SocketAddr = var("LORE_PROXY_BIND", "0.0.0.0:3128")
        .parse()
        .context("LORE_PROXY_BIND must be an address like 0.0.0.0:3128")?;
    let policy = Policy::parse(
        &var("LORE_PROXY_ALLOW", DEFAULT_ALLOW),
        &var("LORE_PROXY_PORTS", "443"),
    )?;
    let listener = TcpListener::bind(bind)
        .await
        .with_context(|| format!("binding {bind}"))?;
    tracing::info!(%bind, allow = %policy.allow.join(","), "egress proxy listening");
    serve(listener, policy).await;
    Ok(())
}

/// Accepts tunnels until the listener fails.
pub async fn serve(listener: TcpListener, policy: Policy) {
    serve_with(listener, policy, Limits::default()).await
}

/// One client's open tunnels; the count goes down when dropped.
struct SourceSlot {
    counts: Arc<std::sync::Mutex<std::collections::HashMap<IpAddr, usize>>>,
    ip: IpAddr,
}

impl Drop for SourceSlot {
    fn drop(&mut self) {
        let mut counts = self.counts.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(count) = counts.get_mut(&self.ip) {
            *count -= 1;
            if *count == 0 {
                counts.remove(&self.ip);
            }
        }
    }
}

/// [`serve`] with given limits.
pub async fn serve_with(listener: TcpListener, policy: Policy, limits: Limits) {
    let policy = Arc::new(policy);
    let slots = Arc::new(Semaphore::new(limits.total));
    let counts: Arc<std::sync::Mutex<std::collections::HashMap<IpAddr, usize>>> = Arc::default();
    loop {
        let Ok((client, peer)) = listener.accept().await else {
            continue;
        };
        let source = {
            let mut table = counts.lock().unwrap_or_else(|e| e.into_inner());
            let count = table.entry(peer.ip()).or_insert(0);
            if *count >= limits.per_source {
                None
            } else {
                *count += 1;
                Some(SourceSlot {
                    counts: counts.clone(),
                    ip: peer.ip(),
                })
            }
        };
        let Some(source) = source else {
            tracing::warn!(%peer, "a client holds as many tunnels as one may; refused");
            drop(client);
            continue;
        };
        let Ok(slot) = slots.clone().try_acquire_owned() else {
            drop(client);
            continue;
        };
        let policy = policy.clone();
        tokio::spawn(async move {
            let ended = tokio::time::timeout(limits.lifetime, tunnel(client, &policy, limits.idle));
            match ended.await {
                Ok(Err(error)) => tracing::debug!(%peer, %error, "a tunnel ended"),
                Err(_) => tracing::info!(%peer, "a tunnel reached its lifetime and was closed"),
                Ok(Ok(())) => {}
            }
            drop(slot);
            drop(source);
        });
    }
}

async fn answer(client: &mut TcpStream, status: &str) -> Result<()> {
    client
        .write_all(
            format!("HTTP/1.1 {status}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
                .as_bytes(),
        )
        .await?;
    Ok(())
}

async fn tunnel(mut client: TcpStream, policy: &Policy, idle: Duration) -> Result<()> {
    let mut head = Vec::new();
    let mut buffer = [0u8; 1024];
    tokio::time::timeout(Duration::from_secs(10), async {
        while !head.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = client.read(&mut buffer).await?;
            if n == 0 || head.len() + n > HEAD_BYTES {
                anyhow::bail!("no complete request head");
            }
            head.extend_from_slice(&buffer[..n]);
        }
        Ok(())
    })
    .await
    .context("the request head took too long")??;
    let end = head.windows(4).position(|w| w == b"\r\n\r\n").unwrap_or(0) + 4;
    let text = String::from_utf8_lossy(&head[..end]).into_owned();
    let mut words = text.lines().next().unwrap_or_default().split_whitespace();
    let (method, target) = (words.next().unwrap_or(""), words.next().unwrap_or(""));
    if !method.eq_ignore_ascii_case("CONNECT") {
        answer(&mut client, "405 Method Not Allowed").await?;
        return Ok(());
    }
    let Some((host, port)) = target.rsplit_once(':') else {
        answer(&mut client, "400 Bad Request").await?;
        return Ok(());
    };
    let port: u16 = port.parse().unwrap_or(0);
    if !policy.ports.contains(&port) || !policy.allows(host) {
        tracing::info!(%host, port, "the egress proxy refused a host that is not allowed");
        answer(&mut client, "403 Forbidden").await?;
        return Ok(());
    }
    let resolved: Vec<SocketAddr> = tokio::time::timeout(
        Duration::from_secs(10),
        tokio::net::lookup_host((host, port)),
    )
    .await
    .ok()
    .and_then(Result::ok)
    .map(Iterator::collect)
    .unwrap_or_default();
    // Every address must be public: a name that also points inside is
    // refused whole.
    if resolved.is_empty()
        || (!policy.allow_private && resolved.iter().any(|addr| !is_public(addr.ip())))
    {
        tracing::warn!(%host, "the egress proxy refused a name that resolves to a non-public address");
        answer(&mut client, "403 Forbidden").await?;
        return Ok(());
    }
    let mut upstream = None;
    for addr in &resolved {
        if let Ok(Ok(stream)) =
            tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(addr)).await
        {
            upstream = Some(stream);
            break;
        }
    }
    let Some(mut upstream) = upstream else {
        answer(&mut client, "502 Bad Gateway").await?;
        return Ok(());
    };
    client
        .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
        .await?;
    // Anything the client sent after the head belongs to the tunnel.
    if head.len() > end {
        upstream.write_all(&head[end..]).await?;
    }
    relay(client, upstream, idle).await
}

/// Carries bytes both ways until both sides are done, or nothing passed
/// for `idle`.
async fn relay(client: TcpStream, upstream: TcpStream, idle: Duration) -> Result<()> {
    let (mut client_read, mut client_write) = client.into_split();
    let (mut upstream_read, mut upstream_write) = upstream.into_split();
    let mut up = vec![0u8; 16 * 1024];
    let mut down = vec![0u8; 16 * 1024];
    let (mut up_open, mut down_open) = (true, true);
    let mut last = tokio::time::Instant::now();
    while up_open || down_open {
        tokio::select! {
            read = client_read.read(&mut up), if up_open => {
                let n = read?;
                if n == 0 {
                    up_open = false;
                    let _ = upstream_write.shutdown().await;
                } else {
                    upstream_write.write_all(&up[..n]).await?;
                    last = tokio::time::Instant::now();
                }
            }
            read = upstream_read.read(&mut down), if down_open => {
                let n = read?;
                if n == 0 {
                    down_open = false;
                    let _ = client_write.shutdown().await;
                } else {
                    client_write.write_all(&down[..n]).await?;
                    last = tokio::time::Instant::now();
                }
            }
            _ = tokio::time::sleep_until(last + idle) => {
                anyhow::bail!("idle for {} seconds", idle.as_secs());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_listed_names_are_allowed() {
        let policy = Policy::parse("api.anthropic.com, .openai.com", "443").unwrap();
        assert!(policy.allows("api.anthropic.com"));
        assert!(policy.allows("API.Anthropic.com."));
        assert!(policy.allows("auth.openai.com"));
        assert!(!policy.allows("openai.com"));
        assert!(!policy.allows("evil-api.anthropic.com.attacker.net"));
        assert!(!policy.allows("anthropic.com"));
        assert!(!policy.allows("1.2.3.4"));
        assert!(!policy.allows("[::1]"));
        assert!(!policy.allows("api.anthropic.com\r\nX"));
        assert!(Policy::parse("", "x").is_err());
        let default = Policy::parse(DEFAULT_ALLOW, "443").unwrap();
        for host in ["api.anthropic.com", "chatgpt.com", "api.deepseek.com"] {
            assert!(default.allows(host), "{host}");
        }
        assert!(!default.allows("github.com"));
    }

    #[test]
    fn local_and_private_addresses_are_not_public() {
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "172.20.0.5",
            "192.168.1.1",
            "169.254.169.254",
            "100.100.100.200",
            "0.0.0.0",
            "::1",
            "fe80::1",
            "fd00::1",
            "::ffff:10.0.0.1",
            "::ffff:169.254.169.254",
        ] {
            assert!(!is_public(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["1.1.1.1", "160.79.104.10", "2606:4700::1111"] {
            assert!(is_public(ip.parse().unwrap()), "{ip}");
        }
    }

    async fn start(policy: Policy) -> SocketAddr {
        start_with(policy, Limits::default()).await
    }

    async fn start_with(policy: Policy, limits: Limits) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve_with(listener, policy, limits));
        addr
    }

    /// H8: one client cannot hold every tunnel, and a tunnel that carries
    /// nothing, or lasts too long, is closed.
    #[tokio::test]
    async fn one_client_cannot_hold_the_proxy_and_idle_tunnels_close() {
        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = echo.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = echo.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut buffer = [0u8; 64];
                    while let Ok(n) = socket.read(&mut buffer).await {
                        if n == 0 || socket.write_all(&buffer[..n]).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
        let mut policy = Policy::parse("localhost", &port.to_string()).unwrap();
        policy.allow_private = true;
        let limits = Limits {
            total: 10,
            per_source: 3,
            idle: Duration::from_millis(400),
            lifetime: Duration::from_secs(2),
        };
        let proxy = start_with(policy, limits).await;
        let connect = || async {
            let mut stream = TcpStream::connect(proxy).await.unwrap();
            stream
                .write_all(format!("CONNECT localhost:{port} HTTP/1.1\r\n\r\n").as_bytes())
                .await
                .unwrap();
            let mut reply = vec![0u8; 64];
            let n = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut reply))
                .await
                .ok()
                .and_then(Result::ok)
                .unwrap_or(0);
            (stream, String::from_utf8_lossy(&reply[..n]).into_owned())
        };
        let mut held = Vec::new();
        for _ in 0..3 {
            let (stream, reply) = connect().await;
            assert!(reply.starts_with("HTTP/1.1 200"), "{reply}");
            held.push(stream);
        }
        // A fourth from the same address is refused at once.
        let (_, reply) = connect().await;
        assert_eq!(reply, "");
        // Idle tunnels close by themselves, and the slots come back.
        tokio::time::sleep(Duration::from_millis(900)).await;
        let mut buffer = [0u8; 8];
        let n = tokio::time::timeout(Duration::from_secs(1), held[0].read(&mut buffer))
            .await
            .unwrap()
            .unwrap_or(0);
        assert_eq!(n, 0, "an idle tunnel stayed open");
        let (mut busy, reply) = connect().await;
        assert!(reply.starts_with("HTTP/1.1 200"), "{reply}");
        // A busy tunnel still ends at its lifetime.
        let started = tokio::time::Instant::now();
        loop {
            if busy.write_all(b"ping").await.is_err() {
                break;
            }
            match tokio::time::timeout(Duration::from_millis(200), busy.read(&mut buffer)).await {
                Ok(Ok(0)) | Ok(Err(_)) => break,
                _ => {}
            }
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "the tunnel outlived its lifetime"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(started.elapsed() >= Duration::from_millis(1500));
    }

    async fn ask(proxy: SocketAddr, request: &str) -> String {
        let mut stream = TcpStream::connect(proxy).await.unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut reply = vec![0u8; 256];
        let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut reply))
            .await
            .unwrap()
            .unwrap();
        String::from_utf8_lossy(&reply[..n]).into_owned()
    }

    #[tokio::test]
    async fn plain_http_other_hosts_and_inside_addresses_are_refused() {
        let proxy = start(Policy::parse("localhost,api.anthropic.com", "443").unwrap()).await;
        assert!(
            ask(
                proxy,
                "GET http://api.anthropic.com/ HTTP/1.1\r\nHost: x\r\n\r\n"
            )
            .await
            .starts_with("HTTP/1.1 405")
        );
        assert!(
            ask(proxy, "CONNECT example.com:443 HTTP/1.1\r\n\r\n")
                .await
                .starts_with("HTTP/1.1 403")
        );
        assert!(
            ask(proxy, "CONNECT api.anthropic.com:22 HTTP/1.1\r\n\r\n")
                .await
                .starts_with("HTTP/1.1 403")
        );
        // An allowed name that resolves to a loopback address.
        assert!(
            ask(proxy, "CONNECT localhost:443 HTTP/1.1\r\n\r\n")
                .await
                .starts_with("HTTP/1.1 403")
        );
        assert!(
            ask(proxy, "CONNECT 127.0.0.1:443 HTTP/1.1\r\n\r\n")
                .await
                .starts_with("HTTP/1.1 403")
        );
    }

    #[tokio::test]
    async fn an_allowed_tunnel_carries_bytes_both_ways() {
        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = echo.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut socket, _) = echo.accept().await.unwrap();
            let mut buffer = [0u8; 64];
            let n = socket.read(&mut buffer).await.unwrap();
            socket.write_all(&buffer[..n]).await.unwrap();
        });
        let mut policy = Policy::parse("localhost", &port.to_string()).unwrap();
        policy.allow_private = true;
        let proxy = start(policy).await;
        let mut stream = TcpStream::connect(proxy).await.unwrap();
        stream
            .write_all(format!("CONNECT localhost:{port} HTTP/1.1\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut reply = vec![0u8; 64];
        let n = stream.read(&mut reply).await.unwrap();
        assert!(String::from_utf8_lossy(&reply[..n]).starts_with("HTTP/1.1 200"));
        stream.write_all(b"ping").await.unwrap();
        let n = stream.read(&mut reply).await.unwrap();
        assert_eq!(&reply[..n], b"ping");
    }
}
