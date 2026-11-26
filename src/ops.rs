//! Provider calls: the one function every service call goes through, the
//! access check in front of it, and the rules for what an agent may ask
//! for. The credential is added here, on the server side, and every
//! response is redacted before it travels back.

use std::time::Duration;

use serde_json::Value;

use crate::{
    db::Db,
    vault::{Secret, VaultKey},
};

/// A provider answer larger than this is not read to the end.
pub const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
/// Longest response text an agent or the admin page sees.
pub const MAX_BODY_CHARS: usize = 100_000;
/// Longest request path accepted.
const MAX_PATH_CHARS: usize = 1000;
/// The methods a provider call may use.
const METHODS: &[&str] = &["GET", "POST", "PUT", "PATCH", "DELETE"];
/// What every occurrence of the credential is replaced with in a response.
const REDACTED: &str = "[redacted]";

/// How the credential reaches the service.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Auth {
    /// `Authorization: Bearer <secret>`.
    Bearer,
    /// Bearer, plus the Accept and API version headers GitHub asks for.
    BearerGithub,
    /// `PRIVATE-TOKEN: <secret>`.
    PrivateToken,
    /// `x-api-key: <secret>`.
    ApiKey,
}

/// One service lore can call on an agent's behalf. Everything about it is
/// fixed but the credential and, for gitlab and dokploy, the server URL
/// the administrator enters.
#[derive(Clone, Copy, Debug)]
pub struct Provider {
    /// cloudflare | github | gitlab | dokploy.
    pub id: &'static str,
    /// Cloudflare, GitHub, GitLab (self-hosted), Dokploy.
    pub label: &'static str,
    /// The MCP tool that calls it.
    pub tool: &'static str,
    /// The API base when it is fixed; empty when the admin enters the URL.
    pub fixed_base: &'static str,
    /// Appended to the admin-entered server URL to get the API base.
    pub url_suffix: &'static str,
    /// True when the admin enters the server's URL.
    pub needs_url: bool,
    pub auth: Auth,
    /// A link to the service's API reference, shown by `integrations`.
    pub api_docs: &'static str,
}

pub const CLOUDFLARE: Provider = Provider {
    id: "cloudflare",
    label: "Cloudflare",
    tool: "cloudflare",
    fixed_base: "https://api.cloudflare.com/client/v4",
    url_suffix: "",
    needs_url: false,
    auth: Auth::Bearer,
    api_docs: "https://developers.cloudflare.com/api/",
};

pub const GITHUB: Provider = Provider {
    id: "github",
    label: "GitHub",
    tool: "github",
    fixed_base: "https://api.github.com",
    url_suffix: "",
    needs_url: false,
    auth: Auth::BearerGithub,
    api_docs: "https://docs.github.com/rest",
};

pub const GITLAB: Provider = Provider {
    id: "gitlab",
    label: "GitLab (self-hosted)",
    tool: "git_server",
    fixed_base: "",
    url_suffix: "/api/v4",
    needs_url: true,
    auth: Auth::PrivateToken,
    api_docs: "https://docs.gitlab.com/ee/api/",
};

pub const DOKPLOY: Provider = Provider {
    id: "dokploy",
    label: "Dokploy",
    tool: "dokploy",
    fixed_base: "",
    url_suffix: "/api",
    needs_url: true,
    auth: Auth::ApiKey,
    api_docs: "https://docs.dokploy.com/docs/core-api/introduction",
};

/// The four services, in the order they are listed everywhere.
pub const ALL: &[Provider] = &[CLOUDFLARE, GITHUB, GITLAB, DOKPLOY];

impl Provider {
    /// The provider with this id, when there is one.
    pub fn find(id: &str) -> Option<Self> {
        let id = id.trim().to_lowercase();
        ALL.iter().find(|provider| provider.id == id).copied()
    }

    /// The API base: the fixed one, or the admin-entered server URL with
    /// the suffix appended.
    pub fn api_base(&self, base_url: &str) -> String {
        if self.fixed_base.is_empty() {
            format!("{}{}", base_url.trim_end_matches('/'), self.url_suffix)
        } else {
            self.fixed_base.to_string()
        }
    }

    /// The harmless read the admin page's Test button makes.
    pub fn test_request(&self) -> OpsRequest {
        let mut path = "/user";
        let mut query = None;
        if self.id == "cloudflare" {
            path = "/zones";
            let mut map = serde_json::Map::new();
            map.insert("per_page".into(), Value::from(1));
            query = Some(map);
        } else if self.id == "dokploy" {
            path = "/project.all";
        }
        OpsRequest {
            provider: *self,
            method: "GET".into(),
            path: path.into(),
            query,
            body: None,
        }
    }
}

/// One provider call an agent or the admin page asks for.
#[derive(Debug, Clone)]
pub struct OpsRequest {
    pub provider: Provider,
    /// GET, POST, PUT, PATCH or DELETE, case-insensitive on the way in.
    pub method: String,
    /// The path after the API base, starting with `/`.
    pub path: String,
    /// Query parameters: strings, numbers and booleans.
    pub query: Option<serde_json::Map<String, Value>>,
    /// The JSON body; refused on GET.
    pub body: Option<Value>,
}

/// What a provider answered, ready to show: the credential already
/// redacted, the text cut to a readable length.
#[derive(Debug)]
pub struct OpsResponse {
    /// The upstream HTTP status.
    pub status: u16,
    pub body: String,
    /// True when the text was cut.
    pub truncated: bool,
}

/// Why a call did not happen.
#[derive(Debug)]
pub enum OpsError {
    /// The request itself is not valid: method, path, query or body.
    Invalid(String),
    /// The service could not be reached, or answered nothing usable.
    Transport(String),
}

impl OpsError {
    /// The sentence to show, safe for the agent to read: never a
    /// credential, a query or a body.
    pub fn message(&self) -> &str {
        match self {
            OpsError::Invalid(reason) | OpsError::Transport(reason) => reason,
        }
    }
}

/// Why a provider call was refused, as the one sentence the agent sees.
#[derive(Debug)]
pub struct Denied {
    /// The sentence itself. No credential in it, ever.
    pub reason: String,
}

impl Denied {
    fn because(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }

    /// A database failure while checking access: the agent sees an error,
    /// not a silence.
    fn internal(error: &anyhow::Error) -> Self {
        Self::because(format!("internal error: {error}"))
    }
}

/// What `authorize` hands the caller: where to send the call, and the
/// decrypted credential, which never leaves the caller's memory.
#[derive(Debug)]
pub struct Authorized {
    /// The API base: the fixed one, or the stored server URL plus suffix.
    pub api_base: String,
    /// The admin-entered server URL itself (gitlab and dokploy), empty for
    /// the providers with a fixed base.
    pub server_url: String,
    pub secret: Secret,
}

/// A level's rank: anything that is not `full` or `read` counts as `off`,
/// so a damaged or unknown level never grants more than it says.
fn level_rank(level: &str) -> usize {
    match level {
        "full" => 2,
        "read" => 1,
        _ => 0,
    }
}

/// The level an agent really has on a provider: the more restrictive of
/// the level of the token it authenticated with and that of the agent its
/// session names. The token is the only identity lore has verified; the
/// session name still honours a restriction the admin set for it. A
/// shared-token client can name its session anything, so only a
/// restriction on `shared` itself binds every shared-token client.
pub fn effective_level(
    db: &Db,
    token_agent: &str,
    session_agent: &str,
    provider: &str,
) -> anyhow::Result<&'static str> {
    let mut rank = level_rank(&db.ops_level(token_agent, provider)?);
    let session_agent = session_agent.trim();
    if !session_agent.is_empty() && !session_agent.eq_ignore_ascii_case(token_agent.trim()) {
        rank = rank.min(level_rank(&db.ops_level(session_agent, provider)?));
    }
    Ok(["off", "read", "full"][rank])
}

/// The name a provider call is logged under: the session's agent, with
/// ` via <token agent>` when the token says something else.
pub fn acting_as(token_agent: &str, session_agent: &str) -> String {
    let (token, session) = (token_agent.trim(), session_agent.trim());
    if session.is_empty() || session.eq_ignore_ascii_case(token) {
        token.to_string()
    } else {
        format!("{session} via {token}")
    }
}

/// The one access check every provider call goes through, in this order:
/// the vault, the kill switch, the stored credential, the agent's level
/// (see `effective_level`), and the level against the method. `method` is
/// already normalised. Only then is the credential decrypted.
pub fn authorize(
    db: &Db,
    key: Option<&VaultKey>,
    token_agent: &str,
    session_agent: &str,
    provider: Provider,
    method: &str,
) -> Result<Authorized, Denied> {
    let Some(key) = key else {
        return Err(Denied::because("the vault is not enabled on this server"));
    };
    let enabled = db.ops_enabled().map_err(|error| Denied::internal(&error))?;
    if !enabled {
        return Err(Denied::because(
            "operations are switched off by the administrator",
        ));
    }
    let stored = db
        .vault(provider.id)
        .map_err(|error| Denied::internal(&error))?;
    let Some(stored) = stored else {
        return Err(Denied::because(format!(
            "no {} credential is stored",
            provider.id
        )));
    };
    if provider.needs_url && stored.base_url.trim().is_empty() {
        return Err(Denied::because(format!(
            "no {} server URL is stored; the administrator must enter it",
            provider.id
        )));
    }
    let level = effective_level(db, token_agent, session_agent, provider.id)
        .map_err(|error| Denied::internal(&error))?;
    match level {
        "full" => {}
        "read" if method == "GET" => {}
        "read" => {
            return Err(Denied::because(format!(
                "you have read-only access to {}",
                provider.id
            )));
        }
        _ => {
            return Err(Denied::because(format!(
                "you have no access to {}",
                provider.id
            )));
        }
    }
    let secret = key
        .decrypt(provider.id, &stored.base_url, &stored.nonce, &stored.secret)
        .map_err(|error| Denied::because(format!("internal error: {error}")))?;
    Ok(Authorized {
        api_base: provider.api_base(&stored.base_url),
        server_url: stored.base_url,
        secret,
    })
}

/// Checks the request shape: method, path, query values and body, and
/// that the path does not reach an endpoint that mints credentials. Ok
/// carries the path as the service will see it (dot segments resolved),
/// which is what gets logged. Callers run this before the access check,
/// so a broken request is answered before any credential is touched;
/// `call` runs the same checks again.
pub fn validate(req: &OpsRequest) -> Result<String, OpsError> {
    let method = normalize_method(&req.method)?;
    let path = normalize_path(&req.path)?;
    if let Some(reason) = denied_path(&req.provider, &path) {
        return Err(OpsError::Invalid(reason));
    }
    if let Some(query) = &req.query {
        for value in query.values() {
            if !matches!(value, Value::String(_) | Value::Number(_) | Value::Bool(_)) {
                return Err(OpsError::Invalid(
                    "query values must be strings, numbers or booleans".into(),
                ));
            }
        }
    }
    if method == "GET" && req.body.is_some() {
        return Err(OpsError::Invalid("GET takes no body".into()));
    }
    Ok(path)
}

/// One of `METHODS`, uppercased.
pub fn normalize_method(method: &str) -> Result<String, OpsError> {
    let method = method.trim().to_uppercase();
    if METHODS.contains(&method.as_str()) {
        Ok(method)
    } else {
        Err(OpsError::Invalid(format!(
            "method must be one of: {}",
            METHODS.join(", ")
        )))
    }
}

/// The path rules: after the API base, starting with `/`, and never able
/// to reach another host or smuggle a query or a fragment in.
pub fn validate_path(path: &str) -> Result<(), OpsError> {
    if !path.starts_with('/') {
        return Err(OpsError::Invalid(
            "the path must start with `/` and be the part after the API base".into(),
        ));
    }
    if path.chars().count() > MAX_PATH_CHARS {
        return Err(OpsError::Invalid(format!(
            "the path must be at most {MAX_PATH_CHARS} characters"
        )));
    }
    for (needle, reason) in [
        ("://", "the path must not contain `://`"),
        (
            "?",
            "the path must carry no query string; pass `query` instead",
        ),
        ("#", "the path must carry no fragment"),
    ] {
        if path.contains(needle) {
            return Err(OpsError::Invalid(reason.into()));
        }
    }
    if path.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(OpsError::Invalid(
            "the path must contain no whitespace or control characters".into(),
        ));
    }
    // A backslash is a path separator to URL parsers, and an encoded dot
    // or backslash is a dot segment or a separator in disguise.
    let lower = path.to_ascii_lowercase();
    if path.contains('\\') || lower.contains("%2e") || lower.contains("%5c") {
        return Err(OpsError::Invalid(
            "the path must not contain `\\`, `%2e` or `%5c`".into(),
        ));
    }
    // `..` is refused as a segment, also between encoded slashes.
    if lower
        .replace("%2f", "/")
        .split('/')
        .any(|segment| segment == "..")
    {
        return Err(OpsError::Invalid(
            "the path must not contain a `..` segment".into(),
        ));
    }
    Ok(())
}

/// The path after the API base as the service will see it: checked by
/// `validate_path`, then resolved the way every URL parser resolves it,
/// and refused when it would climb out of the API base.
pub fn normalize_path(path: &str) -> Result<String, OpsError> {
    validate_path(path)?;
    const PROBE: &str = "https://lore.invalid/base";
    let url = reqwest::Url::parse(&format!("{PROBE}{path}"))
        .map_err(|_| OpsError::Invalid("the path is not valid".into()))?;
    match url.path().strip_prefix("/base") {
        Some("") => Ok("/".into()),
        Some(rest) if rest.starts_with('/') => Ok(rest.to_string()),
        _ => Err(OpsError::Invalid(LEAVES_BASE.into())),
    }
}

/// The refusal for a path that would leave the API base.
const LEAVES_BASE: &str = "the path must stay below the provider's API base";

/// Endpoints that create, rotate or hand out credentials — API tokens,
/// access and deploy tokens, SSH and deploy keys, runner registration
/// tokens, API keys. An agent with `full` access could otherwise mint a
/// credential of its own and so hold one after all. Each pattern matches
/// the leading path segments (`*` is any one segment), lowercased and
/// percent-decoded except for `%2F` (GitLab's encoded project ids), on
/// every method.
const DENIED_PATHS: &[(&str, &[&str])] = &[
    (
        "cloudflare",
        &[
            "user/tokens",
            "accounts/*/tokens",
            "accounts/*/access/service_tokens",
            "zones/*/access/service_tokens",
        ],
    ),
    (
        "github",
        &[
            "authorizations",
            "applications",
            "app/installations/*/access_tokens",
            "user/keys",
            "repos/*/*/keys",
            "repos/*/*/actions/runners/registration-token",
            "repos/*/*/actions/runners/remove-token",
            "repos/*/*/actions/runners/generate-jitconfig",
            "orgs/*/actions/runners/registration-token",
            "orgs/*/actions/runners/remove-token",
            "orgs/*/actions/runners/generate-jitconfig",
        ],
    ),
    (
        "gitlab",
        &[
            "personal_access_tokens",
            "user/personal_access_tokens",
            "users/*/personal_access_tokens",
            "users/*/impersonation_tokens",
            "projects/*/access_tokens",
            "groups/*/access_tokens",
            "projects/*/deploy_tokens",
            "groups/*/deploy_tokens",
            "deploy_tokens",
            "user/keys",
            "users/*/keys",
            "projects/*/deploy_keys",
            "deploy_keys",
            "user/runners",
            "runners",
            "projects/*/triggers",
            "projects/*/runners/reset_registration_token",
            "groups/*/runners/reset_registration_token",
        ],
    ),
    (
        "dokploy",
        &[
            "user.createapikey",
            "user.deleteapikey",
            "user.generateapikey",
            "user.generatetoken",
            "auth.generatetoken",
        ],
    ),
];

/// The refusal for a path on the credential denylist, or `None`.
pub fn denied_path(provider: &Provider, path: &str) -> Option<String> {
    let decoded = decode_for_match(path);
    let segments: Vec<&str> = decoded.split('/').filter(|s| !s.is_empty()).collect();
    let patterns = DENIED_PATHS
        .iter()
        .find(|(id, _)| *id == provider.id)
        .map(|(_, patterns)| *patterns)
        .unwrap_or(&[]);
    for pattern in patterns {
        let parts: Vec<&str> = pattern.split('/').collect();
        if segments.len() >= parts.len()
            && parts
                .iter()
                .zip(&segments)
                .all(|(part, segment)| *part == "*" || part == segment)
        {
            return Some(format!(
                "lore does not let agents call {} `/{pattern}`: it creates, rotates or \
                 reveals credentials. Ask the user to do this themselves.",
                provider.label
            ));
        }
    }
    None
}

/// The path as a server reads it, for the denylist: percent escapes
/// decoded (except `%2F`, which stays inside its segment), lowercased.
fn decode_for_match(path: &str) -> String {
    let bytes = path.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%'
            && index + 2 < bytes.len()
            && let Some(byte) = std::str::from_utf8(&bytes[index + 1..index + 3])
                .ok()
                .and_then(|hex| u8::from_str_radix(hex, 16).ok())
        {
            if byte == b'/' {
                out.extend_from_slice(b"%2f");
            } else {
                out.push(byte);
            }
            index += 3;
            continue;
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).to_lowercase()
}

/// Makes one provider call: the credential is added here, the response is
/// redacted and cut, and redirects are never followed (that is the
/// client's doing; `client` builds it that way).
pub async fn call(
    client: &reqwest::Client,
    base: &str,
    secret: &Secret,
    req: &OpsRequest,
) -> Result<OpsResponse, OpsError> {
    let method = normalize_method(&req.method)?;
    validate(req)?;

    // The final URL is always the API base plus the path: parse both and
    // refuse anything that would send the credential to another host, or
    // anywhere on the host outside the API base.
    let base_url = reqwest::Url::parse(base)
        .map_err(|_| OpsError::Invalid("the provider's API base is not a valid URL".into()))?;
    let mut url = reqwest::Url::parse(&format!("{}{}", base.trim_end_matches('/'), req.path))
        .map_err(|_| OpsError::Invalid("the request URL is not valid".into()))?;
    if url.scheme() != base_url.scheme()
        || url.host_str() != base_url.host_str()
        || url.port() != base_url.port()
    {
        return Err(OpsError::Invalid(
            "the path would send the request to another host".into(),
        ));
    }
    let base_path = base_url.path().trim_end_matches('/');
    let path = url.path();
    if !(path == base_path || path.starts_with(&format!("{base_path}/"))) {
        return Err(OpsError::Invalid(LEAVES_BASE.into()));
    }
    if let Some(query) = &req.query {
        for (key, value) in query {
            let value = match value {
                Value::String(text) => text.clone(),
                Value::Number(number) => number.to_string(),
                Value::Bool(flag) => flag.to_string(),
                _ => {
                    return Err(OpsError::Invalid(
                        "query values must be strings, numbers or booleans".into(),
                    ));
                }
            };
            url.query_pairs_mut().append_pair(key, &value);
        }
    }
    let body = match (method.as_str(), &req.body) {
        ("GET", Some(_)) => return Err(OpsError::Invalid("GET takes no body".into())),
        (_, Some(value)) => Some(value),
        _ => None,
    };

    let mut request = client.request(method_as(&method), url);
    request = match req.provider.auth {
        Auth::Bearer => request.header(
            "authorization",
            sensitive_header(&format!("Bearer {}", secret.expose()))?,
        ),
        Auth::BearerGithub => request
            .header(
                "authorization",
                sensitive_header(&format!("Bearer {}", secret.expose()))?,
            )
            .header("accept", "application/vnd.github+json")
            .header("x-github-api-version", "2022-11-28"),
        Auth::PrivateToken => request.header("private-token", sensitive_header(secret.expose())?),
        Auth::ApiKey => request.header("x-api-key", sensitive_header(secret.expose())?),
    };
    if let Some(value) = body {
        request = request.json(value);
    }

    let mut response = request
        .send()
        .await
        .map_err(|error| OpsError::Transport(transport_reason(&error)))?;
    let status = response.status().as_u16();

    // Read at most 2 MiB, then stop: a runaway response cannot pin the
    // server or the agent's context.
    let mut bytes: Vec<u8> = Vec::new();
    let mut too_big = false;
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| OpsError::Transport(transport_reason(&error)))?
    {
        if bytes.len() + chunk.len() > MAX_RESPONSE_BYTES {
            let room = MAX_RESPONSE_BYTES - bytes.len();
            bytes.extend_from_slice(&chunk[..room]);
            too_big = true;
            break;
        }
        bytes.extend_from_slice(&chunk);
    }

    // A response cut at 2 MiB may end inside a character: what came
    // before it is still text. Anything else that is not UTF-8 is binary.
    let text = match std::str::from_utf8(&bytes) {
        Ok(text) => Some(text),
        Err(error) if too_big && error.error_len().is_none() => {
            std::str::from_utf8(&bytes[..error.valid_up_to()]).ok()
        }
        Err(_) => None,
    };
    // A provider that echoes the credential back must not hand it to the
    // agent: every occurrence goes before the text leaves this function.
    let (text, truncated) = match text {
        None => (
            format!(
                "[binary response: {} bytes of binary data received{}]",
                bytes.len(),
                if too_big { ", cut at 2 MiB" } else { "" }
            ),
            false,
        ),
        Some(text) => {
            let text = redact(text, secret.expose());
            let truncated = too_big || text.chars().count() > MAX_BODY_CHARS;
            let text: String = if truncated {
                text.chars().take(MAX_BODY_CHARS).collect()
            } else {
                text
            };
            (text, truncated)
        }
    };
    Ok(OpsResponse {
        status,
        body: text,
        truncated,
    })
}

/// A header value that carries the credential, marked sensitive so no
/// debug output of the request ever prints it. A credential that is not
/// valid header text is refused, never sent half-built.
pub fn sensitive_header(value: &str) -> Result<reqwest::header::HeaderValue, OpsError> {
    let mut header = reqwest::header::HeaderValue::from_str(value).map_err(|_| {
        OpsError::Invalid(
            "the stored credential is not valid header text; the administrator must enter it again"
                .into(),
        )
    })?;
    header.set_sensitive(true);
    Ok(header)
}

/// Every occurrence of the credential in a response, also in the encoded
/// forms a service may echo it in (JSON-escaped, percent-encoded,
/// base64), replaced with `[redacted]`.
pub fn redact(text: &str, secret: &str) -> String {
    use base64::Engine;
    if secret.is_empty() {
        return text.to_string();
    }
    let json = serde_json::to_string(secret).unwrap_or_default();
    let mut forms = vec![
        secret.to_string(),
        json.strip_prefix('"')
            .and_then(|inner| inner.strip_suffix('"'))
            .unwrap_or_default()
            .to_string(),
        percent_encode(secret),
        base64::engine::general_purpose::STANDARD.encode(secret),
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(secret),
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(secret),
    ];
    // Longest first, so a form that contains another goes whole.
    forms.sort_by_key(|form| std::cmp::Reverse(form.len()));
    forms.dedup();
    let mut text = text.to_string();
    for form in forms.iter().filter(|form| !form.is_empty()) {
        text = text.replace(form.as_str(), REDACTED);
    }
    text
}

/// Every byte outside the unreserved set as `%XX`, as a query string or a
/// form would carry the credential.
fn percent_encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// What lore calls itself to the services it operates.
const USER_AGENT: &str = concat!("lore/", env!("CARGO_PKG_VERSION"));

/// The HTTP client every provider call goes through: no redirects, so a
/// credential is never forwarded to another host, no proxy from the
/// environment, and 60 s per call. It names itself, because GitHub answers
/// 403 to any request without a `User-Agent`.
pub fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .user_agent(USER_AGENT)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .timeout(Duration::from_secs(60))
        .build()
        .expect("building the provider client")
}

/// The server URL the administrator enters for gitlab or dokploy:
/// `https://` only (`http://` is allowed for localhost and 127.0.0.1,
/// which tests use), a host, no credentials, no query and no fragment. A
/// trailing `/` and a trailing `/api` or `/api/v4` are stripped, so the
/// admin may paste either form.
pub fn normalize_server_url(url: &str) -> Result<String, String> {
    let url = url.trim();
    let parsed = reqwest::Url::parse(url).map_err(|_| {
        "the server URL is not valid; it looks like https://git.example.com".to_string()
    })?;
    let host = parsed.host_str().unwrap_or("");
    let local = parsed.scheme() == "http" && (host == "localhost" || host == "127.0.0.1");
    if parsed.scheme() != "https" && !local {
        return Err("the server URL must use https (http is only allowed for localhost)".into());
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("the server URL must not carry a username or password".into());
    }
    if parsed.query().is_some() {
        return Err("the server URL must not carry a query".into());
    }
    if parsed.fragment().is_some() {
        return Err("the server URL must not carry a fragment".into());
    }
    // The parsed form is stored, so what is kept is exactly what every
    // later parse of it sees.
    let mut cleaned = parsed.as_str().trim_end_matches('/').to_string();
    for suffix in ["/api/v4", "/api"] {
        if cleaned.ends_with(suffix) {
            cleaned.truncate(cleaned.len() - suffix.len());
            break;
        }
    }
    Ok(cleaned.trim_end_matches('/').to_string())
}

/// One of `METHODS` as a `reqwest::Method`; the input is normalised.
fn method_as(method: &str) -> reqwest::Method {
    match method {
        "GET" => reqwest::Method::GET,
        "POST" => reqwest::Method::POST,
        "PUT" => reqwest::Method::PUT,
        "PATCH" => reqwest::Method::PATCH,
        _ => reqwest::Method::DELETE,
    }
}

/// A short, secret-free sentence for a transport failure. The credential
/// travels in headers, which reqwest errors never repeat.
pub fn transport_reason(error: &reqwest::Error) -> String {
    if error.is_timeout() {
        "the request timed out".into()
    } else if error.is_connect() {
        "the connection failed".into()
    } else if error.is_builder() {
        "the request could not be built".into()
    } else if error.is_body() {
        "the request body could not be sent".into()
    } else {
        "the response could not be read".into()
    }
}

#[cfg(test)]
mod tests {
    use axum::{
        Router,
        body::Bytes,
        extract::{Request, State},
        http::{StatusCode, header},
        response::IntoResponse,
        routing::any,
    };
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::db::PROVIDERS;

    /// One request the mock server received.
    #[derive(Debug, Clone, Default)]
    struct Seen {
        method: String,
        path: String,
        query: String,
        headers: Vec<(String, String)>,
        body: String,
    }

    type Log = Arc<Mutex<Vec<Seen>>>;

    /// The headers worth checking, lowercased as HTTP names are.
    const WATCHED: [&str; 6] = [
        "user-agent",
        "authorization",
        "accept",
        "x-github-api-version",
        "private-token",
        "x-api-key",
    ];

    /// Serves a router that records every request and answers with a
    /// fixed status and body. A local mock, never a real service.
    async fn serve(router: Router) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            axum::serve(listener, router.into_make_service())
                .await
                .unwrap();
        });
        base
    }

    fn recording_router(log: &Log, status: StatusCode, body: impl Into<Bytes>) -> Router {
        let log = log.clone();
        let body = body.into();
        Router::new().route(
            "/{*rest}",
            any(move |State(log): State<Log>, request: Request| async move {
                let (parts, raw) = request.into_parts();
                let raw = axum::body::to_bytes(raw, 4 * 1024 * 1024)
                    .await
                    .unwrap_or_default();
                let mut seen = Seen {
                    method: parts.method.to_string(),
                    path: parts.uri.path().to_string(),
                    query: parts.uri.query().unwrap_or_default().to_string(),
                    body: String::from_utf8_lossy(&raw).into_owned(),
                    ..Default::default()
                };
                for name in WATCHED {
                    if let Some(value) = parts.headers.get(name) {
                        seen.headers
                            .push((name.to_string(), value.to_str().unwrap_or("").to_string()));
                    }
                }
                log.lock().unwrap().push(seen);
                (status, body).into_response()
            })
            .with_state(log),
        )
    }

    /// The newest request the mock saw.
    fn last(log: &Log) -> Seen {
        log.lock().unwrap().last().cloned().unwrap()
    }

    fn temp_db() -> Db {
        let dir = std::env::temp_dir().join(format!(
            "lore-ops-test-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        Db::open(&dir.join("lore.db")).unwrap()
    }

    fn key() -> VaultKey {
        VaultKey::from_env_value(&"ab".repeat(32)).unwrap().unwrap()
    }

    fn request(provider: Provider, method: &str, path: &str) -> OpsRequest {
        OpsRequest {
            provider,
            method: method.into(),
            path: path.into(),
            query: None,
            body: None,
        }
    }

    /// One provider's auth expectation: what the mock must have received.
    type Expected = Vec<(String, String)>;

    fn headers(pairs: &[(&str, &str)]) -> Expected {
        pairs
            .iter()
            .map(|(name, value)| ((*name).to_string(), (*value).to_string()))
            .collect()
    }

    #[tokio::test]
    async fn each_provider_sends_its_own_auth_header() {
        let log: Log = Arc::new(Mutex::new(Vec::new()));
        let base = serve(recording_router(&log, StatusCode::OK, "{\"ok\":true}")).await;
        let client = client();
        let secret = Secret::new("test-credential-value");

        let cases: [(Provider, String, Expected); 4] = [
            (
                CLOUDFLARE,
                format!("{base}/client/v4"),
                headers(&[
                    ("user-agent", USER_AGENT),
                    ("authorization", "Bearer test-credential-value"),
                    // reqwest's own default Accept.
                    ("accept", "*/*"),
                ]),
            ),
            (
                GITHUB,
                base.clone(),
                headers(&[
                    ("user-agent", USER_AGENT),
                    ("authorization", "Bearer test-credential-value"),
                    ("accept", "application/vnd.github+json"),
                    ("x-github-api-version", "2022-11-28"),
                ]),
            ),
            (
                GITLAB,
                format!("{base}/api/v4"),
                headers(&[
                    ("user-agent", USER_AGENT),
                    ("accept", "*/*"),
                    ("private-token", "test-credential-value"),
                ]),
            ),
            (
                DOKPLOY,
                format!("{base}/api"),
                headers(&[
                    ("user-agent", USER_AGENT),
                    ("accept", "*/*"),
                    ("x-api-key", "test-credential-value"),
                ]),
            ),
        ];
        for (provider, api_base, headers) in cases {
            call(
                &client,
                &api_base,
                &secret,
                &request(provider, "get", "/zones"),
            )
            .await
            .unwrap();
            let seen = last(&log);
            assert_eq!(seen.method, "GET", "{}", provider.id);
            assert_eq!(seen.headers, headers, "{}", provider.id);
        }
        // The four ids are exactly the fixed list.
        let ids: Vec<&str> = ALL.iter().map(|provider| provider.id).collect();
        assert_eq!(ids, PROVIDERS);
    }

    #[tokio::test]
    async fn query_and_body_are_passed_through() {
        let log: Log = Arc::new(Mutex::new(Vec::new()));
        let base = serve(recording_router(&log, StatusCode::CREATED, "{}")).await;
        let client = client();
        let mut query = serde_json::Map::new();
        query.insert("per_page".into(), Value::from(2));
        query.insert("labels".into(), Value::from("bug x&y"));
        query.insert("open".into(), Value::from(true));

        let response = call(
            &client,
            &base,
            &Secret::new("test-credential-value"),
            &OpsRequest {
                provider: GITHUB,
                method: "POST".into(),
                path: "/repos/owner/repo/issues".into(),
                query: Some(query),
                body: Some(serde_json::json!({"title": "Add refunds"})),
            },
        )
        .await
        .unwrap();
        assert_eq!(response.status, 201);
        let seen = last(&log);
        assert_eq!(seen.method, "POST");
        assert_eq!(seen.path, "/repos/owner/repo/issues");
        assert!(seen.query.contains("per_page=2"), "{}", seen.query);
        assert!(seen.query.contains("labels=bug+x%26y"), "{}", seen.query);
        assert!(seen.query.contains("open=true"), "{}", seen.query);
        assert_eq!(seen.body, "{\"title\":\"Add refunds\"}");
        assert!(seen.headers.contains(&(
            "authorization".into(),
            "Bearer test-credential-value".into()
        )));

        // GET refuses a body; a query value that is not a string, a number
        // or a boolean is refused without a call.
        let mut bad_query = serde_json::Map::new();
        bad_query.insert("filters".into(), Value::from(vec!["a"]));
        for req in [
            OpsRequest {
                provider: GITHUB,
                method: "GET".into(),
                path: "/user".into(),
                query: None,
                body: Some(serde_json::json!({})),
            },
            OpsRequest {
                provider: GITHUB,
                method: "POST".into(),
                path: "/user".into(),
                query: Some(bad_query),
                body: None,
            },
            OpsRequest {
                provider: GITHUB,
                method: "TELEPORT".into(),
                path: "/user".into(),
                query: None,
                body: None,
            },
        ] {
            assert!(call(&client, &base, &Secret::new("x"), &req).await.is_err());
        }
        assert_eq!(log.lock().unwrap().len(), 1);
    }

    #[test]
    fn paths_are_checked_before_anything_is_sent() {
        assert!(validate_path("/zones").is_ok());
        assert!(validate_path("/zones/{zone_id}/dns_records").is_ok());
        for bad in [
            "zones",
            "/a?x=1",
            "/a#b",
            "/a b",
            "/a\nb",
            "/../x",
            "/a/..",
            &format!("/{}", "x".repeat(MAX_PATH_CHARS)),
        ] {
            assert!(validate_path(bad).is_err(), "{bad:?} was accepted");
        }
    }

    #[tokio::test]
    async fn a_path_cannot_change_the_host() {
        let log: Log = Arc::new(Mutex::new(Vec::new()));
        let base = serve(recording_router(&log, StatusCode::OK, "{}")).await;
        // A path that looks like a URL stays a path: the request goes to
        // the base's host, with the base's port, as one opaque path.
        call(
            &client(),
            &base,
            &Secret::new("test-credential-value"),
            &request(GITHUB, "GET", "//api.example.com/user"),
        )
        .await
        .unwrap();
        let seen = last(&log);
        assert_eq!(seen.path, "//api.example.com/user");
        assert!(seen.headers.contains(&(
            "authorization".into(),
            "Bearer test-credential-value".into()
        )));
    }

    #[tokio::test]
    async fn a_redirect_is_returned_as_is_and_not_followed() {
        let router = Router::new().route(
            "/api/user",
            axum::routing::get(|| async {
                (
                    StatusCode::FOUND,
                    [(header::LOCATION, "https://api.example.com/user")],
                )
                    .into_response()
            }),
        );
        let base = serve(router).await;
        let response = call(
            &client(),
            &format!("{base}/api"),
            &Secret::new("test-credential-value"),
            &request(GITHUB, "GET", "/user"),
        )
        .await
        .unwrap();
        // The 302 came back; the credential never went anywhere else.
        assert_eq!(response.status, 302);
    }

    #[tokio::test]
    async fn an_echoed_credential_is_redacted() {
        let secret = "test-credential-value";
        let log: Log = Arc::new(Mutex::new(Vec::new()));
        let body = format!("your token is {secret} and again {secret}");
        let base = serve(recording_router(&log, StatusCode::OK, body)).await;
        let response = call(
            &client(),
            &base,
            &Secret::new(secret),
            &request(GITHUB, "GET", "/user"),
        )
        .await
        .unwrap();
        assert_eq!(
            response.body,
            "your token is [redacted] and again [redacted]"
        );
    }

    #[tokio::test]
    async fn long_bodies_are_cut_to_a_readable_length() {
        let log: Log = Arc::new(Mutex::new(Vec::new()));
        let big = "x".repeat(MAX_BODY_CHARS + 50_000);
        let base = serve(recording_router(&log, StatusCode::OK, big)).await;
        let response = call(
            &client(),
            &base,
            &Secret::new("test-credential-value"),
            &request(DOKPLOY, "GET", "/project.all"),
        )
        .await
        .unwrap();
        assert!(response.truncated);
        assert_eq!(response.body.chars().count(), MAX_BODY_CHARS);

        // Past the 2 MiB read cap the text is cut as well.
        let huge = "y".repeat(MAX_RESPONSE_BYTES + 1024 * 1024);
        let base = serve(recording_router(&log, StatusCode::OK, huge)).await;
        let response = call(
            &client(),
            &base,
            &Secret::new("test-credential-value"),
            &request(DOKPLOY, "GET", "/project.all"),
        )
        .await
        .unwrap();
        assert!(response.truncated);
        assert_eq!(response.body.chars().count(), MAX_BODY_CHARS);

        // Cut at 2 MiB inside a multi-byte character: still text.
        let multi = format!("y{}", "é".repeat(MAX_RESPONSE_BYTES));
        let base = serve(recording_router(&log, StatusCode::OK, multi)).await;
        let response = call(
            &client(),
            &base,
            &Secret::new("test-credential-value"),
            &request(DOKPLOY, "GET", "/project.all"),
        )
        .await
        .unwrap();
        assert!(response.truncated);
        assert!(response.body.starts_with("yé"), "{}", &response.body[..20]);

        // A short body is not cut.
        let base = serve(recording_router(&log, StatusCode::OK, "{}")).await;
        let response = call(
            &client(),
            &base,
            &Secret::new("test-credential-value"),
            &request(DOKPLOY, "GET", "/project.all"),
        )
        .await
        .unwrap();
        assert!(!response.truncated);
        assert_eq!(response.body, "{}");
    }

    #[tokio::test]
    async fn binary_bodies_become_one_line() {
        let log: Log = Arc::new(Mutex::new(Vec::new()));
        let bytes = Bytes::from(vec![0x89u8, b'P', b'N', b'G', 0xff, 0x00, 0x01]);
        let base = serve(recording_router(&log, StatusCode::OK, bytes)).await;
        let response = call(
            &client(),
            &base,
            &Secret::new("test-credential-value"),
            &request(GITLAB, "GET", "/projects"),
        )
        .await
        .unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(
            response.body,
            "[binary response: 7 bytes of binary data received]"
        );
        assert!(!response.truncated);
    }

    #[test]
    fn server_urls_are_validated_and_normalised() {
        assert_eq!(
            normalize_server_url("https://git.example.com").unwrap(),
            "https://git.example.com"
        );
        // The admin may paste either form.
        assert_eq!(
            normalize_server_url("https://git.example.com/").unwrap(),
            "https://git.example.com"
        );
        assert_eq!(
            normalize_server_url("https://git.example.com/api/v4").unwrap(),
            "https://git.example.com"
        );
        assert_eq!(
            normalize_server_url("https://git.example.com/api").unwrap(),
            "https://git.example.com"
        );
        assert_eq!(
            normalize_server_url("https://git.example.com/team/api/v4/").unwrap(),
            "https://git.example.com/team"
        );
        // Local addresses may use http, which the tests rely on.
        assert_eq!(
            normalize_server_url("http://localhost:8123/x/").unwrap(),
            "http://localhost:8123/x"
        );
        assert_eq!(
            normalize_server_url("http://127.0.0.1:3000/api").unwrap(),
            "http://127.0.0.1:3000"
        );
        for bad in [
            "http://git.example.com",
            "ftp://git.example.com",
            "https://user:pass@git.example.com",
            "https://git.example.com?x=1",
            "https://git.example.com#frag",
            "not a url",
            "",
        ] {
            assert!(normalize_server_url(bad).is_err(), "{bad:?} was accepted");
        }
    }

    #[test]
    fn api_bases_come_from_the_fixed_url_or_the_admins() {
        assert_eq!(
            CLOUDFLARE.api_base("ignored"),
            "https://api.cloudflare.com/client/v4"
        );
        assert_eq!(GITHUB.api_base(""), "https://api.github.com");
        assert_eq!(
            GITLAB.api_base("https://git.example.com"),
            "https://git.example.com/api/v4"
        );
        // Even a trailing slash left behind cannot double up.
        assert_eq!(
            GITLAB.api_base("https://git.example.com/"),
            "https://git.example.com/api/v4"
        );
        assert_eq!(
            DOKPLOY.api_base("https://deploy.example.com"),
            "https://deploy.example.com/api"
        );
    }

    #[test]
    fn authorize_walks_its_checks_in_order() {
        let db = temp_db();
        let key = key();
        let auth = |method: &str| authorize(&db, Some(&key), "claude", "claude", GITHUB, method);

        // No vault key on the server.
        let denied = authorize(&db, None, "claude", "claude", GITHUB, "GET").unwrap_err();
        assert_eq!(denied.reason, "the vault is not enabled on this server");

        // The kill switch.
        db.set_ops_enabled(false).unwrap();
        assert_eq!(
            auth("GET").unwrap_err().reason,
            "operations are switched off by the administrator"
        );
        db.set_ops_enabled(true).unwrap();

        // Nothing stored for the provider.
        assert_eq!(
            auth("GET").unwrap_err().reason,
            "no github credential is stored"
        );

        // A stored credential, but the agent has no access.
        let (nonce, secret) = key.encrypt("github", "", "ghp_test-token-42");
        db.set_vault("github", "", &nonce, &secret, "d-42").unwrap();
        db.set_ops_level("claude", "github", "off").unwrap();
        assert_eq!(
            auth("GET").unwrap_err().reason,
            "you have no access to github"
        );

        // Read-only: GET goes through, a write does not.
        db.set_ops_level("claude", "github", "read").unwrap();
        assert_eq!(
            auth("POST").unwrap_err().reason,
            "you have read-only access to github"
        );
        let granted = auth("GET").unwrap();
        assert_eq!(granted.api_base, "https://api.github.com");
        assert_eq!(granted.secret.expose(), "ghp_test-token-42");

        // Full is the default: no row, everything allowed.
        db.set_ops_level("claude", "github", "full").unwrap();
        assert_eq!(auth("DELETE").unwrap().api_base, "https://api.github.com");

        // A provider that needs the server URL.
        let (nonce, secret) = key.encrypt("gitlab", "", "glpat-1234");
        db.set_vault("gitlab", "", &nonce, &secret, "1234").unwrap();
        let denied = authorize(&db, Some(&key), "claude", "claude", GITLAB, "GET").unwrap_err();
        assert_eq!(
            denied.reason,
            "no gitlab server URL is stored; the administrator must enter it"
        );
        let (nonce, secret) = key.encrypt("gitlab", "https://git.example.com", "glpat-1234");
        db.set_vault("gitlab", "https://git.example.com", &nonce, &secret, "1234")
            .unwrap();
        let granted = authorize(&db, Some(&key), "claude", "claude", GITLAB, "GET").unwrap();
        assert_eq!(granted.api_base, "https://git.example.com/api/v4");
        assert_eq!(granted.server_url, "https://git.example.com");
        assert_eq!(granted.secret.expose(), "glpat-1234");

        // A row pointed at another server without the credential being
        // entered again no longer decrypts: the call is refused.
        db.set_vault(
            "gitlab",
            "https://attacker.example",
            &nonce,
            &secret,
            "1234",
        )
        .unwrap();
        let denied = authorize(&db, Some(&key), "claude", "claude", GITLAB, "GET").unwrap_err();
        assert!(denied.reason.contains("server URL"), "{}", denied.reason);
    }

    #[test]
    fn the_level_is_the_stricter_of_token_and_session() {
        let db = temp_db();
        let key = key();
        let (nonce, secret) = key.encrypt("github", "", "ghp_test-token-42");
        db.set_vault("github", "", &nonce, &secret, "d-42").unwrap();

        // The admin restricts `codex`; codex connects with the shared token
        // and names its session `codex`: the restriction holds.
        db.set_ops_level("codex", "github", "off").unwrap();
        assert_eq!(
            effective_level(&db, "shared", "codex", "github").unwrap(),
            "off"
        );
        let denied = authorize(&db, Some(&key), "shared", "codex", GITHUB, "GET").unwrap_err();
        assert_eq!(denied.reason, "you have no access to github");
        // Restricting `shared` binds every shared-token client, whatever
        // its session says.
        db.set_ops_level("shared", "github", "read").unwrap();
        assert_eq!(
            effective_level(&db, "shared", "other", "github").unwrap(),
            "read"
        );
        assert!(authorize(&db, Some(&key), "shared", "other", GITHUB, "POST").is_err());
        assert!(authorize(&db, Some(&key), "shared", "other", GITHUB, "GET").is_ok());
        // An empty session name falls back to the token.
        assert_eq!(
            effective_level(&db, "shared", "", "github").unwrap(),
            "read"
        );
        assert_eq!(acting_as("shared", "codex"), "codex via shared");
        assert_eq!(acting_as("claude", "claude"), "claude");
        assert_eq!(acting_as("claude", ""), "claude");
    }

    #[test]
    fn an_unknown_level_grants_nothing() {
        assert_eq!(level_rank("full"), 2);
        assert_eq!(level_rank("read"), 1);
        for odd in ["off", "READ", "sometimes", ""] {
            assert_eq!(level_rank(odd), 0, "{odd:?}");
        }
    }

    #[test]
    fn credential_minting_endpoints_are_refused() {
        for (provider, path) in [
            (CLOUDFLARE, "/user/tokens"),
            (CLOUDFLARE, "/accounts/abc/tokens/xyz/value"),
            (GITHUB, "/repos/owner/repo/keys"),
            (GITHUB, "/user/keys"),
            (GITHUB, "/orgs/acme/actions/runners/registration-token"),
            (GITLAB, "/personal_access_tokens/self/rotate"),
            (GITLAB, "/projects/group%2Fproject/access_tokens"),
            (GITLAB, "/users/7/impersonation_tokens"),
            (DOKPLOY, "/user.createApiKey"),
            // Encodings and doubled slashes do not hide it.
            (CLOUDFLARE, "/user/%74okens"),
            (CLOUDFLARE, "//User//Tokens"),
            (GITLAB, "/a/./../personal_access_tokens"),
        ] {
            let req = OpsRequest {
                provider,
                method: "POST".into(),
                path: path.into(),
                query: None,
                body: None,
            };
            match validate(&req) {
                Err(OpsError::Invalid(reason)) => {
                    assert!(
                        reason.contains("credentials") || reason.contains("`..`"),
                        "{path}: {reason}"
                    );
                }
                other => panic!("{path} was accepted: {other:?}"),
            }
        }
        // Ordinary calls next to them go through.
        for (provider, path) in [
            (CLOUDFLARE, "/zones"),
            (CLOUDFLARE, "/user"),
            (GITHUB, "/repos/owner/repo/pulls"),
            (GITHUB, "/user/repos"),
            (GITLAB, "/projects/group%2Fproject/merge_requests"),
            (DOKPLOY, "/application.deploy"),
        ] {
            assert!(
                denied_path(&provider, &normalize_path(path).unwrap()).is_none(),
                "{path}"
            );
        }
    }

    #[test]
    fn dot_segments_and_backslashes_cannot_leave_the_base() {
        for bad in [
            "/%2e%2e/%2e%2e/user/tokens",
            "/.%2E/x",
            "/a\\..\\..\\x",
            "/a/..%2fb",
            "/a/%5cb",
        ] {
            assert!(normalize_path(bad).is_err(), "{bad:?} was accepted");
        }
        assert_eq!(normalize_path("/a/./b").unwrap(), "/a/b");
        assert_eq!(normalize_path("/zones").unwrap(), "/zones");
    }

    #[test]
    fn redaction_covers_encoded_forms() {
        use base64::Engine;
        let secret = "tok/en+1=x";
        let text = format!(
            "{secret} {} {} {}",
            serde_json::to_string(secret).unwrap(),
            "tok%2Fen%2B1%3Dx",
            base64::engine::general_purpose::STANDARD.encode(secret)
        );
        let out = redact(&text, secret);
        assert!(!out.contains("tok"), "{out}");
        assert_eq!(redact("nothing here", secret), "nothing here");
    }

    #[test]
    fn test_requests_are_harmless_reads() {
        assert_eq!(CLOUDFLARE.test_request().path, "/zones");
        assert_eq!(
            CLOUDFLARE.test_request().query.as_ref().unwrap()["per_page"],
            Value::from(1)
        );
        assert_eq!(GITHUB.test_request().path, "/user");
        assert_eq!(GITLAB.test_request().path, "/user");
        assert_eq!(DOKPLOY.test_request().path, "/project.all");
        for provider in ALL {
            let req = provider.test_request();
            assert_eq!(req.method, "GET");
            assert!(req.body.is_none());
            assert!(validate(&req).is_ok(), "{}", provider.id);
        }
        // A credential that is not header text is refused, never sent.
        assert!(sensitive_header("ok-value").unwrap().is_sensitive());
        assert!(sensitive_header("bad\nvalue").is_err());
    }

    #[tokio::test]
    async fn an_unreachable_service_is_a_transport_error() {
        // Port 1 on localhost refuses connections; nothing real is called.
        let response = call(
            &client(),
            "http://127.0.0.1:1/api",
            &Secret::new("test-credential-value"),
            &request(DOKPLOY, "GET", "/project.all"),
        )
        .await;
        let error = response.unwrap_err();
        assert!(matches!(error, OpsError::Transport(_)), "{error:?}");
        assert!(
            error.message().contains("connection"),
            "{}",
            error.message()
        );
    }
}
