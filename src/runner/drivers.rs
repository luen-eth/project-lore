//! How the runner drives each CLI: where its state lives, how it is signed
//! in and out, how its sign-in state and models are read. This is the only
//! code that knows the CLIs; lore itself is CLI-agnostic.
//!
//! Every CLI runs with a cleared environment: `PATH`, `HOME`, the locale,
//! the CLI's own state directory, and the credentials the owner stored for
//! it. The runner's own link secret never reaches a CLI.

use std::{
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    process::{Child, ChildStdin, Command},
    sync::{Mutex, mpsc},
};

use super::protocol::{CredentialKind, FromRunner, Kind, LoginMethod, Secret, TerminalMode};

/// The models Claude Code accepts as aliases; it has no command that lists
/// them.
pub const CLAUDE_MODELS: &[&str] = &["opus", "sonnet", "haiku", "fable", "default"];

/// DeepSeek's model names from its API documentation, offered when
/// `opencode models` cannot be asked.
pub const DEEPSEEK_MODELS: &[&str] = &["deepseek-v4-pro", "deepseek-flash"];

/// How long a `claude setup-token` token lasts.
const SETUP_TOKEN_DAYS: i64 = 365;

/// Longest a quick CLI command (status, version, models) may take.
const QUICK_TIMEOUT: Duration = Duration::from_secs(60);

/// Longest an interactive sign-in may wait for the owner.
const LOGIN_TIMEOUT: Duration = Duration::from_secs(15 * 60);

/// How long a device login's code may follow its URL.
const CODE_GRACE: Duration = Duration::from_secs(3);

/// Most output kept from one quick command.
const OUTPUT_CAP: usize = 256 * 1024;

/// Longest status detail sent to lore.
const DETAIL_CHARS: usize = 400;

/// Largest pasted credential accepted.
pub const MAX_CREDENTIAL_BYTES: usize = 64 * 1024;

/// What the runner was configured with.
#[derive(Debug, Clone)]
pub struct Settings {
    pub kind: Kind,
    /// The model provider; for opencode, the one it is pointed at.
    pub provider: String,
    /// The agent user's home: a named volume.
    pub home: PathBuf,
    /// The CLI executable.
    pub program: PathBuf,
}

/// The output of one quick command, with every known secret removed.
#[derive(Debug)]
pub struct Output {
    pub success: bool,
    pub text: String,
}

/// An interactive sign-in in progress.
struct Login {
    id: u64,
    child: Child,
    stdin: Option<ChildStdin>,
}

/// One CLI and its state.
pub struct Driver {
    pub settings: Settings,
    login: Mutex<Option<Login>>,
}

impl Driver {
    pub fn new(settings: Settings) -> Self {
        Self {
            settings,
            login: Mutex::new(None),
        }
    }

    pub fn kind(&self) -> Kind {
        self.settings.kind
    }

    /// The runner's own files in the volume: the stored credentials
    /// (`secrets.env`) and what is known about the sign-in.
    fn state_dir(&self) -> PathBuf {
        self.settings.home.join(".lore-runner")
    }

    fn secrets_file(&self) -> PathBuf {
        self.state_dir().join("secrets.env")
    }

    fn sign_in_file(&self) -> PathBuf {
        self.state_dir().join("sign-in.json")
    }

    fn claude_dir(&self) -> PathBuf {
        self.settings.home.join(".claude")
    }

    fn codex_home(&self) -> PathBuf {
        self.settings.home.join(".codex")
    }

    fn opencode_config(&self) -> PathBuf {
        self.settings
            .home
            .join(".config")
            .join("opencode")
            .join("opencode.json")
    }

    /// The variable an opencode provider reads its API key from:
    /// `DEEPSEEK_API_KEY` for `deepseek`.
    pub fn provider_key_var(&self) -> String {
        let provider: String = self
            .settings
            .provider
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() {
                    c.to_ascii_uppercase()
                } else {
                    '_'
                }
            })
            .collect();
        format!("{provider}_API_KEY")
    }

    /// Variables the container may set for the CLI itself (an alternative
    /// to signing in from the page); passed through when set.
    fn passthrough_vars(&self) -> Vec<String> {
        match self.kind() {
            Kind::Claude => vec!["CLAUDE_CODE_OAUTH_TOKEN".into()],
            Kind::Codex => vec!["CODEX_API_KEY".into()],
            Kind::Opencode => vec![self.provider_key_var()],
        }
    }

    /// Creates the state directories and the CLI settings the runner
    /// relies on, without touching anything the owner set.
    pub fn prepare(&self) -> Result<()> {
        create_private_dir(&self.state_dir())?;
        match self.kind() {
            Kind::Claude => {
                let dir = self.claude_dir();
                create_private_dir(&dir)?;
                // Sessions are kept a year instead of the default month.
                let path = dir.join("settings.json");
                let mut settings: serde_json::Value = std::fs::read_to_string(&path)
                    .ok()
                    .and_then(|text| serde_json::from_str(&text).ok())
                    .unwrap_or_else(|| serde_json::json!({}));
                if let Some(object) = settings.as_object_mut()
                    && !object.contains_key("cleanupPeriodDays")
                {
                    object.insert("cleanupPeriodDays".into(), 365.into());
                    write_private(&path, serde_json::to_string_pretty(&settings)?.as_bytes())?;
                }
            }
            Kind::Codex => {
                let home = self.codex_home();
                create_private_dir(&home)?;
                // Credentials in `auth.json`, which the volume keeps.
                let path = home.join("config.toml");
                let current = std::fs::read_to_string(&path).unwrap_or_default();
                if !current
                    .lines()
                    .any(|line| line.trim_start().starts_with("cli_auth_credentials_store"))
                {
                    let updated = format!("cli_auth_credentials_store = \"file\"\n{current}");
                    write_private(&path, updated.as_bytes())?;
                }
            }
            Kind::Opencode => {
                let path = self.opencode_config();
                if let Some(parent) = path.parent() {
                    create_private_dir(parent)?;
                }
                if !path.exists() {
                    let config = serde_json::json!({
                        "$schema": "https://opencode.ai/config.json",
                        "update": "disable",
                    });
                    write_private(&path, serde_json::to_string_pretty(&config)?.as_bytes())?;
                }
            }
        }
        Ok(())
    }

    /// The credentials stored in the volume, as `NAME=value` pairs.
    fn stored_vars(&self) -> Vec<(String, String)> {
        let Ok(text) = std::fs::read_to_string(self.secrets_file()) else {
            return Vec::new();
        };
        text.lines()
            .filter_map(|line| line.split_once('='))
            .map(|(name, value)| (name.trim().to_string(), value.trim().to_string()))
            .filter(|(name, value)| !name.is_empty() && !value.is_empty())
            .collect()
    }

    /// Every secret the CLI's output could echo: stored credentials,
    /// passed-through variables and the tokens inside Codex's `auth.json`.
    pub fn secrets(&self) -> Vec<String> {
        let mut secrets: Vec<String> = self
            .stored_vars()
            .into_iter()
            .map(|(_, value)| value)
            .collect();
        for name in self.passthrough_vars() {
            if let Ok(value) = std::env::var(&name)
                && !value.trim().is_empty()
            {
                secrets.push(value.trim().to_string());
            }
        }
        if self.kind() == Kind::Codex
            && let Ok(text) = std::fs::read_to_string(self.codex_home().join("auth.json"))
            && let Ok(value) = serde_json::from_str::<serde_json::Value>(&text)
        {
            collect_long_strings(&value, &mut secrets);
        }
        secrets
    }

    /// Removes every known secret from CLI output.
    pub fn redact(&self, text: &str) -> String {
        redact_with(text, &self.secrets())
    }

    /// A command for the CLI with the cleared environment.
    fn command(&self, args: &[&str]) -> Command {
        self.command_for(&self.settings.program, args)
    }

    /// What a terminal runs (part 6d): the CLI's own interactive interface
    /// with the model the owner chose, or `shell`, both with the CLI's
    /// cleared environment and its stored credentials, and a terminal type
    /// that allows colour.
    pub fn terminal_command(
        &self,
        mode: TerminalMode,
        model: Option<&str>,
        shell: &Path,
    ) -> Command {
        // A model is a plain name (lore checks it); one that looks like an
        // option is left out rather than passed on.
        let model = model
            .map(str::trim)
            .filter(|model| !model.is_empty() && !model.starts_with('-'));
        let mut args: Vec<String> = Vec::new();
        if let (TerminalMode::Cli, Some(model)) = (mode, model) {
            match self.kind() {
                Kind::Claude => args.extend(["--model".into(), model.into()]),
                Kind::Codex => args.extend(["-m".into(), model.into()]),
                Kind::Opencode => {
                    let model = if model.contains('/') {
                        model.to_string()
                    } else {
                        format!("{}/{model}", self.settings.provider)
                    };
                    args.extend(["--model".into(), model]);
                }
            }
        }
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let mut command = match mode {
            TerminalMode::Cli => self.command(&args),
            TerminalMode::Shell => self.command_for(shell, &[]),
        };
        command
            .env("TERM", "xterm-256color")
            .env("COLORTERM", "truecolor")
            .env_remove("NO_COLOR");
        command
    }

    fn command_for(&self, program: &Path, args: &[&str]) -> Command {
        let mut command = Command::new(program);
        command.args(args).env_clear();
        if let Ok(path) = std::env::var("PATH") {
            command.env("PATH", path);
        }
        command
            .env("HOME", &self.settings.home)
            .env("LANG", "C.UTF-8")
            .env("TERM", "dumb")
            .env("NO_COLOR", "1")
            .current_dir(&self.settings.home);
        if let Ok(user) = std::env::var("USER") {
            command.env("USER", user);
        }
        match self.kind() {
            Kind::Claude => {
                command
                    .env("CLAUDE_CONFIG_DIR", self.claude_dir())
                    .env("DISABLE_AUTOUPDATER", "1");
            }
            Kind::Codex => {
                command.env("CODEX_HOME", self.codex_home());
            }
            Kind::Opencode => {
                command
                    .env("XDG_CONFIG_HOME", self.settings.home.join(".config"))
                    .env("XDG_DATA_HOME", self.settings.home.join(".local/share"))
                    .env("XDG_STATE_HOME", self.settings.home.join(".local/state"))
                    .env("XDG_CACHE_HOME", self.settings.home.join(".cache"))
                    .env("OPENCODE_DISABLE_AUTOUPDATE", "1");
            }
        }
        for name in self.passthrough_vars() {
            if let Ok(value) = std::env::var(&name)
                && !value.trim().is_empty()
            {
                command.env(&name, value.trim());
            }
        }
        for (name, value) in self.stored_vars() {
            command.env(name, value);
        }
        command.kill_on_drop(true);
        command
    }

    /// Runs a quick command to the end, with `stdin` written to it.
    pub async fn run(&self, args: &[&str], stdin: Option<&str>) -> Result<Output> {
        let mut command = self.command(args);
        command
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command
            .spawn()
            .with_context(|| format!("starting {}", self.settings.program.display()))?;
        if let (Some(input), Some(mut pipe)) = (stdin, child.stdin.take()) {
            pipe.write_all(input.as_bytes()).await?;
            pipe.write_all(b"\n").await?;
            drop(pipe);
        }
        let output = tokio::time::timeout(QUICK_TIMEOUT, child.wait_with_output())
            .await
            .context("the command took too long")??;
        let mut bytes = output.stdout;
        bytes.extend_from_slice(&output.stderr);
        bytes.truncate(OUTPUT_CAP);
        Ok(Output {
            success: output.status.success(),
            text: self.redact(&strip_ansi(&String::from_utf8_lossy(&bytes))),
        })
    }

    /// The CLI's version line, or `None` when it cannot be run.
    pub async fn version(&self) -> Option<String> {
        let output = self.run(&["--version"], None).await.ok()?;
        output
            .text
            .lines()
            .map(str::trim)
            .find(|line| !line.is_empty() && !line.starts_with("WARNING"))
            .map(|line| line.chars().take(120).collect())
    }

    /// The sign-in state, as a `Status` message.
    pub async fn status(&self, id: Option<u64>) -> FromRunner {
        let cli_version = self.version().await;
        let (signed_in, method, login_ends, detail) = match self.kind() {
            Kind::Claude => self.claude_status().await,
            Kind::Codex => self.codex_status().await,
            Kind::Opencode => self.opencode_status(),
        };
        FromRunner::Status {
            id,
            signed_in,
            method,
            login_ends,
            cli_version,
            detail: shorten(&detail, DETAIL_CHARS),
        }
    }

    async fn claude_status(&self) -> (bool, Option<String>, Option<String>, String) {
        let stored = self
            .stored_vars()
            .iter()
            .any(|(name, _)| name == "CLAUDE_CODE_OAUTH_TOKEN");
        let output = self.run(&["auth", "status", "--text"], None).await;
        let (success, text) = match output {
            Ok(output) => (output.success, output.text),
            Err(error) => (false, error.to_string()),
        };
        let lower = text.to_lowercase();
        let refused = [
            "not logged in",
            "not authenticated",
            "no credentials",
            "logged out",
        ]
        .iter()
        .any(|phrase| lower.contains(phrase));
        let signed_in = success && !refused;
        let meta = self.sign_in_meta();
        let (method, ends) = if stored {
            let ends = meta
                .as_ref()
                .and_then(|meta| meta.get("ends").and_then(|v| v.as_str()))
                .map(str::to_string);
            (Some("setup-token".to_string()), ends)
        } else if signed_in {
            (Some("claude.ai sign-in".to_string()), find_date(&text))
        } else {
            (None, None)
        };
        (signed_in, method, ends, text)
    }

    async fn codex_status(&self) -> (bool, Option<String>, Option<String>, String) {
        match self.run(&["login", "status"], None).await {
            Ok(output) => {
                let lower = output.text.to_lowercase();
                let method = if lower.contains("api key") {
                    Some("API key".to_string())
                } else if output.success {
                    Some("ChatGPT".to_string())
                } else {
                    None
                };
                let text = output
                    .text
                    .lines()
                    .filter(|line| !line.starts_with("WARNING"))
                    .collect::<Vec<_>>()
                    .join("\n");
                (output.success, method, None, text)
            }
            Err(error) => (false, None, None, error.to_string()),
        }
    }

    fn opencode_status(&self) -> (bool, Option<String>, Option<String>, String) {
        let var = self.provider_key_var();
        let stored = self.stored_vars().iter().any(|(name, _)| *name == var);
        let from_env = std::env::var(&var).is_ok_and(|value| !value.trim().is_empty());
        if stored || from_env {
            (
                true,
                Some("API key".into()),
                None,
                format!(
                    "an API key for {} is {}",
                    self.settings.provider,
                    if stored {
                        "stored in the agent's volume"
                    } else {
                        "set in the container environment"
                    }
                ),
            )
        } else {
            (
                false,
                None,
                None,
                format!("no API key for {} yet", self.settings.provider),
            )
        }
    }

    fn sign_in_meta(&self) -> Option<serde_json::Value> {
        std::fs::read_to_string(self.sign_in_file())
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok())
    }

    /// The models the CLI offers, and where the list came from.
    pub async fn models(&self) -> (Vec<String>, &'static str) {
        match self.kind() {
            Kind::Claude => (
                CLAUDE_MODELS.iter().map(|m| m.to_string()).collect(),
                "fixed",
            ),
            Kind::Codex => {
                for args in [
                    &["debug", "models"][..],
                    &["debug", "models", "--bundled"][..],
                ] {
                    if let Ok(output) = self.run(args, None).await
                        && output.success
                    {
                        let models = codex_models(&output.text);
                        if !models.is_empty() {
                            return (models, "cli");
                        }
                    }
                }
                (Vec::new(), "fallback")
            }
            Kind::Opencode => {
                if let Ok(output) = self.run(&["models"], None).await
                    && output.success
                {
                    let models = provider_models(&output.text, &self.settings.provider);
                    if !models.is_empty() {
                        return (models, "cli");
                    }
                }
                let fallback = if self.settings.provider == "deepseek" {
                    DEEPSEEK_MODELS.iter().map(|m| m.to_string()).collect()
                } else {
                    Vec::new()
                };
                (fallback, "fallback")
            }
        }
    }

    /// Stores a pasted credential in the volume. Never echoes it.
    pub async fn set_credential(&self, kind: CredentialKind, value: &Secret) -> Result<String> {
        if !self.kind().credentials().contains(&kind) {
            bail!(
                "a {} cannot sign {} in",
                kind.label(),
                self.settings.kind.id()
            );
        }
        let value = value.expose().trim();
        if value.is_empty() {
            bail!("the {} is empty", kind.label());
        }
        if value.len() > MAX_CREDENTIAL_BYTES {
            bail!("the {} is too long", kind.label());
        }
        let single_line = |what: &str| -> Result<()> {
            if value.chars().any(|c| c.is_whitespace() || c.is_control()) {
                bail!("the {what} must be one line without spaces");
            }
            Ok(())
        };
        match kind {
            CredentialKind::SetupToken => {
                single_line("token")?;
                self.store_var("CLAUDE_CODE_OAUTH_TOKEN", value)?;
                let ends = add_days_iso(SETUP_TOKEN_DAYS);
                write_private(
                    &self.sign_in_file(),
                    serde_json::json!({ "method": "setup-token", "saved": add_days_iso(0),
                                        "ends": ends })
                    .to_string()
                    .as_bytes(),
                )?;
                Ok("the token is stored in the agent's volume".into())
            }
            CredentialKind::AuthJson => {
                let parsed: serde_json::Value = serde_json::from_str(value)
                    .map_err(|_| anyhow::anyhow!("that is not a JSON document"))?;
                if !parsed.is_object() {
                    bail!("auth.json must be a JSON object");
                }
                self.prepare()?;
                write_private(&self.codex_home().join("auth.json"), value.as_bytes())?;
                Ok("auth.json is stored in the agent's volume".into())
            }
            CredentialKind::ApiKey => {
                single_line("API key")?;
                match self.kind() {
                    Kind::Codex => {
                        let output = self.run(&["login", "--with-api-key"], Some(value)).await?;
                        if !output.success {
                            bail!(
                                "codex refused the key: {}",
                                shorten(&output.text, DETAIL_CHARS)
                            );
                        }
                        Ok("codex is signed in with the API key".into())
                    }
                    _ => {
                        self.store_var(&self.provider_key_var(), value)?;
                        Ok(format!(
                            "the {} API key is stored in the agent's volume",
                            self.settings.provider
                        ))
                    }
                }
            }
        }
    }

    /// Sets one variable in `secrets.env`, keeping the others.
    fn store_var(&self, name: &str, value: &str) -> Result<()> {
        create_private_dir(&self.state_dir())?;
        let mut lines: Vec<String> = self
            .stored_vars()
            .into_iter()
            .filter(|(existing, _)| existing != name)
            .map(|(existing, value)| format!("{existing}={value}"))
            .collect();
        lines.push(format!("{name}={value}"));
        write_private(&self.secrets_file(), (lines.join("\n") + "\n").as_bytes())
    }

    /// Removes the stored sign-in: the runner's files and the CLI's own.
    pub async fn logout(&self) -> Result<String> {
        self.cancel_login().await;
        let _ = std::fs::remove_file(self.secrets_file());
        let _ = std::fs::remove_file(self.sign_in_file());
        match self.kind() {
            Kind::Claude => {
                let _ = self.run(&["auth", "logout"], None).await;
            }
            Kind::Codex => {
                let _ = self.run(&["logout"], None).await;
                let _ = std::fs::remove_file(self.codex_home().join("auth.json"));
            }
            Kind::Opencode => {}
        }
        Ok("signed out".into())
    }

    /// Starts an interactive sign-in. Lines the CLI prints are read until
    /// the URL (and, for a device login, the code) shows; that becomes the
    /// `LoginPrompt`. When the CLI exits a `LoginDone` and a fresh
    /// `Status` follow.
    pub async fn login_start(
        self: &Arc<Self>,
        id: u64,
        method: LoginMethod,
        out: mpsc::Sender<FromRunner>,
    ) -> Result<()> {
        if !self.kind().login_methods().contains(&method) {
            bail!(
                "{} has no {} sign-in; paste a credential instead",
                self.kind().id(),
                method.id()
            );
        }
        self.cancel_login().await;
        let args: &[&str] = match method {
            LoginMethod::Device => &["login", "--device-auth"],
            LoginMethod::Interactive => &["auth", "login", "--claudeai"],
        };
        let mut command = self.command(args);
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command
            .spawn()
            .with_context(|| format!("starting {}", self.settings.program.display()))?;
        let stdin = child.stdin.take();
        let (lines_tx, mut lines_rx) = mpsc::channel::<String>(64);
        for pipe in [
            child
                .stdout
                .take()
                .map(|p| Box::new(p) as Box<dyn tokio::io::AsyncRead + Send + Unpin>),
            child
                .stderr
                .take()
                .map(|p| Box::new(p) as Box<dyn tokio::io::AsyncRead + Send + Unpin>),
        ]
        .into_iter()
        .flatten()
        {
            let lines_tx = lines_tx.clone();
            tokio::spawn(async move {
                let mut reader = BufReader::new(pipe).lines();
                while let Ok(Some(line)) = reader.next_line().await {
                    if lines_tx.send(line).await.is_err() {
                        break;
                    }
                }
            });
        }
        drop(lines_tx);
        *self.login.lock().await = Some(Login { id, child, stdin });

        let driver = self.clone();
        tokio::spawn(async move {
            let needs_code = method == LoginMethod::Interactive;
            let (mut url, mut code) = (None::<String>, None::<String>);
            let mut said = Vec::new();
            let mut prompted = false;
            let mut url_seen: Option<tokio::time::Instant> = None;
            let deadline = tokio::time::Instant::now() + LOGIN_TIMEOUT;
            loop {
                let wait = match url_seen {
                    // A URL without a code yet: give the code a moment.
                    Some(seen) if !prompted => {
                        (seen + CODE_GRACE).saturating_duration_since(tokio::time::Instant::now())
                    }
                    _ => deadline.saturating_duration_since(tokio::time::Instant::now()),
                };
                match tokio::time::timeout(wait, lines_rx.recv()).await {
                    Ok(Some(line)) => {
                        let line = driver.redact(&strip_ansi(&line));
                        if url.is_none() {
                            url = find_url(&line);
                            if url.is_some() {
                                url_seen = Some(tokio::time::Instant::now());
                            }
                        }
                        if code.is_none() && method == LoginMethod::Device {
                            code = find_device_code(&line);
                        }
                        if !line.trim().is_empty() && said.len() < 20 {
                            said.push(line.trim().to_string());
                        }
                    }
                    Ok(None) => break,
                    Err(_) if tokio::time::Instant::now() >= deadline => break,
                    Err(_) => {}
                }
                let ready = url.is_some() && (needs_code || code.is_some());
                let waited = url_seen.is_some_and(|seen| seen.elapsed() >= CODE_GRACE);
                if !prompted && (ready || waited) {
                    prompted = true;
                    let _ = out
                        .send(FromRunner::LoginPrompt {
                            id,
                            url: url.clone(),
                            code: code.clone(),
                            needs_code,
                            message: shorten(&said.join("\n"), DETAIL_CHARS),
                        })
                        .await;
                }
            }
            // The CLI closed its output or the time ran out: collect it.
            let status = {
                let mut guard = driver.login.lock().await;
                match guard.as_mut() {
                    Some(login) if login.id == id => {
                        let status =
                            match tokio::time::timeout(Duration::from_secs(10), login.child.wait())
                                .await
                            {
                                Ok(Ok(status)) => Some(status),
                                _ => {
                                    let _ = login.child.kill().await;
                                    None
                                }
                            };
                        *guard = None;
                        status
                    }
                    // Cancelled, or replaced by a newer sign-in.
                    _ => return,
                }
            };
            let ok = status.is_some_and(|status| status.success());
            if !prompted {
                let _ = out
                    .send(FromRunner::LoginPrompt {
                        id,
                        url: None,
                        code: None,
                        needs_code: false,
                        message: shorten(&said.join("\n"), DETAIL_CHARS),
                    })
                    .await;
            }
            let message = if ok {
                "signed in".to_string()
            } else if status.is_none() {
                "the sign-in did not finish in time".to_string()
            } else {
                shorten(&said.join("\n"), DETAIL_CHARS)
            };
            let _ = out.send(FromRunner::LoginDone { id, ok, message }).await;
            let _ = out.send(driver.status(None).await).await;
        });
        Ok(())
    }

    /// Writes the code the browser showed to the running sign-in.
    pub async fn login_code(&self, code: &Secret) -> Result<()> {
        let code = code.expose().trim();
        if code.is_empty() || code.len() > 4096 || code.contains(['\n', '\r']) {
            bail!("the code must be one line");
        }
        let mut guard = self.login.lock().await;
        let Some(stdin) = guard.as_mut().and_then(|login| login.stdin.as_mut()) else {
            bail!("no sign-in is waiting for a code; start it again");
        };
        stdin.write_all(code.as_bytes()).await?;
        stdin.write_all(b"\n").await?;
        stdin.flush().await?;
        Ok(())
    }

    /// Ends a running sign-in, if there is one.
    pub async fn cancel_login(&self) -> bool {
        let taken = self.login.lock().await.take();
        match taken {
            Some(mut login) => {
                let _ = login.child.kill().await;
                true
            }
            None => false,
        }
    }
}

/// Creates a directory readable by its owner only.
fn create_private_dir(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path).with_context(|| format!("creating {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Writes a file readable by its owner only, through a temporary file so a
/// half-written credential never replaces a good one.
pub fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let parent = path.parent().context("a file needs a directory")?;
    std::fs::create_dir_all(parent)?;
    let temp = parent.join(format!(
        ".{}.tmp",
        path.file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default()
    ));
    {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&temp)
            .with_context(|| format!("writing {}", temp.display()))?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&temp, std::fs::Permissions::from_mode(0o600))?;
    }
    std::fs::rename(&temp, path).with_context(|| format!("replacing {}", path.display()))?;
    Ok(())
}

/// Every string of at least 16 characters inside a JSON value.
fn collect_long_strings(value: &serde_json::Value, out: &mut Vec<String>) {
    match value {
        serde_json::Value::String(text) if text.len() >= 16 => out.push(text.clone()),
        serde_json::Value::Array(items) => {
            for item in items {
                collect_long_strings(item, out);
            }
        }
        serde_json::Value::Object(map) => {
            for item in map.values() {
                collect_long_strings(item, out);
            }
        }
        _ => {}
    }
}

/// Replaces every secret of at least eight characters with `[redacted]`.
pub fn redact_with(text: &str, secrets: &[String]) -> String {
    let mut secrets: Vec<&str> = secrets
        .iter()
        .map(|s| s.as_str())
        .filter(|s| s.len() >= 8)
        .collect();
    // Longest first, so a secret that contains another goes whole.
    secrets.sort_by_key(|s| std::cmp::Reverse(s.len()));
    let mut text = text.to_string();
    for secret in secrets {
        if text.contains(secret) {
            text = text.replace(secret, "[redacted]");
        }
    }
    text
}

/// Removes terminal escape sequences.
pub fn strip_ansi(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            match chars.peek() {
                Some('[') => {
                    chars.next();
                    for c in chars.by_ref() {
                        if c.is_ascii_alphabetic() || c == '~' {
                            break;
                        }
                    }
                }
                Some(']') => {
                    // An OSC sequence (a hyperlink): up to BEL or ESC \.
                    chars.next();
                    while let Some(c) = chars.next() {
                        if c == '\u{7}' {
                            break;
                        }
                        if c == '\u{1b}' {
                            chars.next();
                            break;
                        }
                    }
                }
                _ => {
                    chars.next();
                }
            }
        } else if c == '\r' || (c.is_control() && c != '\n' && c != '\t') {
            continue;
        } else {
            out.push(c);
        }
    }
    out
}

/// The first `https://` URL on a line.
pub fn find_url(line: &str) -> Option<String> {
    let start = line.find("https://")?;
    let url: String = line[start..]
        .chars()
        .take_while(|c| !c.is_whitespace() && !matches!(c, '"' | '\'' | '<' | '>'))
        .collect();
    let url = url.trim_end_matches(['.', ',', ')', ']', ';']).to_string();
    (url.len() > "https://".len()).then_some(url)
}

/// A device code such as `ABCD-12345`: two or three groups of capitals
/// and digits joined by dashes.
pub fn find_device_code(line: &str) -> Option<String> {
    line.split(|c: char| c.is_whitespace() || matches!(c, ':' | '"' | '\'' | '`'))
        .map(|word| word.trim_matches(|c: char| !c.is_ascii_alphanumeric()))
        .find(|word| {
            let groups: Vec<&str> = word.split('-').collect();
            (2..=3).contains(&groups.len())
                && groups.iter().all(|group| {
                    (4..=6).contains(&group.len())
                        && group
                            .chars()
                            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
                })
                && word.chars().any(|c| c.is_ascii_uppercase())
        })
        .map(str::to_string)
}

/// The first ISO 8601 date (`YYYY-MM-DD…`) in a text.
fn find_date(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    (0..bytes.len().saturating_sub(9)).find_map(|i| {
        let candidate = &text.get(i..i + 10)?;
        let ok = candidate.chars().enumerate().all(|(n, c)| match n {
            4 | 7 => c == '-',
            _ => c.is_ascii_digit(),
        });
        ok.then(|| {
            text[i..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | ':' | '.' | '+'))
                .collect()
        })
    })
}

/// The listed model slugs of `codex debug models`.
pub fn codex_models(json: &str) -> Vec<String> {
    let start = json.find('{').unwrap_or(0);
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&json[start..]) else {
        return Vec::new();
    };
    value["models"]
        .as_array()
        .map(|models| {
            models
                .iter()
                .filter(|model| model["visibility"].as_str().is_none_or(|v| v == "list"))
                .filter_map(|model| model["slug"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// The models of one provider in `opencode models` output
/// (`provider/model` per line), without the provider prefix.
pub fn provider_models(text: &str, provider: &str) -> Vec<String> {
    let prefix = format!("{provider}/");
    let mut models: Vec<String> = text
        .lines()
        .map(str::trim)
        .filter_map(|line| line.strip_prefix(&prefix))
        .map(|model| model.split_whitespace().next().unwrap_or("").to_string())
        .filter(|model| !model.is_empty())
        .collect();
    models.dedup();
    models
}

/// Cuts a text to `max` characters.
pub fn shorten(text: &str, max: usize) -> String {
    let text = text.trim();
    if text.chars().count() <= max {
        return text.to_string();
    }
    let mut cut: String = text.chars().take(max).collect();
    cut.push('…');
    cut
}

/// Now plus `days`, as ISO 8601 UTC.
fn add_days_iso(days: i64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    iso_from_unix(now + days * 86_400)
}

/// Unix seconds as `YYYY-MM-DDTHH:MM:SSZ`.
pub fn iso_from_unix(seconds: i64) -> String {
    let (days, rest) = (seconds.div_euclid(86_400), seconds.rem_euclid(86_400));
    // Howard Hinnant's days-to-civil conversion.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_output_is_read_for_the_url_and_the_code() {
        let line = "\u{1b}[94mhttps://auth.openai.com/codex/device\u{1b}[0m.";
        assert_eq!(
            find_url(&strip_ansi(line)).as_deref(),
            Some("https://auth.openai.com/codex/device")
        );
        assert_eq!(
            find_device_code("   Enter this one-time code: \u{1b}[1mABCD-12XYZ\u{1b}[0m")
                .or_else(|| find_device_code(&strip_ansi(
                    "   Enter this one-time code: \u{1b}[1mABCD-12XYZ\u{1b}[0m"
                )))
                .as_deref(),
            Some("ABCD-12XYZ")
        );
        assert_eq!(find_device_code("see 2026-01-02 and gpt-5"), None);
        assert_eq!(find_url("no link here"), None);
        assert_eq!(
            find_date("Token ends 2027-11-26T10:00:00Z, renew").as_deref(),
            Some("2027-11-26T10:00:00Z")
        );
    }

    #[test]
    fn model_lists_are_read_from_each_cli() {
        let catalog = r#"WARNING: x
{"models":[{"slug":"gpt-6","visibility":"list"},{"slug":"hidden","visibility":"hide"},{"slug":"gpt-5.5"}]}"#;
        assert_eq!(codex_models(catalog), vec!["gpt-6", "gpt-5.5"]);
        assert!(codex_models("not json").is_empty());
        let listed = "anthropic/claude-x\ndeepseek/deepseek-v4-pro\ndeepseek/deepseek-flash\n";
        assert_eq!(
            provider_models(listed, "deepseek"),
            vec!["deepseek-v4-pro", "deepseek-flash"]
        );
    }

    #[test]
    fn secrets_are_redacted_longest_first() {
        let secrets = vec!["abcdefgh".to_string(), "abcdefgh-longer".to_string()];
        assert_eq!(
            redact_with("x abcdefgh-longer y abcdefgh", &secrets),
            "x [redacted] y [redacted]"
        );
        // Too short to redact safely.
        assert_eq!(redact_with("abc", &["abc".into()]), "abc");
        assert_eq!(iso_from_unix(0), "1970-01-01T00:00:00Z");
    }
}
