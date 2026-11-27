//! The runner link: what lore and a built-in agent's runner say to each
//! other over the WebSocket at `/runner/ws`.
//!
//! Every frame is one JSON text message, an object whose `type` names the
//! message. The runner opens with [`FromRunner::Hello`]; lore answers
//! [`ToRunner::Welcome`] or [`ToRunner::Refused`] and closes. After that
//! lore sends commands and the runner answers and streams events. A command
//! that expects an answer carries an `id`, and the answer repeats it.
//!
//! The protocol is versioned by [`PROTOCOL_VERSION`]: a new message or a
//! new optional field keeps the number; a change an older peer would
//! misread raises it, and lore refuses a runner that speaks another one.
//! Unknown fields are ignored on both sides, so optional fields can be
//! added without breaking an older peer.
//!
//! Secrets cross the link only inside [`Secret`], whose `Debug` output is
//! `[redacted]`, so a message can be logged with `{:?}` without leaking
//! one. lore never stores or logs what a `Secret` holds.

use serde::{Deserialize, Serialize};

/// The version of this protocol. Both sides must speak the same one.
pub const PROTOCOL_VERSION: u32 = 2;

/// Largest frame either side accepts, in bytes.
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;

/// The CLI a runner drives. lore itself never runs one: it only shows the
/// kind and passes it on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// Claude Code (`claude`).
    Claude,
    /// The Codex CLI (`codex`).
    Codex,
    /// opencode (`opencode`), pointed at a provider such as DeepSeek.
    Opencode,
}

impl Kind {
    pub fn id(self) -> &'static str {
        match self {
            Kind::Claude => "claude",
            Kind::Codex => "codex",
            Kind::Opencode => "opencode",
        }
    }

    pub fn parse(id: &str) -> Option<Self> {
        match id.trim().to_ascii_lowercase().as_str() {
            "claude" => Some(Kind::Claude),
            "codex" => Some(Kind::Codex),
            "opencode" => Some(Kind::Opencode),
            _ => None,
        }
    }

    /// The executable on the image's `PATH`.
    pub fn program(self) -> &'static str {
        self.id()
    }

    /// How the owner may sign this kind in from the admin page.
    pub fn login_methods(self) -> &'static [LoginMethod] {
        match self {
            Kind::Claude => &[LoginMethod::Interactive],
            Kind::Codex => &[LoginMethod::Device],
            Kind::Opencode => &[],
        }
    }

    /// Which credentials the owner may paste for this kind.
    pub fn credentials(self) -> &'static [CredentialKind] {
        match self {
            Kind::Claude => &[CredentialKind::SetupToken, CredentialKind::ApiKey],
            Kind::Codex => &[CredentialKind::AuthJson, CredentialKind::ApiKey],
            Kind::Opencode => &[CredentialKind::ApiKey],
        }
    }
}

/// A value that must never be printed: a token, a key, an `auth.json`, a
/// login code. Serialized as the plain string; `Debug` shows nothing.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[redacted]")
    }
}

/// An interactive sign-in the runner drives and the page relays.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoginMethod {
    /// `codex login --device-auth`: a URL and a one-time code to enter there.
    Device,
    /// `claude auth login`: a URL; the code the browser shows is pasted back.
    Interactive,
}

impl LoginMethod {
    pub fn id(self) -> &'static str {
        match self {
            LoginMethod::Device => "device",
            LoginMethod::Interactive => "interactive",
        }
    }
}

/// A credential the owner pastes in the admin page. The runner writes it
/// into the agent's own volume (mode 0600); lore only passes it through.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    /// A token made with `claude setup-token` (`CLAUDE_CODE_OAUTH_TOKEN`).
    SetupToken,
    /// The contents of a Codex `auth.json` made elsewhere.
    AuthJson,
    /// A provider API key: `codex login --with-api-key`, or the key of an
    /// opencode provider (`DEEPSEEK_API_KEY` for DeepSeek), or Anthropic's
    /// for Claude Code (`ANTHROPIC_API_KEY`).
    ApiKey,
}

impl CredentialKind {
    pub fn id(self) -> &'static str {
        match self {
            CredentialKind::SetupToken => "setup_token",
            CredentialKind::AuthJson => "auth_json",
            CredentialKind::ApiKey => "api_key",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            CredentialKind::SetupToken => "setup token",
            CredentialKind::AuthJson => "auth.json",
            CredentialKind::ApiKey => "API key",
        }
    }
}

/// What a run is for (used from part 6b on).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunKind {
    /// A board task, ending in a push to the task's repository.
    Task,
    /// A task another agent handed over.
    Help,
    /// A conversation; no push rights.
    Chat,
}

/// What a terminal shows (used from part 6d on).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminalMode {
    /// The CLI's own interactive interface.
    Cli,
    /// A shell as the agent user.
    Shell,
}

/// Everything a runner needs to start a run (part 6b). The token is the
/// run-scoped lore token: it reaches lore's MCP endpoint and git proxy for
/// this run only.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunSpec {
    pub run_id: String,
    pub kind: RunKind,
    /// `https://lore/git/<route>/<owner>/<repo>.git`, cloned into
    /// `/work/<run id>`.
    pub clone_url: String,
    /// lore's MCP endpoint as the CLI reaches it.
    pub mcp_url: String,
    pub token: Secret,
    pub model: String,
    pub prompt: String,
    /// A CLI session to resume, for a follow-up.
    #[serde(default)]
    pub resume: Option<String>,
    /// The name of the run's directory under `/work`, when it is not the
    /// run id: a conversation keeps one name for every turn, because a
    /// CLI finds the session it resumes by its working directory.
    #[serde(default)]
    pub workdir: Option<String>,
    pub wall_clock_secs: u64,
    pub output_cap_bytes: u64,
}

/// lore's MCP endpoint for one terminal's CLI and the token it calls it
/// with (`lore_term_…`), which lore accepts only while that terminal is
/// open, only on its internal listener and only from the agent's runner
/// address.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TerminalMcp {
    pub url: String,
    pub token: Secret,
}

/// lore to runner.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ToRunner {
    /// The hello was accepted.
    Welcome { protocol: u32 },
    /// The hello was refused; lore closes the link after this.
    Refused { reason: String },
    /// Report the sign-in state (answered with `Status`).
    Status {
        id: u64,
        /// The owner pressed Check: forget what was refused lately and try
        /// the first credential again.
        #[serde(default)]
        check: bool,
    },
    /// List the models the CLI offers (answered with `Models`).
    ListModels { id: u64 },
    /// Start an interactive sign-in (answered with `LoginPrompt`, later
    /// followed by `LoginDone`).
    LoginStart { id: u64, method: LoginMethod },
    /// The code the browser showed, for `claude auth login` (answered with
    /// `Done`).
    LoginCode { id: u64, code: Secret },
    /// Abandon a running sign-in (answered with `Done`).
    LoginCancel { id: u64 },
    /// Store a pasted credential in the agent's volume (answered with
    /// `Done`, then an unsolicited `Status`).
    SetCredential {
        id: u64,
        credential: CredentialKind,
        value: Secret,
    },
    /// Remove the stored sign-in (answered with `Done`).
    Logout { id: u64 },
    /// Liveness check (answered with `Pong`).
    Ping { id: u64 },
    /// Part 6b: start a run.
    RunStart { spec: RunSpec },
    /// Part 6b/6c: a follow-up message to a running CLI (a follow-up
    /// question resumes the CLI's session in a new run instead).
    #[allow(
        dead_code,
        reason = "reserved: follow-ups resume the session in a new run"
    )]
    RunInput { run_id: String, text: String },
    /// Part 6b: interrupt the CLI, then kill it if it does not stop.
    RunStop { run_id: String },
    /// Part 6b: delete `/work/<run id>` (the runner also does it by itself
    /// when a run ends).
    #[allow(dead_code, reason = "sent from part 6b on")]
    CleanWorkdir { run_id: String },
    /// Open a terminal: a PTY running the CLI's own interface or a shell.
    /// Answered by `TerminalOutput` frames and, when it ends or cannot be
    /// opened, one `TerminalExit`.
    TerminalOpen {
        term_id: String,
        mode: TerminalMode,
        cols: u16,
        rows: u16,
        /// The model the owner chose, for the CLI's interface; empty or
        /// missing for the CLI's default.
        #[serde(default)]
        model: Option<String>,
        /// lore's MCP server for the CLI's interface (never for a shell):
        /// where it is and the terminal's own token, valid while this
        /// terminal is open. Missing from an older lore.
        #[serde(default)]
        mcp: Option<TerminalMcp>,
    },
    /// Bytes typed into a terminal, base64. Empty data types nothing: it
    /// says someone is still looking, which keeps the terminal from being
    /// closed as idle.
    TerminalInput { term_id: String, data: String },
    /// The terminal's size changed.
    TerminalResize {
        term_id: String,
        cols: u16,
        rows: u16,
    },
    /// Close a terminal: its whole session is killed.
    TerminalClose { term_id: String },
    /// Claude's credentials: which comes first when both are stored
    /// (`subscription` or `api_key`) and whether to fall back to the other.
    /// Sent after the welcome and whenever the owner changes them.
    ClaudeCredentials { priority: String, fallback: bool },
}

/// The resources an agent container uses, as the runner reads them.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Resources {
    /// One-minute load average of the host.
    #[serde(default)]
    pub load: Option<f64>,
    /// Memory the container uses and may use, from its cgroup.
    #[serde(default)]
    pub mem_used_bytes: Option<u64>,
    #[serde(default)]
    pub mem_limit_bytes: Option<u64>,
    /// Free space where runs clone their repositories.
    #[serde(default)]
    pub work_free_bytes: Option<u64>,
    /// What the runner's persistent directory (the stored sign-in and the
    /// conversations' transcripts) holds.
    #[serde(default)]
    pub state_bytes: Option<u64>,
    /// Free space on the runner's persistent volume.
    #[serde(default)]
    pub state_free_bytes: Option<u64>,
    /// How many leftover entries the runner's janitor removed since the
    /// runner started, and when it last removed some (ISO 8601).
    #[serde(default)]
    pub cleaned: Option<u64>,
    #[serde(default)]
    pub cleaned_at: Option<String>,
}

/// One output line of a run, inside [`FromRunner::RunOutputs`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunLine {
    pub seq: u64,
    pub stream: String,
    pub line: String,
}

/// Runner to lore.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FromRunner {
    /// The first message on a link.
    Hello {
        protocol: u32,
        agent: String,
        kind: Kind,
        /// The model provider (`anthropic`, `openai`, `deepseek`, …).
        provider: String,
        runner_version: String,
        #[serde(default)]
        cli_version: Option<String>,
    },
    /// The sign-in state, as an answer (`id`) or on its own (no `id`).
    Status {
        #[serde(default)]
        id: Option<u64>,
        signed_in: bool,
        /// How it is signed in (`setup-token`, `ChatGPT`, `API key`, …).
        #[serde(default)]
        method: Option<String>,
        /// When the sign-in ends, ISO 8601, when the runner knows.
        #[serde(default)]
        login_ends: Option<String>,
        #[serde(default)]
        cli_version: Option<String>,
        /// What the CLI said, shortened and with every stored secret
        /// removed.
        #[serde(default)]
        detail: String,
    },
    /// What the owner must do to finish an interactive sign-in.
    LoginPrompt {
        id: u64,
        #[serde(default)]
        url: Option<String>,
        /// The one-time code to enter at the URL (device login).
        #[serde(default)]
        code: Option<String>,
        /// The owner must paste a code back (`LoginCode`).
        needs_code: bool,
        #[serde(default)]
        message: String,
    },
    /// An interactive sign-in ended.
    LoginDone {
        id: u64,
        ok: bool,
        #[serde(default)]
        message: String,
    },
    /// The models the CLI offers.
    Models {
        id: u64,
        models: Vec<String>,
        /// `cli` (asked the CLI), `fixed` (the CLI has no list), or
        /// `fallback` (the CLI could not be asked).
        source: String,
    },
    /// A command without a richer answer finished.
    Done {
        id: u64,
        ok: bool,
        #[serde(default)]
        message: String,
    },
    /// A command failed.
    Error {
        #[serde(default)]
        id: Option<u64>,
        message: String,
    },
    /// A command this runner does not implement.
    Unsupported {
        command: String,
        #[serde(default)]
        target: Option<String>,
    },
    Pong {
        id: u64,
    },
    /// Sent every minute.
    Resources(Resources),
    /// Part 6b: a run started.
    RunStarted {
        run_id: String,
        #[serde(default)]
        session_id: Option<String>,
        /// The commit the default branch was at when the checkout was
        /// made, so lore can tell later whether the run moved it.
        #[serde(default)]
        base: Option<String>,
        /// Which kind of credential the CLI was started with (`API key`,
        /// `subscription`), never the credential itself.
        #[serde(default)]
        credential: Option<String>,
    },
    /// Part 6b: one line of a run's output, parsed from the CLI's JSON
    /// stream (`text`, `tool`, `result`, `error` or `raw`).
    RunOutput {
        run_id: String,
        seq: u64,
        stream: String,
        line: String,
    },
    /// Several output lines of a run in one frame, in order: what a
    /// runner sends while the CLI prints (a CLI that prints thousands of
    /// short lines would otherwise pass the link's frame limit).
    RunOutputs {
        run_id: String,
        lines: Vec<RunLine>,
    },
    /// A run ended and its work area was deleted.
    RunExit {
        run_id: String,
        #[serde(default)]
        code: Option<i32>,
        pushed: bool,
        #[serde(default)]
        head: Option<String>,
        #[serde(default)]
        work_free_bytes: Option<u64>,
        /// Why the CLI did not end by itself (`timeout`, `stopped`,
        /// `output_cap`, `link_closed`), or why the run failed before or
        /// around it (`failed: …`). None when the CLI exited on its own.
        #[serde(default)]
        reason: Option<String>,
        /// The CLI's final message (redacted), for a conversation.
        #[serde(default)]
        answer: Option<String>,
    },
    /// Terminal bytes, base64.
    TerminalOutput {
        term_id: String,
        data: String,
    },
    /// A terminal closed, or could not be opened.
    TerminalExit {
        term_id: String,
        #[serde(default)]
        code: Option<i32>,
        /// Why, when it was not the program ending by itself.
        #[serde(default)]
        message: Option<String>,
    },
}

impl FromRunner {
    /// The `id` of the command this answers, if it answers one.
    pub fn answers(&self) -> Option<u64> {
        match self {
            FromRunner::Status { id, .. } | FromRunner::Error { id, .. } => *id,
            FromRunner::LoginPrompt { id, .. }
            | FromRunner::LoginDone { id, .. }
            | FromRunner::Models { id, .. }
            | FromRunner::Done { id, .. }
            | FromRunner::Pong { id } => Some(*id),
            _ => None,
        }
    }
}

/// Encodes a message as one text frame.
pub fn encode<T: Serialize>(message: &T) -> String {
    serde_json::to_string(message).expect("protocol messages always serialize")
}

/// Decodes one text frame.
pub fn decode<'a, T: Deserialize<'a>>(text: &'a str) -> Result<T, serde_json::Error> {
    serde_json::from_str(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_message_round_trips_with_a_stable_shape() {
        let spec = RunSpec {
            run_id: "r1".into(),
            kind: RunKind::Task,
            clone_url: "http://lore:8080/git/github/o/r.git".into(),
            mcp_url: "http://lore:8080/mcp".into(),
            token: Secret::new("run-token"),
            model: "sonnet".into(),
            prompt: "do it".into(),
            resume: None,
            workdir: None,
            wall_clock_secs: 2700,
            output_cap_bytes: 1 << 20,
        };
        let to: Vec<ToRunner> = vec![
            ToRunner::Welcome { protocol: 1 },
            ToRunner::Refused { reason: "x".into() },
            ToRunner::Status { id: 1, check: true },
            ToRunner::ListModels { id: 2 },
            ToRunner::LoginStart {
                id: 3,
                method: LoginMethod::Device,
            },
            ToRunner::LoginCode {
                id: 4,
                code: Secret::new("abc"),
            },
            ToRunner::LoginCancel { id: 5 },
            ToRunner::SetCredential {
                id: 6,
                credential: CredentialKind::SetupToken,
                value: Secret::new("sk-ant-oat01-secret"),
            },
            ToRunner::Logout { id: 7 },
            ToRunner::Ping { id: 8 },
            ToRunner::RunStart { spec },
            ToRunner::RunInput {
                run_id: "r1".into(),
                text: "more".into(),
            },
            ToRunner::RunStop {
                run_id: "r1".into(),
            },
            ToRunner::CleanWorkdir {
                run_id: "r1".into(),
            },
            ToRunner::TerminalOpen {
                term_id: "t1".into(),
                mode: TerminalMode::Cli,
                cols: 80,
                rows: 24,
                model: Some("opus".into()),
                mcp: Some(TerminalMcp {
                    url: "http://lore:8081/mcp".into(),
                    token: Secret::new("lore_term_x"),
                }),
            },
            ToRunner::TerminalInput {
                term_id: "t1".into(),
                data: "bHM=".into(),
            },
            ToRunner::TerminalResize {
                term_id: "t1".into(),
                cols: 100,
                rows: 30,
            },
            ToRunner::TerminalClose {
                term_id: "t1".into(),
            },
        ];
        for message in to {
            let text = encode(&message);
            assert_eq!(decode::<ToRunner>(&text).unwrap(), message, "{text}");
        }
        let from: Vec<FromRunner> = vec![
            FromRunner::Hello {
                protocol: 1,
                agent: "codex-builtin".into(),
                kind: Kind::Codex,
                provider: "openai".into(),
                runner_version: "0.1.0".into(),
                cli_version: Some("codex-cli 0.166.0".into()),
            },
            FromRunner::Status {
                id: None,
                signed_in: true,
                method: Some("ChatGPT".into()),
                login_ends: None,
                cli_version: None,
                detail: "Logged in".into(),
            },
            FromRunner::LoginPrompt {
                id: 3,
                url: Some("https://auth.openai.com/codex/device".into()),
                code: Some("ABCD-12345".into()),
                needs_code: false,
                message: String::new(),
            },
            FromRunner::LoginDone {
                id: 3,
                ok: true,
                message: String::new(),
            },
            FromRunner::Models {
                id: 2,
                models: vec!["gpt-5.5".into()],
                source: "cli".into(),
            },
            FromRunner::Done {
                id: 6,
                ok: true,
                message: String::new(),
            },
            FromRunner::Error {
                id: Some(9),
                message: "no".into(),
            },
            FromRunner::Unsupported {
                command: "run_start".into(),
                target: Some("r1".into()),
            },
            FromRunner::Pong { id: 8 },
            FromRunner::Resources(Resources {
                load: Some(0.5),
                ..Resources::default()
            }),
            FromRunner::RunStarted {
                run_id: "r1".into(),
                session_id: None,
                base: Some("abc".into()),
                credential: Some("API key".into()),
            },
            FromRunner::RunOutput {
                run_id: "r1".into(),
                seq: 1,
                stream: "text".into(),
                line: "hi".into(),
            },
            FromRunner::RunOutputs {
                run_id: "r1".into(),
                lines: vec![RunLine {
                    seq: 2,
                    stream: "stderr".into(),
                    line: "x".into(),
                }],
            },
            FromRunner::RunExit {
                run_id: "r1".into(),
                code: Some(0),
                pushed: true,
                head: Some("abc".into()),
                work_free_bytes: Some(1),
                reason: Some("timeout".into()),
                answer: Some("It is in src/main.rs.".into()),
            },
            FromRunner::TerminalOutput {
                term_id: "t1".into(),
                data: "aGk=".into(),
            },
            FromRunner::TerminalExit {
                term_id: "t1".into(),
                code: None,
                message: Some("closed".into()),
            },
        ];
        for message in from {
            let text = encode(&message);
            assert_eq!(decode::<FromRunner>(&text).unwrap(), message, "{text}");
        }
        // The wire shape is part of the protocol.
        assert_eq!(
            encode(&ToRunner::LoginStart {
                id: 3,
                method: LoginMethod::Interactive
            }),
            r#"{"type":"login_start","id":3,"method":"interactive"}"#
        );
        // Unknown fields are ignored, so optional ones can be added.
        let status: FromRunner =
            decode(r#"{"type":"status","signed_in":false,"later":"field"}"#).unwrap();
        assert_eq!(status.answers(), None);
        // The terminal fields added in part 6d are optional, so a peer
        // built before them still reads and writes these messages.
        let open: ToRunner =
            decode(r#"{"type":"terminal_open","term_id":"t1","mode":"shell","cols":80,"rows":24}"#)
                .unwrap();
        assert!(matches!(open, ToRunner::TerminalOpen { model: None, .. }));
        let exit: FromRunner =
            decode(r#"{"type":"terminal_exit","term_id":"t1","code":0}"#).unwrap();
        assert!(matches!(
            exit,
            FromRunner::TerminalExit { message: None, .. }
        ));
        // The help-mode fields (part 6c) are optional too.
        let started: FromRunner = decode(r#"{"type":"run_started","run_id":"r1"}"#).unwrap();
        assert!(matches!(started, FromRunner::RunStarted { base: None, .. }));
        let ended: FromRunner =
            decode(r#"{"type":"run_exit","run_id":"r1","pushed":false}"#).unwrap();
        assert!(matches!(ended, FromRunner::RunExit { answer: None, .. }));
    }

    #[test]
    fn secrets_never_show_in_debug_output() {
        let message = ToRunner::SetCredential {
            id: 1,
            credential: CredentialKind::AuthJson,
            value: Secret::new("{\"tokens\":\"very-secret\"}"),
        };
        let shown = format!("{message:?}");
        assert!(!shown.contains("very-secret"), "{shown}");
        assert!(shown.contains("[redacted]"));
        assert!(encode(&message).contains("very-secret"));
    }
}
