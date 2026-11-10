#![allow(unused_crate_dependencies)] // shared crate deps are for the proxy server

//! `herdr-agent` — ergonomic agent orchestration through `herdr-auth-proxy`.
//!
//! `herdr-auth call agent.prompt --params '<json>'` forces callers to escape
//! prompt text as JSON. This CLI takes prompt text as a plain argument, from a
//! file, or from stdin, and sends the same NDJSON request to the proxy.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand, ValueEnum};
use herdr_auth_proxy::client;
use serde_json::{Value, json};

/// Socket timeout used when a wait has no explicit deadline. A local unix
/// socket request can still be interrupted with Ctrl-C.
const INDEFINITE_TIMEOUT_MS: u64 = 24 * 60 * 60 * 1000;

#[derive(Debug, Parser)]
#[command(
    name = "herdr-agent",
    version,
    about = "Inspect, spawn, prompt, and close herdr agents through herdr-auth-proxy",
    after_help = "Examples:\n  herdr-agent spawn --kind opencode --name worker\n  herdr-agent prompt worker --text-file prompt.md\n  printf 'review this\\n' | herdr-agent prompt worker\n  herdr-agent read worker --lines 200\n  herdr-agent wait worker --until idle --wait-ms 300000\n  herdr-agent kill worker\n\nPrompt text is sent verbatim; prefer --text-file or stdin over --text to avoid shell quoting."
)]
struct Cli {
    /// Proxy socket path (default: herdr-auth-proxy's resolved auth socket)
    #[arg(long, global = true, env = "HERDR_AUTH_SOCKET")]
    socket: Option<PathBuf>,

    /// JWT for this request (overrides $HERDR_AUTH_JWT; prefer --token-file since flags leak into ps)
    #[arg(long, global = true)]
    token: Option<String>,

    /// File containing the JWT
    #[arg(long, global = true, env = "HERDR_AUTH_TOKEN_FILE")]
    token_file: Option<PathBuf>,

    /// Pretty-print the result payload
    #[arg(long, global = true)]
    pretty: bool,

    /// Print the raw response line instead of the result payload
    #[arg(long, global = true)]
    raw: bool,

    /// Socket read/write timeout in milliseconds (default: 60s, or wait + 60s for prompt/wait)
    #[arg(long, global = true)]
    timeout_ms: Option<u64>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Atomically create a tab, mint a token, and start a jailed agent
    Spawn(SpawnArgs),
    /// Send prompt text to an agent (plain text; no JSON escaping)
    Prompt(PromptArgs),
    /// List agents owned by the caller
    List,
    /// Show an agent
    Get(TargetArgs),
    /// Read agent terminal output
    Read(ReadArgs),
    /// Wait until an agent reaches one of the requested states
    Wait(WaitArgs),
    /// Close an agent's pane (or tab with --tab)
    #[command(visible_alias = "close")]
    Kill(KillArgs),
}

#[derive(Debug, Args)]
struct SpawnArgs {
    /// Agent kind (only sandbox-wrapped kinds are accepted, e.g. opencode)
    #[arg(long)]
    kind: String,

    /// Agent name, usable as the `prompt` target
    #[arg(long)]
    name: Option<String>,

    /// Must match the caller token's cwd; it cannot change the cwd
    #[arg(long)]
    cwd: Option<String>,

    /// Must match the caller token's workspace_id
    #[arg(long)]
    workspace: Option<String>,

    /// Tab label
    #[arg(long)]
    label: Option<String>,

    /// Focus the new tab
    #[arg(long)]
    focus: bool,

    /// Lifetime of the agent token in seconds (clamped to max_token_ttl_s)
    #[arg(long)]
    ttl_s: Option<u64>,

    /// Capability to grant the agent (repeatable)
    #[arg(long = "grant")]
    grants: Vec<String>,

    /// Agent arguments (pass after `--`)
    #[arg(last = true, allow_hyphen_values = true)]
    args: Vec<String>,
}

#[derive(Debug, Args)]
struct PromptArgs {
    /// Agent name or pane id
    target: String,

    /// Prompt text (still subject to shell quoting; prefer --text-file or stdin)
    #[arg(long, conflicts_with = "text_file")]
    text: Option<String>,

    /// Read prompt text verbatim from a file ("-" = stdin)
    #[arg(long, value_name = "PATH")]
    text_file: Option<PathBuf>,

    /// Wait up to this many milliseconds for the agent to become idle
    /// (default: 900000; use --no-wait to return immediately)
    #[arg(long, conflicts_with = "no_wait")]
    wait_ms: Option<u64>,

    /// Submit the prompt and return immediately
    #[arg(long)]
    no_wait: bool,
}

#[derive(Debug, Args)]
struct TargetArgs {
    /// Agent name or pane id
    target: String,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ReadSourceArg {
    Visible,
    Recent,
    #[value(name = "recent-unwrapped")]
    RecentUnwrapped,
    Detection,
}

impl ReadSourceArg {
    fn api_name(self) -> &'static str {
        match self {
            Self::Visible => "visible",
            Self::Recent => "recent",
            Self::RecentUnwrapped => "recent_unwrapped",
            Self::Detection => "detection",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ReadFormatArg {
    Text,
    Ansi,
}

impl ReadFormatArg {
    fn api_name(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Ansi => "ansi",
        }
    }
}

#[derive(Debug, Args)]
struct ReadArgs {
    /// Agent name or pane id
    target: String,

    /// Terminal snapshot source
    #[arg(long, value_enum, default_value_t = ReadSourceArg::Recent)]
    source: ReadSourceArg,

    /// Limit the number of lines
    #[arg(long)]
    lines: Option<u32>,

    /// Output format
    #[arg(long, value_enum)]
    format: Option<ReadFormatArg>,

    /// Shorthand for --format ansi
    #[arg(long)]
    ansi: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum AgentStatusArg {
    Idle,
    Working,
    Blocked,
    Done,
    Unknown,
}

impl AgentStatusArg {
    fn api_name(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Working => "working",
            Self::Blocked => "blocked",
            Self::Done => "done",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Args)]
struct WaitArgs {
    /// Agent name or pane id
    target: String,

    /// State to match (repeatable; default: idle, done, or blocked)
    #[arg(long = "until", value_enum)]
    until: Vec<AgentStatusArg>,

    /// Fail after this many milliseconds (default: wait indefinitely)
    #[arg(long)]
    wait_ms: Option<u64>,
}

#[derive(Debug, Args)]
struct KillArgs {
    /// Agent name or pane id
    target: String,

    /// Close the agent's whole tab instead of just its pane
    #[arg(long)]
    tab: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Output {
    Json,
    ReadText,
}

#[derive(Debug)]
enum Plan {
    Request {
        method: String,
        params: Value,
        timeout_ms: u64,
        output: Output,
    },
    Kill {
        target: String,
        tab: bool,
        timeout_ms: u64,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("herdr-agent: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), String> {
    let plan = build_plan(&cli.command, cli.timeout_ms)?;
    let token = resolve_token(&cli)?;
    let socket = cli.socket.clone().unwrap_or_else(client::default_socket);
    match plan {
        Plan::Request {
            method,
            params,
            timeout_ms,
            output,
        } => {
            let response =
                client::exchange(&socket, token.as_deref(), &method, params, timeout_ms)?;
            print_response(&cli, &response, output)
        }
        Plan::Kill {
            target,
            tab,
            timeout_ms,
        } => {
            let response = kill(&socket, token.as_deref(), &target, tab, timeout_ms)?;
            print_response(&cli, &response, Output::Json)
        }
    }
}

fn print_response(cli: &Cli, response: &str, output: Output) -> Result<(), String> {
    if cli.raw {
        println!("{response}");
    }

    let result = client::response_result(response)?;
    if cli.raw {
        return Ok(());
    }

    // `read` prints terminal text by default, matching `herdr agent read`.
    // --pretty/--raw expose the full JSON envelope instead.
    if output == Output::ReadText
        && !cli.pretty
        && let Some(text) = result.pointer("/read/text").and_then(Value::as_str)
    {
        print!("{text}");
        return Ok(());
    }

    let rendered = if cli.pretty {
        serde_json::to_string_pretty(&result)
    } else {
        serde_json::to_string(&result)
    }
    .map_err(|error| format!("encode result: {error}"))?;
    println!("{rendered}");
    Ok(())
}

fn build_plan(command: &Command, timeout_override: Option<u64>) -> Result<Plan, String> {
    match command {
        Command::Spawn(args) => {
            let params = client::spawn_params(
                &args.kind,
                &args.args,
                args.name.as_deref(),
                args.cwd.as_deref(),
                args.workspace.as_deref(),
                args.label.as_deref(),
                args.focus,
                args.ttl_s,
                &args.grants,
            )?;
            Ok(Plan::Request {
                method: "auth.agent.spawn".into(),
                params,
                timeout_ms: timeout_override.unwrap_or(client::DEFAULT_TIMEOUT_MS),
                output: Output::Json,
            })
        }
        Command::Prompt(args) => {
            let text = client::read_prompt_text(args.text.as_deref(), args.text_file.as_deref())?;
            if text.is_empty() {
                return Err("prompt text is empty".into());
            }
            let wait_ms = if args.no_wait {
                None
            } else {
                Some(args.wait_ms.unwrap_or(client::DEFAULT_PROMPT_WAIT_MS))
            };
            let timeout_ms = timeout_override.unwrap_or_else(|| {
                wait_ms
                    .map(|wait| wait.saturating_add(client::WAIT_TIMEOUT_MARGIN_MS))
                    .unwrap_or(client::DEFAULT_TIMEOUT_MS)
            });
            Ok(Plan::Request {
                method: "agent.prompt".into(),
                params: client::prompt_params(&args.target, &text, wait_ms),
                timeout_ms,
                output: Output::Json,
            })
        }
        Command::List => Ok(Plan::Request {
            method: "agent.list".into(),
            params: json!({}),
            timeout_ms: timeout_override.unwrap_or(client::DEFAULT_TIMEOUT_MS),
            output: Output::Json,
        }),
        Command::Get(args) => Ok(Plan::Request {
            method: "agent.get".into(),
            params: json!({ "target": args.target }),
            timeout_ms: timeout_override.unwrap_or(client::DEFAULT_TIMEOUT_MS),
            output: Output::Json,
        }),
        Command::Read(args) => {
            let format = if args.ansi {
                ReadFormatArg::Ansi
            } else {
                args.format.unwrap_or(ReadFormatArg::Text)
            };
            let mut params = json!({
                "target": args.target,
                "source": args.source.api_name(),
                "format": format.api_name(),
                "strip_ansi": format != ReadFormatArg::Ansi,
            });
            if let Some(lines) = args.lines {
                params["lines"] = json!(lines);
            }
            Ok(Plan::Request {
                method: "agent.read".into(),
                params,
                timeout_ms: timeout_override.unwrap_or(client::DEFAULT_TIMEOUT_MS),
                output: Output::ReadText,
            })
        }
        Command::Wait(args) => {
            let mut params = json!({ "target": args.target });
            if !args.until.is_empty() {
                let until = args
                    .until
                    .iter()
                    .map(|status| status.api_name())
                    .collect::<Vec<_>>();
                params["until"] = json!(until);
            }
            let timeout_ms = timeout_override.unwrap_or_else(|| {
                args.wait_ms
                    .map(|wait| wait.saturating_add(client::WAIT_TIMEOUT_MARGIN_MS))
                    .unwrap_or(INDEFINITE_TIMEOUT_MS)
            });
            if let Some(wait_ms) = args.wait_ms {
                params["timeout_ms"] = json!(wait_ms);
            }
            Ok(Plan::Request {
                method: "agent.wait".into(),
                params,
                timeout_ms,
                output: Output::Json,
            })
        }
        Command::Kill(args) => Ok(Plan::Kill {
            target: args.target.clone(),
            tab: args.tab,
            timeout_ms: timeout_override.unwrap_or(client::DEFAULT_TIMEOUT_MS),
        }),
    }
}

fn kill(
    socket: &Path,
    token: Option<&str>,
    target: &str,
    tab: bool,
    timeout_ms: u64,
) -> Result<String, String> {
    if tab {
        let tab_id = if looks_like_tab_id(target) {
            target.to_owned()
        } else {
            resolve_agent_field(socket, token, target, "tab_id", timeout_ms)?
        };
        return client::exchange(
            socket,
            token,
            "tab.close",
            json!({ "tab_id": tab_id }),
            timeout_ms,
        );
    }

    let pane_id = if looks_like_pane_id(target) {
        target.to_owned()
    } else {
        resolve_agent_field(socket, token, target, "pane_id", timeout_ms)?
    };
    client::exchange(
        socket,
        token,
        "pane.close",
        json!({ "pane_id": pane_id }),
        timeout_ms,
    )
}

/// Resolve an agent name to a field of its `agent.get` result. Pane/tab ids
/// skip this and go straight to close, so a crashed agent's pane can still be
/// cleaned up by id.
fn resolve_agent_field(
    socket: &Path,
    token: Option<&str>,
    target: &str,
    field: &str,
    timeout_ms: u64,
) -> Result<String, String> {
    let response = client::exchange(
        socket,
        token,
        "agent.get",
        json!({ "target": target }),
        timeout_ms,
    )?;
    let result = client::response_result(&response)?;
    let pointer = format!("/agent/{field}");
    result
        .pointer(&pointer)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| format!("agent `{target}` has no {field}"))
}

fn looks_like_pane_id(target: &str) -> bool {
    looks_like_id(target, 'p')
}

fn looks_like_tab_id(target: &str) -> bool {
    looks_like_id(target, 't')
}

fn looks_like_id(target: &str, prefix: char) -> bool {
    let Some((_, id)) = target.rsplit_once(':') else {
        return false;
    };
    let mut chars = id.chars();
    chars.next() == Some(prefix) && chars.all(|c| c.is_ascii_digit())
}

fn resolve_token(cli: &Cli) -> Result<Option<String>, String> {
    let env_token = std::env::var("HERDR_AUTH_JWT").ok();
    client::resolve_token_from(
        cli.token.as_deref(),
        cli.token_file.as_deref(),
        env_token.as_deref(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn request(plan: Plan) -> (String, Value, u64, Output) {
        match plan {
            Plan::Request {
                method,
                params,
                timeout_ms,
                output,
            } => (method, params, timeout_ms, output),
            Plan::Kill { .. } => panic!("expected a request plan"),
        }
    }

    fn prompt(text: &str, wait_ms: Option<u64>, no_wait: bool) -> Command {
        Command::Prompt(PromptArgs {
            target: "worker".into(),
            text: Some(text.into()),
            text_file: None,
            wait_ms,
            no_wait,
        })
    }

    #[test]
    fn prompt_waits_by_default_and_extends_the_socket_timeout() {
        let (method, params, timeout, _) =
            request(build_plan(&prompt("hello", None, false), None).unwrap());
        assert_eq!(method, "agent.prompt");
        assert_eq!(params["target"], json!("worker"));
        assert_eq!(params["text"], json!("hello"));
        assert_eq!(
            params["wait"],
            json!({"timeout_ms": client::DEFAULT_PROMPT_WAIT_MS})
        );
        assert_eq!(
            timeout,
            client::DEFAULT_PROMPT_WAIT_MS + client::WAIT_TIMEOUT_MARGIN_MS
        );
    }

    #[test]
    fn prompt_no_wait_omits_the_wait_object() {
        let (_, params, timeout, _) =
            request(build_plan(&prompt("hello", None, true), None).unwrap());
        assert!(params.get("wait").is_none());
        assert_eq!(timeout, client::DEFAULT_TIMEOUT_MS);
    }

    #[test]
    fn prompt_honors_an_explicit_wait_and_timeout() {
        let (_, params, timeout, _) =
            request(build_plan(&prompt("hello", Some(1_000), false), Some(5_000)).unwrap());
        assert_eq!(params["wait"], json!({"timeout_ms": 1_000}));
        assert_eq!(timeout, 5_000);
    }

    #[test]
    fn prompt_text_is_not_json_escaped_twice() {
        let text = "line one\n\"quoted\" $HOME `cmd`";
        let (_, params, _, _) = request(build_plan(&prompt(text, None, true), None).unwrap());
        assert_eq!(params["text"], json!(text));
    }

    #[test]
    fn empty_prompt_text_is_rejected() {
        let error = build_plan(&prompt("", None, true), None).unwrap_err();
        assert_eq!(error, "prompt text is empty");
    }

    #[test]
    fn spawn_uses_the_shared_spawn_params_builder() {
        let command = Command::Spawn(SpawnArgs {
            kind: "opencode".into(),
            name: Some("worker".into()),
            cwd: None,
            workspace: None,
            label: None,
            focus: false,
            ttl_s: None,
            grants: vec!["report_status".into()],
            args: vec!["--model".into(), "x".into()],
        });
        let (method, params, timeout, _) = request(build_plan(&command, None).unwrap());
        assert_eq!(method, "auth.agent.spawn");
        assert_eq!(params["kind"], json!("opencode"));
        assert_eq!(params["name"], json!("worker"));
        assert_eq!(params["args"], json!(["--model", "x"]));
        assert_eq!(timeout, client::DEFAULT_TIMEOUT_MS);
    }

    #[test]
    fn list_and_get_use_allowed_methods() {
        let (method, params, _, _) = request(build_plan(&Command::List, None).unwrap());
        assert_eq!(method, "agent.list");
        assert_eq!(params, json!({}));

        let (method, params, _, _) = request(
            build_plan(
                &Command::Get(TargetArgs {
                    target: "worker".into(),
                }),
                None,
            )
            .unwrap(),
        );
        assert_eq!(method, "agent.get");
        assert_eq!(params, json!({"target": "worker"}));
    }

    #[test]
    fn read_defaults_to_recent_text() {
        let command = Command::Read(ReadArgs {
            target: "worker".into(),
            source: ReadSourceArg::Recent,
            lines: Some(200),
            format: None,
            ansi: false,
        });
        let (method, params, _, output) = request(build_plan(&command, None).unwrap());
        assert_eq!(method, "agent.read");
        assert_eq!(params["target"], json!("worker"));
        assert_eq!(params["source"], json!("recent"));
        assert_eq!(params["format"], json!("text"));
        assert_eq!(params["strip_ansi"], json!(true));
        assert_eq!(params["lines"], json!(200));
        assert_eq!(output, Output::ReadText);
    }

    #[test]
    fn read_ansi_keeps_escape_sequences() {
        let command = Command::Read(ReadArgs {
            target: "worker".into(),
            source: ReadSourceArg::RecentUnwrapped,
            lines: None,
            format: None,
            ansi: true,
        });
        let (_, params, _, _) = request(build_plan(&command, None).unwrap());
        assert_eq!(params["source"], json!("recent_unwrapped"));
        assert_eq!(params["format"], json!("ansi"));
        assert_eq!(params["strip_ansi"], json!(false));
        assert!(params.get("lines").is_none());
    }

    #[test]
    fn wait_defaults_to_indefinite_and_can_cap_the_wait() {
        let command = Command::Wait(WaitArgs {
            target: "worker".into(),
            until: vec![AgentStatusArg::Idle, AgentStatusArg::Blocked],
            wait_ms: None,
        });
        let (method, params, timeout, _) = request(build_plan(&command, None).unwrap());
        assert_eq!(method, "agent.wait");
        assert_eq!(params["until"], json!(["idle", "blocked"]));
        assert!(params.get("timeout_ms").is_none());
        assert_eq!(timeout, INDEFINITE_TIMEOUT_MS);

        let command = Command::Wait(WaitArgs {
            target: "worker".into(),
            until: Vec::new(),
            wait_ms: Some(1_000),
        });
        let (_, params, timeout, _) = request(build_plan(&command, None).unwrap());
        assert!(params.get("until").is_none());
        assert_eq!(params["timeout_ms"], json!(1_000));
        assert_eq!(timeout, 1_000 + client::WAIT_TIMEOUT_MARGIN_MS);
    }

    #[test]
    fn kill_targets_panes_or_tabs_and_resolves_names() {
        let kill = build_plan(
            &Command::Kill(KillArgs {
                target: "worker".into(),
                tab: false,
            }),
            None,
        )
        .unwrap();
        assert!(matches!(
            kill,
            Plan::Kill {
                tab: false,
                timeout_ms: client::DEFAULT_TIMEOUT_MS,
                ..
            }
        ));

        assert!(looks_like_pane_id("w1:p2"));
        assert!(looks_like_tab_id("w1:t3"));
        assert!(!looks_like_pane_id("worker"));
        assert!(!looks_like_pane_id("w1:t3"));
    }
}
