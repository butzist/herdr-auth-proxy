#![allow(unused_crate_dependencies)] // shared crate deps are for the proxy server

//! `herdr-agent` — ergonomic agent orchestration through `herdr-auth-proxy`.
//!
//! `herdr-auth call agent.prompt --params '<json>'` forces callers to escape
//! prompt text as JSON. This CLI takes prompt text as a plain argument, from a
//! file, or from stdin, and sends the same NDJSON request to the proxy.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};
use herdr_auth_proxy::client;
use serde_json::Value;

#[derive(Debug, Parser)]
#[command(
    name = "herdr-agent",
    version,
    about = "Spawn and prompt herdr agents through herdr-auth-proxy",
    after_help = "Examples:\n  herdr-agent spawn --kind opencode --name worker\n  herdr-agent prompt worker --text-file prompt.md\n  printf 'review this\\n' | herdr-agent prompt worker\n\nPrompt text is sent verbatim; prefer --text-file or stdin over --text to avoid shell quoting."
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

    /// Socket read/write timeout in milliseconds (default: 60s, or wait + 60s for `prompt`)
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
    let (method, params, timeout_ms) = build_request(&cli.command, cli.timeout_ms)?;
    let token = resolve_token(&cli)?;
    let socket = cli.socket.clone().unwrap_or_else(client::default_socket);
    let response = client::exchange(&socket, token.as_deref(), &method, params, timeout_ms)?;

    if cli.raw {
        println!("{response}");
    }

    let result = client::response_result(&response)?;
    if cli.raw {
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

fn build_request(
    command: &Command,
    timeout_override: Option<u64>,
) -> Result<(String, Value, u64), String> {
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
            Ok((
                "auth.agent.spawn".into(),
                params,
                timeout_override.unwrap_or(client::DEFAULT_TIMEOUT_MS),
            ))
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
            Ok((
                "agent.prompt".into(),
                client::prompt_params(&args.target, &text, wait_ms),
                timeout_ms,
            ))
        }
    }
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
        let (method, params, timeout) = build_request(&prompt("hello", None, false), None).unwrap();
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
        let (_, params, timeout) = build_request(&prompt("hello", None, true), None).unwrap();
        assert!(params.get("wait").is_none());
        assert_eq!(timeout, client::DEFAULT_TIMEOUT_MS);
    }

    #[test]
    fn prompt_honors_an_explicit_wait_and_timeout() {
        let (_, params, timeout) =
            build_request(&prompt("hello", Some(1_000), false), Some(5_000)).unwrap();
        assert_eq!(params["wait"], json!({"timeout_ms": 1_000}));
        assert_eq!(timeout, 5_000);
    }

    #[test]
    fn prompt_text_is_not_json_escaped_twice() {
        let text = "line one\n\"quoted\" $HOME `cmd`";
        let (_, params, _) = build_request(&prompt(text, None, true), None).unwrap();
        assert_eq!(params["text"], json!(text));
    }

    #[test]
    fn empty_prompt_text_is_rejected() {
        let error = build_request(&prompt("", None, true), None).unwrap_err();
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
        let (method, params, timeout) = build_request(&command, None).unwrap();
        assert_eq!(method, "auth.agent.spawn");
        assert_eq!(params["kind"], json!("opencode"));
        assert_eq!(params["name"], json!("worker"));
        assert_eq!(params["args"], json!(["--model", "x"]));
        assert_eq!(timeout, client::DEFAULT_TIMEOUT_MS);
    }
}
