#![allow(unused_crate_dependencies)] // shared crate deps are for the proxy server

//! `herdr-auth` — client CLI for `herdr-auth-proxy`.
//!
//! Speaks herdr's JSON API envelope (`{"id","method","params"}` →
//! `{"id","result"}` or `{"id","error":{...}}`) over the proxy's unix socket,
//! plus the proxy's `auth.*` extension methods.
//!
//! Authentication: the JWT is taken from `--token`, `--token-file`, or
//! `$HERDR_AUTH_JWT` (in that order of precedence) and sent as an `auth.hello`
//! first line. Without a token the CLI still connects; the proxy then falls
//! back to reading `HERDR_AUTH_JWT` from the CLI process environment
//! (peer-environ mode).

use std::fs;
use std::io::{self, IsTerminal, Read};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use herdr_auth_proxy::client;
use herdr_auth_proxy::grants;
use serde_json::{Map, Value, json};

#[derive(Debug, Parser)]
#[command(
    name = "herdr-auth",
    version,
    about = "Client for herdr-auth-proxy (herdr JSON API + auth.* extensions)",
    after_help = "Grantable agent capabilities: report_status, report_metadata, read_own_pane, wait_own_output"
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

    /// Socket read/write timeout in milliseconds
    #[arg(long, global = true, default_value_t = 60_000)]
    timeout_ms: u64,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Call any herdr method or proxy extension
    Call {
        method: String,
        /// Inline JSON params object
        #[arg(long, conflicts_with = "params_file")]
        params: Option<String>,
        /// Read the JSON params object from a file ("-" = stdin)
        #[arg(long)]
        params_file: Option<PathBuf>,
    },
    /// Show the identity and permissions the proxy associates with this connection
    Whoami,
    /// List herdr methods known to the proxy and its policy
    Methods,
    /// Token operations
    Token {
        #[command(subcommand)]
        command: TokenCommand,
    },
    /// Agent operations
    Agent {
        #[command(subcommand)]
        command: AgentCommand,
    },
}

#[derive(Debug, Subcommand)]
enum TokenCommand {
    /// Mint a JWT (always a subset of the caller's permissions)
    Mint {
        #[arg(long, default_value = "agent")]
        role: String,
        /// Label suffix; the token sub is always prefixed with the minter sub
        #[arg(long)]
        sub: Option<String>,
        /// Lifetime in seconds (clamped to max_token_ttl_s and the caller's mint cap)
        #[arg(long)]
        ttl_s: Option<u64>,
        /// Bind an agent token to a pane
        #[arg(long)]
        pane: Option<String>,
        /// Safe working directory for panes/agents created with this token
        #[arg(long)]
        cwd: Option<String>,
        /// Workspace this token may create tabs/panes in
        #[arg(long = "workspace")]
        workspace_id: Option<String>,
        /// Capability to grant an agent token (repeatable)
        #[arg(long = "grant")]
        grants: Vec<String>,
        /// Extra permission object as JSON (orchestrator tokens only)
        #[arg(long)]
        perm: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum AgentCommand {
    /// Atomically create a tab, mint a token, and start a jailed agent
    Spawn {
        #[arg(long)]
        kind: String,
        #[arg(long)]
        name: Option<String>,
        /// Must match the caller token's cwd; it cannot change the cwd
        #[arg(long)]
        cwd: Option<String>,
        /// Must match the caller token's workspace_id
        #[arg(long)]
        workspace: Option<String>,
        #[arg(long)]
        label: Option<String>,
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
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("herdr-auth: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), String> {
    let (method, params) = build_request(&cli.command)?;
    let token = resolve_token(&cli)?;
    let socket = cli.socket.clone().unwrap_or_else(client::default_socket);
    let response = client::exchange(&socket, token.as_deref(), &method, params, cli.timeout_ms)?;

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

fn build_request(command: &Command) -> Result<(String, Value), String> {
    match command {
        Command::Call {
            method,
            params,
            params_file,
        } => {
            let params = resolve_params(params.as_deref(), params_file.as_deref())?;
            Ok((method.clone(), params))
        }
        Command::Whoami => Ok(("auth.whoami".into(), json!({}))),
        Command::Methods => Ok(("auth.methods".into(), json!({}))),
        Command::Token {
            command:
                TokenCommand::Mint {
                    role,
                    sub,
                    ttl_s,
                    pane,
                    cwd,
                    workspace_id,
                    grants,
                    perm,
                },
        } => {
            grants::validate(grants)?;
            let mut params = Map::new();
            params.insert("role".into(), json!(role));
            if let Some(sub) = sub {
                params.insert("sub".into(), json!(sub));
            }
            if let Some(ttl_s) = ttl_s {
                params.insert("ttl_s".into(), json!(ttl_s));
            }
            if let Some(pane) = pane {
                params.insert("pane_id".into(), json!(pane));
            }
            if let Some(cwd) = cwd {
                params.insert("cwd".into(), json!(cwd));
            }
            if let Some(workspace_id) = workspace_id {
                params.insert("workspace_id".into(), json!(workspace_id));
            }
            if !grants.is_empty() {
                params.insert("grants".into(), json!(grants));
            }
            if let Some(perm) = perm {
                params.insert("perm".into(), client::parse_json_object(perm, "--perm")?);
            }
            Ok(("auth.token.mint".into(), Value::Object(params)))
        }
        Command::Agent {
            command:
                AgentCommand::Spawn {
                    kind,
                    name,
                    cwd,
                    workspace,
                    label,
                    focus,
                    ttl_s,
                    grants,
                    args,
                },
        } => {
            let params = client::spawn_params(
                kind,
                args,
                name.as_deref(),
                cwd.as_deref(),
                workspace.as_deref(),
                label.as_deref(),
                *focus,
                *ttl_s,
                grants,
            )?;
            Ok(("auth.agent.spawn".into(), params))
        }
    }
}

fn resolve_params(inline: Option<&str>, file: Option<&Path>) -> Result<Value, String> {
    if let Some(inline) = inline {
        return client::parse_json_object(inline, "--params");
    }
    if let Some(path) = file {
        if path == Path::new("-") {
            return read_stdin_json();
        }
        let text = fs::read_to_string(path)
            .map_err(|error| format!("read {}: {error}", path.display()))?;
        return client::parse_json_object(&text, &path.display().to_string());
    }
    if io::stdin().is_terminal() {
        return Ok(json!({}));
    }
    read_stdin_json()
}

fn read_stdin_json() -> Result<Value, String> {
    let mut text = String::new();
    io::stdin()
        .read_to_string(&mut text)
        .map_err(|error| format!("read stdin: {error}"))?;
    if text.trim().is_empty() {
        return Ok(json!({}));
    }
    client::parse_json_object(&text, "stdin")
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

    #[test]
    fn spawn_builds_proxy_params() {
        let command = Command::Agent {
            command: AgentCommand::Spawn {
                kind: "opencode".into(),
                name: Some("alice".into()),
                cwd: Some("/work".into()),
                workspace: None,
                label: None,
                focus: false,
                ttl_s: Some(600),
                grants: vec!["report_status".into(), "read_own_pane".into()],
                args: vec!["--model".into(), "x".into()],
            },
        };
        let (method, params) = build_request(&command).unwrap();
        assert_eq!(method, "auth.agent.spawn");
        assert_eq!(params["kind"], json!("opencode"));
        assert_eq!(params["args"], json!(["--model", "x"]));
        assert_eq!(params["grants"], json!(["report_status", "read_own_pane"]));
        assert_eq!(params["focus"], json!(false));
        assert_eq!(params["ttl_s"], json!(600));
        assert_eq!(params["name"], json!("alice"));
    }

    #[test]
    fn mint_builds_proxy_params() {
        let command = Command::Token {
            command: TokenCommand::Mint {
                role: "agent".into(),
                sub: Some("bob".into()),
                ttl_s: Some(120),
                pane: Some("w1:p2".into()),
                cwd: Some("/work".into()),
                workspace_id: Some("w1".into()),
                grants: vec!["report_metadata".into()],
                perm: None,
            },
        };
        let (method, params) = build_request(&command).unwrap();
        assert_eq!(method, "auth.token.mint");
        assert_eq!(params["role"], json!("agent"));
        assert_eq!(params["pane_id"], json!("w1:p2"));
        assert_eq!(params["cwd"], json!("/work"));
        assert_eq!(params["workspace_id"], json!("w1"));
        assert_eq!(params["grants"], json!(["report_metadata"]));
    }

    #[test]
    fn unknown_grant_is_rejected() {
        let error = grants::validate(&["root".into()]).unwrap_err();
        assert!(error.contains("unknown grant `root`"), "{error}");
        assert!(error.contains("report_status"), "{error}");
    }
}
