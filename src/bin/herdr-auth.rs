#![allow(unused_crate_dependencies)] // shared crate deps are for the proxy server

//! `herdr-auth` — client CLI for `herdr-auth-proxy`.
//!
//! Speaks herdr's JSON API envelope (`{"id","method","params"}` →
//! `{"id","result"}` or `{"id","error":{...}}`) over the proxy's unix socket,
//! plus the proxy's `auth.*` extension methods.
//!
//! Authentication: the JWT is taken from `--token`, `--token-file`, or
//! `$HERDR_AUTH_JWT` and sent as an `auth.hello` first line. Without a token the
//! CLI still connects; the proxy then falls back to reading `HERDR_AUTH_JWT`
//! from the CLI process environment (peer-environ mode).

use std::fs;
use std::io::{self, BufRead, BufReader, IsTerminal, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand};
use herdr_auth_proxy::config;
use herdr_auth_proxy::grants::GRANTABLE_AGENT_CAPABILITIES;
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

    /// JWT for this request (prefer $HERDR_AUTH_JWT or --token-file; flags leak into ps)
    #[arg(long, global = true, env = "HERDR_AUTH_JWT", hide_env_values = true)]
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
        #[arg(long)]
        sub: Option<String>,
        /// Lifetime in seconds (clamped to the caller's mint cap)
        #[arg(long)]
        ttl_s: Option<u64>,
        /// Bind an agent token to a pane
        #[arg(long)]
        pane: Option<String>,
        /// Capability to grant (repeatable)
        #[arg(long = "grant")]
        grants: Vec<String>,
        /// Extra permission object as JSON (orchestrator tokens)
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
        #[arg(long)]
        cwd: Option<String>,
        #[arg(long)]
        workspace: Option<String>,
        #[arg(long)]
        label: Option<String>,
        #[arg(long)]
        focus: bool,
        /// Lifetime of the agent token in seconds
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
    let socket = cli.socket.clone().unwrap_or_else(|| {
        config::load()
            .map(|(_, paths)| paths.auth_socket)
            .unwrap_or_else(|_| PathBuf::from("/run/herdr-auth-proxy/auth.sock"))
    });
    let response = exchange(&socket, token.as_deref(), &method, params, cli.timeout_ms)?;

    if cli.raw {
        println!("{response}");
    }

    let value: Value = serde_json::from_str(&response)
        .map_err(|error| format!("invalid response from proxy: {error}"))?;
    if let Some(error) = value.get("error") {
        return Err(format_error(error));
    }
    if cli.raw {
        return Ok(());
    }

    let result = value.get("result").cloned().unwrap_or(Value::Null);
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
                    grants,
                    perm,
                },
        } => {
            validate_grants(grants)?;
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
            if !grants.is_empty() {
                params.insert("grants".into(), json!(grants));
            }
            if let Some(perm) = perm {
                params.insert("perm".into(), parse_json(perm, "--perm")?);
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
            validate_grants(grants)?;
            let mut params = Map::new();
            params.insert("kind".into(), json!(kind));
            if !args.is_empty() {
                params.insert("args".into(), json!(args));
            }
            if let Some(name) = name {
                params.insert("name".into(), json!(name));
            }
            if let Some(cwd) = cwd {
                params.insert("cwd".into(), json!(cwd));
            }
            if let Some(workspace) = workspace {
                params.insert("workspace_id".into(), json!(workspace));
            }
            if let Some(label) = label {
                params.insert("label".into(), json!(label));
            }
            params.insert("focus".into(), json!(focus));
            if let Some(ttl_s) = ttl_s {
                params.insert("ttl_s".into(), json!(ttl_s));
            }
            if !grants.is_empty() {
                params.insert("grants".into(), json!(grants));
            }
            Ok(("auth.agent.spawn".into(), Value::Object(params)))
        }
    }
}

fn resolve_params(inline: Option<&str>, file: Option<&Path>) -> Result<Value, String> {
    if let Some(inline) = inline {
        return parse_json(inline, "--params");
    }
    if let Some(path) = file {
        if path == Path::new("-") {
            return read_stdin_json();
        }
        let text = fs::read_to_string(path)
            .map_err(|error| format!("read {}: {error}", path.display()))?;
        return parse_json(&text, &path.display().to_string());
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
    parse_json(&text, "stdin")
}

fn parse_json(text: &str, source: &str) -> Result<Value, String> {
    let value: Value = serde_json::from_str(text)
        .map_err(|error| format!("invalid JSON from {source}: {error}"))?;
    if !value.is_object() {
        return Err(format!("{source} must contain a JSON object"));
    }
    Ok(value)
}

fn resolve_token(cli: &Cli) -> Result<Option<String>, String> {
    if let Some(token) = cli
        .token
        .as_deref()
        .map(str::trim)
        .filter(|t| !t.is_empty())
    {
        return Ok(Some(token.to_owned()));
    }
    if let Some(path) = &cli.token_file {
        let token = fs::read_to_string(path)
            .map_err(|error| format!("read token file {}: {error}", path.display()))?;
        let token = token.trim();
        if token.is_empty() {
            return Err(format!("token file {} is empty", path.display()));
        }
        return Ok(Some(token.to_owned()));
    }
    Ok(None)
}

fn exchange(
    socket: &Path,
    token: Option<&str>,
    method: &str,
    params: Value,
    timeout_ms: u64,
) -> Result<String, String> {
    let stream = UnixStream::connect(socket)
        .map_err(|error| format!("connect {}: {error}", socket.display()))?;
    let timeout = Duration::from_millis(timeout_ms);
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|error| format!("set read timeout: {error}"))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|error| format!("set write timeout: {error}"))?;

    let mut writer = stream
        .try_clone()
        .map_err(|error| format!("clone socket: {error}"))?;
    let mut reader = BufReader::new(stream);

    if let Some(jwt) = token {
        let hello = json!({
            "id": request_id("hello"),
            "method": "auth.hello",
            "params": { "jwt": jwt },
        });
        write_line(&mut writer, &hello)?;
        let response = read_line(&mut reader)?;
        ensure_ok(&response, "auth.hello")?;
    }

    let request = json!({
        "id": request_id("cli"),
        "method": method,
        "params": params,
    });
    write_line(&mut writer, &request)?;
    read_line(&mut reader)
}

fn write_line(writer: &mut impl Write, value: &Value) -> Result<(), String> {
    let mut line = serde_json::to_vec(value).map_err(|error| format!("encode request: {error}"))?;
    line.push(b'\n');
    writer
        .write_all(&line)
        .map_err(|error| format!("write request: {error}"))?;
    writer
        .flush()
        .map_err(|error| format!("flush request: {error}"))
}

fn read_line(reader: &mut impl BufRead) -> Result<String, String> {
    let mut line = String::new();
    let read = reader
        .read_line(&mut line)
        .map_err(|error| format!("read response: {error}"))?;
    if read == 0 {
        return Err("proxy closed the connection without a response".into());
    }
    Ok(line.trim_end().to_owned())
}

fn ensure_ok(response: &str, what: &str) -> Result<(), String> {
    let value: Value = serde_json::from_str(response)
        .map_err(|error| format!("invalid {what} response: {error}"))?;
    if let Some(error) = value.get("error") {
        return Err(format!("{what}: {}", format_error(error)));
    }
    Ok(())
}

fn format_error(error: &Value) -> String {
    let code = error.get("code").and_then(Value::as_str).unwrap_or("error");
    let message = error
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or("request failed");
    format!("{message} ({code})")
}

fn request_id(prefix: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    format!("{prefix}-{}-{nanos}", std::process::id())
}

fn validate_grants(grants: &[String]) -> Result<(), String> {
    for grant in grants {
        if !GRANTABLE_AGENT_CAPABILITIES.contains(&grant.as_str()) {
            return Err(format!(
                "unknown grant `{grant}` (allowed: {})",
                GRANTABLE_AGENT_CAPABILITIES.join(", ")
            ));
        }
    }
    Ok(())
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
                grants: vec!["report_metadata".into()],
                perm: None,
            },
        };
        let (method, params) = build_request(&command).unwrap();
        assert_eq!(method, "auth.token.mint");
        assert_eq!(params["role"], json!("agent"));
        assert_eq!(params["pane_id"], json!("w1:p2"));
        assert_eq!(params["grants"], json!(["report_metadata"]));
    }

    #[test]
    fn unknown_grant_is_rejected() {
        let error = validate_grants(&["root".into()]).unwrap_err();
        assert!(error.contains("unknown grant `root`"), "{error}");
        assert!(error.contains("report_status"), "{error}");
    }

    #[test]
    fn params_must_be_an_object() {
        assert!(parse_json("[]", "test").is_err());
        assert!(parse_json("{}", "test").is_ok());
    }

    #[test]
    fn error_is_formatted_with_code() {
        let error = json!({"code": "forbidden", "message": "nope"});
        assert_eq!(format_error(&error), "nope (forbidden)");
    }
}
