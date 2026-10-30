//! herdr-auth-proxy server / lifecycle CLI.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand};
use herdr_auth_proxy::{config, cwd, grants, lifecycle, server};
use serde_json::{Map, Value, json};

#[derive(Debug, Parser)]
#[command(
    name = "herdr-auth-proxy",
    version,
    about = "JWT-authenticating proxy for herdr's socket API"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the proxy in the foreground (started detached by `wrap`)
    Serve,
    /// Ensure the proxy is running, then exec the given command (e.g. herdr)
    Wrap {
        #[arg(last = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
    /// Mint a token through the running proxy (uses $HERDR_AUTH_JWT)
    Mint {
        /// Role to mint (bootstrap permits agent or orchestrator, never admin)
        #[arg(long, default_value = "orchestrator")]
        role: String,
        /// Label suffix; the token sub is always prefixed with the minter sub
        #[arg(long)]
        sub: Option<String>,
        #[arg(long)]
        ttl_s: Option<u64>,
        #[arg(long)]
        pane: Option<String>,
        /// Safe working directory for panes/agents created with this token
        #[arg(long)]
        cwd: Option<String>,
        /// Workspace this token may create tabs/panes in
        #[arg(long = "workspace")]
        workspace_id: Option<String>,
        /// Grant (agent tokens): report_status, report_metadata, read_own_pane,
        /// wait_own_output
        #[arg(long = "grant")]
        grants: Vec<String>,
        /// Permission object as JSON (orchestrator tokens)
        #[arg(long)]
        perm: Option<String>,
    },
    /// Stop the running proxy
    Stop,
    /// Show proxy status
    Status,
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("herdr-auth-proxy: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), String> {
    match cli.command.unwrap_or(Command::Serve) {
        Command::Serve => {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .map_err(|error| format!("tokio runtime: {error}"))?;
            runtime.block_on(server::run())
        }
        Command::Wrap { command } => lifecycle::wrap(&command),
        Command::Mint {
            role,
            sub,
            ttl_s,
            pane,
            cwd,
            workspace_id,
            grants,
            perm,
        } => mint(MintArgs {
            role,
            sub,
            ttl_s,
            pane,
            cwd,
            workspace_id,
            grants,
            perm,
        }),
        Command::Stop => {
            let (_, paths) = config::load()?;
            lifecycle::stop(&paths)
        }
        Command::Status => {
            let (_, paths) = config::load()?;
            println!("{}", lifecycle::status(&paths));
            Ok(())
        }
    }
}

struct MintArgs {
    role: String,
    sub: Option<String>,
    ttl_s: Option<u64>,
    pane: Option<String>,
    cwd: Option<String>,
    workspace_id: Option<String>,
    grants: Vec<String>,
    perm: Option<String>,
}

fn mint(args: MintArgs) -> Result<(), String> {
    let MintArgs {
        role,
        sub,
        ttl_s,
        pane,
        cwd,
        workspace_id,
        grants: requested_grants,
        perm,
    } = args;
    grants::validate(&requested_grants)?;
    let cwd = cwd.map(|value| cwd::canonical(&value)).transpose()?;
    let (_, paths) = config::load()?;

    let bootstrap = std::env::var("HERDR_AUTH_JWT").map_err(|_| {
        "HERDR_AUTH_JWT is not set (run from a shell started by \
         `herdr-auth-proxy wrap -- herdr`)"
            .to_string()
    })?;
    let bootstrap = bootstrap.trim();
    if bootstrap.is_empty() {
        return Err("HERDR_AUTH_JWT is empty".to_string());
    }

    let mut params = Map::new();
    params.insert("role".into(), json!(&role));
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
    if !requested_grants.is_empty() {
        params.insert("grants".into(), json!(requested_grants));
    }
    if let Some(perm) = perm {
        let perm = serde_json::from_str::<Value>(&perm)
            .map_err(|error| format!("parse --perm: {error}"))?;
        params.insert("perm".into(), perm);
    }

    let result = call(
        &paths.auth_socket,
        bootstrap,
        "auth.token.mint",
        Value::Object(params),
    )?;
    let token = result
        .get("token")
        .and_then(Value::as_str)
        .ok_or_else(|| "proxy returned no token".to_string())?;
    println!("{token}");
    Ok(())
}

fn call(socket: &Path, token: &str, method: &str, params: Value) -> Result<Value, String> {
    let stream = UnixStream::connect(socket)
        .map_err(|error| format!("connect {}: {error}", socket.display()))?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(60)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(60)));
    let mut writer = stream
        .try_clone()
        .map_err(|error| format!("clone socket: {error}"))?;
    let mut reader = BufReader::new(stream);

    let hello = json!({
        "id": "hello",
        "method": "auth.hello",
        "params": { "jwt": token },
    });
    writeln!(writer, "{hello}").map_err(|error| format!("write hello: {error}"))?;
    writer
        .flush()
        .map_err(|error| format!("flush hello: {error}"))?;
    let response = read_response(&mut reader)?;
    if let Some(error) = response.get("error") {
        return Err(format_error(error));
    }

    let request = json!({ "id": "mint", "method": method, "params": params });
    writeln!(writer, "{request}").map_err(|error| format!("write request: {error}"))?;
    writer
        .flush()
        .map_err(|error| format!("flush request: {error}"))?;
    let response = read_response(&mut reader)?;
    if let Some(error) = response.get("error") {
        return Err(format_error(error));
    }
    Ok(response.get("result").cloned().unwrap_or(Value::Null))
}

fn read_response(reader: &mut impl BufRead) -> Result<Value, String> {
    let mut line = String::new();
    let read = reader
        .read_line(&mut line)
        .map_err(|error| format!("read response: {error}"))?;
    if read == 0 {
        return Err("proxy closed the connection without a response".into());
    }
    serde_json::from_str(line.trim_end()).map_err(|error| format!("invalid response: {error}"))
}

fn format_error(error: &Value) -> String {
    let code = error.get("code").and_then(Value::as_str).unwrap_or("error");
    let message = error
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or("request failed");
    format!("{message} ({code})")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_is_formatted_with_code() {
        let error = json!({"code": "forbidden", "message": "nope"});
        assert_eq!(format_error(&error), "nope (forbidden)");
    }
}
