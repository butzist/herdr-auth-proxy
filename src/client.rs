//! Shared client helpers for the `herdr-auth` and `herdr-agent` binaries.
//!
//! Speaks herdr's JSON API envelope (`{"id","method","params"}` →
//! `{"id","result"}` or `{"id","error":{...}}`) over the proxy's unix socket,
//! and builds the params objects for the proxy's `auth.agent.spawn` extension
//! and herdr's `agent.prompt`.

use std::fs;
use std::io::{self, BufRead, BufReader, IsTerminal, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value, json};

use crate::config;
use crate::grants;

/// Default socket timeout for non-streaming calls.
pub const DEFAULT_TIMEOUT_MS: u64 = 60_000;

/// Default wait for `herdr-agent prompt`, matching the shell helper this
/// replaced (15 minutes).
pub const DEFAULT_PROMPT_WAIT_MS: u64 = 900_000;

/// Extra socket timeout granted on top of an `agent.prompt` wait so the proxy
/// can deliver the final response instead of timing out first.
pub const WAIT_TIMEOUT_MARGIN_MS: u64 = 60_000;

/// The proxy's resolved auth socket (or a conventional fallback).
pub fn default_socket() -> PathBuf {
    config::load()
        .map(|(_, paths)| paths.auth_socket)
        .unwrap_or_else(|_| PathBuf::from("/run/herdr-auth-proxy/auth.sock"))
}

/// Explicit flags win over the inherited environment: `HERDR_AUTH_JWT` must not
/// silently turn a `--token`/`--token-file` test into an orchestrator call.
pub fn resolve_token_from(
    token: Option<&str>,
    token_file: Option<&Path>,
    env_token: Option<&str>,
) -> Result<Option<String>, String> {
    if let Some(token) = token.map(str::trim).filter(|token| !token.is_empty()) {
        return Ok(Some(token.to_owned()));
    }
    if let Some(path) = token_file {
        let token = fs::read_to_string(path)
            .map_err(|error| format!("read token file {}: {error}", path.display()))?;
        let token = token.trim();
        if token.is_empty() {
            return Err(format!("token file {} is empty", path.display()));
        }
        return Ok(Some(token.to_owned()));
    }
    if let Some(token) = env_token.map(str::trim).filter(|token| !token.is_empty()) {
        return Ok(Some(token.to_owned()));
    }
    Ok(None)
}

/// Send one request (after an optional `auth.hello`) and return the raw
/// response line.
pub fn exchange(
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

/// Parse a response line and return its `result` payload, turning an `error`
/// envelope into a readable message.
pub fn response_result(response: &str) -> Result<Value, String> {
    let value: Value = serde_json::from_str(response)
        .map_err(|error| format!("invalid response from proxy: {error}"))?;
    if let Some(error) = value.get("error") {
        return Err(format_error(error));
    }
    Ok(value.get("result").cloned().unwrap_or(Value::Null))
}

/// Read prompt text verbatim: inline text, a file (`-` = stdin), or stdin when
/// neither is supplied. There is deliberately no JSON layer here.
pub fn read_prompt_text(text: Option<&str>, text_file: Option<&Path>) -> Result<String, String> {
    if let Some(text) = text {
        return Ok(text.to_owned());
    }
    if let Some(path) = text_file {
        if path == Path::new("-") {
            return read_stdin_text();
        }
        return fs::read_to_string(path)
            .map_err(|error| format!("read {}: {error}", path.display()));
    }
    if io::stdin().is_terminal() {
        return Err("no prompt text: pass --text, --text-file, or pipe text on stdin".to_string());
    }
    read_stdin_text()
}

/// Build `agent.prompt` params. `wait_ms` of `None` returns immediately;
/// `Some(ms)` waits for the agent to become idle (herdr's `wait` object).
pub fn prompt_params(target: &str, text: &str, wait_ms: Option<u64>) -> Value {
    let mut params = json!({ "target": target, "text": text });
    if let Some(wait_ms) = wait_ms {
        params["wait"] = json!({ "timeout_ms": wait_ms });
    }
    params
}

/// Build `auth.agent.spawn` params. Keep this in one place so `herdr-agent
/// spawn` and `herdr-auth agent spawn` cannot drift apart.
#[allow(clippy::too_many_arguments)]
pub fn spawn_params(
    kind: &str,
    args: &[String],
    name: Option<&str>,
    cwd: Option<&str>,
    workspace_id: Option<&str>,
    label: Option<&str>,
    focus: bool,
    ttl_s: Option<u64>,
    grants: &[String],
) -> Result<Value, String> {
    grants::validate(grants)?;
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
    if let Some(workspace_id) = workspace_id {
        params.insert("workspace_id".into(), json!(workspace_id));
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
    Ok(Value::Object(params))
}

/// Parse a JSON object from an argument, file, or stdin.
pub fn parse_json_object(text: &str, source: &str) -> Result<Value, String> {
    let value: Value = serde_json::from_str(text)
        .map_err(|error| format!("invalid JSON from {source}: {error}"))?;
    if !value.is_object() {
        return Err(format!("{source} must contain a JSON object"));
    }
    Ok(value)
}

pub fn format_error(error: &Value) -> String {
    let code = error.get("code").and_then(Value::as_str).unwrap_or("error");
    let message = error
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or("request failed");
    format!("{message} ({code})")
}

pub fn request_id(prefix: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    format!("{prefix}-{}-{nanos}", std::process::id())
}

fn read_stdin_text() -> Result<String, String> {
    let mut text = String::new();
    io::stdin()
        .read_to_string(&mut text)
        .map_err(|error| format!("read stdin: {error}"))?;
    Ok(text)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_token_beats_environment() {
        let resolved = resolve_token_from(Some("flag"), None, Some("env")).unwrap();
        assert_eq!(resolved.as_deref(), Some("flag"));
    }

    #[test]
    fn explicit_token_file_beats_environment() {
        let path = std::env::temp_dir().join(format!("hap-token-{}", request_id("test")));
        std::fs::write(&path, "file\n").unwrap();
        let resolved = resolve_token_from(None, Some(&path), Some("env")).unwrap();
        assert_eq!(resolved.as_deref(), Some("file"));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn environment_is_the_fallback() {
        let resolved = resolve_token_from(None, None, Some("env")).unwrap();
        assert_eq!(resolved.as_deref(), Some("env"));
        assert_eq!(resolve_token_from(None, None, Some("  ")).unwrap(), None);
    }

    #[test]
    fn params_must_be_an_object() {
        assert!(parse_json_object("[]", "test").is_err());
        assert!(parse_json_object("{}", "test").is_ok());
    }

    #[test]
    fn error_is_formatted_with_code() {
        let error = json!({"code": "forbidden", "message": "nope"});
        assert_eq!(format_error(&error), "nope (forbidden)");
    }

    #[test]
    fn response_result_returns_the_payload() {
        let result = response_result(r#"{"id":"x","result":{"pane_id":"w1:p1"}}"#).unwrap();
        assert_eq!(result["pane_id"], json!("w1:p1"));
    }

    #[test]
    fn response_result_rejects_an_error_envelope() {
        let error = response_result(r#"{"id":"x","error":{"code":"forbidden","message":"nope"}}"#)
            .unwrap_err();
        assert_eq!(error, "nope (forbidden)");
    }

    #[test]
    fn prompt_params_only_include_wait_when_requested() {
        assert_eq!(
            prompt_params("worker", "hello", None),
            json!({"target": "worker", "text": "hello"})
        );
        assert_eq!(
            prompt_params("worker", "hello", Some(900_000)),
            json!({"target": "worker", "text": "hello", "wait": {"timeout_ms": 900_000}})
        );
    }

    #[test]
    fn prompt_text_is_read_verbatim_from_a_file() {
        let path = std::env::temp_dir().join(format!("hap-prompt-{}", request_id("test")));
        let text = "line one\n\"quoted\" $HOME\n";
        std::fs::write(&path, text).unwrap();
        let read = read_prompt_text(None, Some(&path)).unwrap();
        assert_eq!(read, text);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn inline_prompt_text_wins_over_a_file() {
        let read = read_prompt_text(Some("inline"), Some(Path::new("/does/not/exist"))).unwrap();
        assert_eq!(read, "inline");
    }

    #[test]
    fn spawn_params_include_only_supplied_fields() {
        let params = spawn_params(
            "opencode",
            &["--model".into(), "x".into()],
            Some("alice"),
            Some("/work"),
            None,
            None,
            false,
            Some(600),
            &["report_status".into()],
        )
        .unwrap();
        assert_eq!(params["kind"], json!("opencode"));
        assert_eq!(params["args"], json!(["--model", "x"]));
        assert_eq!(params["name"], json!("alice"));
        assert_eq!(params["cwd"], json!("/work"));
        assert_eq!(params["focus"], json!(false));
        assert_eq!(params["ttl_s"], json!(600));
        assert_eq!(params["grants"], json!(["report_status"]));
        assert!(params.get("workspace_id").is_none());
        assert!(params.get("label").is_none());
    }

    #[test]
    fn spawn_params_reject_unknown_grants() {
        let error = spawn_params(
            "opencode",
            &[],
            None,
            None,
            None,
            None,
            false,
            None,
            &["root".into()],
        )
        .unwrap_err();
        assert!(error.contains("unknown grant `root`"), "{error}");
    }
}
