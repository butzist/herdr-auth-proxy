//! Minimal stdio MCP server for `herdr-auth mcp`.
//!
//! The server is deliberately small: JSON-RPC 2.0 over newline-delimited
//! stdin/stdout, a fixed tool set that maps to proxy methods, and two
//! documentation resources. Every tool call uses the normal one-request
//! `auth.sock` exchange, so the proxy remains the only authorization boundary.

use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use serde_json::{Value, json};

use crate::client;

const PROTOCOL_VERSION: &str = "2025-06-18";
const NOTIFY_WAIT_MS: u64 = 25_000;

/// `(targets, statuses by target, agent name by pane)`.
type StatusSnapshot = (
    Vec<String>,
    std::collections::BTreeMap<String, String>,
    std::collections::BTreeMap<String, String>,
);

const INSTRUCTIONS: &str = r#"herdr-auth MCP server

You control sandboxed herdr agents through this server. Every tool call is
authorized by the proxy from your JWT; there is no unrestricted passthrough.

Messaging loop:
  1. message-send {to, body, thread_id?, reply_to?}
     - `to` is an agent name, pane id, token subject, jti, or "parent".
     - Parent <-> child is always allowed. Sibling agents need a peer-grant
       from their shared parent.
  2. message-poll {wait_ms?, limit?} claims unread messages and returns them
     with a `claim_id`.
  3. message-ack {ids, claim_id} marks them done. Unacked claims become
     visible again after the lease expires.

Waiting:
  - Agents (developer/reviewer) may wait indefinitely: `wait_ms: 0` is allowed.
  - Orchestrators are capped (default 30s). Never rely on an orchestrator
    parking forever: prefer `watch` + `poll`, or end the turn and let the proxy
    wake you.
  - `watch {targets?, until?, ttl_s?}` returns immediately. The proxy monitors
    the owned children and prompts you when a watched status changes; then call
    `poll` to collect `changes`.
  - `poll {wait_ms?, ...}` also returns queued watch changes. Its `waiting` map
    tells you which agents are parked in a proxy wait (they are not deadlocked
    silently).
  - `agent-list` / `agent-get` add a `waiting` field for the same reason.

Use `reply_to` and `thread_id` to keep request/response pairs together. Do not
use pane.read or agent.prompt for orchestration; they are intentionally not
available in the normal workflow. `agent-read` is an admin-only diagnostic.

If this client is idle with unread messages, the proxy first sends an MCP
notification and then, after a short timeout, may prompt the agent with a
fixed message telling it to call message-poll.
"#;

const MCP_DOC: &str = r#"# herdr-auth MCP server

Transport: stdio, JSON-RPC 2.0, one JSON object per line.
Authentication: `HERDR_AUTH_JWT`, `--token`, or `--token-file` (JWT only).

The proxy is the authorization boundary. Tools are fixed; there is no
`call`/passthrough tool. Ownership, role allowlists, message relationships and
admin-only methods are enforced in the proxy.

Run it as:

```sh
export HERDR_AUTH_JWT=$(...)
herdr-auth mcp
```

MCP clients that support `initialize.instructions` should surface them to the
model. Tool descriptions and JSON schemas are authoritative for parameters.
"#;

const MESSAGES_DOC: &str = r#"# Agent messages

Message methods are available to every authenticated role, but the proxy checks
the relationship between sender and recipient:

- a principal may message its direct parent and its direct children;
- two siblings may message each other only after their shared parent runs
  `peer-grant`;
- grants are direct (not transitive), optionally time-limited, and revocable;
- admins may address any known principal.

Delivery is at-least-once:

1. `message-send` queues a durable message in `state.db`.
2. `message-poll` atomically claims deliverable messages for the caller and
   returns a `claim_id`.
3. `message-ack` requires the matching `claim_id`. If it is missing, the claim
   lease expires and the message is delivered again.

`message-notify` is a read-only long-poll used for MCP notifications; it never
claims a message. The stage-2 fallback only prompts an idle target with a fixed
proxy-generated string, and only if the target has not polled since the
message was queued.

`has_more` is true when the poll returned `limit` messages, meaning more may
be queued for the caller. `claim_id` at the top level identifies the single
claim for every message returned by that poll.

Orchestrator waits are capped by `orchestrator_max_wait_ms` (default 30000);
agent waits default to unlimited. A `waiting` entry in `poll`, `agent-list` or
`agent-get` is proxy-side state: the agent is parked in a proxy wait, not busy
working. `watch` is the non-blocking alternative to a long `poll`.
"#;

#[derive(Clone)]
pub struct Options {
    pub socket: PathBuf,
    pub token: Option<String>,
    pub timeout_ms: u64,
}

pub fn run(options: Options) -> Result<(), String> {
    let out = Arc::new(Mutex::new(std::io::stdout()));
    spawn_notifier(options.clone(), out.clone());

    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        let line = line.map_err(|error| format!("read stdin: {error}"))?;
        if line.trim().is_empty() {
            continue;
        }
        let request: Value = match serde_json::from_str(&line) {
            Ok(value) => value,
            Err(error) => {
                write_message(
                    &out,
                    &json!({
                        "jsonrpc": "2.0",
                        "id": Value::Null,
                        "error": {"code": -32700, "message": format!("parse error: {error}")},
                    }),
                )?;
                continue;
            }
        };
        if let Some(response) = handle(&options, &request) {
            write_message(&out, &response)?;
        }
    }
    Ok(())
}

fn handle(options: &Options, request: &Value) -> Option<Value> {
    let id = request.get("id").cloned()?;
    let method = request.get("method").and_then(Value::as_str).unwrap_or("");
    let params = request.get("params").cloned().unwrap_or(json!({}));

    let result = match method {
        "initialize" => Ok(json!({
            "protocolVersion": params
                .get("protocolVersion")
                .and_then(Value::as_str)
                .unwrap_or(PROTOCOL_VERSION),
            "capabilities": {
                "tools": {"listChanged": false},
                "resources": {"subscribe": false, "listChanged": false},
            },
            "serverInfo": {
                "name": "herdr-auth",
                "version": env!("CARGO_PKG_VERSION"),
            },
            "instructions": INSTRUCTIONS,
        })),
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({ "tools": tools() })),
        "tools/call" => call_tool(options, &params),
        "resources/list" => Ok(json!({ "resources": resources() })),
        "resources/read" => read_resource(&params),
        "logging/setLevel" => Ok(json!({})),
        _ => Err((-32601, format!("method not found: {method}"))),
    };

    Some(match result {
        Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
        Err((code, message)) => json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {"code": code, "message": message},
        }),
    })
}

fn call_tool(options: &Options, params: &Value) -> Result<Value, (i64, String)> {
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| (-32602, "tools/call requires a name".to_string()))?;
    let arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));

    let (method, call_params, timeout_ms) = match name {
        "agent-spawn" => ("auth.agent.spawn", arguments, options.timeout_ms),
        "agent-list" => ("agent.list", json!({}), options.timeout_ms),
        "agent-get" => (
            "agent.get",
            json!({"target": required(&arguments, "target")?}),
            options.timeout_ms,
        ),
        "agent-wait" => {
            let mut params = json!({"target": required(&arguments, "target")?});
            for key in ["until", "timeout_ms"] {
                if let Some(value) = arguments.get(key) {
                    params[key] = value.clone();
                }
            }
            // The proxy clamps this per role. An explicit 0 means "no client
            // timeout": the proxy still returns at its role cap.
            let timeout = match arguments.get("timeout_ms").and_then(Value::as_u64) {
                Some(0) => 0,
                Some(wait) => wait.saturating_add(client::WAIT_TIMEOUT_MARGIN_MS),
                None => options.timeout_ms,
            };
            ("agent.wait", params, timeout)
        }
        "agent-kill" => {
            let target = required(&arguments, "target")?;
            let tab = arguments
                .get("tab")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if tab {
                let tab_id = resolve_field(options, &target, "tab_id")?;
                ("tab.close", json!({"tab_id": tab_id}), options.timeout_ms)
            } else {
                let pane_id = resolve_field(options, &target, "pane_id")?;
                (
                    "pane.close",
                    json!({"pane_id": pane_id}),
                    options.timeout_ms,
                )
            }
        }
        "agent-read" => {
            let target = required(&arguments, "target")?;
            let pane_id = resolve_field(options, &target, "pane_id")?;
            let mut params = json!({"pane_id": pane_id});
            for key in ["source", "lines", "format", "strip_ansi"] {
                if let Some(value) = arguments.get(key) {
                    params[key] = value.clone();
                }
            }
            ("pane.read", params, options.timeout_ms)
        }
        "message-send" => {
            let mut params = json!({
                "to": required(&arguments, "to")?,
                "body": required(&arguments, "body")?,
            });
            for key in ["thread_id", "reply_to", "ttl_s"] {
                if let Some(value) = arguments.get(key) {
                    params[key] = value.clone();
                }
            }
            ("auth.message.send", params, options.timeout_ms)
        }
        "message-poll" => {
            return Ok(run_message_poll(options, &arguments));
        }
        "poll" => {
            return Ok(run_poll(options, &arguments));
        }
        "watch" => {
            let mut params = json!({});
            for key in ["targets", "until", "ttl_s"] {
                if let Some(value) = arguments.get(key) {
                    params[key] = value.clone();
                }
            }
            ("auth.watch.begin", params, options.timeout_ms)
        }
        "watch-cancel" => (
            "auth.watch.end",
            json!({"watch_id": required(&arguments, "watch_id")?}),
            options.timeout_ms,
        ),
        "message-ack" => (
            "auth.message.ack",
            json!({
                "ids": arguments.get("ids").cloned().unwrap_or(json!([])),
                "claim_id": required(&arguments, "claim_id")?,
            }),
            options.timeout_ms,
        ),
        "message-status" => ("auth.message.status", json!({}), options.timeout_ms),
        "peer-grant" => {
            let mut params = json!({
                "a": required(&arguments, "a")?,
                "b": required(&arguments, "b")?,
            });
            if let Some(value) = arguments.get("ttl_s") {
                params["ttl_s"] = value.clone();
            }
            ("auth.message.peer.grant", params, options.timeout_ms)
        }
        "peer-revoke" => (
            "auth.message.peer.revoke",
            json!({"grant_id": required(&arguments, "grant_id")?}),
            options.timeout_ms,
        ),
        "peer-list" => ("auth.message.peer.list", json!({}), options.timeout_ms),
        "whoami" => ("auth.whoami", json!({}), options.timeout_ms),
        other => return Err((-32602, format!("unknown tool: {other}"))),
    };

    let response = match client::exchange(
        &options.socket,
        options.token.as_deref(),
        method,
        call_params,
        timeout_ms,
    ) {
        Ok(response) => response,
        Err(error) => return Ok(tool_error(&error)),
    };
    let mut result = match client::response_result(&response) {
        Ok(result) => result,
        Err(error) => return Ok(tool_error(&error)),
    };
    decorate_agent_waits(options, method, &mut result);
    let text = serde_json::to_string_pretty(&result).unwrap_or_else(|_| result.to_string());
    Ok(json!({
        "content": [{"type": "text", "text": text}],
        "isError": false,
    }))
}

fn proxy_call(
    options: &Options,
    method: &str,
    params: Value,
    timeout_ms: u64,
) -> Result<Value, String> {
    let response = client::exchange(
        &options.socket,
        options.token.as_deref(),
        method,
        params,
        timeout_ms,
    )?;
    client::response_result(&response)
}

/// Register the blocking wait with the proxy so orchestrators can tell
/// `waiting` apart from `working`. The proxy returns the role-capped duration.
fn begin_wait(options: &Options, kind: &str, wait_ms: u64) -> Result<(String, u64, bool), String> {
    let result = proxy_call(
        options,
        "auth.wait.begin",
        json!({"kind": kind, "wait_ms": wait_ms}),
        options.timeout_ms,
    )?;
    let wait_id = result
        .get("wait_id")
        .and_then(Value::as_str)
        .ok_or_else(|| "auth.wait.begin returned no wait_id".to_string())?
        .to_string();
    let effective = result
        .get("wait_ms")
        .and_then(Value::as_u64)
        .unwrap_or(wait_ms);
    let capped = result
        .get("capped")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    Ok((wait_id, effective, capped))
}

fn end_wait(options: &Options, wait_id: &str) {
    let _ = proxy_call(
        options,
        "auth.wait.end",
        json!({"wait_id": wait_id}),
        options.timeout_ms,
    );
}

fn tool_result(result: Value) -> Value {
    let text = serde_json::to_string_pretty(&result).unwrap_or_else(|_| result.to_string());
    json!({
        "content": [{"type": "text", "text": text}],
        "isError": false,
    })
}

fn run_message_poll(options: &Options, arguments: &Value) -> Value {
    let requested = arguments
        .get("wait_ms")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let (wait_id, wait_ms, capped) = match begin_wait(options, "message-poll", requested) {
        Ok(wait) => wait,
        Err(error) => return tool_error(&error),
    };
    let mut params = json!({"wait_ms": wait_ms});
    if let Some(limit) = arguments.get("limit") {
        params["limit"] = limit.clone();
    }
    // 0 means "no socket timeout"; the proxy still returns at the role cap.
    let timeout = if wait_ms == 0 {
        0
    } else {
        wait_ms.saturating_add(client::WAIT_TIMEOUT_MARGIN_MS)
    };
    let response = client::exchange(
        &options.socket,
        options.token.as_deref(),
        "auth.message.poll",
        params,
        timeout,
    );
    end_wait(options, &wait_id);
    let response = match response {
        Ok(response) => response,
        Err(error) => return tool_error(&error),
    };
    let mut result = match client::response_result(&response) {
        Ok(result) => result,
        Err(error) => return tool_error(&error),
    };
    if capped {
        result["capped"] = json!(true);
    }
    tool_result(result)
}

/// Map waits to the agent names the caller already sees.
fn waiting_json(options: &Options, panes: &std::collections::BTreeMap<String, String>) -> Value {
    let Ok(result) = proxy_call(options, "auth.agent.waits", json!({}), options.timeout_ms) else {
        return json!({});
    };
    let mut out = serde_json::Map::new();
    for wait in result
        .get("waits")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
    {
        let Some(pane) = wait
            .get("pane_id")
            .and_then(Value::as_str)
            .map(str::to_owned)
        else {
            continue;
        };
        let key = panes.get(&pane).cloned().unwrap_or(pane);
        out.insert(key, wait);
    }
    Value::Object(out)
}

/// Collect status changes recorded by `auth.watch.begin`.
fn drain_watches(options: &Options) -> Vec<Value> {
    let Ok(result) = proxy_call(options, "auth.watch.drain", json!({}), options.timeout_ms) else {
        return Vec::new();
    };
    result
        .get("watches")
        .and_then(Value::as_array)
        .map(|watches| {
            watches
                .iter()
                .filter_map(|watch| watch.get("changes").and_then(Value::as_array))
                .flatten()
                .cloned()
                .map(|mut change| {
                    if let Some(object) = change.as_object_mut() {
                        object.entry("source").or_insert_with(|| json!("watch"));
                    }
                    change
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Collapse changes that describe the same transition. A transition can be
/// observed twice in one `poll`: once by `auth.watch.*` and once by the poll's
/// own status diff. Records carry `source` (`watch` / `poll`) for diagnostics;
/// the first record wins, and it is the richer watch record when both exist.
fn dedupe_changes(changes: Vec<Value>) -> Vec<Value> {
    let mut seen = std::collections::HashSet::new();
    changes
        .into_iter()
        .filter(|change| {
            let key = (
                change
                    .get("target")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                change
                    .get("from")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                change
                    .get("to")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
            );
            seen.insert(key)
        })
        .collect()
}

fn decorate_agent_waits(options: &Options, method: &str, result: &mut Value) {
    if !matches!(method, "agent.list" | "agent.get") {
        return;
    }
    let Ok(waits) = proxy_call(options, "auth.agent.waits", json!({}), options.timeout_ms) else {
        return;
    };
    let waits = waits
        .get("waits")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let waiting_for = |pane: &str| {
        waits
            .iter()
            .find(|wait| wait.get("pane_id").and_then(Value::as_str) == Some(pane))
            .cloned()
            .unwrap_or(Value::Null)
    };
    if method == "agent.list" {
        if let Some(agents) = result.get_mut("agents").and_then(Value::as_array_mut) {
            for agent in agents {
                let pane = agent
                    .get("pane_id")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                let waiting = pane.as_deref().map(waiting_for).unwrap_or(Value::Null);
                agent["waiting"] = waiting;
            }
        }
        return;
    }
    let pane = result
        .pointer("/agent/pane_id")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let waiting = pane.as_deref().map(waiting_for).unwrap_or(Value::Null);
    if let Some(agent) = result.get_mut("agent") {
        agent["waiting"] = waiting.clone();
    }
    result["waiting"] = waiting;
}

fn run_poll(options: &Options, arguments: &Value) -> Value {
    let requested = arguments
        .get("wait_ms")
        .and_then(Value::as_u64)
        .unwrap_or(30_000);
    let (wait_id, wait_ms, _capped) = match begin_wait(options, "poll", requested) {
        Ok(wait) => wait,
        Err(error) => return tool_error(&error),
    };
    let out = run_poll_inner(options, arguments, wait_ms);
    end_wait(options, &wait_id);
    out
}

fn run_poll_inner(options: &Options, arguments: &Value, wait_ms: u64) -> Value {
    use std::collections::BTreeMap;
    use std::time::Instant;

    let limit = arguments
        .get("limit")
        .and_then(Value::as_u64)
        .unwrap_or(10)
        .clamp(1, 100) as usize;
    let messages_enabled = arguments
        .get("messages")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let targets_filter: Vec<String> = arguments
        .get("targets")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let until: Vec<String> = arguments
        .get("until")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();

    let start = Instant::now();
    let deadline = if wait_ms == 0 {
        None
    } else {
        Some(start + std::time::Duration::from_millis(wait_ms))
    };

    // initial statuses
    // helper closure to fetch statuses
    let fetch = |opts: &Options, filter: &Vec<String>| -> Result<StatusSnapshot, String> {
        let resp = client::exchange(
            &opts.socket,
            opts.token.as_deref(),
            "agent.list",
            json!({}),
            opts.timeout_ms,
        )?;
        let result = client::response_result(&resp)?;
        let agents = result
            .get("agents")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let mut targets = Vec::new();
        let mut statuses = BTreeMap::new();
        let mut names = BTreeMap::new();
        for agent in agents {
            let name = agent.get("name").and_then(Value::as_str).map(str::to_owned);
            let pane = agent
                .get("pane_id")
                .and_then(Value::as_str)
                .map(str::to_owned);
            if let (Some(pane), Some(name)) = (&pane, &name) {
                names.insert(pane.clone(), name.clone());
            }
            let target = name.clone().or(pane.clone());
            let Some(target) = target else {
                continue;
            };
            if !filter.is_empty()
                && !filter.contains(&target)
                && !pane.as_ref().map(|p| filter.contains(p)).unwrap_or(false)
            {
                continue;
            }
            targets.push(target.clone());
            let status = if let Some(s) = agent.get("agent_status").and_then(Value::as_str) {
                s.to_string()
            } else {
                // fetch via agent.get
                let r = client::exchange(
                    &opts.socket,
                    opts.token.as_deref(),
                    "agent.get",
                    json!({"target": target}),
                    opts.timeout_ms,
                );
                match r {
                    Ok(resp) => client::response_result(&resp)
                        .ok()
                        .and_then(|v| {
                            v.pointer("/agent/agent_status")
                                .and_then(Value::as_str)
                                .map(str::to_owned)
                        })
                        .unwrap_or_else(|| "unknown".to_string()),
                    Err(_) => "unknown".to_string(),
                }
            };
            statuses.insert(target, status);
        }
        Ok((targets, statuses, names))
    };

    let (_initial_targets, initial_statuses, names) = match fetch(options, &targets_filter) {
        Ok(v) => v,
        Err(e) => return tool_error(&e),
    };
    let initial = initial_statuses;

    // A fired watch already has changes relative to an earlier baseline; return
    // them immediately so the wake-up is not lost.
    let mut watch_changes = drain_watches(options);
    if !watch_changes.is_empty() {
        return tool_result(json!({
            "timed_out": false,
            "waited_ms": 0,
            "messages": [],
            "changes": dedupe_changes(watch_changes),
            "statuses": initial,
            "waiting": waiting_json(options, &names),
        }));
    }

    loop {
        // check messages
        if messages_enabled {
            let slice = if wait_ms == 0 {
                2000u64
            } else {
                let remaining = deadline
                    .unwrap()
                    .saturating_duration_since(Instant::now())
                    .as_millis() as u64;
                remaining.clamp(1, 5000)
            };
            let resp = client::exchange(
                &options.socket,
                options.token.as_deref(),
                "auth.message.poll",
                json!({"wait_ms": slice, "limit": limit}),
                slice.saturating_add(client::WAIT_TIMEOUT_MARGIN_MS),
            );
            if let Ok(resp) = resp
                && let Ok(result) = client::response_result(&resp)
            {
                let msgs = result
                    .get("messages")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                if !msgs.is_empty() {
                    let waited = start.elapsed().as_millis() as u64;
                    let mut changes = std::mem::take(&mut watch_changes);
                    changes.extend(drain_watches(options));
                    let mut out = json!({
                        "timed_out": false,
                        "waited_ms": waited,
                        "messages": msgs,
                        "claim_id": result.get("claim_id"),
                        "changes": dedupe_changes(changes),
                    });
                    // statuses
                    if let Ok((_, statuses, names)) = fetch(options, &targets_filter) {
                        out["statuses"] = json!(statuses);
                        out["waiting"] = waiting_json(options, &names);
                    }
                    return tool_result(out);
                }
            }
        } else {
            let slice = if wait_ms == 0 {
                2000u64
            } else {
                let remaining = deadline
                    .unwrap()
                    .saturating_duration_since(Instant::now())
                    .as_millis() as u64;
                remaining.clamp(1, 5000)
            };
            std::thread::sleep(std::time::Duration::from_millis(slice));
        }

        // refresh statuses
        let (_cur_targets, cur_statuses, cur_names) = match fetch(options, &targets_filter) {
            Ok(v) => v,
            Err(e) => return tool_error(&e),
        };
        let waiting = waiting_json(options, &cur_names);

        // detect changes against initial (and removed)
        let mut changes = std::mem::take(&mut watch_changes);
        changes.extend(drain_watches(options));
        let mut all_keys: std::collections::BTreeSet<String> = initial.keys().cloned().collect();
        for k in cur_statuses.keys() {
            all_keys.insert(k.clone());
        }
        for key in &all_keys {
            let old = initial.get(key).map(|s| s.as_str()).unwrap_or("__absent__");
            let new = cur_statuses
                .get(key)
                .map(|s| s.as_str())
                .unwrap_or("killed");
            if old != new
                && (until.is_empty() || until.contains(&new.to_string()) || new == "killed")
            {
                changes.push(json!({
                    "target": key,
                    "from": old,
                    "to": new,
                    "source": "poll",
                }));
            }
        }
        let changes = dedupe_changes(changes);
        if !changes.is_empty() {
            let waited = start.elapsed().as_millis() as u64;
            let out = json!({
                "timed_out": false,
                "waited_ms": waited,
                "messages": [],
                "changes": changes,
                "statuses": cur_statuses,
                "waiting": waiting,
            });
            return tool_result(out);
        }
        // timeout check
        if let Some(dl) = deadline
            && Instant::now() >= dl
        {
            let waited = start.elapsed().as_millis() as u64;
            let mut changes = std::mem::take(&mut watch_changes);
            changes.extend(drain_watches(options));
            let changes = dedupe_changes(changes);
            let timed_out = changes.is_empty();
            let out = json!({
                "timed_out": timed_out,
                "waited_ms": waited,
                "messages": [],
                "changes": changes,
                "statuses": cur_statuses,
                "waiting": waiting,
            });
            return tool_result(out);
        }
    }
}

fn tool_error(error: &str) -> Value {
    json!({
        "content": [{"type": "text", "text": error}],
        "isError": true,
    })
}

fn required(arguments: &Value, key: &str) -> Result<String, (i64, String)> {
    arguments
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| (-32602, format!("missing required argument `{key}`")))
}

fn resolve_field(options: &Options, target: &str, field: &str) -> Result<String, (i64, String)> {
    let looks_like_id = target.contains(':');
    if looks_like_id {
        return Ok(target.to_owned());
    }
    let response = client::exchange(
        &options.socket,
        options.token.as_deref(),
        "agent.get",
        json!({"target": target}),
        options.timeout_ms,
    )
    .map_err(|error| (-32000, error))?;
    let result = client::response_result(&response).map_err(|error| (-32000, error))?;
    result
        .pointer(&format!("/agent/{field}"))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| (-32000, format!("agent has no {field}")))
}

fn tools() -> Vec<Value> {
    vec![
        tool(
            "agent-spawn",
            "Create a tab, mint a child agent token, and start a sandboxed agent.",
            json!({
                "type": "object",
                "properties": {
                    "kind": {"type": "string", "description": "Must be a sandboxed agent kind configured on the proxy"},
                    "name": {"type": "string"},
                    "cwd": {"type": "string", "description": "Must match the caller token cwd"},
                    "workspace_id": {"type": "string"},
                    "label": {"type": "string"},
                    "focus": {"type": "boolean"},
                    "ttl_s": {"type": "integer"},
                    "grants": {"type": "array", "items": {"type": "string"}},
                    "args": {"type": "array", "items": {"type": "string"}}
                },
                "required": ["kind"]
            }),
        ),
        tool(
            "agent-list",
            "List agents owned by the caller.",
            json!({"type": "object", "properties": {}}),
        ),
        tool(
            "agent-get",
            "Get one owned agent by name or pane id.",
            json!({
                "type": "object",
                "properties": {"target": {"type": "string"}},
                "required": ["target"]
            }),
        ),
        tool(
            "agent-wait",
            "Wait for an owned agent to reach a lifecycle state. Orchestrator timeouts are capped (default 30s); use `watch` instead of parking.",
            json!({
                "type": "object",
                "properties": {
                    "target": {"type": "string"},
                    "until": {"type": "array", "items": {"type": "string"}},
                    "timeout_ms": {"type": "integer"}
                },
                "required": ["target"]
            }),
        ),
        tool(
            "agent-kill",
            "Close an agent's pane, or its whole tab with `tab: true`.",
            json!({
                "type": "object",
                "properties": {
                    "target": {"type": "string"},
                    "tab": {"type": "boolean"}
                },
                "required": ["target"]
            }),
        ),
        tool(
            "agent-read",
            "ADMIN ONLY diagnostic: read raw terminal output.",
            json!({
                "type": "object",
                "properties": {
                    "target": {"type": "string"},
                    "source": {"type": "string"},
                    "lines": {"type": "integer"},
                    "format": {"type": "string"},
                    "strip_ansi": {"type": "boolean"}
                },
                "required": ["target"]
            }),
        ),
        tool(
            "message-send",
            "Queue a durable message for a parent, child, granted sibling, or `to: \"parent\"`.",
            json!({
                "type": "object",
                "properties": {
                    "to": {"type": "string"},
                    "body": {"type": "string"},
                    "thread_id": {"type": "string"},
                    "reply_to": {"type": "string"},
                    "ttl_s": {"type": "integer"}
                },
                "required": ["to", "body"]
            }),
        ),
        tool(
            "message-poll",
            "Claim unread messages. wait_ms=0 waits as long as your role allows: agents may wait indefinitely, orchestrators are capped (default 30s).",
            json!({
                "type": "object",
                "properties": {
                    "wait_ms": {"type": "integer"},
                    "limit": {"type": "integer"}
                }
            }),
        ),
        tool(
            "poll",
            "Collect messages, fired watch changes, and owned child status changes. wait_ms=0 waits up to your role cap (or indefinitely for agents). Orchestrators should prefer `watch` + a short `poll`. `changes` are deduped and carry `source` (`watch` or `poll`).",
            json!({
                "type": "object",
                "properties": {
                    "wait_ms": {"type": "integer", "description": "Maximum wait in ms; 0 = role cap (or indefinitely for agents)"},
                    "limit": {"type": "integer"},
                    "messages": {"type": "boolean", "description": "Also wait for and claim incoming messages"},
                    "targets": {"type": "array", "items": {"type": "string"}, "description": "Agent names/pane ids to watch; default all owned"},
                    "until": {"type": "array", "items": {"type": "string"}, "description": "Only trigger on these child statuses"}
                }
            }),
        ),
        tool(
            "watch",
            "Register a non-blocking watch on owned children. Returns immediately; the proxy prompts you (when idle) on a matching change. Call `poll` afterwards. Prefer this over a long `poll`.",
            json!({
                "type": "object",
                "properties": {
                    "targets": {"type": "array", "items": {"type": "string"}, "description": "Agent names/pane ids; default all owned children"},
                    "until": {"type": "array", "items": {"type": "string"}, "description": "Only trigger on these statuses (idle, working, done, blocked, unknown, killed)"},
                    "ttl_s": {"type": "integer", "description": "Watch lifetime in seconds (default 600, max 3600)"}
                }
            }),
        ),
        tool(
            "watch-cancel",
            "Cancel a watch before it fires or expires.",
            json!({
                "type": "object",
                "properties": {"watch_id": {"type": "string"}},
                "required": ["watch_id"]
            }),
        ),
        tool(
            "message-ack",
            "Acknowledge claimed messages with the matching claim_id.",
            json!({
                "type": "object",
                "properties": {
                    "ids": {"type": "array", "items": {"type": "string"}},
                    "claim_id": {"type": "string"}
                },
                "required": ["ids", "claim_id"]
            }),
        ),
        tool(
            "message-status",
            "Show queued/claimed counts, last poll, and an unresponsive hint.",
            json!({"type": "object", "properties": {}}),
        ),
        tool(
            "peer-grant",
            "Allow two direct children of the caller to message each other.",
            json!({
                "type": "object",
                "properties": {
                    "a": {"type": "string"},
                    "b": {"type": "string"},
                    "ttl_s": {"type": "integer"}
                },
                "required": ["a", "b"]
            }),
        ),
        tool(
            "peer-revoke",
            "Revoke a peer grant by id.",
            json!({
                "type": "object",
                "properties": {"grant_id": {"type": "string"}},
                "required": ["grant_id"]
            }),
        ),
        tool(
            "peer-list",
            "List peer grants created by the caller.",
            json!({"type": "object", "properties": {}}),
        ),
        tool(
            "whoami",
            "Show the identity and permissions the proxy associates with this client.",
            json!({"type": "object", "properties": {}}),
        ),
    ]
}

fn tool(name: &str, description: &str, input_schema: Value) -> Value {
    json!({
        "name": name,
        "description": description,
        "inputSchema": input_schema,
    })
}

fn resources() -> Vec<Value> {
    vec![
        json!({
            "uri": "herdr://docs/mcp",
            "name": "herdr-auth MCP server",
            "description": "Transport, authentication, and tool model",
            "mimeType": "text/markdown",
        }),
        json!({
            "uri": "herdr://docs/messages",
            "name": "Agent message semantics",
            "description": "Relationships, delivery guarantees, and wake-up behaviour",
            "mimeType": "text/markdown",
        }),
    ]
}

fn read_resource(params: &Value) -> Result<Value, (i64, String)> {
    let uri = params
        .get("uri")
        .and_then(Value::as_str)
        .ok_or_else(|| (-32602, "resources/read requires uri".to_string()))?;
    let text = match uri {
        "herdr://docs/mcp" => MCP_DOC,
        "herdr://docs/messages" => MESSAGES_DOC,
        other => return Err((-32602, format!("unknown resource: {other}"))),
    };
    Ok(json!({
        "contents": [{
            "uri": uri,
            "mimeType": "text/markdown",
            "text": text,
        }]
    }))
}

fn spawn_notifier(options: Options, out: Arc<Mutex<std::io::Stdout>>) {
    thread::spawn(move || {
        let mut last_ids: Vec<String> = Vec::new();
        loop {
            let response = client::exchange(
                &options.socket,
                options.token.as_deref(),
                "auth.message.notify",
                json!({"wait_ms": NOTIFY_WAIT_MS}),
                NOTIFY_WAIT_MS + 10_000,
            );
            let Ok(response) = response else {
                thread::sleep(Duration::from_secs(2));
                continue;
            };
            let Ok(result) = client::response_result(&response) else {
                thread::sleep(Duration::from_secs(2));
                continue;
            };
            let messages = result
                .get("messages")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let ids: Vec<String> = messages
                .iter()
                .filter_map(|message| message.get("id").and_then(Value::as_str))
                .map(str::to_owned)
                .collect();
            if ids.is_empty() {
                continue;
            }
            if ids == last_ids {
                thread::sleep(Duration::from_secs(5));
                continue;
            }
            last_ids = ids;
            let notification = json!({
                "jsonrpc": "2.0",
                "method": "notifications/message",
                "params": {
                    "level": "info",
                    "logger": "herdr-auth/messages",
                    "data": {
                        "type": "message_available",
                        "pending": messages.len(),
                        "messages": messages,
                    }
                }
            });
            let _ = write_message(&out, &notification);
        }
    });
}

fn write_message(out: &Arc<Mutex<std::io::Stdout>>, message: &Value) -> Result<(), String> {
    let mut out = out.lock().map_err(|_| "stdout lock poisoned".to_string())?;
    serde_json::to_writer(&mut *out, message).map_err(|error| format!("encode: {error}"))?;
    out.write_all(b"\n")
        .and_then(|_| out.flush())
        .map_err(|error| format!("write stdout: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initialize_advertises_instructions_and_tools() {
        let options = Options {
            socket: PathBuf::from("/nonexistent"),
            token: None,
            timeout_ms: 1,
        };
        let response = handle(
            &options,
            &json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
        )
        .unwrap();
        assert_eq!(response["id"], json!(1));
        assert!(
            response["result"]["instructions"]
                .as_str()
                .unwrap()
                .contains("message-poll")
        );
        assert!(response["result"]["capabilities"]["tools"].is_object());
    }

    #[test]
    fn tools_list_has_message_and_no_prompt_or_read_for_the_workflow() {
        let tools = tools();
        let names: Vec<&str> = tools
            .iter()
            .filter_map(|tool| tool.get("name").and_then(Value::as_str))
            .collect();
        assert!(names.contains(&"message-send"));
        assert!(names.contains(&"message-poll"));
        assert!(names.contains(&"poll"));
        assert!(names.contains(&"peer-grant"));
        assert!(names.contains(&"agent-read"));
        assert!(!names.contains(&"prompt"));
    }

    #[test]
    fn resources_are_readable() {
        let result = read_resource(&json!({"uri": "herdr://docs/messages"})).unwrap();
        assert!(
            result["contents"][0]["text"]
                .as_str()
                .unwrap()
                .contains("peer-grant")
        );
    }

    #[test]
    fn watch_and_poll_duplicate_changes_collapse() {
        let changes = dedupe_changes(vec![
            json!({
                "target": "dev-2", "pane_id": "w1:p2",
                "from": "working", "to": "done", "source": "watch"
            }),
            json!({
                "target": "dev-2", "from": "working", "to": "done",
                "source": "poll"
            }),
            json!({
                "target": "dev-2", "from": "working", "to": "blocked",
                "source": "poll"
            }),
        ]);
        assert_eq!(changes.len(), 2);
        // The first (watch) record wins and keeps its richer payload.
        assert_eq!(changes[0]["source"], json!("watch"));
        assert_eq!(changes[0]["pane_id"], json!("w1:p2"));
        assert_eq!(changes[1]["to"], json!("blocked"));
    }

    #[test]
    fn distinct_transitions_are_not_deduped() {
        let changes = dedupe_changes(vec![
            json!({"target": "dev-2", "from": "idle", "to": "working", "source": "poll"}),
            json!({"target": "dev-2", "from": "working", "to": "done", "source": "poll"}),
        ]);
        assert_eq!(changes.len(), 2);
    }

    /// Minimal blocking proxy for the client-side `poll` / `message-poll`
    /// flows. Records every method call so the tests can assert ordering.
    struct FakeProxy {
        dir: PathBuf,
        socket: PathBuf,
        stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
        calls: std::sync::Arc<Mutex<Vec<(String, Value)>>>,
        handle: Option<thread::JoinHandle<()>>,
    }

    impl FakeProxy {
        fn new(handler: impl Fn(&str, &Value) -> Value + Send + 'static) -> Self {
            let dir = std::env::temp_dir().join(format!("hap-mcp-{}", crate::jwt::random_id()));
            std::fs::create_dir_all(&dir).unwrap();
            let socket = dir.join("auth.sock");
            let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
            listener.set_nonblocking(true).unwrap();
            let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let calls = std::sync::Arc::new(Mutex::new(Vec::new()));
            let thread_stop = stop.clone();
            let thread_calls = calls.clone();
            let handle = thread::spawn(move || {
                while !thread_stop.load(std::sync::atomic::Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            stream
                                .set_read_timeout(Some(Duration::from_millis(500)))
                                .ok();
                            let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
                            let mut line = String::new();
                            if reader.read_line(&mut line).unwrap_or(0) == 0 {
                                continue;
                            }
                            let Ok(request) = serde_json::from_str::<Value>(line.trim()) else {
                                continue;
                            };
                            let method = request
                                .get("method")
                                .and_then(Value::as_str)
                                .unwrap_or("")
                                .to_string();
                            let params = request.get("params").cloned().unwrap_or(json!({}));
                            thread_calls
                                .lock()
                                .unwrap()
                                .push((method.clone(), params.clone()));
                            let result = handler(&method, &params);
                            let id = request.get("id").cloned().unwrap_or(Value::Null);
                            let response = match result.get("__error").and_then(Value::as_str) {
                                Some(error) => {
                                    json!({"id": id, "error": {"code": "error", "message": error}})
                                }
                                None => json!({"id": id, "result": result}),
                            };
                            let _ = writeln!(stream, "{response}");
                        }
                        Err(ref error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(2));
                        }
                        Err(_) => break,
                    }
                }
            });
            Self {
                dir,
                socket,
                stop,
                calls,
                handle: Some(handle),
            }
        }

        fn options(&self) -> Options {
            Options {
                socket: self.socket.clone(),
                token: None,
                timeout_ms: 2_000,
            }
        }

        fn methods(&self) -> Vec<String> {
            self.calls
                .lock()
                .unwrap()
                .iter()
                .map(|(method, _)| method.clone())
                .collect()
        }
    }

    impl Drop for FakeProxy {
        fn drop(&mut self) {
            self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
            if let Some(handle) = self.handle.take() {
                let _ = handle.join();
            }
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn result_text(value: &Value) -> Value {
        let text = value["content"][0]["text"].as_str().unwrap();
        serde_json::from_str(text).unwrap()
    }

    #[test]
    fn message_poll_registers_uses_and_ends_the_capped_wait() {
        let proxy = FakeProxy::new(|method, _| match method {
            "auth.wait.begin" => json!({"wait_id": "w-1", "wait_ms": 1_000, "capped": true}),
            "auth.message.poll" => json!({"messages": [], "timed_out": true}),
            "auth.wait.end" => json!({"ended": true}),
            _ => json!({"__error": "unexpected"}),
        });
        let out = run_message_poll(&proxy.options(), &json!({"wait_ms": 0}));
        assert_eq!(result_text(&out)["timed_out"], json!(true));
        assert_eq!(result_text(&out)["capped"], json!(true));
        assert_eq!(
            proxy.methods(),
            vec!["auth.wait.begin", "auth.message.poll", "auth.wait.end"]
        );
        let calls = proxy.calls.lock().unwrap();
        assert_eq!(calls[0].1["kind"], json!("message-poll"));
        assert_eq!(calls[1].1["wait_ms"], json!(1_000));
    }

    #[test]
    fn poll_with_zero_wait_returns_at_the_effective_cap_instead_of_hanging() {
        let proxy = FakeProxy::new(|method, _| match method {
            "auth.wait.begin" => json!({"wait_id": "w-2", "wait_ms": 1, "capped": true}),
            "auth.watch.drain" => json!({"watches": []}),
            "auth.message.poll" => json!({"messages": [], "timed_out": true}),
            "auth.agent.waits" => json!({"waits": []}),
            "agent.list" => json!({"agents": []}),
            "agent.get" => json!({"__error": "unexpected"}),
            "auth.wait.end" => json!({"ended": true}),
            _ => json!({"__error": "unexpected"}),
        });
        let started = std::time::Instant::now();
        let out = run_poll(&proxy.options(), &json!({"wait_ms": 0}));
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(result_text(&out)["timed_out"], json!(true));
        assert!(proxy.methods().contains(&"auth.message.poll".to_string()));
        assert_eq!(proxy.methods().last().unwrap(), "auth.wait.end");
    }

    #[test]
    fn poll_returns_a_fired_watch_without_blocking() {
        let proxy = FakeProxy::new(|method, _| match method {
            "auth.wait.begin" => json!({"wait_id": "w-3", "wait_ms": 0, "capped": false}),
            "auth.watch.drain" => json!({"watches": [{
                "watch_id": "watch-1",
                "changes": [{"target": "worker", "pane_id": "w1:p2", "from": "working", "to": "idle"}]
            }]}),
            "agent.list" => json!({"agents": []}),
            "auth.wait.end" => json!({"ended": true}),
            _ => json!({"__error": "unexpected"}),
        });
        let out = run_poll(&proxy.options(), &json!({"wait_ms": 0}));
        let out = result_text(&out);
        assert_eq!(out["timed_out"], json!(false));
        assert_eq!(out["changes"][0]["to"], json!("idle"));
        assert!(!proxy.methods().contains(&"auth.message.poll".to_string()));
    }
}
