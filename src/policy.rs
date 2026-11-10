//! Method registry, role allowlists, and ownership/response helpers.

use serde_json::Value;

use crate::grants;
use crate::jwt::Role;
use crate::state::State;

/// All herdr 0.9.5 (protocol 22) API methods. Unknown methods are denied and
/// logged with the `[new-command]` tag.
pub const KNOWN_METHODS: &[&str] = &[
    "ping",
    "server.stop",
    "server.live_handoff",
    "server.reload_config",
    "server.ssh_agent.register",
    "server.agent_manifests",
    "server.reload_agent_manifests",
    "notification.show",
    "product_announcement.dismiss",
    "release_notes.dismiss",
    "command.invoke",
    "client.window_title.set",
    "client.window_title.clear",
    "client_shell.surface.set",
    "session.snapshot",
    "workspace.create",
    "workspace.list",
    "workspace.get",
    "workspace.focus",
    "workspace.rename",
    "workspace.move",
    "workspace.move_block",
    "workspace.report_metadata",
    "workspace.close",
    "worktree.list",
    "worktree.create",
    "worktree.open",
    "worktree.remove",
    "tab.create",
    "tab.list",
    "tab.get",
    "tab.focus",
    "tab.rename",
    "tab.move",
    "tab.close",
    "agent.list",
    "agent.get",
    "agent.read",
    "agent.explain",
    "agent.send_keys",
    "agent.rename",
    "agent.view.set",
    "agent.view.clear",
    "agent.focus",
    "agent.start",
    "agent.prompt",
    "agent.wait",
    "pane.split",
    "pane.swap",
    "pane.move",
    "pane.zoom",
    "pane.layout",
    "pane.process_info",
    "layout.export",
    "layout.apply",
    "layout.set_split_ratio",
    "pane.neighbor",
    "pane.edges",
    "pane.focus_direction",
    "pane.resize",
    "pane.scroll",
    "pane.clear",
    "pane.edit_scrollback",
    "pane.selection.read",
    "pane.copy_motion",
    "pane.copy_search",
    "pane.list",
    "pane.current",
    "pane.get",
    "pane.focus",
    "pane.input.set",
    "pane.link.activate",
    "pane.link.resolve",
    "pane.rename",
    "pane.send_text",
    "pane.send_keys",
    "pane.send_input",
    "pane.read",
    "pane.report_agent",
    "pane.report_agent_session",
    "pane.report_metadata",
    "pane.clear_agent_authority",
    "pane.release_agent",
    "pane.close",
    "popup.close",
    "events.subscribe",
    "events.wait",
    "pane.wait_for_output",
    "integration.list",
    "integration.install",
    "integration.uninstall",
    "plugin.link",
    "plugin.list",
    "plugin.unlink",
    "plugin.enable",
    "plugin.disable",
    "plugin.action.list",
    "plugin.action.invoke",
    "plugin.log.list",
    "plugin.pane.open",
    "plugin.pane.focus",
    "plugin.pane.close",
];

/// Minimal orchestrator workflow (default-deny everything else).
/// Agent kinds that have a sandbox wrapper. A token's `agent_kinds` may narrow
/// this list but never widen it: any other kind would run unsandboxed.
pub const SANDBOXED_AGENT_KINDS: &[&str] = &["opencode"];

pub const ORCHESTRATOR_METHODS: &[&str] = &[
    "ping",
    // The only way an orchestrator may create a pane/start an agent is the
    // atomic auth.agent.spawn (proxy env/cwd/token authority). Direct
    // pane.split/tab.create/agent.start are intentionally denied: they create
    // or use plain shells that run arbitrary code as the herdr user.
    // read (owned only / filtered)
    "pane.list",
    "pane.get",
    "pane.read",
    "pane.wait_for_output",
    "tab.list",
    "tab.get",
    "agent.list",
    "agent.get",
    "agent.read",
    "agent.wait",
    // control (owned)
    "tab.close",
    "pane.close",
    "agent.prompt",
    // proxy extensions
    "auth.whoami",
    "auth.methods",
    "auth.token.mint",
    "auth.agent.spawn",
];

pub fn is_known(method: &str) -> bool {
    KNOWN_METHODS.contains(&method) || method.starts_with("auth.")
}

pub fn allowed(role: Role, method: &str) -> bool {
    match role {
        Role::Admin => is_known(method),
        Role::Orchestrator => ORCHESTRATOR_METHODS.contains(&method),
        Role::Agent => method == "ping" || grants::methods(&[]).contains(&method),
    }
}

pub fn allowed_for(role: Role, method: &str, agent_grants: &[String]) -> bool {
    match role {
        Role::Agent => grants::methods(agent_grants).contains(&method) || method == "ping",
        _ => allowed(role, method),
    }
}

pub fn pane_id_param(params: &Value) -> Option<&str> {
    params
        .get("pane_id")
        .or_else(|| params.get("target_pane_id"))
        .and_then(Value::as_str)
}

pub fn tab_id_param(params: &Value) -> Option<&str> {
    params.get("tab_id").and_then(Value::as_str)
}

/// Agent targets are either a pane id (`w1:p2`) or an agent name.
///
/// herdr's agent methods use `target`; older/other shapes use `agent`.
pub fn agent_target_pane(params: &Value) -> Option<&str> {
    params
        .get("target")
        .or_else(|| params.get("agent"))
        .and_then(Value::as_str)
        .filter(|value| value.contains(':'))
}

pub fn agent_target(params: &Value) -> Option<&str> {
    params
        .get("target")
        .or_else(|| params.get("agent"))
        .and_then(Value::as_str)
}

/// Record ids returned by creation methods.
pub fn record_created(
    method: &str,
    result: &Value,
    state: &mut State,
    sub: &str,
    jti: &str,
    cwd: Option<&str>,
) {
    match method {
        "pane.split" => {
            if let Some(pane) = result.pointer("/pane/pane_id").and_then(Value::as_str) {
                state.record_pane(pane, sub, Some(jti), cwd);
            }
        }
        "tab.create" => {
            if let Some(tab) = result.pointer("/tab/tab_id").and_then(Value::as_str) {
                state.record_tab(tab, sub);
            }
            if let Some(pane) = result.pointer("/root_pane/pane_id").and_then(Value::as_str) {
                state.record_pane(pane, sub, Some(jti), cwd);
            }
        }
        _ => {}
    }
}

/// The new pane id returned by a creation method, if any.
pub fn created_pane_id<'a>(method: &str, result: &'a Value) -> Option<&'a str> {
    match method {
        "pane.split" => result.pointer("/pane/pane_id").and_then(Value::as_str),
        "tab.create" => result.pointer("/root_pane/pane_id").and_then(Value::as_str),
        _ => None,
    }
}

/// Filter list responses to the caller's owned ids.
pub fn filter_result(method: &str, result: &mut Value, state: &State, sub: &str) {
    let (key, is_tab) = match method {
        "pane.list" => ("panes", false),
        "agent.list" => ("agents", false),
        "tab.list" => ("tabs", true),
        _ => return,
    };
    let Some(items) = result.get_mut(key).and_then(Value::as_array_mut) else {
        return;
    };
    items.retain(|item| {
        let id = item
            .get(if is_tab { "tab_id" } else { "pane_id" })
            .and_then(Value::as_str);
        let Some(id) = id else { return false };
        if is_tab {
            state.owns_tab(id, sub)
        } else {
            state.owns_pane(id, sub)
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn registry_is_complete_enough() {
        assert!(is_known("pane.report_agent"));
        assert!(is_known("auth.whoami"));
        assert!(!is_known("pane.invented"));
    }

    #[test]
    fn orchestrator_allowlist_is_minimal() {
        assert!(allowed(Role::Orchestrator, "auth.agent.spawn"));
        assert!(allowed(Role::Orchestrator, "pane.wait_for_output"));
        assert!(!allowed(Role::Orchestrator, "pane.split"));
        assert!(!allowed(Role::Orchestrator, "tab.create"));
        assert!(!allowed(Role::Orchestrator, "agent.start"));
        assert!(!allowed(Role::Orchestrator, "pane.send_text"));
        assert!(!allowed(Role::Orchestrator, "layout.apply"));
        assert!(!allowed(Role::Orchestrator, "events.subscribe"));
        assert!(!allowed(Role::Orchestrator, "workspace.create"));
    }

    #[test]
    fn agent_allowlist_follows_grants() {
        let grants = vec!["report_status".to_string()];
        assert!(allowed_for(Role::Agent, "pane.report_agent", &grants));
        assert!(!allowed_for(Role::Agent, "pane.read", &grants));
        assert!(!allowed_for(Role::Agent, "pane.report_agent", &[]));
        assert!(allowed_for(Role::Agent, "ping", &[]));
        assert!(!allowed_for(Role::Agent, "pane.send_text", &grants));
    }

    #[test]
    fn agent_targets_use_target_field() {
        assert_eq!(
            agent_target_pane(&json!({"target": "w1:p2"})),
            Some("w1:p2")
        );
        assert_eq!(agent_target(&json!({"target": "alice"})), Some("alice"));
        assert_eq!(agent_target_pane(&json!({"target": "alice"})), None);
    }

    #[test]
    fn list_filtering_keeps_owned_only() {
        let mut state = State::default();
        state.record_pane("w1:p1", "alice", None, None);
        let mut result = json!({"panes": [
            {"pane_id": "w1:p1"},
            {"pane_id": "w1:p2"}
        ]});
        filter_result("pane.list", &mut result, &state, "alice");
        let panes = result["panes"].as_array().unwrap();
        assert_eq!(panes.len(), 1);
        assert_eq!(panes[0]["pane_id"], "w1:p1");
    }

    #[test]
    fn creation_responses_record_ownership() {
        let mut state = State::default();
        record_created(
            "tab.create",
            &json!({"tab": {"tab_id": "w1:t2"}, "root_pane": {"pane_id": "w1:p3"}}),
            &mut state,
            "alice",
            "j1",
            Some("/work"),
        );
        assert!(state.owns_tab("w1:t2", "alice"));
        assert!(state.owns_pane("w1:p3", "alice"));
        assert_eq!(state.pane_cwd("w1:p3"), Some("/work"));
    }
}
