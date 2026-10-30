//! Grantable agent capabilities. The proxy intersects the requested set with
//! this list *and* the minter's `agent_grants`.

pub const GRANTABLE_AGENT_CAPABILITIES: &[&str] = &[
    "report_status",
    "report_metadata",
    "read_own_pane",
    "wait_own_output",
];

pub fn validate(grants: &[String]) -> Result<(), String> {
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

/// Whether every requested grant is in `allowed`.
pub fn is_subset(requested: &[String], allowed: &[String]) -> bool {
    requested
        .iter()
        .all(|grant| allowed.iter().any(|a| a == grant))
}

/// Methods unlocked by a grant set (plus `ping`).
pub fn methods(grants: &[String]) -> Vec<&'static str> {
    let mut methods = vec!["ping"];
    for grant in grants {
        match grant.as_str() {
            "report_status" => {
                methods.push("pane.report_agent");
                methods.push("pane.report_agent_session");
            }
            "report_metadata" => methods.push("pane.report_metadata"),
            "read_own_pane" => {
                methods.push("pane.get");
                methods.push("pane.read");
                methods.push("agent.get");
            }
            "wait_own_output" => methods.push("pane.wait_for_output"),
            _ => {}
        }
    }
    methods
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_status_covers_the_opencode_plugin() {
        let methods = methods(&["report_status".into()]);
        assert!(methods.contains(&"pane.report_agent"));
        assert!(methods.contains(&"pane.report_agent_session"));
        assert!(methods.contains(&"ping"));
        assert!(!methods.contains(&"pane.read"));
    }

    #[test]
    fn subset_is_enforced() {
        assert!(is_subset(
            &["report_status".into()],
            &["report_status".into(), "read_own_pane".into()]
        ));
        assert!(!is_subset(
            &["read_own_pane".into()],
            &["report_status".into()]
        ));
    }
}
