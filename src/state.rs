//! Pane/tab ownership and token binding, persisted as JSON.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Entry {
    pub sub: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    /// Canonical working directory the pane was created in, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TokenEntry {
    pub sub: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pane_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exp: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct State {
    #[serde(default)]
    pub panes: HashMap<String, Entry>,
    #[serde(default)]
    pub tabs: HashMap<String, Entry>,
    #[serde(default)]
    pub tokens: HashMap<String, TokenEntry>,
}

impl State {
    pub fn load(path: &Path) -> Self {
        fs::read_to_string(path)
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| format!("create {}: {error}", parent.display()))?;
        }
        let text =
            serde_json::to_string_pretty(self).map_err(|error| format!("encode state: {error}"))?;
        let tmp = path.with_extension("json.tmp");
        fs::write(&tmp, text).map_err(|error| format!("write {}: {error}", tmp.display()))?;
        fs::rename(&tmp, path).map_err(|error| format!("rename {}: {error}", path.display()))
    }

    pub fn prune(&mut self, now: u64) {
        self.tokens
            .retain(|_, token| token.exp.is_none_or(|exp| exp > now));
    }

    pub fn record_pane(&mut self, pane_id: &str, sub: &str, jti: Option<&str>, cwd: Option<&str>) {
        self.panes.insert(
            pane_id.to_owned(),
            Entry {
                sub: sub.to_owned(),
                jti: jti.map(str::to_owned),
                cwd: cwd.map(str::to_owned),
            },
        );
    }

    pub fn record_tab(&mut self, tab_id: &str, sub: &str) {
        self.tabs.insert(
            tab_id.to_owned(),
            Entry {
                sub: sub.to_owned(),
                jti: None,
                cwd: None,
            },
        );
    }

    pub fn pane_cwd(&self, pane_id: &str) -> Option<&str> {
        self.panes
            .get(pane_id)
            .and_then(|entry| entry.cwd.as_deref())
    }

    pub fn bind_token(&mut self, jti: &str, pane_id: &str) {
        if let Some(token) = self.tokens.get_mut(jti) {
            token.pane_id = Some(pane_id.to_owned());
        }
    }

    pub fn pane_of_token(&self, jti: &str) -> Option<String> {
        self.tokens.get(jti).and_then(|token| token.pane_id.clone())
    }

    pub fn owns_pane(&self, pane_id: &str, sub: &str) -> bool {
        self.panes
            .get(pane_id)
            .is_some_and(|entry| entry.sub == sub)
            || self
                .tokens
                .values()
                .any(|token| token.sub == sub && token.pane_id.as_deref() == Some(pane_id))
    }

    pub fn owns_tab(&self, tab_id: &str, sub: &str) -> bool {
        self.tabs.get(tab_id).is_some_and(|entry| entry.sub == sub)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ownership_roundtrip() {
        let mut state = State::default();
        state.record_pane("w1:p1", "alice", None, Some("/work"));
        state.record_tab("w1:t1", "alice");
        assert_eq!(state.pane_cwd("w1:p1"), Some("/work"));
        assert!(state.owns_pane("w1:p1", "alice"));
        assert!(!state.owns_pane("w1:p1", "bob"));
        assert!(state.owns_tab("w1:t1", "alice"));
        assert!(!state.owns_tab("w1:t1", "bob"));
    }

    #[test]
    fn token_binding_confers_ownership() {
        let mut state = State::default();
        state.tokens.insert(
            "j1".into(),
            TokenEntry {
                sub: "alice".into(),
                pane_id: None,
                exp: None,
            },
        );
        state.bind_token("j1", "w1:p9");
        assert!(state.owns_pane("w1:p9", "alice"));
        assert_eq!(state.pane_of_token("j1").as_deref(), Some("w1:p9"));
    }

    #[test]
    fn expired_tokens_are_pruned() {
        let mut state = State::default();
        state.tokens.insert(
            "old".into(),
            TokenEntry {
                sub: "a".into(),
                pane_id: None,
                exp: Some(10),
            },
        );
        state.tokens.insert(
            "new".into(),
            TokenEntry {
                sub: "a".into(),
                pane_id: None,
                exp: Some(100),
            },
        );
        state.prune(50);
        assert!(!state.tokens.contains_key("old"));
        assert!(state.tokens.contains_key("new"));
    }
}
