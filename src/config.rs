//! Path resolution and config loading.
//!
//! Mirrors herdr's socket discovery: `HERDR_SOCKET_PATH` → `HERDR_SESSION` →
//! `<config>/herdr.sock`.

use std::env;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct Config {
    /// Upstream herdr socket. `None` (or "auto") follows herdr's resolution.
    pub upstream_socket: Option<String>,
    /// Downstream auth socket. `None` uses the runtime dir default.
    pub auth_socket: Option<String>,
    /// Default lifetime for agent tokens.
    pub agent_ttl_s: u64,
    /// Hard cap for every explicitly requested token lifetime (seconds). A
    /// token never expires later than `now + max_token_ttl_s` when a TTL is
    /// requested, regardless of what the caller asks for.
    pub max_token_ttl_s: u64,
    /// How long the upstream socket may be unreachable before the proxy exits.
    pub death_grace_s: u64,
    /// Maximum `wait_ms` accepted by `auth.message.poll` / `.notify`.
    pub message_poll_max_ms: u64,
    /// Agent kinds that have a sandbox wrapper. `agent.start` /
    /// `auth.agent.spawn` may only start these, and agent tokens report as one
    /// of them. A token's `perm.agent_kinds` may narrow this list, never widen
    /// it. The first entry is the default reporting kind.
    pub sandboxed_agent_kinds: Vec<String>,
    /// Claim lease for at-least-once delivery; unacked messages reappear.
    pub message_claim_lease_s: u64,
    /// Default lifetime of a queued message.
    pub message_ttl_s: u64,
    /// Largest accepted message body.
    pub message_max_bytes: usize,
    /// Stage 1 notification to stage 2 `agent.prompt` fallback delay.
    pub message_wakeup_after_s: u64,
    /// Minimum interval between wake-up prompts for one target.
    pub message_wakeup_min_interval_s: u64,
    /// Age after which an idle target with unread mail is flagged unresponsive.
    pub message_stale_s: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            upstream_socket: None,
            auth_socket: None,
            agent_ttl_s: 86_400,
            max_token_ttl_s: 86_400,
            death_grace_s: 15,
            message_poll_max_ms: 3_600_000,
            sandboxed_agent_kinds: vec!["opencode".to_string()],
            message_claim_lease_s: 300,
            message_ttl_s: 86_400,
            message_max_bytes: 262_144,
            message_wakeup_after_s: 10,
            message_wakeup_min_interval_s: 30,
            message_stale_s: 120,
        }
    }
}

impl Config {
    /// Reject an unusable sandboxed-kind list instead of silently starting an
    /// unsandboxed agent or minting an empty reporting identity.
    pub fn validate(&self) -> Result<(), String> {
        if self.sandboxed_agent_kinds.is_empty() {
            return Err("sandboxed_agent_kinds must not be empty".to_string());
        }
        let mut seen = std::collections::BTreeSet::new();
        for kind in &self.sandboxed_agent_kinds {
            let mut chars = kind.chars();
            let valid = kind.len() <= 32
                && chars.next().is_some_and(|c| c.is_ascii_lowercase())
                && chars
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_');
            if !valid {
                return Err(format!(
                    "invalid sandboxed agent kind `{kind}` (expected [a-z][a-z0-9_-]{{0,31}})"
                ));
            }
            if !seen.insert(kind.as_str()) {
                return Err(format!("duplicate sandboxed agent kind `{kind}`"));
            }
        }
        Ok(())
    }

    /// Reporting kind for tokens that do not carry an explicit `agent_kind`.
    pub fn default_agent_kind(&self) -> Option<&str> {
        self.sandboxed_agent_kinds.first().map(String::as_str)
    }

    pub fn allows_agent_kind(&self, kind: &str) -> bool {
        self.sandboxed_agent_kinds
            .iter()
            .any(|allowed| allowed == kind)
    }
}
#[derive(Debug, Clone)]
pub struct Paths {
    pub config_dir: PathBuf,
    pub state_dir: PathBuf,
    pub auth_socket: PathBuf,
    pub upstream_socket: PathBuf,
    pub state_file: PathBuf,
    pub state_db: PathBuf,
    pub pid_file: PathBuf,
    pub log_file: PathBuf,
}

fn home_dir() -> Result<PathBuf, String> {
    env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty())
        .ok_or_else(|| "HOME is not set".to_string())
}

fn xdg_dir(var: &str, fallback: &[&str]) -> Result<PathBuf, String> {
    if let Some(value) = env::var_os(var).filter(|value| !value.is_empty()) {
        return Ok(PathBuf::from(value));
    }
    let mut path = home_dir()?;
    for part in fallback {
        path.push(part);
    }
    Ok(path)
}

pub fn config_dir() -> Result<PathBuf, String> {
    xdg_dir("XDG_CONFIG_HOME", &[".config"]).map(|path| path.join("herdr-auth-proxy"))
}

pub fn state_dir() -> Result<PathBuf, String> {
    xdg_dir("XDG_STATE_HOME", &[".local", "state"]).map(|path| path.join("herdr-auth-proxy"))
}

fn runtime_dir() -> Result<PathBuf, String> {
    if let Some(value) = env::var_os("XDG_RUNTIME_DIR").filter(|value| !value.is_empty()) {
        return Ok(PathBuf::from(value).join("herdr-auth-proxy"));
    }
    state_dir()
}

/// herdr's config dir (`$XDG_CONFIG_HOME/herdr` or `~/.config/herdr`).
pub fn herdr_dir() -> Result<PathBuf, String> {
    xdg_dir("XDG_CONFIG_HOME", &[".config"]).map(|path| path.join("herdr"))
}

/// Mirrors `src/session.rs::active_api_socket_path` in herdr.
pub fn herdr_socket() -> Result<PathBuf, String> {
    if let Some(path) = env::var_os("HERDR_SOCKET_PATH").filter(|value| !value.is_empty()) {
        return Ok(PathBuf::from(path));
    }
    if let Some(session) = env::var_os("HERDR_SESSION").filter(|value| !value.is_empty()) {
        return Ok(herdr_dir()?
            .join("sessions")
            .join(session)
            .join("herdr.sock"));
    }
    Ok(herdr_dir()?.join("herdr.sock"))
}

pub fn load() -> Result<(Config, Paths), String> {
    let config_dir = config_dir()?;
    let state_dir = state_dir()?;
    let config_path = config_dir.join("config.toml");
    let config = match fs::read_to_string(&config_path) {
        Ok(text) => toml::from_str(&text)
            .map_err(|error| format!("parse {}: {error}", config_path.display()))?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Config::default(),
        Err(error) => return Err(format!("read {}: {error}", config_path.display())),
    };
    config.validate()?;

    let runtime = runtime_dir()?;
    let auth_socket = match &config.auth_socket {
        Some(path) if path != "auto" => PathBuf::from(path),
        _ => runtime.join("auth.sock"),
    };
    let upstream_socket = match &config.upstream_socket {
        Some(path) if path != "auto" => PathBuf::from(path),
        _ => herdr_socket()?,
    };

    let paths = Paths {
        state_file: state_dir.join("state.json"),
        state_db: state_dir.join("state.db"),
        pid_file: runtime.join("proxy.pid"),
        log_file: state_dir.join("proxy.log"),
        config_dir,
        state_dir,
        auth_socket,
        upstream_socket,
    };
    Ok((config, paths))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_sane() {
        let config = Config::default();
        assert_eq!(config.agent_ttl_s, 86_400);
        assert_eq!(config.max_token_ttl_s, 86_400);
        assert_eq!(config.death_grace_s, 15);
        assert_eq!(config.message_poll_max_ms, 3_600_000);
        assert_eq!(config.message_claim_lease_s, 300);
        assert_eq!(config.message_max_bytes, 262_144);
        assert_eq!(config.sandboxed_agent_kinds, vec!["opencode"]);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn sandboxed_agent_kinds_are_validated() {
        let with = |kinds: &[&str]| Config {
            sandboxed_agent_kinds: kinds.iter().map(|kind| (*kind).to_string()).collect(),
            ..Config::default()
        };
        assert!(with(&[]).validate().is_err());
        assert!(with(&["opencode", "opencode"]).validate().is_err());
        assert!(with(&["OpenCode"]).validate().is_err());

        let config = with(&["opencode", "claude-code"]);
        assert!(config.validate().is_ok());
        assert_eq!(config.default_agent_kind(), Some("opencode"));
        assert!(config.allows_agent_kind("claude-code"));
        assert!(!config.allows_agent_kind("unknown"));
    }
}
