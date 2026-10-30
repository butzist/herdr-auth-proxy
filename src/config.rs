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
    /// How long the upstream socket may be unreachable before the proxy exits.
    pub death_grace_s: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            upstream_socket: None,
            auth_socket: None,
            agent_ttl_s: 86_400,
            death_grace_s: 15,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Paths {
    pub config_dir: PathBuf,
    pub state_dir: PathBuf,
    pub auth_socket: PathBuf,
    pub upstream_socket: PathBuf,
    pub key_file: PathBuf,
    pub pub_file: PathBuf,
    pub state_file: PathBuf,
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
        key_file: config_dir.join("keys").join("ed25519.key"),
        pub_file: config_dir.join("keys").join("ed25519.pub"),
        state_file: state_dir.join("state.json"),
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
        assert_eq!(config.death_grace_s, 15);
    }
}
