//! Lifecycle helpers: start detached, wrap the herdr command, stop, status.

use std::io::{BufRead, BufReader};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use crate::config::Paths;

/// Ensure the proxy is running.
///
/// If this call starts a new proxy, returns the process-scoped bootstrap token
/// that `wrap` must place in the herdr process's `HERDR_AUTH_JWT` environment
/// variable. If the proxy was already running, returns `None`.
pub fn ensure_running(paths: &Paths) -> Result<Option<String>, String> {
    if socket_alive(&paths.auth_socket) {
        return Ok(None);
    }
    if let Some(parent) = paths.auth_socket.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("create {}: {error}", parent.display()))?;
    }
    if let Some(parent) = paths.log_file.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&paths.log_file)
        .map_err(|error| format!("open {}: {error}", paths.log_file.display()))?;
    let stderr = log
        .try_clone()
        .map_err(|error| format!("clone log: {error}"))?;

    let exe = std::env::current_exe().map_err(|error| format!("current_exe: {error}"))?;
    let mut command = Command::new(exe);
    command
        .arg("serve")
        .env("HERDR_AUTH_BOOTSTRAP_STDOUT", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::from(stderr));
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command
        .spawn()
        .map_err(|error| format!("spawn proxy: {error}"))?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "proxy has no stdout pipe".to_string())?;
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        let result = reader
            .read_line(&mut line)
            .map_err(|error| error.to_string())
            .map(|read| {
                if read == 0 {
                    String::new()
                } else {
                    line.trim().to_owned()
                }
            });
        let _ = tx.send(result);
    });
    let token = match rx.recv_timeout(Duration::from_secs(10)) {
        Ok(Ok(token)) if !token.is_empty() => token,
        Ok(Ok(_)) => {
            return Err(format!(
                "proxy did not send a bootstrap token (see {})",
                paths.log_file.display()
            ));
        }
        Ok(Err(error)) => return Err(format!("read bootstrap token: {error}")),
        Err(_) => {
            return Err(format!(
                "timed out waiting for the proxy bootstrap token (see {})",
                paths.log_file.display()
            ));
        }
    };

    for _ in 0..100 {
        if socket_alive(&paths.auth_socket) {
            return Ok(Some(token));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Err(format!(
        "proxy did not become ready at {} (see {})",
        paths.auth_socket.display(),
        paths.log_file.display()
    ))
}

pub fn wrap(command: &[String]) -> Result<(), String> {
    if command.is_empty() {
        return Err("usage: herdr-auth-proxy wrap -- <command> [args...]".into());
    }
    let (_, paths) = crate::config::load()?;
    let bootstrap = ensure_running(&paths)?;

    let mut child = Command::new(&command[0]);
    child.args(&command[1..]);
    if let Some(token) = bootstrap {
        child.env("HERDR_AUTH_JWT", token);
    }
    let error = child.exec();
    Err(format!("exec {}: {error}", command[0]))
}

pub fn stop(paths: &Paths) -> Result<(), String> {
    let pid_text = std::fs::read_to_string(&paths.pid_file)
        .map_err(|error| format!("read {}: {error}", paths.pid_file.display()))?;
    let pid: i32 = pid_text
        .trim()
        .parse()
        .map_err(|error| format!("invalid pid file: {error}"))?;
    unsafe {
        if libc::kill(pid, libc::SIGTERM) != 0 {
            return Err(format!("kill {pid}: {}", std::io::Error::last_os_error()));
        }
    }
    Ok(())
}

pub fn status(paths: &Paths) -> String {
    let pid = std::fs::read_to_string(&paths.pid_file)
        .ok()
        .map(|text| text.trim().to_string());
    let alive = socket_alive(&paths.auth_socket);
    format!(
        "socket={} alive={} pid={} upstream={}",
        paths.auth_socket.display(),
        alive,
        pid.as_deref().unwrap_or("-"),
        paths.upstream_socket.display()
    )
}

fn socket_alive(path: &Path) -> bool {
    std::os::unix::net::UnixStream::connect(path).is_ok()
}
