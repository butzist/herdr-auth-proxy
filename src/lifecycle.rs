//! Lifecycle helpers: start detached, wrap the herdr command, stop, status.

use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use crate::config::Paths;

pub fn ensure_running(paths: &Paths) -> Result<(), String> {
    if socket_alive(&paths.auth_socket) {
        return Ok(());
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
        .stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(stderr));
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    command
        .spawn()
        .map_err(|error| format!("spawn proxy: {error}"))?;

    for _ in 0..100 {
        if socket_alive(&paths.auth_socket) {
            return Ok(());
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
    ensure_running(&paths)?;

    let error = Command::new(&command[0]).args(&command[1..]).exec();
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
