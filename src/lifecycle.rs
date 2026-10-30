//! Lifecycle helpers: start detached, wrap the herdr command, stop, status.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use serde_json::Value;

use crate::config::Paths;
use crate::environ;

/// Ensure the proxy is running.
///
/// If this call starts a new proxy, returns the process-scoped bootstrap token
/// that `wrap` must place in the herdr process's `HERDR_AUTH_JWT` environment
/// variable. If the proxy was already running, returns `None`; `wrap` then
/// re-adopts the token of the running herdr server (`adopt_existing`).
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
    let token = match ensure_running(&paths)? {
        Some(bootstrap) => bootstrap,
        None => adopt_existing(&paths)?,
    };

    let mut child = Command::new(&command[0]);
    child.args(&command[1..]);
    // Always set it: an inherited token from a previous proxy generation is
    // invalid and must never leak into the herdr session.
    child.env("HERDR_AUTH_JWT", token);
    let error = child.exec();
    Err(format!("exec {}: {error}", command[0]))
}

/// The proxy is already running, so `wrap` did not receive the bootstrap token
/// over the startup pipe. Recover the token that the running herdr server
/// already carries; if there is no server, replace the proxy (nothing can be
/// using the old in-memory key) so a fresh bootstrap token can be minted.
fn adopt_existing(paths: &Paths) -> Result<String, String> {
    if let Some(token) = upstream_jwt(&paths.upstream_socket) {
        if proxy_accepts(&paths.auth_socket, &token) {
            return Ok(token);
        }
        // The proxy may have exited between the liveness check and the probe.
        if !socket_alive(&paths.auth_socket) {
            return ensure_running(paths)?
                .ok_or_else(|| "proxy is not running and handed out no bootstrap token".into());
        }
        return Err(format!(
            "the herdr server at {} carries a HERDR_AUTH_JWT that this proxy rejects; \
             restart the herdr server (`herdr server stop`) and run wrap again",
            paths.upstream_socket.display()
        ));
    }
    if socket_alive(&paths.upstream_socket) {
        return Err(format!(
            "the herdr server at {} is running without a usable HERDR_AUTH_JWT; \
             restart the herdr server (`herdr server stop`) and run wrap again",
            paths.upstream_socket.display()
        ));
    }

    // No upstream server: prefer the caller's token when it belongs to this
    // proxy (keeps re-wraps cheap), otherwise replace the proxy (safe — nothing
    // can depend on the old in-memory key) to mint a fresh bootstrap token.
    if let Some(token) = std::env::var("HERDR_AUTH_JWT")
        .ok()
        .filter(|token| proxy_accepts(&paths.auth_socket, token))
    {
        return Ok(token);
    }
    restart_proxy(paths)?;
    ensure_running(paths)?.ok_or_else(|| "proxy restarted but handed out no bootstrap token".into())
}

/// Read `HERDR_AUTH_JWT` from the environment of the process listening on the
/// herdr socket. Used to re-adopt the token of an already-running session.
fn upstream_jwt(socket: &Path) -> Option<String> {
    let stream = UnixStream::connect(socket).ok()?;
    let environ = std::fs::read(format!("/proc/{}/environ", peer_pid(&stream)?)).ok()?;
    environ::parse_jwt(&environ)
}

/// `SO_PEERCRED` pid (std's `peer_cred` is still unstable).
fn peer_pid(stream: &UnixStream) -> Option<i32> {
    use std::os::fd::AsRawFd;

    let mut cred = std::mem::MaybeUninit::<libc::ucred>::uninit();
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            cred.as_mut_ptr().cast(),
            &mut len,
        )
    };
    if result != 0 {
        return None;
    }
    Some(unsafe { cred.assume_init() }.pid)
}

/// Verify with the proxy that `token` is accepted as a non-agent token (this
/// also proves it was signed by the *running* proxy, not by a previous
/// generation). Agent tokens must never become the server's environment token.
fn proxy_accepts(socket: &Path, token: &str) -> bool {
    let Ok(mut stream) = UnixStream::connect(socket) else {
        return false;
    };
    let timeout = Some(Duration::from_secs(5));
    let _ = stream.set_read_timeout(timeout);
    let _ = stream.set_write_timeout(timeout);
    let hello = serde_json::json!({
        "id": "wrap-check",
        "method": "auth.hello",
        "params": { "jwt": token },
    });
    if writeln!(stream, "{hello}").is_err() {
        return false;
    }
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    if reader.read_line(&mut line).is_err() {
        return false;
    }
    let accepted = serde_json::from_str::<Value>(&line).ok().and_then(|value| {
        let ok = value.pointer("/result/ok").and_then(Value::as_bool)?;
        let role = value.pointer("/result/role").and_then(Value::as_str)?;
        Some(ok && role != "agent")
    }) == Some(true);
    if accepted {
        // The proxy expects exactly one request after `auth.hello`; finishing
        // the exchange keeps the probe out of the error log.
        let done =
            serde_json::json!({"id": "wrap-check-done", "method": "auth.whoami", "params": {}});
        if writeln!(reader.get_mut(), "{done}").is_ok() {
            let mut response = String::new();
            let _ = reader.read_line(&mut response);
        }
    }
    accepted
}

fn restart_proxy(paths: &Paths) -> Result<(), String> {
    stop(paths).map_err(|error| format!("cannot replace the running proxy: {error}"))?;
    for _ in 0..200 {
        if !socket_alive(&paths.auth_socket) {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Err(format!(
        "proxy at {} did not stop; stop it manually and run wrap again",
        paths.auth_socket.display()
    ))
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
    let upstream_alive = socket_alive(&paths.upstream_socket);
    let server_jwt = if upstream_jwt(&paths.upstream_socket).is_some() {
        "present"
    } else {
        "missing"
    };
    format!(
        "socket={} alive={} pid={} upstream={} upstream_alive={} server_jwt={}",
        paths.auth_socket.display(),
        alive,
        pid.as_deref().unwrap_or("-"),
        paths.upstream_socket.display(),
        upstream_alive,
        server_jwt
    )
}

fn socket_alive(path: &Path) -> bool {
    std::os::unix::net::UnixStream::connect(path).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;

    fn short_socket(tag: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        std::env::temp_dir().join(format!("hap-{tag}-{}-{nanos}.sock", std::process::id()))
    }

    #[test]
    fn peer_pid_is_the_connecting_process() {
        let (left, right) = UnixStream::pair().unwrap();
        assert_eq!(peer_pid(&left), Some(std::process::id() as i32));
        assert_eq!(peer_pid(&right), Some(std::process::id() as i32));
    }

    #[test]
    fn proxy_accepts_requires_a_non_agent_token() {
        let socket = short_socket("hello-ok");
        let listener = UnixListener::bind(&socket).unwrap();
        let responder = std::thread::spawn(move || {
            for reply in [
                r#"{"id":"wrap-check","result":{"ok":true,"role":"orchestrator"}}"#,
                r#"{"id":"wrap-check","result":{"ok":true,"role":"agent"}}"#,
                r#"{"id":"wrap-check","error":{"code":"unauthorized"}}"#,
            ] {
                let (mut stream, _) = listener.accept().unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut request = String::new();
                reader.read_line(&mut request).unwrap();
                assert!(request.contains("\"method\":\"auth.hello\""));
                writeln!(stream, "{reply}").unwrap();
                if reply.contains("orchestrator") {
                    // `proxy_accepts` follows up with auth.whoami.
                    let mut follow_up = String::new();
                    reader.read_line(&mut follow_up).unwrap();
                    assert!(follow_up.contains("\"method\":\"auth.whoami\""));
                    writeln!(stream, "{{\"id\":\"wrap-check-done\",\"result\":{{}}}}").unwrap();
                }
            }
        });

        assert!(proxy_accepts(&socket, "good"));
        assert!(!proxy_accepts(&socket, "agent"));
        assert!(!proxy_accepts(&socket, "bad"));
        responder.join().unwrap();
        std::fs::remove_file(socket).unwrap();
    }

    #[test]
    fn missing_socket_is_not_accepted() {
        assert!(!proxy_accepts(&short_socket("absent"), "token"));
    }
}
