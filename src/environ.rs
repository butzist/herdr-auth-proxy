//! Read `HERDR_AUTH_JWT` / `HERDR_PANE_ID` from a peer process's environment.
//!
//! Only Linux. Requires the proxy to run as the same uid as the peer (bwrap
//! keeps the herdr uid) or as root.

/// Parse a NUL-separated environ block for `key`.
pub fn parse_var(environ: &[u8], key: &str) -> Option<String> {
    let needle = format!("{key}=");
    environ.split(|byte| *byte == 0).find_map(|entry| {
        let text = std::str::from_utf8(entry).ok()?;
        text.strip_prefix(&needle)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
    })
}

pub fn parse_jwt(environ: &[u8]) -> Option<String> {
    parse_var(environ, "HERDR_AUTH_JWT")
}

pub fn parse_pane(environ: &[u8]) -> Option<String> {
    parse_var(environ, "HERDR_PANE_ID")
}

pub async fn var_from_pid(pid: i32, key: &str) -> Option<String> {
    let path = format!("/proc/{pid}/environ");
    let environ = tokio::fs::read(path).await.ok()?;
    parse_var(&environ, key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nul_separated_environ() {
        let environ = b"PATH=/bin\0HERDR_AUTH_JWT=tok\0HERDR_PANE_ID=w1:p2\0";
        assert_eq!(parse_jwt(environ).as_deref(), Some("tok"));
        assert_eq!(parse_pane(environ).as_deref(), Some("w1:p2"));
        assert_eq!(parse_var(environ, "MISSING"), None);
    }

    #[test]
    fn ignores_empty_values() {
        assert_eq!(parse_var(b"HERDR_AUTH_JWT=\0", "HERDR_AUTH_JWT"), None);
    }
}
