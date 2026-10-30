//! Working-directory claims: validation and canonicalization.
//!
//! A token's `cwd` is the only working directory its holder may create panes
//! or start agents in. Caller-supplied `cwd` parameters are never trusted.

use std::path::{Path, PathBuf};

/// Canonicalize a claimed/requested working directory.
///
/// Requires an absolute path that exists and is a directory; resolves
/// symlinks so later containment checks compare real paths.
pub fn canonical(value: &str) -> Result<String, String> {
    let path = Path::new(value);
    if !path.is_absolute() {
        return Err(format!("cwd `{value}` must be absolute"));
    }
    let canonical: PathBuf =
        std::fs::canonicalize(path).map_err(|error| format!("cwd `{value}`: {error}"))?;
    if !canonical.is_dir() {
        return Err(format!("cwd `{value}` is not a directory"));
    }
    canonical
        .into_os_string()
        .into_string()
        .map_err(|_| format!("cwd `{value}` is not valid UTF-8"))
}

/// Validate a cwd that is already stored in a token.
///
/// Token claims are canonicalized at mint time, so a different canonical
/// result means the directory was replaced (for example by a symlink) after
/// the token was issued. Fail closed instead of following it.
pub fn canonical_claim(value: &str) -> Result<String, String> {
    let canonical = canonical(value)?;
    if canonical != value {
        return Err(format!(
            "cwd `{value}` changed since the token was minted (now `{canonical}`)"
        ));
    }
    Ok(canonical)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_relative_paths() {
        assert!(canonical("relative/path").is_err());
    }

    #[test]
    fn accepts_and_canonicalizes_current_dir() {
        let current = std::env::current_dir().unwrap();
        let value = canonical(current.to_str().unwrap()).unwrap();
        assert!(Path::new(&value).is_absolute());
        assert!(Path::new(&value).is_dir());
    }

    #[test]
    fn rejects_missing_paths() {
        assert!(canonical("/definitely/not/a/real/directory").is_err());
    }

    #[test]
    fn canonical_claim_rejects_non_canonical_values() {
        let current = std::env::current_dir().unwrap();
        let value = canonical(current.to_str().unwrap()).unwrap();
        assert_eq!(canonical_claim(&value).unwrap(), value);
        assert!(canonical_claim(&format!("{value}/.")).is_err());
    }
}
