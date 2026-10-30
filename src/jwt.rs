//! Minimal compact JWS (HS256 / HMAC-SHA256) implementation.

use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::keys::Keys;

pub const ISS: &str = "herdr-auth-proxy";
const HEADER: &str = r#"{"alg":"HS256","typ":"JWT"}"#;
type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Agent,
    Orchestrator,
    Admin,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Agent => "agent",
            Role::Orchestrator => "orchestrator",
            Role::Admin => "admin",
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Perm {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub agent_grants: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub agent_kinds: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mint_max_ttl_s: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub iss: String,
    pub sub: String,
    pub jti: String,
    pub iat: u64,
    pub nbf: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exp: Option<u64>,
    pub role: Role,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pane_id: Option<String>,
    /// The only working directory this token may create panes or start agents
    /// in. `None` means no directory is authorized (spawn paths fail closed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    /// The only workspace this token may create tabs/panes in. Assigned when
    /// the orchestrator token is minted; child tokens inherit it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub grants: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub perm: Option<Perm>,
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

pub fn random_id() -> String {
    let mut bytes = [0u8; 16];
    if let Ok(mut file) = std::fs::File::open("/dev/urandom") {
        use std::io::Read;
        let _ = file.read_exact(&mut bytes);
    }
    B64URL.encode(bytes)
}

pub fn mint(keys: &Keys, claims: &Claims) -> Result<String, String> {
    let header = B64URL.encode(HEADER);
    let payload = B64URL
        .encode(serde_json::to_vec(claims).map_err(|error| format!("encode claims: {error}"))?);
    let signing_input = format!("{header}.{payload}");
    let mut mac =
        HmacSha256::new_from_slice(keys.secret()).map_err(|error| format!("init hmac: {error}"))?;
    mac.update(signing_input.as_bytes());
    let signature = mac.finalize().into_bytes();
    Ok(format!(
        "{signing_input}.{}",
        B64URL.encode(signature.as_slice())
    ))
}

pub fn verify(keys: &Keys, token: &str) -> Result<Claims, String> {
    let mut parts = token.split('.');
    let (Some(header), Some(payload), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err("malformed token".into());
    };

    let header_bytes = B64URL
        .decode(header)
        .map_err(|error| format!("decode header: {error}"))?;
    let header_json: serde_json::Value =
        serde_json::from_slice(&header_bytes).map_err(|error| format!("parse header: {error}"))?;
    if header_json.get("alg").and_then(serde_json::Value::as_str) != Some("HS256") {
        return Err("unsupported alg".into());
    }

    let signature_bytes = B64URL
        .decode(signature)
        .map_err(|error| format!("decode signature: {error}"))?;
    let signing_input = format!("{header}.{payload}");
    let mut mac =
        HmacSha256::new_from_slice(keys.secret()).map_err(|error| format!("init hmac: {error}"))?;
    mac.update(signing_input.as_bytes());
    mac.verify_slice(&signature_bytes)
        .map_err(|_| "invalid signature".to_string())?;

    let payload_bytes = B64URL
        .decode(payload)
        .map_err(|error| format!("decode payload: {error}"))?;
    let claims: Claims =
        serde_json::from_slice(&payload_bytes).map_err(|error| format!("parse claims: {error}"))?;

    let now = now();
    if claims.iss != ISS {
        return Err("unexpected issuer".into());
    }
    if claims.nbf > now + 60 {
        return Err("token not yet valid".into());
    }
    if claims.exp.is_some_and(|exp| exp <= now) {
        return Err("token expired".into());
    }
    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> Keys {
        // Deterministic test key.
        Keys::from_secret([7u8; 32])
    }

    fn claims() -> Claims {
        Claims {
            iss: ISS.into(),
            sub: "test".into(),
            jti: "j1".into(),
            iat: now(),
            nbf: now(),
            exp: Some(now() + 60),
            role: Role::Agent,
            pane_id: Some("w1:p1".into()),
            cwd: Some("/work".into()),
            workspace_id: Some("w1".into()),
            grants: vec!["report_status".into()],
            perm: None,
        }
    }

    #[test]
    fn roundtrip() {
        let keys = keys();
        let token = mint(&keys, &claims()).unwrap();
        let verified = verify(&keys, &token).unwrap();
        assert_eq!(verified.sub, "test");
        assert_eq!(verified.role, Role::Agent);
        assert_eq!(verified.pane_id.as_deref(), Some("w1:p1"));
        assert_eq!(verified.cwd.as_deref(), Some("/work"));
        assert_eq!(verified.workspace_id.as_deref(), Some("w1"));
    }

    #[test]
    fn tampering_is_rejected() {
        let keys = keys();
        let token = mint(&keys, &claims()).unwrap();
        let mut tampered = token.clone();
        tampered.push('x');
        assert!(verify(&keys, &tampered).is_err());
        assert!(verify(&keys, "not.a.token").is_err());
    }

    #[test]
    fn a_different_key_is_rejected() {
        let token = mint(&keys(), &claims()).unwrap();
        let other = Keys::from_secret([8u8; 32]);
        assert!(verify(&other, &token).is_err());
    }

    #[test]
    fn expiry_is_enforced() {
        let keys = keys();
        let mut expired = claims();
        expired.exp = Some(now() - 1);
        let token = mint(&keys, &expired).unwrap();
        assert!(verify(&keys, &token).is_err());
    }
}
