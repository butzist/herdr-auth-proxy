//! In-memory HMAC signing key.
//!
//! The proxy generates a fresh 32-byte secret on every start and never writes
//! it to disk. Tokens are therefore valid only for the lifetime of the proxy
//! process; a restart invalidates all outstanding tokens.

use std::io::Read;

pub struct Keys {
    secret: [u8; 32],
}

impl Keys {
    /// Generate a fresh random signing key.
    pub fn generate() -> Result<Self, String> {
        let mut secret = [0u8; 32];
        std::fs::File::open("/dev/urandom")
            .and_then(|mut file| file.read_exact(&mut secret))
            .map_err(|error| format!("read /dev/urandom: {error}"))?;
        Ok(Self { secret })
    }

    pub(crate) fn secret(&self) -> &[u8; 32] {
        &self.secret
    }

    #[cfg(test)]
    pub(crate) fn from_secret(secret: [u8; 32]) -> Self {
        Self { secret }
    }
}
