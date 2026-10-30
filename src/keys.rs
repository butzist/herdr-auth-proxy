//! Ed25519 keypair: generated on first run in the config dir.

use std::fs;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::{SigningKey, VerifyingKey};

use crate::config::Paths;

pub struct KeyPair {
    pub signing: SigningKey,
    pub verifying: VerifyingKey,
}

impl KeyPair {
    /// Load the existing keypair or create one (private key `0600`).
    pub fn load_or_create(paths: &Paths) -> Result<Self, String> {
        if paths.key_file.exists() {
            let seed = read_b64(&paths.key_file)?;
            let seed: [u8; 32] = seed
                .try_into()
                .map_err(|_| format!("{} is not a 32-byte key", paths.key_file.display()))?;
            let signing = SigningKey::from_bytes(&seed);
            return Ok(Self::from_signing(signing));
        }

        if let Some(parent) = paths.key_file.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| format!("create {}: {error}", parent.display()))?;
            let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
        }

        let mut seed = [0u8; 32];
        fs::File::open("/dev/urandom")
            .and_then(|mut file| file.read_exact(&mut seed))
            .map_err(|error| format!("read /dev/urandom: {error}"))?;
        let signing = SigningKey::from_bytes(&seed);
        let keypair = Self::from_signing(signing);
        write_b64(&paths.key_file, &seed, 0o600)?;
        write_b64(&paths.pub_file, keypair.verifying.as_bytes(), 0o644)?;
        Ok(keypair)
    }

    pub(crate) fn from_signing(signing: SigningKey) -> Self {
        let verifying = signing.verifying_key();
        Self { signing, verifying }
    }

    /// Base64 public key (for distribution / debugging).
    pub fn public_key_b64(&self) -> String {
        B64.encode(self.verifying.as_bytes())
    }
}

fn read_b64(path: &std::path::Path) -> Result<Vec<u8>, String> {
    let text =
        fs::read_to_string(path).map_err(|error| format!("read {}: {error}", path.display()))?;
    B64.decode(text.trim())
        .map_err(|error| format!("decode {}: {error}", path.display()))
}

fn write_b64(path: &std::path::Path, bytes: &[u8], mode: u32) -> Result<(), String> {
    let encoded = B64.encode(bytes);
    fs::write(path, format!("{encoded}\n"))
        .map_err(|error| format!("write {}: {error}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|error| format!("chmod {}: {error}", path.display()))
}
