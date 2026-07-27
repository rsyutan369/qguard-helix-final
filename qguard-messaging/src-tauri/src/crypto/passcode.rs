//! Shared passcode-unlock primitives: memory-hard secret stretching (Argon2id)
//! plus HKDF-SHA3-256 verifier/wrap-key derivation. Used by both the workspace
//! lock (`commands::workspace`) and the app-entry PIN (`commands::applock`) so
//! the hardened KDF logic lives in exactly one place.

use zeroize::Zeroize;

use crate::crypto::kdf::{derive_32_with_salt, sha3_hex};
use crate::crypto::symmetric::KEY_SIZE;
use crate::error::{QGuardError, Result};

/// KDF versions for stored unlock credentials.
pub const KDF_LEGACY_HKDF: u8 = 0;
pub const KDF_ARGON2ID_V1: u8 = 1;

/// Argon2id parameters: 64 MiB, 3 passes, 1 lane (OWASP-recommended class).
const ARGON2_MEMORY_KIB: u32 = 64 * 1024;
const ARGON2_ITERATIONS: u32 = 3;
const ARGON2_LANES: u32 = 1;

pub fn random_salt() -> Vec<u8> {
    use rand::RngCore;
    let mut salt = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    salt.to_vec()
}

/// Memory-hard Argon2id prehash of the unlock secret.
pub fn argon2id_prehash(salt: &[u8], secret: &[u8]) -> Result<[u8; 32]> {
    use argon2::{Algorithm, Argon2, Params, Version};
    let params = Params::new(ARGON2_MEMORY_KIB, ARGON2_ITERATIONS, ARGON2_LANES, Some(32))
        .map_err(|e| QGuardError::Crypto(format!("argon2id params: {e}")))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    argon
        .hash_password_into(secret, salt, &mut out)
        .map_err(|e| QGuardError::Crypto(format!("argon2id stretch failed: {e}")))?;
    Ok(out)
}

/// Input keying material every HKDF subkey is derived from. Legacy (v0) feeds
/// the raw secret straight into HKDF (pre-upgrade credentials); v1 prehashes
/// with Argon2id first.
pub fn secret_ikm(kdf_version: u8, salt: &[u8], secret: &[u8]) -> Result<Vec<u8>> {
    match kdf_version {
        KDF_LEGACY_HKDF => Ok(secret.to_vec()),
        KDF_ARGON2ID_V1 => Ok(argon2id_prehash(salt, secret)?.to_vec()),
        other => Err(QGuardError::Crypto(format!(
            "unlock credential uses unsupported KDF version {other}; update QGuard Messaging"
        ))),
    }
}

/// Run the (deliberately slow, memory-hard) secret stretch on the blocking pool
/// so it never freezes the main thread.
pub async fn stretch_secret(kdf_version: u8, salt: Vec<u8>, mut secret: Vec<u8>) -> Result<Vec<u8>> {
    tauri::async_runtime::spawn_blocking(move || {
        let ikm = secret_ikm(kdf_version, &salt, &secret);
        secret.zeroize();
        ikm
    })
    .await
    .map_err(|e| QGuardError::Crypto(format!("secret stretch worker failed: {e}")))?
}

/// Verifier (hash of an independent HKDF subkey) — validates a re-entered secret
/// without revealing any unlock key. `info` is the domain-separation context.
pub fn derive_verifier(salt: &[u8], ikm: &[u8], info: &[u8]) -> Result<String> {
    let mut k = derive_32_with_salt(salt, ikm, info)?;
    let verifier = sha3_hex(&k);
    k.zeroize();
    Ok(verifier)
}

/// A 32-byte wrap key (distinct HKDF context from the verifier).
pub fn derive_wrap_key(salt: &[u8], ikm: &[u8], info: &[u8]) -> Result<[u8; KEY_SIZE]> {
    derive_32_with_salt(salt, ikm, info)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ikm_versions_are_domain_separated() {
        let salt = random_salt();
        let secret = b"correct horse battery staple";
        let legacy = secret_ikm(KDF_LEGACY_HKDF, &salt, secret).unwrap();
        assert_eq!(legacy, secret.to_vec());
        let hardened = secret_ikm(KDF_ARGON2ID_V1, &salt, secret).unwrap();
        assert_eq!(hardened, secret_ikm(KDF_ARGON2ID_V1, &salt, secret).unwrap());
        assert_ne!(hardened, legacy);
        assert!(secret_ikm(99, &salt, secret).is_err());
    }

    #[test]
    fn verifier_is_deterministic_and_context_separated() {
        let salt = random_salt();
        let ikm = secret_ikm(KDF_ARGON2ID_V1, &salt, b"pin-123456").unwrap();
        let a = derive_verifier(&salt, &ikm, b"context-a").unwrap();
        assert_eq!(a, derive_verifier(&salt, &ikm, b"context-a").unwrap());
        assert_ne!(a, derive_verifier(&salt, &ikm, b"context-b").unwrap());
    }
}
