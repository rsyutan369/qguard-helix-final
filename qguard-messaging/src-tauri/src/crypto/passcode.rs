//! Shared passcode-unlock primitives: secret stretching plus HKDF-SHA3-256
//! verifier/wrap-key derivation. Used by the workspace lock
//! (`commands::workspace`), the app-entry PIN (`commands::applock`), the
//! privacy screen and the recovery PIN so the KDF logic lives in exactly one
//! place.
//!
//! Which stretch a NEW credential gets depends on the device's FIPS policy
//! (`provider::approved_mode`): Argon2id normally, PBKDF2-HMAC-SHA-512 in
//! approved mode, because Argon2id is not a FIPS-approved function. Every
//! stored credential records its `kdf_version`, so both kinds always open, and
//! the unlock paths re-seal a credential under the current preference once the
//! secret has been proven (`needs_reseal`).

use zeroize::Zeroize;

use crate::crypto::kdf::{derive_32_with_salt, sha3_hex};
use crate::crypto::provider;
use crate::crypto::symmetric::KEY_SIZE;
use crate::error::{QGuardError, Result};

/// KDF versions for stored unlock credentials.
pub const KDF_LEGACY_HKDF: u8 = 0;
pub const KDF_ARGON2ID_V1: u8 = 1;
/// PBKDF2-HMAC-SHA-512, `provider::APPROVED_PBKDF2_ITERATIONS` (SP 800-132).
pub const KDF_PBKDF2_SHA512_V2: u8 = 2;

/// Argon2id parameters: 64 MiB, 3 passes, 1 lane (OWASP-recommended class).
const ARGON2_MEMORY_KIB: u32 = 64 * 1024;
const ARGON2_ITERATIONS: u32 = 3;
const ARGON2_LANES: u32 = 1;

/// The KDF new credentials get under a given policy.
pub fn kdf_for_mode(approved: bool) -> u8 {
    if approved {
        KDF_PBKDF2_SHA512_V2
    } else {
        KDF_ARGON2ID_V1
    }
}

/// The KDF new credentials get on this device right now.
pub fn preferred_kdf() -> u8 {
    kdf_for_mode(provider::approved_mode())
}

/// True when a credential sealed with `kdf_version` should be re-sealed under
/// the current preference the next time its secret is proven.
pub fn needs_reseal(kdf_version: u8) -> bool {
    kdf_version != preferred_kdf()
}

pub fn kdf_label(kdf_version: u8) -> &'static str {
    match kdf_version {
        KDF_LEGACY_HKDF => "HKDF-SHA3-256 (legacy, unstretched)",
        KDF_ARGON2ID_V1 => "Argon2id (64 MiB, 3 passes)",
        KDF_PBKDF2_SHA512_V2 => "PBKDF2-HMAC-SHA-512 (600,000 iterations)",
        _ => "unknown",
    }
}

pub fn kdf_is_approved(kdf_version: u8) -> bool {
    kdf_version == KDF_PBKDF2_SHA512_V2
}

/// The KDF of a record stored before it recorded one (duress PIN, social
/// recovery): always Argon2id.
pub fn legacy_stored_kdf() -> u8 {
    KDF_ARGON2ID_V1
}

/// 128-bit random salt from the cryptographic module (SP 800-132 §5.1).
pub fn random_salt() -> Vec<u8> {
    provider::random_array::<16>().to_vec()
}

/// Memory-hard Argon2id prehash of the unlock secret.
pub fn argon2id_prehash(salt: &[u8], secret: &[u8]) -> Result<[u8; 32]> {
    let mut out = [0u8; 32];
    provider::argon2id(secret, salt, ARGON2_MEMORY_KIB, ARGON2_ITERATIONS, ARGON2_LANES, &mut out)?;
    Ok(out)
}

/// PBKDF2-HMAC-SHA-512 prehash of the unlock secret (approved mode).
pub fn pbkdf2_prehash(salt: &[u8], secret: &[u8]) -> Result<[u8; 32]> {
    let mut out = [0u8; 32];
    provider::pbkdf2(
        provider::APPROVED_PBKDF2_PRF,
        secret,
        salt,
        provider::APPROVED_PBKDF2_ITERATIONS,
        &mut out,
    )?;
    Ok(out)
}

/// Input keying material every HKDF subkey is derived from. Legacy (v0) feeds
/// the raw secret straight into HKDF (pre-upgrade credentials); v1 prehashes
/// with Argon2id; v2 with PBKDF2.
pub fn secret_ikm(kdf_version: u8, salt: &[u8], secret: &[u8]) -> Result<Vec<u8>> {
    match kdf_version {
        KDF_LEGACY_HKDF => Ok(secret.to_vec()),
        KDF_ARGON2ID_V1 => Ok(argon2id_prehash(salt, secret)?.to_vec()),
        KDF_PBKDF2_SHA512_V2 => Ok(pbkdf2_prehash(salt, secret)?.to_vec()),
        other => Err(QGuardError::Crypto(format!(
            "unlock credential uses unsupported KDF version {other}; update QGuard Messaging"
        ))),
    }
}

/// Run the (deliberately slow) secret stretch on the blocking pool so it never
/// freezes the main thread.
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
        let approved = secret_ikm(KDF_PBKDF2_SHA512_V2, &salt, secret).unwrap();
        assert_eq!(approved, secret_ikm(KDF_PBKDF2_SHA512_V2, &salt, secret).unwrap());
        assert_ne!(approved, hardened);
        assert_eq!(approved.len(), 32);
        assert!(secret_ikm(99, &salt, secret).is_err());
    }

    #[test]
    fn approved_mode_selects_pbkdf2_and_standard_mode_argon2id() {
        assert_eq!(kdf_for_mode(true), KDF_PBKDF2_SHA512_V2);
        assert_eq!(kdf_for_mode(false), KDF_ARGON2ID_V1);
        assert!(kdf_is_approved(KDF_PBKDF2_SHA512_V2));
        assert!(!kdf_is_approved(KDF_ARGON2ID_V1));
        assert!(!kdf_is_approved(KDF_LEGACY_HKDF));
        assert_eq!(salt_bits(), 128);
    }

    /// The approved-mode stretch is exactly PBKDF2-HMAC-SHA-512 with the
    /// published parameters: a reference computation must agree with it.
    #[test]
    fn pbkdf2_prehash_is_pbkdf2_hmac_sha512_at_600000_iterations() {
        let salt = b"0123456789abcdef";
        let mut reference = [0u8; 32];
        provider::pbkdf2(provider::Hash::Sha512, b"a fourteen+ password", salt, 600_000, &mut reference).unwrap();
        assert_eq!(pbkdf2_prehash(salt, b"a fourteen+ password").unwrap(), reference);
    }

    fn salt_bits() -> usize {
        random_salt().len() * 8
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
