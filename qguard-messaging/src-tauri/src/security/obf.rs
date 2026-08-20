//! Compile-time string obfuscation for sensitive identifiers and protocol
//! domain-separation tags, so they do not appear as readable literals in the
//! shipped binary (frustrates `strings`/static binary scraping).
//!
//! This is OBFUSCATION, not encryption: `deobf` reproduces the exact original
//! bytes, so every cryptographic domain-separation value is preserved
//! byte-for-byte. The round-trip tests below prove byte-exactness against the
//! known plaintext, and the existing crypto encrypt/decrypt round-trip tests
//! provide a second, independent guarantee. Plaintext appears ONLY in the
//! `#[cfg(test)]` oracle below -- never in shipped code.

const OBF_KEY: [u8; 32] = [90, 54, 193, 158, 123, 18, 228, 141, 64, 169, 63, 102, 210, 27, 247, 136, 44, 85, 144, 174, 99, 7, 188, 65, 153, 224, 20, 125, 202, 54, 82, 251];

#[inline]
fn deobf(data: &[u8]) -> Vec<u8> {
    data.iter()
        .enumerate()
        .map(|(i, b)| b ^ OBF_KEY[i % OBF_KEY.len()])
        .collect()
}

const HKDF_SALT: &[u8] = &[11, 113, 180, 255, 9, 118, 201, 192, 37, 218, 76, 7, 181, 114, 153, 239, 1, 29, 219, 234, 37, 42, 239, 9, 216, 211, 57, 79, 255, 0, 127, 141, 107];
pub fn hkdf_salt() -> Vec<u8> { deobf(HKDF_SALT) }

const RATCHET_ROOT_KEY: &[u8] = &[11, 113, 180, 255, 9, 118, 201, 192, 37, 218, 76, 7, 181, 114, 153, 239, 1, 7, 255, 193, 23, 76, 217, 56, 180, 150, 37];
pub fn ratchet_root_key() -> Vec<u8> { deobf(RATCHET_ROOT_KEY) }

const RATCHET_CHAIN: &[u8] = &[11, 113, 180, 255, 9, 118, 201, 192, 37, 218, 76, 7, 181, 114, 153, 239, 1, 22, 248, 207, 10, 105, 145, 55, 168];
pub fn ratchet_chain() -> Vec<u8> { deobf(RATCHET_CHAIN) }

const RATCHET_ROOT_ROTATION: &[u8] = &[11, 113, 180, 255, 9, 118, 201, 192, 37, 218, 76, 7, 181, 114, 153, 239, 1, 7, 255, 193, 23, 42, 238, 46, 237, 129, 96, 20, 165, 88, 127, 141, 107];
pub fn ratchet_root_rotation() -> Vec<u8> { deobf(RATCHET_ROOT_ROTATION) }

const KEY_MATERIAL_AAD: &[u8] = &[11, 113, 180, 255, 9, 118, 201, 192, 37, 218, 76, 7, 181, 114, 153, 239, 1, 17, 245, 216, 10, 100, 217, 108, 210, 133, 109, 80, 135, 87, 38, 158, 40, 95, 160, 242, 86, 100, 213];
pub fn key_material_aad() -> Vec<u8> { deobf(KEY_MATERIAL_AAD) }

const VAULT_RECOVERY_MATERIAL_AAD: &[u8] = &[11, 113, 180, 255, 9, 118, 201, 192, 37, 218, 76, 7, 181, 114, 153, 239, 1, 3, 241, 219, 15, 115, 145, 19, 252, 131, 123, 11, 175, 68, 43, 214, 23, 87, 181, 251, 9, 123, 133, 225, 109, 223, 14];
pub fn vault_recovery_material_aad() -> Vec<u8> { deobf(VAULT_RECOVERY_MATERIAL_AAD) }

const VAULT_MASTER_MATERIAL_AAD: &[u8] = &[11, 113, 180, 255, 9, 118, 201, 192, 37, 218, 76, 7, 181, 114, 153, 239, 1, 3, 241, 219, 15, 115, 145, 12, 248, 147, 96, 24, 184, 27, 31, 154, 46, 83, 179, 247, 26, 126, 201, 251, 113];
pub fn vault_master_material_aad() -> Vec<u8> { deobf(VAULT_MASTER_MATERIAL_AAD) }

const WORKSPACE_VAULT_UNLOCK_INFO: &[u8] = &[11, 113, 180, 255, 9, 118, 201, 218, 47, 219, 84, 21, 162, 122, 148, 237, 1, 3, 241, 219, 15, 115, 145, 20, 247, 140, 123, 30, 161, 27, 36, 202];
pub fn workspace_vault_unlock_info() -> Vec<u8> { deobf(WORKSPACE_VAULT_UNLOCK_INFO) }

const WORKSPACE_VAULT_WRAP_AAD: &[u8] = &[11, 113, 180, 255, 9, 118, 201, 218, 47, 219, 84, 21, 162, 122, 148, 237, 1, 3, 241, 219, 15, 115, 145, 22, 235, 129, 100, 80, 188, 7];
pub fn workspace_vault_wrap_aad() -> Vec<u8> { deobf(WORKSPACE_VAULT_WRAP_AAD) }

const WORKSPACE_CHAT_VERIFIER_INFO: &[u8] = &[11, 113, 180, 255, 9, 118, 201, 218, 47, 219, 84, 21, 162, 122, 148, 237, 1, 22, 248, 207, 23, 42, 234, 36, 235, 137, 114, 20, 175, 68, 127, 141, 107];
pub fn workspace_chat_verifier_info() -> Vec<u8> { deobf(WORKSPACE_CHAT_VERIFIER_INFO) }

const WORKSPACE_MATERIAL_AAD: &[u8] = &[11, 113, 180, 255, 9, 118, 201, 218, 47, 219, 84, 21, 162, 122, 148, 237, 1, 24, 241, 218, 6, 117, 213, 32, 245, 205, 98, 76];
pub fn workspace_material_aad() -> Vec<u8> { deobf(WORKSPACE_MATERIAL_AAD) }

const APPLOCK_VERIFIER_INFO: &[u8] = &[11, 113, 180, 255, 9, 118, 201, 204, 48, 217, 115, 9, 177, 112, 218, 222, 73, 39, 249, 200, 10, 98, 206, 108, 239, 209];
pub fn applock_verifier_info() -> Vec<u8> { deobf(APPLOCK_VERIFIER_INFO) }

const APPLOCK_SEK_WRAP_INFO: &[u8] = &[11, 113, 180, 255, 9, 118, 201, 204, 48, 217, 115, 9, 177, 112, 218, 219, 105, 30, 189, 249, 17, 102, 204, 108, 239, 209];
pub fn applock_sek_wrap_info() -> Vec<u8> { deobf(APPLOCK_SEK_WRAP_INFO) }

const APPLOCK_SESSION_WRAP_AAD: &[u8] = &[11, 113, 180, 255, 9, 118, 201, 204, 48, 217, 115, 9, 177, 112, 218, 219, 73, 38, 227, 199, 12, 105, 145, 22, 235, 129, 100, 80, 188, 7];
pub fn applock_session_wrap_aad() -> Vec<u8> { deobf(APPLOCK_SESSION_WRAP_AAD) }

const APPLOCK_MATERIAL_AAD: &[u8] = &[11, 113, 180, 255, 9, 118, 201, 204, 48, 217, 115, 9, 177, 112, 218, 197, 77, 33, 245, 220, 10, 102, 208, 108, 239, 209];
pub fn applock_material_aad() -> Vec<u8> { deobf(APPLOCK_MATERIAL_AAD) }

const LOCAL_RATCHET_INFO: &[u8] = &[11, 113, 180, 255, 9, 118, 201, 225, 47, 202, 94, 10, 255, 105, 150, 252, 79, 61, 245, 218];
pub fn local_ratchet_info() -> Vec<u8> { deobf(LOCAL_RATCHET_INFO) }

const KEYRING_SERVICE_BYTES: &[u8] = &[11, 113, 180, 255, 9, 118, 196, 192, 37, 218, 76, 7, 181, 114, 153, 239, 12, 17, 245, 216, 10, 100, 217, 97, 210, 133, 109, 14];
pub fn keyring_service_bytes() -> Vec<u8> { deobf(KEYRING_SERVICE_BYTES) }

const VAULT_STREAM_WRAP_INFO: &[u8] = &[11, 113, 180, 255, 9, 118, 201, 219, 33, 220, 83, 18, 255, 72, 131, 250, 73, 52, 253, 131, 37, 110, 208, 36, 210, 133, 109, 80, 157, 68, 51, 139, 119, 64, 240];
pub fn vault_stream_wrap_info() -> Vec<u8> { deobf(VAULT_STREAM_WRAP_INFO) }

const VAULT_STREAM_CHUNK_AAD_PREFIX: &[u8] = &[11, 113, 180, 255, 9, 118, 201, 219, 33, 220, 83, 18, 255, 72, 131, 250, 73, 52, 253, 131, 32, 111, 201, 47, 242, 205, 98, 76, 240];
pub fn vault_stream_chunk_aad_prefix() -> Vec<u8> { deobf(VAULT_STREAM_CHUNK_AAD_PREFIX) }

const VAULT_RECOVERY_WRAP_INFO: &[u8] = &[11, 113, 180, 255, 9, 118, 201, 219, 33, 220, 83, 18, 255, 73, 146, 235, 67, 35, 245, 220, 26, 42, 235, 51, 248, 144, 57, 11, 251];
pub fn vault_recovery_wrap_info() -> Vec<u8> { deobf(VAULT_RECOVERY_WRAP_INFO) }

const VAULT_RECOVERY_VERIFIER_INFO: &[u8] = &[11, 113, 180, 255, 9, 118, 201, 219, 33, 220, 83, 18, 255, 73, 146, 235, 67, 35, 245, 220, 26, 42, 234, 36, 235, 137, 114, 20, 175, 68, 127, 141, 107];
pub fn vault_recovery_verifier_info() -> Vec<u8> { deobf(VAULT_RECOVERY_VERIFIER_INFO) }

const FILE_KEY_WRAP_INFO: &[u8] = &[11, 113, 180, 255, 9, 118, 201, 192, 37, 218, 76, 7, 181, 114, 153, 239, 1, 19, 249, 194, 6, 76, 217, 56, 180, 183, 102, 28, 186, 27, 36, 202];
pub fn file_key_wrap_info() -> Vec<u8> { deobf(FILE_KEY_WRAP_INFO) }

const FILE_RECOVERY_WRAP: &[u8] = &[11, 113, 180, 255, 9, 118, 201, 255, 37, 202, 80, 16, 183, 105, 142, 165, 91, 39, 241, 222, 78, 113, 141];
pub fn file_recovery_wrap() -> Vec<u8> { deobf(FILE_RECOVERY_WRAP) }

const ENTERPRISE_WRAP_INFO: &[u8] = &[43, 81, 180, 255, 9, 118, 201, 251, 33, 220, 83, 18, 255, 105, 146, 235, 67, 35, 245, 220, 26, 42, 204, 48, 250, 205, 99, 15, 171, 70, 127, 141, 107];
pub fn enterprise_wrap_info() -> Vec<u8> { deobf(ENTERPRISE_WRAP_INFO) }

const HYBRID_WRAP_INFO: &[u8] = &[43, 81, 180, 255, 9, 118, 201, 229, 57, 203, 77, 15, 182, 54, 146, 230, 88, 48, 226, 222, 17, 110, 207, 36, 180, 146, 113, 30, 165, 64, 55, 137, 35, 27, 183, 175];
pub fn hybrid_wrap_info() -> Vec<u8> { deobf(HYBRID_WRAP_INFO) }

// --- Portable Hybrid Identity (.qgkey) ------------------------------------
// Domain separation for the passphrase-protected identity bundle, the ML-KEM
// encapsulation that seals a per-file key to a recipient identity, and the HKDF
// step that turns that shared secret into the AES-256-GCM wrapping key.

const PORTABLE_IDENTITY_BUNDLE_INFO: &[u8] = &[11,113,180,255,9,118,201,221,47,219,75,7,176,119,146,165,101,49,245,192,23,110,200,56,180,162,97,19,174,90,55,214,44,7];
pub fn portable_identity_bundle_info() -> Vec<u8> { deobf(PORTABLE_IDENTITY_BUNDLE_INFO) }

const PORTABLE_IDENTITY_KEM_INFO: &[u8] = &[11,113,180,255,9,118,201,221,47,219,75,7,176,119,146,165,101,49,245,192,23,110,200,56,180,171,81,48,231,64,99];
pub fn portable_identity_kem_info() -> Vec<u8> { deobf(PORTABLE_IDENTITY_KEM_INFO) }

const PORTABLE_IDENTITY_WRAP_INFO: &[u8] = &[11,113,180,255,9,118,201,221,47,219,75,7,176,119,146,165,101,49,245,192,23,110,200,56,180,183,102,28,186,27,36,202];
pub fn portable_identity_wrap_info() -> Vec<u8> { deobf(PORTABLE_IDENTITY_WRAP_INFO) }

/// OS keychain service identifier, reconstructed from its obfuscated form.
pub fn keyring_service() -> String {
    String::from_utf8(keyring_service_bytes())
        .expect("obfuscated keyring service identifier is valid UTF-8")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Proves every obfuscated payload de-obfuscates to its exact original
    /// bytes. If any value drifted, this fails here AND the crypto round-trip
    /// tests fail -- so domain separation can never silently change.
    #[test]
    fn obfuscated_values_round_trip_to_exact_plaintext() {
        assert_eq!(hkdf_salt(), b"QGuard-Messaging-HKDF-SHA3-256-v1".to_vec());
        assert_eq!(ratchet_root_key(), b"QGuard-Messaging-RootKey-v1".to_vec());
        assert_eq!(ratchet_chain(), b"QGuard-Messaging-Chain-v1".to_vec());
        assert_eq!(ratchet_root_rotation(), b"QGuard-Messaging-Root-Rotation-v1".to_vec());
        assert_eq!(key_material_aad(), b"QGuard-Messaging-Device-Key-Material-v1".to_vec());
        assert_eq!(vault_recovery_material_aad(), b"QGuard-Messaging-Vault-Recovery-Material-v1".to_vec());
        assert_eq!(vault_master_material_aad(), b"QGuard-Messaging-Vault-Master-Material-v1".to_vec());
        assert_eq!(workspace_vault_unlock_info(), b"QGuard-Workspace-Vault-Unlock-v1".to_vec());
        assert_eq!(workspace_vault_wrap_aad(), b"QGuard-Workspace-Vault-Wrap-v1".to_vec());
        assert_eq!(workspace_chat_verifier_info(), b"QGuard-Workspace-Chat-Verifier-v1".to_vec());
        assert_eq!(workspace_material_aad(), b"QGuard-Workspace-Material-v1".to_vec());
        assert_eq!(applock_verifier_info(), b"QGuard-AppLock-Verifier-v1".to_vec());
        assert_eq!(applock_sek_wrap_info(), b"QGuard-AppLock-SEK-Wrap-v1".to_vec());
        assert_eq!(applock_session_wrap_aad(), b"QGuard-AppLock-Session-Wrap-v1".to_vec());
        assert_eq!(applock_material_aad(), b"QGuard-AppLock-Material-v1".to_vec());
        assert_eq!(local_ratchet_info(), b"QGuard-local-ratchet".to_vec());
        assert_eq!(vault_stream_wrap_info(), b"QGuard-Vault-Stream-FileKey-Wrap-v1".to_vec());
        assert_eq!(vault_stream_chunk_aad_prefix(), b"QGuard-Vault-Stream-Chunk-v1:".to_vec());
        assert_eq!(vault_recovery_wrap_info(), b"QGuard-Vault-Recovery-Wrap-v1".to_vec());
        assert_eq!(vault_recovery_verifier_info(), b"QGuard-Vault-Recovery-Verifier-v1".to_vec());
        assert_eq!(file_key_wrap_info(), b"QGuard-Messaging-FileKey-Wrap-v1".to_vec());
        assert_eq!(file_recovery_wrap(), b"QGuard-recovery-wrap-v1".to_vec());
        assert_eq!(enterprise_wrap_info(), b"qguard-vault-recovery-pqc-wrap-v1".to_vec());
        assert_eq!(hybrid_wrap_info(), b"qguard-hybrid-enterprise-recovery-v1".to_vec());
        assert_eq!(portable_identity_bundle_info(), b"QGuard-Portable-Identity-Bundle-v1".to_vec());
        assert_eq!(portable_identity_kem_info(), b"QGuard-Portable-Identity-KEM-v1".to_vec());
        assert_eq!(portable_identity_wrap_info(), b"QGuard-Portable-Identity-Wrap-v1".to_vec());
        assert_eq!(keyring_service(), "QGuard Messaging Device Keys");
    }
}
