use chrono::{DateTime, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroize;

use crate::crypto::hybrid_kex::{decapsulate, encapsulate, LocalKemKeypair};
use crate::crypto::kdf::sha3_hex;
use crate::crypto::signatures::{dual_sign, dual_verify, LocalSigningKeypair};
use crate::crypto::symmetric::{self, KEY_SIZE};
use crate::crypto::vault_recovery;
use crate::crypto::{AlgorithmSuite, DualSignature, EncryptedEnvelope, HybridCiphertext};
use crate::error::{QGuardError, Result};

const CHUNK_SIZE: usize = 1024 * 1024;

#[derive(Clone, Debug)]
pub struct EncryptionContext {
    pub owner_user_id: String,
    pub owner_device_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedFileMetadata {
    pub file_id: String,
    pub encrypted_name: String,
    pub original_size: u64,
    pub chunk_size: usize,
    pub content_type: String,
    pub merkle_root: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WrappedFileKey {
    pub recipient_device_id: String,
    pub hybrid_ciphertext: HybridCiphertext,
    pub wrapped_key: EncryptedEnvelope,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedFilePackage {
    pub metadata: EncryptedFileMetadata,
    pub encrypted_chunks: Vec<EncryptedEnvelope>,
    pub wrapped_keys: Vec<WrappedFileKey>,
    /// Optional quantum-safe recovery wrap of the same file key. Lets the owner
    /// decrypt on a brand-new device using only their recovery key.
    #[serde(default)]
    pub recovery_wrapped_key: Option<EncryptedEnvelope>,
    pub metadata_signature: DualSignature,
    pub signer_ed25519_public: Vec<u8>,
    pub signer_mldsa_public: Vec<u8>,
    pub suite: AlgorithmSuite,
}

pub fn encrypt_file_for_device(
    file_name: &str,
    content_type: &str,
    plaintext: &[u8],
    context: EncryptionContext,
    recipient_device_id: &str,
    recipient_kem_public: (&[u8], &[u8]),
    signer: &LocalSigningKeypair,
    recovery_wrap_key: Option<&[u8; KEY_SIZE]>,
) -> Result<EncryptedFilePackage> {
    let file_id = Uuid::new_v4().to_string();
    let mut file_key = symmetric::random_key();
    let name_aad = format!(
        "QGuard-file-name-v1:{file_id}:{}:{}",
        context.owner_user_id, context.owner_device_id
    );
    let name_env = symmetric::encrypt(&file_key, file_name.as_bytes(), name_aad.as_bytes())?;
    let encrypted_name = serde_json::to_string(&name_env)
        .map_err(|e| QGuardError::Crypto(format!("metadata encode failed: {e}")))?;

    let mut encrypted_chunks = Vec::new();
    let mut chunk_hashes = Vec::new();
    for (index, chunk) in plaintext.chunks(CHUNK_SIZE).enumerate() {
        let aad = format!(
            "QGuard-file-chunk-v1:{file_id}:{index}:{}:{}",
            context.owner_user_id, context.owner_device_id
        );
        let encrypted = symmetric::encrypt(&file_key, chunk, aad.as_bytes())?;
        chunk_hashes.extend_from_slice(&encrypted.nonce);
        chunk_hashes.extend_from_slice(sha3_hex(&encrypted.ciphertext).as_bytes());
        chunk_hashes.extend_from_slice(&encrypted.tag);
        encrypted_chunks.push(encrypted);
    }

    let metadata = EncryptedFileMetadata {
        file_id,
        encrypted_name,
        original_size: plaintext.len() as u64,
        chunk_size: CHUNK_SIZE,
        content_type: content_type.to_string(),
        merkle_root: sha3_hex(&chunk_hashes),
        created_at: Utc::now(),
    };

    let (hybrid_ciphertext, wrapping_secret) = encapsulate(
        recipient_kem_public.0,
        recipient_kem_public.1,
        b"QGuard-Messaging-FileKey-Wrap-v1",
    )?;
    let wrapped_key = symmetric::encrypt(
        &wrapping_secret,
        &file_key,
        wrapped_file_key_aad(&context, &metadata.file_id).as_bytes(),
    )?;
    let wrapped_keys = vec![WrappedFileKey {
        recipient_device_id: recipient_device_id.to_string(),
        hybrid_ciphertext,
        wrapped_key,
    }];

    // Optionally seal the same file key under the quantum-safe recovery key.
    let recovery_wrapped_key = match recovery_wrap_key {
        Some(key) => Some(vault_recovery::wrap_file_key(
            key,
            &file_key,
            &metadata.file_id,
            &context.owner_user_id,
        )?),
        None => None,
    };

    let signable = file_signable(
        &metadata,
        &encrypted_chunks,
        &wrapped_keys,
        recovery_wrapped_key.as_ref(),
    )?;
    let metadata_signature = dual_sign(&signer.ed25519_secret, &signer.mldsa_secret, &signable)?;

    file_key.zeroize();

    Ok(EncryptedFilePackage {
        metadata,
        encrypted_chunks,
        wrapped_keys,
        recovery_wrapped_key,
        metadata_signature,
        signer_ed25519_public: signer.ed25519_public.clone(),
        signer_mldsa_public: signer.mldsa_public.clone(),
        suite: AlgorithmSuite::default(),
    })
}

pub fn decrypt_file_for_device(
    package: &EncryptedFilePackage,
    recipient_device_id: &str,
    recipient_keys: &LocalKemKeypair,
    context: EncryptionContext,
) -> Result<Vec<u8>> {
    verify_file_metadata(package)?;

    if let Some(wrapped) = package
        .wrapped_keys
        .iter()
        .find(|w| w.recipient_device_id == recipient_device_id)
    {
        return decrypt_file_with_wrapped_key(package, wrapped, recipient_keys, &context);
    }

    let mut last_error: Option<QGuardError> = None;
    for wrapped in &package.wrapped_keys {
        let fallback_context = EncryptionContext {
            owner_user_id: context.owner_user_id.clone(),
            owner_device_id: wrapped.recipient_device_id.clone(),
        };
        match decrypt_file_with_wrapped_key(package, wrapped, recipient_keys, &fallback_context) {
            Ok(plaintext) => return Ok(plaintext),
            Err(error) => last_error = Some(error),
        }
    }

    let available_devices = package
        .wrapped_keys
        .iter()
        .map(|wrapped| wrapped.recipient_device_id.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    Err(QGuardError::NotFound(format!(
        "wrapped file key for current device {recipient_device_id}; available wrapped devices: {}; last local unwrap attempt: {}",
        if available_devices.is_empty() {
            "none"
        } else {
            available_devices.as_str()
        },
        last_error
            .map(|error| error.to_string())
            .unwrap_or_else(|| "not attempted".to_string())
    )))
}

pub fn decrypt_file_name_for_device(
    package: &EncryptedFilePackage,
    recipient_device_id: &str,
    recipient_keys: &LocalKemKeypair,
    context: EncryptionContext,
) -> Result<String> {
    verify_file_metadata(package)?;

    if let Some(wrapped) = package
        .wrapped_keys
        .iter()
        .find(|w| w.recipient_device_id == recipient_device_id)
    {
        return decrypt_file_name_with_wrapped_key(package, wrapped, recipient_keys, &context);
    }

    let mut last_error: Option<QGuardError> = None;
    for wrapped in &package.wrapped_keys {
        let fallback_context = EncryptionContext {
            owner_user_id: context.owner_user_id.clone(),
            owner_device_id: wrapped.recipient_device_id.clone(),
        };
        match decrypt_file_name_with_wrapped_key(
            package,
            wrapped,
            recipient_keys,
            &fallback_context,
        ) {
            Ok(file_name) => return Ok(file_name),
            Err(error) => last_error = Some(error),
        }
    }

    let available_devices = package
        .wrapped_keys
        .iter()
        .map(|wrapped| wrapped.recipient_device_id.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    Err(QGuardError::NotFound(format!(
        "wrapped file key for current device {recipient_device_id}; available wrapped devices: {}; last local filename unwrap attempt: {}",
        if available_devices.is_empty() {
            "none"
        } else {
            available_devices.as_str()
        },
        last_error
            .map(|error| error.to_string())
            .unwrap_or_else(|| "not attempted".to_string())
    )))
}

fn decrypt_file_name_with_wrapped_key(
    package: &EncryptedFilePackage,
    wrapped: &WrappedFileKey,
    recipient_keys: &LocalKemKeypair,
    context: &EncryptionContext,
) -> Result<String> {
    let wrapping_secret = decapsulate(
        &recipient_keys.x25519_secret,
        &recipient_keys.mlkem_secret,
        &wrapped.hybrid_ciphertext,
        b"QGuard-Messaging-FileKey-Wrap-v1",
    )?;
    let mut file_key_bytes = symmetric::decrypt(
        &wrapping_secret,
        &wrapped.wrapped_key,
        wrapped_file_key_aad(context, &package.metadata.file_id).as_bytes(),
    )?;
    if file_key_bytes.len() != 32 {
        return Err(QGuardError::Crypto(
            "invalid unwrapped file key".to_string(),
        ));
    }
    let mut file_key = [0u8; 32];
    file_key.copy_from_slice(&file_key_bytes);

    let encrypted_name: EncryptedEnvelope = serde_json::from_str(&package.metadata.encrypted_name)
        .map_err(|e| QGuardError::Crypto(format!("encrypted file name decode failed: {e}")))?;
    let name_aad = format!(
        "QGuard-file-name-v1:{}:{}:{}",
        package.metadata.file_id, context.owner_user_id, context.owner_device_id
    );
    let name_bytes = symmetric::decrypt(&file_key, &encrypted_name, name_aad.as_bytes())?;

    file_key.zeroize();
    file_key_bytes.zeroize();

    String::from_utf8(name_bytes)
        .map_err(|e| QGuardError::Crypto(format!("encrypted file name is not UTF-8: {e}")))
}

fn decrypt_chunks_with_file_key(
    package: &EncryptedFilePackage,
    file_key: &[u8; KEY_SIZE],
    context: &EncryptionContext,
) -> Result<Vec<u8>> {
    let mut plaintext = Vec::with_capacity(package.metadata.original_size as usize);
    for (index, chunk) in package.encrypted_chunks.iter().enumerate() {
        let aad = format!(
            "QGuard-file-chunk-v1:{}:{index}:{}:{}",
            package.metadata.file_id, context.owner_user_id, context.owner_device_id
        );
        let data = symmetric::decrypt(file_key, chunk, aad.as_bytes())?;
        plaintext.extend_from_slice(&data);
    }
    Ok(plaintext)
}

fn unwrap_file_key_with_device(
    package: &EncryptedFilePackage,
    wrapped: &WrappedFileKey,
    recipient_keys: &LocalKemKeypair,
    context: &EncryptionContext,
) -> Result<[u8; KEY_SIZE]> {
    let wrapping_secret = decapsulate(
        &recipient_keys.x25519_secret,
        &recipient_keys.mlkem_secret,
        &wrapped.hybrid_ciphertext,
        b"QGuard-Messaging-FileKey-Wrap-v1",
    )?;
    let mut file_key_bytes = symmetric::decrypt(
        &wrapping_secret,
        &wrapped.wrapped_key,
        wrapped_file_key_aad(context, &package.metadata.file_id).as_bytes(),
    )?;
    if file_key_bytes.len() != KEY_SIZE {
        file_key_bytes.zeroize();
        return Err(QGuardError::Crypto("invalid unwrapped file key".to_string()));
    }
    let mut file_key = [0u8; KEY_SIZE];
    file_key.copy_from_slice(&file_key_bytes);
    file_key_bytes.zeroize();
    Ok(file_key)
}

fn decrypt_file_with_wrapped_key(
    package: &EncryptedFilePackage,
    wrapped: &WrappedFileKey,
    recipient_keys: &LocalKemKeypair,
    context: &EncryptionContext,
) -> Result<Vec<u8>> {
    let mut file_key = unwrap_file_key_with_device(package, wrapped, recipient_keys, context)?;
    let result = decrypt_chunks_with_file_key(package, &file_key, context);
    file_key.zeroize();
    result
}

/// Decrypt an uploaded vault package using the owner's quantum-safe recovery key
/// — no access to the original device is required.
pub fn decrypt_file_with_recovery(
    package: &EncryptedFilePackage,
    owner_user_id: &str,
    recovery_wrap_key: &[u8; KEY_SIZE],
) -> Result<Vec<u8>> {
    verify_file_metadata(package)?;
    let recovery_env = package.recovery_wrapped_key.as_ref().ok_or_else(|| {
        QGuardError::NotFound(
            "this vault file was stored without a recovery key; re-protect it with recovery enabled"
                .to_string(),
        )
    })?;
    let mut file_key =
        vault_recovery::unwrap_file_key(recovery_wrap_key, recovery_env, &package.metadata.file_id, owner_user_id)?;

    // The chunk AAD is bound to the encrypting device id; try each wrapped
    // recipient device until the chunks authenticate.
    let mut candidates: Vec<&str> = package
        .wrapped_keys
        .iter()
        .map(|wrapped| wrapped.recipient_device_id.as_str())
        .collect();
    candidates.dedup();
    let mut last_error =
        QGuardError::Crypto("no candidate owner device id for recovery decrypt".to_string());
    for device_id in candidates {
        let context = EncryptionContext {
            owner_user_id: owner_user_id.to_string(),
            owner_device_id: device_id.to_string(),
        };
        match decrypt_chunks_with_file_key(package, &file_key, &context) {
            Ok(plaintext) => {
                file_key.zeroize();
                return Ok(plaintext);
            }
            Err(error) => last_error = error,
        }
    }
    file_key.zeroize();
    Err(last_error)
}

/// Add (or refresh) the recovery wrap on an existing package and re-sign it. The
/// bulk ciphertext (chunks) is unchanged. Requires a device key that can
/// currently unwrap the file key.
pub fn rewrap_package_with_recovery(
    package: &EncryptedFilePackage,
    owner_user_id: &str,
    recipient_keys: &[LocalKemKeypair],
    recovery_wrap_key: &[u8; KEY_SIZE],
    signer: &LocalSigningKeypair,
) -> Result<EncryptedFilePackage> {
    verify_file_metadata(package)?;

    // Recover the file key by trying each wrapped recipient against each device key.
    let mut file_key: Option<[u8; KEY_SIZE]> = None;
    'outer: for wrapped in &package.wrapped_keys {
        let context = EncryptionContext {
            owner_user_id: owner_user_id.to_string(),
            owner_device_id: wrapped.recipient_device_id.clone(),
        };
        for keys in recipient_keys {
            if let Ok(key) = unwrap_file_key_with_device(package, wrapped, keys, &context) {
                file_key = Some(key);
                break 'outer;
            }
        }
    }
    let mut file_key = file_key.ok_or_else(|| {
        QGuardError::NotFound(
            "this device cannot unwrap the file key, so it cannot re-protect this package".to_string(),
        )
    })?;

    let recovery_wrapped_key = Some(vault_recovery::wrap_file_key(
        recovery_wrap_key,
        &file_key,
        &package.metadata.file_id,
        owner_user_id,
    )?);
    file_key.zeroize();

    let signable = file_signable(
        &package.metadata,
        &package.encrypted_chunks,
        &package.wrapped_keys,
        recovery_wrapped_key.as_ref(),
    )?;
    let metadata_signature = dual_sign(&signer.ed25519_secret, &signer.mldsa_secret, &signable)?;

    Ok(EncryptedFilePackage {
        metadata: package.metadata.clone(),
        encrypted_chunks: package.encrypted_chunks.clone(),
        wrapped_keys: package.wrapped_keys.clone(),
        recovery_wrapped_key,
        metadata_signature,
        signer_ed25519_public: signer.ed25519_public.clone(),
        signer_mldsa_public: signer.mldsa_public.clone(),
        suite: package.suite.clone(),
    })
}

fn wrapped_file_key_aad(context: &EncryptionContext, file_id: &str) -> String {
    format!(
        "QGuard-wrapped-file-key-v1:{file_id}:{}:{}",
        context.owner_user_id, context.owner_device_id
    )
}

pub fn verify_file_metadata(package: &EncryptedFilePackage) -> Result<()> {
    let signable = file_signable(
        &package.metadata,
        &package.encrypted_chunks,
        &package.wrapped_keys,
        package.recovery_wrapped_key.as_ref(),
    )?;
    dual_verify(
        &package.signer_ed25519_public,
        &package.signer_mldsa_public,
        &signable,
        &package.metadata_signature,
    )
}

fn file_signable(
    metadata: &EncryptedFileMetadata,
    chunks: &[EncryptedEnvelope],
    wrapped_keys: &[WrappedFileKey],
    recovery_wrapped_key: Option<&EncryptedEnvelope>,
) -> Result<Vec<u8>> {
    let mut data = serde_json::to_vec(metadata)
        .map_err(|e| QGuardError::Crypto(format!("metadata encode failed: {e}")))?;
    for chunk in chunks {
        data.extend_from_slice(&chunk.nonce);
        data.extend_from_slice(&chunk.ciphertext);
        data.extend_from_slice(&chunk.tag);
    }
    for wrapped in wrapped_keys {
        data.extend_from_slice(wrapped.recipient_device_id.as_bytes());
        data.extend_from_slice(&wrapped.hybrid_ciphertext.x25519_ephemeral_public);
        data.extend_from_slice(&wrapped.hybrid_ciphertext.ml_kem_ciphertext);
        data.extend_from_slice(&wrapped.wrapped_key.nonce);
        data.extend_from_slice(&wrapped.wrapped_key.ciphertext);
        data.extend_from_slice(&wrapped.wrapped_key.tag);
    }
    // Authenticate the optional recovery wrap when present. Packages without one
    // produce the same bytes as before, so existing signatures still verify, and
    // stripping or altering a recovery wrap on a v2 package breaks the signature.
    if let Some(env) = recovery_wrapped_key {
        data.extend_from_slice(b"QGuard-recovery-wrap-v1");
        data.extend_from_slice(&env.nonce);
        data.extend_from_slice(&env.ciphertext);
        data.extend_from_slice(&env.tag);
    }
    Ok(data)
}

pub fn random_voice_note_bytes(len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_encrypts_verifies_and_rejects_tamper() {
        let recipient = LocalKemKeypair::generate();
        let signer = LocalSigningKeypair::generate();
        let package = encrypt_file_for_device(
            "secret.pdf",
            "application/pdf",
            b"file contents",
            EncryptionContext {
                owner_user_id: "user-1".to_string(),
                owner_device_id: "device-1".to_string(),
            },
            "device-1",
            (&recipient.x25519_public, &recipient.mlkem_public),
            &signer,
            None,
        )
        .unwrap();

        assert!(verify_file_metadata(&package).is_ok());
        let decrypted = decrypt_file_for_device(
            &package,
            "device-1",
            &recipient,
            EncryptionContext {
                owner_user_id: "user-1".to_string(),
                owner_device_id: "device-1".to_string(),
            },
        )
        .unwrap();
        assert_eq!(decrypted, b"file contents");
        let mut tampered = package.clone();
        tampered.encrypted_chunks[0].ciphertext[0] ^= 1;
        assert!(verify_file_metadata(&tampered).is_err());
    }

    #[test]
    fn decrypt_falls_back_to_wrapped_device_context_when_local_keys_match() {
        let recipient = LocalKemKeypair::generate();
        let signer = LocalSigningKeypair::generate();
        let package = encrypt_file_for_device(
            "secret.pdf",
            "application/pdf",
            b"file contents",
            EncryptionContext {
                owner_user_id: "user-1".to_string(),
                owner_device_id: "old-device".to_string(),
            },
            "old-device",
            (&recipient.x25519_public, &recipient.mlkem_public),
            &signer,
            None,
        )
        .unwrap();

        let decrypted = decrypt_file_for_device(
            &package,
            "new-device",
            &recipient,
            EncryptionContext {
                owner_user_id: "user-1".to_string(),
                owner_device_id: "new-device".to_string(),
            },
        )
        .unwrap();
        assert_eq!(decrypted, b"file contents");
    }

    #[test]
    fn recovery_key_decrypts_and_rewrap_adds_it() {
        let recipient = LocalKemKeypair::generate();
        let signer = LocalSigningKeypair::generate();
        let root = crate::crypto::vault_recovery::generate_recovery_root();
        let recovery_wrap_key = crate::crypto::vault_recovery::derive_wrap_key(&root).unwrap();
        let ctx = || EncryptionContext {
            owner_user_id: "user-1".to_string(),
            owner_device_id: "device-1".to_string(),
        };

        // Encrypt WITH recovery: the recovery key alone decrypts, and so does the device.
        let package = encrypt_file_for_device(
            "secret.pdf",
            "application/pdf",
            b"file contents",
            ctx(),
            "device-1",
            (&recipient.x25519_public, &recipient.mlkem_public),
            &signer,
            Some(&recovery_wrap_key),
        )
        .unwrap();
        assert!(verify_file_metadata(&package).is_ok());
        assert_eq!(decrypt_file_with_recovery(&package, "user-1", &recovery_wrap_key).unwrap(), b"file contents");
        assert_eq!(decrypt_file_for_device(&package, "device-1", &recipient, ctx()).unwrap(), b"file contents");
        let wrong = crate::crypto::vault_recovery::derive_wrap_key(&crate::crypto::vault_recovery::generate_recovery_root()).unwrap();
        assert!(decrypt_file_with_recovery(&package, "user-1", &wrong).is_err());

        // A package stored WITHOUT recovery can be re-wrapped in place to add it.
        let plain_package = encrypt_file_for_device(
            "a.bin",
            "application/octet-stream",
            b"more bytes",
            ctx(),
            "device-1",
            (&recipient.x25519_public, &recipient.mlkem_public),
            &signer,
            None,
        )
        .unwrap();
        assert!(decrypt_file_with_recovery(&plain_package, "user-1", &recovery_wrap_key).is_err());
        let rewrapped = rewrap_package_with_recovery(
            &plain_package,
            "user-1",
            std::slice::from_ref(&recipient),
            &recovery_wrap_key,
            &signer,
        )
        .unwrap();
        assert!(verify_file_metadata(&rewrapped).is_ok());
        assert_eq!(decrypt_file_with_recovery(&rewrapped, "user-1", &recovery_wrap_key).unwrap(), b"more bytes");
        assert_eq!(decrypt_file_for_device(&rewrapped, "device-1", &recipient, ctx()).unwrap(), b"more bytes");
    }
}
