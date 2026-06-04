use chrono::{DateTime, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroize;

use crate::crypto::hybrid_kex::{decapsulate, encapsulate, LocalKemKeypair};
use crate::crypto::kdf::sha3_hex;
use crate::crypto::signatures::{dual_sign, dual_verify, LocalSigningKeypair};
use crate::crypto::symmetric;
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

    let signable = file_signable(&metadata, &encrypted_chunks, &wrapped_keys)?;
    let metadata_signature = dual_sign(&signer.ed25519_secret, &signer.mldsa_secret, &signable)?;

    file_key.zeroize();

    Ok(EncryptedFilePackage {
        metadata,
        encrypted_chunks,
        wrapped_keys,
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

fn decrypt_file_with_wrapped_key(
    package: &EncryptedFilePackage,
    wrapped: &WrappedFileKey,
    recipient_keys: &LocalKemKeypair,
    context: &EncryptionContext,
) -> Result<Vec<u8>> {
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

    let mut plaintext = Vec::with_capacity(package.metadata.original_size as usize);
    for (index, chunk) in package.encrypted_chunks.iter().enumerate() {
        let aad = format!(
            "QGuard-file-chunk-v1:{}:{index}:{}:{}",
            package.metadata.file_id, context.owner_user_id, context.owner_device_id
        );
        let data = symmetric::decrypt(&file_key, chunk, aad.as_bytes())?;
        plaintext.extend_from_slice(&data);
    }

    file_key.zeroize();
    file_key_bytes.zeroize();
    Ok(plaintext)
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
}
