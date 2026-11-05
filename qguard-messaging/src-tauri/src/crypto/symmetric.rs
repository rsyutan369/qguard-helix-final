use crate::error::{QGuardError, Result};

use super::provider;
use super::EncryptedEnvelope;

pub const KEY_SIZE: usize = 32;
pub const NONCE_SIZE: usize = provider::AES_GCM_NONCE_BYTES;
pub const TAG_SIZE: usize = provider::AES_GCM_TAG_BYTES;

pub fn random_key() -> [u8; KEY_SIZE] {
    provider::random_array()
}

/// AES-256-GCM. The nonce is chosen inside the cryptographic module.
pub fn encrypt(key: &[u8; KEY_SIZE], plaintext: &[u8], aad: &[u8]) -> Result<EncryptedEnvelope> {
    let sealed = provider::aes256gcm_seal(key, aad, plaintext)?;
    Ok(EncryptedEnvelope {
        nonce: sealed.nonce.to_vec(),
        ciphertext: sealed.ciphertext,
        tag: sealed.tag.to_vec(),
    })
}

pub fn decrypt(key: &[u8; KEY_SIZE], envelope: &EncryptedEnvelope, aad: &[u8]) -> Result<Vec<u8>> {
    if envelope.nonce.len() != NONCE_SIZE || envelope.tag.len() != TAG_SIZE {
        return Err(QGuardError::Crypto("invalid AES-GCM envelope".to_string()));
    }
    provider::aes256gcm_open(key, &envelope.nonce, aad, &envelope.ciphertext, &envelope.tag)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypts_and_rejects_tamper() {
        let key = random_key();
        let mut env = encrypt(&key, b"secret", b"aad").unwrap();
        assert_eq!(decrypt(&key, &env, b"aad").unwrap(), b"secret");
        env.ciphertext[0] ^= 1;
        assert!(decrypt(&key, &env, b"aad").is_err());
    }
}
