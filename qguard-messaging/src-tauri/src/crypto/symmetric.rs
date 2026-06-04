use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Key, Nonce,
};
use rand::RngCore;

use crate::error::{QGuardError, Result};

use super::EncryptedEnvelope;

pub const KEY_SIZE: usize = 32;
pub const NONCE_SIZE: usize = 12;
pub const TAG_SIZE: usize = 16;

pub fn random_key() -> [u8; KEY_SIZE] {
    let mut key = [0u8; KEY_SIZE];
    rand::rngs::OsRng.fill_bytes(&mut key);
    key
}

pub fn random_nonce() -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    nonce
}

pub fn encrypt(key: &[u8; KEY_SIZE], plaintext: &[u8], aad: &[u8]) -> Result<EncryptedEnvelope> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce_bytes = random_nonce();
    let ciphertext_with_tag = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|e| QGuardError::Crypto(format!("AES-256-GCM encrypt failed: {e}")))?;

    if ciphertext_with_tag.len() < TAG_SIZE {
        return Err(QGuardError::Crypto("ciphertext tag missing".to_string()));
    }

    let tag_start = ciphertext_with_tag.len() - TAG_SIZE;
    Ok(EncryptedEnvelope {
        nonce: nonce_bytes.to_vec(),
        ciphertext: ciphertext_with_tag[..tag_start].to_vec(),
        tag: ciphertext_with_tag[tag_start..].to_vec(),
    })
}

pub fn decrypt(key: &[u8; KEY_SIZE], envelope: &EncryptedEnvelope, aad: &[u8]) -> Result<Vec<u8>> {
    if envelope.nonce.len() != NONCE_SIZE || envelope.tag.len() != TAG_SIZE {
        return Err(QGuardError::Crypto("invalid AES-GCM envelope".to_string()));
    }

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let mut ciphertext_with_tag =
        Vec::with_capacity(envelope.ciphertext.len() + envelope.tag.len());
    ciphertext_with_tag.extend_from_slice(&envelope.ciphertext);
    ciphertext_with_tag.extend_from_slice(&envelope.tag);

    cipher
        .decrypt(
            Nonce::from_slice(&envelope.nonce),
            Payload {
                msg: ciphertext_with_tag.as_ref(),
                aad,
            },
        )
        .map_err(|_| QGuardError::Crypto("AEAD authentication failed".to_string()))
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
