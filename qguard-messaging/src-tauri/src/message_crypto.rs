use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::crypto::signatures::dual_sign;
use crate::crypto::symmetric;
use crate::crypto::{AlgorithmSuite, DualSignature, EncryptedEnvelope, HybridCiphertext};
use crate::error::Result;
use crate::ratchet::RatchetSession;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum MessageKind {
    Text,
    FileReference,
    VoiceNote,
    System,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedMessageEnvelope {
    pub message_id: String,
    pub conversation_id: String,
    pub sender_user_id: String,
    pub recipient_user_id: String,
    pub sender_device_id: String,
    pub recipient_device_id: String,
    pub counter: u64,
    pub kind: MessageKind,
    pub sealed_sender: bool,
    pub envelope: EncryptedEnvelope,
    pub aad: Vec<u8>,
    pub hybrid_ciphertext: HybridCiphertext,
    pub prekey_id: String,
    pub prekey_kind: String,
    pub message_signature: DualSignature,
    pub sender_ed25519_public: Vec<u8>,
    pub sender_mldsa_public: Vec<u8>,
    pub suite: AlgorithmSuite,
    pub created_at: DateTime<Utc>,
}

pub fn encrypt_message(
    session: &mut RatchetSession,
    conversation_id: &str,
    sender_user_id: &str,
    recipient_user_id: &str,
    sender_device_id: &str,
    recipient_device_id: &str,
    hybrid_ciphertext: HybridCiphertext,
    prekey_id: &str,
    prekey_kind: &str,
    kind: MessageKind,
    plaintext: &[u8],
    signing: MessageSigningContext<'_>,
) -> Result<EncryptedMessageEnvelope> {
    let message_id = Uuid::new_v4().to_string();
    let message_key = session.next_send_key()?;
    let aad = message_aad(
        &message_id,
        conversation_id,
        sender_user_id,
        recipient_user_id,
        sender_device_id,
        recipient_device_id,
        message_key.counter,
    );
    let envelope = symmetric::encrypt(&message_key.key, plaintext, &aad)?;

    let mut encrypted = EncryptedMessageEnvelope {
        message_id,
        conversation_id: conversation_id.to_string(),
        sender_user_id: sender_user_id.to_string(),
        recipient_user_id: recipient_user_id.to_string(),
        sender_device_id: sender_device_id.to_string(),
        recipient_device_id: recipient_device_id.to_string(),
        counter: message_key.counter,
        kind,
        sealed_sender: true,
        envelope,
        aad,
        hybrid_ciphertext,
        prekey_id: prekey_id.to_string(),
        prekey_kind: prekey_kind.to_string(),
        message_signature: DualSignature {
            ed25519: Vec::new(),
            ml_dsa_65: Vec::new(),
        },
        sender_ed25519_public: signing.ed25519_public.to_vec(),
        sender_mldsa_public: signing.mldsa_public.to_vec(),
        suite: AlgorithmSuite::default(),
        created_at: Utc::now(),
    };
    let signable = message_signable(&encrypted);
    encrypted.message_signature =
        dual_sign(signing.ed25519_secret, signing.mldsa_secret, &signable)?;
    Ok(encrypted)
}

pub fn decrypt_message(
    session: &mut RatchetSession,
    envelope: &EncryptedMessageEnvelope,
) -> Result<Vec<u8>> {
    let key = session.receive_key(&envelope.message_id, envelope.counter)?;
    symmetric::decrypt(&key.key, &envelope.envelope, &envelope.aad)
}

pub fn message_aad(
    message_id: &str,
    conversation_id: &str,
    sender_user_id: &str,
    recipient_user_id: &str,
    sender_device_id: &str,
    recipient_device_id: &str,
    counter: u64,
) -> Vec<u8> {
    format!(
        "QGM1|{message_id}|{conversation_id}|{sender_user_id}|{recipient_user_id}|{sender_device_id}|{recipient_device_id}|{counter}"
    )
    .into_bytes()
}

#[derive(Clone, Copy)]
pub struct MessageSigningContext<'a> {
    pub ed25519_secret: &'a [u8; 32],
    pub mldsa_secret: &'a [u8],
    pub ed25519_public: &'a [u8],
    pub mldsa_public: &'a [u8],
}

pub fn message_signable(envelope: &EncryptedMessageEnvelope) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(envelope.message_id.as_bytes());
    data.extend_from_slice(envelope.conversation_id.as_bytes());
    data.extend_from_slice(envelope.sender_user_id.as_bytes());
    data.extend_from_slice(envelope.recipient_user_id.as_bytes());
    data.extend_from_slice(envelope.sender_device_id.as_bytes());
    data.extend_from_slice(envelope.recipient_device_id.as_bytes());
    data.extend_from_slice(&envelope.counter.to_be_bytes());
    data.extend_from_slice(format!("{:?}", envelope.kind).as_bytes());
    data.extend_from_slice(&envelope.envelope.nonce);
    data.extend_from_slice(&envelope.envelope.ciphertext);
    data.extend_from_slice(&envelope.envelope.tag);
    data.extend_from_slice(&envelope.aad);
    data.extend_from_slice(&envelope.hybrid_ciphertext.x25519_ephemeral_public);
    data.extend_from_slice(&envelope.hybrid_ciphertext.ml_kem_ciphertext);
    data.extend_from_slice(envelope.prekey_id.as_bytes());
    data.extend_from_slice(envelope.prekey_kind.as_bytes());
    data.extend_from_slice(&envelope.sender_ed25519_public);
    data.extend_from_slice(&envelope.sender_mldsa_public);
    data
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::signatures::LocalSigningKeypair;

    #[test]
    fn message_roundtrip_and_tamper_rejection() {
        let shared = [9u8; 32];
        let mut send = RatchetSession::new("s", shared).unwrap();
        let mut recv = RatchetSession::new("s", shared).unwrap();
        let signer = LocalSigningKeypair::generate();
        let mut envelope = encrypt_message(
            &mut send,
            "conv",
            "sender-user",
            "recipient-user",
            "sender-device",
            "recipient-device",
            HybridCiphertext {
                x25519_ephemeral_public: vec![1; 32],
                ml_kem_ciphertext: vec![2; 1088],
                suite: AlgorithmSuite::default(),
            },
            "prekey-1",
            "signed_prekey",
            MessageKind::Text,
            b"hello",
            MessageSigningContext {
                ed25519_secret: &signer.ed25519_secret,
                mldsa_secret: &signer.mldsa_secret,
                ed25519_public: &signer.ed25519_public,
                mldsa_public: &signer.mldsa_public,
            },
        )
        .unwrap();

        assert_eq!(decrypt_message(&mut recv, &envelope).unwrap(), b"hello");
        envelope.envelope.tag[0] ^= 1;
        let mut recv2 = RatchetSession::new("s", shared).unwrap();
        assert!(decrypt_message(&mut recv2, &envelope).is_err());
    }

    #[test]
    fn replay_attack_is_rejected() {
        let shared = [1u8; 32];
        let mut send = RatchetSession::new("s", shared).unwrap();
        let mut recv = RatchetSession::new("s", shared).unwrap();
        let signer = LocalSigningKeypair::generate();
        let envelope = encrypt_message(
            &mut send,
            "conv",
            "sender-user",
            "recipient-user",
            "a",
            "b",
            HybridCiphertext {
                x25519_ephemeral_public: vec![1; 32],
                ml_kem_ciphertext: vec![2; 1088],
                suite: AlgorithmSuite::default(),
            },
            "prekey-1",
            "signed_prekey",
            MessageKind::Text,
            b"hello",
            MessageSigningContext {
                ed25519_secret: &signer.ed25519_secret,
                mldsa_secret: &signer.mldsa_secret,
                ed25519_public: &signer.ed25519_public,
                mldsa_public: &signer.mldsa_public,
            },
        )
        .unwrap();
        assert!(decrypt_message(&mut recv, &envelope).is_ok());
        assert!(decrypt_message(&mut recv, &envelope).is_err());
    }
}
