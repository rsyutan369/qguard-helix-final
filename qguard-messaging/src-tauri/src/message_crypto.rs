use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroize;

use crate::crypto::signatures::dual_sign;
use crate::crypto::symmetric;
use crate::crypto::{AlgorithmSuite, DualSignature, EncryptedEnvelope, HybridCiphertext};
use crate::error::Result;
use crate::pq_ratchet::{HeaderKind, RatchetHeader};
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
    /// The hybrid encapsulation the message key comes from. Present on every
    /// one-shot envelope and on a ratchet `init`; absent (`null`) on an
    /// ordinary ratchet message, whose key comes from the session.
    #[serde(default)]
    pub hybrid_ciphertext: Option<HybridCiphertext>,
    /// Empty when there is no hybrid ciphertext.
    #[serde(default)]
    pub prekey_id: String,
    #[serde(default)]
    pub prekey_kind: String,
    pub message_signature: DualSignature,
    pub sender_ed25519_public: Vec<u8>,
    pub sender_mldsa_public: Vec<u8>,
    pub suite: AlgorithmSuite,
    pub created_at: DateTime<Utc>,
    /// Session ratchet header (see `crate::pq_ratchet`). Absent on one-shot
    /// envelopes, which therefore serialise exactly as they always have.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ratchet: Option<RatchetHeader>,
}

impl EncryptedMessageEnvelope {
    /// The AAD this envelope's fields say it was sealed under.
    pub fn expected_aad(&self) -> Vec<u8> {
        match &self.ratchet {
            Some(header) => message_aad_v2(
                &self.message_id,
                &self.conversation_id,
                &self.sender_user_id,
                &self.recipient_user_id,
                &self.sender_device_id,
                &self.recipient_device_id,
                self.counter,
                header,
            ),
            None => message_aad(
                &self.message_id,
                &self.conversation_id,
                &self.sender_user_id,
                &self.recipient_user_id,
                &self.sender_device_id,
                &self.recipient_device_id,
                self.counter,
            ),
        }
    }
}

/// Who a message is from and to — the fields every seal binds into its AAD.
#[derive(Clone, Copy)]
pub struct MessageAddress<'a> {
    pub conversation_id: &'a str,
    pub sender_user_id: &'a str,
    pub recipient_user_id: &'a str,
    pub sender_device_id: &'a str,
    pub recipient_device_id: &'a str,
}

/// Seal one message under a ratchet message key.
///
/// `hybrid_ciphertext` / `prekey_*` are the session's seeding material on an
/// `init` header and absent otherwise. The header is bound twice: its digest is
/// in the AAD (so the AEAD tag covers it) and its canonical bytes are in the
/// signable (so both signatures cover it).
#[allow(clippy::too_many_arguments)]
pub fn encrypt_ratchet_message(
    address: MessageAddress<'_>,
    header: RatchetHeader,
    message_key: &[u8; 32],
    seed: Option<(HybridCiphertext, String, String)>,
    session_combiner: &str,
    kind: MessageKind,
    plaintext: &[u8],
    signing: MessageSigningContext<'_>,
) -> Result<EncryptedMessageEnvelope> {
    header.validate()?;
    if (header.kind == HeaderKind::Init) != seed.is_some() {
        return Err(crate::error::QGuardError::InvalidInput(
            "a ratchet init carries its seeding encapsulation, and only an init does".to_string(),
        ));
    }
    let message_id = Uuid::new_v4().to_string();
    let counter = u64::from(header.n);
    let aad = message_aad_v2(
        &message_id,
        address.conversation_id,
        address.sender_user_id,
        address.recipient_user_id,
        address.sender_device_id,
        address.recipient_device_id,
        counter,
        &header,
    );
    let envelope = symmetric::encrypt(message_key, plaintext, &aad)?;
    let (hybrid_ciphertext, prekey_id, prekey_kind) = match seed {
        Some((ciphertext, id, kind)) => (Some(ciphertext), id, kind),
        None => (None, String::new(), String::new()),
    };
    // The envelope suite names what this envelope actually is: a ratchet
    // envelope of a session seeded with `session_combiner`.
    let suite = AlgorithmSuite {
        kem_combiner: session_combiner.to_string(),
        ratchet: crate::pq_ratchet::RATCHET_PROTOCOL.to_string(),
        ..AlgorithmSuite::default()
    };
    let mut encrypted = EncryptedMessageEnvelope {
        message_id,
        conversation_id: address.conversation_id.to_string(),
        sender_user_id: address.sender_user_id.to_string(),
        recipient_user_id: address.recipient_user_id.to_string(),
        sender_device_id: address.sender_device_id.to_string(),
        recipient_device_id: address.recipient_device_id.to_string(),
        counter,
        kind,
        sealed_sender: false,
        envelope,
        aad,
        hybrid_ciphertext,
        prekey_id,
        prekey_kind,
        message_signature: DualSignature { ed25519: Vec::new(), ml_dsa_65: Vec::new() },
        sender_ed25519_public: signing.ed25519_public.to_vec(),
        sender_mldsa_public: signing.mldsa_public.to_vec(),
        suite,
        created_at: Utc::now(),
        ratchet: Some(header),
    };
    let signable = message_signable(&encrypted);
    encrypted.message_signature = dual_sign(signing.ed25519_secret, signing.mldsa_secret, &signable)?;
    Ok(encrypted)
}

#[allow(clippy::too_many_arguments)]
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
    encrypt_message_with_key(
        session,
        conversation_id,
        sender_user_id,
        recipient_user_id,
        sender_device_id,
        recipient_device_id,
        hybrid_ciphertext,
        prekey_id,
        prekey_kind,
        kind,
        plaintext,
        signing,
    )
    .map(|(envelope, mut message_key)| {
        message_key.zeroize();
        envelope
    })
}

/// Seal a message and also hand back the AES key it was sealed under.
///
/// The key is returned so the SENDER can record it in the message-key ledger
/// for its own archive copy (see `crate::message_keys`): its own history then
/// never depends on a prekey surviving. The caller owns the key and wipes it.
#[allow(clippy::too_many_arguments)]
pub fn encrypt_message_with_key(
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
) -> Result<(EncryptedMessageEnvelope, [u8; 32])> {
    let message_id = Uuid::new_v4().to_string();
    let message_key = session.next_send_key()?;
    // The envelope's suite describes the encapsulation it actually carries
    // (including which hybrid combiner), not this build's newest capability.
    let suite = hybrid_ciphertext.suite.clone();
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
        // Kept for wire compatibility only, and deliberately FALSE. This is not
        // a sealed-sender design: the sender's user and device ids travel in
        // the clear in this very envelope (and in its AAD), so the relay always
        // knows who is talking to whom. Claiming otherwise on the wire was
        // simply untrue; nothing reads the flag to make a decision.
        sealed_sender: false,
        envelope,
        aad,
        hybrid_ciphertext: Some(hybrid_ciphertext),
        prekey_id: prekey_id.to_string(),
        prekey_kind: prekey_kind.to_string(),
        message_signature: DualSignature {
            ed25519: Vec::new(),
            ml_dsa_65: Vec::new(),
        },
        sender_ed25519_public: signing.ed25519_public.to_vec(),
        sender_mldsa_public: signing.mldsa_public.to_vec(),
        suite,
        created_at: Utc::now(),
        ratchet: None,
    };
    let signable = message_signable(&encrypted);
    encrypted.message_signature =
        dual_sign(signing.ed25519_secret, signing.mldsa_secret, &signable)?;
    Ok((encrypted, message_key.key))
}

pub fn decrypt_message(
    session: &mut RatchetSession,
    envelope: &EncryptedMessageEnvelope,
) -> Result<Vec<u8>> {
    decrypt_message_with_key(session, envelope).map(|(plaintext, mut message_key)| {
        message_key.zeroize();
        plaintext
    })
}

/// Open a message and also hand back the AES key that opened it, so the
/// receiver can record it in the message-key ledger. The caller wipes the key.
pub fn decrypt_message_with_key(
    session: &mut RatchetSession,
    envelope: &EncryptedMessageEnvelope,
) -> Result<(Vec<u8>, [u8; 32])> {
    let key = session.receive_key(&envelope.message_id, envelope.counter)?;
    let plaintext = symmetric::decrypt(&key.key, &envelope.envelope, &envelope.aad)?;
    Ok((plaintext, key.key))
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

/// The AAD of a ratchet envelope: the v1 fields under a `QGM2` tag, plus the
/// digest of the ratchet header, so the AEAD tag covers the header too.
///
/// A v1 reader rejects it (wrong tag) and fails closed — it never sees one,
/// because ratchet envelopes only go to devices that advertised the ratchet.
#[allow(clippy::too_many_arguments)]
pub fn message_aad_v2(
    message_id: &str,
    conversation_id: &str,
    sender_user_id: &str,
    recipient_user_id: &str,
    sender_device_id: &str,
    recipient_device_id: &str,
    counter: u64,
    header: &RatchetHeader,
) -> Vec<u8> {
    format!(
        "QGM2|{message_id}|{conversation_id}|{sender_user_id}|{recipient_user_id}|{sender_device_id}|{recipient_device_id}|{counter}|{}",
        header.digest_hex()
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
    if let Some(hybrid) = &envelope.hybrid_ciphertext {
        data.extend_from_slice(&hybrid.x25519_ephemeral_public);
        data.extend_from_slice(&hybrid.ml_kem_ciphertext);
    }
    data.extend_from_slice(envelope.prekey_id.as_bytes());
    data.extend_from_slice(envelope.prekey_kind.as_bytes());
    data.extend_from_slice(&envelope.sender_ed25519_public);
    data.extend_from_slice(&envelope.sender_mldsa_public);
    // Appended only when a header is present, so every one-shot envelope
    // keeps verifying byte-for-byte against what older builds signed.
    if let Some(header) = &envelope.ratchet {
        data.extend_from_slice(b"|QGR-signable|");
        data.extend_from_slice(&header.canonical_bytes());
    }
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
        // Mirrors commands::messaging::messaging_receive_encrypted_message: the
        // per-message session opens the sender's chain, so the receiving chain
        // is re-pointed at it rather than being a second, independent chain.
        recv.receiving_chain_key = recv.sending_chain_key;
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
        recv2.receiving_chain_key = recv2.sending_chain_key;
        assert!(decrypt_message(&mut recv2, &envelope).is_err());
    }

    #[test]
    fn replay_attack_is_rejected() {
        let shared = [1u8; 32];
        let mut send = RatchetSession::new("s", shared).unwrap();
        let mut recv = RatchetSession::new("s", shared).unwrap();
        // Mirrors commands::messaging::messaging_receive_encrypted_message: the
        // per-message session opens the sender's chain, so the receiving chain
        // is re-pointed at it rather than being a second, independent chain.
        recv.receiving_chain_key = recv.sending_chain_key;
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
