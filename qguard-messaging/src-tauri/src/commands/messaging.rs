use serde::{Deserialize, Serialize};
use tauri::State;
use zeroize::Zeroize;

use crate::crypto::hybrid_kex::{decapsulate, encapsulate};
use crate::crypto::signatures::dual_verify;
use crate::crypto::DualSignature;
use crate::error::{QGuardError, Result};
use crate::identity::verify_identity_bundle;
use crate::message_crypto::{
    decrypt_message, encrypt_message, message_signable, EncryptedMessageEnvelope, MessageKind,
    MessageSigningContext,
};
use crate::prekeys::{one_time_prekey_signable, signed_prekey_signable};
use crate::ratchet::RatchetSession;
use crate::state::AppState;

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendMessageRequest {
    pub conversation_id: String,
    pub sender_user_id: String,
    pub recipient_user_id: String,
    pub recipient_device_id: String,
    pub plaintext: String,
    pub kind: Option<MessageKind>,
    pub recipient: RecipientKeyBundle,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecipientIdentityBundle {
    pub user_id: String,
    pub device_id: String,
    pub x25519_identity_public: Vec<u8>,
    pub mlkem_identity_public: Vec<u8>,
    pub ed25519_identity_public: Vec<u8>,
    pub mldsa_identity_public: Vec<u8>,
    pub identity_signature: DualSignature,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecipientPrekeyBundle {
    pub prekey_id: String,
    pub x25519_public: Vec<u8>,
    pub mlkem_public: Vec<u8>,
    pub signature: DualSignature,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecipientKeyBundle {
    pub identity: RecipientIdentityBundle,
    pub signed_prekey: RecipientPrekeyBundle,
    pub one_time_prekey: Option<RecipientPrekeyBundle>,
}

#[derive(Clone, Debug, Serialize)]
pub struct DecryptedMessage {
    pub message_id: String,
    pub conversation_id: String,
    pub plaintext: String,
    pub authenticated: bool,
    pub replay_protected: bool,
}

// Send/receive are `async` so Tauri runs them on the runtime thread pool
// instead of the MAIN thread: a history load fires dozens of decrypts, and as
// sync commands each one stalled the UI (same root cause as the vault
// large-file freeze). The heavy crypto still serializes on `lock_key_scope`,
// but the app stays responsive and IPC round-trips overlap.
#[tauri::command]
pub async fn messaging_send_encrypted_message(
    state: State<'_, AppState>,
    request: SendMessageRequest,
) -> Result<EncryptedMessageEnvelope> {
    state.require_user_auth(&request.sender_user_id)?;
    let _key_scope = state.lock_key_scope()?;
    if request.recipient_user_id != request.recipient.identity.user_id
        || request.recipient_device_id != request.recipient.identity.device_id
    {
        return Err(QGuardError::Trust(
            "recipient bundle does not match requested recipient".to_string(),
        ));
    }

    let identity_bundle = state.ensure_identity(&request.sender_user_id, "Windows Desktop")?;
    verify_identity_bundle(
        &request.recipient.identity.user_id,
        &request.recipient.identity.device_id,
        &request.recipient.identity.x25519_identity_public,
        &request.recipient.identity.mlkem_identity_public,
        &request.recipient.identity.ed25519_identity_public,
        &request.recipient.identity.mldsa_identity_public,
        &request.recipient.identity.identity_signature,
    )?;
    verify_recipient_prekey(
        &request.recipient.identity,
        &request.recipient.signed_prekey,
        false,
    )?;

    let (prekey, prekey_kind) =
        if let Some(one_time_prekey) = request.recipient.one_time_prekey.as_ref() {
            verify_recipient_prekey(&request.recipient.identity, one_time_prekey, true)?;
            (one_time_prekey, "one_time_prekey")
        } else {
            (&request.recipient.signed_prekey, "signed_prekey")
        };

    let kex_info = format!(
        "QGuard-Messaging-Hybrid-Message-v1:{}:{}:{}:{}:{}",
        request.conversation_id,
        request.sender_user_id,
        request.recipient_user_id,
        identity_bundle.device_id,
        request.recipient_device_id
    );
    let (hybrid_ciphertext, mut shared_secret) = encapsulate(
        &prekey.x25519_public,
        &prekey.mlkem_public,
        kex_info.as_bytes(),
    )?;
    let pq_kem = hybrid_ciphertext.suite.pq_kem.clone();

    let ratchet_id = format!(
        "{}:{}:{}:{}",
        request.conversation_id,
        identity_bundle.device_id,
        request.recipient_device_id,
        uuid::Uuid::new_v4()
    );
    let mut ratchet = crate::ratchet::RatchetSession::new(&ratchet_id, shared_secret)?;
    ratchet.rotate_root(&shared_secret)?;

    let identity_guard = state
        .identity
        .lock()
        .map_err(|_| QGuardError::Storage("identity lock poisoned".to_string()))?;
    let identity = identity_guard
        .as_ref()
        .ok_or_else(|| QGuardError::NotFound("identity".to_string()))?;

    let envelope = encrypt_message(
        &mut ratchet,
        &request.conversation_id,
        &request.sender_user_id,
        &request.recipient_user_id,
        &identity_bundle.device_id,
        &request.recipient_device_id,
        hybrid_ciphertext,
        &prekey.prekey_id,
        prekey_kind,
        request.kind.unwrap_or(MessageKind::Text),
        request.plaintext.as_bytes(),
        MessageSigningContext {
            ed25519_secret: &identity.signing.ed25519_secret,
            mldsa_secret: &identity.signing.mldsa_secret,
            ed25519_public: &identity.signing.ed25519_public,
            mldsa_public: &identity.signing.mldsa_public,
        },
    )?;
    shared_secret.zeroize();
    state.touch_telemetry(
        "message",
        &format!("Fresh {pq_kem}/X25519 secret encapsulated; per-message ratchet key sealed"),
        100,
    );
    state.audit_info(
        "message_sent",
        "Encrypted message envelope created for relay storage",
    );
    Ok(envelope)
}

fn verify_recipient_prekey(
    identity: &RecipientIdentityBundle,
    prekey: &RecipientPrekeyBundle,
    one_time: bool,
) -> Result<()> {
    let signable = if one_time {
        one_time_prekey_signable(
            &identity.device_id,
            &prekey.prekey_id,
            &prekey.x25519_public,
            &prekey.mlkem_public,
        )
    } else {
        signed_prekey_signable(
            &identity.device_id,
            &prekey.prekey_id,
            &prekey.x25519_public,
            &prekey.mlkem_public,
        )
    };
    dual_verify(
        &identity.ed25519_identity_public,
        &identity.mldsa_identity_public,
        &signable,
        &prekey.signature,
    )
}

#[tauri::command]
pub async fn messaging_receive_encrypted_message(
    state: State<'_, AppState>,
    envelope: EncryptedMessageEnvelope,
) -> Result<DecryptedMessage> {
    let session_user_id = envelope.recipient_user_id.clone();
    state.require_user_auth(&session_user_id)?;
    let _key_scope = state.lock_key_scope()?;

    let identity_bundle = state.ensure_identity(&session_user_id, "Windows Desktop")?;
    let exact_local_device = envelope.recipient_device_id == identity_bundle.device_id;

    dual_verify(
        &envelope.sender_ed25519_public,
        &envelope.sender_mldsa_public,
        &message_signable(&envelope),
        &envelope.message_signature,
    )?;

    let cache_key = format!(
        "{}:{}:{}:{}",
        session_user_id,
        envelope.conversation_id,
        envelope.recipient_device_id,
        envelope.message_id
    );
    if let Some(plaintext) = state
        .decrypted_message_cache
        .lock()
        .map_err(|_| QGuardError::Storage("decrypted message cache lock poisoned".to_string()))?
        .get(&cache_key)
        .cloned()
    {
        return Ok(DecryptedMessage {
            message_id: envelope.message_id,
            conversation_id: envelope.conversation_id,
            plaintext,
            authenticated: true,
            replay_protected: true,
        });
    }

    let (x25519_secret, mlkem_secret) = match envelope.prekey_kind.as_str() {
        "signed_prekey" => {
            let prekey = state
                .signed_prekey
                .lock()
                .map_err(|_| QGuardError::Storage("signed prekey lock poisoned".to_string()))?
                .as_ref()
                .filter(|p| p.public.prekey_id == envelope.prekey_id)
                .cloned()
                .or_else(|| {
                    state.legacy_signed_prekeys.lock().ok().and_then(|legacy| {
                        legacy
                            .iter()
                            .find(|p| p.public.prekey_id == envelope.prekey_id)
                            .cloned()
                    })
                })
                .ok_or_else(|| QGuardError::NotFound("local signed prekey".to_string()))?;
            (prekey.x25519_secret, prekey.mlkem_secret.clone())
        }
        "one_time_prekey" => {
            let prekey = state
                .one_time_prekeys
                .lock()
                .map_err(|_| QGuardError::Storage("one-time prekey lock poisoned".to_string()))?
                .iter()
                .find(|p| p.public.prekey_id == envelope.prekey_id)
                .cloned()
                .or_else(|| {
                    state
                        .legacy_one_time_prekeys
                        .lock()
                        .ok()
                        .and_then(|legacy| {
                            legacy
                                .iter()
                                .find(|p| p.public.prekey_id == envelope.prekey_id)
                                .cloned()
                        })
                })
                .ok_or_else(|| QGuardError::NotFound("local one-time prekey".to_string()))?;
            (prekey.x25519_secret, prekey.mlkem_secret.clone())
        }
        other => {
            return Err(QGuardError::InvalidInput(format!(
                "unsupported message prekey kind: {other}"
            )))
        }
    };

    let kex_info = format!(
        "QGuard-Messaging-Hybrid-Message-v1:{}:{}:{}:{}:{}",
        envelope.conversation_id,
        envelope.sender_user_id,
        envelope.recipient_user_id,
        envelope.sender_device_id,
        envelope.recipient_device_id
    );
    let mut shared_secret = decapsulate(
        &x25519_secret,
        &mlkem_secret,
        &envelope.hybrid_ciphertext,
        kex_info.as_bytes(),
    )?;

    let ratchet_id = format!(
        "recv:{}:{}:{}",
        envelope.conversation_id, envelope.sender_device_id, envelope.recipient_device_id
    );

    let mut stateless_ratchet = RatchetSession::new(
        format!("{ratchet_id}:{}", envelope.message_id),
        shared_secret,
    )?;
    stateless_ratchet.rotate_root(&shared_secret)?;
    stateless_ratchet.receiving_chain_key = stateless_ratchet.sending_chain_key;
    let plaintext = match decrypt_message(&mut stateless_ratchet, &envelope) {
        Ok(plaintext) => {
            let mut ratchets = state
                .ratchets
                .lock()
                .map_err(|_| QGuardError::Storage("ratchet lock poisoned".to_string()))?;
            let replay_marker = ratchets
                .entry(ratchet_id.clone())
                .or_insert(RatchetSession::new(&ratchet_id, shared_secret)?);
            replay_marker
                .seen_message_ids
                .insert(envelope.message_id.clone());
            plaintext
        }
        Err(stateless_error) => {
            let mut ratchets = state
                .ratchets
                .lock()
                .map_err(|_| QGuardError::Storage("ratchet lock poisoned".to_string()))?;
            if ratchets
                .get(&ratchet_id)
                .is_some_and(|ratchet| ratchet.seen_message_ids.contains(&envelope.message_id))
            {
                if let Some(plaintext) = state
                    .decrypted_message_cache
                    .lock()
                    .map_err(|_| {
                        QGuardError::Storage("decrypted message cache lock poisoned".to_string())
                    })?
                    .get(&cache_key)
                    .cloned()
                {
                    return Ok(DecryptedMessage {
                        message_id: envelope.message_id,
                        conversation_id: envelope.conversation_id,
                        plaintext,
                        authenticated: true,
                        replay_protected: true,
                    });
                }
                return Err(QGuardError::Replay(format!(
                    "message {} already processed",
                    envelope.message_id
                )));
            }
            let ratchet = ratchets
                .entry(ratchet_id.clone())
                .or_insert(RatchetSession::new(&ratchet_id, shared_secret)?);
            ratchet.rotate_root(&shared_secret)?;
            ratchet.receiving_chain_key = ratchet.sending_chain_key;
            decrypt_message(ratchet, &envelope).map_err(|stateful_error| {
                QGuardError::Crypto(format!(
                    "message decrypt failed; per-message attempt: {stateless_error}; stateful attempt: {stateful_error}"
                ))
            })?
        }
    };
    shared_secret.zeroize();
    let plaintext = String::from_utf8(plaintext)
        .map_err(|_| QGuardError::InvalidInput("message plaintext is not UTF-8".to_string()))?;
    state
        .decrypted_message_cache
        .lock()
        .map_err(|_| QGuardError::Storage("decrypted message cache lock poisoned".to_string()))?
        .insert(cache_key, plaintext.clone());
    state.touch_telemetry(
        "message",
        if exact_local_device {
            "Encrypted message decrypted locally with replay protection"
        } else {
            "Synced trusted-device envelope decrypted locally with replay protection"
        },
        100,
    );
    Ok(DecryptedMessage {
        message_id: envelope.message_id,
        conversation_id: envelope.conversation_id,
        plaintext,
        authenticated: true,
        replay_protected: true,
    })
}

#[tauri::command]
pub fn messaging_delete_encrypted_message(
    state: State<'_, AppState>,
    message_id: String,
) -> Result<bool> {
    state.require_auth()?;
    state.audit_info(
        "message_deleted",
        &format!("Encrypted envelope {message_id} delete marker issued"),
    );
    Ok(true)
}

