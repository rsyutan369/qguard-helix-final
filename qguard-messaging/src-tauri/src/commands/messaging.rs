use serde::{Deserialize, Serialize};
use tauri::State;
use zeroize::Zeroize;

use crate::crypto::hybrid_kex::{decapsulate, encapsulate};
use crate::crypto::signatures::dual_verify;
use crate::crypto::{AlgorithmSuite, DualSignature};
use crate::error::{QGuardError, Result};
use crate::identity::{verify_identity_bundle, platform_device_label};
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
    /// The suite the recipient device published when it registered.
    ///
    /// Carried so the KEM-compatibility gate below runs in the BACKEND. The
    /// client filters unusable devices out of delivery too, but a check that
    /// lives only there is advisory -- this is the one that decides whether an
    /// envelope is produced at all.
    #[serde(default)]
    pub suite: Option<AlgorithmSuite>,
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

/// How thoroughly the sender of an inbound envelope was proven.
///
/// The distinction is the whole point. Verifying an envelope's dual signature
/// against the public keys CARRIED IN THAT ENVELOPE proves only that the
/// envelope is internally consistent -- anyone who can write to the relay can
/// mint a keypair, sign whatever they like with it, and attach the matching
/// public keys. It is `RegisteredDevice` that turns the signature into
/// authentication, by requiring those keys to be the ones the named device
/// actually published to `messaging_devices`.
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SenderVerification {
    /// The signature validates AND its keys are the sender device's registered
    /// identity keys. This is the only state that means "authenticated".
    RegisteredDevice,
    /// The signature validates against the keys inside the envelope, but no
    /// registered identity was supplied for the sender device (it was never
    /// registered, or its row is gone), so the keys are anchored to nothing.
    /// Self-consistent, NOT authenticated.
    UnverifiedDevice,
}

#[derive(Clone, Debug, Serialize)]
pub struct DecryptedMessage {
    pub message_id: String,
    pub conversation_id: String,
    pub plaintext: String,
    /// True only for `SenderVerification::RegisteredDevice`.
    pub authenticated: bool,
    pub replay_protected: bool,
    pub sender_verification: SenderVerification,
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

    let identity_bundle = state.ensure_identity(&request.sender_user_id, platform_device_label())?;
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
    verify_recipient_kem_interoperates(&request.recipient.identity)?;

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

/// The stable prefix every "this device no longer holds that key" error starts
/// with. The UI matches on it to tell a RETIRED KEY apart from a real decrypt
/// failure: the first is an expected, permanent consequence of the device
/// having re-keyed (a reinstall, a rotation past the legacy window, the FIPS
/// 203 cutover) and needs an explanation, while the second means the ciphertext
/// or the signature did not hold up and needs alarm. Rendering both as
/// "Decryption failed" made an entire history of re-keyed messages read as a
/// broken cipher. Keep this string in sync with `RETIRED_PREKEY_MARKER` in
/// src/pages/SecureChatPage.tsx.
const RETIRED_PREKEY_MARKER: &str = "sealed to a retired device key";

fn retired_prekey_error(kind: &str, prekey_id: &str) -> QGuardError {
    QGuardError::NotFound(format!(
        "{RETIRED_PREKEY_MARKER}: this device no longer holds the {kind} prekey {prekey_id} this message was encrypted to, so the message cannot be opened here."
    ))
}

/// Refuse to seal to a device whose KEM this build cannot interoperate with.
///
/// Every signature and length check above PASSES for a pre-FIPS-203 device: its
/// identity bundle is validly signed, and Kyber-1024 keys are exactly as long
/// as ML-KEM-1024 ones. Encapsulating to them succeeds, produces a
/// well-formed envelope, and yields a shared secret the recipient can never
/// reproduce -- so the message lands in their history as a permanent decrypt
/// failure while the sender is told it was delivered. Failing here instead
/// turns a silent, unrecoverable data loss into an actionable message.
fn verify_recipient_kem_interoperates(identity: &RecipientIdentityBundle) -> Result<()> {
    let interoperates = identity
        .suite
        .as_ref()
        .is_some_and(AlgorithmSuite::kem_interoperates);
    if interoperates {
        return Ok(());
    }
    Err(QGuardError::Trust(format!(
        "recipient device {} is registered with pre-FIPS-203 key material ({}) and cannot decrypt anything this build seals. That device must update to the FIPS 203 build and re-register its keys.",
        identity.device_id,
        crate::crypto::LEGACY_PQ_KEM_PRE_FIPS,
    )))
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

/// Anchor an inbound envelope's signing keys to the sender device's REGISTERED
/// identity.
///
/// ---------------------------------------------------------------------------
/// WHY A SIGNATURE CHECK ALONE IS NOT AUTHENTICATION
/// ---------------------------------------------------------------------------
/// `dual_verify` is handed `envelope.sender_ed25519_public` and
/// `envelope.sender_mldsa_public` -- both of which travel INSIDE the envelope
/// being checked. That proves self-consistency and nothing else. Anyone able to
/// place a row in `messaging_message_envelopes` (the relay itself, a
/// compromised service role, a co-member of a group conversation) could:
///   1. generate their own Ed25519 + ML-DSA-65 keypair,
///   2. encapsulate to the victim's PUBLISHED prekey bundle (public by design),
///   3. stamp any `sender_device_id` they like on the envelope,
///   4. sign it with their own key and attach their own public keys,
/// and every check in the old receive path passed. The message rendered with a
/// "Verified" badge under the impersonated sender's name. That also made
/// out-of-band safety-number verification decorative for messages: a user could
/// confirm a peer's fingerprint and still be shown forgeries signed by a key
/// that fingerprint never covered.
///
/// This closes it. The registered bundle is verified first (so a relay cannot
/// hand us a made-up row), then the envelope's signing keys must be EXACTLY the
/// registered ones. A mismatch is an active forgery signal, so it fails closed
/// rather than downgrading to "unverified" -- a downgrade would let an attacker
/// pick their own verification level.
fn verify_sender_identity(
    envelope: &EncryptedMessageEnvelope,
    sender: Option<&RecipientIdentityBundle>,
) -> Result<SenderVerification> {
    // No registry row supplied: the caller could not find the sender device.
    // The honest answer is "unanchored", never "verified".
    let Some(sender) = sender else {
        return Ok(SenderVerification::UnverifiedDevice);
    };

    if sender.user_id != envelope.sender_user_id || sender.device_id != envelope.sender_device_id {
        return Err(QGuardError::Trust(format!(
            "sender identity bundle is for device {} of user {}, but the envelope claims device {} of user {}",
            sender.device_id, sender.user_id, envelope.sender_device_id, envelope.sender_user_id,
        )));
    }

    // Proves the bundle binds these signing keys to this (user_id, device_id).
    // Without it a relay could publish a row containing the very keys it used to
    // sign the forgery.
    verify_identity_bundle(
        &sender.user_id,
        &sender.device_id,
        &sender.x25519_identity_public,
        &sender.mlkem_identity_public,
        &sender.ed25519_identity_public,
        &sender.mldsa_identity_public,
        &sender.identity_signature,
    )
    .map_err(|_| {
        QGuardError::Trust(format!(
            "registered identity for sender device {} failed its own signature check; refusing to trust it",
            sender.device_id
        ))
    })?;

    if sender.ed25519_identity_public != envelope.sender_ed25519_public
        || sender.mldsa_identity_public != envelope.sender_mldsa_public
    {
        return Err(QGuardError::Trust(format!(
            "message claims to come from device {} but is signed by a key that device never registered; refusing it",
            envelope.sender_device_id
        )));
    }

    Ok(SenderVerification::RegisteredDevice)
}

/// Recompute the AAD from the envelope's own fields and require it to equal the
/// AAD the ciphertext was actually sealed under.
///
/// `decrypt_message` passes `envelope.aad` through verbatim, so without this the
/// bytes bound into the AES-GCM tag and the fields the UI renders are two
/// independent things that merely usually agree. Pinning them together means a
/// message can never display one sender / conversation / counter while having
/// been sealed under another.
fn verify_aad_matches_envelope(envelope: &EncryptedMessageEnvelope) -> Result<()> {
    let expected = crate::message_crypto::message_aad(
        &envelope.message_id,
        &envelope.conversation_id,
        &envelope.sender_user_id,
        &envelope.recipient_user_id,
        &envelope.sender_device_id,
        &envelope.recipient_device_id,
        envelope.counter,
    );
    if expected != envelope.aad {
        return Err(QGuardError::Trust(
            "message metadata does not match the associated data it was sealed under; refusing it"
                .to_string(),
        ));
    }
    Ok(())
}

// `sender_identity` is the sender device's row from `messaging_devices`, when
// this client could find one. Optional so a missing row degrades to an honest
// "unverified" rather than an unreadable message -- but a row that IS present
// and does not match fails the whole call.
#[tauri::command]
pub async fn messaging_receive_encrypted_message(
    state: State<'_, AppState>,
    envelope: EncryptedMessageEnvelope,
    sender_identity: Option<RecipientIdentityBundle>,
) -> Result<DecryptedMessage> {
    let session_user_id = envelope.recipient_user_id.clone();
    state.require_user_auth(&session_user_id)?;
    let _key_scope = state.lock_key_scope()?;

    let identity_bundle = state.ensure_identity(&session_user_id, platform_device_label())?;
    let exact_local_device = envelope.recipient_device_id == identity_bundle.device_id;

    dual_verify(
        &envelope.sender_ed25519_public,
        &envelope.sender_mldsa_public,
        &message_signable(&envelope),
        &envelope.message_signature,
    )?;
    verify_aad_matches_envelope(&envelope)?;
    let sender_verification = verify_sender_identity(&envelope, sender_identity.as_ref())?;

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
            authenticated: sender_verification == SenderVerification::RegisteredDevice,
            replay_protected: true,
            sender_verification,
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
                .ok_or_else(|| retired_prekey_error("signed", &envelope.prekey_id))?;
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
                .ok_or_else(|| retired_prekey_error("one-time", &envelope.prekey_id))?;
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
                        authenticated: sender_verification == SenderVerification::RegisteredDevice,
                        replay_protected: true,
                        sender_verification,
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
        authenticated: sender_verification == SenderVerification::RegisteredDevice,
        replay_protected: true,
        sender_verification,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hybrid_kex::LocalKemKeypair;
    use crate::crypto::{AlgorithmSuite, HybridCiphertext};
    use crate::identity::LocalIdentity;
    use crate::message_crypto::{encrypt_message, MessageKind, MessageSigningContext};
    use crate::ratchet::RatchetSession;

    /// Build a real, correctly signed envelope from `sender` to the named peer.
    fn envelope_from(
        sender: &LocalIdentity,
        sender_user_id: &str,
        recipient_user_id: &str,
        recipient_device_id: &str,
    ) -> EncryptedMessageEnvelope {
        let mut ratchet = RatchetSession::new("t", [4u8; 32]).unwrap();
        encrypt_message(
            &mut ratchet,
            "conv-1",
            sender_user_id,
            recipient_user_id,
            &sender.device_id,
            recipient_device_id,
            HybridCiphertext {
                x25519_ephemeral_public: vec![1; 32],
                ml_kem_ciphertext: vec![2; 1568],
                suite: AlgorithmSuite::default(),
            },
            "prekey-1",
            "signed_prekey",
            MessageKind::Text,
            b"hello",
            MessageSigningContext {
                ed25519_secret: &sender.signing.ed25519_secret,
                mldsa_secret: &sender.signing.mldsa_secret,
                ed25519_public: &sender.signing.ed25519_public,
                mldsa_public: &sender.signing.mldsa_public,
            },
        )
        .unwrap()
    }

    fn registry_row(identity: &LocalIdentity) -> RecipientIdentityBundle {
        let bundle = identity.public_bundle().unwrap();
        RecipientIdentityBundle {
            user_id: bundle.user_id,
            device_id: bundle.device_id,
            x25519_identity_public: bundle.x25519_identity_public,
            mlkem_identity_public: bundle.mlkem_identity_public,
            ed25519_identity_public: bundle.ed25519_identity_public,
            mldsa_identity_public: bundle.mldsa_identity_public,
            identity_signature: bundle.signature,
            suite: Some(bundle.suite),
        }
    }

    #[test]
    fn sender_is_authenticated_only_against_its_registered_identity() {
        let sender = LocalIdentity::generate("user-a", "Desktop").unwrap();
        let envelope = envelope_from(&sender, "user-a", "user-b", "device-b");
        // The envelope's own signature verifies -- that part was never in doubt.
        dual_verify(
            &envelope.sender_ed25519_public,
            &envelope.sender_mldsa_public,
            &message_signable(&envelope),
            &envelope.message_signature,
        )
        .unwrap();
        assert_eq!(
            verify_sender_identity(&envelope, Some(&registry_row(&sender))).unwrap(),
            SenderVerification::RegisteredDevice
        );
    }

    #[test]
    fn a_forged_sender_is_refused_even_though_its_signature_verifies() {
        // The forgery: an attacker mints their own keypair, signs an envelope
        // with it, and stamps the VICTIM's device id on the result. Before the
        // registry check this decrypted and rendered as "Verified".
        let victim = LocalIdentity::generate("user-a", "Desktop").unwrap();
        let mut attacker = LocalIdentity::generate("user-a", "Desktop").unwrap();
        attacker.device_id = victim.device_id.clone();
        let forged = envelope_from(&attacker, "user-a", "user-b", "device-b");

        // Self-consistency still passes: that is exactly why it is not enough.
        dual_verify(
            &forged.sender_ed25519_public,
            &forged.sender_mldsa_public,
            &message_signable(&forged),
            &forged.message_signature,
        )
        .unwrap();

        let error = verify_sender_identity(&forged, Some(&registry_row(&victim))).unwrap_err();
        assert!(
            format!("{error:?}").contains("never registered"),
            "expected a registered-key rejection, got {error:?}"
        );
    }

    #[test]
    fn a_registry_row_that_fails_its_own_signature_is_refused() {
        let sender = LocalIdentity::generate("user-a", "Desktop").unwrap();
        let envelope = envelope_from(&sender, "user-a", "user-b", "device-b");
        let mut row = registry_row(&sender);
        // A relay swapping the KEM keys in the published row keeps the signing
        // keys (so the envelope still matches) but breaks the bundle signature.
        let swapped = LocalKemKeypair::generate();
        row.x25519_identity_public = swapped.x25519_public.clone();
        row.mlkem_identity_public = swapped.mlkem_public.clone();
        let error = verify_sender_identity(&envelope, Some(&row)).unwrap_err();
        assert!(
            format!("{error:?}").contains("failed its own signature check"),
            "expected a bundle rejection, got {error:?}"
        );
    }

    #[test]
    fn a_missing_registry_row_is_unverified_not_authenticated() {
        let sender = LocalIdentity::generate("user-a", "Desktop").unwrap();
        let envelope = envelope_from(&sender, "user-a", "user-b", "device-b");
        assert_eq!(
            verify_sender_identity(&envelope, None).unwrap(),
            SenderVerification::UnverifiedDevice
        );
    }

    #[test]
    fn a_bundle_for_a_different_device_is_refused() {
        let sender = LocalIdentity::generate("user-a", "Desktop").unwrap();
        let other = LocalIdentity::generate("user-a", "Desktop").unwrap();
        let envelope = envelope_from(&sender, "user-a", "user-b", "device-b");
        let error = verify_sender_identity(&envelope, Some(&registry_row(&other))).unwrap_err();
        assert!(
            format!("{error:?}").contains("but the envelope claims device"),
            "expected a device-mismatch rejection, got {error:?}"
        );
    }

    #[test]
    fn aad_must_match_the_envelope_it_is_attached_to() {
        let sender = LocalIdentity::generate("user-a", "Desktop").unwrap();
        let mut envelope = envelope_from(&sender, "user-a", "user-b", "device-b");
        verify_aad_matches_envelope(&envelope).unwrap();
        // Re-point the rendered sender without re-sealing: the AAD still carries
        // the original, so the two no longer agree.
        envelope.sender_user_id = "user-c".to_string();
        let error = verify_aad_matches_envelope(&envelope).unwrap_err();
        assert!(
            format!("{error:?}").contains("does not match the associated data"),
            "expected an AAD mismatch, got {error:?}"
        );
    }
}
