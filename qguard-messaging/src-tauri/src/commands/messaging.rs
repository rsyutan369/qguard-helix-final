use serde::{Deserialize, Serialize};
use tauri::State;
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::hybrid_kex::{decapsulate, encapsulate_with, KemCombiner};
use crate::crypto::signatures::dual_verify;
use crate::crypto::symmetric;
use crate::crypto::{AlgorithmSuite, DualSignature, EncryptedEnvelope, HybridCiphertext};
use crate::device_pins::{identity_digest, DeviceStanding, PinSubject};
use crate::error::{QGuardError, Result};
use crate::identity::{verify_identity_bundle, platform_device_label};
use crate::message_crypto::{
    decrypt_message_with_key, encrypt_message_with_key, message_signable,
    EncryptedMessageEnvelope, MessageKind, MessageSigningContext,
};
use crate::prekeys::{verify_prekey_signature, PrekeyKind, PrekeySignature};
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
    /// The original dual signature plus, from current builds, the
    /// domain-separated one (see `crate::prekeys`).
    pub signature: PrekeySignature,
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
    /// The signature validates and its keys match the directory row for the
    /// sender device — but that device was added to the sender's account after
    /// this device first recorded their devices, and has not been approved
    /// here (see `crate::device_pins`). The directory vouches for it; nothing
    /// else does. NOT authenticated.
    UnapprovedDevice,
}

#[derive(Clone, Debug, Serialize)]
pub struct DecryptedMessage {
    pub message_id: String,
    pub conversation_id: String,
    pub plaintext: String,
    /// True only for `SenderVerification::RegisteredDevice`.
    pub authenticated: bool,
    pub sender_verification: SenderVerification,
}

/// The fields of an envelope that are enough to re-derive its message key and
/// prove it — WITHOUT its signature block.
///
/// Used by `messaging_cache_envelope_key`, which records keys for envelopes the
/// user has not opened yet so that the prekey they were sealed to can be
/// destroyed. It needs no signature for that: the AAD check ties these fields to
/// the ciphertext, and the AES-GCM tag proves the derived key is the right one.
/// Leaving the ML-DSA signature and public key out cuts each request to a
/// fraction of the size, which matters when a whole history is being caught up.
/// Who sent the message is still verified in full when it is actually read.
#[derive(Clone, Debug, Deserialize)]
pub struct EnvelopeKeyRequest {
    pub message_id: String,
    pub conversation_id: String,
    pub sender_user_id: String,
    pub recipient_user_id: String,
    pub sender_device_id: String,
    pub recipient_device_id: String,
    pub counter: u64,
    pub envelope: EncryptedEnvelope,
    pub aad: Vec<u8>,
    pub hybrid_ciphertext: HybridCiphertext,
    pub prekey_id: String,
    pub prekey_kind: String,
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EnvelopeKeyStatus {
    /// The key was derived, proven against the ciphertext, and recorded.
    Cached,
    /// This exact envelope already had its key on record.
    AlreadyCached,
    /// The envelope can never be opened on this device (its prekey is already
    /// gone, or it does not authenticate). Nothing to wait for.
    Unreadable,
}

#[derive(Clone, Debug, Serialize)]
pub struct EnvelopeKeyOutcome {
    pub status: EnvelopeKeyStatus,
    pub reason: Option<String>,
}

/// One envelope to look up in the message-key ledger.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LedgerProbe {
    pub message_id: String,
    pub nonce: Vec<u8>,
    pub tag: Vec<u8>,
}

/// Upper bound on one ledger lookup batch.
const MAX_LEDGER_PROBES: usize = 2_000;

fn message_kex_info(
    conversation_id: &str,
    sender_user_id: &str,
    recipient_user_id: &str,
    sender_device_id: &str,
    recipient_device_id: &str,
) -> String {
    format!(
        "QGuard-Messaging-Hybrid-Message-v1:{conversation_id}:{sender_user_id}:{recipient_user_id}:{sender_device_id}:{recipient_device_id}"
    )
}

/// Everything needed to turn an envelope back into its message key, borrowed
/// from either a full envelope or a signature-less [`EnvelopeKeyRequest`].
struct KeyTransport<'a> {
    message_id: &'a str,
    conversation_id: &'a str,
    sender_user_id: &'a str,
    recipient_user_id: &'a str,
    sender_device_id: &'a str,
    recipient_device_id: &'a str,
    counter: u64,
    sealed: &'a EncryptedEnvelope,
    aad: &'a [u8],
    hybrid_ciphertext: &'a HybridCiphertext,
    prekey_id: &'a str,
    prekey_kind: &'a str,
}

impl<'a> KeyTransport<'a> {
    fn of(envelope: &'a EncryptedMessageEnvelope) -> Self {
        Self {
            message_id: &envelope.message_id,
            conversation_id: &envelope.conversation_id,
            sender_user_id: &envelope.sender_user_id,
            recipient_user_id: &envelope.recipient_user_id,
            sender_device_id: &envelope.sender_device_id,
            recipient_device_id: &envelope.recipient_device_id,
            counter: envelope.counter,
            sealed: &envelope.envelope,
            aad: &envelope.aad,
            hybrid_ciphertext: &envelope.hybrid_ciphertext,
            prekey_id: &envelope.prekey_id,
            prekey_kind: &envelope.prekey_kind,
        }
    }

    fn of_request(request: &'a EnvelopeKeyRequest) -> Self {
        Self {
            message_id: &request.message_id,
            conversation_id: &request.conversation_id,
            sender_user_id: &request.sender_user_id,
            recipient_user_id: &request.recipient_user_id,
            sender_device_id: &request.sender_device_id,
            recipient_device_id: &request.recipient_device_id,
            counter: request.counter,
            sealed: &request.envelope,
            aad: &request.aad,
            hybrid_ciphertext: &request.hybrid_ciphertext,
            prekey_id: &request.prekey_id,
            prekey_kind: &request.prekey_kind,
        }
    }

    fn kex_info(&self) -> String {
        message_kex_info(
            self.conversation_id,
            self.sender_user_id,
            self.recipient_user_id,
            self.sender_device_id,
            self.recipient_device_id,
        )
    }

    /// Recompute the AAD from the fields and require it to equal the AAD the
    /// ciphertext was actually sealed under.
    ///
    /// The AAD is passed to AES-GCM verbatim, so without this the bytes bound
    /// into the tag and the fields the UI renders are two independent things
    /// that merely usually agree. Pinning them together means a message can
    /// never display one sender / conversation / counter while having been
    /// sealed under another.
    fn verify_aad(&self) -> Result<()> {
        let expected = crate::message_crypto::message_aad(
            self.message_id,
            self.conversation_id,
            self.sender_user_id,
            self.recipient_user_id,
            self.sender_device_id,
            self.recipient_device_id,
            self.counter,
        );
        if expected != self.aad {
            return Err(QGuardError::Trust(
                "message metadata does not match the associated data it was sealed under; refusing it"
                    .to_string(),
            ));
        }
        Ok(())
    }
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
    // Everything above shows the bundle is self-consistent, which a row the
    // relay invented also is. This is the check that it is a device THIS
    // device has recorded for the recipient: nothing is sealed to one that
    // appeared later and has not been approved, or whose keys changed.
    state.require_accepted_device(
        &request.sender_user_id,
        &pin_subject_of(&request.recipient.identity),
    )?;

    let (prekey, prekey_kind) =
        if let Some(one_time_prekey) = request.recipient.one_time_prekey.as_ref() {
            verify_recipient_prekey(&request.recipient.identity, one_time_prekey, true)?;
            (one_time_prekey, "one_time_prekey")
        } else {
            (&request.recipient.signed_prekey, "signed_prekey")
        };

    let kex_info = message_kex_info(
        &request.conversation_id,
        &request.sender_user_id,
        &request.recipient_user_id,
        &identity_bundle.device_id,
        &request.recipient_device_id,
    );
    // The transcript-bound combiner is used only for a device that has
    // published that it can open it; anything older gets the combiner it
    // understands, because sealing with one it does not is a message that
    // device can never read.
    let combiner = KemCombiner::for_peer_suite(request.recipient.identity.suite.as_ref());
    let (hybrid_ciphertext, shared_secret) = encapsulate_with(
        &prekey.x25519_public,
        &prekey.mlkem_public,
        kex_info.as_bytes(),
        combiner,
    )?;
    let shared_secret = Zeroizing::new(shared_secret);
    let pq_kem = hybrid_ciphertext.suite.pq_kem.clone();

    let ratchet_id = format!(
        "{}:{}:{}:{}",
        request.conversation_id,
        identity_bundle.device_id,
        request.recipient_device_id,
        uuid::Uuid::new_v4()
    );
    let mut ratchet = crate::ratchet::RatchetSession::new(&ratchet_id, *shared_secret)?;
    ratchet.rotate_root(shared_secret.as_slice())?;

    let (envelope, message_key) = {
        let identity_guard = state
            .identity
            .lock()
            .map_err(|_| QGuardError::Storage("identity lock poisoned".to_string()))?;
        let identity = identity_guard
            .as_ref()
            .ok_or_else(|| QGuardError::NotFound("identity".to_string()))?;
        encrypt_message_with_key(
            &mut ratchet,
            &request.conversation_id,
            &request.sender_user_id,
            &request.recipient_user_id,
            &identity_bundle.device_id,
            &request.recipient_device_id,
            hybrid_ciphertext,
            &prekey.prekey_id,
            prekey_kind,
            request.kind.clone().unwrap_or(MessageKind::Text),
            request.plaintext.as_bytes(),
            MessageSigningContext {
                ed25519_secret: &identity.signing.ed25519_secret,
                mldsa_secret: &identity.signing.mldsa_secret,
                ed25519_public: &identity.signing.ed25519_public,
                mldsa_public: &identity.signing.mldsa_public,
            },
        )?
    };
    let message_key = Zeroizing::new(message_key);

    // The copy the sender seals to ITS OWN device is how it reads its own sent
    // messages back. Its key is recorded right here, so that history never
    // depends on one of this device's prekeys still existing.
    if request.recipient_user_id == request.sender_user_id
        && request.recipient_device_id == identity_bundle.device_id
    {
        state.remember_message_key(
            &request.sender_user_id,
            &envelope.message_id,
            &envelope.envelope.nonce,
            &envelope.envelope.tag,
            &message_key,
        );
    }

    state.touch_telemetry(
        "message",
        &format!("Fresh {pq_kem}/X25519 encapsulation; message key derived and sealed"),
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
/// having re-keyed (a reinstall, a rotation past the retention window, the FIPS
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
    verify_prekey_signature(
        if one_time { PrekeyKind::OneTime } else { PrekeyKind::Signed },
        &identity.user_id,
        &identity.device_id,
        &prekey.prekey_id,
        &prekey.x25519_public,
        &prekey.mlkem_public,
        &identity.ed25519_identity_public,
        &identity.mldsa_identity_public,
        &prekey.signature,
    )
    .map(|_| ())
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

/// What a device pin compares for this device (see `crate::device_pins`).
fn pin_subject_of(identity: &RecipientIdentityBundle) -> PinSubject {
    PinSubject {
        user_id: identity.user_id.clone(),
        device_id: identity.device_id.clone(),
        digest: identity_digest(
            &identity.ed25519_identity_public,
            &identity.mldsa_identity_public,
            &identity.x25519_identity_public,
            &identity.mlkem_identity_public,
        ),
    }
}

/// See [`KeyTransport::verify_aad`].
fn verify_aad_matches_envelope(envelope: &EncryptedMessageEnvelope) -> Result<()> {
    KeyTransport::of(envelope).verify_aad()
}

type PrekeySecrets = (Zeroizing<[u8; 32]>, Zeroizing<Vec<u8>>);

/// The private half of the prekey an envelope was sealed to, if this device
/// still holds it: the published one first, then the retired ones still inside
/// their retention window.
fn prekey_secrets(state: &AppState, prekey_kind: &str, prekey_id: &str) -> Result<PrekeySecrets> {
    match prekey_kind {
        "signed_prekey" => {
            let current = state
                .signed_prekey
                .lock()
                .map_err(|_| QGuardError::Storage("signed prekey lock poisoned".to_string()))?
                .as_ref()
                .filter(|prekey| prekey.public.prekey_id == prekey_id)
                .map(|prekey| {
                    (
                        Zeroizing::new(prekey.x25519_secret),
                        Zeroizing::new(prekey.mlkem_secret.clone()),
                    )
                });
            if let Some(found) = current {
                return Ok(found);
            }
            state
                .legacy_signed_prekeys
                .lock()
                .map_err(|_| QGuardError::Storage("legacy signed prekey lock poisoned".to_string()))?
                .iter()
                .find(|prekey| prekey.public.prekey_id == prekey_id)
                .map(|prekey| {
                    (
                        Zeroizing::new(prekey.x25519_secret),
                        Zeroizing::new(prekey.mlkem_secret.clone()),
                    )
                })
                .ok_or_else(|| retired_prekey_error("signed", prekey_id))
        }
        "one_time_prekey" => {
            let current = state
                .one_time_prekeys
                .lock()
                .map_err(|_| QGuardError::Storage("one-time prekey lock poisoned".to_string()))?
                .iter()
                .find(|prekey| prekey.public.prekey_id == prekey_id)
                .map(|prekey| {
                    (
                        Zeroizing::new(prekey.x25519_secret),
                        Zeroizing::new(prekey.mlkem_secret.clone()),
                    )
                });
            if let Some(found) = current {
                return Ok(found);
            }
            state
                .legacy_one_time_prekeys
                .lock()
                .map_err(|_| {
                    QGuardError::Storage("legacy one-time prekey lock poisoned".to_string())
                })?
                .iter()
                .find(|prekey| prekey.public.prekey_id == prekey_id)
                .map(|prekey| {
                    (
                        Zeroizing::new(prekey.x25519_secret),
                        Zeroizing::new(prekey.mlkem_secret.clone()),
                    )
                })
                .ok_or_else(|| retired_prekey_error("one-time", prekey_id))
        }
        other => Err(QGuardError::InvalidInput(format!(
            "unsupported message prekey kind: {other}"
        ))),
    }
}

/// Decapsulate an envelope's hybrid ciphertext with the prekey it names.
fn decapsulate_for(state: &AppState, transport: &KeyTransport) -> Result<Zeroizing<[u8; 32]>> {
    let (x25519_secret, mlkem_secret) =
        prekey_secrets(state, transport.prekey_kind, transport.prekey_id)?;
    Ok(Zeroizing::new(decapsulate(
        &x25519_secret,
        &mlkem_secret,
        transport.hybrid_ciphertext,
        transport.kex_info().as_bytes(),
    )?))
}

/// The AES key a per-message session derives for this envelope: exactly the
/// derivation `messaging_send_encrypted_message` performs on the other side.
fn per_message_key(
    shared_secret: &[u8; 32],
    transport: &KeyTransport,
) -> Result<Zeroizing<[u8; 32]>> {
    let mut session = RatchetSession::new(
        format!(
            "recv:{}:{}:{}:{}",
            transport.conversation_id,
            transport.sender_device_id,
            transport.recipient_device_id,
            transport.message_id
        ),
        *shared_secret,
    )?;
    session.rotate_root(shared_secret)?;
    // The per-message session opens the sender's chain, so the receiving chain
    // is re-pointed at it rather than being a second, independent chain.
    session.receiving_chain_key = session.sending_chain_key;
    let key = session.receive_key(transport.message_id, transport.counter)?;
    Ok(Zeroizing::new(key.key))
}

/// Open an envelope with the prekey it was sealed to, returning the plaintext
/// and the message key that opened it.
///
/// Tries the per-message derivation every current build uses, then the
/// in-session derivation an older build may have used.
fn open_with_prekey(
    state: &AppState,
    envelope: &EncryptedMessageEnvelope,
    transport: &KeyTransport,
) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>)> {
    let shared_secret = decapsulate_for(state, transport)?;
    let ratchet_id = format!(
        "recv:{}:{}:{}",
        envelope.conversation_id, envelope.sender_device_id, envelope.recipient_device_id
    );

    let per_message = per_message_key(&shared_secret, transport).and_then(|key| {
        symmetric::decrypt(&key, transport.sealed, transport.aad).map(|plaintext| (plaintext, key))
    });

    let mut ratchets = state
        .ratchets
        .lock()
        .map_err(|_| QGuardError::Storage("ratchet lock poisoned".to_string()))?;
    match per_message {
        Ok(opened) => {
            ratchets
                .entry(ratchet_id.clone())
                .or_insert(RatchetSession::new(&ratchet_id, *shared_secret)?)
                .seen_message_ids
                .insert(envelope.message_id.clone());
            Ok(opened)
        }
        Err(per_message_error) => {
            if ratchets
                .get(&ratchet_id)
                .is_some_and(|ratchet| ratchet.seen_message_ids.contains(&envelope.message_id))
            {
                return Err(QGuardError::Replay(format!(
                    "message {} already processed",
                    envelope.message_id
                )));
            }
            let ratchet = ratchets
                .entry(ratchet_id.clone())
                .or_insert(RatchetSession::new(&ratchet_id, *shared_secret)?);
            ratchet.rotate_root(shared_secret.as_slice())?;
            ratchet.receiving_chain_key = ratchet.sending_chain_key;
            decrypt_message_with_key(ratchet, envelope)
                .map(|(plaintext, key)| (plaintext, Zeroizing::new(key)))
                .map_err(|stateful_error| {
                    QGuardError::Crypto(format!(
                        "message decrypt failed; per-message attempt: {per_message_error}; stateful attempt: {stateful_error}"
                    ))
                })
        }
    }
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

    // Authenticity first, on EVERY path — including the ledger one below. A
    // cached key says the ciphertext can be opened; it says nothing about who
    // sent it.
    dual_verify(
        &envelope.sender_ed25519_public,
        &envelope.sender_mldsa_public,
        &message_signable(&envelope),
        &envelope.message_signature,
    )?;
    verify_aad_matches_envelope(&envelope)?;
    let sender_verification = verify_sender_identity(&envelope, sender_identity.as_ref())?;
    // "Registered" means the keys match the directory's row. A device the
    // directory added later is only as trustworthy as the directory, so until
    // it is approved here its messages are shown as unverified; a device id
    // whose keys CHANGED is refused outright.
    let sender_verification = match (sender_verification, sender_identity.as_ref()) {
        (SenderVerification::RegisteredDevice, Some(sender)) => {
            match state.device_standing(&session_user_id, &pin_subject_of(sender)) {
                Some(DeviceStanding::New) => SenderVerification::UnapprovedDevice,
                Some(DeviceStanding::KeyChanged) => {
                    return Err(QGuardError::Trust(format!(
                        "message claims to come from device {}, which is presenting different identity keys than the ones recorded for it; refusing it",
                        envelope.sender_device_id
                    )))
                }
                Some(DeviceStanding::Pinned) | None => SenderVerification::RegisteredDevice,
            }
        }
        (verification, _) => verification,
    };
    let authenticated = sender_verification == SenderVerification::RegisteredDevice;

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
            authenticated,
            sender_verification,
        });
    }

    // The ledger first: an envelope this device has opened before no longer
    // needs its prekey at all, which is what lets retired prekeys be destroyed.
    // A recorded key that does not open the ciphertext is ignored, not trusted
    // — the prekey path below still gets its turn.
    let from_ledger = state
        .cached_message_key(
            &session_user_id,
            &envelope.message_id,
            &envelope.envelope.nonce,
            &envelope.envelope.tag,
        )
        .map(Zeroizing::new)
        .and_then(|key| symmetric::decrypt(&key, &envelope.envelope, &envelope.aad).ok());

    let (plaintext, opened_from_ledger) = match from_ledger {
        Some(plaintext) => (plaintext, true),
        None => {
            let transport = KeyTransport::of(&envelope);
            let (plaintext, message_key) = open_with_prekey(&state, &envelope, &transport)?;
            state.remember_message_key(
                &session_user_id,
                &envelope.message_id,
                &envelope.envelope.nonce,
                &envelope.envelope.tag,
                &message_key,
            );
            // This prekey was still needed. If it is a retired one, that is
            // evidence it is not ready to be destroyed yet.
            state.note_prekey_needed(&session_user_id, &envelope.prekey_id);
            (plaintext, false)
        }
    };

    let plaintext = String::from_utf8(plaintext)
        .map_err(|_| QGuardError::InvalidInput("message plaintext is not UTF-8".to_string()))?;
    state
        .decrypted_message_cache
        .lock()
        .map_err(|_| QGuardError::Storage("decrypted message cache lock poisoned".to_string()))?
        .insert(cache_key, plaintext.clone());
    state.touch_telemetry(
        "message",
        match (opened_from_ledger, exact_local_device) {
            (true, _) => "Encrypted message opened with its recorded message key (no prekey needed)",
            (false, true) => "Encrypted message decrypted locally with its device prekey",
            (false, false) => "Synced trusted-device envelope decrypted locally with its device prekey",
        },
        100,
    );
    Ok(DecryptedMessage {
        message_id: envelope.message_id,
        conversation_id: envelope.conversation_id,
        plaintext,
        authenticated,
        sender_verification,
    })
}

/// Errors that say "this envelope will never open here", as opposed to "try
/// again later". Only the first kind may be skipped when catching up keys: a
/// transient fault treated as permanent would let a prekey be destroyed while
/// messages still depended on it.
fn is_permanent_open_failure(error: &QGuardError) -> bool {
    matches!(
        error,
        QGuardError::Crypto(_)
            | QGuardError::NotFound(_)
            | QGuardError::InvalidInput(_)
            | QGuardError::Trust(_)
            | QGuardError::Replay(_)
    )
}

/// Record the message key for an envelope WITHOUT returning its plaintext.
///
/// This is how keys for messages the user has not opened yet get into the
/// ledger, so the prekey they were sealed to can be retired safely. The
/// plaintext is decrypted only to prove the derived key is correct and is
/// wiped immediately; it never crosses back into the WebView.
///
/// `Err` means "could not tell right now" and must stop the caller from
/// concluding anything. A permanently unreadable envelope is `Ok(Unreadable)`.
#[tauri::command]
pub async fn messaging_cache_envelope_key(
    state: State<'_, AppState>,
    request: EnvelopeKeyRequest,
) -> Result<EnvelopeKeyOutcome> {
    let user_id = request.recipient_user_id.clone();
    state.require_user_auth(&user_id)?;
    let _key_scope = state.lock_key_scope()?;
    state.ensure_identity(&user_id, platform_device_label())?;

    if !state.with_message_keys(&user_id, |ledger| ledger.is_available())? {
        return Err(QGuardError::Storage(
            "the message key ledger on this device could not be opened, so no key can be recorded right now"
                .to_string(),
        ));
    }
    if state
        .cached_message_key(
            &user_id,
            &request.message_id,
            &request.envelope.nonce,
            &request.envelope.tag,
        )
        .is_some()
    {
        return Ok(EnvelopeKeyOutcome {
            status: EnvelopeKeyStatus::AlreadyCached,
            reason: None,
        });
    }

    let transport = KeyTransport::of_request(&request);
    let derived = transport
        .verify_aad()
        .and_then(|_| decapsulate_for(&state, &transport))
        .and_then(|shared_secret| per_message_key(&shared_secret, &transport))
        .and_then(|key| {
            // Proof that the key is right: it has to open the ciphertext.
            symmetric::decrypt(&key, transport.sealed, transport.aad)
                .map(Zeroizing::new)
                .map(|_plaintext| key)
        });

    match derived {
        Ok(message_key) => {
            state.remember_message_key(
                &user_id,
                &request.message_id,
                &request.envelope.nonce,
                &request.envelope.tag,
                &message_key,
            );
            state.note_prekey_needed(&user_id, &request.prekey_id);
            Ok(EnvelopeKeyOutcome {
                status: EnvelopeKeyStatus::Cached,
                reason: None,
            })
        }
        Err(error) if is_permanent_open_failure(&error) => Ok(EnvelopeKeyOutcome {
            status: EnvelopeKeyStatus::Unreadable,
            reason: Some(error.to_string()),
        }),
        Err(error) => Err(error),
    }
}

/// Which of these envelopes already have their key in the ledger. Lets the
/// catch-up pass skip everything it does not need to fetch in full.
#[tauri::command]
pub fn messaging_message_keys_lookup(
    state: State<'_, AppState>,
    user_id: Option<String>,
    items: Vec<LedgerProbe>,
) -> Result<Vec<bool>> {
    let user_id = state.resolve_user_id(user_id)?;
    if items.len() > MAX_LEDGER_PROBES {
        return Err(QGuardError::InvalidInput(format!(
            "at most {MAX_LEDGER_PROBES} envelopes can be looked up at once"
        )));
    }
    state.with_message_keys(&user_id, |ledger| {
        items
            .iter()
            .map(|item| ledger.contains(&item.message_id, &item.nonce, &item.tag))
            .collect()
    })
}

/// Write the message-key ledger out now. Returns whether the copy on disk is
/// known to be complete (false when the ledger is unavailable).
#[tauri::command]
pub fn messaging_flush_message_keys(
    state: State<'_, AppState>,
    user_id: Option<String>,
) -> Result<bool> {
    let user_id = state.resolve_user_id(user_id)?;
    state.flush_message_keys(&user_id)
}

/// Destroy the recorded keys of messages their SENDER has deleted.
///
/// `messaging_delete_encrypted_message` covers a deletion made on this device.
/// This covers the other side: a recipient learns that a message was deleted
/// from the relay (live, or the next time it checks), and without this its
/// ledger would go on holding a key for ciphertext everyone meant to be gone.
/// Returns how many keys were destroyed; unknown ids are simply not counted.
#[tauri::command]
pub fn messaging_forget_message_keys(
    state: State<'_, AppState>,
    user_id: Option<String>,
    message_ids: Vec<String>,
) -> Result<usize> {
    let user_id = state.resolve_user_id(user_id)?;
    if message_ids.len() > MAX_LEDGER_PROBES {
        return Err(QGuardError::InvalidInput(format!(
            "at most {MAX_LEDGER_PROBES} messages can be forgotten at once"
        )));
    }
    let forgotten = state.with_message_keys(&user_id, |ledger| {
        message_ids.iter().filter(|id| ledger.forget(id)).count()
    })?;
    if forgotten == 0 {
        return Ok(0);
    }
    state.flush_message_keys(&user_id)?;
    if let Ok(mut cache) = state.decrypted_message_cache.lock() {
        cache.retain(|cache_key, plaintext| {
            let deleted = message_ids
                .iter()
                .any(|id| cache_key.rsplit(':').next() == Some(id.as_str()));
            if deleted {
                plaintext.zeroize();
            }
            !deleted
        });
    }
    state.audit_info(
        "message_keys_forgotten",
        &format!("{forgotten} recorded message key(s) destroyed for messages deleted by their sender"),
    );
    Ok(forgotten)
}

/// Destroy this device's ability to open a deleted message.
///
/// `message_id` is the envelope the UI was showing; `message_ids` are the other
/// envelopes of the same message (one is sealed per device, and a synced copy
/// may have been opened here too). Their keys are removed from the ledger and
/// the removal is written out immediately, and any decrypted copy still in
/// memory is dropped — so "delete" is no longer just a marker on the relay.
#[tauri::command]
pub fn messaging_delete_encrypted_message(
    state: State<'_, AppState>,
    message_id: String,
    message_ids: Option<Vec<String>>,
) -> Result<bool> {
    let session = state.require_auth()?;
    let mut ids = message_ids.unwrap_or_default();
    ids.push(message_id.clone());
    ids.sort();
    ids.dedup();

    // Best effort on the ledger: a deletion must never fail because the ledger
    // is unavailable — there is then nothing recorded to remove.
    let forgotten = state
        .with_message_keys(&session.user_id, |ledger| {
            ids.iter().filter(|id| ledger.forget(id)).count()
        })
        .unwrap_or(0);
    if forgotten > 0 {
        let _ = state.flush_message_keys(&session.user_id);
    }
    if let Ok(mut cache) = state.decrypted_message_cache.lock() {
        cache.retain(|cache_key, plaintext| {
            let deleted = ids
                .iter()
                .any(|id| cache_key.rsplit(':').next() == Some(id.as_str()));
            if deleted {
                plaintext.zeroize();
            }
            !deleted
        });
    }
    state.audit_info(
        "message_deleted",
        &format!(
            "Encrypted envelope {message_id} deleted; {forgotten} recorded message key(s) destroyed"
        ),
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
