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
    decrypt_message_with_key, encrypt_message_with_key, encrypt_ratchet_message, message_signable,
    EncryptedMessageEnvelope, MessageAddress, MessageKind, MessageSigningContext,
};
use crate::pq_ratchet::{self, HeaderKind, InitContext, InitMaterial, RatchetHeader, Session, SessionSummary};
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

/// How a message's key was established.
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MessageProtocol {
    /// Its own hybrid encapsulation to a prekey of this device.
    OneShot,
    /// A post-quantum ratchet session (`crate::pq_ratchet`). Known from the
    /// header, which both signatures and the AEAD tag cover.
    Ratchet,
}

#[derive(Clone, Debug, Serialize)]
pub struct DecryptedMessage {
    pub message_id: String,
    pub conversation_id: String,
    pub plaintext: String,
    /// True only for `SenderVerification::RegisteredDevice`.
    pub authenticated: bool,
    pub sender_verification: SenderVerification,
    pub protocol: MessageProtocol,
    /// Hybrid combiner behind this message's key: the ciphertext's own for a
    /// one-shot envelope, the seeding one for a ratchet session. `None` when
    /// this device can no longer tell (the session is gone).
    pub kem_combiner: Option<String>,
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
    #[serde(default)]
    pub hybrid_ciphertext: Option<HybridCiphertext>,
    #[serde(default)]
    pub prekey_id: String,
    #[serde(default)]
    pub prekey_kind: String,
    #[serde(default)]
    pub ratchet: Option<RatchetHeader>,
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
    hybrid_ciphertext: Option<&'a HybridCiphertext>,
    prekey_id: &'a str,
    prekey_kind: &'a str,
    ratchet: Option<&'a RatchetHeader>,
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
            hybrid_ciphertext: envelope.hybrid_ciphertext.as_ref(),
            prekey_id: &envelope.prekey_id,
            prekey_kind: &envelope.prekey_kind,
            ratchet: envelope.ratchet.as_ref(),
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
            hybrid_ciphertext: request.hybrid_ciphertext.as_ref(),
            prekey_id: &request.prekey_id,
            prekey_kind: &request.prekey_kind,
            ratchet: request.ratchet.as_ref(),
        }
    }

    /// The info string the hybrid encapsulation was bound to: the
    /// conversation for a one-shot envelope, the session for a ratchet seed.
    fn kex_info(&self) -> String {
        match self.ratchet {
            Some(header) => pq_ratchet::init_kex_info(
                &header.session,
                self.sender_user_id,
                self.recipient_user_id,
                self.sender_device_id,
                self.recipient_device_id,
            ),
            None => message_kex_info(
                self.conversation_id,
                self.sender_user_id,
                self.recipient_user_id,
                self.sender_device_id,
                self.recipient_device_id,
            ),
        }
    }

    fn hybrid(&self) -> Result<&'a HybridCiphertext> {
        self.hybrid_ciphertext.ok_or_else(|| {
            QGuardError::InvalidInput("this envelope carries no hybrid encapsulation".to_string())
        })
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
        // A ratchet envelope binds its header digest too (`QGM2`), so a header
        // swapped between envelopes fails here before any key is touched.
        let expected = match self.ratchet {
            Some(header) => {
                header.validate()?;
                crate::message_crypto::message_aad_v2(
                    self.message_id,
                    self.conversation_id,
                    self.sender_user_id,
                    self.recipient_user_id,
                    self.sender_device_id,
                    self.recipient_device_id,
                    self.counter,
                    header,
                )
            }
            None => crate::message_crypto::message_aad(
                self.message_id,
                self.conversation_id,
                self.sender_user_id,
                self.recipient_user_id,
                self.sender_device_id,
                self.recipient_device_id,
                self.counter,
            ),
        };
        if self.ratchet.is_some_and(|header| u64::from(header.n) != self.counter) {
            return Err(QGuardError::Trust(
                "ratchet envelope counter does not match its header; refusing it".to_string(),
            ));
        }
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
    send_encrypted_message(&state, request)
}

pub(crate) fn send_encrypted_message(
    state: &AppState,
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

    // A session with the recipient device when both sides want one. The
    // sender's copy to ITS OWN device stays one-shot: its own-history path
    // never depends on a session. Any failure falls back to one-shot, which
    // every build can open — the PQ status badge shows which mode was used.
    let to_own_device = request.recipient_user_id == request.sender_user_id
        && request.recipient_device_id == identity_bundle.device_id;
    if !to_own_device
        && state.ratchet_enabled()
        && pq_ratchet::peer_supports(request.recipient.identity.suite.as_ref())
    {
        match send_on_session(state, &request, &identity_bundle.device_id, prekey, prekey_kind) {
            Ok(envelope) => return Ok(envelope),
            Err(error) => state.audit_info(
                "ratchet_send_fell_back",
                &format!(
                    "Ratchet session to device {} unavailable ({error}); sent as a one-shot envelope",
                    request.recipient_device_id
                ),
            ),
        }
    }

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

/// Seal `request` on the ratchet session with its recipient device, starting
/// one if there is none worth using. The session is saved BEFORE the envelope
/// is returned: a chain position must never be handed out twice, and a crash
/// after this point can only cost a message that was never sent.
fn send_on_session(
    state: &AppState,
    request: &SendMessageRequest,
    local_device: &str,
    prekey: &RecipientPrekeyBundle,
    prekey_kind: &str,
) -> Result<EncryptedMessageEnvelope> {
    let user_id = request.sender_user_id.as_str();
    let peer = request.recipient_device_id.as_str();
    let now = chrono::Utc::now().timestamp();
    // Nothing may advance a session whose spent keys could not be recorded.
    if !state.with_message_keys(user_id, |ledger| ledger.is_available())? {
        return Err(QGuardError::Storage("the message key ledger is unavailable".to_string()));
    }
    let peer_signing = pq_ratchet::signing_digest(
        &request.recipient.identity.ed25519_identity_public,
        &request.recipient.identity.mldsa_identity_public,
    );

    let existing = state.with_ratchet_sessions(user_id, local_device, |book| {
        if !book.is_available() {
            return Err(QGuardError::Storage("ratchet sessions could not be opened".to_string()));
        }
        Ok(book
            .active(peer, now)
            // The device must still present the keys the session was made
            // with: a re-keyed device gets a fresh session, never the old one.
            .filter(|session| session.peer_signing == peer_signing)
            // An unanswered seed must still be openable: once the peer has
            // rotated the prekey it was sealed to, start again on the new one.
            .filter(|session| {
                session.pending_init().is_none_or(|init| {
                    init.prekey_kind != "signed_prekey" || init.prekey_id == request.recipient.signed_prekey.prekey_id
                })
            })
            .cloned())
    })??;

    let fresh = existing.is_none();
    let mut session = match existing {
        Some(session) => session,
        None => {
            let session_id = pq_ratchet::new_session_id();
            let kex_info = pq_ratchet::init_kex_info(
                &session_id,
                user_id,
                &request.recipient_user_id,
                local_device,
                peer,
            );
            let combiner = KemCombiner::for_peer_suite(request.recipient.identity.suite.as_ref());
            let (hybrid_ciphertext, shared) =
                encapsulate_with(&prekey.x25519_public, &prekey.mlkem_public, kex_info.as_bytes(), combiner)?;
            let shared = Zeroizing::new(shared);
            let ctx = InitContext {
                session_id: &session_id,
                initiator_device: local_device,
                responder_device: peer,
                hybrid_digest: pq_ratchet::hybrid_digest(&hybrid_ciphertext),
            };
            Session::initiate(
                &shared,
                &ctx,
                &peer_signing,
                InitMaterial {
                    hybrid_ciphertext,
                    prekey_id: prekey.prekey_id.clone(),
                    prekey_kind: prekey_kind.to_string(),
                },
                now,
            )?
        }
    };

    let (header, message_key) = session.next_send(now)?;
    let seed = match header.kind {
        HeaderKind::Init => session
            .pending_init()
            .map(|init| (init.hybrid_ciphertext.clone(), init.prekey_id.clone(), init.prekey_kind.clone())),
        HeaderKind::Msg => None,
    };
    let combiner = session.init_combiner.clone();
    let envelope = {
        let identity_guard = state
            .identity
            .lock()
            .map_err(|_| QGuardError::Storage("identity lock poisoned".to_string()))?;
        let identity = identity_guard
            .as_ref()
            .ok_or_else(|| QGuardError::NotFound("identity".to_string()))?;
        encrypt_ratchet_message(
            MessageAddress {
                conversation_id: &request.conversation_id,
                sender_user_id: user_id,
                recipient_user_id: &request.recipient_user_id,
                sender_device_id: local_device,
                recipient_device_id: peer,
            },
            header,
            &message_key,
            seed,
            &combiner,
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

    state.with_ratchet_sessions(user_id, local_device, |book| {
        if fresh {
            book.put(session)
        } else {
            book.update(session)
        }
    })?;
    if !state.persist_ratchet_sessions(user_id)? {
        return Err(QGuardError::Storage("the ratchet session could not be saved".to_string()));
    }
    state.touch_telemetry(
        "message",
        if fresh {
            "New post-quantum ratchet session seeded with a fresh ML-KEM-1024/X25519 encapsulation"
        } else {
            "Message key advanced on the post-quantum ratchet session"
        },
        100,
    );
    state.audit_info("message_sent", "Encrypted ratchet envelope created for relay storage");
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
pub(crate) fn pin_subject_of(identity: &RecipientIdentityBundle) -> PinSubject {
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
        transport.hybrid()?,
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
    receive_encrypted_message(&state, envelope, sender_identity)
}

pub(crate) fn receive_encrypted_message(
    state: &AppState,
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
    let protocol = if envelope.ratchet.is_some() { MessageProtocol::Ratchet } else { MessageProtocol::OneShot };

    // What the badge may say about how this message was protected. For a
    // ratchet message the combiner is a property of its session, known while
    // this device still holds the session; an init also names it in its seed.
    let mut kem_combiner = envelope
        .hybrid_ciphertext
        .as_ref()
        .map(|hybrid| hybrid.suite.kem_combiner.clone());
    if let Some(header) = envelope.ratchet.as_ref() {
        let from_session = state
            .with_ratchet_sessions(&session_user_id, &identity_bundle.device_id, |book| {
                book.find(&envelope.sender_device_id, &header.session)
                    .map(|session| session.init_combiner.clone())
            })
            .ok()
            .flatten();
        if from_session.is_some() {
            kem_combiner = from_session;
        }
    }

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
            protocol,
            kem_combiner,
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
            let (plaintext, message_key) = match envelope.ratchet.as_ref() {
                Some(header) => {
                    let opened = open_ratchet(
                        state,
                        &envelope,
                        &transport,
                        header,
                        sender_verification,
                        &session_user_id,
                        &identity_bundle.device_id,
                    )?;
                    kem_combiner = Some(opened.kem_combiner);
                    (opened.plaintext, opened.message_key)
                }
                None => open_with_prekey(state, &envelope, &transport)?,
            };
            state.remember_message_key(
                &session_user_id,
                &envelope.message_id,
                &envelope.envelope.nonce,
                &envelope.envelope.tag,
                &message_key,
            );
            if !envelope.prekey_id.is_empty() {
                // This prekey was still needed. If it is a retired one, that
                // is evidence it is not ready to be destroyed yet.
                state.note_prekey_needed(&session_user_id, &envelope.prekey_id);
            }
            if envelope.ratchet.is_some() {
                // The session moved past this message's key, which now exists
                // only in the ledger: ledger first, then the sessions. A
                // failure leaves both dirty in memory; the next write catches
                // up, and until then the copy on disk can still re-derive.
                let _ = state.persist_ratchet_sessions(&session_user_id);
            }
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
        match (opened_from_ledger, protocol, exact_local_device) {
            (true, _, _) => "Encrypted message opened with its recorded message key (no prekey needed)",
            (false, MessageProtocol::Ratchet, _) => "Encrypted message opened with its post-quantum ratchet session key",
            (false, MessageProtocol::OneShot, true) => "Encrypted message decrypted locally with its device prekey",
            (false, MessageProtocol::OneShot, false) => "Synced trusted-device envelope decrypted locally with its device prekey",
        },
        100,
    );
    Ok(DecryptedMessage {
        message_id: envelope.message_id,
        conversation_id: envelope.conversation_id,
        plaintext,
        authenticated,
        sender_verification,
        protocol,
        kem_combiner,
    })
}

/// The stable prefix of "this message belongs to a ratchet session this device
/// does not hold". The UI matches on it to start a fresh session with the
/// sender (see `messaging_reset_ratchet_session`) and to explain the gap,
/// instead of reporting a broken cipher. Keep in sync with
/// `RATCHET_SESSION_MISSING_MARKER` in src/lib/ratchet-status.ts.
const RATCHET_SESSION_MISSING_MARKER: &str = "secure session unavailable";

struct RatchetOpened {
    plaintext: Vec<u8>,
    message_key: Zeroizing<[u8; 32]>,
    kem_combiner: String,
}

/// Open a ratchet envelope addressed to this device.
///
/// Every change to a session happens on a CLONE that is committed only after
/// the AEAD tag verifies, so a malformed or hostile header can never move real
/// state. The caller has already verified both signatures, the AAD (which
/// binds the header) and the sender's registered identity.
fn open_ratchet(
    state: &AppState,
    envelope: &EncryptedMessageEnvelope,
    transport: &KeyTransport,
    header: &RatchetHeader,
    sender_verification: SenderVerification,
    user_id: &str,
    local_device: &str,
) -> Result<RatchetOpened> {
    header.validate()?;
    if envelope.recipient_device_id != local_device {
        return Err(QGuardError::NotFound(
            "this ratchet message was sealed to another of your devices".to_string(),
        ));
    }
    let now = chrono::Utc::now().timestamp();
    let peer = envelope.sender_device_id.as_str();
    let peer_signing = pq_ratchet::signing_digest(&envelope.sender_ed25519_public, &envelope.sender_mldsa_public);

    let existing = state.with_ratchet_sessions(user_id, local_device, |book| {
        book.find(peer, &header.session).cloned()
    })?;

    if let Some(session) = existing {
        if session.peer_signing != peer_signing {
            return Err(QGuardError::Trust(format!(
                "ratchet message claims session {} but is signed by a key that session was never established with; refusing it",
                header.session
            )));
        }
        let mut trial = session.clone();
        let key = trial.recv(header, now)?;
        let plaintext = symmetric::decrypt(&key, transport.sealed, transport.aad)?;
        let kem_combiner = trial.init_combiner.clone();
        let session_id = trial.id.clone();
        state.with_ratchet_sessions(user_id, local_device, |book| {
            book.update(trial);
            book.promote(peer, &session_id);
        })?;
        return Ok(RatchetOpened { plaintext, message_key: key, kem_combiner });
    }

    if header.kind == HeaderKind::Msg {
        return Err(QGuardError::Crypto(format!(
            "{RATCHET_SESSION_MISSING_MARKER}: this message belongs to secure session {} with device {peer}, which this device does not hold (it was reset, expired, or never started here). A new session is started with the next message you send them.",
            header.session
        )));
    }

    // An init this device has not seen: the seed comes from our prekey.
    let hybrid = transport.hybrid()?;
    let shared = decapsulate_for(state, transport)?;
    let ctx = InitContext {
        session_id: &header.session,
        initiator_device: peer,
        responder_device: local_device,
        hybrid_digest: pq_ratchet::hybrid_digest(hybrid),
    };
    let kem_combiner = hybrid.suite.kem_combiner.clone();
    if sender_verification != SenderVerification::RegisteredDevice {
        // Not a device this device will hold a session with (unregistered or
        // not yet approved): open this one message from the seed alone, as a
        // one-shot envelope would be, and keep nothing.
        let key = pq_ratchet::init_message_key(&shared, &ctx, header)?;
        let plaintext = symmetric::decrypt(&key, transport.sealed, transport.aad)?;
        return Ok(RatchetOpened { plaintext, message_key: key, kem_combiner });
    }
    let mut session = Session::accept(&shared, &ctx, header, &peer_signing, &kem_combiner, now)?;
    let key = session.recv(header, now)?;
    let plaintext = symmetric::decrypt(&key, transport.sealed, transport.aad)?;
    state.with_ratchet_sessions(user_id, local_device, |book| book.put(session))?;
    Ok(RatchetOpened { plaintext, message_key: key, kem_combiner })
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
    if transport.ratchet.is_some_and(|header| header.kind == HeaderKind::Msg) {
        // Its key comes from a session, not a prekey: no prekey depends on
        // it, and it is recorded when it is opened.
        return Ok(EnvelopeKeyOutcome {
            status: EnvelopeKeyStatus::Unreadable,
            reason: Some("ratchet message: its key comes from the session, not a prekey".to_string()),
        });
    }
    let derived = transport
        .verify_aad()
        .and_then(|_| decapsulate_for(&state, &transport))
        .and_then(|shared_secret| match transport.ratchet {
            // A ratchet seed, recorded from the seed alone: no signature
            // here, so no session is started on its strength.
            Some(header) => pq_ratchet::init_message_key(
                &shared_secret,
                &InitContext {
                    session_id: &header.session,
                    initiator_device: transport.sender_device_id,
                    responder_device: transport.recipient_device_id,
                    hybrid_digest: pq_ratchet::hybrid_digest(transport.hybrid()?),
                },
                header,
            ),
            None => per_message_key(&shared_secret, &transport),
        })
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

/// What the app can truthfully say about ratchet sessions on this device.
#[derive(Clone, Debug, Serialize)]
pub struct RatchetStatus {
    /// This install advertises the ratchet and starts sessions.
    pub enabled: bool,
    /// `QGUARD_RATCHET` overrides the setting (`Some`), or not (`None`).
    pub env_override: Option<bool>,
    /// The session file could be opened. False means "cannot tell", not "none".
    pub available: bool,
    /// The protocol label this build speaks.
    pub protocol: String,
    /// Active session per requested peer device; absent = no session.
    pub sessions: std::collections::HashMap<String, SessionSummary>,
}

const MAX_STATUS_PEERS: usize = 64;

fn ratchet_status_for(state: &AppState, user_id: &str, peer_device_ids: &[String]) -> Result<RatchetStatus> {
    if peer_device_ids.len() > MAX_STATUS_PEERS {
        return Err(QGuardError::InvalidInput(format!(
            "at most {MAX_STATUS_PEERS} devices can be asked about at once"
        )));
    }
    let local_device = state.ensure_identity(user_id, platform_device_label())?.device_id;
    let now = chrono::Utc::now().timestamp();
    let (available, sessions) = state.with_ratchet_sessions(user_id, &local_device, |book| {
        let sessions = peer_device_ids
            .iter()
            .filter_map(|peer| book.summary_for(peer, now).map(|summary| (peer.clone(), summary)))
            .collect();
        (book.is_available(), sessions)
    })?;
    Ok(RatchetStatus {
        enabled: state.ratchet_enabled(),
        env_override: pq_ratchet::env_override(),
        available,
        protocol: pq_ratchet::RATCHET_PROTOCOL.to_string(),
        sessions,
    })
}

/// Session facts for the PQ status badge and the dashboard. No key material.
#[tauri::command]
pub fn messaging_ratchet_status(
    state: State<'_, AppState>,
    user_id: Option<String>,
    peer_device_ids: Vec<String>,
) -> Result<RatchetStatus> {
    let user_id = state.resolve_user_id(user_id)?;
    let _key_scope = state.lock_key_scope()?;
    ratchet_status_for(&state, &user_id, &peer_device_ids)
}

/// Settings → Advanced: advertise the ratchet (and start sessions) or not.
/// The caller re-publishes this device's suite so peers see the change.
#[tauri::command]
pub fn messaging_set_ratchet_enabled(
    state: State<'_, AppState>,
    user_id: Option<String>,
    enabled: bool,
) -> Result<RatchetStatus> {
    let user_id = state.resolve_user_id(user_id)?;
    let _key_scope = state.lock_key_scope()?;
    state.set_ratchet_enabled(enabled)?;
    state.audit_info(
        "ratchet_setting_changed",
        if enabled {
            "Post-quantum session ratchet turned on for this device"
        } else {
            "Post-quantum session ratchet turned off for this device; new messages are one-shot envelopes"
        },
    );
    ratchet_status_for(&state, &user_id, &[])
}

/// Forget the ratchet session(s) with one peer device, or with every device
/// when none is named. The next message to that device starts a fresh session
/// from its prekey — the same path every first message takes. Returns whether
/// anything was forgotten.
#[tauri::command]
pub fn messaging_reset_ratchet_session(
    state: State<'_, AppState>,
    user_id: Option<String>,
    peer_device_id: Option<String>,
) -> Result<bool> {
    let user_id = state.resolve_user_id(user_id)?;
    let _key_scope = state.lock_key_scope()?;
    let local_device = state.ensure_identity(&user_id, platform_device_label())?.device_id;
    let forgotten = state.with_ratchet_sessions(&user_id, &local_device, |book| match peer_device_id.as_deref() {
        Some(peer) => usize::from(book.forget_peer(peer)),
        None => book.forget_all(),
    })?;
    if forgotten > 0 {
        state.persist_ratchet_sessions(&user_id)?;
        state.audit_info(
            "ratchet_session_reset",
            &match peer_device_id.as_deref() {
                Some(peer) => format!("Secure session with device {peer} reset; the next message starts a new one"),
                None => format!("{forgotten} secure session(s) reset; the next message to each device starts a new one"),
            },
        );
    }
    Ok(forgotten > 0)
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

/// Two complete devices — each its own `AppState`, data directory, identity,
/// prekeys, ledger and session file — talking through the real send and
/// receive paths. The relay is modelled as a JSON round trip of each envelope.
#[cfg(test)]
mod ratchet_tests {
    use super::*;
    use crate::test_support::TestDevice;

    /// The messaging side of a test device.
    trait Messaging {
        fn send_to(&self, peer: &TestDevice, text: &str) -> EncryptedMessageEnvelope;
        fn open_from(&self, sender: &TestDevice, envelope: &EncryptedMessageEnvelope) -> Result<DecryptedMessage>;
        fn status_with(&self, peer: &TestDevice) -> Option<SessionSummary>;
        fn forget_decrypted_cache(&self);
    }

    impl Messaging for TestDevice {
        fn send_to(&self, peer: &TestDevice, text: &str) -> EncryptedMessageEnvelope {
            let envelope = send_encrypted_message(
                &self.state,
                SendMessageRequest {
                    conversation_id: "conv-1".to_string(),
                    sender_user_id: self.user.clone(),
                    recipient_user_id: peer.user.clone(),
                    recipient_device_id: peer.device_id.clone(),
                    plaintext: text.to_string(),
                    kind: Some(MessageKind::Text),
                    recipient: peer.key_bundle(),
                },
            )
            .expect("send");
            relay(&envelope)
        }

        fn open_from(&self, sender: &TestDevice, envelope: &EncryptedMessageEnvelope) -> Result<DecryptedMessage> {
            receive_encrypted_message(&self.state, envelope.clone(), Some(sender.identity_row()))
        }

        fn status_with(&self, peer: &TestDevice) -> Option<SessionSummary> {
            ratchet_status_for(&self.state, &self.user, &[peer.device_id.clone()])
                .expect("status")
                .sessions
                .remove(&peer.device_id)
        }

        fn forget_decrypted_cache(&self) {
            self.state.decrypted_message_cache.lock().unwrap().clear();
        }
    }

    /// What the relay stores and hands back.
    fn relay(envelope: &EncryptedMessageEnvelope) -> EncryptedMessageEnvelope {
        serde_json::from_value(serde_json::to_value(envelope).unwrap()).unwrap()
    }

    fn opened(device: &TestDevice, sender: &TestDevice, envelope: &EncryptedMessageEnvelope, text: &str) {
        let message = device.open_from(sender, envelope).expect("open");
        assert_eq!(message.plaintext, text);
        assert!(message.authenticated);
        assert_eq!(message.protocol, MessageProtocol::Ratchet);
        assert_eq!(message.kem_combiner.as_deref(), Some(crate::crypto::CURRENT_KEM_COMBINER));
    }

    fn sign_as(device: &TestDevice, envelope: &mut EncryptedMessageEnvelope) {
        let identity = device.state.identity.lock().unwrap();
        let signing = &identity.as_ref().unwrap().signing;
        envelope.sender_ed25519_public = signing.ed25519_public.clone();
        envelope.sender_mldsa_public = signing.mldsa_public.clone();
        envelope.message_signature =
            crate::crypto::signatures::dual_sign(&signing.ed25519_secret, &signing.mldsa_secret, &message_signable(envelope))
                .unwrap();
    }

    #[test]
    fn two_devices_converse_on_one_session() {
        let alice = TestDevice::new(true);
        let bob = TestDevice::new(true);

        let first = alice.send_to(&bob, "hello bob");
        let header = first.ratchet.clone().expect("a capable peer gets a ratchet envelope");
        assert_eq!(header.kind, HeaderKind::Init);
        assert!(first.hybrid_ciphertext.is_some(), "an init carries its seed");
        assert!(first.aad.starts_with(b"QGM2|"));
        opened(&bob, &alice, &first, "hello bob");

        let reply = bob.send_to(&alice, "hi alice");
        let reply_header = reply.ratchet.clone().unwrap();
        assert_eq!(reply_header.kind, HeaderKind::Msg);
        assert_eq!(reply_header.session, header.session, "the responder answers on the session it was offered");
        assert!(reply.hybrid_ciphertext.is_none(), "an ordinary ratchet message carries no encapsulation");
        assert!(reply.prekey_id.is_empty());
        opened(&alice, &bob, &reply, "hi alice");

        for round in 0..6 {
            let burst: Vec<_> = (0..3).map(|i| alice.send_to(&bob, &format!("a{round}.{i}"))).collect();
            for (i, envelope) in burst.iter().enumerate().rev() {
                assert_eq!(envelope.ratchet.as_ref().unwrap().kind, HeaderKind::Msg);
                opened(&bob, &alice, envelope, &format!("a{round}.{i}")); // newest first
            }
            let back = bob.send_to(&alice, &format!("b{round}"));
            opened(&alice, &bob, &back, &format!("b{round}"));
        }
        let summary = bob.status_with(&alice).expect("bob holds the session");
        assert!(summary.ratcheted);
        assert_eq!(summary.session_id, header.session);
        assert!(alice.status_with(&bob).unwrap().ratcheted);
    }

    #[test]
    fn a_reopened_message_comes_from_the_ledger_not_the_session() {
        let alice = TestDevice::new(true);
        let bob = TestDevice::new(true);
        let first = alice.send_to(&bob, "once");
        opened(&bob, &alice, &first, "once");
        bob.forget_decrypted_cache();
        // The chain has moved past this key; only the ledger can open it now.
        opened(&bob, &alice, &first, "once");
    }

    #[test]
    fn sessions_and_spent_keys_survive_a_restart_on_both_sides() {
        let alice = TestDevice::new(true);
        let bob = TestDevice::new(true);
        let first = alice.send_to(&bob, "before");
        opened(&bob, &alice, &first, "before");
        let reply = bob.send_to(&alice, "reply");
        opened(&alice, &bob, &reply, "reply");

        let alice = alice.restart();
        let bob = bob.restart();
        assert!(bob.status_with(&alice).is_some(), "the session was written to disk");
        // History still opens after the restart (from the ledger)...
        opened(&bob, &alice, &first, "before");
        // ...and the conversation carries on where it left off.
        let after = alice.send_to(&bob, "after");
        assert_eq!(after.ratchet.as_ref().unwrap().kind, HeaderKind::Msg);
        opened(&bob, &alice, &after, "after");
        let again = bob.send_to(&alice, "again");
        opened(&alice, &bob, &again, "again");
    }

    #[test]
    fn a_post_quantum_step_happens_on_the_message_cadence() {
        let alice = TestDevice::new(true);
        let bob = TestDevice::new(true);
        let first = alice.send_to(&bob, "0");
        opened(&bob, &alice, &first, "0");
        let mut saw_offer = false;
        let mut saw_answer = false;
        for i in 0..(pq_ratchet::PQ_STEP_EVERY_MESSAGES + 4) {
            let from_bob = bob.send_to(&alice, &format!("b{i}"));
            let header = from_bob.ratchet.as_ref().unwrap();
            saw_offer |= header.pq_offer.is_some();
            saw_answer |= header.pq_answer.is_some();
            opened(&alice, &bob, &from_bob, &format!("b{i}"));
            let from_alice = alice.send_to(&bob, &format!("a{i}"));
            let header = from_alice.ratchet.as_ref().unwrap();
            saw_offer |= header.pq_offer.is_some();
            saw_answer |= header.pq_answer.is_some();
            opened(&bob, &alice, &from_alice, &format!("a{i}"));
        }
        assert!(saw_offer && saw_answer, "an ML-KEM-1024 offer and its answer must cross the wire");
        assert!(alice.status_with(&bob).unwrap().pq_steps >= 1);
        assert!(bob.status_with(&alice).unwrap().pq_steps >= 1);
    }

    #[test]
    fn a_peer_without_the_capability_gets_a_one_shot_envelope() {
        let alice = TestDevice::new(true);
        let bob = TestDevice::new(false);
        let envelope = alice.send_to(&bob, "plain");
        assert!(envelope.ratchet.is_none());
        let json = serde_json::to_value(&envelope).unwrap();
        assert!(json.get("ratchet").is_none(), "a one-shot envelope must not grow a field");
        assert!(json["hybrid_ciphertext"].is_object());
        assert!(envelope.aad.starts_with(b"QGM1|"));
        let message = bob.open_from(&alice, &envelope).unwrap();
        assert_eq!(message.plaintext, "plain");
        assert_eq!(message.protocol, MessageProtocol::OneShot);
        assert!(alice.status_with(&bob).is_none(), "no session was started");

        // And with the capability off on the SENDER, nothing starts either.
        let carol = TestDevice::new(false);
        let dave = TestDevice::new(true);
        assert!(carol.send_to(&dave, "x").ratchet.is_none());
    }

    #[test]
    fn the_copy_to_your_own_device_stays_one_shot() {
        let alice = TestDevice::new(true);
        let own = send_encrypted_message(
            &alice.state,
            SendMessageRequest {
                conversation_id: "conv-1".to_string(),
                sender_user_id: alice.user.clone(),
                recipient_user_id: alice.user.clone(),
                recipient_device_id: alice.device_id.clone(),
                plaintext: "note to self".to_string(),
                kind: Some(MessageKind::Text),
                recipient: alice.key_bundle(),
            },
        )
        .unwrap();
        assert!(own.ratchet.is_none());
        assert_eq!(alice.open_from(&alice, &own).unwrap().plaintext, "note to self");
    }

    #[test]
    fn a_tampered_envelope_is_refused_and_never_moves_the_session() {
        let alice = TestDevice::new(true);
        let bob = TestDevice::new(true);
        let first = alice.send_to(&bob, "seed");
        opened(&bob, &alice, &first, "seed");
        let genuine = alice.send_to(&bob, "genuine");

        // Relay edits: header, ciphertext, stripping the header. The
        // signatures catch each one.
        let mut header_edit = genuine.clone();
        header_edit.ratchet.as_mut().unwrap().n += 1;
        assert!(bob.open_from(&alice, &header_edit).is_err());
        let mut body_edit = genuine.clone();
        body_edit.envelope.ciphertext[0] ^= 1;
        assert!(bob.open_from(&alice, &body_edit).is_err());
        let mut stripped = genuine.clone();
        stripped.ratchet = None;
        assert!(bob.open_from(&alice, &stripped).is_err(), "a header cannot be stripped");

        // A sender's own bad envelope (valid signature, wrong tag) fails at the
        // AEAD on the trial copy, so the real session is untouched.
        let mut bad_tag = genuine.clone();
        bad_tag.envelope.tag[0] ^= 1;
        sign_as(&alice, &mut bad_tag);
        assert!(bob.open_from(&alice, &bad_tag).is_err());
        opened(&bob, &alice, &genuine, "genuine");
    }

    #[test]
    fn a_session_answers_only_to_the_keys_it_was_made_with() {
        let alice = TestDevice::new(true);
        let bob = TestDevice::new(true);
        let mallory = TestDevice::new(true);
        let first = alice.send_to(&bob, "seed");
        opened(&bob, &alice, &first, "seed");
        let next = alice.send_to(&bob, "next");

        // Mallory re-signs Alice's envelope with her own keys and attaches
        // them; with no registry row the envelope is self-consistent.
        let mut forged = next.clone();
        sign_as(&mallory, &mut forged);
        let error = receive_encrypted_message(&bob.state, forged, None).unwrap_err();
        assert!(format!("{error}").contains("never established with"), "{error}");
        opened(&bob, &alice, &next, "next");
    }

    #[test]
    fn a_lost_session_is_reported_and_the_next_message_back_recovers() {
        let alice = TestDevice::new(true);
        let bob = TestDevice::new(true);
        let first = alice.send_to(&bob, "seed");
        opened(&bob, &alice, &first, "seed");
        let reply = bob.send_to(&alice, "reply");
        opened(&alice, &bob, &reply, "reply");

        // Bob loses his sessions (reset in the Trust Center, restored backup…).
        bob.state
            .with_ratchet_sessions(&bob.user, &bob.device_id, |book| book.forget_all())
            .unwrap();
        let lost = alice.send_to(&bob, "lost");
        let error = bob.open_from(&alice, &lost).unwrap_err();
        assert!(format!("{error}").contains(RATCHET_SESSION_MISSING_MARKER), "{error}");

        // Bob's next message starts a fresh session; Alice adopts it, and her
        // next message travels on it.
        let fresh = bob.send_to(&alice, "new session");
        assert_eq!(fresh.ratchet.as_ref().unwrap().kind, HeaderKind::Init);
        opened(&alice, &bob, &fresh, "new session");
        let recovered = alice.send_to(&bob, "recovered");
        assert_eq!(recovered.ratchet.as_ref().unwrap().session, fresh.ratchet.as_ref().unwrap().session);
        opened(&bob, &alice, &recovered, "recovered");
    }

    #[test]
    fn an_unanchored_sender_is_read_once_but_never_given_a_session() {
        let alice = TestDevice::new(true);
        let bob = TestDevice::new(true);
        let first = alice.send_to(&bob, "who am i");
        let message = receive_encrypted_message(&bob.state, first, None).unwrap();
        assert_eq!(message.plaintext, "who am i");
        assert!(!message.authenticated);
        assert!(bob.status_with(&alice).is_none());
    }

    #[test]
    fn simultaneous_first_messages_settle_on_one_session() {
        let alice = TestDevice::new(true);
        let bob = TestDevice::new(true);
        let from_alice = alice.send_to(&bob, "a");
        let from_bob = bob.send_to(&alice, "b");
        assert_ne!(from_alice.ratchet.as_ref().unwrap().session, from_bob.ratchet.as_ref().unwrap().session);
        opened(&bob, &alice, &from_alice, "a");
        opened(&alice, &bob, &from_bob, "b");
        // Whatever each side uses now, everything keeps opening, and after an
        // exchange both use the same session.
        for i in 0..3 {
            let a = alice.send_to(&bob, &format!("a{i}"));
            opened(&bob, &alice, &a, &format!("a{i}"));
            let b = bob.send_to(&alice, &format!("b{i}"));
            opened(&alice, &bob, &b, &format!("b{i}"));
        }
        assert_eq!(
            alice.status_with(&bob).unwrap().session_id,
            bob.status_with(&alice).unwrap().session_id
        );
    }

    #[test]
    fn resetting_sessions_starts_over_from_the_prekey() {
        let alice = TestDevice::new(true);
        let bob = TestDevice::new(true);
        let first = alice.send_to(&bob, "one");
        opened(&bob, &alice, &first, "one");
        let removed = alice
            .state
            .with_ratchet_sessions(&alice.user, &alice.device_id, |book| book.forget_peer(&bob.device_id))
            .unwrap();
        assert!(removed);
        let again = alice.send_to(&bob, "two");
        assert_eq!(again.ratchet.as_ref().unwrap().kind, HeaderKind::Init);
        assert_ne!(again.ratchet.as_ref().unwrap().session, first.ratchet.as_ref().unwrap().session);
        opened(&bob, &alice, &again, "two");
    }

    #[test]
    fn the_key_catch_up_records_a_seed_but_never_starts_a_session() {
        let alice = TestDevice::new(true);
        let bob = TestDevice::new(true);
        let first = alice.send_to(&bob, "unread");
        let request = EnvelopeKeyRequest {
            message_id: first.message_id.clone(),
            conversation_id: first.conversation_id.clone(),
            sender_user_id: first.sender_user_id.clone(),
            recipient_user_id: first.recipient_user_id.clone(),
            sender_device_id: first.sender_device_id.clone(),
            recipient_device_id: first.recipient_device_id.clone(),
            counter: first.counter,
            envelope: first.envelope.clone(),
            aad: first.aad.clone(),
            hybrid_ciphertext: first.hybrid_ciphertext.clone(),
            prekey_id: first.prekey_id.clone(),
            prekey_kind: first.prekey_kind.clone(),
            ratchet: first.ratchet.clone(),
        };
        let transport = KeyTransport::of_request(&request);
        transport.verify_aad().unwrap();
        let shared = decapsulate_for(&bob.state, &transport).unwrap();
        let header = request.ratchet.as_ref().unwrap();
        let key = pq_ratchet::init_message_key(
            &shared,
            &InitContext {
                session_id: &header.session,
                initiator_device: &request.sender_device_id,
                responder_device: &request.recipient_device_id,
                hybrid_digest: pq_ratchet::hybrid_digest(request.hybrid_ciphertext.as_ref().unwrap()),
            },
            header,
        )
        .unwrap();
        assert_eq!(symmetric::decrypt(&key, &first.envelope, &first.aad).unwrap(), b"unread");
        assert!(bob.status_with(&alice).is_none());
    }
}

/// What a build from before the ratchet (1.3.12) can and cannot read. Its
/// envelope type is reproduced here exactly; the point is that one-shot
/// envelopes from this build still parse and verify there, and that ratchet
/// envelopes fail closed there instead of being misread.
#[cfg(test)]
mod interop_tests {
    use super::*;
    use crate::identity::LocalIdentity;

    #[derive(Deserialize)]
    #[allow(dead_code)]
    struct EnvelopeV1312 {
        message_id: String,
        conversation_id: String,
        sender_user_id: String,
        recipient_user_id: String,
        sender_device_id: String,
        recipient_device_id: String,
        counter: u64,
        kind: MessageKind,
        sealed_sender: bool,
        envelope: EncryptedEnvelope,
        aad: Vec<u8>,
        hybrid_ciphertext: HybridCiphertext,
        prekey_id: String,
        prekey_kind: String,
        message_signature: DualSignature,
        sender_ed25519_public: Vec<u8>,
        sender_mldsa_public: Vec<u8>,
        suite: AlgorithmSuite,
        created_at: chrono::DateTime<chrono::Utc>,
    }

    /// `message_signable` exactly as 1.3.12 computes it.
    fn signable_v1312(e: &EnvelopeV1312) -> Vec<u8> {
        let mut data = Vec::new();
        for part in [
            e.message_id.as_bytes(),
            e.conversation_id.as_bytes(),
            e.sender_user_id.as_bytes(),
            e.recipient_user_id.as_bytes(),
            e.sender_device_id.as_bytes(),
            e.recipient_device_id.as_bytes(),
        ] {
            data.extend_from_slice(part);
        }
        data.extend_from_slice(&e.counter.to_be_bytes());
        data.extend_from_slice(format!("{:?}", e.kind).as_bytes());
        data.extend_from_slice(&e.envelope.nonce);
        data.extend_from_slice(&e.envelope.ciphertext);
        data.extend_from_slice(&e.envelope.tag);
        data.extend_from_slice(&e.aad);
        data.extend_from_slice(&e.hybrid_ciphertext.x25519_ephemeral_public);
        data.extend_from_slice(&e.hybrid_ciphertext.ml_kem_ciphertext);
        data.extend_from_slice(e.prekey_id.as_bytes());
        data.extend_from_slice(e.prekey_kind.as_bytes());
        data.extend_from_slice(&e.sender_ed25519_public);
        data.extend_from_slice(&e.sender_mldsa_public);
        data
    }

    fn signing(identity: &LocalIdentity) -> MessageSigningContext<'_> {
        MessageSigningContext {
            ed25519_secret: &identity.signing.ed25519_secret,
            mldsa_secret: &identity.signing.mldsa_secret,
            ed25519_public: &identity.signing.ed25519_public,
            mldsa_public: &identity.signing.mldsa_public,
        }
    }

    fn one_shot_from(identity: &LocalIdentity) -> EncryptedMessageEnvelope {
        let mut session = RatchetSession::new("t", [5u8; 32]).unwrap();
        crate::message_crypto::encrypt_message(
            &mut session,
            "conv",
            "ua",
            "ub",
            &identity.device_id,
            "db",
            HybridCiphertext {
                x25519_ephemeral_public: vec![1; 32],
                ml_kem_ciphertext: vec![2; 1568],
                suite: AlgorithmSuite::default(),
            },
            "pk",
            "signed_prekey",
            MessageKind::Text,
            b"hi",
            signing(identity),
        )
        .unwrap()
    }

    fn address(identity: &LocalIdentity) -> MessageAddress<'_> {
        MessageAddress {
            conversation_id: "conv",
            sender_user_id: "ua",
            recipient_user_id: "ub",
            sender_device_id: &identity.device_id,
            recipient_device_id: "db",
        }
    }

    #[test]
    fn a_one_shot_envelope_still_parses_and_verifies_on_1_3_12() {
        let identity = LocalIdentity::generate("ua", "Desktop").unwrap();
        let envelope = one_shot_from(&identity);
        let json = serde_json::to_string(&envelope).unwrap();
        assert!(!json.contains("\"ratchet\""), "no new field on the wire: {json}");
        let old: EnvelopeV1312 = serde_json::from_str(&json).expect("1.3.12 parses it");
        assert_eq!(signable_v1312(&old), message_signable(&envelope), "signatures cover the same bytes");
        dual_verify(&old.sender_ed25519_public, &old.sender_mldsa_public, &signable_v1312(&old), &old.message_signature)
            .expect("1.3.12 verifies it");
    }

    #[test]
    fn an_envelope_written_by_1_3_12_opens_here() {
        // A stored 1.3.12 envelope has no `ratchet` key and a hybrid object.
        let identity = LocalIdentity::generate("ua", "Desktop").unwrap();
        let mut json = serde_json::to_value(one_shot_from(&identity)).unwrap();
        json.as_object_mut().unwrap().remove("ratchet");
        let parsed: EncryptedMessageEnvelope = serde_json::from_value(json).unwrap();
        assert!(parsed.ratchet.is_none() && parsed.hybrid_ciphertext.is_some());
        dual_verify(
            &parsed.sender_ed25519_public,
            &parsed.sender_mldsa_public,
            &message_signable(&parsed),
            &parsed.message_signature,
        )
        .unwrap();
        verify_aad_matches_envelope(&parsed).unwrap();
    }

    #[test]
    fn a_ratchet_envelope_fails_closed_on_1_3_12() {
        let identity = LocalIdentity::generate("ua", "Desktop").unwrap();
        let header = RatchetHeader {
            v: 1,
            kind: HeaderKind::Msg,
            session: "ab".repeat(16),
            dh: vec![9; 32],
            pn: 0,
            n: 3,
            pq_offer: None,
            pq_answer: None,
        };
        let envelope = encrypt_ratchet_message(
            address(&identity),
            header,
            &[7u8; 32],
            None,
            crate::crypto::CURRENT_KEM_COMBINER,
            MessageKind::Text,
            b"hi",
            signing(&identity),
        )
        .unwrap();
        let json = serde_json::to_string(&envelope).unwrap();
        assert!(
            serde_json::from_str::<EnvelopeV1312>(&json).is_err(),
            "1.3.12 must refuse it (no hybrid ciphertext), not misread it"
        );
        // Here it verifies, and its AAD is the v2 one that binds the header.
        dual_verify(
            &envelope.sender_ed25519_public,
            &envelope.sender_mldsa_public,
            &message_signable(&envelope),
            &envelope.message_signature,
        )
        .unwrap();
        verify_aad_matches_envelope(&envelope).unwrap();
        assert_eq!(envelope.expected_aad(), envelope.aad);
        // An init must carry its seed, and nothing else may.
        let as_init = RatchetHeader { kind: HeaderKind::Init, ..envelope.ratchet.clone().unwrap() };
        assert!(encrypt_ratchet_message(
            address(&identity),
            as_init,
            &[7u8; 32],
            None,
            "",
            MessageKind::Text,
            b"hi",
            signing(&identity),
        )
        .is_err());
    }
}
