//! Recovery (roadmap Phase 5; design: `docs/superpowers/specs/2026-10-19-recovery-design.md`).
//!
//!   * Encrypted history backup (§2): the message-key ledger, sealed under the
//!     account's recovery key — restoring it makes the history still on the
//!     relay readable on a new device.
//!   * Social recovery (§3): the recovery key itself, recovered with the help
//!     of `k` of `n` verified contacts plus a PIN only the owner knows.
//!
//! Everything secret is made and opened here. The relay stores only sealed
//! shares, a wrapped recovery key it cannot open, and public request keys.

use std::collections::HashMap;

use base64::Engine as _;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tauri::State;
use zeroize::{Zeroize, Zeroizing};

use crate::commands::calls::{local_identity, CallPeerIdentity};
use crate::crypto::hybrid_kex::{decapsulate, encapsulate_bound, LocalKemKeypair};
use crate::crypto::kdf::{derive_32_with_salt, sha3_256};
use crate::crypto::passcode;
use crate::crypto::shamir::{self, Share, SECRET_LEN};
use crate::crypto::signatures::{dual_sign, dual_verify};
use crate::crypto::symmetric;
use crate::crypto::vault_recovery;
use crate::crypto::{DualSignature, EncryptedEnvelope, HybridCiphertext};
use crate::device_pins::DeviceStanding;
use crate::error::{QGuardError, Result};
use crate::state::AppState;

// ---------------------------------------------------------------------------
// The recovery key the caller types
// ---------------------------------------------------------------------------

/// The recovery root for a typed key, checked against what this device or the
/// account registry (`account_verifier`, read by the client from migration
/// 029's table) says the key is. Without either there is nothing to check
/// against, and nothing is sealed under an unchecked key.
fn checked_recovery_root(
    state: &AppState,
    user_id: &str,
    recovery_key: &str,
    account_verifier: Option<&str>,
) -> Result<Zeroizing<[u8; 32]>> {
    let root = Zeroizing::new(vault_recovery::decode_recovery_key(recovery_key)?);
    let verifier = vault_recovery::derive_verifier(&root)?;
    let local = state.load_vault_recovery_public(user_id).ok().flatten().map(|record| record.verifier);
    let expected: Vec<String> = local.into_iter().chain(account_verifier.map(str::to_string)).collect();
    if expected.is_empty() {
        return Err(QGuardError::NotFound(
            "set up a recovery key first (Quantum Vault → Recovery); it is what protects the backup".to_string(),
        ));
    }
    if !expected.iter().any(|candidate| candidate == &verifier) {
        return Err(QGuardError::Trust("that is not this account's recovery key".to_string()));
    }
    Ok(root)
}

// ---------------------------------------------------------------------------
// 5.3 History backup
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryBackupExport {
    pub file_b64: String,
    pub file_name: String,
    pub entries: usize,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryBackupImport {
    pub added: usize,
    pub already_held: usize,
}

fn export_history(state: &AppState, user_id: &str, recovery_key: &str, account_verifier: Option<&str>) -> Result<HistoryBackupExport> {
    let root = checked_recovery_root(state, user_id, recovery_key, account_verifier)?;
    // Everything opened so far is in the ledger; make sure it is all there.
    let _ = state.flush_message_keys(user_id);
    let (payload, entries) = state.with_message_keys(user_id, |ledger| {
        if !ledger.is_available() {
            return Err(QGuardError::Storage("the message key ledger on this device could not be opened".to_string()));
        }
        Ok((ledger.export_backup()?, ledger.len()))
    })??;
    let now = Utc::now();
    let file = crate::history_backup::seal(&root, user_id, &payload, now.timestamp())?;
    state.audit_info("history_backup_exported", &format!("Encrypted history backup made ({entries} message keys)"));
    Ok(HistoryBackupExport {
        file_b64: base64::engine::general_purpose::STANDARD.encode(file),
        file_name: format!("qguard-history-{}.qgbackup", now.format("%Y-%m-%d")),
        entries,
    })
}

fn import_history(
    state: &AppState,
    user_id: &str,
    recovery_key: &str,
    account_verifier: Option<&str>,
    file_b64: &str,
) -> Result<HistoryBackupImport> {
    let root = checked_recovery_root(state, user_id, recovery_key, account_verifier)?;
    let file = base64::engine::general_purpose::STANDARD
        .decode(file_b64.trim())
        .map_err(|_| QGuardError::InvalidInput("the backup file could not be read".to_string()))?;
    let payload = crate::history_backup::open(&root, user_id, &file)?;
    let (added, already_held) = state.with_message_keys(user_id, |ledger| ledger.import_backup(&payload))??;
    state.flush_message_keys(user_id)?;
    state.audit_info("history_backup_restored", &format!("History backup restored: {added} message keys added, {already_held} already held"));
    Ok(HistoryBackupImport { added, already_held })
}

#[tauri::command]
pub async fn history_backup_export(
    state: State<'_, AppState>,
    mut recovery_key: String,
    account_verifier: Option<String>,
) -> Result<HistoryBackupExport> {
    let session = state.require_auth()?;
    state.check_decrypt_rate_limit("history_backup", &session.user_id, 10, 300)?;
    let out = export_history(&state, &session.user_id, &recovery_key, account_verifier.as_deref());
    recovery_key.zeroize();
    out
}

#[tauri::command]
pub async fn history_backup_import(
    state: State<'_, AppState>,
    mut recovery_key: String,
    account_verifier: Option<String>,
    file_b64: String,
) -> Result<HistoryBackupImport> {
    let session = state.require_auth()?;
    state.check_decrypt_rate_limit("history_backup", &session.user_id, 10, 300)?;
    let out = import_history(&state, &session.user_id, &recovery_key, account_verifier.as_deref(), &file_b64);
    recovery_key.zeroize();
    out
}

// ---------------------------------------------------------------------------
// 5.1 Social recovery
// ---------------------------------------------------------------------------

const SOCIAL_VERSION: u8 = 1;
const WRAP_INFO: &[u8] = b"QGuard-SocialRecovery-Wrap-v1";
const SHARE_KEM_INFO: &str = "QGuard-SocialRecovery-v1:share:";
const RELEASE_KEM_INFO: &str = "QGuard-SocialRecovery-v1:release:";
const SHARE_SEAL_INFO: &[u8] = b"QGuard-SocialRecovery-ShareSeal-v1";
const GUARDIAN_DOC: &str = "guardian-shares";
const GUARDIAN_DOC_AAD: &[u8] = b"QGuard-Messaging-Guardian-Shares-v1";
const REQUEST_DOC: &str = "recovery-request";
const REQUEST_DOC_AAD: &[u8] = b"QGuard-Messaging-Recovery-Request-v1";
/// A request older than this is not approved.
const REQUEST_MAX_AGE_SECS: i64 = 7 * 24 * 3600;
const MIN_PIN_CHARS: usize = 6;

/// The owner's published recovery record (stored by the client in
/// `messaging_social_recovery`, migration 038). Holds nothing secret.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SocialRecoveryRecord {
    pub v: u8,
    pub setup_id: String,
    pub threshold: u8,
    pub share_count: u8,
    pub salt_b64: String,
    /// The recovery root, under HKDF(S ‖ Argon2id(PIN)). Nobody can open it
    /// without k shares AND the PIN.
    pub wrapped_root: EncryptedEnvelope,
    pub guardians: Vec<GuardianRef>,
    pub created_at: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GuardianRef {
    pub user_id: String,
    pub device_id: String,
    pub x: u8,
}

/// One share, sealed to one guardian device and signed by the owner's device.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShareOffer {
    pub v: u8,
    pub setup_id: String,
    pub owner_user_id: String,
    pub owner_device_id: String,
    pub guardian_user_id: String,
    pub guardian_device_id: String,
    pub x: u8,
    pub threshold: u8,
    pub share_count: u8,
    pub created_at: i64,
    pub ciphertext: HybridCiphertext,
    pub sealed: EncryptedEnvelope,
    pub signature: DualSignature,
}

/// A new device's request for help, with a fresh hybrid key the shares are
/// re-sealed to. Signed by that device's identity.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryRequest {
    pub v: u8,
    pub request_id: String,
    pub user_id: String,
    pub device_id: String,
    pub x25519_public: Vec<u8>,
    pub mlkem_public: Vec<u8>,
    pub created_at: i64,
    pub signature: DualSignature,
}

/// A guardian's share, re-sealed to a request and signed by the guardian.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShareRelease {
    pub v: u8,
    pub request_id: String,
    pub setup_id: String,
    pub owner_user_id: String,
    pub guardian_user_id: String,
    pub guardian_device_id: String,
    pub x: u8,
    pub created_at: i64,
    pub ciphertext: HybridCiphertext,
    pub sealed: EncryptedEnvelope,
    pub signature: DualSignature,
}

#[derive(Clone, Serialize, Deserialize)]
struct HeldShare {
    setup_id: String,
    owner_device_id: String,
    x: u8,
    y: [u8; SECRET_LEN],
    threshold: u8,
    share_count: u8,
    received_at: i64,
}

impl Drop for HeldShare {
    fn drop(&mut self) {
        self.y.zeroize();
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HeldShareSummary {
    pub owner_user_id: String,
    pub setup_id: String,
    pub threshold: u8,
    pub share_count: u8,
    pub received_at: i64,
}

#[derive(Serialize, Deserialize)]
struct PendingRequest {
    request: RecoveryRequest,
    keypair: LocalKemKeypair,
}

fn push_field(out: &mut Vec<u8>, field: &[u8]) {
    out.extend_from_slice(&(field.len() as u32).to_be_bytes());
    out.extend_from_slice(field);
}

fn framed(context: &[u8], fields: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    push_field(&mut out, context);
    for field in fields {
        push_field(&mut out, field);
    }
    out
}

fn ciphertext_digest(ciphertext: &HybridCiphertext) -> [u8; 32] {
    sha3_256(&framed(b"ct", &[&ciphertext.x25519_ephemeral_public, &ciphertext.ml_kem_ciphertext, ciphertext.suite.kem_combiner.as_bytes()]))
}

fn offer_header(offer: &ShareOffer) -> Vec<u8> {
    framed(
        b"QGuard-SocialRecovery-ShareOffer-v1",
        &[
            &[offer.v, offer.x, offer.threshold, offer.share_count],
            offer.setup_id.as_bytes(),
            offer.owner_user_id.as_bytes(),
            offer.owner_device_id.as_bytes(),
            offer.guardian_user_id.as_bytes(),
            offer.guardian_device_id.as_bytes(),
            &offer.created_at.to_be_bytes(),
        ],
    )
}

fn offer_signable(offer: &ShareOffer) -> Vec<u8> {
    let mut out = offer_header(offer);
    push_field(&mut out, &ciphertext_digest(&offer.ciphertext));
    push_field(&mut out, &offer.sealed.nonce);
    push_field(&mut out, &offer.sealed.ciphertext);
    push_field(&mut out, &offer.sealed.tag);
    out
}

fn request_signable(request: &RecoveryRequest) -> Vec<u8> {
    framed(
        b"QGuard-SocialRecovery-Request-v1",
        &[
            &[request.v],
            request.request_id.as_bytes(),
            request.user_id.as_bytes(),
            request.device_id.as_bytes(),
            &request.x25519_public,
            &request.mlkem_public,
            &request.created_at.to_be_bytes(),
        ],
    )
}

fn release_header(release: &ShareRelease) -> Vec<u8> {
    framed(
        b"QGuard-SocialRecovery-Release-v1",
        &[
            &[release.v, release.x],
            release.request_id.as_bytes(),
            release.setup_id.as_bytes(),
            release.owner_user_id.as_bytes(),
            release.guardian_user_id.as_bytes(),
            release.guardian_device_id.as_bytes(),
            &release.created_at.to_be_bytes(),
        ],
    )
}

fn release_signable(release: &ShareRelease) -> Vec<u8> {
    let mut out = release_header(release);
    push_field(&mut out, &ciphertext_digest(&release.ciphertext));
    push_field(&mut out, &release.sealed.nonce);
    push_field(&mut out, &release.sealed.ciphertext);
    push_field(&mut out, &release.sealed.tag);
    out
}

/// Four words both people compare before a guardian releases a share: proof,
/// out of band, that the request on the guardian's screen is the one the owner
/// just made — a relay inventing a request cannot match the owner's screen.
pub fn request_code(request: &RecoveryRequest) -> Vec<String> {
    let digest = sha3_256(&request_signable(request));
    let mut bits: u64 = 0;
    for byte in digest.iter().take(5) {
        bits = (bits << 8) | u64::from(*byte);
    }
    let words = crate::commands::contact_verification::words();
    (0..4).map(|index| words[((bits >> (30 - 10 * index)) & 0x3ff) as usize].to_string()).collect()
}

fn wrap_key(salt: &[u8], secret: &[u8; SECRET_LEN], pin: &str) -> Result<Zeroizing<[u8; 32]>> {
    let mut stretched = passcode::argon2id_prehash(salt, pin.as_bytes())?;
    let mut ikm = Zeroizing::new(Vec::with_capacity(64));
    ikm.extend_from_slice(secret);
    ikm.extend_from_slice(&stretched);
    stretched.zeroize();
    derive_32_with_salt(salt, &ikm, WRAP_INFO).map(Zeroizing::new)
}

fn root_aad(user_id: &str, setup_id: &str) -> Vec<u8> {
    format!("QGuard-SocialRecovery-Root-v1|{user_id}|{setup_id}").into_bytes()
}

fn seal_share(peer_x25519: &[u8], peer_mlkem: &[u8], kem_info: &str, y: &[u8; SECRET_LEN], aad: &[u8]) -> Result<(HybridCiphertext, EncryptedEnvelope)> {
    let (ciphertext, secret) = encapsulate_bound(peer_x25519, peer_mlkem, kem_info.as_bytes())?;
    let secret = Zeroizing::new(secret);
    let key = Zeroizing::new(crate::crypto::kdf::derive_32(&*secret, SHARE_SEAL_INFO)?);
    let sealed = symmetric::encrypt(&key, y, aad)?;
    Ok((ciphertext, sealed))
}

fn open_share(
    x25519_secret: &[u8; 32],
    mlkem_secret: &[u8],
    ciphertext: &HybridCiphertext,
    kem_info: &str,
    sealed: &EncryptedEnvelope,
    aad: &[u8],
) -> Result<Zeroizing<[u8; SECRET_LEN]>> {
    let secret = Zeroizing::new(decapsulate(x25519_secret, mlkem_secret, ciphertext, kem_info.as_bytes())?);
    let key = Zeroizing::new(crate::crypto::kdf::derive_32(&*secret, SHARE_SEAL_INFO)?);
    let mut plain = symmetric::decrypt(&key, sealed, aad)?;
    let out: [u8; SECRET_LEN] = plain
        .as_slice()
        .try_into()
        .map_err(|_| QGuardError::Crypto("a recovery share has the wrong length".to_string()))?;
    plain.zeroize();
    Ok(Zeroizing::new(out))
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SocialRecoverySetup {
    pub record: SocialRecoveryRecord,
    pub offers: Vec<ShareOffer>,
}

fn setup_social_recovery(
    state: &AppState,
    recovery_key: &str,
    account_verifier: Option<&str>,
    pin: &str,
    threshold: u8,
    guardians: &[CallPeerIdentity],
) -> Result<SocialRecoverySetup> {
    let identity = local_identity(state)?;
    let root = checked_recovery_root(state, &identity.user_id, recovery_key, account_verifier)?;
    if pin.chars().count() < MIN_PIN_CHARS {
        return Err(QGuardError::InvalidInput(format!("the recovery PIN must be at least {MIN_PIN_CHARS} characters")));
    }
    let share_count = u8::try_from(guardians.len()).map_err(|_| QGuardError::InvalidInput("too many helpers".to_string()))?;
    for (index, guardian) in guardians.iter().enumerate() {
        guardian.verify()?;
        if guardian.user_id == identity.user_id {
            return Err(QGuardError::InvalidInput("helpers must be other people".to_string()));
        }
        if guardians[..index].iter().any(|other| other.device_id == guardian.device_id) {
            return Err(QGuardError::InvalidInput("the same device was chosen twice".to_string()));
        }
        // Only devices the user has verified (Phase 3): the shares go to the
        // devices they checked, not to whatever the directory lists.
        let subject = guardian.pin_subject();
        let verified = state
            .with_device_pins(&identity.user_id, |book| (book.standing(&subject), book.verification(&subject)))?;
        match verified {
            (Some(DeviceStanding::Pinned), Some(view)) if view.verified.is_some() => {}
            _ => {
                return Err(QGuardError::Trust(format!(
                    "device {} is not a verified contact device; verify that contact first",
                    guardian.device_id
                )))
            }
        }
    }
    let mut secret = Zeroizing::new([0u8; SECRET_LEN]);
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, secret.as_mut());
    let shares = shamir::split(&secret, threshold, share_count)?;
    let salt = passcode::random_salt();
    let setup_id = {
        let mut id = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut id);
        hex::encode(id)
    };
    let key = wrap_key(&salt, &secret, pin)?;
    let wrapped_root = symmetric::encrypt(&key, root.as_slice(), &root_aad(&identity.user_id, &setup_id))?;
    let now = Utc::now().timestamp();

    let mut offers = Vec::with_capacity(shares.len());
    let mut refs = Vec::with_capacity(shares.len());
    for (guardian, share) in guardians.iter().zip(shares.iter()) {
        let mut offer = ShareOffer {
            v: SOCIAL_VERSION,
            setup_id: setup_id.clone(),
            owner_user_id: identity.user_id.clone(),
            owner_device_id: identity.device_id.clone(),
            guardian_user_id: guardian.user_id.clone(),
            guardian_device_id: guardian.device_id.clone(),
            x: share.x,
            threshold,
            share_count,
            created_at: now,
            ciphertext: HybridCiphertext {
                x25519_ephemeral_public: Vec::new(),
                ml_kem_ciphertext: Vec::new(),
                suite: crate::crypto::AlgorithmSuite::default(),
            },
            sealed: EncryptedEnvelope { nonce: Vec::new(), ciphertext: Vec::new(), tag: Vec::new() },
            signature: DualSignature { ed25519: Vec::new(), ml_dsa_65: Vec::new() },
        };
        let info = format!("{SHARE_KEM_INFO}{setup_id}:{}", guardian.device_id);
        let (ciphertext, sealed) = seal_share(&guardian.x25519_identity_public, &guardian.mlkem_identity_public, &info, &share.y, &offer_header(&offer))?;
        offer.ciphertext = ciphertext;
        offer.sealed = sealed;
        offer.signature = dual_sign(&identity.signing.ed25519_secret, &identity.signing.mldsa_secret, &offer_signable(&offer))?;
        refs.push(GuardianRef { user_id: guardian.user_id.clone(), device_id: guardian.device_id.clone(), x: share.x });
        offers.push(offer);
    }
    state.audit_info(
        "social_recovery_configured",
        &format!("Social recovery set up: any {threshold} of {share_count} verified contacts plus the recovery PIN"),
    );
    Ok(SocialRecoverySetup {
        record: SocialRecoveryRecord {
            v: SOCIAL_VERSION,
            setup_id,
            threshold,
            share_count,
            salt_b64: base64::engine::general_purpose::STANDARD.encode(&salt),
            wrapped_root,
            guardians: refs,
            created_at: now,
        },
        offers,
    })
}

fn load_held(state: &AppState, user_id: &str) -> Result<HashMap<String, HeldShare>> {
    match state.load_user_secret_doc(user_id, GUARDIAN_DOC, GUARDIAN_DOC_AAD, "recovery shares held")? {
        None => Ok(HashMap::new()),
        Some(bytes) => serde_json::from_slice(&bytes).map_err(|e| QGuardError::Storage(format!("recovery shares held: {e}"))),
    }
}

fn save_held(state: &AppState, user_id: &str, held: &HashMap<String, HeldShare>) -> Result<()> {
    let bytes = Zeroizing::new(serde_json::to_vec(held).map_err(|e| QGuardError::Storage(format!("recovery shares held: {e}")))?);
    state.save_user_secret_doc(user_id, GUARDIAN_DOC, GUARDIAN_DOC_AAD, &bytes, "recovery shares held")
}

/// Guardian side: accept and keep a share someone sealed to this device.
fn hold_share(state: &AppState, offer: &ShareOffer, owner: &CallPeerIdentity) -> Result<HeldShareSummary> {
    if offer.v != SOCIAL_VERSION {
        return Err(QGuardError::InvalidInput("unsupported recovery share version".to_string()));
    }
    let identity = local_identity(state)?;
    owner.verify()?;
    if offer.owner_user_id != owner.user_id || offer.owner_device_id != owner.device_id {
        return Err(QGuardError::Trust("recovery share does not come from the device it names".to_string()));
    }
    if offer.guardian_user_id != identity.user_id || offer.guardian_device_id != identity.device_id {
        return Err(QGuardError::Trust("recovery share was made for another device".to_string()));
    }
    dual_verify(&owner.ed25519_identity_public, &owner.mldsa_identity_public, &offer_signable(offer), &offer.signature)
        .map_err(|_| QGuardError::Trust("recovery share signature does not verify".to_string()))?;
    // Held only for a device this device has recorded for that person.
    if state.device_standing(&identity.user_id, &owner.pin_subject()) != Some(DeviceStanding::Pinned) {
        return Err(QGuardError::Trust("the sending device is not one recorded for that contact".to_string()));
    }
    let info = format!("{SHARE_KEM_INFO}{}:{}", offer.setup_id, offer.guardian_device_id);
    let y = open_share(&identity.kem.x25519_secret, &identity.kem.mlkem_secret, &offer.ciphertext, &info, &offer.sealed, &offer_header(offer))?;
    let mut held = load_held(state, &identity.user_id)?;
    if held.get(&offer.owner_user_id).is_some_and(|existing| existing.received_at > offer.created_at) {
        return Err(QGuardError::Replay("an older recovery share than the one already held".to_string()));
    }
    held.insert(
        offer.owner_user_id.clone(),
        HeldShare {
            setup_id: offer.setup_id.clone(),
            owner_device_id: offer.owner_device_id.clone(),
            x: offer.x,
            y: *y,
            threshold: offer.threshold,
            share_count: offer.share_count,
            received_at: offer.created_at,
        },
    );
    save_held(state, &identity.user_id, &held)?;
    state.audit_info("social_recovery_share_held", "Holding a recovery share for a contact");
    Ok(HeldShareSummary {
        owner_user_id: offer.owner_user_id.clone(),
        setup_id: offer.setup_id.clone(),
        threshold: offer.threshold,
        share_count: offer.share_count,
        received_at: offer.created_at,
    })
}

fn held_summaries(state: &AppState) -> Result<Vec<HeldShareSummary>> {
    let user_id = state.user_id()?;
    let mut out: Vec<HeldShareSummary> = load_held(state, &user_id)?
        .into_iter()
        .map(|(owner_user_id, share)| HeldShareSummary {
            owner_user_id,
            setup_id: share.setup_id.clone(),
            threshold: share.threshold,
            share_count: share.share_count,
            received_at: share.received_at,
        })
        .collect();
    out.sort_by(|a, b| a.owner_user_id.cmp(&b.owner_user_id));
    Ok(out)
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryRequestView {
    pub request: RecoveryRequest,
    pub code: Vec<String>,
}

/// New device: make (or return the pending) request for help.
fn create_request(state: &AppState) -> Result<RecoveryRequestView> {
    let identity = local_identity(state)?;
    if let Some(bytes) = state.load_user_secret_doc(&identity.user_id, REQUEST_DOC, REQUEST_DOC_AAD, "recovery request")? {
        if let Ok(pending) = serde_json::from_slice::<PendingRequest>(&bytes) {
            if Utc::now().timestamp() - pending.request.created_at < REQUEST_MAX_AGE_SECS && pending.request.device_id == identity.device_id {
                let code = request_code(&pending.request);
                return Ok(RecoveryRequestView { request: pending.request, code });
            }
        }
    }
    let keypair = LocalKemKeypair::generate();
    let mut id = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut id);
    let mut request = RecoveryRequest {
        v: SOCIAL_VERSION,
        request_id: hex::encode(id),
        user_id: identity.user_id.clone(),
        device_id: identity.device_id.clone(),
        x25519_public: keypair.x25519_public.clone(),
        mlkem_public: keypair.mlkem_public.clone(),
        created_at: Utc::now().timestamp(),
        signature: DualSignature { ed25519: Vec::new(), ml_dsa_65: Vec::new() },
    };
    request.signature = dual_sign(&identity.signing.ed25519_secret, &identity.signing.mldsa_secret, &request_signable(&request))?;
    let pending = PendingRequest { request: request.clone(), keypair };
    let bytes = Zeroizing::new(serde_json::to_vec(&pending).map_err(|e| QGuardError::Storage(format!("recovery request: {e}")))?);
    state.save_user_secret_doc(&identity.user_id, REQUEST_DOC, REQUEST_DOC_AAD, &bytes, "recovery request")?;
    state.audit_info("social_recovery_requested", "Asked contacts for help recovering the recovery key");
    let code = request_code(&request);
    Ok(RecoveryRequestView { request, code })
}

/// Guardian side: after confirming the code with the owner out of band,
/// re-seal the held share to the request's key.
fn release_share(state: &AppState, request: &RecoveryRequest, requester: &CallPeerIdentity) -> Result<ShareRelease> {
    if request.v != SOCIAL_VERSION {
        return Err(QGuardError::InvalidInput("unsupported recovery request version".to_string()));
    }
    let identity = local_identity(state)?;
    requester.verify()?;
    if request.user_id != requester.user_id || request.device_id != requester.device_id {
        return Err(QGuardError::Trust("recovery request does not come from the device it names".to_string()));
    }
    dual_verify(&requester.ed25519_identity_public, &requester.mldsa_identity_public, &request_signable(request), &request.signature)
        .map_err(|_| QGuardError::Trust("recovery request signature does not verify".to_string()))?;
    if Utc::now().timestamp() - request.created_at > REQUEST_MAX_AGE_SECS {
        return Err(QGuardError::Replay("this recovery request has expired; ask them to make a new one".to_string()));
    }
    let held = load_held(state, &identity.user_id)?;
    let share = held
        .get(&request.user_id)
        .ok_or_else(|| QGuardError::NotFound("this device holds no recovery share for that person".to_string()))?;
    let mut release = ShareRelease {
        v: SOCIAL_VERSION,
        request_id: request.request_id.clone(),
        setup_id: share.setup_id.clone(),
        owner_user_id: request.user_id.clone(),
        guardian_user_id: identity.user_id.clone(),
        guardian_device_id: identity.device_id.clone(),
        x: share.x,
        created_at: Utc::now().timestamp(),
        ciphertext: HybridCiphertext {
            x25519_ephemeral_public: Vec::new(),
            ml_kem_ciphertext: Vec::new(),
            suite: crate::crypto::AlgorithmSuite::default(),
        },
        sealed: EncryptedEnvelope { nonce: Vec::new(), ciphertext: Vec::new(), tag: Vec::new() },
        signature: DualSignature { ed25519: Vec::new(), ml_dsa_65: Vec::new() },
    };
    let info = format!("{RELEASE_KEM_INFO}{}:{}", request.request_id, identity.device_id);
    let (ciphertext, sealed) = seal_share(&request.x25519_public, &request.mlkem_public, &info, &share.y, &release_header(&release))?;
    release.ciphertext = ciphertext;
    release.sealed = sealed;
    release.signature = dual_sign(&identity.signing.ed25519_secret, &identity.signing.mldsa_secret, &release_signable(&release))?;
    state.audit_info("social_recovery_share_released", "Released a recovery share to a contact's confirmed request");
    Ok(release)
}

/// New device: rebuild the recovery key from k releases and the PIN. Returns
/// the recovery key, encoded as the user knows it.
fn finish_recovery(
    state: &AppState,
    record: &SocialRecoveryRecord,
    releases: &[ShareRelease],
    guardians: &[CallPeerIdentity],
    pin: &str,
) -> Result<String> {
    let identity = local_identity(state)?;
    let bytes = state
        .load_user_secret_doc(&identity.user_id, REQUEST_DOC, REQUEST_DOC_AAD, "recovery request")?
        .ok_or_else(|| QGuardError::NotFound("no recovery request is pending on this device".to_string()))?;
    let pending: PendingRequest = serde_json::from_slice(&bytes).map_err(|e| QGuardError::Storage(format!("recovery request: {e}")))?;
    let mut shares: Vec<Share> = Vec::new();
    for release in releases {
        // Only releases for THIS request and setup, from a device the record
        // names at the x it was given, signed by that device's keys.
        if release.request_id != pending.request.request_id || release.setup_id != record.setup_id || release.owner_user_id != identity.user_id {
            continue;
        }
        let Some(listed) = record.guardians.iter().find(|g| g.device_id == release.guardian_device_id && g.user_id == release.guardian_user_id) else {
            continue;
        };
        if listed.x != release.x || shares.iter().any(|share| share.x == release.x) {
            continue;
        }
        let Some(guardian) = guardians.iter().find(|g| g.device_id == release.guardian_device_id && g.user_id == release.guardian_user_id) else {
            continue;
        };
        if guardian.verify().is_err()
            || dual_verify(&guardian.ed25519_identity_public, &guardian.mldsa_identity_public, &release_signable(release), &release.signature).is_err()
        {
            continue;
        }
        let info = format!("{RELEASE_KEM_INFO}{}:{}", release.request_id, release.guardian_device_id);
        let Ok(y) = open_share(&pending.keypair.x25519_secret, &pending.keypair.mlkem_secret, &release.ciphertext, &info, &release.sealed, &release_header(release)) else {
            continue;
        };
        shares.push(Share { x: release.x, y: *y });
        if shares.len() == usize::from(record.threshold) {
            break;
        }
    }
    if shares.len() < usize::from(record.threshold) {
        return Err(QGuardError::NotFound(format!(
            "{} of the {} shares needed have arrived",
            shares.len(),
            record.threshold
        )));
    }
    let secret = shamir::combine(&shares)?;
    let salt = base64::engine::general_purpose::STANDARD
        .decode(&record.salt_b64)
        .map_err(|_| QGuardError::InvalidInput("recovery record salt is malformed".to_string()))?;
    let key = wrap_key(&salt, &secret, pin)?;
    let mut root_bytes = symmetric::decrypt(&key, &record.wrapped_root, &root_aad(&identity.user_id, &record.setup_id))
        .map_err(|_| QGuardError::Trust("the recovery PIN is wrong (or a share was not genuine)".to_string()))?;
    let root: [u8; 32] = root_bytes
        .as_slice()
        .try_into()
        .map_err(|_| QGuardError::Crypto("recovered key has the wrong length".to_string()))?;
    root_bytes.zeroize();
    let root = Zeroizing::new(root);
    let encoded = vault_recovery::encode_recovery_key(&root);
    state.delete_user_secret_doc(&identity.user_id, REQUEST_DOC);
    state.audit_info("social_recovery_completed", "Recovery key rebuilt with help from contacts");
    Ok(encoded)
}

#[tauri::command]
pub async fn social_recovery_setup(
    state: State<'_, AppState>,
    mut recovery_key: String,
    account_verifier: Option<String>,
    mut pin: String,
    threshold: u8,
    guardians: Vec<CallPeerIdentity>,
) -> Result<SocialRecoverySetup> {
    let session = state.require_auth()?;
    state.check_decrypt_rate_limit("social_recovery", &session.user_id, 10, 300)?;
    let _key_scope = state.lock_key_scope()?;
    let out = setup_social_recovery(&state, &recovery_key, account_verifier.as_deref(), &pin, threshold, &guardians);
    recovery_key.zeroize();
    pin.zeroize();
    out
}

#[tauri::command]
pub async fn social_recovery_hold_share(state: State<'_, AppState>, offer: ShareOffer, owner: CallPeerIdentity) -> Result<HeldShareSummary> {
    state.require_auth()?;
    let _key_scope = state.lock_key_scope()?;
    hold_share(&state, &offer, &owner)
}

#[tauri::command]
pub fn social_recovery_held(state: State<'_, AppState>) -> Result<Vec<HeldShareSummary>> {
    state.require_auth()?;
    held_summaries(&state)
}

#[tauri::command]
pub async fn social_recovery_request(state: State<'_, AppState>) -> Result<RecoveryRequestView> {
    state.require_auth()?;
    let _key_scope = state.lock_key_scope()?;
    create_request(&state)
}

#[tauri::command]
pub fn social_recovery_request_code(request: RecoveryRequest) -> Vec<String> {
    request_code(&request)
}

#[tauri::command]
pub async fn social_recovery_release(
    state: State<'_, AppState>,
    request: RecoveryRequest,
    requester: CallPeerIdentity,
) -> Result<ShareRelease> {
    let session = state.require_auth()?;
    state.check_decrypt_rate_limit("social_recovery_release", &session.user_id, 10, 300)?;
    let _key_scope = state.lock_key_scope()?;
    release_share(&state, &request, &requester)
}

#[tauri::command]
pub async fn social_recovery_finish(
    state: State<'_, AppState>,
    record: SocialRecoveryRecord,
    releases: Vec<ShareRelease>,
    guardians: Vec<CallPeerIdentity>,
    mut pin: String,
) -> Result<String> {
    let session = state.require_auth()?;
    // The PIN is the factor guardians do not have: few tries.
    state.check_decrypt_rate_limit("social_recovery_finish", &session.user_id, 5, 900)?;
    let _key_scope = state.lock_key_scope()?;
    let out = finish_recovery(&state, &record, &releases, &guardians, &pin);
    pin.zeroize();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::contact_verification::verify_each_other_for_test;
    use crate::test_support::TestDevice;

    /// Give `device` a recovery key and return it.
    fn with_recovery_key(device: &TestDevice) -> String {
        let root = vault_recovery::generate_recovery_root();
        let verifier = vault_recovery::derive_verifier(&root).unwrap();
        device.state.test_install_recovery_verifier(&device.user, &verifier);
        vault_recovery::encode_recovery_key(&root)
    }

    #[test]
    fn a_history_backup_restores_message_keys_on_a_new_device_of_the_same_account() {
        let old = TestDevice::new(false);
        let key = with_recovery_key(&old);
        old.state.remember_message_key(&old.user, "m1", &[1; 12], &[2; 16], &[3; 32]);
        old.state.remember_message_key(&old.user, "m2", &[4; 12], &[5; 16], &[6; 32]);
        let exported = export_history(&old.state, &old.user, &key, None).unwrap();
        assert_eq!(exported.entries, 2);
        assert!(exported.file_name.ends_with(".qgbackup"));

        // A wrong key is refused before anything is sealed.
        let other_key = vault_recovery::encode_recovery_key(&vault_recovery::generate_recovery_root());
        assert!(export_history(&old.state, &old.user, &other_key, None).is_err());

        // The same account on a brand-new device (same user, fresh data dir):
        // it has no local recovery record, so the account verifier is used.
        let verifier = vault_recovery::derive_verifier(&vault_recovery::decode_recovery_key(&key).unwrap()).unwrap();
        let fresh = TestDevice::open(
            std::env::temp_dir().join(format!("qguard-restore-{}", uuid::Uuid::new_v4())),
            old.user.clone(),
        );
        assert!(fresh.state.cached_message_key(&fresh.user, "m1", &[1; 12], &[2; 16]).is_none());
        assert!(import_history(&fresh.state, &fresh.user, &key, None, &exported.file_b64).is_err(), "nothing to check the key against");
        let restored = import_history(&fresh.state, &fresh.user, &key, Some(&verifier), &exported.file_b64).unwrap();
        assert_eq!((restored.added, restored.already_held), (2, 0));
        assert_eq!(fresh.state.cached_message_key(&fresh.user, "m1", &[1; 12], &[2; 16]), Some([3; 32]));
        // Importing again changes nothing; another account cannot load it.
        let again = import_history(&fresh.state, &fresh.user, &key, Some(&verifier), &exported.file_b64).unwrap();
        assert_eq!((again.added, again.already_held), (0, 2));
        let stranger = TestDevice::new(false);
        assert!(import_history(&stranger.state, &stranger.user, &key, Some(&verifier), &exported.file_b64).is_err());
        let fresh_dir = fresh.dir.clone();
        drop(fresh);
        let _ = std::fs::remove_dir_all(fresh_dir);
    }

    #[test]
    fn three_contacts_and_the_pin_rebuild_the_recovery_key_and_nothing_less_does() {
        let owner = TestDevice::new(false);
        let key = with_recovery_key(&owner);
        let guardians: Vec<TestDevice> = (0..3).map(|_| TestDevice::new(false)).collect();
        for guardian in &guardians {
            verify_each_other_for_test(&owner, guardian);
        }
        let peers: Vec<CallPeerIdentity> = guardians.iter().map(TestDevice::call_peer).collect();

        // Refusals first: weak PIN, unverified helper, k > n.
        assert!(setup_social_recovery(&owner.state, &key, None, "123", 2, &peers).is_err());
        let stranger = TestDevice::new(false);
        let mut with_stranger = peers.clone();
        with_stranger.push(stranger.call_peer());
        assert!(setup_social_recovery(&owner.state, &key, None, "correct horse", 2, &with_stranger).is_err());
        assert!(setup_social_recovery(&owner.state, &key, None, "correct horse", 4, &peers).is_err());

        let setup = setup_social_recovery(&owner.state, &key, None, "correct horse", 2, &peers).unwrap();
        assert_eq!(setup.offers.len(), 3);
        for (guardian, offer) in guardians.iter().zip(&setup.offers) {
            // A share sealed to one guardian cannot be held by another.
            let wrong = guardians.iter().find(|g| g.device_id != guardian.device_id).unwrap();
            assert!(hold_share(&wrong.state, offer, &owner.call_peer()).is_err());
            let mut tampered = offer.clone();
            tampered.threshold = 1;
            assert!(hold_share(&guardian.state, &tampered, &owner.call_peer()).is_err());
            hold_share(&guardian.state, offer, &owner.call_peer()).unwrap();
            assert_eq!(held_summaries(&guardian.state).unwrap()[0].owner_user_id, owner.user);
        }

        // Every device is lost. The owner signs in on a new one.
        let new_device = TestDevice::open(
            std::env::temp_dir().join(format!("qguard-recover-{}", uuid::Uuid::new_v4())),
            owner.user.clone(),
        );
        let view = create_request(&new_device.state).unwrap();
        assert_eq!(view.code.len(), 4);
        assert_eq!(create_request(&new_device.state).unwrap().request.request_id, view.request.request_id, "a pending request is reused");
        // A guardian's code matches the owner's (they compare it out of band).
        assert_eq!(request_code(&view.request), view.code);

        let releases: Vec<ShareRelease> = guardians
            .iter()
            .map(|guardian| release_share(&guardian.state, &view.request, &new_device.call_peer()).unwrap())
            .collect();
        // A forged request (relay-made, other keys) is refused by a guardian.
        let mut forged = view.request.clone();
        forged.x25519_public[0] ^= 1;
        assert!(release_share(&guardians[0].state, &forged, &new_device.call_peer()).is_err());

        // One share is not enough; the wrong PIN fails; two plus the PIN works.
        assert!(finish_recovery(&new_device.state, &setup.record, &releases[..1], &peers, "correct horse").is_err());
        assert!(finish_recovery(&new_device.state, &setup.record, &releases[..2], &peers, "wrong horse").is_err());
        let recovered = finish_recovery(&new_device.state, &setup.record, &releases[1..], &peers, "correct horse").unwrap();
        assert_eq!(recovered, key, "the very same recovery key comes back");
        // The request is consumed.
        assert!(finish_recovery(&new_device.state, &setup.record, &releases, &peers, "correct horse").is_err());
        let dir = new_device.dir.clone();
        drop(new_device);
        let _ = std::fs::remove_dir_all(dir);
    }
}
