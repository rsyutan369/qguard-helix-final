use chrono::Utc;
use serde::Serialize;
use tauri::State;

use crate::crypto::AlgorithmSuite;
use crate::error::{QGuardError, Result};
use crate::identity::{PublicIdentityBundle, platform_device_label};
use crate::prekeys::{generate_one_time_prekeys, PublicOneTimePrekey, PublicSignedPrekey};
use crate::state::AppState;

// One-time prekey pool caps. The active pool keeps every key that may still be
// referenced by an in-flight X3DH message; once it grows past the cap the
// oldest keys are retired into the legacy pool (still able to decrypt) instead
// of being dropped, and the legacy pool itself is bounded so key material on
// disk cannot grow without limit.
const ONE_TIME_PREKEY_ACTIVE_CAP: usize = 96;
const ONE_TIME_PREKEY_LEGACY_CAP: usize = 192;
const ONE_TIME_PREKEY_REPLENISH_MAX: u32 = 64;

#[derive(Clone, Debug, Serialize)]
pub struct PrivateKeyUnlockStatus {
    pub unlocked: bool,
    pub device_id: String,
    pub fingerprint: String,
    pub storage: String,
    pub suite: AlgorithmSuite,
    pub private_key_exported: bool,
}

#[tauri::command]
pub fn keys_unlock_private_key(
    state: State<'_, AppState>,
    user_id: Option<String>,
) -> Result<PrivateKeyUnlockStatus> {
    let session_user_id = state.resolve_user_id(user_id)?;
    state.check_decrypt_rate_limit("key_unlock", &session_user_id, 12, 300)?;
    let _key_scope = state.lock_key_scope()?;
    let identity = state.ensure_identity(&session_user_id, platform_device_label())?;
    state.audit_info(
        "keys_unlock_private_key",
        "Device-bound private key unlocked locally for decryption",
    );
    state.touch_telemetry(
        "key",
        "Device-bound private key unlocked; no private key bytes exported",
        100,
    );
    Ok(PrivateKeyUnlockStatus {
        unlocked: true,
        device_id: identity.device_id,
        fingerprint: identity.fingerprint,
        storage: "OS keychain / device-bound secure storage".to_string(),
        suite: identity.suite,
        private_key_exported: false,
    })
}

#[tauri::command]
pub fn keys_upload_identity_bundle(
    state: State<'_, AppState>,
    user_id: Option<String>,
) -> Result<PublicIdentityBundle> {
    let session_user_id = state.resolve_user_id(user_id)?;
    let _key_scope = state.lock_key_scope()?;
    let bundle = state.ensure_identity(&session_user_id, platform_device_label())?;
    state.audit_info(
        "keys_upload_identity",
        "Public identity bundle prepared for Supabase relay",
    );
    Ok(bundle)
}

#[tauri::command]
pub fn keys_upload_signed_prekey(
    state: State<'_, AppState>,
    user_id: Option<String>,
) -> Result<PublicSignedPrekey> {
    let session_user_id = state.resolve_user_id(user_id)?;
    let _key_scope = state.lock_key_scope()?;
    state.ensure_identity(&session_user_id, platform_device_label())?;
    let prekey = state
        .signed_prekey
        .lock()
        .map_err(|_| QGuardError::Storage("signed prekey lock poisoned".to_string()))?
        .as_ref()
        .map(|p| p.public.clone())
        .ok_or_else(|| QGuardError::NotFound("signed prekey".to_string()))?;
    Ok(prekey)
}

#[tauri::command]
pub fn keys_upload_one_time_prekeys(
    state: State<'_, AppState>,
    user_id: Option<String>,
) -> Result<Vec<PublicOneTimePrekey>> {
    let session_user_id = state.resolve_user_id(user_id)?;
    let _key_scope = state.lock_key_scope()?;
    state.ensure_identity(&session_user_id, platform_device_label())?;
    let prekeys = state
        .one_time_prekeys
        .lock()
        .map_err(|_| QGuardError::Storage("one-time prekey lock poisoned".to_string()))?
        .iter()
        .map(|p| p.public.clone())
        .collect();
    Ok(prekeys)
}

/// Generate FRESH one-time prekeys so the published pool can recover after
/// peers consume the uploaded ones. Without this the pool generated once at
/// identity creation is static: re-uploading the same prekey IDs inserts
/// nothing (they already exist with `consumed_at` set) and the device stays
/// stuck at "Awaiting prekey material" forever.
///
/// Async so ML-KEM-1024/ML-DSA-65 generation and the encrypted key-material
/// write run on the async worker pool, never the main/UI thread (same pattern
/// as `call_caller_setup` and the vault commands). No `.await` inside, so no
/// lock is held across a suspend point.
#[tauri::command]
pub async fn keys_replenish_one_time_prekeys(
    state: State<'_, AppState>,
    user_id: Option<String>,
    needed: u32,
) -> Result<Vec<PublicOneTimePrekey>> {
    let session_user_id = state.resolve_user_id(user_id)?;
    state.check_decrypt_rate_limit("prekey_replenish", &session_user_id, 12, 300)?;
    let _key_scope = state.lock_key_scope()?;
    state.ensure_identity(&session_user_id, platform_device_label())?;

    let needed = needed.clamp(1, ONE_TIME_PREKEY_REPLENISH_MAX) as usize;
    let identity = state
        .identity
        .lock()
        .map_err(|_| QGuardError::Storage("identity lock poisoned".to_string()))?
        .as_ref()
        .filter(|identity| identity.user_id == session_user_id)
        .cloned()
        .ok_or_else(|| QGuardError::NotFound("identity".to_string()))?;

    let fresh = generate_one_time_prekeys(&identity, needed)?;
    let publics: Vec<PublicOneTimePrekey> = fresh.iter().map(|p| p.public.clone()).collect();

    {
        // Lock order pool -> legacy matches the decrypt path in
        // commands/messaging.rs, which holds the pool guard while falling
        // back to the legacy pool.
        let mut pool = state
            .one_time_prekeys
            .lock()
            .map_err(|_| QGuardError::Storage("one-time prekey lock poisoned".to_string()))?;
        let mut legacy = state.legacy_one_time_prekeys.lock().map_err(|_| {
            QGuardError::Storage("legacy one-time prekey lock poisoned".to_string())
        })?;
        pool.extend(fresh);
        retire_excess_one_time_prekeys(&mut pool, &mut legacy);
    }
    state.persist_current_device_key_material()?;
    state.audit_info(
        "keys_replenish_one_time_prekeys",
        &format!("Generated {needed} fresh one-time prekeys for the published pool"),
    );
    state.touch_telemetry(
        "key",
        "One-time prekey pool replenished with fresh hybrid material",
        100,
    );
    Ok(publics)
}

/// Acknowledge that the superseded device row named by
/// `PublicIdentityBundle::replaced_device_id` has been revoked on the relay, so
/// the bundle stops advertising it. Kept separate from the revoke itself
/// because the revoke is a Supabase RPC the client owns; until it confirms, the
/// id must keep being reported or a dropped call would strand a dead device row
/// as a permanent delivery target.
#[tauri::command]
pub fn keys_ack_superseded_device(state: State<'_, AppState>) -> Result<()> {
    state.require_auth()?;
    state.clear_superseded_device_id();
    Ok(())
}

/// The exact phrase `keys_reset_device_identity` requires. A typed
/// confirmation, not a boolean, because the boolean would be one stray
/// `true` away from wiping a working device's keys.
const RESET_DEVICE_IDENTITY_CONFIRMATION: &str = "RESET THIS DEVICE IDENTITY";

/// Discard this device's key material and register a brand-new identity.
///
/// DESTRUCTIVE AND IRREVERSIBLE: every message already sealed to this device --
/// its whole history on the relay, including the user's own copies -- becomes
/// permanently unreadable here. It exists only as the deliberate way out of a
/// device whose stored keys genuinely cannot be opened; `ensure_identity`
/// deliberately refuses to do this on its own, because doing it automatically
/// on a transient fault is what destroyed histories silently.
#[tauri::command]
pub async fn keys_reset_device_identity(
    state: State<'_, AppState>,
    user_id: Option<String>,
    confirmation: String,
) -> Result<PublicIdentityBundle> {
    let session_user_id = state.resolve_user_id(user_id)?;
    if confirmation.trim() != RESET_DEVICE_IDENTITY_CONFIRMATION {
        return Err(QGuardError::InvalidInput(format!(
            "device identity reset requires the confirmation phrase \"{RESET_DEVICE_IDENTITY_CONFIRMATION}\""
        )));
    }
    state.check_decrypt_rate_limit("device_identity_reset", &session_user_id, 3, 3600)?;
    let _key_scope = state.lock_key_scope()?;
    let bundle = state.reset_device_identity(&session_user_id, platform_device_label())?;
    state.audit_info(
        "keys_reset_device_identity",
        "Device key material discarded on explicit user confirmation; fresh identity generated",
    );
    state.touch_telemetry(
        "key",
        "Device identity reset -- previously sealed history is no longer readable on this device",
        100,
    );
    Ok(bundle)
}

#[tauri::command]
pub fn keys_rotate_prekeys(
    state: State<'_, AppState>,
    user_id: Option<String>,
    only_if_due: Option<bool>,
) -> Result<PublicSignedPrekey> {
    let session_user_id = state.resolve_user_id(user_id)?;
    let _key_scope = state.lock_key_scope()?;
    state.ensure_identity(&session_user_id, platform_device_label())?;

    let identity = {
        let identity_guard = state
            .identity
            .lock()
            .map_err(|_| QGuardError::Storage("identity lock poisoned".to_string()))?;
        identity_guard
            .as_ref()
            .filter(|identity| identity.user_id == session_user_id)
            .cloned()
    };
    let identity = match identity {
        Some(identity) => identity,
        None => {
            state.ensure_identity(&session_user_id, platform_device_label())?;
            state
                .identity
                .lock()
                .map_err(|_| QGuardError::Storage("identity lock poisoned".to_string()))?
                .as_ref()
                .cloned()
                .ok_or_else(|| QGuardError::NotFound("identity".to_string()))?
        }
    };

    // The scheduled rotation asks with `only_if_due`: the schedule is decided
    // HERE, from the key's real age, so several triggers firing close together
    // (bootstrap, a prekey-readiness pass, a second window) cannot each mint a
    // new key. A manual "Rotate now" omits it and always rotates.
    if only_if_due.unwrap_or(false) {
        let current = state
            .signed_prekey
            .lock()
            .map_err(|_| QGuardError::Storage("signed prekey lock poisoned".to_string()))?
            .as_ref()
            .map(|prekey| prekey.public.clone());
        if let Some(current) = current {
            let age = Utc::now().timestamp() - current.created_at.timestamp();
            if age < SIGNED_PREKEY_ROTATION_SECS {
                return Ok(current);
            }
        }
    }
    // Counted only for a rotation that is really going to happen, so the
    // scheduled "is it due yet?" calls cannot use up a manual rotation's budget.
    state.check_decrypt_rate_limit("key_rotate", &session_user_id, 6, 300)?;

    // Backpressure instead of loss. Retired prekeys used to be capped by
    // DROPPING the oldest, which silently made everything sealed to it
    // unreadable. Now a retired prekey leaves only through
    // `keys_purge_retired_prekeys`, after its messages are accounted for — so if
    // that clean-up has not been able to run, rotation waits for it.
    let retained = state
        .legacy_signed_prekeys
        .lock()
        .map_err(|_| QGuardError::Storage("legacy signed prekey lock poisoned".to_string()))?
        .len();
    if retained >= MAX_RETAINED_SIGNED_PREKEYS {
        return Err(QGuardError::Trust(format!(
            "prekey rotation is paused: {retained} retired prekeys are still waiting to be cleaned up. They are removed automatically once the messages sealed to them have been recorded; rotation resumes after that."
        )));
    }

    let signed = crate::prekeys::generate_signed_prekey(&identity)?;
    let public = signed.public.clone();
    let previous_signed = state
        .signed_prekey
        .lock()
        .map_err(|_| QGuardError::Storage("signed prekey lock poisoned".to_string()))?
        .replace(signed);
    if let Some(previous_signed) = previous_signed {
        let mut legacy = state
            .legacy_signed_prekeys
            .lock()
            .map_err(|_| QGuardError::Storage("legacy signed prekey lock poisoned".to_string()))?;
        if !legacy
            .iter()
            .any(|prekey| prekey.public.prekey_id == previous_signed.public.prekey_id)
        {
            // Its retirement time is stamped when the material is persisted
            // just below (see `AppState::retained_prekey_retirements`).
            legacy.push(previous_signed);
        }
    }
    state.persist_current_device_key_material()?;
    state.audit_info("keys_rotate_prekeys", "Signed prekey rotated");
    state.touch_telemetry("key", "Signed prekey rotated and persisted locally", 100);
    Ok(public)
}

/// How long a signed prekey stays the published one before the scheduled
/// rotation replaces it. This is the size of a forward-secrecy epoch: every
/// message sealed to this device inside one epoch shares one prekey.
pub const SIGNED_PREKEY_ROTATION_SECS: i64 = 24 * 60 * 60;
/// How long a retired prekey is kept before it may be destroyed. A sender can
/// still be holding the bundle it fetched a moment before the rotation, and a
/// device that was offline can come back to envelopes sealed to it.
pub const RETIRED_PREKEY_GRACE_SECS: i64 = 7 * 24 * 60 * 60;
/// How long a retired prekey must have gone UNNEEDED — no envelope having to be
/// opened with it because its key was missing from the ledger — before it is
/// destroyed. This is the evidence that the catch-up pass really did account
/// for everything sealed to it.
pub const RETIRED_PREKEY_QUIET_SECS: i64 = 3 * 24 * 60 * 60;
/// Beyond this many retired prekeys, rotation pauses rather than discard one.
pub const MAX_RETAINED_SIGNED_PREKEYS: usize = 64;
/// Upper bound on the prekeys one clean-up request may name.
const MAX_PURGE_REQUEST_IDS: usize = 512;

/// What can truthfully be said about Secure Chat forward secrecy on this
/// device, from the state of its prekeys.
///
/// Forward secrecy here is per rotation period: it exists to the extent that
/// the signed prekey really is being replaced on schedule and the retired ones
/// really can be destroyed. `healthy` is false whenever either stops being
/// true, and `summary` says which — it never reports a mechanism (a "ratchet")
/// the protocol does not have.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForwardSecrecyPosture {
    pub healthy: bool,
    pub summary: String,
}

/// Rotation is "overdue" once the prekey has been in use for two full periods:
/// one period is the schedule, and a device that was simply switched off
/// overnight should not read as a fault the moment it starts.
const ROTATION_OVERDUE_FACTOR: i64 = 2;

fn whole_units(seconds: i64) -> String {
    let seconds = seconds.max(0);
    if seconds < 3600 {
        "under an hour".to_string()
    } else if seconds < 2 * 24 * 3600 {
        let hours = seconds / 3600;
        format!("{hours} hour{}", if hours == 1 { "" } else { "s" })
    } else {
        format!("{} days", seconds / (24 * 3600))
    }
}

pub fn describe_forward_secrecy(
    signed_prekey_age_secs: Option<i64>,
    retained_signed_prekeys: usize,
    ledger_available: bool,
) -> ForwardSecrecyPosture {
    let Some(age) = signed_prekey_age_secs else {
        return ForwardSecrecyPosture {
            healthy: false,
            summary: "Awaiting prekey material".to_string(),
        };
    };
    if !ledger_available {
        return ForwardSecrecyPosture {
            healthy: false,
            summary: "Degraded: the message-key ledger cannot be opened, so retired prekeys cannot be destroyed"
                .to_string(),
        };
    }
    if retained_signed_prekeys >= MAX_RETAINED_SIGNED_PREKEYS {
        return ForwardSecrecyPosture {
            healthy: false,
            summary: format!(
                "Degraded: prekey rotation is paused with {retained_signed_prekeys} retired prekeys awaiting clean-up"
            ),
        };
    }
    if age >= SIGNED_PREKEY_ROTATION_SECS * ROTATION_OVERDUE_FACTOR {
        return ForwardSecrecyPosture {
            healthy: false,
            summary: format!(
                "Degraded: the signed prekey has been in use for {} (it should rotate every {})",
                whole_units(age),
                whole_units(SIGNED_PREKEY_ROTATION_SECS),
            ),
        };
    }
    ForwardSecrecyPosture {
        healthy: true,
        summary: format!(
            "Signed prekey rotates every {}; current one in use for {}; {} retired awaiting clean-up",
            whole_units(SIGNED_PREKEY_ROTATION_SECS),
            whole_units(age),
            retained_signed_prekeys,
        ),
    }
}

/// [`describe_forward_secrecy`] for the device as it is right now.
pub fn forward_secrecy_posture(state: &AppState, user_id: &str) -> ForwardSecrecyPosture {
    let now = Utc::now().timestamp();
    let age = state
        .signed_prekey
        .lock()
        .ok()
        .and_then(|prekey| prekey.as_ref().map(|prekey| now - prekey.public.created_at.timestamp()));
    let retained = state
        .legacy_signed_prekeys
        .lock()
        .map(|prekeys| prekeys.len())
        .unwrap_or(0);
    let ledger_available = state
        .with_message_keys(user_id, |ledger| ledger.is_available())
        .unwrap_or(false);
    describe_forward_secrecy(age, retained, ledger_available)
}

/// Split retired prekeys into those past their grace period and, of those, the
/// ones the ledger evidence says may be destroyed now.
///
/// A prekey with no recorded retirement time is treated as retired this very
/// moment — never as "old enough".
fn classify_retired_prekeys(
    retired: &[(String, Option<i64>)],
    now: i64,
    is_quiet: &dyn Fn(&str) -> bool,
) -> (Vec<String>, Vec<String>) {
    let mut past_grace = Vec::new();
    let mut purgeable = Vec::new();
    for (prekey_id, retired_at) in retired {
        let Some(retired_at) = retired_at else { continue };
        if now.saturating_sub(*retired_at) < RETIRED_PREKEY_GRACE_SECS {
            continue;
        }
        past_grace.push(prekey_id.clone());
        if is_quiet(prekey_id) {
            purgeable.push(prekey_id.clone());
        }
    }
    (past_grace, purgeable)
}

/// Where this device's prekeys stand: what the scheduled rotation and the
/// retired-prekey clean-up act on, and what the dashboards report. Every field
/// is read from the real key material and ledger — nothing here is a constant
/// dressed up as status.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PrekeyStatus {
    pub signed_prekey_id: Option<String>,
    pub signed_prekey_created_at: Option<String>,
    pub signed_prekey_age_seconds: Option<i64>,
    pub rotation_interval_seconds: i64,
    /// The published signed prekey is older than one rotation interval.
    pub rotation_due: bool,
    /// Too many retired prekeys are waiting for clean-up; rotation is paused.
    pub rotation_blocked: bool,
    /// Retired signed prekeys this device still holds.
    pub retained_signed_prekeys: usize,
    pub oldest_retired_at: Option<String>,
    pub retired_grace_seconds: i64,
    pub retired_quiet_seconds: i64,
    /// Retired prekeys past their grace period — the reason to run a catch-up.
    pub past_grace_signed_prekey_ids: Vec<String>,
    /// Of those, the ones that could be destroyed right now.
    pub purgeable_signed_prekey_ids: Vec<String>,
    /// Of the one-time prekeys the caller reports as claimed on the relay, the
    /// ones this device still holds and that are old enough to clean up.
    pub past_grace_one_time_prekey_ids: Vec<String>,
    /// False when the message-key ledger could not be opened: nothing is being
    /// recorded, so nothing can be destroyed either.
    pub ledger_available: bool,
    pub ledger_entries: usize,
    /// [`describe_forward_secrecy`] for this state, so every screen reports the
    /// same thing in the same words instead of each re-deriving its own.
    pub forward_secrecy_healthy: bool,
    pub forward_secrecy_summary: String,
}

fn retired_signed_prekeys(state: &AppState) -> Result<Vec<(String, Option<i64>)>> {
    Ok(state
        .legacy_signed_prekeys
        .lock()
        .map_err(|_| QGuardError::Storage("legacy signed prekey lock poisoned".to_string()))?
        .iter()
        .map(|prekey| {
            let id = prekey.public.prekey_id.clone();
            let retired_at = state.prekey_retired_at(&id);
            (id, retired_at)
        })
        .collect())
}

/// One-time prekeys among `candidates` that this device still holds and that
/// were created at least a grace period ago.
fn held_one_time_prekeys_past_grace(
    state: &AppState,
    candidates: &[String],
    now: i64,
) -> Result<Vec<String>> {
    if candidates.is_empty() {
        return Ok(Vec::new());
    }
    // Lock order pool -> legacy, matching `keys_replenish_one_time_prekeys`.
    let pool = state
        .one_time_prekeys
        .lock()
        .map_err(|_| QGuardError::Storage("one-time prekey lock poisoned".to_string()))?;
    let legacy = state
        .legacy_one_time_prekeys
        .lock()
        .map_err(|_| QGuardError::Storage("legacy one-time prekey lock poisoned".to_string()))?;
    Ok(pool
        .iter()
        .chain(legacy.iter())
        .filter(|prekey| {
            now.saturating_sub(prekey.public.created_at.timestamp()) >= RETIRED_PREKEY_GRACE_SECS
                && candidates.contains(&prekey.public.prekey_id)
        })
        .map(|prekey| prekey.public.prekey_id.clone())
        .collect())
}

/// `claimed_one_time_prekey_ids` is optional input for the clean-up pass: the
/// one-time prekeys the relay shows as claimed. The device answers which of
/// them it still holds and may clean up; it is not told anything else.
#[tauri::command]
pub fn keys_prekey_status(
    state: State<'_, AppState>,
    user_id: Option<String>,
    claimed_one_time_prekey_ids: Option<Vec<String>>,
) -> Result<PrekeyStatus> {
    let session_user_id = state.resolve_user_id(user_id)?;
    let _key_scope = state.lock_key_scope()?;
    state.ensure_identity(&session_user_id, platform_device_label())?;
    let now = Utc::now().timestamp();
    let claimed_one_time = claimed_one_time_prekey_ids.unwrap_or_default();
    if claimed_one_time.len() > MAX_PURGE_REQUEST_IDS {
        return Err(QGuardError::InvalidInput(format!(
            "at most {MAX_PURGE_REQUEST_IDS} one-time prekeys can be checked at once"
        )));
    }
    let past_grace_one_time_prekey_ids =
        held_one_time_prekeys_past_grace(&state, &claimed_one_time, now)?;

    let current = state
        .signed_prekey
        .lock()
        .map_err(|_| QGuardError::Storage("signed prekey lock poisoned".to_string()))?
        .as_ref()
        .map(|prekey| (prekey.public.prekey_id.clone(), prekey.public.created_at));
    let age = current.as_ref().map(|(_, created_at)| now - created_at.timestamp());

    let retired = retired_signed_prekeys(&state)?;
    let (ledger_available, ledger_entries, (past_grace, purgeable)) =
        state.with_message_keys(&session_user_id, |ledger| {
            (
                ledger.is_available(),
                ledger.len(),
                classify_retired_prekeys(&retired, now, &|prekey_id| {
                    ledger.prekey_quiet_for(prekey_id, RETIRED_PREKEY_QUIET_SECS, now)
                }),
            )
        })?;
    let oldest_retired_at = retired
        .iter()
        .filter_map(|(_, retired_at)| *retired_at)
        .min()
        .and_then(|seconds| chrono::DateTime::<Utc>::from_timestamp(seconds, 0))
        .map(|at| at.to_rfc3339());
    let rotation_blocked = retired.len() >= MAX_RETAINED_SIGNED_PREKEYS;
    let forward_secrecy = describe_forward_secrecy(age, retired.len(), ledger_available);

    Ok(PrekeyStatus {
        signed_prekey_id: current.as_ref().map(|(id, _)| id.clone()),
        signed_prekey_created_at: current.as_ref().map(|(_, created_at)| created_at.to_rfc3339()),
        signed_prekey_age_seconds: age,
        rotation_interval_seconds: SIGNED_PREKEY_ROTATION_SECS,
        rotation_due: age.is_some_and(|age| age >= SIGNED_PREKEY_ROTATION_SECS) && !rotation_blocked,
        rotation_blocked,
        retained_signed_prekeys: retired.len(),
        oldest_retired_at,
        retired_grace_seconds: RETIRED_PREKEY_GRACE_SECS,
        retired_quiet_seconds: RETIRED_PREKEY_QUIET_SECS,
        past_grace_signed_prekey_ids: past_grace,
        purgeable_signed_prekey_ids: purgeable,
        past_grace_one_time_prekey_ids,
        ledger_available,
        ledger_entries,
        forward_secrecy_healthy: forward_secrecy.healthy,
        forward_secrecy_summary: forward_secrecy.summary,
    })
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PrekeyPurgeOutcome {
    pub purged_signed_prekey_ids: Vec<String>,
    pub purged_one_time_prekeys: usize,
    pub retained_signed_prekeys: usize,
}

/// Destroy retired prekeys whose messages are all accounted for.
///
/// THE ONLY PLACE A PREKEY IS EVER DESTROYED, and it is irreversible: anything
/// still sealed to a destroyed prekey whose key is not in the ledger can never
/// be opened on this device again. So every condition has to hold at once:
///
///   1. The caller names the prekey in `drained_signed_prekey_ids`: it has just
///      walked every envelope on the relay sealed to that prekey and recorded
///      (or ruled out) each one's key. Envelopes in conversations the user has
///      not opened are the reason this cannot be inferred from reading alone.
///   2. The ledger is available and has been written to disk successfully.
///   3. The prekey was retired at least [`RETIRED_PREKEY_GRACE_SECS`] ago.
///   4. Nothing has needed it for [`RETIRED_PREKEY_QUIET_SECS`] — if the
///      catch-up had missed something, ordinary use would have shown it here.
///
/// Conditions 2-4 are decided here from this device's own records; the caller
/// cannot assert them. A prekey that misses any condition simply stays, and is
/// looked at again next time.
///
/// `drained_one_time_prekey_ids` does the same for one-time prekeys the relay
/// shows as claimed (only builds older than this one claim them): same
/// catch-up, same age and quiet rules.
#[tauri::command]
pub async fn keys_purge_retired_prekeys(
    state: State<'_, AppState>,
    user_id: Option<String>,
    drained_signed_prekey_ids: Vec<String>,
    drained_one_time_prekey_ids: Option<Vec<String>>,
) -> Result<PrekeyPurgeOutcome> {
    let session_user_id = state.resolve_user_id(user_id)?;
    state.check_decrypt_rate_limit("prekey_purge", &session_user_id, 12, 300)?;
    let _key_scope = state.lock_key_scope()?;
    state.ensure_identity(&session_user_id, platform_device_label())?;
    let drained_one_time: Vec<String> = drained_one_time_prekey_ids.unwrap_or_default();
    if drained_signed_prekey_ids.len() + drained_one_time.len() > MAX_PURGE_REQUEST_IDS {
        return Err(QGuardError::InvalidInput(format!(
            "at most {MAX_PURGE_REQUEST_IDS} prekeys can be named in one clean-up"
        )));
    }

    // Make sure it is THIS user's ledger in memory before judging by it.
    state.with_message_keys(&session_user_id, |_| ())?;
    // Everything recorded so far must be durable BEFORE any key that could
    // re-derive it is destroyed.
    if !state.flush_message_keys(&session_user_id)? {
        return Err(QGuardError::Storage(
            "the message key ledger is unavailable, so no prekey was destroyed".to_string(),
        ));
    }

    let now = Utc::now().timestamp();
    let retired = retired_signed_prekeys(&state)?;
    let (purge_signed, quiet_one_time): (Vec<String>, Vec<String>) =
        state.with_message_keys(&session_user_id, |ledger| {
            let (_, purgeable) = classify_retired_prekeys(&retired, now, &|prekey_id| {
                ledger.prekey_quiet_for(prekey_id, RETIRED_PREKEY_QUIET_SECS, now)
            });
            let signed = purgeable
                .into_iter()
                .filter(|id| drained_signed_prekey_ids.contains(id))
                .collect();
            let one_time = drained_one_time
                .iter()
                .filter(|id| ledger.prekey_quiet_for(id, RETIRED_PREKEY_QUIET_SECS, now))
                .cloned()
                .collect();
            (signed, one_time)
        })?;

    let mut purged_one_time_prekeys = 0usize;
    if !purge_signed.is_empty() {
        let mut legacy_signed = state
            .legacy_signed_prekeys
            .lock()
            .map_err(|_| QGuardError::Storage("legacy signed prekey lock poisoned".to_string()))?;
        // Dropping a `LocalSignedPrekey` wipes its secrets.
        legacy_signed.retain(|prekey| !purge_signed.contains(&prekey.public.prekey_id));
    }
    if !quiet_one_time.is_empty() {
        let purgeable = |prekey: &crate::prekeys::LocalOneTimePrekey| {
            now.saturating_sub(prekey.public.created_at.timestamp()) >= RETIRED_PREKEY_GRACE_SECS
                && quiet_one_time.contains(&prekey.public.prekey_id)
        };
        // Lock order pool -> legacy, matching `keys_replenish_one_time_prekeys`.
        let mut pool = state
            .one_time_prekeys
            .lock()
            .map_err(|_| QGuardError::Storage("one-time prekey lock poisoned".to_string()))?;
        let mut legacy = state.legacy_one_time_prekeys.lock().map_err(|_| {
            QGuardError::Storage("legacy one-time prekey lock poisoned".to_string())
        })?;
        let before = pool.len() + legacy.len();
        pool.retain(|prekey| !purgeable(prekey));
        legacy.retain(|prekey| !purgeable(prekey));
        purged_one_time_prekeys = before - (pool.len() + legacy.len());
    }

    if !purge_signed.is_empty() || purged_one_time_prekeys > 0 {
        state.persist_current_device_key_material()?;
        let _ = state.with_message_keys(&session_user_id, |ledger| {
            ledger.forget_prekeys(&purge_signed);
            ledger.forget_prekeys(&quiet_one_time);
        });
        let _ = state.flush_message_keys(&session_user_id);
        state.audit_info(
            "keys_purge_retired_prekeys",
            &format!(
                "Destroyed {} retired signed prekey(s) and {} claimed one-time prekey(s) after message-key catch-up",
                purge_signed.len(),
                purged_one_time_prekeys
            ),
        );
        state.touch_telemetry(
            "key",
            "Retired prekeys destroyed; traffic from their epoch is no longer decryptable with a device prekey",
            100,
        );
    }

    let retained_signed_prekeys = state
        .legacy_signed_prekeys
        .lock()
        .map_err(|_| QGuardError::Storage("legacy signed prekey lock poisoned".to_string()))?
        .len();
    Ok(PrekeyPurgeOutcome {
        purged_signed_prekey_ids: purge_signed,
        purged_one_time_prekeys,
        retained_signed_prekeys,
    })
}

/// Retire the oldest active one-time prekeys past the pool cap into the
/// legacy pool (which stays decrypt-capable for in-flight messages) and bound
/// the legacy pool itself so persisted key material cannot grow forever.
fn retire_excess_one_time_prekeys(
    pool: &mut Vec<crate::prekeys::LocalOneTimePrekey>,
    legacy: &mut Vec<crate::prekeys::LocalOneTimePrekey>,
) {
    if pool.len() > ONE_TIME_PREKEY_ACTIVE_CAP {
        let retire_count = pool.len() - ONE_TIME_PREKEY_ACTIVE_CAP;
        let retired: Vec<_> = pool.drain(0..retire_count).collect();
        legacy.extend(retired);
    }
    if legacy.len() > ONE_TIME_PREKEY_LEGACY_CAP {
        let excess = legacy.len() - ONE_TIME_PREKEY_LEGACY_CAP;
        legacy.drain(0..excess);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::LocalIdentity;
    use crate::prekeys::LocalOneTimePrekey;

    fn prekey_batch(count: usize, label: &str) -> Vec<LocalOneTimePrekey> {
        let identity = LocalIdentity::generate("user", "Desktop").unwrap();
        let template = generate_one_time_prekeys(&identity, 1)
            .unwrap()
            .pop()
            .unwrap();
        (0..count)
            .map(|index| {
                let mut prekey = template.clone();
                prekey.public.prekey_id = format!("{label}-{index}");
                prekey
            })
            .collect()
    }

    #[test]
    fn retire_keeps_pool_and_legacy_bounded_and_ordered() {
        let mut pool = prekey_batch(ONE_TIME_PREKEY_ACTIVE_CAP + 10, "active");
        let mut legacy = prekey_batch(ONE_TIME_PREKEY_LEGACY_CAP - 5, "legacy");

        retire_excess_one_time_prekeys(&mut pool, &mut legacy);

        assert_eq!(pool.len(), ONE_TIME_PREKEY_ACTIVE_CAP);
        assert_eq!(legacy.len(), ONE_TIME_PREKEY_LEGACY_CAP);
        // The OLDEST active keys were retired (newest stay published/active).
        assert_eq!(pool[0].public.prekey_id, "active-10");
        // Retired keys landed at the tail of legacy, still decrypt-capable.
        assert_eq!(
            legacy.last().unwrap().public.prekey_id,
            format!("active-{}", 9)
        );
    }

    const NOW: i64 = 1_800_000_000;

    fn retired(id: &str, age_secs: Option<i64>) -> (String, Option<i64>) {
        (id.to_string(), age_secs.map(|age| NOW - age))
    }

    #[test]
    fn retired_prekey_inside_grace_period_is_never_purgeable() {
        let list = [
            retired("fresh", Some(0)),
            retired("almost", Some(RETIRED_PREKEY_GRACE_SECS - 1)),
        ];
        // Even when the ledger says everything is quiet.
        let (past_grace, purgeable) = classify_retired_prekeys(&list, NOW, &|_| true);
        assert!(past_grace.is_empty());
        assert!(purgeable.is_empty());
    }

    #[test]
    fn retired_prekey_past_grace_needs_a_quiet_ledger_too() {
        let list = [
            retired("quiet", Some(RETIRED_PREKEY_GRACE_SECS)),
            retired("still-needed", Some(RETIRED_PREKEY_GRACE_SECS * 3)),
        ];
        let (past_grace, purgeable) =
            classify_retired_prekeys(&list, NOW, &|prekey_id| prekey_id == "quiet");
        assert_eq!(past_grace, vec!["quiet".to_string(), "still-needed".to_string()]);
        assert_eq!(purgeable, vec!["quiet".to_string()]);
    }

    #[test]
    fn retired_prekey_without_a_recorded_time_is_kept() {
        // No retirement time means "retired just now", never "old enough".
        let list = [retired("unknown", None)];
        let (past_grace, purgeable) = classify_retired_prekeys(&list, NOW, &|_| true);
        assert!(past_grace.is_empty());
        assert!(purgeable.is_empty());
    }

    #[test]
    fn retired_prekey_with_a_future_timestamp_is_kept() {
        // A clock that moved backwards must not make a prekey look ancient.
        let list = [retired("from-the-future", Some(-RETIRED_PREKEY_GRACE_SECS * 10))];
        let (past_grace, purgeable) = classify_retired_prekeys(&list, NOW, &|_| true);
        assert!(past_grace.is_empty());
        assert!(purgeable.is_empty());
    }

    #[test]
    fn purge_evidence_comes_from_the_real_ledger() {
        use crate::message_keys::MessageKeyLedger;

        let retired_at = NOW - RETIRED_PREKEY_GRACE_SECS - 1;
        let list = [
            ("never-needed".to_string(), Some(retired_at)),
            ("needed-yesterday".to_string(), Some(retired_at)),
            ("needed-long-ago".to_string(), Some(retired_at)),
        ];
        let quiet_in = |ledger: &MessageKeyLedger| {
            classify_retired_prekeys(&list, NOW, &|prekey_id| {
                ledger.prekey_quiet_for(prekey_id, RETIRED_PREKEY_QUIET_SECS, NOW)
            })
            .1
        };

        // A ledger that only started watching an hour ago has not seen enough
        // to vouch for anything, whatever the prekeys' ages.
        let young = MessageKeyLedger::empty("user", NOW - 3600);
        assert!(quiet_in(&young).is_empty());

        // An established ledger vouches for exactly the prekeys nothing has
        // needed recently.
        let mut established =
            MessageKeyLedger::empty("user", NOW - RETIRED_PREKEY_QUIET_SECS - 1);
        established.note_prekey_needed("needed-yesterday", NOW - 24 * 60 * 60);
        established.note_prekey_needed("needed-long-ago", NOW - RETIRED_PREKEY_QUIET_SECS);
        assert_eq!(
            quiet_in(&established),
            vec!["never-needed".to_string(), "needed-long-ago".to_string()]
        );

        // An unavailable ledger vouches for nothing.
        let unavailable = MessageKeyLedger::unavailable("user", NOW + 60);
        assert!(quiet_in(&unavailable).is_empty());
    }

    #[test]
    fn forward_secrecy_is_only_reported_healthy_when_rotation_is_really_happening() {
        let hour = 3600;
        // No prekey at all.
        let none = describe_forward_secrecy(None, 0, true);
        assert!(!none.healthy);
        assert_eq!(none.summary, "Awaiting prekey material");

        // Fresh prekey, ledger working, a few retired ones waiting: healthy.
        let fresh = describe_forward_secrecy(Some(5 * hour), 3, true);
        assert!(fresh.healthy, "{}", fresh.summary);
        assert!(fresh.summary.contains("5 hours"), "{}", fresh.summary);
        assert!(fresh.summary.contains("3 retired"), "{}", fresh.summary);

        // One period old is still on schedule (the device may have been off).
        assert!(describe_forward_secrecy(Some(SIGNED_PREKEY_ROTATION_SECS + hour), 0, true).healthy);

        // Two periods old is not.
        let stale = describe_forward_secrecy(Some(SIGNED_PREKEY_ROTATION_SECS * 2), 0, true);
        assert!(!stale.healthy);
        assert!(stale.summary.starts_with("Degraded"), "{}", stale.summary);

        // A ledger that cannot be opened means nothing can be destroyed.
        let no_ledger = describe_forward_secrecy(Some(hour), 0, false);
        assert!(!no_ledger.healthy);
        assert!(no_ledger.summary.contains("ledger"), "{}", no_ledger.summary);

        // Rotation paused by backpressure.
        let paused = describe_forward_secrecy(Some(hour), MAX_RETAINED_SIGNED_PREKEYS, true);
        assert!(!paused.healthy);
        assert!(paused.summary.contains("paused"), "{}", paused.summary);

        // Whatever the state, it never claims a ratchet.
        for posture in [none, fresh, stale, no_ledger, paused] {
            assert!(!posture.summary.to_lowercase().contains("ratchet"), "{}", posture.summary);
        }
    }

    #[test]
    fn rotation_backpressure_threshold_exceeds_a_full_grace_period_of_daily_rotations() {
        // One rotation per interval for a whole grace + quiet period must fit
        // under the cap with room to spare, or a healthy device would pause
        // its own rotation.
        let steady_state =
            (RETIRED_PREKEY_GRACE_SECS + RETIRED_PREKEY_QUIET_SECS) / SIGNED_PREKEY_ROTATION_SECS;
        assert!((steady_state as usize) * 2 < MAX_RETAINED_SIGNED_PREKEYS);
    }

    #[test]
    fn retire_is_noop_below_caps() {
        let mut pool = prekey_batch(4, "active");
        let mut legacy: Vec<LocalOneTimePrekey> = Vec::new();
        retire_excess_one_time_prekeys(&mut pool, &mut legacy);
        assert_eq!(pool.len(), 4);
        assert!(legacy.is_empty());
    }
}
