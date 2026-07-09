use std::path::{Path, PathBuf};

use base64::Engine;
use serde::{Deserialize, Serialize};
use tauri::State;
use zeroize::Zeroize;

use crate::crypto::hybrid_kex::{decapsulate, encapsulate};
use crate::crypto::{DualSignature, HybridCiphertext};
use crate::crypto::kdf::{hkdf_sha3_256, sha3_256};
use crate::error::{QGuardError, Result};
use crate::identity::verify_identity_bundle;
use crate::state::AppState;

const INFO_C2A: &[u8] = b"qguard-call-media-v1:caller-to-callee";
const INFO_A2C: &[u8] = b"qguard-call-media-v1:callee-to-caller";
const KEM_INFO_PREFIX: &str = "qguard-call-kem-v1:";

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CallSetup {
    pub hybrid_ciphertext: Option<HybridCiphertext>,
    pub send_key_b64: String,
    pub recv_key_b64: String,
    pub safety_number: String,
}

/// Derive the two directional 32-byte keys + safety number from the shared secret.
/// `role` is "caller" or "callee" and selects which derived key is send vs recv.
fn derive_call_setup(
    shared: &[u8; 32],
    role: &str,
    ciphertext: Option<HybridCiphertext>,
) -> Result<CallSetup> {
    let c2a = hkdf_sha3_256(shared, INFO_C2A, 32)?; // caller -> callee
    let a2c = hkdf_sha3_256(shared, INFO_A2C, 32)?; // callee -> caller
    let (send, recv) = match role {
        "caller" => (&c2a, &a2c),
        "callee" => (&a2c, &c2a),
        other => return Err(QGuardError::InvalidInput(format!("bad call role: {other}"))),
    };
    let b64 = base64::engine::general_purpose::STANDARD;
    let setup = CallSetup {
        hybrid_ciphertext: ciphertext,
        send_key_b64: b64.encode(send),
        recv_key_b64: b64.encode(recv),
        safety_number: safety_number(shared),
    };
    Ok(setup)
}

/// 60-bit SAS rendered as five 4-digit groups, so both ends can verbally verify.
fn safety_number(shared: &[u8; 32]) -> String {
    let digest = sha3_256(shared);
    let mut acc: u64 = 0;
    for byte in digest.iter().take(8) {
        acc = (acc << 8) | (*byte as u64);
    }
    let mut groups = Vec::with_capacity(5);
    for i in 0..5 {
        groups.push(format!("{:04}", ((acc >> (i * 12)) & 0x0fff) as u16));
    }
    groups.join("-")
}

/// Peer identity material for an outgoing call, as published in the device
/// registry. The KEM keys are only trusted after the identity-bundle dual
/// signature (Ed25519 + ML-DSA-65) validates — a relay that swaps KEM keys
/// without the matching signing keys is rejected before any media key exists.
#[derive(Clone, Debug, Deserialize)]
pub struct CallPeerIdentity {
    pub user_id: String,
    pub device_id: String,
    pub x25519_identity_public: Vec<u8>,
    pub mlkem_identity_public: Vec<u8>,
    pub ed25519_identity_public: Vec<u8>,
    pub mldsa_identity_public: Vec<u8>,
    pub identity_signature: DualSignature,
}

// `async` is load-bearing, not cosmetic: a synchronous `#[tauri::command]` runs
// on the WebView's main thread, so the KEM math + identity/keyring access below
// would freeze the whole UI event loop for the duration. During a call that is
// catastrophic — a frozen event loop cannot process WebRTC ICE/DTLS negotiation
// or realtime call signals, so the peer connection stalls and drops on BOTH
// ends the moment the callee accepts. Declaring the command `async` makes Tauri
// run it on the async runtime's worker pool instead, keeping the UI thread free
// (mirrors the vault_* off-main-thread pattern). The bodies contain no `.await`,
// so nothing is held across a suspend point and the future stays `Send`.
#[tauri::command]
pub async fn call_caller_setup(
    state: State<'_, AppState>,
    peer: CallPeerIdentity,
    call_id: String,
) -> Result<CallSetup> {
    state.require_auth()?;
    verify_identity_bundle(
        &peer.user_id,
        &peer.device_id,
        &peer.x25519_identity_public,
        &peer.mlkem_identity_public,
        &peer.ed25519_identity_public,
        &peer.mldsa_identity_public,
        &peer.identity_signature,
    )
    .map_err(|_| {
        QGuardError::Crypto(
            "peer device identity signature failed verification; call refused".to_string(),
        )
    })?;
    let info = format!("{KEM_INFO_PREFIX}{call_id}");
    let (ciphertext, mut shared) = encapsulate(
        &peer.x25519_identity_public,
        &peer.mlkem_identity_public,
        info.as_bytes(),
    )?;
    let result = derive_call_setup(&shared, "caller", Some(ciphertext));
    shared.zeroize();
    let setup = result?;
    state.audit_info(
        "call_caller_setup",
        "Peer identity verified (Ed25519 + ML-DSA-65); quantum-safe call media key established (caller)",
    );
    Ok(setup)
}

// Async for the same reason as `call_caller_setup`: this runs the instant the
// callee taps Accept and touches the OS keyring + encrypted identity material
// (`ensure_identity`) plus KEM decapsulation. On the main thread that stall is
// exactly what froze the app and dropped the call at connect time.
#[tauri::command]
pub async fn call_callee_setup(
    state: State<'_, AppState>,
    hybrid_ciphertext: HybridCiphertext,
    call_id: String,
) -> Result<CallSetup> {
    state.require_auth()?;
    let user_id = state.user_id()?;
    state.ensure_identity(&user_id, "Windows Desktop")?;
    let guard = state
        .identity
        .lock()
        .map_err(|_| QGuardError::Storage("identity lock poisoned".to_string()))?;
    let identity = guard
        .as_ref()
        .ok_or_else(|| QGuardError::NotFound("identity".to_string()))?;
    let info = format!("{KEM_INFO_PREFIX}{call_id}");
    let mut shared = decapsulate(
        &identity.kem.x25519_secret,
        &identity.kem.mlkem_secret,
        &hybrid_ciphertext,
        info.as_bytes(),
    )?;
    let result = derive_call_setup(&shared, "callee", None);
    shared.zeroize();
    drop(guard);
    let setup = result?;
    state.audit_info("call_callee_setup", "Quantum-safe call media key established (callee)");
    Ok(setup)
}

// ---------------------------------------------------------------------------
// GPU freeze watchdog / safe mode
//
// On some Windows machines (seen on Intel Iris Xe with outdated drivers) the
// GPU driver can wedge during a video call and freeze the whole machine so
// hard that only a power cut recovers it — nothing is ever logged. The media
// pipeline already runs on software codecs (see `run()` in lib.rs), but as a
// last line of defense the frontend sets a marker file while a call's media
// pipeline is live and clears it on teardown. If the app starts and the
// marker is still present, the previous session died mid-call (freeze, crash,
// power loss), and we permanently switch WebView2 to full software rendering
// (`--disable-gpu`) until the user opts back in from Settings after fixing
// their graphics driver. A graceful window close also clears the marker (see
// `on_window_event`), so normal quits never trip the watchdog.
// ---------------------------------------------------------------------------

const CALL_ACTIVE_MARKER: &str = "call-active.marker";
const GPU_SAFE_MODE_FLAG: &str = "gpu-safe-mode.flag";

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GpuSafeModeStatus {
    /// The safe-mode flag file exists; software rendering applies now or on next launch.
    pub active: bool,
    /// The current process actually launched WebView2 with `--disable-gpu`.
    pub applied_this_session: bool,
    pub enabled_at: Option<String>,
    pub reason: Option<String>,
}

fn call_marker_path(dir: &Path) -> PathBuf {
    dir.join(CALL_ACTIVE_MARKER)
}

fn gpu_safe_mode_path(dir: &Path) -> PathBuf {
    dir.join(GPU_SAFE_MODE_FLAG)
}

pub fn write_call_marker(dir: &Path) {
    let _ = std::fs::create_dir_all(dir);
    let _ = std::fs::write(call_marker_path(dir), chrono::Utc::now().to_rfc3339());
}

pub fn clear_call_marker(dir: &Path) {
    let _ = std::fs::remove_file(call_marker_path(dir));
}

/// Startup check, called before the WebView2 environment is created. Converts
/// a stale call marker (unclean shutdown mid-call) into the persistent safe-mode
/// flag. Returns whether this launch must add `--disable-gpu`. Best-effort IO:
/// a failure here must never stop the app from starting.
pub fn gpu_safe_mode_boot_check(dir: &Path) -> bool {
    let marker = call_marker_path(dir);
    if marker.exists() {
        let flag = serde_json::json!({
            "enabledAt": chrono::Utc::now().to_rfc3339(),
            "reason": "The app shut down unexpectedly during a call, so video calls now use device-safe software rendering.",
        });
        let _ = std::fs::create_dir_all(dir);
        let _ = std::fs::write(gpu_safe_mode_path(dir), flag.to_string());
        let _ = std::fs::remove_file(&marker);
    }
    gpu_safe_mode_path(dir).exists()
}

fn disable_gpu_applied() -> bool {
    // Token match: `--disable-gpu-memory-buffer-video-frames` must NOT count.
    std::env::var("WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS")
        .map(|args| args.split_whitespace().any(|t| t == "--disable-gpu"))
        .unwrap_or(false)
}

pub fn read_gpu_safe_mode(dir: &Path) -> GpuSafeModeStatus {
    let path = gpu_safe_mode_path(dir);
    let mut enabled_at = None;
    let mut reason = None;
    let active = path.exists();
    if active {
        if let Ok(raw) = std::fs::read_to_string(&path) {
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(&raw) {
                enabled_at = value.get("enabledAt").and_then(|v| v.as_str()).map(String::from);
                reason = value.get("reason").and_then(|v| v.as_str()).map(String::from);
            }
        }
    }
    GpuSafeModeStatus { active, applied_this_session: disable_gpu_applied(), enabled_at, reason }
}

// The watchdog commands deliberately skip `require_auth`: they carry no data,
// and the end marker must clear during teardown even after a logout mid-call —
// otherwise the next launch would enter safe mode spuriously.

#[tauri::command]
pub fn call_watchdog_begin(state: State<'_, AppState>) -> Result<()> {
    write_call_marker(&state.data_dir);
    Ok(())
}

#[tauri::command]
pub fn call_watchdog_end(state: State<'_, AppState>) -> Result<()> {
    clear_call_marker(&state.data_dir);
    Ok(())
}

#[tauri::command]
pub fn call_gpu_safe_mode_status(state: State<'_, AppState>) -> Result<GpuSafeModeStatus> {
    Ok(read_gpu_safe_mode(&state.data_dir))
}

/// Settings opt-out: takes effect on the next launch (the WebView2 environment
/// args are fixed at process start).
#[tauri::command]
pub fn call_gpu_safe_mode_clear(state: State<'_, AppState>) -> Result<GpuSafeModeStatus> {
    let _ = std::fs::remove_file(gpu_safe_mode_path(&state.data_dir));
    state.audit_info("call_gpu_safe_mode_clear", "GPU safe mode disabled from Settings");
    Ok(read_gpu_safe_mode(&state.data_dir))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hybrid_kex::LocalKemKeypair;

    #[test]
    fn caller_and_callee_derive_mirrored_keys_and_matching_sas() {
        let callee = LocalKemKeypair::generate();
        let info = b"qguard-call-kem-v1:call-1";
        let (ct, mut s_caller) =
            encapsulate(&callee.x25519_public, &callee.mlkem_public, info).unwrap();
        let mut s_callee =
            decapsulate(&callee.x25519_secret, &callee.mlkem_secret, &ct, info).unwrap();
        assert_eq!(s_caller, s_callee, "shared secret must match");

        let caller = derive_call_setup(&s_caller, "caller", Some(ct.clone())).unwrap();
        let callee_setup = derive_call_setup(&s_callee, "callee", None).unwrap();

        // caller.send == callee.recv and caller.recv == callee.send
        assert_eq!(caller.send_key_b64, callee_setup.recv_key_b64);
        assert_eq!(caller.recv_key_b64, callee_setup.send_key_b64);
        assert_ne!(caller.send_key_b64, caller.recv_key_b64);
        assert_eq!(caller.safety_number, callee_setup.safety_number);
        assert_eq!(caller.safety_number.split('-').count(), 5);
        s_caller.zeroize();
        s_callee.zeroize();
    }

    #[test]
    fn caller_setup_rejects_swapped_peer_kem_keys() {
        let identity = crate::identity::LocalIdentity::generate("user-1", "Desktop").unwrap();
        let bundle = identity.public_bundle().unwrap();
        // The registry-published bundle verifies as-is.
        verify_identity_bundle(
            &bundle.user_id,
            &bundle.device_id,
            &bundle.x25519_identity_public,
            &bundle.mlkem_identity_public,
            &bundle.ed25519_identity_public,
            &bundle.mldsa_identity_public,
            &bundle.signature,
        )
        .unwrap();
        // A relay that substitutes its own KEM keys (MITM attempt) must fail the
        // dual-signature check that gates every outgoing call.
        let attacker = LocalKemKeypair::generate();
        assert!(verify_identity_bundle(
            &bundle.user_id,
            &bundle.device_id,
            &attacker.x25519_public,
            &attacker.mlkem_public,
            &bundle.ed25519_identity_public,
            &bundle.mldsa_identity_public,
            &bundle.signature,
        )
        .is_err());
    }

    fn watchdog_tmp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("qguard-watchdog-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn boot_check_is_clean_without_marker_or_flag() {
        let dir = watchdog_tmp_dir("clean");
        assert!(!gpu_safe_mode_boot_check(&dir));
        assert!(!read_gpu_safe_mode(&dir).active);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn stale_call_marker_promotes_to_persistent_safe_mode() {
        let dir = watchdog_tmp_dir("promote");
        write_call_marker(&dir);
        // Simulated relaunch after a mid-call freeze/crash.
        assert!(gpu_safe_mode_boot_check(&dir), "safe mode must engage");
        assert!(!call_marker_path(&dir).exists(), "marker must be consumed");
        let status = read_gpu_safe_mode(&dir);
        assert!(status.active);
        assert!(status.enabled_at.is_some());
        assert!(status.reason.is_some());
        // Safe mode persists across further clean launches...
        assert!(gpu_safe_mode_boot_check(&dir));
        // ...until the user opts out.
        let _ = std::fs::remove_file(gpu_safe_mode_path(&dir));
        assert!(!gpu_safe_mode_boot_check(&dir));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn graceful_teardown_clears_marker_and_never_trips_safe_mode() {
        let dir = watchdog_tmp_dir("graceful");
        write_call_marker(&dir);
        clear_call_marker(&dir);
        assert!(!gpu_safe_mode_boot_check(&dir));
        assert!(!read_gpu_safe_mode(&dir).active);
        let _ = std::fs::remove_dir_all(&dir);
    }
}