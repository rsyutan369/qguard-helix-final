use base64::Engine;
use serde::Serialize;
use tauri::State;
use zeroize::Zeroize;

use crate::crypto::hybrid_kex::{decapsulate, encapsulate};
use crate::crypto::HybridCiphertext;
use crate::crypto::kdf::{hkdf_sha3_256, sha3_256};
use crate::error::{QGuardError, Result};
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

#[tauri::command]
pub fn call_caller_setup(
    state: State<'_, AppState>,
    peer_x25519_public: Vec<u8>,
    peer_mlkem_public: Vec<u8>,
    call_id: String,
) -> Result<CallSetup> {
    state.require_auth()?;
    let info = format!("{KEM_INFO_PREFIX}{call_id}");
    let (ciphertext, mut shared) =
        encapsulate(&peer_x25519_public, &peer_mlkem_public, info.as_bytes())?;
    let setup = derive_call_setup(&shared, "caller", Some(ciphertext));
    shared.zeroize();
    state.audit_info("call_caller_setup", "Quantum-safe call media key established (caller)");
    setup
}

#[tauri::command]
pub fn call_callee_setup(
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
    let setup = derive_call_setup(&shared, "callee", None);
    shared.zeroize();
    drop(guard);
    state.audit_info("call_callee_setup", "Quantum-safe call media key established (callee)");
    setup
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
}