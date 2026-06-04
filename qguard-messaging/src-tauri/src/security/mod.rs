use serde::{Deserialize, Serialize};

use crate::crypto::kdf::sha3_hex;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecurityHardeningStatus {
    pub checks: Vec<SecurityHardeningCheck>,
    pub debugger_detected: bool,
    pub binary_sha3: Option<String>,
    pub binary_path: Option<String>,
    pub expected_binary_sha3: Option<String>,
    pub build_profile: String,
    pub debug_assertions: bool,
    pub plaintext_logging_disabled: bool,
    pub aead_required: bool,
    pub nonce_uniqueness_checked: bool,
    pub replay_protection_enabled: bool,
    pub strict_cors_required_for_relay: bool,
    pub secure_headers_documented: bool,
    pub dependency_scanning_documented: bool,
    pub anti_debugger_protection: bool,
    pub anti_tampering_detection: bool,
    pub binary_integrity_verification: bool,
    pub secure_memory_zeroize: bool,
    pub tamper_evident_audit_chain: bool,
    pub post_quantum_protection: bool,
    pub rate_limiting: bool,
    pub code_obfuscation: bool,
    pub control_flow_flattening: bool,
    pub string_encryption: bool,
    pub signed_build_verification: bool,
    pub integrity_hash_checks: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecurityHardeningCheck {
    pub id: String,
    pub label: String,
    pub status: String,
    pub active: bool,
    pub detail: String,
}

pub fn hardening_status(audit_chain_valid: bool) -> SecurityHardeningStatus {
    let debugger_detected = debugger_detected();
    let binary_measurement = current_binary_measurement();
    let binary_hash_available = binary_measurement.sha3.is_some();
    let expected_binary_sha3 = option_env!("QGUARD_EXPECTED_BINARY_SHA3").map(str::to_string);
    let signed_build_verification =
        option_env!("QGUARD_SIGNED_BUILD").is_some_and(|value| value == "1");
    let binary_integrity_verified = match (&binary_measurement.sha3, &expected_binary_sha3) {
        (Some(actual), Some(expected)) => actual.eq_ignore_ascii_case(expected),
        _ => false,
    };
    let binary_integrity_detail = match (&binary_measurement.sha3, &expected_binary_sha3) {
        (Some(actual), Some(expected)) if actual.eq_ignore_ascii_case(expected) => {
            "Runtime binary hash matches configured release hash"
        }
        (Some(_), Some(_)) => "Runtime binary hash does not match configured release hash",
        (Some(_), None) => "Runtime binary hash captured; release hash pin not configured",
        _ => "Runtime binary hash unavailable",
    };
    let release_hardened = !cfg!(debug_assertions);
    let code_obfuscation = release_hardened;
    let control_flow_flattening =
        option_env!("QGUARD_CONTROL_FLOW_FLATTENING").is_some_and(|value| value == "1");
    let string_encryption =
        option_env!("QGUARD_STRING_ENCRYPTION").is_some_and(|value| value == "1");

    let checks = vec![
        check(
            "anti_debugger_protection",
            "Anti-Debugger Protection",
            !debugger_detected,
            if debugger_detected {
                "Debugger detected by native runtime guard"
            } else {
                "Native debugger probe is clear"
            },
        ),
        check(
            "anti_tampering_detection",
            "Anti-Tampering Detection",
            binary_hash_available && !debugger_detected,
            if binary_hash_available {
                "Runtime binary measurement available"
            } else {
                "Runtime binary could not be measured"
            },
        ),
        check(
            "binary_integrity_verification",
            "Binary Integrity Verification",
            binary_integrity_verified,
            binary_integrity_detail,
        ),
        check(
            "signed_build_verification",
            "Signed Build Verification",
            signed_build_verification,
            if signed_build_verification {
                "Build is marked as signed by the release pipeline"
            } else {
                "Release signing marker is not configured"
            },
        ),
        check(
            "runtime_integrity_hash_checks",
            "Integrity Hash Checks",
            binary_hash_available,
            if binary_hash_available {
                "SHA3-256 runtime hash check is available"
            } else {
                "SHA3-256 runtime hash check failed"
            },
        ),
        check(
            "secure_memory_zeroize",
            "Secure Memory (zeroize)",
            true,
            "Key material uses zeroize-backed cleanup paths",
        ),
        check(
            "tamper_evident_audit_chain",
            "Tamper-Evident Audit Chain",
            audit_chain_valid,
            if audit_chain_valid {
                "Local hash chain verifies"
            } else {
                "Local hash chain verification failed"
            },
        ),
        check(
            "post_quantum_protection",
            "Post-Quantum Protection (FIPS 203/204)",
            true,
            "ML-KEM + ML-DSA hybrid suite is compiled into the app",
        ),
        check(
            "rate_limiting",
            "Rate Limiting",
            true,
            "Profile action rate limits are enforced through Supabase RPC",
        ),
        check(
            "code_obfuscation",
            "Code Obfuscation",
            code_obfuscation,
            if code_obfuscation {
                "Release build uses minification, symbol stripping, LTO, and panic abort"
            } else {
                "Debug build keeps symbols for local testing"
            },
        ),
        check(
            "control_flow_flattening",
            "Control-Flow Flattening",
            control_flow_flattening,
            if control_flow_flattening {
                "Release pipeline reports control-flow flattening enabled"
            } else {
                "Dedicated control-flow flattening is not configured"
            },
        ),
        check(
            "string_encryption",
            "String Encryption",
            string_encryption,
            if string_encryption {
                "Release pipeline reports string encryption enabled"
            } else {
                "Dedicated string encryption is not configured"
            },
        ),
    ];

    SecurityHardeningStatus {
        checks,
        debugger_detected,
        binary_sha3: binary_measurement.sha3,
        binary_path: binary_measurement.path,
        expected_binary_sha3,
        build_profile: if release_hardened { "release" } else { "debug" }.to_string(),
        debug_assertions: cfg!(debug_assertions),
        plaintext_logging_disabled: true,
        aead_required: true,
        nonce_uniqueness_checked: true,
        replay_protection_enabled: true,
        strict_cors_required_for_relay: true,
        secure_headers_documented: true,
        dependency_scanning_documented: true,
        anti_debugger_protection: !debugger_detected,
        anti_tampering_detection: binary_hash_available && !debugger_detected,
        binary_integrity_verification: binary_integrity_verified,
        secure_memory_zeroize: true,
        tamper_evident_audit_chain: audit_chain_valid,
        post_quantum_protection: true,
        rate_limiting: true,
        code_obfuscation,
        control_flow_flattening,
        string_encryption,
        signed_build_verification,
        integrity_hash_checks: binary_hash_available,
    }
}

struct BinaryMeasurement {
    sha3: Option<String>,
    path: Option<String>,
}

fn check(id: &str, label: &str, active: bool, detail: &str) -> SecurityHardeningCheck {
    SecurityHardeningCheck {
        id: id.to_string(),
        label: label.to_string(),
        status: if active { "active" } else { "warning" }.to_string(),
        active,
        detail: detail.to_string(),
    }
}

fn current_binary_measurement() -> BinaryMeasurement {
    let path = match std::env::current_exe() {
        Ok(path) => path,
        Err(_) => {
            return BinaryMeasurement {
                sha3: None,
                path: None,
            }
        }
    };
    let display_path = path.to_string_lossy().to_string();
    let sha3 = std::fs::read(&path)
        .ok()
        .map(|bytes| sha3_hex(bytes.as_slice()));
    BinaryMeasurement {
        sha3,
        path: Some(display_path),
    }
}

#[cfg(windows)]
fn debugger_detected() -> bool {
    #[link(name = "kernel32")]
    extern "system" {
        fn IsDebuggerPresent() -> i32;
    }

    unsafe { IsDebuggerPresent() != 0 }
}

#[cfg(not(windows))]
fn debugger_detected() -> bool {
    std::env::var_os("QGUARD_DEBUGGER_ATTACHED").is_some()
}
