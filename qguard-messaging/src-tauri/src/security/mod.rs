use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

use crate::crypto::kdf::sha3_hex;

pub mod android_bridge;
pub mod content_uri;
pub mod device_privacy;
pub mod keystore;
pub mod obf;
pub mod public_downloads;
pub mod saf_folder;
pub mod selftest;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecurityHardeningStatus {
    pub checks: Vec<SecurityHardeningCheck>,
    pub debugger_detected: bool,
    pub binary_sha3: Option<String>,
    pub binary_path: Option<String>,
    pub expected_binary_sha3: Option<String>,
    pub build_profile: String,
    pub debug_assertions: bool,
    // Every boolean below mirrors a row of `checks` and is derived the same
    // way. (Seven further fields used to sit here — "plaintext logging
    // disabled", "nonce uniqueness checked", "replay protection enabled",
    // "strict CORS", "secure headers / dependency scanning documented", "AEAD
    // required" — each hardcoded to `true`. Nothing measured them and nothing
    // read them, yet they were exported in the security report as findings.
    // They are gone rather than kept as claims.)
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
    /// Transport posture this launch asked the platform WebView for.
    pub tls_policy: TlsPolicy,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecurityHardeningCheck {
    pub id: String,
    pub label: String,
    pub status: String,
    pub active: bool,
    pub detail: String,
}

// ---------------------------------------------------------------------------
// TLS transport policy
//
// Every byte this app sends to Supabase (auth, relay rows, storage, realtime)
// travels over the embedded WebView's own TLS stack -- this process opens no
// sockets of its own. So "TLS 1.3 / X25519MLKEM768 preferred / classical
// fallback controlled by policy" is not something the Rust code can negotiate;
// it is something it must CONFIGURE, at the one moment it can: before the
// WebView environment is created.
//
// Scope, stated honestly because it differs by platform:
//   - Windows (WebView2): enforced here, through the browser arguments below.
//   - Android (system WebView): the OS owns the TLS stack and takes no such
//     switches. Android 10+ negotiates TLS 1.3 by default and recent Chromium
//     WebViews offer X25519MLKEM768; neither can be pinned from inside the app,
//     so `TlsPolicy::enforced_by_app` reports false there rather than claiming
//     a control that does not exist.
//
// The transport is a defence-in-depth layer regardless: message, call and vault
// payloads are already end-to-end encrypted before they reach it.
//
// This struct records what was CONFIGURED. The dashboard gate is decided in the
// frontend from what was NEGOTIATED (src/lib/transport-evidence.ts measures the
// live backend connection), so Android passes on a measured TLS 1.3 + hybrid
// ML-KEM connection and Windows fails if its runtime ignored the request.
// ---------------------------------------------------------------------------

/// Which transport posture this launch asked the WebView for.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TlsPolicy {
    /// "strict" (default) or "compat", from `QGUARD_TLS_POLICY`.
    pub mode: String,
    /// Strict mode refuses anything below TLS 1.3 outright.
    pub minimum_version: String,
    /// Hybrid post-quantum key agreement (X25519MLKEM768) requested.
    pub post_quantum_key_agreement: bool,
    /// False where the platform gives the app no way to set this (Android).
    pub enforced_by_app: bool,
    pub detail: String,
}

/// Read the operator's transport policy. `compat` exists because a TLS-1.2-only
/// inspection proxy would otherwise break every connection with no diagnosable
/// cause; it is a deliberate, named, visible downgrade rather than a silent one.
pub fn tls_policy() -> TlsPolicy {
    let strict = !std::env::var("QGUARD_TLS_POLICY")
        .map(|value| value.trim().eq_ignore_ascii_case("compat"))
        .unwrap_or(false);
    let enforced = cfg!(target_os = "windows");
    TlsPolicy {
        mode: if strict { "strict" } else { "compat" }.to_string(),
        minimum_version: if strict { "TLS 1.3" } else { "TLS 1.2" }.to_string(),
        post_quantum_key_agreement: true,
        enforced_by_app: enforced,
        detail: if !enforced {
            "The platform WebView owns the TLS stack on this OS; the app cannot pin a minimum version. Application payloads remain end-to-end encrypted independently of the transport.".to_string()
        } else if strict {
            "Strict: connections below TLS 1.3 are refused and hybrid post-quantum key agreement (X25519MLKEM768) is requested. Set QGUARD_TLS_POLICY=compat to allow TLS 1.2 where an inspection proxy requires it.".to_string()
        } else {
            "Compat: TLS 1.2 is permitted by policy (QGUARD_TLS_POLICY=compat). Hybrid post-quantum key agreement is still requested.".to_string()
        },
    }
}

/// The WebView2 switches that implement [`tls_policy`].
///
/// Unrecognised `--enable-features` names are ignored by Chromium, so naming
/// both the historical and current spellings of the post-quantum feature is
/// safe across the WebView2 versions this app supports (Chromium 86+).
pub fn tls_browser_arguments(policy: &TlsPolicy) -> String {
    let mut args = String::from("--enable-features=PostQuantumKyber,UseMLKEMForTLS");
    if policy.mode == "strict" {
        args.push_str(" --ssl-version-min=tls1.3");
    }
    args
}

#[cfg(test)]
mod tls_policy_tests {
    use super::*;

    #[test]
    fn strict_mode_pins_tls13_and_requests_hybrid_pq() {
        let policy = TlsPolicy {
            mode: "strict".to_string(),
            minimum_version: "TLS 1.3".to_string(),
            post_quantum_key_agreement: true,
            enforced_by_app: true,
            detail: String::new(),
        };
        let args = tls_browser_arguments(&policy);
        assert!(args.contains("--ssl-version-min=tls1.3"));
        assert!(args.contains("PostQuantumKyber"));
    }

    #[test]
    fn compat_mode_drops_the_floor_but_keeps_hybrid_pq() {
        let policy = TlsPolicy {
            mode: "compat".to_string(),
            minimum_version: "TLS 1.2".to_string(),
            post_quantum_key_agreement: true,
            enforced_by_app: true,
            detail: String::new(),
        };
        let args = tls_browser_arguments(&policy);
        assert!(!args.contains("ssl-version-min"));
        assert!(args.contains("UseMLKEMForTLS"));
    }

    #[test]
    fn the_default_policy_is_strict() {
        // Nothing in the process sets it, so this reads the shipped default.
        if std::env::var("QGUARD_TLS_POLICY").is_err() {
            assert_eq!(tls_policy().mode, "strict");
        }
    }
}

pub fn hardening_status(audit_chain_valid: bool) -> SecurityHardeningStatus {
    build_hardening_status(
        audit_chain_valid,
        current_binary_measurement(),
        &selftest::report(),
        debugger_probe(),
    )
}

/// The report, as a function of what was measured. Split from
/// [`hardening_status`] so each row can be exercised against a measurement
/// that did not go well, not only against this process's own.
fn build_hardening_status(
    audit_chain_valid: bool,
    binary_measurement: BinaryMeasurement,
    self_test: &selftest::SelfTestReport,
    debugger_probe: Option<bool>,
) -> SecurityHardeningStatus {
    let transport_policy = tls_policy();
    let debugger_detected = debugger_probe == Some(true);
    let debugger_clear = debugger_probe == Some(false);
    let post_quantum_self_test = self_test.post_quantum();
    let symmetric_self_test = self_test.symmetric();
    let binary_hash_available = binary_measurement.sha3.is_some();
    let signed_build_verification =
        option_env!("QGUARD_SIGNED_BUILD").is_some_and(|value| value == "1");
    // Binary integrity: prefer a compile-time pin (CI), else a release manifest
    // (`release.integrity.json`) shipped beside the binary. When a release signing
    // key is embedded at build time, the manifest signature is verified too. (A
    // self-checking hash cannot defend against an attacker who also rewrites the
    // check; code signing provides the external trust root -- see signed build.)
    let release_manifest = read_release_manifest();
    let expected_binary_sha3 = option_env!("QGUARD_EXPECTED_BINARY_SHA3")
        .map(str::to_string)
        .or_else(|| release_manifest.as_ref().map(|manifest| manifest.binary_sha3.clone()));
    let binary_hash_match = match (&binary_measurement.sha3, &expected_binary_sha3) {
        (Some(actual), Some(expected)) => actual.eq_ignore_ascii_case(expected),
        _ => false,
    };
    // Some(true/false) when a release key + manifest signature are both present.
    let manifest_signature_valid = release_manifest
        .as_ref()
        .and_then(release_manifest_signature_valid);
    let binary_integrity_verified = binary_hash_match && manifest_signature_valid != Some(false);
    let binary_integrity_detail = if !binary_hash_available {
        "Runtime binary hash unavailable"
    } else if expected_binary_sha3.is_none() {
        "Runtime binary hash captured; no release manifest or hash pin configured"
    } else if !binary_hash_match {
        "Runtime binary hash does not match the release manifest"
    } else if manifest_signature_valid == Some(false) {
        "Release manifest signature is invalid"
    } else if manifest_signature_valid == Some(true) {
        "Runtime binary hash matches the signed release manifest"
    } else {
        "Runtime binary hash matches the release manifest (unsigned; code signing adds an external trust root)"
    };
    // Name the artifact that was actually measured, and distinguish "could not
    // find our image" from "found it but could not read it". The previous text
    // said only "could not be measured", which is what let a packaging change
    // (the release APK stopping shipping a standalone `.so`) sit unexplained on
    // the dashboard instead of pointing at the file it had looked for.
    let measured_artifact = binary_measurement.path.as_deref().map(artifact_name);
    let anti_tampering_detail = match (binary_hash_available, measured_artifact) {
        (true, Some(name)) => format!("Runtime image measured: {name}"),
        (true, None) => "Runtime image measured".to_string(),
        (false, Some(name)) => format!("Runtime image {name} could not be read"),
        (false, None) => "Runtime image could not be located in this process".to_string(),
    };
    let integrity_hash_detail = match (binary_hash_available, measured_artifact) {
        (true, Some(name)) => format!("SHA3-256 runtime hash computed over {name}"),
        (true, None) => "SHA3-256 runtime hash check is available".to_string(),
        (false, _) => "SHA3-256 runtime hash check failed: no runtime image to hash".to_string(),
    };

    let release_hardened = !cfg!(debug_assertions);
    let code_obfuscation = release_hardened;
    let control_flow_flattening =
        option_env!("QGUARD_CONTROL_FLOW_FLATTENING").is_some_and(|value| value == "1");
    // Sensitive identifiers and protocol domain-separation tags are XOR-obfuscated
    // at compile time (see security::obf). Whether that actually holds for THIS
    // image is measured, not assumed: the running image is searched for those
    // identifiers in clear while it is being hashed (see `measure_file`).
    let string_encryption = binary_measurement.protected_strings_exposed == Some(false);
    let string_encryption_detail = match (binary_measurement.protected_strings_exposed, measured_artifact) {
        (Some(false), Some(name)) => format!(
            "Protected identifiers checked against {name}: none appears in clear"
        ),
        (Some(false), None) => "Protected identifiers checked against the running image: none appears in clear".to_string(),
        (Some(true), _) => "A protected identifier appears in clear in the running image".to_string(),
        (None, _) => "Not measured: the running image could not be read".to_string(),
    };

    let checks = vec![
        check(
            "anti_debugger_protection",
            "Anti-Debugger Protection",
            debugger_clear,
            match debugger_probe {
                Some(true) => "Debugger detected by native runtime guard",
                Some(false) => "Native debugger probe is clear",
                None => "Not measured: this platform has no native debugger probe",
            },
        ),
        check(
            "anti_tampering_detection",
            "Anti-Tampering Detection",
            binary_hash_available && debugger_clear,
            anti_tampering_detail,
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
            integrity_hash_detail,
        ),
        check(
            "secure_memory_zeroize",
            "Secure Memory (zeroize)",
            self_test.zeroize.is_ok(),
            match &self_test.zeroize {
                Ok(()) => "Wipe self-test passed; key types zeroize themselves when dropped".to_string(),
                Err(failure) => format!("Wipe self-test FAILED: {failure}"),
            },
        ),
        check(
            "symmetric_crypto_self_test",
            "AES-256-GCM / SHA3-256 Self-Test",
            symmetric_self_test.is_ok(),
            match &symmetric_self_test {
                Ok(()) => "AES-256-GCM round trip, tamper rejection and SHA3-256 test vectors passed at start-up".to_string(),
                Err(failure) => format!("Start-up self-test FAILED: {failure}"),
            },
        ),
        check(
            "tls_transport_policy",
            "Transport Policy (TLS 1.3 + hybrid PQ)",
            transport_policy.enforced_by_app && transport_policy.mode == "strict",
            &transport_policy.detail,
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
            post_quantum_self_test.is_ok(),
            match &post_quantum_self_test {
                Ok(()) => "X25519 + ML-KEM-1024 key agreement and Ed25519 + ML-DSA-65 signatures passed their start-up self-test".to_string(),
                Err(failure) => format!("Start-up self-test FAILED: {failure}"),
            },
        ),
        check(
            "rate_limiting",
            "Rate Limiting",
            self_test.rate_limiter.is_ok(),
            match &self_test.rate_limiter {
                Ok(()) => "Native key operations (unlock, rotation, clean-up, identity reset) are rate limited; limiter self-test passed".to_string(),
                Err(failure) => format!("Rate limiter self-test FAILED: {failure}"),
            },
        ),
        check(
            "code_obfuscation",
            "Code Obfuscation",
            code_obfuscation,
            if code_obfuscation {
                "Release build: symbols stripped, link-time optimised, size-optimised"
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
            "String Obfuscation",
            string_encryption,
            string_encryption_detail,
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
        anti_debugger_protection: debugger_clear,
        anti_tampering_detection: binary_hash_available && debugger_clear,
        binary_integrity_verification: binary_integrity_verified,
        secure_memory_zeroize: self_test.zeroize.is_ok(),
        tamper_evident_audit_chain: audit_chain_valid,
        post_quantum_protection: post_quantum_self_test.is_ok(),
        rate_limiting: self_test.rate_limiter.is_ok(),
        code_obfuscation,
        control_flow_flattening,
        string_encryption,
        signed_build_verification,
        integrity_hash_checks: binary_hash_available,
        tls_policy: transport_policy,
    }
}

#[derive(Clone)]
struct BinaryMeasurement {
    sha3: Option<String>,
    path: Option<String>,
    /// Whether any identifier `security::obf` is meant to hide was found in
    /// clear in the image. `None` when the image could not be read.
    protected_strings_exposed: Option<bool>,
}

/// Identifiers that must not be readable in the shipped image. Reconstructed at
/// run time from their obfuscated form, so this list does not itself put them
/// in the binary. Short values are left out: a few bytes can occur by chance.
fn protected_identifiers() -> Vec<Vec<u8>> {
    [
        obf::keyring_service_bytes(),
        obf::hkdf_salt(),
        obf::key_material_aad(),
        obf::vault_master_material_aad(),
        obf::vault_stream_wrap_info(),
        obf::workspace_vault_unlock_info(),
    ]
    .into_iter()
    .filter(|identifier| identifier.len() >= 16)
    .collect()
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    let first = needle[0];
    let last_start = haystack.len() - needle.len();
    let mut index = 0;
    while index <= last_start {
        match haystack[index..=last_start].iter().position(|byte| *byte == first) {
            Some(offset) => {
                let start = index + offset;
                if &haystack[start..start + needle.len()] == needle {
                    return true;
                }
                index = start + 1;
            }
            None => return false,
        }
    }
    false
}

/// Whether any of `identifiers` occurs in `image`.
fn any_identifier_in_clear(image: &[u8], identifiers: &[Vec<u8>]) -> bool {
    identifiers
        .iter()
        .any(|identifier| contains_bytes(image, identifier))
}

fn check(id: &str, label: &str, active: bool, detail: impl Into<String>) -> SecurityHardeningCheck {
    SecurityHardeningCheck {
        id: id.to_string(),
        label: label.to_string(),
        status: if active { "active" } else { "warning" }.to_string(),
        active,
        detail: detail.into(),
    }
}

fn measure_file(path: &std::path::Path) -> BinaryMeasurement {
    // One read serves both measurements: the hash, and the search for
    // identifiers that are supposed to be obfuscated.
    let image = std::fs::read(path).ok();
    let sha3 = image.as_deref().map(sha3_hex);
    let protected_strings_exposed = image
        .as_deref()
        .map(|bytes| any_identifier_in_clear(bytes, &protected_identifiers()));
    BinaryMeasurement {
        sha3,
        path: Some(path.to_string_lossy().to_string()),
        protected_strings_exposed,
    }
}

/// A symbol guaranteed to live inside THIS library's own loaded image. Its
/// address is what identifies our mapping in `/proc/self/maps`; see
/// `locate_self_image`.
#[cfg(any(target_os = "android", test))]
#[inline(never)]
fn image_anchor() {}

/// Skip `count` whitespace-separated fields and return the remainder.
///
/// `/proc/<pid>/maps` pathnames may contain spaces, so the path is taken as
/// everything after the fixed fields rather than as the last field.
#[cfg(any(target_os = "android", test))]
fn skip_fields(mut rest: &str, count: usize) -> Option<&str> {
    for _ in 0..count {
        rest = rest.trim_start();
        let end = rest.find(char::is_whitespace)?;
        rest = &rest[end..];
    }
    Some(rest.trim_start())
}

/// The file backing the mapping that CONTAINS `addr`, parsed from the text of a
/// `/proc/<pid>/maps` file.
///
/// Containment — not a filename match — is the identifying test, and that is the
/// whole point. See `locate_self_image` for why matching on the name failed.
#[cfg(any(target_os = "android", test))]
fn mapping_backing_file(maps: &str, addr: usize) -> Option<String> {
    for line in maps.lines() {
        // "start-end perms offset dev inode    pathname"
        let Some((range, rest)) = line.split_once(' ') else { continue };
        let Some((start, end)) = range.split_once('-') else { continue };
        let (Ok(start), Ok(end)) = (
            usize::from_str_radix(start, 16),
            usize::from_str_radix(end, 16),
        ) else {
            continue;
        };
        if addr < start || addr >= end {
            continue;
        }
        let Some(path) = skip_fields(rest, 4) else { continue };
        // A file replaced while still mapped (an app upgrade in flight) keeps
        // its mapping but gains this marker; the name before it is still the
        // file we were loaded from.
        let path = path.strip_suffix(" (deleted)").unwrap_or(path).trim_end();
        // Anonymous regions and the kernel's pseudo-mappings ("[stack]",
        // "[heap]", "[vdso]") have no backing file and are skipped by this.
        if !path.starts_with('/') {
            continue;
        }
        return Some(path.to_string());
    }
    None
}

/// The on-disk file backing THIS application's own code, read from the kernel's
/// own view of the process.
///
/// TWO Android-specific traps live here, and the second one is why the first
/// fix was not enough.
///
/// 1. `std::env::current_exe()` is not our code on Android: the process
///    executable is the zygote (`/system/bin/app_process64`), which every app on
///    the device shares and which the app sandbox cannot read anyway.
///
/// 2. Looking for a mapped path that ends in `.so` and contains the crate name
///    then found nothing on RELEASE builds. Release variants are packaged with
///    `extractNativeLibs="false"`, so there is no `.so` on disk at all: the
///    library is stored uncompressed inside the APK and mapped straight out of
///    it, and `/proc/self/maps` names the backing file — `.../base.apk`. Debug
///    variants set `extractNativeLibs="true"` (AGP does this to speed up
///    incremental installs) and DO have a real `.so`, which is exactly why this
///    only ever failed on an installed release build.
///
/// Both traps are the same mistake: guessing at the path instead of asking which
/// file backs our code. `image_anchor` is unambiguously inside our own image, so
/// the mapping that contains its address is ours whatever the file is called —
/// extracted `.so`, in-APK `base.apk`, or any future packaging. No JNI, no APK
/// layout assumptions, no name matching.
#[cfg(target_os = "android")]
fn locate_self_image() -> Option<String> {
    let maps = std::fs::read_to_string("/proc/self/maps").ok()?;
    mapping_backing_file(&maps, image_anchor as *const () as usize)
}

/// Reduce a library path to the file that actually exists on disk.
///
/// The kernel's maps name the plain APK, but bionic's own APIs (`dladdr`,
/// `dl_iterate_phdr`, linker errors, crash dumps) report a library loaded from
/// inside an APK using the composite form
/// `/data/app/.../base.apk!/lib/arm64-v8a/libfoo.so`. That string names no file,
/// so anything reaching us in that form has to be reduced to its container
/// before it can be read.
#[cfg(any(target_os = "android", test))]
fn container_path(path: &str) -> &str {
    match path.find("!/") {
        Some(index) => &path[..index],
        None => path,
    }
}

#[cfg(target_os = "android")]
fn measure_self_image() -> BinaryMeasurement {
    match locate_self_image().as_deref().map(container_path) {
        Some(path) => measure_file(std::path::Path::new(path)),
        // Deliberately reported as unmeasured rather than substituting the
        // zygote: a hash of a file that is not our code would be worse than no
        // hash, because it would look like a passing integrity check.
        None => BinaryMeasurement {
            sha3: None,
            path: None,
            protected_strings_exposed: None,
        },
    }
}

#[cfg(not(target_os = "android"))]
fn measure_self_image() -> BinaryMeasurement {
    match std::env::current_exe() {
        Ok(path) => measure_file(&path),
        Err(_) => BinaryMeasurement {
            sha3: None,
            path: None,
            protected_strings_exposed: None,
        },
    }
}

/// The running image cannot change while the process is alive, so it is hashed
/// at most once. This is not only an optimisation: `security_hardening_status`
/// is a synchronous Tauri command and therefore runs on the main thread, and the
/// artifact being read is tens of megabytes (on Android the whole APK).
/// Re-reading it on every dashboard load would stall the UI.
fn current_binary_measurement() -> BinaryMeasurement {
    static MEASUREMENT: OnceLock<BinaryMeasurement> = OnceLock::new();
    MEASUREMENT.get_or_init(measure_self_image).clone()
}

/// Warm the measurement off the main thread so the first dashboard load never
/// pays for the read. Safe to call more than once.
pub fn prime_binary_measurement() {
    std::thread::spawn(|| {
        let _ = current_binary_measurement();
    });
    // The cryptographic self-test is the other once-per-process measurement.
    selftest::prime();
}

/// Trailing path component, for user-facing detail text.
fn artifact_name(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

/// Whether a debugger is attached to this process: `Some(true)` / `Some(false)`
/// when the platform can say, `None` when it cannot.
///
/// The non-Windows branch used to read an environment variable
/// (`QGUARD_DEBUGGER_ATTACHED`), i.e. it reported "clear" unless the person
/// debugging the app chose to announce themselves. That was not a probe.
#[cfg(windows)]
fn debugger_probe() -> Option<bool> {
    #[link(name = "kernel32")]
    extern "system" {
        fn IsDebuggerPresent() -> i32;
    }

    Some(unsafe { IsDebuggerPresent() != 0 })
}

/// Linux and Android: the kernel records the tracing process, if any, in
/// `/proc/self/status`. A debugger (ptrace) shows up as a non-zero `TracerPid`.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn debugger_probe() -> Option<bool> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    tracer_pid(&status).map(|pid| pid != 0)
}

/// No native probe on this platform. Reported as not measured — never as clear.
#[cfg(not(any(windows, target_os = "linux", target_os = "android")))]
fn debugger_probe() -> Option<bool> {
    None
}

/// The `TracerPid` value from the text of a `/proc/<pid>/status` file.
#[cfg(any(target_os = "linux", target_os = "android", test))]
fn tracer_pid(status: &str) -> Option<u32> {
    status
        .lines()
        .find_map(|line| line.strip_prefix("TracerPid:"))
        .and_then(|value| value.trim().parse().ok())
}

#[derive(Debug, Deserialize)]
struct ReleaseIntegrityManifest {
    binary_sha3: String,
    #[serde(default)]
    signature: Option<String>,
}

/// Read `release.integrity.json` from the directory containing the running
/// executable. Absent in dev builds; written beside the binary by the hardened
/// release pipeline.
fn read_release_manifest() -> Option<ReleaseIntegrityManifest> {
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?;
    let bytes = std::fs::read(dir.join("release.integrity.json")).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Verify the manifest's Ed25519 signature over the pinned hash using the
/// release public key embedded at build time. Returns `Some(true)` when a key
/// and signature are present and valid, `Some(false)` when present but invalid,
/// and `None` when no release key or signature is configured.
fn release_manifest_signature_valid(manifest: &ReleaseIntegrityManifest) -> Option<bool> {
    let pub_hex = option_env!("QGUARD_RELEASE_ED25519_PUB")?;
    let signature_hex = manifest.signature.as_ref()?;
    let (Ok(public_key), Ok(signature)) = (hex::decode(pub_hex), hex::decode(signature_hex)) else {
        return Some(false);
    };
    Some(crate::crypto::provider::ed25519_verify(&public_key, manifest.binary_sha3.as_bytes(), &signature).is_ok())
}

#[cfg(test)]
mod tests {
    use super::{image_anchor, mapping_backing_file};

    #[test]
    fn reads_the_tracer_from_a_proc_status_file() {
        let untraced = "Name:\tqguard\nState:\tR (running)\nTracerPid:\t0\nUid:\t1000\n";
        let traced = "Name:\tqguard\nTracerPid:\t4242\nUid:\t1000\n";
        assert_eq!(super::tracer_pid(untraced), Some(0));
        assert_eq!(super::tracer_pid(traced), Some(4242));
        // A file without the field, or with a malformed one, yields no answer —
        // which the report shows as "not measured", never as "clear".
        assert_eq!(super::tracer_pid("Name:\tqguard\n"), None);
        assert_eq!(super::tracer_pid("TracerPid:\tnot-a-number\n"), None);
        assert_eq!(super::tracer_pid(""), None);
    }

    #[test]
    fn finds_an_identifier_in_clear_and_only_when_it_is_there() {
        let identifiers = vec![b"QGuard-Protected-Identifier-v1".to_vec()];
        let mut image = vec![0u8; 4096];
        assert!(!super::any_identifier_in_clear(&image, &identifiers));

        // At the very start, in the middle, and flush against the end.
        for offset in [0, 1777, 4096 - identifiers[0].len()] {
            let mut with = image.clone();
            with[offset..offset + identifiers[0].len()].copy_from_slice(&identifiers[0]);
            assert!(super::any_identifier_in_clear(&with, &identifiers), "offset {offset}");
        }

        // A near miss (one byte different) and a truncated tail are not matches.
        let mut near = identifiers[0].clone();
        near[5] ^= 0x01;
        image[100..100 + near.len()].copy_from_slice(&near);
        let tail = &identifiers[0][..identifiers[0].len() - 1];
        let tail_start = image.len() - tail.len();
        image[tail_start..].copy_from_slice(tail);
        assert!(!super::any_identifier_in_clear(&image, &identifiers));

        // Repeated first bytes must not make the search skip a real match.
        let needle = vec![b"aab".to_vec()];
        assert!(super::any_identifier_in_clear(b"aaab", &needle));
        assert!(!super::any_identifier_in_clear(b"aaaa", &needle));
        assert!(!super::any_identifier_in_clear(b"", &needle));
        assert!(!super::any_identifier_in_clear(b"abc", &[Vec::new()]));
    }

    #[test]
    fn the_protected_identifier_list_is_long_enough_to_mean_something() {
        let identifiers = super::protected_identifiers();
        assert!(identifiers.len() >= 4, "{} identifiers", identifiers.len());
        assert!(identifiers.iter().all(|identifier| identifier.len() >= 16));
    }

    fn measured(protected_strings_exposed: Option<bool>) -> super::BinaryMeasurement {
        super::BinaryMeasurement {
            sha3: protected_strings_exposed.map(|_| "ab".repeat(32)),
            path: protected_strings_exposed.map(|_| "/opt/qguard/qguard-messaging".to_string()),
            protected_strings_exposed,
        }
    }

    fn row<'a>(status: &'a super::SecurityHardeningStatus, id: &str) -> &'a super::SecurityHardeningCheck {
        status.checks.iter().find(|check| check.id == id).unwrap_or_else(|| panic!("no {id} row"))
    }

    #[test]
    fn every_measured_row_follows_its_measurement() {
        let healthy = super::selftest::report();

        // Everything measured and clean.
        let good = super::build_hardening_status(true, measured(Some(false)), &healthy, Some(false));
        for id in [
            "anti_debugger_protection",
            "anti_tampering_detection",
            "runtime_integrity_hash_checks",
            "secure_memory_zeroize",
            "symmetric_crypto_self_test",
            "post_quantum_protection",
            "rate_limiting",
            "string_encryption",
            "tamper_evident_audit_chain",
        ] {
            assert!(row(&good, id).active, "{id}: {}", row(&good, id).detail);
        }
        assert!(row(&good, "string_encryption").detail.contains("qguard-messaging"));

        // A debugger attached: both rows that depend on it go out.
        let debugged = super::build_hardening_status(true, measured(Some(false)), &healthy, Some(true));
        assert!(debugged.debugger_detected);
        assert!(!row(&debugged, "anti_debugger_protection").active);
        assert!(!row(&debugged, "anti_tampering_detection").active);

        // No probe on this platform: "not measured", never "clear".
        let unprobed = super::build_hardening_status(true, measured(Some(false)), &healthy, None);
        assert!(!unprobed.debugger_detected);
        assert!(!row(&unprobed, "anti_debugger_protection").active);
        assert!(row(&unprobed, "anti_debugger_protection").detail.starts_with("Not measured"));

        // A protected identifier readable in the image.
        let exposed = super::build_hardening_status(true, measured(Some(true)), &healthy, Some(false));
        assert!(!row(&exposed, "string_encryption").active);
        assert!(!exposed.string_encryption);

        // The image could not be read at all.
        let unread = super::build_hardening_status(true, measured(None), &healthy, Some(false));
        assert!(!row(&unread, "string_encryption").active);
        assert!(row(&unread, "string_encryption").detail.starts_with("Not measured"));
        assert!(!row(&unread, "runtime_integrity_hash_checks").active);

        // A self-test that failed is reported as failed, in every place it shows.
        let mut broken = healthy.clone();
        broken.signatures = Err("a broken ML-DSA-65 half was accepted".to_string());
        broken.zeroize = Err("a wiped key array still held data".to_string());
        broken.rate_limiter = Err("the rate limiter admitted an attempt past its limit".to_string());
        broken.aead = Err("AES-256-GCM accepted a modified ciphertext".to_string());
        let failed = super::build_hardening_status(true, measured(Some(false)), &broken, Some(false));
        for id in ["post_quantum_protection", "secure_memory_zeroize", "rate_limiting", "symmetric_crypto_self_test"] {
            assert!(!row(&failed, id).active, "{id}");
            assert!(row(&failed, id).detail.contains("FAILED"), "{id}: {}", row(&failed, id).detail);
        }
        assert!(!failed.post_quantum_protection);
        assert!(!failed.secure_memory_zeroize);
        assert!(!failed.rate_limiting);

        // And a broken audit chain.
        assert!(!row(&super::build_hardening_status(false, measured(Some(false)), &healthy, Some(false)), "tamper_evident_audit_chain").active);
    }

    #[test]
    fn the_report_carries_no_unmeasured_assertions() {
        // Every row must be something this function derived. The seven fields
        // that were hardcoded `true` are gone from the serialized report.
        let status = super::build_hardening_status(true, measured(Some(false)), &super::selftest::report(), Some(false));
        let json = serde_json::to_value(&status).unwrap();
        for removed in [
            "plaintext_logging_disabled",
            "aead_required",
            "nonce_uniqueness_checked",
            "replay_protection_enabled",
            "strict_cors_required_for_relay",
            "secure_headers_documented",
            "dependency_scanning_documented",
        ] {
            assert!(json.get(removed).is_none(), "{removed} is still reported");
        }
        // The self-tested rows agree with the self-test itself.
        let self_test = super::selftest::report();
        assert_eq!(status.post_quantum_protection, self_test.post_quantum().is_ok());
        assert_eq!(status.secure_memory_zeroize, self_test.zeroize.is_ok());
        assert_eq!(status.rate_limiting, self_test.rate_limiter.is_ok());
        // And the release text no longer describes a profile setting the
        // project does not use.
        assert!(status.checks.iter().all(|check| !check.detail.contains("panic abort")));
    }

    /// A DEBUG Android variant: `extractNativeLibs="true"`, so the library is
    /// unpacked to `lib/` and mapped from a real `.so`.
    const EXTRACTED_MAPS: &str = "\
7f8a1c0000-7f8a1c8000 r--p 00000000 fd:03 1441802 /data/app/~~kQ9==/com.qguard.messaging-xY7==/lib/arm64/libqguard_messaging_lib.so
7f8a1c8000-7f8a9d4000 r-xp 00008000 fd:03 1441802 /data/app/~~kQ9==/com.qguard.messaging-xY7==/lib/arm64/libqguard_messaging_lib.so
7f8a9d4000-7f8a9e0000 rw-p 00000000 00:00 0 [anon:.bss]
7fff2a1000-7fff2c2000 rw-p 00000000 00:00 0 [stack]
";

    /// A RELEASE Android variant: `extractNativeLibs="false"`, so no `.so` is
    /// written to disk at all and the library is mapped straight out of the
    /// uncompressed APK entry. This is the shape that produced the reported
    /// "Runtime binary could not be measured" on the physical tablet.
    const IN_APK_MAPS: &str = "\
7f8a1c0000-7f8a1c8000 r--p 003a1000 fd:03 1441800 /data/app/~~kQ9==/com.qguard.messaging-xY7==/base.apk
7f8a1c8000-7f8a9d4000 r-xp 003a9000 fd:03 1441800 /data/app/~~kQ9==/com.qguard.messaging-xY7==/base.apk
7f8a9d4000-7f8a9e0000 rw-p 00000000 00:00 0 [anon:.bss]
";

    const CODE_ADDR: usize = 0x7f8a_2000_00;

    #[test]
    fn measures_the_library_when_the_release_packaging_maps_it_out_of_the_apk() {
        // The regression under test: name matching ("ends with .so and contains
        // the crate name") finds nothing here, because the release APK ships no
        // standalone .so. Containment finds our image regardless.
        assert_eq!(
            mapping_backing_file(IN_APK_MAPS, CODE_ADDR).as_deref(),
            Some("/data/app/~~kQ9==/com.qguard.messaging-xY7==/base.apk"),
        );
    }

    #[test]
    fn measures_the_extracted_library_when_one_is_unpacked() {
        assert_eq!(
            mapping_backing_file(EXTRACTED_MAPS, CODE_ADDR).as_deref(),
            Some("/data/app/~~kQ9==/com.qguard.messaging-xY7==/lib/arm64/libqguard_messaging_lib.so"),
        );
    }

    #[test]
    fn ignores_anonymous_and_pseudo_mappings() {
        // 0x7f8a9d8000 falls inside "[anon:.bss]" in both fixtures: a mapping
        // with no backing file must never be reported as a measurable image.
        assert_eq!(mapping_backing_file(EXTRACTED_MAPS, 0x7f8a_9d80_00), None);
    }

    #[test]
    fn reports_the_original_file_when_an_upgrade_replaced_it_mid_run() {
        let maps = "7f8a1c8000-7f8a9d4000 r-xp 00008000 fd:03 1441802 /data/app/~~kQ9==/pkg/base.apk (deleted)\n";
        assert_eq!(
            mapping_backing_file(maps, CODE_ADDR).as_deref(),
            Some("/data/app/~~kQ9==/pkg/base.apk"),
        );
    }

    #[test]
    fn keeps_pathnames_that_contain_spaces_intact() {
        // The path is the remainder of the line, not its last whitespace field.
        let maps = "7f8a1c8000-7f8a9d4000 r-xp 00008000 fd:03 1441802 /data/app/My App/base.apk\n";
        assert_eq!(
            mapping_backing_file(maps, CODE_ADDR).as_deref(),
            Some("/data/app/My App/base.apk"),
        );
    }

    #[test]
    fn reduces_a_composite_in_apk_library_path_to_the_apk_that_holds_it() {
        // `dladdr`/`dl_iterate_phdr` name an in-APK library this way. The "!/"
        // form is a linker construct, not a file, so only the container can be
        // read -- and the plain APK path must pass through untouched.
        assert_eq!(
            super::container_path("/data/app/~~kQ9==/pkg/base.apk!/lib/arm64-v8a/libqguard_messaging_lib.so"),
            "/data/app/~~kQ9==/pkg/base.apk",
        );
        assert_eq!(super::container_path("/data/app/~~kQ9==/pkg/base.apk"), "/data/app/~~kQ9==/pkg/base.apk");
        assert_eq!(super::container_path("/x/lib/libfoo.so"), "/x/lib/libfoo.so");
    }

    #[test]
    fn returns_none_when_no_mapping_contains_the_address() {
        assert_eq!(mapping_backing_file(EXTRACTED_MAPS, 0x10_0000), None);
        assert_eq!(mapping_backing_file("", CODE_ADDR), None);
        assert_eq!(mapping_backing_file("garbage line\n", CODE_ADDR), None);
    }

    #[test]
    fn the_anchor_address_resolves_against_this_processs_own_mappings() {
        // Not Android, but the parser has to agree with a real kernel dump: the
        // anchor lives in this test binary, so its address must resolve to a
        // real file on any platform that publishes /proc/self/maps.
        let Ok(maps) = std::fs::read_to_string("/proc/self/maps") else {
            return; // Windows/macOS: no procfs, nothing to cross-check here.
        };
        let resolved = mapping_backing_file(&maps, image_anchor as *const () as usize);
        assert!(resolved.is_some(), "anchor did not resolve against real maps");
        assert!(std::path::Path::new(&resolved.unwrap()).exists());
    }
}
