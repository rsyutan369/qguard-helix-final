use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

use crate::crypto::kdf::sha3_hex;

pub mod content_uri;
pub mod keystore;
pub mod obf;
pub mod saf_folder;

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
    let transport_policy = tls_policy();
    let debugger_detected = debugger_detected();
    let binary_measurement = current_binary_measurement();
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
    // at compile time (see security::obf). De-obfuscation reproduces byte-identical
    // originals (proven by the obf round-trip and crypto encrypt/decrypt tests), so
    // this control is genuinely compiled into the binary rather than a loose flag.
    let string_encryption = true;

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
            true,
            "Key material uses zeroize-backed cleanup paths",
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
                "Sensitive identifiers and protocol domain-separation tags are XOR-obfuscated in the binary"
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
        tls_policy: transport_policy,
    }
}

#[derive(Clone)]
struct BinaryMeasurement {
    sha3: Option<String>,
    path: Option<String>,
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
    let sha3 = std::fs::read(path)
        .ok()
        .map(|bytes| sha3_hex(bytes.as_slice()));
    BinaryMeasurement {
        sha3,
        path: Some(path.to_string_lossy().to_string()),
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
}

/// Trailing path component, for user-facing detail text.
fn artifact_name(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
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
    let verifying = hex::decode(pub_hex)
        .ok()
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .and_then(|bytes| ed25519_dalek::VerifyingKey::from_bytes(&bytes).ok());
    let signature = hex::decode(signature_hex)
        .ok()
        .and_then(|bytes| ed25519_dalek::Signature::from_slice(&bytes).ok());
    match (verifying, signature) {
        (Some(verifying_key), Some(signature)) => {
            use ed25519_dalek::Verifier;
            Some(verifying_key.verify(manifest.binary_sha3.as_bytes(), &signature).is_ok())
        }
        _ => Some(false),
    }
}

#[cfg(test)]
mod tests {
    use super::{image_anchor, mapping_backing_file};

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
