//! What the cryptographic boundary can truthfully report about itself
//! (Settings → Security → FIPS 140-3, `commands::crypto_module`).
//!
//! Two different claims are kept apart everywhere:
//! * `approved`  — the ALGORITHM is FIPS-approved (true for AES-GCM, SHA-3,
//!   ML-KEM, ... whichever backend runs it);
//! * `validated` — THIS BUILD performs it inside a module whose CMVP
//!   certificate lists it. Only a wolfCrypt FIPS build can make that true, and
//!   only for the algorithms its certificate covers.

use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ModuleIdentity {
    pub backend: String,
    pub name: String,
    pub version: String,
    /// The wolfCrypt FIPS package version, for a FIPS build only.
    pub fips_module_version: Option<String>,
    /// `wolfCrypt_GetStatus_fips()` (0 = operational), for a FIPS build only.
    pub fips_status: Option<i32>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Certificate {
    pub number: u32,
    pub module: &'static str,
    pub module_version: &'static str,
    pub standard: &'static str,
    pub validated_on: &'static str,
    pub sunset: &'static str,
    pub url: String,
    /// Algorithm ids (see `algorithms`) inside this certificate's boundary.
    pub covers: Vec<&'static str>,
    /// The tested operational environments relevant to this app.
    pub tested_platforms: Vec<&'static str>,
}

/// The wolfCrypt FIPS 140-3 certificate a FIPS package version maps to.
/// Checked on csrc.nist.gov on 2026-11-03; none of them lists ML-KEM, ML-DSA,
/// EdDSA, HKDF or PBKDF (the "wolfCrypt Post Quantum" module that would is
/// still on the CMVP Implementation Under Test list).
pub fn wolfcrypt_certificate(fips_module_version: &str) -> Option<Certificate> {
    let common = ["aes-256-gcm", "sha3", "sha2", "hmac-sha3-256", "drbg"];
    let (number, module_version, validated_on, sunset, tested_platforms) = match fips_module_version {
        "5.2.3" => (
            5548,
            "5.2.3",
            "2026-10-09",
            "2031-10-08",
            vec![
                "Windows 11 Pro — Intel Core i7-1255U",
                "Android 13 — Samsung Galaxy S23 (Snapdragon 8 Gen 2)",
                "Android 11 — MediaTek MT6762",
            ],
        ),
        "5.2.0" | "5.2.0.1" => (5041, "5.2.0.1", "2025-07-18", "2030-07-17", vec!["Windows 10 — Intel Core i5-5300U"]),
        _ => return None,
    };
    Some(Certificate {
        number,
        module: "wolfCrypt",
        module_version,
        standard: "FIPS 140-3 Level 1",
        validated_on,
        sunset,
        url: format!("https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/{number}"),
        covers: common.to_vec(),
        tested_platforms,
    })
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AlgorithmStatus {
    pub id: &'static str,
    pub name: &'static str,
    pub standard: &'static str,
    pub used_for: &'static str,
    /// A FIPS-approved algorithm.
    pub approved: bool,
    /// Performed inside a validated module in this build.
    pub validated: bool,
    pub note: Option<&'static str>,
}

pub fn algorithms(backend: &str, certificate: Option<&Certificate>) -> Vec<AlgorithmStatus> {
    let covered = |id: &str| certificate.is_some_and(|c| c.covers.contains(&id));
    let os_generator = backend != "wolfcrypt";
    let row = |id, name, standard, used_for, approved, note| AlgorithmStatus {
        id,
        name,
        standard,
        used_for,
        approved,
        validated: approved && covered(id),
        note,
    };
    vec![
        row("aes-256-gcm", "AES-256-GCM", "SP 800-38D", "Messages, files, attachments, key wrapping", true, Some("Encryption nonces are generated inside the module (IG C.H).")),
        row("sha3", "SHA3-256 / SHA3-512", "FIPS 202", "Fingerprints, transcripts, file integrity", true, None),
        row("sha2", "SHA-256 / SHA-512", "FIPS 180-4", "PBKDF2 in approved mode, legacy digests", true, None),
        row("hmac-sha3-256", "HMAC-SHA3-256", "FIPS 198-1", "Ratchet chain keys, verification codes", true, None),
        row("hkdf", "HKDF-SHA3-256", "SP 800-56C r2", "Every derived key", true, None),
        row("pbkdf2", "PBKDF2-HMAC-SHA-512", "SP 800-132", "Passwords and PINs in approved mode", true, None),
        row("ml-kem-1024", "ML-KEM-1024", "FIPS 203", "Key establishment (hybrid with X25519)", true, None),
        row("ml-dsa", "ML-DSA-65 / ML-DSA-87", "FIPS 204", "Device identity (65), Quantum Vault headers (87)", true, None),
        row("ed25519", "Ed25519", "FIPS 186-5", "Classical half of every dual signature", true, None),
        if os_generator {
            row("drbg", "Operating-system random generator", "—", "Keys, nonces, salts", false, Some("Windows BCryptGenRandom / Android getrandom, outside this module."))
        } else {
            row("drbg", "Hash_DRBG", "SP 800-90A", "Keys, nonces, salts", true, None)
        },
        row("x25519", "X25519", "RFC 7748", "Classical half of the hybrid key exchange", false, Some("Not FIPS-approved. Only ever combined with ML-KEM-1024, whose approved secret comes first in the HKDF combiner (SP 800-56C r2).")),
        row("argon2id", "Argon2id", "RFC 9106", "Passwords and PINs in standard mode", false, Some("Not FIPS-approved. Replaced by PBKDF2 in approved mode; read only to open older credentials.")),
        row("shamir", "Shamir secret sharing", "—", "Splitting recovery secrets", false, Some("Not a FIPS-approved function.")),
    ]
}

/// Cryptography the app relies on that does not go through this boundary.
pub fn outside_boundary() -> Vec<&'static str> {
    vec![
        "Call audio and video frames are encrypted with AES-256-GCM by the WebView's WebCrypto (WebRTC encoded transforms), not by this module.",
        "TLS to the QGuard servers is the WebView's network stack.",
        "The device storage key is held by the platform key store (Android Keystore, Windows Credential Manager).",
        "The browser preview build uses WebCrypto and @noble/hashes; the desktop and Android apps route that work to this module.",
    ]
}
