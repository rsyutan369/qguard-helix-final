//! Known-answer and pairwise self-tests of the active backend.
//!
//! They run once, before the first keyed operation (`provider::operational`),
//! and `lib.rs` starts them in the background at launch so that first call
//! rarely waits. One failure puts the boundary into its error state: every
//! keyed operation refuses for the rest of the process.
//!
//! Vector sources: SHA (FIPS 180-4 / 202 "abc"), AES-256-GCM (GCM spec test
//! case 16), X25519 (RFC 7748 §6.1), Ed25519 (RFC 8032 §7.1 test 1). The
//! HMAC, HKDF and PBKDF2 vectors and the ML-KEM-1024 / ML-DSA vectors in
//! `kat/` were produced by OpenSSL 3.5 and cross-checked against wolfCrypt
//! 5.9.4 and PQClean: both implementations derive the same public keys from
//! the same seeds, decapsulate OpenSSL's ciphertext to its shared secret and
//! accept its signatures (docs/FIPS_140_3.md).

use std::sync::OnceLock;
use std::time::Instant;

use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SelfTestResult {
    pub name: &'static str,
    pub passed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SelfTestReport {
    pub passed: bool,
    pub backend: String,
    pub ran_at: String,
    pub duration_ms: u64,
    pub results: Vec<SelfTestResult>,
}

impl SelfTestReport {
    pub fn failed_names(&self) -> Vec<&'static str> {
        self.results.iter().filter(|r| !r.passed).map(|r| r.name).collect()
    }
}

/// The self-test report of this process, running the suite on first use.
pub fn self_test_report() -> &'static SelfTestReport {
    static REPORT: OnceLock<SelfTestReport> = OnceLock::new();
    REPORT.get_or_init(|| {
        let started = Instant::now();
        let results = suite_active::run();
        let passed = results.iter().all(|r| r.passed);
        if !passed {
            tracing::error!(failed = ?results.iter().filter(|r| !r.passed).map(|r| r.name).collect::<Vec<_>>(), "cryptographic self-test failed; keyed operations disabled");
        }
        SelfTestReport {
            passed,
            backend: super::backend::identity().backend,
            ran_at: chrono::Utc::now().to_rfc3339(),
            duration_ms: started.elapsed().as_millis() as u64,
            results,
        }
    })
}

fn unhex(hex: &str) -> Vec<u8> {
    hex::decode(hex).expect("self-test vector is valid hex")
}

pub(super) fn check(name: &'static str, test: impl FnOnce() -> Result<(), String>) -> SelfTestResult {
    // A panic inside a backend is a failed test, not a crashed app.
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(test)) {
        Ok(Ok(())) => SelfTestResult { name, passed: true, detail: None },
        Ok(Err(detail)) => SelfTestResult { name, passed: false, detail: Some(detail) },
        Err(_) => SelfTestResult { name, passed: false, detail: Some("panicked".to_string()) },
    }
}

fn expect_eq(what: &str, got: &[u8], want_hex: &str) -> Result<(), String> {
    if got == unhex(want_hex).as_slice() {
        Ok(())
    } else {
        Err(format!("{what}: got {}", hex::encode(got)))
    }
}

pub(super) mod vectors {
    pub const SHA3_256_ABC: &str = "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532";
    pub const SHA3_512_ABC: &str = "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0";
    pub const SHA256_ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    pub const SHA512_ABC: &str = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";

    pub const HMAC_KEY: &[u8] = b"QGuard HMAC key 0123456789abcdef";
    pub const HMAC_MSG: &[u8] = b"QGuard HMAC-SHA3-256 KAT";
    pub const HMAC_SHA3_256: &str = "7ab808cda6547388ab74b12b669787869e168c43adfb401352f6e3c1dbdc5318";

    pub const HKDF_IKM: &[u8] = b"QGuard HKDF ikm";
    pub const HKDF_SALT: &[u8] = b"QGuard HKDF salt";
    pub const HKDF_INFO: &[u8] = b"QGuard HKDF info";
    pub const HKDF_SHA3_256_L42: &str = "701af8024a8a3346d30ad00c12fb45d92b3bf656ea4adb171b027364606be75aa2209af08b3f0f75456d";

    pub const PBKDF2_PASSWORD: &[u8] = b"QGuard password 14+";
    pub const PBKDF2_SALT: &[u8] = b"QGuard PBKDF2 salt";
    pub const PBKDF2_ITERATIONS: u32 = 1000;
    pub const PBKDF2_SHA512: &str = "d4afd34b182f5428d1f64351a02f20308c7379fb0e42eed6c3cca951feddcba4";
    pub const PBKDF2_SHA3_256: &str = "2fa92715177fb3f2bef8a7ea81b7ceb72183827f89bc171bdc70c5cca4f9c7e9";
    pub const PBKDF2_SHA256: &str = "657c1b9b918fb2cdce58fc3c81fec9fada76bd791d96ae83063d84833faba0bb";

    // GCM specification, test case 16 (AES-256, 96-bit IV, AAD).
    pub const GCM_KEY: &str = "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308";
    pub const GCM_IV: &str = "cafebabefacedbaddecaf888";
    pub const GCM_AAD: &str = "feedfacedeadbeeffeedfacedeadbeefabaddad2";
    pub const GCM_PT: &str = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39";
    pub const GCM_CT: &str = "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662";
    pub const GCM_TAG: &str = "76fc6ece0f4e1768cddf8853bb2d551b";

    // RFC 7748 §6.1.
    pub const X25519_A_SECRET: &str = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
    pub const X25519_A_PUBLIC: &str = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
    pub const X25519_B_PUBLIC: &str = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
    pub const X25519_SHARED: &str = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";

    // RFC 8032 §7.1, test 1 (empty message).
    pub const ED25519_SEED: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    pub const ED25519_PUBLIC: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    pub const ED25519_SIG: &str = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";

    pub const MLKEM1024_DK: &[u8] = include_bytes!("kat/mlkem1024.dk");
    pub const MLKEM1024_EK: &[u8] = include_bytes!("kat/mlkem1024.ek");
    pub const MLKEM1024_CT: &[u8] = include_bytes!("kat/mlkem1024.ct");
    pub const MLKEM1024_SS: &[u8] = include_bytes!("kat/mlkem1024.ss");
    pub const MLDSA_MSG: &[u8] = include_bytes!("kat/mldsa.msg");
    pub const MLDSA65_PK: &[u8] = include_bytes!("kat/mldsa65.pk");
    pub const MLDSA65_SIG: &[u8] = include_bytes!("kat/mldsa65.sig");
    pub const MLDSA87_PK: &[u8] = include_bytes!("kat/mldsa87.pk");
    pub const MLDSA87_SIG: &[u8] = include_bytes!("kat/mldsa87.sig");
}

/// The suite, written once and instantiated per backend.
macro_rules! define_suite {
    ($module:ident, $backend:path) => {
        pub(super) mod $module {
            use super::vectors as v;
            use super::{check, expect_eq, unhex, SelfTestResult};
            use crate::crypto::provider::{Hash, MlDsa};
            use $backend as b;

            fn arr<const N: usize>(hex: &str) -> [u8; N] {
                let bytes = unhex(hex);
                let mut out = [0u8; N];
                out.copy_from_slice(&bytes);
                out
            }

            fn err(e: impl std::fmt::Display) -> String {
                e.to_string()
            }

            pub(crate) fn run() -> Vec<SelfTestResult> {
                let mut results = Vec::new();
                for (name, hash, want) in [
                    ("SHA3-256", Hash::Sha3_256, v::SHA3_256_ABC),
                    ("SHA3-512", Hash::Sha3_512, v::SHA3_512_ABC),
                    ("SHA-256", Hash::Sha256, v::SHA256_ABC),
                    ("SHA-512", Hash::Sha512, v::SHA512_ABC),
                ] {
                    results.push(check(name, || {
                        let mut out = vec![0u8; hash.output_bytes()];
                        b::hash(hash, b"abc", &mut out).map_err(err)?;
                        expect_eq(name, &out, want)
                    }));
                }
                results.push(check("SHA3-256 (incremental)", || {
                    let mut state = b::Sha3_256State::new().map_err(err)?;
                    state.update(b"a").map_err(err)?;
                    let mut fork = state.clone();
                    state.update(b"bc").map_err(err)?;
                    fork.update(b"bc").map_err(err)?;
                    let (one, two) = (state.finalize().map_err(err)?, fork.finalize().map_err(err)?);
                    expect_eq("incremental", &one, v::SHA3_256_ABC)?;
                    expect_eq("cloned state", &two, v::SHA3_256_ABC)
                }));
                results.push(check("HMAC-SHA3-256", || {
                    let mut out = [0u8; 32];
                    b::hmac(Hash::Sha3_256, v::HMAC_KEY, v::HMAC_MSG, &mut out).map_err(err)?;
                    expect_eq("HMAC-SHA3-256", &out, v::HMAC_SHA3_256)
                }));
                results.push(check("HKDF-SHA3-256", || {
                    let mut out = [0u8; 42];
                    b::hkdf(Hash::Sha3_256, Some(v::HKDF_SALT), v::HKDF_IKM, v::HKDF_INFO, &mut out).map_err(err)?;
                    expect_eq("HKDF-SHA3-256", &out, v::HKDF_SHA3_256_L42)
                }));
                for (name, hash, want) in [
                    ("PBKDF2-HMAC-SHA-512", Hash::Sha512, v::PBKDF2_SHA512),
                    ("PBKDF2-HMAC-SHA3-256", Hash::Sha3_256, v::PBKDF2_SHA3_256),
                    ("PBKDF2-HMAC-SHA-256", Hash::Sha256, v::PBKDF2_SHA256),
                ] {
                    results.push(check(name, || {
                        let mut out = [0u8; 32];
                        b::pbkdf2(hash, v::PBKDF2_PASSWORD, v::PBKDF2_SALT, v::PBKDF2_ITERATIONS, &mut out).map_err(err)?;
                        expect_eq(name, &out, want)
                    }));
                }
                results.push(check("AES-256-GCM", || {
                    let key: [u8; 32] = arr(v::GCM_KEY);
                    let iv: [u8; 12] = arr(v::GCM_IV);
                    let tag: [u8; 16] = arr(v::GCM_TAG);
                    let aad = unhex(v::GCM_AAD);
                    let plaintext = b::aes256gcm_open(&key, &iv, &aad, &unhex(v::GCM_CT), &tag)
                        .map_err(err)?
                        .ok_or("known ciphertext did not authenticate")?;
                    expect_eq("decrypt", &plaintext, v::GCM_PT)?;
                    let mut bad_tag = tag;
                    bad_tag[0] ^= 1;
                    if b::aes256gcm_open(&key, &iv, &aad, &unhex(v::GCM_CT), &bad_tag).map_err(err)?.is_some() {
                        return Err("a modified tag authenticated".to_string());
                    }
                    let (nonce, ciphertext, tag) = b::aes256gcm_seal(&key, b"aad", b"round trip").map_err(err)?;
                    let (nonce2, _, _) = b::aes256gcm_seal(&key, b"aad", b"round trip").map_err(err)?;
                    if nonce == nonce2 {
                        return Err("two encryptions drew the same nonce".to_string());
                    }
                    match b::aes256gcm_open(&key, &nonce, b"aad", &ciphertext, &tag).map_err(err)? {
                        Some(back) if back == b"round trip" => Ok(()),
                        _ => Err("seal/open round trip failed".to_string()),
                    }
                }));
                results.push(check("X25519", || {
                    let secret: [u8; 32] = arr(v::X25519_A_SECRET);
                    expect_eq("public", &b::x25519_public(&secret).map_err(err)?, v::X25519_A_PUBLIC)?;
                    let (shared, contributory) = b::x25519_shared(&secret, &arr(v::X25519_B_PUBLIC)).map_err(err)?;
                    expect_eq("shared", &shared[..], v::X25519_SHARED)?;
                    let (_, low_order_contributory) = b::x25519_shared(&secret, &[0u8; 32]).map_err(err)?;
                    if !contributory || low_order_contributory {
                        return Err("contributory flag is wrong".to_string());
                    }
                    Ok(())
                }));
                results.push(check("Ed25519", || {
                    let seed: [u8; 32] = arr(v::ED25519_SEED);
                    let public = b::ed25519_public(&seed).map_err(err)?;
                    expect_eq("public", &public, v::ED25519_PUBLIC)?;
                    let signature = b::ed25519_sign(&seed, b"").map_err(err)?;
                    expect_eq("signature", &signature, v::ED25519_SIG)?;
                    if !b::ed25519_verify(&public, b"", &signature).map_err(err)? {
                        return Err("RFC 8032 signature rejected".to_string());
                    }
                    if b::ed25519_verify(&public, b"x", &signature).map_err(err)? {
                        return Err("signature over another message accepted".to_string());
                    }
                    Ok(())
                }));
                results.push(check("ML-KEM-1024", || {
                    // FIPS 203 dk = dk_PKE (1536) || ek (1568) || H(ek) (32) || z (32).
                    if &v::MLKEM1024_DK[1536..3104] != v::MLKEM1024_EK {
                        return Err("decapsulation key does not embed its encapsulation key".to_string());
                    }
                    let mut ek_hash = [0u8; 32];
                    b::hash(Hash::Sha3_256, v::MLKEM1024_EK, &mut ek_hash).map_err(err)?;
                    if ek_hash[..] != v::MLKEM1024_DK[3104..3136] {
                        return Err("H(ek) inside the decapsulation key is wrong".to_string());
                    }
                    let shared = b::mlkem1024_decapsulate(v::MLKEM1024_DK, v::MLKEM1024_CT).map_err(err)?;
                    if &shared[..] != v::MLKEM1024_SS {
                        return Err("known ciphertext decapsulated to the wrong secret".to_string());
                    }
                    let mut tampered = v::MLKEM1024_CT.to_vec();
                    tampered[0] ^= 1;
                    if &b::mlkem1024_decapsulate(v::MLKEM1024_DK, &tampered).map_err(err)?[..] == v::MLKEM1024_SS {
                        return Err("implicit rejection returned the real secret".to_string());
                    }
                    let (public, secret) = b::mlkem1024_keypair().map_err(err)?;
                    let (ciphertext, sent) = b::mlkem1024_encapsulate(&public).map_err(err)?;
                    if b::mlkem1024_decapsulate(&secret, &ciphertext).map_err(err)?[..] != sent[..] {
                        return Err("pairwise encapsulate/decapsulate disagreed".to_string());
                    }
                    Ok(())
                }));
                for (name, params, pk, sig) in [
                    ("ML-DSA-65", MlDsa::Ml65, v::MLDSA65_PK, v::MLDSA65_SIG),
                    ("ML-DSA-87", MlDsa::Ml87, v::MLDSA87_PK, v::MLDSA87_SIG),
                ] {
                    results.push(check(name, || {
                        if !b::mldsa_verify(params, pk, v::MLDSA_MSG, sig).map_err(err)? {
                            return Err("known signature rejected".to_string());
                        }
                        if b::mldsa_verify(params, pk, b"another message", sig).map_err(err)? {
                            return Err("signature over another message accepted".to_string());
                        }
                        let (public, secret) = b::mldsa_keypair(params).map_err(err)?;
                        let signature = b::mldsa_sign(params, &secret, b"pairwise").map_err(err)?;
                        if !b::mldsa_verify(params, &public, b"pairwise", &signature).map_err(err)? {
                            return Err("pairwise sign/verify failed".to_string());
                        }
                        Ok(())
                    }));
                }
                results.push(check("Random generator", || {
                    let (mut one, mut two) = ([0u8; 32], [0u8; 32]);
                    b::random(&mut one).map_err(err)?;
                    b::random(&mut two).map_err(err)?;
                    if one == two || one == [0u8; 32] {
                        return Err("generator repeated itself".to_string());
                    }
                    Ok(())
                }));
                results
            }
        }
    };
}

define_suite!(suite_active, crate::crypto::provider::backend);
#[cfg(all(test, feature = "wolfcrypt"))]
define_suite!(suite_rustcrypto, crate::crypto::provider::rustcrypto);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_backend_passes_every_known_answer_test() {
        let report = self_test_report();
        let failures: Vec<_> = report.results.iter().filter(|r| !r.passed).collect();
        assert!(failures.is_empty(), "self-test failures: {failures:?}");
        assert!(report.results.len() >= 15);
    }

    /// With the wolfCrypt backend compiled in, the reference backend must still
    /// pass the same vectors: the two are interchangeable only if both do.
    #[cfg(feature = "wolfcrypt")]
    #[test]
    fn reference_backend_passes_the_same_vectors() {
        let failures: Vec<_> = suite_rustcrypto::run().into_iter().filter(|r| !r.passed).collect();
        assert!(failures.is_empty(), "reference backend failures: {failures:?}");
    }

    #[test]
    fn a_failing_check_is_reported_not_raised() {
        let failed = check("demo", || Err("broken".to_string()));
        assert!(!failed.passed);
        let panicked = check("demo", || panic!("boom"));
        assert_eq!(panicked.detail.as_deref(), Some("panicked"));
    }
}
