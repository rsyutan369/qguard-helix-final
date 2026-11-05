//! wolfCrypt backend (`--features wolfcrypt`).
//!
//! Every function calls into `wolfcrypt/qg_wolfcrypt.c`, a flat shim over the
//! wolfCrypt API. build.rs either compiles wolfCrypt from `WOLFSSL_DIR` with
//! `wolfcrypt/user_settings.h` (development; open-source wolfSSL is GPLv3, so
//! such a build must not be distributed with this proprietary app), or links a
//! prebuilt library from `WOLFSSL_LIB_DIR` — the route for wolfSSL's
//! commercially licensed FIPS 140-3 package, built exactly as its Security
//! Policy prescribes.

use std::ffi::{c_char, c_int, c_void, CStr};
use std::sync::OnceLock;

use zeroize::Zeroizing;

use super::status::ModuleIdentity;
use super::{Hash, MlDsa, MLKEM1024_CIPHERTEXT_BYTES, MLKEM1024_PUBLIC_KEY_BYTES, MLKEM1024_SECRET_KEY_BYTES};
use crate::error::{QGuardError, Result};

const QG_INVALID: c_int = 1;
const QG_NONCONTRIBUTORY: c_int = 2;

extern "C" {
    fn qg_wc_init() -> c_int;
    fn qg_wc_version() -> *const c_char;
    fn qg_wc_fips_version(major: *mut c_int, minor: *mut c_int, patch: *mut c_int) -> c_int;
    fn qg_wc_fips_status() -> c_int;
    fn qg_wc_random(out: *mut u8, len: usize) -> c_int;
    fn qg_wc_aes256gcm_seal(
        key: *const u8,
        aad: *const u8,
        aad_len: usize,
        pt: *const u8,
        pt_len: usize,
        iv_out: *mut u8,
        ct_out: *mut u8,
        tag_out: *mut u8,
    ) -> c_int;
    fn qg_wc_aes256gcm_open(
        key: *const u8,
        iv: *const u8,
        aad: *const u8,
        aad_len: usize,
        ct: *const u8,
        ct_len: usize,
        tag: *const u8,
        pt_out: *mut u8,
    ) -> c_int;
    fn qg_wc_hash(sel: c_int, data: *const u8, len: usize, out: *mut u8) -> c_int;
    fn qg_wc_sha3_256_new() -> *mut c_void;
    fn qg_wc_sha3_256_update(h: *mut c_void, data: *const u8, len: usize) -> c_int;
    fn qg_wc_sha3_256_final(h: *mut c_void, out: *mut u8) -> c_int;
    fn qg_wc_sha3_256_clone(h: *const c_void) -> *mut c_void;
    fn qg_wc_sha3_256_free(h: *mut c_void);
    fn qg_wc_hmac(sel: c_int, key: *const u8, key_len: usize, data: *const u8, len: usize, out: *mut u8) -> c_int;
    fn qg_wc_hkdf(
        sel: c_int,
        ikm: *const u8,
        ikm_len: usize,
        salt: *const u8,
        salt_len: usize,
        info: *const u8,
        info_len: usize,
        out: *mut u8,
        out_len: usize,
    ) -> c_int;
    fn qg_wc_pbkdf2(
        sel: c_int,
        pw: *const u8,
        pw_len: usize,
        salt: *const u8,
        salt_len: usize,
        iterations: u32,
        out: *mut u8,
        out_len: usize,
    ) -> c_int;
    fn qg_wc_x25519_public(secret: *const u8, public_out: *mut u8) -> c_int;
    fn qg_wc_x25519_shared(secret: *const u8, peer: *const u8, out: *mut u8) -> c_int;
    fn qg_wc_ed25519_public(seed: *const u8, public_out: *mut u8) -> c_int;
    fn qg_wc_ed25519_sign(seed: *const u8, msg: *const u8, len: usize, sig_out: *mut u8) -> c_int;
    fn qg_wc_ed25519_verify(public_key: *const u8, msg: *const u8, len: usize, sig: *const u8) -> c_int;
    fn qg_wc_mlkem1024_keypair(pk_out: *mut u8, sk_out: *mut u8) -> c_int;
    #[cfg(test)]
    fn qg_wc_mlkem1024_keypair_from_seed(seed: *const u8, pk_out: *mut u8, sk_out: *mut u8) -> c_int;
    fn qg_wc_mlkem1024_encapsulate(pk: *const u8, ct_out: *mut u8, ss_out: *mut u8) -> c_int;
    fn qg_wc_mlkem1024_decapsulate(sk: *const u8, ct: *const u8, ss_out: *mut u8) -> c_int;
    fn qg_wc_mldsa_keypair(level: c_int, pk_out: *mut u8, pk_len: usize, sk_out: *mut u8, sk_len: usize) -> c_int;
    fn qg_wc_mldsa_sign(
        level: c_int,
        sk: *const u8,
        sk_len: usize,
        msg: *const u8,
        msg_len: usize,
        sig_out: *mut u8,
        sig_cap: usize,
        sig_len: *mut usize,
    ) -> c_int;
    fn qg_wc_mldsa_verify(
        level: c_int,
        pk: *const u8,
        pk_len: usize,
        msg: *const u8,
        msg_len: usize,
        sig: *const u8,
        sig_len: usize,
    ) -> c_int;
}

fn sel(hash: Hash) -> c_int {
    match hash {
        Hash::Sha256 => 1,
        Hash::Sha512 => 2,
        Hash::Sha3_256 => 3,
        Hash::Sha3_512 => 4,
    }
}

fn level(params: MlDsa) -> c_int {
    match params {
        MlDsa::Ml65 => 3,
        MlDsa::Ml87 => 5,
    }
}

fn check(ret: c_int, what: &str) -> Result<()> {
    if ret == 0 {
        Ok(())
    } else {
        Err(QGuardError::Crypto(format!("wolfCrypt {what} failed ({ret})")))
    }
}

/// `wolfCrypt_Init` (and, in a FIPS build, the module status) exactly once.
fn init() -> Result<()> {
    static INIT: OnceLock<c_int> = OnceLock::new();
    check(*INIT.get_or_init(|| unsafe { qg_wc_init() }), "initialisation")
}

pub(crate) fn identity() -> ModuleIdentity {
    let version = unsafe { CStr::from_ptr(qg_wc_version()) }.to_string_lossy().into_owned();
    let (mut major, mut minor, mut patch) = (0, 0, 0);
    let fips = unsafe { qg_wc_fips_version(&mut major, &mut minor, &mut patch) } == 0;
    ModuleIdentity {
        backend: "wolfcrypt".to_string(),
        name: if fips { "wolfCrypt FIPS 140-3 module".to_string() } else { "wolfCrypt (open-source build, not a FIPS module)".to_string() },
        version: format!("wolfSSL {version}"),
        fips_module_version: fips.then(|| format!("{major}.{minor}.{patch}")),
        fips_status: fips.then(|| unsafe { qg_wc_fips_status() }),
    }
}

pub(crate) fn random(out: &mut [u8]) -> Result<()> {
    init()?;
    check(unsafe { qg_wc_random(out.as_mut_ptr(), out.len()) }, "Hash_DRBG")
}

pub(crate) fn aes256gcm_seal(key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Result<([u8; 12], Vec<u8>, [u8; 16])> {
    init()?;
    let mut nonce = [0u8; 12];
    let mut tag = [0u8; 16];
    let mut ciphertext = vec![0u8; plaintext.len()];
    let ret = unsafe {
        qg_wc_aes256gcm_seal(
            key.as_ptr(),
            aad.as_ptr(),
            aad.len(),
            plaintext.as_ptr(),
            plaintext.len(),
            nonce.as_mut_ptr(),
            ciphertext.as_mut_ptr(),
            tag.as_mut_ptr(),
        )
    };
    check(ret, "AES-256-GCM encrypt")?;
    Ok((nonce, ciphertext, tag))
}

pub(crate) fn aes256gcm_open(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], ciphertext: &[u8], tag: &[u8; 16]) -> Result<Option<Vec<u8>>> {
    init()?;
    let mut plaintext = vec![0u8; ciphertext.len()];
    let ret = unsafe {
        qg_wc_aes256gcm_open(
            key.as_ptr(),
            nonce.as_ptr(),
            aad.as_ptr(),
            aad.len(),
            ciphertext.as_ptr(),
            ciphertext.len(),
            tag.as_ptr(),
            plaintext.as_mut_ptr(),
        )
    };
    if ret == QG_INVALID {
        return Ok(None);
    }
    check(ret, "AES-256-GCM decrypt")?;
    Ok(Some(plaintext))
}

pub(crate) fn hash(hash: Hash, data: &[u8], out: &mut [u8]) -> Result<()> {
    init()?;
    if out.len() != hash.output_bytes() {
        return Err(QGuardError::Crypto("hash output buffer has the wrong length".to_string()));
    }
    check(unsafe { qg_wc_hash(sel(hash), data.as_ptr(), data.len(), out.as_mut_ptr()) }, hash.label())
}

pub(crate) struct Sha3_256State(*mut c_void);

// The state is a heap object owned by exactly one Rust value; wolfCrypt keeps
// no reference to it between calls.
unsafe impl Send for Sha3_256State {}
unsafe impl Sync for Sha3_256State {}

impl Sha3_256State {
    pub(crate) fn new() -> Result<Self> {
        init()?;
        let state = unsafe { qg_wc_sha3_256_new() };
        if state.is_null() {
            return Err(QGuardError::Crypto("wolfCrypt SHA3-256 init failed".to_string()));
        }
        Ok(Self(state))
    }
    pub(crate) fn update(&mut self, data: &[u8]) -> Result<()> {
        check(unsafe { qg_wc_sha3_256_update(self.0, data.as_ptr(), data.len()) }, "SHA3-256 update")
    }
    pub(crate) fn finalize(self) -> Result<[u8; 32]> {
        let mut out = [0u8; 32];
        check(unsafe { qg_wc_sha3_256_final(self.0, out.as_mut_ptr()) }, "SHA3-256 final")?;
        Ok(out)
    }
}

impl Clone for Sha3_256State {
    fn clone(&self) -> Self {
        let copy = unsafe { qg_wc_sha3_256_clone(self.0) };
        assert!(!copy.is_null(), "wolfCrypt SHA3-256 copy failed");
        Self(copy)
    }
}

impl Drop for Sha3_256State {
    fn drop(&mut self) {
        unsafe { qg_wc_sha3_256_free(self.0) }
    }
}

pub(crate) fn hmac(hash: Hash, key: &[u8], data: &[u8], out: &mut [u8]) -> Result<()> {
    init()?;
    if out.len() != hash.output_bytes() {
        return Err(QGuardError::Crypto("HMAC output buffer has the wrong length".to_string()));
    }
    check(
        unsafe { qg_wc_hmac(sel(hash), key.as_ptr(), key.len(), data.as_ptr(), data.len(), out.as_mut_ptr()) },
        "HMAC",
    )
}

pub(crate) fn hkdf(hash: Hash, salt: Option<&[u8]>, ikm: &[u8], info: &[u8], out: &mut [u8]) -> Result<()> {
    init()?;
    let salt = salt.unwrap_or(&[]);
    check(
        unsafe {
            qg_wc_hkdf(
                sel(hash),
                ikm.as_ptr(),
                ikm.len(),
                salt.as_ptr(),
                salt.len(),
                info.as_ptr(),
                info.len(),
                out.as_mut_ptr(),
                out.len(),
            )
        },
        "HKDF",
    )
}

pub(crate) fn pbkdf2(hash: Hash, password: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]) -> Result<()> {
    init()?;
    check(
        unsafe {
            qg_wc_pbkdf2(
                sel(hash),
                password.as_ptr(),
                password.len(),
                salt.as_ptr(),
                salt.len(),
                iterations,
                out.as_mut_ptr(),
                out.len(),
            )
        },
        "PBKDF2",
    )
}

pub(crate) fn x25519_public(secret: &[u8; 32]) -> Result<[u8; 32]> {
    init()?;
    let mut public = [0u8; 32];
    check(unsafe { qg_wc_x25519_public(secret.as_ptr(), public.as_mut_ptr()) }, "X25519 public key")?;
    Ok(public)
}

pub(crate) fn x25519_shared(secret: &[u8; 32], peer_public: &[u8; 32]) -> Result<(Zeroizing<[u8; 32]>, bool)> {
    init()?;
    let mut shared = Zeroizing::new([0u8; 32]);
    match unsafe { qg_wc_x25519_shared(secret.as_ptr(), peer_public.as_ptr(), shared.as_mut_ptr()) } {
        0 => Ok((shared, true)),
        QG_NONCONTRIBUTORY => Ok((shared, false)),
        other => Err(QGuardError::Crypto(format!("wolfCrypt X25519 failed ({other})"))),
    }
}

pub(crate) fn ed25519_public(seed: &[u8; 32]) -> Result<[u8; 32]> {
    init()?;
    let mut public = [0u8; 32];
    check(unsafe { qg_wc_ed25519_public(seed.as_ptr(), public.as_mut_ptr()) }, "Ed25519 public key")?;
    Ok(public)
}

pub(crate) fn ed25519_sign(seed: &[u8; 32], message: &[u8]) -> Result<[u8; 64]> {
    init()?;
    let mut signature = [0u8; 64];
    check(
        unsafe { qg_wc_ed25519_sign(seed.as_ptr(), message.as_ptr(), message.len(), signature.as_mut_ptr()) },
        "Ed25519 sign",
    )?;
    Ok(signature)
}

pub(crate) fn ed25519_verify(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> Result<bool> {
    init()?;
    match unsafe { qg_wc_ed25519_verify(public_key.as_ptr(), message.as_ptr(), message.len(), signature.as_ptr()) } {
        0 => Ok(true),
        QG_INVALID => Ok(false),
        other => Err(QGuardError::Crypto(format!("invalid Ed25519 public key (wolfCrypt {other})"))),
    }
}

pub(crate) fn mlkem1024_keypair() -> Result<(Vec<u8>, Zeroizing<Vec<u8>>)> {
    init()?;
    let mut public = vec![0u8; MLKEM1024_PUBLIC_KEY_BYTES];
    let mut secret = Zeroizing::new(vec![0u8; MLKEM1024_SECRET_KEY_BYTES]);
    check(unsafe { qg_wc_mlkem1024_keypair(public.as_mut_ptr(), secret.as_mut_ptr()) }, "ML-KEM-1024 key generation")?;
    Ok((public, secret))
}

/// FIPS 203 KeyGen_internal(d, z) — known-answer tests only.
#[cfg(test)]
pub(crate) fn mlkem1024_keypair_from_seed(seed: &[u8; 64]) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>)> {
    init()?;
    let mut public = vec![0u8; MLKEM1024_PUBLIC_KEY_BYTES];
    let mut secret = Zeroizing::new(vec![0u8; MLKEM1024_SECRET_KEY_BYTES]);
    check(
        unsafe { qg_wc_mlkem1024_keypair_from_seed(seed.as_ptr(), public.as_mut_ptr(), secret.as_mut_ptr()) },
        "ML-KEM-1024 key generation",
    )?;
    Ok((public, secret))
}

pub(crate) fn mlkem1024_encapsulate(public_key: &[u8]) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>)> {
    init()?;
    let mut ciphertext = vec![0u8; MLKEM1024_CIPHERTEXT_BYTES];
    let mut shared = Zeroizing::new([0u8; 32]);
    check(
        unsafe { qg_wc_mlkem1024_encapsulate(public_key.as_ptr(), ciphertext.as_mut_ptr(), shared.as_mut_ptr()) },
        "ML-KEM-1024 encapsulate",
    )?;
    Ok((ciphertext, shared))
}

pub(crate) fn mlkem1024_decapsulate(secret_key: &[u8], ciphertext: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    init()?;
    let mut shared = Zeroizing::new([0u8; 32]);
    check(
        unsafe { qg_wc_mlkem1024_decapsulate(secret_key.as_ptr(), ciphertext.as_ptr(), shared.as_mut_ptr()) },
        "ML-KEM-1024 decapsulate",
    )?;
    Ok(shared)
}

pub(crate) fn mldsa_keypair(params: MlDsa) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>)> {
    init()?;
    let mut public = vec![0u8; params.public_key_bytes()];
    let mut secret = Zeroizing::new(vec![0u8; params.secret_key_bytes()]);
    check(
        unsafe { qg_wc_mldsa_keypair(level(params), public.as_mut_ptr(), public.len(), secret.as_mut_ptr(), secret.len()) },
        "ML-DSA key generation",
    )?;
    Ok((public, secret))
}

pub(crate) fn mldsa_sign(params: MlDsa, secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>> {
    init()?;
    let mut signature = vec![0u8; params.signature_bytes()];
    let mut written = 0usize;
    check(
        unsafe {
            qg_wc_mldsa_sign(
                level(params),
                secret_key.as_ptr(),
                secret_key.len(),
                message.as_ptr(),
                message.len(),
                signature.as_mut_ptr(),
                signature.len(),
                &mut written,
            )
        },
        "ML-DSA sign",
    )?;
    signature.truncate(written);
    Ok(signature)
}

/// Interchangeability: whatever one backend produces, the other must accept.
/// Existing users' keys were made by the reference backend, so this is what
/// lets a device switch to wolfCrypt without re-keying anything.
#[cfg(test)]
mod interop {
    use super::super::rustcrypto as reference;
    use super::super::selftest;
    use super::*;

    #[test]
    fn ml_kem_keys_and_ciphertexts_cross_over() {
        let (wc_pk, wc_sk) = mlkem1024_keypair().unwrap();
        let (ct, ss) = reference::mlkem1024_encapsulate(&wc_pk).unwrap();
        assert_eq!(mlkem1024_decapsulate(&wc_sk, &ct).unwrap()[..], ss[..]);

        let (ref_pk, ref_sk) = reference::mlkem1024_keypair().unwrap();
        let (ct, ss) = mlkem1024_encapsulate(&ref_pk).unwrap();
        assert_eq!(reference::mlkem1024_decapsulate(&ref_sk, &ct).unwrap()[..], ss[..]);
        assert_eq!(mlkem1024_decapsulate(&ref_sk, &ct).unwrap()[..], ss[..]);
    }

    #[test]
    fn known_answer_ml_kem_key_is_reproduced_from_its_seed() {
        // kat/mlkem1024.dk was expanded from this seed; OpenSSL derived the same ek.
        let seed: [u8; 64] = crate::crypto::provider::sha3_512(b"QGuard ML-KEM-1024 KAT seed");
        let (pk, sk) = mlkem1024_keypair_from_seed(&seed).unwrap();
        assert_eq!(pk, selftest::vectors::MLKEM1024_EK);
        assert_eq!(&sk[..], selftest::vectors::MLKEM1024_DK);
    }

    #[test]
    fn ml_dsa_signatures_cross_over_both_parameter_sets() {
        for params in [MlDsa::Ml65, MlDsa::Ml87] {
            let (ref_pk, ref_sk) = reference::mldsa_keypair(params).unwrap();
            let sig = reference::mldsa_sign(params, &ref_sk, b"made by PQClean").unwrap();
            assert!(mldsa_verify(params, &ref_pk, b"made by PQClean", &sig).unwrap(), "{params:?}");
            // wolfCrypt can sign with a key PQClean generated (same FIPS 204 encoding).
            let sig = mldsa_sign(params, &ref_sk, b"signed by wolfCrypt").unwrap();
            assert!(reference::mldsa_verify(params, &ref_pk, b"signed by wolfCrypt", &sig).unwrap(), "{params:?}");

            let (wc_pk, wc_sk) = mldsa_keypair(params).unwrap();
            let sig = mldsa_sign(params, &wc_sk, b"made by wolfCrypt").unwrap();
            assert!(reference::mldsa_verify(params, &wc_pk, b"made by wolfCrypt", &sig).unwrap(), "{params:?}");
            assert!(!reference::mldsa_verify(params, &wc_pk, b"other", &sig).unwrap(), "{params:?}");
        }
    }

    #[test]
    fn classical_keys_and_aead_cross_over() {
        let seed = [42u8; 32];
        assert_eq!(ed25519_public(&seed).unwrap(), reference::ed25519_public(&seed).unwrap());
        // Ed25519 is deterministic: both backends produce the same signature.
        assert_eq!(ed25519_sign(&seed, b"msg").unwrap(), reference::ed25519_sign(&seed, b"msg").unwrap());

        // An UNCLAMPED stored X25519 secret, as x25519-dalek keeps them.
        let alice = [0xffu8; 32];
        let bob = [0x07u8; 32];
        assert_eq!(x25519_public(&alice).unwrap(), reference::x25519_public(&alice).unwrap());
        let bob_public = reference::x25519_public(&bob).unwrap();
        let (wc, wc_ok) = x25519_shared(&alice, &bob_public).unwrap();
        let (rc, rc_ok) = reference::x25519_shared(&alice, &bob_public).unwrap();
        assert_eq!((wc_ok, &wc[..]), (rc_ok, &rc[..]));
        // RFC 7748: the top bit of a peer key is ignored by both.
        let mut high_bit = bob_public;
        high_bit[31] |= 0x80;
        assert_eq!(x25519_shared(&alice, &high_bit).unwrap().0[..], reference::x25519_shared(&alice, &high_bit).unwrap().0[..]);

        let key = [9u8; 32];
        let (nonce, ct, tag) = aes256gcm_seal(&key, b"aad", b"wolfCrypt sealed").unwrap();
        assert_eq!(reference::aes256gcm_open(&key, &nonce, b"aad", &ct, &tag).unwrap().unwrap(), b"wolfCrypt sealed");
        let (nonce, ct, tag) = reference::aes256gcm_seal(&key, b"aad", b"reference sealed").unwrap();
        assert_eq!(aes256gcm_open(&key, &nonce, b"aad", &ct, &tag).unwrap().unwrap(), b"reference sealed");
        assert!(aes256gcm_open(&key, &nonce, b"other aad", &ct, &tag).unwrap().is_none());

        let mut a = [0u8; 48];
        let mut b = [0u8; 48];
        hkdf(Hash::Sha3_256, None, b"ikm", b"info", &mut a).unwrap();
        reference::hkdf(Hash::Sha3_256, None, b"ikm", b"info", &mut b).unwrap();
        assert_eq!(a, b, "absent salt");
        hkdf(Hash::Sha3_256, Some(&[]), b"ikm", b"info", &mut a).unwrap();
        assert_eq!(a, b, "empty salt is HashLen zeros");
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        pbkdf2(Hash::Sha512, b"123456", b"0123456789abcdef", 2000, &mut a).unwrap();
        reference::pbkdf2(Hash::Sha512, b"123456", b"0123456789abcdef", 2000, &mut b).unwrap();
        assert_eq!(a, b, "a 6-digit PIN through PBKDF2");
    }
}

pub(crate) fn mldsa_verify(params: MlDsa, public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool> {
    init()?;
    match unsafe {
        qg_wc_mldsa_verify(
            level(params),
            public_key.as_ptr(),
            public_key.len(),
            message.as_ptr(),
            message.len(),
            signature.as_ptr(),
            signature.len(),
        )
    } {
        0 => Ok(true),
        QG_INVALID => Ok(false),
        other => Err(QGuardError::Crypto(format!("wolfCrypt {} verify failed ({other})", params.label()))),
    }
}
