//! Default backend: the RustCrypto, dalek and PQClean crates QGuard Messaging
//! has always shipped (`aes-gcm`, `sha2`, `sha3`, `hmac`, `hkdf`,
//! `x25519-dalek`, `ed25519-dalek`, `pqcrypto-mlkem`, `pqcrypto-mldsa`).
//! Correct implementations of approved algorithms, but not a validated
//! module: `status.rs` reports every algorithm here as outside a validated
//! boundary. Randomness is the operating system's generator.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use pqcrypto_mldsa::{mldsa65, mldsa87};
use pqcrypto_mlkem::mlkem1024;
use rand::RngCore;
use sha2::{Sha256, Sha512};
use sha3::{Digest, Sha3_256, Sha3_512};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};
use zeroize::Zeroizing;

use super::status::ModuleIdentity;
use super::{Hash, MlDsa};
use crate::error::{QGuardError, Result};

// Only the active backend is asked who it is; in a wolfCrypt test build this
// one is compiled for the cross-backend tests alone.
#[cfg_attr(feature = "wolfcrypt", allow(dead_code))]
pub(crate) fn identity() -> ModuleIdentity {
    ModuleIdentity {
        backend: "rustcrypto".to_string(),
        name: "RustCrypto + dalek + PQClean (bundled)".to_string(),
        version: "aes-gcm 0.10 · sha2/sha3 0.10 · hmac/hkdf 0.12 · x25519/ed25519-dalek 2 · pqcrypto-mlkem/mldsa 0.1"
            .to_string(),
        fips_module_version: None,
        fips_status: None,
    }
}

fn crypto_err(what: &str) -> QGuardError {
    QGuardError::Crypto(what.to_string())
}

pub(crate) fn random(out: &mut [u8]) -> Result<()> {
    rand::rngs::OsRng
        .try_fill_bytes(out)
        .map_err(|e| QGuardError::Crypto(format!("OS random generator failed: {e}")))
}

pub(crate) fn aes256gcm_seal(key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Result<([u8; 12], Vec<u8>, [u8; 16])> {
    let mut nonce = [0u8; 12];
    random(&mut nonce)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let mut sealed = cipher
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext, aad })
        .map_err(|e| QGuardError::Crypto(format!("AES-256-GCM encrypt failed: {e}")))?;
    let tag_start = sealed.len().checked_sub(16).ok_or_else(|| crypto_err("ciphertext tag missing"))?;
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&sealed[tag_start..]);
    sealed.truncate(tag_start);
    Ok((nonce, sealed, tag))
}

pub(crate) fn aes256gcm_open(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], ciphertext: &[u8], tag: &[u8; 16]) -> Result<Option<Vec<u8>>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let mut joined = Vec::with_capacity(ciphertext.len() + tag.len());
    joined.extend_from_slice(ciphertext);
    joined.extend_from_slice(tag);
    Ok(cipher.decrypt(Nonce::from_slice(nonce), Payload { msg: &joined, aad }).ok())
}

pub(crate) fn hash(hash: Hash, data: &[u8], out: &mut [u8]) -> Result<()> {
    if out.len() != hash.output_bytes() {
        return Err(crypto_err("hash output buffer has the wrong length"));
    }
    match hash {
        Hash::Sha256 => out.copy_from_slice(&Sha256::digest(data)),
        Hash::Sha512 => out.copy_from_slice(&Sha512::digest(data)),
        Hash::Sha3_256 => out.copy_from_slice(&Sha3_256::digest(data)),
        Hash::Sha3_512 => out.copy_from_slice(&Sha3_512::digest(data)),
    }
    Ok(())
}

#[derive(Clone)]
pub(crate) struct Sha3_256State(Sha3_256);

impl Sha3_256State {
    pub(crate) fn new() -> Result<Self> {
        Ok(Self(Sha3_256::new()))
    }
    pub(crate) fn update(&mut self, data: &[u8]) -> Result<()> {
        Digest::update(&mut self.0, data);
        Ok(())
    }
    pub(crate) fn finalize(self) -> Result<[u8; 32]> {
        Ok(self.0.finalize().into())
    }
}

fn mac<M: Mac + hmac::digest::KeyInit>(key: &[u8], data: &[u8], out: &mut [u8]) -> Result<()> {
    let mut mac = <M as hmac::digest::KeyInit>::new_from_slice(key).map_err(|_| crypto_err("HMAC key rejected"))?;
    mac.update(data);
    let tag = mac.finalize().into_bytes();
    if out.len() != tag.len() {
        return Err(crypto_err("HMAC output buffer has the wrong length"));
    }
    out.copy_from_slice(&tag);
    Ok(())
}

pub(crate) fn hmac(hash: Hash, key: &[u8], data: &[u8], out: &mut [u8]) -> Result<()> {
    match hash {
        Hash::Sha256 => mac::<Hmac<Sha256>>(key, data, out),
        Hash::Sha512 => mac::<Hmac<Sha512>>(key, data, out),
        Hash::Sha3_256 => mac::<Hmac<Sha3_256>>(key, data, out),
        Hash::Sha3_512 => mac::<Hmac<Sha3_512>>(key, data, out),
    }
}

pub(crate) fn hkdf(hash: Hash, salt: Option<&[u8]>, ikm: &[u8], info: &[u8], out: &mut [u8]) -> Result<()> {
    let expanded = match hash {
        Hash::Sha256 => hkdf::Hkdf::<Sha256>::new(salt, ikm).expand(info, out),
        Hash::Sha512 => hkdf::Hkdf::<Sha512>::new(salt, ikm).expand(info, out),
        Hash::Sha3_256 => hkdf::Hkdf::<Sha3_256>::new(salt, ikm).expand(info, out),
        Hash::Sha3_512 => hkdf::Hkdf::<Sha3_512>::new(salt, ikm).expand(info, out),
    };
    expanded.map_err(|e| QGuardError::Crypto(format!("HKDF expand failed: {e}")))
}

/// RFC 8018 §5.2 over the keyed HMAC state (cloned per iteration).
fn pbkdf2_with<M: Mac + hmac::digest::KeyInit + Clone>(password: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]) -> Result<()> {
    let prf = <M as hmac::digest::KeyInit>::new_from_slice(password).map_err(|_| crypto_err("PBKDF2 password rejected"))?;
    let block_len = <M as hmac::digest::OutputSizeUser>::output_size();
    for (index, chunk) in out.chunks_mut(block_len).enumerate() {
        let block_index = u32::try_from(index + 1).map_err(|_| crypto_err("PBKDF2 output too long"))?;
        let mut first = prf.clone();
        first.update(salt);
        first.update(&block_index.to_be_bytes());
        let mut u = Zeroizing::new(first.finalize().into_bytes().to_vec());
        let mut t = Zeroizing::new(u.to_vec());
        for _ in 1..iterations {
            let mut next = prf.clone();
            next.update(&u);
            u = Zeroizing::new(next.finalize().into_bytes().to_vec());
            for (acc, byte) in t.iter_mut().zip(u.iter()) {
                *acc ^= byte;
            }
        }
        chunk.copy_from_slice(&t[..chunk.len()]);
    }
    Ok(())
}

pub(crate) fn pbkdf2(hash: Hash, password: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]) -> Result<()> {
    match hash {
        Hash::Sha256 => pbkdf2_with::<Hmac<Sha256>>(password, salt, iterations, out),
        Hash::Sha512 => pbkdf2_with::<Hmac<Sha512>>(password, salt, iterations, out),
        Hash::Sha3_256 => pbkdf2_with::<Hmac<Sha3_256>>(password, salt, iterations, out),
        Hash::Sha3_512 => pbkdf2_with::<Hmac<Sha3_512>>(password, salt, iterations, out),
    }
}

pub(crate) fn x25519_public(secret: &[u8; 32]) -> Result<[u8; 32]> {
    let secret = StaticSecret::from(*secret);
    Ok(*X25519Public::from(&secret).as_bytes())
}

pub(crate) fn x25519_shared(secret: &[u8; 32], peer_public: &[u8; 32]) -> Result<(Zeroizing<[u8; 32]>, bool)> {
    let shared = StaticSecret::from(*secret).diffie_hellman(&X25519Public::from(*peer_public));
    Ok((Zeroizing::new(*shared.as_bytes()), shared.was_contributory()))
}

pub(crate) fn ed25519_public(seed: &[u8; 32]) -> Result<[u8; 32]> {
    Ok(SigningKey::from_bytes(seed).verifying_key().to_bytes())
}

pub(crate) fn ed25519_sign(seed: &[u8; 32], message: &[u8]) -> Result<[u8; 64]> {
    Ok(SigningKey::from_bytes(seed).sign(message).to_bytes())
}

pub(crate) fn ed25519_verify(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> Result<bool> {
    let verifying = VerifyingKey::from_bytes(public_key)
        .map_err(|e| QGuardError::Crypto(format!("invalid Ed25519 public key: {e}")))?;
    Ok(verifying.verify(message, &Signature::from_bytes(signature)).is_ok())
}

pub(crate) fn mlkem1024_keypair() -> Result<(Vec<u8>, Zeroizing<Vec<u8>>)> {
    use pqcrypto_traits::kem::{PublicKey as _, SecretKey as _};
    let (public, secret) = mlkem1024::keypair();
    Ok((public.as_bytes().to_vec(), Zeroizing::new(secret.as_bytes().to_vec())))
}

pub(crate) fn mlkem1024_encapsulate(public_key: &[u8]) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>)> {
    use pqcrypto_traits::kem::{Ciphertext as _, PublicKey as _, SharedSecret as _};
    let public = mlkem1024::PublicKey::from_bytes(public_key).map_err(|_| crypto_err("invalid ML-KEM-1024 encapsulation key"))?;
    let (shared, ciphertext) = mlkem1024::encapsulate(&public);
    let mut secret = Zeroizing::new([0u8; 32]);
    secret.copy_from_slice(shared.as_bytes());
    Ok((ciphertext.as_bytes().to_vec(), secret))
}

pub(crate) fn mlkem1024_decapsulate(secret_key: &[u8], ciphertext: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    use pqcrypto_traits::kem::{Ciphertext as _, SecretKey as _, SharedSecret as _};
    let secret = mlkem1024::SecretKey::from_bytes(secret_key)
        .map_err(|e| QGuardError::Crypto(format!("invalid ML-KEM-1024 decapsulation key: {e:?}")))?;
    let ciphertext = mlkem1024::Ciphertext::from_bytes(ciphertext)
        .map_err(|e| QGuardError::Crypto(format!("invalid ML-KEM-1024 ciphertext: {e:?}")))?;
    let shared = mlkem1024::decapsulate(&ciphertext, &secret);
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(shared.as_bytes());
    Ok(out)
}

pub(crate) fn mldsa_keypair(params: MlDsa) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>)> {
    use pqcrypto_traits::sign::{PublicKey as _, SecretKey as _};
    Ok(match params {
        MlDsa::Ml65 => {
            let (public, secret) = mldsa65::keypair();
            (public.as_bytes().to_vec(), Zeroizing::new(secret.as_bytes().to_vec()))
        }
        MlDsa::Ml87 => {
            let (public, secret) = mldsa87::keypair();
            (public.as_bytes().to_vec(), Zeroizing::new(secret.as_bytes().to_vec()))
        }
    })
}

pub(crate) fn mldsa_sign(params: MlDsa, secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>> {
    use pqcrypto_traits::sign::{DetachedSignature as _, SecretKey as _};
    let rejected = |e| QGuardError::Crypto(format!("invalid {} secret key: {e:?}", params.label()));
    Ok(match params {
        MlDsa::Ml65 => {
            let secret = mldsa65::SecretKey::from_bytes(secret_key).map_err(rejected)?;
            mldsa65::detached_sign(message, &secret).as_bytes().to_vec()
        }
        MlDsa::Ml87 => {
            let secret = mldsa87::SecretKey::from_bytes(secret_key).map_err(rejected)?;
            mldsa87::detached_sign(message, &secret).as_bytes().to_vec()
        }
    })
}

pub(crate) fn mldsa_verify(params: MlDsa, public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool> {
    use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _};
    let bad_key = |e| QGuardError::Crypto(format!("invalid {} public key: {e:?}", params.label()));
    let bad_sig = |e| QGuardError::Crypto(format!("invalid {} signature: {e:?}", params.label()));
    Ok(match params {
        MlDsa::Ml65 => {
            let public = mldsa65::PublicKey::from_bytes(public_key).map_err(bad_key)?;
            let signature = mldsa65::DetachedSignature::from_bytes(signature).map_err(bad_sig)?;
            mldsa65::verify_detached_signature(&signature, message, &public).is_ok()
        }
        MlDsa::Ml87 => {
            let public = mldsa87::PublicKey::from_bytes(public_key).map_err(bad_key)?;
            let signature = mldsa87::DetachedSignature::from_bytes(signature).map_err(bad_sig)?;
            mldsa87::verify_detached_signature(&signature, message, &public).is_ok()
        }
    })
}
