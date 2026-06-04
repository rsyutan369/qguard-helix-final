use hkdf::Hkdf;
use sha3::{Digest, Sha3_256};
use zeroize::Zeroize;

use crate::error::{QGuardError, Result};

const SALT: &[u8] = b"QGuard-Messaging-HKDF-SHA3-256-v1";

pub fn hkdf_sha3_256(ikm: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>> {
    if ikm.is_empty() || len == 0 || len > 8160 {
        return Err(QGuardError::Crypto("invalid HKDF input".to_string()));
    }

    let hk = Hkdf::<Sha3_256>::new(Some(SALT), ikm);
    let mut out = vec![0u8; len];
    hk.expand(info, &mut out)
        .map_err(|e| QGuardError::Crypto(format!("HKDF expand failed: {e}")))?;
    Ok(out)
}

pub fn derive_32(ikm: &[u8], info: &[u8]) -> Result<[u8; 32]> {
    let mut derived = hkdf_sha3_256(ikm, info, 32)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&derived);
    derived.zeroize();
    Ok(out)
}

pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    let digest = Sha3_256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

pub fn sha3_hex(data: &[u8]) -> String {
    hex::encode(sha3_256(data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_deterministic_distinct_context_keys() {
        let ikm = b"hybrid secret";
        let a = derive_32(ikm, b"a").unwrap();
        let b = derive_32(ikm, b"b").unwrap();
        assert_ne!(a, b);
        assert_eq!(a, derive_32(ikm, b"a").unwrap());
    }
}
