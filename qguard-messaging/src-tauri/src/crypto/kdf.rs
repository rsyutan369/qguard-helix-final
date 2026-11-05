use zeroize::Zeroize;

use super::provider;
use crate::error::{QGuardError, Result};

pub fn hkdf_sha3_256(ikm: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>> {
    if ikm.is_empty() || len == 0 || len > 8160 {
        return Err(QGuardError::Crypto("invalid HKDF input".to_string()));
    }

    let salt = crate::security::obf::hkdf_salt();
    let mut out = vec![0u8; len];
    provider::hkdf_sha3_256(Some(salt.as_slice()), ikm, info, &mut out)?;
    Ok(out)
}

pub fn derive_32(ikm: &[u8], info: &[u8]) -> Result<[u8; 32]> {
    let mut derived = hkdf_sha3_256(ikm, info, 32)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&derived);
    derived.zeroize();
    Ok(out)
}

/// HKDF-SHA3-256 with an explicit caller-supplied salt (instead of the fixed
/// module salt). Used by recovery wrapping where each wrap carries its own salt.
pub fn derive_32_with_salt(salt: &[u8], ikm: &[u8], info: &[u8]) -> Result<[u8; 32]> {
    if ikm.is_empty() {
        return Err(QGuardError::Crypto("invalid HKDF input".to_string()));
    }
    let mut out = [0u8; 32];
    provider::hkdf_sha3_256(Some(salt), ikm, info, &mut out)?;
    Ok(out)
}

pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    provider::sha3_256(data)
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
