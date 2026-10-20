//! Shamir secret sharing over GF(2^8) (roadmap 5.1 social recovery).
//!
//! A 32-byte secret is split byte-wise: each byte is the constant term of its
//! own random polynomial of degree k-1, evaluated at x = 1..=n. Any k shares
//! reconstruct it by Lagrange interpolation at x = 0; k-1 shares reveal nothing
//! (every value of the secret is equally consistent with them).
//!
//! Field arithmetic uses the AES polynomial (x^8 + x^4 + x^3 + x + 1) with
//! shift-and-add multiplication — no lookup tables indexed by secret data.

use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{QGuardError, Result};

pub const SECRET_LEN: usize = 32;
pub const MAX_SHARES: u8 = 16;

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Share {
    /// Evaluation point, 1..=n. Never 0 (that is the secret).
    pub x: u8,
    pub y: [u8; SECRET_LEN],
}

impl Drop for Share {
    fn drop(&mut self) {
        self.y.zeroize();
    }
}

impl std::fmt::Debug for Share {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Share").field("x", &self.x).field("y", &"<redacted>").finish()
    }
}

fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut product = 0u8;
    for _ in 0..8 {
        // Branch-free: add `a` when the low bit of `b` is set.
        product ^= a & (0u8.wrapping_sub(b & 1));
        let carry = 0u8.wrapping_sub(a >> 7);
        a = (a << 1) ^ (0x1b & carry);
        b >>= 1;
    }
    product
}

/// a^254 = a^-1 in GF(2^8) (a != 0).
fn gf_inv(a: u8) -> u8 {
    let mut result = 1u8;
    let mut base = a;
    let mut exponent = 254u8;
    while exponent > 0 {
        if exponent & 1 == 1 {
            result = gf_mul(result, base);
        }
        base = gf_mul(base, base);
        exponent >>= 1;
    }
    result
}

/// Split `secret` into `n` shares, any `k` of which reconstruct it.
pub fn split(secret: &[u8; SECRET_LEN], k: u8, n: u8) -> Result<Vec<Share>> {
    if k < 2 || n < k || n > MAX_SHARES {
        return Err(QGuardError::InvalidInput(format!(
            "a recovery split needs 2 <= threshold <= helpers <= {MAX_SHARES}"
        )));
    }
    let mut shares: Vec<Share> = (1..=n).map(|x| Share { x, y: [0; SECRET_LEN] }).collect();
    let mut coefficients = Zeroizing::new(vec![0u8; usize::from(k)]);
    for (index, byte) in secret.iter().enumerate() {
        coefficients[0] = *byte;
        OsRng.fill_bytes(&mut coefficients[1..]);
        for share in shares.iter_mut() {
            // Horner: c0 + x(c1 + x(c2 + ...)).
            let mut value = 0u8;
            for coefficient in coefficients.iter().rev() {
                value = gf_mul(value, share.x) ^ coefficient;
            }
            share.y[index] = value;
        }
    }
    Ok(shares)
}

/// Rebuild the secret from at least `k` distinct shares (extra shares are
/// fine; with fewer than k the result is simply wrong, which the caller's
/// AEAD check then reports).
pub fn combine(shares: &[Share]) -> Result<Zeroizing<[u8; SECRET_LEN]>> {
    if shares.len() < 2 {
        return Err(QGuardError::InvalidInput("at least two shares are needed".to_string()));
    }
    for (index, share) in shares.iter().enumerate() {
        if share.x == 0 {
            return Err(QGuardError::InvalidInput("a share at x = 0 is not a share".to_string()));
        }
        if shares[..index].iter().any(|other| other.x == share.x) {
            return Err(QGuardError::InvalidInput("the same share was supplied twice".to_string()));
        }
    }
    let mut secret = Zeroizing::new([0u8; SECRET_LEN]);
    for (i, share) in shares.iter().enumerate() {
        // Lagrange basis at 0: prod_{j != i} x_j / (x_j - x_i); in GF(2^8)
        // subtraction is XOR.
        let mut basis = 1u8;
        for (j, other) in shares.iter().enumerate() {
            if i != j {
                basis = gf_mul(basis, gf_mul(other.x, gf_inv(other.x ^ share.x)));
            }
        }
        for (byte, y) in secret.iter_mut().zip(share.y.iter()) {
            *byte ^= gf_mul(basis, *y);
        }
    }
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret() -> [u8; SECRET_LEN] {
        let mut out = [0u8; SECRET_LEN];
        OsRng.fill_bytes(&mut out);
        out
    }

    #[test]
    fn field_arithmetic_is_right() {
        // FIPS-197 §4.2: {57} • {83} = {c1}; {57} • {13} = {fe}.
        assert_eq!(gf_mul(0x57, 0x83), 0xc1);
        assert_eq!(gf_mul(0x57, 0x13), 0xfe);
        for a in 1..=255u8 {
            assert_eq!(gf_mul(a, gf_inv(a)), 1, "inverse of {a}");
        }
    }

    #[test]
    fn every_k_subset_reconstructs_for_every_k_of_n_up_to_5_of_7() {
        for n in 2..=7u8 {
            for k in 2..=n.min(5) {
                let original = secret();
                let shares = split(&original, k, n).unwrap();
                assert_eq!(shares.len(), usize::from(n));
                // Every contiguous window of k shares, plus all n.
                for start in 0..=(usize::from(n) - usize::from(k)) {
                    let subset = &shares[start..start + usize::from(k)];
                    assert_eq!(*combine(subset).unwrap(), original, "k={k} n={n} start={start}");
                }
                assert_eq!(*combine(&shares).unwrap(), original);
                // k-1 shares give a different value (negative control).
                if k > 2 {
                    assert_ne!(*combine(&shares[..usize::from(k) - 1]).unwrap(), original);
                }
            }
        }
    }

    #[test]
    fn fewer_than_k_shares_carry_no_information() {
        // For a 2-of-n split, one share's byte is uniform whatever the secret:
        // across many splits of the SAME secret, each byte value shows up.
        let fixed = [0x42u8; SECRET_LEN];
        let mut seen = [false; 256];
        for _ in 0..4000 {
            let shares = split(&fixed, 2, 3).unwrap();
            seen[usize::from(shares[0].y[0])] = true;
        }
        let distinct = seen.iter().filter(|value| **value).count();
        assert!(distinct > 240, "a single share looks uniform ({distinct}/256 values seen)");
    }

    #[test]
    fn bad_inputs_are_refused() {
        let original = secret();
        assert!(split(&original, 1, 3).is_err());
        assert!(split(&original, 4, 3).is_err());
        assert!(split(&original, 2, MAX_SHARES + 1).is_err());
        let shares = split(&original, 2, 3).unwrap();
        assert!(combine(&shares[..1]).is_err());
        assert!(combine(&[shares[0].clone(), shares[0].clone()]).is_err(), "duplicate share");
        let zero = Share { x: 0, y: [0; SECRET_LEN] };
        assert!(combine(&[zero, shares[1].clone()]).is_err());
    }
}
