//! FIPS approved-mode policy for this device.
//!
//! Approved mode changes what NEW cryptographic material is made with; it
//! never stops existing material from opening:
//! * every password and PIN is stretched with PBKDF2 (SP 800-132) instead of
//!   Argon2id, which is not a FIPS-approved function; credentials sealed
//!   with Argon2id still open and are re-sealed with PBKDF2 on their next
//!   successful unlock (and back, if approved mode is switched off);
//! * the Quantum Vault — the credential that unwraps the vault key — must be
//!   a password of at least [`APPROVED_PASSWORD_MIN_CHARS`] characters.
//!
//! The switch is per device (`AppState`), `QGUARD_FIPS_APPROVED_MODE=1/0`
//! overrides it, and a build with `--features fips-approved-mode` cannot
//! leave approved mode at all.

use std::sync::atomic::{AtomicBool, Ordering};

use super::Hash;

const FORCED: bool = cfg!(feature = "fips-approved-mode");

static APPROVED: AtomicBool = AtomicBool::new(false);

/// PBKDF2 PRF in approved mode. SHA-512: every validated PBKDF service
/// covers HMAC-SHA-512 (HMAC-SHA3 is not on AWS-LC's), and it is in CNSA 2.0.
pub const APPROVED_PBKDF2_PRF: Hash = Hash::Sha512;

/// PBKDF2 iterations in approved mode. SP 800-132 asks for as many as the
/// unlock delay allows. 600,000 is roughly 3x the OWASP figure for
/// HMAC-SHA-512, to recover part of what dropping Argon2id's memory cost loses.
pub const APPROVED_PBKDF2_ITERATIONS: u32 = 600_000;

/// Shortest vault password approved mode accepts. PBKDF2 has no memory cost,
/// so a 6-12 digit PIN in front of the vault key would be guessable offline
/// by anyone who got past the device key store. 14 characters is also the
/// minimum the AWS-LC 3 Security Policy (CMVP #5298) sets for its approved
/// PBKDF; wolfCrypt FIPS v6+ accepts shorter passwords, so this is ours.
pub const APPROVED_PASSWORD_MIN_CHARS: usize = 14;

pub fn approved_mode() -> bool {
    FORCED || APPROVED.load(Ordering::SeqCst)
}

pub fn approved_mode_forced() -> bool {
    FORCED
}

pub fn set_approved_mode(enabled: bool) {
    APPROVED.store(enabled, Ordering::SeqCst);
}
