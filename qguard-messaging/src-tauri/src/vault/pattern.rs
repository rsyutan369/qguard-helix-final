//! Unlock patterns: the dots a user connects on a 4 × 4 grid.
//!
//! A pattern reaches the core as text, `4x4:<dot>-<dot>-…`, with the dots
//! numbered 0–15 row by row. Only the canonical form of a pattern the pad can
//! actually draw is accepted: at least [`MIN_DOTS`] distinct dots, each on the
//! grid, and no stroke that jumps over a dot not yet connected (the pad picks
//! such a dot up on the way, so a sequence that skips it was never drawn).
//! That canonical text is the secret the KDF stretches, so the same pattern
//! always gives the same bytes.
//!
//! Why 4 × 4: all 3 × 3 patterns together are about 389,000 — fewer than the
//! 6-digit PINs. On 4 × 4 there are about 1.3 million patterns of exactly 6
//! dots and 79 million of 8.

use zeroize::Zeroizing;

use crate::error::{QGuardError, Result};

pub const GRID: u8 = 4;
pub const DOTS: u8 = GRID * GRID;
pub const MIN_DOTS: usize = 6;
const PREFIX: &str = "4x4:";

fn invalid() -> QGuardError {
    QGuardError::InvalidInput(format!("Draw a pattern that connects at least {MIN_DOTS} dots."))
}

fn gcd(a: i32, b: i32) -> i32 {
    if b == 0 {
        a.abs()
    } else {
        gcd(b, a % b)
    }
}

/// Dots strictly between `a` and `b` on the straight line joining them.
pub fn between(a: u8, b: u8) -> Vec<u8> {
    if a == b {
        return Vec::new();
    }
    let (grid, a, b) = (GRID as i32, a as i32, b as i32);
    let (dr, dc) = (b / grid - a / grid, b % grid - a % grid);
    let steps = gcd(dr, dc);
    (1..steps)
        .map(|k| ((a / grid + dr / steps * k) * grid + a % grid + dc / steps * k) as u8)
        .collect()
}

/// The dots of a canonical pattern, or an error naming what to draw.
pub fn parse(raw: &str) -> Result<Vec<u8>> {
    let body = raw.strip_prefix(PREFIX).ok_or_else(invalid)?;
    let mut dots: Vec<u8> = Vec::with_capacity(DOTS as usize);
    let mut seen = [false; DOTS as usize];
    for part in body.split('-') {
        // Canonical numbers only: no sign, no padding, no spaces.
        if part.is_empty() || part.len() > 2 || (part.len() == 2 && part.starts_with('0')) || !part.bytes().all(|b| b.is_ascii_digit()) {
            return Err(invalid());
        }
        let dot: u8 = part.parse().map_err(|_| invalid())?;
        if dot >= DOTS || seen[dot as usize] {
            return Err(invalid());
        }
        if let Some(&previous) = dots.last() {
            if between(previous, dot).iter().any(|skipped| !seen[*skipped as usize]) {
                return Err(invalid());
            }
        }
        seen[dot as usize] = true;
        dots.push(dot);
    }
    if dots.len() < MIN_DOTS {
        return Err(invalid());
    }
    Ok(dots)
}

/// The bytes a pattern is stretched from: its canonical text.
pub fn secret_bytes(raw: &str) -> Result<Zeroizing<Vec<u8>>> {
    let dots = parse(raw)?;
    let text = format!("{PREFIX}{}", dots.iter().map(u8::to_string).collect::<Vec<_>>().join("-"));
    Ok(Zeroizing::new(text.into_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_drawable_pattern_is_accepted_as_its_canonical_bytes() {
        assert_eq!(parse("4x4:0-1-2-3-7-11").unwrap(), vec![0, 1, 2, 3, 7, 11]);
        assert_eq!(&*secret_bytes("4x4:5-6-10-9-13-14").unwrap(), b"4x4:5-6-10-9-13-14");
        // Knight's moves pass over no dot; 3 → 9 passes over 6, already connected.
        assert!(parse("4x4:0-6-13-4-10-3-9").is_ok());
        // 6 → 12 is a diagonal over 9, which is not connected yet.
        assert!(parse("4x4:0-6-12-9-3-5").is_err());
    }

    #[test]
    fn short_repeated_off_grid_or_odd_spellings_are_refused() {
        for raw in [
            "4x4:0-1-2-3-7",       // five dots
            "4x4:0-1-2-3-7-3",     // a dot twice
            "4x4:0-1-2-3-7-16",    // off the grid
            "3x3:0-1-2-5-8-7",     // another grid
            "4x4:0-1-2-3-7-011",   // padded number
            "4x4: 0-1-2-3-7-11",   // spaces
            "4x4:0-1-2-3-7-11-",   // trailing separator
            "",
        ] {
            assert!(parse(raw).is_err(), "{raw:?} was accepted");
        }
    }

    #[test]
    fn a_stroke_cannot_jump_a_dot_it_has_not_connected() {
        // 0 → 2 passes over 1; 0 → 15 over 5 and 10; 3 → 12 over 6 and 9.
        assert_eq!(between(0, 2), vec![1]);
        assert_eq!(between(0, 15), vec![5, 10]);
        assert_eq!(between(3, 12), vec![6, 9]);
        assert!(between(0, 6).is_empty());
        assert!(parse("4x4:0-2-3-7-11-15").is_err());
        // Once 1 is connected, jumping over it is fine.
        assert!(parse("4x4:1-0-2-3-7-11").is_ok());
        assert!(parse("4x4:5-10-0-15-14-13").is_ok());
        assert!(parse("4x4:0-15-14-13-12-8").is_err());
    }
}
