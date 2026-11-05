//! 12-word recovery phrases (BIP-39, English word list).
//!
//! A phrase is 128 random bits plus a 4-bit checksum (the first bits of the
//! entropy's SHA-256), cut into twelve 11-bit indexes into the standard 2048-
//! word list — the same encoding hardware wallets use, so the words are
//! familiar and a typo is almost always caught. The checksum only catches
//! mistakes; the secret is the 128 random bits.
//!
//! `bip39_english.txt` is the list from github.com/bitcoin/bips
//! (bip-0039/english.txt, SHA-256
//! 2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda); a test
//! checks that hash so the list cannot drift.

use std::sync::OnceLock;

use zeroize::Zeroizing;

use crate::crypto::provider;
use crate::error::{QGuardError, Result};

/// Words in a phrase.
pub const WORDS: usize = 12;
/// Bytes of entropy a phrase carries.
pub const ENTROPY_BYTES: usize = 16;

const LIST: &str = include_str!("bip39_english.txt");

fn word_list() -> &'static [&'static str] {
    static WORDLIST: OnceLock<Vec<&'static str>> = OnceLock::new();
    WORDLIST.get_or_init(|| LIST.split_whitespace().collect())
}

/// A new random phrase's entropy.
pub fn generate() -> Zeroizing<[u8; ENTROPY_BYTES]> {
    Zeroizing::new(provider::random_array::<ENTROPY_BYTES>())
}

/// The twelve words for this entropy.
pub fn encode(entropy: &[u8; ENTROPY_BYTES]) -> Zeroizing<Vec<String>> {
    let list = word_list();
    let checksum = provider::sha256(entropy)[0] >> 4;
    // 128 bits of entropy then 4 of checksum, read 11 bits at a time.
    let mut bits = Zeroizing::new(u128::from_be_bytes(*entropy));
    let mut words = Zeroizing::new(Vec::with_capacity(WORDS));
    for position in 0..WORDS {
        let start = position * 11;
        let index = if start + 11 <= 128 {
            ((*bits >> (128 - start - 11)) & 0x7ff) as usize
        } else {
            // The last word: the low 7 bits of entropy, then the checksum.
            (((*bits & 0x7f) as usize) << 4) | checksum as usize
        };
        words.push(list[index].to_string());
    }
    *bits = 0;
    words
}

/// Split what someone typed or pasted into lowercase words: any mix of
/// spaces, new lines, commas and list numbers ("1." / "1)") is accepted.
fn split_words(input: &str) -> Vec<String> {
    input
        .split(|c: char| c.is_whitespace() || c == ',' || c == ';')
        .map(|word| word.trim_matches(|c: char| !c.is_ascii_alphabetic()).to_ascii_lowercase())
        .filter(|word| !word.is_empty())
        .collect()
}

/// A typed word's index. Every BIP-39 word is unique in its first four
/// letters, so those four (or more) are enough.
fn lookup(word: &str) -> Option<usize> {
    let list = word_list();
    if let Ok(index) = list.binary_search(&word) {
        return Some(index);
    }
    if word.len() < 4 {
        return None;
    }
    let mut matches = list.iter().enumerate().filter(|(_, candidate)| candidate.starts_with(word)).map(|(i, _)| i);
    match (matches.next(), matches.next()) {
        (Some(only), None) => Some(only),
        _ => None,
    }
}

/// The entropy a typed phrase carries, or a message that says exactly what to
/// fix (which word, how many, or that the checksum does not match).
pub fn decode(input: &str) -> Result<Zeroizing<[u8; ENTROPY_BYTES]>> {
    let words = Zeroizing::new(split_words(input));
    if words.len() != WORDS {
        return Err(QGuardError::InvalidInput(format!(
            "A recovery phrase has {WORDS} words — {} entered.",
            words.len()
        )));
    }
    let mut bits = Zeroizing::new(0u128);
    let mut checksum = 0u8;
    for (position, word) in words.iter().enumerate() {
        let index = lookup(word).ok_or_else(|| {
            QGuardError::InvalidInput(format!("Word {} (\"{word}\") is not a recovery phrase word. Check its spelling.", position + 1))
        })? as u128;
        if position + 1 < WORDS {
            *bits = (*bits << 11) | index;
        } else {
            *bits = (*bits << 7) | (index >> 4);
            checksum = (index & 0x0f) as u8;
        }
    }
    let entropy = Zeroizing::new(bits.to_be_bytes());
    *bits = 0;
    if provider::sha256(&*entropy)[0] >> 4 != checksum {
        return Err(QGuardError::InvalidInput(
            "These words are not a valid recovery phrase. Check each word and their order.".to_string(),
        ));
    }
    Ok(entropy)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_word_list_is_the_published_bip39_english_list() {
        assert_eq!(
            hex::encode(provider::sha256(LIST.replace("\r\n", "\n").as_bytes())),
            "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
        );
        let list = word_list();
        assert_eq!(list.len(), 2048);
        assert!(list.windows(2).all(|pair| pair[0] < pair[1]), "sorted, for binary search");
        let prefixes: std::collections::HashSet<&str> = list.iter().map(|word| &word[..word.len().min(4)]).collect();
        assert_eq!(prefixes.len(), 2048, "unique in the first four letters");
    }

    /// Vectors from the BIP-39 specification (trezor/python-mnemonic vectors.json).
    #[test]
    fn matches_the_bip39_test_vectors() {
        let vectors = [
            ("00000000000000000000000000000000", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"),
            ("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f", "legal winner thank year wave sausage worth useful legal winner thank yellow"),
            ("80808080808080808080808080808080", "letter advice cage absurd amount doctor acoustic avoid letter advice cage above"),
            ("ffffffffffffffffffffffffffffffff", "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"),
            ("9e885d952ad362caeb4efe34a8e91bd2", "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic"),
            ("c0ba5a8e914111210f2bd131f3d5e08d", "scheme spot photo card baby mountain device kick cradle pact join borrow"),
        ];
        for (hex_entropy, phrase) in vectors {
            let mut entropy = [0u8; ENTROPY_BYTES];
            hex::decode_to_slice(hex_entropy, &mut entropy).unwrap();
            assert_eq!(encode(&entropy).join(" "), phrase, "{hex_entropy}");
            assert_eq!(*decode(phrase).unwrap(), entropy, "{hex_entropy}");
        }
    }

    #[test]
    fn random_phrases_round_trip_however_they_are_typed() {
        for _ in 0..50 {
            let entropy = generate();
            let words = encode(&entropy);
            assert_eq!(*decode(&words.join(" ")).unwrap(), *entropy);
            let numbered: String = words.iter().enumerate().map(|(i, w)| format!("{}. {}\n", i + 1, w.to_uppercase())).collect();
            assert_eq!(*decode(&numbered).unwrap(), *entropy);
            let prefixes: Vec<&str> = words.iter().map(|w| &w[..w.len().min(4)]).collect();
            assert_eq!(*decode(&prefixes.join(", ")).unwrap(), *entropy);
        }
    }

    #[test]
    fn mistakes_are_named() {
        let good = "legal winner thank year wave sausage worth useful legal winner thank yellow";
        assert!(decode("legal winner thank").unwrap_err().to_string().contains("12 words — 3 entered"));
        assert!(decode(&good.replace("wave", "wavx")).unwrap_err().to_string().contains("Word 5"));
        // Two words swapped: every word is real, the checksum is not.
        let swapped = good.replace("thank year", "year thank");
        assert!(decode(&swapped).unwrap_err().to_string().contains("not a valid recovery phrase"));
        // Too short to be a unique prefix.
        assert!(decode(&good.replace("legal winner", "leg winner")).is_err());
    }
}
