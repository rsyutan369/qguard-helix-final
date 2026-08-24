//! Passphrase strength for the Portable Hybrid Identity bundle (`.qgkey`).
//!
//! A `.qgkey` is an **offline artefact**: once someone has the file, nothing
//! rate-limits them. They can grind guesses on their own hardware for as long as
//! they like, and the only thing standing in the way is Argon2id (64 MiB, 3
//! passes) and how much entropy the passphrase actually carries. Argon2id buys a
//! constant factor; entropy buys exponential growth. Only one of those wins.
//!
//! So the bundle gate is an **entropy floor**, not a character count. A
//! 12-character password a person invented ("Summer2024!") sails past a length
//! rule and falls to a wordlist in minutes; five random words are longer to type
//! and astronomically stronger.
//!
//! # How the estimate works
//!
//! Two independent models run over the input and the **lower** one wins. An
//! estimator that guesses high is worse than useless here — it tells the user
//! they are safe when they are not — so every ambiguity resolves downward.
//!
//! **Composition model.** The naive `length × log2(pool)` is the reason weak
//! passwords score well: `Summer2024!!` is twelve characters over a 94-symbol
//! pool, which "proves" 78 bits for something a wordlist finds in seconds. The
//! flaw is that it counts characters when an attacker guesses *structure*. So
//! the input is split into runs of one character class and each run is scored
//! for what it really costs:
//!
//! * A run of letters that looks like one word — short, and cased the way people
//!   case words — is worth one dictionary lookup plus a bit for which
//!   capitalization, not `len × log2(52)`. Longer or mixed-case runs are not
//!   word-shaped and keep full credit.
//! * A four-digit run inside 1900–2100 is a year: about 200 candidates, not
//!   10 000.
//! * A run of the same symbol repeated is worth the first symbol and very little
//!   after it.
//!
//! **Word model.** If the input reads as separated words, score it as a choice
//! of that many words from a large dictionary ([`HUMAN_WORD_CANDIDATES`]).
//!
//! **Penalties** then cut both: runs of one character, ascending or descending
//! sequences, and any substring from the embedded blocklist.
//!
//! The result is a floor on what an attacker needs, not a promise. Two limits
//! are worth stating rather than hiding:
//!
//! * **No breach corpus.** It does not know `qw3rty` is a keyboard walk or that
//!   a given string appeared in a leak. The blocklist covers the handful that
//!   matter most for this product; a real corpus check would be strictly better.
//! * **No grammar model.** A grammatical English sentence is far weaker than the
//!   same words in random order, because each word predicts the next — but both
//!   look identical to a tokenizer. So a long sentence scores like a long word
//!   list and can pass when a language model would say otherwise. Separating
//!   them needs n-gram data this module does not carry.
//!
//! Both limits push in the same direction: a passphrase a person invented is
//! worth *less* than this scores it. That is the reason [`generate`] exists and
//! why the UI should lead with it — a generated phrase's entropy is counted, not
//! estimated, so neither limit applies to it.
//!
//! # The generator
//!
//! [`generate`] is the answer to "then what do I type?". It draws words
//! uniformly from the embedded BIP-39 English list (2048 words = exactly 11 bits
//! each) using the OS CSPRNG with rejection sampling, so a 7-word phrase carries
//! a provable 77 bits — no estimation involved. That is the path the UI should
//! push people down.

use rand::RngCore;

use crate::error::{QGuardError, Result};

/// Entropy a new `.qgkey` passphrase must carry, in bits.
///
/// 70 bits is set against an *offline* attacker who has the bundle. At Argon2id
/// 64 MiB / t=3 a well-funded attacker manages on the order of 10^5 guesses per
/// second per GPU; 2^70 guesses is out of reach for any budget by a wide margin,
/// while still being reachable by a 7-word generated phrase (77 bits) or a
/// long, genuinely random human passphrase.
pub const MIN_PASSPHRASE_BITS: f64 = 70.0;

/// Absolute character floor, enforced alongside the entropy floor.
///
/// A short string can score well on the character model if it mixes classes;
/// this stops anything that is simply too short to survive a targeted attack,
/// regardless of what the estimator thinks.
pub const MIN_PASSPHRASE_LEN: usize = 12;

/// Words [`generate`] produces by default: 7 × 11 bits = 77 bits, comfortably
/// clear of [`MIN_PASSPHRASE_BITS`] with margin to spare.
pub const DEFAULT_GENERATED_WORDS: usize = 7;
/// Fewest words [`generate`] will produce. 6 words = 66 bits, which is below the
/// floor on its own — allowed only so a caller can compose a longer phrase.
pub const MIN_GENERATED_WORDS: usize = 6;
/// Most words [`generate`] will produce, so a stray argument cannot ask for a
/// phrase nobody will ever type.
pub const MAX_GENERATED_WORDS: usize = 16;

/// Candidate pool assumed per word in the word model: 2048, i.e. 11 bits.
///
/// English has far more words than that, but people do not choose uniformly from
/// it — a handful of thousands of common words cover almost everything anyone
/// picks. 2048 is deliberately the size of the embedded generator list too, so
/// the estimator and [`generate`] agree by construction: a phrase this module
/// produces scores exactly the entropy it provably carries, and a human phrase of
/// the same shape is not flattered relative to it.
const HUMAN_WORD_CANDIDATES: f64 = 2048.0;

/// The BIP-39 English wordlist: 2048 words, so exactly 11 bits per word.
const WORDLIST_SOURCE: &str = include_str!("testdata/passphrase_wordlist.txt");
const WORDLIST_LEN: usize = 2048;
/// log2(2048).
const BITS_PER_GENERATED_WORD: f64 = 11.0;

/// Substrings that make a passphrase predictable for *this* product in
/// particular. Kept short and deliberate: a real blocklist belongs in a
/// breach-corpus check, but these are the guesses an attacker targeting a QGuard
/// user would try first, plus the handful of passwords that top every leak.
const BLOCKED_SUBSTRINGS: &[&str] = &[
    "qguard", "quantum", "vault", "helix", "password", "passphrase", "letmein",
    "qwerty", "asdf", "iloveyou", "welcome", "admin", "secret", "changeme",
    "123456", "abc123", "111111", "monkey", "dragon", "sunshine", "princess",
    "football", "baseball", "trustno1", "master", "shadow", "michael", "superman",
];

/// How a passphrase scored, in a shape the UI can render directly.
#[derive(Clone, Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PassphraseStrength {
    /// Conservative entropy estimate in bits.
    pub bits: f64,
    /// `bits` as a fraction of the floor, clamped to 0.0–1.0, for a meter.
    pub fraction: f64,
    /// `weak` | `fair` | `strong` | `excellent`.
    pub verdict: &'static str,
    /// Whether this passphrase may be used for a new bundle.
    pub acceptable: bool,
    /// What is dragging the score down, in plain language. Empty when nothing is.
    pub issues: Vec<String>,
    /// One concrete next step, or `None` when the passphrase is already fine.
    pub suggestion: Option<String>,
}

/// Score a passphrase without deciding anything about it.
pub fn estimate(passphrase: &str) -> PassphraseStrength {
    let chars: Vec<char> = passphrase.chars().collect();
    let mut issues = Vec::new();

    if chars.is_empty() {
        return PassphraseStrength {
            bits: 0.0,
            fraction: 0.0,
            verdict: "weak",
            acceptable: false,
            issues: vec!["Enter a passphrase.".to_string()],
            suggestion: Some(format!(
                "Generate one — {DEFAULT_GENERATED_WORDS} random words is {:.0} bits.",
                DEFAULT_GENERATED_WORDS as f64 * BITS_PER_GENERATED_WORD
            )),
        };
    }

    let lower = passphrase.to_lowercase();
    let mut bits = composition_model_bits(passphrase, &chars, &mut issues);
    bits -= pattern_penalty_bits(&chars, &lower, &mut issues);

    // The word model only applies when the input actually reads as words; when
    // it does, it is usually the more honest number for a human-chosen phrase.
    if let Some(word_bits) = word_model_bits(passphrase) {
        bits = bits.min(word_bits);
    }

    let bits = bits.max(0.0);

    if chars.len() < MIN_PASSPHRASE_LEN {
        issues.push(format!(
            "Too short — {MIN_PASSPHRASE_LEN} characters is the minimum, and length matters more than symbols."
        ));
    }

    let acceptable = bits >= MIN_PASSPHRASE_BITS && chars.len() >= MIN_PASSPHRASE_LEN;
    let verdict = if bits < MIN_PASSPHRASE_BITS * 0.6 {
        "weak"
    } else if bits < MIN_PASSPHRASE_BITS {
        "fair"
    } else if bits < MIN_PASSPHRASE_BITS * 1.4 {
        "strong"
    } else {
        "excellent"
    };

    let suggestion = if acceptable {
        None
    } else {
        Some(format!(
            "Use {DEFAULT_GENERATED_WORDS} random words instead — that is {:.0} bits and easy to retype. Tap Generate.",
            DEFAULT_GENERATED_WORDS as f64 * BITS_PER_GENERATED_WORD
        ))
    };

    PassphraseStrength {
        bits,
        fraction: (bits / MIN_PASSPHRASE_BITS).clamp(0.0, 1.0),
        verdict,
        acceptable,
        issues,
        suggestion,
    }
}

/// The gate: reject anything that would not survive an offline attack on a
/// stolen bundle. The error names the actual shortfall so the user can act on it.
pub fn require_strong(passphrase: &str) -> Result<()> {
    let strength = estimate(passphrase);
    if strength.acceptable {
        return Ok(());
    }
    let detail = if strength.issues.is_empty() {
        String::new()
    } else {
        format!(" {}", strength.issues.join(" "))
    };
    Err(QGuardError::InvalidInput(format!(
        "This passphrase is too weak for an identity bundle ({:.0} bits; {:.0} needed). \
         A .qgkey can be attacked offline for as long as someone likes, so its passphrase is the \
         only thing protecting every file sealed to this identity.{detail} \
         Generate a {DEFAULT_GENERATED_WORDS}-word passphrase instead.",
        strength.bits, MIN_PASSPHRASE_BITS
    )))
}

/// Generate a passphrase of `words` uniformly random words, space separated.
///
/// Words are drawn **without replacement**. Entropy is therefore
/// `log2(2048 × 2047 × …)`, which is 76.99 bits for the default seven — within a
/// hundredth of a bit of the 77 that replacement would give. The reason to do it
/// this way is not entropy but agreement: the estimator counts *distinct* words,
/// so a phrase containing "cannon cannon" would score 11 bits lower than it looks
/// and the gate would reject a passphrase this function had just recommended.
/// Drawing without replacement makes that impossible. It also avoids handing
/// someone a phrase with a stutter in it.
pub fn generate(words: usize) -> Result<String> {
    let words = words.clamp(MIN_GENERATED_WORDS, MAX_GENERATED_WORDS);
    let mut list = wordlist();
    let mut chosen: Vec<&'static str> = Vec::with_capacity(words);
    for _ in 0..words {
        // swap_remove keeps the draw uniform over what is left, in O(1).
        chosen.push(list.swap_remove(uniform_index(list.len())));
    }
    Ok(chosen.join(" "))
}

/// Bits carried by a phrase [`generate`] produced, counting the without-
/// replacement draw exactly rather than assuming `11 × words`.
pub fn generated_bits(words: usize) -> f64 {
    let words = words.clamp(MIN_GENERATED_WORDS, MAX_GENERATED_WORDS);
    (0..words)
        .map(|drawn| ((WORDLIST_LEN - drawn) as f64).log2())
        .sum()
}

fn wordlist() -> Vec<&'static str> {
    let list: Vec<&'static str> = WORDLIST_SOURCE
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();
    debug_assert_eq!(
        list.len(),
        WORDLIST_LEN,
        "the wordlist must stay exactly {WORDLIST_LEN} words, or the per-word entropy is wrong"
    );
    list
}

/// Uniform index in `0..len` from the OS CSPRNG.
///
/// Rejection sampling, not `% len`: the modulo shortcut biases toward low
/// indices whenever `len` does not divide the generator's range, which quietly
/// costs real entropy. With len = 2048 (a power of two) the rejection branch
/// never fires, but the loop keeps this correct if the list ever changes size.
fn uniform_index(len: usize) -> usize {
    debug_assert!(len > 0);
    let len = len as u64;
    let limit = u64::MAX - (u64::MAX % len) - 1;
    let mut buf = [0u8; 8];
    loop {
        rand::rngs::OsRng.fill_bytes(&mut buf);
        let value = u64::from_le_bytes(buf);
        if value <= limit {
            return (value % len) as usize;
        }
    }
}

/// Longest run of letters still treated as possibly one dictionary word.
const MAX_WORD_LIKE_LEN: usize = 12;
/// Bits for which capitalization form a word takes (lower / Title / UPPER).
const CAPITALIZATION_BITS: f64 = 1.6;
/// Candidate years an attacker tries for a four-digit run that looks like one.
const YEAR_CANDIDATES: f64 = 200.0;

/// Score the passphrase by what an attacker actually has to guess: its
/// structure, run by run, rather than its characters one at a time.
fn composition_model_bits(passphrase: &str, chars: &[char], issues: &mut Vec<String>) -> f64 {
    let mut bits = 0.0;
    let mut runs = 0usize;
    let mut word_like_runs = 0usize;

    for run in class_runs(passphrase) {
        runs += 1;
        bits += match run.class {
            CharClass::Alpha => {
                // Score each capitalization-delimited token, not the whole run.
                let mut run_bits = 0.0;
                for token in word_tokens(&run.text) {
                    let (token_bits, word_like) = alpha_run_bits(&token);
                    if word_like {
                        word_like_runs += 1;
                    }
                    run_bits += token_bits;
                }
                run_bits
            }
            CharClass::Digit => digit_run_bits(&run.text),
            CharClass::Symbol => symbol_run_bits(&run.text),
            // Separators are structure, not secret: an attacker assumes them.
            CharClass::Space => 0.0,
            CharClass::Other => run.text.chars().count() as f64 * 100f64.log2(),
        };
    }

    // A password built from two or three class runs is the shape every cracking
    // rule set generates first. Say so, because it is the thing to fix.
    if (2..=4).contains(&runs) && word_like_runs >= 1 {
        issues.push(
            "This is the classic word-then-digits-then-symbol shape — cracking tools generate it first."
                .to_string(),
        );
    }

    if runs == 1 && !chars.iter().any(|c| c.is_ascii_whitespace()) {
        issues.push("Only one kind of character — length is doing all the work here.".to_string());
    }

    bits
}

/// Split into word-ish tokens, treating both separators **and** internal
/// capitalization as boundaries.
///
/// Without the capitalization rule, `MyDogsNameIsRex` is one 15-letter run and
/// the character model calls it 85 bits of randomness. It is five ordinary
/// words, and an attacker's rule sets generate exactly that shape — so it has to
/// tokenize the same way `my dogs name is rex` does.
fn word_tokens(passphrase: &str) -> Vec<String> {
    let mut tokens: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut previous_lower = false;
    for c in passphrase.chars() {
        if c.is_alphabetic() {
            if c.is_uppercase() && previous_lower && !current.is_empty() {
                tokens.push(std::mem::take(&mut current));
            }
            current.push(c);
            previous_lower = c.is_lowercase();
        } else {
            if !current.is_empty() {
                tokens.push(std::mem::take(&mut current));
            }
            previous_lower = false;
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CharClass {
    Alpha,
    Digit,
    Symbol,
    Space,
    Other,
}

struct ClassRun {
    class: CharClass,
    text: String,
}

fn class_of(c: char) -> CharClass {
    if c.is_ascii_alphabetic() {
        CharClass::Alpha
    } else if c.is_ascii_digit() {
        CharClass::Digit
    } else if c.is_whitespace() {
        CharClass::Space
    } else if c.is_ascii_graphic() {
        CharClass::Symbol
    } else {
        CharClass::Other
    }
}

/// Split into maximal runs of a single character class.
fn class_runs(passphrase: &str) -> Vec<ClassRun> {
    let mut runs: Vec<ClassRun> = Vec::new();
    for c in passphrase.chars() {
        let class = class_of(c);
        match runs.last_mut() {
            Some(last) if last.class == class => last.text.push(c),
            _ => runs.push(ClassRun {
                class,
                text: c.to_string(),
            }),
        }
    }
    runs
}

/// How much of a run's length is doing real work.
///
/// `aaaaaaaaaaaa` is twelve characters and one choice. Scaling a run's bits by
/// its distinct-character share collapses that without touching ordinary text,
/// which is why this is applied per run rather than across the whole
/// passphrase — every English phrase reuses letters, and a global version
/// punished real word phrases harder than it punished the padding it was
/// written to catch.
fn repetition_ratio(run: &str) -> f64 {
    let total = run.chars().count();
    if total == 0 {
        return 1.0;
    }
    let mut seen: Vec<char> = run.chars().collect();
    seen.sort_unstable();
    seen.dedup();
    ((seen.len() * 2) as f64 / total as f64).min(1.0)
}

/// Bits for a run of letters, and whether it was treated as one word.
///
/// A run that is short and cased the way people case words (`summer`, `Summer`,
/// `SUMMER`) is charged one dictionary lookup, because that is all it costs to
/// guess. A long or internally-mixed run (`vRmZpLx`) is not word-shaped and
/// keeps full per-character credit.
fn alpha_run_bits(run: &str) -> (f64, bool) {
    let len = run.chars().count();
    let pool: f64 =
        if run.chars().any(|c| c.is_ascii_uppercase()) && run.chars().any(|c| c.is_ascii_lowercase())
        {
            52.0
        } else {
            26.0
        };
    let char_bits = len as f64 * pool.log2();

    let all_lower = run.chars().all(|c| c.is_ascii_lowercase());
    let all_upper = run.chars().all(|c| c.is_ascii_uppercase());
    let title_case = run
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_uppercase())
        && run.chars().skip(1).all(|c| c.is_ascii_lowercase());

    let word_shaped = len <= MAX_WORD_LIKE_LEN && (all_lower || all_upper || title_case);
    if word_shaped {
        let word_bits = HUMAN_WORD_CANDIDATES.log2() + CAPITALIZATION_BITS;
        // Take the cheaper of the two: if the run is so short that brute force
        // beats a dictionary, brute force is what an attacker would do. No
        // repetition discount here — it is already capped at one guess.
        (char_bits.min(word_bits), char_bits > word_bits)
    } else {
        (char_bits * repetition_ratio(run), false)
    }
}

/// Bits for a run of digits. Four digits that read as a year cost far less than
/// four arbitrary ones, because that is what an attacker tries.
fn digit_run_bits(run: &str) -> f64 {
    let len = run.chars().count();
    if len == 4 {
        if let Ok(value) = run.parse::<u32>() {
            if (1900..=2100).contains(&value) {
                return YEAR_CANDIDATES.log2();
            }
        }
    }
    len as f64 * 10f64.log2() * repetition_ratio(run)
}

/// Bits for a run of symbols. The first is a real choice; repeats of the same
/// symbol are nearly free, and even distinct ones cluster on the number row.
fn symbol_run_bits(run: &str) -> f64 {
    let mut chars: Vec<char> = run.chars().collect();
    let total = chars.len();
    chars.sort_unstable();
    chars.dedup();
    let distinct = chars.len() as f64;
    distinct * 32f64.log2() + (total as f64 - distinct) * 1.0
}

/// Score an input that reads as separated words as a choice of that many words.
/// Returns `None` when the input is not word-shaped.
fn word_model_bits(passphrase: &str) -> Option<f64> {
    // Only applies when the input is essentially words: if a third or more of it
    // is digits and symbols, the composition model is the better description.
    let alphabetic = passphrase.chars().filter(|c| c.is_alphabetic()).count();
    let separators = passphrase
        .chars()
        .filter(|c| c.is_whitespace() || *c == '-' || *c == '_' || *c == '.')
        .count();
    if alphabetic + separators < (passphrase.chars().count() * 2).div_ceil(3) {
        return None;
    }

    let words = word_tokens(passphrase);
    // One token is just a string; two or more is a phrase.
    if words.len() < 2 {
        return None;
    }
    // A repeated word is one guess, not two.
    let mut distinct: Vec<String> = words.iter().map(|w| w.to_lowercase()).collect();
    distinct.sort();
    distinct.dedup();
    Some(distinct.len() as f64 * HUMAN_WORD_CANDIDATES.log2())
}

/// Bits to subtract for structure an attacker's wordlist already covers.
fn pattern_penalty_bits(chars: &[char], lower: &str, issues: &mut Vec<String>) -> f64 {
    let mut penalty = 0.0;

    // A blocked word only matters when it *is* the passphrase, or close to it.
    // "master" alone falls in seconds; "regular letter master trip advice garbage
    // render" is not weakened by containing it, and penalising that would let the
    // gate reject phrases this module's own generator produces. So the penalty
    // needs the word to dominate: either it covers a third of the input, or the
    // input is only a couple of tokens long.
    let total_chars = chars.len();
    let token_count = word_tokens(lower).len();
    if let Some(blocked) = BLOCKED_SUBSTRINGS.iter().find(|word| lower.contains(**word)) {
        let dominates = blocked.len() * 3 >= total_chars || token_count <= 3;
        if dominates {
            issues.push(format!(
                "Built around \"{blocked}\" — that is on every attacker's first-guess list."
            ));
            penalty += 24.0;
        }
    }

    // A run of the same character three or more times.
    let mut run = 1usize;
    let mut longest_run = 1usize;
    for pair in chars.windows(2) {
        if pair[0] == pair[1] {
            run += 1;
            longest_run = longest_run.max(run);
        } else {
            run = 1;
        }
    }
    if longest_run >= 3 {
        issues.push("Repeated characters add almost nothing.".to_string());
        penalty += (longest_run as f64 - 2.0) * 3.0;
    }

    // Ascending or descending runs: "abcd", "4321".
    let mut seq = 1usize;
    let mut longest_seq = 1usize;
    for pair in chars.windows(2) {
        let (a, b) = (pair[0] as i32, pair[1] as i32);
        if b - a == 1 || a - b == 1 {
            seq += 1;
            longest_seq = longest_seq.max(seq);
        } else {
            seq = 1;
        }
    }
    if longest_seq >= 4 {
        issues.push("Sequential characters are the first thing guessing tools try.".to_string());
        penalty += (longest_seq as f64 - 3.0) * 4.0;
    }

    penalty
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_wordlist_is_exactly_2048_clean_words() {
        let list = wordlist();
        assert_eq!(list.len(), WORDLIST_LEN);
        assert!(list.iter().all(|w| w.len() >= 3 && w.len() <= 8));
        assert!(list
            .iter()
            .all(|w| w.chars().all(|c| c.is_ascii_lowercase())));
        let mut sorted = list.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), WORDLIST_LEN, "words must be unique");
    }

    #[test]
    fn generated_passphrases_clear_the_floor_and_vary() {
        let a = generate(DEFAULT_GENERATED_WORDS).unwrap();
        let b = generate(DEFAULT_GENERATED_WORDS).unwrap();
        assert_ne!(a, b, "two generated passphrases must not collide");
        assert_eq!(a.split(' ').count(), DEFAULT_GENERATED_WORDS);
        assert!(generated_bits(DEFAULT_GENERATED_WORDS) >= MIN_PASSPHRASE_BITS);
        // And the estimator must agree that what we generate is usable — if it
        // ever disagreed, the UI would offer a passphrase it then refuses.
        require_strong(&a).expect("a generated passphrase must pass the gate");
        require_strong(&b).expect("a generated passphrase must pass the gate");
    }

    #[test]
    fn generate_clamps_absurd_word_counts() {
        assert_eq!(generate(1).unwrap().split(' ').count(), MIN_GENERATED_WORDS);
        assert_eq!(
            generate(9_999).unwrap().split(' ').count(),
            MAX_GENERATED_WORDS
        );
    }

    /// Every one of these passes a 12-character length rule. None of them should
    /// survive an offline attack, and this is exactly what the old gate let
    /// through.
    #[test]
    fn passphrases_that_beat_a_length_rule_are_still_refused() {
        for weak in [
            "Summer2024!!",
            "Password1234",
            "qguard-vault",
            "aaaaaaaaaaaaaaaa",
            "abcdefghijklmnop",
            "Quantum2024!",
            "letmein123456",
            "correct horse battery",
        ] {
            assert!(
                require_strong(weak).is_err(),
                "{weak:?} should be refused but was accepted ({:.1} bits)",
                estimate(weak).bits
            );
        }
    }

    #[test]
    fn genuinely_strong_passphrases_are_accepted() {
        for strong in [
            "ridge lantern copper vessel marble tundra harbor",
            "7Kq#vR2mZ!pLx9Wn&4Ts",
        ] {
            require_strong(strong)
                .unwrap_or_else(|e| panic!("{strong:?} should pass but was refused: {e}"));
        }
    }

    #[test]
    fn short_passphrases_are_refused_whatever_they_score() {
        assert!(require_strong("short").is_err());
        // High character-model score, but too short to survive a targeted attack.
        assert!(require_strong("aA1!bB2@").is_err());
    }

    #[test]
    fn repetition_and_sequences_do_not_buy_entropy() {
        let padded = estimate("ridge lantern aaaaaaaaaaaaaaaaaaaa").bits;
        let honest = estimate("ridge lantern copper vessel marble tundra harbor").bits;
        assert!(
            padded < honest,
            "padding with repeats must not outscore real words ({padded:.1} vs {honest:.1})"
        );
    }

    #[test]
    fn the_estimate_is_shaped_for_a_meter() {
        let weak = estimate("password1234");
        assert_eq!(weak.verdict, "weak");
        assert!(!weak.acceptable);
        assert!(weak.fraction >= 0.0 && weak.fraction <= 1.0);
        assert!(weak.suggestion.is_some());
        assert!(!weak.issues.is_empty());

        let strong = estimate(&generate(DEFAULT_GENERATED_WORDS).unwrap());
        assert!(strong.acceptable);
        assert_eq!(strong.fraction, 1.0);
        assert!(strong.suggestion.is_none());
    }

    #[test]
    fn an_empty_passphrase_is_handled_rather_than_panicking() {
        let empty = estimate("");
        assert_eq!(empty.bits, 0.0);
        assert!(!empty.acceptable);
        assert!(require_strong("").is_err());
    }
}


#[cfg(test)]
mod calibration {
    use super::*;

    /// The estimator's behaviour on known passphrases, asserted rather than
    /// eyeballed. Any change to the model has to face this table.
    ///
    /// The right-hand column is the honest reason each one lands where it does —
    /// if a future tweak moves one of these, the reason is what to argue with.
    #[test]
    fn known_passphrases_land_where_they_should() {
        struct Case {
            passphrase: &'static str,
            accepted: bool,
            because: &'static str,
        }

        let cases = [
            Case { passphrase: "Summer2024!!", accepted: false,
                   because: "word + year + symbols is the shape every rule set generates first" },
            Case { passphrase: "Password1234", accepted: false,
                   because: "blocklisted word, and the digits are a sequence" },
            Case { passphrase: "Quantum2024!", accepted: false,
                   because: "product word an attacker targeting QGuard tries immediately" },
            Case { passphrase: "qguard-vault", accepted: false,
                   because: "two blocklisted product words" },
            Case { passphrase: "aaaaaaaaaaaaaaaa", accepted: false,
                   because: "sixteen characters, one choice" },
            Case { passphrase: "abcdefghijklmnop", accepted: false,
                   because: "a straight alphabet run" },
            Case { passphrase: "Tr0ub4dor&3", accepted: false,
                   because: "xkcd 936's own example of a password that only looks strong" },
            Case { passphrase: "correct horse battery staple", accepted: false,
                   because: "44 bits — the joke was right in 2011 and is not enough now" },
            Case { passphrase: "ridge lantern copper vessel marble tundra harbor", accepted: true,
                   because: "seven independent words, the shape generate() produces" },
            Case { passphrase: "7Kq#vR2mZ!pLx9Wn&4Ts", accepted: true,
                   because: "twenty characters with no exploitable structure" },
        ];

        for case in cases {
            let strength = estimate(case.passphrase);
            assert_eq!(
                strength.acceptable, case.accepted,
                "{:?} scored {:.1} bits and was {}, but {} — {}",
                case.passphrase,
                strength.bits,
                if strength.acceptable { "accepted" } else { "refused" },
                if case.accepted { "it should pass" } else { "it should fail" },
                case.because,
            );
        }
    }

    /// The number the product tells people to trust has to be the number the gate
    /// enforces. If `generate` ever drifts below the floor the UI would be
    /// recommending a passphrase the app then refuses.
    #[test]
    fn the_generator_and_the_gate_agree() {
        assert!(
            generated_bits(DEFAULT_GENERATED_WORDS) >= MIN_PASSPHRASE_BITS,
            "the default word count must clear the floor"
        );
        // Run it repeatedly: word choice is random, so this catches a model that
        // only passes for lucky draws.
        for _ in 0..256 {
            let phrase = generate(DEFAULT_GENERATED_WORDS).unwrap();
            let strength = estimate(&phrase);
            assert!(
                strength.acceptable,
                "generate() produced {phrase:?}, which the gate then refused at {:.1} bits",
                strength.bits
            );
        }
    }

    /// Drawing without replacement is what guarantees the test above: a repeated
    /// word would count once in the estimator and silently cost 11 bits.
    #[test]
    fn generated_words_are_never_repeated() {
        for _ in 0..64 {
            let phrase = generate(MAX_GENERATED_WORDS).unwrap();
            let words: Vec<&str> = phrase.split(' ').collect();
            let mut unique = words.clone();
            unique.sort_unstable();
            unique.dedup();
            assert_eq!(unique.len(), words.len(), "repeated word in {phrase:?}");
        }
    }
}
