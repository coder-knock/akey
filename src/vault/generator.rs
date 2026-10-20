//! Password / passphrase generator.
//!
//! See `DESIGN.md` §17.1 / §17.2 for the recipe grammar and diceware wordlist choice.
//!
//! The output is what ends up in a `Concealed` field; it is what the `run` masker
//! protects. The generator itself never touches the vault and never writes audit.

use std::sync::LazyLock;

use crate::error::{Error, Result};

/// EFF Short Wordlist #1 (1296 words). CC-BY-SA 3.0 — `https://www.eff.org/files/2016/09/08/eff_short_wordlist_1.txt`.
/// Each line is `<4-digit roll>\t<word>`; we drop the roll column at load time.
const EFF_SHORT_RAW: &str = include_str!("../../assets/diceware/eff-short.txt");

const LETTERS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";
const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{};:,.<>/?~";
const HEX: &[u8] = b"0123456789abcdef";
const BASE32_CROCKFORD: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const BASE64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const NO_AMBIGUOUS: &[u8] = b"0O1lI|";

const DEFAULT_LENGTH: usize = 32;
const MAX_LENGTH: usize = 4096;
const MAX_PASSPHRASE_WORDS: usize = 10;

/// Default minimum length for a recovery passphrase. Overridable via
/// `--min-passphrase-len` / `AKEY_RECOVERY_MIN_LEN`. Lives here only because
/// `generator` is the module that already talks about length bounds.
pub const MIN_PASSPHRASE_LEN: usize = 12;
pub const MIN_PASSPHRASE_LEN_FLOOR: usize = 8;
pub const MIN_PASSPHRASE_LEN_CEIL: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Recipe {
    pub letters: bool,
    pub digits: bool,
    pub symbols: bool,
    pub no_ambiguous: bool,
    pub hex: bool,
    pub base32: bool,
    pub base64: bool,
    pub passphrase: bool,
    /// For character recipes this is the character count; for passphrase recipes this is
    /// the word count.
    pub length: usize,
}

impl Recipe {
    pub fn parse(raw: &str) -> Result<Self> {
        let mut out = Recipe {
            letters: false,
            digits: false,
            symbols: false,
            no_ambiguous: false,
            hex: false,
            base32: false,
            base64: false,
            passphrase: false,
            length: DEFAULT_LENGTH,
        };
        let mut length_set = false;
        for token in raw.split(',').map(str::trim).filter(|t| !t.is_empty()) {
            match token {
                "letters" => out.letters = true,
                "digits" => out.digits = true,
                "symbols" => out.symbols = true,
                "no-ambiguous" => out.no_ambiguous = true,
                "hex" => out.hex = true,
                "base32" => out.base32 = true,
                "base64" => out.base64 = true,
                "passphrase" => out.passphrase = true,
                other => match other.parse::<usize>() {
                    Ok(n) if n > 0 && n <= MAX_LENGTH => {
                        out.length = n;
                        length_set = true;
                    }
                    Ok(n) => {
                        return Err(Error::usage(crate::msg!(
                            "password length {n} out of range; expected 1..={MAX_LENGTH}",
                            "密码长度 {n} 超出范围；应为 1..={MAX_LENGTH}",
                            n
                        )));
                    }
                    Err(_) => {
                        return Err(Error::usage(crate::msg!(
                            "unknown password recipe token '{other}'; expected letters, digits, symbols, no-ambiguous, hex, base32, base64, passphrase or a length",
                            "无法识别的密码配方项 '{other}'；应为 letters、digits、symbols、no-ambiguous、hex、base32、base64、passphrase 或一个长度",
                            other
                        )));
                    }
                },
            }
        }
        // Defaults for the empty / partial recipe.
        if raw.trim().is_empty() {
            out.letters = true;
            out.digits = true;
            out.symbols = true;
            out.length = DEFAULT_LENGTH;
        }
        if out.passphrase {
            if out.letters || out.digits || out.symbols || out.hex || out.base32 || out.base64 {
                return Err(Error::usage(crate::msg!(
                    "passphrase recipe cannot be combined with letters/digits/symbols/hex/base32/base64",
                    "passphrase 配方不能与 letters/digits/symbols/hex/base32/base64 同时使用"
                )));
            }
            if out.length == 0 || out.length > MAX_PASSPHRASE_WORDS {
                return Err(Error::usage(crate::msg!(
                    "passphrase word count must be 1..={MAX_PASSPHRASE_WORDS}",
                    "passphrase 词数应为 1..={MAX_PASSPHRASE_WORDS}"
                )));
            }
        }
        if !out.passphrase
            && !(out.letters || out.digits || out.symbols || out.hex || out.base32 || out.base64)
        {
            out.letters = true;
            out.digits = true;
            out.symbols = true;
        }
        if !length_set && !out.passphrase {
            out.length = DEFAULT_LENGTH;
        }
        Ok(out)
    }

    pub fn length(&self) -> usize {
        self.length
    }

    /// Character pool to sample from. Empty string ⇒ recipe cannot be sampled (this is a
    /// programming error and `generate` will surface it as a usage error).
    pub fn pool(&self) -> Vec<u8> {
        let mut pool: Vec<u8> = Vec::new();
        if self.hex {
            pool.extend_from_slice(HEX);
        } else if self.base32 {
            pool.extend_from_slice(BASE32_CROCKFORD);
        } else if self.base64 {
            pool.extend_from_slice(BASE64);
        } else {
            if self.letters {
                pool.extend_from_slice(LETTERS);
            }
            if self.digits {
                pool.extend_from_slice(DIGITS);
            }
            if self.symbols {
                pool.extend_from_slice(SYMBOLS);
            }
        }
        if self.no_ambiguous {
            pool.retain(|b| !NO_AMBIGUOUS.contains(b));
        }
        pool
    }
}

/// Produce a string sampled from `recipe.length` characters of the recipe's pool.
pub fn generate(recipe: &Recipe) -> String {
    if recipe.passphrase {
        return generate_passphrase(recipe.length);
    }
    let pool = recipe.pool();
    if pool.is_empty() {
        return String::new();
    }
    let mut buf = vec![0u8; recipe.length + recipe.length / 2 + 8];
    rand::fill(buf.as_mut_slice());
    let size = pool.len();
    let limit = 256 - (256 % size);
    let mut cursor = 0usize;
    let mut out = String::with_capacity(recipe.length);
    while out.len() < recipe.length {
        if cursor >= buf.len() {
            rand::fill(buf.as_mut_slice());
            cursor = 0;
        }
        let mut byte = buf[cursor];
        cursor += 1;
        while byte as usize >= limit {
            if cursor >= buf.len() {
                rand::fill(buf.as_mut_slice());
                cursor = 0;
            }
            byte = buf[cursor];
            cursor += 1;
        }
        let c = pool[byte as usize % size] as char;
        out.push(c);
    }
    out
}

/// Pick `n` words from the EFF short list and join them with `-`. Words are lowercase,
/// ASCII, no separator inside each word.
pub fn generate_passphrase(n: usize) -> String {
    if n == 0 {
        return String::new();
    }
    let words = eff_short_words();
    let mut buf = vec![0u8; (n * 4).max(8)];
    rand::fill(buf.as_mut_slice());
    let mut out = String::new();
    for i in 0..n {
        let idx = (u32::from_le_bytes([buf[i * 4], buf[i * 4 + 1], buf[i * 4 + 2], buf[i * 4 + 3]])
            as usize)
            % words.len();
        if i > 0 {
            out.push('-');
        }
        out.push_str(words[idx]);
    }
    out
}

/// Lazily parsed view of the EFF short wordlist.
pub fn eff_short_words() -> &'static [&'static str] {
    static CACHE: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
        EFF_SHORT_RAW
            .lines()
            .filter_map(|line| line.split('\t').nth(1))
            .collect()
    });
    &CACHE
}

#[cfg(test)]
mod tests {
    use super::*;

    fn is_symbol(c: char) -> bool {
        SYMBOLS.contains(&(c as u8))
    }

    #[test]
    fn recipe_empty_means_default_three_pool_thirty_two() {
        let r = Recipe::parse("").unwrap();
        assert!(r.letters);
        assert!(r.digits);
        assert!(r.symbols);
        assert!(!r.no_ambiguous);
        assert!(!r.passphrase);
        assert_eq!(r.length(), 32);
    }

    #[test]
    fn recipe_tokens_combine_with_or() {
        let r = Recipe::parse("letters,16").unwrap();
        assert!(r.letters && !r.digits && !r.symbols);
        assert_eq!(r.length(), 16);

        let r = Recipe::parse("digits,12").unwrap();
        assert!(!r.letters && r.digits && !r.symbols);
        assert_eq!(r.length(), 12);

        let r = Recipe::parse("letters,digits,20").unwrap();
        assert!(r.letters && r.digits && !r.symbols);
        assert_eq!(r.length(), 20);
    }

    #[test]
    fn recipe_no_ambiguous_is_a_filter_not_a_pool() {
        let r = Recipe::parse("no-ambiguous,24").unwrap();
        assert!(r.no_ambiguous);
        assert!(
            r.letters && r.digits && r.symbols,
            "default pool still applies"
        );
        assert_eq!(r.length(), 24);
    }

    #[test]
    fn recipe_alphabet_tokens_replace_the_pool() {
        let hex = Recipe::parse("hex,16").unwrap();
        assert!(hex.hex && !hex.letters && !hex.digits);
        assert_eq!(hex.length(), 16);

        let b32 = Recipe::parse("base32,32").unwrap();
        assert!(b32.base32);
        assert_eq!(b32.length(), 32);

        let b64 = Recipe::parse("base64,24").unwrap();
        assert!(b64.base64);
        assert_eq!(b64.length(), 24);
    }

    #[test]
    fn recipe_passphrase_uses_word_count_not_char_count() {
        let r = Recipe::parse("passphrase,5").unwrap();
        assert!(r.passphrase);
        assert_eq!(r.length(), 5);
        assert!(Recipe::parse("passphrase,0").is_err());
        assert!(Recipe::parse("passphrase,11").is_err());
    }

    #[test]
    fn recipe_passphrase_and_pool_tokens_are_mutually_exclusive() {
        assert!(Recipe::parse("passphrase,letters,5").is_err());
        assert!(Recipe::parse("letters,passphrase,5").is_err());
    }

    #[test]
    fn recipe_unknown_token_is_rejected() {
        assert!(Recipe::parse("emoji,16").is_err());
        assert!(Recipe::parse("letters,emoji,16").is_err());
    }

    #[test]
    fn recipe_length_out_of_range_is_rejected() {
        assert!(Recipe::parse("letters,0").is_err());
        assert!(Recipe::parse("letters,4097").is_err());
    }

    #[test]
    fn generate_default_length_is_thirty_two_and_uses_full_pool() {
        let r = Recipe::parse("").unwrap();
        let s = generate(&r);
        assert_eq!(s.len(), 32);
        assert!(
            s.chars()
                .all(|c| c.is_ascii_alphabetic() || c.is_ascii_digit() || is_symbol(c)),
            "every char must come from the default pool: {s}"
        );
    }

    #[test]
    fn generate_letters_only_is_only_ascii_letters() {
        let r = Recipe::parse("letters,40").unwrap();
        let s = generate(&r);
        assert_eq!(s.len(), 40);
        assert!(s.chars().all(|c| c.is_ascii_alphabetic()), "{s}");
    }

    #[test]
    fn generate_digits_only_is_only_ascii_digits() {
        let r = Recipe::parse("digits,16").unwrap();
        let s = generate(&r);
        assert_eq!(s.len(), 16);
        assert!(s.chars().all(|c| c.is_ascii_digit()), "{s}");
    }

    #[test]
    fn generate_no_ambiguous_excludes_lookalikes() {
        let r = Recipe::parse("no-ambiguous,200").unwrap();
        let s = generate(&r);
        for c in s.chars() {
            assert!(
                !matches!(c, '0' | 'O' | '1' | 'l' | 'I' | '|'),
                "no-ambiguous filter must exclude {c:?} in {s}"
            );
        }
    }

    #[test]
    fn generate_hex_only_uses_hex_alphabet() {
        let r = Recipe::parse("hex,64").unwrap();
        let s = generate(&r);
        assert!(s.chars().all(|c| c.is_ascii_hexdigit()), "{s}");
        assert_eq!(s.len(), 64);
    }

    #[test]
    fn generate_base32_only_uses_crockford_alphabet() {
        let r = Recipe::parse("base32,32").unwrap();
        let s = generate(&r);
        for c in s.chars() {
            assert!(
                matches!(c,
                    '0'..='9' | 'A'..='H' | 'J'..='K' | 'M'..='N' | 'P'..='T' | 'V'..='Z'
                ),
                "non-Crockford char {c:?} in {s}"
            );
        }
    }

    #[test]
    fn generate_base64_uses_its_64_alphabet() {
        let r = Recipe::parse("base64,32").unwrap();
        let s = generate(&r);
        for c in s.chars() {
            assert!(
                matches!(c, 'A'..='Z' | 'a'..='z' | '0'..='9' | '+' | '/'),
                "non-base64 char {c:?} in {s}"
            );
        }
    }

    #[test]
    fn generate_two_runs_are_almost_certainly_different() {
        let r = Recipe::parse("letters,digits,symbols,32").unwrap();
        let a = generate(&r);
        let b = generate(&r);
        assert_ne!(a, b, "32-char random output collided — CSPRNG broken?");
    }

    #[test]
    fn passphrase_uses_wordlist_and_separator() {
        let p = generate_passphrase(5);
        assert_eq!(p.split('-').count(), 5);
        let words = eff_short_words();
        for word in p.split('-') {
            assert!(
                words.contains(&word),
                "word {word:?} not in the embedded EFF short wordlist"
            );
        }
    }

    #[test]
    fn passphrase_zero_words_is_empty_string() {
        assert!(generate_passphrase(0).is_empty());
    }

    #[test]
    fn wordlist_is_nonempty_lowercase_and_unique() {
        let words = eff_short_words();
        assert!(words.len() >= 1024);
        let mut sorted: Vec<&str> = words.to_vec();
        sorted.sort();
        let before = sorted.len();
        sorted.dedup();
        assert_eq!(sorted.len(), before, "duplicate word in wordlist");
        for w in words {
            assert_eq!(*w, w.to_lowercase().as_str(), "non-lowercase word: {w}");
        }
    }
}
