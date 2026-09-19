//! Subprocess output masking: replace secrets flowing through stdout/stderr with a placeholder.
//!
//! This is the line of defense `akey run` turns on by default — on the "AI calls an external tool"
//! path it keeps plaintext echoed by that tool from ever entering the conversation context.
//!
//! The hard part is **matching across chunks**: a secret may be split arbitrarily between two read
//! chunks, so up to `max_secret_len - 1` trailing bytes must be withheld until they are known not to form a match.

use crate::output::TAINTED;

/// Values shorter than this are not masked — otherwise short strings like `true`, `0`, or `prod` would be turned into mosaic.
pub const MIN_SECRET_LEN: usize = 8;

/// A streaming masker: feed it the bytes of a subprocess read chunk, it returns **masked** bytes.
///
/// The algorithm is a left-to-right greedy longest match:
/// - the full window at position `i` (`max_len` bytes) is not complete yet → `break`, hold the tail
///   for the next chunk;
/// - the window is complete and hits a secret (longest tried first) → emit the placeholder and
///   advance by `secret.len()`;
/// - no hit → emit the byte verbatim, advance by 1.
///
/// Refusing to conclude while the window is incomplete is what lets "longest match" hold across
/// chunks: otherwise a chunk stopping exactly at a shorter secret's end would replace it first and then leak the longer secret's tail verbatim.
///
/// Only `finish()` (end of stream) gives up the hold-back and runs the tail through the same rules.
#[derive(Default)]
pub struct Masker {
    /// Whether there is anything to mask. With none, the caller inherits directly, saving a pipe copy.
    enabled: bool,
    /// The secrets taking part in masking, **in descending length** so the longest is tried first, with no duplicates.
    secrets: Vec<Vec<u8>>,
    /// Length of the longest entry in `secrets`; 0 when there are none.
    max_len: usize,
    /// The tail consumed but not yet safe to emit.
    pending: Vec<u8>,
}

/// Never prints secret values.
impl std::fmt::Debug for Masker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Masker")
            .field("enabled", &self.enabled)
            .field("secret_count", &self.secrets.len())
            .field("max_len", &self.max_len)
            .field("pending_len", &self.pending.len())
            .finish()
    }
}

impl Masker {
    pub fn new() -> Self {
        Masker::default()
    }

    /// Build from a batch of plaintexts. Values shorter than [`MIN_SECRET_LEN`] are ignored.
    pub fn with_secrets<I: IntoIterator<Item = String>>(secrets: I) -> Self {
        let mut masker = Masker::new();
        for secret in secrets {
            masker.add(&secret);
        }
        masker
    }

    /// Add one plaintext. Empty values, values shorter than [`MIN_SECRET_LEN`], values that are
    /// already the placeholder, and duplicates are all ignored.
    pub fn add(&mut self, secret: &str) {
        if secret.len() < MIN_SECRET_LEN || secret == TAINTED {
            return;
        }
        let bytes = secret.as_bytes();
        if self.secrets.iter().any(|s| s.as_slice() == bytes) {
            return;
        }
        self.secrets.push(bytes.to_vec());
        // Descending order: the first hit during a scan is the longest one.
        self.secrets
            .sort_unstable_by_key(|secret| std::cmp::Reverse(secret.len()));
        self.max_len = self.secrets.first().map_or(0, Vec::len);
        self.enabled = true;
    }

    /// Whether there is anything to mask (with none the caller should inherit directly, saving a pipe copy).
    pub fn is_active(&self) -> bool {
        self.enabled
    }

    /// Consume one read chunk and return the **safe-to-emit** masked bytes.
    ///
    /// May return empty — everything is still awaiting confirmation (the tail is held back).
    pub fn push(&mut self, chunk: &[u8]) -> Vec<u8> {
        if !self.enabled {
            // No secrets means no buffering: straight through, zero-copy semantics (the caller still holds the chunk).
            return chunk.to_vec();
        }
        self.pending.extend_from_slice(chunk);
        self.scan(true)
    }

    /// End of stream: run the held-back tail through the same rules and emit it.
    pub fn finish(&mut self) -> Vec<u8> {
        if !self.enabled {
            self.pending.clear();
            return Vec::new();
        }
        self.scan(false)
    }

    /// Scan `pending`, emit the bytes that are settled, and `drain` the consumed head.
    ///
    /// With `keep_tail` true, hold back a tail that could still start a match; with false (end of stream), process everything.
    fn scan(&mut self, keep_tail: bool) -> Vec<u8> {
        let pending = &self.pending;
        let secrets = &self.secrets;
        let max_len = self.max_len;

        let mut out = Vec::with_capacity(pending.len());
        let mut i = 0;
        while i < pending.len() {
            // The full window at position `i` is not complete yet → concluding now could miss a
            // longer secret; hold the tail (at most max_len - 1 bytes) for the next chunk.
            if keep_tail && i + max_len > pending.len() {
                break;
            }
            let rest = &pending[i..];
            // Try the longest first (secrets are sorted by descending length), so any hit is the longest match.
            if let Some(secret) = secrets.iter().find(|s| rest.starts_with(s)) {
                out.extend_from_slice(TAINTED.as_bytes());
                i += secret.len();
            } else {
                out.push(pending[i]);
                i += 1;
            }
        }
        // One drain, avoiding the O(n²) shifting of a byte-at-a-time remove(0).
        self.pending.drain(..i);
        out
    }
}

/// The placeholder, for tests and docs to reference.
pub fn placeholder() -> &'static str {
    TAINTED
}

#[cfg(test)]
mod tests {
    use super::*;

    const LONG: &str = "ghp_0123456789abcdef";
    const SHORT: &str = "12345678";

    fn mk(secrets: &[&str]) -> Masker {
        Masker::with_secrets(secrets.iter().map(|s| s.to_string()))
    }

    /// Feed everything at once plus finish, and return the complete output.
    fn feed_all(masker: &mut Masker, input: &[u8]) -> Vec<u8> {
        let mut out = masker.push(input);
        out.extend(masker.finish());
        out
    }

    /// Feed byte by byte and return the complete output (including finish) — for cross-chunk regressions.
    fn feed_bytes(masker: &mut Masker, input: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        for byte in input {
            out.extend(masker.push(std::slice::from_ref(byte)));
        }
        out.extend(masker.finish());
        out
    }

    #[test]
    fn same_chunk() {
        let mut masker = mk(&[LONG]);
        let input = format!("token={LONG} end");
        let out = feed_all(&mut masker, input.as_bytes());
        assert_eq!(
            String::from_utf8(out).expect("output should be UTF-8"),
            format!("token={TAINTED} end"),
            "a secret inside one chunk must be replaced, with the surrounding text untouched"
        );
    }

    #[test]
    fn split_across_chunks_byte_by_byte() {
        let input = format!("before {LONG} middle {LONG} after").into_bytes();
        let expected = format!("before {TAINTED} middle {TAINTED} after").into_bytes();

        let mut one_shot = mk(&[LONG]);
        let once = feed_all(&mut one_shot, &input);

        let mut drip = mk(&[LONG]);
        let byte_wise = feed_bytes(&mut drip, &input);

        assert_eq!(once, expected, "the one-shot result");
        assert_eq!(byte_wise, once, "1-byte chunking must be byte-identical to the one-shot feed");
    }

    #[test]
    fn split_at_every_position() {
        let input = format!("x{LONG}y").into_bytes();
        let expected = format!("x{TAINTED}y").into_bytes();
        for split in 0..=input.len() {
            let mut masker = mk(&[LONG]);
            let mut out = masker.push(&input[..split]);
            out.extend(masker.push(&input[split..]));
            out.extend(masker.finish());
            assert_eq!(out, expected, "the split at {split} must still be replaced in full");
        }
    }

    #[test]
    fn short_values_untouched() {
        let mut masker = mk(&["true", "0", "prod", "1234567"]);
        assert!(!masker.is_active(), "all shorter than MIN_SECRET_LEN → not active");

        let out = feed_all(&mut masker, b"true 0 prod 1234567");
        assert_eq!(out, b"true 0 prod 1234567", "short values must pass through verbatim");

        // Exactly 8 bytes turns it on.
        let mut boundary = mk(&["12345678"]);
        assert!(boundary.is_active(), "a length equal to MIN_SECRET_LEN should activate");
        assert_eq!(feed_all(&mut boundary, b"12345678"), TAINTED.as_bytes());
    }

    #[test]
    fn multiple_secrets_in_one_chunk() {
        let second = "sk-ant-api03-xyz";
        let mut masker = mk(&[LONG, second]);
        let input = format!("{LONG} and {second} and {LONG}").into_bytes();
        let out = feed_all(&mut masker, &input);
        assert_eq!(
            String::from_utf8(out).expect("output should be UTF-8"),
            format!("{TAINTED} and {TAINTED} and {TAINTED}")
        );
    }

    #[test]
    fn longest_match_wins_on_shared_prefix() {
        let long = format!("{SHORT}EXTRA");
        for order in [[SHORT, &long[..]], [&long[..], SHORT]] {
            let mut masker = mk(&order);
            // Both one-shot and byte-by-byte feeding must leave a single placeholder, with no "EXTRA" fragments.
            assert_eq!(
                feed_all(&mut masker, &long.clone().into_bytes()),
                TAINTED.as_bytes(),
                "one-shot: the longest match must be taken"
            );

            let mut drip = mk(&order);
            assert_eq!(
                feed_bytes(&mut drip, &long.clone().into_bytes()),
                TAINTED.as_bytes(),
                "byte-by-byte: the longest match must be taken"
            );
        }

        // A prefix secret appearing on its own must still be masked.
        let mut masker = mk(&[SHORT, &long[..]]);
        assert_eq!(feed_all(&mut masker, SHORT.as_bytes()), TAINTED.as_bytes());
    }

    #[test]
    fn finish_flushes_held_secret() {
        // The longer candidate forces the shorter complete secret to be held in the buffer first.
        let long = "ABCDEFGHIJKLMNOPQRST";
        let mut masker = mk(&[SHORT, long]);
        let held = masker.push(SHORT.as_bytes());
        assert!(held.is_empty(), "a complete short secret should be held back, waiting on a longer candidate");

        let tail = masker.finish();
        assert_eq!(tail, TAINTED.as_bytes(), "finish must flush the secret out of the buffer");
        assert!(masker.finish().is_empty(), "finish should be idempotent and not re-emit");

        // At end of stream a truncated secret prefix is not a complete secret and must be emitted verbatim (data must not vanish into thin air).
        let mut truncated = mk(&[LONG]);
        assert!(truncated.push(&LONG.as_bytes()[..5]).is_empty());
        assert_eq!(truncated.finish(), LONG.as_bytes()[..5].to_vec());
    }

    #[test]
    fn empty_and_secret_free_inputs_pass_through() {
        let mut empty = Masker::new();
        assert!(!empty.is_active());
        assert!(empty.push(b"").is_empty());
        assert!(empty.finish().is_empty());

        assert!(
            !Masker::with_secrets(Vec::new()).is_active(),
            "an empty set should not activate masking"
        );

        let mut plain = Masker::new();
        assert_eq!(feed_all(&mut plain, b"just some output\n"), b"just some output\n");

        // Short values only: it passes through as well.
        let mut shorts = mk(&["true", "0"]);
        assert_eq!(feed_all(&mut shorts, b"true and 0"), b"true and 0");
    }

    #[test]
    fn binary_bytes_pass_through() {
        let mut masker = mk(&[LONG]);
        let mut input = vec![0xff, 0x00, 0xfe, 0x80];
        input.extend_from_slice(LONG.as_bytes());
        input.extend_from_slice(&[0x81, 0xc3, 0x28]);

        let mut expected = vec![0xff, 0x00, 0xfe, 0x80];
        expected.extend_from_slice(TAINTED.as_bytes());
        expected.extend_from_slice(&[0x81, 0xc3, 0x28]);

        assert_eq!(feed_all(&mut masker, &input), expected, "non-UTF-8 bytes pass through verbatim");

        let mut drip = mk(&[LONG]);
        assert_eq!(feed_bytes(&mut drip, &input), expected, "the same holds byte by byte");
    }

    #[test]
    fn arbitrary_chunkings_match_one_shot() {
        // Deterministic pseudo-random (LCG) chunking: several secrets plus binary noise; any split must match the one-shot feed.
        const A: &str = "sk-live-0123456789abcdef";
        const B: &str = "ABCDEFGHIJKLMNOPQRST";
        const C: &str = "sk-live-0123"; // a shorter value sharing a prefix with A
        let mut input = Vec::new();
        let mut state: u32 = 0x2545_F491;
        for i in 0..256u32 {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223) ^ i;
            if state.is_multiple_of(7) {
                let secret: &[u8] = match state % 3 {
                    0 => A.as_bytes(),
                    1 => B.as_bytes(),
                    _ => C.as_bytes(),
                };
                input.extend_from_slice(secret);
            } else {
                input.push((state >> 11) as u8); // includes arbitrary non-UTF-8 bytes
            }
        }

        let mut one_shot = mk(&[A, B, C]);
        let expected = feed_all(&mut one_shot, &input);

        let mut state: u32 = 7;
        for round in 0..64 {
            let mut chunked = mk(&[C, A, B]);
            let mut out = Vec::new();
            let mut pos = 0;
            while pos < input.len() {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                let take = (state as usize % 5) + 1;
                let end = (pos + take).min(input.len());
                out.extend(chunked.push(&input[pos..end]));
                pos = end;
            }
            out.extend(chunked.finish());
            assert_eq!(out, expected, "random chunking diverges from the one-shot feed on round {round}");
            for secret in [A, B, C] {
                assert!(
                    !out.windows(secret.len()).any(|w| w == secret.as_bytes()),
                    "plaintext secret {secret} survives in the round-{round} output"
                );
            }
        }
    }
}
