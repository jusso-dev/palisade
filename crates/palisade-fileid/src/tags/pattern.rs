//! Masked byte patterns: the only thing a content rule matches.
//!
//! A pattern is a fixed-length run of bytes, each with a mask: a file byte
//! `b` matches pattern byte `v` with mask `m` when `b & m == v`. A mask of
//! `0xff` is an exact byte, `0x00` is any byte (`??`), and `0xf0` or `0x0f`
//! is a nibble wildcard (`4?`, `?d`). There are no repetitions, gaps or
//! alternatives, so checking a pattern at one position costs exactly its
//! length, and a scan is linear in the bytes scanned.

#![forbid(unsafe_code)]

use super::rules::RuleErrorKind;
use super::{MAX_PATTERN_LEN, MIN_ATOM_LEN};

/// A compiled pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Pattern {
    /// The expected bits, already masked.
    value: Vec<u8>,
    /// Which bits of each byte are compared.
    mask: Vec<u8>,
}

impl Pattern {
    /// Parses hex text: pairs of hex digits or `?`, with optional ASCII
    /// whitespace anywhere, such as `4D 5A ?? 0?`.
    pub(super) fn from_hex(text: &str) -> Result<Self, RuleErrorKind> {
        let mut nibbles = Vec::new();
        for c in text.chars() {
            if c.is_ascii_whitespace() {
                continue;
            }
            let nibble = match c {
                '?' => None,
                _ => Some(
                    u8::try_from(c.to_digit(16).ok_or(RuleErrorKind::BadHex)?)
                        .map_err(|_| RuleErrorKind::BadHex)?,
                ),
            };
            if nibbles.len() >= MAX_PATTERN_LEN * 2 {
                return Err(RuleErrorKind::PatternTooLong);
            }
            nibbles.push(nibble);
        }
        if nibbles.is_empty() {
            return Err(RuleErrorKind::EmptyPattern);
        }
        if nibbles.len() % 2 != 0 {
            return Err(RuleErrorKind::BadHex);
        }
        let (value, mask) = nibbles
            .chunks(2)
            .map(|pair| match pair {
                [high, low] => {
                    let (hv, hm) = high.map_or((0, 0), |n| (n << 4, 0xf0));
                    let (lv, lm) = low.map_or((0, 0), |n| (n, 0x0f));
                    (hv | lv, hm | lm)
                }
                _ => (0, 0),
            })
            .unzip();
        Ok(Self { value, mask })
    }

    /// Exact bytes of `text` (UTF-8), or with `wide`, of `text` as
    /// UTF-16LE. Wide text must be ASCII.
    pub(super) fn from_text(text: &str, wide: bool) -> Result<Self, RuleErrorKind> {
        if text.is_empty() {
            return Err(RuleErrorKind::EmptyPattern);
        }
        // Checked before anything is allocated.
        let len = if wide {
            text.len().saturating_mul(2)
        } else {
            text.len()
        };
        if len > MAX_PATTERN_LEN {
            return Err(RuleErrorKind::PatternTooLong);
        }
        let value: Vec<u8> = if wide {
            if !text.is_ascii() {
                return Err(RuleErrorKind::WideNotAscii);
            }
            text.bytes().flat_map(|b| [b, 0]).collect()
        } else {
            text.as_bytes().to_vec()
        };
        let mask = vec![0xff; value.len()];
        Ok(Self { value, mask })
    }

    /// The pattern length in bytes.
    pub(super) fn len(&self) -> usize {
        self.value.len()
    }

    /// Feeds the length, value and mask bytes to `h`: what the pattern
    /// matches, however its source text was written.
    pub(super) fn encode(&self, h: &mut sha2::Sha256) {
        use sha2::Digest as _;
        h.update(
            u64::try_from(self.value.len())
                .unwrap_or(u64::MAX)
                .to_le_bytes(),
        );
        h.update(&self.value);
        h.update(&self.mask);
    }

    /// Whether `data` starts with a match. Costs at most [`Self::len`]
    /// comparisons.
    pub(super) fn matches(&self, data: &[u8]) -> bool {
        data.len() >= self.value.len()
            && data
                .iter()
                .zip(self.value.iter().zip(&self.mask))
                .all(|(b, (v, m))| b & m == *v)
    }

    /// The longest run of exact bytes, as (offset in the pattern, bytes):
    /// the literal the multi-pattern searcher looks for. The first of
    /// equally long runs is taken. `None` if the longest is shorter than
    /// [`MIN_ATOM_LEN`].
    pub(super) fn atom(&self) -> Option<(usize, &[u8])> {
        let mut best = (0, 0);
        let mut start = 0;
        for (i, m) in self.mask.iter().enumerate() {
            if *m == 0xff {
                let run = i + 1 - start;
                if run > best.1 {
                    best = (start, run);
                }
            } else {
                start = i + 1;
            }
        }
        let (at, len) = best;
        if len < MIN_ATOM_LEN {
            return None;
        }
        self.value.get(at..at + len).map(|bytes| (at, bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_with_wildcards_and_nibbles() {
        let p = Pattern::from_hex("4D 5a ?? 0? ?f").unwrap();
        assert_eq!(p.len(), 5);
        assert!(p.matches(b"MZ\x00\x05\x3f"));
        assert!(p.matches(b"MZ\xff\x0f\xff"));
        assert!(!p.matches(b"MZ\x00\x15\x3f"));
        assert!(!p.matches(b"MZ\x00\x05\x3e"));
        assert!(!p.matches(b"MZ\x00\x05"), "too short");
        assert_eq!(
            Pattern::from_hex("4d5a").unwrap(),
            Pattern::from_hex("4D 5A").unwrap()
        );
    }

    #[test]
    fn bad_hex() {
        assert_eq!(Pattern::from_hex("4"), Err(RuleErrorKind::BadHex));
        assert_eq!(Pattern::from_hex("4G"), Err(RuleErrorKind::BadHex));
        assert_eq!(Pattern::from_hex("  "), Err(RuleErrorKind::EmptyPattern));
        assert_eq!(Pattern::from_hex("٣٣"), Err(RuleErrorKind::BadHex));
        let long = "00".repeat(MAX_PATTERN_LEN + 1);
        assert_eq!(Pattern::from_hex(&long), Err(RuleErrorKind::PatternTooLong));
        assert!(Pattern::from_hex(&"00".repeat(MAX_PATTERN_LEN)).is_ok());
    }

    #[test]
    fn text_and_wide_text() {
        let p = Pattern::from_text("ab", true).unwrap();
        assert!(p.matches(b"a\0b\0"));
        assert_eq!(
            Pattern::from_text("é", true),
            Err(RuleErrorKind::WideNotAscii)
        );
        assert_eq!(
            Pattern::from_text("", false),
            Err(RuleErrorKind::EmptyPattern)
        );
        assert!(
            Pattern::from_text("é", false)
                .unwrap()
                .matches("é".as_bytes())
        );
    }

    #[test]
    fn atom_is_the_longest_exact_run() {
        let p = Pattern::from_hex("41 ?? 42 43 44 ?? 45 46 47").unwrap();
        assert_eq!(p.atom(), Some((2, &b"BCD"[..])));
        let p = Pattern::from_hex("41 ?? 42 4? 43").unwrap();
        assert_eq!(p.atom(), None, "no run of two exact bytes");
        let p = Pattern::from_hex("41 42").unwrap();
        assert_eq!(p.atom(), Some((0, &b"AB"[..])));
    }
}
