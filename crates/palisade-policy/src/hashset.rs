//! First-class hash sets (#368): a library set of SHA-256 digests that a
//! criterion references by ID and pinned version, instead of having it
//! expanded into criteria of at most 25 values.
//!
//! [`Digests`] is the set as the bundle carries it and the evaluator reads
//! it: raw 32-byte digests, sorted and without repeats, in one buffer. A
//! membership test is a binary search, and one entry costs its 32 bytes,
//! so a million-entry set is 32 MB however many rules reference it.
//!
//! In a bundle a set is one CBOR byte string, the digests concatenated.
//! The reader is strict ([`Digests::from_sorted_bytes`]): the length must
//! be a multiple of 32 and the digests strictly ascending, so one set has
//! exactly one encoding. A delta changes a set by the digests it adds and
//! removes ([`Digests::patch`]), each a set of the same form.
//!
//! # Fail closed
//!
//! A criterion whose set is not in the bundle, is another kind of set, has
//! another field or is at another version is `Unknown` (note
//! `set_unresolved`), so it never lets an allow match, and its negation is
//! `Unknown` too (ADR 0018).

use core::fmt;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::model::{Field, FieldClass};

/// The length of one digest, in bytes: SHA-256.
pub const DIGEST_LEN: usize = 32;

/// One SHA-256 digest.
pub type Digest = [u8; DIGEST_LEN];

/// Whether a hash set may be on `field`: a SHA-256 hash of the file
/// (`hash.sha256`, `hash.authenticode_sha256`, `hash.page_sha256`,
/// `hash.msi_fuzzy_sha256`), never a signer field.
#[must_use]
pub const fn field_allowed(field: Field) -> bool {
    matches!(field.class(), FieldClass::Hash { hex_len: 64 }) && !field.is_signer()
}

/// A set of SHA-256 digests, sorted and without repeats. Cloning shares
/// the buffer.
#[derive(Clone, PartialEq, Eq, Hash, Default)]
pub struct Digests(Arc<[u8]>);

/// Why bytes are not a set of digests, or a patch does not apply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DigestsError {
    /// The length is not a multiple of [`DIGEST_LEN`].
    Length(usize),
    /// The digest at this index is not above the one before it.
    NotAscending(usize),
    /// A value is not 64 hexadecimal digits.
    NotHex,
    /// A patch removes a digest the set does not hold.
    RemoveMissing,
    /// A patch adds a digest the set already holds.
    AddPresent,
}

impl fmt::Display for DigestsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Length(n) => write!(f, "{n} bytes is not a whole number of 32-byte digests"),
            Self::NotAscending(i) => {
                write!(
                    f,
                    "digest {i} is not above the one before it: not sorted, or repeated"
                )
            }
            Self::NotHex => f.write_str("a hash is not 64 hexadecimal digits"),
            Self::RemoveMissing => f.write_str("the patch removes a digest the set does not hold"),
            Self::AddPresent => f.write_str("the patch adds a digest the set already holds"),
        }
    }
}

impl std::error::Error for DigestsError {}

impl Digests {
    /// Reads digests that are already in canonical form: whole digests,
    /// strictly ascending.
    ///
    /// # Errors
    ///
    /// [`DigestsError::Length`] or [`DigestsError::NotAscending`].
    pub fn from_sorted_bytes(bytes: &[u8]) -> Result<Self, DigestsError> {
        let (digests, rest) = bytes.as_chunks::<DIGEST_LEN>();
        if !rest.is_empty() {
            return Err(DigestsError::Length(bytes.len()));
        }
        if let Some(i) = digests.windows(2).position(|pair| pair[0] >= pair[1]) {
            return Err(DigestsError::NotAscending(i + 1));
        }
        Ok(Self(bytes.into()))
    }

    /// The set of `digests`, in any order, repeats removed.
    #[must_use]
    pub fn from_digests(digests: impl IntoIterator<Item = Digest>) -> Self {
        let mut v: Vec<Digest> = digests.into_iter().collect();
        v.sort_unstable();
        v.dedup();
        Self(v.concat().into())
    }

    /// The set of hashes written as hex, with or without `0x`, in any case.
    ///
    /// # Errors
    ///
    /// [`DigestsError::NotHex`] if a value is not a SHA-256 in hex.
    pub fn from_hex<S: AsRef<str>>(
        hashes: impl IntoIterator<Item = S>,
    ) -> Result<Self, DigestsError> {
        let mut out = Vec::new();
        for h in hashes {
            out.push(decode(h.as_ref()).ok_or(DigestsError::NotHex)?);
        }
        Ok(Self::from_digests(out))
    }

    /// The canonical bytes: the digests concatenated.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The number of digests.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len() / DIGEST_LEN
    }

    /// Whether the set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The digests, ascending.
    pub fn iter(&self) -> impl Iterator<Item = &[u8]> {
        self.0
            .as_chunks::<DIGEST_LEN>()
            .0
            .iter()
            .map(<[u8; DIGEST_LEN]>::as_slice)
    }

    /// Whether the set holds `digest`: a binary search.
    #[must_use]
    pub fn contains(&self, digest: &[u8]) -> bool {
        if digest.len() != DIGEST_LEN {
            return false;
        }
        let (mut lo, mut hi) = (0, self.len());
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let at = mid * DIGEST_LEN;
            match self.0[at..at + DIGEST_LEN].cmp(digest) {
                core::cmp::Ordering::Less => lo = mid + 1,
                core::cmp::Ordering::Greater => hi = mid,
                core::cmp::Ordering::Equal => return true,
            }
        }
        false
    }

    /// Whether the set holds the hash written as `hex` (64 digits, no
    /// prefix, any case, as the agent reports a fact). `None` if it is not
    /// a SHA-256 in that form.
    #[must_use]
    pub fn contains_hex(&self, hex: &str) -> Option<bool> {
        let mut d = [0u8; DIGEST_LEN];
        crate::ops::anchor::decode_hex_into(hex, &mut d)?;
        Some(self.contains(&d))
    }

    /// This set with `remove` taken out and `add` put in. Strict, so a
    /// patch only applies to the exact set it was made from: every digest
    /// removed must be held, and none added may be.
    ///
    /// # Errors
    ///
    /// [`DigestsError::RemoveMissing`] or [`DigestsError::AddPresent`].
    pub fn patch(&self, add: &Self, remove: &Self) -> Result<Self, DigestsError> {
        let mut out: Vec<u8> =
            Vec::with_capacity((self.len() + add.len()).saturating_sub(remove.len()) * DIGEST_LEN);
        let mut removes = remove.iter().peekable();
        let mut adds = add.iter().peekable();
        for d in self.iter() {
            while let Some(a) = adds.peek().copied().filter(|a| *a < d) {
                out.extend_from_slice(a);
                adds.next();
            }
            if adds.peek().is_some_and(|a| *a == d) {
                return Err(DigestsError::AddPresent);
            }
            match removes.peek() {
                Some(r) if *r == d => {
                    removes.next();
                }
                Some(r) if *r < d => return Err(DigestsError::RemoveMissing),
                _ => out.extend_from_slice(d),
            }
        }
        if removes.next().is_some() {
            return Err(DigestsError::RemoveMissing);
        }
        for a in adds {
            out.extend_from_slice(a);
        }
        Ok(Self(out.into()))
    }

    /// What `new` adds to this set and what it removes: the patch that
    /// [`Self::patch`] applies to this set to give `new`.
    #[must_use]
    pub fn diff(&self, new: &Self) -> (Self, Self) {
        let (mut add, mut remove) = (Vec::new(), Vec::new());
        let mut a = self.iter().peekable();
        let mut b = new.iter().peekable();
        loop {
            match (a.peek().copied(), b.peek().copied()) {
                (Some(x), Some(y)) if x == y => {
                    a.next();
                    b.next();
                }
                (Some(x), Some(y)) if x < y => {
                    remove.extend_from_slice(x);
                    a.next();
                }
                (Some(_), Some(y)) | (None, Some(y)) => {
                    add.extend_from_slice(y);
                    b.next();
                }
                (Some(x), None) => {
                    remove.extend_from_slice(x);
                    a.next();
                }
                (None, None) => break,
            }
        }
        (Self(add.into()), Self(remove.into()))
    }
}

impl fmt::Debug for Digests {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Digests({} entries)", self.len())
    }
}

/// A SHA-256 written as hex, with or without `0x`.
fn decode(hex: &str) -> Option<Digest> {
    let canonical = crate::ops::normalize_hex(hex)?;
    let mut d = [0u8; DIGEST_LEN];
    crate::ops::anchor::decode_hex_into(&canonical, &mut d)?;
    Some(d)
}

impl Serialize for Digests {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for Digests {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl serde::de::Visitor<'_> for V {
            type Value = Digests;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("32-byte digests, ascending")
            }
            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Digests, E> {
                Digests::from_sorted_bytes(v).map_err(E::custom)
            }
        }
        d.deserialize_bytes(V)
    }
}

#[cfg(test)]
mod tests;
