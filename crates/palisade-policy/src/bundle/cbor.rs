//! Canonical CBOR for policy bundles (#43).
//!
//! This is the subset of CBOR (RFC 8949) that bundles use, in the core
//! deterministic encoding of RFC 8949 §4.2:
//!
//! - integers, lengths and counts in their shortest form;
//! - definite lengths only;
//! - map keys sorted bytewise by their encoded form, with no duplicates;
//! - no floating point, no tags, and no simple values other than `false`,
//!   `true` and `null`;
//! - text strings are valid UTF-8 in Unicode Normalization Form C.
//!
//! The encoder can only write canonical bytes: a [`Map`] keeps its entries
//! sorted and unique, and [`encode`] refuses text that is not NFC and
//! nesting the decoder would refuse. The decoder ([`decode`]) is strict: it
//! rejects every input that is not exactly what [`encode`] writes for the
//! value it reads, so `encode(decode(b)) == b` for every `b` it accepts. It
//! is safe on untrusted input: it never panics, checks every declared
//! length against the bytes that remain before it allocates, and bounds the
//! input size, the nesting depth and the number of items ([`Limits`]).

use core::cmp::Ordering;
use core::fmt;

use unicode_normalization::is_nfc;

/// Deepest nesting of arrays and maps. A value that is not an array or a
/// map has depth 0, and `[[]]` has depth 2.
pub const MAX_DEPTH: usize = 64;

/// One CBOR data item.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    /// An unsigned integer (major type 0).
    Uint(u64),
    /// A negative integer, `-1 - n` (major type 1).
    Nint(u64),
    /// A byte string (major type 2).
    Bytes(Vec<u8>),
    /// A text string (major type 3). [`encode`] requires NFC.
    Text(String),
    /// An array (major type 4).
    Array(Vec<Self>),
    /// A map (major type 5).
    Map(Map),
    /// `false` or `true`.
    Bool(bool),
    /// `null`.
    Null,
}

impl Value {
    /// The integer `n`, as [`Value::Uint`] or [`Value::Nint`].
    #[must_use]
    pub const fn int(n: i64) -> Self {
        if n < 0 {
            // `-1 - n` for a negative `n` is `!n` reinterpreted, and fits.
            Self::Nint((!n).cast_unsigned())
        } else {
            Self::Uint(n.cast_unsigned())
        }
    }

    /// The value as an `i64`, if it is an integer that fits.
    #[must_use]
    pub fn as_i64(&self) -> Option<i64> {
        match *self {
            Self::Uint(n) => i64::try_from(n).ok(),
            Self::Nint(n) => i64::try_from(n).ok().map(|n| -1 - n),
            _ => None,
        }
    }
}

/// A map whose entries are sorted by the encoded form of their keys, with
/// no two keys alike.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Map {
    entries: Vec<(Value, Value)>,
}

impl Map {
    /// Builds a map from entries in any order.
    ///
    /// # Errors
    ///
    /// [`EncodeError::DuplicateKey`] if two keys encode alike, or the error
    /// of a key that cannot be encoded.
    pub fn new(entries: Vec<(Value, Value)>) -> Result<Self, EncodeError> {
        let mut keyed = entries
            .into_iter()
            .map(|(k, v)| Ok((encode(&k)?, k, v)))
            .collect::<Result<Vec<_>, EncodeError>>()?;
        keyed.sort_by(|a, b| a.0.cmp(&b.0));
        if keyed.windows(2).any(|w| w[0].0 == w[1].0) {
            return Err(EncodeError::DuplicateKey);
        }
        Ok(Self {
            entries: keyed.into_iter().map(|(_, k, v)| (k, v)).collect(),
        })
    }

    /// The entries, in canonical order.
    #[must_use]
    pub fn entries(&self) -> &[(Value, Value)] {
        &self.entries
    }

    /// The entries, in canonical order.
    #[must_use]
    pub fn into_entries(self) -> Vec<(Value, Value)> {
        self.entries
    }

    /// The value of `key`, if the map has it.
    #[must_use]
    pub fn get(&self, key: &Value) -> Option<&Value> {
        self.entries.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    /// The number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the map has no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// A value has no canonical encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncodeError {
    /// A text string is not in Normalization Form C.
    NotNfc,
    /// Arrays and maps nest deeper than [`MAX_DEPTH`].
    TooDeep,
    /// Two keys of one map encode alike.
    DuplicateKey,
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotNfc => "a text string is not in Unicode Normalization Form C",
            Self::TooDeep => "arrays and maps nest too deep",
            Self::DuplicateKey => "a map has two equal keys",
        })
    }
}

impl std::error::Error for EncodeError {}

/// Writes the canonical encoding of `value`.
///
/// # Errors
///
/// [`EncodeError`] if a text string is not NFC, or the value nests deeper
/// than [`MAX_DEPTH`].
pub fn encode(value: &Value) -> Result<Vec<u8>, EncodeError> {
    let mut out = Vec::new();
    write(&mut out, value, 0)?;
    Ok(out)
}

fn write(out: &mut Vec<u8>, value: &Value, depth: usize) -> Result<(), EncodeError> {
    match value {
        Value::Uint(n) => head(out, 0, *n),
        Value::Nint(n) => head(out, 1, *n),
        Value::Bytes(b) => {
            head(out, 2, count(b.len()));
            out.extend_from_slice(b);
        }
        Value::Text(s) => {
            if !is_nfc(s) {
                return Err(EncodeError::NotNfc);
            }
            head(out, 3, count(s.len()));
            out.extend_from_slice(s.as_bytes());
        }
        Value::Array(items) => {
            let depth = deeper(depth).ok_or(EncodeError::TooDeep)?;
            head(out, 4, count(items.len()));
            for item in items {
                write(out, item, depth)?;
            }
        }
        Value::Map(map) => {
            let depth = deeper(depth).ok_or(EncodeError::TooDeep)?;
            head(out, 5, count(map.len()));
            for (k, v) in &map.entries {
                write(out, k, depth)?;
                write(out, v, depth)?;
            }
        }
        Value::Bool(false) => out.push(0xf4),
        Value::Bool(true) => out.push(0xf5),
        Value::Null => out.push(0xf6),
    }
    Ok(())
}

/// A length as a CBOR argument. `usize` is at most 64 bits on every
/// supported target.
fn count(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

fn deeper(depth: usize) -> Option<usize> {
    let depth = depth + 1;
    (depth <= MAX_DEPTH).then_some(depth)
}

/// Writes an initial byte and its argument in the shortest form.
fn head(out: &mut Vec<u8>, major: u8, arg: u64) {
    let m = major << 5;
    if let Ok(b) = u8::try_from(arg) {
        if b < 24 {
            out.push(m | b);
        } else {
            out.extend_from_slice(&[m | 24, b]);
        }
    } else if let Ok(h) = u16::try_from(arg) {
        out.push(m | 25);
        out.extend_from_slice(&h.to_be_bytes());
    } else if let Ok(w) = u32::try_from(arg) {
        out.push(m | 26);
        out.extend_from_slice(&w.to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend_from_slice(&arg.to_be_bytes());
    }
}

/// Bounds on what [`decode_with_limits`] reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// The largest input, in bytes.
    pub max_bytes: usize,
    /// The deepest nesting of arrays and maps, at most [`MAX_DEPTH`].
    pub max_depth: usize,
    /// The most data items, counting every array, map, key and value.
    pub max_items: usize,
}

impl Limits {
    /// 64 MiB (#43's default bundle limit), [`MAX_DEPTH`] and 4 Mi items.
    pub const DEFAULT: Self = Self {
        max_bytes: 64 << 20,
        max_depth: MAX_DEPTH,
        max_items: 4 << 20,
    };
}

impl Default for Limits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Why an input was rejected, and where.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodeError {
    /// The offset of the data item at fault, in bytes.
    pub offset: usize,
    /// What is wrong with it.
    pub kind: DecodeErrorKind,
}

/// What is wrong with an input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeErrorKind {
    /// The input is larger than [`Limits::max_bytes`].
    TooLarge,
    /// The input ends inside a data item, or a length is longer than what
    /// remains.
    Truncated,
    /// Bytes follow the data item.
    TrailingBytes,
    /// An integer, length or count is not in its shortest form.
    NonCanonical,
    /// An indefinite length, or a break code.
    Indefinite,
    /// Additional information 28 to 30, which RFC 8949 reserves.
    Reserved,
    /// A floating-point number.
    Float,
    /// A tag.
    Tag,
    /// A simple value other than `false`, `true` and `null`.
    Simple,
    /// A text string is not valid UTF-8.
    InvalidUtf8,
    /// A text string is not in Normalization Form C.
    NotNfc,
    /// A map key equals the one before it.
    DuplicateKey,
    /// A map key sorts before the one before it.
    UnsortedKeys,
    /// Arrays and maps nest deeper than [`Limits::max_depth`].
    TooDeep,
    /// More data items than [`Limits::max_items`].
    TooManyItems,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let what = match self.kind {
            DecodeErrorKind::TooLarge => "the input is too large",
            DecodeErrorKind::Truncated => "the input ends inside a data item",
            DecodeErrorKind::TrailingBytes => "bytes follow the data item",
            DecodeErrorKind::NonCanonical => "a number is not in its shortest form",
            DecodeErrorKind::Indefinite => "an indefinite length is not allowed",
            DecodeErrorKind::Reserved => "reserved additional information",
            DecodeErrorKind::Float => "floating point is not allowed",
            DecodeErrorKind::Tag => "tags are not allowed",
            DecodeErrorKind::Simple => "only the simple values false, true and null are allowed",
            DecodeErrorKind::InvalidUtf8 => "a text string is not valid UTF-8",
            DecodeErrorKind::NotNfc => "a text string is not in Unicode Normalization Form C",
            DecodeErrorKind::DuplicateKey => "a map key is repeated",
            DecodeErrorKind::UnsortedKeys => "map keys are not in canonical order",
            DecodeErrorKind::TooDeep => "arrays and maps nest too deep",
            DecodeErrorKind::TooManyItems => "too many data items",
        };
        write!(f, "{what} (at byte {})", self.offset)
    }
}

impl std::error::Error for DecodeError {}

/// Reads one canonical data item that fills `bytes`, within
/// [`Limits::DEFAULT`].
///
/// # Errors
///
/// [`DecodeError`] for any input that is not the canonical encoding of a
/// value, or that exceeds the limits.
pub fn decode(bytes: &[u8]) -> Result<Value, DecodeError> {
    decode_with_limits(bytes, &Limits::DEFAULT)
}

/// Reads one canonical data item that fills `bytes`, within `limits`.
///
/// # Errors
///
/// As [`decode`].
pub fn decode_with_limits(bytes: &[u8], limits: &Limits) -> Result<Value, DecodeError> {
    let (value, used) = decode_prefix(bytes, limits)?;
    if used == bytes.len() {
        Ok(value)
    } else {
        Err(DecodeError {
            offset: used,
            kind: DecodeErrorKind::TrailingBytes,
        })
    }
}

/// Reads the canonical data item at the start of `bytes`, and returns it
/// with the number of bytes it took. Nothing after it is read.
///
/// # Errors
///
/// As [`decode`], except that bytes after the item are not an error.
pub fn decode_prefix(bytes: &[u8], limits: &Limits) -> Result<(Value, usize), DecodeError> {
    if bytes.len() > limits.max_bytes {
        return Err(DecodeError {
            offset: 0,
            kind: DecodeErrorKind::TooLarge,
        });
    }
    let mut reader = Reader {
        bytes,
        pos: 0,
        items: 0,
        limits,
    };
    let value = reader.value(0)?;
    Ok((value, reader.pos))
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
    items: usize,
    limits: &'a Limits,
}

const fn fail<T>(offset: usize, kind: DecodeErrorKind) -> Result<T, DecodeError> {
    Err(DecodeError { offset, kind })
}

impl<'a> Reader<'a> {
    fn remaining(&self) -> usize {
        self.bytes.len() - self.pos
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        if n > self.remaining() {
            return fail(self.pos, DecodeErrorKind::Truncated);
        }
        let out = &self.bytes[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        let mut out = [0; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    /// The argument of the item that starts at `start`, which must be in
    /// its shortest form.
    fn argument(&mut self, start: usize, info: u8) -> Result<u64, DecodeError> {
        let (n, min) = match info {
            0..=23 => return Ok(u64::from(info)),
            24 => (u64::from(self.array::<1>()?[0]), 24),
            25 => (u64::from(u16::from_be_bytes(self.array()?)), 0x100),
            26 => (u64::from(u32::from_be_bytes(self.array()?)), 0x1_0000),
            27 => (u64::from_be_bytes(self.array()?), 0x1_0000_0000),
            31 => return fail(start, DecodeErrorKind::Indefinite),
            _ => return fail(start, DecodeErrorKind::Reserved),
        };
        if n < min {
            fail(start, DecodeErrorKind::NonCanonical)
        } else {
            Ok(n)
        }
    }

    /// A length or count whose items take at least `unit` bytes each, so it
    /// can be checked against what remains before anything is allocated.
    fn length(&mut self, start: usize, info: u8, unit: usize) -> Result<usize, DecodeError> {
        let n = self.argument(start, info)?;
        match usize::try_from(n) {
            Ok(n) if n.checked_mul(unit).is_some_and(|b| b <= self.remaining()) => Ok(n),
            _ => fail(start, DecodeErrorKind::Truncated),
        }
    }

    fn deeper(&self, start: usize, depth: usize) -> Result<usize, DecodeError> {
        let depth = depth + 1;
        if depth > self.limits.max_depth.min(MAX_DEPTH) {
            fail(start, DecodeErrorKind::TooDeep)
        } else {
            Ok(depth)
        }
    }

    fn value(&mut self, depth: usize) -> Result<Value, DecodeError> {
        let start = self.pos;
        let Some(&initial) = self.bytes.get(start) else {
            return fail(start, DecodeErrorKind::Truncated);
        };
        self.pos += 1;
        self.items += 1;
        if self.items > self.limits.max_items {
            return fail(start, DecodeErrorKind::TooManyItems);
        }
        let (major, info) = (initial >> 5, initial & 0x1f);
        Ok(match major {
            0 => Value::Uint(self.argument(start, info)?),
            1 => Value::Nint(self.argument(start, info)?),
            2 => {
                let n = self.length(start, info, 1)?;
                Value::Bytes(self.take(n)?.to_vec())
            }
            3 => {
                let n = self.length(start, info, 1)?;
                let Ok(text) = core::str::from_utf8(self.take(n)?) else {
                    return fail(start, DecodeErrorKind::InvalidUtf8);
                };
                if !is_nfc(text) {
                    return fail(start, DecodeErrorKind::NotNfc);
                }
                Value::Text(text.to_owned())
            }
            4 => {
                let depth = self.deeper(start, depth)?;
                let n = self.length(start, info, 1)?;
                // The count is bounded by the input, not by memory: grow as
                // items arrive.
                let mut items = Vec::with_capacity(n.min(1024));
                for _ in 0..n {
                    items.push(self.value(depth)?);
                }
                Value::Array(items)
            }
            5 => {
                let depth = self.deeper(start, depth)?;
                let n = self.length(start, info, 2)?;
                let mut entries = Vec::with_capacity(n.min(1024));
                let mut previous: Option<(usize, usize)> = None;
                for _ in 0..n {
                    let key_start = self.pos;
                    let key = self.value(depth)?;
                    let key_end = self.pos;
                    if let Some((a, b)) = previous {
                        match self.bytes[a..b].cmp(&self.bytes[key_start..key_end]) {
                            Ordering::Less => {}
                            Ordering::Equal => {
                                return fail(key_start, DecodeErrorKind::DuplicateKey);
                            }
                            Ordering::Greater => {
                                return fail(key_start, DecodeErrorKind::UnsortedKeys);
                            }
                        }
                    }
                    previous = Some((key_start, key_end));
                    let value = self.value(depth)?;
                    entries.push((key, value));
                }
                Value::Map(Map { entries })
            }
            6 => return fail(start, DecodeErrorKind::Tag),
            _ => match info {
                20 => Value::Bool(false),
                21 => Value::Bool(true),
                22 => Value::Null,
                25..=27 => return fail(start, DecodeErrorKind::Float),
                28..=30 => return fail(start, DecodeErrorKind::Reserved),
                31 => return fail(start, DecodeErrorKind::Indefinite),
                _ => return fail(start, DecodeErrorKind::Simple),
            },
        })
    }
}

#[cfg(test)]
mod tests;
