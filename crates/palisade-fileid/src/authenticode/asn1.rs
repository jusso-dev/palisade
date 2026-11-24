//! A strict, zero-copy DER reader for the Authenticode structures.
//!
//! Every ASN.1 byte the signature code reads goes through this module, so it
//! is the one place to audit. The reader:
//!
//! - accepts **DER only**: indefinite lengths (BER), non-minimal length
//!   encodings and lengths of more than four octets are rejected with a typed
//!   [`Asn1Error`];
//! - accepts single-octet tags only (tag numbers 0 to 30), which is all that
//!   PKCS#7, X.509 and Authenticode use;
//! - never allocates: every element it returns borrows from the input, and
//!   every length is checked against the bytes actually present before it is
//!   used, so a declared length can never drive an allocation;
//! - never panics: all offset arithmetic is checked.
//!
//! Offsets in errors are relative to the start of the buffer the outermost
//! [`Reader`] was created over (plus the `base` given to [`Reader::new`]).

#![forbid(unsafe_code)]

use std::fmt;

/// Universal tags used by the signature code.
pub(crate) mod tag {
    pub const BOOLEAN: u8 = 0x01;
    pub const INTEGER: u8 = 0x02;
    pub const BIT_STRING: u8 = 0x03;
    pub const OCTET_STRING: u8 = 0x04;
    pub const NULL: u8 = 0x05;
    pub const OID: u8 = 0x06;
    pub const UTC_TIME: u8 = 0x17;
    pub const GENERALIZED_TIME: u8 = 0x18;
    pub const SEQUENCE: u8 = 0x30;
    pub const SET: u8 = 0x31;

    /// A context-specific, constructed tag: `[n]` EXPLICIT, or IMPLICIT over
    /// a constructed type.
    pub const fn context_cons(n: u8) -> u8 {
        0xa0 | n
    }

    /// A context-specific, primitive tag: `[n]` IMPLICIT over a primitive
    /// type.
    pub const fn context_prim(n: u8) -> u8 {
        0x80 | n
    }
}

/// What was wrong with a DER encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Asn1ErrorKind {
    /// An element's header or content runs past the end of its container.
    Truncated,
    /// A BER indefinite length (`0x80`). DER forbids it.
    IndefiniteLength,
    /// A length in long form that fits the short form, or with a leading
    /// zero octet. DER forbids both.
    NonMinimalLength,
    /// A length of more than four octets, or the reserved `0xff` form.
    LengthTooLarge,
    /// A multi-octet (high) tag number. Nothing Authenticode uses needs one.
    HighTagNumber,
    /// Constructed elements nested more than 64 levels deep inside an
    /// element that is only checked, not interpreted.
    TooDeep,
    /// A different element was found where a specific one is required.
    UnexpectedTag {
        /// The tag required.
        expected: u8,
        /// The tag found.
        found: u8,
    },
    /// A required element is missing: its container ended early.
    Missing {
        /// The tag required.
        expected: u8,
    },
    /// Bytes are left over inside a container after its last element.
    TrailingData,
    /// An element's content is not a valid encoding of its type (an empty
    /// integer, a malformed object identifier, an impossible date, and so
    /// on).
    InvalidValue,
}

impl fmt::Display for Asn1ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("element runs past the end of its container"),
            Self::IndefiniteLength => f.write_str("indefinite length (BER) is not DER"),
            Self::NonMinimalLength => f.write_str("length is not minimally encoded"),
            Self::LengthTooLarge => f.write_str("length is too large"),
            Self::HighTagNumber => f.write_str("multi-octet tag numbers are not supported"),
            Self::TooDeep => f.write_str("elements are nested too deeply"),
            Self::UnexpectedTag { expected, found } => {
                write!(f, "expected tag {expected:#04x}, found {found:#04x}")
            }
            Self::Missing { expected } => write!(f, "missing element with tag {expected:#04x}"),
            Self::TrailingData => f.write_str("unexpected data after the last element"),
            Self::InvalidValue => f.write_str("invalid value encoding"),
        }
    }
}

/// A DER decoding error, with the offset of the offending element.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Asn1Error {
    /// What went wrong.
    pub kind: Asn1ErrorKind,
    /// Offset of the element (or of the end of its container), relative to
    /// the start of the signature blob.
    pub offset: usize,
}

impl fmt::Display for Asn1Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} at offset {:#x}", self.kind, self.offset)
    }
}

impl std::error::Error for Asn1Error {}

pub(crate) type Result<T> = std::result::Result<T, Asn1Error>;

pub(crate) const fn err(kind: Asn1ErrorKind, offset: usize) -> Asn1Error {
    Asn1Error { kind, offset }
}

/// One decoded element: its tag, its content bytes and its whole encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Tlv<'a> {
    pub tag: u8,
    /// The content octets (the value), without tag and length.
    pub content: &'a [u8],
    /// The whole encoding: tag, length and content.
    pub raw: &'a [u8],
    /// Offset of the tag octet.
    pub offset: usize,
    /// Offset of the first content octet.
    pub content_offset: usize,
}

impl<'a> Tlv<'a> {
    /// A reader over this element's content.
    pub fn reader(&self) -> Reader<'a> {
        Reader::new(self.content, self.content_offset)
    }

    /// An error of `kind` located at this element.
    pub const fn error(&self, kind: Asn1ErrorKind) -> Asn1Error {
        err(kind, self.offset)
    }

    /// Fails with [`Asn1ErrorKind::UnexpectedTag`] unless the tag is `tag`.
    pub fn expect(self, tag: u8) -> Result<Self> {
        if self.tag == tag {
            Ok(self)
        } else {
            Err(self.error(Asn1ErrorKind::UnexpectedTag {
                expected: tag,
                found: self.tag,
            }))
        }
    }
}

/// A cursor over a sequence of DER elements.
#[derive(Debug, Clone)]
pub(crate) struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
    base: usize,
}

impl<'a> Reader<'a> {
    /// A reader over `data`, whose first byte is at offset `base` for error
    /// reporting.
    pub const fn new(data: &'a [u8], base: usize) -> Self {
        Self { data, pos: 0, base }
    }

    /// The offset of the next element, for error reporting.
    pub const fn offset(&self) -> usize {
        self.base.saturating_add(self.pos)
    }

    /// Whether every element has been read.
    pub const fn is_empty(&self) -> bool {
        self.pos >= self.data.len()
    }

    /// The bytes not read yet.
    pub fn remaining(&self) -> &'a [u8] {
        self.data.get(self.pos..).unwrap_or_default()
    }

    /// The tag of the next element, if any, without consuming it.
    pub fn peek_tag(&self) -> Option<u8> {
        self.data.get(self.pos).copied()
    }

    /// Reads the next element, whatever its tag.
    pub fn read_any(&mut self) -> Result<Tlv<'a>> {
        let start = self.pos;
        let at = self.offset();
        let tag = *self
            .data
            .get(start)
            .ok_or(err(Asn1ErrorKind::Truncated, at))?;
        if tag & 0x1f == 0x1f {
            return Err(err(Asn1ErrorKind::HighTagNumber, at));
        }
        let len_at = start
            .checked_add(1)
            .ok_or(err(Asn1ErrorKind::Truncated, at))?;
        let first = *self
            .data
            .get(len_at)
            .ok_or(err(Asn1ErrorKind::Truncated, at))?;
        let (len, header) = match first {
            0x00..=0x7f => (usize::from(first), 2_usize),
            0x80 => return Err(err(Asn1ErrorKind::IndefiniteLength, at)),
            0xff => return Err(err(Asn1ErrorKind::LengthTooLarge, at)),
            _ => {
                let n = usize::from(first & 0x7f);
                if n > 4 {
                    return Err(err(Asn1ErrorKind::LengthTooLarge, at));
                }
                let octets_at = len_at
                    .checked_add(1)
                    .ok_or(err(Asn1ErrorKind::Truncated, at))?;
                let octets = octets_at
                    .checked_add(n)
                    .and_then(|end| self.data.get(octets_at..end))
                    .ok_or(err(Asn1ErrorKind::Truncated, at))?;
                if octets.first() == Some(&0) {
                    return Err(err(Asn1ErrorKind::NonMinimalLength, at));
                }
                let value = octets
                    .iter()
                    .fold(0_u64, |acc, b| (acc << 8) | u64::from(*b));
                if value < 0x80 {
                    return Err(err(Asn1ErrorKind::NonMinimalLength, at));
                }
                let len =
                    usize::try_from(value).map_err(|_| err(Asn1ErrorKind::LengthTooLarge, at))?;
                (len, n.saturating_add(2))
            }
        };
        let content_start = start
            .checked_add(header)
            .ok_or(err(Asn1ErrorKind::Truncated, at))?;
        let end = content_start
            .checked_add(len)
            .ok_or(err(Asn1ErrorKind::Truncated, at))?;
        let (Some(content), Some(raw)) =
            (self.data.get(content_start..end), self.data.get(start..end))
        else {
            return Err(err(Asn1ErrorKind::Truncated, at));
        };
        self.pos = end;
        Ok(Tlv {
            tag,
            content,
            raw,
            offset: at,
            content_offset: self.base.saturating_add(content_start),
        })
    }

    /// Reads the next element, which must have tag `tag`.
    pub fn read(&mut self, tag: u8) -> Result<Tlv<'a>> {
        if self.is_empty() {
            return Err(err(Asn1ErrorKind::Missing { expected: tag }, self.offset()));
        }
        self.read_any()?.expect(tag)
    }

    /// Reads the next element if it has tag `tag`.
    pub fn read_optional(&mut self, tag: u8) -> Result<Option<Tlv<'a>>> {
        if self.peek_tag() == Some(tag) {
            self.read_any().map(Some)
        } else {
            Ok(None)
        }
    }

    /// Fails with [`Asn1ErrorKind::TrailingData`] if anything is left.
    pub fn finish(&self) -> Result<()> {
        if self.is_empty() {
            Ok(())
        } else {
            Err(err(Asn1ErrorKind::TrailingData, self.offset()))
        }
    }
}

/// Reads exactly one element from `data` with tag `tag`, with nothing after
/// it.
pub(crate) fn single(data: &[u8], base: usize, tag: u8) -> Result<Tlv<'_>> {
    let mut reader = Reader::new(data, base);
    let tlv = reader.read(tag)?;
    reader.finish()?;
    Ok(tlv)
}

/// The content of an OBJECT IDENTIFIER, checked to be well formed: non-empty,
/// with no padded (`0x80`-led) arcs and no unterminated final arc.
pub(crate) fn oid_bytes<'a>(tlv: &Tlv<'a>) -> Result<&'a [u8]> {
    let content = tlv.expect(tag::OID)?.content;
    let invalid = tlv.error(Asn1ErrorKind::InvalidValue);
    match content.last() {
        Some(last) if last & 0x80 == 0 => {}
        _ => return Err(invalid),
    }
    let mut arc_start = true;
    for byte in content {
        if arc_start && *byte == 0x80 {
            return Err(invalid);
        }
        arc_start = byte & 0x80 == 0;
    }
    Ok(content)
}

/// Reads an OBJECT IDENTIFIER.
pub(crate) fn read_oid<'a>(reader: &mut Reader<'a>) -> Result<&'a [u8]> {
    let tlv = reader.read(tag::OID)?;
    oid_bytes(&tlv)
}

/// The content of an INTEGER, checked to be non-empty. Serial numbers in
/// real certificates are not always minimally encoded, so that is not
/// enforced; they are compared as encoded.
pub(crate) fn integer_bytes<'a>(tlv: &Tlv<'a>) -> Result<&'a [u8]> {
    let content = tlv.expect(tag::INTEGER)?.content;
    if content.is_empty() {
        return Err(tlv.error(Asn1ErrorKind::InvalidValue));
    }
    Ok(content)
}

/// A small non-negative INTEGER (a version number).
pub(crate) fn read_small_uint(reader: &mut Reader<'_>) -> Result<u32> {
    let tlv = reader.read(tag::INTEGER)?;
    let content = integer_bytes(&tlv)?;
    let invalid = tlv.error(Asn1ErrorKind::InvalidValue);
    if content.len() > 4 || content.first().is_some_and(|b| b & 0x80 != 0) {
        return Err(invalid);
    }
    Ok(content
        .iter()
        .fold(0_u32, |acc, b| (acc << 8) | u32::from(*b)))
}

/// An unsigned big-endian INTEGER with its sign octet removed, and its size
/// in bits. Fails for negative or empty integers.
pub(crate) fn unsigned_integer<'a>(tlv: &Tlv<'a>) -> Result<(&'a [u8], u32)> {
    let content = integer_bytes(tlv)?;
    if content.first().is_some_and(|b| b & 0x80 != 0) {
        return Err(tlv.error(Asn1ErrorKind::InvalidValue));
    }
    let start = content
        .iter()
        .position(|b| *b != 0)
        .unwrap_or(content.len());
    let magnitude = content.get(start..).unwrap_or_default();
    let bits = match magnitude.first() {
        None => 0,
        Some(top) => {
            let bytes = u32::try_from(magnitude.len()).unwrap_or(u32::MAX);
            bytes
                .saturating_sub(1)
                .saturating_mul(8)
                .saturating_add(8 - top.leading_zeros())
        }
    };
    Ok((magnitude, bits))
}

/// The content of a BIT STRING with no unused bits (a key or a signature).
pub(crate) fn bit_string_octets<'a>(tlv: &Tlv<'a>) -> Result<&'a [u8]> {
    let content = tlv.expect(tag::BIT_STRING)?.content;
    match content.split_first() {
        Some((0, rest)) => Ok(rest),
        _ => Err(tlv.error(Asn1ErrorKind::InvalidValue)),
    }
}

/// The first content octet of a BIT STRING of flags (bit 0 is the most
/// significant bit, as ASN.1 numbers them), or 0 when it is empty. The
/// unused bits of the last octet must be zero (X.690 11.2.1).
pub(crate) fn bit_string_flags(tlv: &Tlv<'_>) -> Result<u8> {
    let content = tlv.expect(tag::BIT_STRING)?.content;
    let invalid = tlv.error(Asn1ErrorKind::InvalidValue);
    match content {
        [0, rest @ ..] => Ok(rest.first().copied().unwrap_or(0)),
        [unused @ 1..=7, rest @ ..] => {
            let last = rest.last().ok_or(invalid)?;
            if last & ((1_u8 << unused) - 1) != 0 {
                return Err(invalid);
            }
            Ok(rest.first().copied().unwrap_or(0))
        }
        _ => Err(invalid),
    }
}

/// How deep [`validate`] follows constructed elements.
pub(crate) const MAX_DEPTH: usize = 64;

/// Checks that `tlv`, and every element inside it when it is constructed,
/// is well-formed DER as far as this reader enforces (tags and lengths),
/// without interpreting it. Used for parts of a signature that are kept or
/// skipped rather than decoded. Iterative, with at most [`MAX_DEPTH`]
/// readers on the stack, so hostile nesting cannot exhaust the call stack.
pub(crate) fn validate(tlv: &Tlv<'_>) -> Result<()> {
    let mut stack: Vec<Reader<'_>> = Vec::new();
    if tlv.tag & 0x20 != 0 {
        stack.push(tlv.reader());
    }
    while let Some(top) = stack.last_mut() {
        if top.is_empty() {
            stack.pop();
            continue;
        }
        let child = top.read_any()?;
        if child.tag & 0x20 != 0 {
            if stack.len() >= MAX_DEPTH {
                return Err(child.error(Asn1ErrorKind::TooDeep));
            }
            stack.push(child.reader());
        }
    }
    Ok(())
}

/// The longest text read from a signature, in characters. Longer strings are
/// cut, and the caller records a warning.
pub(crate) const MAX_TEXT_CHARS: usize = 4096;

/// Decoded text, and whether it was cut at [`MAX_TEXT_CHARS`].
pub(crate) struct Text {
    pub text: String,
    pub truncated: bool,
}

/// Decodes a BMPString (UTF-16BE; unpaired surrogates become U+FFFD).
pub(crate) fn bmp_text(content: &[u8], at: usize) -> Result<Text> {
    if content.len() % 2 != 0 {
        return Err(err(Asn1ErrorKind::InvalidValue, at));
    }
    let units = content
        .chunks_exact(2)
        .map(|pair| match pair {
            [hi, lo] => u16::from_be_bytes([*hi, *lo]),
            _ => 0,
        })
        // Text is often written NUL-terminated.
        .take_while(|unit| *unit != 0);
    let mut text = String::new();
    let mut truncated = false;
    for (count, c) in char::decode_utf16(units).enumerate() {
        if count >= MAX_TEXT_CHARS {
            truncated = true;
            break;
        }
        text.push(c.unwrap_or(char::REPLACEMENT_CHARACTER));
    }
    Ok(Text { text, truncated })
}

/// Decodes an IA5String or other single-byte text. Bytes outside ASCII
/// become U+FFFD.
pub(crate) fn ascii_text(content: &[u8]) -> Text {
    let mut text = String::new();
    let mut truncated = false;
    for (count, byte) in content.iter().take_while(|b| **b != 0).enumerate() {
        if count >= MAX_TEXT_CHARS {
            truncated = true;
            break;
        }
        text.push(if byte.is_ascii() {
            char::from(*byte)
        } else {
            char::REPLACEMENT_CHARACTER
        });
    }
    Text { text, truncated }
}

/// A UTCTime or GeneralizedTime, as seconds since the Unix epoch (UTC).
///
/// Accepts the DER forms: `YYMMDDHHMMSSZ` (years 1950 to 2049) and
/// `YYYYMMDDHHMMSS[.fff]Z`. Fractions are dropped.
pub(crate) fn time(tlv: &Tlv<'_>) -> Result<i64> {
    let invalid = tlv.error(Asn1ErrorKind::InvalidValue);
    let text = tlv.content;
    let (year, rest) = match tlv.tag {
        tag::UTC_TIME => {
            let yy = digits(text.get(..2).ok_or(invalid)?).ok_or(invalid)?;
            let year = if yy < 50 { 2000 + yy } else { 1900 + yy };
            (year, text.get(2..).ok_or(invalid)?)
        }
        tag::GENERALIZED_TIME => (
            digits(text.get(..4).ok_or(invalid)?).ok_or(invalid)?,
            text.get(4..).ok_or(invalid)?,
        ),
        found => {
            return Err(tlv.error(Asn1ErrorKind::UnexpectedTag {
                expected: tag::UTC_TIME,
                found,
            }));
        }
    };
    let field = |at: usize| {
        rest.get(at..at.saturating_add(2))
            .and_then(digits)
            .ok_or(invalid)
    };
    let (month, day, hour, minute, second) =
        (field(0)?, field(2)?, field(4)?, field(6)?, field(8)?);
    let tail = rest.get(10..).ok_or(invalid)?;
    let zone_ok = match (tlv.tag, tail) {
        (_, b"Z") => true,
        (tag::GENERALIZED_TIME, [b'.', fraction @ .., b'Z']) => {
            !fraction.is_empty() && fraction.iter().all(u8::is_ascii_digit)
        }
        _ => false,
    };
    if !zone_ok
        || !(1..=12).contains(&month)
        || day == 0
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return Err(invalid);
    }
    let days = days_from_civil(i64::from(year), month, day);
    Ok(days * 86_400 + i64::from(hour * 3600 + minute * 60 + second))
}

/// Parses ASCII decimal digits.
fn digits(text: &[u8]) -> Option<u32> {
    if text.is_empty() || !text.iter().all(u8::is_ascii_digit) {
        return None;
    }
    text.iter().try_fold(0_u32, |acc, d| {
        acc.checked_mul(10)?.checked_add(u32::from(d - b'0'))
    })
}

const fn is_leap(year: u32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

const fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        2 if is_leap(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's
/// `days_from_civil`).
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let m = i64::from(month);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + i64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The DER header (tag and length) for an element of `len` content bytes.
#[cfg(test)]
pub(crate) fn header(tag: u8, len: usize) -> Vec<u8> {
    let mut out = vec![tag];
    if len < 0x80 {
        out.push(u8::try_from(len).unwrap_or(0));
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|b| **b == 0).count();
        let significant = bytes.get(skip..).unwrap_or_default();
        out.push(0x80 | u8::try_from(significant.len()).unwrap_or(0));
        out.extend_from_slice(significant);
    }
    out
}

/// An object identifier from a signature or certificate, kept for reports.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ObjectId(Vec<u8>);

impl ObjectId {
    /// Wraps the content octets of an OBJECT IDENTIFIER.
    pub(crate) fn from_der(content: &[u8]) -> Self {
        Self(content.to_vec())
    }

    /// The content octets, as encoded.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for ObjectId {
    /// Dotted-decimal form, such as `1.2.840.113549.1.7.2`. An arc too large
    /// for 64 bits is shown as `?`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut value: Option<u64> = Some(0);
        let mut first = true;
        for byte in &self.0 {
            value = value
                .and_then(|v| v.checked_mul(128))
                .and_then(|v| v.checked_add(u64::from(byte & 0x7f)));
            if byte & 0x80 != 0 {
                continue;
            }
            match (first, value) {
                (true, Some(v)) => {
                    let (a, b) = match v {
                        0..=39 => (0, v),
                        40..=79 => (1, v - 40),
                        _ => (2, v - 80),
                    };
                    write!(f, "{a}.{b}")?;
                }
                (true, None) => f.write_str("2.?")?,
                (false, Some(v)) => write!(f, ".{v}")?,
                (false, None) => f.write_str(".?")?,
            }
            first = false;
            value = Some(0);
        }
        Ok(())
    }
}

impl fmt::Debug for ObjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ObjectId({self})")
    }
}

/// Object identifiers, as DER content octets.
pub(crate) mod oid {
    /// 1.2.840.113549.1.7.2 `signedData`.
    pub const SIGNED_DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02];
    /// 1.3.6.1.4.1.311.2.1.4 `SPC_INDIRECT_DATA_OBJID`.
    pub const SPC_INDIRECT_DATA: &[u8] =
        &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x04];
    /// 1.3.6.1.4.1.311.2.1.15 `SPC_PE_IMAGE_DATA_OBJID`.
    pub const SPC_PE_IMAGE_DATA: &[u8] =
        &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x0f];
    /// 1.3.6.1.4.1.311.2.1.11 `SPC_STATEMENT_TYPE_OBJID`.
    pub const SPC_STATEMENT_TYPE: &[u8] =
        &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x0b];
    /// 1.3.6.1.4.1.311.2.1.12 `SPC_SP_OPUS_INFO_OBJID`.
    pub const SPC_SP_OPUS_INFO: &[u8] =
        &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x0c];
    /// 1.3.6.1.4.1.311.2.1.21 individual code signing.
    pub const SPC_INDIVIDUAL: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x15];
    /// 1.3.6.1.4.1.311.2.1.22 commercial code signing.
    pub const SPC_COMMERCIAL: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x16];
    /// 1.3.6.1.4.1.311.2.3.1 page hashes, SHA-1 (version 1).
    pub const PAGE_HASHES_V1: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x03, 0x01];
    /// 1.3.6.1.4.1.311.2.3.2 page hashes, SHA-256 (version 2).
    pub const PAGE_HASHES_V2: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x03, 0x02];
    /// 1.3.6.1.4.1.311.2.4.1 `szOID_NESTED_SIGNATURE`.
    pub const NESTED_SIGNATURE: &[u8] =
        &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x04, 0x01];
    /// 1.3.6.1.4.1.311.3.3.1 RFC 3161 timestamp token (unauthenticated
    /// attribute).
    pub const RFC3161_TIMESTAMP: &[u8] =
        &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x03, 0x03, 0x01];
    /// 1.2.840.113549.1.9.3 `contentType`.
    pub const CONTENT_TYPE: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x03];
    /// 1.2.840.113549.1.9.4 `messageDigest`.
    pub const MESSAGE_DIGEST: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04];
    /// 1.2.840.113549.1.9.5 `signingTime`.
    pub const SIGNING_TIME: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x05];
    /// 1.2.840.113549.1.9.6 `counterSignature`.
    pub const COUNTER_SIGNATURE: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x06];

    /// 1.2.840.113549.2.2 MD2.
    pub const MD2: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x02];
    /// 1.2.840.113549.2.5 MD5.
    pub const MD5: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05];
    /// 1.3.14.3.2.26 SHA-1.
    pub const SHA1: &[u8] = &[0x2b, 0x0e, 0x03, 0x02, 0x1a];
    /// 2.16.840.1.101.3.4.2.1 SHA-256.
    pub const SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
    /// 2.16.840.1.101.3.4.2.2 SHA-384.
    pub const SHA384: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02];
    /// 2.16.840.1.101.3.4.2.3 SHA-512.
    pub const SHA512: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03];

    /// 1.2.840.113549.1.1.1 `rsaEncryption`.
    pub const RSA_ENCRYPTION: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
    /// 1.2.840.113549.1.1.2 `md2WithRSAEncryption`.
    pub const MD2_WITH_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x02];
    /// 1.2.840.113549.1.1.4 `md5WithRSAEncryption`.
    pub const MD5_WITH_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x04];
    /// 1.2.840.113549.1.1.5 `sha1WithRSAEncryption`.
    pub const SHA1_WITH_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05];
    /// 1.2.840.113549.1.1.8 `id-mgf1`.
    pub const MGF1: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08];
    /// 1.2.840.113549.1.1.10 `id-RSASSA-PSS`.
    pub const RSASSA_PSS: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a];
    /// 1.2.840.113549.1.1.11 `sha256WithRSAEncryption`.
    pub const SHA256_WITH_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
    /// 1.2.840.113549.1.1.12 `sha384WithRSAEncryption`.
    pub const SHA384_WITH_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c];
    /// 1.2.840.113549.1.1.13 `sha512WithRSAEncryption`.
    pub const SHA512_WITH_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d];

    /// 1.2.840.10045.2.1 `id-ecPublicKey`.
    pub const EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
    /// 1.2.840.10045.4.1 `ecdsa-with-SHA1`.
    pub const ECDSA_WITH_SHA1: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x01];
    /// 1.2.840.10045.4.3.2 `ecdsa-with-SHA256`.
    pub const ECDSA_WITH_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
    /// 1.2.840.10045.4.3.3 `ecdsa-with-SHA384`.
    pub const ECDSA_WITH_SHA384: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03];
    /// 1.2.840.10045.4.3.4 `ecdsa-with-SHA512`.
    pub const ECDSA_WITH_SHA512: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04];
    /// 1.2.840.10045.3.1.7 `prime256v1` (P-256).
    pub const P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
    /// 1.3.132.0.34 `secp384r1` (P-384).
    pub const P384: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];
    /// 1.3.132.0.35 `secp521r1` (P-521).
    pub const P521: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x23];
    /// 1.3.101.112 `id-Ed25519`.
    pub const ED25519: &[u8] = &[0x2b, 0x65, 0x70];
    /// 1.3.101.113 `id-Ed448`.
    pub const ED448: &[u8] = &[0x2b, 0x65, 0x71];

    /// 2.5.29.14 `subjectKeyIdentifier`.
    pub const SUBJECT_KEY_IDENTIFIER: &[u8] = &[0x55, 0x1d, 0x0e];
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_one(data: &[u8]) -> Result<Tlv<'_>> {
        Reader::new(data, 0).read_any()
    }

    #[test]
    fn short_and_long_lengths() {
        let tlv = read_one(&[0x04, 0x02, 0xaa, 0xbb]).unwrap();
        assert_eq!(
            (tlv.tag, tlv.content, tlv.content_offset),
            (0x04, &[0xaa, 0xbb][..], 2)
        );
        let mut long = vec![0x04, 0x81, 0x80];
        long.extend(std::iter::repeat_n(7, 0x80));
        let tlv = read_one(&long).unwrap();
        assert_eq!(tlv.content.len(), 0x80);
        assert_eq!(tlv.raw.len(), long.len());
    }

    #[test]
    fn rejects_ber_and_bad_lengths() {
        let kind = |data: &[u8]| read_one(data).unwrap_err().kind;
        assert_eq!(
            kind(&[0x30, 0x80, 0x00, 0x00]),
            Asn1ErrorKind::IndefiniteLength
        );
        assert_eq!(
            kind(&[0x04, 0x81, 0x05, 1, 2, 3, 4, 5]),
            Asn1ErrorKind::NonMinimalLength
        );
        assert_eq!(
            kind(&[0x04, 0x82, 0x00, 0x90]),
            Asn1ErrorKind::NonMinimalLength
        );
        assert_eq!(
            kind(&[0x04, 0x85, 1, 0, 0, 0, 0]),
            Asn1ErrorKind::LengthTooLarge
        );
        assert_eq!(kind(&[0x04, 0xff]), Asn1ErrorKind::LengthTooLarge);
        assert_eq!(
            kind(&[0x04, 0x84, 0x7f, 0xff, 0xff, 0xff]),
            Asn1ErrorKind::Truncated
        );
        assert_eq!(kind(&[0x04, 0x03, 1]), Asn1ErrorKind::Truncated);
        assert_eq!(kind(&[0x04]), Asn1ErrorKind::Truncated);
        assert_eq!(kind(&[]), Asn1ErrorKind::Truncated);
        assert_eq!(kind(&[0x1f, 0x81, 0x00]), Asn1ErrorKind::HighTagNumber);
    }

    #[test]
    fn expected_tags_and_trailing_data() {
        let mut r = Reader::new(&[0x05, 0x00, 0x02, 0x01, 0x07], 10);
        assert_eq!(
            r.clone().read(tag::INTEGER).unwrap_err(),
            err(
                Asn1ErrorKind::UnexpectedTag {
                    expected: tag::INTEGER,
                    found: tag::NULL
                },
                10
            )
        );
        assert!(r.read_optional(tag::INTEGER).unwrap().is_none());
        r.read(tag::NULL).unwrap();
        assert_eq!(
            r.finish().unwrap_err(),
            err(Asn1ErrorKind::TrailingData, 12)
        );
        assert_eq!(read_small_uint(&mut r).unwrap(), 7);
        r.finish().unwrap();
        assert_eq!(
            r.read(tag::NULL).unwrap_err().kind,
            Asn1ErrorKind::Missing {
                expected: tag::NULL
            }
        );
        assert_eq!(
            single(&[0x05, 0x00, 0x00], 0, tag::NULL).unwrap_err().kind,
            Asn1ErrorKind::TrailingData
        );
    }

    #[test]
    fn object_identifiers() {
        let tlv = read_one(&[0x06, 0x03, 0x2b, 0x65, 0x70]).unwrap();
        let bytes = oid_bytes(&tlv).unwrap();
        assert_eq!(ObjectId::from_der(bytes).to_string(), "1.3.101.112");
        assert_eq!(
            ObjectId::from_der(oid::SIGNED_DATA).to_string(),
            "1.2.840.113549.1.7.2"
        );
        assert_eq!(
            ObjectId::from_der(oid::SHA256).to_string(),
            "2.16.840.1.101.3.4.2.1"
        );
        assert_eq!(
            ObjectId::from_der(oid::NESTED_SIGNATURE).to_string(),
            "1.3.6.1.4.1.311.2.4.1"
        );
        for bad in [
            &[0x06, 0x00][..],
            &[0x06, 0x01, 0x81],
            &[0x06, 0x02, 0x80, 0x01],
        ] {
            let tlv = read_one(bad).unwrap();
            assert_eq!(
                oid_bytes(&tlv).unwrap_err().kind,
                Asn1ErrorKind::InvalidValue
            );
        }
        // An arc over 64 bits still displays.
        let huge = ObjectId::from_der(&[
            0x2b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
        ]);
        assert_eq!(huge.to_string(), "1.3.?");
    }

    #[test]
    fn every_known_oid_is_well_formed() {
        use oid::*;
        for o in [
            SIGNED_DATA,
            SPC_INDIRECT_DATA,
            SPC_PE_IMAGE_DATA,
            SPC_STATEMENT_TYPE,
            SPC_SP_OPUS_INFO,
            SPC_INDIVIDUAL,
            SPC_COMMERCIAL,
            PAGE_HASHES_V1,
            PAGE_HASHES_V2,
            NESTED_SIGNATURE,
            RFC3161_TIMESTAMP,
            CONTENT_TYPE,
            MESSAGE_DIGEST,
            SIGNING_TIME,
            COUNTER_SIGNATURE,
            MD2,
            MD5,
            SHA1,
            SHA256,
            SHA384,
            SHA512,
            RSA_ENCRYPTION,
            MD2_WITH_RSA,
            MD5_WITH_RSA,
            SHA1_WITH_RSA,
            MGF1,
            RSASSA_PSS,
            SHA256_WITH_RSA,
            SHA384_WITH_RSA,
            SHA512_WITH_RSA,
            EC_PUBLIC_KEY,
            ECDSA_WITH_SHA1,
            ECDSA_WITH_SHA256,
            ECDSA_WITH_SHA384,
            ECDSA_WITH_SHA512,
            P256,
            P384,
            P521,
            ED25519,
            ED448,
            SUBJECT_KEY_IDENTIFIER,
        ] {
            let mut der = header(tag::OID, o.len());
            der.extend_from_slice(o);
            assert!(
                oid_bytes(&read_one(&der).unwrap()).is_ok(),
                "{:?}",
                ObjectId::from_der(o)
            );
        }
        let dotted = |o: &[u8]| ObjectId::from_der(o).to_string();
        assert_eq!(dotted(SPC_PE_IMAGE_DATA), "1.3.6.1.4.1.311.2.1.15");
        assert_eq!(dotted(RFC3161_TIMESTAMP), "1.3.6.1.4.1.311.3.3.1");
        assert_eq!(dotted(PAGE_HASHES_V2), "1.3.6.1.4.1.311.2.3.2");
        assert_eq!(dotted(ECDSA_WITH_SHA384), "1.2.840.10045.4.3.3");
        assert_eq!(dotted(P521), "1.3.132.0.35");
        assert_eq!(dotted(RSASSA_PSS), "1.2.840.113549.1.1.10");
        assert_eq!(dotted(SUBJECT_KEY_IDENTIFIER), "2.5.29.14");
    }

    #[test]
    fn integers() {
        let tlv = read_one(&[0x02, 0x03, 0x00, 0x80, 0x01]).unwrap();
        assert_eq!(unsigned_integer(&tlv).unwrap(), (&[0x80, 0x01][..], 16));
        let negative = read_one(&[0x02, 0x01, 0x80]).unwrap();
        assert!(unsigned_integer(&negative).is_err());
        let empty = read_one(&[0x02, 0x00]).unwrap();
        assert!(integer_bytes(&empty).is_err());
        assert_eq!(
            read_small_uint(&mut Reader::new(&[0x02, 0x01, 0x03], 0)).unwrap(),
            3
        );
        assert!(read_small_uint(&mut Reader::new(&[0x02, 0x05, 1, 0, 0, 0, 0], 0)).is_err());
    }

    #[test]
    fn validation_walks_nested_elements() {
        let ok = read_one(&[0x30, 0x06, 0x31, 0x02, 0x05, 0x00, 0x04, 0x00]).unwrap();
        validate(&ok).unwrap();
        // A truncated element two levels down.
        let bad = read_one(&[0x30, 0x04, 0x31, 0x02, 0x04, 0x05]).unwrap();
        assert_eq!(validate(&bad).unwrap_err().kind, Asn1ErrorKind::Truncated);
        // A BER indefinite length inside a primitive-looking wrapper.
        let ber = read_one(&[0xa0, 0x04, 0x30, 0x80, 0x00, 0x00]).unwrap();
        assert_eq!(
            validate(&ber).unwrap_err().kind,
            Asn1ErrorKind::IndefiniteLength
        );
        // Primitive elements are not looked inside.
        validate(&read_one(&[0x04, 0x02, 0x30, 0x80]).unwrap()).unwrap();
        // Nesting beyond the limit.
        let mut deep = vec![0x05, 0x00];
        for _ in 0..=MAX_DEPTH {
            deep = [header(tag::SEQUENCE, deep.len()), deep].concat();
        }
        assert_eq!(
            validate(&read_one(&deep).unwrap()).unwrap_err().kind,
            Asn1ErrorKind::TooDeep
        );
    }

    #[test]
    fn bit_strings() {
        let key = read_one(&[0x03, 0x03, 0x00, 0xab, 0xcd]).unwrap();
        assert_eq!(bit_string_octets(&key).unwrap(), &[0xab, 0xcd]);
        let padded = read_one(&[0x03, 0x02, 0x01, 0xfe]).unwrap();
        assert!(bit_string_octets(&padded).is_err());
        assert_eq!(bit_string_flags(&padded).unwrap(), 0xfe);
        // Unused bits must be zero.
        let dirty = read_one(&[0x03, 0x02, 0x07, 0xff]).unwrap();
        assert!(bit_string_flags(&dirty).is_err());
        let clean = read_one(&[0x03, 0x02, 0x07, 0x80]).unwrap();
        assert_eq!(bit_string_flags(&clean).unwrap(), 0x80);
        let empty = read_one(&[0x03, 0x01, 0x00]).unwrap();
        assert_eq!(bit_string_flags(&empty).unwrap(), 0);
        let bad = read_one(&[0x03, 0x01, 0x03]).unwrap();
        assert!(bit_string_flags(&bad).is_err());
    }

    #[test]
    fn times() {
        let t = |tag: u8, text: &str| {
            let mut der = header(tag, text.len());
            der.extend_from_slice(text.as_bytes());
            time(&read_one(&der).unwrap())
        };
        assert_eq!(t(tag::UTC_TIME, "231114221320Z").unwrap(), 1_700_000_000);
        assert_eq!(
            t(tag::GENERALIZED_TIME, "20231114221320Z").unwrap(),
            1_700_000_000
        );
        assert_eq!(
            t(tag::GENERALIZED_TIME, "20231114221320.5Z").unwrap(),
            1_700_000_000
        );
        assert_eq!(t(tag::UTC_TIME, "700101000000Z").unwrap(), 0);
        assert_eq!(t(tag::UTC_TIME, "491231235959Z").unwrap(), 2_524_607_999);
        assert_eq!(
            t(tag::GENERALIZED_TIME, "19000301000000Z").unwrap(),
            -2_203_891_200
        );
        assert_eq!(
            t(tag::GENERALIZED_TIME, "20240229000000Z").unwrap(),
            1_709_164_800
        );
        for bad in [
            "231114221320",
            "2311142213Z",
            "231314221320Z",
            "230230000000Z",
            "231114241320Z",
            "23111422132aZ",
            "231114221320+0100",
            "231114221320.5Z",
        ] {
            assert!(t(tag::UTC_TIME, bad).is_err(), "{bad}");
        }
        assert!(t(tag::GENERALIZED_TIME, "20230229000000Z").is_err());
        assert!(t(tag::GENERALIZED_TIME, "20231114221320.Z").is_err());
        assert!(t(tag::OCTET_STRING, "231114221320Z").is_err());
    }

    #[test]
    fn text() {
        let bmp: Vec<u8> = "Pal\u{e9}"
            .encode_utf16()
            .flat_map(u16::to_be_bytes)
            .collect();
        assert_eq!(bmp_text(&bmp, 0).unwrap().text, "Pal\u{e9}");
        assert!(bmp_text(&[0x00], 0).is_err());
        assert_eq!(
            bmp_text(&[0xd8, 0x00, 0x00, 0x41], 0).unwrap().text,
            "\u{FFFD}A"
        );
        assert_eq!(
            bmp_text(&[0x00, 0x41, 0x00, 0x00, 0x00, 0x42], 0)
                .unwrap()
                .text,
            "A"
        );
        assert_eq!(ascii_text(b"ab\xffc\0d").text, "ab\u{FFFD}c");
        let long = vec![b'a'; MAX_TEXT_CHARS + 5];
        let cut = ascii_text(&long);
        assert!(cut.truncated && cut.text.len() == MAX_TEXT_CHARS);
        let long_bmp: Vec<u8> = std::iter::repeat_n([0x00, 0x61], MAX_TEXT_CHARS + 1)
            .flatten()
            .collect();
        assert!(bmp_text(&long_bmp, 0).unwrap().truncated);
    }

    #[test]
    fn headers_round_trip() {
        for len in [
            0_usize, 1, 0x7f, 0x80, 0xff, 0x100, 0xffff, 0x1_0000, 0x100_0000,
        ] {
            let mut der = header(tag::OCTET_STRING, len);
            der.resize(der.len() + len, 0);
            assert_eq!(read_one(&der).unwrap().content.len(), len);
        }
    }
}
