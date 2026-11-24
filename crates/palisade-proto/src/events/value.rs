//! Value types of the event schema.
//!
//! Every type here has exactly one accepted form, and deserialising checks it,
//! so an [`Event`](super::Event) cannot hold an out-of-range value. Text and
//! hex forms are strict: readers never normalise case or trim input. The
//! mapping engine ([`crate::mapping`]) does the normalising of OS-native
//! values before they reach these types.

use std::collections::BTreeMap;
use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use palisade_core::Uuid7;

/// A value is not in its canonical form or is out of range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValueError(&'static str);

impl ValueError {
    pub(crate) const UNKNOWN_EVENT_TYPE: Self = Self("unknown event type");

    /// What was expected.
    #[must_use]
    pub const fn message(&self) -> &'static str {
        self.0
    }
}

impl fmt::Display for ValueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for ValueError {}

/// Reads a value from its text form through `FromStr`. Works for borrowed
/// and owned strings alike.
pub(crate) fn deserialize_from_str<'de, D, T>(
    deserializer: D,
    expecting: &'static str,
) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: FromStr<Err = ValueError>,
{
    struct V<T>(&'static str, std::marker::PhantomData<T>);
    impl<T: FromStr<Err = ValueError>> Visitor<'_> for V<T> {
        type Value = T;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(self.0)
        }
        fn visit_str<E: de::Error>(self, v: &str) -> Result<T, E> {
            v.parse().map_err(|e: ValueError| E::custom(e.message()))
        }
    }
    deserializer.deserialize_str(V(expecting, std::marker::PhantomData))
}

/// Reads an optional field that, when present, must hold a value: `null` is
/// rejected. Writers leave unset fields out, so `null` has no meaning, and
/// accepting it would let a document pass the JSON Schema's presence rules
/// in one reader and fail them in another.
pub(crate) fn present<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

/// Implements serde through `Display` and `FromStr`, so the text form has one
/// definition.
macro_rules! string_serde {
    ($ty:ty, $expecting:literal) => {
        impl Serialize for $ty {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.collect_str(self)
            }
        }

        impl<'de> Deserialize<'de> for $ty {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                deserialize_from_str(deserializer, $expecting)
            }
        }
    };
}

// ---------------------------------------------------------------------------
// Bounded text
// ---------------------------------------------------------------------------

/// Non-empty text of at most `MAX` characters (Unicode scalar values, as JSON
/// Schema's `maxLength` counts them).
///
/// Empty text is not a value: a field with nothing to say is left out.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Text<const MAX: usize>(String);

impl<const MAX: usize> Text<MAX> {
    /// Checks the length.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError`] if the text is empty or longer than `MAX`.
    pub fn new(text: impl Into<String>) -> Result<Self, ValueError> {
        let text = text.into();
        if text.is_empty() {
            return Err(ValueError("expected non-empty text"));
        }
        if text.chars().count() > MAX {
            return Err(ValueError("text is too long"));
        }
        Ok(Self(text))
    }

    /// The text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<const MAX: usize> fmt::Display for Text<MAX> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl<const MAX: usize> FromStr for Text<MAX> {
    type Err = ValueError;

    fn from_str(s: &str) -> Result<Self, ValueError> {
        Self::new(s)
    }
}

impl<const MAX: usize> Serialize for Text<MAX> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de, const MAX: usize> Deserialize<'de> for Text<MAX> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct V<const MAX: usize>;
        impl<const MAX: usize> Visitor<'_> for V<MAX> {
            type Value = Text<MAX>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "non-empty text of at most {MAX} characters")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Text<MAX>, E> {
                // A character is at most 4 bytes, so longer input is rejected
                // before it is copied.
                if v.len() > MAX.saturating_mul(4) {
                    return Err(E::custom("text is too long"));
                }
                Text::new(v).map_err(|e| E::custom(e.message()))
            }
        }
        deserializer.deserialize_str(V::<MAX>)
    }
}

impl<const MAX: usize> JsonSchema for Text<MAX> {
    fn inline_schema() -> bool {
        true
    }

    fn schema_name() -> std::borrow::Cow<'static, str> {
        format!("Text{MAX}").into()
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "string",
            "minLength": 1,
            "maxLength": MAX
        })
    }
}

/// A name or short label: at most 256 characters.
pub type Name = Text<256>;
/// A file-system path or a command line: at most 32,767 characters, the
/// longest the OS accepts.
pub type LongText = Text<32_767>;
/// A human-readable event description: at most 1024 characters.
pub type Description = Text<1024>;

// ---------------------------------------------------------------------------
// Bounded list
// ---------------------------------------------------------------------------

/// A list of at most `MAX` items.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BoundedVec<T, const MAX: usize>(Vec<T>);

impl<T, const MAX: usize> BoundedVec<T, MAX> {
    /// Checks the length.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError`] if there are more than `MAX` items.
    pub fn new(items: Vec<T>) -> Result<Self, ValueError> {
        if items.len() > MAX {
            return Err(ValueError("too many items"));
        }
        Ok(Self(items))
    }

    /// The items.
    #[must_use]
    pub fn as_slice(&self) -> &[T] {
        &self.0
    }

    /// Whether the list is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The number of items.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// The items, in order.
    pub fn iter(&self) -> std::slice::Iter<'_, T> {
        self.0.iter()
    }
}

impl<T, const MAX: usize> Default for BoundedVec<T, MAX> {
    fn default() -> Self {
        Self(Vec::new())
    }
}

impl<T: Serialize, const MAX: usize> Serialize for BoundedVec<T, MAX> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de, T: Deserialize<'de>, const MAX: usize> Deserialize<'de> for BoundedVec<T, MAX> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct V<T, const MAX: usize>(std::marker::PhantomData<T>);
        impl<'de, T: Deserialize<'de>, const MAX: usize> Visitor<'de> for V<T, MAX> {
            type Value = BoundedVec<T, MAX>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "a list of at most {MAX} items")
            }
            fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut items = Vec::new();
                while let Some(item) = seq.next_element()? {
                    // Stop as soon as the limit is passed, without reading the rest.
                    if items.len() == MAX {
                        return Err(de::Error::custom(format!("a list of at most {MAX} items")));
                    }
                    items.push(item);
                }
                Ok(BoundedVec(items))
            }
        }
        deserializer.deserialize_seq(V(std::marker::PhantomData))
    }
}

impl<T: JsonSchema, const MAX: usize> JsonSchema for BoundedVec<T, MAX> {
    fn inline_schema() -> bool {
        true
    }

    fn schema_name() -> std::borrow::Cow<'static, str> {
        format!("BoundedVec{MAX}_{}", T::schema_name()).into()
    }

    fn json_schema(generator: &mut SchemaGenerator) -> Schema {
        let items = generator.subschema_for::<T>();
        json_schema!({
            "type": "array",
            "items": items,
            "maxItems": MAX
        })
    }
}

// ---------------------------------------------------------------------------
// Hex digests
// ---------------------------------------------------------------------------

/// Parses lowercase hex into `out`, which must be exactly half as long.
fn parse_hex_into(s: &str, out: &mut [u8]) -> Result<(), ValueError> {
    const ERR: ValueError = ValueError("expected lowercase hexadecimal of the right length");
    if s.len() != out.len().saturating_mul(2) {
        return Err(ERR);
    }
    for (byte, pair) in out.iter_mut().zip(s.as_bytes().chunks_exact(2)) {
        let &[hi, lo] = pair else { return Err(ERR) };
        *byte = (hex_digit(hi).ok_or(ERR)? << 4) | hex_digit(lo).ok_or(ERR)?;
    }
    Ok(())
}

const fn hex_digit(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

fn write_hex(f: &mut fmt::Formatter<'_>, bytes: &[u8]) -> fmt::Result {
    for byte in bytes {
        write!(f, "{byte:02x}")?;
    }
    Ok(())
}

/// A fixed-length digest of `N` bytes, written as `2N` lowercase hex digits.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Hex<const N: usize>([u8; N]);

impl<const N: usize> Hex<N> {
    /// Wraps raw digest bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; N]) -> Self {
        Self(bytes)
    }

    /// The raw digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; N] {
        &self.0
    }
}

impl<const N: usize> FromStr for Hex<N> {
    type Err = ValueError;

    fn from_str(s: &str) -> Result<Self, ValueError> {
        let mut bytes = [0u8; N];
        parse_hex_into(s, &mut bytes)?;
        Ok(Self(bytes))
    }
}

impl<const N: usize> fmt::Display for Hex<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_hex(f, &self.0)
    }
}

impl<const N: usize> fmt::Debug for Hex<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hex({self})")
    }
}

impl<const N: usize> Serialize for Hex<N> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de, const N: usize> Deserialize<'de> for Hex<N> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserialize_from_str(deserializer, "lowercase hexadecimal of the right length")
    }
}

impl<const N: usize> JsonSchema for Hex<N> {
    fn inline_schema() -> bool {
        true
    }

    fn schema_name() -> std::borrow::Cow<'static, str> {
        format!("Hex{N}").into()
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        let pattern = format!("^[0-9a-f]{{{}}}$", N.saturating_mul(2));
        json_schema!({
            "type": "string",
            "pattern": pattern
        })
    }
}

/// A SHA-256 digest.
pub type Sha256Hex = Hex<32>;
/// A SHA-1 digest. Interop only: SHA-1 is not collision resistant (ADR 0008).
pub type Sha1Hex = Hex<20>;
/// An MD5 digest. Interop only: MD5 is not collision resistant (ADR 0008).
pub type Md5Hex = Hex<16>;

/// A digest whose length depends on its source, 1 to 64 bytes, written as
/// lowercase hex. Used for certificate TBS hashes (whose algorithm follows
/// the certificate's signature algorithm) and OS-native policy hashes.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HexBytes(Vec<u8>);

impl HexBytes {
    /// Most bytes.
    pub const MAX: usize = 64;

    /// Wraps raw bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError`] if there are no bytes or more than [`Self::MAX`].
    pub fn new(bytes: &[u8]) -> Result<Self, ValueError> {
        if bytes.is_empty() || bytes.len() > Self::MAX {
            return Err(ValueError("expected 1 to 64 bytes"));
        }
        Ok(Self(bytes.to_vec()))
    }

    /// The raw bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl FromStr for HexBytes {
    type Err = ValueError;

    fn from_str(s: &str) -> Result<Self, ValueError> {
        const ERR: ValueError = ValueError("expected 1 to 64 bytes of lowercase hexadecimal");
        if s.is_empty() || s.len() % 2 != 0 || s.len() > Self::MAX.saturating_mul(2) {
            return Err(ERR);
        }
        let mut bytes = vec![0u8; s.len() / 2];
        parse_hex_into(s, &mut bytes).map_err(|_| ERR)?;
        Ok(Self(bytes))
    }
}

impl fmt::Display for HexBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_hex(f, &self.0)
    }
}

impl fmt::Debug for HexBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HexBytes({self})")
    }
}

string_serde!(HexBytes, "1 to 64 bytes of lowercase hexadecimal");

impl JsonSchema for HexBytes {
    fn inline_schema() -> bool {
        true
    }

    fn schema_name() -> std::borrow::Cow<'static, str> {
        "HexBytes".into()
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "string",
            "pattern": "^([0-9a-f]{2}){1,64}$"
        })
    }
}

// ---------------------------------------------------------------------------
// GUID
// ---------------------------------------------------------------------------

/// A GUID of any version, as OS-native sources use them (policy GUIDs, rule
/// IDs, correlation activity IDs).
///
/// The only accepted text form is 36 characters of lowercase hex with
/// hyphens at the standard positions, without braces. Palisade's own object
/// IDs use [`Uuid7`] instead, which also checks the version.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Guid([u8; 16]);

impl Guid {
    /// Wraps 16 bytes, in the order of the text form.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// The 16 bytes, in the order of the text form.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl FromStr for Guid {
    type Err = ValueError;

    fn from_str(s: &str) -> Result<Self, ValueError> {
        const ERR: ValueError = ValueError("expected a GUID in canonical lowercase form");
        if s.len() != 36 {
            return Err(ERR);
        }
        let parts: Vec<&str> = s.split('-').collect();
        let &[a, b, c, d, e] = parts.as_slice() else {
            return Err(ERR);
        };
        if [a.len(), b.len(), c.len(), d.len(), e.len()] != [8, 4, 4, 4, 12] {
            return Err(ERR);
        }
        let mut bytes = [0u8; 16];
        let hex: String = [a, b, c, d, e].concat();
        parse_hex_into(&hex, &mut bytes).map_err(|_| ERR)?;
        Ok(Self(bytes))
    }
}

impl fmt::Display for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, byte) in self.0.iter().enumerate() {
            if matches!(i, 4 | 6 | 8 | 10) {
                f.write_str("-")?;
            }
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Guid({self})")
    }
}

string_serde!(Guid, "a GUID in canonical lowercase form");

impl JsonSchema for Guid {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "Guid".into()
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "description": "A GUID in canonical lowercase form, without braces.",
            "type": "string",
            "pattern": "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
        })
    }
}

// ---------------------------------------------------------------------------
// Security identifier
// ---------------------------------------------------------------------------

/// A Windows security identifier in its canonical text form, for example
/// `S-1-5-21-1004336348-1177238915-682003330-512`.
///
/// The canonical form is the one the OS and [`palisade_fileid::fsctx::sid::Sid`]
/// write: an uppercase `S-1-`, the identifier authority in decimal when it
/// is below 2^32 and otherwise `0x` and 12 uppercase hex digits, then 0 to
/// 15 sub-authorities in decimal, all without leading zeros. Only that form
/// is accepted, so each SID has one spelling. Use [`Sid::normalise`] to read
/// other spellings.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Sid(String);

impl Sid {
    /// The text form.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Reads any spelling the file-identity parser accepts (a lowercase
    /// `s`, a hex authority of any width or case) and returns the canonical
    /// form.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError`] if the text is not a SID.
    pub fn normalise(text: &str) -> Result<Self, ValueError> {
        text.parse::<palisade_fileid::fsctx::sid::Sid>()
            .map(Self::from)
            .map_err(|_| SID_ERROR)
    }
}

const SID_ERROR: ValueError = ValueError("expected a security identifier such as S-1-5-18");

impl From<palisade_fileid::fsctx::sid::Sid> for Sid {
    fn from(sid: palisade_fileid::fsctx::sid::Sid) -> Self {
        Self(sid.to_string())
    }
}

impl FromStr for Sid {
    type Err = ValueError;

    fn from_str(s: &str) -> Result<Self, ValueError> {
        let sid = Self::normalise(s)?;
        if sid.0 != s {
            return Err(SID_ERROR);
        }
        Ok(sid)
    }
}

impl fmt::Display for Sid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for Sid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sid({})", self.0)
    }
}

string_serde!(Sid, "a security identifier such as S-1-5-18");

impl JsonSchema for Sid {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "Sid".into()
    }

    /// The pattern checks the shape and digit counts. The bounds (a decimal
    /// authority below 2^32, a hex one from 2^32 and below 2^48, and
    /// sub-authorities below 2^32) are checked only by the reader.
    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "description": "A Windows security identifier in its canonical text form.",
            "type": "string",
            "pattern": "^S-1-(0|[1-9][0-9]{0,9}|0x[0-9A-F]{12})(-(0|[1-9][0-9]{0,9})){0,15}$"
        })
    }
}

// ---------------------------------------------------------------------------
// Timestamp
// ---------------------------------------------------------------------------

/// A point in time, in UTC, with microsecond precision.
///
/// The text form is RFC 3339 with exactly six fractional digits and `Z`, for
/// example `2026-11-24T03:15:22.123456Z`, so every instant has one spelling
/// and timestamps sort as text. Years 0001 to 9999 are accepted. Leap seconds
/// (`:60`) are not representable and are rejected.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(i64);

const MICROS_PER_SECOND: i64 = 1_000_000;
const SECONDS_PER_DAY: i64 = 86_400;
/// 0001-01-01T00:00:00Z, in seconds from the Unix epoch.
const MIN_SECONDS: i64 = -62_135_596_800;
/// 9999-12-31T23:59:59Z, in seconds from the Unix epoch.
const MAX_SECONDS: i64 = 253_402_300_799;

impl Timestamp {
    /// The earliest representable instant, 0001-01-01T00:00:00.000000Z.
    pub const MIN: Self = Self(MIN_SECONDS * MICROS_PER_SECOND);
    /// The latest representable instant, 9999-12-31T23:59:59.999999Z.
    pub const MAX: Self = Self(MAX_SECONDS * MICROS_PER_SECOND + (MICROS_PER_SECOND - 1));

    /// Builds a timestamp from microseconds since 1970-01-01T00:00:00Z.
    /// Returns `None` outside years 0001 to 9999.
    #[must_use]
    pub const fn from_unix_micros(micros: i64) -> Option<Self> {
        if micros < Self::MIN.0 || micros > Self::MAX.0 {
            None
        } else {
            Some(Self(micros))
        }
    }

    /// Microseconds since 1970-01-01T00:00:00Z.
    #[must_use]
    pub const fn unix_micros(self) -> i64 {
        self.0
    }

    /// Reads an RFC 3339 UTC timestamp as OS event logs write it: `Z` as the
    /// offset, and 0 to 9 fractional digits. Digits after the sixth are
    /// truncated (not rounded), so `.1234567Z` becomes `.123456Z`.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError`] for any other form, an invalid date or time,
    /// or a year outside 0001 to 9999.
    pub fn parse_utc(s: &str) -> Result<Self, ValueError> {
        const ERR: ValueError = ValueError("expected an RFC 3339 UTC timestamp");
        let body = s.strip_suffix('Z').ok_or(ERR)?;
        let (main, fraction) = match body.split_once('.') {
            Some((main, fraction)) => {
                if fraction.is_empty() || fraction.len() > 9 {
                    return Err(ERR);
                }
                (main, fraction)
            }
            None => (body, ""),
        };
        if !fraction.bytes().all(|b| b.is_ascii_digit()) {
            return Err(ERR);
        }
        let seconds = parse_date_time(main).ok_or(ERR)?;
        let mut micros: i64 = 0;
        let mut place: i64 = 100_000;
        for digit in fraction.bytes().take(6) {
            micros += i64::from(digit - b'0') * place;
            place /= 10;
        }
        Self::from_unix_micros(seconds * MICROS_PER_SECOND + micros).ok_or(ERR)
    }
}

/// Days from 1970-01-01 to the given civil date (proleptic Gregorian).
/// Howard Hinnant's `days_from_civil`.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The civil date of a day count from 1970-01-01. Howard Hinnant's
/// `civil_from_days`.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

const fn is_leap(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

const fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        2 if is_leap(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Parses `YYYY-MM-DDTHH:MM:SS` into seconds from the Unix epoch.
fn parse_date_time(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() != 19 {
        return None;
    }
    let separators = [(4, b'-'), (7, b'-'), (10, b'T'), (13, b':'), (16, b':')];
    for (i, c) in separators {
        if b.get(i) != Some(&c) {
            return None;
        }
    }
    let num = |from: usize, to: usize| -> Option<i64> {
        let part = s.get(from..to)?;
        if !part.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        part.parse().ok()
    };
    let (year, month, day) = (num(0, 4)?, num(5, 7)?, num(8, 10)?);
    let (hour, minute, second) = (num(11, 13)?, num(14, 16)?, num(17, 19)?);
    if year < 1
        || !(1..=12).contains(&month)
        || day < 1
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }
    Some(days_from_civil(year, month, day) * SECONDS_PER_DAY + hour * 3600 + minute * 60 + second)
}

impl FromStr for Timestamp {
    type Err = ValueError;

    /// Accepts only the canonical form: six fractional digits and `Z`.
    fn from_str(s: &str) -> Result<Self, ValueError> {
        const ERR: ValueError =
            ValueError("expected an RFC 3339 UTC timestamp with six fractional digits");
        // `YYYY-MM-DDTHH:MM:SS.ffffffZ` is 27 bytes.
        if s.len() != 27 || s.as_bytes().get(19) != Some(&b'.') {
            return Err(ERR);
        }
        Self::parse_utc(s).map_err(|_| ERR)
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let seconds = self.0.div_euclid(MICROS_PER_SECOND);
        let micros = self.0.rem_euclid(MICROS_PER_SECOND);
        let days = seconds.div_euclid(SECONDS_PER_DAY);
        let secs_of_day = seconds.rem_euclid(SECONDS_PER_DAY);
        let (year, month, day) = civil_from_days(days);
        write!(
            f,
            "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{micros:06}Z",
            secs_of_day / 3600,
            secs_of_day % 3600 / 60,
            secs_of_day % 60
        )
    }
}

impl fmt::Debug for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Timestamp({self})")
    }
}

string_serde!(
    Timestamp,
    "an RFC 3339 UTC timestamp with six fractional digits"
);

impl JsonSchema for Timestamp {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "Timestamp".into()
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "description": "An RFC 3339 UTC timestamp with exactly six fractional digits and `Z`.",
            "type": "string",
            "format": "date-time",
            "pattern": "^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]\\.[0-9]{6}Z$"
        })
    }
}

// ---------------------------------------------------------------------------
// Severity
// ---------------------------------------------------------------------------

/// Event severity, 0 (lowest) to 10 (highest).
///
/// [`Severity::syslog`] maps it to the eight syslog severities (RFC 5424).
/// Palisade never emits syslog `emergency` (the system is unusable); that
/// level belongs to the host OS.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct Severity(u8);

impl Severity {
    /// The highest severity.
    pub const MAX: Self = Self(10);

    /// Returns `None` above 10.
    #[must_use]
    pub const fn new(value: u8) -> Option<Self> {
        if value <= 10 { Some(Self(value)) } else { None }
    }

    /// Clamps to 10. For tables that are checked when they are generated.
    pub(crate) const fn clamped(value: u8) -> Self {
        if value <= 10 { Self(value) } else { Self::MAX }
    }

    /// The numeric value.
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }

    /// The syslog severity for this level:
    ///
    /// | Severity | Syslog |
    /// |---|---|
    /// | 0 | 7 debug |
    /// | 1 to 3 | 6 informational |
    /// | 4 to 5 | 5 notice |
    /// | 6 to 7 | 4 warning |
    /// | 8 | 3 error |
    /// | 9 | 2 critical |
    /// | 10 | 1 alert |
    #[must_use]
    pub const fn syslog(self) -> SyslogSeverity {
        match self.0 {
            0 => SyslogSeverity::Debug,
            1..=3 => SyslogSeverity::Informational,
            4 | 5 => SyslogSeverity::Notice,
            6 | 7 => SyslogSeverity::Warning,
            8 => SyslogSeverity::Error,
            9 => SyslogSeverity::Critical,
            _ => SyslogSeverity::Alert,
        }
    }
}

impl<'de> Deserialize<'de> for Severity {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = u8::deserialize(deserializer)?;
        Self::new(value).ok_or_else(|| de::Error::custom("expected a severity from 0 to 10"))
    }
}

impl JsonSchema for Severity {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "Severity".into()
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "description": "Event severity, 0 (lowest) to 10 (highest).",
            "type": "integer",
            "minimum": 0,
            "maximum": 10
        })
    }
}

/// A syslog severity (RFC 5424, section 6.2.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SyslogSeverity {
    /// 0: the system is unusable. Never produced by [`Severity::syslog`].
    Emergency,
    /// 1: action must be taken immediately.
    Alert,
    /// 2: critical conditions.
    Critical,
    /// 3: error conditions.
    Error,
    /// 4: warning conditions.
    Warning,
    /// 5: normal but significant condition.
    Notice,
    /// 6: informational messages.
    Informational,
    /// 7: debug-level messages.
    Debug,
}

impl SyslogSeverity {
    /// The numeric code, 0 to 7.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Emergency => 0,
            Self::Alert => 1,
            Self::Critical => 2,
            Self::Error => 3,
            Self::Warning => 4,
            Self::Notice => 5,
            Self::Informational => 6,
            Self::Debug => 7,
        }
    }
}

// ---------------------------------------------------------------------------
// Labels
// ---------------------------------------------------------------------------

/// A label key: 1 to 64 characters, a lowercase letter first, then lowercase
/// letters, digits, `_`, `.`, `:` or `-`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LabelKey(String);

impl LabelKey {
    /// The key.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for LabelKey {
    type Err = ValueError;

    fn from_str(s: &str) -> Result<Self, ValueError> {
        const ERR: ValueError = ValueError("expected a label key such as `team` or `app.tier`");
        let mut bytes = s.bytes();
        let first_ok = bytes.next().is_some_and(|b| b.is_ascii_lowercase());
        let rest_ok = bytes.all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'.' | b':' | b'-')
        });
        if !first_ok || !rest_ok || s.len() > 64 {
            return Err(ERR);
        }
        Ok(Self(s.to_owned()))
    }
}

impl fmt::Display for LabelKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

string_serde!(LabelKey, "a label key such as `team` or `app.tier`");

/// Free-form key/value labels copied from policy tags: at most 64 entries,
/// each value 1 to 256 characters. Duplicate keys are rejected.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Labels(BTreeMap<LabelKey, Name>);

impl Labels {
    /// Most entries.
    pub const MAX: usize = 64;

    /// Checks the number of entries.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError`] if there are more than [`Self::MAX`] entries.
    pub fn new(map: BTreeMap<LabelKey, Name>) -> Result<Self, ValueError> {
        if map.len() > Self::MAX {
            return Err(ValueError("at most 64 labels"));
        }
        Ok(Self(map))
    }

    /// The entries.
    #[must_use]
    pub const fn as_map(&self) -> &BTreeMap<LabelKey, Name> {
        &self.0
    }

    /// Whether there are no labels.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Serialize for Labels {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Labels {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Labels;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a map of at most 64 labels")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> Result<Labels, A::Error> {
                let mut map = BTreeMap::new();
                while let Some((key, value)) = access.next_entry::<LabelKey, Name>()? {
                    if map.len() == Labels::MAX {
                        return Err(de::Error::custom("at most 64 labels"));
                    }
                    if map.contains_key(&key) {
                        return Err(de::Error::custom(format!("duplicate label `{key}`")));
                    }
                    map.insert(key, value);
                }
                Ok(Labels(map))
            }
        }
        deserializer.deserialize_map(V)
    }
}

impl JsonSchema for Labels {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "Labels".into()
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "description": "Free-form labels from policy tags.",
            "type": "object",
            "maxProperties": 64,
            "propertyNames": {
                "pattern": "^[a-z][a-z0-9_.:-]{0,63}$"
            },
            "additionalProperties": {
                "type": "string",
                "minLength": 1,
                "maxLength": 256
            }
        })
    }
}

// ---------------------------------------------------------------------------
// IP address
// ---------------------------------------------------------------------------

/// An IPv4 or IPv6 address.
///
/// The only accepted text form is the one the standard library writes:
/// dotted decimal without leading zeros for IPv4, and the RFC 5952 form
/// (lowercase, shortest, `::` for the longest zero run) for IPv6. So each
/// address has one spelling.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IpAddress(pub IpAddr);

impl FromStr for IpAddress {
    type Err = ValueError;

    fn from_str(s: &str) -> Result<Self, ValueError> {
        const ERR: ValueError = ValueError("expected an IP address in canonical form");
        let addr: IpAddr = s.parse().map_err(|_| ERR)?;
        if addr.to_string() != s {
            return Err(ERR);
        }
        Ok(Self(addr))
    }
}

impl fmt::Display for IpAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

string_serde!(IpAddress, "an IP address in canonical form");

impl JsonSchema for IpAddress {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "IpAddress".into()
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "description": "An IPv4 or IPv6 address in canonical form.",
            "type": "string",
            "anyOf": [{ "format": "ipv4" }, { "format": "ipv6" }]
        })
    }
}

/// The JSON Schema of a flag that is written only when set: the constant
/// `true`. See `flag` in the parent module.
pub(crate) fn flag_schema(_: &mut SchemaGenerator) -> Schema {
    json_schema!({ "type": "boolean", "const": true })
}

// ---------------------------------------------------------------------------
// DNS name
// ---------------------------------------------------------------------------

/// A DNS host name, for example `files.example.org`.
///
/// The only accepted form is lowercase ASCII without a trailing dot: 1 to
/// 253 characters, in labels of 1 to 63 letters, digits, `-` or `_`, each
/// starting and ending with a letter, digit or `_`. A single label (a short
/// host name) is accepted. Internationalised names are written in their
/// ASCII (punycode) form. Use [`DnsName::normalise`] to lowercase a name and
/// drop a trailing dot.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DnsName(String);

const DNS_NAME_ERROR: ValueError =
    ValueError("expected a lowercase DNS name such as files.example.org");

impl DnsName {
    /// The name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Lowercases ASCII letters and drops one trailing dot, then checks the
    /// canonical form.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError`] if the result is not a DNS name.
    pub fn normalise(text: &str) -> Result<Self, ValueError> {
        let text = text.strip_suffix('.').unwrap_or(text);
        // Lowercasing ASCII keeps the length: reject long input first.
        if text.len() > 253 {
            return Err(DNS_NAME_ERROR);
        }
        text.to_ascii_lowercase().parse()
    }
}

impl FromStr for DnsName {
    type Err = ValueError;

    fn from_str(s: &str) -> Result<Self, ValueError> {
        if s.is_empty() || s.len() > 253 {
            return Err(DNS_NAME_ERROR);
        }
        let edge = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_';
        for label in s.split('.') {
            let bytes = label.as_bytes();
            let (Some(&first), Some(&last)) = (bytes.first(), bytes.last()) else {
                return Err(DNS_NAME_ERROR);
            };
            if bytes.len() > 63
                || !edge(first)
                || !edge(last)
                || !bytes.iter().all(|&b| edge(b) || b == b'-')
            {
                return Err(DNS_NAME_ERROR);
            }
        }
        Ok(Self(s.to_owned()))
    }
}

impl fmt::Display for DnsName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

string_serde!(DnsName, "a lowercase DNS name such as files.example.org");

impl JsonSchema for DnsName {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "DnsName".into()
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "description": "A lowercase DNS name without a trailing dot.",
            "type": "string",
            "minLength": 1,
            "maxLength": 253,
            "pattern": "^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?(\\.[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)*$"
        })
    }
}

// ---------------------------------------------------------------------------
// JSON Pointer
// ---------------------------------------------------------------------------

/// A JSON Pointer (RFC 6901) to a member of an object, for example
/// `/rules/3/name`: 1 to 1024 characters, `/` and then reference tokens in
/// which `~` appears only as `~0` (for `~`) or `~1` (for `/`).
///
/// RFC 6901 escaping is mandatory and unique, so each pointer has one
/// spelling. The empty pointer (the whole document) is not a value: a change
/// to a whole object is recorded as changes to its members.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct JsonPointer(String);

impl JsonPointer {
    /// The pointer.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for JsonPointer {
    type Err = ValueError;

    fn from_str(s: &str) -> Result<Self, ValueError> {
        const ERR: ValueError = ValueError(
            "expected a JSON Pointer such as /rules/0/name, with `~` written as ~0 or ~1",
        );
        if !s.starts_with('/') || s.chars().count() > 1024 {
            return Err(ERR);
        }
        let mut chars = s.chars();
        while let Some(c) = chars.next() {
            if c == '~' && !matches!(chars.next(), Some('0' | '1')) {
                return Err(ERR);
            }
        }
        Ok(Self(s.to_owned()))
    }
}

impl fmt::Display for JsonPointer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

string_serde!(JsonPointer, "a JSON Pointer such as /rules/0/name");

impl JsonSchema for JsonPointer {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "JsonPointer".into()
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "description": "A non-empty JSON Pointer (RFC 6901).",
            "type": "string",
            "maxLength": 1024,
            "pattern": "^(/([^~/]|~[01])*)+$"
        })
    }
}

// ---------------------------------------------------------------------------
// JSON value
// ---------------------------------------------------------------------------

/// A JSON value recorded in an event, such as the old or new value of a
/// changed setting.
///
/// It follows the event's own rules, so it has one canonical form: no
/// `null` (an absent value is left out), integers only (the models Palisade
/// records have no floating-point fields), object keys unique and written in
/// sorted order. Bounded: strings of at most 4096 characters, keys of at
/// most 256, nesting at most 16 deep, and at most 1024 values in all. The
/// JSON Schema states the shape and the string limits; the depth and count
/// limits, and the integer range (`i64::MIN` to `u64::MAX`), are checked
/// only by the reader.
///
/// The representation is private: a value is built only by
/// [`JsonValue::new`] or by reading JSON, which check the same rules, so an
/// event can never hold a value that its own reader would reject.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct JsonValue(Node);

/// The checked tree. An integer that fits `i64` is always `Int`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Node {
    Bool(bool),
    Int(i64),
    UInt(u64),
    String(String),
    Array(Vec<Self>),
    Object(BTreeMap<String, Self>),
}

impl JsonValue {
    /// Most nesting levels.
    pub const MAX_DEPTH: usize = 16;
    /// Most values, counting every nested value.
    pub const MAX_NODES: usize = 1024;
    /// Longest string, in characters.
    pub const MAX_STRING: usize = 4096;
    /// Longest object key, in characters.
    pub const MAX_KEY: usize = 256;

    /// Checks a JSON value against the rules above.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError`] for `null`, a number that is not an integer
    /// from `i64::MIN` to `u64::MAX`, or a value over a limit.
    pub fn new(value: serde_json::Value) -> Result<Self, ValueError> {
        Self::deserialize(value).map_err(|e: serde_json::Error| {
            let text = e.to_string();
            if text.contains("null") {
                ValueError("null is not a value: leave the member out")
            } else if text.contains("integers") || text.contains("floating") {
                ValueError("a JSON value holds integers only")
            } else {
                ValueError("a JSON value is over a size, depth or length limit")
            }
        })
    }

    /// The value as a `serde_json` value.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        fn convert(node: &Node) -> serde_json::Value {
            match node {
                Node::Bool(b) => serde_json::Value::Bool(*b),
                Node::Int(i) => serde_json::Value::from(*i),
                Node::UInt(u) => serde_json::Value::from(*u),
                Node::String(s) => serde_json::Value::String(s.clone()),
                Node::Array(items) => items.iter().map(convert).collect(),
                Node::Object(map) => map
                    .iter()
                    .map(|(k, v)| (k.clone(), convert(v)))
                    .collect::<serde_json::Map<_, _>>()
                    .into(),
            }
        }
        convert(&self.0)
    }
}

impl Serialize for JsonValue {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl Serialize for Node {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Bool(b) => serializer.serialize_bool(*b),
            Self::Int(i) => serializer.serialize_i64(*i),
            Self::UInt(u) => serializer.serialize_u64(*u),
            Self::String(s) => serializer.serialize_str(s),
            Self::Array(items) => items.serialize(serializer),
            Self::Object(map) => map.serialize(serializer),
        }
    }
}

/// Reads one [`JsonValue`], counting nesting and values against the limits.
struct JsonSeed<'a> {
    depth: usize,
    nodes: &'a std::cell::Cell<usize>,
}

impl JsonSeed<'_> {
    fn count<E: de::Error>(&self) -> Result<(), E> {
        let n = self.nodes.get().saturating_add(1);
        if n > JsonValue::MAX_NODES {
            return Err(E::custom("a JSON value may hold at most 1024 values"));
        }
        self.nodes.set(n);
        Ok(())
    }

    /// The seed for a value inside this one.
    const fn child(&self) -> JsonSeed<'_> {
        JsonSeed {
            depth: self.depth.saturating_add(1),
            nodes: self.nodes,
        }
    }
}

impl<'de> de::DeserializeSeed<'de> for JsonSeed<'_> {
    type Value = Node;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Node, D::Error> {
        // The root is at depth 1, so a value at depth 17 is the 17th level.
        if self.depth > JsonValue::MAX_DEPTH {
            return Err(de::Error::custom("a JSON value may nest at most 16 deep"));
        }
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for JsonSeed<'_> {
    type Value = Node;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON value without null or non-integer numbers")
    }

    fn visit_bool<E: de::Error>(self, v: bool) -> Result<Node, E> {
        self.count()?;
        Ok(Node::Bool(v))
    }

    fn visit_i64<E: de::Error>(self, v: i64) -> Result<Node, E> {
        self.count()?;
        Ok(Node::Int(v))
    }

    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Node, E> {
        self.count()?;
        Ok(i64::try_from(v).map_or(Node::UInt(v), Node::Int))
    }

    fn visit_f64<E: de::Error>(self, _: f64) -> Result<Node, E> {
        Err(E::custom("a JSON value holds integers only"))
    }

    fn visit_unit<E: de::Error>(self) -> Result<Node, E> {
        Err(E::custom("null is not a value: leave the member out"))
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<Node, E> {
        self.count()?;
        // A character is at most 4 bytes: reject long input without counting.
        if v.len() > JsonValue::MAX_STRING.saturating_mul(4)
            || v.chars().count() > JsonValue::MAX_STRING
        {
            return Err(E::custom(
                "a string in a JSON value may hold at most 4096 characters",
            ));
        }
        Ok(Node::String(v.to_owned()))
    }

    fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Node, A::Error> {
        self.count()?;
        let mut items = Vec::new();
        while let Some(item) = seq.next_element_seed(self.child())? {
            items.push(item);
        }
        Ok(Node::Array(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> Result<Node, A::Error> {
        self.count()?;
        let mut map = BTreeMap::new();
        while let Some(key) = access.next_key_seed(KeySeed)? {
            if map.contains_key(&key) {
                return Err(de::Error::custom(format!("duplicate key `{key}`")));
            }
            let value = access.next_value_seed(self.child())?;
            map.insert(key, value);
        }
        Ok(Node::Object(map))
    }
}

/// Reads an object key, rejecting an over-long one before copying it.
struct KeySeed;

impl<'de> de::DeserializeSeed<'de> for KeySeed {
    type Value = String;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<String, D::Error> {
        deserializer.deserialize_str(self)
    }
}

impl Visitor<'_> for KeySeed {
    type Value = String;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a key of at most 256 characters")
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<String, E> {
        if v.len() > JsonValue::MAX_KEY.saturating_mul(4) || v.chars().count() > JsonValue::MAX_KEY
        {
            return Err(E::custom(
                "a key in a JSON value may hold at most 256 characters",
            ));
        }
        Ok(v.to_owned())
    }
}

impl<'de> Deserialize<'de> for JsonValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let nodes = std::cell::Cell::new(0);
        de::DeserializeSeed::deserialize(
            JsonSeed {
                depth: 1,
                nodes: &nodes,
            },
            deserializer,
        )
        .map(JsonValue)
    }
}

impl JsonSchema for JsonValue {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "JsonValue".into()
    }

    fn json_schema(generator: &mut SchemaGenerator) -> Schema {
        let this = generator.subschema_for::<Self>();
        json_schema!({
            "description": "A JSON value without null or non-integer numbers. Nesting (at most 16) and size (at most 1024 values) are checked by the reader.",
            "anyOf": [
                { "type": "boolean" },
                { "type": "integer" },
                { "type": "string", "maxLength": 4096 },
                { "type": "array", "items": this.clone() },
                {
                    "type": "object",
                    "propertyNames": { "maxLength": 256 },
                    "additionalProperties": this
                }
            ]
        })
    }
}

// ---------------------------------------------------------------------------
// Sorted set
// ---------------------------------------------------------------------------

/// A set of at most `MAX` values, written as a list in ascending order
/// without repeats. That is its only accepted form, so each set has one
/// spelling. The JSON Schema checks that items are unique; the order is
/// checked only by the reader.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SortedSet<T, const MAX: usize>(Vec<T>);

impl<T: Ord, const MAX: usize> SortedSet<T, MAX> {
    /// Sorts and removes repeats.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError`] if more than `MAX` distinct values remain.
    pub fn new(mut items: Vec<T>) -> Result<Self, ValueError> {
        items.sort();
        items.dedup();
        if items.len() > MAX {
            return Err(ValueError("too many items"));
        }
        Ok(Self(items))
    }

    /// The values, in ascending order.
    #[must_use]
    pub fn as_slice(&self) -> &[T] {
        &self.0
    }

    /// Whether the set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<T, const MAX: usize> Default for SortedSet<T, MAX> {
    fn default() -> Self {
        Self(Vec::new())
    }
}

impl<T: Serialize, const MAX: usize> Serialize for SortedSet<T, MAX> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de, T: Deserialize<'de> + Ord, const MAX: usize> Deserialize<'de> for SortedSet<T, MAX> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let items = BoundedVec::<T, MAX>::deserialize(deserializer)?.0;
        if items.windows(2).any(|w| matches!(w, [a, b] if a >= b)) {
            return Err(de::Error::custom(
                "a set is written in ascending order without repeats",
            ));
        }
        Ok(Self(items))
    }
}

impl<T: JsonSchema, const MAX: usize> JsonSchema for SortedSet<T, MAX> {
    fn inline_schema() -> bool {
        true
    }

    fn schema_name() -> std::borrow::Cow<'static, str> {
        format!("SortedSet{MAX}_{}", T::schema_name()).into()
    }

    fn json_schema(generator: &mut SchemaGenerator) -> Schema {
        let items = generator.subschema_for::<T>();
        json_schema!({
            "type": "array",
            "items": items,
            "maxItems": MAX,
            "uniqueItems": true
        })
    }
}

// ---------------------------------------------------------------------------
// Registry key
// ---------------------------------------------------------------------------

/// The root keys, in their canonical spelling, and the other spellings
/// [`RegistryKey::normalise`] reads (compared ASCII case-insensitively).
const REGISTRY_ROOTS: &[(&str, &[&str])] = &[
    (
        "HKEY_LOCAL_MACHINE",
        &["HKEY_LOCAL_MACHINE", "HKLM", "\\REGISTRY\\MACHINE"],
    ),
    ("HKEY_USERS", &["HKEY_USERS", "HKU", "\\REGISTRY\\USER"]),
    ("HKEY_CURRENT_USER", &["HKEY_CURRENT_USER", "HKCU"]),
    ("HKEY_CLASSES_ROOT", &["HKEY_CLASSES_ROOT", "HKCR"]),
    ("HKEY_CURRENT_CONFIG", &["HKEY_CURRENT_CONFIG", "HKCC"]),
];

/// The longest registry key name component the OS allows, in characters.
const REGISTRY_COMPONENT_MAX: usize = 255;

/// A registry key path, for example
/// `HKEY_LOCAL_MACHINE\SOFTWARE\Policies`.
///
/// The canonical form starts with the full name of a root key
/// (`HKEY_LOCAL_MACHINE`, `HKEY_USERS`, `HKEY_CURRENT_USER`,
/// `HKEY_CLASSES_ROOT` or `HKEY_CURRENT_CONFIG`), followed by zero or more
/// `\`-separated components of 1 to 255 characters, with no trailing `\`. At
/// most 32,767 characters in all. Components keep the case they were
/// reported in. Use [`RegistryKey::normalise`] to read the kernel form
/// (`\REGISTRY\MACHINE\...`) and the short root names (`HKLM\...`).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RegistryKey(String);

const REGISTRY_KEY_ERROR: ValueError = ValueError(
    "expected a registry key such as HKEY_LOCAL_MACHINE\\SOFTWARE, with components of 1 to 255 characters",
);

impl RegistryKey {
    /// The path.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Reads the full root names, the short root names (`HKLM`, `HKU`,
    /// `HKCU`, `HKCR`, `HKCC`) and the kernel forms (`\REGISTRY\MACHINE`,
    /// `\REGISTRY\USER`), in any ASCII case, with one trailing `\`, and
    /// returns the canonical form.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError`] if the text is not a registry key path.
    pub fn normalise(text: &str) -> Result<Self, ValueError> {
        // The canonical form is at most 32,767 characters, and no root
        // spelling is more than 13 bytes longer than its canonical name.
        if text.len() > 32_767usize.saturating_mul(4).saturating_add(16) {
            return Err(REGISTRY_KEY_ERROR);
        }
        let text = text.strip_suffix('\\').unwrap_or(text);
        for (canonical, spellings) in REGISTRY_ROOTS {
            for spelling in *spellings {
                let Some(head) = text.get(..spelling.len()) else {
                    continue;
                };
                if !head.eq_ignore_ascii_case(spelling) {
                    continue;
                }
                let rest = text.get(spelling.len()..).unwrap_or_default();
                if rest.is_empty() || rest.starts_with('\\') {
                    return format!("{canonical}{rest}").parse();
                }
            }
        }
        Err(REGISTRY_KEY_ERROR)
    }
}

impl FromStr for RegistryKey {
    type Err = ValueError;

    fn from_str(s: &str) -> Result<Self, ValueError> {
        if s.chars().count() > 32_767 {
            return Err(REGISTRY_KEY_ERROR);
        }
        let mut parts = s.split('\\');
        let root = parts.next().unwrap_or_default();
        if !REGISTRY_ROOTS.iter().any(|(r, _)| *r == root) {
            return Err(REGISTRY_KEY_ERROR);
        }
        for part in parts {
            let len = part.chars().count();
            if len == 0 || len > REGISTRY_COMPONENT_MAX {
                return Err(REGISTRY_KEY_ERROR);
            }
        }
        Ok(Self(s.to_owned()))
    }
}

impl fmt::Display for RegistryKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

string_serde!(
    RegistryKey,
    "a registry key such as HKEY_LOCAL_MACHINE\\SOFTWARE"
);

impl JsonSchema for RegistryKey {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "RegistryKey".into()
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "description": "A registry key path: the full root key name, then components of 1 to 255 characters separated by `\\`.",
            "type": "string",
            "maxLength": 32_767,
            "pattern": "^HKEY_(LOCAL_MACHINE|USERS|CURRENT_USER|CLASSES_ROOT|CURRENT_CONFIG)(\\\\[^\\\\]{1,255})*$"
        })
    }
}

// ---------------------------------------------------------------------------
// Token
// ---------------------------------------------------------------------------

/// A short machine-readable word: 1 to 64 characters, a lowercase letter
/// first, then lowercase letters, digits or `_`. Used for `action` and
/// `rule_type`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Token(String);

impl Token {
    /// The token.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for Token {
    type Err = ValueError;

    fn from_str(s: &str) -> Result<Self, ValueError> {
        const ERR: ValueError = ValueError("expected a token such as `execute` or `load`");
        let mut bytes = s.bytes();
        let first_ok = bytes.next().is_some_and(|b| b.is_ascii_lowercase());
        let rest_ok = bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
        if !first_ok || !rest_ok || s.len() > 64 {
            return Err(ERR);
        }
        Ok(Self(s.to_owned()))
    }
}

impl fmt::Display for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

string_serde!(Token, "a token such as `execute` or `load`");

impl JsonSchema for Token {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "Token".into()
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "description": "A lowercase machine-readable word.",
            "type": "string",
            "pattern": "^[a-z][a-z0-9_]{0,63}$"
        })
    }
}

// ---------------------------------------------------------------------------
// Typed IDs
// ---------------------------------------------------------------------------

/// The ID of a tenant.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(transparent)]
pub struct TenantId(pub Uuid7);

/// The ID of an enrolled device, assigned by the server at enrolment.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(transparent)]
pub struct HostId(pub Uuid7);
