//! Catalog authoring (#51): an unsigned catalog definition from a recorded
//! set of files.
//!
//! An organisation that wants to allow an unsigned line-of-business app by
//! publisher can record the files its installer writes (#72's capture
//! mode), list their digests in a catalog, and sign the catalog with an
//! organisation certificate (#13, #18). [`build_catalog`] does the middle
//! step: it turns the recorded [`CatalogEntry`]s into an [`UnsignedCtl`],
//! the DER certificate trust list a catalog signs. Signing it is not done
//! here.
//!
//! The output is the v2 format (`szOID_CATALOG_LIST_MEMBER2`, SHA-256
//! members), in DER: every `SET OF` sorted, every INTEGER minimal. Each
//! member is listed by its digest, as a raw-octet tag, with the
//! `SPC_INDIRECT_DATA` digest a lookup matches on:
//!
//! - a PE image by its Authenticode SHA-256 (`SPC_PE_IMAGE_DATA`), the
//!   digest the OS computes for a PE member;
//! - any other file by its flat SHA-256, under the flat-file subject
//!   interface package.
//!
//! The file name and an `OSAttr` value are kept as name-value pairs, for
//! people reading the catalog; nothing ever matches on them. Members are
//! sorted by digest and duplicates dropped, so the same set of files gives
//! the same bytes whatever order it was recorded in. [`super::parse_ctl`]
//! reads the output back, and a test checks that it does, member for
//! member.

#![forbid(unsafe_code)]

use std::fmt;

use super::ctl::oid;
use crate::authenticode::asn1::oid as asn1_oid;
use crate::hash::{Digest, HashAlgorithm};

/// The most members one catalog definition may list:
/// [`super::MAX_MEMBERS`], so everything [`build_catalog`] writes can be
/// read back in full.
pub const MAX_AUTHORED_MEMBERS: usize = super::MAX_MEMBERS;
/// The longest file name or attribute value written, in UTF-16 units. A
/// longer one is refused, not cut, so the catalog never says less than
/// the recording did.
pub const MAX_AUTHORED_TEXT: usize = 1024;

/// How a member file is hashed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EntryKind {
    /// A conformant PE image, listed by its Authenticode SHA-256.
    PeImage,
    /// Any other file, listed by its flat SHA-256.
    Flat,
}

/// One recorded file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogEntry {
    /// How it is listed.
    pub kind: EntryKind,
    /// Its SHA-256: the Authenticode image hash for [`EntryKind::PeImage`],
    /// the flat hash for [`EntryKind::Flat`].
    pub digest: Digest,
    /// The file name recorded, without a directory. Informational.
    pub file_name: String,
}

impl CatalogEntry {
    /// The entry for a file, from its identity hashes: the Authenticode
    /// SHA-256 when it is a conformant PE image, else its flat SHA-256.
    /// `None` for an empty file (whose digest is never an identity) or when
    /// the needed digest was not computed.
    #[must_use]
    pub fn from_digests(file_name: &str, digests: &super::FileDigests) -> Option<Self> {
        let (kind, digest) = match (&digests.authenticode_sha256, &digests.flat_sha256) {
            (Some(a), _) => (EntryKind::PeImage, a.clone()),
            (None, Some(f)) => (EntryKind::Flat, f.clone()),
            (None, None) => return None,
        };
        (digest.algorithm() == HashAlgorithm::Sha256).then(|| Self {
            kind,
            digest,
            file_name: file_name.to_owned(),
        })
    }
}

/// Why a catalog definition could not be built.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AuthorError {
    /// No entries: a catalog that lists nothing allows nothing.
    Empty,
    /// More than [`MAX_AUTHORED_MEMBERS`] distinct entries.
    TooManyMembers(usize),
    /// An entry's digest is not SHA-256.
    NotSha256 {
        /// The entry's position in the input.
        entry: usize,
    },
    /// A file name, the catalog name or an `OSAttr` value is empty,
    /// longer than [`MAX_AUTHORED_TEXT`], or holds a NUL or another control
    /// character.
    BadText {
        /// Which field.
        field: &'static str,
        /// The entry's position in the input, for a file name.
        entry: Option<usize>,
    },
    /// The same digest is recorded with two kinds (PE and flat): the
    /// recording is inconsistent.
    ConflictingKinds {
        /// The second entry's position in the input.
        entry: usize,
    },
}

impl fmt::Display for AuthorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("a catalog must list at least one file"),
            Self::TooManyMembers(n) => {
                write!(f, "{n} members is more than {MAX_AUTHORED_MEMBERS}")
            }
            Self::NotSha256 { entry } => write!(f, "entry {entry} is not a SHA-256 digest"),
            Self::BadText { field, entry } => match entry {
                Some(e) => write!(f, "entry {e}: unusable {field}"),
                None => write!(f, "unusable {field}"),
            },
            Self::ConflictingKinds { entry } => {
                write!(f, "entry {entry} repeats a digest with another kind")
            }
        }
    }
}

impl std::error::Error for AuthorError {}

/// An unsigned catalog definition: a DER `CertificateTrustList`, ready to
/// be wrapped in a SignedData and signed (#13, #18).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsignedCtl {
    /// The DER encoding.
    pub der: Vec<u8>,
    /// How many members it lists (after duplicates were dropped).
    pub members: usize,
}

/// `CRYPTCAT_ATTR_AUTHENTICATED | NAMEASCII | DATAASCII`: how catalog tools
/// flag text name-value pairs.
const TEXT_FLAGS: u32 = 0x1001_0001;
/// The subject interface package GUIDs of PE images and of flat files.
const PE_SIP: &str = "{C689AAB8-8E78-11D0-8C47-00C04FC295EE}";
const FLAT_SIP: &str = "{DE351A42-8E59-11D0-8C47-00C04FC295EE}";
/// 1.3.6.1.4.1.311.2.1.25 `SPC_CAB_DATA_OBJID`: the indirect data type
/// catalog tools write for a flat-hashed member.
const SPC_CAB_DATA: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x19];

/// Builds an unsigned v2 catalog definition listing `entries`.
///
/// `name` is the catalog's list identifier (kept as UTF-16 text, as
/// catalog tools write it) and `os_attr` its catalog-wide `OSAttr` value
/// (for example `2:10.0`), also written on each member. `this_update` is
/// the effective date, in seconds since the Unix epoch, from 1950 to 2049
/// (written as UTCTime).
pub fn build_catalog(
    entries: &[CatalogEntry],
    name: &str,
    os_attr: &str,
    this_update: i64,
) -> Result<UnsignedCtl, AuthorError> {
    check_text(name, "catalog name", None)?;
    check_text(os_attr, "OSAttr", None)?;
    if entries.is_empty() {
        return Err(AuthorError::Empty);
    }
    // Sorted by digest, duplicates dropped, kinds consistent.
    let mut sorted: Vec<(usize, &CatalogEntry)> = entries.iter().enumerate().collect();
    for (i, e) in &sorted {
        if e.digest.algorithm() != HashAlgorithm::Sha256 {
            return Err(AuthorError::NotSha256 { entry: *i });
        }
        check_text(&e.file_name, "file name", Some(*i))?;
    }
    sorted.sort_by(|a, b| {
        a.1.digest
            .as_bytes()
            .cmp(b.1.digest.as_bytes())
            .then(a.0.cmp(&b.0))
    });
    let mut unique: Vec<&CatalogEntry> = Vec::new();
    for (i, e) in sorted {
        match unique.last() {
            Some(last) if last.digest == e.digest => {
                if last.kind != e.kind {
                    return Err(AuthorError::ConflictingKinds { entry: i });
                }
            }
            _ => unique.push(e),
        }
    }
    if unique.len() > MAX_AUTHORED_MEMBERS {
        return Err(AuthorError::TooManyMembers(unique.len()));
    }
    let members: Vec<Vec<u8>> = unique.iter().map(|e| member(e, os_attr)).collect();
    let refs: Vec<&[u8]> = members.iter().map(Vec::as_slice).collect();
    let extension = seq(&[
        &oid_tlv(oid::CAT_NAMEVALUE),
        &octets(&name_value("OSAttr", os_attr)),
    ]);
    let der = seq(&[
        &seq(&[&oid_tlv(oid::CATALOG_LIST)]),
        &octets(&utf16z(name)),
        &utc_time(this_update),
        &seq(&[&oid_tlv(oid::CATALOG_LIST_MEMBER2), &[0x05, 0x00]]),
        &seq(&refs),
        &tlv(0xa0, &seq(&[&extension])),
    ]);
    Ok(UnsignedCtl {
        der,
        members: unique.len(),
    })
}

/// One `TrustedSubject`.
fn member(entry: &CatalogEntry, os_attr: &str) -> Vec<u8> {
    let digest = entry.digest.as_bytes();
    let data = match entry.kind {
        // SpcPeImageData { flags BIT STRING, file [0] { [2] { [0] "" } } }
        EntryKind::PeImage => seq(&[
            &oid_tlv(oid::SPC_PE_IMAGE_DATA),
            &seq(&[&[0x03, 0x01, 0x00], &tlv(0xa0, &tlv(0xa2, &tlv(0x80, &[])))]),
        ]),
        EntryKind::Flat => seq(&[&oid_tlv(SPC_CAB_DATA), &tlv(0xa2, &tlv(0x80, &[]))]),
    };
    let sha256 = seq(&[&oid_tlv(asn1_oid::SHA256), &[0x05, 0x00]]);
    let indirect = seq(&[&data, &seq(&[&sha256, &octets(digest)])]);
    let sip = match entry.kind {
        EntryKind::PeImage => PE_SIP,
        EntryKind::Flat => FLAT_SIP,
    };
    let info = seq(&[&bmp(sip), &integer(512)]);
    let attrs = [
        attribute(oid::CAT_NAMEVALUE, &name_value("File", &entry.file_name)),
        attribute(oid::CAT_NAMEVALUE, &name_value("OSAttr", os_attr)),
        attribute(oid::SPC_INDIRECT_DATA, &indirect),
        attribute(oid::CAT_MEMBERINFO, &info),
    ];
    let refs: Vec<&[u8]> = attrs.iter().map(Vec::as_slice).collect();
    seq(&[&octets(digest), &set(&refs)])
}

fn check_text(text: &str, field: &'static str, entry: Option<usize>) -> Result<(), AuthorError> {
    let units = text.encode_utf16().count();
    if text.is_empty() || units > MAX_AUTHORED_TEXT || text.chars().any(char::is_control) {
        return Err(AuthorError::BadText { field, entry });
    }
    Ok(())
}

// --- DER writing -------------------------------------------------------------

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 0x80 {
        out.push(u8::try_from(len).unwrap_or(0));
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|b| **b == 0).count();
        let significant = bytes.get(skip..).unwrap_or_default();
        out.push(0x80 | u8::try_from(significant.len()).unwrap_or(0));
        out.extend_from_slice(significant);
    }
    out.extend_from_slice(content);
    out
}

fn seq(parts: &[&[u8]]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}

/// A DER `SET OF`: the elements in ascending order of their encodings.
fn set(parts: &[&[u8]]) -> Vec<u8> {
    let mut sorted = parts.to_vec();
    sorted.sort_unstable();
    tlv(0x31, &sorted.concat())
}

fn octets(bytes: &[u8]) -> Vec<u8> {
    tlv(0x04, bytes)
}

fn oid_tlv(content: &[u8]) -> Vec<u8> {
    tlv(0x06, content)
}

/// A minimal non-negative INTEGER.
fn integer(value: u32) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let skip = bytes.iter().take_while(|b| **b == 0).count().min(3);
    let mut content = bytes.get(skip..).unwrap_or_default().to_vec();
    if content.first().is_some_and(|b| b & 0x80 != 0) {
        content.insert(0, 0);
    }
    tlv(0x02, &content)
}

fn bmp(text: &str) -> Vec<u8> {
    let units: Vec<u8> = text.encode_utf16().flat_map(u16::to_be_bytes).collect();
    tlv(0x1e, &units)
}

/// UTF-16LE, NUL-terminated, as catalogs store text.
fn utf16z(text: &str) -> Vec<u8> {
    let mut out: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
    out.extend([0, 0]);
    out
}

/// `CAT_NAMEVALUE ::= SEQUENCE { tag BMPString, flags INTEGER, value OCTET
/// STRING }`, a text value.
fn name_value(name: &str, value: &str) -> Vec<u8> {
    seq(&[&bmp(name), &integer(TEXT_FLAGS), &octets(&utf16z(value))])
}

fn attribute(type_oid: &[u8], value: &[u8]) -> Vec<u8> {
    seq(&[&oid_tlv(type_oid), &set(&[value])])
}

/// A UTCTime for `t`, clamped to the years UTCTime can carry (1950 to
/// 2049).
fn utc_time(t: i64) -> Vec<u8> {
    // 1950-01-01 and 2049-12-31T23:59:59.
    let t = t.clamp(-631_152_000, 2_524_607_999);
    let days = t.div_euclid(86_400);
    let secs = t.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    let text = format!(
        "{:02}{:02}{:02}{:02}{:02}{:02}Z",
        y.rem_euclid(100),
        m,
        d,
        secs / 3600,
        (secs / 60) % 60,
        secs % 60
    );
    tlv(0x17, text.as_bytes())
}

/// The civil date of a day count since 1970-01-01 (proleptic Gregorian).
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_time_is_exact_in_range_and_clamped_outside() {
        assert_eq!(utc_time(1_700_000_000), tlv(0x17, b"231114221320Z"));
        assert_eq!(utc_time(0), tlv(0x17, b"700101000000Z"));
        assert_eq!(utc_time(951_782_400), tlv(0x17, b"000229000000Z")); // 2000-02-29
        assert_eq!(utc_time(i64::MIN), tlv(0x17, b"500101000000Z"));
        assert_eq!(utc_time(i64::MAX), tlv(0x17, b"491231235959Z"));
    }

    #[test]
    fn integers_are_minimal() {
        assert_eq!(integer(0), [0x02, 0x01, 0x00]);
        assert_eq!(integer(0x80), [0x02, 0x02, 0x00, 0x80]);
        assert_eq!(integer(512), [0x02, 0x02, 0x02, 0x00]);
        assert_eq!(integer(TEXT_FLAGS), [0x02, 0x04, 0x10, 0x01, 0x00, 0x01]);
    }

    #[test]
    fn the_flat_data_oid_is_spc_cab_data() {
        assert_eq!(
            crate::authenticode::ObjectId::from_der(SPC_CAB_DATA).to_string(),
            "1.3.6.1.4.1.311.2.1.25"
        );
    }
}
