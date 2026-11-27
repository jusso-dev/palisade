//! Decodes the certificate trust list (CTL) a catalog signs.
//!
//! ```text
//! CertificateTrustList ::= SEQUENCE {
//!     version          CTLVersion DEFAULT v1,      -- INTEGER { v1(0) }
//!     subjectUsage     SEQUENCE OF OBJECT IDENTIFIER,
//!     listIdentifier   OCTET STRING OPTIONAL,
//!     sequenceNumber   INTEGER OPTIONAL,
//!     ctlThisUpdate    Time,
//!     ctlNextUpdate    Time OPTIONAL,
//!     subjectAlgorithm AlgorithmIdentifier,
//!     trustedSubjects  SEQUENCE OF TrustedSubject OPTIONAL,
//!     ctlExtensions    [0] EXPLICIT Extensions OPTIONAL }
//!
//! TrustedSubject ::= SEQUENCE {
//!     subjectIdentifier OCTET STRING,              -- the member tag
//!     subjectAttributes SET OF Attribute OPTIONAL }
//! ```
//!
//! A catalog's subject usage includes `szOID_CATALOG_LIST`
//! (1.3.6.1.4.1.311.12.1.1). Its members' attributes are
//! `SPC_INDIRECT_DATA` (1.3.6.1.4.1.311.2.1.4, the member's digest),
//! `CAT_NAMEVALUE` (1.3.6.1.4.1.311.12.2.1, name-value pairs such as
//! `File` and `OSAttr`), `CAT_MEMBERINFO` (1.3.6.1.4.1.311.12.2.2, the
//! subject interface package GUID) and `CAT_MEMBERINFO2`
//! (1.3.6.1.4.1.311.12.2.3). Catalog-wide name-value pairs are CTL
//! extensions with the `CAT_NAMEVALUE` OID.
//!
//! Strict DER, like the rest of the crate: an explicitly encoded `version`
//! of v1 or `critical` FALSE is rejected, and so is any invalid element,
//! anywhere, including an INTEGER that is not minimally encoded and a
//! member attribute `SET OF` whose elements are not in DER order. Every
//! collection has a fixed limit, and so does the decoded trust list as a
//! whole ([`MAX_DECODED_BYTES`]).

#![forbid(unsafe_code)]

use std::fmt;
use std::mem::size_of;

use crate::authenticode::asn1::{self, Asn1Error, Asn1ErrorKind, ObjectId, Tlv, read_oid, tag};
use crate::authenticode::pkcs7::parse_digest_alg;
use crate::authenticode::{DigestAlgorithm, SignatureError};

/// The most members read from one catalog (262,144; the largest OS
/// catalogs list tens of thousands). Further members are decoded and
/// checked like the others, then dropped, and
/// [`CertificateTrustList::members_truncated`] is set; a file listed only
/// past the limit is not found, so a lookup fails closed.
pub const MAX_MEMBERS: usize = 1 << 18;
/// The most attributes read from one member, and the most catalog-wide
/// extensions read. Past it the catalog is rejected
/// ([`CtlError::TooManyAttributes`]).
pub const MAX_ATTRIBUTES: usize = 64;
/// The most name-value pairs kept per member and for the catalog itself.
/// Further pairs are dropped with a warning.
pub const MAX_NAME_VALUES: usize = 32;
/// The longest name-value value kept, in bytes. Longer values are cut
/// with a warning.
pub const MAX_VALUE_BYTES: usize = 8192;
/// The most warnings kept for one catalog.
pub const MAX_CTL_WARNINGS: usize = 64;
/// The most memory a decoded trust list may take: 128 MiB, twice
/// [`super::MAX_CATALOG_SIZE`]. What is counted is the size of every value
/// kept (members, their name-value pairs and the catalog-wide ones) and
/// the heap bytes each one owns, as allocated. It is checked as each
/// member and extension is decoded, and before the member list grows, so
/// the overshoot is at most the one member being decoded (itself bounded
/// by the per-member limits).
///
/// The per-member limits alone do not bound this: short name-value pairs
/// take a few bytes each in the file but tens of bytes decoded, so a
/// hostile catalog under the size limit could decode to gigabytes before
/// its signature is checked. Real catalogs, whose members carry a digest
/// and a few longer name-value pairs, decode to under twice their size.
/// A catalog over the limit is rejected ([`CtlError::DecodedTooLarge`]),
/// so none of its members is indexed.
pub const MAX_DECODED_BYTES: usize = 128 * 1024 * 1024;

/// The object identifiers this module knows, as encoded.
pub(crate) mod oid {
    /// `szOID_CTL` 1.3.6.1.4.1.311.10.1: the content type of a catalog.
    pub const CTL: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x0a, 0x01];
    /// `szOID_CATALOG_LIST` 1.3.6.1.4.1.311.12.1.1.
    pub const CATALOG_LIST: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x0c, 0x01, 0x01];
    /// `szOID_CATALOG_LIST_MEMBER` 1.3.6.1.4.1.311.12.1.2 (v1: SHA-1
    /// member tags).
    pub const CATALOG_LIST_MEMBER: &[u8] =
        &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x0c, 0x01, 0x02];
    /// `szOID_CATALOG_LIST_MEMBER2` 1.3.6.1.4.1.311.12.1.3 (v2: SHA-256
    /// member tags).
    pub const CATALOG_LIST_MEMBER2: &[u8] =
        &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x0c, 0x01, 0x03];
    /// `SPC_INDIRECT_DATA_OBJID` 1.3.6.1.4.1.311.2.1.4.
    pub const SPC_INDIRECT_DATA: &[u8] =
        &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x04];
    /// `SPC_PE_IMAGE_DATA_OBJID` 1.3.6.1.4.1.311.2.1.15.
    pub const SPC_PE_IMAGE_DATA: &[u8] =
        &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x0f];
    /// `CAT_NAMEVALUE_OBJID` 1.3.6.1.4.1.311.12.2.1.
    pub const CAT_NAMEVALUE: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x0c, 0x02, 0x01];
    /// `CAT_MEMBERINFO_OBJID` 1.3.6.1.4.1.311.12.2.2.
    pub const CAT_MEMBERINFO: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x0c, 0x02, 0x02];
    /// `CAT_MEMBERINFO2_OBJID` 1.3.6.1.4.1.311.12.2.3.
    pub const CAT_MEMBERINFO2: &[u8] =
        &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x0c, 0x02, 0x03];
}

/// Why a CTL could not be decoded. A catalog with any of these is unusable
/// as a whole: none of its members is indexed.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CtlError {
    /// The DER encoding is invalid.
    Asn1(Asn1Error),
    /// An algorithm identifier, or a member's digest, is malformed.
    Signature(SignatureError),
    /// `version` is encoded and is not v1 (0). (An encoded v1, or a
    /// version that is negative, not minimally encoded or does not fit a
    /// `u32`, is an [`Self::Asn1`] error.)
    Version(u32),
    /// The subject usage does not include `szOID_CATALOG_LIST`: this is a
    /// trust list of something else (certificates, for example), not a
    /// catalog of files.
    NotCatalogList,
    /// A member has more than one attribute of a kind that must appear at
    /// most once (`SPC_INDIRECT_DATA`, `CAT_MEMBERINFO`).
    DuplicateAttribute {
        /// The member's position in the list.
        member: usize,
        /// The attribute type.
        attribute: ObjectId,
    },
    /// An attribute that must have exactly one value has another number.
    AttributeValueCount {
        /// The member's position in the list.
        member: usize,
        /// The attribute type.
        attribute: ObjectId,
    },
    /// A member's digest is not as long as its algorithm's output.
    DigestLength {
        /// The member's position in the list.
        member: usize,
    },
    /// A member, the catalog's extensions or its subject usage has more
    /// than [`MAX_ATTRIBUTES`] entries.
    TooManyAttributes,
    /// A critical CTL extension this crate does not process.
    UnhandledCriticalExtension(ObjectId),
    /// The decoded trust list would take more than [`MAX_DECODED_BYTES`].
    /// Decoding stopped there.
    DecodedTooLarge {
        /// The offset of the member or extension that went over.
        offset: usize,
    },
}

impl fmt::Display for CtlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Asn1(e) => write!(f, "invalid DER: {e}"),
            Self::Signature(e) => write!(f, "{e}"),
            Self::Version(v) => write!(f, "CTL version {v} is not v1"),
            Self::NotCatalogList => f.write_str("the trust list is not a catalog list"),
            Self::DuplicateAttribute { member, attribute } => {
                write!(f, "member {member} has attribute {attribute} twice")
            }
            Self::AttributeValueCount { member, attribute } => {
                write!(
                    f,
                    "member {member} attribute {attribute} must have one value"
                )
            }
            Self::DigestLength { member } => {
                write!(f, "member {member} digest has the wrong length")
            }
            Self::TooManyAttributes => f.write_str("too many attributes or extensions"),
            Self::UnhandledCriticalExtension(o) => {
                write!(f, "critical CTL extension {o} is not processed")
            }
            Self::DecodedTooLarge { offset } => write!(
                f,
                "the decoded trust list exceeds {MAX_DECODED_BYTES} bytes at offset {offset:#x}"
            ),
        }
    }
}

impl std::error::Error for CtlError {}

impl From<Asn1Error> for CtlError {
    fn from(e: Asn1Error) -> Self {
        Self::Asn1(e)
    }
}

impl From<SignatureError> for CtlError {
    fn from(e: SignatureError) -> Self {
        match e {
            SignatureError::Asn1(e) => Self::Asn1(e),
            other => Self::Signature(other),
        }
    }
}

type Result<T> = std::result::Result<T, CtlError>;

/// The CTL's `subjectAlgorithm`: how member tags are formed.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SubjectAlgorithm {
    /// `szOID_CATALOG_LIST_MEMBER`: a v1 catalog, whose member tags are
    /// UTF-16LE text ([`MemberTag::Text`]), usually the SHA-1 digest in
    /// hex.
    CatalogListMember,
    /// `szOID_CATALOG_LIST_MEMBER2`: a v2 catalog, whose member tags are
    /// raw octets ([`MemberTag::Bytes`]), usually the SHA-256 digest
    /// itself.
    CatalogListMemberV2,
    /// Any other algorithm, kept as its OID.
    Other(ObjectId),
}

/// A name-value value.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum NameValueData {
    /// UTF-16LE text, decoded. Ill-formed UTF-16 became U+FFFD and was
    /// reported as [`CtlWarning::LossyText`].
    Text(String),
    /// Binary data (the `CRYPTCAT_ATTR_DATABASE64` flag is set), as stored.
    Bytes(Vec<u8>),
}

/// One `CAT_NAMEVALUE`: `SEQUENCE { tag BMPString, flags INTEGER, value
/// OCTET STRING }`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NameValue {
    /// The name (`File`, `OSAttr`, `HWID1` and so on).
    pub name: String,
    /// The `CRYPTCAT_ATTR_*` flags, as stored.
    pub flags: u32,
    /// The value.
    pub value: NameValueData,
}

impl NameValue {
    /// `CRYPTCAT_ATTR_DATABASE64`: the value is binary.
    pub const DATA_BASE64: u32 = 0x0002_0000;

    /// The value as text, if it is text.
    #[must_use]
    pub fn text(&self) -> Option<&str> {
        match &self.value {
            NameValueData::Text(t) => Some(t),
            NameValueData::Bytes(_) => None,
        }
    }
}

/// The digest a member's `SPC_INDIRECT_DATA` attribute signs.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MemberDigest {
    /// The digest algorithm.
    pub alg: DigestAlgorithm,
    /// The digest. Its length matches the algorithm.
    pub digest: Vec<u8>,
    /// The indirect data type: `SPC_PE_IMAGE_DATA` for a PE member, whose
    /// digest is its Authenticode image hash (#47); other types for other
    /// files, whose digest is the hash their subject interface package
    /// computes (the flat hash, #46, for files without one).
    pub data_type: ObjectId,
}

impl MemberDigest {
    /// Whether the member is a PE image (`SPC_PE_IMAGE_DATA`).
    #[must_use]
    pub fn is_pe_image(&self) -> bool {
        self.data_type.as_bytes() == oid::SPC_PE_IMAGE_DATA
    }
}

/// A member tag (`subjectIdentifier`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum MemberTag {
    /// UTF-16LE text, decoded: the form of v1 catalogs
    /// (`szOID_CATALOG_LIST_MEMBER`), usually the digest in uppercase hex.
    /// Ill-formed UTF-16 became U+FFFD ([`CtlWarning::LossyText`]).
    Text(String),
    /// Raw octets, up to [`MAX_VALUE_BYTES`]: the form of v2 catalogs
    /// (`szOID_CATALOG_LIST_MEMBER2`), usually the digest itself.
    Bytes(Vec<u8>),
}

impl MemberTag {
    /// Whether the tag names `digest`: its uppercase (or lowercase) hex as
    /// text, or its octets.
    #[must_use]
    pub fn is_digest(&self, digest: &[u8]) -> bool {
        match self {
            Self::Text(t) => tag_is_hex_of(t, digest),
            Self::Bytes(b) => b == digest,
        }
    }
}

/// One `TrustedSubject`: a file the catalog lists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogMember {
    /// The member tag (`subjectIdentifier`). Usually the member's digest
    /// (as hex text in v1 catalogs, as raw octets in v2), but any value is
    /// allowed; members are indexed by [`Self::digest`], never by the tag.
    pub tag: MemberTag,
    /// The signed digest. `None` when the member has no `SPC_INDIRECT_DATA`
    /// attribute, or its digest algorithm is unknown
    /// ([`CtlWarning::UnknownDigest`]); such a member is never matched.
    pub digest: Option<MemberDigest>,
    /// Its name-value pairs, in order, up to [`MAX_NAME_VALUES`].
    pub name_values: Vec<NameValue>,
    /// `CAT_MEMBERINFO.subjGuid`: the subject interface package GUID.
    pub subject_guid: Option<String>,
    /// `CAT_MEMBERINFO.certVersion`.
    pub cert_version: Option<u32>,
    /// Whether a `CAT_MEMBERINFO2` attribute is present (checked as DER,
    /// not interpreted).
    pub member_info2: bool,
}

impl CatalogMember {
    /// The first name-value pair called `name` (ASCII case-insensitive),
    /// as text.
    #[must_use]
    pub fn attribute(&self, name: &str) -> Option<&str> {
        find_text(&self.name_values, name)
    }

    /// The `File` attribute: the file name recorded when the catalog was
    /// made. Informational; a match is by digest, never by name.
    #[must_use]
    pub fn file_name(&self) -> Option<&str> {
        self.attribute("File")
    }

    /// The `OSAttr` attribute.
    #[must_use]
    pub fn os_attr(&self) -> Option<&str> {
        self.attribute("OSAttr")
    }
}

fn find_text<'a>(values: &'a [NameValue], name: &str) -> Option<&'a str> {
    values
        .iter()
        .find(|v| v.name.eq_ignore_ascii_case(name))
        .and_then(NameValue::text)
}

/// Something unusual in a CTL that does not make it unusable.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CtlWarning {
    /// A member has no `SPC_INDIRECT_DATA` attribute, so it cannot match.
    NoDigest {
        /// The member's position in the list.
        member: usize,
    },
    /// A member's digest algorithm is unknown, so it cannot match.
    UnknownDigest {
        /// The member's position in the list.
        member: usize,
        /// The algorithm.
        alg: ObjectId,
    },
    /// A member's tag does not name its digest ([`MemberTag::is_digest`]):
    /// a text tag is not the digest in hex (either case), or a raw-octet
    /// tag is not the digest's octets. Members are indexed by digest, so
    /// this changes no lookup.
    TagNotDigest {
        /// The member's position in the list.
        member: usize,
    },
    /// An attribute of an unknown type was checked as DER and ignored.
    UnknownAttribute(ObjectId),
    /// A non-critical CTL extension of an unknown type was ignored.
    UnknownExtension(ObjectId),
    /// More than [`MAX_NAME_VALUES`] name-value pairs; the rest were
    /// dropped.
    TooManyNameValues,
    /// Text was cut at 4096 characters, or a value at
    /// [`MAX_VALUE_BYTES`].
    Truncated,
    /// Text was not well-formed UTF-16; bad units became U+FFFD.
    LossyText,
    /// More than [`MAX_CTL_WARNINGS`] warnings; the rest were dropped.
    WarningsTruncated,
}

/// A decoded certificate trust list of a catalog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateTrustList {
    /// `subjectUsage`, in order. Always includes `szOID_CATALOG_LIST`.
    pub subject_usage: Vec<ObjectId>,
    /// `listIdentifier`, as stored (often a GUID's 16 bytes or text).
    pub list_identifier: Option<Vec<u8>>,
    /// `sequenceNumber`: the INTEGER content octets, as encoded (minimal,
    /// two's complement).
    pub sequence_number: Option<Vec<u8>>,
    /// `ctlThisUpdate` (the catalog's effective date), in seconds since
    /// the Unix epoch (UTC).
    pub this_update: i64,
    /// `ctlNextUpdate`, in seconds since the Unix epoch (UTC).
    pub next_update: Option<i64>,
    /// `subjectAlgorithm`.
    pub subject_algorithm: SubjectAlgorithm,
    /// The members, in order, up to [`MAX_MEMBERS`].
    pub members: Vec<CatalogMember>,
    /// Whether members past [`MAX_MEMBERS`] were not read.
    pub members_truncated: bool,
    /// Catalog-wide name-value pairs (CTL extensions with the
    /// `CAT_NAMEVALUE` OID), up to [`MAX_NAME_VALUES`].
    pub attributes: Vec<NameValue>,
    /// Anything unusual.
    pub warnings: Vec<CtlWarning>,
}

impl CertificateTrustList {
    /// The first catalog-wide name-value pair called `name` (ASCII
    /// case-insensitive), as text.
    #[must_use]
    pub fn attribute(&self, name: &str) -> Option<&str> {
        find_text(&self.attributes, name)
    }

    /// The catalog-wide OS attribute: `OSAttr`, or else `OS`.
    #[must_use]
    pub fn os_attr(&self) -> Option<&str> {
        self.attribute("OSAttr").or_else(|| self.attribute("OS"))
    }
}

/// Collects warnings up to [`MAX_CTL_WARNINGS`].
#[derive(Default)]
struct Warnings(Vec<CtlWarning>);

impl Warnings {
    fn push(&mut self, warning: CtlWarning) {
        if self.0.contains(&warning) {
            return;
        }
        if self.0.len() < MAX_CTL_WARNINGS {
            self.0.push(warning);
        } else if !self.0.contains(&CtlWarning::WarningsTruncated) {
            self.0.push(CtlWarning::WarningsTruncated);
        }
    }
}

/// Decodes a CTL: `der` is exactly one `CertificateTrustList` SEQUENCE.
///
/// This decodes structure only. A catalog file is a signed CTL; use
/// [`super::parse_catalog`] for it, which also checks the signature.
pub fn parse_ctl(der: &[u8]) -> std::result::Result<CertificateTrustList, CtlError> {
    let seq = asn1::single(der, 0, tag::SEQUENCE)?;
    parse_ctl_tlv(&seq)
}

/// Decodes the CTL SEQUENCE `seq`.
pub(crate) fn parse_ctl_tlv(seq: &Tlv<'_>) -> Result<CertificateTrustList> {
    let mut warnings = Warnings::default();
    let mut r = seq.reader();
    if r.peek_tag() == Some(tag::INTEGER) {
        // DEFAULT v1: DER omits it, so an encoded v1 is not DER, and any
        // other version is unknown. Invalid DER in the INTEGER (or a
        // negative or over-long value) is an ASN.1 error.
        let at = r.offset();
        let version = read_minimal_uint(&mut r)?;
        if version == 0 {
            return Err(asn1::err(Asn1ErrorKind::InvalidValue, at).into());
        }
        return Err(CtlError::Version(version));
    }

    let usage = r.read(tag::SEQUENCE)?;
    let mut u = usage.reader();
    let mut subject_usage = Vec::new();
    let mut catalog_list = false;
    while !u.is_empty() {
        let id = read_oid(&mut u)?;
        if subject_usage.len() >= MAX_ATTRIBUTES {
            return Err(CtlError::TooManyAttributes);
        }
        catalog_list |= id == oid::CATALOG_LIST;
        subject_usage.push(ObjectId::from_der(id));
    }
    if !catalog_list {
        return Err(CtlError::NotCatalogList);
    }

    let list_identifier = r
        .read_optional(tag::OCTET_STRING)?
        .map(|t| t.content.to_vec());
    let sequence_number = match r.read_optional(tag::INTEGER)? {
        Some(t) => Some(minimal_integer(&t)?.to_vec()),
        None => None,
    };
    let this_update = asn1::time(&r.read_any()?)?;
    let next_update = match r.peek_tag() {
        Some(tag::UTC_TIME | tag::GENERALIZED_TIME) => Some(asn1::time(&r.read_any()?)?),
        _ => None,
    };
    let subject_algorithm = match parse_digest_alg(&r.read(tag::SEQUENCE)?)? {
        Err(id) if id.as_bytes() == oid::CATALOG_LIST_MEMBER => SubjectAlgorithm::CatalogListMember,
        Err(id) if id.as_bytes() == oid::CATALOG_LIST_MEMBER2 => {
            SubjectAlgorithm::CatalogListMemberV2
        }
        Err(id) => SubjectAlgorithm::Other(id),
        // A plain digest algorithm: kept as its OID.
        Ok(alg) => SubjectAlgorithm::Other(digest_oid(alg)),
    };

    // v2 catalogs store member tags as raw octets, v1 (and any other) as
    // UTF-16LE text.
    let binary_tags = subject_algorithm == SubjectAlgorithm::CatalogListMemberV2;
    let mut budget = Budget::default();
    let mut members: Vec<CatalogMember> = Vec::new();
    let mut members_truncated = false;
    // The position in `trustedSubjects`, for errors and warnings; past
    // MAX_MEMBERS it runs ahead of `members.len()`.
    let mut position = 0_usize;
    if let Some(subjects) = r.read_optional(tag::SEQUENCE)? {
        let mut s = subjects.reader();
        while !s.is_empty() {
            let subject = s.read(tag::SEQUENCE)?;
            let index = position;
            position = position.saturating_add(1);
            if index >= MAX_MEMBERS {
                // Still decoded and checked, so a truncated catalog meets
                // the same rules; only one is held at a time.
                parse_member(&subject, index, binary_tags, &mut Warnings::default())?;
                members_truncated = true;
                continue;
            }
            let member = parse_member(&subject, index, binary_tags, &mut warnings)?;
            budget.charge(member_heap(&member), subject.offset)?;
            budget.reserve_member(&mut members, subject.offset)?;
            members.push(member);
        }
    }

    let mut attributes = Vec::new();
    if let Some(ext) = r.read_optional(tag::context_cons(0))? {
        let list = asn1::single(ext.content, ext.content_offset, tag::SEQUENCE)?;
        parse_extensions(&list, &mut attributes, &mut warnings, &mut budget)?;
    }
    r.finish()?;

    Ok(CertificateTrustList {
        subject_usage,
        list_identifier,
        sequence_number,
        this_update,
        next_update,
        subject_algorithm,
        members,
        members_truncated,
        attributes,
        warnings: warnings.0,
    })
}

/// Counts the memory a decoded trust list holds against
/// [`MAX_DECODED_BYTES`].
#[derive(Default)]
struct Budget {
    used: usize,
    /// The member list capacity already charged.
    list_capacity: usize,
}

impl Budget {
    /// Charges `bytes` for the element at `offset`.
    fn charge(&mut self, bytes: usize, offset: usize) -> Result<()> {
        self.used = self.used.saturating_add(bytes);
        if self.used > MAX_DECODED_BYTES {
            return Err(CtlError::DecodedTooLarge { offset });
        }
        Ok(())
    }

    /// Makes room for one more member, charging the growth of the list's
    /// allocation before it is made.
    fn reserve_member(&mut self, members: &mut Vec<CatalogMember>, offset: usize) -> Result<()> {
        if members.len() < members.capacity() {
            return Ok(());
        }
        // Never past MAX_MEMBERS in all; callers keep `len` below it.
        let room = MAX_MEMBERS.saturating_sub(members.len()).max(1);
        let extra = members.capacity().max(4).min(room);
        self.charge(extra.saturating_mul(size_of::<CatalogMember>()), offset)?;
        members.reserve_exact(extra);
        // The allocator may give more than asked for; count that too.
        let asked = self.list_capacity.saturating_add(extra);
        let surplus = members.capacity().saturating_sub(asked);
        self.list_capacity = members.capacity();
        self.charge(surplus.saturating_mul(size_of::<CatalogMember>()), offset)
    }
}

/// The heap bytes a member owns, as allocated (its own size is charged
/// with the member list).
fn member_heap(member: &CatalogMember) -> usize {
    let tag = match &member.tag {
        MemberTag::Text(t) => t.capacity(),
        MemberTag::Bytes(b) => b.capacity(),
    };
    let digest = member.digest.as_ref().map_or(0, |d| {
        d.digest
            .capacity()
            .saturating_add(d.data_type.as_bytes().len())
    });
    let guid = member.subject_guid.as_ref().map_or(0, String::capacity);
    tag.saturating_add(digest)
        .saturating_add(guid)
        .saturating_add(name_values_heap(&member.name_values))
}

/// The heap bytes a name-value list owns: its allocation and each pair's
/// text or data.
fn name_values_heap(values: &Vec<NameValue>) -> usize {
    values.iter().fold(
        values.capacity().saturating_mul(size_of::<NameValue>()),
        |acc, v| {
            let value = match &v.value {
                NameValueData::Text(t) => t.capacity(),
                NameValueData::Bytes(b) => b.capacity(),
            };
            acc.saturating_add(v.name.capacity()).saturating_add(value)
        },
    )
}

/// The content of an INTEGER, checked to be minimally encoded (X.690
/// 8.3.2): no leading `00` before an octet whose top bit is clear, and no
/// leading `ff` before one whose top bit is set. `00 80` is minimal: the
/// zero keeps the value positive.
fn minimal_integer<'a>(tlv: &Tlv<'a>) -> Result<&'a [u8]> {
    let content = asn1::integer_bytes(tlv)?;
    if let [first, second, ..] = content {
        let redundant =
            (*first == 0x00 && second & 0x80 == 0) || (*first == 0xff && second & 0x80 != 0);
        if redundant {
            return Err(tlv.error(Asn1ErrorKind::InvalidValue).into());
        }
    }
    Ok(content)
}

/// Reads a non-negative, minimally encoded INTEGER that fits a `u32`
/// (up to five content octets, the first `00`, for values from
/// `0x8000_0000`).
fn read_minimal_uint(reader: &mut asn1::Reader<'_>) -> Result<u32> {
    let tlv = reader.read(tag::INTEGER)?;
    minimal_integer(&tlv)?;
    let (magnitude, _) = asn1::unsigned_integer(&tlv)?;
    if magnitude.len() > 4 {
        return Err(tlv.error(Asn1ErrorKind::InvalidValue).into());
    }
    Ok(magnitude
        .iter()
        .fold(0_u32, |acc, b| (acc << 8) | u32::from(*b)))
}

/// Reads the next element of a DER `SET OF` reader, checking that its
/// encoding does not sort before `previous`'s (X.690 11.6: ascending
/// order, the encodings compared as octet strings; for complete TLVs that
/// is the slice order).
fn read_set_element<'a>(
    reader: &mut asn1::Reader<'a>,
    previous: &mut Option<&'a [u8]>,
) -> Result<Tlv<'a>> {
    let element = reader.read_any()?;
    if previous.is_some_and(|p| element.raw < p) {
        return Err(element.error(Asn1ErrorKind::InvalidValue).into());
    }
    *previous = Some(element.raw);
    Ok(element)
}

/// The OID of a known digest algorithm, for reporting.
fn digest_oid(alg: DigestAlgorithm) -> ObjectId {
    use crate::authenticode::asn1::oid;
    ObjectId::from_der(match alg {
        DigestAlgorithm::Md2 => oid::MD2,
        DigestAlgorithm::Md5 => oid::MD5,
        DigestAlgorithm::Sha1 => oid::SHA1,
        DigestAlgorithm::Sha256 => oid::SHA256,
        DigestAlgorithm::Sha384 => oid::SHA384,
        DigestAlgorithm::Sha512 => oid::SHA512,
    })
}

fn parse_extensions(
    list: &Tlv<'_>,
    attributes: &mut Vec<NameValue>,
    warnings: &mut Warnings,
    budget: &mut Budget,
) -> Result<()> {
    let mut l = list.reader();
    let mut count = 0_usize;
    while !l.is_empty() {
        count = count.saturating_add(1);
        if count > MAX_ATTRIBUTES {
            return Err(CtlError::TooManyAttributes);
        }
        let extension = l.read(tag::SEQUENCE)?;
        let mut e = extension.reader();
        let id = read_oid(&mut e)?;
        let critical = match e.read_optional(tag::BOOLEAN)? {
            Some(flag) => {
                // DEFAULT FALSE: DER never encodes FALSE.
                if !asn1::boolean(&flag)? {
                    return Err(flag.error(Asn1ErrorKind::InvalidValue).into());
                }
                true
            }
            None => false,
        };
        let value = e.read(tag::OCTET_STRING)?;
        e.finish()?;
        if id == oid::CAT_NAMEVALUE {
            let nv = asn1::single(value.content, value.content_offset, tag::SEQUENCE)?;
            let before = name_values_heap(attributes);
            push_name_value(attributes, parse_name_value(&nv, warnings)?, warnings);
            let after = name_values_heap(attributes);
            budget.charge(after.saturating_sub(before), extension.offset)?;
        } else if critical {
            return Err(CtlError::UnhandledCriticalExtension(ObjectId::from_der(id)));
        } else {
            warnings.push(CtlWarning::UnknownExtension(ObjectId::from_der(id)));
        }
    }
    Ok(())
}

fn push_name_value(list: &mut Vec<NameValue>, value: NameValue, warnings: &mut Warnings) {
    if list.len() < MAX_NAME_VALUES {
        list.push(value);
    } else {
        warnings.push(CtlWarning::TooManyNameValues);
    }
}

fn parse_member(
    subject: &Tlv<'_>,
    index: usize,
    binary_tags: bool,
    warnings: &mut Warnings,
) -> Result<CatalogMember> {
    let mut s = subject.reader();
    let identifier = s.read(tag::OCTET_STRING)?;
    let attrs = s.read_optional(tag::SET)?;
    s.finish()?;

    let tag = if binary_tags {
        let raw = identifier.content;
        let kept = raw.get(..MAX_VALUE_BYTES).unwrap_or(raw);
        if kept.len() < raw.len() {
            warnings.push(CtlWarning::Truncated);
        }
        MemberTag::Bytes(kept.to_vec())
    } else {
        MemberTag::Text(utf16le_text(identifier.content, warnings))
    };
    let mut member = CatalogMember {
        tag,
        digest: None,
        name_values: Vec::new(),
        subject_guid: None,
        cert_version: None,
        member_info2: false,
    };
    let mut seen_indirect = false;
    let mut seen_info = false;
    if let Some(attrs) = attrs {
        let mut a = attrs.reader();
        let mut count = 0_usize;
        let mut previous = None;
        while !a.is_empty() {
            count = count.saturating_add(1);
            if count > MAX_ATTRIBUTES {
                return Err(CtlError::TooManyAttributes);
            }
            let attr = read_set_element(&mut a, &mut previous)?.expect(tag::SEQUENCE)?;
            let mut at = attr.reader();
            let attr_type = read_oid(&mut at)?;
            let values = at.read(tag::SET)?;
            at.finish()?;
            // The attribute's values are a `SET OF` too.
            let mut v = values.reader();
            let mut previous_value = None;
            while !v.is_empty() {
                read_set_element(&mut v, &mut previous_value)?;
            }
            let duplicate = || CtlError::DuplicateAttribute {
                member: index,
                attribute: ObjectId::from_der(attr_type),
            };
            match attr_type {
                oid::SPC_INDIRECT_DATA => {
                    if seen_indirect {
                        return Err(duplicate());
                    }
                    seen_indirect = true;
                    let value = single_value(attr_type, &values, index)?;
                    member.digest = parse_member_digest(&value, index, warnings)?;
                }
                oid::CAT_NAMEVALUE => {
                    let mut v = values.reader();
                    while !v.is_empty() {
                        let nv = v.read(tag::SEQUENCE)?;
                        let parsed = parse_name_value(&nv, warnings)?;
                        push_name_value(&mut member.name_values, parsed, warnings);
                    }
                }
                oid::CAT_MEMBERINFO => {
                    if seen_info {
                        return Err(duplicate());
                    }
                    seen_info = true;
                    let value = single_value(attr_type, &values, index)?.expect(tag::SEQUENCE)?;
                    let mut m = value.reader();
                    let guid = m.read(tag::BMP_STRING)?;
                    let text = asn1::bmp_text(guid.content, guid.offset)?;
                    if text.truncated {
                        warnings.push(CtlWarning::Truncated);
                    }
                    member.subject_guid = Some(text.text);
                    member.cert_version = Some(read_minimal_uint(&mut m)?);
                    m.finish()?;
                }
                oid::CAT_MEMBERINFO2 => {
                    asn1::validate(&values)?;
                    member.member_info2 = true;
                }
                other => {
                    asn1::validate(&values)?;
                    warnings.push(CtlWarning::UnknownAttribute(ObjectId::from_der(other)));
                }
            }
        }
    }
    // Kept for as long as the trust list is: no spare capacity.
    member.name_values.shrink_to_fit();
    match &member.digest {
        None if !seen_indirect => warnings.push(CtlWarning::NoDigest { member: index }),
        Some(d) if !member.tag.is_digest(&d.digest) => {
            warnings.push(CtlWarning::TagNotDigest { member: index });
        }
        _ => {}
    }
    Ok(member)
}

/// The single value of a member attribute.
fn single_value<'a>(attr_type: &[u8], values: &Tlv<'a>, member: usize) -> Result<Tlv<'a>> {
    let mut v = values.reader();
    let count_error = || CtlError::AttributeValueCount {
        member,
        attribute: ObjectId::from_der(attr_type),
    };
    if v.is_empty() {
        return Err(count_error());
    }
    let value = v.read_any()?;
    if !v.is_empty() {
        return Err(count_error());
    }
    Ok(value)
}

/// `SpcIndirectDataContent ::= SEQUENCE { data
/// SpcAttributeTypeAndOptionalValue, messageDigest DigestInfo }`. Returns
/// `None` (with a warning) for an unknown digest algorithm.
fn parse_member_digest(
    value: &Tlv<'_>,
    member: usize,
    warnings: &mut Warnings,
) -> Result<Option<MemberDigest>> {
    let mut r = value.expect(tag::SEQUENCE)?.reader();
    let data = r.read(tag::SEQUENCE)?;
    let mut d = data.reader();
    let data_type = read_oid(&mut d)?;
    if !d.is_empty() {
        // The type's value is checked as DER, not interpreted.
        asn1::validate(&d.read_any()?)?;
    }
    d.finish()?;
    let digest_info = r.read(tag::SEQUENCE)?;
    let mut di = digest_info.reader();
    let alg = parse_digest_alg(&di.read(tag::SEQUENCE)?)?;
    let digest = di.read(tag::OCTET_STRING)?.content;
    di.finish()?;
    r.finish()?;
    match alg {
        Ok(alg) if digest.len() != alg.digest_len() => Err(CtlError::DigestLength { member }),
        Ok(alg) => Ok(Some(MemberDigest {
            alg,
            digest: digest.to_vec(),
            data_type: ObjectId::from_der(data_type),
        })),
        Err(alg) => {
            warnings.push(CtlWarning::UnknownDigest { member, alg });
            Ok(None)
        }
    }
}

/// `SEQUENCE { tag BMPString, flags INTEGER, value OCTET STRING }`.
fn parse_name_value(nv: &Tlv<'_>, warnings: &mut Warnings) -> Result<NameValue> {
    let mut r = nv.expect(tag::SEQUENCE)?.reader();
    let name = r.read(tag::BMP_STRING)?;
    let name_text = asn1::bmp_text(name.content, name.offset)?;
    if name_text.truncated {
        warnings.push(CtlWarning::Truncated);
    }
    let flags = read_minimal_uint(&mut r)?;
    let value = r.read(tag::OCTET_STRING)?.content;
    r.finish()?;
    let value = if flags & NameValue::DATA_BASE64 != 0 {
        let kept = value.get(..MAX_VALUE_BYTES).unwrap_or(value);
        if kept.len() < value.len() {
            warnings.push(CtlWarning::Truncated);
        }
        NameValueData::Bytes(kept.to_vec())
    } else {
        NameValueData::Text(utf16le_text(value, warnings))
    };
    Ok(NameValue {
        name: name_text.text,
        flags,
        value,
    })
}

/// Decodes UTF-16LE text up to the first NUL unit, keeping at most
/// [`MAX_VALUE_BYTES`] bytes and [`asn1::MAX_TEXT_CHARS`] characters (a
/// [`CtlWarning::Truncated`] warning otherwise). An odd trailing byte or an
/// unpaired surrogate becomes U+FFFD, with a [`CtlWarning::LossyText`]
/// warning.
fn utf16le_text(bytes: &[u8], warnings: &mut Warnings) -> String {
    let end = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .position(|pair| pair == &[0, 0])
        .map_or(bytes.len(), |units| units.saturating_mul(2));
    let body = bytes.get(..end).unwrap_or_default();
    let mut truncated = body.len() > MAX_VALUE_BYTES;
    let body = body.get(..MAX_VALUE_BYTES).unwrap_or(body);
    let mut units: Vec<u16> = body
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes(*pair))
        .collect();
    // A cut at the byte limit can split a surrogate pair: drop its first
    // half rather than report the text as ill-formed.
    if truncated && units.last().is_some_and(|u| (0xd800..0xdc00).contains(u)) {
        units.pop();
    }
    let mut text = String::new();
    let mut lossy = false;
    for (count, c) in char::decode_utf16(units).enumerate() {
        if count >= asn1::MAX_TEXT_CHARS {
            truncated = true;
            break;
        }
        text.push(c.unwrap_or_else(|_| {
            lossy = true;
            char::REPLACEMENT_CHARACTER
        }));
    }
    if !truncated && body.len() % 2 == 1 {
        lossy = true;
        text.push(char::REPLACEMENT_CHARACTER);
    }
    if lossy {
        warnings.push(CtlWarning::LossyText);
    }
    if truncated {
        warnings.push(CtlWarning::Truncated);
    }
    text
}

/// Whether `tag` is the uppercase hex of `digest` (lowercase is accepted
/// too: the OS compares tags case-insensitively).
fn tag_is_hex_of(tag: &str, digest: &[u8]) -> bool {
    const DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    let bytes = tag.as_bytes();
    if bytes.len() != digest.len().saturating_mul(2) {
        return false;
    }
    digest
        .iter()
        .zip(bytes.as_chunks::<2>().0)
        .all(|(b, [h, l])| {
            let hi = DIGITS.get(usize::from(b >> 4)).copied();
            let lo = DIGITS.get(usize::from(b & 0x0f)).copied();
            Some(h.to_ascii_uppercase()) == hi && Some(l.to_ascii_uppercase()) == lo
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(bytes: &[u8]) -> (String, Vec<CtlWarning>) {
        let mut w = Warnings::default();
        let t = utf16le_text(bytes, &mut w);
        (t, w.0)
    }

    fn le(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    #[test]
    fn utf16le_stops_at_nul() {
        let mut b = le("AB");
        b.extend([0, 0]);
        b.extend(le("CD"));
        assert_eq!(text(&b), ("AB".to_owned(), vec![]));
        assert_eq!(text(&le("x")), ("x".to_owned(), vec![]));
        assert_eq!(text(&[]), (String::new(), vec![]));
    }

    #[test]
    fn utf16le_odd_and_surrogates_are_lossy() {
        let (t, w) = text(&[b'A', 0, b'B']);
        assert_eq!(t, "A\u{fffd}");
        assert_eq!(w, [CtlWarning::LossyText]);
        let (t, w) = text(&[0x00, 0xd8, b'A', 0]);
        assert_eq!(t, "\u{fffd}A");
        assert_eq!(w, [CtlWarning::LossyText]);
        // A real pair decodes.
        assert_eq!(text(&le("\u{1f600}")).0, "\u{1f600}");
    }

    #[test]
    fn utf16le_is_bounded() {
        let long = le(&"a".repeat(asn1::MAX_TEXT_CHARS + 10));
        let (t, w) = text(&long);
        assert_eq!(t.chars().count(), asn1::MAX_TEXT_CHARS);
        assert_eq!(w, [CtlWarning::Truncated]);
        // Exactly at the limit, NUL-terminated: not truncated.
        let mut exact = le(&"a".repeat(asn1::MAX_TEXT_CHARS));
        exact.extend([0, 0]);
        let (t, w) = text(&exact);
        assert_eq!(t.len(), asn1::MAX_TEXT_CHARS);
        assert_eq!(w, []);
    }

    #[test]
    fn tag_hex_comparison() {
        assert!(tag_is_hex_of("0AFF", &[0x0a, 0xff]));
        assert!(tag_is_hex_of("0aff", &[0x0a, 0xff]));
        assert!(!tag_is_hex_of("0AFE", &[0x0a, 0xff]));
        assert!(!tag_is_hex_of("0AF", &[0x0a, 0xff]));
        assert!(!tag_is_hex_of("\u{e9}\u{e9}", &[0x0a]));
    }

    #[test]
    fn known_oids_encode_their_dotted_form() {
        let check = |der: &[u8], dotted: &str| {
            assert_eq!(ObjectId::from_der(der).to_string(), dotted);
        };
        check(oid::CTL, "1.3.6.1.4.1.311.10.1");
        check(oid::CATALOG_LIST, "1.3.6.1.4.1.311.12.1.1");
        check(oid::CATALOG_LIST_MEMBER, "1.3.6.1.4.1.311.12.1.2");
        check(oid::CATALOG_LIST_MEMBER2, "1.3.6.1.4.1.311.12.1.3");
        check(oid::SPC_INDIRECT_DATA, "1.3.6.1.4.1.311.2.1.4");
        check(oid::SPC_PE_IMAGE_DATA, "1.3.6.1.4.1.311.2.1.15");
        check(oid::CAT_NAMEVALUE, "1.3.6.1.4.1.311.12.2.1");
        check(oid::CAT_MEMBERINFO, "1.3.6.1.4.1.311.12.2.2");
        check(oid::CAT_MEMBERINFO2, "1.3.6.1.4.1.311.12.2.3");
    }
}
