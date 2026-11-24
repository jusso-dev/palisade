//! X.509 certificates (#49): a strict DER parser that extracts every
//! attribute signer rules match on, as plain data.
//!
//! Every byte is read through the strict reader in `asn1.rs`. The parser
//! hashes the exact `tbsCertificate` bytes found in the certificate and
//! never re-encodes them, so the TBS hash is the one the OS records.

#![forbid(unsafe_code)]

use std::collections::HashSet;
use std::fmt;

use serde::{Serialize, Serializer};

use super::asn1::{self, Asn1Error, Asn1ErrorKind, ObjectId, Tlv, oid, read_oid, tag};
use super::crypto::{self, PublicKey, Verified};
use super::eku::Eku;
use super::pkcs7::{self, CertKey};
use super::signature::{
    DigestAlgorithm, KeyAlgorithm, SignatureAlgorithm, SignatureError, Unsupported,
};
use super::verify;
use crate::hash::{AlgorithmSet, HashAlgorithm, hash_bytes};

/// Why a certificate could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum CertificateError {
    /// The DER encoding is invalid, or a field has the wrong structure.
    Asn1(Asn1Error),
    /// The version is not v1, v2 or v3.
    UnsupportedVersion(u32),
    /// A field the certificate's version does not allow: extensions before
    /// v3, or unique identifiers in a v1 certificate.
    FieldNotAllowed,
    /// An extension appears more than once (RFC 5280, 4.2).
    DuplicateExtension(ObjectId),
    /// The outer `signatureAlgorithm` differs from the `signature` field
    /// inside the TBS certificate (RFC 5280, 4.1.1.2).
    SignatureAlgorithmMismatch,
    /// An algorithm identifier has parameters where none are allowed, or
    /// invalid ones.
    AlgorithmParameters,
}

impl fmt::Display for CertificateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Asn1(e) => write!(f, "invalid DER: {e}"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported certificate version {v}"),
            Self::FieldNotAllowed => f.write_str("a field the certificate version does not allow"),
            Self::DuplicateExtension(o) => write!(f, "extension {o} appears twice"),
            Self::SignatureAlgorithmMismatch => {
                f.write_str("signatureAlgorithm differs from the TBS signature field")
            }
            Self::AlgorithmParameters => f.write_str("invalid algorithm parameters"),
        }
    }
}

impl std::error::Error for CertificateError {}

impl From<Asn1Error> for CertificateError {
    fn from(e: Asn1Error) -> Self {
        Self::Asn1(e)
    }
}

impl From<SignatureError> for CertificateError {
    fn from(e: SignatureError) -> Self {
        match e {
            SignatureError::Asn1(e) => Self::Asn1(e),
            _ => Self::AlgorithmParameters,
        }
    }
}

type Result<T> = std::result::Result<T, CertificateError>;

/// A typed name attribute: the components signer rules match on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AttributeKind {
    /// `CN`, 2.5.4.3.
    CommonName,
    /// `SN`, 2.5.4.4 (surname).
    Surname,
    /// `serialNumber`, 2.5.4.5 (a registration number, not the
    /// certificate serial).
    SerialNumber,
    /// `C`, 2.5.4.6.
    Country,
    /// `L`, 2.5.4.7.
    Locality,
    /// `S` or `ST`, 2.5.4.8.
    State,
    /// `STREET`, 2.5.4.9.
    Street,
    /// `O`, 2.5.4.10.
    Organization,
    /// `OU`, 2.5.4.11.
    OrganizationalUnit,
    /// `T`, 2.5.4.12.
    Title,
    /// `businessCategory`, 2.5.4.15.
    BusinessCategory,
    /// `PostalCode`, 2.5.4.17.
    PostalCode,
    /// `G`, 2.5.4.42.
    GivenName,
    /// `I`, 2.5.4.43.
    Initials,
    /// `E`, 1.2.840.113549.1.9.1.
    Email,
    /// `DC`, 0.9.2342.19200300.100.1.25.
    DomainComponent,
    /// `jurisdictionL`, 1.3.6.1.4.1.311.60.2.1.1 (extended validation).
    JurisdictionLocality,
    /// `jurisdictionST`, 1.3.6.1.4.1.311.60.2.1.2 (extended validation).
    JurisdictionState,
    /// `jurisdictionC`, 1.3.6.1.4.1.311.60.2.1.3 (extended validation).
    JurisdictionCountry,
}

impl AttributeKind {
    const TABLE: [(Self, &'static [u8], Option<&'static str>); 19] = [
        (Self::CommonName, oid::AT_COMMON_NAME, Some("CN")),
        (Self::Surname, oid::AT_SURNAME, Some("SN")),
        (
            Self::SerialNumber,
            oid::AT_SERIAL_NUMBER,
            Some("SERIALNUMBER"),
        ),
        (Self::Country, oid::AT_COUNTRY, Some("C")),
        (Self::Locality, oid::AT_LOCALITY, Some("L")),
        (Self::State, oid::AT_STATE, Some("S")),
        (Self::Street, oid::AT_STREET, Some("STREET")),
        (Self::Organization, oid::AT_ORGANIZATION, Some("O")),
        (
            Self::OrganizationalUnit,
            oid::AT_ORGANIZATIONAL_UNIT,
            Some("OU"),
        ),
        (Self::Title, oid::AT_TITLE, Some("T")),
        (Self::BusinessCategory, oid::AT_BUSINESS_CATEGORY, None),
        (Self::PostalCode, oid::AT_POSTAL_CODE, Some("PostalCode")),
        (Self::GivenName, oid::AT_GIVEN_NAME, Some("G")),
        (Self::Initials, oid::AT_INITIALS, Some("I")),
        (Self::Email, oid::AT_EMAIL, Some("E")),
        (Self::DomainComponent, oid::AT_DOMAIN_COMPONENT, Some("DC")),
        (
            Self::JurisdictionLocality,
            oid::AT_JURISDICTION_LOCALITY,
            None,
        ),
        (Self::JurisdictionState, oid::AT_JURISDICTION_STATE, None),
        (
            Self::JurisdictionCountry,
            oid::AT_JURISDICTION_COUNTRY,
            None,
        ),
    ];

    fn from_oid(id: &[u8]) -> Option<Self> {
        Self::TABLE
            .iter()
            .find(|(_, o, _)| *o == id)
            .map(|(k, _, _)| *k)
    }

    /// The label OS tooling uses in a rendered DN (`CN`, `O`, `S` and so
    /// on). `None` for attributes it renders as `OID.<dotted>`.
    #[must_use]
    pub fn os_label(self) -> Option<&'static str> {
        Self::TABLE
            .iter()
            .find(|(k, _, _)| *k == self)
            .and_then(|(_, _, label)| *label)
    }
}

/// One attribute of a distinguished name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NameAttribute {
    /// The attribute type.
    pub oid: ObjectId,
    /// The typed component, if the type is one of [`AttributeKind`].
    pub kind: Option<AttributeKind>,
    /// The decoded value. A NUL or other control character is kept, never
    /// treated as the end of the value. A value that is not a string type
    /// is shown as `#` and the hex of its DER encoding (RFC 4514).
    pub value: String,
    /// `true` when [`Self::value`] is not an exact decoding: invalid UTF-8,
    /// a non-ASCII byte in an ASCII string type, a character outside a
    /// restricted string type's repertoire, a surrogate in a BMPString, an
    /// invalid code point, or a value that is not a string at all. Such
    /// values must not be used as
    /// identities, because different encodings can decode to the same
    /// text.
    pub lossy: bool,
}

impl NameAttribute {
    /// Whether the value is an exact decoding, not empty or only
    /// whitespace, with no control characters, so it is safe to match as an
    /// identity string.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        !self.lossy && !self.value.trim().is_empty() && !self.value.chars().any(char::is_control)
    }
}

/// A distinguished name (`subject` or `issuer`), as ordered RDNs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DistinguishedName {
    /// The `Name` exactly as encoded, tag and length included. Chain
    /// building compares names by these bytes.
    #[serde(serialize_with = "serialize_hex")]
    pub der: Vec<u8>,
    /// The RDNs in encoded order; each holds one attribute or more (a
    /// multi-valued RDN).
    pub rdns: Vec<Vec<NameAttribute>>,
    /// The DN as OS tooling renders it: RDNs in reverse encoded order, so a
    /// name encoded `C, S, L, O, CN` reads `CN=…, O=…, L=…, S=…, C=…`.
    /// See [`DistinguishedName::render`].
    pub canonical: String,
}

impl DistinguishedName {
    /// Every attribute, in encoded order.
    pub fn attributes(&self) -> impl Iterator<Item = &NameAttribute> {
        self.rdns.iter().flatten()
    }

    /// Every attribute of `kind`, in encoded order.
    pub fn values(&self, kind: AttributeKind) -> impl Iterator<Item = &NameAttribute> {
        self.attributes().filter(move |a| a.kind == Some(kind))
    }

    /// The first attribute of `kind`, in encoded order.
    #[must_use]
    pub fn first(&self, kind: AttributeKind) -> Option<&NameAttribute> {
        self.values(kind).next()
    }

    /// The first `CN`.
    #[must_use]
    pub fn common_name(&self) -> Option<&str> {
        self.first(AttributeKind::CommonName)
            .map(|a| a.value.as_str())
    }

    /// The first `O`.
    #[must_use]
    pub fn organization(&self) -> Option<&str> {
        self.first(AttributeKind::Organization)
            .map(|a| a.value.as_str())
    }

    /// Renders RDNs as OS tooling does: in reverse encoded order, separated
    /// by `, `, with the attributes of a multi-valued RDN joined by ` + `.
    /// Each attribute is `LABEL=value`, with the [`AttributeKind::os_label`]
    /// or `OID.<dotted>`. A value that is empty, starts or ends with a
    /// space, or contains `,` `+` `=` `"` `<` `>` `#` `;` or a line break is
    /// wrapped in double quotes, with any `"` doubled.
    #[must_use]
    pub fn render(rdns: &[Vec<NameAttribute>]) -> String {
        let mut out = String::new();
        for (i, rdn) in rdns.iter().rev().enumerate() {
            if i > 0 {
                out.push_str(", ");
            }
            for (j, attr) in rdn.iter().enumerate() {
                if j > 0 {
                    out.push_str(" + ");
                }
                match attr.kind.and_then(AttributeKind::os_label) {
                    Some(label) => out.push_str(label),
                    None => {
                        out.push_str("OID.");
                        out.push_str(&attr.oid.to_string());
                    }
                }
                out.push('=');
                push_quoted(&mut out, &attr.value);
            }
        }
        out
    }
}

impl fmt::Display for DistinguishedName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.canonical)
    }
}

fn push_quoted(out: &mut String, value: &str) {
    let needs_quotes = value.is_empty()
        || value.starts_with(' ')
        || value.ends_with(' ')
        || value.chars().any(|c| {
            matches!(
                c,
                ',' | '+' | '=' | '"' | '<' | '>' | '#' | ';' | '\n' | '\r'
            )
        });
    if needs_quotes {
        out.push('"');
        for c in value.chars() {
            if c == '"' {
                out.push('"');
            }
            out.push(c);
        }
        out.push('"');
    } else {
        out.push_str(value);
    }
}

/// The `basicConstraints` extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub struct BasicConstraints {
    /// `cA`: the subject may issue certificates.
    pub ca: bool,
    /// `pathLenConstraint`: the most non-self-issued intermediate CA
    /// certificates that may follow this one in a path.
    pub path_len: Option<u32>,
}

/// The `keyUsage` extension, as its bits (ASN.1 bit 0, `digitalSignature`,
/// is the most significant bit of the `u16`). Serialised as the list of
/// usage names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeyUsage(pub u16);

impl KeyUsage {
    /// Every usage, with its name, in bit order.
    pub const NAMES: [&'static str; 9] = [
        "digital_signature",
        "non_repudiation",
        "key_encipherment",
        "data_encipherment",
        "key_agreement",
        "key_cert_sign",
        "crl_sign",
        "encipher_only",
        "decipher_only",
    ];
    /// `digitalSignature` (bit 0).
    pub const DIGITAL_SIGNATURE: u16 = 0x8000;
    /// `keyCertSign` (bit 5).
    pub const KEY_CERT_SIGN: u16 = 0x0400;
    /// `cRLSign` (bit 6).
    pub const CRL_SIGN: u16 = 0x0200;

    /// Whether every bit of `mask` is set.
    #[must_use]
    pub const fn contains(self, mask: u16) -> bool {
        self.0 & mask == mask
    }

    /// The names of the usages set, in bit order. Bits after
    /// `decipherOnly` (bit 8) are not named.
    pub fn names(self) -> impl Iterator<Item = &'static str> {
        Self::NAMES
            .iter()
            .enumerate()
            .filter(move |(i, _)| self.0 & (0x8000_u16 >> i) != 0)
            .map(|(_, name)| *name)
    }
}

impl Serialize for KeyUsage {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.collect_seq(self.names())
    }
}

impl Serialize for ObjectId {
    /// Dotted-decimal form, such as `"1.3.6.1.5.5.7.3.3"`.
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

/// Everything about one X.509 certificate that signer rules match on.
///
/// Field names are stable: they are the JSON names, and they follow the
/// names used in issue #49. Hashes, thumbprints, key identifiers and the
/// serial are lowercase hex; times are seconds since the Unix epoch (UTC).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CertSummary {
    /// 1, 2 or 3.
    pub version: u8,
    /// The serial number's INTEGER content octets as encoded, in hex.
    pub serial: String,
    /// The subject.
    pub subject: DistinguishedName,
    /// The issuer.
    pub issuer: DistinguishedName,
    /// `notBefore`.
    pub not_before: i64,
    /// `notAfter`.
    pub not_after: i64,
    /// The algorithm the issuer signed this certificate with.
    pub sig_alg: SignatureAlgorithm,
    /// The subject key's algorithm (with the curve, for EC keys).
    pub public_key_alg: KeyAlgorithm,
    /// The key size in bits: the RSA modulus, or the curve size.
    pub key_bits: Option<u32>,
    /// SHA-1 of the whole certificate (the classic thumbprint).
    pub sha1_thumbprint: String,
    /// SHA-256 of the whole certificate.
    pub sha256_thumbprint: String,
    /// SHA-256 of the DER `subjectPublicKeyInfo`: identifies the key,
    /// whatever certificate carries it.
    pub spki_sha256: String,
    /// The hash of the DER `tbsCertificate`, exactly as encoded, under the
    /// digest of [`Self::sig_alg`]: 40 hex characters for SHA-1, 64 for
    /// SHA-256, 96 for SHA-384 and 128 for SHA-512. This is the value OS
    /// code integrity signer rules and events use. `None` when the
    /// signature algorithm has no SHA digest (MD5, Ed25519, unknown).
    pub tbs_hash: Option<String>,
    /// The digest [`Self::tbs_hash`] uses.
    pub tbs_hash_alg: Option<DigestAlgorithm>,
    /// SHA-256 of the DER `tbsCertificate`, always: a uniform identity.
    pub tbs_hash_sha256: String,
    /// The `subjectKeyIdentifier` extension.
    pub subject_key_id: Option<String>,
    /// The `keyIdentifier` of the `authorityKeyIdentifier` extension.
    pub authority_key_id: Option<String>,
    /// The `basicConstraints` extension.
    pub basic_constraints: Option<BasicConstraints>,
    /// The `keyUsage` extension.
    pub key_usage: Option<KeyUsage>,
    /// The `extKeyUsage` extension, every OID in encoded order. `None` when
    /// the extension is absent.
    pub extended_key_usage: Option<Vec<Eku>>,
    /// The policy OIDs of the `certificatePolicies` extension.
    pub certificate_policies: Vec<ObjectId>,
    /// The URIs of the `cRLDistributionPoints` extension's full names.
    pub crl_distribution_points: Vec<String>,
    /// The OCSP URIs of the `authorityInfoAccess` extension.
    pub ocsp_urls: Vec<String>,
    /// The `caIssuers` URIs of the `authorityInfoAccess` extension.
    pub ca_issuers_urls: Vec<String>,
    /// The subject equals the issuer and the certificate's signature
    /// verifies with its own key.
    pub is_self_signed: bool,
    /// Critical extensions this crate does not process. A certificate with
    /// any is not used in a chain (RFC 5280, 4.2).
    pub unhandled_critical_extensions: Vec<ObjectId>,
    /// The whole certificate, DER. Serialised as base64.
    #[serde(serialize_with = "serialize_base64")]
    pub der: Vec<u8>,
}

impl CertSummary {
    /// Parses one DER certificate. `der` must be exactly the certificate,
    /// with nothing after it.
    pub fn from_der(der: &[u8]) -> Result<Self> {
        parse_within(der, &mut Budget::new(1))
    }

    /// The certificate in PEM form: `-----BEGIN CERTIFICATE-----`, the DER
    /// in base64 in lines of 64 characters, `-----END CERTIFICATE-----`,
    /// each line ending in `\n`.
    #[must_use]
    pub fn pem(&self) -> String {
        let body = base64(&self.der);
        let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
        for line in body.as_bytes().chunks(64) {
            out.push_str(std::str::from_utf8(line).unwrap_or_default());
            out.push('\n');
        }
        out.push_str("-----END CERTIFICATE-----\n");
        out
    }

    /// Whether the `extKeyUsage` extension lists `eku`.
    #[must_use]
    pub fn has_eku(&self, eku: &ObjectId) -> bool {
        self.extended_key_usage
            .as_ref()
            .is_some_and(|list| list.iter().any(|e| e.oid == *eku))
    }

    /// Whether this certificate permits `eku`: it has no `extKeyUsage`
    /// extension (any usage), or the extension lists `eku` or
    /// `anyExtendedKeyUsage`.
    #[must_use]
    pub fn permits_eku(&self, eku: &ObjectId) -> bool {
        self.extended_key_usage.as_ref().is_none_or(|list| {
            list.iter()
                .any(|e| e.oid == *eku || e.oid.as_bytes() == super::eku::ANY.oid)
        })
    }
}

fn serialize_hex<S: Serializer>(bytes: &[u8], s: S) -> std::result::Result<S::Ok, S::Error> {
    s.serialize_str(&hex(bytes))
}

fn serialize_base64<S: Serializer>(bytes: &[u8], s: S) -> std::result::Result<S::Ok, S::Error> {
    s.serialize_str(&base64(bytes))
}

/// Lowercase hex.
pub(crate) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        for nibble in [b >> 4, b & 0x0f] {
            out.push(char::from(
                DIGITS.get(usize::from(nibble)).copied().unwrap_or(b'0'),
            ));
        }
    }
    out
}

/// Standard base64 (RFC 4648, section 4) with padding.
fn base64(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let sextet = |v: u32| char::from(TABLE.get((v & 0x3f) as usize).copied().unwrap_or(b'A'));
    let mut out = String::with_capacity(bytes.len().div_ceil(3).saturating_mul(4));
    for chunk in bytes.chunks(3) {
        let b = |i: usize| u32::from(chunk.get(i).copied().unwrap_or(0));
        let v = (b(0) << 16) | (b(1) << 8) | b(2);
        out.push(sextet(v >> 18));
        out.push(sextet(v >> 12));
        out.push(if chunk.len() > 1 { sextet(v >> 6) } else { '=' });
        out.push(if chunk.len() > 2 { sextet(v) } else { '=' });
    }
    out
}

/// The borrowed parts of a certificate that signature checks need.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Raw<'a> {
    /// The DER `tbsCertificate`, as encoded: what the issuer signed.
    pub tbs: &'a [u8],
    /// The `signatureValue` octets.
    pub signature: &'a [u8],
    /// The subject key, if it is one the crypto module can verify with.
    pub key: Option<CertKey<'a>>,
}

/// The fields of a certificate, borrowed and structurally checked, but not
/// decoded.
struct Walked<'a> {
    raw: Raw<'a>,
    version: u32,
    serial: &'a [u8],
    sig_alg: Tlv<'a>,
    issuer: Tlv<'a>,
    not_before: i64,
    not_after: i64,
    subject: Tlv<'a>,
    /// The DER `subjectPublicKeyInfo`.
    spki: &'a [u8],
    key_alg: KeyAlgorithm,
    key_bits: Option<u32>,
    extensions: Option<Tlv<'a>>,
}

/// Walks the structure of one DER certificate. `der` must be exactly the
/// certificate. Checks everything structural: DER, field order, the version
/// rules for unique identifiers and extensions, and that the two signature
/// algorithm fields agree.
fn walk(der: &[u8]) -> Result<Walked<'_>> {
    let cert = asn1::single(der, 0, tag::SEQUENCE)?;
    let mut c = cert.reader();
    let tbs = c.read(tag::SEQUENCE)?;
    let outer_alg = c.read(tag::SEQUENCE)?;
    let signature = asn1::bit_string_octets(&c.read(tag::BIT_STRING)?)?;
    c.finish()?;

    let mut t = tbs.reader();
    let version = match t.read_optional(tag::context_cons(0))? {
        Some(explicit) => {
            let mut v = explicit.reader();
            let n = asn1::read_small_uint(&mut v)?;
            v.finish()?;
            // DER omits a DEFAULT value: v1 has no explicit version.
            if n == 0 {
                return Err(explicit.error(Asn1ErrorKind::InvalidValue).into());
            }
            n
        }
        None => 0,
    };
    if version > 2 {
        return Err(CertificateError::UnsupportedVersion(
            version.saturating_add(1),
        ));
    }
    let serial = asn1::integer_bytes(&t.read(tag::INTEGER)?)?;
    let sig_alg = t.read(tag::SEQUENCE)?;
    if sig_alg.raw != outer_alg.raw {
        return Err(CertificateError::SignatureAlgorithmMismatch);
    }
    let issuer = t.read(tag::SEQUENCE)?;
    let validity = t.read(tag::SEQUENCE)?;
    let mut v = validity.reader();
    let not_before = asn1::time(&v.read_any()?)?;
    let not_after = asn1::time(&v.read_any()?)?;
    v.finish()?;
    let subject = t.read(tag::SEQUENCE)?;
    let spki = t.read(tag::SEQUENCE)?;
    for unique_id in [tag::context_prim(1), tag::context_prim(2)] {
        if let Some(id) = t.read_optional(unique_id)? {
            if version == 0 {
                return Err(CertificateError::FieldNotAllowed);
            }
            implicit_bit_string(&id)?;
        }
    }
    let extensions = match t.read_optional(tag::context_cons(3))? {
        Some(explicit) => {
            if version != 2 {
                return Err(CertificateError::FieldNotAllowed);
            }
            Some(asn1::single(
                explicit.content,
                explicit.content_offset,
                tag::SEQUENCE,
            )?)
        }
        None => None,
    };
    t.finish()?;
    let (key_alg, key_bits, key) = pkcs7::parse_spki(&spki)?;
    Ok(Walked {
        raw: Raw {
            tbs: tbs.raw,
            signature,
            key,
        },
        version,
        serial,
        sig_alg,
        issuer,
        not_before,
        not_after,
        subject,
        spki: spki.raw,
        key_alg,
        key_bits,
        extensions,
    })
}

/// Checks an `[n] IMPLICIT BIT STRING`: an unused-bits count of 0 to 7,
/// at least one content octet when it is not 0, and zero unused bits
/// (X.690 11.2.1).
fn implicit_bit_string(tlv: &Tlv<'_>) -> Result<()> {
    let invalid = || CertificateError::Asn1(tlv.error(Asn1ErrorKind::InvalidValue));
    let (unused, rest) = tlv.content.split_first().ok_or_else(invalid)?;
    match (unused, rest.last()) {
        (0, _) => Ok(()),
        (1..=7, Some(last)) if last & ((1_u8 << unused) - 1) == 0 => Ok(()),
        _ => Err(invalid()),
    }
}

/// A count of certificate signatures that may still be verified. Running
/// out never makes a result more trusted: a link not checked is not made,
/// and a certificate whose self-signature was not checked is not
/// self-signed.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Budget {
    left: usize,
    used: usize,
    /// A check was wanted after the budget ran out.
    pub exhausted: bool,
}

impl Budget {
    /// A budget of `checks` verifications.
    pub const fn new(checks: usize) -> Self {
        Self {
            left: checks,
            used: 0,
            exhausted: false,
        }
    }

    /// Spends one verification. `false`, and marks the budget exhausted,
    /// when none is left.
    pub fn take(&mut self) -> bool {
        if self.left == 0 {
            self.exhausted = true;
            false
        } else {
            self.left -= 1;
            self.used += 1;
            true
        }
    }

    /// How many verifications were spent.
    pub const fn used(&self) -> usize {
        self.used
    }

    /// How many verifications are left.
    pub const fn left(&self) -> usize {
        self.left
    }

    /// Records that `inner`, a budget carved out of this one, was spent.
    pub fn absorb(&mut self, inner: &Self) {
        let n = inner.used.min(self.left);
        self.left -= n;
        self.used += n;
        self.exhausted |= inner.exhausted;
    }
}

/// The borrowed parts of `der` that signature checks need. Walks the
/// structure again, without decoding names or hashing.
pub(crate) fn split(der: &[u8]) -> Result<Raw<'_>> {
    walk(der).map(|w| w.raw)
}

/// Checks that the key in `issuer` made the signature on `child`, a
/// certificate whose signature algorithm is `alg`.
pub(crate) fn check_signed_by(
    child: &Raw<'_>,
    alg: &SignatureAlgorithm,
    issuer: &Raw<'_>,
    issuer_key_alg: &KeyAlgorithm,
) -> Verified {
    let digest = match alg {
        SignatureAlgorithm::RsaPkcs1(d) | SignatureAlgorithm::Ecdsa(d) => *d,
        SignatureAlgorithm::RsaPss { digest, .. } => *digest,
        other => return Verified::Unsupported(Unsupported::SignatureAlgorithm(other.clone())),
    };
    let scheme = match verify::scheme(alg, digest) {
        Ok(scheme) => scheme,
        Err(why) => return Verified::Unsupported(why),
    };
    let key = match issuer.key {
        Some(CertKey::Rsa { der, bits }) => PublicKey::Rsa { der, bits },
        Some(CertKey::Ec { curve, point }) => PublicKey::Ec { curve, point },
        None => return Verified::Unsupported(Unsupported::KeyAlgorithm(issuer_key_alg.clone())),
    };
    crypto::verify(scheme, key, child.tbs, child.signature)
}

/// Parses one DER certificate into its summary. Checking a self-issued
/// certificate's own signature costs one unit of `budget`; with none left,
/// the certificate is reported as not self-signed, which can only make a
/// chain look less complete, never more trusted.
pub(crate) fn parse_within(der: &[u8], budget: &mut Budget) -> Result<CertSummary> {
    let w = walk(der)?;
    let sig_alg = signature_algorithm(&w.sig_alg)?;
    let issuer = parse_name(&w.issuer)?;
    let subject = parse_name(&w.subject)?;
    let (public_key_alg, key_bits) = (w.key_alg.clone(), w.key_bits);
    let mut ext = Extensions::default();
    if let Some(list) = &w.extensions {
        parse_extensions(list, &mut ext)?;
    }

    let thumbprints = hash_bytes(der, AlgorithmSet::SHA1 | AlgorithmSet::SHA256);
    let hex_of = |hashes: &crate::hash::FlatHashes, alg: HashAlgorithm| {
        hashes.get(alg).map(ToString::to_string).unwrap_or_default()
    };
    let tbs_hash_alg =
        signature_digest(&sig_alg).filter(|d| matches!(d, DigestAlgorithm::Sha1) || d.is_sha2());
    let own = tbs_hash_alg.and_then(DigestAlgorithm::hash_algorithm);
    let mut tbs_set = AlgorithmSet::SHA256;
    if let Some(alg) = own {
        tbs_set.insert(alg);
    }
    let tbs_hashes = hash_bytes(w.raw.tbs, tbs_set);
    let self_signed = subject.der == issuer.der
        && budget.take()
        && check_signed_by(&w.raw, &sig_alg, &w.raw, &public_key_alg) == Verified::Valid;

    Ok(CertSummary {
        version: u8::try_from(w.version.saturating_add(1)).unwrap_or(u8::MAX),
        serial: hex(w.serial),
        subject,
        issuer,
        not_before: w.not_before,
        not_after: w.not_after,
        sig_alg,
        public_key_alg,
        key_bits,
        sha1_thumbprint: hex_of(&thumbprints, HashAlgorithm::Sha1),
        sha256_thumbprint: hex_of(&thumbprints, HashAlgorithm::Sha256),
        spki_sha256: hex_of(
            &hash_bytes(w.spki, AlgorithmSet::SHA256),
            HashAlgorithm::Sha256,
        ),
        tbs_hash: own.map(|alg| hex_of(&tbs_hashes, alg)),
        tbs_hash_alg,
        tbs_hash_sha256: hex_of(&tbs_hashes, HashAlgorithm::Sha256),
        subject_key_id: ext.subject_key_id,
        authority_key_id: ext.authority_key_id,
        basic_constraints: ext.basic_constraints,
        key_usage: ext.key_usage,
        extended_key_usage: ext.extended_key_usage,
        certificate_policies: ext.certificate_policies,
        crl_distribution_points: ext.crl_distribution_points,
        ocsp_urls: ext.ocsp_urls,
        ca_issuers_urls: ext.ca_issuers_urls,
        is_self_signed: self_signed,
        unhandled_critical_extensions: ext.unhandled_critical,
        der: der.to_vec(),
    })
}

/// The digest a signature algorithm hashes with, if it names one.
pub(crate) fn signature_digest(alg: &SignatureAlgorithm) -> Option<DigestAlgorithm> {
    match alg {
        SignatureAlgorithm::RsaPkcs1(d) | SignatureAlgorithm::Ecdsa(d) => Some(*d),
        SignatureAlgorithm::RsaPss { digest, .. } => Some(*digest),
        _ => None,
    }
}

/// A certificate's `signatureAlgorithm`.
pub(crate) fn signature_algorithm(id: &Tlv<'_>) -> Result<SignatureAlgorithm> {
    let mut r = id.reader();
    let alg = read_oid(&mut r)?;
    let params = if r.is_empty() {
        None
    } else {
        Some(r.read_any()?)
    };
    r.finish()?;
    if let Some(p) = &params {
        asn1::validate(p)?;
    }
    // RSA PKCS #1 identifiers take NULL parameters (RFC 4055 allows them
    // absent too); ECDSA identifiers take none at all (RFC 5758, 3.2).
    let null_or_absent = params
        .as_ref()
        .is_none_or(|p| p.tag == tag::NULL && p.content.is_empty());
    let rsa = |digest| {
        if null_or_absent {
            Ok(SignatureAlgorithm::RsaPkcs1(digest))
        } else {
            Err(CertificateError::AlgorithmParameters)
        }
    };
    let ecdsa = |digest| {
        if params.is_none() {
            Ok(SignatureAlgorithm::Ecdsa(digest))
        } else {
            Err(CertificateError::AlgorithmParameters)
        }
    };
    match alg {
        oid::MD2_WITH_RSA => rsa(DigestAlgorithm::Md2),
        oid::MD5_WITH_RSA => rsa(DigestAlgorithm::Md5),
        oid::SHA1_WITH_RSA => rsa(DigestAlgorithm::Sha1),
        oid::SHA256_WITH_RSA => rsa(DigestAlgorithm::Sha256),
        oid::SHA384_WITH_RSA => rsa(DigestAlgorithm::Sha384),
        oid::SHA512_WITH_RSA => rsa(DigestAlgorithm::Sha512),
        oid::ECDSA_WITH_SHA1 => ecdsa(DigestAlgorithm::Sha1),
        oid::ECDSA_WITH_SHA256 => ecdsa(DigestAlgorithm::Sha256),
        oid::ECDSA_WITH_SHA384 => ecdsa(DigestAlgorithm::Sha384),
        oid::ECDSA_WITH_SHA512 => ecdsa(DigestAlgorithm::Sha512),
        oid::RSASSA_PSS => Ok(pkcs7::parse_pss_params(params.as_ref())?
            .unwrap_or_else(|| SignatureAlgorithm::Other(ObjectId::from_der(alg)))),
        oid::ED25519 | oid::ED448 if params.is_some() => Err(CertificateError::AlgorithmParameters),
        oid::ED25519 => Ok(SignatureAlgorithm::Ed25519),
        oid::ED448 => Ok(SignatureAlgorithm::Ed448),
        other => Ok(SignatureAlgorithm::Other(ObjectId::from_der(other))),
    }
}

/// `Name ::= SEQUENCE OF RelativeDistinguishedName`, each a non-empty
/// `SET OF AttributeTypeAndValue`.
pub(crate) fn parse_name(name: &Tlv<'_>) -> Result<DistinguishedName> {
    let mut rdns = Vec::new();
    let mut r = name.reader();
    while !r.is_empty() {
        let set = r.read(tag::SET)?;
        let mut s = set.reader();
        if s.is_empty() {
            return Err(set.error(Asn1ErrorKind::InvalidValue).into());
        }
        let mut rdn = Vec::new();
        while !s.is_empty() {
            let atv = s.read(tag::SEQUENCE)?;
            let mut a = atv.reader();
            let id = read_oid(&mut a)?;
            let value = a.read_any()?;
            a.finish()?;
            asn1::validate(&value)?;
            let (text, lossy) = match asn1::x509_text(&value)? {
                Some(decoded) => (decoded.text, decoded.lossy),
                None => (format!("#{}", hex(value.raw)), true),
            };
            rdn.push(NameAttribute {
                oid: ObjectId::from_der(id),
                kind: AttributeKind::from_oid(id),
                value: text,
                lossy,
            });
        }
        rdns.push(rdn);
    }
    Ok(DistinguishedName {
        der: name.raw.to_vec(),
        canonical: DistinguishedName::render(&rdns),
        rdns,
    })
}

#[derive(Default)]
struct Extensions {
    subject_key_id: Option<String>,
    authority_key_id: Option<String>,
    basic_constraints: Option<BasicConstraints>,
    key_usage: Option<KeyUsage>,
    extended_key_usage: Option<Vec<Eku>>,
    certificate_policies: Vec<ObjectId>,
    crl_distribution_points: Vec<String>,
    ocsp_urls: Vec<String>,
    ca_issuers_urls: Vec<String>,
    unhandled_critical: Vec<ObjectId>,
}

/// `Extensions ::= SEQUENCE SIZE (1..MAX) OF Extension`.
fn parse_extensions(list: &Tlv<'_>, ext: &mut Extensions) -> Result<()> {
    let mut l = list.reader();
    if l.is_empty() {
        return Err(list.error(Asn1ErrorKind::InvalidValue).into());
    }
    let mut seen = HashSet::new();
    while !l.is_empty() {
        let extension = l.read(tag::SEQUENCE)?;
        let mut e = extension.reader();
        let id = read_oid(&mut e)?;
        let critical = match e.read_optional(tag::BOOLEAN)? {
            // DER omits a DEFAULT value, so an explicit FALSE is not DER.
            Some(flag) => explicit_true(&flag)?,
            None => false,
        };
        let value = e.read(tag::OCTET_STRING)?;
        e.finish()?;
        if !seen.insert(id) {
            return Err(CertificateError::DuplicateExtension(ObjectId::from_der(id)));
        }
        let handled = parse_extension(id, &value, ext)?;
        if critical && !handled {
            ext.unhandled_critical.push(ObjectId::from_der(id));
        }
    }
    Ok(())
}

/// A BOOLEAN with `DEFAULT FALSE`: present only when TRUE, because DER
/// omits a value equal to its default (X.690 11.5).
fn explicit_true(flag: &Tlv<'_>) -> Result<bool> {
    if asn1::boolean(flag)? {
        Ok(true)
    } else {
        Err(flag.error(Asn1ErrorKind::InvalidValue).into())
    }
}

/// Reads a known extension into `ext`. Returns whether the extension is
/// one this crate processes, meaning chain building or trust acts on it.
/// Extensions read only for reports (alternative names, CRL distribution
/// points, authority information access, and certificate policies with a
/// qualifier this crate does not know) return `false`, so a critical one
/// is recorded as unhandled and keeps the certificate out of chains.
fn parse_extension(id: &[u8], value: &Tlv<'_>, ext: &mut Extensions) -> Result<bool> {
    let inner = |t: u8| asn1::single(value.content, value.content_offset, t);
    match id {
        oid::SUBJECT_KEY_IDENTIFIER => {
            ext.subject_key_id = Some(hex(inner(tag::OCTET_STRING)?.content));
        }
        oid::AUTHORITY_KEY_IDENTIFIER => {
            // SEQUENCE { [0] keyIdentifier, [1] authorityCertIssuer,
            // [2] authorityCertSerialNumber }, all optional.
            let seq = inner(tag::SEQUENCE)?;
            let mut r = seq.reader();
            if let Some(key_id) = r.read_optional(tag::context_prim(0))? {
                ext.authority_key_id = Some(hex(key_id.content));
            }
            if let Some(names) = r.read_optional(tag::context_cons(1))? {
                asn1::validate(&names)?;
            }
            if let Some(serial) = r.read_optional(tag::context_prim(2))? {
                if serial.content.is_empty() {
                    return Err(serial.error(Asn1ErrorKind::InvalidValue).into());
                }
            }
            r.finish()?;
        }
        oid::BASIC_CONSTRAINTS => {
            let seq = inner(tag::SEQUENCE)?;
            let mut r = seq.reader();
            let ca = match r.read_optional(tag::BOOLEAN)? {
                Some(flag) => explicit_true(&flag)?,
                None => false,
            };
            let path_len = if r.peek_tag() == Some(tag::INTEGER) {
                Some(asn1::read_small_uint(&mut r)?)
            } else {
                None
            };
            r.finish()?;
            ext.basic_constraints = Some(BasicConstraints { ca, path_len });
        }
        oid::KEY_USAGE => {
            ext.key_usage = Some(KeyUsage(asn1::bit_string_flags16(&inner(
                tag::BIT_STRING,
            )?)?));
        }
        oid::EXT_KEY_USAGE => {
            let seq = inner(tag::SEQUENCE)?;
            let mut r = seq.reader();
            if r.is_empty() {
                return Err(seq.error(Asn1ErrorKind::InvalidValue).into());
            }
            let mut list = Vec::new();
            while !r.is_empty() {
                list.push(Eku::new(ObjectId::from_der(read_oid(&mut r)?)));
            }
            ext.extended_key_usage = Some(list);
        }
        oid::CERTIFICATE_POLICIES => {
            let seq = inner(tag::SEQUENCE)?;
            let mut r = seq.reader();
            if r.is_empty() {
                return Err(seq.error(Asn1ErrorKind::InvalidValue).into());
            }
            // The policy OIDs are only reported. The two qualifiers
            // RFC 5280 defines (CPS pointer and user notice) are text for
            // people; any other qualifier is one this crate cannot
            // interpret, so a critical extension holding one is unhandled
            // (RFC 5280, 4.2.1.4).
            let mut known_qualifiers = true;
            while !r.is_empty() {
                let info = r.read(tag::SEQUENCE)?;
                let mut i = info.reader();
                let policy = read_oid(&mut i)?;
                if let Some(qualifiers) = i.read_optional(tag::SEQUENCE)? {
                    let mut q = qualifiers.reader();
                    if q.is_empty() {
                        return Err(qualifiers.error(Asn1ErrorKind::InvalidValue).into());
                    }
                    while !q.is_empty() {
                        let qualifier = q.read(tag::SEQUENCE)?;
                        let mut qi = qualifier.reader();
                        let kind = read_oid(&mut qi)?;
                        asn1::validate(&qi.read_any()?)?;
                        qi.finish()?;
                        known_qualifiers &= matches!(kind, oid::QT_CPS | oid::QT_UNOTICE);
                    }
                }
                i.finish()?;
                ext.certificate_policies.push(ObjectId::from_der(policy));
            }
            return Ok(known_qualifiers);
        }
        oid::CRL_DISTRIBUTION_POINTS => {
            // Reported only: revocation is not checked here (#50).
            let seq = inner(tag::SEQUENCE)?;
            let mut r = seq.reader();
            while !r.is_empty() {
                parse_distribution_point(&r.read(tag::SEQUENCE)?, ext)?;
            }
            return Ok(false);
        }
        oid::AUTHORITY_INFO_ACCESS => {
            let seq = inner(tag::SEQUENCE)?;
            let mut r = seq.reader();
            while !r.is_empty() {
                let desc = r.read(tag::SEQUENCE)?;
                let mut d = desc.reader();
                let method = read_oid(&mut d)?;
                let location = d.read_any()?;
                d.finish()?;
                asn1::validate(&location)?;
                if location.tag == tag::context_prim(6) {
                    let uri = uri_text(location.content);
                    match method {
                        oid::AD_OCSP => ext.ocsp_urls.push(uri),
                        oid::AD_CA_ISSUERS => ext.ca_issuers_urls.push(uri),
                        _ => {}
                    }
                }
            }
            // Reported only; nothing is fetched.
            return Ok(false);
        }
        oid::SUBJECT_ALT_NAME | oid::ISSUER_ALT_NAME => {
            // Not used for code signing identity; checked as DER only, and
            // not processed, so a critical one is unhandled.
            asn1::validate(&inner(tag::SEQUENCE)?)?;
            return Ok(false);
        }
        _ => return Ok(false),
    }
    Ok(true)
}

/// `DistributionPoint ::= SEQUENCE { distributionPoint [0]
/// DistributionPointName OPTIONAL, reasons [1] OPTIONAL, cRLIssuer [2]
/// OPTIONAL }`. Keeps the URIs of a `fullName`.
fn parse_distribution_point(point: &Tlv<'_>, ext: &mut Extensions) -> Result<()> {
    let mut r = point.reader();
    if let Some(name) = r.read_optional(tag::context_cons(0))? {
        let mut n = name.reader();
        let choice = n.read_any()?;
        n.finish()?;
        if choice.tag == tag::context_cons(0) {
            // fullName [0] IMPLICIT GeneralNames.
            let mut g = choice.reader();
            while !g.is_empty() {
                let general = g.read_any()?;
                asn1::validate(&general)?;
                if general.tag == tag::context_prim(6) {
                    ext.crl_distribution_points.push(uri_text(general.content));
                }
            }
        } else if choice.tag == tag::context_cons(1) {
            asn1::validate(&choice)?;
        } else {
            return Err(choice
                .error(Asn1ErrorKind::UnexpectedTag {
                    expected: tag::context_cons(0),
                    found: choice.tag,
                })
                .into());
        }
    }
    if let Some(reasons) = r.read_optional(tag::context_prim(1))? {
        implicit_bit_string(&reasons)?;
    }
    if let Some(issuer) = r.read_optional(tag::context_cons(2))? {
        asn1::validate(&issuer)?;
    }
    r.finish()?;
    Ok(())
}

/// An IA5String URI. Bytes outside ASCII become U+FFFD; nothing is cut.
fn uri_text(content: &[u8]) -> String {
    content
        .iter()
        .map(|b| {
            if b.is_ascii() {
                char::from(*b)
            } else {
                char::REPLACEMENT_CHARACTER
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_and_base64() {
        assert_eq!(hex(&[0x00, 0x0f, 0xa0, 0xff]), "000fa0ff");
        for (input, expected) in [
            (&b""[..], ""),
            (b"f", "Zg=="),
            (b"fo", "Zm8="),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg=="),
            (b"fooba", "Zm9vYmE="),
            (b"foobar", "Zm9vYmFy"),
            (&[0xff, 0xfe, 0xfd], "//79"),
        ] {
            assert_eq!(base64(input), expected);
        }
    }

    #[test]
    fn rendering_quotes_special_values() {
        let attr = |kind, oid: &[u8], value: &str| NameAttribute {
            oid: ObjectId::from_der(oid),
            kind: Some(kind),
            value: value.into(),
            lossy: false,
        };
        let rdns = vec![
            vec![attr(AttributeKind::Country, oid::AT_COUNTRY, "AU")],
            vec![attr(
                AttributeKind::Organization,
                oid::AT_ORGANIZATION,
                "Tests, \"Pty\"",
            )],
            vec![
                attr(AttributeKind::CommonName, oid::AT_COMMON_NAME, "A"),
                attr(
                    AttributeKind::OrganizationalUnit,
                    oid::AT_ORGANIZATIONAL_UNIT,
                    "",
                ),
            ],
            vec![attr(
                AttributeKind::JurisdictionCountry,
                oid::AT_JURISDICTION_COUNTRY,
                " x",
            )],
        ];
        assert_eq!(
            DistinguishedName::render(&rdns),
            "OID.1.3.6.1.4.1.311.60.2.1.3=\" x\", CN=A + OU=\"\", O=\"Tests, \"\"Pty\"\"\", C=AU"
        );
    }

    #[test]
    fn ecdsa_signature_algorithms_take_no_parameters() {
        let alg = |params: &[u8]| {
            let mut content = vec![0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
            content.extend_from_slice(params);
            let mut der = asn1::header(tag::SEQUENCE, content.len());
            der.extend(content);
            let tlv = asn1::single(&der, 0, tag::SEQUENCE).unwrap();
            signature_algorithm(&tlv)
        };
        assert_eq!(
            alg(&[]).unwrap(),
            SignatureAlgorithm::Ecdsa(DigestAlgorithm::Sha256)
        );
        assert_eq!(
            alg(&[0x05, 0x00]).unwrap_err(),
            CertificateError::AlgorithmParameters
        );
        // RSA PKCS #1 keeps accepting NULL or absent parameters.
        let rsa = |params: &[u8]| {
            let mut content = vec![
                0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
            ];
            content.extend_from_slice(params);
            let mut der = asn1::header(tag::SEQUENCE, content.len());
            der.extend(content);
            let tlv = asn1::single(&der, 0, tag::SEQUENCE).unwrap();
            signature_algorithm(&tlv)
        };
        assert!(rsa(&[]).is_ok() && rsa(&[0x05, 0x00]).is_ok());
    }

    #[test]
    fn report_only_extensions_are_unhandled_when_critical() {
        let ext = |id: &[u8], value: &[u8]| {
            let mut inner = asn1::header(tag::OCTET_STRING, value.len());
            inner.extend_from_slice(value);
            let mut content = asn1::header(tag::OID, id.len());
            content.extend_from_slice(id);
            content.extend_from_slice(&[0x01, 0x01, 0xff]);
            content.extend(inner);
            let mut der = asn1::header(tag::SEQUENCE, content.len());
            der.extend(content);
            der
        };
        let parse = |extension: &[u8]| {
            let mut der = asn1::header(tag::SEQUENCE, extension.len());
            der.extend_from_slice(extension);
            let list = asn1::single(&der, 0, tag::SEQUENCE).unwrap();
            let mut out = Extensions::default();
            parse_extensions(&list, &mut out).map(|()| out)
        };
        // A critical subjectAltName holding an INTEGER: well-formed DER,
        // but not processed, so unhandled.
        let san = ext(oid::SUBJECT_ALT_NAME, &[0x30, 0x03, 0x02, 0x01, 0x05]);
        let out = parse(&san).unwrap();
        assert_eq!(
            out.unhandled_critical,
            [ObjectId::from_der(oid::SUBJECT_ALT_NAME)]
        );
        // Critical CRL distribution points and AIA are reported only.
        let cdp = ext(oid::CRL_DISTRIBUTION_POINTS, &[0x30, 0x00]);
        assert_eq!(parse(&cdp).unwrap().unhandled_critical.len(), 1);
        let aia = ext(oid::AUTHORITY_INFO_ACCESS, &[0x30, 0x00]);
        assert_eq!(parse(&aia).unwrap().unhandled_critical.len(), 1);
        // certificatePolicies: policy 1.2.3 with a qualifier.
        let policies = |qualifier: &[u8]| {
            let mut q = qualifier.to_vec();
            q.extend_from_slice(&[0x16, 0x01, b'x']);
            let mut qs = asn1::header(tag::SEQUENCE, q.len() + 2);
            qs.extend(asn1::header(tag::SEQUENCE, q.len()));
            qs.extend(q);
            let mut info = vec![0x06, 0x02, 0x2a, 0x03];
            info.extend(qs);
            let mut list = asn1::header(tag::SEQUENCE, info.len() + 2);
            list.extend(asn1::header(tag::SEQUENCE, info.len()));
            list.extend(info);
            ext(oid::CERTIFICATE_POLICIES, &list)
        };
        // A CPS pointer is understood: handled, and the policy reported.
        let mut cps = asn1::header(tag::OID, oid::QT_CPS.len());
        cps.extend_from_slice(oid::QT_CPS);
        let out = parse(&policies(&cps)).unwrap();
        assert!(out.unhandled_critical.is_empty());
        assert_eq!(
            out.certificate_policies,
            [ObjectId::from_der(&[0x2a, 0x03])]
        );
        // An unknown qualifier: still reported, but unhandled.
        let out = parse(&policies(&[0x06, 0x02, 0x2a, 0x04])).unwrap();
        assert_eq!(
            out.unhandled_critical,
            [ObjectId::from_der(oid::CERTIFICATE_POLICIES)]
        );
        assert_eq!(
            out.certificate_policies,
            [ObjectId::from_der(&[0x2a, 0x03])]
        );
    }

    #[test]
    fn key_usage_names() {
        let ku = KeyUsage(0x8000 | 0x0400 | 0x0080);
        assert_eq!(
            ku.names().collect::<Vec<_>>(),
            ["digital_signature", "key_cert_sign", "decipher_only"]
        );
        assert!(ku.contains(KeyUsage::KEY_CERT_SIGN));
        assert!(!ku.contains(KeyUsage::CRL_SIGN));
    }
}
