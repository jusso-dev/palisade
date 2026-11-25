//! Certificate extraction (#49): every certificate a signed file carries,
//! for building trust bundles offline.
//!
//! [`extract_certificates`] takes the bytes of a signed file and returns
//! the certificates embedded in its signatures, outer and nested:
//!
//! - a **PE image**: every PKCS#7 entry of its certificate table;
//! - a **cabinet** (`MSCF`): the PKCS#7 signature its reserved header area
//!   points to;
//! - a bare **PKCS#7 SignedData** (a detached `.p7`, an `.p7b`, a catalog
//!   `.cat` or a package signature): the SignedData itself.
//!
//! [`CertSelection`] picks all of them, only each signature's signer (the
//! leaf), or only the self-signed roots, and [`CertificateBundle`] collects
//! certificates from many files without duplicates and writes them as one
//! PEM bundle or as DER files. The `pal fileid certs` command (#55) is a
//! thin wrapper over these; walking directories is the caller's job.
//!
//! Nothing here verifies a signature or decides trust: a certificate is
//! listed because the file carries it, which is what a bundle author needs
//! to review. The same strict DER reader as the rest of the crate is used:
//! every element of each SignedData is checked as DER (tags and lengths),
//! nested signatures included, one level at a time. A malformed outer
//! signature is an error; a malformed nested one, or a certificate that
//! does not parse as X.509, is skipped with a warning. Every count is
//! bounded ([`MAX_EXTRACTED_SIGNATURES`], [`super::MAX_CERTIFICATES`] per
//! signature, [`MAX_EXTRACT_NESTING`]). Only the first SignerInfo of a
//! SignedData is read for its signer, as Authenticode and catalogs have
//! exactly one.

#![forbid(unsafe_code)]

use std::collections::HashSet;
use std::fmt;

use serde::Serialize;

use super::asn1::{self, Asn1Error, Reader, Tlv, oid, read_oid, tag};
use super::chain::{MAX_FILE_SIGNATURE_CHECKS, TrustConfig, build_chain_within};
use super::pkcs7;
use super::signature::SignerIdentifier;
use super::x509::{self, Budget, CertSummary};
use crate::pe::{self, DataDirectoryKind, ParseOptions};

/// The most signatures (outer and nested) read from one file.
pub const MAX_EXTRACTED_SIGNATURES: usize = super::MAX_SIGNATURES;
/// The deepest nested signature followed.
pub const MAX_EXTRACT_NESTING: usize = super::MAX_NESTING_DEPTH as usize;
/// The most certificates a [`CertificateBundle`] holds.
pub const MAX_BUNDLE_CERTIFICATES: usize = 65_536;
/// The largest input read: 256 MiB.
pub const MAX_EXTRACT_INPUT: usize = 256 * 1024 * 1024;

/// What kind of file the certificates came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SignedFileKind {
    /// A PE image's certificate table.
    PeImage,
    /// A cabinet's signature.
    Cabinet,
    /// A bare PKCS#7 SignedData (detached signature, certificate bag,
    /// catalog, package signature).
    Pkcs7,
}

/// Which certificates to keep.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CertSelection {
    /// Every certificate.
    #[default]
    All,
    /// Each signature's signer certificate.
    Leaf,
    /// The self-signed root at the top of each signer's as-provided chain,
    /// when the file carries it.
    Root,
}

/// Why nothing could be extracted.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExtractError {
    /// The input is larger than [`MAX_EXTRACT_INPUT`].
    TooLarge(usize),
    /// The input is not a PE image, a cabinet or a PKCS#7 SignedData.
    UnknownFormat,
    /// A PE image that could not be parsed.
    Pe(String),
    /// A cabinet whose header or signature location is invalid.
    Cabinet(CabinetError),
    /// The file is of a known kind but carries no signature.
    Unsigned,
    /// A signature (the outer one, or the only one) is not valid DER.
    Asn1(Asn1Error),
}

impl fmt::Display for ExtractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge(n) => write!(f, "{n} bytes is larger than {MAX_EXTRACT_INPUT}"),
            Self::UnknownFormat => f.write_str("not a PE image, a cabinet or a PKCS#7 SignedData"),
            Self::Pe(e) => write!(f, "PE image: {e}"),
            Self::Cabinet(e) => write!(f, "cabinet: {e}"),
            Self::Unsigned => f.write_str("the file carries no signature"),
            Self::Asn1(e) => write!(f, "signature: invalid DER: {e}"),
        }
    }
}

impl std::error::Error for ExtractError {}

/// Why a cabinet's signature could not be located.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CabinetError {
    /// The header is shorter than its fixed fields.
    Truncated,
    /// The header's `cbCabinet` is longer than the file.
    LengthMismatch {
        /// What the header says.
        declared: u32,
        /// The file's length.
        actual: usize,
    },
    /// The reserved header area is too short to hold a signature location.
    ReserveTooShort(u16),
    /// The signature location lies outside the file, or inside the cabinet
    /// itself (before `cbCabinet`): a signer appends it after the cabinet.
    SignatureOutOfRange {
        /// Its offset.
        offset: u32,
        /// Its length.
        size: u32,
    },
    /// `cbCabinet` is smaller than the fixed header.
    TooShort(u32),
    /// The reserved area names a signature of zero bytes.
    EmptySignature,
}

impl fmt::Display for CabinetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("truncated header"),
            Self::LengthMismatch { declared, actual } => {
                write!(
                    f,
                    "header says {declared} bytes, the file has only {actual}"
                )
            }
            Self::ReserveTooShort(n) => {
                write!(f, "reserved header area of {n} bytes holds no signature")
            }
            Self::SignatureOutOfRange { offset, size } => write!(
                f,
                "signature at {offset} ({size} bytes) is outside the file or inside the cabinet"
            ),
            Self::TooShort(n) => write!(f, "header says the cabinet is only {n} bytes"),
            Self::EmptySignature => f.write_str("the signature location is empty"),
        }
    }
}

impl std::error::Error for CabinetError {}

/// One certificate found in a file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExtractedCert {
    /// The signature it was found in: 0 for the first outer signature, then
    /// in the order signatures are read (outer, then its nested ones).
    pub signature: usize,
    /// Whether it is that signature's signer.
    pub is_signer: bool,
    /// Whether it is the self-signed root of the signer's as-provided
    /// chain.
    pub is_root: bool,
    /// The certificate.
    pub cert: CertSummary,
}

/// Something that did not stop extraction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ExtractWarning {
    /// A certificate could not be parsed and was skipped.
    UnparseableCertificate {
        /// The signature.
        signature: usize,
        /// Its position among that signature's certificates.
        position: usize,
    },
    /// A nested signature, or a later certificate table entry, is not valid
    /// DER and was skipped.
    UnreadableSignature {
        /// The index it would have had.
        signature: usize,
    },
    /// The signer certificate is not among the signature's certificates.
    SignerNotFound {
        /// The signature.
        signature: usize,
    },
    /// More than [`MAX_EXTRACTED_SIGNATURES`] signatures (counting those
    /// that could not be read), more than [`MAX_EXTRACTED_SIGNATURES`]
    /// nested signature values on one signer, nesting deeper than
    /// [`MAX_EXTRACT_NESTING`], more than [`super::MAX_CERTIFICATE_ENTRIES`]
    /// certificate table entries, or more than
    /// [`MAX_FILE_SIGNATURE_CHECKS`] certificate signature checks; the rest
    /// were not read (or not checked, so a certificate may not be marked
    /// as a root).
    LimitReached,
}

/// What [`extract_certificates`] found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Extraction {
    /// The kind of file.
    pub kind: SignedFileKind,
    /// How many signatures were read.
    pub signatures: usize,
    /// The certificates [`CertSelection`] kept, each once per signature (a
    /// copy the signature carries twice is kept once, by SHA-256
    /// thumbprint), in the order the file carries them.
    pub certificates: Vec<ExtractedCert>,
    /// Anything unusual.
    pub warnings: Vec<ExtractWarning>,
}

/// Extracts the certificates of a signed file. See the module docs.
pub fn extract_certificates(
    data: &[u8],
    selection: CertSelection,
) -> Result<Extraction, ExtractError> {
    if data.len() > MAX_EXTRACT_INPUT {
        return Err(ExtractError::TooLarge(data.len()));
    }
    let mut table_warnings = Vec::new();
    let (kind, blobs) = if data.starts_with(b"MZ") {
        (
            SignedFileKind::PeImage,
            pe_blobs(data, &mut table_warnings)?,
        )
    } else if data.starts_with(b"MSCF") {
        let blob = cabinet_signature(data).map_err(ExtractError::Cabinet)?;
        let blobs = if blob.is_empty() {
            Vec::new()
        } else {
            vec![blob]
        };
        (SignedFileKind::Cabinet, blobs)
    } else if data.first() == Some(&tag::SEQUENCE) {
        (SignedFileKind::Pkcs7, vec![data])
    } else {
        return Err(ExtractError::UnknownFormat);
    };
    if blobs.is_empty() {
        return Err(ExtractError::Unsigned);
    }

    let mut walker = Walker::default();
    for w in table_warnings {
        walker.warn(w);
    }
    for (i, blob) in blobs.iter().enumerate() {
        if let Err(e) = walker.signature(blob, 0) {
            // The first signature must read; a later one is a warning.
            if i == 0 && walker.signatures.is_empty() {
                return Err(ExtractError::Asn1(e));
            }
            walker.warn(ExtractWarning::UnreadableSignature {
                signature: walker.signatures.len(),
            });
        }
    }

    // Certificate self-signature checks and chain links share one budget
    // for the file, as `evaluate_trust` does.
    let mut budget = Budget::new(MAX_FILE_SIGNATURE_CHECKS);
    let mut certificates = Vec::new();
    let mut cert_warnings = Vec::new();
    for (index, sig) in walker.signatures.iter().enumerate() {
        let mut parsed: Vec<Option<CertSummary>> = Vec::with_capacity(sig.certs.len());
        for (position, der) in sig.certs.iter().enumerate() {
            let mut one = Budget::new(budget.left().min(1));
            let result = x509::parse_within(der, &mut one);
            budget.absorb(&one);
            match result {
                Ok(c) => parsed.push(Some(c)),
                Err(_) => {
                    cert_warnings.push(ExtractWarning::UnparseableCertificate {
                        signature: index,
                        position,
                    });
                    parsed.push(None);
                }
            }
        }
        // The signer: the first certificate that parsed in full and that
        // the SignerInfo's identifier names.
        let signer = sig.sid.as_ref().and_then(|sid| {
            sig.certs.iter().enumerate().position(|(i, der)| {
                parsed.get(i).is_some_and(Option::is_some)
                    && pkcs7::parse_certificate(der).is_ok_and(|c| pkcs7::matches(&c, sid))
            })
        });
        if signer.is_none() {
            cert_warnings.push(ExtractWarning::SignerNotFound { signature: index });
        }
        let signer_thumbprint = signer
            .and_then(|s| parsed.get(s))
            .and_then(Option::as_ref)
            .map(|c| c.sha256_thumbprint.clone());
        // The root: the self-signed top of the signer's as-provided chain,
        // built with no trust configuration (nothing is trusted here).
        let owned: Vec<Vec<u8>> = sig.certs.iter().map(|c| c.to_vec()).collect();
        let root_thumbprint = signer
            .and_then(|s| build_chain_within(&owned, s, &TrustConfig::new(), &mut budget).ok())
            .and_then(|chain| chain.root_cert().map(|r| r.sha256_thumbprint.clone()));
        let mut seen: HashSet<String> = HashSet::new();
        for cert in parsed.into_iter().flatten() {
            if !seen.insert(cert.sha256_thumbprint.clone()) {
                continue;
            }
            let is_signer = signer_thumbprint.as_deref() == Some(cert.sha256_thumbprint.as_str());
            let is_root = root_thumbprint.as_deref() == Some(cert.sha256_thumbprint.as_str());
            let keep = match selection {
                CertSelection::All => true,
                CertSelection::Leaf => is_signer,
                CertSelection::Root => is_root,
            };
            if keep {
                certificates.push(ExtractedCert {
                    signature: index,
                    is_signer,
                    is_root,
                    cert,
                });
            }
        }
    }
    if budget.exhausted {
        walker.warn(ExtractWarning::LimitReached);
    }
    let mut warnings = walker.warnings;
    warnings.extend(cert_warnings);
    Ok(Extraction {
        kind,
        signatures: walker.signatures.len(),
        certificates,
        warnings,
    })
}

/// The PKCS#7 entries of a PE image's certificate table, at most
/// [`super::MAX_CERTIFICATE_ENTRIES`] entries of any type, as the verifier
/// reads it (#48). A table that is declared but rejected, too large, or
/// whose first entry is malformed is an error, never "unsigned".
fn pe_blobs<'a>(
    data: &'a [u8],
    warnings: &mut Vec<ExtractWarning>,
) -> Result<Vec<&'a [u8]>, ExtractError> {
    let info = pe::parse_with(data, &ParseOptions::metadata_only())
        .map_err(|e| ExtractError::Pe(e.to_string()))?;
    let Some(table) = info.certificate_table else {
        let declared = info
            .data_directories
            .get(DataDirectoryKind::Security.index())
            .is_some_and(|entry| entry.size != 0);
        return if declared {
            Err(ExtractError::Pe(
                "the certificate table is declared but invalid".to_owned(),
            ))
        } else {
            Ok(Vec::new())
        };
    };
    if table.size > super::MAX_CERTIFICATE_TABLE_SIZE {
        return Err(ExtractError::Pe(format!(
            "certificate table of {} bytes is too large",
            table.size
        )));
    }
    let table = usize::try_from(table.offset)
        .ok()
        .zip(usize::try_from(table.size).ok())
        .and_then(|(offset, size)| data.get(offset..offset.checked_add(size)?))
        .ok_or_else(|| ExtractError::Pe("certificate table outside the file".to_owned()))?;
    let mut blobs = Vec::new();
    let mut pos = 0_usize;
    let mut entries = 0_usize;
    while pos < table.len() {
        if entries >= super::MAX_CERTIFICATE_ENTRIES {
            warnings.push(ExtractWarning::LimitReached);
            break;
        }
        entries += 1;
        let header = table.get(pos..pos.saturating_add(8));
        let length = header
            .and_then(|h| h.get(0..4))
            .and_then(|b| b.try_into().ok())
            .map(u32::from_le_bytes)
            .and_then(|l| usize::try_from(l).ok())
            .filter(|l| *l >= 8);
        let body = length.and_then(|l| table.get(pos.saturating_add(8)..pos.checked_add(l)?));
        let (Some(header), Some(length), Some(body)) = (header, length, body) else {
            if pos == 0 {
                return Err(ExtractError::Pe(
                    "the first certificate table entry is malformed".to_owned(),
                ));
            }
            // Padding or a damaged later entry: the walk stops here.
            break;
        };
        let kind = header
            .get(6..8)
            .and_then(|b| b.try_into().ok())
            .map(u16::from_le_bytes);
        // WIN_CERT_TYPE_PKCS_SIGNED_DATA.
        if kind == Some(2) {
            // The SignedData element only, without the entry's padding.
            let mut r = Reader::new(body, 0);
            if let Ok(tlv) = r.read(tag::SEQUENCE) {
                blobs.push(tlv.raw);
            } else {
                blobs.push(body);
            }
        }
        let next = pos.saturating_add(length).saturating_add(7) & !7;
        if next <= pos {
            break;
        }
        pos = next;
    }
    Ok(blobs)
}

/// The signature of a cabinet: `CFHEADER` with `cfhdrRESERVE_PRESENT`,
/// whose reserved area starts with a 4-byte value, then the signature's
/// offset and length (both 32-bit little-endian). `cbCabinet` counts the
/// cabinet only; the signer appends the signature after it.
fn cabinet_signature(data: &[u8]) -> Result<&[u8], CabinetError> {
    const FIXED: usize = 36;
    const RESERVE_PRESENT: u16 = 0x0004;
    let u16_at = |at: usize| {
        data.get(at..at + 2)
            .and_then(|b| b.try_into().ok())
            .map(u16::from_le_bytes)
    };
    let u32_at = |at: usize| {
        data.get(at..at + 4)
            .and_then(|b| b.try_into().ok())
            .map(u32::from_le_bytes)
    };
    let (Some(declared), Some(flags)) = (u32_at(8), u16_at(30)) else {
        return Err(CabinetError::Truncated);
    };
    if data.len() < FIXED {
        return Err(CabinetError::Truncated);
    }
    if usize::try_from(declared).is_ok_and(|d| d < FIXED) {
        return Err(CabinetError::TooShort(declared));
    }
    let Some(cabinet_end) = usize::try_from(declared).ok().filter(|d| *d <= data.len()) else {
        return Err(CabinetError::LengthMismatch {
            declared,
            actual: data.len(),
        });
    };
    if flags & RESERVE_PRESENT == 0 {
        return Ok(&[]);
    }
    let Some(reserve) = u16_at(FIXED) else {
        return Err(CabinetError::Truncated);
    };
    // cbCFHeader (2), cbCFFolder (1), cbCFData (1), then abReserve.
    let area = FIXED + 4;
    if reserve < 12 {
        return Err(CabinetError::ReserveTooShort(reserve));
    }
    let (Some(offset), Some(size)) = (u32_at(area + 4), u32_at(area + 8)) else {
        return Err(CabinetError::Truncated);
    };
    let range = usize::try_from(offset)
        .ok()
        .zip(usize::try_from(size).ok())
        .filter(|(o, _)| *o >= cabinet_end.max(area + usize::from(reserve)))
        .and_then(|(o, s)| data.get(o..o.checked_add(s)?));
    if size == 0 {
        return Err(CabinetError::EmptySignature);
    }
    let blob = range.ok_or(CabinetError::SignatureOutOfRange { offset, size })?;
    // The signer pads the blob; keep the SignedData element only.
    let mut r = Reader::new(blob, 0);
    Ok(r.read(tag::SEQUENCE).map_or(blob, |tlv| tlv.raw))
}

/// One signature's certificates and signer.
struct Found<'a> {
    certs: Vec<&'a [u8]>,
    sid: Option<SignerIdentifier>,
}

#[derive(Default)]
struct Walker<'a> {
    signatures: Vec<Found<'a>>,
    /// Signatures tried, read or not: bounded by
    /// [`MAX_EXTRACTED_SIGNATURES`], so unreadable nested values cannot make
    /// the walk try without end.
    attempts: usize,
    warnings: Vec<ExtractWarning>,
}

impl<'a> Walker<'a> {
    fn warn(&mut self, w: ExtractWarning) {
        if !self.warnings.contains(&w) {
            self.warnings.push(w);
        }
    }

    /// Reads one `ContentInfo` holding a SignedData, whatever its content
    /// type, then its nested signatures.
    fn signature(&mut self, der: &'a [u8], depth: usize) -> Result<(), Asn1Error> {
        if self.attempts >= MAX_EXTRACTED_SIGNATURES || depth > MAX_EXTRACT_NESTING {
            self.warn(ExtractWarning::LimitReached);
            return Ok(());
        }
        self.attempts += 1;
        let mut outer = Reader::new(der, 0);
        // Read with the strict DER reader. Each certificate is validated
        // whole; nested signatures are read (and so checked) one level at a
        // time below, so their depth is bounded by MAX_EXTRACT_NESTING, not
        // by the DER reader's own depth limit.
        let content_info = outer.read(tag::SEQUENCE)?;
        let mut ci = content_info.reader();
        let content_type = read_oid(&mut ci)?;
        if content_type != oid::SIGNED_DATA {
            return Err(content_info.error(asn1::Asn1ErrorKind::InvalidValue));
        }
        let explicit = ci.read(tag::context_cons(0))?;
        ci.finish()?;
        let sd = asn1::single(explicit.content, explicit.content_offset, tag::SEQUENCE)?;
        let mut r = sd.reader();
        for t in [tag::INTEGER, tag::SET, tag::SEQUENCE] {
            asn1::validate(&r.read(t)?)?;
        }
        let mut certs = Vec::new();
        if let Some(set) = r.read_optional(tag::context_cons(0))? {
            let mut c = set.reader();
            while !c.is_empty() {
                let choice = c.read_any()?;
                asn1::validate(&choice)?;
                if choice.tag == tag::SEQUENCE && certs.len() < super::MAX_CERTIFICATES {
                    certs.push(choice.raw);
                }
            }
        }
        if let Some(crls) = r.read_optional(tag::context_cons(1))? {
            asn1::validate(&crls)?;
        }
        let infos = r.read(tag::SET)?;
        r.finish()?;
        // Authenticode and catalogs have exactly one SignerInfo; only the
        // first is read for the signer and nested signatures, and any
        // others are checked as DER.
        let mut sid = None;
        let mut nested: Vec<&'a [u8]> = Vec::new();
        let mut i = infos.reader();
        let mut first = true;
        while !i.is_empty() {
            let info = i.read(tag::SEQUENCE)?;
            if first {
                let truncated;
                (sid, nested, truncated) = signer_info(&info)?;
                if truncated {
                    self.warn(ExtractWarning::LimitReached);
                }
                first = false;
            } else {
                asn1::validate(&info)?;
            }
        }
        self.signatures.push(Found { certs, sid });
        for child in nested {
            let index = self.signatures.len();
            if self.signature(child, depth + 1).is_err() {
                self.warn(ExtractWarning::UnreadableSignature { signature: index });
            }
        }
        Ok(())
    }
}

/// A SignerInfo's identifier, its nested signatures, and whether nested
/// values past the limit were dropped.
type SignerParts<'a> = (Option<SignerIdentifier>, Vec<&'a [u8]>, bool);

/// A SignerInfo's identifier and its nested signatures. Every part but the
/// nested signatures (which the walker reads itself, one level at a time)
/// is checked as DER.
///
/// At most [`MAX_EXTRACTED_SIGNATURES`] nested values are kept; the rest
/// are still checked as DER, and the third value says some were dropped.
fn signer_info<'a>(info: &Tlv<'a>) -> Result<SignerParts<'a>, Asn1Error> {
    let mut r = info.reader();
    r.read(tag::INTEGER)?;
    let sid_start = r.clone();
    let sid = pkcs7::parse_sid(&mut r).ok();
    if sid.is_none() {
        // Not a form `parse_sid` knows: still one valid element.
        r = sid_start;
        asn1::validate(&r.read_any()?)?;
    }
    let mut nested = Vec::new();
    let mut truncated = false;
    while !r.is_empty() {
        let field = r.read_any()?;
        if field.tag != tag::context_cons(1) {
            asn1::validate(&field)?;
            continue;
        }
        let mut attrs = field.reader();
        while !attrs.is_empty() {
            let attr = attrs.read(tag::SEQUENCE)?;
            let mut a = attr.reader();
            let id = read_oid(&mut a)?;
            let values = a.read(tag::SET)?;
            a.finish()?;
            if id == oid::NESTED_SIGNATURE {
                let mut v = values.reader();
                while !v.is_empty() {
                    let value = v.read_any()?;
                    if nested.len() < MAX_EXTRACTED_SIGNATURES {
                        nested.push(value.raw);
                    } else {
                        truncated = true;
                    }
                }
            } else {
                asn1::validate(&values)?;
            }
        }
    }
    Ok((sid, nested, truncated))
}

/// Certificates from many files, each kept once (by SHA-256 thumbprint), in
/// the order first seen, up to [`MAX_BUNDLE_CERTIFICATES`].
#[derive(Debug, Clone, Default)]
pub struct CertificateBundle {
    certificates: Vec<CertSummary>,
    seen: HashSet<String>,
    /// Whether certificates past [`MAX_BUNDLE_CERTIFICATES`] were dropped.
    pub truncated: bool,
}

impl CertificateBundle {
    /// An empty bundle.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds the certificates of `extraction`. Returns how many were new.
    pub fn add(&mut self, extraction: &Extraction) -> usize {
        let mut added = 0;
        for c in &extraction.certificates {
            if self.insert(&c.cert) {
                added += 1;
            }
        }
        added
    }

    /// Adds one certificate. Returns whether it was new.
    pub fn insert(&mut self, cert: &CertSummary) -> bool {
        if self.seen.contains(&cert.sha256_thumbprint) {
            return false;
        }
        if self.certificates.len() >= MAX_BUNDLE_CERTIFICATES {
            self.truncated = true;
            return false;
        }
        self.seen.insert(cert.sha256_thumbprint.clone());
        self.certificates.push(cert.clone());
        true
    }

    /// The certificates, in the order first seen.
    #[must_use]
    pub fn certificates(&self) -> &[CertSummary] {
        &self.certificates
    }

    /// Every certificate as PEM, one after another.
    #[must_use]
    pub fn to_pem(&self) -> String {
        self.certificates.iter().map(CertSummary::pem).collect()
    }

    /// Each certificate's DER, with a file name: its SHA-256 thumbprint
    /// and `.cer`. Thumbprints are hex, so the names are safe on every OS.
    pub fn der_files(&self) -> impl Iterator<Item = (String, &[u8])> {
        self.certificates
            .iter()
            .map(|c| (format!("{}.cer", c.sha256_thumbprint), c.der.as_slice()))
    }
}
