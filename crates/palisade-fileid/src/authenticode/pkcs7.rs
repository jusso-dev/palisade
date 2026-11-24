//! Decodes an Authenticode PKCS#7 SignedData into borrowed parts.
//!
//! Only structure is decoded here; [`super::verify`] does the cryptography.
//! Every collection is capped by a fixed limit, and every byte slice borrows
//! from the input, so no declared length ever sizes an allocation.

#![forbid(unsafe_code)]

use super::asn1::{self, ObjectId, Reader, Tlv, oid, read_oid, read_small_uint, tag};
use super::signature::{
    Curve, DigestAlgorithm, KeyAlgorithm, PageHashes, SignatureAlgorithm, SignatureError,
    SignatureWarning, SignerIdentifier, StatementType, TimestampKind, TimestampToken,
};
use crate::hash::HashAlgorithm;

/// The most certificates kept from one SignedData.
pub const MAX_CERTIFICATES: usize = 64;
/// The most timestamps kept from one SignerInfo.
pub const MAX_TIMESTAMPS: usize = 8;
/// The most warnings kept for one signature.
pub const MAX_WARNINGS: usize = 32;
/// The most nested SignedData values collected from one SignerInfo. Further
/// ones are counted against [`super::MAX_SIGNATURES`] by the caller anyway,
/// so collecting one more than the limit is enough to report it.
const MAX_NESTED_COLLECTED: usize = super::MAX_SIGNATURES + 1;

/// The `SpcSerializedObject` class ID of the page hash moniker,
/// `A6B586D5-B4A1-2466-AE05-A217DA8E60D6`, as encoded.
const PAGE_HASH_CLASS_ID: [u8; 16] = [
    0xa6, 0xb5, 0x86, 0xd5, 0xb4, 0xa1, 0x24, 0x66, 0xae, 0x05, 0xa2, 0x17, 0xda, 0x8e, 0x60, 0xd6,
];

type Result<T> = std::result::Result<T, SignatureError>;

/// A digest algorithm identifier: known, or the unknown OID.
pub(crate) type DigestId = std::result::Result<DigestAlgorithm, ObjectId>;

/// Collects warnings up to [`MAX_WARNINGS`].
#[derive(Debug, Default)]
pub(crate) struct Warnings(pub Vec<SignatureWarning>);

impl Warnings {
    pub fn push(&mut self, warning: SignatureWarning) {
        if self.0.len() < MAX_WARNINGS {
            if !self.0.contains(&warning) {
                self.0.push(warning);
            }
        } else if self.0.last() != Some(&SignatureWarning::WarningsTruncated) {
            self.0.push(SignatureWarning::WarningsTruncated);
        }
    }
}

/// `SpcIndirectDataContent`.
#[derive(Debug)]
pub(crate) struct IndirectData<'a> {
    /// The content octets of the `SpcIndirectDataContent` SEQUENCE: what the
    /// `messageDigest` attribute hashes.
    pub content: &'a [u8],
    pub digest_alg: DigestId,
    /// The signed image digest.
    pub digest: &'a [u8],
    pub pe_image_flags: Option<u8>,
    pub page_hashes: Option<PageHashes>,
}

/// The signer attributes taken from the authenticated attributes.
#[derive(Debug, Default)]
pub(crate) struct Opus {
    pub program_name: Option<String>,
    pub more_info_url: Option<String>,
}

/// One SignerInfo.
#[derive(Debug)]
pub(crate) struct Signer<'a> {
    pub sid: SignerIdentifier,
    pub digest_alg: DigestId,
    /// The authenticated attributes with their `[0]` tag replaced by the SET
    /// tag: the bytes the signature covers.
    pub signed_attrs: Vec<u8>,
    /// The `messageDigest` attribute.
    pub message_digest: &'a [u8],
    pub opus: Opus,
    pub statement_type: Option<StatementType>,
    pub signing_time: Option<i64>,
    pub sig_alg: SignatureAlgorithm,
    pub signature: &'a [u8],
    /// Nested signatures: the DER of each `ContentInfo`, with its offset.
    pub nested: Vec<(&'a [u8], usize)>,
    pub timestamps: Vec<TimestampToken>,
}

/// A decoded SignedData.
#[derive(Debug)]
pub(crate) struct SignedData<'a> {
    /// Whether `digestAlgorithms` lists the signer's digest algorithm.
    pub signer_digest_listed: bool,
    pub indirect: IndirectData<'a>,
    /// Every X.509 certificate, DER-encoded, in blob order.
    pub certificates: Vec<&'a [u8]>,
    pub signer: Signer<'a>,
    pub warnings: Warnings,
}

/// Decodes a `ContentInfo` holding an Authenticode SignedData. `der` must
/// be exactly one element; `base` is its offset, for errors. Returns the
/// SignedData and the number of bytes after the element.
pub(crate) fn parse_content_info(der: &[u8], base: usize) -> Result<(SignedData<'_>, &[u8])> {
    let mut outer = Reader::new(der, base);
    let content_info = outer.read(tag::SEQUENCE)?;
    let trailing = outer.remaining();
    let mut ci = content_info.reader();
    let content_type = read_oid(&mut ci)?;
    if content_type != oid::SIGNED_DATA {
        return Err(SignatureError::NotSignedData(ObjectId::from_der(
            content_type,
        )));
    }
    let explicit = ci.read(tag::context_cons(0))?;
    ci.finish()?;
    let signed_data = asn1::single(explicit.content, explicit.content_offset, tag::SEQUENCE)?;
    Ok((parse_signed_data(&signed_data)?, trailing))
}

fn parse_signed_data<'a>(sd: &Tlv<'a>) -> Result<SignedData<'a>> {
    let mut warnings = Warnings::default();
    let mut r = sd.reader();
    // PKCS#7 v1.5 SignedData is version 1. Higher versions (CMS) are read
    // the same way; the version itself carries no trust.
    read_small_uint(&mut r)?;
    let digest_algorithms = r.read(tag::SET)?;

    // encapContentInfo / contentInfo.
    let encap = r.read(tag::SEQUENCE)?;
    let mut e = encap.reader();
    let content_type = read_oid(&mut e)?;
    if content_type != oid::SPC_INDIRECT_DATA {
        return Err(SignatureError::NotIndirectData(ObjectId::from_der(
            content_type,
        )));
    }
    let explicit = e
        .read_optional(tag::context_cons(0))?
        .ok_or(SignatureError::MissingContent)?;
    e.finish()?;
    let indirect = asn1::single(explicit.content, explicit.content_offset, tag::SEQUENCE)?;
    let indirect = parse_indirect_data(&indirect, &mut warnings)?;

    let mut certificates = Vec::new();
    if let Some(set) = r.read_optional(tag::context_cons(0))? {
        let mut certs = set.reader();
        while !certs.is_empty() {
            let choice = certs.read_any()?;
            if choice.tag != tag::SEQUENCE {
                warnings.push(SignatureWarning::NonX509Certificate);
            } else if certificates.len() < MAX_CERTIFICATES {
                certificates.push(choice.raw);
            } else {
                warnings.push(SignatureWarning::TooManyCertificates);
            }
        }
    }
    // CRLs are not used for Authenticode verification; revocation is #50.
    r.read_optional(tag::context_cons(1))?;

    let signer_infos = r.read(tag::SET)?;
    r.finish()?;
    let mut infos = signer_infos.reader();
    let mut count = 0_usize;
    let mut first = None;
    while !infos.is_empty() {
        let info = infos.read_any()?;
        count = count.saturating_add(1);
        if first.is_none() {
            first = Some(info);
        }
    }
    let signer = match (count, first) {
        (1, Some(info)) => parse_signer_info(&info, &mut warnings)?,
        _ => return Err(SignatureError::SignerCount(count)),
    };

    let signer_digest_listed = match &signer.digest_alg {
        Ok(alg) => digest_set_contains(&digest_algorithms, *alg)?,
        Err(_) => false,
    };
    Ok(SignedData {
        signer_digest_listed,
        indirect,
        certificates,
        signer,
        warnings,
    })
}

fn digest_set_contains(set: &Tlv<'_>, wanted: DigestAlgorithm) -> Result<bool> {
    let mut r = set.reader();
    let mut found = false;
    while !r.is_empty() {
        let id = r.read(tag::SEQUENCE)?;
        if parse_digest_alg(&id)? == Ok(wanted) {
            found = true;
        }
    }
    Ok(found)
}

/// A DigestAlgorithmIdentifier: an OID with absent or NULL parameters.
pub(crate) fn parse_digest_alg(id: &Tlv<'_>) -> Result<DigestId> {
    let mut r = id.expect(tag::SEQUENCE)?.reader();
    let alg = read_oid(&mut r)?;
    if let Some(params) = r.read_optional(tag::NULL)? {
        if !params.content.is_empty() {
            return Err(SignatureError::AlgorithmParameters);
        }
    }
    if !r.is_empty() {
        return Err(SignatureError::AlgorithmParameters);
    }
    Ok(digest_from_oid(alg))
}

fn digest_from_oid(alg: &[u8]) -> DigestId {
    Ok(match alg {
        oid::MD2 => DigestAlgorithm::Md2,
        oid::MD5 => DigestAlgorithm::Md5,
        oid::SHA1 => DigestAlgorithm::Sha1,
        oid::SHA256 => DigestAlgorithm::Sha256,
        oid::SHA384 => DigestAlgorithm::Sha384,
        oid::SHA512 => DigestAlgorithm::Sha512,
        other => return Err(ObjectId::from_der(other)),
    })
}

fn parse_indirect_data<'a>(seq: &Tlv<'a>, warnings: &mut Warnings) -> Result<IndirectData<'a>> {
    let mut r = seq.reader();
    // SpcAttributeTypeAndOptionalValue.
    let data = r.read(tag::SEQUENCE)?;
    let mut d = data.reader();
    let data_type = read_oid(&mut d)?;
    if data_type != oid::SPC_PE_IMAGE_DATA {
        return Err(SignatureError::NotPeImageData(ObjectId::from_der(
            data_type,
        )));
    }
    let mut pe_image_flags = None;
    let mut page_hashes = None;
    if let Some(value) = d.read_optional(tag::SEQUENCE)? {
        // SpcPeImageData ::= SEQUENCE { flags BIT STRING DEFAULT, file [0] SpcLink OPTIONAL }
        let mut v = value.reader();
        if let Some(flags) = v.read_optional(tag::BIT_STRING)? {
            pe_image_flags = Some(asn1::bit_string_flags(&flags)?);
        }
        if let Some(file) = v.read_optional(tag::context_cons(0))? {
            let link = asn1::single(file.content, file.content_offset, tag::context_cons(1));
            if let Ok(moniker) = link {
                page_hashes = parse_page_hash_moniker(&moniker, warnings);
            }
        }
        v.finish()?;
    }
    d.finish()?;

    // DigestInfo.
    let digest_info = r.read(tag::SEQUENCE)?;
    let mut di = digest_info.reader();
    let digest_alg = parse_digest_alg(&di.read(tag::SEQUENCE)?)?;
    let digest = di.read(tag::OCTET_STRING)?.content;
    di.finish()?;
    r.finish()?;
    if let Ok(alg) = digest_alg {
        if digest.len() != alg.digest_len() {
            return Err(SignatureError::DigestLength);
        }
    }
    Ok(IndirectData {
        content: seq.content,
        digest_alg,
        digest,
        pe_image_flags,
        page_hashes,
    })
}

/// `SpcSerializedObject` (`[1] IMPLICIT SEQUENCE { classId OCTET STRING,
/// serializedData OCTET STRING }`). Returns the page hash table if the class
/// ID is the page hash one and the table is well formed; a malformed table
/// is dropped with a warning, because page hashes are optional.
fn parse_page_hash_moniker(moniker: &Tlv<'_>, warnings: &mut Warnings) -> Option<PageHashes> {
    let mut r = moniker.reader();
    let class_id = r.read(tag::OCTET_STRING).ok()?;
    if class_id.content != PAGE_HASH_CLASS_ID {
        return None;
    }
    let parsed = r
        .read(tag::OCTET_STRING)
        .ok()
        .and_then(|data| parse_page_hash_table(data.content, data.content_offset));
    if parsed.is_none() {
        warnings.push(SignatureWarning::PageHashesMalformed);
    }
    parsed
}

/// `SET { SEQUENCE { OID, SET { OCTET STRING table } } }`.
fn parse_page_hash_table(data: &[u8], base: usize) -> Option<PageHashes> {
    let set = asn1::single(data, base, tag::SET).ok()?;
    let mut entries = set.reader();
    let entry = entries.read(tag::SEQUENCE).ok()?;
    let mut e = entry.reader();
    let algorithm = match read_oid(&mut e).ok()? {
        oid::PAGE_HASHES_V1 => HashAlgorithm::Sha1,
        oid::PAGE_HASHES_V2 => HashAlgorithm::Sha256,
        _ => return None,
    };
    let values = e.read(tag::SET).ok()?;
    let table = asn1::single(values.content, values.content_offset, tag::OCTET_STRING).ok()?;
    let record = algorithm.digest_len().checked_add(4)?;
    if table.content.is_empty() || table.content.len() % record != 0 {
        return None;
    }
    Some(PageHashes {
        algorithm,
        table: table.content.to_vec(),
    })
}

fn parse_signer_info<'a>(info: &Tlv<'a>, warnings: &mut Warnings) -> Result<Signer<'a>> {
    let mut r = info.expect(tag::SEQUENCE)?.reader();
    let version = read_small_uint(&mut r)?;
    let sid = match r.peek_tag() {
        Some(tag::SEQUENCE) => {
            let ias = r.read(tag::SEQUENCE)?;
            let mut i = ias.reader();
            let issuer = i.read(tag::SEQUENCE)?;
            let serial = i.read(tag::INTEGER)?;
            i.finish()?;
            SignerIdentifier::IssuerAndSerial {
                issuer: issuer.raw.to_vec(),
                serial: asn1::integer_bytes(&serial)?.to_vec(),
            }
        }
        _ => {
            let ski = r.read(tag::context_prim(0))?;
            SignerIdentifier::SubjectKeyId(ski.content.to_vec())
        }
    };
    let expected_version = match sid {
        SignerIdentifier::IssuerAndSerial { .. } => 1,
        SignerIdentifier::SubjectKeyId(_) => 3,
    };
    if version != expected_version {
        warnings.push(SignatureWarning::SignerVersionMismatch(version));
    }
    let digest_alg = parse_digest_alg(&r.read(tag::SEQUENCE)?)?;
    let attrs = r
        .read_optional(tag::context_cons(0))?
        .ok_or(SignatureError::MissingAuthenticatedAttributes)?;
    let sig_alg_id = r.read(tag::SEQUENCE)?;
    let signature = r.read(tag::OCTET_STRING)?.content;
    let unsigned = r.read_optional(tag::context_cons(1))?;
    r.finish()?;

    let mut signed_attrs = attrs.raw.to_vec();
    if let Some(first) = signed_attrs.first_mut() {
        *first = tag::SET;
    }
    let auth = parse_authenticated_attributes(&attrs, warnings)?;
    let sig_alg = parse_signature_alg(&sig_alg_id, &digest_alg)?;

    let mut nested = Vec::new();
    let mut timestamps = Vec::new();
    if let Some(unsigned) = unsigned {
        parse_unauthenticated_attributes(&unsigned, &mut nested, &mut timestamps, warnings)?;
    }
    Ok(Signer {
        sid,
        digest_alg,
        signed_attrs,
        message_digest: auth.message_digest,
        opus: auth.opus,
        statement_type: auth.statement_type,
        signing_time: auth.signing_time,
        sig_alg,
        signature,
        nested,
        timestamps,
    })
}

struct Authenticated<'a> {
    message_digest: &'a [u8],
    opus: Opus,
    statement_type: Option<StatementType>,
    signing_time: Option<i64>,
}

/// Reads one `Attribute ::= SEQUENCE { type OID, values SET }`.
fn read_attribute<'a>(r: &mut Reader<'a>) -> Result<(&'a [u8], Tlv<'a>)> {
    let attr = r.read(tag::SEQUENCE)?;
    let mut a = attr.reader();
    let attr_type = read_oid(&mut a)?;
    let values = a.read(tag::SET)?;
    a.finish()?;
    Ok((attr_type, values))
}

/// The single value of an attribute.
fn single_value<'a>(attr_type: &[u8], values: &Tlv<'a>) -> Result<Tlv<'a>> {
    let mut v = values.reader();
    let count_error = || SignatureError::AttributeValueCount(ObjectId::from_der(attr_type));
    if v.is_empty() {
        return Err(count_error());
    }
    let value = v.read_any()?;
    if !v.is_empty() {
        return Err(count_error());
    }
    Ok(value)
}

fn parse_authenticated_attributes<'a>(
    attrs: &Tlv<'a>,
    warnings: &mut Warnings,
) -> Result<Authenticated<'a>> {
    let mut r = attrs.reader();
    let mut content_type = None;
    let mut message_digest = None;
    let mut opus = None;
    let mut statement_type = None;
    let mut signing_time = None;
    while !r.is_empty() {
        let (attr_type, values) = read_attribute(&mut r)?;
        let duplicate = || SignatureError::DuplicateAttribute(ObjectId::from_der(attr_type));
        match attr_type {
            oid::CONTENT_TYPE => {
                let value = single_value(attr_type, &values)?;
                if content_type.replace(asn1::oid_bytes(&value)?).is_some() {
                    return Err(duplicate());
                }
            }
            oid::MESSAGE_DIGEST => {
                let value = single_value(attr_type, &values)?.expect(tag::OCTET_STRING)?;
                if message_digest.replace(value.content).is_some() {
                    return Err(duplicate());
                }
            }
            oid::SIGNING_TIME => {
                let value = single_value(attr_type, &values)?;
                if signing_time.replace(asn1::time(&value)?).is_some() {
                    return Err(duplicate());
                }
            }
            oid::SPC_SP_OPUS_INFO => {
                let value = single_value(attr_type, &values)?;
                if opus.replace(parse_opus_info(&value, warnings)?).is_some() {
                    return Err(duplicate());
                }
            }
            oid::SPC_STATEMENT_TYPE => {
                let value = single_value(attr_type, &values)?;
                if statement_type
                    .replace(parse_statement_type(&value)?)
                    .is_some()
                {
                    return Err(duplicate());
                }
            }
            other => warnings.push(SignatureWarning::UnknownAuthenticatedAttribute(
                ObjectId::from_der(other),
            )),
        }
    }
    let content_type = content_type
        .ok_or_else(|| SignatureError::MissingAttribute(ObjectId::from_der(oid::CONTENT_TYPE)))?;
    if content_type != oid::SPC_INDIRECT_DATA {
        return Err(SignatureError::ContentTypeMismatch(ObjectId::from_der(
            content_type,
        )));
    }
    let message_digest = message_digest
        .ok_or_else(|| SignatureError::MissingAttribute(ObjectId::from_der(oid::MESSAGE_DIGEST)))?;
    Ok(Authenticated {
        message_digest,
        opus: opus.unwrap_or_default(),
        statement_type,
        signing_time,
    })
}

/// `SpcSpOpusInfo ::= SEQUENCE { programName [0] EXPLICIT SpcString
/// OPTIONAL, moreInfo [1] EXPLICIT SpcLink OPTIONAL }`.
fn parse_opus_info(value: &Tlv<'_>, warnings: &mut Warnings) -> Result<Opus> {
    let mut r = value.expect(tag::SEQUENCE)?.reader();
    let mut opus = Opus::default();
    if let Some(name) = r.read_optional(tag::context_cons(0))? {
        let inner = asn1::single(name.content, name.content_offset, tag::context_prim(0))
            .or_else(|_| asn1::single(name.content, name.content_offset, tag::context_prim(1)))?;
        opus.program_name = Some(spc_text(&inner, warnings)?);
    }
    if let Some(more) = r.read_optional(tag::context_cons(1))? {
        let mut m = more.reader();
        let link = m.read_any()?;
        m.finish()?;
        if link.tag == tag::context_prim(0) {
            let text = asn1::ascii_text(link.content);
            if text.truncated {
                warnings.push(SignatureWarning::TextTruncated);
            }
            opus.more_info_url = Some(text.text);
        } else {
            warnings.push(SignatureWarning::UnreadLinkForm);
        }
    }
    r.finish()?;
    Ok(opus)
}

/// An `SpcString`: `[0] IMPLICIT BMPString` or `[1] IMPLICIT IA5String`.
fn spc_text(inner: &Tlv<'_>, warnings: &mut Warnings) -> Result<String> {
    let text = if inner.tag == tag::context_prim(0) {
        asn1::bmp_text(inner.content, inner.offset)?
    } else {
        asn1::ascii_text(inner.content)
    };
    if text.truncated {
        warnings.push(SignatureWarning::TextTruncated);
    }
    Ok(text.text)
}

/// `SpcStatementType ::= SEQUENCE OF OBJECT IDENTIFIER`.
fn parse_statement_type(value: &Tlv<'_>) -> Result<StatementType> {
    let mut r = value.expect(tag::SEQUENCE)?.reader();
    let (mut individual, mut commercial, mut other) = (false, false, false);
    while !r.is_empty() {
        match read_oid(&mut r)? {
            oid::SPC_INDIVIDUAL => individual = true,
            oid::SPC_COMMERCIAL => commercial = true,
            _ => other = true,
        }
    }
    Ok(match (individual, commercial, other) {
        (true, false, false) => StatementType::Individual,
        (false, true, false) => StatementType::Commercial,
        _ => StatementType::Other,
    })
}

fn parse_unauthenticated_attributes<'a>(
    attrs: &Tlv<'a>,
    nested: &mut Vec<(&'a [u8], usize)>,
    timestamps: &mut Vec<TimestampToken>,
    warnings: &mut Warnings,
) -> Result<()> {
    let mut r = attrs.reader();
    while !r.is_empty() {
        let (attr_type, values) = read_attribute(&mut r)?;
        let kind = match attr_type {
            oid::NESTED_SIGNATURE => None,
            oid::COUNTER_SIGNATURE => Some(TimestampKind::CounterSignature),
            oid::RFC3161_TIMESTAMP => Some(TimestampKind::Rfc3161),
            other => {
                warnings.push(SignatureWarning::UnknownUnauthenticatedAttribute(
                    ObjectId::from_der(other),
                ));
                continue;
            }
        };
        let mut v = values.reader();
        while !v.is_empty() {
            let value = v.read_any()?;
            match kind {
                None if nested.len() < MAX_NESTED_COLLECTED => {
                    nested.push((value.raw, value.offset));
                }
                Some(kind) if timestamps.len() < MAX_TIMESTAMPS => {
                    timestamps.push(TimestampToken {
                        kind,
                        der: value.raw.to_vec(),
                    });
                }
                _ => warnings.push(SignatureWarning::LimitReached),
            }
        }
    }
    Ok(())
}

/// The SignerInfo's signature algorithm. A digest it names must agree with
/// the SignerInfo's digest algorithm (except for RSA-PSS, whose parameters
/// are checked at verification).
fn parse_signature_alg(id: &Tlv<'_>, signer_digest: &DigestId) -> Result<SignatureAlgorithm> {
    let mut r = id.expect(tag::SEQUENCE)?.reader();
    let alg = read_oid(&mut r)?;
    let params = if r.is_empty() {
        None
    } else {
        Some(r.read_any()?)
    };
    r.finish()?;
    let null_or_absent = |params: &Option<Tlv<'_>>| match params {
        None => true,
        Some(p) => p.tag == tag::NULL && p.content.is_empty(),
    };
    let implied = |digest: DigestAlgorithm| -> Result<DigestAlgorithm> {
        if !null_or_absent(&params) {
            return Err(SignatureError::AlgorithmParameters);
        }
        match signer_digest {
            Ok(d) if *d == digest => Ok(digest),
            _ => Err(SignatureError::InconsistentDigestAlgorithms),
        }
    };
    // Only reached for algorithms that take their digest from the signer.
    let signer = || -> Result<DigestAlgorithm> {
        if !null_or_absent(&params) {
            return Err(SignatureError::AlgorithmParameters);
        }
        Ok(*signer_digest
            .as_ref()
            .map_err(|_| SignatureError::InconsistentDigestAlgorithms)?)
    };
    let other = |alg: &[u8]| SignatureAlgorithm::Other(ObjectId::from_der(alg));
    Ok(match alg {
        oid::RSA_ENCRYPTION => match signer_digest {
            Ok(_) => SignatureAlgorithm::RsaPkcs1(signer()?),
            Err(_) => other(alg),
        },
        oid::MD2_WITH_RSA => SignatureAlgorithm::RsaPkcs1(implied(DigestAlgorithm::Md2)?),
        oid::MD5_WITH_RSA => SignatureAlgorithm::RsaPkcs1(implied(DigestAlgorithm::Md5)?),
        oid::SHA1_WITH_RSA => SignatureAlgorithm::RsaPkcs1(implied(DigestAlgorithm::Sha1)?),
        oid::SHA256_WITH_RSA => SignatureAlgorithm::RsaPkcs1(implied(DigestAlgorithm::Sha256)?),
        oid::SHA384_WITH_RSA => SignatureAlgorithm::RsaPkcs1(implied(DigestAlgorithm::Sha384)?),
        oid::SHA512_WITH_RSA => SignatureAlgorithm::RsaPkcs1(implied(DigestAlgorithm::Sha512)?),
        oid::ECDSA_WITH_SHA1 => SignatureAlgorithm::Ecdsa(implied(DigestAlgorithm::Sha1)?),
        oid::ECDSA_WITH_SHA256 => SignatureAlgorithm::Ecdsa(implied(DigestAlgorithm::Sha256)?),
        oid::ECDSA_WITH_SHA384 => SignatureAlgorithm::Ecdsa(implied(DigestAlgorithm::Sha384)?),
        oid::ECDSA_WITH_SHA512 => SignatureAlgorithm::Ecdsa(implied(DigestAlgorithm::Sha512)?),
        // Some signers name the key algorithm instead of a signature one.
        oid::EC_PUBLIC_KEY => match signer_digest {
            Ok(_) => SignatureAlgorithm::Ecdsa(signer()?),
            Err(_) => other(alg),
        },
        oid::RSASSA_PSS => parse_pss_params(params.as_ref()).unwrap_or_else(|| other(alg)),
        oid::ED25519 if params.is_none() => SignatureAlgorithm::Ed25519,
        oid::ED448 if params.is_none() => SignatureAlgorithm::Ed448,
        oid::ED25519 | oid::ED448 => return Err(SignatureError::AlgorithmParameters),
        _ => other(alg),
    })
}

/// `RSASSA-PSS-params` (RFC 4055). Returns `None` when a digest or mask
/// function is unknown or the encoding is invalid.
fn parse_pss_params(params: Option<&Tlv<'_>>) -> Option<SignatureAlgorithm> {
    let seq = params?.expect(tag::SEQUENCE).ok()?;
    let mut r = seq.reader();
    let mut digest = DigestAlgorithm::Sha1;
    let mut mgf1_digest = DigestAlgorithm::Sha1;
    let mut salt_len = 20;
    if let Some(hash) = r.read_optional(tag::context_cons(0)).ok()? {
        let id = asn1::single(hash.content, hash.content_offset, tag::SEQUENCE).ok()?;
        digest = parse_digest_alg(&id).ok()?.ok()?;
    }
    if let Some(mgf) = r.read_optional(tag::context_cons(1)).ok()? {
        let id = asn1::single(mgf.content, mgf.content_offset, tag::SEQUENCE).ok()?;
        let mut m = id.reader();
        if read_oid(&mut m).ok()? != oid::MGF1 {
            return None;
        }
        mgf1_digest = parse_digest_alg(&m.read(tag::SEQUENCE).ok()?).ok()?.ok()?;
        m.finish().ok()?;
    }
    if let Some(salt) = r.read_optional(tag::context_cons(2)).ok()? {
        let mut s = salt.reader();
        salt_len = read_small_uint(&mut s).ok()?;
        s.finish().ok()?;
    }
    if let Some(trailer) = r.read_optional(tag::context_cons(3)).ok()? {
        let mut t = trailer.reader();
        if read_small_uint(&mut t).ok()? != 1 {
            return None;
        }
        t.finish().ok()?;
    }
    r.finish().ok()?;
    Some(SignatureAlgorithm::RsaPss {
        digest,
        mgf1_digest,
        salt_len,
    })
}

/// A signer's public key, as the crypto module takes it.
#[derive(Debug, Clone, Copy)]
pub(crate) enum CertKey<'a> {
    Rsa { der: &'a [u8], bits: u32 },
    Ec { curve: Curve, point: &'a [u8] },
}

/// The parts of an X.509 certificate needed to match a signer and verify
/// its signature. Chain building and the rest of the certificate are #49.
#[derive(Debug, Clone)]
pub(crate) struct Certificate<'a> {
    /// The issuer `Name`, DER-encoded.
    pub issuer: &'a [u8],
    /// The serial number's INTEGER content octets.
    pub serial: &'a [u8],
    /// The subject key identifier extension, if present.
    pub subject_key_id: Option<&'a [u8]>,
    pub key_alg: KeyAlgorithm,
    pub key_bits: Option<u32>,
    /// `None` when the key algorithm is not one that can be verified.
    pub key: Option<CertKey<'a>>,
}

/// Decodes the parts of `der` (one X.509 certificate) that signer matching
/// needs.
pub(crate) fn parse_certificate(
    der: &[u8],
) -> std::result::Result<Certificate<'_>, asn1::Asn1Error> {
    let cert = asn1::single(der, 0, tag::SEQUENCE)?;
    let mut c = cert.reader();
    let tbs = c.read(tag::SEQUENCE)?;
    c.read(tag::SEQUENCE)?;
    c.read(tag::BIT_STRING)?;
    c.finish()?;

    let mut t = tbs.reader();
    t.read_optional(tag::context_cons(0))?;
    let serial = asn1::integer_bytes(&t.read(tag::INTEGER)?)?;
    t.read(tag::SEQUENCE)?;
    let issuer = t.read(tag::SEQUENCE)?.raw;
    t.read(tag::SEQUENCE)?;
    t.read(tag::SEQUENCE)?;
    let spki = t.read(tag::SEQUENCE)?;
    t.read_optional(tag::context_prim(1))?;
    t.read_optional(tag::context_prim(2))?;
    let mut subject_key_id = None;
    if let Some(ext) = t.read_optional(tag::context_cons(3))? {
        let list = asn1::single(ext.content, ext.content_offset, tag::SEQUENCE)?;
        let mut l = list.reader();
        while !l.is_empty() {
            let extension = l.read(tag::SEQUENCE)?;
            let mut e = extension.reader();
            let id = read_oid(&mut e)?;
            e.read_optional(tag::BOOLEAN)?;
            let value = e.read(tag::OCTET_STRING)?;
            e.finish()?;
            if id == oid::SUBJECT_KEY_IDENTIFIER && subject_key_id.is_none() {
                let key_id = asn1::single(value.content, value.content_offset, tag::OCTET_STRING)?;
                subject_key_id = Some(key_id.content);
            }
        }
    }
    t.finish()?;

    let (key_alg, key_bits, key) = parse_spki(&spki)?;
    Ok(Certificate {
        issuer,
        serial,
        subject_key_id,
        key_alg,
        key_bits,
        key,
    })
}

type Spki<'a> = (KeyAlgorithm, Option<u32>, Option<CertKey<'a>>);

fn parse_spki<'a>(spki: &Tlv<'a>) -> std::result::Result<Spki<'a>, asn1::Asn1Error> {
    let mut s = spki.reader();
    let alg_id = s.read(tag::SEQUENCE)?;
    let key_bits_tlv = s.read(tag::BIT_STRING)?;
    s.finish()?;
    let key = asn1::bit_string_octets(&key_bits_tlv)?;
    let mut a = alg_id.reader();
    let alg = read_oid(&mut a)?;
    let params = if a.is_empty() {
        None
    } else {
        Some(a.read_any()?)
    };
    a.finish()?;
    Ok(match alg {
        oid::RSA_ENCRYPTION | oid::RSASSA_PSS => {
            let rsa = asn1::single(key, key_bits_tlv.content_offset, tag::SEQUENCE)?;
            let mut k = rsa.reader();
            let (_, bits) = asn1::unsigned_integer(&k.read(tag::INTEGER)?)?;
            asn1::unsigned_integer(&k.read(tag::INTEGER)?)?;
            k.finish()?;
            (
                KeyAlgorithm::Rsa,
                Some(bits),
                Some(CertKey::Rsa { der: key, bits }),
            )
        }
        oid::EC_PUBLIC_KEY => {
            let curve_oid = match &params {
                Some(p) => asn1::oid_bytes(p).ok(),
                None => None,
            };
            let curve = match curve_oid {
                Some(oid::P256) => Curve::P256,
                Some(oid::P384) => Curve::P384,
                Some(oid::P521) => Curve::P521,
                Some(other) => {
                    return Ok((KeyAlgorithm::EcOther(ObjectId::from_der(other)), None, None));
                }
                None => return Ok((KeyAlgorithm::Other(ObjectId::from_der(alg)), None, None)),
            };
            let bits = match curve {
                Curve::P256 => 256,
                Curve::P384 => 384,
                Curve::P521 => 521,
            };
            (
                KeyAlgorithm::Ec(curve),
                Some(bits),
                Some(CertKey::Ec { curve, point: key }),
            )
        }
        oid::ED25519 => (KeyAlgorithm::Ed25519, Some(256), None),
        oid::ED448 => (KeyAlgorithm::Ed448, Some(456), None),
        other => (KeyAlgorithm::Other(ObjectId::from_der(other)), None, None),
    })
}

/// Whether `cert` is the one `sid` names.
pub(crate) fn matches(cert: &Certificate<'_>, sid: &SignerIdentifier) -> bool {
    match sid {
        SignerIdentifier::IssuerAndSerial { issuer, serial } => {
            cert.issuer == issuer.as_slice() && cert.serial == serial.as_slice()
        }
        SignerIdentifier::SubjectKeyId(id) => cert.subject_key_id == Some(id.as_slice()),
    }
}
