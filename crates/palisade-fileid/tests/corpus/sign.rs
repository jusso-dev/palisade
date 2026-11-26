//! Pure-Rust Authenticode signing for the fixture generator: PKCS#7
//! SignedData over `SpcIndirectDataContent`, as code signers write it, so
//! fixtures can be made on any OS without OS signing tools (#25).
//!
//! Only SHA-256 is written. The signature covers the DER `SET` of the
//! authenticated attributes; the `messageDigest` attribute is the SHA-256 of
//! the content octets of the `SpcIndirectDataContent` SEQUENCE.

use palisade_fileid::authenticode::hash_pe;
use palisade_fileid::hash::{AlgorithmSet, HashAlgorithm};
use sha2::{Digest as _, Sha256};

use super::der::*;
use super::pki::{Cert, Key, OID_SHA256};

const OID_SIGNED_DATA: &str = "1.2.840.113549.1.7.2";
const OID_SPC_INDIRECT_DATA: &str = "1.3.6.1.4.1.311.2.1.4";
const OID_SPC_PE_IMAGE_DATA: &str = "1.3.6.1.4.1.311.2.1.15";
const OID_CONTENT_TYPE: &str = "1.2.840.113549.1.9.3";
const OID_MESSAGE_DIGEST: &str = "1.2.840.113549.1.9.4";
const OID_SIGNING_TIME: &str = "1.2.840.113549.1.9.5";
const OID_SPC_SP_OPUS_INFO: &str = "1.3.6.1.4.1.311.2.1.12";
const OID_SPC_STATEMENT_TYPE: &str = "1.3.6.1.4.1.311.2.1.11";
const OID_INDIVIDUAL_CODE_SIGNING: &str = "1.3.6.1.4.1.311.2.1.21";
const OID_NESTED_SIGNATURE: &str = "1.3.6.1.4.1.311.2.4.1";
const OID_PAGE_HASHES_V2: &str = "1.3.6.1.4.1.311.2.3.2";
/// `A6B586D5-B4A1-2466-AE05-A217DA8E60D6`, as encoded.
const PAGE_HASH_CLASS_ID: [u8; 16] = [
    0xa6, 0xb5, 0x86, 0xd5, 0xb4, 0xa1, 0x24, 0x66, 0xae, 0x05, 0xa2, 0x17, 0xda, 0x8e, 0x60, 0xd6,
];

/// The fixed signing time of every fixture: 2026-01-01 00:00:00 UTC.
pub const SIGNING_TIME: i64 = 1_767_225_600;

/// What to sign with.
pub struct Signer<'a> {
    pub leaf: &'a Cert,
    pub key: &'a Key,
    /// Certificates to embed after the leaf (intermediates, root).
    pub chain: &'a [&'a Cert],
}

fn attribute(id: &str, value: &[u8]) -> Vec<u8> {
    seq(&[&oid(id), &set(&[value])])
}

/// `SpcIndirectDataContent` for a PE image digest, with an optional SHA-256
/// page hash table (raw `offset || digest` entries).
fn indirect_data(image_digest: &[u8], page_table: Option<&[u8]>) -> Vec<u8> {
    let file = match page_table {
        // SpcLink [1] moniker: SpcSerializedObject { classId, serializedData }
        // whose data is SET { SEQUENCE { pageHashesV2, SET { OCTET STRING } } }.
        Some(table) => {
            let data = set(&[&seq(&[&oid(OID_PAGE_HASHES_V2), &set(&[&octets(table)])])]);
            tlv(0xa1, &[octets(&PAGE_HASH_CLASS_ID), octets(&data)].concat())
        }
        // SpcLink [2] file: SpcString [0] "" (BMP, empty).
        None => tlv(0xa2, &tlv(0x80, &[])),
    };
    let pe_image_data = seq(&[&bits(&[]), &explicit(0, &file)]);
    seq(&[
        &seq(&[&oid(OID_SPC_PE_IMAGE_DATA), &pe_image_data]),
        &seq(&[&alg(OID_SHA256), &octets(image_digest)]),
    ])
}

/// The content octets of a DER TLV (what `messageDigest` covers).
fn content_of(der: &[u8]) -> &[u8] {
    let len_byte = der[1];
    let header = if len_byte < 0x80 {
        2
    } else {
        2 + usize::from(len_byte & 0x7f)
    };
    &der[header..]
}

/// A PKCS#7 SignedData (DER) that signs `image_digest`, the SHA-256
/// Authenticode digest of a PE. `nested` signatures go in the unsigned
/// attributes, as dual signing does.
pub fn signed_data(
    signer: &Signer<'_>,
    image_digest: &[u8],
    page_table: Option<&[u8]>,
    nested: &[Vec<u8>],
) -> Vec<u8> {
    let content = indirect_data(image_digest, page_table);
    envelope(signer, OID_SPC_INDIRECT_DATA, &content, nested)
}

/// The OID of a certificate trust list, a catalog's content.
pub const OID_CTL: &str = "1.3.6.1.4.1.311.10.1";

/// A signed catalog: SignedData whose content is `ctl` (a DER
/// `CertificateTrustList`).
pub fn signed_catalog(signer: &Signer<'_>, ctl: &[u8]) -> Vec<u8> {
    envelope(signer, OID_CTL, ctl, &[])
}

/// SignedData over `content` (one DER SEQUENCE) of type `content_type`.
fn envelope(
    signer: &Signer<'_>,
    content_type: &str,
    content: &[u8],
    nested: &[Vec<u8>],
) -> Vec<u8> {
    let digest = Sha256::digest(content_of(content));
    // SpcSpOpusInfo { programName [0] SpcString { unicode [0] }, moreInfo [1] SpcLink { url [0] } }.
    let program: Vec<u8> = "Palisade test fixture"
        .encode_utf16()
        .flat_map(u16::to_be_bytes)
        .collect();
    let opus = seq(&[
        &explicit(0, &tlv(0x80, &program)),
        &explicit(1, &tlv(0x80, b"https://example.test/fixture")),
    ]);
    let attrs = [
        attribute(OID_CONTENT_TYPE, &oid(content_type)),
        attribute(OID_SIGNING_TIME, &time(SIGNING_TIME)),
        attribute(
            OID_SPC_STATEMENT_TYPE,
            &seq(&[&oid(OID_INDIVIDUAL_CODE_SIGNING)]),
        ),
        attribute(OID_MESSAGE_DIGEST, &octets(&digest)),
        attribute(OID_SPC_SP_OPUS_INFO, &opus),
    ];
    let attr_refs: Vec<&[u8]> = attrs.iter().map(Vec::as_slice).collect();
    let signed_attrs = set(&attr_refs);
    let signature = signer.key.sign(&signed_attrs);
    // [0] IMPLICIT SET OF Attribute: the same encoding with tag A0.
    let mut implicit_attrs = signed_attrs.clone();
    implicit_attrs[0] = 0xa0;

    let issuer_and_serial = {
        // The issuer of the leaf is the subject of the next certificate, or
        // the leaf itself when it is self-signed.
        let issuer = signer
            .chain
            .first()
            .map_or(&signer.leaf.subject, |c| &c.subject);
        seq(&[issuer, &int(signer.leaf.serial)])
    };
    let mut signer_info: Vec<Vec<u8>> = vec![
        int(1),
        issuer_and_serial,
        alg(OID_SHA256),
        implicit_attrs,
        match signer.key {
            Key::Rsa(_) => alg(super::pki::OID_RSA),
            Key::P256 { .. } => alg_no_params(super::pki::OID_ECDSA_SHA256),
        },
        octets(&signature),
    ];
    if !nested.is_empty() {
        let values: Vec<&[u8]> = nested.iter().map(Vec::as_slice).collect();
        signer_info.push(tlv(
            0xa1,
            &seq(&[&oid(OID_NESTED_SIGNATURE), &set(&values)]),
        ));
    }
    let si_refs: Vec<&[u8]> = signer_info.iter().map(Vec::as_slice).collect();
    let mut certs: Vec<&[u8]> = vec![&signer.leaf.der];
    certs.extend(signer.chain.iter().map(|c| c.der.as_slice()));
    let sd = seq(&[
        &int(1),
        &set(&[&alg(OID_SHA256)]),
        &seq(&[&oid(content_type), &explicit(0, content)]),
        &tlv(0xa0, &certs.concat()),
        &set(&[&seq(&si_refs)]),
    ]);
    seq(&[&oid(OID_SIGNED_DATA), &explicit(0, &sd)])
}

/// A `WIN_CERTIFICATE` entry (revision 2.0, PKCS#7), padded to 8 bytes.
pub fn win_certificate(pkcs7: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(pkcs7.len() as u32 + 8).to_le_bytes());
    out.extend_from_slice(&0x0200_u16.to_le_bytes());
    out.extend_from_slice(&2_u16.to_le_bytes());
    out.extend_from_slice(pkcs7);
    while out.len() % 8 != 0 {
        out.push(0);
    }
    out
}

/// The SHA-256 Authenticode digest of `image`, which must be a PE.
pub fn authenticode_sha256(image: &[u8]) -> Vec<u8> {
    hash_pe(image, AlgorithmSet::EMPTY)
        .expect("a PE image")
        .get(HashAlgorithm::Sha256)
        .expect("SHA-256 is always computed")
        .as_bytes()
        .to_vec()
}
