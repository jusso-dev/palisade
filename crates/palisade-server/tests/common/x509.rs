//! A minimal X.509 v3 certificate builder for tests: ECDSA P-256 keys and
//! signatures from `ring`, hand-encoded DER. Only what the tests need:
//! self-signed CAs, and leaves with subject alternative names and one
//! extended key usage.

use std::net::IpAddr;

use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};

const OID_ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
const OID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const OID_P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const OID_CN: &[u8] = &[0x55, 0x04, 0x03];
const OID_BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
const OID_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];
const OID_EXT_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x25];
const OID_SAN: &[u8] = &[0x55, 0x1d, 0x11];
const OID_SERVER_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
const OID_CLIENT_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02];

/// Which extended key usage a leaf carries.
#[derive(Clone, Copy)]
pub enum Usage {
    Server,
    Client,
}

/// A key pair and its PKCS#8 encoding.
pub struct Key {
    pair: EcdsaKeyPair,
    pkcs8: Vec<u8>,
}

impl Key {
    pub fn generate() -> Self {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
            .unwrap()
            .as_ref()
            .to_vec();
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &pkcs8, &rng).unwrap();
        Self { pair, pkcs8 }
    }

    pub fn pem(&self) -> String {
        pem("PRIVATE KEY", &self.pkcs8)
    }

    fn spki(&self) -> Vec<u8> {
        let alg = seq(&[oid(OID_EC_PUBLIC_KEY), oid(OID_P256)].concat());
        seq(&[alg, bit_string(self.pair.public_key().as_ref())].concat())
    }

    fn sign(&self, msg: &[u8]) -> Vec<u8> {
        self.pair
            .sign(&SystemRandom::new(), msg)
            .unwrap()
            .as_ref()
            .to_vec()
    }
}

/// A certificate authority: its key, name and certificate.
pub struct Ca {
    pub key: Key,
    name: Vec<u8>,
    pub der: Vec<u8>,
}

impl Ca {
    pub fn new(common_name: &str) -> Self {
        let key = Key::generate();
        let name = name(common_name);
        let exts = [
            extension(OID_BASIC_CONSTRAINTS, true, &seq(&tlv(0x01, &[0xff]))),
            // keyCertSign and cRLSign.
            extension(OID_KEY_USAGE, true, &tlv(0x03, &[0x01, 0x06])),
        ]
        .concat();
        let der = certificate(&key, &name, &name, &key.spki(), &exts);
        Self { key, name, der }
    }

    pub fn pem(&self) -> String {
        pem("CERTIFICATE", &self.der)
    }

    /// Issues a leaf for `sans` (DNS names or IP literals). Returns the
    /// certificate PEM and the key PEM.
    pub fn issue(&self, sans: &[&str], usage: Usage) -> (String, String) {
        let key = Key::generate();
        let subject = name(sans.first().copied().unwrap_or("leaf"));
        let mut names = Vec::new();
        for s in sans {
            match s.parse::<IpAddr>() {
                Ok(IpAddr::V4(v4)) => names.extend(tlv(0x87, &v4.octets())),
                Ok(IpAddr::V6(v6)) => names.extend(tlv(0x87, &v6.octets())),
                Err(_) => names.extend(tlv(0x82, s.as_bytes())),
            }
        }
        let eku = match usage {
            Usage::Server => OID_SERVER_AUTH,
            Usage::Client => OID_CLIENT_AUTH,
        };
        let mut exts = vec![
            // digitalSignature.
            extension(OID_KEY_USAGE, true, &tlv(0x03, &[0x07, 0x80])),
            extension(OID_EXT_KEY_USAGE, false, &seq(&oid(eku))),
        ];
        if !names.is_empty() {
            exts.push(extension(OID_SAN, false, &seq(&names)));
        }
        let der = certificate(&self.key, &self.name, &subject, &key.spki(), &exts.concat());
        (pem("CERTIFICATE", &der), key.pem())
    }
}

fn certificate(
    issuer_key: &Key,
    issuer: &[u8],
    subject: &[u8],
    spki: &[u8],
    exts: &[u8],
) -> Vec<u8> {
    use std::sync::atomic::{AtomicU8, Ordering};
    static SERIAL: AtomicU8 = AtomicU8::new(1);
    let alg = seq(&oid(OID_ECDSA_SHA256));
    let validity = seq(&[tlv(0x17, b"200101000000Z"), tlv(0x18, b"20991231235959Z")].concat());
    let tbs = seq(&[
        tlv(0xa0, &tlv(0x02, &[0x02])),
        tlv(0x02, &[0x01, SERIAL.fetch_add(1, Ordering::Relaxed) & 0x7f]),
        alg.clone(),
        issuer.to_vec(),
        validity,
        subject.to_vec(),
        spki.to_vec(),
        tlv(0xa3, &seq(exts)),
    ]
    .concat());
    let sig = issuer_key.sign(&tbs);
    seq(&[tbs, alg, bit_string(&sig)].concat())
}

fn name(common_name: &str) -> Vec<u8> {
    let atv = seq(&[oid(OID_CN), tlv(0x0c, common_name.as_bytes())].concat());
    seq(&tlv(0x31, &atv))
}

fn extension(id: &[u8], critical: bool, value: &[u8]) -> Vec<u8> {
    let mut body = oid(id);
    if critical {
        body.extend(tlv(0x01, &[0xff]));
    }
    body.extend(tlv(0x04, value));
    seq(&body)
}

fn oid(bytes: &[u8]) -> Vec<u8> {
    tlv(0x06, bytes)
}

fn bit_string(bytes: &[u8]) -> Vec<u8> {
    let mut body = vec![0];
    body.extend_from_slice(bytes);
    tlv(0x03, &body)
}

fn seq(body: &[u8]) -> Vec<u8> {
    tlv(0x30, body)
}

fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = body.len();
    if len < 0x80 {
        out.push(u8::try_from(len).unwrap());
    } else {
        let bytes: Vec<u8> = len
            .to_be_bytes()
            .into_iter()
            .skip_while(|b| *b == 0)
            .collect();
        out.push(0x80 | u8::try_from(bytes.len()).unwrap());
        out.extend(bytes);
    }
    out.extend_from_slice(body);
    out
}

fn pem(label: &str, der: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut b64 = String::new();
    for chunk in der.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |acc, (i, b)| acc | (u32::from(*b) << (16 - 8 * i)));
        for i in 0..4 {
            if i <= chunk.len() {
                let idx = usize::try_from((n >> (18 - 6 * i)) & 0x3f).unwrap();
                b64.push(char::from(ALPHABET[idx]));
            } else {
                b64.push('=');
            }
        }
    }
    let mut out = format!("-----BEGIN {label}-----\n");
    for line in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).unwrap());
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}
