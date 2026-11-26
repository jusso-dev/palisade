//! A throwaway test PKI: keys, X.509 certificates and CRLs, made at test
//! time and trusted by nothing outside these tests.
//!
//! RSA keys come from a deterministic RNG seeded by the key's name, so every
//! run (and every machine) makes the same keys, certificates and signatures,
//! and the golden hashes of signed fixtures are stable. These keys are test
//! material only: anyone can recompute them from this file.

use rand_core::{TryCryptoRng, TryRng};
use rsa::traits::PublicKeyParts;
use rsa::{Pkcs1v15Sign, PrivateKey};
use sha2::{Digest as _, Sha256};

use super::der::*;

pub const OID_RSA: &str = "1.2.840.113549.1.1.1";
pub const OID_SHA256_RSA: &str = "1.2.840.113549.1.1.11";
pub const OID_SHA1_RSA: &str = "1.2.840.113549.1.1.5";
pub const OID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
pub const OID_P256: &str = "1.2.840.10045.3.1.7";
pub const OID_ECDSA_SHA256: &str = "1.2.840.10045.4.3.2";
pub const OID_SHA256: &str = "2.16.840.1.101.3.4.2.1";
pub const OID_SHA1: &str = "1.3.14.3.2.26";
pub const EKU_CODE_SIGNING: &str = "1.3.6.1.5.5.7.3.3";
pub const EKU_SERVER_AUTH: &str = "1.3.6.1.5.5.7.3.1";

/// A deterministic RNG: SHA-256 in counter mode over a seed. Good enough
/// for repeatable throwaway test keys; never for anything else.
pub struct TestRng {
    seed: [u8; 32],
    counter: u64,
    buf: [u8; 32],
    used: usize,
}

impl TestRng {
    pub fn new(label: &str) -> Self {
        Self {
            seed: Sha256::digest(format!("palisade test key: {label}")).into(),
            counter: 0,
            buf: [0; 32],
            used: 32,
        }
    }

    fn byte(&mut self) -> u8 {
        if self.used == 32 {
            let mut h = Sha256::new();
            h.update(self.seed);
            h.update(self.counter.to_le_bytes());
            self.buf = h.finalize().into();
            self.counter += 1;
            self.used = 0;
        }
        let b = self.buf[self.used];
        self.used += 1;
        b
    }
}

impl TryRng for TestRng {
    type Error = core::convert::Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut b = [0; 4];
        self.try_fill_bytes(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut b = [0; 8];
        self.try_fill_bytes(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        for d in dst {
            *d = self.byte();
        }
        Ok(())
    }
}

impl TryCryptoRng for TestRng {}

/// A signing key.
pub enum Key {
    Rsa(Box<PrivateKey>),
    /// ECDSA P-256 (ring), as PKCS#8, with its public point.
    P256 {
        pkcs8: Vec<u8>,
        public: Vec<u8>,
    },
}

impl Key {
    /// An RSA key of `bits`, the same on every run for the same `label`.
    pub fn rsa(label: &str, bits: usize) -> Self {
        let mut rng = TestRng::new(label);
        Self::Rsa(Box::new(PrivateKey::new(&mut rng, bits).unwrap()))
    }

    /// An ECDSA P-256 key. ECDSA keys and signatures are random, so
    /// fixtures signed by one are not reproducible byte for byte; the
    /// corpus uses them only where that does not matter.
    pub fn p256() -> Self {
        use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
            .unwrap()
            .as_ref()
            .to_vec();
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &pkcs8, &rng).unwrap();
        let public = pair.public_key().as_ref().to_vec();
        Self::P256 { pkcs8, public }
    }

    pub fn bits(&self) -> usize {
        match self {
            Self::Rsa(k) => k.size() * 8,
            Self::P256 { .. } => 256,
        }
    }

    /// `SubjectPublicKeyInfo`.
    pub fn spki(&self) -> Vec<u8> {
        match self {
            Self::Rsa(k) => {
                let pk = seq(&[&uint(&k.n_bytes()), &uint(&k.e_bytes())]);
                seq(&[&alg(OID_RSA), &bits(&pk)])
            }
            Self::P256 { public, .. } => seq(&[
                &seq(&[&oid(OID_EC_PUBLIC_KEY), &oid(OID_P256)]),
                &bits(public),
            ]),
        }
    }

    /// The `AlgorithmIdentifier` of this key's signatures over SHA-256.
    pub fn sig_alg(&self) -> Vec<u8> {
        match self {
            Self::Rsa(_) => alg(OID_SHA256_RSA),
            Self::P256 { .. } => alg_no_params(OID_ECDSA_SHA256),
        }
    }

    /// Signs `message` with SHA-256.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        match self {
            Self::Rsa(k) => k
                .sign(Pkcs1v15Sign::new::<Sha256>(), &Sha256::digest(message))
                .unwrap(),
            Self::P256 { pkcs8, .. } => {
                use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair};
                let rng = ring::rand::SystemRandom::new();
                let pair =
                    EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8, &rng).unwrap();
                pair.sign(&rng, message).unwrap().as_ref().to_vec()
            }
        }
    }

    /// The subject key identifier: SHA-256 of the public key, first 20 bytes.
    pub fn key_id(&self) -> Vec<u8> {
        Sha256::digest(self.spki())[..20].to_vec()
    }
}

/// `Name` with an O and a CN.
pub fn name(cn: &str) -> Vec<u8> {
    let rdn = |o: &str, v: &str| set(&[&seq(&[&oid(o), &utf8(v)])]);
    seq(&[&rdn("2.5.4.10", "Palisade Tests"), &rdn("2.5.4.3", cn)])
}

fn ext(id: &str, critical: bool, value: &[u8]) -> Vec<u8> {
    if critical {
        seq(&[&oid(id), &boolean(true), &octets(value)])
    } else {
        seq(&[&oid(id), &octets(value)])
    }
}

/// What kind of certificate to issue.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    /// A CA: `cA`, `keyCertSign` and `cRLSign`.
    Ca,
    /// A code-signing leaf: `digitalSignature`, EKU code signing.
    CodeSigning,
    /// A leaf with only the TLS server EKU, which code signing must refuse.
    ServerAuth,
}

/// A certificate to issue.
pub struct Spec<'a> {
    pub cn: &'a str,
    pub serial: u64,
    pub not_before: i64,
    pub not_after: i64,
    pub role: Role,
    pub key: &'a Key,
}

/// A certificate: its DER, and what is needed to issue under it.
pub struct Cert {
    pub der: Vec<u8>,
    pub subject: Vec<u8>,
    pub serial: u64,
    pub key_id: Vec<u8>,
}

/// Issues `spec`, signed by `issuer` (or self-signed when `None`).
pub fn issue(spec: &Spec<'_>, issuer: Option<(&Cert, &Key)>) -> Cert {
    let subject = name(spec.cn);
    let key_id = spec.key.key_id();
    let (issuer_name, signer, aki) = match issuer {
        Some((cert, key)) => (cert.subject.clone(), key, cert.key_id.clone()),
        None => (subject.clone(), spec.key, key_id.clone()),
    };
    let mut exts = Vec::new();
    match spec.role {
        Role::Ca => {
            exts.push(ext("2.5.29.19", true, &seq(&[&boolean(true)])));
            // keyCertSign (5) | cRLSign (6): bits 0b0000_0110 shifted.
            exts.push(ext("2.5.29.15", true, &tlv(0x03, &[0x01, 0x06])));
        }
        Role::CodeSigning | Role::ServerAuth => {
            exts.push(ext("2.5.29.19", true, &seq(&[])));
            // digitalSignature (0).
            exts.push(ext("2.5.29.15", true, &tlv(0x03, &[0x07, 0x80])));
            let eku = if spec.role == Role::CodeSigning {
                EKU_CODE_SIGNING
            } else {
                EKU_SERVER_AUTH
            };
            exts.push(ext("2.5.29.37", false, &seq(&[&oid(eku)])));
        }
    }
    exts.push(ext("2.5.29.14", false, &octets(&key_id)));
    exts.push(ext("2.5.29.35", false, &seq(&[&tlv(0x80, &aki)])));
    let ext_refs: Vec<&[u8]> = exts.iter().map(Vec::as_slice).collect();
    let tbs = seq(&[
        &explicit(0, &int(2)),
        &int(spec.serial),
        &signer.sig_alg(),
        &issuer_name,
        &seq(&[&time(spec.not_before), &time(spec.not_after)]),
        &subject,
        &spec.key.spki(),
        &explicit(3, &seq(&ext_refs)),
    ]);
    let sig = signer.sign(&tbs);
    let der = seq(&[&tbs, &signer.sig_alg(), &bits(&sig)]);
    Cert {
        der,
        subject,
        serial: spec.serial,
        key_id,
    }
}

/// A v2 CRL from `issuer`, listing `revoked` serials (revoked at
/// `revoked_at`, reason key compromise).
pub fn crl(
    issuer: (&Cert, &Key),
    this_update: i64,
    next_update: i64,
    revoked: &[(u64, i64)],
) -> Vec<u8> {
    let (cert, key) = issuer;
    let entries: Vec<Vec<u8>> = revoked
        .iter()
        .map(|(serial, at)| {
            // reasonCode keyCompromise (1).
            let reason = seq(&[&oid("2.5.29.21"), &octets(&tlv(0x0a, &[1]))]);
            seq(&[&int(*serial), &time(*at), &seq(&[&reason])])
        })
        .collect();
    let entry_refs: Vec<&[u8]> = entries.iter().map(Vec::as_slice).collect();
    let aki = seq(&[
        &oid("2.5.29.35"),
        &octets(&seq(&[&tlv(0x80, &cert.key_id)])),
    ]);
    let number = seq(&[&oid("2.5.29.20"), &octets(&int(1))]);
    let mut parts: Vec<Vec<u8>> = vec![
        int(1),
        key.sig_alg(),
        cert.subject.clone(),
        time(this_update),
        time(next_update),
    ];
    if !entries.is_empty() {
        parts.push(seq(&entry_refs));
    }
    parts.push(explicit(0, &seq(&[&aki, &number])));
    let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
    let tbs = seq(&refs);
    let sig = key.sign(&tbs);
    seq(&[&tbs, &key.sig_alg(), &bits(&sig)])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_test_rng_is_deterministic_per_label() {
        let mut a = TestRng::new("x");
        let mut b = TestRng::new("x");
        let mut c = TestRng::new("y");
        let (x1, x2, y) = (
            a.try_next_u64().unwrap(),
            b.try_next_u64().unwrap(),
            c.try_next_u64().unwrap(),
        );
        assert_eq!(x1, x2);
        assert_ne!(x1, y);
    }
}
