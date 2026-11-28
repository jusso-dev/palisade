//! The agent's TLS client (#223): server authentication by pin, and the
//! device key as the client identity.
//!
//! The agent does not trust the OS root store. A server chain is accepted
//! only if it verifies under the WebPKI rules (hostname always checked,
//! validity, key usage) to a root whose `SubjectPublicKeyInfo` SHA-256 is
//! one of the agent's pins:
//!
//! - before enrolment, the CA pin it was installed with
//!   (`PALISADE_CA_PIN=sha256/<hex>`);
//! - afterwards, the server pins of its current trust set.
//!
//! The server sends its root at the end of its chain; the verifier builds a
//! one-certificate root store from the last certificate whose key matches a
//! pin, and lets WebPKI verify the rest against it. A chain whose root is
//! not pinned fails with `transport.pin_mismatch` (possible interception),
//! which is never retried on a weaker setting.
//!
//! Protocol versions, cipher suites and groups are the same restricted
//! `ring` provider as the server's `default` profile (#223): TLS 1.3 and
//! 1.2, AES-GCM only, X25519, P-256 and P-384.
//!
//! The client certificate is signed with [`LeafKey::sign_tls`], so the
//! private key stays inside the key type; the TPM-backed key of #220 slots
//! in behind the same signing call.

#![forbid(unsafe_code)]

use std::fmt;
use std::sync::Arc;

use palisade_proto::events::Sha256Hex;
use palisade_proto::pki::leaf_key::LeafKey;
use palisade_proto::pki::spki_sha256;
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, ring};
use rustls::pki_types::{CertificateDer, ServerName, SubjectPublicKeyInfoDer, UnixTime};
use rustls::server::ParsedCertificate;
use rustls::sign::{CertifiedKey, Signer, SigningKey};
use rustls::{
    ClientConfig, DigitallySignedStruct, Error as TlsError, RootCertStore, SignatureAlgorithm,
    SignatureScheme,
};

/// The restricted provider (#223 `default` profile).
#[must_use]
pub fn provider() -> CryptoProvider {
    use ring::cipher_suite as cs;
    use ring::kx_group as kx;
    CryptoProvider {
        cipher_suites: vec![
            cs::TLS13_AES_256_GCM_SHA384,
            cs::TLS13_AES_128_GCM_SHA256,
            cs::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            cs::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            cs::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            cs::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        ],
        kx_groups: vec![kx::X25519, kx::SECP256R1, kx::SECP384R1],
        ..ring::default_provider()
    }
}

/// The marker [`PinnedVerifier`] puts in its error, so the transport can
/// tell a pin mismatch from other TLS failures.
pub const PIN_MISMATCH: &str = "transport.pin_mismatch";

/// Verifies a server chain against pinned root keys.
#[derive(Debug)]
pub struct PinnedVerifier {
    pins: Vec<Sha256Hex>,
    provider: Arc<CryptoProvider>,
}

impl PinnedVerifier {
    /// A verifier that accepts roots whose key hash is in `pins`.
    #[must_use]
    pub fn new(pins: Vec<Sha256Hex>) -> Self {
        Self {
            pins,
            provider: Arc::new(provider()),
        }
    }
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        // The pinned root: the last certificate the server sent whose key is
        // pinned. Self-signed or not, WebPKI checks the chain up to it.
        let root = intermediates
            .iter()
            .rev()
            .find(|c| spki_of(c).is_some_and(|spki| self.pins.contains(&spki_sha256(&spki))));
        let Some(root) = root else {
            return Err(TlsError::General(PIN_MISMATCH.to_owned()));
        };
        let mut roots = RootCertStore::empty();
        roots
            .add(root.clone().into_owned())
            .map_err(|_| TlsError::General(PIN_MISMATCH.to_owned()))?;
        let inner =
            WebPkiServerVerifier::builder_with_provider(Arc::new(roots), self.provider.clone())
                .build()
                .map_err(|e| TlsError::General(e.to_string()))?;
        let rest: Vec<CertificateDer<'_>> = intermediates
            .iter()
            .filter(|c| c.as_ref() != root.as_ref())
            .cloned()
            .collect();
        inner.verify_server_cert(end_entity, &rest, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// A certificate's DER `SubjectPublicKeyInfo`, through WebPKI's parser.
fn spki_of(cert: &CertificateDer<'_>) -> Option<Vec<u8>> {
    // `ParsedCertificate` parses as an end entity, which reads any
    // certificate's key without judging its use.
    ParsedCertificate::try_from(cert)
        .ok()
        .map(|p| p.subject_public_key_info().as_ref().to_vec())
}

/// The device key as a `rustls` signing key: ECDSA P-384 with SHA-384.
pub struct DeviceSigningKey(pub Arc<LeafKey>);

impl fmt::Debug for DeviceSigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DeviceSigningKey({:?})", self.0)
    }
}

impl SigningKey for DeviceSigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        offered
            .contains(&SignatureScheme::ECDSA_NISTP384_SHA384)
            .then(|| Box::new(DeviceSigner(self.0.clone())) as Box<dyn Signer>)
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        Some(SubjectPublicKeyInfoDer::from(
            self.0.public_key().spki_der(),
        ))
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ECDSA
    }
}

struct DeviceSigner(Arc<LeafKey>);

impl fmt::Debug for DeviceSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DeviceSigner")
    }
}

impl Signer for DeviceSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, TlsError> {
        self.0
            .sign_tls(message)
            .map_err(|e| TlsError::General(e.to_string()))
    }

    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ECDSA_NISTP384_SHA384
    }
}

/// A client configuration: `pins` authenticate the server, and `identity`
/// (the device chain and key), when given, authenticates the client.
///
/// # Errors
///
/// A message if `rustls` refuses the protocol versions.
pub fn client_config(
    pins: Vec<Sha256Hex>,
    identity: Option<(Vec<Vec<u8>>, Arc<LeafKey>)>,
) -> Result<Arc<ClientConfig>, String> {
    let provider = Arc::new(provider());
    let builder = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedVerifier::new(pins)));
    let config = match identity {
        None => builder.with_no_client_auth(),
        Some((chain, key)) => {
            let certified = CertifiedKey::new(
                chain.into_iter().map(CertificateDer::from).collect(),
                Arc::new(DeviceSigningKey(key)),
            );
            builder.with_client_cert_resolver(Arc::new(Resolver(Arc::new(certified))))
        }
    };
    Ok(Arc::new(config))
}

#[derive(Debug)]
struct Resolver(Arc<CertifiedKey>);

impl rustls::client::ResolvesClientCert for Resolver {
    fn resolve(&self, _: &[&[u8]], schemes: &[SignatureScheme]) -> Option<Arc<CertifiedKey>> {
        schemes
            .contains(&SignatureScheme::ECDSA_NISTP384_SHA384)
            .then(|| self.0.clone())
    }

    fn has_certs(&self) -> bool {
        true
    }
}
