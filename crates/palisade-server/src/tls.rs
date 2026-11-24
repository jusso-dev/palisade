//! TLS for every listener.
//!
//! All listeners terminate TLS with `rustls` and the `ring` provider
//! ([ADR 0008](../../../docs/adr/0008-cryptographic-algorithms.md)). There is
//! no plaintext listener and no option to add one. The provider is cut down
//! to an explicit allowlist of cipher suites and key exchange groups, so a
//! future default change in `rustls` cannot widen the policy:
//!
//! | Profile | TLS 1.3 suites | TLS 1.2 suites | Key exchange |
//! |---|---|---|---|
//! | `default` | AES-256-GCM-SHA384, AES-128-GCM-SHA256 | ECDHE-ECDSA/RSA with AES-256-GCM or AES-128-GCM | X25519, P-256, P-384 |
//! | `asd-strict` | AES-256-GCM-SHA384 | ECDHE-ECDSA/RSA with AES-256-GCM-SHA384 | P-384 |
//!
//! ChaCha20-Poly1305 is left out because it is not on the ASD-approved list.
//! TLS 1.0 and 1.1 are not implemented by `rustls` at all. TLS 1.2 requires
//! the extended master secret extension.
//!
//! The agent listener requires a client certificate that chains to the
//! configured agent CA bundle. Checking that certificate against the
//! enrolled device record and revocation state is enrolment work (#223).

use std::path::Path;
use std::sync::Arc;

use rustls::crypto::{CryptoProvider, ring};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::server::{ParsedCertificate, WebPkiClientVerifier};
use rustls::{RootCertStore, ServerConfig, SupportedProtocolVersion, version};

use crate::config::{CryptoProfile, TlsSettings, TlsVersion};
use crate::secret::read_secret_file;

/// Largest certificate or CA bundle file accepted, in bytes.
const MAX_CERT_FILE: u64 = 1024 * 1024;
/// Largest private key file accepted, in bytes.
const MAX_KEY_FILE: usize = 64 * 1024;

/// The restricted `ring` provider for `profile`.
pub fn provider(profile: CryptoProfile) -> CryptoProvider {
    use ring::cipher_suite as cs;
    use ring::kx_group as kx;
    let base = ring::default_provider();
    let (cipher_suites, kx_groups) = match profile {
        CryptoProfile::Default => (
            vec![
                cs::TLS13_AES_256_GCM_SHA384,
                cs::TLS13_AES_128_GCM_SHA256,
                cs::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                cs::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                cs::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                cs::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            ],
            vec![kx::X25519, kx::SECP256R1, kx::SECP384R1],
        ),
        CryptoProfile::AsdStrict => (
            vec![
                cs::TLS13_AES_256_GCM_SHA384,
                cs::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                cs::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            ],
            vec![kx::SECP384R1],
        ),
    };
    CryptoProvider {
        cipher_suites,
        kx_groups,
        ..base
    }
}

static TLS12_AND_13: [&SupportedProtocolVersion; 2] = [&version::TLS13, &version::TLS12];
static TLS13_ONLY: [&SupportedProtocolVersion; 1] = [&version::TLS13];

fn versions(min: TlsVersion) -> &'static [&'static SupportedProtocolVersion] {
    match min {
        TlsVersion::Tls12 => &TLS12_AND_13,
        TlsVersion::Tls13 => &TLS13_ONLY,
    }
}

/// The server certificate chain and key, loaded once and shared.
#[derive(Clone)]
pub struct Identity {
    chain: Vec<CertificateDer<'static>>,
    key: Arc<PrivateKeyDer<'static>>,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("chain_len", &self.chain.len())
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl Identity {
    /// Loads the chain from `cert_file` and the key from `key_file` (a
    /// secret file; see [`read_secret_file`]).
    pub fn load(tls: &TlsSettings) -> Result<Self, String> {
        let chain = read_certs(&tls.cert_file)?;
        let key_pem = read_secret_file(&tls.key_file, MAX_KEY_FILE)?;
        // The PEM parser's error text can quote input lines, so it is not
        // passed on: only the path and a fixed reason are reported.
        let key = PrivateKeyDer::from_pem_slice(&key_pem).map_err(|_| {
            format!(
                "{}: no PKCS#8, PKCS#1 or SEC1 private key found in PEM form",
                tls.key_file.display()
            )
        })?;
        Ok(Self {
            chain,
            key: Arc::new(key),
        })
    }

    fn leaf(&self) -> Result<&CertificateDer<'static>, String> {
        self.chain
            .first()
            .ok_or_else(|| "the certificate chain is empty".to_owned())
    }
}

/// Reads one or more PEM certificates. Fails if there are none.
pub fn read_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, String> {
    use std::io::Read;
    let shown = path.display();
    let file = std::fs::File::open(path).map_err(|e| format!("cannot read {shown}: {e}"))?;
    let mut bytes = Vec::new();
    file.take(MAX_CERT_FILE + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("cannot read {shown}: {e}"))?;
    if bytes.len() as u64 > MAX_CERT_FILE {
        return Err(format!("{shown} is larger than {MAX_CERT_FILE} bytes"));
    }
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&bytes)
        .collect::<Result<_, _>>()
        .map_err(|e| format!("{shown}: invalid PEM certificate: {e}"))?;
    if certs.is_empty() {
        return Err(format!("{shown}: no PEM certificates found"));
    }
    Ok(certs)
}

/// Builds the `rustls` server configuration for one listener.
///
/// `client_ca` is set for the agent listener: the handshake then fails
/// unless the client presents a certificate chaining to one of those CAs.
pub fn server_config(
    tls: &TlsSettings,
    identity: &Identity,
    client_ca: Option<&Path>,
    alpn: &[&[u8]],
) -> Result<Arc<ServerConfig>, String> {
    let provider = Arc::new(provider(tls.profile));
    let builder = ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(versions(tls.min_version))
        .map_err(|e| format!("TLS policy rejected by rustls: {e}"))?;
    let builder = match client_ca {
        None => builder.with_no_client_auth(),
        Some(path) => {
            let mut roots = RootCertStore::empty();
            for cert in read_certs(path)? {
                roots
                    .add(cert)
                    .map_err(|e| format!("{}: unusable CA certificate: {e}", path.display()))?;
            }
            let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider)
                .build()
                .map_err(|e| format!("{}: {e}", path.display()))?;
            builder.with_client_cert_verifier(verifier)
        }
    };
    let mut config = builder
        .with_single_cert(identity.chain.clone(), identity.key.clone_key())
        .map_err(|e| {
            format!(
                "{} and {} do not form a usable certificate and key: {e}",
                tls.cert_file.display(),
                tls.key_file.display()
            )
        })?;
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    config.ignore_client_order = true;
    config.require_ems = true;
    Ok(Arc::new(config))
}

/// Fills `buf` from the TLS provider's secure random source, so the crate
/// reaches `ring` only through `rustls` (ADR 0008).
pub fn fill_random(buf: &mut [u8]) -> Result<(), String> {
    static RANDOM: std::sync::OnceLock<&'static dyn rustls::crypto::SecureRandom> =
        std::sync::OnceLock::new();
    RANDOM
        .get_or_init(|| ring::default_provider().secure_random)
        .fill(buf)
        .map_err(|_| "the system random source failed".to_owned())
}

/// Checks that `host` is one of the leaf certificate's subject alternative
/// names (DNS or IP), using the same matching a TLS client applies.
pub fn leaf_covers(identity: &Identity, host: &ServerName<'_>) -> Result<(), String> {
    let parsed = ParsedCertificate::try_from(identity.leaf()?)
        .map_err(|e| format!("cannot parse the leaf certificate: {e}"))?;
    rustls::client::verify_server_name(&parsed, host).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::CipherSuite;
    use rustls::NamedGroup;

    fn suites(p: &CryptoProvider) -> Vec<CipherSuite> {
        p.cipher_suites.iter().map(|s| s.suite()).collect()
    }

    fn groups(p: &CryptoProvider) -> Vec<NamedGroup> {
        p.kx_groups.iter().map(|g| g.name()).collect()
    }

    #[test]
    fn default_profile_is_aead_gcm_only() {
        let p = provider(CryptoProfile::Default);
        let s = suites(&p);
        assert_eq!(s.len(), 6);
        for suite in &s {
            let name = format!("{suite:?}");
            assert!(name.contains("_GCM_"), "{name} is not AES-GCM");
            assert!(!name.contains("CHACHA"), "{name}");
        }
        assert_eq!(
            groups(&p),
            [
                NamedGroup::X25519,
                NamedGroup::secp256r1,
                NamedGroup::secp384r1
            ]
        );
    }

    #[test]
    fn strict_profile_is_aes256_sha384_p384() {
        let p = provider(CryptoProfile::AsdStrict);
        for suite in suites(&p) {
            let name = format!("{suite:?}");
            assert!(name.contains("AES_256_GCM_SHA384"), "{name}");
        }
        assert_eq!(groups(&p), [NamedGroup::secp384r1]);
    }

    #[test]
    fn versions_follow_minimum() {
        assert_eq!(versions(TlsVersion::Tls12).len(), 2);
        assert_eq!(versions(TlsVersion::Tls13).len(), 1);
    }
}
