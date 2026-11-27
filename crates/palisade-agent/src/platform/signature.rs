//! [`SignatureVerifier`] through `palisade_fileid`.
//!
//! Every verdict comes from `palisade_fileid`'s own verification: the
//! Authenticode signatures and their chains (#48, #49), timestamps, expiry
//! and revocation (#50), and the catalog store (#51). None of it calls the
//! OS, so this backend is the same on every OS and its tests run
//! everywhere. The OS trust-verification API
//! (`palisade_fileid::win::trust`, feature `os-trust`) is a diagnostic
//! cross-check that must never decide, so it is not consulted here.

use std::io::Read as _;
use std::path::Path;

use palisade_core::platform::{
    CertificateSummary, Clock, ErrorKind, PlatformError, Result, SignatureResult, SignatureSource,
    SignatureVerifier, UtcTime,
};
use palisade_fileid::authenticode::{
    CertSummary, ChainReport, DigestAlgorithm, ReportWarning, RevocationSet, SigningState,
    TrustConfig, ValidityContext, ValidityPolicy, VerificationError, VerifyOptions, evaluate_trust,
    evaluate_validity, hash_pe, verify_pe,
};
use palisade_fileid::catalog::{
    CatalogMatch, CatalogStatus, CatalogStore, FileDigests, LoadReport,
};
use palisade_fileid::hash::{AlgorithmSet, Digest, HashAlgorithm, hash_bytes};
use palisade_fileid::pe::{ParseOptions, parse_with};

use super::io_error;
use super::system::{SystemClock, open_shared};

/// The largest file read for signature checks by default: 256 MiB. A
/// larger file is [`ErrorKind::TooLarge`], never reported as unsigned.
pub const DEFAULT_MAX_FILE_SIZE: u64 = 256 * 1024 * 1024;

/// What signatures are judged against. Everything here comes from policy
/// (#6, #9); the default trusts nothing, so every chain is
/// [`VerificationError::UntrustedRoot`] until policy supplies anchors.
#[derive(Debug, Clone, Default)]
pub struct SignatureSettings {
    /// Anchors and intermediates for code-signing chains.
    pub trust: TrustConfig,
    /// Anchors for timestamping authorities.
    pub tsa_trust: TrustConfig,
    /// Expiry, timestamp and key-size rules.
    pub policy: ValidityPolicy,
    /// Revocation data.
    pub revocation: RevocationSet,
}

/// Signature lookup and chain validation through `palisade_fileid`.
///
/// Fail closed (ADR 0018):
///
/// - a file that cannot be read, or is larger than the size limit, is an
///   error, never "unsigned"; a file that starts like a PE image (`MZ`) but
///   does not parse, or whose certificate table cannot be read, is
///   [`VerificationError::MalformedSignature`], never "unsigned";
/// - a file whose hash is revoked (its flat or Authenticode SHA-256 or
///   SHA-1, under `settings.revocation`) is
///   [`VerificationError::RevokedByHash`], on the embedded and the catalog
///   path alike;
/// - a signature or catalog match that relies on SHA-1 (an image digest,
///   a signer digest, a member digest or a catalog's own signature) is
///   [`VerificationError::WeakHashAlgorithm`], never `Ok`, so no allow
///   rests on it (ADR 0008);
/// - with no catalog store loaded, [`SignatureVerifier::catalog`] is
///   [`ErrorKind::Unsupported`], not "no catalog signature"; and when the
///   store is incomplete (a catalog was unreadable, or a load error or
///   limit left catalogs or members out), a miss is an error too, since
///   the file could be in what is missing;
/// - a catalog match whose validity was never judged is not `Ok`.
///
/// **When things are judged.** Embedded signatures are judged on every
/// call, against `settings` and `clock`. A catalog's own signature (its
/// chain's expiry, timestamps and revocation) is judged once, when the
/// store is built, against the `ValidityOptions` given to its builder:
/// rebuild the store to re-judge it (the catalog index refresh, #60, #65).
/// The rest of a catalog verdict is judged on every call: revocation of
/// the file's own hash and SHA-1 use against `settings`, and trust as the
/// store recorded it.
///
/// Signing times and expiry are judged against `clock`. The agent's
/// anchored time and clock floor (ADR 0018, #220) replace the plain wall
/// clock when they land.
#[derive(Debug)]
pub struct FileidSignatures<C = SystemClock> {
    settings: SignatureSettings,
    catalogs: Option<CatalogStore>,
    /// Every catalog that was meant to be loaded is in the store.
    catalogs_complete: bool,
    clock: C,
    max_file_size: u64,
}

impl FileidSignatures<SystemClock> {
    /// A verifier with `settings`, no catalog store, and the system clock.
    #[must_use]
    pub fn new(settings: SignatureSettings) -> Self {
        Self::with_clock(settings, SystemClock)
    }
}

impl<C: Clock> FileidSignatures<C> {
    /// A verifier that judges time against `clock`.
    #[must_use]
    pub fn with_clock(settings: SignatureSettings, clock: C) -> Self {
        Self {
            settings,
            catalogs: None,
            catalogs_complete: false,
            clock,
            max_file_size: DEFAULT_MAX_FILE_SIZE,
        }
    }

    /// Uses `store` for catalog lookups. Load it with
    /// `palisade_fileid::catalog::CatalogStoreBuilder`, with the trust
    /// configuration and validity options of each source: a match is only
    /// `Ok` if its catalog is trusted and its validity was judged.
    ///
    /// `loads` are the reports of every load call that built it. If any
    /// reports an error (I/O, a size, byte, count, depth or entry limit, a
    /// file that changed) or dropped errors, or the store holds an
    /// unreadable catalog or a truncated index, the store is incomplete
    /// and a catalog miss is an error, not "no catalog signature".
    #[must_use]
    pub fn with_catalogs<'a>(
        mut self,
        store: CatalogStore,
        loads: impl IntoIterator<Item = &'a LoadReport>,
    ) -> Self {
        let loaded = loads
            .into_iter()
            .all(|r| r.errors.is_empty() && !r.errors_truncated);
        let indexed = store
            .records()
            .iter()
            .all(|r| !r.index_truncated && !matches!(r.status, CatalogStatus::Unreadable(_)));
        self.catalogs_complete = loaded && indexed;
        self.catalogs = Some(store);
        self
    }

    /// Sets the largest file read.
    #[must_use]
    pub const fn with_max_file_size(mut self, bytes: u64) -> Self {
        self.max_file_size = bytes;
        self
    }

    fn read(&self, path: &str) -> Result<Vec<u8>> {
        let p = Path::new(path);
        if !p.is_absolute() {
            return Err(PlatformError::new(
                ErrorKind::InvalidInput,
                format!("not an absolute path: {path}"),
            ));
        }
        let file = open_shared(p).map_err(|e| io_error(&e, path))?;
        let meta = file.metadata().map_err(|e| io_error(&e, path))?;
        // A named data stream on a directory reports the directory
        // attribute but holds data: decide from the path, as the shared
        // file-system backend does. The directory itself is still refused.
        if meta.is_dir() && !super::system::names_a_stream(path) {
            return Err(PlatformError::new(
                ErrorKind::InvalidInput,
                format!("a directory has no signature: {path}"),
            ));
        }
        let mut bytes = Vec::new();
        file.take(self.max_file_size.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|e| io_error(&e, path))?;
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > self.max_file_size {
            return Err(PlatformError::new(
                ErrorKind::TooLarge,
                format!(
                    "{path} is larger than {} bytes, the signature check limit",
                    self.max_file_size
                ),
            ));
        }
        Ok(bytes)
    }
}

/// A display name for a certificate: the `CN`, else the `O`, else the whole
/// distinguished name.
fn name(dn: &palisade_fileid::authenticode::DistinguishedName) -> String {
    dn.common_name()
        .or_else(|| dn.organization())
        .map_or_else(|| dn.canonical.clone(), str::to_owned)
}

fn summary(cert: &CertSummary) -> CertificateSummary {
    let flat = hash_bytes(&cert.der, AlgorithmSet::SHA256);
    let mut sha256 = [0_u8; 32];
    if let Some(d) = flat.get(HashAlgorithm::Sha256) {
        sha256.copy_from_slice(d.as_bytes());
    }
    CertificateSummary {
        subject: name(&cert.subject),
        issuer: name(&cert.issuer),
        sha256,
    }
}

/// The full chain, leaf first.
fn chain(report: Option<&ChainReport>) -> Vec<CertificateSummary> {
    report
        .map(|c| c.full_chain_certs().map(summary).collect())
        .unwrap_or_default()
}

fn utc(secs: i64) -> UtcTime {
    UtcTime(secs.saturating_mul(1_000_000))
}

/// Whether a digest algorithm is SHA-256 or stronger. An unknown one is
/// not.
fn is_sha2(alg: Option<DigestAlgorithm>) -> bool {
    alg.is_some_and(DigestAlgorithm::is_sha2)
}

/// The status of a catalog match.
fn catalog_status(m: &CatalogMatch<'_>) -> VerificationError {
    if m.relies_on_sha1() {
        return VerificationError::WeakHashAlgorithm;
    }
    if !m.trusted() {
        return VerificationError::UntrustedRoot;
    }
    match &m.record.validity {
        Some(v) => v.error,
        // Trusted, but expiry and revocation were never checked: not Ok.
        None => VerificationError::Generic,
    }
}

/// The digests a revoked-hash entry may name: the flat SHA-256 and SHA-1
/// of the file, and for a PE image its Authenticode SHA-256 and SHA-1.
fn revocation_digests(data: &[u8]) -> Vec<Digest> {
    let mut digests = hash_bytes(data, AlgorithmSet::SHA256 | AlgorithmSet::SHA1).digests;
    if let Some(image) = hash_pe(data, AlgorithmSet::EMPTY) {
        digests.extend(image.digests);
    }
    digests
}

/// One embedded result that says the signature could not be read.
fn malformed() -> Vec<SignatureResult> {
    vec![SignatureResult {
        source: SignatureSource::Embedded,
        status: VerificationError::MalformedSignature,
        chain: Vec::new(),
        signing_time: None,
    }]
}

impl<C: Clock> SignatureVerifier for FileidSignatures<C> {
    fn embedded(&self, path: &str) -> Result<Vec<SignatureResult>> {
        let data = self.read(path)?;
        let Ok(info) = parse_with(&data, &ParseOptions::metadata_only()) else {
            // Not a PE image: no embedded Authenticode signature. But a
            // file that starts like one and does not parse is not
            // "unsigned": its signature cannot be read.
            return Ok(if data.starts_with(b"MZ") {
                malformed()
            } else {
                Vec::new()
            });
        };
        let Ok(report) = verify_pe(&data, &VerifyOptions::default()) else {
            return Ok(malformed());
        };
        // A certificate entry of an unknown revision or type is skipped by
        // the parser, so a signed image whose entry was altered can read as
        // unsigned. Any such entry means the signature cannot be read.
        let unknown_entry = report
            .warnings
            .iter()
            .any(|w| matches!(w, ReportWarning::UnknownEntry { .. }));
        if report.signatures.is_empty() {
            // An unreadable certificate table is a malformed signature,
            // not an unsigned file.
            return Ok(match report.signing_state {
                SigningState::Unsigned if !unknown_entry => Vec::new(),
                _ => malformed(),
            });
        }
        let s = &self.settings;
        // `relax_trust` hands chain building the certificates a policy
        // option lets issue despite basic constraints. `evaluate_validity`
        // still refuses the relaxation unless an option names the issuer,
        // so with no options this is the configured trust, unchanged.
        let mut chain_trust = s.trust.clone();
        s.policy.relax_trust(&mut chain_trust);
        let trust = evaluate_trust(&report, &chain_trust, info.version_info.as_ref());
        let digests = revocation_digests(&data);
        let ctx = ValidityContext {
            now: self.clock.now_utc().unix_secs(),
            clock_floor: None,
            policy: &s.policy,
            revocation: &s.revocation,
            tsa_trust: &s.tsa_trust,
            file_digests: &digests,
            version: info.version_info.as_ref(),
        };
        let validity = evaluate_validity(&report, &trust, &ctx);

        let mut order: Vec<usize> = (0..report.signatures.len()).collect();
        if let Some(p) = validity.primary {
            order.retain(|&i| i != p);
            order.insert(0, p);
        }
        Ok(order
            .into_iter()
            .map(|i| {
                let judged = validity.signatures.iter().find(|v| v.signature == i);
                let signer = trust.signers.iter().find(|t| t.signature == i);
                // No verdict for a signature means it is not valid.
                let mut status = judged.map_or(VerificationError::Generic, |v| v.error);
                // As for catalogs (ADR 0008): a signature that rests on
                // SHA-1, for the image digest or the signer's, is weak.
                let sha2 = report
                    .signatures
                    .get(i)
                    .is_some_and(|sig| is_sha2(sig.digest_alg) && is_sha2(sig.signer_digest_alg));
                if status == VerificationError::Ok && !sha2 {
                    status = VerificationError::WeakHashAlgorithm;
                }
                SignatureResult {
                    source: SignatureSource::Embedded,
                    status,
                    chain: chain(signer.and_then(|t| t.chain.as_ref())),
                    signing_time: judged.and_then(|v| v.signing_time).map(utc),
                }
            })
            .collect())
    }

    fn catalog(&self, path: &str) -> Result<Option<SignatureResult>> {
        let store = self.catalogs.as_ref().ok_or_else(|| {
            PlatformError::new(ErrorKind::Unsupported, "no catalog store is loaded")
        })?;
        let data = self.read(path)?;
        let found = store.lookup(&FileDigests::of_bytes(&data));
        // Prefer a match the agent accepts: a trusted catalog, judged Ok,
        // with no SHA-1 in it. Lookup orders by digest kind, so a SHA-1
        // match in one catalog could otherwise hide a SHA-2 match in
        // another. With none acceptable, the first (best-ordered) match
        // decides, as before.
        let best = found
            .matches
            .iter()
            .find(|m| catalog_status(m) == VerificationError::Ok)
            .or_else(|| found.matches.first());
        let Some(best) = best else {
            if !self.catalogs_complete {
                return Err(PlatformError::new(
                    ErrorKind::TooLarge,
                    "the catalog store is incomplete, so a miss is not conclusive",
                ));
            }
            return Ok(None);
        };
        let signer = best.record.signer.and_then(|i| store.signers().get(i));
        Ok(Some(SignatureResult {
            source: SignatureSource::Catalog,
            // The store judged the catalog; the file's own hash is judged
            // here, against the current revocation data.
            status: if self
                .settings
                .revocation
                .file_revoked(&revocation_digests(&data))
                .is_some()
            {
                VerificationError::RevokedByHash
            } else {
                catalog_status(best)
            },
            chain: chain(signer.and_then(|s| s.trust.chain.as_ref())),
            signing_time: best
                .record
                .validity
                .as_ref()
                .and_then(|v| v.signing_time)
                .map(utc),
        }))
    }
}
