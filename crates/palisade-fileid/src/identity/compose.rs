//! Builds a [`FileIdentity`] from the outputs of the other modules.

#![forbid(unsafe_code)]

use std::ffi::OsStr;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::authenticode::{
    AuthenticodeHashes, CertRevocation, CertSummary, ChainReport, DigestAlgorithm,
    ImageHashOptions, ImageHashStatus, ImageHashes, InvalidReason, RevocationChecker,
    RevocationFailure, RevocationSet, SignatureKind, SignatureReport, SignatureStatus,
    SigningState as EmbeddedSigning, TrustConfig, TrustReport, ValidityContext, ValidityPolicy,
    ValidityReport, VerificationError, VerifyOptions, evaluate_trust, evaluate_validity,
    hash_image_reader, verify_certificate_table,
};
use crate::catalog::{CatalogSource, CatalogStore, DigestKind, FileDigests};
use crate::filetype::{Classification, ContentFlags, FileKind, classify, classify_bytes};
use crate::fsctx::{KnownFolders, PathForms, path_variables_matched};
use crate::hash::{AlgorithmSet, Digest, HashAlgorithm, HashError, HashOptions, MultiHasher};
use crate::pe::version::{VersionField, VersionInfo};
use crate::pe::{self, DataDirectoryKind, FileCharacteristics, PeFormat, PeInfo};

use super::masquerade;
use super::protected::ProtectedList;
use super::record::{
    AuthenticodeSummary, CatalogMatchSummary, CatalogState, CertBrief, ChainSummary, Derived,
    EffectiveName, ElevationSummary, EmbeddedState, ExportSummary, Field, FileIdentity, FsInfo,
    Hashes, KindSummary, ManifestSummary, MotwSummary, PathInfo, PdbSummary, PeSummary,
    PublisherProduct, SectionSummary, SignatureSummary, SigningState, SigningStateKind, Timestamps,
    TrustSource, TrustedSigner, VersionSummary,
};
use super::strength;
use super::tier::{Tier, Tiers};

/// The default [`IdentityContext::max_in_memory`]: 512 MiB.
pub const MAX_IN_MEMORY: u64 = 512 * 1024 * 1024;

/// Everything [`identify`] needs besides the file: trust anchors, the
/// catalog index, revocation data, the protected-binary list, the clock
/// and options. The library keeps no state of its own.
#[derive(Debug, Clone)]
pub struct IdentityContext<'a> {
    /// Anchors for code signers.
    pub code_trust: &'a TrustConfig,
    /// Anchors for timestamping authorities.
    pub tsa_trust: &'a TrustConfig,
    /// The catalogs to look the file up in. `None` skips the lookup.
    pub catalogs: Option<&'a CatalogStore>,
    /// Revocation data.
    pub revocation: &'a RevocationSet,
    /// The validity settings.
    pub validity: &'a ValidityPolicy,
    /// The current time, in seconds since the Unix epoch.
    pub now: i64,
    /// A lower bound on real time (see [`ValidityContext::clock_floor`]).
    pub clock_floor: Option<i64>,
    /// The protected-binary and protected-vendor lists.
    pub protected: &'a ProtectedList,
    /// The machine's known folders, for path variables and the protected
    /// binaries' expected locations. `None` leaves those unassessed.
    pub known_folders: Option<&'a KnownFolders>,
    /// Which flat hashes to compute. SHA-256 is always added.
    pub flat_algorithms: AlgorithmSet,
    /// Hashing limits.
    pub hash_options: HashOptions,
    /// Files larger than this are not read into memory, so their PE
    /// metadata and signatures are not read; their hashes are still
    /// streamed. Default [`MAX_IN_MEMORY`].
    pub max_in_memory: u64,
}

impl IdentityContext<'_> {
    /// A context that trusts nothing, looks nothing up and uses the built-in
    /// protected list, at time `now`. For tools and tests; the agent builds
    /// its context from policy.
    #[must_use]
    pub fn untrusted(now: i64) -> IdentityContext<'static> {
        static EMPTY_TRUST: std::sync::OnceLock<TrustConfig> = std::sync::OnceLock::new();
        static EMPTY_REVOCATION: std::sync::OnceLock<RevocationSet> = std::sync::OnceLock::new();
        static DEFAULT_VALIDITY: std::sync::OnceLock<ValidityPolicy> = std::sync::OnceLock::new();
        static DEFAULT_LIST: std::sync::OnceLock<ProtectedList> = std::sync::OnceLock::new();
        let trust = EMPTY_TRUST.get_or_init(TrustConfig::new);
        IdentityContext {
            code_trust: trust,
            tsa_trust: trust,
            catalogs: None,
            revocation: EMPTY_REVOCATION.get_or_init(RevocationSet::new),
            validity: DEFAULT_VALIDITY.get_or_init(ValidityPolicy::default),
            now,
            clock_floor: None,
            protected: DEFAULT_LIST.get_or_init(ProtectedList::defaults),
            known_folders: None,
            flat_algorithms: AlgorithmSet::DEFAULT,
            hash_options: HashOptions::default(),
            max_in_memory: MAX_IN_MEMORY,
        }
    }
}

/// Why [`identify`] produced no record at all. Anything after the file is
/// opened is recorded in [`FileIdentity::errors`] instead.
#[derive(Debug)]
#[non_exhaustive]
pub enum IdentifyError {
    /// The file could not be opened or its metadata read.
    Open(io::Error),
    /// The path is not a regular file.
    NotAFile,
}

impl std::fmt::Display for IdentifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Open(e) => write!(f, "cannot open the file: {e}"),
            Self::NotAFile => f.write_str("not a regular file"),
        }
    }
}

impl std::error::Error for IdentifyError {}

/// Computes the identity of the file at `path`, for the requested tiers.
///
/// The file is opened once, without following it as a FIFO, and every
/// tier reads that one handle, so all attributes describe the same file.
/// The trust tier needs the hash tier's digests and computes them too.
/// Failures within a tier are recorded in [`FileIdentity::errors`] and
/// leave that tier's fields [`Field::Unavailable`]; nothing in the record
/// is ever guessed.
pub fn identify(
    path: &Path,
    tiers: Tiers,
    ctx: &IdentityContext<'_>,
) -> Result<FileIdentity, IdentifyError> {
    if !std::fs::metadata(path)
        .map_err(IdentifyError::Open)?
        .is_file()
    {
        return Err(IdentifyError::NotAFile);
    }
    let mut file = crate::hash::open_without_blocking(path).map_err(IdentifyError::Open)?;
    let meta = file.metadata().map_err(IdentifyError::Open)?;
    if !meta.is_file() {
        return Err(IdentifyError::NotAFile);
    }
    let text = path.to_string_lossy().into_owned();
    let mut id = FileIdentity::empty(Some(text.clone()), None, tiers);
    let len = meta.len();

    // T0 always runs: it costs one stat, and every other tier needs the
    // size.
    id.size = Field::Computed(len);
    id.timestamps = Field::Computed(timestamps(&meta));
    // The final path is the open handle's, so it describes the file whose
    // content is read below even if the path is replaced meanwhile.
    id.fs.path = Field::Computed(path_info(&text, false, Some(&file)));
    id.computed_tiers.insert(Tier::Stat);

    let content = Content::read(&mut file, len, tiers, ctx, &mut id);
    compose(&mut id, content, tiers, ctx);
    context_tier(&mut id, &file, tiers, ctx);
    finish(&mut id, ctx);
    Ok(id)
}

/// Computes the identity of an uploaded file held in memory. `name_hint`
/// is the name the uploader gave, which is untrusted: it is used for the
/// name checks only, never as a location. There is no file system context.
#[must_use]
pub fn identify_bytes(
    bytes: &[u8],
    name_hint: Option<&str>,
    tiers: Tiers,
    ctx: &IdentityContext<'_>,
) -> FileIdentity {
    let mut id = FileIdentity::empty(None, name_hint.map(str::to_owned), tiers);
    let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    id.size = Field::Computed(len);
    id.timestamps = Field::NotApplicable;
    id.fs.path = name_hint.map_or(Field::NotApplicable, |n| {
        Field::Computed(path_info(n, true, None))
    });
    id.computed_tiers.insert(Tier::Stat);
    let mut cursor = io::Cursor::new(bytes);
    let content = Content::read(&mut cursor, len, tiers, ctx, &mut id);
    compose(&mut id, content, tiers, ctx);
    if tiers.contains(Tier::Context) {
        id.fs.not_applicable_context();
    }
    finish(&mut id, ctx);
    id
}

/// What was read from the file's content.
struct Content {
    /// The whole file, when a tier needs it and it fits
    /// [`IdentityContext::max_in_memory`].
    bytes: Option<Vec<u8>>,
    /// The hashes, from one streaming pass.
    hashes: Option<ImageHashes>,
    /// The content classification (#44). It reads only the head of the
    /// file and a few bounded targeted reads, so it runs on large files
    /// too.
    kind: Option<Classification>,
}

impl Content {
    /// Reads the content once. When a tier needs the bytes and the file
    /// fits [`IdentityContext::max_in_memory`], it is read into memory and hashed from
    /// there, so the PE metadata, the digests and the signatures all
    /// describe exactly the same bytes. A larger file is only streamed
    /// through the hashes.
    fn read<R: Read + Seek>(
        r: &mut R,
        len: u64,
        tiers: Tiers,
        ctx: &IdentityContext<'_>,
        id: &mut FileIdentity,
    ) -> Self {
        let need_bytes = tiers.contains(Tier::Classify) || tiers.contains(Tier::Trust);
        let need_hashes = tiers.contains(Tier::Hash) || tiers.contains(Tier::Trust);
        let mut out = Self {
            bytes: None,
            hashes: None,
            kind: None,
        };
        if need_bytes {
            if len > ctx.max_in_memory {
                let msg = format!(
                    "{len} bytes is over the in-memory limit of {}",
                    ctx.max_in_memory
                );
                for tier in [Tier::Classify, Tier::Trust] {
                    if tiers.contains(tier) {
                        id.error(tier, "too_large", msg.clone());
                    }
                }
            } else {
                let mut buf = Vec::with_capacity(usize::try_from(len).unwrap_or(0));
                let read = r
                    .seek(SeekFrom::Start(0))
                    .and_then(|_| r.take(len.saturating_add(1)).read_to_end(&mut buf));
                let failure = match read {
                    Ok(_) if u64::try_from(buf.len()).ok() == Some(len) => {
                        id.content_sha256 = Some(sha256_hex(&buf));
                        out.bytes = Some(buf);
                        None
                    }
                    Ok(_) => Some((
                        "changed_while_read",
                        "the file changed size while it was read".to_owned(),
                    )),
                    Err(e) => Some(("read_failed", e.to_string())),
                };
                if let Some((code, msg)) = failure {
                    // Charged to every requested tier that needed the
                    // bytes or would have hashed them; nothing describes a
                    // file that changed under the read.
                    for tier in [Tier::Classify, Tier::Hash, Tier::Trust] {
                        if tiers.contains(tier) {
                            id.error(tier, code, msg.clone());
                        }
                    }
                    if need_hashes {
                        id.hashes = Field::Unavailable(msg);
                    }
                    return out;
                }
            }
        }
        if tiers.contains(Tier::Classify) {
            let name = id.name.file_name.as_deref().map(OsStr::new);
            out.kind = match &out.bytes {
                Some(bytes) => Some(classify_bytes(bytes, name)),
                None => match r.seek(SeekFrom::Start(0)) {
                    Ok(_) => Some(classify(&mut *r, name)),
                    Err(e) => {
                        id.error(Tier::Classify, "read_failed", e.to_string());
                        None
                    }
                },
            };
        }
        if need_hashes {
            // Every algorithm a revoked file hash is listed in, so a hash
            // revoked by, say, its SHA-384 is found whatever the caller
            // asked to compute; both the flat and the Authenticode digests.
            let revoked_algs = ctx
                .revocation
                .file_hashes()
                .iter()
                .fold(AlgorithmSet::EMPTY, |set, d| {
                    set | AlgorithmSet::from(d.algorithm())
                });
            let options = ImageHashOptions {
                hash: HashOptions {
                    algorithms: ctx.flat_algorithms | AlgorithmSet::SHA256 | revoked_algs,
                    ..ctx.hash_options
                },
                authenticode_extra: revoked_algs,
                parallel: false,
            };
            let result = match &out.bytes {
                Some(bytes) => hash_image_reader(bytes.as_slice(), len, &options),
                None => r
                    .seek(SeekFrom::Start(0))
                    .map_err(HashError::Io)
                    .and_then(|_| hash_image_reader(&mut *r, len, &options)),
            };
            match result {
                Ok(ImageHashStatus::Complete(h)) => {
                    if let Some(d) = h.flat.get(HashAlgorithm::Sha256) {
                        id.content_sha256 = Some(d.to_string());
                    }
                    out.hashes = Some(h);
                }
                Ok(ImageHashStatus::TooLarge { limit }) => {
                    let msg = format!("{len} bytes is over the hash limit of {limit}");
                    id.hashes = Field::Unavailable(msg.clone());
                    id.error(Tier::Hash, "too_large", msg);
                }
                Err(e) => {
                    id.hashes = Field::Unavailable(e.to_string());
                    id.error(Tier::Hash, "hash_failed", e.to_string());
                }
            }
        }
        out
    }
}

/// The SHA-256 of `bytes`, lowercase hex.
fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = MultiHasher::new(AlgorithmSet::SHA256);
    h.update(bytes);
    h.finalize()
        .get(HashAlgorithm::Sha256)
        .map(ToString::to_string)
        .unwrap_or_default()
}

/// The classify, hash and trust tiers.
fn compose(id: &mut FileIdentity, content: Content, tiers: Tiers, ctx: &IdentityContext<'_>) {
    let info = content.bytes.as_deref().map(pe::parse);
    let pe_info = match &info {
        Some(Ok(p)) => Some(p),
        _ => None,
    };
    // PE content, by the parse when the bytes were read, otherwise by the
    // classifier's look at the headers (a large file, or the hash tier
    // alone), so a missing Authenticode digest of a PE is `unavailable`,
    // not `not_applicable`.
    let is_pe = match &info {
        Some(r) => r.is_ok(),
        None => match &content.kind {
            Some(k) => k.content_kind == FileKind::Pe,
            None => content
                .hashes
                .as_ref()
                .is_some_and(|h| h.authenticode.is_some()),
        },
    };
    let deep_pending = Field::pending(&[52, 53]);

    if tiers.contains(Tier::Classify) {
        match (&info, content.bytes.is_some()) {
            (Some(Ok(p)), _) => {
                id.pe = Field::Computed(pe_summary(p, id.name.file_name.as_deref()));
            }
            (Some(Err(_)), _) => id.pe = Field::NotApplicable,
            (None, _) => id.pe = Field::Unavailable("the content could not be read".to_owned()),
        }
        id.kind = match &content.kind {
            Some(c) => Field::Computed(kind_summary(c)),
            None => Field::Unavailable("the content could not be read".to_owned()),
        };
        if content.bytes.is_some() && content.kind.is_some() {
            id.computed_tiers.insert(Tier::Classify);
        }
    }

    // The trust tier computes the digests too; they are reported whenever
    // they exist.
    if let Some(h) = &content.hashes {
        id.hashes = Field::Computed(hashes(h, is_pe));
        id.computed_tiers.insert(Tier::Hash);
    }

    if tiers.contains(Tier::Trust) {
        trust_tier(id, &content, pe_info, ctx);
    }

    if tiers.contains(Tier::Deep) {
        id.installer = deep_pending.clone();
        id.package = deep_pending;
        id.script = Field::pending(&[52]);
    }
}

fn trust_tier(
    id: &mut FileIdentity,
    content: &Content,
    pe_info: Option<&PeInfo>,
    ctx: &IdentityContext<'_>,
) {
    let Some(hashes) = &content.hashes else {
        let why = "the trust tier needs the file's digests, which were not computed";
        id.signing_state = Field::Unavailable(why.to_owned());
        id.signatures = Field::Unavailable(why.to_owned());
        id.catalog_matches = Field::Unavailable(why.to_owned());
        id.error(Tier::Trust, "no_digests", why);
        return;
    };
    let version = pe_info.and_then(|p| p.version_info.as_ref());

    let digests = file_digests(hashes);
    // Embedded signatures (#48), chains (#49) and validity (#50).
    let mut embedded = EmbeddedState::NotChecked;
    let mut embedded_invalid_reason = None;
    let mut sigs: Option<(SignatureReport, TrustReport, ValidityReport)> = None;
    // A PE image whose Authenticode digests could not be computed has its
    // signatures left unchecked, so its state stays unverified.
    if let (Some(info), Some(bytes), Some(image)) = (pe_info, &content.bytes, &hashes.authenticode)
    {
        {
            let report = verify_certificate_table(bytes, info, image, &VerifyOptions::default());
            let trust = evaluate_trust(&report, ctx.code_trust, version);
            let vctx = ValidityContext {
                now: ctx.now,
                clock_floor: ctx.clock_floor,
                policy: ctx.validity,
                revocation: ctx.revocation,
                tsa_trust: ctx.tsa_trust,
                file_digests: &digests,
                version,
            };
            let validity = evaluate_validity(&report, &trust, &vctx);
            embedded = match &report.signing_state {
                EmbeddedSigning::Unsigned => EmbeddedState::Unsigned,
                EmbeddedSigning::Valid => EmbeddedState::Valid,
                EmbeddedSigning::Invalid(reason) => {
                    embedded_invalid_reason = Some(invalid_reason(reason));
                    EmbeddedState::Invalid
                }
            };
            sigs = Some((report, trust, validity));
        }
    }

    // Catalogs (#51). One lookup serves the summary and the signer.
    let catalog_digests =
        FileDigests::from_hashes(hashes.authenticode.as_ref(), Some(&hashes.flat));
    // A file revoked by hash is never vouched for, by any signer.
    let file_revoked = ctx.revocation.file_revoked(&digests).is_some();
    let found = ctx.catalogs.map(|store| store.lookup(&catalog_digests));
    // The time revocation is judged at: the later of the clock and the
    // floor, as for embedded signatures (ADR 0012).
    let effective_now = ctx.clock_floor.map_or(ctx.now, |f| f.max(ctx.now));
    // One budget of CRL signature checks for every catalog signer.
    let mut checker = ctx.revocation.checker();
    let mut matches = Vec::new();
    // Which matches a revoked catalog signer disqualifies.
    let mut usable = Vec::new();
    let catalog = match (ctx.catalogs, &found) {
        (Some(store), Some(found)) => {
            for m in &found.matches {
                let chain = m.signer.and_then(|s| s.trust.chain.as_ref());
                let signer_revoked =
                    chain.is_some_and(|c| chain_revoked(c, ctx, &mut checker, effective_now));
                // A catalog vouches only when its signer is trusted and its
                // signature's validity (expiry, revocation of its own hash,
                // key sizes, timestamps) was judged and passed: a catalog
                // whose validity was never judged does not vouch (#50).
                let validity_ok = m.usable();
                usable.push(validity_ok && !m.relies_on_sha1() && !signer_revoked && !file_revoked);
                matches.push(CatalogMatchSummary {
                    catalog_id: m.record.id.as_ref().map(Digest::to_string),
                    catalog_path: m.record.path.as_ref().map(|p| p.display().to_string()),
                    source: match m.record.source {
                        CatalogSource::System => "system",
                        CatalogSource::DriverStore => "driver_store",
                        CatalogSource::Policy => "policy",
                    },
                    member: m.member,
                    matched_by: match m.matched_by {
                        DigestKind::AuthenticodeSha256 => "authenticode_sha256",
                        DigestKind::AuthenticodeSha1 => "authenticode_sha1",
                        DigestKind::FlatSha256 => "sha256",
                        DigestKind::FlatSha1 => "sha1",
                    },
                    trusted: m.trusted(),
                    validity: m.record.validity.as_ref().map(|v| v.error),
                    relies_on_sha1: m.relies_on_sha1(),
                    signer_revoked,
                    publisher_name: m
                        .signer
                        .and_then(|s| s.identity.as_ref())
                        .and_then(|i| i.publisher_name.as_ref())
                        .map(|p| p.value.clone()),
                    signer: chain.and_then(ChainReport::leaf_cert).map(cert_brief),
                });
            }
            if found.truncated {
                id.error(
                    Tier::Trust,
                    "catalog_matches_truncated",
                    "more catalogs list the file than are reported",
                );
            }
            // A store whose index was cut short cannot show that a file is
            // not listed.
            let index_truncated = store.records().iter().any(|r| r.index_truncated);
            if usable.iter().any(|u| *u) {
                CatalogState::ListedTrusted
            } else if found.matches.iter().zip(&matches).any(|(m, summary)| {
                m.usable() && m.relies_on_sha1() && !summary.signer_revoked && !file_revoked
            }) {
                CatalogState::ListedTrustedSha1Only
            } else if !found.matches.is_empty() {
                CatalogState::ListedUntrusted
            } else if index_truncated {
                id.error(
                    Tier::Trust,
                    "catalog_index_truncated",
                    "the catalog index is incomplete, so a missing match proves nothing",
                );
                CatalogState::NotChecked
            } else {
                CatalogState::NotListed
            }
        }
        _ => CatalogState::NotChecked,
    };

    // The signer that vouches for the file: a fully valid embedded
    // signature first, then the best trusted catalog that does not rely on
    // SHA-1.
    let mut signer = None;
    let mut embedded_sha1_only = false;
    let mut summaries = Vec::new();
    let mut verification_error = if file_revoked {
        VerificationError::RevokedByHash
    } else {
        VerificationError::NotSigned
    };
    let mut clock_suspect = ctx.clock_floor.is_some_and(|f| ctx.now < f);
    if let Some((report, trust, validity)) = &sigs {
        verification_error = validity.error;
        clock_suspect |= validity.clock_suspect;
        for sig in &report.signatures {
            let t = trust.signers.iter().find(|s| s.signature == sig.index);
            let v = validity
                .signatures
                .iter()
                .find(|v| v.signature == sig.index);
            summaries.push(SignatureSummary {
                index: sig.index,
                kind: match sig.kind {
                    SignatureKind::Nested => "nested",
                    SignatureKind::Catalog => "catalog",
                    _ => "embedded",
                },
                depth: sig.depth,
                parent: sig.parent,
                status: status_name(&sig.status),
                status_detail: format!("{:?}", sig.status),
                digest_alg: sig.digest_alg,
                signer_digest_alg: sig.signer_digest_alg,
                sig_alg: sig.sig_alg.clone(),
                key_alg: sig.key_alg.clone(),
                key_bits: sig.key_bits,
                digest_match: sig.digest_match,
                program_name: sig.signer.as_ref().and_then(|s| s.program_name.clone()),
                more_info_url: sig.signer.as_ref().and_then(|s| s.more_info_url.clone()),
                claimed_signing_time: sig.signer.as_ref().and_then(|s| s.signing_time),
                has_page_hashes: sig.page_hashes.is_some(),
                // The signature and, when a chain was built, every
                // certificate on it (#49).
                os_ci_compatible: t.map_or_else(|| sig.os_ci_compatible(), |t| t.os_ci_compatible),
                trusted: t.is_some_and(|t| t.trusted),
                untrusted: t.map(|t| t.untrusted.clone()).unwrap_or_default(),
                validity_error: v.map_or(VerificationError::Generic, |v| v.error),
                trusted_signing_time: v.and_then(|v| v.signing_time),
                timestamps: sig.timestamp_tokens.len(),
                chain: t.and_then(|t| t.chain.as_ref()).map(chain_summary),
            });
        }
        // A primary signature that rests on SHA-1 (its content digest or
        // its signer digest) is valid, but no allow decision may rest on it
        // (ADR 0008, ADR 0017): it is not a trusted signer, as a catalog
        // match that relies on SHA-1 is not.
        let sha2_primary = validity
            .primary
            .and_then(|p| report.signatures.get(p))
            .is_some_and(|sig| {
                sig.digest_alg.is_some_and(DigestAlgorithm::is_sha2)
                    && sig.signer_digest_alg.is_some_and(DigestAlgorithm::is_sha2)
            });
        embedded_sha1_only = validity.primary.is_some() && !sha2_primary;
        if let (Some(p), Some(identity), false, true) = (
            validity.primary,
            &validity.identity,
            file_revoked,
            sha2_primary,
        ) {
            let chain = trust
                .signers
                .iter()
                .find(|s| s.signature == p)
                .and_then(|s| s.chain.as_ref());
            signer = Some(TrustedSigner {
                source: TrustSource::Embedded,
                signature: Some(p),
                catalog_match: None,
                publisher_name: identity.publisher_name.as_ref().map(|n| n.value.clone()),
                publisher_dn: identity.publisher_dn.clone(),
                product_name: identity.product_name.clone(),
                leaf: chain.and_then(ChainReport::leaf_cert).map(cert_brief),
                pca: chain.and_then(ChainReport::pca_cert).map(cert_brief),
                root: chain.and_then(full_root).map(cert_brief),
                well_known_root_id: chain.and_then(|c| c.well_known_root_id),
                anchored_to: chain
                    .and_then(|c| c.anchored_to.as_ref())
                    .map(|a| a.label.clone()),
            });
        }
    }
    if signer.is_none()
        && let Some(found) = &found
    {
        let best = found
            .matches
            .iter()
            .enumerate()
            .find(|(i, _)| usable.get(*i).copied().unwrap_or(false));
        if let Some((i, m)) = best {
            let chain = m.signer.and_then(|s| s.trust.chain.as_ref());
            let identity = m.signer.and_then(|s| s.identity.as_ref());
            signer = Some(TrustedSigner {
                source: TrustSource::Catalog,
                signature: None,
                catalog_match: Some(i),
                publisher_name: identity
                    .and_then(|i| i.publisher_name.as_ref())
                    .map(|n| n.value.clone()),
                publisher_dn: identity.and_then(|i| i.publisher_dn.clone()),
                product_name: version
                    .and_then(|v| v.get(VersionField::ProductName))
                    .filter(|p| !p.trim().is_empty())
                    .map(str::to_owned),
                leaf: chain.and_then(ChainReport::leaf_cert).map(cert_brief),
                pca: chain.and_then(ChainReport::pca_cert).map(cert_brief),
                root: chain.and_then(full_root).map(cert_brief),
                well_known_root_id: chain.and_then(|c| c.well_known_root_id),
                anchored_to: chain
                    .and_then(|c| c.anchored_to.as_ref())
                    .map(|a| a.label.clone()),
            });
        }
    }

    // A valid embedded signature whose signer was revoked (a certificate in
    // its chain, or its own hash) is no weaker evidence of tampering than a
    // broken one: it is invalid, never merely untrusted.
    let revoked = matches!(
        verification_error,
        VerificationError::Revoked | VerificationError::RevokedByHash
    );
    let state = signing_state_kind(
        signer.is_some(),
        file_revoked || (embedded == EmbeddedState::Valid && signer.is_none() && revoked),
        embedded,
        catalog,
    );

    id.signing_state = Field::Computed(SigningState {
        state,
        embedded,
        embedded_invalid_reason,
        catalog,
        verification_error,
        clock_suspect,
        embedded_sha1_only,
        signer,
    });
    if sigs.is_some() {
        id.signatures = Field::Computed(summaries);
    } else if content.bytes.is_none() {
        let why = "the file was not read into memory, so its signatures were not read";
        id.signatures = Field::Unavailable(why.to_owned());
        id.error(Tier::Trust, "signatures_unread", why);
    } else if pe_info.is_some() {
        let why = "the image's Authenticode digests could not be computed";
        id.signatures = Field::Unavailable(why.to_owned());
        id.error(Tier::Trust, "signatures_unread", why);
    } else {
        id.signatures = Field::pending(&[52, 53]);
    }
    id.catalog_matches = match ctx.catalogs {
        Some(_) => Field::Computed(matches),
        None => Field::NotRequested,
    };
    if id.signatures.is_computed() || (content.bytes.is_some() && pe_info.is_none()) {
        id.computed_tiers.insert(Tier::Trust);
    }
}

/// Whether a catalog signer's chain is revoked, or its revocation state is
/// unknown where policy says that fails. Catalog signatures carry no
/// trusted signing time here (catalog timestamps are #50), so every entry
/// counts, whatever its date.
fn chain_revoked(
    chain: &ChainReport,
    ctx: &IdentityContext<'_>,
    checker: &mut RevocationChecker<'_>,
    now: i64,
) -> bool {
    let certs: Vec<&CertSummary> = chain.full_chain_certs().collect();
    (0..certs.len()).any(|i| match checker.state_of(&certs, i, now) {
        CertRevocation::Good => false,
        CertRevocation::Unknown => ctx.revocation.failure == RevocationFailure::FailClosed,
        // Revoked, or a CRL that was not checked: both fail closed.
        _ => true,
    })
}

/// The context tier: mark-of-the-web and path variables. Owner,
/// writability, streams and reparse points are #54.
fn context_tier(
    id: &mut FileIdentity,
    file: &std::fs::File,
    tiers: Tiers,
    ctx: &IdentityContext<'_>,
) {
    if !tiers.contains(Tier::Context) {
        return;
    }
    let pending = Field::pending(&[54]);
    id.fs.file_id = pending.clone();
    id.fs.volume = pending.clone();
    id.fs.owner = pending.clone();
    id.fs.user_writable = pending.clone();
    id.fs.streams = pending.clone();
    id.fs.reparse = pending.clone();
    id.fs.provenance = pending;
    // The stream is read for the opened file itself: by the handle's final
    // path, and kept only if that path still names the same file, so the
    // record never pairs this file's content with another file's mark.
    id.fs.motw = read_motw(file);
    if let Field::Unavailable(why) = &id.fs.motw
        && cfg!(all(windows, feature = "os-trust"))
    {
        let why = why.clone();
        id.error(Tier::Context, "motw_unreadable", why);
    }
    id.fs.path_variables = match (ctx.known_folders, id.fs.path.computed()) {
        (None, _) => Field::Unavailable("no known folders in the context".to_owned()),
        (Some(folders), Some(info)) => match info.rule_path() {
            Some(p) => match path_variables_matched(&p, folders, None) {
                Ok(vars) => Field::Computed(vars.iter().map(|v| v.token().to_owned()).collect()),
                Err(e) => Field::Unavailable(e.to_string()),
            },
            None => Field::Unavailable("the path is not a full Windows path".to_owned()),
        },
        (Some(_), None) => Field::Unavailable("no path".to_owned()),
    };
    // The tier counts as computed only when it computed something: with
    // every field pending or unavailable it did not.
    if id.fs.motw.is_computed() || id.fs.path_variables.is_computed() {
        id.computed_tiers.insert(Tier::Context);
    }
}

#[cfg(all(windows, feature = "os-trust"))]
fn read_motw(file: &std::fs::File) -> Field<Option<MotwSummary>> {
    match crate::win::links::read_motw_of(file) {
        Ok(m) => Field::Computed(m.as_ref().map(motw_summary)),
        Err(e) => Field::Unavailable(e.to_string()),
    }
}

#[cfg(not(all(windows, feature = "os-trust")))]
fn read_motw(_file: &std::fs::File) -> Field<Option<MotwSummary>> {
    if cfg!(windows) {
        Field::Unavailable("built without the os-trust feature".to_owned())
    } else {
        Field::NotApplicable
    }
}

#[cfg(all(windows, feature = "os-trust"))]
fn motw_summary(m: &crate::fsctx::Motw) -> MotwSummary {
    MotwSummary {
        zone_id: m.zone.map(crate::fsctx::Zone::id),
        external: m.claims_external_origin(),
        host_url: m.host_url.clone(),
        referrer_url: m.referrer_url.clone(),
    }
}

impl FsInfo {
    pub(crate) fn not_applicable_context(&mut self) {
        self.file_id = Field::NotApplicable;
        self.volume = Field::NotApplicable;
        self.owner = Field::NotApplicable;
        self.user_writable = Field::NotApplicable;
        self.streams = Field::NotApplicable;
        self.reparse = Field::NotApplicable;
        self.motw = Field::NotApplicable;
        self.path_variables = Field::NotApplicable;
        self.provenance = Field::NotApplicable;
    }
}

/// Derived attributes, the masquerade assessment and strengths.
fn finish(id: &mut FileIdentity, ctx: &IdentityContext<'_>) {
    id.derived = derived_for(id);
    id.masquerade = masquerade::assess(id, ctx.protected, ctx.code_trust, ctx.known_folders);
    id.strengths = strength::classify(id);
}

pub(super) fn derived_for(id: &FileIdentity) -> Derived {
    let pe = id.pe.computed();
    let version = pe.and_then(|p| p.version.as_ref());
    let effective_file_name = version
        .and_then(|v| {
            [
                (v.original_file_name.as_ref(), "original_file_name"),
                (v.internal_name.as_ref(), "internal_name"),
                (v.file_description.as_ref(), "file_description"),
                (v.product_name.as_ref(), "product_name"),
            ]
            .into_iter()
            .find_map(|(value, source)| {
                value
                    .filter(|s| !s.trim().is_empty())
                    .map(|s| EffectiveName {
                        value: s.clone(),
                        source,
                    })
            })
        })
        .or_else(|| {
            id.name.file_name.as_ref().map(|n| EffectiveName {
                value: n.clone(),
                source: "file_name",
            })
        });
    let signer = id.trusted_signer();
    let publisher_name = signer.and_then(|s| s.publisher_name.clone());
    let publisher_product = signer.and_then(|s| {
        Some(PublisherProduct {
            publisher: s.publisher_name.clone()?,
            product: s.product_name.clone()?,
        })
    });
    Derived {
        effective_file_name,
        publisher_name,
        publisher_product,
        is_kernel_driver: pe.map(|p| p.is_kernel_driver),
        is_dotnet: pe.map(|p| p.is_dotnet),
        requires_elevation: pe.map(|p| p.requires_elevation.value),
    }
}

// ---------------------------------------------------------------------------
// Field builders.

fn timestamps(meta: &std::fs::Metadata) -> Timestamps {
    let secs = |t: io::Result<SystemTime>| {
        t.ok().and_then(|t| match t.duration_since(UNIX_EPOCH) {
            Ok(d) => i64::try_from(d.as_secs()).ok(),
            Err(e) => i64::try_from(e.duration().as_secs()).ok().map(|s| -s),
        })
    };
    Timestamps {
        modified: secs(meta.modified()),
        created: secs(meta.created()),
        accessed: secs(meta.accessed()),
    }
}

fn path_info(text: &str, claimed: bool, opened: Option<&std::fs::File>) -> PathInfo {
    let mut forms = PathForms::from_original(text);
    if let Some(f) = opened {
        forms.final_path = final_path(f);
    }
    PathInfo {
        original: text.to_owned(),
        claimed,
        normalized: forms
            .normalized
            .as_ref()
            .ok()
            .map(crate::fsctx::NormalizedPath::to_win32_string),
        normalize_error: forms.normalized.as_ref().err().map(ToString::to_string),
        final_path: forms
            .final_path
            .as_ref()
            .map(crate::fsctx::NormalizedPath::to_win32_string),
        lexical_key: forms.lexical_key(),
        rule_key: forms.case_folded(),
    }
}

#[cfg(all(windows, feature = "os-trust"))]
fn final_path(f: &std::fs::File) -> Option<crate::fsctx::NormalizedPath> {
    crate::win::links::final_path_of(f).ok()
}

#[cfg(not(all(windows, feature = "os-trust")))]
const fn final_path(_f: &std::fs::File) -> Option<crate::fsctx::NormalizedPath> {
    None
}

fn pe_summary(p: &PeInfo, file_name: Option<&str>) -> PeSummary {
    let version = p.version_info.as_ref().map(version_summary);
    let elevation = p.requires_elevation(file_name);
    PeSummary {
        format: match p.optional.format {
            PeFormat::Pe32 => "pe32",
            _ => "pe32_plus",
        },
        machine: p.coff.machine.raw(),
        machine_name: format!("{:?}", p.coff.machine),
        subsystem: subsystem_raw(p),
        subsystem_name: format!("{:?}", p.optional.subsystem),
        characteristics: p.coff.characteristics.names(),
        dll_characteristics: p.optional.dll_characteristics.names(),
        is_dll: p.coff.characteristics.contains(FileCharacteristics::DLL),
        entry_point: p.optional.entry_point,
        image_base: p.optional.image_base,
        size_of_image: p.optional.size_of_image,
        coff_timestamp: p.coff.time_date_stamp,
        timestamp_is_reproducible: p.timestamp_is_reproducible(),
        checksum_stored: p.checksum.stored,
        checksum_valid: p.checksum.computed.map(|c| c == p.checksum.stored),
        sections: p
            .sections
            .iter()
            .map(|s| SectionSummary {
                name: s.name.clone(),
                virtual_size: s.virtual_size,
                raw_size: s.size_of_raw_data,
                entropy: s.entropy.map(|e| (e * 1000.0).round() / 1000.0),
                writable_and_executable: s.is_writable_and_executable(),
            })
            .collect(),
        has_certificate_table: p.certificate_table.is_some(),
        overlay_size: p.overlay.map(|o| o.size),
        pdb: p.debug.codeview.as_ref().map(|c| PdbSummary {
            path: c.path.clone(),
            guid: c.guid_string(),
            age: c.age,
        }),
        imports: p.imports.as_ref().map(|i| i.all_module_names.clone()),
        imports_truncated: p.imports.as_ref().is_some_and(|i| i.truncated),
        exports: p.exports.as_ref().map(|e| ExportSummary {
            dll_name: e.dll_name.clone(),
            count: e.exports.len(),
            cpl_applet: e.notable.cpl_applet,
            dll_register_server: e.notable.dll_register_server,
            dll_get_class_object: e.notable.dll_get_class_object,
            service_main: e.notable.service_main,
            truncated: e.truncated,
        }),
        manifest: p.manifest.as_ref().map(|m| ManifestSummary {
            id: p.manifest_id,
            execution_level: m.execution_level.as_ref().map(|l| format!("{l:?}")),
            ui_access: m.ui_access,
            auto_elevate: m.auto_elevate,
        }),
        is_dotnet: p.data_directory(DataDirectoryKind::ClrRuntime).is_some(),
        is_kernel_driver: p.is_kernel_driver(),
        driver_signals: p.driver.signals.iter().map(|s| format!("{s:?}")).collect(),
        version,
        requires_elevation: ElevationSummary {
            value: elevation.requires_elevation,
            reason: format!("{:?}", elevation.reason),
        },
        warnings: p.parse_warnings.len(),
        warnings_truncated: p.parse_warnings_truncated,
    }
}

/// `CamelCase` to `snake_case`, for the `Debug` names of #44's enums.
fn snake(debug: &str) -> String {
    let mut out = String::with_capacity(debug.len() + 4);
    for (i, c) in debug.chars().enumerate() {
        if c.is_ascii_uppercase() {
            if i > 0 {
                out.push('_');
            }
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

fn kind_summary(c: &Classification) -> KindSummary {
    let (content_kind, script_kind) = match c.content_kind {
        FileKind::Script(s) => ("script".to_owned(), Some(snake(&format!("{s:?}")))),
        other => (snake(&format!("{other:?}")), None),
    };
    let extension_kind = match c.extension_kind {
        crate::filetype::ExtensionKind::Kind(FileKind::Script(s)) => {
            format!("script:{}", snake(&format!("{s:?}")))
        }
        crate::filetype::ExtensionKind::Kind(k) => snake(&format!("{k:?}")),
        other => snake(&format!("{other:?}")),
    };
    let ContentFlags {
        macro_capable_container,
        package_signature_present,
        python_zipapp,
        script_signature_block,
        encoded_script,
        name_bidi_control,
        name_double_extension,
    } = c.flags;
    let flags = [
        ("macro_capable_container", macro_capable_container),
        ("package_signature_present", package_signature_present),
        ("python_zipapp", python_zipapp),
        ("script_signature_block", script_signature_block),
        ("encoded_script", encoded_script),
        ("name_bidi_control", name_bidi_control),
        ("name_double_extension", name_double_extension),
    ]
    .into_iter()
    .filter_map(|(n, set)| set.then_some(n))
    .collect();
    KindSummary {
        classifier_version: c.classifier_version,
        content_kind,
        script_kind,
        pe_sub_kind: c.pe.as_ref().map(|p| snake(&format!("{:?}", p.sub_kind))),
        extension_kind,
        executable_content: c.is_executable_content(),
        mismatch: c.mismatch,
        mismatch_severity: snake(&format!("{:?}", c.mismatch_severity)),
        confidence: snake(&format!("{:?}", c.confidence)),
        heuristic: c.heuristic,
        extension_assisted: c.extension_assisted,
        flags,
        parse_error: c.parse_error.as_ref().map(ToString::to_string),
    }
}

fn subsystem_raw(p: &PeInfo) -> u16 {
    use crate::pe::Subsystem as S;
    match p.optional.subsystem {
        S::Unknown => 0,
        S::Native => 1,
        S::WindowsGui => 2,
        S::WindowsCui => 3,
        S::Os2Cui => 5,
        S::PosixCui => 7,
        S::NativeWindows => 8,
        S::WindowsCeGui => 9,
        S::EfiApplication => 10,
        S::EfiBootServiceDriver => 11,
        S::EfiRuntimeDriver => 12,
        S::EfiRom => 13,
        S::Xbox => 14,
        S::WindowsBootApplication => 16,
        S::Other(v) => v,
    }
}

fn version_summary(v: &VersionInfo) -> VersionSummary {
    let get = |f: VersionField| v.get(f).map(str::to_owned);
    VersionSummary {
        original_file_name: get(VersionField::OriginalFileName),
        internal_name: get(VersionField::InternalName),
        file_description: get(VersionField::FileDescription),
        product_name: get(VersionField::ProductName),
        company_name: get(VersionField::CompanyName),
        file_version: get(VersionField::FileVersion),
        product_version: get(VersionField::ProductVersion),
        file_version_quad: v.file_version().map(|q| q.to_string()),
        product_version_quad: v.product_version().map(|q| q.to_string()),
        language: v.selected_table().map(|t| t.key.clone()),
    }
}

fn hex(d: Option<&Digest>) -> Option<String> {
    d.map(Digest::to_string)
}

fn hashes(h: &ImageHashes, is_pe: bool) -> Hashes {
    let f = &h.flat;
    let authenticode = match &h.authenticode {
        Some(a) => Field::Computed(authenticode_summary(a)),
        None if is_pe => Field::Unavailable("the image hash was not computed".to_owned()),
        None => Field::NotApplicable,
    };
    let conformant = h
        .authenticode
        .as_ref()
        .is_some_and(|a| a.status.is_conformant());
    Hashes {
        size: f.size,
        empty: f.empty,
        sha256: hex(f.get(HashAlgorithm::Sha256)),
        sha1: hex(f.get(HashAlgorithm::Sha1)),
        md5: hex(f.get(HashAlgorithm::Md5)),
        sha384: hex(f.get(HashAlgorithm::Sha384)),
        sha512: hex(f.get(HashAlgorithm::Sha512)),
        authenticode,
        authoritative: if f.empty {
            "none"
        } else if conformant {
            "authenticode_sha256"
        } else {
            "sha256"
        },
        msi_normalised_sha256: Field::pending(&[53]),
        script_normalised_sha256: Field::pending(&[52]),
    }
}

fn authenticode_summary(a: &AuthenticodeHashes) -> AuthenticodeSummary {
    AuthenticodeSummary {
        sha256: hex(a.sha256()),
        sha1: hex(a.get(HashAlgorithm::Sha1)),
        conformant: a.status.is_conformant(),
        non_conformance: a.status.reasons().iter().map(ToString::to_string).collect(),
        page_sha256: a.page_sha256().map(|d| d.to_string()),
        page_sha1: a.page_sha1().map(|d| d.to_string()),
        page_hashes_error: match &a.page_hashes {
            Some(Err(e)) => Some(e.to_string()),
            _ => None,
        },
    }
}

/// Every digest of the file, for revoked-hash entries.
fn file_digests(h: &ImageHashes) -> Vec<Digest> {
    let mut out: Vec<Digest> = h.flat.digests.clone();
    if let Some(a) = &h.authenticode {
        out.extend(a.digests.iter().cloned());
    }
    out
}

fn invalid_reason(r: &InvalidReason) -> String {
    match r {
        InvalidReason::CertificateTable(e) => format!("certificate table: {e:?}"),
        InvalidReason::Signature(s) => format!("signature: {}", status_name(s)),
        InvalidReason::ScriptSignatureBlock => "script signature block".to_owned(),
    }
}

const fn status_name(s: &SignatureStatus) -> &'static str {
    match s {
        SignatureStatus::Valid => "valid",
        SignatureStatus::DigestMismatch => "digest_mismatch",
        SignatureStatus::NonConformantImage => "non_conformant_image",
        SignatureStatus::BadSignature(_) => "bad_signature",
        SignatureStatus::WeakAlgorithm(_) => "weak_algorithm",
        SignatureStatus::Unsupported(_) => "unsupported",
        SignatureStatus::Malformed(_) => "malformed",
    }
}

fn cert_brief(c: &CertSummary) -> CertBrief {
    CertBrief {
        subject: c.subject.canonical.clone(),
        issuer: c.issuer.canonical.clone(),
        serial: c.serial.clone(),
        not_before: c.not_before,
        not_after: c.not_after,
        sha1_thumbprint: c.sha1_thumbprint.clone(),
        sha256_thumbprint: c.sha256_thumbprint.clone(),
        tbs_hash: c.tbs_hash.clone(),
        tbs_hash_alg: c.tbs_hash_alg,
        tbs_hash_sha256: c.tbs_hash_sha256.clone(),
    }
}

/// The last certificate of the full chain.
fn full_root(c: &ChainReport) -> Option<&CertSummary> {
    c.full_chain.certs.last().and_then(|i| c.cert(*i))
}

fn chain_summary(c: &ChainReport) -> ChainSummary {
    ChainSummary {
        leaf: c.leaf_cert().map(cert_brief),
        pca: c.pca_cert().map(cert_brief),
        root: full_root(c).map(cert_brief),
        length: c.full_chain.certs.len(),
        anchored: c.full_chain.anchored,
        anchored_to: c.anchored_to.as_ref().map(|a| a.label.clone()),
        well_known_root_id: c.well_known_root_id,
        issues: c.issues.len(),
    }
}

/// The signing verdict from its evidence. `revoked` is a revoked file hash,
/// or a revoked signer behind a valid embedded signature. `trusted_signer`
/// is whether a
/// trusted signer vouches for the file: a valid embedded signature that
/// passed every check, or a catalog match counted usable (trusted, and not
/// relying on SHA-1). "Unsigned" needs both halves of the evidence: no
/// embedded signature, and a catalog lookup that found nothing. Without the
/// lookup (no store, or an index cut short) the file may be catalog-signed,
/// so it is unverified.
fn signing_state_kind(
    trusted_signer: bool,
    revoked: bool,
    embedded: EmbeddedState,
    catalog: CatalogState,
) -> SigningStateKind {
    if trusted_signer {
        SigningStateKind::Trusted
    } else if revoked || embedded == EmbeddedState::Invalid {
        // A broken embedded signature, or a revoked file or signer, is
        // invalid whatever a catalog says: an untrusted catalog listing
        // does not make it merely "untrusted".
        SigningStateKind::Invalid
    } else if embedded == EmbeddedState::NotChecked
        || (embedded == EmbeddedState::Unsigned && catalog == CatalogState::NotChecked)
    {
        SigningStateKind::Unverified
    } else if embedded == EmbeddedState::Valid
        || matches!(
            catalog,
            CatalogState::ListedUntrusted | CatalogState::ListedTrustedSha1Only
        )
    {
        SigningStateKind::Untrusted
    } else {
        SigningStateKind::Unsigned
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signing_state_never_trusts_without_a_usable_signer() {
        use CatalogState as C;
        use EmbeddedState as E;
        // A catalog match that relies on SHA-1 is never trust, and never
        // "unsigned"; a catalog index cut short is "not checked", so an
        // unsigned file is unverified, never unsigned.
        for embedded in [E::Unsigned, E::Valid, E::Invalid, E::NotChecked] {
            for catalog in [
                C::NotChecked,
                C::NotListed,
                C::ListedUntrusted,
                C::ListedTrustedSha1Only,
                C::ListedTrusted,
            ] {
                let k = signing_state_kind(false, false, embedded, catalog);
                assert_ne!(k, SigningStateKind::Trusted, "{embedded:?} {catalog:?}");
            }
            assert_ne!(
                signing_state_kind(false, false, embedded, C::ListedTrustedSha1Only),
                SigningStateKind::Unsigned,
                "{embedded:?}"
            );
        }
        assert_eq!(
            signing_state_kind(false, false, E::Unsigned, C::NotChecked),
            SigningStateKind::Unverified
        );
        assert_eq!(
            signing_state_kind(false, false, E::Unsigned, C::NotListed),
            SigningStateKind::Unsigned
        );
        // A broken embedded signature is invalid even when an untrusted
        // catalog lists the file.
        for catalog in [C::ListedUntrusted, C::ListedTrustedSha1Only, C::NotListed] {
            assert_eq!(
                signing_state_kind(false, false, E::Invalid, catalog),
                SigningStateKind::Invalid,
                "{catalog:?}"
            );
        }
        // A revoked hash is invalid whatever else is listed, and a trusted
        // signer is the only way to `Trusted`.
        assert_eq!(
            signing_state_kind(false, true, E::Valid, C::ListedTrusted),
            SigningStateKind::Invalid
        );
        assert_eq!(
            signing_state_kind(true, false, E::Valid, C::NotListed),
            SigningStateKind::Trusted
        );
    }
}
