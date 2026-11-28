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
use crate::installer::{InstallerIdentity, InstallerKind, parse_installer};
use crate::package::{PackageIdentity, PackageSignatureIssue, parse_package};
use crate::pe::version::{VersionField, VersionInfo};
use crate::pe::{self, DataDirectoryKind, FileCharacteristics, PeFormat, PeInfo};
use crate::script::{
    ScriptAnchorPolicy, ScriptInvalidReason, ScriptKind, ScriptOptions, ScriptReport,
    ScriptSigningState, ScriptTrustAnchors, evaluate_script_trust, verify_script,
};

use super::masquerade;
use super::protected::ProtectedList;
use super::record::{
    AuthenticodeSummary, CatalogMatchSummary, CatalogState, CertBrief, ChainSummary,
    ContentTagsSummary, Derived, EffectiveName, ElevationSummary, EmbeddedState, ExportSummary,
    Field, FileIdentity, FsInfo, Hashes, InstallerSummary, KindSummary, ManifestSummary,
    MotwSummary, PackageSummary, PathInfo, PdbSummary, PeSummary, PublisherProduct, ScriptSummary,
    SectionSummary, SignatureSummary, SigningState, SigningStateKind, Timestamps, TrustSource,
    TrustedSigner, VersionSummary,
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
    /// The content tagging rules the deep tier scans with (#44): the
    /// built-in set, plus the organisation's from policy. `None` leaves
    /// the tags unavailable. The field exists whatever the features, so a
    /// context built field by field compiles however a dependency graph
    /// unifies them; without `content-rules` it can only be `None`.
    pub content_rules: Option<&'a ContentRules>,
}

/// The compiled content tagging rules (#44).
#[cfg(feature = "content-rules")]
pub use crate::tags::ContentRules;

/// Stands in for the content tagging rules when the `content-rules`
/// feature is off. It has no values, so a context can only hold `None`.
#[cfg(not(feature = "content-rules"))]
#[derive(Debug)]
pub enum ContentRules {}

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
            content_rules: builtin_content_rules(),
        }
    }
}

/// The built-in content tagging rules, compiled once.
#[cfg(feature = "content-rules")]
fn builtin_content_rules() -> Option<&'static ContentRules> {
    static RULES: std::sync::OnceLock<ContentRules> = std::sync::OnceLock::new();
    Some(RULES.get_or_init(|| {
        #[expect(
            clippy::expect_used,
            reason = "the built-in rules are fixed and compiled by the tags module's own tests"
        )]
        ContentRules::new(None).expect("the built-in content rules compile")
    }))
}

#[cfg(not(feature = "content-rules"))]
const fn builtin_content_rules() -> Option<&'static ContentRules> {
    None
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
    let pe_report = compose(&mut id, content, tiers, ctx);
    if tiers.contains(Tier::Trust) {
        id.os_cross_check = os_cross_check(&file, path, pe_report.as_ref());
    }
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
    let _ = compose(&mut id, content, tiers, ctx);
    if tiers.contains(Tier::Trust) {
        // The OS verifies files on disk, not uploads.
        id.os_cross_check = Field::NotApplicable;
    }
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
        let need_bytes = tiers.contains(Tier::Classify)
            || tiers.contains(Tier::Trust)
            || tiers.contains(Tier::Deep);
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
                for tier in [Tier::Classify, Tier::Trust, Tier::Deep] {
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
                    for tier in [Tier::Classify, Tier::Hash, Tier::Trust, Tier::Deep] {
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
        // The trust and deep tiers need the content kind too: which
        // signature reader runs depends on it.
        if tiers.contains(Tier::Classify)
            || tiers.contains(Tier::Trust)
            || tiers.contains(Tier::Deep)
        {
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
/// Returns the PE image's signature report, when the trust tier read one,
/// for the OS cross-check.
fn compose(
    id: &mut FileIdentity,
    content: Content,
    tiers: Tiers,
    ctx: &IdentityContext<'_>,
) -> Option<SignatureReport> {
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
    // Scripts, installer packages and app packages, chosen by the content
    // the classifier saw, never by the name alone: a PE named `.ps1` is
    // judged as a PE, so no script or package signature can vouch for it.
    let non_pe = if is_pe || !(tiers.contains(Tier::Trust) || tiers.contains(Tier::Deep)) {
        None
    } else {
        content
            .kind
            .as_ref()
            .and_then(|k| NonPe::read(k, content.bytes.as_deref()))
    };

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
        let mut summary = hashes(h, is_pe);
        // The normalised hashes need the content parsed, which the hash
        // tier alone does not read: they are filled in where the reader
        // ran, and are not applicable to other kinds.
        let kind = content.kind.as_ref().map(|k| k.content_kind);
        summary.msi_normalised_sha256 = match (&non_pe, kind) {
            (Some(NonPe::Installer(Ok(i))), _) => Field::Computed(i.normalised_sha256.to_string()),
            (Some(NonPe::Installer(Err(e))), _) => Field::Unavailable(e.message.clone()),
            (_, Some(k)) if is_installer_kind(k) => Field::Unavailable(
                "the installer was not read (request the trust or deep tier)".to_owned(),
            ),
            // The content kind was not determined (the hash tier alone):
            // it may be an installer, unless it is a PE image.
            (_, None) if !is_pe => Field::Unavailable(
                "the file type was not determined (request the classify, trust or deep tier)"
                    .to_owned(),
            ),
            _ => Field::NotApplicable,
        };
        summary.script_normalised_sha256 = match (&non_pe, kind) {
            (Some(NonPe::Script(r)), _) => r.normalised_hash.as_ref().map_or_else(
                || Field::Unavailable(script_unhashed_reason(r).to_owned()),
                |d| Field::Computed(d.to_string()),
            ),
            (_, Some(FileKind::Script(s))) if script_kind_of(s).is_some() => Field::Unavailable(
                "the script was not read (request the trust or deep tier)".to_owned(),
            ),
            (_, None) if !is_pe => Field::Unavailable(
                "the file type was not determined (request the classify, trust or deep tier)"
                    .to_owned(),
            ),
            _ => Field::NotApplicable,
        };
        id.hashes = Field::Computed(summary);
        id.computed_tiers.insert(Tier::Hash);
    }

    let pe_report = if tiers.contains(Tier::Trust) {
        trust_tier(id, &content, pe_info, non_pe.as_ref(), ctx)
    } else {
        None
    };

    if tiers.contains(Tier::Deep) {
        deep_tier(id, &content, is_pe, non_pe.as_ref(), ctx);
    }
    pe_report
}

/// A non-PE format this crate reads signatures and identity from.
enum NonPe {
    /// A script whose format has a signature package (#52).
    Script(Box<ScriptReport>),
    /// A Windows Installer package (#53), or why it could not be read.
    Installer(Result<Box<InstallerIdentity>, Unread>),
    /// An app package or bundle (#53), or why it could not be read.
    Package(Result<Box<PackageIdentity>, Unread>),
}

/// Why a container could not be read at all.
#[derive(Debug, Clone)]
struct Unread {
    /// It is over the reader's size limit: not read, so not judged.
    too_large: bool,
    /// What went wrong, for reading.
    message: String,
}

impl NonPe {
    /// Reads `bytes` as the format `kind` names. `None` for any other
    /// content, and when the bytes were not read (a reason is recorded:
    /// the format's signatures are then not checked).
    fn read(kind: &Classification, bytes: Option<&[u8]>) -> Option<Self> {
        let content = kind.content_kind;
        let script = match content {
            FileKind::Script(s) => script_kind_of(s).map(|k| {
                // `.vbe`/`.jse` and components share their content kind
                // with a plain script; the extension tells them apart, and
                // the script reader reports those unread.
                match (k, kind.extension.as_deref()) {
                    (ScriptKind::VbScript, Some("vbe")) => ScriptKind::EncodedVbScript,
                    (ScriptKind::JScript, Some("jse")) => ScriptKind::EncodedJScript,
                    (ScriptKind::PowerShell, Some("ps1xml" | "psc1" | "cdxml")) => {
                        ScriptKind::PowerShellXml
                    }
                    (k, _) => k,
                }
            }),
            _ => None,
        };
        let wanted = script.is_some()
            || is_installer_kind(content)
            || matches!(
                content,
                FileKind::Msix | FileKind::Appx | FileKind::MsixBundle | FileKind::AppxBundle
            );
        if !wanted {
            return None;
        }
        // Not read into memory (too large): the trust tier records why.
        let bytes = bytes?;
        Some(if let Some(k) = script {
            Self::Script(Box::new(verify_script(bytes, k, &ScriptOptions::default())))
        } else if is_installer_kind(content) {
            Self::Installer(parse_installer(bytes).map(Box::new).map_err(|e| Unread {
                too_large: matches!(e, crate::installer::InstallerError::TooLarge(_)),
                message: e.to_string(),
            }))
        } else {
            Self::Package(parse_package(bytes).map(Box::new).map_err(|e| Unread {
                too_large: matches!(e, crate::package::PackageError::TooLarge(_)),
                message: e.to_string(),
            }))
        })
    }
}

const fn is_installer_kind(k: FileKind) -> bool {
    matches!(
        k,
        FileKind::Msi | FileKind::Msp | FileKind::Mst | FileKind::Msm
    )
}

/// The script signature format of a classified script kind, for the kinds
/// that have one.
const fn script_kind_of(k: crate::filetype::ScriptKind) -> Option<ScriptKind> {
    use crate::filetype::ScriptKind as F;
    match k {
        F::PowerShell => Some(ScriptKind::PowerShell),
        F::VbScript => Some(ScriptKind::VbScript),
        F::JScript => Some(ScriptKind::JScript),
        F::Wsf => Some(ScriptKind::WindowsScriptFile),
        F::Wsc => Some(ScriptKind::ScriptComponent),
        _ => None,
    }
}

fn script_unhashed_reason(r: &ScriptReport) -> &'static str {
    if r.empty_text {
        "the script's text is empty, so its digest identifies nothing"
    } else if matches!(
        r.signing_state,
        ScriptSigningState::TooLargeForSignatureCheck { .. }
    ) {
        "the script is over the size limit, so it was not read"
    } else if r.text_issue.is_some() {
        "the script's text cannot be decoded without ambiguity"
    } else if r.kind.signature_supported() {
        "the script's signature block cannot be read"
    } else {
        "this script format is not read"
    }
}

fn trust_tier(
    id: &mut FileIdentity,
    content: &Content,
    pe_info: Option<&PeInfo>,
    non_pe: Option<&NonPe>,
    ctx: &IdentityContext<'_>,
) -> Option<SignatureReport> {
    let Some(hashes) = &content.hashes else {
        let why = "the trust tier needs the file's digests, which were not computed";
        id.signing_state = Field::Unavailable(why.to_owned());
        id.signatures = Field::Unavailable(why.to_owned());
        id.catalog_matches = Field::Unavailable(why.to_owned());
        id.error(Tier::Trust, "no_digests", why);
        return None;
    };
    let version = pe_info.and_then(|p| p.version_info.as_ref());

    let mut digests = file_digests(hashes);
    // A script or installer is also revoked, and catalog-listed, by the
    // digest its signature signs: the script package's digest of the text,
    // or the installer's content hash.
    match non_pe {
        Some(NonPe::Script(r)) => {
            if let Some(sip) = &r.sip_digests {
                digests.extend(sip.digests.iter().cloned());
            }
        }
        Some(NonPe::Installer(Ok(i))) => digests.push(i.content_sha256.clone()),
        _ => {}
    }
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
    // Script, installer and package signatures (#52, #53): the same trust
    // and validity evaluation as a PE file's, over the format's own report.
    // A format that is not read, a file over its size limit, and a package
    // the strict reader refuses never read as unsigned.
    let mut package_publisher = None;
    if let Some(non_pe) = non_pe {
        let report = match non_pe {
            NonPe::Script(r) => match &r.signing_state {
                ScriptSigningState::TooLargeForSignatureCheck { size, limit } => {
                    id.error(
                        Tier::Trust,
                        "signatures_unread",
                        format!("{size} bytes is over the script signature limit of {limit}"),
                    );
                    None
                }
                _ if !r.kind.signature_supported() => None,
                _ => Some(Ok(r.signatures.clone())),
            },
            NonPe::Installer(Ok(i)) => {
                let mut report = i.signature.clone().unwrap_or_else(unsigned_report);
                // Bytes after the compound file's last sector are outside
                // the content hash: a signed package with data appended
                // (a second file glued on, the CVE-2020-1464 pattern) is
                // not what its signer signed, so no signature is valid.
                if installer_trailing_bytes(i).is_some() && i.signature.is_some() {
                    demote_unsigned_tail(&mut report);
                }
                Some(Ok(report))
            }
            NonPe::Package(Ok(p)) => {
                package_publisher = Some(p);
                Some(Ok(p
                    .signature
                    .as_ref()
                    .map_or_else(unsigned_report, |s| s.report.clone())))
            }
            NonPe::Installer(Err(e)) | NonPe::Package(Err(e)) => Some(Err(e.clone())),
        };
        match report {
            // Not read: the state stays unverified.
            None => {}
            Some(Err(Unread {
                too_large: true,
                message,
            })) => {
                id.error(Tier::Trust, "signatures_unread", message);
            }
            Some(Err(Unread { message, .. })) => {
                // Any container the strict reader refuses is an error,
                // never an unsigned file.
                embedded = EmbeddedState::Invalid;
                embedded_invalid_reason = Some(format!("unreadable: {message}"));
            }
            Some(Ok(report)) => {
                let mut trust = match non_pe {
                    NonPe::Script(r) => {
                        evaluate_script_trust(
                            r,
                            &ScriptTrustAnchors {
                                policy: ctx.code_trust,
                                os_root_store: None,
                            },
                            ScriptAnchorPolicy::PolicyAnchors,
                        )
                        .trust
                    }
                    _ => evaluate_trust(&report, ctx.code_trust, None),
                };
                let vctx = ValidityContext {
                    now: ctx.now,
                    clock_floor: ctx.clock_floor,
                    policy: ctx.validity,
                    revocation: ctx.revocation,
                    tsa_trust: ctx.tsa_trust,
                    file_digests: &digests,
                    version: None,
                };
                let mut validity = evaluate_validity(&report, &trust, &vctx);
                // A packaged app's display name, only once its manifest's
                // publisher is shown to be the signer (#53).
                if let (Some(p), Some(identity)) = (package_publisher, validity.identity.as_mut()) {
                    if let Some(name) = p.publisher_display_name.as_deref() {
                        let _ = identity.attach_package_publisher(&p.publisher_dn, name);
                    }
                    if let Some(t) = trust.identity.as_mut() {
                        t.package_display_name
                            .clone_from(&identity.package_display_name);
                    }
                }
                embedded = match &report.signing_state {
                    EmbeddedSigning::Unsigned => EmbeddedState::Unsigned,
                    EmbeddedSigning::Valid => EmbeddedState::Valid,
                    EmbeddedSigning::Invalid(reason) => {
                        embedded_invalid_reason = Some(match non_pe {
                            NonPe::Script(r) => script_invalid_reason(r),
                            NonPe::Installer(Ok(i)) => match installer_trailing_bytes(i) {
                                Some(n) => format!(
                                    "trailing data is not signed: {n} bytes follow the signed package"
                                ),
                                None => invalid_reason(reason),
                            },
                            NonPe::Package(Ok(p)) => p
                                .signature
                                .as_ref()
                                .and_then(|s| s.issue.as_ref())
                                .map_or_else(|| invalid_reason(reason), package_issue_name),
                            _ => invalid_reason(reason),
                        });
                        EmbeddedState::Invalid
                    }
                };
                sigs = Some((report, trust, validity));
            }
        }
    }

    // Catalogs (#51). One lookup serves the summary and the signer. A
    // script is listed by its script package digest and an installer by
    // its content hash; whether those match catalogs made by OS tooling is
    // not yet checked (#51), so for them a miss proves nothing.
    let (catalog_digests, miss_proves_nothing) = match non_pe {
        Some(NonPe::Script(r)) => (r.catalog_digests(), true),
        Some(NonPe::Installer(Ok(i))) => (
            FileDigests {
                flat_sha256: Some(i.content_sha256.clone()),
                ..FileDigests::default()
            },
            true,
        ),
        _ => (
            FileDigests::from_hashes(hashes.authenticode.as_ref(), Some(&hashes.flat)),
            false,
        ),
    };
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
            } else if miss_proves_nothing {
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
                    SignatureKind::Script => "script",
                    SignatureKind::Msi => "msi",
                    SignatureKind::Package => "package",
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
                package_display_name: identity.package_display_name.clone(),
            });
        }
    }
    // The product of a non-PE file comes from what its signature covers:
    // a script's signed metadata, an installer's `ProductName` (the
    // signature covers every stream). A package has none: its family name
    // is its product identity.
    if let Some(s) = signer.as_mut() {
        let product = match non_pe {
            Some(NonPe::Script(r)) => r
                .signature()
                .and_then(|sig| sig.signer.as_ref())
                .and_then(|a| a.signed_metadata.product.clone()),
            Some(NonPe::Installer(Ok(i))) => i.properties.product_name.clone(),
            _ => None,
        };
        if non_pe.is_some() {
            s.product_name =
                product.filter(|p| !p.trim().is_empty() && !p.chars().any(char::is_control));
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
                package_display_name: None,
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
        // A format with no signature reader here (a cabinet, a Java
        // archive, an encoded script): its signatures, if it has any, are
        // not read, so it stays unverified.
        id.signatures = Field::Unavailable("this file type's signatures are not read".to_owned());
    }
    id.catalog_matches = match ctx.catalogs {
        Some(_) => Field::Computed(matches),
        None => Field::NotRequested,
    };
    if id.signatures.is_computed() || (content.bytes.is_some() && pe_info.is_none()) {
        id.computed_tiers.insert(Tier::Trust);
    }
    sigs.filter(|_| pe_info.is_some())
        .map(|(report, _, _)| report)
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
    // The Palisade provenance tag has no reader yet (#54).
    id.fs.provenance = Field::pending(&[54]);
    read_fs_details(id, file);
    // The stream is read for the opened file itself: by the handle's final
    // path, and kept only if that path still names the same file, so the
    // record never pairs this file's content with another file's mark.
    // A named stream has no mark of its own: `Zone.Identifier` is a stream
    // of the host file, and the host's mark would credit the stream with a
    // download origin it may not share.
    id.fs.motw = if id.name.stream.is_some() {
        Field::NotApplicable
    } else {
        read_motw(file)
    };
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
    let fs = &id.fs;
    if fs.motw.is_computed()
        || fs.path_variables.is_computed()
        || fs.file_id.is_computed()
        || fs.volume.is_computed()
        || fs.owner.is_computed()
        || fs.user_writable.is_computed()
        || fs.streams.is_computed()
        || fs.reparse.is_computed()
    {
        id.computed_tiers.insert(Tier::Context);
    }
}

#[cfg(all(windows, feature = "os-trust"))]
fn read_motw(file: &std::fs::File) -> Field<Option<MotwSummary>> {
    // The handle may name a stream though the path given did not (a link
    // to one): its own final path decides.
    if crate::win::links::final_path_of(file).is_ok_and(|p| p.stream().is_some()) {
        return Field::NotApplicable;
    }
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

/// The file ID, volume, owner, writability, streams and reparse point of
/// the opened file, from the OS (#54). Every read is of the open handle, or
/// of the path the handle's own final path names, so nothing describes
/// another file. A read that fails leaves its field unavailable.
#[cfg(all(windows, feature = "os-trust"))]
fn read_fs_details(id: &mut FileIdentity, file: &std::fs::File) {
    use crate::fsctx::writable::{AssessOptions, WritabilityCache};
    use crate::win::{access, links, security::NameCache, volume};
    let unavailable = |e: &io::Error| e.to_string();

    // The real path of the opened file: every path-based read below uses
    // it, never the path as given (a link could lead elsewhere).
    let final_path = links::final_path_of(file).map(|p| p.to_win32_string());

    id.fs.file_id = match links::read_meta(file) {
        Ok(meta) => {
            let (count, names) = match &final_path {
                Ok(p) => links::hard_links(Path::new(p), file)
                    .map_or((None, Vec::new()), |h| (Some(h.count), h.names.clone())),
                Err(_) => (None, Vec::new()),
            };
            Field::Computed(super::record::FileIdSummary {
                volume_serial: meta.volume_serial,
                file_id: meta
                    .file_id
                    .map(|b| b.iter().map(|x| format!("{x:02x}")).collect()),
                usn_journal_id: meta.usn.map(|(j, _)| j),
                usn: meta.usn.map(|(_, u)| u),
                link_count: count,
                link_names: names,
            })
        }
        Err(e) => Field::Unavailable(unavailable(&e)),
    };

    let vol = volume::read_volume(file);
    id.fs.volume = Field::Computed(volume_summary(&vol));

    let mut names = NameCache::default();
    let local = matches!(
        vol.location_class(),
        crate::fsctx::LocationClass::OsVolume | crate::fsctx::LocationClass::OtherFixed
    );
    id.fs.owner = match access::read_owner(file, vol.fs_type.as_ref(), local, &mut names) {
        Ok(o) => Field::Computed(super::record::OwnerSummary {
            sid: o.owner_sid.map(|s| s.to_string()),
            name: o.owner_name.clone(),
            trust_class: snake(&format!("{:?}", o.owner_trust_class)),
            supported: o.owner_supported,
        }),
        Err(e) => Field::Unavailable(unavailable(&e)),
    };

    // The access check reopens by path: its verdict is kept only if that
    // path still names the opened file before and after it ran, so the
    // record never pairs this file's ID and owner with another file's
    // writability. Otherwise it is unavailable, and the path stays Weak.
    let still_this_file = |p: &str| {
        let opened = links::read_meta(file)
            .ok()
            .and_then(|m| m.file_id.zip(m.volume_serial));
        let at_path = links::open_link_itself(Path::new(p))
            .and_then(|f| links::read_meta(&f))
            .ok()
            .and_then(|m| m.file_id.zip(m.volume_serial));
        opened.is_some() && opened == at_path
    };
    id.fs.user_writable = match &final_path {
        Ok(p) if !still_this_file(p) => {
            Field::Unavailable("the file's final path no longer names the opened file".to_owned())
        }
        Ok(p) => match access::assess_file(
            Path::new(p),
            &crate::fsctx::EvaluationOptions::default(),
            AssessOptions::default(),
            &mut WritabilityCache::default(),
        ) {
            Ok(_) if !still_this_file(p) => Field::Unavailable(
                "the file's final path changed while its writability was read".to_owned(),
            ),
            Ok(w) => Field::Computed(super::record::WritableSummary {
                path_user_writable: w.path_user_writable(),
                file_user_writable: w.file_user_writable,
                first_user_writable_ancestor: w.first_user_writable_ancestor.clone(),
                change_perms_by_non_admin: w.change_perms_by_non_admin,
                principals_with_write: w
                    .principals_with_write
                    .iter()
                    .map(ToString::to_string)
                    .collect(),
            }),
            Err(e) => Field::Unavailable(unavailable(&e)),
        },
        Err(e) => Field::Unavailable(unavailable(e)),
    };

    id.fs.streams = match links::read_streams(file) {
        Ok(s) => Field::Computed(super::record::StreamsSummary {
            streams: s
                .streams
                .iter()
                .map(|st| super::record::StreamSummary {
                    name: st.name.clone(),
                    size: st.size,
                    benign: st.benign.map(|b| snake(&format!("{b:?}"))),
                    executable_content: st.is_executable_content,
                })
                .collect(),
            truncated: s.truncated,
        }),
        Err(e) => Field::Unavailable(unavailable(&e)),
    };

    // The reparse point of the path as given: the opened handle followed
    // it, so the link itself is opened without following.
    id.fs.reparse = match id.path.as_deref() {
        Some(p) => {
            match links::open_link_itself(Path::new(p)).and_then(|f| links::read_reparse(&f)) {
                Ok(r) => Field::Computed(r.map(|r| reparse_summary(&r))),
                Err(e) => Field::Unavailable(unavailable(&e)),
            }
        }
        None => Field::NotApplicable,
    };

    // Every field that could not be read is an error of the tier, as the
    // `Field::Unavailable` contract says.
    let failures: Vec<(&'static str, String)> = [
        ("file_id_unreadable", unavailable_reason(&id.fs.file_id)),
        ("owner_unreadable", unavailable_reason(&id.fs.owner)),
        (
            "writability_unreadable",
            unavailable_reason(&id.fs.user_writable),
        ),
        ("streams_unreadable", unavailable_reason(&id.fs.streams)),
        ("reparse_unreadable", unavailable_reason(&id.fs.reparse)),
    ]
    .into_iter()
    .filter_map(|(code, why)| why.map(|w| (code, w)))
    .collect();
    for (code, why) in failures {
        id.error(Tier::Context, code, why);
    }
}

/// The reason of an unavailable field.
#[cfg(all(windows, feature = "os-trust"))]
fn unavailable_reason<T>(f: &Field<T>) -> Option<String> {
    match f {
        Field::Unavailable(why) => Some(why.clone()),
        _ => None,
    }
}

#[cfg(not(all(windows, feature = "os-trust")))]
fn read_fs_details(id: &mut FileIdentity, _file: &std::fs::File) {
    let why = if cfg!(windows) {
        "built without the os-trust feature"
    } else {
        "read from the Windows file system only"
    };
    id.fs.file_id = Field::Unavailable(why.to_owned());
    id.fs.volume = Field::Unavailable(why.to_owned());
    id.fs.owner = Field::Unavailable(why.to_owned());
    id.fs.user_writable = Field::Unavailable(why.to_owned());
    id.fs.streams = Field::Unavailable(why.to_owned());
    id.fs.reparse = Field::Unavailable(why.to_owned());
}

#[cfg(all(windows, feature = "os-trust"))]
fn volume_summary(v: &crate::fsctx::VolumeInfo) -> super::record::VolumeSummary {
    use crate::fsctx::FsType;
    super::record::VolumeSummary {
        fs_type: v.fs_type.as_ref().map(|f| match f {
            FsType::Other(name) => name.clone(),
            other => snake(&format!("{other:?}")),
        }),
        location: snake(&format!("{:?}", v.location_class())),
        drive_type: v.drive_type.map(|d| snake(&format!("{d:?}"))),
        bus_type: v.bus_type.map(|b| snake(&format!("{b:?}"))),
        is_hotplug: v.is_hotplug,
        is_os_volume: v.is_os_volume,
        serial: v.serial,
        supports_owner: v.supports_owner(),
    }
}

#[cfg(all(windows, feature = "os-trust"))]
fn reparse_summary(r: &crate::fsctx::reparse::ReparsePoint) -> super::record::ReparseSummary {
    use crate::fsctx::reparse::{ReparseKind, ReparseTarget};
    super::record::ReparseSummary {
        kind: match r.kind {
            ReparseKind::Symlink => "symlink",
            ReparseKind::Junction => "junction",
            ReparseKind::MountPoint => "mount_point",
            ReparseKind::AppExecLink => "app_exec_link",
            ReparseKind::CloudPlaceholder => "cloud_placeholder",
            ReparseKind::Dedup => "dedup",
            ReparseKind::Other(_) => "other",
        }
        .to_owned(),
        tag: r.tag,
        target: match &r.target {
            Some(ReparseTarget::Link(l)) => Some(l.print_name.clone()),
            Some(ReparseTarget::AppExecLink(a)) => Some(a.target_path.clone()),
            None => None,
        },
        alias_package_family_name: r.app_exec_link().map(|a| a.package_family_name.clone()),
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

/// How many bytes follow an installer package's last sector, if any.
fn installer_trailing_bytes(i: &InstallerIdentity) -> Option<u64> {
    i.warnings.iter().find_map(|w| match w {
        crate::installer::InstallerWarning::TrailingData(n) if *n > 0 => Some(*n),
        _ => None,
    })
}

/// Marks every signature of `report` as not covering the file, with no
/// primary: the file holds bytes no signature signs.
fn demote_unsigned_tail(report: &mut SignatureReport) {
    for sig in &mut report.signatures {
        if sig.status.is_valid() {
            sig.status = SignatureStatus::DigestMismatch;
            sig.signer = None;
            sig.digest_match = Some(false);
        }
    }
    report.primary = None;
    report.signing_state =
        EmbeddedSigning::Invalid(InvalidReason::Signature(SignatureStatus::DigestMismatch));
}

/// The report of a format's file with no signature.
fn unsigned_report() -> SignatureReport {
    SignatureReport {
        entries: Vec::new(),
        signatures: Vec::new(),
        primary: None,
        signing_state: EmbeddedSigning::Unsigned,
        tolerate_digest_mismatch: false,
        image_status: crate::authenticode::AuthenticodeStatus::Conformant,
        warnings: Vec::new(),
    }
}

fn script_invalid_reason(r: &ScriptReport) -> String {
    match &r.signing_state {
        ScriptSigningState::DigestMismatch => "the script changed after signing".to_owned(),
        ScriptSigningState::Invalid(ScriptInvalidReason::Text(t)) => {
            format!("script text: {}", snake(&format!("{t:?}")))
        }
        ScriptSigningState::Invalid(ScriptInvalidReason::Block(b)) => {
            format!("script signature block: {b}")
        }
        ScriptSigningState::Invalid(ScriptInvalidReason::Signature(s)) => {
            format!("signature: {}", status_name(s))
        }
        other => format!("{other:?}"),
    }
}

fn package_issue_name(issue: &PackageSignatureIssue) -> String {
    match issue {
        PackageSignatureIssue::PublisherMismatch { .. } => {
            "publisher_mismatch: the manifest's publisher is not the signer".to_owned()
        }
        PackageSignatureIssue::BlockMap(e) => format!("block_map: {e}"),
        PackageSignatureIssue::BadContainer => "bad_container".to_owned(),
        PackageSignatureIssue::NotLast => "not_last: data could follow the signature".to_owned(),
        PackageSignatureIssue::NoContentTypes => "no_content_types".to_owned(),
        PackageSignatureIssue::SignerUnreadable => "signer_unreadable".to_owned(),
        PackageSignatureIssue::NotZip64 => "not_zip64".to_owned(),
    }
}

/// The deep tier: the installer, package and script records (#52, #53).
fn deep_tier(
    id: &mut FileIdentity,
    content: &Content,
    is_pe: bool,
    non_pe: Option<&NonPe>,
    ctx: &IdentityContext<'_>,
) {
    const NOT_READ: &str = "the content could not be read";
    id.installer = Field::NotApplicable;
    id.package = Field::NotApplicable;
    id.script = Field::NotApplicable;
    id.content_tags = content_tags(content.bytes.as_deref(), ctx);
    if let Field::Unavailable(why) = &id.content_tags
        && content.bytes.is_some()
    {
        let why = why.clone();
        id.error(Tier::Deep, "content_tags_unavailable", why);
    }
    if content.bytes.is_none() {
        // Too large to read, or a read that failed: what it is may still
        // be one of these, so nothing is "not applicable".
        let kind = content.kind.as_ref().map(|k| k.content_kind);
        match kind {
            Some(k) if is_installer_kind(k) => id.installer = Field::Unavailable(NOT_READ.into()),
            Some(FileKind::Msix | FileKind::Appx | FileKind::MsixBundle | FileKind::AppxBundle) => {
                id.package = Field::Unavailable(NOT_READ.into());
            }
            Some(FileKind::Script(s)) if script_kind_of(s).is_some() => {
                id.script = Field::Unavailable(NOT_READ.into());
            }
            Some(_) => {}
            None => {
                id.installer = Field::Unavailable(NOT_READ.into());
                id.package = Field::Unavailable(NOT_READ.into());
                id.script = Field::Unavailable(NOT_READ.into());
            }
        }
        return;
    }
    // A PE image has no installer, package or script record; its deep
    // tier is its content tags.
    if is_pe {
        if id.content_tags.is_computed() {
            id.computed_tiers.insert(Tier::Deep);
        }
        return;
    }
    match non_pe {
        Some(NonPe::Script(r)) => id.script = Field::Computed(script_summary(r)),
        Some(NonPe::Installer(Ok(i))) => id.installer = Field::Computed(installer_summary(i)),
        Some(NonPe::Package(Ok(p))) => id.package = Field::Computed(package_summary(p)),
        Some(NonPe::Installer(Err(e))) => {
            id.installer = Field::Unavailable(e.message.clone());
            id.error(Tier::Deep, "installer_unreadable", e.message.clone());
        }
        Some(NonPe::Package(Err(e))) => {
            id.package = Field::Unavailable(e.message.clone());
            id.error(Tier::Deep, "package_unreadable", e.message.clone());
        }
        None => {}
    }
    if id.installer.is_computed()
        || id.package.is_computed()
        || id.script.is_computed()
        || id.content_tags.is_computed()
    {
        id.computed_tiers.insert(Tier::Deep);
    }
}

/// The OS trust-verification API's verdict on the opened file's embedded
/// signatures, compared with this library's (#48). Diagnostic only (ADR
/// 0018): it is recorded and never read to decide. Only a PE image's
/// signatures are compared.
#[cfg(all(windows, feature = "os-trust"))]
fn os_cross_check(
    file: &std::fs::File,
    path: &Path,
    report: Option<&SignatureReport>,
) -> Field<super::record::OsCrossCheckSummary> {
    let Some(report) = report else {
        return Field::NotApplicable;
    };
    match crate::win::trust::verify_file(file, path) {
        Ok(os) => Field::Computed(cross_check_summary(&crate::authenticode::cross_check(
            report, &os,
        ))),
        Err(e) => Field::Unavailable(e.to_string()),
    }
}

#[cfg(not(all(windows, feature = "os-trust")))]
fn os_cross_check(
    _file: &std::fs::File,
    _path: &Path,
    report: Option<&SignatureReport>,
) -> Field<super::record::OsCrossCheckSummary> {
    match report {
        None => Field::NotApplicable,
        Some(_) if cfg!(windows) => {
            Field::Unavailable("built without the os-trust feature".to_owned())
        }
        Some(_) => Field::Unavailable("the OS trust-verification API is Windows only".to_owned()),
    }
}

/// The record's form of a cross-check. Kept apart from the OS call so it is
/// tested on every OS.
#[cfg_attr(not(all(windows, feature = "os-trust")), allow(dead_code))]
fn cross_check_summary(c: &crate::authenticode::CrossCheck) -> super::record::OsCrossCheckSummary {
    use crate::authenticode::Outcome;
    super::record::OsCrossCheckSummary {
        agrees: c.agrees(),
        comparisons: c
            .comparisons
            .iter()
            .map(|x| super::record::OsComparisonSummary {
                os_index: x.os_index,
                os_code: x.os.as_ref().map(|o| o.code),
                outcome: match x.outcome {
                    Outcome::Agree => "agree",
                    Outcome::OsAcceptsRustRejects => "os_accepts_rust_rejects",
                    Outcome::RustAcceptsOsRejects => "rust_accepts_os_rejects",
                    Outcome::OnlyOs => "only_os",
                    Outcome::OnlyRust => "only_rust",
                    Outcome::NotComparable => "not_comparable",
                }
                .to_owned(),
            })
            .collect(),
        secondary_count_differs: c.secondary_count_differs,
    }
}

/// The content tags of `bytes` (#44). A file too large to be held in memory
/// is not tagged here: the scan would need another read of the file.
#[cfg(feature = "content-rules")]
fn content_tags(bytes: Option<&[u8]>, ctx: &IdentityContext<'_>) -> Field<ContentTagsSummary> {
    let Some(rules) = ctx.content_rules else {
        return Field::Unavailable("no content rules in the context".to_owned());
    };
    let Some(bytes) = bytes else {
        return Field::Unavailable("the file was not read into memory".to_owned());
    };
    let report = crate::tags::scan_bytes(bytes, rules, &crate::tags::ScanLimits::default());
    Field::Computed(ContentTagsSummary {
        tags: report.tags.clone(),
        complete: report.status == crate::tags::ScanStatus::Complete,
        builtin_version: report.builtin_version,
        rules_version: report.rules_version,
        rules_digest: report
            .rules_digest
            .map(|d| d.iter().map(|b| format!("{b:02x}")).collect()),
    })
}

#[cfg(not(feature = "content-rules"))]
fn content_tags(_bytes: Option<&[u8]>, ctx: &IdentityContext<'_>) -> Field<ContentTagsSummary> {
    match ctx.content_rules {
        Some(never) => match *never {},
        None => Field::Unavailable("built without the content-rules feature".to_owned()),
    }
}

fn script_summary(r: &ScriptReport) -> ScriptSummary {
    ScriptSummary {
        kind: r.kind,
        encoding: r.encoding,
        text_issue: r.text_issue,
        signing_state: match r.signing_state {
            ScriptSigningState::Unsigned => "unsigned",
            ScriptSigningState::Valid => "valid",
            ScriptSigningState::DigestMismatch => "digest_mismatch",
            ScriptSigningState::TooLargeForSignatureCheck { .. } => "too_large",
            _ => "invalid",
        },
        invalid_reason: match r.signing_state {
            ScriptSigningState::Unsigned
            | ScriptSigningState::Valid
            | ScriptSigningState::TooLargeForSignatureCheck { .. } => None,
            _ => Some(script_invalid_reason(r)),
        },
        block: r.block,
        empty_text: r.empty_text,
        signed_metadata: r
            .signature()
            .filter(|s| !s.untrusted_signer_attrs)
            .and_then(|s| s.signer.as_ref())
            .map(|a| a.signed_metadata.clone()),
        warnings: r.warnings.clone(),
    }
}

fn installer_summary(i: &InstallerIdentity) -> InstallerSummary {
    let guid = |g: &crate::installer::GuidText| g.canonical().unwrap_or_else(|| g.text.clone());
    let p = &i.properties;
    InstallerSummary {
        kind: match i.kind {
            InstallerKind::Msi => "msi",
            InstallerKind::Msp => "msp",
            InstallerKind::Mst => "mst",
            InstallerKind::Msm => "msm",
        },
        product_code: p.product_code.as_ref().map(guid),
        upgrade_code: p.upgrade_code.as_ref().map(guid),
        package_code: i.package_code.as_ref().map(guid),
        product_name: p.product_name.clone(),
        product_version: p.product_version_text.clone(),
        product_version_quad: i.product_version().map(|q| q.to_string()),
        manufacturer: p.manufacturer.clone(),
        product_language: p.product_language.clone(),
        platform: i.summary.platform().map(str::to_owned),
        patch_targets: i.patch_targets().iter().map(guid).collect(),
        transform_target: i
            .transform
            .as_ref()
            .and_then(|t| t.target_product_code.as_ref())
            .map(guid),
        binaries: i.embedded.binaries.len(),
        custom_actions: i.embedded.custom_actions.len(),
        executable_actions: i.embedded.has_executable_actions(),
        elevated_actions: i.embedded.custom_actions.iter().any(|a| a.no_impersonate),
        cabinets: i.embedded.cabinets.len(),
        signed: i.signature.is_some(),
        signature_valid: i.signature_valid() && installer_trailing_bytes(i).is_none(),
        trailing_bytes: installer_trailing_bytes(i),
        content_sha256: i.content_sha256.to_string(),
        warnings: i.warnings.iter().map(|w| format!("{w:?}")).collect(),
    }
}

fn package_summary(p: &PackageIdentity) -> PackageSummary {
    PackageSummary {
        is_bundle: p.is_bundle,
        name: p.name.clone(),
        publisher_dn: p.publisher_dn.clone(),
        publisher_id: p.publisher_id.clone(),
        pfn: p.pfn.clone(),
        full_name: p.full_name.clone(),
        version: p.version.to_string(),
        arch: p.arch.clone(),
        resource_id: p.resource_id.clone(),
        display_name: p.display_name.clone(),
        publisher_display_name: p.publisher_display_name.clone(),
        is_framework: p.is_framework,
        is_resource_package: p.is_resource_package,
        runs_full_trust: p.runs_full_trust(),
        executables: p.apps.iter().filter_map(|a| a.executable.clone()).collect(),
        aliases: p
            .extensions
            .iter()
            .flat_map(|e| e.aliases.iter().cloned())
            .collect(),
        capabilities: p.capabilities.iter().map(|c| c.name.clone()).collect(),
        members: p.members.iter().map(|m| m.file_name.clone()).collect(),
        signed: p.signature.is_some(),
        signature_valid: p.signature_valid(),
        signature_issue: p
            .signature
            .as_ref()
            .and_then(|s| s.issue.as_ref())
            .map(package_issue_name),
    }
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

    /// The OS cross-check is a diagnostic (ADR 0018): the record's summary
    /// keeps an OS rejection of a signature this library accepts, as a
    /// disagreement, for reading only.
    #[test]
    fn os_cross_check_summary_keeps_disagreements() {
        use crate::authenticode::{
            AuthenticodeStatus, CrossCheck, OsSignatureResult, OsTrustResult, Outcome, code,
            cross_check,
        };
        let report = SignatureReport {
            entries: Vec::new(),
            signatures: Vec::new(),
            primary: None,
            signing_state: EmbeddedSigning::Unsigned,
            tolerate_digest_mismatch: false,
            image_status: AuthenticodeStatus::Conformant,
            warnings: Vec::new(),
        };
        let os = OsTrustResult {
            signatures: vec![OsSignatureResult {
                index: 0,
                code: code::TRUST_E_BAD_DIGEST,
            }],
            secondary_count: 0,
            truncated: false,
        };
        let check: CrossCheck = cross_check(&report, &os);
        assert_eq!(check.comparisons[0].outcome, Outcome::OnlyOs);
        let summary = cross_check_summary(&check);
        assert!(!summary.agrees);
        assert_eq!(summary.comparisons[0].outcome, "only_os");
        assert_eq!(
            summary.comparisons[0].os_code,
            Some(code::TRUST_E_BAD_DIGEST)
        );
    }

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
