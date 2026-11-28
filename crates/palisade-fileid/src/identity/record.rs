//! The [`FileIdentity`] record and its field groups (schema `fileid.v1`).
//!
//! Every type here is plain data with a stable serde form: field names are
//! `snake_case`, enums are tagged with `snake_case` names, digests are
//! lowercase hex and times are seconds since the Unix epoch (UTC). The
//! evolution rules are in the module documentation of [`super`].

#![forbid(unsafe_code)]

use serde::Serialize;

use super::strength::AttributeStrength;
use super::tier::{Tier, Tiers};
use crate::authenticode::{
    DigestAlgorithm, KeyAlgorithm, SignatureAlgorithm, UntrustedReason, VerificationError,
};

/// The schema version of [`FileIdentity`].
pub const SCHEMA_VERSION: &str = "fileid.v1";

/// One attribute group, with why it has no value when it has none.
///
/// A consumer must never read "not computed" as "absent": an unsigned file
/// has `signing_state` [`Field::Computed`] with state `unsigned`, while a
/// file whose signatures were not examined has [`Field::NotRequested`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", content = "value", rename_all = "snake_case")]
pub enum Field<T> {
    /// The value.
    Computed(T),
    /// The tier that computes it was not requested.
    NotRequested,
    /// It does not apply to this file (for example, PE metadata of a text
    /// file).
    NotApplicable,
    /// This library does not compute it yet; the issues that will.
    NotYetSupported(Pending),
    /// It was requested and applies, but could not be computed. The
    /// reason is also in [`FileIdentity::errors`] when it is an error.
    Unavailable(String),
}

impl<T> Field<T> {
    /// The value, if computed.
    #[must_use]
    pub const fn computed(&self) -> Option<&T> {
        match self {
            Self::Computed(v) => Some(v),
            _ => None,
        }
    }

    /// Whether it holds a value.
    #[must_use]
    pub const fn is_computed(&self) -> bool {
        matches!(self, Self::Computed(_))
    }

    /// How much this state says, for [`FileIdentity::merge`]: a value beats
    /// any reason, and any reason beats "not requested".
    pub(crate) const fn rank(&self) -> u8 {
        match self {
            Self::Computed(_) => 2,
            Self::NotApplicable | Self::NotYetSupported(_) | Self::Unavailable(_) => 1,
            Self::NotRequested => 0,
        }
    }

    /// Takes `other` when it says more.
    pub(crate) fn absorb(&mut self, other: Self) {
        if other.rank() > self.rank() {
            *self = other;
        }
    }

    pub(crate) const fn pending(issues: &'static [u16]) -> Self {
        Self::NotYetSupported(Pending { issues })
    }
}

/// The issues that will compute a [`Field::NotYetSupported`] field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Pending {
    /// The GitHub issue numbers.
    pub issues: &'static [u16],
}

/// The value type of a field this library does not compute yet. It has no
/// values, so such a field can only be one of the reasons in [`Field`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum NotYetDefined {}

/// Everything known about one file. See the module documentation of
/// [`super`].
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FileIdentity {
    /// Always [`SCHEMA_VERSION`].
    pub schema: &'static str,
    /// The version of `palisade-fileid` that made the record.
    pub library_version: &'static str,
    /// The path given to [`super::identify`]. `None` for
    /// [`super::identify_bytes`].
    pub path: Option<String>,
    /// The name hint given to [`super::identify_bytes`]: untrusted, as the
    /// uploader claimed it.
    pub name_hint: Option<String>,
    /// The tiers the caller asked for.
    pub requested_tiers: Tiers,
    /// The tiers whose attributes were computed. A requested tier is
    /// missing here when it failed, or when nothing in it applies to the
    /// file yet (the deep tier of a PE image, until content tags run).
    pub computed_tiers: Tiers,
    /// The file name, from the path or the name hint. Needs no I/O.
    pub name: NameInfo,
    /// The size in bytes (stat tier).
    pub size: Field<u64>,
    /// The SHA-256 of the bytes the content tiers read, hex: set whenever a
    /// tier read the whole file (classify, hash or trust), so two records
    /// can be shown to describe the same content before they are merged.
    /// `None` when no tier read it.
    pub content_sha256: Option<String>,
    /// File system times (stat tier).
    pub timestamps: Field<Timestamps>,
    /// The content-based file kind (#44, classify tier).
    pub kind: Field<KindSummary>,
    /// PE headers and version information (classify tier).
    pub pe: Field<PeSummary>,
    /// Flat, Authenticode and page hashes (hash tier).
    pub hashes: Field<Hashes>,
    /// The file's signing state, embedded and catalog signatures together
    /// (trust tier).
    pub signing_state: Field<SigningState>,
    /// Every embedded signature with its chain (trust tier).
    pub signatures: Field<Vec<SignatureSummary>>,
    /// Every catalog that lists the file (trust tier).
    pub catalog_matches: Field<Vec<CatalogMatchSummary>>,
    /// Windows Installer identity (#53, deep tier).
    pub installer: Field<InstallerSummary>,
    /// Packaged-app identity (#53, deep tier).
    pub package: Field<PackageSummary>,
    /// Script signature and identity (#52, deep tier).
    pub script: Field<ScriptSummary>,
    /// File system context (stat and context tiers).
    pub fs: FsInfo,
    /// Attributes worked out from the groups above.
    pub derived: Derived,
    /// The renamed and masquerading binary assessment.
    pub masquerade: Masquerade,
    /// How strong each attribute is as a rule identity.
    pub strengths: Vec<AttributeStrength>,
    /// What went wrong, per tier.
    pub errors: Vec<IdentityError>,
}

impl FileIdentity {
    /// A record with nothing computed yet.
    pub(crate) fn empty(path: Option<String>, name_hint: Option<String>, tiers: Tiers) -> Self {
        let name = NameInfo::from_text(path.as_deref().or(name_hint.as_deref()));
        Self {
            schema: SCHEMA_VERSION,
            library_version: env!("CARGO_PKG_VERSION"),
            path,
            name_hint,
            requested_tiers: tiers,
            computed_tiers: Tiers::EMPTY,
            name,
            size: Field::NotRequested,
            content_sha256: None,
            timestamps: Field::NotRequested,
            kind: Field::NotRequested,
            pe: Field::NotRequested,
            hashes: Field::NotRequested,
            signing_state: Field::NotRequested,
            signatures: Field::NotRequested,
            catalog_matches: Field::NotRequested,
            installer: Field::NotRequested,
            package: Field::NotRequested,
            script: Field::NotRequested,
            fs: FsInfo::not_requested(),
            derived: Derived::default(),
            masquerade: Masquerade::default(),
            strengths: Vec::new(),
            errors: Vec::new(),
        }
    }

    /// The trusted signer, if the file has one.
    #[must_use]
    pub fn trusted_signer(&self) -> Option<&TrustedSigner> {
        self.signing_state.computed()?.signer.as_ref()
    }

    /// The version resource, if the PE was parsed and has one.
    #[must_use]
    pub fn version(&self) -> Option<&VersionSummary> {
        self.pe.computed()?.version.as_ref()
    }

    pub(crate) fn error(&mut self, tier: Tier, code: &'static str, message: impl Into<String>) {
        self.errors.push(IdentityError {
            tier,
            code,
            message: message.into(),
        });
    }
}

/// The file name, as the path or name hint gives it.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
pub struct NameInfo {
    /// The file's name: the last path component, without the drive and
    /// without a stream suffix, as the file-type classifier (#44) reads it
    /// (trailing dots and spaces kept). For a named stream
    /// (`notes.txt:run.exe`) it is the host file's name. `None` when no path
    /// or hint was given.
    pub file_name: Option<String>,
    /// The extension of [`Self::file_name`] after Win32 trimming of
    /// trailing dots and spaces, lowercased, without the dot. Empty when
    /// the name has none (a dot file such as `.profile` has none).
    pub extension: Option<String>,
    /// The named alternate data stream the path addresses (`run.exe` for
    /// `notes.txt:run.exe`), without a `:$DATA` type suffix. `None` for
    /// the file's own (default) stream.
    pub stream: Option<String>,
}

impl NameInfo {
    pub(crate) fn from_text(text: Option<&str>) -> Self {
        let (host, stream) = match text.and_then(last_component) {
            Some(c) => split_stream(c),
            None => (None, None),
        };
        let file_name = host.filter(|n| !n.is_empty()).map(str::to_owned);
        let extension = file_name.as_deref().map(extension_of);
        Self {
            file_name,
            extension,
            stream: stream.map(str::to_owned),
        }
    }
}

/// `path` without a leading drive (`C:`), as the file-type classifier
/// (#44) reads it: the drive is dropped from the whole path, before it is
/// split, so a one-letter component later in the path is never taken for
/// one.
pub(crate) fn without_drive(path: &str) -> &str {
    match path.as_bytes() {
        [d, b':', ..] if d.is_ascii_alphabetic() => path.get(2..).unwrap_or_default(),
        _ => path,
    }
}

/// The default data stream suffix `::$DATA` (any case), which names the
/// file itself, removed from `component`. Any other stream suffix, such as
/// `:$DATA` (a stream named `$DATA`) or `:evil.exe`, is kept: it names a
/// different stream, and the name checks see it.
/// A bare `::$DATA` with no name before it is not a stream of anything
/// and is kept whole.
pub(crate) fn without_default_stream(component: &str) -> &str {
    const SUFFIX: &str = "::$DATA";
    component
        .len()
        .checked_sub(SUFFIX.len())
        .filter(|cut| {
            *cut > 0
                && component
                    .get(*cut..)
                    .is_some_and(|s| s.eq_ignore_ascii_case(SUFFIX))
        })
        .and_then(|cut| component.get(..cut))
        .unwrap_or(component)
}

/// Splits a last path component (after [`without_default_stream`]) into
/// the host file's name and the named stream, as `host:stream[:type]`, the
/// way the file-type classifier (#44) reads it. A component with an empty
/// host (`:x`, a bare `::$DATA`) is kept whole as the name, with no stream,
/// so the name checks still see it.
pub(crate) fn split_stream(component: &str) -> (Option<&str>, Option<&str>) {
    let mut parts = component.splitn(3, ':');
    let host = parts.next().unwrap_or_default();
    if host.is_empty() {
        return (Some(component), None);
    }
    let stream = parts.next().filter(|s| !s.is_empty());
    (Some(host), stream)
}

/// The last path component of `path`, with the drive and the default data
/// stream suffix removed. `None` when the path ends in a separator.
pub(crate) fn last_component(path: &str) -> Option<&str> {
    without_drive(path)
        .rsplit(['\\', '/'])
        .next()
        .map(without_default_stream)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_from_paths() {
        let n = |p: &str| NameInfo::from_text(Some(p)).file_name;
        assert_eq!(n(r"C:\temp\a::$DATA").as_deref(), Some("a"));
        assert_eq!(n(r"C:\temp\a::$data").as_deref(), Some("a"));
        // A named stream: the host is the file name, the stream is kept.
        let s = |p: &str| NameInfo::from_text(Some(p));
        let ads = s(r"C:\Windows\System32\a:powershell.exe");
        assert_eq!(ads.file_name.as_deref(), Some("a"));
        assert_eq!(ads.stream.as_deref(), Some("powershell.exe"));
        let ads = s(r"C:\temp\extool.pdf:ads:$DATA");
        assert_eq!(ads.file_name.as_deref(), Some("extool.pdf"));
        assert_eq!(ads.extension.as_deref(), Some("pdf"));
        assert_eq!(ads.stream.as_deref(), Some("ads"));
        assert_eq!(s(r"C:\temp\a:$DATA").stream.as_deref(), Some("$DATA"));
        // No host: kept whole, never dropped.
        assert_eq!(n("::$DATA").as_deref(), Some("::$DATA"));
        assert_eq!(n(r"C:\temp\::$DATA").as_deref(), Some("::$DATA"));
        // A dot file has no extension.
        assert_eq!(s(".profile").extension.as_deref(), Some(""));
        assert_eq!(s("a.b.exe").extension.as_deref(), Some("exe"));
        assert_eq!(n("C:app.exe").as_deref(), Some("app.exe"));
        assert_eq!(n("app.exe").as_deref(), Some("app.exe"));
        assert_eq!(n(r"C:\dir\"), None);
        assert_eq!(
            NameInfo::from_text(Some(r"C:\t\Invoice.PDF.exe::$DATA"))
                .extension
                .as_deref(),
            Some("exe")
        );
    }
}

/// The lowercased extension of `name` as Win32 sees it: trailing dots and
/// spaces are dropped first, then whatever follows the last dot. A leading
/// dot (`.profile`) makes a hidden-file name, not an extension, as #44
/// reads it.
pub(crate) fn extension_of(name: &str) -> String {
    split_extension(name.trim_end_matches(['.', ' ']))
        .map(|(_, ext)| ext.to_lowercase())
        .unwrap_or_default()
}

/// `stem.ext`, with a non-empty stem.
pub(crate) fn split_extension(name: &str) -> Option<(&str, &str)> {
    let (stem, ext) = name.rsplit_once('.')?;
    (!stem.is_empty()).then_some((stem, ext))
}

/// File system times, in seconds since the Unix epoch (UTC).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
pub struct Timestamps {
    /// Last write. `None` if the platform did not report it.
    pub modified: Option<i64>,
    /// Creation. `None` if the platform did not report it.
    pub created: Option<i64>,
    /// Last access. `None` if the platform did not report it.
    pub accessed: Option<i64>,
}

/// The content-based classification (#44). Names are the `Debug` forms
/// of [`crate::filetype`]'s enums in `snake_case`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct KindSummary {
    /// [`crate::filetype::CLASSIFIER_VERSION`].
    pub classifier_version: u16,
    /// What the content is, such as `pe`, `msi` or `script`.
    pub content_kind: String,
    /// The script language, for a script (`power_shell`, `batch`, ...).
    pub script_kind: Option<String>,
    /// The PE sub-kind, for a PE (`exe`, `dll`, `driver`, ...).
    pub pe_sub_kind: Option<String>,
    /// What the extension claims: `none`, `inert`, `other`, or a kind.
    pub extension_kind: String,
    /// The content can run code, natively or through a host.
    pub executable_content: bool,
    /// Content and name disagree.
    pub mismatch: bool,
    /// `none`, `benign`, `suspicious` or `critical`.
    pub mismatch_severity: String,
    /// `low`, `medium` or `high`.
    pub confidence: String,
    /// The kind rests on a heuristic.
    pub heuristic: bool,
    /// The extension decided the kind where content could not.
    pub extension_assisted: bool,
    /// The informational flags that are set (`macro_capable_container`,
    /// `script_signature_block`, ...).
    pub flags: Vec<&'static str>,
    /// Why part of the file could not be parsed.
    pub parse_error: Option<String>,
}

/// PE header and version-resource attributes (#45).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PeSummary {
    /// `pe32` or `pe32_plus`.
    pub format: &'static str,
    /// The COFF `Machine` value.
    pub machine: u16,
    /// Its name, for reading.
    pub machine_name: String,
    /// The optional header `Subsystem` value.
    pub subsystem: u16,
    /// Its name, for reading.
    pub subsystem_name: String,
    /// The COFF characteristics that are set.
    pub characteristics: Vec<&'static str>,
    /// The DLL characteristics that are set.
    pub dll_characteristics: Vec<&'static str>,
    /// `IMAGE_FILE_DLL` is set.
    pub is_dll: bool,
    /// `AddressOfEntryPoint`.
    pub entry_point: u32,
    /// `ImageBase`.
    pub image_base: u64,
    /// `SizeOfImage`.
    pub size_of_image: u32,
    /// The COFF `TimeDateStamp`.
    pub coff_timestamp: u32,
    /// The COFF timestamp is a reproducible-build hash, not a time.
    pub timestamp_is_reproducible: bool,
    /// The stored checksum.
    pub checksum_stored: u32,
    /// Whether it equals the computed one; `None` when not computed.
    pub checksum_valid: Option<bool>,
    /// The sections.
    pub sections: Vec<SectionSummary>,
    /// The image has a certificate table (embedded signatures).
    pub has_certificate_table: bool,
    /// Bytes after the image and certificate table, if any.
    pub overlay_size: Option<u64>,
    /// The CodeView PDB reference.
    pub pdb: Option<PdbSummary>,
    /// The imported module names, if the image has an import table.
    pub imports: Option<Vec<String>>,
    /// The import listing was cut at a limit.
    pub imports_truncated: bool,
    /// The export table.
    pub exports: Option<ExportSummary>,
    /// The application manifest.
    pub manifest: Option<ManifestSummary>,
    /// The CLR runtime header data directory is present (.NET).
    pub is_dotnet: bool,
    /// The image is a kernel-mode driver.
    pub is_kernel_driver: bool,
    /// Why it is (or is not) a driver.
    pub driver_signals: Vec<String>,
    /// The version resource.
    pub version: Option<VersionSummary>,
    /// Whether starting it is expected to ask for elevation, and why.
    pub requires_elevation: ElevationSummary,
    /// How many parse warnings there were.
    pub warnings: usize,
    /// More warnings occurred than were kept.
    pub warnings_truncated: bool,
}

/// One section.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SectionSummary {
    /// The name.
    pub name: String,
    /// `VirtualSize`.
    pub virtual_size: u32,
    /// `SizeOfRawData`.
    pub raw_size: u32,
    /// Shannon entropy of its raw data, in bits per byte.
    pub entropy: Option<f64>,
    /// Both writable and executable.
    pub writable_and_executable: bool,
}

/// The CodeView PDB reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PdbSummary {
    /// The PDB path as stored.
    pub path: String,
    /// The PDB GUID, in registry format.
    pub guid: String,
    /// The PDB age.
    pub age: u32,
}

/// The export table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExportSummary {
    /// The DLL name the table records.
    pub dll_name: Option<String>,
    /// How many exports were read.
    pub count: usize,
    /// `CPlApplet` is exported (a control panel applet).
    pub cpl_applet: bool,
    /// `DllRegisterServer` is exported.
    pub dll_register_server: bool,
    /// `DllGetClassObject` is exported.
    pub dll_get_class_object: bool,
    /// `ServiceMain` is exported.
    pub service_main: bool,
    /// The table was not read in full; a `false` above is not reliable.
    pub truncated: bool,
}

/// The application manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ManifestSummary {
    /// The `RT_MANIFEST` ID it came from.
    pub id: Option<u16>,
    /// `requestedExecutionLevel`, as written.
    pub execution_level: Option<String>,
    /// `uiAccess`.
    pub ui_access: Option<bool>,
    /// `autoElevate`.
    pub auto_elevate: Option<bool>,
}

/// Fields of the selected version-resource language block, as stored. The
/// names match the OS audit event fields.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
pub struct VersionSummary {
    /// `OriginalFilename`.
    pub original_file_name: Option<String>,
    /// `InternalName`.
    pub internal_name: Option<String>,
    /// `FileDescription`.
    pub file_description: Option<String>,
    /// `ProductName`.
    pub product_name: Option<String>,
    /// `CompanyName`.
    pub company_name: Option<String>,
    /// `FileVersion`, the string.
    pub file_version: Option<String>,
    /// `ProductVersion`, the string.
    pub product_version: Option<String>,
    /// The file version rules use: the fixed info when present, otherwise
    /// parsed from the string.
    pub file_version_quad: Option<String>,
    /// The product version, the same way.
    pub product_version_quad: Option<String>,
    /// The selected block's key (language and code page).
    pub language: Option<String>,
}

/// The #45 elevation heuristic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ElevationSummary {
    /// Whether starting the file is expected to ask for elevation.
    pub value: bool,
    /// Why, for reading.
    pub reason: String,
}

/// The digests of the file (#46, #47).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Hashes {
    /// Bytes hashed.
    pub size: u64,
    /// The file is empty: every flat digest is the well-known empty digest,
    /// never an identity.
    pub empty: bool,
    /// Flat SHA-256: the primary identity.
    pub sha256: Option<String>,
    /// Flat SHA-1. Interop only: not collision resistant.
    pub sha1: Option<String>,
    /// Flat MD5. Interop only: not collision resistant.
    pub md5: Option<String>,
    /// Flat SHA-384, when requested.
    pub sha384: Option<String>,
    /// Flat SHA-512, when requested.
    pub sha512: Option<String>,
    /// The Authenticode image hashes, for a PE image.
    pub authenticode: Field<AuthenticodeSummary>,
    /// Which digest identifies the file: `authenticode_sha256` for a
    /// conformant PE image, `sha256` for everything else (a non-PE file,
    /// or a non-conformant image, whose Authenticode digest is not
    /// authoritative), `none` for an empty file.
    pub authoritative: &'static str,
    /// The normalised, timestamp-free installer hash (#53): the same
    /// across copies of a package that differ only in timestamps. Medium,
    /// for explicit opt-in rules; the flat hash stays the identity.
    pub msi_normalised_sha256: Field<String>,
    /// The normalised script hash (#52): the UTF-8 text without the
    /// signature block, the byte order mark and line-ending differences.
    /// Weak to medium, for explicit opt-in rules only.
    pub script_normalised_sha256: Field<String>,
}

/// The Authenticode image hashes and page hash values (#47).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuthenticodeSummary {
    /// The Authenticode SHA-256.
    pub sha256: Option<String>,
    /// The Authenticode SHA-1. Not collision resistant.
    pub sha1: Option<String>,
    /// The layout conforms to the Authenticode specification. When it does
    /// not, these digests are a best effort and not authoritative.
    pub conformant: bool,
    /// Why it does not conform.
    pub non_conformance: Vec<String>,
    /// The SHA-256 code integrity "page hash" rule value.
    pub page_sha256: Option<String>,
    /// The SHA-1 code integrity "page hash" rule value.
    pub page_sha1: Option<String>,
    /// Why there are no page hashes, when there are none.
    pub page_hashes_error: Option<String>,
}

/// The overall signing state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SigningStateKind {
    /// A trusted signer vouches for the file: a valid embedded signature
    /// that passed every trust and validity check, or a trusted catalog
    /// that lists the file without relying on SHA-1.
    Trusted,
    /// Signed or catalog-listed, but no trusted signer vouches for it.
    Untrusted,
    /// It carries a signature, none is valid, and no catalog vouches for it;
    /// or its hash is on the revoked list, whatever signs it.
    Invalid,
    /// No embedded signature, and no catalog lists it.
    Unsigned,
    /// No trusted signer vouches for it, and it may still be signed: its
    /// format's embedded signatures are not read (a cabinet, an encoded
    /// script, a file over a reader's size limit), or it has no embedded
    /// signature and no catalog lookup could show it is not listed (no
    /// store was given, the index was cut short, or the file is a script or
    /// installer, whose catalog digests are not yet checked against OS
    /// tooling). Treated as untrusted.
    Unverified,
}

/// Where a trusted signer comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustSource {
    /// An embedded signature.
    Embedded,
    /// A catalog that lists the file.
    Catalog,
}

/// The embedded signatures, judged together (#48).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EmbeddedState {
    /// No embedded signature.
    Unsigned,
    /// At least one is cryptographically valid.
    Valid,
    /// It has one or more, and none is valid.
    Invalid,
    /// The format's embedded signatures are not read (no reader for it, or
    /// over the reader's size limit).
    NotChecked,
}

/// What the catalog lookup found (#51).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CatalogState {
    /// No catalog store was given.
    NotChecked,
    /// No loaded catalog lists the file.
    NotListed,
    /// Only catalogs whose signer is not trusted list it.
    ListedUntrusted,
    /// Only trusted catalogs that rely on SHA-1 (the member digest or the
    /// catalog signature) list it. Never enough to trust the file
    /// (ADR 0008).
    ListedTrustedSha1Only,
    /// A trusted catalog lists it, without relying on SHA-1.
    ListedTrusted,
}

/// The signing state: embedded signatures and catalogs folded together.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SigningState {
    /// The verdict.
    pub state: SigningStateKind,
    /// The embedded signatures.
    pub embedded: EmbeddedState,
    /// Why the embedded signatures are invalid, when they are.
    pub embedded_invalid_reason: Option<String>,
    /// The catalog lookup.
    pub catalog: CatalogState,
    /// The #50 verdict on the embedded signatures, as the shared error
    /// code (`ok` when one passed every check).
    pub verification_error: VerificationError,
    /// The clock is before the floor (#50).
    pub clock_suspect: bool,
    /// The embedded signature that passed every check rests on SHA-1 (its
    /// content or signer digest), so it vouches for nothing (ADR 0008,
    /// ADR 0017): the counterpart of [`CatalogState::ListedTrustedSha1Only`].
    pub embedded_sha1_only: bool,
    /// The trusted signer that vouches for the file.
    pub signer: Option<TrustedSigner>,
}

/// The signer publisher rules can use.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TrustedSigner {
    /// Where it comes from.
    pub source: TrustSource,
    /// The embedded signature, an index into
    /// [`FileIdentity::signatures`].
    pub signature: Option<usize>,
    /// The catalog match, an index into [`FileIdentity::catalog_matches`].
    pub catalog_match: Option<usize>,
    /// The publisher name (leaf `CN`, or `O`).
    pub publisher_name: Option<String>,
    /// The leaf subject DN.
    pub publisher_dn: Option<String>,
    /// The product name, from the version resource (embedded signers).
    pub product_name: Option<String>,
    /// The signer certificate.
    pub leaf: Option<CertBrief>,
    /// The PCA certificate (highest intermediate in the file).
    pub pca: Option<CertBrief>,
    /// The root of the full chain.
    pub root: Option<CertBrief>,
    /// The well-known root ID of the chain, from the trust configuration.
    pub well_known_root_id: Option<u8>,
    /// The trust anchor reached, by label.
    pub anchored_to: Option<String>,
    /// For a packaged app, its `PublisherDisplayName`, carried only once
    /// the manifest's publisher is checked to be this signer. Display only:
    /// rules match the publisher name and DN, never this.
    pub package_display_name: Option<String>,
}

/// One embedded signature (#48), with its chain (#49) and validity (#50).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SignatureSummary {
    /// Its position, depth first.
    pub index: usize,
    /// `embedded`, `nested`, `script`, `msi` or `package`.
    pub kind: &'static str,
    /// 0 for embedded, 1 and up for nested.
    pub depth: u8,
    /// The signature that carries it, for a nested one.
    pub parent: Option<usize>,
    /// The verdict, as a stable name.
    pub status: &'static str,
    /// The verdict in detail, for reading.
    pub status_detail: String,
    /// The image digest algorithm.
    pub digest_alg: Option<DigestAlgorithm>,
    /// The SignerInfo digest algorithm.
    pub signer_digest_alg: Option<DigestAlgorithm>,
    /// The signature algorithm.
    pub sig_alg: Option<SignatureAlgorithm>,
    /// The signer key algorithm.
    pub key_alg: Option<KeyAlgorithm>,
    /// The signer key size in bits.
    pub key_bits: Option<u32>,
    /// The signed image digest matches the file.
    pub digest_match: Option<bool>,
    /// `SpcSpOpusInfo` program name (signed, but chosen by the signer).
    pub program_name: Option<String>,
    /// `SpcSpOpusInfo` URL.
    pub more_info_url: Option<String>,
    /// The `signingTime` claim. Not a trusted time.
    pub claimed_signing_time: Option<i64>,
    /// The signature carries a page hash table.
    pub has_page_hashes: bool,
    /// An OS-native code integrity signer rule can use it.
    pub os_ci_compatible: bool,
    /// Its signer is trusted (#49).
    pub trusted: bool,
    /// Why it is not.
    pub untrusted: Vec<UntrustedReason>,
    /// The #50 verdict.
    pub validity_error: VerificationError,
    /// The trusted signing time, from a verified timestamp.
    pub trusted_signing_time: Option<i64>,
    /// How many timestamps it carries.
    pub timestamps: usize,
    /// The chain of its signer certificate.
    pub chain: Option<ChainSummary>,
}

/// A signer chain (#49).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ChainSummary {
    /// The signer certificate.
    pub leaf: Option<CertBrief>,
    /// The PCA certificate.
    pub pca: Option<CertBrief>,
    /// The last certificate of the full chain.
    pub root: Option<CertBrief>,
    /// Certificates on the full chain.
    pub length: usize,
    /// The full chain reaches a trust anchor.
    pub anchored: bool,
    /// The anchor, by label.
    pub anchored_to: Option<String>,
    /// The well-known root ID.
    pub well_known_root_id: Option<u8>,
    /// How many issues chain building found.
    pub issues: usize,
}

/// The file's identity on its volume (#54).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FileIdSummary {
    /// The volume serial number.
    pub volume_serial: Option<u64>,
    /// The 128-bit file ID, hex.
    pub file_id: Option<String>,
    /// The change journal's ID, when the volume keeps a journal.
    pub usn_journal_id: Option<u64>,
    /// The file's last update sequence number.
    pub usn: Option<i64>,
    /// How many hard links the file has. More than one means other names
    /// reach the same content.
    pub link_count: Option<u32>,
    /// Those names, as far as they could be listed.
    pub link_names: Vec<String>,
}

/// The volume a file is on (#54).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VolumeSummary {
    /// The file system (`ntfs`, `refs`, `fat`, `ex_fat`, `udf`, `cdfs`,
    /// `network`, or another name).
    pub fs_type: Option<String>,
    /// Where the file lives: `os_volume`, `other_fixed`, `removable`,
    /// `optical`, `network`, `ram_disk`, `virtual_disk` or `unknown`.
    pub location: String,
    /// The drive type, as the OS reports it.
    pub drive_type: Option<String>,
    /// The disk's bus.
    pub bus_type: Option<String>,
    /// The disk is hot-pluggable.
    pub is_hotplug: Option<bool>,
    /// It is the volume the OS runs from.
    pub is_os_volume: Option<bool>,
    /// The volume serial number.
    pub serial: Option<u32>,
    /// Owners on this volume can be relied on (a local NTFS or ReFS disk).
    pub supports_owner: bool,
}

/// A file's owner (#54).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OwnerSummary {
    /// The owner SID, as `S-1-…`.
    pub sid: Option<String>,
    /// The account name, when it resolves. Display only.
    pub name: Option<String>,
    /// `admin_equivalent`, `non_admin` or `unknown`.
    pub trust_class: String,
    /// Owners on this volume can be relied on. When `false`, the owner is
    /// not reported and the class is `unknown`.
    pub supported: bool,
}

/// Whether non-administrators can change a file or what its path names
/// (#54, ISM-1392, ISM-1746).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WritableSummary {
    /// The file, or any folder above it on its real or lexical chain, is
    /// writable by some non-administrator, or could not be read: a path
    /// rule for it is unsafe. Fails closed.
    pub path_user_writable: bool,
    /// The file itself is writable by some non-administrator.
    pub file_user_writable: bool,
    /// The nearest user-writable folder above it.
    pub first_user_writable_ancestor: Option<String>,
    /// Some non-administrator may change permissions or the owner on the
    /// file or a folder above it.
    pub change_perms_by_non_admin: bool,
    /// The principals that may hold a write-type right, as SIDs.
    pub principals_with_write: Vec<String>,
}

/// One alternate data stream (#54).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StreamSummary {
    /// The stream's name.
    pub name: String,
    /// Its size in bytes.
    pub size: u64,
    /// A well-known benign stream (the mark-of-the-web, thumbnails and so
    /// on), by name.
    pub benign: Option<String>,
    /// Its content is executable: code kept in a stream. `None` when it
    /// was not looked at.
    pub executable_content: Option<bool>,
}

/// A reparse point (#54).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReparseSummary {
    /// `symlink`, `junction`, `mount_point`, `app_exec_link`,
    /// `cloud_placeholder`, `dedup` or `other`.
    pub kind: String,
    /// The tag.
    pub tag: u32,
    /// Where a link points, as it prints it.
    pub target: Option<String>,
    /// An app execution alias's package family name.
    pub alias_package_family_name: Option<String>,
}

/// A script's signature and identity (#52).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ScriptSummary {
    /// The format it was read as (`power_shell`, `vb_script` and so on).
    pub kind: crate::script::ScriptKind,
    /// The text encoding (`no_bom`, `utf8_bom`, `utf16_le`, `utf16_be`).
    /// `None` when the file was not read.
    pub encoding: Option<crate::script::TextEncoding>,
    /// Why the text cannot be decoded without ambiguity, if it cannot.
    pub text_issue: Option<crate::script::TextIssue>,
    /// The signing state: `unsigned`, `valid`, `digest_mismatch`,
    /// `invalid` or `too_large`.
    pub signing_state: &'static str,
    /// Why it is invalid, for reading.
    pub invalid_reason: Option<String>,
    /// The signature block's offset and length, when it is well formed.
    pub block: Option<crate::script::BlockLocation>,
    /// The text outside the block is empty: its digests identify nothing.
    pub empty_text: bool,
    /// The signed metadata (version-like fields) of the signature, when
    /// it decoded. The signer's claims: trusted only as far as the signer
    /// is, which is `signing_state`'s verdict.
    pub signed_metadata: Option<crate::authenticode::SignedMetadata>,
    /// Anything unusual.
    pub warnings: Vec<crate::script::ScriptWarning>,
}

/// A Windows Installer package's identity (#53).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InstallerSummary {
    /// `msi`, `msp`, `mst` or `msm`.
    pub kind: &'static str,
    /// `ProductCode`, canonical (braced, upper case) when well formed,
    /// otherwise as written.
    pub product_code: Option<String>,
    /// `UpgradeCode`, the same way.
    pub upgrade_code: Option<String>,
    /// The `PackageCode` (summary revision number), the same way.
    pub package_code: Option<String>,
    /// `ProductName`. Free text the author chooses.
    pub product_name: Option<String>,
    /// `ProductVersion`, as written.
    pub product_version: Option<String>,
    /// `ProductVersion` as a quad, when it parses.
    pub product_version_quad: Option<String>,
    /// `Manufacturer`. Free text the author chooses: never a publisher.
    pub manufacturer: Option<String>,
    /// `ProductLanguage`.
    pub product_language: Option<String>,
    /// The summary template's platform.
    pub platform: Option<String>,
    /// For a patch, the product codes it targets.
    pub patch_targets: Vec<String>,
    /// For a transform, the product code it applies to.
    pub transform_target: Option<String>,
    /// How many `Binary` table rows, custom actions and embedded cabinets.
    pub binaries: usize,
    /// How many custom actions.
    pub custom_actions: usize,
    /// Whether any custom action runs executable content.
    pub executable_actions: bool,
    /// Whether any custom action runs elevated (no impersonation).
    pub elevated_actions: bool,
    /// How many embedded cabinets.
    pub cabinets: usize,
    /// The package has a signature stream.
    pub signed: bool,
    /// The signature verifies against the content and nothing follows the
    /// signed package (trust is separate).
    pub signature_valid: bool,
    /// Bytes after the compound file's last sector, which no signature or
    /// hash covers. A signed package with any is invalid.
    pub trailing_bytes: Option<u64>,
    /// The content hash the signature signs, hex.
    pub content_sha256: String,
    /// What could not be read, for reading.
    pub warnings: Vec<String>,
}

/// A packaged app's or bundle's identity (#53).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PackageSummary {
    /// Whether it is a bundle.
    pub is_bundle: bool,
    /// `Identity@Name`.
    pub name: String,
    /// `Identity@Publisher`, exactly as written.
    pub publisher_dn: String,
    /// The 13-character publisher ID.
    pub publisher_id: String,
    /// The package family name. Only as strong as the signature that
    /// binds `Identity@Publisher`: see [`super::strength`].
    pub pfn: String,
    /// The package full name.
    pub full_name: String,
    /// `Identity@Version`.
    pub version: String,
    /// `Identity@ProcessorArchitecture`.
    pub arch: String,
    /// `Identity@ResourceId`.
    pub resource_id: String,
    /// `Properties/DisplayName`. Free text.
    pub display_name: Option<String>,
    /// `Properties/PublisherDisplayName`. Free text: never a publisher.
    pub publisher_display_name: Option<String>,
    /// A framework package.
    pub is_framework: bool,
    /// A resource package.
    pub is_resource_package: bool,
    /// Declares the restricted `runFullTrust` capability.
    pub runs_full_trust: bool,
    /// Application executables, relative to the package root.
    pub executables: Vec<String>,
    /// App execution aliases.
    pub aliases: Vec<String>,
    /// Capability names.
    pub capabilities: Vec<String>,
    /// For a bundle, the member file names.
    pub members: Vec<String>,
    /// It has `AppxSignature.p7x`.
    pub signed: bool,
    /// The signature is valid for the package: the Authenticode checks,
    /// the package digest, the block map and the publisher. Trust is
    /// separate.
    pub signature_valid: bool,
    /// Why a sound signature is still not valid for this package
    /// (`publisher_mismatch`, `block_map` and so on), for reading.
    pub signature_issue: Option<String>,
}

/// The rule-relevant attributes of one certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CertBrief {
    /// The subject DN.
    pub subject: String,
    /// The issuer DN.
    pub issuer: String,
    /// The serial number, hex.
    pub serial: String,
    /// `notBefore`.
    pub not_before: i64,
    /// `notAfter`.
    pub not_after: i64,
    /// SHA-1 of the certificate.
    pub sha1_thumbprint: String,
    /// SHA-256 of the certificate.
    pub sha256_thumbprint: String,
    /// The TBS hash under the certificate's own signature digest: the value
    /// OS code integrity signer rules use.
    pub tbs_hash: Option<String>,
    /// The digest of [`Self::tbs_hash`].
    pub tbs_hash_alg: Option<DigestAlgorithm>,
    /// The SHA-256 of the TBS certificate.
    pub tbs_hash_sha256: String,
}

/// A catalog that lists the file (#51).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CatalogMatchSummary {
    /// The catalog's SHA-256.
    pub catalog_id: Option<String>,
    /// Where it was loaded from.
    pub catalog_path: Option<String>,
    /// `system`, `driver_store` or `policy`.
    pub source: &'static str,
    /// The member's position in the catalog.
    pub member: usize,
    /// Which digest matched.
    pub matched_by: &'static str,
    /// The catalog's signer is trusted.
    pub trusted: bool,
    /// The catalog signature's validity verdict (#50): `ok`, or why it
    /// failed (expired, revoked and so on). `None` when it was not judged,
    /// and then the catalog does not vouch for the file.
    pub validity: Option<palisade_core::VerificationError>,
    /// The match rests on SHA-1 (the member digest or the catalog
    /// signature).
    pub relies_on_sha1: bool,
    /// The revocation data revokes a certificate of the catalog signer's
    /// chain (or cannot rule it out where policy fails closed), so the
    /// catalog vouches for nothing.
    pub signer_revoked: bool,
    /// The catalog signer's publisher name, when trusted.
    pub publisher_name: Option<String>,
    /// The catalog's signer certificate, trusted or not.
    pub signer: Option<CertBrief>,
}

/// File system context (#54).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FsInfo {
    /// The path forms (stat tier).
    pub path: Field<PathInfo>,
    /// The file ID, change journal stamp and hard links (context tier,
    /// #54).
    pub file_id: Field<FileIdSummary>,
    /// The volume (context tier, #54).
    pub volume: Field<VolumeSummary>,
    /// The owner (context tier, #54).
    pub owner: Field<OwnerSummary>,
    /// Writability by non-administrators of the file and every folder
    /// above it (context tier, #54). A path counts as user-writable for
    /// strength unless this is computed and says it is not.
    pub user_writable: Field<WritableSummary>,
    /// Alternate data streams (context tier, #54).
    pub streams: Field<Vec<StreamSummary>>,
    /// The reparse point the path names, if any (context tier, #54).
    /// `Computed(None)` means it is not a reparse point.
    pub reparse: Field<Option<ReparseSummary>>,
    /// The mark-of-the-web (context tier). `Computed(None)` means the file
    /// has no `Zone.Identifier` stream.
    pub motw: Field<Option<MotwSummary>>,
    /// The Palisade path variables that cover the path (context tier).
    pub path_variables: Field<Vec<String>>,
    /// The Palisade provenance tag (#54).
    pub provenance: Field<NotYetDefined>,
}

impl FsInfo {
    const fn not_requested() -> Self {
        Self {
            path: Field::NotRequested,
            file_id: Field::NotRequested,
            volume: Field::NotRequested,
            owner: Field::NotRequested,
            user_writable: Field::NotRequested,
            streams: Field::NotRequested,
            reparse: Field::NotRequested,
            motw: Field::NotRequested,
            path_variables: Field::NotRequested,
            provenance: Field::NotRequested,
        }
    }

    pub(crate) fn absorb(&mut self, other: Self) {
        // Both computed: keep this one, but a final path (or rule key) only
        // the other record resolved is kept too, so a later record that
        // contradicts it is still refused.
        if let (Field::Computed(mine), Field::Computed(theirs)) = (&mut self.path, &other.path) {
            if mine.final_path.is_none() {
                mine.final_path.clone_from(&theirs.final_path);
            }
            if mine.rule_key.is_none() {
                mine.rule_key.clone_from(&theirs.rule_key);
            }
        }
        self.path.absorb(other.path);
        self.file_id.absorb(other.file_id);
        self.volume.absorb(other.volume);
        self.owner.absorb(other.owner);
        self.user_writable.absorb(other.user_writable);
        self.streams.absorb(other.streams);
        self.reparse.absorb(other.reparse);
        self.motw.absorb(other.motw);
        self.path_variables.absorb(other.path_variables);
        self.provenance.absorb(other.provenance);
    }
}

/// The path forms of a file (#54).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PathInfo {
    /// The path as given.
    pub original: String,
    /// The path is a claim, not a location this library opened: the name
    /// hint of [`super::identify_bytes`].
    pub claimed: bool,
    /// The normalised Win32 form, when the path is a fully qualified
    /// Windows path.
    pub normalized: Option<String>,
    /// Why it could not be normalised.
    pub normalize_error: Option<String>,
    /// The final path of the opened file, with links resolved (Windows
    /// with the `os-trust` feature).
    pub final_path: Option<String>,
    /// The case-folded key of the name as written.
    pub lexical_key: Option<String>,
    /// The case-folded key of the final path: what path rules match.
    pub rule_key: Option<String>,
}

impl PathInfo {
    /// The path rules about the opened file match: the final path when the
    /// OS gave one (its components are long names the OS expanded, so it
    /// is marked as such), otherwise the normalised path as written.
    pub(crate) fn rule_path(&self) -> Option<crate::fsctx::NormalizedPath> {
        if let Some(fp) = &self.final_path {
            #[allow(unused_mut)]
            let mut p = crate::fsctx::normalize_win32(fp).ok()?;
            #[cfg(all(windows, feature = "os-trust"))]
            p.mark_long_names_verified();
            return Some(p);
        }
        crate::fsctx::normalize_win32(self.normalized.as_deref()?).ok()
    }
}

/// The mark-of-the-web (#54).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MotwSummary {
    /// The `ZoneId` number.
    pub zone_id: Option<u32>,
    /// It records an external origin (internet or restricted zone).
    pub external: bool,
    /// `HostUrl`.
    pub host_url: Option<String>,
    /// `ReferrerUrl`.
    pub referrer_url: Option<String>,
}

/// Attributes worked out from the groups above.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
pub struct Derived {
    /// The file name OS-native rules match on, and where it came from.
    pub effective_file_name: Option<EffectiveName>,
    /// The trusted signer's publisher name.
    pub publisher_name: Option<String>,
    /// The trusted signer's publisher with the product name.
    pub publisher_product: Option<PublisherProduct>,
    /// The image is a kernel-mode driver.
    pub is_kernel_driver: Option<bool>,
    /// The image is a .NET assembly.
    pub is_dotnet: Option<bool>,
    /// Starting it is expected to ask for elevation.
    pub requires_elevation: Option<bool>,
}

/// An effective file name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EffectiveName {
    /// The name.
    pub value: String,
    /// `original_file_name`, `internal_name`, `file_description`,
    /// `product_name` (the version-resource fallback chain) or `file_name`
    /// (the name on disk, when the chain is empty).
    pub source: &'static str,
}

/// A publisher with a product.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PublisherProduct {
    /// The publisher name.
    pub publisher: String,
    /// The product name.
    pub product: String,
}

/// The renamed and masquerading binary assessment. See
/// [`super::masquerade`].
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
pub struct Masquerade {
    /// 0 (nothing suspicious) to 100.
    pub score: u8,
    /// What was found.
    pub reasons: Vec<MasqueradeReason>,
    /// Checks that could not run for want of an input, by name.
    pub unassessed: Vec<&'static str>,
    /// The protected binary the version resource's `OriginalFilename`
    /// names, if any, whoever signed the file.
    pub claims_protected: Option<String>,
}

/// One finding of the masquerade assessment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MasqueradeReason {
    /// The on-disk name differs from the name the file was built with.
    NameMismatch {
        /// The on-disk name.
        on_disk: String,
        /// `OriginalFilename`.
        original_file_name: Option<String>,
        /// `InternalName`.
        internal_name: Option<String>,
    },
    /// Executable content behind an extension that claims something else
    /// (#44's suspicious or critical mismatch), or PE content behind an
    /// extension the OS does not load PE images under.
    ExtensionMismatch {
        /// The extension, lowercased (empty for none).
        extension: String,
        /// The content kind.
        content_kind: String,
    },
    /// A protected binary, signed by its expected signer, under another
    /// name or outside its expected locations.
    KnownBinaryRelocated {
        /// The protected binary's original file name.
        binary: String,
        /// Its on-disk name is not one of the expected names.
        renamed: bool,
        /// Its path is outside every expected location.
        moved: bool,
    },
    /// A file that claims a protected binary's original file name, but is
    /// not signed by its expected signer.
    ProtectedNameClaimed {
        /// The claimed original file name.
        binary: String,
    },
    /// A version resource that claims a protected vendor, on a file the
    /// vendor's expected signer does not vouch for.
    SignerImpersonation {
        /// The protected vendor.
        vendor: String,
        /// `company_name` or `product_name`.
        field: &'static str,
    },
    /// A bidirectional control character in a path component.
    BidiControl {
        /// The component.
        component: String,
        /// The code point, as `U+XXXX`.
        code_point: String,
    },
    /// A character that looks like a Latin letter, mixed with Latin letters
    /// in one name.
    Homoglyph {
        /// The component.
        component: String,
        /// The character, as `U+XXXX`.
        code_point: String,
        /// The Latin character it looks like.
        looks_like: char,
    },
    /// A decoy extension before an executable one (`invoice.pdf.exe`).
    DoubleExtension {
        /// The on-disk name.
        name: String,
    },
    /// The path names an alternate data stream of a file: code kept in a
    /// stream hides behind its host's name.
    AlternateDataStream {
        /// The host file's name.
        host: String,
        /// The stream's name.
        stream: String,
    },
    /// The name ends with a dot or a space, which Win32 drops.
    TrailingDotOrSpace {
        /// The on-disk name.
        name: String,
    },
}

/// A problem in one tier. The record still holds everything else.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IdentityError {
    /// The tier.
    pub tier: Tier,
    /// A stable code.
    pub code: &'static str,
    /// What went wrong, for reading.
    pub message: String,
}
