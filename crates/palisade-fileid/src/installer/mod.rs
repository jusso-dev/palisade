//! Windows Installer packages (#53): `.msi` databases, `.msp` patches,
//! `.mst` transforms and `.msm` merge modules.
//!
//! [`parse_installer`] reads a package from memory and returns an
//! [`InstallerIdentity`]: what kind of package it is, the product identity
//! from the `Property` table and the summary information, the patch or
//! transform targets, an inventory of embedded executable content, the
//! package's Authenticode signature, checked against its content, and a
//! normalised SHA-256 that stays the same across copies of a package whose
//! only differences are timestamps.
//!
//! # Layers
//!
//! - `cfb`: a bounded compound-file reader. Every sector belongs to at
//!   most one chain, every directory entry is reached at most once, and any
//!   inconsistency is an error.
//! - `database`: stream-name decoding, the string pool and the tables.
//! - `summary`: the summary information property set.
//! - this module: identity, signature and hashes.
//!
//! # Package kind
//!
//! The root storage's CLSID says what a package is:
//! `000C1084-0000-0000-C000-000000000046` for an installer database (an
//! `.msi`, or an `.msm` when it has a `ModuleSignature` table),
//! `000C1086-…` for a patch and `000C1082-…` for a transform. A file whose
//! root has any other CLSID is [`InstallerError::NotInstaller`].
//!
//! # The signature
//!
//! An installer package is signed by an Authenticode SignedData in the
//! root stream `\u{5}DigitalSignature`. Its indirect data is
//! `SPC_SIPINFO` (1.3.6.1.4.1.311.2.1.30) naming the installer subject
//! type, `000C10F1-0000-0000-C000-000000000046`, and its digest is the
//! **content hash**, computed like this ([`content_digests`]):
//!
//! 1. Start at the root storage.
//! 2. Sort the storage's children by name: compare the UTF-16LE bytes of
//!    the names up to the shorter length; when one is a prefix of the
//!    other, the longer name sorts first.
//! 3. For each child in that order: in the root, skip
//!    `\u{5}DigitalSignature`, and hash the content of
//!    `\u{5}MsiDigitalSignatureEx` only through step 5; hash a stream's
//!    bytes; recurse into a storage.
//! 4. After the children, hash the storage's 16-byte CLSID.
//! 5. When the package has `\u{5}MsiDigitalSignatureEx`, the hash includes
//!    that stream's bytes at its sorted place, and the stream must equal
//!    the **metadata hash**: the same walk over names, sizes, CLSIDs, state
//!    bits and times instead of content (see [`metadata_digest`]).
//!
//! [`SignatureKind::Msi`] signatures go through the same SignedData
//! decoder, signer certificate lookup, `messageDigest` and signature checks
//! as PE signatures, nested signatures included. Their report then feeds
//! [`crate::authenticode::evaluate_trust`] and
//! [`crate::authenticode::evaluate_validity`] unchanged.
//!
//! # Fail conservative
//!
//! A package is reported signed only when its container parses without
//! any inconsistency. A compound file this reader rejects is an error, not
//! an unsigned package. A signature stream that does not decode is
//! [`SignatureStatus::Malformed`]; an `MsiDigitalSignatureEx` that does not
//! match is a digest mismatch; a content hash that does not match is
//! [`SignatureStatus::DigestMismatch`]. None of those is ever valid.
//!
//! # The normalised hash
//!
//! [`InstallerIdentity::normalised_sha256`] is a **Palisade-specific**
//! identity, not one the OS computes. It is SHA-256 over:
//!
//! 1. the ASCII bytes `palisade-msi-normalised-v1\0`;
//! 2. the root CLSID (16 bytes);
//! 3. for every stream except `\u{5}DigitalSignature`,
//!    `\u{5}MsiDigitalSignatureEx` and `\u{5}SummaryInformation` (and
//!    `\u{5}DocumentSummaryInformation`), in the order of a depth-first walk
//!    that visits each storage's children sorted by their UTF-16 names
//!    (code unit order): the path (storage names and the stream name, each
//!    UTF-16LE, joined by U+002F), as a u32 LE byte length and the bytes;
//!    then the content, as a u64 LE length and the bytes; storages add
//!    their path and CLSID the same way, tagged `S` where streams are
//!    tagged `F`;
//! 4. the summary information without its four FILETIME properties (edit
//!    time, last printed, created, last saved), in the canonical encoding
//!    of `summary::canonical_without_times`, tagged `I`, or the tag `N`
//!    if the package has none.
//!
//! Directory-entry times, the signature streams and sector layout never
//! enter it, so two copies of a package that differ only in when they
//! were built, saved or signed hash the same. It is identity of **medium**
//! strength ([`NormalisedHashStrength::Medium`]): it ignores bytes that
//! the flat hash covers, and it is not a signature.
//!
//! # Limits
//!
//! [`MAX_INSTALLER_SIZE`], the CFB limits ([`cfb::MAX_DIRECTORY_ENTRIES`],
//! [`cfb::MAX_STORAGE_DEPTH`]) and the table limits
//! ([`database::MAX_STRINGS`], [`database::MAX_TABLES`]) bound the work and
//! memory any input can cause. The `fuzz_msi_tables` target fuzzes the
//! whole path.

#![forbid(unsafe_code)]

pub mod cfb;
pub mod database;
pub mod summary;

use std::fmt;

use crate::authenticode::pkcs7::Subject;
use crate::authenticode::verify::verify_detached;
use crate::authenticode::{
    AuthenticodeHashes, AuthenticodeStatus, SignatureKind, SignatureReport, SignatureStatus,
};
use crate::hash::{AlgorithmSet, Digest, HashAlgorithm, MultiHasher, Sha256Stream};
use crate::pe::version::FileVersionQuad;

use cfb::{CfbError, CompoundFile, Entry};
use database::{Database, TableError, Value};
use summary::{SummaryError, SummaryInfo, pid};

/// The largest package read: 1 GiB.
pub const MAX_INSTALLER_SIZE: u64 = 1024 * 1024 * 1024;
/// The most rows listed from each inventory table (`Binary`,
/// `CustomAction`, `Media`, `MsiPatchMetadata`).
pub const MAX_INVENTORY_ROWS: usize = 4096;

/// `000C1084-0000-0000-C000-000000000046`: an installer database.
pub const CLSID_DATABASE: [u8; 16] = clsid(0x000c_1084);
/// `000C1086-0000-0000-C000-000000000046`: a patch.
pub const CLSID_PATCH: [u8; 16] = clsid(0x000c_1086);
/// `000C1082-0000-0000-C000-000000000046`: a transform.
pub const CLSID_TRANSFORM: [u8; 16] = clsid(0x000c_1082);
/// `000C10F1-0000-0000-C000-000000000046`: the installer subject type in a
/// signature's `SPC_SIPINFO`.
pub const SIP_GUID_MSI: [u8; 16] = clsid(0x000c_10f1);

/// A GUID of the form `XXXXXXXX-0000-0000-C000-000000000046`, as stored
/// (the first field little-endian).
const fn clsid(first: u32) -> [u8; 16] {
    let b = first.to_le_bytes();
    [
        b[0], b[1], b[2], b[3], 0, 0, 0, 0, 0xc0, 0, 0, 0, 0, 0, 0, 0x46,
    ]
}

const DIGITAL_SIGNATURE: &str = "\u{5}DigitalSignature";
const DIGITAL_SIGNATURE_EX: &str = "\u{5}MsiDigitalSignatureEx";
const SUMMARY_INFORMATION: &str = "\u{5}SummaryInformation";
const DOC_SUMMARY_INFORMATION: &str = "\u{5}DocumentSummaryInformation";

/// The domain tag of the normalised hash.
const NORMALISED_TAG: &[u8] = b"palisade-msi-normalised-v1\0";

/// What kind of package a file is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum InstallerKind {
    /// An installer database (`.msi`).
    Msi,
    /// A patch (`.msp`).
    Msp,
    /// A transform (`.mst`).
    Mst,
    /// A merge module (`.msm`): a database with a `ModuleSignature` table.
    Msm,
}

/// Why a file could not be read as an installer package at all.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum InstallerError {
    /// Larger than [`MAX_INSTALLER_SIZE`].
    TooLarge(u64),
    /// Not a compound file, or a malformed one.
    Container(CfbError),
    /// A compound file whose root CLSID is not an installer type.
    NotInstaller,
}

impl fmt::Display for InstallerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge(n) => write!(f, "package of {n} bytes exceeds {MAX_INSTALLER_SIZE}"),
            Self::Container(e) => write!(f, "compound file: {e}"),
            Self::NotInstaller => f.write_str("not a Windows Installer package"),
        }
    }
}

impl std::error::Error for InstallerError {}

/// Something that could not be read, or looks wrong, in a package that
/// otherwise parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum InstallerWarning {
    /// A table could not be read; fields from it are absent.
    Table(TableError),
    /// The summary information is missing or malformed; fields from it are
    /// absent, and the normalised hash covers its absence.
    Summary(SummaryError),
    /// No summary information stream.
    NoSummary,
    /// Strings in the pool do not all decode in its codepage; affected
    /// characters are U+FFFD.
    LossyStrings,
    /// An inventory table has more than [`MAX_INVENTORY_ROWS`] rows; the
    /// listing is cut there.
    InventoryTruncated(&'static str),
    /// `\u{5}MsiDigitalSignatureEx` is present without
    /// `\u{5}DigitalSignature`.
    OrphanSignatureEx,
    /// A `\u{5}DigitalSignature` storage (not a stream): ignored, and the
    /// package is not treated as signed.
    SignatureNotStream,
}

/// A GUID property, as written, and whether it is a well-formed
/// `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuidText {
    /// The text as written.
    pub text: String,
    /// Whether it is a braced, uppercase-or-lowercase hex GUID.
    pub well_formed: bool,
}

impl GuidText {
    fn new(text: &str) -> Self {
        Self {
            text: text.to_owned(),
            well_formed: is_braced_guid(text),
        }
    }

    /// The GUID in canonical form: braced and uppercase. `None` if it is
    /// not well formed.
    #[must_use]
    pub fn canonical(&self) -> Option<String> {
        self.well_formed.then(|| self.text.to_ascii_uppercase())
    }
}

fn is_braced_guid(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 38
        && b.first() == Some(&b'{')
        && b.last() == Some(&b'}')
        && b.iter().enumerate().skip(1).take(36).all(|(i, c)| match i {
            9 | 14 | 19 | 24 => *c == b'-',
            _ => c.is_ascii_hexdigit(),
        })
}

/// The `Property` table rows this crate reads.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Properties {
    /// `ProductCode`.
    pub product_code: Option<GuidText>,
    /// `UpgradeCode`.
    pub upgrade_code: Option<GuidText>,
    /// `ProductName`.
    pub product_name: Option<String>,
    /// `ProductVersion`, as written.
    pub product_version_text: Option<String>,
    /// `ProductVersion` parsed as `major.minor.build[.revision]`.
    pub product_version: Option<FileVersionQuad>,
    /// `Manufacturer`.
    pub manufacturer: Option<String>,
    /// `ProductLanguage`.
    pub product_language: Option<String>,
    /// `ALLUSERS`.
    pub all_users: Option<String>,
    /// `MSIINSTALLPERUSER`.
    pub install_per_user: Option<String>,
    /// `ARPSYSTEMCOMPONENT`.
    pub arp_system_component: Option<String>,
}

/// The summary information fields.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SummaryFields {
    /// Codepage of the summary strings (property 1).
    pub codepage: Option<i32>,
    /// Title (2).
    pub title: Option<String>,
    /// Subject (3).
    pub subject: Option<String>,
    /// Author (4).
    pub author: Option<String>,
    /// Keywords (5).
    pub keywords: Option<String>,
    /// Comments (6).
    pub comments: Option<String>,
    /// Template (7): `platform;languages` for a database; for a patch the
    /// target product codes; for a transform the target platform and
    /// language.
    pub template: Option<String>,
    /// Last saved by (8): for a patch, the transforms it applies; for a
    /// transform, the platform and language it produces.
    pub last_author: Option<String>,
    /// Revision number (9): the PackageCode of a database; for a patch its
    /// patch code (and obsoleted patches); for a transform, the target and
    /// upgraded product codes and versions.
    pub revision: Option<String>,
    /// Created (12), FILETIME.
    pub created: Option<u64>,
    /// Last saved (13), FILETIME.
    pub last_saved: Option<u64>,
    /// Last printed (11), FILETIME.
    pub last_printed: Option<u64>,
    /// Page count (14): the minimum installer version (e.g. 500 for 5.0).
    pub page_count: Option<i32>,
    /// Word count (15): source image flags (short names, compressed,
    /// administrative image, elevation not required).
    pub word_count: Option<i32>,
    /// Character count (16): for a transform, the validation and error
    /// condition flags.
    pub char_count: Option<i32>,
    /// Creating application (18).
    pub app_name: Option<String>,
    /// Security (19): 0 none, 2 read-only recommended, 4 read-only
    /// enforced.
    pub security: Option<i32>,
}

impl SummaryFields {
    fn from_info(info: &SummaryInfo) -> Self {
        let text = |id| info.text(id).map(str::to_owned);
        Self {
            codepage: info.int(pid::CODEPAGE),
            title: text(pid::TITLE),
            subject: text(pid::SUBJECT),
            author: text(pid::AUTHOR),
            keywords: text(pid::KEYWORDS),
            comments: text(pid::COMMENTS),
            template: text(pid::TEMPLATE),
            last_author: text(pid::LAST_AUTHOR),
            revision: text(pid::REVISION),
            created: info.time(pid::CREATED),
            last_saved: info.time(pid::LAST_SAVED),
            last_printed: info.time(pid::LAST_PRINTED),
            page_count: info.int(pid::PAGE_COUNT),
            word_count: info.int(pid::WORD_COUNT),
            char_count: info.int(pid::CHAR_COUNT),
            app_name: text(pid::APP_NAME),
            security: info.int(pid::SECURITY),
        }
    }

    /// The platform part of the template (`Intel`, `x64`, `Arm64`, ...),
    /// before the `;`.
    #[must_use]
    pub fn platform(&self) -> Option<&str> {
        let t = self.template.as_deref()?;
        let p = t.split(';').next().unwrap_or_default();
        (!p.is_empty()).then_some(p)
    }

    /// The language IDs of the template, after the `;`.
    #[must_use]
    pub fn languages(&self) -> Vec<u16> {
        self.template
            .as_deref()
            .and_then(|t| t.split_once(';'))
            .map(|(_, l)| l.split(',').filter_map(|x| x.trim().parse().ok()).collect())
            .unwrap_or_default()
    }
}

/// Source image flags (summary word count).
pub mod source_flags {
    /// Short file names.
    pub const SHORT_NAMES: i32 = 0x1;
    /// Compressed source files.
    pub const COMPRESSED: i32 = 0x2;
    /// An administrative image.
    pub const ADMIN_IMAGE: i32 = 0x4;
    /// Elevated privileges are not required.
    pub const NO_ELEVATION: i32 = 0x8;
}

/// What a patch targets.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PatchInfo {
    /// The patch code: the first GUID of the revision number.
    pub patch_code: Option<GuidText>,
    /// Patches this one obsoletes: the other GUIDs of the revision number.
    pub obsoletes: Vec<GuidText>,
    /// Target product codes: the template, `;`-separated.
    pub target_product_codes: Vec<GuidText>,
    /// The transforms it applies: the last-saved-by field, `;`-separated.
    pub transforms: Vec<String>,
    /// `MsiPatchMetadata` `Classification`.
    pub classification: Option<String>,
    /// `MsiPatchMetadata` `DisplayName`.
    pub display_name: Option<String>,
    /// `MsiPatchMetadata` `ManufacturerName`.
    pub manufacturer_name: Option<String>,
    /// `MsiPatchMetadata` `TargetProductName`.
    pub target_product_name: Option<String>,
}

/// Transform validation flags (the low 16 bits of the summary character
/// count).
pub mod transform_validation {
    /// The language must match.
    pub const LANGUAGE: u32 = 0x0001;
    /// The product code must match.
    pub const PRODUCT: u32 = 0x0002;
    /// The platform must match.
    pub const PLATFORM: u32 = 0x0004;
    /// The major version must match.
    pub const MAJOR_VERSION: u32 = 0x0008;
    /// Major and minor versions must match.
    pub const MINOR_VERSION: u32 = 0x0010;
    /// Major, minor and update versions must match.
    pub const UPDATE_VERSION: u32 = 0x0020;
    /// The applied version must be less than the base.
    pub const NEW_LESS_BASE: u32 = 0x0040;
    /// Less than or equal.
    pub const NEW_LESS_EQUAL_BASE: u32 = 0x0080;
    /// Equal.
    pub const NEW_EQUAL_BASE: u32 = 0x0100;
    /// Greater than or equal.
    pub const NEW_GREATER_EQUAL_BASE: u32 = 0x0200;
    /// Greater than.
    pub const NEW_GREATER_BASE: u32 = 0x0400;
    /// The upgrade code must match.
    pub const UPGRADE_CODE: u32 = 0x0800;
}

/// What a transform applies to.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TransformInfo {
    /// The original product code (from the revision number).
    pub target_product_code: Option<GuidText>,
    /// The original product version.
    pub target_version: Option<String>,
    /// The product code after the transform.
    pub upgraded_product_code: Option<GuidText>,
    /// The product version after the transform.
    pub upgraded_version: Option<String>,
    /// The upgrade code, when the revision number carries one.
    pub upgrade_code: Option<GuidText>,
    /// The validation flags ([`transform_validation`]).
    pub validation: u32,
    /// The error-condition flags (the high 16 bits of the character count).
    pub error_conditions: u32,
}

/// One `Binary` table row: a named stream of embedded data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BinaryEntry {
    /// The `Name` key.
    pub name: String,
    /// The size of its stream (`Binary.<Name>`), if it is present.
    pub size: Option<u64>,
}

/// What a custom action runs, from the low bits of its type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CustomActionKind {
    /// A DLL (type 1, 17, 65, ...).
    Dll,
    /// An executable (2, 18, 34, 50).
    Exe,
    /// JScript (5, 21, 37, 53).
    JScript,
    /// VBScript (6, 22, 38, 54).
    VbScript,
    /// Anything else: text data, nested installs, property and directory
    /// assignments.
    Other,
}

/// One `CustomAction` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustomAction {
    /// The `Action` key.
    pub action: String,
    /// The `Type` column, as stored.
    pub raw_type: i32,
    /// What it runs.
    pub kind: CustomActionKind,
    /// Where the code comes from: the source bits (`Type & 0x30`): 0x00 a
    /// `Binary` stream, 0x10 an installed file, 0x20 a directory (working
    /// directory of an EXE), 0x30 a property.
    pub source_bits: i32,
    /// The `Source` column.
    pub source: Option<String>,
    /// The `Target` column (an entry point or command line).
    pub target: Option<String>,
    /// Runs in the elevated system context (deferred, no impersonation).
    pub no_impersonate: bool,
}

impl CustomAction {
    /// Whether this action runs executable content the package itself
    /// carries or installs: a DLL, EXE or script from a `Binary` stream or
    /// an installed file, or an EXE in a directory or named by a property
    /// (types 1, 2, 5, 6, 17, 18, 21, 22, 34, 50 and their scripts).
    #[must_use]
    pub fn is_executable_content(&self) -> bool {
        !matches!(self.kind, CustomActionKind::Other)
    }
}

/// One `Media` row with an embedded cabinet (`#name`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmbeddedCabinet {
    /// The cabinet stream name, without the `#`.
    pub name: String,
    /// The size of the stream, if it is present.
    pub size: Option<u64>,
}

/// Executable content carried inside the package (informational, for
/// #7 and #8).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EmbeddedContent {
    /// `Binary` table rows.
    pub binaries: Vec<BinaryEntry>,
    /// `CustomAction` rows.
    pub custom_actions: Vec<CustomAction>,
    /// `Media` rows whose cabinet is embedded.
    pub cabinets: Vec<EmbeddedCabinet>,
}

impl EmbeddedContent {
    /// Whether any custom action runs executable content.
    #[must_use]
    pub fn has_executable_actions(&self) -> bool {
        self.custom_actions
            .iter()
            .any(CustomAction::is_executable_content)
    }
}

/// How firmly the normalised hash identifies a package.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NormalisedHashStrength {
    /// Medium: a content identity that leaves timestamps out by design.
    Medium,
}

/// The identity of an installer package.
#[derive(Debug, Clone)]
pub struct InstallerIdentity {
    /// The package kind.
    pub kind: InstallerKind,
    /// The root CLSID.
    pub clsid: [u8; 16],
    /// The string pool's codepage (0 is the neutral codepage), if the pool
    /// could be read.
    pub codepage: Option<u32>,
    /// The `Property` table fields (empty for patches and transforms,
    /// which usually have none).
    pub properties: Properties,
    /// The summary information.
    pub summary: SummaryFields,
    /// The PackageCode: the summary revision number of a database or merge
    /// module.
    pub package_code: Option<GuidText>,
    /// For a patch, what it targets.
    pub patch: Option<PatchInfo>,
    /// For a transform, what it applies to.
    pub transform: Option<TransformInfo>,
    /// Embedded executable content.
    pub embedded: EmbeddedContent,
    /// The package's signature. `None` when it has no
    /// `\u{5}DigitalSignature` stream.
    pub signature: Option<SignatureReport>,
    /// The content hash (SHA-256) the signature must sign, also the
    /// subject hash a catalog would list.
    pub content_sha256: Digest,
    /// The flat SHA-256 of the whole file.
    pub flat_sha256: Digest,
    /// The normalised SHA-256 (see the module documentation).
    pub normalised_sha256: Digest,
    /// Its strength.
    pub normalised_strength: NormalisedHashStrength,
    /// What could not be read.
    pub warnings: Vec<InstallerWarning>,
}

impl InstallerIdentity {
    /// The product version as a quad.
    #[must_use]
    pub fn product_version(&self) -> Option<FileVersionQuad> {
        self.properties.product_version
    }

    /// Whether the package has a signature that verifies against its
    /// content. Says nothing about whether the signer is trusted.
    #[must_use]
    pub fn signature_valid(&self) -> bool {
        self.signature.as_ref().is_some_and(|r| r.primary.is_some())
    }

    /// Patch targets (empty unless this is a patch).
    #[must_use]
    pub fn patch_targets(&self) -> &[GuidText] {
        self.patch
            .as_ref()
            .map_or(&[], |p| p.target_product_codes.as_slice())
    }
}

/// Parses an installer package.
pub fn parse_installer(data: &[u8]) -> Result<InstallerIdentity, InstallerError> {
    let size = u64::try_from(data.len()).unwrap_or(u64::MAX);
    if size > MAX_INSTALLER_SIZE {
        return Err(InstallerError::TooLarge(size));
    }
    let cf = CompoundFile::parse(data).map_err(InstallerError::Container)?;
    let clsid = cf.root.clsid;
    let base_kind = match clsid {
        CLSID_DATABASE => InstallerKind::Msi,
        CLSID_PATCH => InstallerKind::Msp,
        CLSID_TRANSFORM => InstallerKind::Mst,
        _ => return Err(InstallerError::NotInstaller),
    };
    let root = cf.root.clone();
    let db = Database::open(cf, &root);
    let mut warnings = Vec::new();
    if let Err(e) = &db.strings {
        if base_kind != InstallerKind::Msp {
            warnings.push(InstallerWarning::Table(e.clone()));
        }
    } else if db.strings.as_ref().is_ok_and(|p| p.lossy) {
        warnings.push(InstallerWarning::LossyStrings);
    }
    if let Some(e) = &db.catalog_error {
        if db.strings.is_ok() {
            warnings.push(InstallerWarning::Table(e.clone()));
        }
    }

    let kind = if base_kind == InstallerKind::Msi && db.has_table("ModuleSignature") {
        InstallerKind::Msm
    } else {
        base_kind
    };

    let summary_info = match root.child(&utf16(SUMMARY_INFORMATION)) {
        Some(e) if !e.is_storage => match summary::parse(&db.cf.stream(e), database_decode) {
            Ok(info) => Some(info),
            Err(err) => {
                warnings.push(InstallerWarning::Summary(err));
                None
            }
        },
        _ => {
            warnings.push(InstallerWarning::NoSummary);
            None
        }
    };
    let summary_fields = summary_info
        .as_ref()
        .map(SummaryFields::from_info)
        .unwrap_or_default();

    let properties = read_properties(&db, &mut warnings);
    let package_code = match kind {
        InstallerKind::Msi | InstallerKind::Msm => {
            summary_fields.revision.as_deref().map(GuidText::new)
        }
        _ => None,
    };
    let patch =
        (kind == InstallerKind::Msp).then(|| read_patch(&db, &summary_fields, &mut warnings));
    let transform = (kind == InstallerKind::Mst).then(|| read_transform(&summary_fields));
    let embedded = read_embedded(&db, &mut warnings);

    let content = content_digests(&db.cf, &root);
    let signature = read_signature(&db.cf, &root, &content, &mut warnings);
    let content_sha256 = content_sha256(&db.cf, &root);
    let normalised_sha256 = normalised_hash(&db.cf, &root, summary_info.as_ref());

    Ok(InstallerIdentity {
        kind,
        clsid,
        codepage: db.strings.as_ref().ok().map(|p| p.codepage),
        properties,
        summary: summary_fields,
        package_code,
        patch,
        transform,
        embedded,
        signature,
        content_sha256,
        flat_sha256: sha256(data),
        normalised_sha256,
        normalised_strength: NormalisedHashStrength::Medium,
        warnings,
    })
}

fn sha256(data: &[u8]) -> Digest {
    crate::hash::sha256_of(data)
}

fn utf16(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

/// Summary strings use the same codepage rules as the string pool.
fn database_decode(bytes: &[u8], codepage: u32) -> (String, bool) {
    database::decode(bytes, codepage)
}

fn read_properties(db: &Database<'_>, warnings: &mut Vec<InstallerWarning>) -> Properties {
    let mut out = Properties::default();
    let table = match db.table("Property") {
        Ok(Some(t)) => t,
        Ok(None) => return out,
        Err(e) => {
            push_table_warning(warnings, e);
            return out;
        }
    };
    let (Ok(key), Ok(value)) = (
        table.string_column("Property"),
        table.string_column("Value"),
    ) else {
        push_table_warning(
            warnings,
            TableError::Schema {
                table: "Property".into(),
                column: "Property/Value",
            },
        );
        return out;
    };
    for row in &table.rows {
        let (Some(&k), Some(&v)) = (row.get(key), row.get(value)) else {
            continue;
        };
        let (Some(k), Some(v)) = (db.text(k), db.text(v)) else {
            continue;
        };
        let v = v.to_owned();
        // The key column is the table's primary key, so each name appears
        // at most once in a well-formed table. A repeat keeps the first,
        // as the OS's key lookup would find one row only.
        match k {
            "ProductCode" if out.product_code.is_none() => {
                out.product_code = Some(GuidText::new(&v))
            }
            "UpgradeCode" if out.upgrade_code.is_none() => {
                out.upgrade_code = Some(GuidText::new(&v))
            }
            "ProductName" if out.product_name.is_none() => out.product_name = Some(v),
            "ProductVersion" if out.product_version_text.is_none() => {
                out.product_version = parse_product_version(&v);
                out.product_version_text = Some(v);
            }
            "Manufacturer" if out.manufacturer.is_none() => out.manufacturer = Some(v),
            "ProductLanguage" if out.product_language.is_none() => out.product_language = Some(v),
            "ALLUSERS" if out.all_users.is_none() => out.all_users = Some(v),
            "MSIINSTALLPERUSER" if out.install_per_user.is_none() => {
                out.install_per_user = Some(v);
            }
            "ARPSYSTEMCOMPONENT" if out.arp_system_component.is_none() => {
                out.arp_system_component = Some(v);
            }
            _ => {}
        }
    }
    out
}

fn push_table_warning(warnings: &mut Vec<InstallerWarning>, e: TableError) {
    let w = InstallerWarning::Table(e);
    if !warnings.contains(&w) {
        warnings.push(w);
    }
}

/// `ProductVersion` is `major.minor.build` with an optional fourth field:
/// major and minor at most 255, build at most 65535. Anything else is not
/// a valid product version.
#[must_use]
pub fn parse_product_version(text: &str) -> Option<FileVersionQuad> {
    let parts: Vec<&str> = text.split('.').collect();
    if !(1..=4).contains(&parts.len()) {
        return None;
    }
    let mut v = [0_u16; 4];
    for (slot, part) in v.iter_mut().zip(&parts) {
        if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        *slot = part.parse().ok()?;
    }
    let [a, b, c, d] = v;
    (a <= 255 && b <= 255).then_some(FileVersionQuad(a, b, c, d))
}

fn guids(list: &str) -> Vec<GuidText> {
    list.split(';')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(GuidText::new)
        .collect()
}

fn read_patch(
    db: &Database<'_>,
    summary: &SummaryFields,
    warnings: &mut Vec<InstallerWarning>,
) -> PatchInfo {
    let mut out = PatchInfo::default();
    if let Some(rev) = &summary.revision {
        // The patch code GUID, then obsoleted patch codes, concatenated.
        let mut rest = rev.as_str();
        let mut first = true;
        while rest.len() >= 38 && rest.is_char_boundary(38) {
            let (head, tail) = rest.split_at(38);
            let g = GuidText::new(head);
            if first {
                out.patch_code = Some(g);
                first = false;
            } else {
                out.obsoletes.push(g);
            }
            rest = tail;
        }
        if first {
            out.patch_code = Some(GuidText::new(rev));
        }
    }
    if let Some(t) = &summary.template {
        out.target_product_codes = guids(t);
    }
    if let Some(t) = &summary.last_author {
        out.transforms = t
            .split(';')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect();
    }
    // `MsiPatchMetadata` (Company, Property, Value).
    match db.table("MsiPatchMetadata") {
        Ok(Some(table)) => {
            if let (Ok(p), Ok(v)) = (
                table.string_column("Property"),
                table.string_column("Value"),
            ) {
                for row in table.rows.iter().take(MAX_INVENTORY_ROWS) {
                    let (Some(k), Some(val)) = (
                        row.get(p).and_then(|&x| db.text(x)),
                        row.get(v).and_then(|&x| db.text(x)),
                    ) else {
                        continue;
                    };
                    let val = Some(val.to_owned());
                    match k {
                        "Classification" if out.classification.is_none() => {
                            out.classification = val;
                        }
                        "DisplayName" if out.display_name.is_none() => out.display_name = val,
                        "ManufacturerName" if out.manufacturer_name.is_none() => {
                            out.manufacturer_name = val;
                        }
                        "TargetProductName" if out.target_product_name.is_none() => {
                            out.target_product_name = val;
                        }
                        _ => {}
                    }
                }
            }
        }
        Ok(None) => {}
        Err(e) => push_table_warning(warnings, e),
    }
    out
}

fn read_transform(summary: &SummaryFields) -> TransformInfo {
    let mut out = TransformInfo::default();
    let flags = summary.char_count.unwrap_or(0);
    let flags = u32::from_ne_bytes(flags.to_ne_bytes());
    out.validation = flags & 0xffff;
    out.error_conditions = flags >> 16;
    // `{product}version;{product}version;{upgrade}`.
    if let Some(rev) = &summary.revision {
        let mut fields = rev.split(';');
        let split = |s: Option<&str>| -> (Option<GuidText>, Option<String>) {
            let Some(s) = s else { return (None, None) };
            if s.len() >= 38 && s.is_char_boundary(38) {
                let (g, v) = s.split_at(38);
                (
                    Some(GuidText::new(g)),
                    (!v.is_empty()).then(|| v.to_owned()),
                )
            } else {
                (Some(GuidText::new(s)), None)
            }
        };
        (out.target_product_code, out.target_version) = split(fields.next());
        (out.upgraded_product_code, out.upgraded_version) = split(fields.next());
        out.upgrade_code = fields
            .next()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(GuidText::new);
    }
    out
}

fn read_embedded(db: &Database<'_>, warnings: &mut Vec<InstallerWarning>) -> EmbeddedContent {
    let mut out = EmbeddedContent::default();
    let stream_size = |name: &str| db.streams.get(name).map(|e| e.size);

    match db.table("Binary") {
        Ok(Some(t)) => {
            if let Ok(n) = t.string_column("Name") {
                if t.rows.len() > MAX_INVENTORY_ROWS {
                    warnings.push(InstallerWarning::InventoryTruncated("Binary"));
                }
                for row in t.rows.iter().take(MAX_INVENTORY_ROWS) {
                    if let Some(name) = row.get(n).and_then(|&v| db.text(v)) {
                        out.binaries.push(BinaryEntry {
                            name: name.to_owned(),
                            size: stream_size(&format!("Binary.{name}")),
                        });
                    }
                }
            }
        }
        Ok(None) => {}
        Err(e) => push_table_warning(warnings, e),
    }

    match db.table("CustomAction") {
        Ok(Some(t)) => {
            let cols = (
                t.string_column("Action"),
                t.int_column("Type"),
                t.string_column("Source"),
                t.string_column("Target"),
            );
            if let (Ok(a), Ok(ty), Ok(src), Ok(tgt)) = cols {
                if t.rows.len() > MAX_INVENTORY_ROWS {
                    warnings.push(InstallerWarning::InventoryTruncated("CustomAction"));
                }
                for row in t.rows.iter().take(MAX_INVENTORY_ROWS) {
                    let Some(action) = row.get(a).and_then(|&v| db.text(v)) else {
                        continue;
                    };
                    let raw_type = match row.get(ty) {
                        Some(Value::Int(v)) => *v,
                        _ => 0,
                    };
                    out.custom_actions.push(CustomAction {
                        action: action.to_owned(),
                        raw_type,
                        kind: custom_action_kind(raw_type),
                        source_bits: raw_type & 0x30,
                        source: row.get(src).and_then(|&v| db.text(v)).map(str::to_owned),
                        target: row.get(tgt).and_then(|&v| db.text(v)).map(str::to_owned),
                        no_impersonate: raw_type & 0x800 != 0,
                    });
                }
            } else {
                push_table_warning(
                    warnings,
                    TableError::Schema {
                        table: "CustomAction".into(),
                        column: "Action/Type/Source/Target",
                    },
                );
            }
        }
        Ok(None) => {}
        Err(e) => push_table_warning(warnings, e),
    }

    match db.table("Media") {
        Ok(Some(t)) => {
            if let Ok(c) = t.string_column("Cabinet") {
                if t.rows.len() > MAX_INVENTORY_ROWS {
                    warnings.push(InstallerWarning::InventoryTruncated("Media"));
                }
                for row in t.rows.iter().take(MAX_INVENTORY_ROWS) {
                    if let Some(name) = row
                        .get(c)
                        .and_then(|&v| db.text(v))
                        .and_then(|s| s.strip_prefix('#'))
                    {
                        out.cabinets.push(EmbeddedCabinet {
                            name: name.to_owned(),
                            size: stream_size(name),
                        });
                    }
                }
            }
        }
        Ok(None) => {}
        Err(e) => push_table_warning(warnings, e),
    }
    out
}

/// The kind from the low three bits of a custom action type. A type whose
/// low bits name a DLL, EXE or script runs code; the source bits say from
/// where. Type 7 (a nested install) and 3 (text data) are "other".
#[must_use]
pub fn custom_action_kind(raw_type: i32) -> CustomActionKind {
    match raw_type & 0x07 {
        1 => CustomActionKind::Dll,
        2 => CustomActionKind::Exe,
        5 => CustomActionKind::JScript,
        6 => CustomActionKind::VbScript,
        _ => CustomActionKind::Other,
    }
}

/// The order the content hash visits a storage's children in: by the
/// UTF-16LE bytes of the names, a name that is a prefix of another sorting
/// after it.
fn hash_order(a: &Entry, b: &Entry) -> std::cmp::Ordering {
    let ab = le_bytes(&a.name);
    let bb = le_bytes(&b.name);
    let n = ab.len().min(bb.len());
    match ab.get(..n).cmp(&bb.get(..n)) {
        std::cmp::Ordering::Equal => bb.len().cmp(&ab.len()),
        other => other,
    }
}

fn le_bytes(name: &[u16]) -> Vec<u8> {
    name.iter().flat_map(|u| u.to_le_bytes()).collect()
}

fn is_named(entry: &Entry, name: &str) -> bool {
    entry.name.iter().copied().eq(name.encode_utf16())
}

/// The SHA-256 content hash alone.
fn content_sha256(cf: &CompoundFile<'_>, root: &Entry) -> Digest {
    let mut h = Sha256Stream::default();
    let include_ex = root
        .children
        .iter()
        .any(|c| !c.is_storage && is_named(c, DIGITAL_SIGNATURE_EX));
    hash_storage(cf, root, true, include_ex, &mut |c| h.update(c));
    h.finish()
}

/// The package's content digests (SHA-256, SHA-1, SHA-384 and SHA-512):
/// what its signature signs (see the module documentation).
#[must_use]
pub fn content_digests(cf: &CompoundFile<'_>, root: &Entry) -> AuthenticodeHashes {
    let mut hasher = MultiHasher::new(AlgorithmSet::ALL);
    let ex = root
        .children
        .iter()
        .find(|c| !c.is_storage && is_named(c, DIGITAL_SIGNATURE_EX));
    hash_storage(cf, root, true, ex.is_some(), &mut |c| hasher.update(c));
    let hashed_bytes = hasher.bytes_hashed();
    let flat = hasher.finalize();
    AuthenticodeHashes {
        digests: HashAlgorithm::ALL
            .iter()
            .filter_map(|&a| flat.get(a).cloned())
            .collect(),
        hashed_bytes,
        status: AuthenticodeStatus::Conformant,
        page_hashes: None,
    }
}

fn hash_storage(
    cf: &CompoundFile<'_>,
    storage: &Entry,
    is_root: bool,
    include_ex: bool,
    sink: &mut dyn FnMut(&[u8]),
) {
    let mut children: Vec<&Entry> = storage.children.iter().collect();
    children.sort_by(|a, b| hash_order(a, b));
    for child in children {
        if is_root && is_named(child, DIGITAL_SIGNATURE) {
            continue;
        }
        if is_root && is_named(child, DIGITAL_SIGNATURE_EX) {
            if include_ex && !child.is_storage {
                cf.for_each_chunk(child, &mut *sink);
            }
            continue;
        }
        if child.is_storage {
            hash_storage(cf, child, false, include_ex, sink);
        } else {
            cf.for_each_chunk(child, &mut *sink);
        }
    }
    sink(&storage.clsid);
}

/// The metadata hash that `\u{5}MsiDigitalSignatureEx` must hold, under
/// `alg`: a walk like the content hash, but over each entry's name (except
/// the root's), its CLSID (storages) or the low 4 bytes of its size
/// (streams), its state bits and, except for the root, its creation and
/// modification times. Storages are entered where they sort, without the
/// trailing CLSID of the content hash.
#[must_use]
pub fn metadata_digest(root: &Entry, alg: HashAlgorithm) -> Option<Digest> {
    let mut hasher = MultiHasher::new(AlgorithmSet::from(alg));
    prehash_storage(root, true, &mut hasher);
    hasher.finalize().get(alg).cloned()
}

fn prehash_entry(e: &Entry, is_root: bool, hasher: &mut MultiHasher) {
    if !is_root {
        hasher.update(&le_bytes(&e.name));
    }
    if e.is_storage {
        hasher.update(&e.clsid);
    } else {
        hasher.update(e.raw_size.get(..4).unwrap_or_default());
    }
    hasher.update(&e.state_bits);
    if !is_root {
        hasher.update(&e.times);
    }
}

fn prehash_storage(storage: &Entry, is_root: bool, hasher: &mut MultiHasher) {
    prehash_entry(storage, is_root, hasher);
    let mut children: Vec<&Entry> = storage.children.iter().collect();
    children.sort_by(|a, b| hash_order(a, b));
    for child in children {
        if is_root && (is_named(child, DIGITAL_SIGNATURE) || is_named(child, DIGITAL_SIGNATURE_EX))
        {
            continue;
        }
        if child.is_storage {
            prehash_storage(child, false, hasher);
        } else {
            prehash_entry(child, false, hasher);
        }
    }
}

fn read_signature(
    cf: &CompoundFile<'_>,
    root: &Entry,
    content: &AuthenticodeHashes,
    warnings: &mut Vec<InstallerWarning>,
) -> Option<SignatureReport> {
    let sig = root
        .children
        .iter()
        .find(|c| is_named(c, DIGITAL_SIGNATURE));
    let ex = root
        .children
        .iter()
        .find(|c| is_named(c, DIGITAL_SIGNATURE_EX));
    let sig = match sig {
        Some(s) if s.is_storage => {
            warnings.push(InstallerWarning::SignatureNotStream);
            return None;
        }
        Some(s) => s,
        None => {
            if ex.is_some() {
                warnings.push(InstallerWarning::OrphanSignatureEx);
            }
            return None;
        }
    };
    let der = cf.stream(sig);
    let mut report = verify_detached(
        &der,
        content,
        Subject::Sip(SIP_GUID_MSI),
        SignatureKind::Msi,
    );
    // The metadata hash, when present, must match under the top-level
    // signature's digest algorithm; otherwise the signature cannot be
    // valid, whatever its content digest says.
    if let Some(ex) = ex {
        let expected = report
            .signatures
            .first()
            .and_then(|s| s.digest_alg)
            .and_then(|a| a.hash_algorithm())
            .and_then(|a| metadata_digest(root, a));
        let stored = if ex.is_storage {
            None
        } else {
            Some(cf.stream(ex))
        };
        let ok = matches!((&expected, &stored), (Some(e), Some(s)) if e.as_bytes() == s.as_slice());
        if !ok {
            demote(&mut report, SignatureStatus::DigestMismatch);
        }
    }
    Some(report)
}

/// Marks every valid signature in `report` as `status` and clears the
/// primary: used when a check outside the SignedData fails.
fn demote(report: &mut SignatureReport, status: SignatureStatus) {
    for sig in &mut report.signatures {
        if sig.status.is_valid() {
            sig.status = status.clone();
            sig.signer = None;
        }
    }
    report.primary = None;
    if let Some(first) = report.signatures.first() {
        report.signing_state = crate::authenticode::SigningState::Invalid(
            crate::authenticode::InvalidReason::Signature(first.status.clone()),
        );
    }
}

/// The normalised hash (see the module documentation).
fn normalised_hash(cf: &CompoundFile<'_>, root: &Entry, summary: Option<&SummaryInfo>) -> Digest {
    let mut h = Sha256Stream::default();
    h.update(NORMALISED_TAG);
    h.update(&root.clsid);
    let mut path: Vec<u8> = Vec::new();
    normalised_storage(cf, root, true, &mut path, &mut h);
    match summary {
        Some(info) => {
            let canon = summary::canonical_without_times(info);
            h.update(b"I");
            h.update(&u64::try_from(canon.len()).unwrap_or(u64::MAX).to_le_bytes());
            h.update(&canon);
        }
        None => h.update(b"N"),
    }
    h.finish()
}

fn normalised_storage(
    cf: &CompoundFile<'_>,
    storage: &Entry,
    is_root: bool,
    path: &mut Vec<u8>,
    h: &mut Sha256Stream,
) {
    let mut children: Vec<&Entry> = storage.children.iter().collect();
    children.sort_by(|a, b| a.name.cmp(&b.name));
    for child in children {
        if is_root
            && [
                DIGITAL_SIGNATURE,
                DIGITAL_SIGNATURE_EX,
                SUMMARY_INFORMATION,
                DOC_SUMMARY_INFORMATION,
            ]
            .iter()
            .any(|n| is_named(child, n))
        {
            continue;
        }
        let saved = path.len();
        if !path.is_empty() {
            path.extend_from_slice(&0x2f_u16.to_le_bytes());
        }
        path.extend_from_slice(&le_bytes(&child.name));
        let path_len = u32::try_from(path.len()).unwrap_or(u32::MAX);
        if child.is_storage {
            h.update(b"S");
            h.update(&path_len.to_le_bytes());
            h.update(path);
            h.update(&child.clsid);
            normalised_storage(cf, child, false, path, h);
        } else {
            h.update(b"F");
            h.update(&path_len.to_le_bytes());
            h.update(path);
            h.update(&child.size.to_le_bytes());
            cf.for_each_chunk(child, |c| h.update(c));
        }
        path.truncate(saved);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn product_versions() {
        assert_eq!(
            parse_product_version("1.2.3"),
            Some(FileVersionQuad(1, 2, 3, 0))
        );
        assert_eq!(
            parse_product_version("255.255.65535.7"),
            Some(FileVersionQuad(255, 255, 65535, 7))
        );
        assert_eq!(parse_product_version("256.0.0"), None);
        assert_eq!(parse_product_version("1..2"), None);
        assert_eq!(parse_product_version("1.2.3.4.5"), None);
        assert_eq!(parse_product_version(" 1.2"), None);
    }

    #[test]
    fn guid_text() {
        let g = GuidText::new("{12345678-9abc-DEF0-1234-56789ABCDEF0}");
        assert!(g.well_formed);
        assert_eq!(
            g.canonical().as_deref(),
            Some("{12345678-9ABC-DEF0-1234-56789ABCDEF0}")
        );
        assert!(!GuidText::new("12345678-9abc-DEF0-1234-56789ABCDEF0").well_formed);
        assert!(!GuidText::new("{12345678-9abc-DEF0-1234-56789ABCDEFG}").well_formed);
    }

    #[test]
    fn custom_action_kinds() {
        for (ty, kind) in [
            (1, CustomActionKind::Dll),
            (2, CustomActionKind::Exe),
            (5, CustomActionKind::JScript),
            (6, CustomActionKind::VbScript),
            (34, CustomActionKind::Exe),
            (50, CustomActionKind::Exe),
            (0x401 | 0x800, CustomActionKind::Dll),
            (51, CustomActionKind::Other),
            (19, CustomActionKind::Other),
            (7, CustomActionKind::Other),
        ] {
            assert_eq!(custom_action_kind(ty), kind, "{ty}");
        }
    }

    #[test]
    fn clsids_are_the_documented_guids() {
        assert_eq!(
            CLSID_DATABASE,
            [
                0x84, 0x10, 0x0c, 0, 0, 0, 0, 0, 0xc0, 0, 0, 0, 0, 0, 0, 0x46
            ]
        );
        assert_eq!(SIP_GUID_MSI[..4], [0xf1, 0x10, 0x0c, 0x00]);
    }
}
