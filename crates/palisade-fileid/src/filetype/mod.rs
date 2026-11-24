//! Content-based file type detection (#44).
//!
//! [`classify`] decides what a file is from its bytes (magic numbers and
//! structure), never from its name alone. The name, when given, is used only
//! to report what the extension claims ([`ExtensionKind`]), to flag a
//! mismatch between the two, and as a tie-breaker in the few places the
//! format has no magic (DOS `.com` files, and text that could be any of
//! several script languages).
//!
//! The input is untrusted:
//!
//! - The classifier reads the first [`HEAD_LEN`] bytes, then makes a few
//!   targeted reads whose total is capped at [`MAX_TARGETED_READ`]. It never
//!   loads the whole file.
//! - No input can make it panic. Every read is bounds-checked, all offset
//!   arithmetic is checked, and every loop over file data has a fixed limit.
//! - It never fails. A file it cannot make sense of is
//!   [`FileKind::Unknown`]; a file whose magic is recognised but whose
//!   structures are broken keeps the outer kind. Either way the reason is in
//!   [`Classification::parse_error`].
//!
//! Every result carries [`CLASSIFIER_VERSION`], so results cached by a later
//! stage can be invalidated when the heuristics change.

#![forbid(unsafe_code)]

mod cfb;
mod magic;
mod name;
mod pe_kind;
mod source;
mod text;
mod zip;

use std::ffi::OsStr;
use std::io::{self, Cursor, Read, Seek};

use crate::pe::{Machine, PeErrorKind, Subsystem};

pub use source::{HEAD_LEN, MAX_TARGETED_READ};

use name::NameInfo;
use source::{ReadError, Source};

/// The version of the classification rules. It is bumped whenever a change
/// could classify some file differently, so that cached results can be
/// thrown away.
pub const CLASSIFIER_VERSION: u16 = 1;

/// At most this many bytes of a ZIP central directory are read. A larger
/// directory is read in part and reported with
/// [`ParseError::ZipDirectoryTruncated`].
pub const MAX_ZIP_DIRECTORY: usize = 4 * 1024 * 1024;

/// At most this many ZIP central directory entries are examined.
pub const MAX_ZIP_ENTRIES: usize = 65_536;

/// The largest DOS `.com` file: one 64 KiB segment less the 256-byte program
/// segment prefix.
pub const MAX_COM_SIZE: u64 = 65_280;

/// At most this many PE import descriptors are examined.
pub const MAX_IMPORT_DESCRIPTORS: usize = 256;

/// At most this many PE export names are examined.
pub const MAX_EXPORT_NAMES: usize = 4096;

/// What a file is, judged from its content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FileKind {
    /// A PE32 or PE32+ image. [`Classification::pe`] has the sub-kind.
    Pe,
    /// A 16-bit "new executable" (`NE` header).
    Ne16,
    /// A "linear executable" (`LE` header), as used by 32-bit DOS extenders
    /// and old virtual device drivers.
    Le,
    /// A "linear executable" (`LX` header).
    Lx,
    /// A DOS `MZ` program without a newer header, or an `MZ` file whose PE
    /// headers could not be read.
    Mz16,
    /// A DOS `.com` program. The format has no magic, so this is a heuristic
    /// ([`Classification::heuristic`] is set).
    Com,
    /// An installer database: a compound file whose root CLSID is
    /// `{000C1084-0000-0000-C000-000000000046}`.
    Msi,
    /// An installer patch: root CLSID `{000C1086-0000-0000-C000-000000000046}`.
    Msp,
    /// An installer transform: root CLSID
    /// `{000C1082-0000-0000-C000-000000000046}`.
    Mst,
    /// An installer merge module. It has the installer database CLSID, so it
    /// is told apart from [`Msi`](Self::Msi) only by a `.msm` name.
    Msm,
    /// Any other OLE compound file.
    OtherCfb,
    /// A cabinet archive (`MSCF`).
    Cab,
    /// A ZIP archive not recognised as anything more specific.
    Zip,
    /// An app package (`AppxManifest.xml` at the root).
    Msix,
    /// An app package named `.appx`. The format is the same as
    /// [`Msix`](Self::Msix); only the name differs.
    Appx,
    /// An app bundle (`AppxMetadata/AppxBundleManifest.xml`).
    MsixBundle,
    /// An app bundle named `.appxbundle`.
    AppxBundle,
    /// A Java archive (`META-INF/MANIFEST.MF`).
    Jar,
    /// A compiled HTML help file (`ITSF`).
    Chm,
    /// A shell link (`.lnk`): header size `0x4C` and the shell link CLSID.
    Lnk,
    /// An HTML application.
    Hta,
    /// A script run by an interpreter.
    Script(ScriptKind),
    /// A registry import file.
    Reg,
    /// An ELF object or executable.
    Elf,
    /// A Mach-O object or executable, thin or fat.
    MachO,
    /// An ISO 9660 or UDF disc image.
    Iso,
    /// A 7z archive.
    SevenZip,
    /// A RAR archive (version 4 or 5).
    Rar,
    /// A gzip stream.
    Gzip,
    /// Text that is not recognised as a script.
    Text,
    /// Nothing recognised.
    Unknown,
}

impl FileKind {
    /// Whether files of this kind can run code, natively or through a host
    /// program: every PE sub-kind, NE, LE, LX, DOS `MZ` and `.com`
    /// programs, installer packages, app packages and bundles, Java
    /// archives, compiled help, HTML applications, shell links, every
    /// script kind and registry files. ELF and Mach-O executables are
    /// included too: they run natively on other systems, and some can run
    /// on Windows through a compatibility layer.
    #[must_use]
    pub const fn is_executable_content(self) -> bool {
        matches!(
            self,
            Self::Pe
                | Self::Ne16
                | Self::Le
                | Self::Lx
                | Self::Mz16
                | Self::Com
                | Self::Msi
                | Self::Msp
                | Self::Mst
                | Self::Msm
                | Self::Msix
                | Self::Appx
                | Self::MsixBundle
                | Self::AppxBundle
                | Self::Jar
                | Self::Chm
                | Self::Lnk
                | Self::Hta
                | Self::Script(_)
                | Self::Reg
                | Self::Elf
                | Self::MachO
        )
    }
}

/// The language of a [`FileKind::Script`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum ScriptKind {
    /// PowerShell (`.ps1`, `.psm1`, `.psd1`, `.ps1xml`).
    PowerShell,
    /// A batch file (`.bat`, `.cmd`).
    Batch,
    /// VBScript (`.vbs`, `.vbe`).
    VbScript,
    /// JScript (`.js`, `.jse`).
    JScript,
    /// A Windows Script File (`.wsf`).
    Wsf,
    /// A Windows Script Component (`.wsc`, `.sct`).
    Wsc,
    /// Python source, bytecode or a zip application (`.py`, `.pyw`, `.pyc`,
    /// `.pyo`, `.pyz`).
    Python,
    /// A Unix shell script, or any script whose shebang line names an
    /// interpreter not listed here.
    Shell,
    /// Perl.
    Perl,
    /// Ruby.
    Ruby,
    /// PHP.
    Php,
    /// An XSL stylesheet with embedded script.
    Xsl,
    /// A setup information file (`.inf`).
    Inf,
    /// A settings shortcut (`.settingcontent-ms`).
    SettingContent,
}

/// What kind of PE image a [`FileKind::Pe`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PeSubKind {
    /// An executable program.
    Exe,
    /// A dynamic-link library.
    Dll,
    /// A kernel-mode driver: it imports from the kernel image, the hardware
    /// abstraction layer or another `.sys` module, sets `WDM_DRIVER`, or
    /// uses the native subsystem without importing from `ntdll.dll` (native
    /// user-mode programs such as the session manager import from it) or
    /// with an `INIT` section or `IMAGE_FILE_SYSTEM`. These include every
    /// signal behind [`crate::pe::PeInfo::is_kernel_driver`], so an image
    /// the parser calls a kernel driver is a `Driver` here too, unless the
    /// import table could not be read in full
    /// ([`PeDetails::incomplete`]).
    Driver,
    /// A UEFI image (subsystems 10 to 13).
    Efi,
    /// A Control Panel item: a DLL that exports `CPlApplet`.
    Cpl,
    /// A screen saver: an executable named `.scr`. Screen savers are plain
    /// executables, so only the name tells them apart.
    Scr,
    /// An ActiveX control: a DLL that exports `DllRegisterServer` and has a
    /// `TYPELIB` resource.
    Ocx,
    /// A resource-only image: no entry point and no code sections.
    ResourceOnly,
}

/// The kind of managed code in an image with a CLR header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DotNetKind {
    /// IL only (`COMIMAGE_FLAGS_ILONLY`).
    IlOnly,
    /// Mixed native and managed code.
    Mixed,
    /// The CLR header could not be read.
    Unknown,
}

/// A hybrid ARM64 or x86 image layout, found from the load configuration's
/// hybrid metadata pointer or the machine field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum HybridKind {
    /// ARM64X: one image with both ARM64 and ARM64EC code.
    Arm64X,
    /// ARM64EC: ARM64 code that is call-compatible with x64.
    Arm64Ec,
    /// A compiled hybrid x86 image (CHPE).
    Chpe,
}

/// PE sub-classification, from the headers parsed by [`crate::pe`] plus a
/// few bounded reads of the import, export, resource, CLR and load
/// configuration directories.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeDetails {
    /// The sub-kind.
    pub sub_kind: PeSubKind,
    /// The COFF machine field.
    pub machine: Machine,
    /// The optional header subsystem.
    pub subsystem: Subsystem,
    /// `IMAGE_FILE_DLL` is set.
    pub is_dll: bool,
    /// The image has a CLR header (data directory 14).
    pub dot_net: Option<DotNetKind>,
    /// The hybrid layout, if any.
    pub hybrid: Option<HybridKind>,
    /// Imports from the kernel image, the hardware abstraction layer or a
    /// `.sys` module were found.
    pub imports_kernel: bool,
    /// The export table has `CPlApplet`.
    pub exports_cpl_applet: bool,
    /// The export table has `DllRegisterServer`.
    pub exports_dll_register_server: bool,
    /// The resource root has a `TYPELIB` type.
    pub has_type_library: bool,
    /// A directory could not be read in full, or a limit
    /// ([`MAX_IMPORT_DESCRIPTORS`], [`MAX_EXPORT_NAMES`]) was reached, so
    /// the sub-kind may be less specific than it could be.
    pub incomplete: bool,
}

/// How sure the classifier is of [`Classification::content_kind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Confidence {
    /// A weak hint: a few keywords, or only the extension.
    Low,
    /// Several keywords of one script language.
    Medium,
    /// A defined magic number, structure or marker.
    High,
}

/// How serious a disagreement between content and name is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum MismatchSeverity {
    /// No mismatch.
    None,
    /// A mismatch with no obvious intent to deceive, such as a DLL named
    /// `.ocx`, a text file named `.exe`, or a PE named with an extension
    /// this classifier does not know (`.tmp`).
    Benign,
    /// Executable content behind a name that claims something inert, such as
    /// a PE named `.pdf`, `.txt` or `.jpg`.
    Suspicious,
    /// Executable content behind a name built to deceive: a bidirectional
    /// override character (such as U+202E) or a disguising double extension
    /// (`invoice.pdf.exe`).
    Critical,
}

/// What a file's extension claims it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ExtensionKind {
    /// No name was given, or the name has no extension.
    None,
    /// An extension of a kind this classifier recognises.
    Kind(FileKind),
    /// A document, image, audio, video or data extension that the system
    /// opens with a viewer, never as code (`.pdf`, `.jpg`, `.docx`, ...).
    Inert,
    /// Any other extension.
    Other,
}

/// How text content is encoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TextEncoding {
    /// No byte order mark: ASCII, UTF-8 or a legacy single- or multi-byte
    /// code page.
    EightBit,
    /// UTF-8 with a byte order mark.
    Utf8Bom,
    /// UTF-16 little-endian with a byte order mark.
    Utf16Le,
    /// UTF-16 big-endian with a byte order mark.
    Utf16Be,
    /// UTF-16 little-endian without a byte order mark (detected from the
    /// pattern of zero bytes).
    Utf16LeNoBom,
    /// UTF-16 big-endian without a byte order mark.
    Utf16BeNoBom,
    /// UTF-32 little-endian with a byte order mark.
    Utf32Le,
    /// UTF-32 big-endian with a byte order mark.
    Utf32Be,
}

/// Informational flags. None of them changes the content kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct ContentFlags {
    /// A macro-capable office suite document: a compound file whose root
    /// CLSID is a word processor, spreadsheet or presentation document, or
    /// a ZIP document with a `vbaProject.bin` part. Recorded for script and
    /// macro visibility (#7) only.
    pub macro_capable_container: bool,
    /// An app package or bundle has a package signature
    /// (`AppxSignature.p7x`). Packages without one are still classified as
    /// packages, because some can be installed unsigned.
    pub package_signature_present: bool,
    /// A ZIP archive with `__main__.py` at its root, behind a shebang line
    /// or named `.pyz` or `.pyzw`.
    pub python_zipapp: bool,
    /// The text has a script signature block marker
    /// (`# SIG # Begin signature block` and the like). Parsing the block is
    /// #52.
    pub script_signature_block: bool,
    /// The script is in the system's encoded script format (`#@~^`).
    pub encoded_script: bool,
    /// The name has a bidirectional control character, such as U+202E.
    pub name_bidi_control: bool,
    /// The name has a disguising double extension: a document, media or
    /// archive extension before an executable one (`invoice.pdf.exe`,
    /// `photos.zip.exe`), ignoring dots and spaces between them.
    pub name_double_extension: bool,
}

/// Why part of a file could not be read or parsed.
///
/// A recognised container with a parse error keeps its outer kind
/// (`Zip`, `OtherCfb`, `Mz16`), which may be less specific than the file
/// really is: a package whose directory was cut short, for one, is `Zip`.
/// So [`Classification::is_executable_content`] is true for a `Zip` with a
/// parse error, and callers making allow decisions should treat any
/// classification with a parse error as not established, and fail closed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseError {
    /// The reader failed.
    Io(io::ErrorKind),
    /// A targeted read would have gone over [`MAX_TARGETED_READ`].
    ReadBudgetExceeded,
    /// The file has a PE signature, but its headers could not be read, so
    /// it is classified as [`FileKind::Mz16`].
    Pe(PeErrorKind),
    /// The file ends inside the PE optional header or section table that
    /// its COFF header declares, so it is classified as
    /// [`FileKind::Mz16`].
    PeHeadersTruncated,
    /// The compound file header is invalid.
    CfbHeader,
    /// The compound file's root directory entry could not be read, or the
    /// file ends inside it. When the CLSID itself was read, it still
    /// decides the kind.
    CfbDirectory,
    /// No ZIP end of central directory record was found.
    ZipDirectoryMissing,
    /// The ZIP central directory is malformed: an entry runs past the
    /// directory, an entry's extra field ends inside a subfield, the
    /// directory runs past the file, or the end records are broken.
    ZipDirectoryMalformed,
    /// The ZIP central directory is larger than [`MAX_ZIP_DIRECTORY`] or
    /// has more than [`MAX_ZIP_ENTRIES`] entries; only part was examined.
    ZipDirectoryTruncated,
    /// The ZIP end records and central directory do not form the single,
    /// consistent layout the APPNOTE describes, so ZIP readers could
    /// disagree on the entries: more than one end record could be taken,
    /// data follows the archive comment, the ZIP64 and 32-bit records
    /// disagree, the recorded offset and size do not meet the next record,
    /// the entry count does not match, or another record sits inside the
    /// directory.
    ZipDirectoryAmbiguous,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(kind) => write!(f, "read failed: {kind}"),
            Self::ReadBudgetExceeded => f.write_str("targeted read budget exceeded"),
            Self::Pe(kind) => write!(f, "PE headers could not be read: {kind:?}"),
            Self::PeHeadersTruncated => {
                f.write_str("file ends inside the PE optional header or section table")
            }
            Self::CfbHeader => f.write_str("compound file header is invalid"),
            Self::CfbDirectory => f.write_str("compound file root entry could not be read"),
            Self::ZipDirectoryMissing => f.write_str("no ZIP end of central directory record"),
            Self::ZipDirectoryMalformed => f.write_str("ZIP central directory is malformed"),
            Self::ZipDirectoryTruncated => {
                f.write_str("ZIP central directory is over the size or entry limit")
            }
            Self::ZipDirectoryAmbiguous => {
                f.write_str("ZIP end records or central directory are ambiguous")
            }
        }
    }
}

impl std::error::Error for ParseError {}

impl From<ReadError> for ParseError {
    fn from(e: ReadError) -> Self {
        match e {
            ReadError::Io(kind) => Self::Io(kind),
            ReadError::Budget => Self::ReadBudgetExceeded,
        }
    }
}

/// The result of [`classify`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Classification {
    /// [`CLASSIFIER_VERSION`] at the time of classification.
    pub classifier_version: u16,
    /// What the content is.
    pub content_kind: FileKind,
    /// What the extension claims.
    pub extension_kind: ExtensionKind,
    /// The lowercased extension, if the name has one.
    pub extension: Option<String>,
    /// Content and name disagree (`mismatch_severity` is not `None`).
    pub mismatch: bool,
    /// How serious the disagreement is.
    pub mismatch_severity: MismatchSeverity,
    /// How sure the classifier is of `content_kind`.
    pub confidence: Confidence,
    /// `content_kind` rests on a heuristic rather than a defined magic or
    /// structure: a DOS `.com` file, or a script found by keywords or by
    /// its extension.
    pub heuristic: bool,
    /// The extension decided `content_kind` where content alone could not:
    /// a script language, `.com`, `.msm`, `.appx`, `.scr`, `.hta` with HTML
    /// content, or `.pyc`.
    pub extension_assisted: bool,
    /// PE details, for [`FileKind::Pe`].
    pub pe: Option<PeDetails>,
    /// The text encoding, for text and script content.
    pub text_encoding: Option<TextEncoding>,
    /// Informational flags.
    pub flags: ContentFlags,
    /// The file length.
    pub file_size: u64,
    /// Why part of the file could not be read or parsed, if it could not.
    pub parse_error: Option<ParseError>,
}

impl Classification {
    /// Whether the content can run code; see
    /// [`FileKind::is_executable_content`]. It is also true for a
    /// [`FileKind::Zip`] with a [`parse_error`](Self::parse_error): its
    /// structure was ambiguous, broken or too large to read in full, so it
    /// may be an app package, Java archive or zip application that some ZIP
    /// reader runs, and it fails closed.
    #[must_use]
    pub const fn is_executable_content(&self) -> bool {
        self.content_kind.is_executable_content()
            || (self.parse_error.is_some() && matches!(self.content_kind, FileKind::Zip))
    }
}

/// Classifies a file from its content.
///
/// `name_hint` is the file name or path, if known. It is used to report the
/// extension's claim and any mismatch, and as a tie-breaker where the
/// content has no magic. The reader is left at an unspecified position.
pub fn classify<R: Read + Seek + ?Sized>(
    reader: &mut R,
    name_hint: Option<&OsStr>,
) -> Classification {
    let name = name_hint.map(NameInfo::parse).unwrap_or_default();
    let mut out = Classification {
        classifier_version: CLASSIFIER_VERSION,
        content_kind: FileKind::Unknown,
        extension_kind: name.extension_kind(),
        extension: name.extension.clone(),
        mismatch: false,
        mismatch_severity: MismatchSeverity::None,
        confidence: Confidence::Low,
        heuristic: false,
        extension_assisted: false,
        pe: None,
        text_encoding: None,
        flags: ContentFlags {
            name_bidi_control: name.bidi_control,
            name_double_extension: name.double_extension(),
            ..ContentFlags::default()
        },
        file_size: 0,
        parse_error: None,
    };
    match Source::open(reader) {
        Ok(mut src) => {
            out.file_size = src.len();
            detect(&mut src, &name, &mut out);
            // The reader ended before the length it reported: the result
            // describes only part of the file, so it is not established.
            if src.head_short() && out.parse_error.is_none() {
                out.parse_error = Some(ParseError::Io(io::ErrorKind::UnexpectedEof));
            }
            apply_name_hints(&name, &mut out);
        }
        Err(e) => out.parse_error = Some(e.into()),
    }
    let severity = mismatch_severity(&out, &name);
    out.mismatch_severity = severity;
    out.mismatch = severity != MismatchSeverity::None;
    out
}

/// [`classify`] over bytes held in memory.
#[must_use]
pub fn classify_bytes(data: &[u8], name_hint: Option<&OsStr>) -> Classification {
    classify(&mut Cursor::new(data), name_hint)
}

/// Sets the content kind, with high confidence.
fn set(out: &mut Classification, kind: FileKind) {
    out.content_kind = kind;
    out.confidence = Confidence::High;
}

/// Content detection: magic numbers first, then structure, then text.
fn detect<R: Read + Seek + ?Sized>(
    src: &mut Source<'_, R>,
    name: &NameInfo,
    out: &mut Classification,
) {
    let head = src.head();
    if head.starts_with(b"MZ") {
        pe_kind::classify(src, name, out);
        return;
    }
    if let Some(kind) = magic::fixed(head) {
        set(out, kind);
        return;
    }
    if head.starts_with(&cfb::SIGNATURE) {
        cfb::classify(src, name, out);
        return;
    }
    if zip::starts_like_zip(head) {
        zip::classify(src, name, out, false);
        return;
    }
    // A zip application: a shebang line, then a ZIP archive. The archive
    // is binary, so this is checked before the text test, and only once:
    // anything but a clean zip application is classified as text below.
    // A read failure in the probe is kept, and reported with whatever the
    // text path finds, since the archive could not be ruled out.
    let mut probe_error = None;
    if text::is_shebang_zip(head) {
        let mut probe = out.clone();
        if zip::classify(src, name, &mut probe, true) {
            *out = probe;
            return;
        }
        probe_error = probe.parse_error;
    }
    let head = src.head();
    // Bytecode has a magic at offset 0, so it is checked before the volume
    // descriptors deeper in.
    if let Some(named) = magic::python_bytecode(head, name.extension.as_deref()) {
        set(out, FileKind::Script(ScriptKind::Python));
        out.extension_assisted = named;
        return;
    }
    if let Some(kind) = magic::disc_image(head) {
        let area = head.get(..magic::SYSTEM_AREA_LEN).unwrap_or_default();
        if !text::system_area_is_script(area, name) {
            set(out, kind);
            return;
        }
        // A script with a planted descriptor. The system area alone is
        // classified, so the binary descriptors after it do not hide the
        // script; then the whole head is, and the more telling result is
        // kept: an executable kind over a non-executable one, then the
        // more confident.
        // Both are ranked as they will be reported, with the name's hints
        // applied. If neither finds text or a script, the image is an image.
        let mut area_result = out.clone();
        text::classify_within(src, name, &mut area_result, magic::SYSTEM_AREA_LEN);
        apply_name_hints(name, &mut area_result);
        let mut head_result = out.clone();
        text::classify(src, name, &mut head_result);
        apply_name_hints(name, &mut head_result);
        let rank = |c: &Classification| (c.is_executable_content(), c.confidence);
        let (mut best, other) = if rank(&head_result) > rank(&area_result) {
            (head_result, area_result)
        } else {
            (area_result, head_result)
        };
        // A read that failed for either result (the head's tail read, say)
        // is reported whichever is kept.
        if best.parse_error.is_none() {
            best.parse_error = other.parse_error;
        }
        if best.is_executable_content() || best.content_kind == FileKind::Text {
            *out = best;
        } else {
            set(out, kind);
        }
        return;
    }
    text::classify(src, name, out);
    if out.parse_error.is_none() {
        out.parse_error = probe_error;
    }
}

/// Applies the rules where the name decides between kinds that content
/// alone cannot tell apart.
fn apply_name_hints(name: &NameInfo, out: &mut Classification) {
    // A DOS `.com` program has no magic.
    let weak = matches!(out.content_kind, FileKind::Unknown | FileKind::Text)
        || (matches!(out.content_kind, FileKind::Script(_)) && out.confidence < Confidence::High);
    if weak
        && out.parse_error.is_none()
        && name.is_ext(&["com"])
        && (1..=MAX_COM_SIZE).contains(&out.file_size)
    {
        out.content_kind = FileKind::Com;
        out.confidence = Confidence::Low;
        out.heuristic = true;
        out.extension_assisted = true;
        return;
    }
    // Content in a script's extension is that script: the host runs it,
    // whatever else is in the file. A keyword guess never overrides the
    // extension's language; only a definite marker does. Unrecognised
    // content (binary, or text with binary data) is taken to be the script
    // too, so that it fails closed.
    if let ExtensionKind::Kind(FileKind::Script(claimed)) = out.extension_kind {
        let readable = !matches!(out.parse_error, Some(ParseError::Io(_)));
        let overridable = match out.content_kind {
            FileKind::Text => true,
            FileKind::Unknown => readable && out.file_size > 0,
            FileKind::Script(_) => out.confidence < Confidence::High,
            _ => false,
        };
        if overridable && out.content_kind != FileKind::Script(claimed) {
            out.content_kind = FileKind::Script(claimed);
            out.confidence = Confidence::Low;
            out.heuristic = true;
            out.extension_assisted = true;
        }
    }
    // An HTML application name on content that is not recognised (binary,
    // or text with binary data) fails closed in the same way. Plain text
    // without HTML stays text: the host shows it, but runs nothing.
    if out.extension_kind == ExtensionKind::Kind(FileKind::Hta)
        && out.content_kind == FileKind::Unknown
        && !matches!(out.parse_error, Some(ParseError::Io(_)))
        && out.file_size > 0
    {
        out.content_kind = FileKind::Hta;
        out.confidence = Confidence::Low;
        out.heuristic = true;
        out.extension_assisted = true;
    }
}

/// Grades the disagreement between content and name.
fn mismatch_severity(out: &Classification, name: &NameInfo) -> MismatchSeverity {
    let content = out.content_kind;
    let executable = out.is_executable_content();
    if executable && (name.bidi_control || name.double_extension()) {
        return MismatchSeverity::Critical;
    }
    if content == FileKind::Unknown {
        return MismatchSeverity::None;
    }
    match out.extension_kind {
        ExtensionKind::None => MismatchSeverity::None,
        // Executable content behind a document or media name.
        ExtensionKind::Inert if executable => MismatchSeverity::Suspicious,
        // Behind an unknown name, such as the `.tmp` files installers
        // unpack and run.
        ExtensionKind::Other if executable => MismatchSeverity::Benign,
        ExtensionKind::Inert | ExtensionKind::Other => MismatchSeverity::None,
        ExtensionKind::Kind(claimed) => {
            let sub_kind = out.pe.as_ref().map(|p| p.sub_kind);
            if name::claim_matches(name, claimed, content, sub_kind) {
                MismatchSeverity::None
            } else if executable && !claimed.is_executable_content() {
                MismatchSeverity::Suspicious
            } else {
                MismatchSeverity::Benign
            }
        }
    }
}
