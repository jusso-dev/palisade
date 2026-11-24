//! What a file name claims: the extension, bidirectional control characters
//! and disguising double extensions.
//!
//! The name is never trusted to decide what a file is. It is used to report
//! the claim, to grade a mismatch, and to break ties where the content has
//! no magic.

#![forbid(unsafe_code)]

use std::ffi::OsStr;

use super::{ExtensionKind, FileKind, PeSubKind, ScriptKind};

/// The longest extension kept. Longer "extensions" are reported as
/// [`ExtensionKind::Other`] and are not stored.
const MAX_EXTENSION_LEN: usize = 32;

/// The parts of a file name the classifier uses.
#[derive(Debug, Clone, Default)]
pub(super) struct NameInfo {
    /// The last extension, lowercased.
    pub(super) extension: Option<String>,
    /// The name has an extension longer than [`MAX_EXTENSION_LEN`]. It is
    /// not stored, and claims [`ExtensionKind::Other`].
    pub(super) long_extension: bool,
    /// The extension before it, lowercased and trimmed, if any.
    pub(super) previous_extension: Option<String>,
    /// The name has a bidirectional control character.
    pub(super) bidi_control: bool,
}

/// Bidirectional control characters that can make a name display in a
/// different order from the one the system reads it in.
const fn is_bidi_control(c: char) -> bool {
    matches!(
        c,
        '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
    )
}

/// Trailing dots and spaces, which the OS drops from names.
const TRAILING: [char; 2] = ['.', ' '];

/// Splits `stem.ext`. The stem must not be empty: a leading dot
/// (`.profile`) makes a hidden-file name, not an extension. A stem of
/// spaces is a stem: the OS strips only trailing dots and spaces.
fn split_extension(name: &str) -> Option<(&str, &str)> {
    let (stem, ext) = name.rsplit_once('.')?;
    (!stem.is_empty()).then_some((stem, ext))
}

impl NameInfo {
    /// Parses a file name or path. A leading drive (`C:`) is dropped, both
    /// `/` and `\` separate components, and an alternate data stream suffix
    /// (`name.txt:stream`) is dropped, so the name is the file that holds
    /// the stream. As the OS does, trailing dots and spaces are ignored,
    /// before the last extension and before the one in front of it.
    pub(super) fn parse(name: &OsStr) -> Self {
        let name = name.to_string_lossy();
        let path = match name.as_bytes() {
            [drive, b':', ..] if drive.is_ascii_alphabetic() => name.get(2..).unwrap_or_default(),
            _ => &name,
        };
        let component = path.rsplit(['/', '\\']).next().unwrap_or_default();
        // A bidi control anywhere in the component, the stream name
        // included, is reported.
        let bidi_control = component.chars().any(is_bidi_control);
        let base = component.split(':').next().unwrap_or_default();
        // Only ASCII case is folded. Spaces after the dot and other
        // whitespace stay part of the extension, as they do for the OS, so
        // `app. exe` and `app.exe\u{a0}` are not `.exe`.
        let clean = |s: &str| s.to_ascii_lowercase();
        let mut info = Self {
            bidi_control,
            ..Self::default()
        };
        let Some((stem, ext)) = split_extension(base.trim_end_matches(TRAILING)) else {
            return info;
        };
        let ext = clean(ext);
        if ext.is_empty() {
            return info;
        }
        if ext.len() > MAX_EXTENSION_LEN {
            info.long_extension = true;
            return info;
        }
        info.extension = Some(ext);
        info.previous_extension = split_extension(stem.trim_end_matches(TRAILING))
            .map(|(_, prev)| clean(prev))
            .filter(|p| !p.is_empty() && p.len() <= MAX_EXTENSION_LEN);
        info
    }

    /// Whether the extension is one of `exts`.
    pub(super) fn is_ext(&self, exts: &[&str]) -> bool {
        self.extension.as_deref().is_some_and(|e| exts.contains(&e))
    }

    /// What the extension claims.
    pub(super) fn extension_kind(&self) -> ExtensionKind {
        if self.long_extension {
            return ExtensionKind::Other;
        }
        self.extension.as_deref().map_or(ExtensionKind::None, claim)
    }

    /// An inert extension, or one of a recognised kind that cannot run code
    /// (an archive or disc image), before one that claims executable
    /// content, as in `invoice.pdf.exe` or `photos.zip.exe`.
    pub(super) fn double_extension(&self) -> bool {
        let last_runs = matches!(
            self.extension_kind(),
            ExtensionKind::Kind(k) if k.is_executable_content()
        );
        last_runs
            && self
                .previous_extension
                .as_deref()
                .is_some_and(|p| match claim(p) {
                    ExtensionKind::Inert => true,
                    ExtensionKind::Kind(k) => !k.is_executable_content(),
                    ExtensionKind::None | ExtensionKind::Other => false,
                })
    }
}

/// Extensions of PE images, with the sub-kinds each one fits.
const PE_EXTENSIONS: &[(&str, &[PeSubKind])] = &[
    ("exe", &[PeSubKind::Exe]),
    (
        "dll",
        // Kernel-mode export libraries (such as the hardware abstraction
        // layer) are DLLs too.
        &[
            PeSubKind::Dll,
            PeSubKind::Cpl,
            PeSubKind::Ocx,
            PeSubKind::ResourceOnly,
            PeSubKind::Driver,
        ],
    ),
    ("ocx", &[PeSubKind::Ocx]),
    ("cpl", &[PeSubKind::Cpl]),
    ("scr", &[PeSubKind::Scr]),
    ("sys", &[PeSubKind::Driver]),
    ("drv", &[PeSubKind::Driver, PeSubKind::Dll]),
    ("efi", &[PeSubKind::Efi]),
    ("mui", &[PeSubKind::ResourceOnly, PeSubKind::Dll]),
    ("ax", &[PeSubKind::Dll, PeSubKind::Ocx]),
    ("acm", &[PeSubKind::Dll]),
    ("tsp", &[PeSubKind::Dll]),
    ("ime", &[PeSubKind::Dll]),
    ("pyd", &[PeSubKind::Dll]),
];

/// Extensions of scripts.
const SCRIPT_EXTENSIONS: &[(&str, ScriptKind)] = &[
    ("ps1", ScriptKind::PowerShell),
    ("psm1", ScriptKind::PowerShell),
    ("psd1", ScriptKind::PowerShell),
    ("ps1xml", ScriptKind::PowerShell),
    ("psc1", ScriptKind::PowerShell),
    ("pssc", ScriptKind::PowerShell),
    ("cdxml", ScriptKind::PowerShell),
    ("bat", ScriptKind::Batch),
    ("cmd", ScriptKind::Batch),
    ("vbs", ScriptKind::VbScript),
    ("vbe", ScriptKind::VbScript),
    ("js", ScriptKind::JScript),
    ("jse", ScriptKind::JScript),
    ("wsf", ScriptKind::Wsf),
    ("wsh", ScriptKind::Wsf),
    ("wsc", ScriptKind::Wsc),
    ("sct", ScriptKind::Wsc),
    ("py", ScriptKind::Python),
    ("pyw", ScriptKind::Python),
    ("pyc", ScriptKind::Python),
    ("pyo", ScriptKind::Python),
    ("pyz", ScriptKind::Python),
    ("pyzw", ScriptKind::Python),
    ("sh", ScriptKind::Shell),
    ("bash", ScriptKind::Shell),
    ("zsh", ScriptKind::Shell),
    ("ksh", ScriptKind::Shell),
    ("pl", ScriptKind::Perl),
    ("pm", ScriptKind::Perl),
    ("rb", ScriptKind::Ruby),
    ("php", ScriptKind::Php),
    ("xsl", ScriptKind::Xsl),
    ("xslt", ScriptKind::Xsl),
    ("inf", ScriptKind::Inf),
    ("settingcontent-ms", ScriptKind::SettingContent),
];

/// Extensions of other recognised kinds.
const OTHER_EXTENSIONS: &[(&str, FileKind)] = &[
    ("com", FileKind::Com),
    ("msi", FileKind::Msi),
    ("msp", FileKind::Msp),
    ("mst", FileKind::Mst),
    ("msm", FileKind::Msm),
    ("cab", FileKind::Cab),
    ("zip", FileKind::Zip),
    ("msix", FileKind::Msix),
    ("appx", FileKind::Appx),
    ("msixbundle", FileKind::MsixBundle),
    ("appxbundle", FileKind::AppxBundle),
    ("jar", FileKind::Jar),
    ("chm", FileKind::Chm),
    ("lnk", FileKind::Lnk),
    ("hta", FileKind::Hta),
    ("reg", FileKind::Reg),
    ("iso", FileKind::Iso),
    ("udf", FileKind::Iso),
    ("7z", FileKind::SevenZip),
    ("rar", FileKind::Rar),
    ("gz", FileKind::Gzip),
    ("tgz", FileKind::Gzip),
];

/// Document, media and data extensions that are opened by a viewer, never
/// run.
const INERT_EXTENSIONS: &[&str] = &[
    "txt", "log", "csv", "md", "rtf", "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "odt",
    "ods", "odp", "htm", "html", "xml", "json", "svg", "jpg", "jpeg", "png", "gif", "bmp", "tif",
    "tiff", "ico", "webp", "heic", "mp3", "mp4", "wav", "avi", "mov", "mkv", "wmv", "flac",
];

/// What an extension (lowercased) claims.
fn claim(ext: &str) -> ExtensionKind {
    if PE_EXTENSIONS.iter().any(|(e, _)| *e == ext) {
        return ExtensionKind::Kind(FileKind::Pe);
    }
    if let Some((_, s)) = SCRIPT_EXTENSIONS.iter().find(|(e, _)| *e == ext) {
        return ExtensionKind::Kind(FileKind::Script(*s));
    }
    if let Some((_, k)) = OTHER_EXTENSIONS.iter().find(|(e, _)| *e == ext) {
        return ExtensionKind::Kind(*k);
    }
    if INERT_EXTENSIONS.contains(&ext) {
        return ExtensionKind::Inert;
    }
    ExtensionKind::Other
}

/// Whether `content` (with `sub_kind` for a PE) is what the extension
/// claims (`claimed`).
pub(super) fn claim_matches(
    name: &NameInfo,
    claimed: FileKind,
    content: FileKind,
    sub_kind: Option<PeSubKind>,
) -> bool {
    let ext = name.extension.as_deref().unwrap_or_default();
    match (claimed, content) {
        (FileKind::Pe, FileKind::Pe) => PE_EXTENSIONS
            .iter()
            .find(|(e, _)| *e == ext)
            .zip(sub_kind)
            .is_some_and(|((_, fits), sub)| fits.contains(&sub)),
        // Executable names hold older executable formats too: DOS and
        // 16- and 32-bit DOS-extender programs in `.exe`, and 16-bit
        // libraries and drivers in `.dll`, `.drv` and the like.
        (FileKind::Pe, FileKind::Mz16 | FileKind::Ne16 | FileKind::Le | FileKind::Lx) => {
            ext == "exe"
                || (content == FileKind::Ne16 && matches!(ext, "dll" | "drv" | "cpl" | "scr"))
        }
        // A `.com` name can hold a DOS program of any format, or a PE
        // executable; the system runs all of them.
        (FileKind::Com, FileKind::Com | FileKind::Mz16) => true,
        (FileKind::Com, FileKind::Pe) => sub_kind == Some(PeSubKind::Exe),
        // App packages and bundles are told apart from their `.msix` forms
        // only by name, so the pairs fit either way.
        (FileKind::Msix | FileKind::Appx, FileKind::Msix | FileKind::Appx) => true,
        (
            FileKind::MsixBundle | FileKind::AppxBundle,
            FileKind::MsixBundle | FileKind::AppxBundle,
        ) => true,
        // A merge module has the installer database CLSID.
        (FileKind::Msm, FileKind::Msi) => true,
        // A package or archive renamed to `.zip` is a mismatch: only a
        // plain ZIP fits, through the comparison below.
        (claimed, content) => claimed == content,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> NameInfo {
        NameInfo::parse(OsStr::new(s))
    }

    #[test]
    fn extensions() {
        assert_eq!(parse("a.EXE").extension.as_deref(), Some("exe"));
        assert_eq!(parse(r"C:\dir.d\file").extension, None);
        assert_eq!(
            parse("/x/y/archive.tar.gz").extension.as_deref(),
            Some("gz")
        );
        assert_eq!(
            parse("/x/y/archive.tar.gz").previous_extension.as_deref(),
            Some("tar")
        );
        assert_eq!(parse(".profile").extension, None);
        assert_eq!(parse("a.exe. . ").extension.as_deref(), Some("exe"));
        assert_eq!(parse("a.txt:hidden.exe").extension.as_deref(), Some("txt"));
        assert_eq!(parse("noext").extension, None);
        assert_eq!(parse("a.").extension, None);
        let long = parse(&format!("a.{}", "x".repeat(40)));
        assert_eq!(long.extension, None);
        assert_eq!(long.extension_kind(), ExtensionKind::Other);
        // A one-letter file with a stream is not a drive.
        assert_eq!(parse(r"C:\temp\a:hidden.exe").extension, None);
        assert_eq!(
            parse(r"C:\temp\a.txt:hidden.exe").extension.as_deref(),
            Some("txt")
        );
        assert_eq!(parse("C:app.exe").extension.as_deref(), Some("exe"));
        assert!(parse("a.txt:x\u{202E}exe").bidi_control);
        assert_eq!(parse("   .cmd").extension.as_deref(), Some("cmd"));
        assert_eq!(
            parse("   .pdf.exe").previous_extension.as_deref(),
            Some("pdf")
        );
        assert_eq!(parse("app. exe").extension_kind(), ExtensionKind::Other);
        assert_eq!(
            parse("app.exe\u{a0}").extension_kind(),
            ExtensionKind::Other
        );
    }

    #[test]
    fn double_extensions() {
        assert!(parse("invoice.pdf.exe").double_extension());
        assert!(parse("invoice.pdf          .exe").double_extension());
        assert!(parse("report.txt.ps1").double_extension());
        assert!(parse("invoice.pdf..exe").double_extension());
        assert!(parse("invoice.pdf. .exe").double_extension());
        assert!(parse("photos.zip.exe").double_extension());
        assert!(!parse("archive.tar.gz").double_extension());
        assert!(!parse("setup.x64.exe").double_extension());
        assert!(!parse(".pdf.exe").double_extension());
        assert!(!parse("a.exe.pdf").double_extension());
    }

    #[test]
    fn bidi_controls() {
        assert!(parse("invoice\u{202E}fdp.exe").bidi_control);
        assert!(parse("a\u{2067}b.txt").bidi_control);
        assert!(!parse("plain.exe").bidi_control);
    }

    #[test]
    fn claims() {
        assert_eq!(claim("dll"), ExtensionKind::Kind(FileKind::Pe));
        assert_eq!(
            claim("cmd"),
            ExtensionKind::Kind(FileKind::Script(ScriptKind::Batch))
        );
        assert_eq!(
            claim("msixbundle"),
            ExtensionKind::Kind(FileKind::MsixBundle)
        );
        assert_eq!(claim("jpg"), ExtensionKind::Inert);
        assert_eq!(claim("xyz"), ExtensionKind::Other);
    }
}
