//! A hardened PE32 / PE32+ parser (#45).
//!
//! [`parse`] reads headers, sections, data directories, the debug directory,
//! the import and export tables, the resource tree, the version resource
//! and the application manifest from an in-memory image, and classifies
//! kernel drivers. The input is untrusted:
//!
//! - No input can make the parser panic. Every read is bounds-checked and
//!   all offset arithmetic is checked.
//! - Nothing is allocated from a size the file declares. Every collection is
//!   bounded by the input length or by a fixed limit (see the `MAX_*`
//!   constants).
//! - The parser fails with a [`PeError`] only when it cannot read the
//!   headers at all. Later problems are recorded as [`ParseWarning`]s and the
//!   rest of the result is still returned.
//!
//! Every structure records the file offsets it came from, so later stages
//! (such as the Authenticode image hash, #47) can work on the exact bytes.

#![forbid(unsafe_code)]

mod analysis;
mod debug;
mod driver;
mod imports;
pub mod manifest;
mod name;
mod read;
mod resource;
mod types;
pub mod version;

use std::fmt;

pub use analysis::{compute_checksum, shannon_entropy};
pub use debug::{CodeViewPdb, DebugEntry, DebugInfo, DebugType, MAX_DEBUG_ENTRIES, MAX_PDB_PATH};
pub use driver::{DriverClass, DriverSignal, KERNEL_MODULES};
pub use imports::{
    Export, ExportInfo, ExportTarget, ImportInfo, ImportedFunction, ImportedModule,
    MAX_EXPORT_SLOTS, MAX_EXPORTS, MAX_IMPORT_DESCRIPTORS, MAX_IMPORT_MODULES,
    MAX_IMPORTED_FUNCTIONS, MAX_MODULE_NAME_BYTES, MAX_NAME_LEN, NotableExports,
};
pub use manifest::{
    AssemblyIdentity, Elevation, ElevationReason, ExecutionLevel, Manifest, ManifestError,
};
pub use name::NormalizedName;
pub use resource::{
    MAX_KEPT_RESOURCES, MAX_RESOURCE_DEPTH, MAX_RESOURCE_ENTRIES, MAX_RESOURCE_NAME_UNITS,
    MAX_RESOURCE_TYPES, ResourceData, ResourceId, ResourceSummary, resource_type,
};
pub use types::{
    DataDirectoryKind, DllCharacteristics, FileCharacteristics, Machine, SectionCharacteristics,
    Subsystem,
};

use read::{bytes, to_u64, to_usize, u8_at, u16_at, u32_at, u64_at};
use version::VersionInfo;

/// `e_lfanew` values above this are rejected, as #45 requires.
pub const MAX_E_LFANEW: u32 = 1024 * 1024;

/// At most this many warnings are kept. Further warnings set
/// [`PeInfo::parse_warnings_truncated`].
pub const MAX_WARNINGS: usize = 256;

/// At most this many section headers are read. The format allows 65,535, but
/// every later lookup scans the section table, so the count is bounded to
/// keep parsing time linear in practice. Real images have far fewer.
pub const MAX_SECTIONS: usize = 1024;

/// A section is flagged as "virtual only" when it has no raw data and at
/// least this virtual size.
pub const LARGE_VIRTUAL_SIZE: u32 = 64 * 1024;

const DOS_SIGNATURE: u16 = 0x5a4d; // "MZ"
/// The loader rounds section file pointers down to this boundary when
/// `FileAlignment` is at least this large.
const SECTOR_SIZE: u32 = 0x200;
const PE_SIGNATURE: u32 = 0x0000_4550; // "PE\0\0"
const COFF_HEADER_SIZE: usize = 20;
const SECTION_HEADER_SIZE: usize = 40;
const DATA_DIRECTORY_COUNT: usize = 16;

/// A fatal parse error: the headers could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeError {
    /// File offset at which the problem was found.
    pub offset: u64,
    /// What went wrong.
    pub kind: PeErrorKind,
}

/// The kind of a [`PeError`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PeErrorKind {
    /// The input is shorter than a DOS header (64 bytes).
    TooSmall,
    /// The input does not start with `MZ`.
    NoDosSignature,
    /// `e_lfanew` is above [`MAX_E_LFANEW`] or leaves no room for the PE
    /// signature before the end of the input.
    LfanewOutOfRange(u32),
    /// There is no `PE\0\0` signature at `e_lfanew`.
    NoPeSignature,
    /// The COFF header is cut off by the end of the input.
    TruncatedCoffHeader,
    /// The optional header is cut off by the end of the input.
    TruncatedOptionalHeader,
    /// `SizeOfOptionalHeader` is too small for the fixed fields.
    OptionalHeaderTooSmall(u16),
    /// The optional header magic is neither PE32 (`0x10b`) nor PE32+
    /// (`0x20b`).
    UnknownOptionalHeaderMagic(u16),
    /// [`parse_prefix`] was given fewer bytes than the headers and section
    /// table need, though the file is long enough to hold them.
    PrefixTooShort {
        /// Bytes the headers and section table need.
        needed: u64,
    },
}

impl fmt::Display for PeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            PeErrorKind::TooSmall => f.write_str("input is smaller than a DOS header"),
            PeErrorKind::NoDosSignature => f.write_str("missing MZ signature"),
            PeErrorKind::LfanewOutOfRange(v) => write!(f, "e_lfanew {v:#x} is out of range"),
            PeErrorKind::NoPeSignature => f.write_str("missing PE signature"),
            PeErrorKind::TruncatedCoffHeader => f.write_str("COFF header is truncated"),
            PeErrorKind::TruncatedOptionalHeader => f.write_str("optional header is truncated"),
            PeErrorKind::OptionalHeaderTooSmall(v) => {
                write!(f, "SizeOfOptionalHeader {v} is too small")
            }
            PeErrorKind::UnknownOptionalHeaderMagic(v) => {
                write!(f, "unknown optional header magic {v:#x}")
            }
            PeErrorKind::PrefixTooShort { needed } => {
                write!(f, "the headers need the first {needed} bytes")
            }
        }?;
        write!(f, " (at offset {:#x})", self.offset)
    }
}

impl std::error::Error for PeError {}

/// A non-fatal problem. The affected field is missing or partial; the rest
/// of [`PeInfo`] is still valid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseWarning {
    /// File offset at which the problem was found.
    pub offset: u64,
    /// What went wrong.
    pub kind: WarningKind,
}

/// The kind of a [`ParseWarning`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum WarningKind {
    /// The section table is cut off; only `parsed` of `declared` sections
    /// were read.
    SectionTableTruncated {
        /// `NumberOfSections` from the COFF header.
        declared: u16,
        /// Section headers actually read.
        parsed: u16,
    },
    /// `NumberOfRvaAndSizes` is above 16. Only 16 directories are read.
    TooManyDataDirectories(u32),
    /// `SizeOfOptionalHeader` has room for fewer data directories than
    /// `NumberOfRvaAndSizes` declares.
    DataDirectoriesTruncated {
        /// `NumberOfRvaAndSizes` (capped at 16).
        declared: u32,
        /// Directories that fit.
        parsed: u32,
    },
    /// More than [`MAX_SECTIONS`] sections are declared; only the first
    /// [`MAX_SECTIONS`] were read.
    TooManySections(u16),
    /// Section raw data overlaps so much that computing every section's
    /// entropy would scan more bytes than the file holds. Entropy is `None`
    /// from this section on.
    EntropyBudgetExhausted {
        /// Index of the first section without entropy.
        index: u16,
    },
    /// A section's raw data extends past the end of the input. Entropy is
    /// computed over the part that is present.
    SectionDataOutOfFile {
        /// Index in the section table.
        index: u16,
    },
    /// A data directory's RVA range does not map to raw file data.
    DirectoryNotMapped(DataDirectoryKind),
    /// The certificate table range lies outside the input.
    CertificateTableOutOfFile,
    /// The certificate table entry has a zero offset or size, or points into
    /// the headers. It is ignored.
    CertificateTableInvalid,
    /// The certificate table range overlaps a section's file data. The
    /// table always lies outside the mapped image, so it is ignored.
    CertificateTableOverlapsSection,
    /// The file is too large (over 4 GiB) for the PE checksum.
    ChecksumUnavailable,
    /// A resource directory or entry is out of bounds.
    ResourceOutOfBounds,
    /// A resource directory refers back to one of its own ancestors. The
    /// loop was not followed.
    ResourceLoop,
    /// A resource entry has a numeric ID with bits 16 to 30 set. The OS
    /// compares the full field, so it matches no resource; it was skipped.
    ResourceIdInvalid(u32),
    /// `RT_VERSION` resources exist, but none is the one the OS loads
    /// (`VS_VERSION_INFO`, ID 1, at the language level), so no version
    /// information is reported.
    NoStandardVersionResource,
    /// A resource directory on a loader lookup path has ID entries that are
    /// not strictly ascending (unsorted or duplicated). The OS loader
    /// binary-searches them, so which entry it finds is not well defined;
    /// the first match was used.
    ResourceDirectoryNotSorted,
    /// The resource tree is deeper than allowed; deeper levels were skipped.
    ResourceTooDeep,
    /// More than [`MAX_RESOURCE_ENTRIES`] resource entries; the
    /// rest were skipped.
    ResourceEntryLimit,
    /// A debug directory entry or its data is out of bounds or malformed.
    DebugDirectoryMalformed,
    /// More than [`MAX_DEBUG_ENTRIES`] debug directory entries; the rest
    /// were skipped.
    TooManyDebugEntries,
    /// The version resource could not be parsed, or parsed only in part.
    VersionInfo(version::VersionInfoIssue),
    /// An import descriptor or its data is out of bounds or malformed.
    ImportTableMalformed,
    /// The import descriptor table has no terminating descriptor (one with
    /// no name or no import address table) within the mapped data or
    /// [`MAX_IMPORT_DESCRIPTORS`].
    ImportTableTruncated,
    /// The export directory's tables are out of bounds or malformed.
    ExportTableMalformed,
    /// The standard manifest could not be parsed.
    Manifest(ManifestError),
}

/// Header fields from the COFF file header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoffHeader {
    /// File offset of the COFF header.
    pub offset: u64,
    /// Target machine.
    pub machine: Machine,
    /// `NumberOfSections` as declared.
    pub number_of_sections: u16,
    /// `TimeDateStamp`. When [`DebugInfo::has_repro`] is set this is a hash
    /// of the build inputs, not a time.
    pub time_date_stamp: u32,
    /// `PointerToSymbolTable`.
    pub pointer_to_symbol_table: u32,
    /// `NumberOfSymbols`.
    pub number_of_symbols: u32,
    /// `SizeOfOptionalHeader`.
    pub size_of_optional_header: u16,
    /// `Characteristics`.
    pub characteristics: FileCharacteristics,
}

/// The optional header format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PeFormat {
    /// PE32, magic `0x10b` (32-bit images).
    Pe32,
    /// PE32+, magic `0x20b` (64-bit images).
    Pe32Plus,
}

/// Fields from the optional header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OptionalHeader {
    /// File offset of the optional header.
    pub offset: u64,
    /// PE32 or PE32+.
    pub format: PeFormat,
    /// Linker version, (major, minor).
    pub linker_version: (u8, u8),
    /// `SizeOfCode`.
    pub size_of_code: u32,
    /// `SizeOfInitializedData`.
    pub size_of_initialized_data: u32,
    /// `SizeOfUninitializedData`.
    pub size_of_uninitialized_data: u32,
    /// `AddressOfEntryPoint` (an RVA; zero for many DLLs).
    pub entry_point: u32,
    /// `BaseOfCode`.
    pub base_of_code: u32,
    /// `ImageBase`, widened to 64 bits for PE32.
    pub image_base: u64,
    /// `SectionAlignment`.
    pub section_alignment: u32,
    /// `FileAlignment`.
    pub file_alignment: u32,
    /// Operating system version, (major, minor).
    pub os_version: (u16, u16),
    /// Image version, (major, minor).
    pub image_version: (u16, u16),
    /// Subsystem version, (major, minor).
    pub subsystem_version: (u16, u16),
    /// `Win32VersionValue` (reserved, should be zero).
    pub win32_version_value: u32,
    /// `SizeOfImage`.
    pub size_of_image: u32,
    /// `SizeOfHeaders`.
    pub size_of_headers: u32,
    /// The stored `CheckSum`.
    pub checksum: u32,
    /// File offset of the `CheckSum` field (excluded by the checksum and by
    /// the Authenticode image hash).
    pub checksum_offset: u64,
    /// `Subsystem`.
    pub subsystem: Subsystem,
    /// `DllCharacteristics`.
    pub dll_characteristics: DllCharacteristics,
    /// `SizeOfStackReserve`.
    pub size_of_stack_reserve: u64,
    /// `SizeOfStackCommit`.
    pub size_of_stack_commit: u64,
    /// `SizeOfHeapReserve`.
    pub size_of_heap_reserve: u64,
    /// `SizeOfHeapCommit`.
    pub size_of_heap_commit: u64,
    /// `LoaderFlags`.
    pub loader_flags: u32,
    /// `NumberOfRvaAndSizes` as declared (may exceed 16).
    pub number_of_rva_and_sizes: u32,
}

/// One optional header data directory entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataDirectory {
    /// Which directory this is.
    pub kind: DataDirectoryKind,
    /// `VirtualAddress`: an RVA, except for [`DataDirectoryKind::Security`],
    /// where it is a file offset.
    pub virtual_address: u32,
    /// `Size` in bytes.
    pub size: u32,
    /// File offset of this 8-byte entry in the optional header.
    pub entry_offset: u64,
}

impl DataDirectory {
    /// Whether the entry is non-zero.
    #[must_use]
    pub const fn is_present(&self) -> bool {
        self.virtual_address != 0 || self.size != 0
    }
}

/// A range of bytes in the input file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileRange {
    /// Start offset.
    pub offset: u64,
    /// Length in bytes.
    pub size: u64,
}

/// One section header, plus analysis of its raw data.
#[derive(Debug, Clone, PartialEq)]
pub struct Section {
    /// File offset of the 40-byte section header.
    pub header_offset: u64,
    /// The name up to the first NUL, lossily decoded as UTF-8.
    pub name: String,
    /// The 8 raw name bytes.
    pub raw_name: [u8; 8],
    /// `VirtualSize`.
    pub virtual_size: u32,
    /// `VirtualAddress` (an RVA).
    pub virtual_address: u32,
    /// `SizeOfRawData`.
    pub size_of_raw_data: u32,
    /// `PointerToRawData` (a file offset).
    pub pointer_to_raw_data: u32,
    /// `Characteristics`.
    pub characteristics: SectionCharacteristics,
    /// Shannon entropy of the raw data present in the file, in bits per byte
    /// (0.0 to 8.0). `None` when the section has no raw data in the file, or
    /// [`ParseOptions::section_entropy`] was off.
    pub entropy: Option<f64>,
}

impl Section {
    /// Both `MEM_WRITE` and `MEM_EXECUTE` are set.
    #[must_use]
    pub const fn is_writable_and_executable(&self) -> bool {
        self.characteristics
            .contains(SectionCharacteristics::MEM_WRITE | SectionCharacteristics::MEM_EXECUTE)
    }

    /// No file data (a zero `SizeOfRawData` or `PointerToRawData`), but a
    /// virtual size of at least [`LARGE_VIRTUAL_SIZE`]: typical of unpacking
    /// stubs that fill memory at run time.
    #[must_use]
    pub const fn is_virtual_only(&self) -> bool {
        (self.size_of_raw_data == 0 || self.pointer_to_raw_data == 0)
            && self.virtual_size >= LARGE_VIRTUAL_SIZE
    }

    /// Where the loader reads this section's data from in the file, as
    /// `(offset, size)`, or `None` when it maps the section zero-filled.
    ///
    /// Like the loader, a zero `PointerToRawData` or `SizeOfRawData` means
    /// no file data, and when `FileAlignment` is at least 0x200 the pointer
    /// is rounded down to a 512-byte boundary.
    #[must_use]
    pub const fn file_data(&self, file_alignment: u32) -> Option<(u32, u32)> {
        if self.pointer_to_raw_data == 0 || self.size_of_raw_data == 0 {
            return None;
        }
        let start = if file_alignment >= SECTOR_SIZE {
            self.pointer_to_raw_data & !(SECTOR_SIZE - 1)
        } else {
            self.pointer_to_raw_data
        };
        Some((start, self.size_of_raw_data))
    }
}

/// The stored and computed PE checksums.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Checksum {
    /// The `CheckSum` field. Zero means "not set", which is normal for
    /// user-mode images; kernel drivers must have a valid one.
    pub stored: u32,
    /// The checksum computed with the standard algorithm, or `None` when the
    /// file is over 4 GiB or [`ParseOptions::compute_checksum`] was off.
    pub computed: Option<u32>,
}

impl Checksum {
    /// The stored checksum equals the computed one.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.computed == Some(self.stored)
    }
}

/// Everything [`parse`] extracts from one image.
#[derive(Debug, Clone, PartialEq)]
pub struct PeInfo {
    /// Length of the parsed input, in bytes.
    pub file_size: u64,
    /// `e_lfanew`: the file offset of the PE signature.
    pub e_lfanew: u32,
    /// The COFF file header.
    pub coff: CoffHeader,
    /// The optional header.
    pub optional: OptionalHeader,
    /// The data directories present in the optional header (up to 16, in
    /// index order). Use [`PeInfo::data_directory`] to look one up.
    pub data_directories: Vec<DataDirectory>,
    /// The section headers that were read.
    pub sections: Vec<Section>,
    /// Stored and computed checksums.
    pub checksum: Checksum,
    /// The certificate table (security directory), if present. Its location
    /// is a file offset, always after the headers (the later of
    /// `SizeOfHeaders` and the end of the section table). Parsing it is #48.
    pub certificate_table: Option<FileRange>,
    /// Why a non-zero security directory entry was not accepted as the
    /// certificate table: [`WarningKind::CertificateTableInvalid`],
    /// [`WarningKind::CertificateTableOutOfFile`] or
    /// [`WarningKind::CertificateTableOverlapsSection`]. Kept here as well as
    /// in [`PeInfo::parse_warnings`], which can be truncated, so the
    /// Authenticode image hash can always report it.
    pub certificate_table_issue: Option<WarningKind>,
    /// Bytes after the headers, the last section's file data and the
    /// certificate table, if any.
    pub overlay: Option<FileRange>,
    /// The debug directory.
    pub debug: DebugInfo,
    /// A summary of the resource tree, if the image has one.
    pub resources: Option<ResourceSummary>,
    /// The parsed version resource (`RT_VERSION`), if present.
    pub version_info: Option<VersionInfo>,
    /// The import table, if the image has one.
    pub imports: Option<ImportInfo>,
    /// The export table, if the image has one.
    pub exports: Option<ExportInfo>,
    /// The application manifest: the lowest standard `RT_MANIFEST` ID
    /// present (1, 2 or 3), parsed. `None` when there is none, or when it
    /// does not parse (with a [`WarningKind::Manifest`] warning); a higher
    /// ID is never used in its place.
    pub manifest: Option<Manifest>,
    /// The `RT_MANIFEST` ID [`Self::manifest`] was read from: 1 is the
    /// process manifest the OS reads at process creation (and so the one
    /// that decides elevation); 2 and 3 are DLL isolation manifests.
    pub manifest_id: Option<u16>,
    /// Kernel driver signals and the verdict.
    pub driver: DriverClass,
    /// Non-fatal problems, at most [`MAX_WARNINGS`].
    pub parse_warnings: Vec<ParseWarning>,
    /// More than [`MAX_WARNINGS`] warnings occurred; the rest were dropped.
    pub parse_warnings_truncated: bool,
}

impl PeInfo {
    /// The data directory of `kind`, if the optional header has it and it is
    /// non-zero.
    #[must_use]
    pub fn data_directory(&self, kind: DataDirectoryKind) -> Option<DataDirectory> {
        self.data_directories
            .get(kind.index())
            .copied()
            .filter(DataDirectory::is_present)
    }

    /// Whether the COFF timestamp is a reproducible-build hash rather than a
    /// time (the debug directory has a `REPRO` entry).
    #[must_use]
    pub const fn timestamp_is_reproducible(&self) -> bool {
        self.debug.has_repro
    }

    /// Whether the image is a kernel-mode driver ([`PeInfo::driver`] has
    /// the reasons).
    #[must_use]
    pub const fn is_kernel_driver(&self) -> bool {
        self.driver.is_kernel_driver
    }

    /// The #45 elevation heuristic, for a file named `file_name` (the
    /// final path component, if known), from the process manifest (ID 1)
    /// only. See [`manifest::requires_elevation`].
    #[must_use]
    pub fn requires_elevation(&self, file_name: Option<&str>) -> Elevation {
        let mut fields = Vec::new();
        if let Some(v) = &self.version_info {
            for field in [
                version::VersionField::FileDescription,
                version::VersionField::ProductName,
                version::VersionField::InternalName,
                version::VersionField::OriginalFileName,
            ] {
                if let Some(value) = v.get(field) {
                    fields.push((field.event_name(), value));
                }
            }
        }
        // Only the process manifest (ID 1) decides elevation; IDs 2 and 3
        // are isolation manifests the OS does not read at process creation.
        let process_manifest = self
            .manifest
            .as_ref()
            .filter(|_| self.manifest_id == Some(1));
        manifest::requires_elevation(process_manifest, file_name, &fields)
    }

    /// The section whose mapped range contains `rva`: `VirtualAddress` up
    /// to `VirtualSize` (or `SizeOfRawData` when `VirtualSize` is zero)
    /// rounded up to `SectionAlignment`, as the loader maps it.
    #[must_use]
    pub fn section_for_rva(&self, rva: u32) -> Option<&Section> {
        self.layout().section_for(rva)
    }

    /// Maps the RVA range `rva..rva + len` to a file offset, as the loader
    /// would. The range must lie in the file-backed part of one section, or
    /// in the headers; zero-filled memory has no file offset.
    #[must_use]
    pub fn rva_to_offset(&self, rva: u32, len: u32) -> Option<u64> {
        self.layout().rva_to_offset(rva, len).map(to_u64)
    }

    fn layout(&self) -> Layout<'_> {
        Layout {
            sections: &self.sections,
            size_of_headers: self.optional.size_of_headers,
            section_alignment: self.optional.section_alignment,
            file_alignment: self.optional.file_alignment,
            file_len: usize::try_from(self.file_size).unwrap_or(usize::MAX),
        }
    }
}

/// Collects warnings up to [`MAX_WARNINGS`].
#[derive(Default)]
pub(crate) struct Warnings {
    list: Vec<ParseWarning>,
    truncated: bool,
}

impl Warnings {
    pub(crate) fn push(&mut self, offset: usize, kind: WarningKind) {
        if self.list.len() < MAX_WARNINGS {
            self.list.push(ParseWarning {
                offset: to_u64(offset),
                kind,
            });
        } else {
            self.truncated = true;
        }
    }
}

fn fatal(offset: usize, kind: PeErrorKind) -> PeError {
    PeError {
        offset: to_u64(offset),
        kind,
    }
}

/// How the loader lays out the image in memory: enough to map RVAs to file
/// offsets the way the OS does.
#[derive(Clone, Copy)]
pub(crate) struct Layout<'a> {
    pub(crate) sections: &'a [Section],
    pub(crate) size_of_headers: u32,
    pub(crate) section_alignment: u32,
    pub(crate) file_alignment: u32,
    /// Length of the input. File offsets at or past it are never returned.
    pub(crate) file_len: usize,
}

impl<'a> Layout<'a> {
    /// The section whose mapped virtual range contains `rva`.
    fn section_for(&self, rva: u32) -> Option<&'a Section> {
        self.sections.iter().find(|s| {
            fits_rva_space(s, self.section_alignment)
                && rva
                    .checked_sub(s.virtual_address)
                    .is_some_and(|delta| delta < mapped_span(s, self.section_alignment))
        })
    }

    /// The file offset of `rva`, and how many file-backed bytes follow it
    /// before the end of its section (or of the headers).
    ///
    /// A section is mapped over `VirtualSize` (or `SizeOfRawData` when
    /// `VirtualSize` is zero) rounded up to `SectionAlignment`, so raw bytes
    /// beyond that are not part of the image and cannot shadow the next
    /// section. Only the first `min(SizeOfRawData, span)` bytes come from
    /// the file, starting at [`Section::file_data`]; the rest is zero-filled
    /// and has no file offset. The headers are mapped below both
    /// `SizeOfHeaders` and the lowest section RVA.
    pub(crate) fn backed_extent(&self, rva: u32) -> Option<(usize, u32)> {
        if let Some(s) = self.section_for(rva) {
            let delta = rva.checked_sub(s.virtual_address)?;
            let (start, raw_size) = s.file_data(self.file_alignment)?;
            let backed = raw_size.min(mapped_span(s, self.section_alignment));
            if delta >= backed {
                return None;
            }
            let offset = to_usize(start.checked_add(delta)?)?;
            return clamp_to_file(offset, backed - delta, self.file_len);
        }
        let limit = self
            .sections
            .iter()
            .map(|s| s.virtual_address)
            .min()
            .map_or(self.size_of_headers, |first| {
                first.min(self.size_of_headers)
            });
        if rva < limit {
            clamp_to_file(to_usize(rva)?, limit - rva, self.file_len)
        } else {
            None
        }
    }

    /// Whether `rva` is mapped zero-filled memory: inside a section's mapped
    /// span but past the raw data it declares (or in a section with none).
    /// This depends only on the headers, never on the input's length, so a
    /// truncated file is not mistaken for zero fill.
    pub(crate) fn zero_filled(&self, rva: u32) -> bool {
        let Some(s) = self.section_for(rva) else {
            return false;
        };
        let Some(delta) = rva.checked_sub(s.virtual_address) else {
            return false;
        };
        let backed = s.file_data(self.file_alignment).map_or(0, |(_, raw_size)| {
            raw_size.min(mapped_span(s, self.section_alignment))
        });
        delta >= backed
    }

    /// Maps the RVA range `rva..rva + len` to a file offset. The range must
    /// start inside the file-backed part of one section (or the headers) and
    /// end inside it too. A zero-length range must still start inside.
    pub(crate) fn rva_to_offset(&self, rva: u32, len: u32) -> Option<usize> {
        let (offset, available) = self.backed_extent(rva)?;
        (len <= available).then_some(offset)
    }
}

/// Cuts an extent of `available` bytes at file offset `offset` so it ends at
/// the end of the input. `None` if it starts at or past the end.
fn clamp_to_file(offset: usize, available: u32, file_len: usize) -> Option<(usize, u32)> {
    let in_file = file_len.checked_sub(offset).filter(|n| *n > 0)?;
    let in_file = u32::try_from(in_file).unwrap_or(u32::MAX);
    Some((offset, available.min(in_file)))
}

/// Whether a section's mapped range ends within the 32-bit RVA space (an
/// end of exactly 2^32 is allowed). A section past it is malformed and is
/// never used to map RVAs.
fn fits_rva_space(s: &Section, section_alignment: u32) -> bool {
    u64::from(s.virtual_address) + mapped_span_u64(s, section_alignment) <= 1_u64 << 32
}

/// [`mapped_span`] in 64-bit arithmetic, so rounding near `u32::MAX` is
/// exact instead of saturating.
fn mapped_span_u64(s: &Section, section_alignment: u32) -> u64 {
    let size = u64::from(if s.virtual_size == 0 {
        s.size_of_raw_data
    } else {
        s.virtual_size
    });
    if section_alignment.is_power_of_two() {
        size.next_multiple_of(u64::from(section_alignment))
    } else {
        size
    }
}

/// The size of a section's mapped virtual range: `VirtualSize`, or
/// `SizeOfRawData` when that is zero, rounded up to `SectionAlignment`.
fn mapped_span(s: &Section, section_alignment: u32) -> u32 {
    let size = if s.virtual_size == 0 {
        s.size_of_raw_data
    } else {
        s.virtual_size
    };
    if section_alignment.is_power_of_two() {
        size.checked_next_multiple_of(section_alignment)
            .unwrap_or(u32::MAX)
    } else {
        size
    }
}

/// Which whole-file analyses [`parse_with`] runs.
///
/// Header, directory and resource parsing only touch the structures they
/// read. The two analyses here scan raw data, so their cost grows with the
/// file size; turn them off when only identity metadata is needed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseOptions {
    /// Compute the PE checksum ([`Checksum::computed`]). Reads every byte.
    pub compute_checksum: bool,
    /// Compute each section's entropy ([`Section::entropy`]). Reads every
    /// section's raw data.
    pub section_entropy: bool,
}

impl Default for ParseOptions {
    /// Everything on.
    fn default() -> Self {
        Self {
            compute_checksum: true,
            section_entropy: true,
        }
    }
}

impl ParseOptions {
    /// Both whole-file analyses off: only structures are parsed.
    #[must_use]
    pub const fn metadata_only() -> Self {
        Self {
            compute_checksum: false,
            section_entropy: false,
        }
    }
}

/// Parses a PE32 or PE32+ image held in memory, with every analysis on.
///
/// Returns an error only when the DOS header, PE signature, COFF header or
/// the fixed part of the optional header cannot be read. Everything after
/// that is best effort, with problems reported in [`PeInfo::parse_warnings`].
pub fn parse(data: &[u8]) -> Result<PeInfo, PeError> {
    parse_with(data, &ParseOptions::default())
}

/// Like [`parse`], with a choice of whole-file analyses.
pub fn parse_with(data: &[u8], options: &ParseOptions) -> Result<PeInfo, PeError> {
    parse_impl(data, to_u64(data.len()), options, true)
}

/// Parses the headers of a PE image from `prefix`, the first bytes of a file
/// that is `file_len` bytes long, so a large file can be identified while it
/// is read in one sequential pass.
///
/// The result has the headers, data directories, section table,
/// certificate table location and overlay, which is everything the
/// Authenticode image hash and the page hash tables need. Everything that
/// depends on the file's length (the certificate table checks,
/// [`PeInfo::overlay`], [`PeInfo::file_size`] and the `SectionDataOutOfFile`
/// warnings) uses `file_len`. The DOS, COFF and optional headers and the
/// section table (up to [`MAX_SECTIONS`] entries) must be inside `prefix`
/// when the file is long enough to hold them; otherwise the result would
/// describe fewer sections than the file has, so it is
/// [`PeErrorKind::PrefixTooShort`].
///
/// When `prefix` is shorter than the file, the debug directory, the
/// resource tree, the version info, the manifest, and the import and export
/// tables are **not** parsed (they are left empty, with no warning),
/// because they can lie anywhere in the file. The driver verdict needs the
/// imports, so it is left at its default ([`DriverClass::default`]) too.
/// Neither the checksum nor section entropy is computed
/// ([`ParseOptions::metadata_only`]). When `prefix` holds the whole file
/// the result is that of [`parse_with`] with
/// [`ParseOptions::metadata_only`].
///
/// `prefix` longer than `file_len` is cut to `file_len`.
pub fn parse_prefix(prefix: &[u8], file_len: u64) -> Result<PeInfo, PeError> {
    let prefix = prefix
        .get(
            ..usize::try_from(file_len)
                .unwrap_or(usize::MAX)
                .min(prefix.len()),
        )
        .unwrap_or(prefix);
    let file_len = file_len.max(to_u64(prefix.len()));
    let whole = to_u64(prefix.len()) == file_len;
    let info = parse_impl(prefix, file_len, &ParseOptions::metadata_only(), whole)?;
    if !whole {
        let sections = usize::from(info.coff.number_of_sections).min(MAX_SECTIONS);
        let needed = info
            .optional
            .offset
            .saturating_add(u64::from(info.coff.size_of_optional_header))
            .saturating_add(to_u64(sections.saturating_mul(SECTION_HEADER_SIZE)))
            .min(file_len);
        if needed > to_u64(prefix.len()) {
            return Err(PeError {
                offset: to_u64(prefix.len()),
                kind: PeErrorKind::PrefixTooShort { needed },
            });
        }
    }
    Ok(info)
}

/// [`parse_with`] over `data`, the first bytes of a file of `file_len`
/// bytes. Reads stay inside `data`; length checks use `file_len`. The debug
/// directory, resources (with the version info and manifest), imports,
/// exports and the driver verdict are worked out only when `directories` is
/// set, which must be only when `data` is the whole file.
fn parse_impl(
    data: &[u8],
    file_len: u64,
    options: &ParseOptions,
    directories: bool,
) -> Result<PeInfo, PeError> {
    let mut warnings = Warnings::default();

    if data.len() < 64 {
        return Err(fatal(0, PeErrorKind::TooSmall));
    }
    if u16_at(data, 0) != Some(DOS_SIGNATURE) {
        return Err(fatal(0, PeErrorKind::NoDosSignature));
    }
    let e_lfanew = u32_at(data, 0x3c).ok_or_else(|| fatal(0x3c, PeErrorKind::TooSmall))?;
    let pe_offset = to_usize(e_lfanew)
        .filter(|_| e_lfanew <= MAX_E_LFANEW)
        .filter(|off| off.checked_add(4).is_some_and(|end| end <= data.len()))
        .ok_or_else(|| fatal(0x3c, PeErrorKind::LfanewOutOfRange(e_lfanew)))?;
    if u32_at(data, pe_offset) != Some(PE_SIGNATURE) {
        return Err(fatal(pe_offset, PeErrorKind::NoPeSignature));
    }

    let coff_offset = pe_offset + 4;
    let coff = parse_coff(data, coff_offset)?;
    let opt_offset = coff_offset + COFF_HEADER_SIZE;
    let opt_size = usize::from(coff.size_of_optional_header);
    let (optional, dd_offset) = parse_optional(data, opt_offset, coff.size_of_optional_header)?;

    let data_directories = parse_data_directories(
        data,
        dd_offset,
        opt_offset.saturating_add(opt_size),
        optional.number_of_rva_and_sizes,
        &mut warnings,
    );

    let section_table = opt_offset.saturating_add(opt_size);
    let mut sections = parse_sections(data, section_table, coff.number_of_sections, &mut warnings);

    // Every section's raw range is checked against the file, whatever the
    // options. Entropy, when wanted, is bounded by a budget: legitimate
    // sections do not overlap, so their raw data adds up to at most the file
    // length, and crafted overlapping sections cannot make the work
    // quadratic.
    let mut entropy_budget = options.section_entropy.then_some(data.len());
    for (index, section) in sections.iter_mut().enumerate() {
        let index = u16::try_from(index).unwrap_or(u16::MAX);
        let Some(raw) = section_raw_data(
            data,
            file_len,
            section,
            optional.file_alignment,
            index,
            &mut warnings,
        ) else {
            continue;
        };
        let Some(budget) = entropy_budget else {
            continue;
        };
        if let Some(left) = budget.checked_sub(raw.len()) {
            entropy_budget = Some(left);
            section.entropy = Some(analysis::shannon_entropy(raw));
        } else {
            warnings.push(
                to_usize(section.pointer_to_raw_data).unwrap_or(usize::MAX),
                WarningKind::EntropyBudgetExhausted { index },
            );
            entropy_budget = None;
        }
    }

    let checksum_offset = usize::try_from(optional.checksum_offset).unwrap_or(usize::MAX);
    let computed = if options.compute_checksum {
        let computed = analysis::compute_checksum(data, checksum_offset);
        if computed.is_none() {
            warnings.push(0, WarningKind::ChecksumUnavailable);
        }
        computed
    } else {
        None
    };
    let checksum = Checksum {
        stored: optional.checksum,
        computed,
    };

    let size_of_headers = optional.size_of_headers;
    // `SizeOfHeaders` is untrusted, so the headers are taken to end at the
    // later of it and the end of the section table actually parsed.
    let headers_end = section_table
        .saturating_add(sections.len().saturating_mul(SECTION_HEADER_SIZE))
        .max(to_usize(size_of_headers).unwrap_or(0));
    let mut certificate_table_issue = None;
    let certificate_table = data_directories
        .get(DataDirectoryKind::Security.index())
        .filter(|d| d.is_present())
        .and_then(|d| {
            let entry = usize::try_from(d.entry_offset).unwrap_or(usize::MAX);
            let range = FileRange {
                offset: u64::from(d.virtual_address),
                size: u64::from(d.size),
            };
            let end = range.offset.saturating_add(range.size);
            // A half-zero entry, or one pointing into the headers, is not a
            // certificate table. Rejecting it also stops a zero-size entry
            // at the end of the file from hiding the overlay.
            let start = to_usize(d.virtual_address).unwrap_or(usize::MAX);
            let rejection = if d.size == 0 || d.virtual_address == 0 || start < headers_end {
                Some(WarningKind::CertificateTableInvalid)
            } else if end > file_len {
                Some(WarningKind::CertificateTableOutOfFile)
            } else if sections
                .iter()
                .filter_map(|s| in_file_data(s, optional.file_alignment, file_len))
                .any(|(s_start, s_end)| range.offset < s_end && s_start < end)
            {
                // The certificate table lies outside the image's mapped
                // data, so a range overlapping any section's file data is
                // not one.
                Some(WarningKind::CertificateTableOverlapsSection)
            } else {
                None
            };
            match rejection {
                Some(kind) => {
                    warnings.push(entry, kind.clone());
                    certificate_table_issue = Some(kind);
                    None
                }
                None => Some(range),
            }
        });

    let overlay = find_overlay(
        file_len,
        headers_end,
        optional.file_alignment,
        &sections,
        certificate_table,
    );

    let layout = Layout {
        sections: &sections,
        size_of_headers,
        section_alignment: optional.section_alignment,
        file_alignment: optional.file_alignment,
        file_len: data.len(),
    };
    let debug = data_directories
        .get(DataDirectoryKind::Debug.index())
        .filter(|d| directories && d.is_present())
        .map(|d| debug::parse(data, layout, *d, &mut warnings))
        .unwrap_or_default();

    let mut resources = None;
    let mut version_info = None;
    let mut manifest = None;
    let mut manifest_id = None;
    if let Some(dir) = data_directories
        .get(DataDirectoryKind::Resource.index())
        .filter(|d| directories && d.is_present())
    {
        if let Some(summary) = resource::walk(data, layout, *dir, &mut warnings) {
            version_info = version_from_resources(data, &summary, &mut warnings);
            (manifest, manifest_id) = manifest_from_resources(data, &summary, &mut warnings);
            resources = Some(summary);
        }
    }

    let directory = |kind: DataDirectoryKind| {
        data_directories
            .get(kind.index())
            .copied()
            .filter(|d| directories && d.is_present())
    };
    let imports = directory(DataDirectoryKind::Import)
        .and_then(|d| imports::parse_imports(data, layout, d, optional.format, &mut warnings));
    let exports = directory(DataDirectoryKind::Export)
        .and_then(|d| imports::parse_exports(data, layout, d, &mut warnings));
    // Without the import table the verdict would be a guess, so a prefix
    // parse leaves it at its default rather than report a partial one.
    let driver = if directories {
        driver::classify(
            optional.subsystem,
            coff.characteristics,
            &sections,
            imports.as_ref(),
        )
    } else {
        DriverClass::default()
    };

    Ok(PeInfo {
        file_size: file_len,
        e_lfanew,
        coff,
        optional,
        data_directories,
        sections,
        checksum,
        certificate_table,
        certificate_table_issue,
        overlay,
        debug,
        resources,
        version_info,
        imports,
        exports,
        manifest,
        manifest_id,
        driver,
        parse_warnings: warnings.list,
        parse_warnings_truncated: warnings.truncated,
    })
}

fn parse_coff(data: &[u8], offset: usize) -> Result<CoffHeader, PeError> {
    let header = bytes(data, offset, COFF_HEADER_SIZE)
        .ok_or_else(|| fatal(offset, PeErrorKind::TruncatedCoffHeader))?;
    let field16 = |at| u16_at(header, at).unwrap_or(0);
    let field32 = |at| u32_at(header, at).unwrap_or(0);
    Ok(CoffHeader {
        offset: to_u64(offset),
        machine: Machine::from_raw(field16(0)),
        number_of_sections: field16(2),
        time_date_stamp: field32(4),
        pointer_to_symbol_table: field32(8),
        number_of_symbols: field32(12),
        size_of_optional_header: field16(16),
        characteristics: FileCharacteristics(field16(18)),
    })
}

/// Parses the fixed optional header fields. Returns the header and the file
/// offset of the first data directory entry.
fn parse_optional(
    data: &[u8],
    offset: usize,
    declared_size: u16,
) -> Result<(OptionalHeader, usize), PeError> {
    let magic =
        u16_at(data, offset).ok_or_else(|| fatal(offset, PeErrorKind::TruncatedOptionalHeader))?;
    let (format, fixed_len) = match magic {
        0x10b => (PeFormat::Pe32, 96_usize),
        0x20b => (PeFormat::Pe32Plus, 112_usize),
        other => {
            return Err(fatal(
                offset,
                PeErrorKind::UnknownOptionalHeaderMagic(other),
            ));
        }
    };
    if usize::from(declared_size) < fixed_len {
        return Err(fatal(
            offset,
            PeErrorKind::OptionalHeaderTooSmall(declared_size),
        ));
    }
    let h = bytes(data, offset, fixed_len)
        .ok_or_else(|| fatal(offset, PeErrorKind::TruncatedOptionalHeader))?;
    // `h` holds exactly `fixed_len` bytes, so these reads cannot miss; the
    // zero fallbacks only satisfy the type checker.
    let f8 = |at| u8_at(h, at).unwrap_or(0);
    let f16 = |at| u16_at(h, at).unwrap_or(0);
    let f32 = |at| u32_at(h, at).unwrap_or(0);
    let f64 = |at| u64_at(h, at).unwrap_or(0);
    let pe32 = format == PeFormat::Pe32;
    let wide = |at32: usize, at64: usize| {
        if pe32 {
            u64::from(f32(at32))
        } else {
            f64(at64)
        }
    };
    let header = OptionalHeader {
        offset: to_u64(offset),
        format,
        linker_version: (f8(2), f8(3)),
        size_of_code: f32(4),
        size_of_initialized_data: f32(8),
        size_of_uninitialized_data: f32(12),
        entry_point: f32(16),
        base_of_code: f32(20),
        image_base: wide(28, 24),
        section_alignment: f32(32),
        file_alignment: f32(36),
        os_version: (f16(40), f16(42)),
        image_version: (f16(44), f16(46)),
        subsystem_version: (f16(48), f16(50)),
        win32_version_value: f32(52),
        size_of_image: f32(56),
        size_of_headers: f32(60),
        checksum: f32(64),
        checksum_offset: to_u64(offset.saturating_add(64)),
        subsystem: Subsystem::from_raw(f16(68)),
        dll_characteristics: DllCharacteristics(f16(70)),
        size_of_stack_reserve: wide(72, 72),
        size_of_stack_commit: wide(76, 80),
        size_of_heap_reserve: wide(80, 88),
        size_of_heap_commit: wide(84, 96),
        loader_flags: f32(if pe32 { 88 } else { 104 }),
        number_of_rva_and_sizes: f32(if pe32 { 92 } else { 108 }),
    };
    Ok((header, offset.saturating_add(fixed_len)))
}

fn parse_data_directories(
    data: &[u8],
    start: usize,
    opt_end: usize,
    declared: u32,
    warnings: &mut Warnings,
) -> Vec<DataDirectory> {
    let wanted = if declared > 16 {
        warnings.push(start, WarningKind::TooManyDataDirectories(declared));
        DATA_DIRECTORY_COUNT
    } else {
        to_usize(declared).unwrap_or(DATA_DIRECTORY_COUNT)
    };
    let mut dirs = Vec::with_capacity(wanted);
    for (i, kind) in DataDirectoryKind::ALL.iter().take(wanted).enumerate() {
        let Some(at) = i.checked_mul(8).and_then(|o| o.checked_add(start)) else {
            break;
        };
        let in_header = at.checked_add(8).is_some_and(|end| end <= opt_end);
        let (Some(virtual_address), Some(size)) = (u32_at(data, at), u32_at(data, at + 4)) else {
            break;
        };
        if !in_header {
            break;
        }
        dirs.push(DataDirectory {
            kind: *kind,
            virtual_address,
            size,
            entry_offset: to_u64(at),
        });
    }
    if dirs.len() < wanted {
        warnings.push(
            start,
            WarningKind::DataDirectoriesTruncated {
                declared: u32::try_from(wanted).unwrap_or(u32::MAX),
                parsed: u32::try_from(dirs.len()).unwrap_or(u32::MAX),
            },
        );
    }
    dirs
}

fn parse_sections(
    data: &[u8],
    table: usize,
    declared: u16,
    warnings: &mut Warnings,
) -> Vec<Section> {
    if usize::from(declared) > MAX_SECTIONS {
        warnings.push(table, WarningKind::TooManySections(declared));
    }
    // Only allocate for headers that are actually present in the input.
    let available = data.len().saturating_sub(table) / SECTION_HEADER_SIZE;
    let wanted = usize::from(declared).min(MAX_SECTIONS);
    let count = wanted.min(available);
    let mut sections = Vec::with_capacity(count);
    for i in 0..count {
        let Some(at) = i
            .checked_mul(SECTION_HEADER_SIZE)
            .and_then(|o| o.checked_add(table))
        else {
            break;
        };
        let Some(h) = bytes(data, at, SECTION_HEADER_SIZE) else {
            break;
        };
        let mut raw_name = [0_u8; 8];
        if let Some(name) = bytes(h, 0, 8) {
            raw_name.copy_from_slice(name);
        }
        let name_len = raw_name.iter().position(|b| *b == 0).unwrap_or(8);
        let name =
            String::from_utf8_lossy(raw_name.get(..name_len).unwrap_or_default()).into_owned();
        let f32 = |off| u32_at(h, off).unwrap_or(0);
        sections.push(Section {
            header_offset: to_u64(at),
            name,
            raw_name,
            virtual_size: f32(8),
            virtual_address: f32(12),
            size_of_raw_data: f32(16),
            pointer_to_raw_data: f32(20),
            characteristics: SectionCharacteristics(f32(36)),
            entropy: None,
        });
    }
    if sections.len() < wanted {
        warnings.push(
            table,
            WarningKind::SectionTableTruncated {
                declared,
                parsed: u16::try_from(sections.len()).unwrap_or(u16::MAX),
            },
        );
    }
    sections
}

/// The part of a section's raw data that is present in the file, or `None`
/// if there is none. Warns when the declared range runs past the end.
fn section_raw_data<'a>(
    data: &'a [u8],
    file_len: u64,
    section: &Section,
    file_alignment: u32,
    index: u16,
    warnings: &mut Warnings,
) -> Option<&'a [u8]> {
    let (start, size) = section.file_data(file_alignment)?;
    if u64::from(start) + u64::from(size) > file_len {
        warnings.push(
            to_usize(start).unwrap_or(usize::MAX),
            WarningKind::SectionDataOutOfFile { index },
        );
    }
    let start = to_usize(start)?;
    let end = start.saturating_add(to_usize(size)?);
    data.get(start..end.min(data.len()))
        .filter(|raw| !raw.is_empty())
}

/// The part of a section's file data that is actually in the input, as a
/// `(start, end)` file range, or `None` if none of it is. A section that
/// starts past the end of the input contributes nothing; one that runs past
/// the end is cut there.
fn in_file_data(s: &Section, file_alignment: u32, file_len: u64) -> Option<(u64, u64)> {
    let (start, size) = s.file_data(file_alignment)?;
    let start = u64::from(start);
    (start < file_len).then(|| (start, start.saturating_add(u64::from(size)).min(file_len)))
}

fn find_overlay(
    file_len: u64,
    headers_end: usize,
    file_alignment: u32,
    sections: &[Section],
    certificate_table: Option<FileRange>,
) -> Option<FileRange> {
    let sections_end = sections
        .iter()
        .filter_map(|s| in_file_data(s, file_alignment, file_len))
        .map(|(_, end)| end)
        .max()
        .unwrap_or(0)
        .max(to_u64(headers_end));
    let cert_end = certificate_table.map_or(0, |c| c.offset.saturating_add(c.size));
    let start = sections_end.max(cert_end);
    (start < file_len).then(|| FileRange {
        offset: start,
        size: file_len - start,
    })
}

fn version_from_resources(
    data: &[u8],
    summary: &ResourceSummary,
    warnings: &mut Warnings,
) -> Option<VersionInfo> {
    let Some(entry) = &summary.version_resource else {
        if !summary.version_entries.is_empty() {
            warnings.push(
                usize::try_from(summary.offset).unwrap_or(usize::MAX),
                WarningKind::NoStandardVersionResource,
            );
        }
        return None;
    };
    let resource_root = usize::try_from(summary.offset).unwrap_or(usize::MAX);
    let base = entry
        .file_offset
        .and_then(|o| usize::try_from(o).ok())
        .unwrap_or(resource_root);
    let Some(raw) = entry.bytes(data) else {
        warnings.push(base, WarningKind::ResourceOutOfBounds);
        return None;
    };
    match version::parse_version_info(raw) {
        Ok(info) => {
            for issue in &info.issues {
                warnings.push(
                    base.saturating_add(usize::try_from(issue.offset).unwrap_or(usize::MAX)),
                    WarningKind::VersionInfo(issue.clone()),
                );
            }
            Some(info)
        }
        Err(issue) => {
            warnings.push(
                base.saturating_add(usize::try_from(issue.offset).unwrap_or(usize::MAX)),
                WarningKind::VersionInfo(issue),
            );
            None
        }
    }
}

/// The manifest with the lowest standard `RT_MANIFEST` ID present (1, 2 or
/// 3, found by loader-style lookup), and that ID. If it does not parse, no
/// other manifest is used in its place: a decoy at a higher ID must not
/// stand in for the one the OS reads.
fn manifest_from_resources(
    data: &[u8],
    summary: &ResourceSummary,
    warnings: &mut Warnings,
) -> (Option<Manifest>, Option<u16>) {
    let Some(entry) = summary.standard_manifests.first() else {
        return (None, None);
    };
    let id = match entry.name {
        ResourceId::Id(id) => Some(id),
        ResourceId::Name(_) => None,
    };
    let at = entry
        .file_offset
        .and_then(|o| usize::try_from(o).ok())
        .unwrap_or_else(|| usize::try_from(summary.offset).unwrap_or(usize::MAX));
    let Some(raw) = entry.bytes(data) else {
        warnings.push(at, WarningKind::ResourceOutOfBounds);
        return (None, id);
    };
    match manifest::parse_manifest(raw) {
        Ok(m) => (Some(m), id),
        Err(e) => {
            warnings.push(at, WarningKind::Manifest(e));
            (None, id)
        }
    }
}
