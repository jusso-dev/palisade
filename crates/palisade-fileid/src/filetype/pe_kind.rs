//! `MZ` files: PE sub-classification, and the older NE, LE, LX and DOS
//! formats.
//!
//! The PE headers are parsed by [`crate::pe::parse_prefix`] (#45), over only
//! the header bytes: the DOS header up to the end of the section table. RVAs
//! are then mapped with the same loader layout the parser uses, against the
//! real file length, and the few directories the sub-kind needs (imports,
//! exports, the resource root, the CLR header and the load configuration)
//! are read with small, bounded targeted reads.

#![forbid(unsafe_code)]

use std::io::{Read, Seek};

use super::name::NameInfo;
use super::source::Source;
use super::{
    Classification, Confidence, DotNetKind, FileKind, HybridKind, MAX_EXPORT_NAMES,
    MAX_IMPORT_DESCRIPTORS, ParseError, PeDetails, PeSubKind,
};
use crate::pe::read::{bytes, u16_at, u32_at, u64_at};
use crate::pe::{
    self, DataDirectoryKind, DllCharacteristics, Layout, Machine, PeErrorKind, PeFormat, PeInfo,
    SectionCharacteristics, Subsystem,
};

/// A DOS `MZ` header has its fixed fields in the first 28 bytes.
const DOS_HEADER_MIN: usize = 28;
/// Where `e_cparhdr`, the header size in 16-byte paragraphs, is.
const DOS_HEADER_PARAGRAPHS_AT: usize = 8;
/// Where `e_lfanew` is.
const E_LFANEW_AT: usize = 0x3c;
const COFF_LEN: u64 = 20;
const SECTION_HEADER_LEN: u64 = 40;
const IMPORT_DESCRIPTOR_LEN: usize = 20;
/// Bytes read for an imported module name. A longer name (no NUL in this
/// many bytes) is not judged, and the result is marked incomplete.
const MODULE_NAME_LEN: usize = 256;
/// Bytes read for an export name: enough for `DllRegisterServer\0`. A
/// longer name matches neither name looked for.
const EXPORT_NAME_LEN: usize = 18;
/// At most this many named resource types are examined at the root.
const MAX_NAMED_RESOURCE_TYPES: usize = 256;
/// `"TYPELIB"` as a resource directory string: length, then UTF-16LE.
const TYPELIB_LEN: usize = 7;
/// Bytes of the load configuration read: past the hybrid metadata pointer
/// in both layouts.
const LOAD_CONFIG_LEN: usize = 0xd0;
/// The hybrid metadata pointer, in the 32- and 64-bit load configuration.
const HYBRID_POINTER_32: usize = 0x7c;
const HYBRID_POINTER_64: usize = 0xc8;
/// `COMIMAGE_FLAGS_ILONLY`.
const IL_ONLY: u32 = 1;

/// Classifies a file that starts with `MZ`.
pub(super) fn classify<R: Read + Seek + ?Sized>(
    src: &mut Source<'_, R>,
    name: &NameInfo,
    out: &mut Classification,
) {
    if src.head().len() < DOS_HEADER_MIN {
        // Too short for a DOS header: not a program. Leave it to the text
        // and unknown paths, as if the magic were absent.
        super::text::classify(src, name, out);
        return;
    }
    out.content_kind = FileKind::Mz16;
    out.confidence = Confidence::High;
    let head = src.head();
    let paragraphs = u16_at(head, DOS_HEADER_PARAGRAPHS_AT);
    let e_lfanew = u32_at(head, E_LFANEW_AT);
    let signature = match e_lfanew.map(|at| src.read_at(u64::from(at), 4)) {
        Some(Ok(sig)) => sig,
        Some(Err(e)) => {
            out.parse_error = Some(e.into());
            return;
        }
        // Too short for `e_lfanew`: only a DOS program is possible.
        None => Vec::new(),
    };
    match (signature.as_slice(), e_lfanew) {
        ([b'P', b'E', 0, 0], Some(e_lfanew)) => classify_pe(src, e_lfanew, name, out),
        ([b'N', b'E', ..], _) => out.content_kind = FileKind::Ne16,
        ([b'L', b'E', ..], _) => out.content_kind = FileKind::Le,
        ([b'L', b'X', ..], _) => out.content_kind = FileKind::Lx,
        // A plain DOS program: `e_lfanew` is not meaningful. The header
        // must fit in the file, as DOS requires, so text that happens to
        // start with `MZ` is not taken for a program.
        _ => {
            if paragraphs.map_or(0, u64::from) * 16 > src.len() {
                out.content_kind = FileKind::Unknown;
                out.confidence = Confidence::Low;
                super::text::classify(src, name, out);
            }
        }
    }
}

/// Parses the PE headers and sets the sub-kind. On failure the file stays
/// [`FileKind::Mz16`], with the reason.
fn classify_pe<R: Read + Seek + ?Sized>(
    src: &mut Source<'_, R>,
    e_lfanew: u32,
    name: &NameInfo,
    out: &mut Classification,
) {
    if e_lfanew > pe::MAX_E_LFANEW {
        out.parse_error = Some(ParseError::Pe(PeErrorKind::LfanewOutOfRange(e_lfanew)));
        return;
    }
    let info = match parse_headers(src, e_lfanew) {
        Ok(info) => info,
        Err(e) => {
            out.parse_error = Some(e);
            return;
        }
    };
    let layout = Layout {
        sections: &info.sections,
        size_of_headers: info.optional.size_of_headers,
        section_alignment: info.optional.section_alignment,
        file_alignment: info.optional.file_alignment,
        file_len: usize::try_from(src.len()).unwrap_or(usize::MAX),
    };
    let mut probe = Probe {
        src,
        layout,
        incomplete: false,
    };
    let details = probe.details(&info, name, out);
    out.content_kind = FileKind::Pe;
    out.confidence = Confidence::High;
    out.pe = Some(details);
}

/// Reads the bytes from the start of the file to the end of the section
/// table, and parses them with [`pe::parse_prefix`] against the real file
/// length. Section data, the certificate table and anything else past the
/// headers is not read, and the parser's own directory work (imports,
/// exports, resources, the driver verdict) is skipped for a prefix rather
/// than run over bytes that are not there.
fn parse_headers<R: Read + Seek + ?Sized>(
    src: &mut Source<'_, R>,
    e_lfanew: u32,
) -> Result<PeInfo, ParseError> {
    let coff_at = u64::from(e_lfanew) + 4;
    let coff = src.read_at(coff_at, 20)?;
    let sections = u16_at(&coff, 2).map_or(0, u64::from);
    let optional_len = u16_at(&coff, 16).map_or(0, u64::from);
    let sections = sections.min(u64::try_from(pe::MAX_SECTIONS).unwrap_or(u64::MAX));
    let end = coff_at + COFF_LEN + optional_len + sections * SECTION_HEADER_LEN;
    // At most 1 MiB + 4 + 20 + 65,535 + 40,960 bytes.
    let len = usize::try_from(end).map_err(|_| ParseError::ReadBudgetExceeded)?;
    let headers = src.read_at(0, len)?;
    pe::parse_prefix(&headers, src.len()).map_err(|e| ParseError::Pe(e.kind))
}

/// Bounded reads of the PE directories, through the loader's RVA mapping.
struct Probe<'s, 'r, 'l, R: ?Sized> {
    src: &'s mut Source<'r, R>,
    layout: Layout<'l>,
    incomplete: bool,
}

impl<R: Read + Seek + ?Sized> Probe<'_, '_, '_, R> {
    fn details(&mut self, info: &PeInfo, name: &NameInfo, out: &mut Classification) -> PeDetails {
        let machine = info.coff.machine;
        let subsystem = info.optional.subsystem;
        let is_dll = info.coff.characteristics.is_dll();
        let imports = self.imports(info);
        let (cpl_applet, dll_register_server) = self.exports(info);
        let has_type_library = self.has_type_library(info);
        let dot_net = self.dot_net(info);
        let hybrid = self.hybrid(info);

        let has_code = info.sections.iter().any(|s| {
            s.characteristics.contains(SectionCharacteristics::CNT_CODE)
                || s.characteristics
                    .contains(SectionCharacteristics::MEM_EXECUTE)
        });
        // The other kernel signals of `pe::PeInfo::driver` (#45), so a
        // native image the parser calls a kernel driver is `Driver` here
        // too, even when it also imports `ntdll.dll`.
        let native_kernel_signal = info
            .sections
            .iter()
            .any(|s| s.raw_name.starts_with(b"INIT\0"))
            || info.coff.characteristics.is_system();
        let driver = info
            .optional
            .dll_characteristics
            .contains(DllCharacteristics::WDM_DRIVER)
            || imports.kernel
            || (subsystem == Subsystem::Native && (!imports.ntdll || native_kernel_signal));
        let sub_kind = if subsystem.is_efi() {
            PeSubKind::Efi
        } else if driver {
            PeSubKind::Driver
        } else if is_dll && cpl_applet {
            PeSubKind::Cpl
        } else if is_dll && dll_register_server && has_type_library {
            PeSubKind::Ocx
        } else if info.optional.entry_point == 0 && !has_code {
            PeSubKind::ResourceOnly
        } else if is_dll {
            PeSubKind::Dll
        } else if name.is_ext(&["scr"]) {
            out.extension_assisted = true;
            PeSubKind::Scr
        } else {
            PeSubKind::Exe
        };
        PeDetails {
            sub_kind,
            machine,
            subsystem,
            is_dll,
            dot_net,
            hybrid,
            imports_kernel: imports.kernel,
            exports_cpl_applet: cpl_applet,
            exports_dll_register_server: dll_register_server,
            has_type_library,
            incomplete: self.incomplete,
        }
    }

    /// Up to `len` bytes at `rva`, cut to the file-backed part of its
    /// section. `None`, and the result marked incomplete, if the RVA is
    /// zero (a null pointer, which would otherwise map to the DOS header),
    /// does not map, or the read fails.
    fn read_rva(&mut self, rva: u32, len: usize) -> Option<Vec<u8>> {
        let got = (rva != 0)
            .then(|| self.layout.backed_extent(rva))
            .flatten()
            .and_then(|(offset, available)| {
                let len = usize::try_from(available).map_or(len, |a| a.min(len));
                let offset = u64::try_from(offset).ok()?;
                self.src.read_at(offset, len).ok()
            });
        if got.is_none() {
            self.incomplete = true;
        }
        got
    }

    /// Exactly `len` bytes at `rva`, for a fixed-size structure. A
    /// structure cut short by the end of its section or of the file is
    /// `None`, and the result is marked incomplete.
    fn read_exact(&mut self, rva: u32, len: usize) -> Option<Vec<u8>> {
        let got = self.read_rva(rva, len).filter(|b| b.len() == len);
        if got.is_none() {
            self.incomplete = true;
        }
        got
    }

    /// Reads a NUL-terminated ASCII name at `rva`. `None` if there is no
    /// NUL within `len` bytes. When the name is cut off by the end of its
    /// section or of the file, rather than being longer than `len`, the
    /// result is also marked incomplete.
    fn read_name(&mut self, rva: u32, len: usize) -> Option<Vec<u8>> {
        let mut raw = self.read_rva(rva, len)?;
        let Some(nul) = raw.iter().position(|b| *b == 0) else {
            if raw.len() < len {
                self.incomplete = true;
            }
            return None;
        };
        raw.truncate(nul);
        Some(raw)
    }

    /// The RVA of a data directory. A directory at RVA 0 is absent
    /// whatever its size, as the loader treats it.
    fn directory(info: &PeInfo, kind: DataDirectoryKind) -> Option<u32> {
        info.data_directory(kind)
            .map(|d| d.virtual_address)
            .filter(|rva| *rva != 0)
    }

    /// Which kinds of module the image imports from.
    fn imports(&mut self, info: &PeInfo) -> Imports {
        let mut found = Imports::default();
        let Some(rva) = Self::directory(info, DataDirectoryKind::Import) else {
            return found;
        };
        // The loader reads descriptors until an all-zero one, whatever the
        // directory size says.
        let Some(table) = self.read_rva(rva, MAX_IMPORT_DESCRIPTORS * IMPORT_DESCRIPTOR_LEN) else {
            return found;
        };
        let mut terminated = false;
        for descriptor in table.chunks_exact(IMPORT_DESCRIPTOR_LEN) {
            let name_rva = u32_at(descriptor, 12).unwrap_or(0);
            let thunks = u32_at(descriptor, 16).unwrap_or(0);
            if name_rva == 0 && thunks == 0 {
                terminated = true;
                break;
            }
            let Some(module) = self.read_name(name_rva, MODULE_NAME_LEN) else {
                // A missing, unmapped or unterminated name is not judged.
                self.incomplete = true;
                continue;
            };
            let module = module.to_ascii_lowercase();
            found.kernel |= is_kernel_module(&module);
            found.ntdll |= module == b"ntdll.dll";
        }
        if !terminated {
            self.incomplete = true;
        }
        found
    }

    /// Whether the export table names `CPlApplet` and `DllRegisterServer`.
    fn exports(&mut self, info: &PeInfo) -> (bool, bool) {
        let Some(rva) = Self::directory(info, DataDirectoryKind::Export) else {
            return (false, false);
        };
        let Some(dir) = self.read_exact(rva, 40) else {
            return (false, false);
        };
        let count = u32_at(&dir, 24).map_or(0, |n| usize::try_from(n).unwrap_or(usize::MAX));
        let names_rva = u32_at(&dir, 32).unwrap_or(0);
        if count > MAX_EXPORT_NAMES {
            self.incomplete = true;
        }
        let count = count.min(MAX_EXPORT_NAMES);
        if count == 0 {
            return (false, false);
        }
        let Some(names) = self.read_exact(names_rva, count * 4) else {
            return (false, false);
        };
        let (mut cpl, mut register) = (false, false);
        for entry in names.chunks_exact(4) {
            // A null or unmapped name marks the result incomplete (in
            // `read_rva`). A name with no NUL in `EXPORT_NAME_LEN` bytes is
            // longer than either name looked for, so it is skipped.
            let name_rva = u32_at(entry, 0).unwrap_or(0);
            let Some(name) = self.read_name(name_rva, EXPORT_NAME_LEN) else {
                continue;
            };
            cpl |= name == b"CPlApplet";
            register |= name == b"DllRegisterServer";
            if cpl && register {
                break;
            }
        }
        (cpl, register)
    }

    /// Whether the resource root has a type named `TYPELIB`.
    fn has_type_library(&mut self, info: &PeInfo) -> bool {
        let Some(root) = Self::directory(info, DataDirectoryKind::Resource) else {
            return false;
        };
        let Some(header) = self.read_exact(root, 16) else {
            return false;
        };
        let named = u16_at(&header, 12).map_or(0, usize::from);
        if named > MAX_NAMED_RESOURCE_TYPES {
            self.incomplete = true;
        }
        let named = named.min(MAX_NAMED_RESOURCE_TYPES);
        if named == 0 {
            return false;
        }
        let Some(entries) = root
            .checked_add(16)
            .and_then(|at| self.read_exact(at, named * 8))
        else {
            self.incomplete = true;
            return false;
        };
        for entry in entries.chunks_exact(8) {
            let Some(field) = u32_at(entry, 0) else {
                continue;
            };
            if field & 0x8000_0000 == 0 {
                continue;
            }
            let Some(at) = root.checked_add(field & 0x7fff_ffff) else {
                self.incomplete = true;
                continue;
            };
            // The length first: a name of another length is not
            // `TYPELIB`, and may be shorter than it.
            let Some(length) = self.read_exact(at, 2) else {
                continue;
            };
            if u16_at(&length, 0).map(usize::from) != Some(TYPELIB_LEN) {
                continue;
            }
            let Some(string) = self.read_exact(at, 2 + 2 * TYPELIB_LEN) else {
                continue;
            };
            if is_typelib(&string) {
                return true;
            }
        }
        false
    }

    /// The CLR header flags, if there is a CLR header.
    fn dot_net(&mut self, info: &PeInfo) -> Option<DotNetKind> {
        let rva = Self::directory(info, DataDirectoryKind::ClrRuntime)?;
        let flags = self.read_exact(rva, 0x14).and_then(|h| u32_at(&h, 0x10));
        Some(match flags {
            Some(f) if f & IL_ONLY != 0 => DotNetKind::IlOnly,
            Some(_) => DotNetKind::Mixed,
            None => DotNetKind::Unknown,
        })
    }

    /// The hybrid layout, from the machine field and the load
    /// configuration's hybrid metadata pointer.
    fn hybrid(&mut self, info: &PeInfo) -> Option<HybridKind> {
        let machine = info.coff.machine;
        match machine {
            Machine::Arm64X => return Some(HybridKind::Arm64X),
            Machine::Arm64Ec => return Some(HybridKind::Arm64Ec),
            Machine::ChpeX86 => return Some(HybridKind::Chpe),
            _ => {}
        }
        let rva = Self::directory(info, DataDirectoryKind::LoadConfig)?;
        let config = self.read_rva(rva, LOAD_CONFIG_LEN)?;
        // The structure's own size field says which fields are present.
        let Some(size) = u32_at(&config, 0) else {
            self.incomplete = true;
            return None;
        };
        let size = usize::try_from(size).unwrap_or(usize::MAX);
        let (at, width) = match info.optional.format {
            PeFormat::Pe32Plus => (HYBRID_POINTER_64, 8),
            _ => (HYBRID_POINTER_32, 4),
        };
        if size < at + width {
            return None;
        }
        let pointer = if width == 8 {
            u64_at(&config, at)
        } else {
            u32_at(&config, at).map(u64::from)
        };
        let Some(pointer) = pointer else {
            // The size says the field is there, but the data ends first.
            self.incomplete = true;
            return None;
        };
        if pointer == 0 {
            return None;
        }
        match machine {
            Machine::Arm64 => Some(HybridKind::Arm64X),
            Machine::Amd64 => Some(HybridKind::Arm64Ec),
            Machine::I386 => Some(HybridKind::Chpe),
            _ => None,
        }
    }
}

/// Imported module kinds.
#[derive(Default)]
struct Imports {
    /// The kernel image, the hardware abstraction layer or a `.sys` module.
    kernel: bool,
    /// `ntdll.dll`, which native user-mode programs import.
    ntdll: bool,
}

/// Whether a lowercased module name is the kernel image, the hardware
/// abstraction layer or another kernel-mode module.
fn is_kernel_module(name: &[u8]) -> bool {
    const KERNEL: [&[u8]; 5] = [
        b"ntoskrnl.exe",
        b"ntkrnlpa.exe",
        b"ntkrnlmp.exe",
        b"ntkrpamp.exe",
        b"hal.dll",
    ];
    KERNEL.contains(&name) || (name.len() > 4 && name.ends_with(b".sys"))
}

/// Whether a resource directory string is `TYPELIB`, compared
/// case-insensitively as resource names are.
fn is_typelib(string: &[u8]) -> bool {
    if u16_at(string, 0).map(usize::from) != Some(TYPELIB_LEN) {
        return false;
    }
    let Some(units) = bytes(string, 2, 2 * TYPELIB_LEN) else {
        return false;
    };
    units.chunks_exact(2).zip(b"TYPELIB").all(|(unit, want)| {
        u16_at(unit, 0) == Some(u16::from(*want))
            || u16_at(unit, 0) == Some(u16::from(want.to_ascii_lowercase()))
    })
}

#[cfg(test)]
#[allow(clippy::cast_possible_truncation)]
mod tests {
    use super::*;

    #[test]
    fn kernel_modules() {
        // A long user-mode name is not cut to look like a `.sys`.
        assert!(!is_kernel_module(b"very-long-name-something.sys.dll"));
        assert!(is_kernel_module(b"ntoskrnl.exe"));
        assert!(is_kernel_module(b"hal.dll"));
        assert!(is_kernel_module(b"wdf01000.sys"));
        assert!(!is_kernel_module(b".sys"));
        assert!(!is_kernel_module(b"kernel32.dll"));
    }

    #[test]
    fn typelib_names() {
        let encode = |s: &str| {
            let mut out = (s.len() as u16).to_le_bytes().to_vec();
            out.extend(s.encode_utf16().flat_map(u16::to_le_bytes));
            out
        };
        assert!(is_typelib(&encode("TYPELIB")));
        assert!(is_typelib(&encode("TypeLib")));
        assert!(!is_typelib(&encode("TYPELIX")));
        assert!(!is_typelib(&encode("TYPELIBS")));
        assert!(!is_typelib(&encode("TYPELIB")[..10]));
    }
}
