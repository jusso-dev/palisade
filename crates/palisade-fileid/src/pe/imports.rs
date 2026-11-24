//! The import and export tables (#45).
//!
//! Both are read the way the OS loader reads them. The import descriptor
//! table is read until its all-zero terminator, whatever the directory size
//! says, and an export is looked up by binary search over the sorted name
//! table, as `GetProcAddress` does. The lists kept here are capped
//! ([`MAX_IMPORT_MODULES`], [`MAX_IMPORTED_FUNCTIONS`], [`MAX_EXPORTS`]).
//! Questions that must not be dodged by padding a table (which modules are
//! imported at all, does an export exist) are answered over the whole
//! table, within [`MAX_IMPORT_DESCRIPTORS`], not over the capped lists.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use super::read::{bytes, to_usize, u16_at, u32_at, u64_at};
use super::{DataDirectory, DataDirectoryKind, Layout, PeFormat, WarningKind, Warnings};

/// At most this many imported modules are listed.
pub const MAX_IMPORT_MODULES: usize = 4096;
/// At most this many imported functions are listed, across all modules.
pub const MAX_IMPORTED_FUNCTIONS: usize = 10_000;
/// At most this many import descriptors are read. Module names past the
/// listed ones still count for [`ImportInfo::imports_module`].
pub const MAX_IMPORT_DESCRIPTORS: usize = 65_536;
/// At most this many exports are listed.
pub const MAX_EXPORTS: usize = 10_000;
/// At most this many export address table slots are scanned for unnamed
/// exports. Export ordinals are 16-bit, so real tables are smaller.
pub const MAX_EXPORT_SLOTS: u32 = 65_536;
/// Module, function and forwarder names longer than this many bytes are
/// not read.
pub const MAX_NAME_LEN: usize = 512;

const DESCRIPTOR_SIZE: usize = 20;
const EXPORT_DIRECTORY_SIZE: usize = 40;

/// One imported function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportedFunction {
    /// Imported by name, with the loader's hint.
    Name {
        /// The function name.
        name: String,
        /// The hint (an index into the exporter's name table).
        hint: u16,
    },
    /// Imported by ordinal.
    Ordinal(u16),
}

/// One imported module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedModule {
    /// The module name as written (`KERNEL32.dll`).
    pub name: String,
    /// The functions imported from it that were listed.
    pub functions: Vec<ImportedFunction>,
    /// How many functions were counted for it. Once the table-wide
    /// [`MAX_IMPORTED_FUNCTIONS`] is reached nothing more is read, so this
    /// is then a lower bound ([`ImportInfo::truncated`]).
    pub function_count: usize,
}

/// The import table.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImportInfo {
    /// The listed modules, in table order.
    pub modules: Vec<ImportedModule>,
    /// Every module name in the table (within [`MAX_IMPORT_DESCRIPTORS`]),
    /// ASCII-lowercased, in table order with duplicates kept once.
    pub all_module_names: Vec<String>,
    /// Imported functions across all listed modules.
    pub function_count: usize,
    /// A limit was reached, or part of the table was unreadable, so the
    /// lists are incomplete.
    pub truncated: bool,
}

impl ImportInfo {
    /// Whether any import descriptor names `module` (ASCII
    /// case-insensitive, as the loader compares module names).
    #[must_use]
    pub fn imports_module(&self, module: &str) -> bool {
        let wanted = module.to_ascii_lowercase();
        self.all_module_names.contains(&wanted)
    }
}

/// Where an export leads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExportTarget {
    /// Code or data in this image, at this RVA.
    Rva(u32),
    /// A forwarder: another module's export, as `MODULE.Function` or
    /// `MODULE.#ordinal`.
    Forwarder(String),
}

/// One exported symbol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Export {
    /// The name, if exported by name.
    pub name: Option<String>,
    /// The ordinal (the export directory's `Base` plus the index).
    pub ordinal: u32,
    /// Where it leads.
    pub target: ExportTarget,
}

/// The well-known exports that mark a module's role.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NotableExports {
    /// `CPlApplet`: a control panel applet.
    pub cpl_applet: bool,
    /// `DllRegisterServer`: a self-registering COM server.
    pub dll_register_server: bool,
    /// `DllGetClassObject`: a COM in-process server.
    pub dll_get_class_object: bool,
    /// `ServiceMain`: a service DLL.
    pub service_main: bool,
}

/// The export table.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExportInfo {
    /// The module name the table gives itself.
    pub dll_name: Option<String>,
    /// `NumberOfFunctions`.
    pub number_of_functions: u32,
    /// `NumberOfNames`.
    pub number_of_names: u32,
    /// The exports listed: named ones in name-table order, then unnamed
    /// ones, at most [`MAX_EXPORTS`].
    pub exports: Vec<Export>,
    /// Which well-known exports exist, found by the loader's binary search
    /// over the whole name table, so padding the table cannot hide them.
    pub notable: NotableExports,
    /// A limit was reached, or part of the table was unreadable.
    pub truncated: bool,
}

impl ExportInfo {
    /// The number of forwarders among the listed exports.
    #[must_use]
    pub fn forwarder_count(&self) -> usize {
        self.exports
            .iter()
            .filter(|e| matches!(e.target, ExportTarget::Forwarder(_)))
            .count()
    }
}

/// A NUL-terminated name at `rva`, at most [`MAX_NAME_LEN`] bytes, read
/// from file-backed data only. `None` if unmapped, unterminated or empty.
fn name_at(data: &[u8], layout: Layout<'_>, rva: u32) -> Option<String> {
    if rva == 0 {
        return None;
    }
    let (offset, available) = layout.backed_extent(rva)?;
    let len = to_usize(available)?.min(MAX_NAME_LEN.saturating_add(1));
    let raw = bytes(data, offset, len)?;
    let end = raw.iter().position(|b| *b == 0)?;
    let name = raw.get(..end)?;
    (!name.is_empty()).then(|| String::from_utf8_lossy(name).into_owned())
}

/// `len` file-backed bytes at `rva`.
fn at_rva<'a>(data: &'a [u8], layout: Layout<'_>, rva: u32, len: usize) -> Option<&'a [u8]> {
    if rva == 0 {
        return None;
    }
    let offset = layout.rva_to_offset(rva, u32::try_from(len).ok()?)?;
    bytes(data, offset, len)
}

pub(super) fn parse_imports(
    data: &[u8],
    layout: Layout<'_>,
    dir: DataDirectory,
    format: PeFormat,
    warnings: &mut Warnings,
) -> Option<ImportInfo> {
    let entry_offset = usize::try_from(dir.entry_offset).unwrap_or(usize::MAX);
    let Some((start, available)) = (dir.virtual_address != 0)
        .then(|| layout.backed_extent(dir.virtual_address))
        .flatten()
    else {
        warnings.push(
            entry_offset,
            WarningKind::DirectoryNotMapped(DataDirectoryKind::Import),
        );
        return None;
    };
    let mut info = ImportInfo::default();
    let mut seen = BTreeSet::new();
    let thunk_size = if format == PeFormat::Pe32Plus { 8 } else { 4 };
    let available = to_usize(available).unwrap_or(0);
    let mut terminated = false;
    for i in 0..MAX_IMPORT_DESCRIPTORS {
        let at = i.saturating_mul(DESCRIPTOR_SIZE);
        if at.saturating_add(DESCRIPTOR_SIZE) > available {
            break;
        }
        let Some(d) = bytes(data, start.saturating_add(at), DESCRIPTOR_SIZE) else {
            break;
        };
        if d.iter().all(|b| *b == 0) {
            terminated = true;
            break;
        }
        let field = |o| u32_at(d, o).unwrap_or(0);
        let Some(name) = name_at(data, layout, field(12)) else {
            warnings.push(start.saturating_add(at), WarningKind::ImportTableMalformed);
            info.truncated = true;
            continue;
        };
        let lower = name.to_ascii_lowercase();
        if seen.insert(lower.clone()) {
            info.all_module_names.push(lower);
        }
        if info.modules.len() >= MAX_IMPORT_MODULES {
            info.truncated = true;
            continue;
        }
        let thunks = match field(0) {
            0 => field(16),
            rva => rva,
        };
        let mut module = ImportedModule {
            name,
            functions: Vec::new(),
            function_count: 0,
        };
        read_thunks(data, layout, thunks, thunk_size, &mut module, &mut info);
        info.modules.push(module);
    }
    if !terminated {
        warnings.push(start, WarningKind::ImportTableTruncated);
        info.truncated = true;
    }
    Some(info)
}

fn read_thunks(
    data: &[u8],
    layout: Layout<'_>,
    rva: u32,
    thunk_size: usize,
    module: &mut ImportedModule,
    info: &mut ImportInfo,
) {
    let Some((start, available)) = (rva != 0).then(|| layout.backed_extent(rva)).flatten() else {
        info.truncated = true;
        return;
    };
    let count = to_usize(available).unwrap_or(0) / thunk_size;
    for i in 0..count {
        if info.function_count >= MAX_IMPORTED_FUNCTIONS {
            info.truncated = true;
            return;
        }
        let at = start.saturating_add(i.saturating_mul(thunk_size));
        let (value, by_ordinal) = if thunk_size == 8 {
            let v = u64_at(data, at).unwrap_or(0);
            (v & 0x7fff_ffff_ffff_ffff, v >> 63 == 1)
        } else {
            let v = u64::from(u32_at(data, at).unwrap_or(0));
            (v & 0x7fff_ffff, v >> 31 == 1)
        };
        if value == 0 && !by_ordinal {
            return;
        }
        module.function_count = module.function_count.saturating_add(1);
        let function = if by_ordinal {
            ImportedFunction::Ordinal(u16::try_from(value & 0xffff).unwrap_or(0))
        } else {
            // An unreadable entry ends the module's list: continuing past
            // it would let a crafted table make every entry cost a read
            // without ever counting towards the cap.
            let Ok(hint_rva) = u32::try_from(value) else {
                info.truncated = true;
                return;
            };
            let hint = at_rva(data, layout, hint_rva, 2)
                .and_then(|h| u16_at(h, 0))
                .unwrap_or(0);
            match name_at(data, layout, hint_rva.saturating_add(2)) {
                Some(name) => ImportedFunction::Name { name, hint },
                None => {
                    info.truncated = true;
                    return;
                }
            }
        };
        module.functions.push(function);
        info.function_count = info.function_count.saturating_add(1);
    }
    // No terminator within the mapped data.
    info.truncated = true;
}

pub(super) fn parse_exports(
    data: &[u8],
    layout: Layout<'_>,
    dir: DataDirectory,
    warnings: &mut Warnings,
) -> Option<ExportInfo> {
    let entry_offset = usize::try_from(dir.entry_offset).unwrap_or(usize::MAX);
    let Some(header) = at_rva(data, layout, dir.virtual_address, EXPORT_DIRECTORY_SIZE) else {
        warnings.push(
            entry_offset,
            WarningKind::DirectoryNotMapped(DataDirectoryKind::Export),
        );
        return None;
    };
    let field = |o| u32_at(header, o).unwrap_or(0);
    let base = field(16);
    let mut info = ExportInfo {
        dll_name: name_at(data, layout, field(12)),
        number_of_functions: field(20),
        number_of_names: field(24),
        ..ExportInfo::default()
    };
    let functions = field(28);
    let names = field(32);
    let ordinals = field(36);
    let dir_start = u64::from(dir.virtual_address);
    let dir_end = dir_start.saturating_add(u64::from(dir.size));
    // One warning per table, however many entries are bad.
    let mut reported = false;
    let mut report = |warnings: &mut Warnings| {
        if !reported {
            reported = true;
            warnings.push(
                layout
                    .rva_to_offset(dir.virtual_address, 0)
                    .unwrap_or(entry_offset),
                WarningKind::ExportTableMalformed,
            );
        }
    };

    let function_at = |index: u32| -> Option<ExportTarget> {
        let at = functions.checked_add(index.checked_mul(4)?)?;
        let rva = u32_at(at_rva(data, layout, at, 4)?, 0)?;
        if (dir_start..dir_end).contains(&u64::from(rva)) {
            Some(ExportTarget::Forwarder(name_at(data, layout, rva)?))
        } else {
            Some(ExportTarget::Rva(rva))
        }
    };
    let name_rva_at = |i: u32| -> Option<u32> {
        u32_at(
            at_rva(data, layout, names.checked_add(i.checked_mul(4)?)?, 4)?,
            0,
        )
    };
    let ordinal_at = |i: u32| -> Option<u16> {
        u16_at(
            at_rva(data, layout, ordinals.checked_add(i.checked_mul(2)?)?, 2)?,
            0,
        )
    };

    // Named exports, in name-table order.
    let slots = info.number_of_functions.min(MAX_EXPORT_SLOTS);
    let mut named = vec![false; to_usize(slots).unwrap_or(0)];
    let listed_names = info
        .number_of_names
        .min(u32::try_from(MAX_EXPORTS).unwrap_or(u32::MAX));
    for i in 0..listed_names {
        let (Some(name), Some(index)) = (
            name_rva_at(i).and_then(|r| name_at(data, layout, r)),
            ordinal_at(i),
        ) else {
            report(warnings);
            info.truncated = true;
            break;
        };
        let Some(target) = function_at(u32::from(index)) else {
            report(warnings);
            info.truncated = true;
            continue;
        };
        if let Some(slot) = named.get_mut(usize::from(index)) {
            *slot = true;
        }
        info.exports.push(Export {
            name: Some(name),
            ordinal: base.wrapping_add(u32::from(index)),
            target,
        });
    }
    if info.number_of_names > listed_names {
        info.truncated = true;
    }
    if info.number_of_functions > slots {
        info.truncated = true;
    }
    // Unnamed exports, by ordinal.
    for index in 0..slots {
        if info.exports.len() >= MAX_EXPORTS {
            info.truncated = true;
            break;
        }
        if to_usize(index)
            .and_then(|i| named.get(i))
            .copied()
            .unwrap_or(false)
        {
            continue;
        }
        match function_at(index) {
            // A zero RVA is an unused slot.
            Some(ExportTarget::Rva(0)) => {}
            Some(target) => info.exports.push(Export {
                name: None,
                ordinal: base.wrapping_add(index),
                target,
            }),
            None => {
                report(warnings);
                info.truncated = true;
                break;
            }
        }
    }

    let find = |wanted: &str| -> bool {
        // The loader's binary search over the whole sorted name table.
        let (mut low, mut high) = (0_u32, info.number_of_names);
        while low < high {
            let mid = low + (high - low) / 2;
            let Some(name) = name_rva_at(mid).and_then(|r| name_at(data, layout, r)) else {
                return false;
            };
            match name.as_bytes().cmp(wanted.as_bytes()) {
                std::cmp::Ordering::Equal => return true,
                std::cmp::Ordering::Less => low = mid + 1,
                std::cmp::Ordering::Greater => high = mid,
            }
        }
        false
    };
    info.notable = NotableExports {
        cpl_applet: find("CPlApplet"),
        dll_register_server: find("DllRegisterServer"),
        dll_get_class_object: find("DllGetClassObject"),
        service_main: find("ServiceMain"),
    };
    Some(info)
}
