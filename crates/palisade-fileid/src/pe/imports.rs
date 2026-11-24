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
/// Module, function and forwarder names are kept up to this many bytes;
/// longer ones are cut (and reported as cut). Comparisons, such as the
/// export lookup, always use the whole name.
pub const MAX_NAME_LEN: usize = 512;
/// At most this many bytes of module names are kept in
/// [`ImportInfo::all_module_names`].
pub const MAX_MODULE_NAME_BYTES: usize = 1024 * 1024;

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
    /// Every module name in the table (within [`MAX_IMPORT_DESCRIPTORS`]
    /// and [`MAX_MODULE_NAME_BYTES`]), ASCII-lowercased, in table order with
    /// duplicates kept once.
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

/// A NUL-terminated name at `rva`, read from file-backed data only, as
/// the loader reads it: the name runs to the first NUL, however long.
/// The text kept is cut to [`MAX_NAME_LEN`] bytes. `None` if the RVA is
/// zero or unmapped, or no NUL is found before the end of its section.
/// An empty name is a valid result.
fn name_at(data: &[u8], layout: Layout<'_>, rva: u32) -> Option<Name> {
    let raw = raw_name(data, layout, rva)?;
    let kept = raw.get(..raw.len().min(MAX_NAME_LEN)).unwrap_or_default();
    Some(Name {
        text: String::from_utf8_lossy(kept).into_owned(),
        cut: raw.len() > MAX_NAME_LEN,
    })
}

/// The bytes of the NUL-terminated string at `rva`, without the NUL.
fn raw_name<'a>(data: &'a [u8], layout: Layout<'_>, rva: u32) -> Option<&'a [u8]> {
    if rva == 0 {
        return None;
    }
    let (offset, available) = layout.backed_extent(rva)?;
    let raw = bytes(data, offset, to_usize(available)?)?;
    let end = raw.iter().position(|b| *b == 0)?;
    raw.get(..end)
}

/// A name read by [`name_at`].
struct Name {
    text: String,
    /// Longer than [`MAX_NAME_LEN`]; [`Self::text`] is its start.
    cut: bool,
}

/// One warning per table, however many entries are bad.
struct Once {
    at: usize,
    kind: WarningKind,
    done: bool,
}

impl Once {
    const fn new(at: usize, kind: WarningKind) -> Self {
        Self {
            at,
            kind,
            done: false,
        }
    }

    fn report(&mut self, warnings: &mut Warnings) {
        if !self.done {
            self.done = true;
            warnings.push(self.at, self.kind.clone());
        }
    }
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
    let mut bad = Once::new(start, WarningKind::ImportTableMalformed);
    let mut seen = BTreeSet::new();
    let mut name_bytes = 0_usize;
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
        let field = |o| u32_at(d, o).unwrap_or(0);
        // The loader stops at a descriptor with no name or no import
        // address table, not only at an all-zero one.
        if field(12) == 0 || field(16) == 0 {
            terminated = true;
            break;
        }
        let Some(name) = name_at(data, layout, field(12)) else {
            bad.report(warnings);
            info.truncated = true;
            continue;
        };
        if name.cut {
            bad.report(warnings);
            info.truncated = true;
        }
        let lower = name.text.to_ascii_lowercase();
        if !seen.contains(&lower) {
            if name_bytes.saturating_add(lower.len()) > MAX_MODULE_NAME_BYTES {
                info.truncated = true;
            } else {
                name_bytes = name_bytes.saturating_add(lower.len());
                seen.insert(lower.clone());
                info.all_module_names.push(lower);
            }
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
            name: name.text,
            functions: Vec::new(),
            function_count: 0,
        };
        if !read_thunks(data, layout, thunks, thunk_size, &mut module, &mut info) {
            bad.report(warnings);
        }
        info.modules.push(module);
    }
    if !terminated {
        warnings.push(start, WarningKind::ImportTableTruncated);
        info.truncated = true;
    }
    Some(info)
}

/// Reads one module's thunk array. Returns `false` when part of it was
/// malformed (as opposed to merely over the cap).
fn read_thunks(
    data: &[u8],
    layout: Layout<'_>,
    rva: u32,
    thunk_size: usize,
    module: &mut ImportedModule,
    info: &mut ImportInfo,
) -> bool {
    let Some((start, available)) = (rva != 0).then(|| layout.backed_extent(rva)).flatten() else {
        info.truncated = true;
        return false;
    };
    let count = to_usize(available).unwrap_or(0) / thunk_size;
    for i in 0..count {
        if info.function_count >= MAX_IMPORTED_FUNCTIONS {
            info.truncated = true;
            return true;
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
            return true;
        }
        let function = if by_ordinal {
            ImportedFunction::Ordinal(u16::try_from(value & 0xffff).unwrap_or(0))
        } else {
            // An unreadable entry ends the module's list: continuing past
            // it would let a crafted table make every entry cost a read
            // without ever counting towards the cap.
            let hint = u32::try_from(value)
                .ok()
                .and_then(|r| Some((r, u16_at(at_rva(data, layout, r, 2)?, 0)?)));
            let name = hint
                .and_then(|(r, _)| r.checked_add(2))
                .and_then(|r| name_at(data, layout, r));
            match (hint, name) {
                (Some((_, hint)), Some(name)) => {
                    if name.cut {
                        info.truncated = true;
                    }
                    ImportedFunction::Name {
                        name: name.text,
                        hint,
                    }
                }
                _ => {
                    info.truncated = true;
                    return false;
                }
            }
        };
        module.functions.push(function);
        module.function_count = module.function_count.saturating_add(1);
        info.function_count = info.function_count.saturating_add(1);
    }
    // No terminator within the mapped data.
    info.truncated = true;
    false
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
        dll_name: name_at(data, layout, field(12)).map(|n| n.text),
        number_of_functions: field(20),
        number_of_names: field(24),
        ..ExportInfo::default()
    };
    let functions = field(28);
    let names = field(32);
    let ordinals = field(36);
    let dir_start = u64::from(dir.virtual_address);
    let dir_end = dir_start.saturating_add(u64::from(dir.size));
    let mut bad = Once::new(
        layout
            .rva_to_offset(dir.virtual_address, 0)
            .unwrap_or(entry_offset),
        WarningKind::ExportTableMalformed,
    );
    let number_of_functions = info.number_of_functions;

    // Like the loader, an index past `NumberOfFunctions` is not an export.
    let function_at = |index: u32| -> Option<ExportTarget> {
        if index >= number_of_functions {
            return None;
        }
        let at = functions.checked_add(index.checked_mul(4)?)?;
        let rva = u32_at(at_rva(data, layout, at, 4)?, 0)?;
        if (dir_start..dir_end).contains(&u64::from(rva)) {
            Some(ExportTarget::Forwarder(name_at(data, layout, rva)?.text))
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
    // Not more slots than the export address table has file-backed bytes for.
    let backed_slots = (functions != 0)
        .then(|| layout.backed_extent(functions))
        .flatten()
        .map_or(0, |(_, n)| n / 4);
    let slots = info
        .number_of_functions
        .min(MAX_EXPORT_SLOTS)
        .min(backed_slots);
    let mut named = vec![false; to_usize(slots).unwrap_or(0)];
    let listed_names = info
        .number_of_names
        .min(u32::try_from(MAX_EXPORTS).unwrap_or(u32::MAX));
    for i in 0..listed_names {
        // A bad entry is skipped, not the end of the listing: one crafted
        // name must not hide the rest.
        let (Some(name), Some(index)) = (
            name_rva_at(i).and_then(|r| name_at(data, layout, r)),
            ordinal_at(i),
        ) else {
            bad.report(warnings);
            info.truncated = true;
            continue;
        };
        if name.cut {
            info.truncated = true;
        }
        let Some(target) = function_at(u32::from(index)) else {
            bad.report(warnings);
            info.truncated = true;
            continue;
        };
        if let Some(slot) = named.get_mut(usize::from(index)) {
            *slot = true;
        }
        info.exports.push(Export {
            name: Some(name.text),
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
                bad.report(warnings);
                info.truncated = true;
                break;
            }
        }
    }

    let find = |wanted: &str| -> bool {
        // The loader's binary search over the whole name table: inclusive
        // bounds and midpoint `(low + high) / 2`, comparing whole
        // NUL-terminated names byte by byte (`strcmp`). The name found must
        // also map to a real export.
        let Some(mut high) = info.number_of_names.checked_sub(1) else {
            return false;
        };
        let mut low = 0_u32;
        while low <= high {
            let mid = low + (high - low) / 2;
            let Some(name) = name_rva_at(mid).and_then(|r| raw_name(data, layout, r)) else {
                return false;
            };
            match name.cmp(wanted.as_bytes()) {
                std::cmp::Ordering::Equal => {
                    return ordinal_at(mid).is_some_and(|i| function_at(u32::from(i)).is_some());
                }
                std::cmp::Ordering::Less => low = mid + 1,
                std::cmp::Ordering::Greater => match mid.checked_sub(1) {
                    Some(h) => high = h,
                    None => return false,
                },
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
