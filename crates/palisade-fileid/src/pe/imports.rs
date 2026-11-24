//! The import and export tables (#45).
//!
//! Both are read the way the OS loader reads them. The import descriptor
//! table ends at the first descriptor with no name or no import address
//! table, whatever the directory size says, and an export is looked up by
//! binary search over the name table, as `GetProcAddress` does. Tables and
//! names are read from mapped memory: they may run on into the next
//! section when the two are adjacent, a section's zero-filled tail past
//! its raw data reads as zeros, and unmapped memory, the end of a
//! truncated file, or a read spread over more than [`MAX_READ_EXTENTS`]
//! extents ends the read as unreadable. No name read looks at more
//! than a name's cap, so the work stays linear in the number of entries.
//! The lists kept here are capped
//! ([`MAX_IMPORT_MODULES`], [`MAX_IMPORTED_FUNCTIONS`], [`MAX_EXPORTS`]).
//! Questions that must not be dodged by padding a table (which modules are
//! imported at all, does an export exist) are answered over the whole
//! table, within [`MAX_IMPORT_DESCRIPTORS`], not over the capped lists.
//!
//! Whenever a read is ambiguous, cut or unreadable, the result is marked
//! (`truncated`, and a warning for a malformed table) rather than read as
//! an absence, so it never makes a file look more benign than it is.

#![forbid(unsafe_code)]

use std::borrow::Cow;
use std::collections::BTreeSet;

use super::read::{bytes, to_usize, u16_at, u32_at};
use super::{DataDirectory, DataDirectoryKind, Extent, Layout, PeFormat, WarningKind, Warnings};

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
/// At most this many ordinal table entries are scanned to learn which
/// export slots have a name. With more names than this, which slots are
/// unnamed is unknown, so none is listed as unnamed and the result is
/// [`ExportInfo::truncated`].
pub const MAX_ORDINAL_SCAN: u32 = 131_072;
/// Module, function and forwarder names are kept up to this many bytes;
/// longer ones are cut (and reported as cut). Comparisons, such as the
/// export lookup, always use the whole name.
pub const MAX_NAME_LEN: usize = 512;
/// At most this many bytes of module names are kept in
/// [`ImportInfo::all_module_names`]. Kernel modules are always recorded,
/// in [`ImportInfo::kernel_modules`], however many names come first.
pub const MAX_MODULE_NAME_BYTES: usize = 1024 * 1024;

/// A single read of a name, descriptor or thunk crosses at most this many
/// mapped extents (runs of file-backed bytes or zero fill), so each read
/// costs at most this many section lookups. Real images need two (into a
/// section's zero fill, or into the next section). A read that needs more
/// is unreadable, and is reported as such, never taken as complete.
pub const MAX_READ_EXTENTS: usize = 4;

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
    /// The name was longer than [`MAX_NAME_LEN`], so [`Self::name`] is only
    /// its start. A cut name never matches in [`ImportInfo::imports_module`].
    pub name_cut: bool,
    /// The name is not valid UTF-8, so [`Self::name`] is a lossy rendering
    /// for display (with U+FFFD in place of bad bytes). Which module the
    /// loader resolves it to depends on the system code page, so a lossy
    /// name never matches in [`ImportInfo::imports_module`] and sets
    /// [`ImportInfo::truncated`].
    pub name_lossy: bool,
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
    /// Every complete module name in the table (within
    /// [`MAX_IMPORT_DESCRIPTORS`] and [`MAX_MODULE_NAME_BYTES`]),
    /// ASCII-lowercased, in table order with duplicates kept once. A name cut
    /// at [`MAX_NAME_LEN`], or not valid UTF-8, is not kept. Past either
    /// limit [`Self::truncated`] is set.
    pub all_module_names: Vec<String>,
    /// The [`super::KERNEL_MODULES`] imported anywhere in the table (within
    /// [`MAX_IMPORT_DESCRIPTORS`]), lowercase, in that list's order. This is
    /// never cut short by the caps, so padding a table cannot hide a kernel
    /// import.
    pub kernel_modules: Vec<&'static str>,
    /// Imported functions across all listed modules.
    pub function_count: usize,
    /// A limit was reached, or part of the table was unreadable, so the
    /// lists are incomplete.
    pub truncated: bool,
}

impl ImportInfo {
    /// Whether an import descriptor names `module` (ASCII case-insensitive,
    /// as the loader compares module names), matching whole names only.
    /// A kernel module is found anywhere in the table. Any other module is
    /// found among the listed modules and the names kept in
    /// [`Self::all_module_names`], so `false` for one is reliable only when
    /// [`Self::truncated`] is not set: past [`MAX_IMPORT_DESCRIPTORS`], the
    /// [`MAX_MODULE_NAME_BYTES`] budget, for a name cut at
    /// [`MAX_NAME_LEN`], for a name that is not valid UTF-8, or for a table
    /// that could not be read to its end, a module can be imported and
    /// still not be found.
    #[must_use]
    pub fn imports_module(&self, module: &str) -> bool {
        let wanted = module.to_ascii_lowercase();
        self.kernel_modules.contains(&wanted.as_str())
            || self.all_module_names.contains(&wanted)
            || self
                .modules
                .iter()
                .any(|m| !m.name_cut && !m.name_lossy && m.name.eq_ignore_ascii_case(&wanted))
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
    /// The ordinal (the export directory's `Base` plus the index). An
    /// export whose ordinal does not fit in 32 bits is not listed, and the
    /// table is malformed.
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
    /// If the search meets a name or entry it cannot read, the answer for
    /// that export is unknown: it reads `false`, but [`Self::truncated`] is
    /// set and the table is reported malformed, so `false` is reliable
    /// only when [`Self::truncated`] is not set.
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

/// A NUL-terminated name at `rva`, as the loader reads it. The text kept is
/// at most [`MAX_NAME_LEN`] bytes; a longer name is marked cut, and no more
/// of it is read. `None` if the RVA is zero or unmapped, or the name runs
/// into unmapped memory or the end of the file. An empty name is valid.
fn name_at(data: &[u8], layout: Layout<'_>, rva: u32) -> Option<Name> {
    let (raw, terminated) = c_string(data, layout, rva, MAX_NAME_LEN)?;
    let (text, lossy) = match String::from_utf8_lossy(&raw) {
        Cow::Borrowed(text) => (text.to_owned(), false),
        Cow::Owned(text) => (text, true),
    };
    Some(Name {
        text,
        cut: !terminated,
        lossy,
    })
}

/// Up to `max` bytes of the NUL-terminated string at `rva`, and whether its
/// NUL was found within them. At most `max + 1` bytes are looked at. The
/// string is read from mapped memory: past the end of one section's
/// file-backed bytes it goes on into the next section if that is mapped
/// right after, and a section's zero-filled tail (mapped, but past its
/// declared raw data) reads as NUL, as it does in memory, including at the
/// start (an empty string). `None` if the RVA is zero or unmapped, or the
/// string runs into unmapped memory, or into the end of the input inside
/// the declared raw data (a truncated file), before `max` bytes or a NUL.
fn c_string<'a>(
    data: &'a [u8],
    layout: Layout<'_>,
    rva: u32,
    max: usize,
) -> Option<(Cow<'a, [u8]>, bool)> {
    if rva == 0 {
        return None;
    }
    let limit = max.saturating_add(1);
    let mut out: Cow<'a, [u8]> = Cow::Borrowed(&[]);
    let mut at = rva;
    // Each pass reads at least one byte, and at most `limit` in all, over
    // at most `MAX_READ_EXTENTS` extents.
    for _ in 0..MAX_READ_EXTENTS {
        let (offset, available) = match layout.extent(at) {
            Extent::Backed(offset, available) => (offset, available),
            Extent::Zero(_) => return Some((out, true)),
            Extent::Unmapped => return None,
        };
        let len = to_usize(available)?.min(limit.saturating_sub(out.len()));
        let raw = bytes(data, offset, len)?;
        let end = raw.iter().position(|b| *b == 0);
        let piece = raw.get(..end.unwrap_or(raw.len()))?;
        if out.is_empty() {
            out = Cow::Borrowed(piece);
        } else {
            out.to_mut().extend_from_slice(piece);
        }
        if end.is_some() {
            return Some((out, true));
        }
        if out.len() > max {
            match &mut out {
                Cow::Borrowed(b) => *b = b.get(..max)?,
                Cow::Owned(v) => v.truncate(max),
            }
            return Some((out, false));
        }
        if len == 0 {
            return None;
        }
        at = at.checked_add(u32::try_from(len).ok()?)?;
    }
    // Spread over more extents than a real image uses: unreadable.
    None
}

/// A name read by [`name_at`].
struct Name {
    text: String,
    /// Longer than [`MAX_NAME_LEN`]; [`Self::text`] is its start.
    cut: bool,
    /// Not valid UTF-8; [`Self::text`] is a lossy rendering.
    lossy: bool,
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

/// `N` bytes of mapped memory at `rva`, as the loader lays it out:
/// file-backed bytes, and zeros where they are in a section's zero-filled
/// tail. `None` if any byte is unmapped, or past the end of a truncated
/// input inside the declared raw data (which is never taken for zero fill),
/// or if the bytes are spread over more than [`MAX_READ_EXTENTS`] extents.
fn mapped<const N: usize>(data: &[u8], layout: Layout<'_>, rva: u32) -> Option<[u8; N]> {
    let mut out = [0_u8; N];
    let mut done = 0;
    for _ in 0..MAX_READ_EXTENTS {
        if done >= N {
            break;
        }
        let at = rva.checked_add(u32::try_from(done).ok()?)?;
        match layout.extent(at) {
            Extent::Backed(offset, available) => {
                let n = to_usize(available)?.min(N - done);
                out.get_mut(done..done + n)?
                    .copy_from_slice(bytes(data, offset, n)?);
                done += n;
            }
            // `out` is already zero there.
            Extent::Zero(len) => done += to_usize(len)?.min(N - done),
            Extent::Unmapped => return None,
        }
    }
    (done >= N).then_some(out)
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
    let Some((start, _)) = (dir.virtual_address != 0)
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
    let mut kernel = [false; super::KERNEL_MODULES.len()];
    let thunk_size = if format == PeFormat::Pe32Plus { 8 } else { 4 };
    let mut terminated = false;
    for i in 0..MAX_IMPORT_DESCRIPTORS {
        // The table is read from mapped memory, as the loader reads it: it
        // may go on into an adjacent section, and a section's zero-filled
        // tail reads as zeros, so a terminator there ends the table. An
        // unmapped descriptor, or the end of a truncated input, ends the
        // read without a terminator.
        let d = u32::try_from(i.saturating_mul(DESCRIPTOR_SIZE))
            .ok()
            .and_then(|at| dir.virtual_address.checked_add(at))
            .and_then(|rva| mapped::<DESCRIPTOR_SIZE>(data, layout, rva));
        let Some(d) = d else {
            break;
        };
        let field = |o| u32_at(&d, o).unwrap_or(0);
        // The loader stops at a descriptor with no name or no import
        // address table.
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
        // A lossy name is kept for display only: the module it names is
        // not known exactly.
        if name.lossy {
            info.truncated = true;
        }
        let exact = !name.cut && !name.lossy;
        let lower = name.text.to_ascii_lowercase();
        for (found, module) in kernel.iter_mut().zip(super::KERNEL_MODULES) {
            *found |= exact && lower == module;
        }
        // A cut name is only a prefix: kept for display, never matched.
        if exact && !seen.contains(&lower) {
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
            name_cut: name.cut,
            name_lossy: name.lossy,
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
    info.kernel_modules = super::KERNEL_MODULES
        .iter()
        .zip(kernel)
        .filter_map(|(m, found)| found.then_some(*m))
        .collect();
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
    if rva == 0 {
        info.truncated = true;
        return false;
    }
    // The array is read from mapped memory, as the loader reads it: it may
    // go on into an adjacent section, and a section's zero-filled tail
    // reads as a null thunk. An unmapped slot, or the end of a truncated
    // input, ends it without one. Every slot read either ends the list or
    // counts towards [`MAX_IMPORTED_FUNCTIONS`], so the loop is bounded.
    for i in 0_usize.. {
        let at = u32::try_from(i.saturating_mul(thunk_size))
            .ok()
            .and_then(|at| rva.checked_add(at));
        let raw = if thunk_size == 8 {
            at.and_then(|at| mapped::<8>(data, layout, at))
                .map(u64::from_le_bytes)
        } else {
            at.and_then(|at| mapped::<4>(data, layout, at))
                .map(|b| u64::from(u32::from_le_bytes(b)))
        };
        let Some(v) = raw else {
            break;
        };
        let (value, by_ordinal) = if thunk_size == 8 {
            (v & 0x7fff_ffff_ffff_ffff, v >> 63 == 1)
        } else {
            (v & 0x7fff_ffff, v >> 31 == 1)
        };
        if value == 0 && !by_ordinal {
            return true;
        }
        // Checked after the terminator, so exactly the cap is not "over".
        if info.function_count >= MAX_IMPORTED_FUNCTIONS {
            info.truncated = true;
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
        dll_name: None,
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
    match (field(12), name_at(data, layout, field(12))) {
        (0, _) => {}
        (_, Some(name)) => {
            if name.cut {
                info.truncated = true;
            }
            info.dll_name = Some(name.text);
        }
        (_, None) => {
            bad.report(warnings);
            info.truncated = true;
        }
    }

    // Like the loader, an index past `NumberOfFunctions`, or a slot holding
    // RVA 0, is not an export.
    // A table at RVA 0 is absent: adding an index to it would read the
    // headers as the table.
    let slot_at = |index: u32| -> Slot {
        if index >= number_of_functions || functions == 0 {
            return Slot::Bad;
        }
        let Some(rva) = index
            .checked_mul(4)
            .and_then(|o| functions.checked_add(o))
            .and_then(|at| at_rva(data, layout, at, 4))
            .and_then(|b| u32_at(b, 0))
        else {
            return Slot::Bad;
        };
        if rva == 0 {
            Slot::Unused
        } else if (dir_start..dir_end).contains(&u64::from(rva)) {
            // The loader takes any RVA inside the directory as a forwarder
            // and reads its string wherever it ends, so one whose string
            // runs past the directory is still a forwarder, but the table
            // is malformed.
            let inside = dir_end.saturating_sub(u64::from(rva));
            match c_string(data, layout, rva, MAX_NAME_LEN) {
                Some((raw, terminated)) => {
                    // The string and its NUL, which comes after at least
                    // the bytes kept (and one more if it was cut).
                    let needed = u64::try_from(raw.len())
                        .unwrap_or(u64::MAX)
                        .saturating_add(if terminated { 1 } else { 2 });
                    let flaw = if needed > inside {
                        Flaw::PastDirectory
                    } else if terminated {
                        Flaw::None
                    } else {
                        Flaw::Cut
                    };
                    let text = String::from_utf8_lossy(&raw).into_owned();
                    Slot::Export(ExportTarget::Forwarder(text), flaw)
                }
                None => Slot::Bad,
            }
        } else {
            Slot::Export(ExportTarget::Rva(rva), Flaw::None)
        }
    };
    let name_rva_at = |i: u32| -> Option<u32> {
        let names = (names != 0).then_some(names)?;
        u32_at(
            at_rva(data, layout, names.checked_add(i.checked_mul(4)?)?, 4)?,
            0,
        )
    };
    let ordinal_at = |i: u32| -> Option<u16> {
        let ordinals = (ordinals != 0).then_some(ordinals)?;
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
    // A table the file does not hold in full is malformed, whether or not
    // any entry points into the missing part, and however far past the
    // scan caps it runs: the export address table (4 bytes per function),
    // and the name pointer and ordinal tables (4 and 2 bytes per name).
    let backed = |rva: u32, count: u32, size: u32| {
        count == 0
            || (rva != 0
                && layout
                    .backed_extent(rva)
                    .is_some_and(|(_, n)| u64::from(n) >= u64::from(count) * u64::from(size)))
    };
    if !backed(functions, info.number_of_functions, 4)
        || !backed(names, info.number_of_names, 4)
        || !backed(ordinals, info.number_of_names, 2)
    {
        bad.report(warnings);
        info.truncated = true;
    }
    // Which slots some name points to, from the whole ordinal table, not
    // only the listed names: a slot named past the listing cap, or by a
    // name that cannot be read, is not an unnamed export. If the file does
    // not hold the whole ordinal table, which slots are unnamed is unknown,
    // so none are listed as unnamed.
    let mut named = vec![false; to_usize(slots).unwrap_or(0)];
    let ordinal_table = (ordinals != 0)
        .then(|| layout.backed_extent(ordinals))
        .flatten();
    let known_names = ordinal_table
        .map_or(0, |(_, n)| n / 2)
        .min(info.number_of_names);
    // The scan is bounded: with more names than [`MAX_ORDINAL_SCAN`], which
    // slots are unnamed is not worked out, so none is listed as unnamed and
    // the listing is marked incomplete.
    let list_unnamed = known_names == info.number_of_names && known_names <= MAX_ORDINAL_SCAN;
    if known_names > MAX_ORDINAL_SCAN {
        info.truncated = true;
    }
    // Only needed when the unnamed slots are listed at all.
    if let Some((offset, _)) = ordinal_table.filter(|_| list_unnamed) {
        for i in 0..known_names {
            let index = to_usize(i)
                .and_then(|i| offset.checked_add(i.checked_mul(2)?))
                .and_then(|at| u16_at(data, at));
            if let Some(slot) = index.and_then(|index| named.get_mut(usize::from(index))) {
                *slot = true;
            }
        }
    }
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
        let Slot::Export(target, flaw) = slot_at(u32::from(index)) else {
            bad.report(warnings);
            info.truncated = true;
            continue;
        };
        // `Base + index` must fit: a wrapped ordinal would name another
        // export.
        let Some(ordinal) = base.checked_add(u32::from(index)) else {
            bad.report(warnings);
            info.truncated = true;
            continue;
        };
        flaw.record(&mut info.truncated, &mut bad, warnings);
        info.exports.push(Export {
            name: Some(name.text),
            ordinal,
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
    let unnamed_slots = if list_unnamed { slots } else { 0 };
    for index in 0..unnamed_slots {
        if to_usize(index)
            .and_then(|i| named.get(i))
            .copied()
            .unwrap_or(false)
        {
            continue;
        }
        match slot_at(index) {
            Slot::Unused => {}
            Slot::Export(target, flaw) => {
                // Checked only when there is one to add, so exactly the cap
                // is not "over".
                if info.exports.len() >= MAX_EXPORTS {
                    info.truncated = true;
                    break;
                }
                let Some(ordinal) = base.checked_add(index) else {
                    bad.report(warnings);
                    info.truncated = true;
                    continue;
                };
                flaw.record(&mut info.truncated, &mut bad, warnings);
                info.exports.push(Export {
                    name: None,
                    ordinal,
                    target,
                });
            }
            // One bad slot does not hide the rest.
            Slot::Bad => {
                bad.report(warnings);
                info.truncated = true;
            }
        }
    }

    let number_of_names = info.number_of_names;
    let find = |wanted: &str| -> Lookup {
        // The loader's binary search over the whole name table: inclusive
        // bounds and midpoint `(low + high) / 2`, comparing whole
        // NUL-terminated names byte by byte (`strcmp`). The name found must
        // also map to a real export.
        let Some(mut high) = number_of_names.checked_sub(1) else {
            return Lookup::Absent;
        };
        let mut low = 0_u32;
        while low <= high {
            let mid = low + (high - low) / 2;
            // `strcmp` against `wanted` is decided within `wanted.len() + 1`
            // bytes, so no more are read. A name that cannot be read leaves
            // the answer unknown, never "absent".
            let Some((name, terminated)) =
                name_rva_at(mid).and_then(|r| c_string(data, layout, r, wanted.len()))
            else {
                return Lookup::Unknown;
            };
            // Unterminated within `wanted.len()` bytes means the name is
            // longer: equal so far, so it sorts after `wanted`.
            let order = match name.as_ref().cmp(wanted.as_bytes()) {
                std::cmp::Ordering::Equal if !terminated => std::cmp::Ordering::Greater,
                other => other,
            };
            match order {
                std::cmp::Ordering::Equal => {
                    return match ordinal_at(mid).map(|i| slot_at(u32::from(i))) {
                        Some(Slot::Export(_, flaw)) => Lookup::Found(flaw),
                        Some(Slot::Unused) => Lookup::Absent,
                        Some(Slot::Bad) | None => Lookup::Unknown,
                    };
                }
                std::cmp::Ordering::Less => low = mid + 1,
                std::cmp::Ordering::Greater => match mid.checked_sub(1) {
                    Some(h) => high = h,
                    None => return Lookup::Absent,
                },
            }
        }
        Lookup::Absent
    };
    let lookups = [
        find("CPlApplet"),
        find("DllRegisterServer"),
        find("DllGetClassObject"),
        find("ServiceMain"),
    ];
    // A flaw met by the search is reported as the listing reports it, even
    // when the export is past the listing cap.
    for lookup in lookups {
        match lookup {
            Lookup::Found(flaw) => flaw.record(&mut info.truncated, &mut bad, warnings),
            Lookup::Unknown => {
                bad.report(warnings);
                info.truncated = true;
            }
            Lookup::Absent => {}
        }
    }
    let [
        cpl_applet,
        dll_register_server,
        dll_get_class_object,
        service_main,
    ] = lookups.map(|l| matches!(l, Lookup::Found(_)));
    info.notable = NotableExports {
        cpl_applet,
        dll_register_server,
        dll_get_class_object,
        service_main,
    };
    Some(info)
}

/// What the notable-export search found.
#[derive(Clone, Copy)]
enum Lookup {
    /// The name maps to an export, with this forwarder flaw.
    Found(Flaw),
    /// The name is not in the table, or its slot holds RVA 0.
    Absent,
    /// A name or entry on the search path cannot be read, so whether the
    /// export exists is not known.
    Unknown,
}

/// One slot of the export address table.
enum Slot {
    /// RVA 0: no export at this ordinal.
    Unused,
    /// An export, and what is wrong with its forwarder string, if anything.
    Export(ExportTarget, Flaw),
    /// Past the table (or a table at RVA 0), unreadable, or a forwarder
    /// that cannot be read.
    Bad,
}

/// What is wrong with an export's forwarder string.
#[derive(Clone, Copy)]
enum Flaw {
    None,
    /// Longer than [`MAX_NAME_LEN`]; the text kept is its start.
    Cut,
    /// It ends past the export directory, where the format says it must
    /// not.
    PastDirectory,
}

impl Flaw {
    fn record(self, truncated: &mut bool, bad: &mut Once, warnings: &mut Warnings) {
        match self {
            Self::None => {}
            Self::Cut => *truncated = true,
            Self::PastDirectory => {
                *truncated = true;
                bad.report(warnings);
            }
        }
    }
}
