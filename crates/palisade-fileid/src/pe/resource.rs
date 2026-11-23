//! The resource tree.
//!
//! The tree is three levels deep: type, name, language. Two passes read it:
//!
//! 1. **Direct lookups** for the resources that identity depends on,
//!    `RT_VERSION` and `RT_MANIFEST`. Each follows the exact type → name →
//!    language path the OS loader follows, with its own entry budget, so no
//!    other part of the tree can hide them: not a shared subdirectory, not a
//!    loop, and not thousands of dummy entries under another type.
//! 2. **A bounded general walk** for the summary (types, languages, icons).
//!    It allows [`MAX_RESOURCE_DEPTH`] directory levels and
//!    [`MAX_RESOURCE_ENTRIES`] entries in total, and does not follow a
//!    directory that refers back to one of its own ancestors.
//!
//! Numeric IDs are 16 bits. An ID entry with bits 16 to 30 set matches no
//! resource for the OS, which compares the whole field, so it is skipped
//! with a warning rather than truncated into a valid-looking ID.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use super::read::{bytes, to_u64, to_usize, u16_at, u32_at, utf16_until_nul};
use super::{DataDirectory, DataDirectoryKind, Layout, WarningKind, Warnings};

/// Directory levels the general walk allows, counting the root as level 1.
pub const MAX_RESOURCE_DEPTH: usize = 4;
/// Entries visited at most by the general walk, and by each direct lookup.
pub const MAX_RESOURCE_ENTRIES: usize = 65_535;
/// Version or manifest resources kept at most, each.
pub const MAX_KEPT_RESOURCES: usize = 64;
/// Distinct resource types recorded at most.
pub const MAX_RESOURCE_TYPES: usize = 256;
/// Resource names are cut to this many UTF-16 code units.
pub const MAX_RESOURCE_NAME_UNITS: usize = 256;

const DIRECTORY_SIZE: usize = 16;
const ENTRY_SIZE: usize = 8;
const DATA_ENTRY_SIZE: usize = 16;
const HIGH_BIT: u32 = 0x8000_0000;
/// The resource ID of the version resource the OS loads (`VS_VERSION_INFO`).
const VS_VERSION_INFO_ID: u16 = 1;
/// `LANG_NEUTRAL`.
const LANG_NEUTRAL: u16 = 0;

/// Well-known resource type IDs.
pub mod resource_type {
    /// `RT_ICON`.
    pub const ICON: u16 = 3;
    /// `RT_GROUP_ICON`.
    pub const GROUP_ICON: u16 = 14;
    /// `RT_VERSION`.
    pub const VERSION: u16 = 16;
    /// `RT_MANIFEST`.
    pub const MANIFEST: u16 = 24;
}

/// A resource type, name or language: a numeric ID or a string.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ResourceId {
    /// A numeric ID.
    Id(u16),
    /// A name, cut to [`MAX_RESOURCE_NAME_UNITS`] code units.
    Name(String),
}

/// One leaf of the resource tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceData {
    /// The type (level 1).
    pub type_id: ResourceId,
    /// The name (level 2).
    pub name: ResourceId,
    /// The language (level 3).
    pub language: ResourceId,
    /// RVA of the data.
    pub rva: u32,
    /// Size of the data in bytes.
    pub size: u32,
    /// The code page recorded in the data entry.
    pub code_page: u32,
    /// File offset of the data, if the whole RVA range maps to file data.
    pub file_offset: Option<u64>,
}

impl ResourceData {
    /// The resource bytes, if they lie inside `file`.
    #[must_use]
    pub fn bytes<'a>(&self, file: &'a [u8]) -> Option<&'a [u8]> {
        let offset = usize::try_from(self.file_offset?).ok()?;
        bytes(file, offset, to_usize(self.size)?)
    }
}

/// What the resource passes found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResourceSummary {
    /// File offset of the root resource directory.
    pub offset: u64,
    /// Directory entries visited by the general walk.
    pub entry_count: usize,
    /// Distinct resource types, at most [`MAX_RESOURCE_TYPES`].
    pub types: BTreeSet<ResourceId>,
    /// Distinct numeric language IDs of all leaves the general walk reached.
    pub languages: BTreeSet<u16>,
    /// Every `RT_VERSION` leaf (type 16 → any name → any language), in tree
    /// order, at most [`MAX_KEPT_RESOURCES`].
    pub version_entries: Vec<ResourceData>,
    /// The version resource the OS loads: type 16, name ID 1
    /// (`VS_VERSION_INFO`), preferring the language-neutral leaf and
    /// otherwise the first language. When an image carries several
    /// languages the OS may pick another by UI language; all of them are in
    /// [`version_entries`](Self::version_entries).
    pub version_resource: Option<ResourceData>,
    /// Every `RT_MANIFEST` leaf, in tree order, at most
    /// [`MAX_KEPT_RESOURCES`]. Parsing them is deferred.
    pub manifest_entries: Vec<ResourceData>,
    /// An `RT_ICON` or `RT_GROUP_ICON` resource exists.
    pub has_icons: bool,
}

/// The resource tree bytes and how to read them.
struct Tree<'a> {
    /// From the root directory to the end of the file-backed part of its
    /// section. Offsets inside the tree are relative to this.
    bytes: &'a [u8],
    /// File offset of `bytes`.
    base: usize,
    layout: Layout<'a>,
}

/// One directory entry.
struct Entry {
    /// Offset of the entry, relative to the tree.
    at: usize,
    name_field: u32,
    target: u32,
}

impl Entry {
    const fn is_directory(&self) -> bool {
        self.target & HIGH_BIT != 0
    }

    const fn target_offset(&self) -> u32 {
        self.target & !HIGH_BIT
    }
}

/// Bounds how many entries one pass reads.
struct Budget {
    left: usize,
    exhausted: bool,
}

impl Budget {
    const fn new() -> Self {
        Self {
            left: MAX_RESOURCE_ENTRIES,
            exhausted: false,
        }
    }

    fn take(&mut self) -> bool {
        if let Some(left) = self.left.checked_sub(1) {
            self.left = left;
            true
        } else {
            self.exhausted = true;
            false
        }
    }
}

impl<'a> Tree<'a> {
    fn file_offset(&self, at: usize) -> usize {
        self.base.saturating_add(at)
    }

    /// The entries of the directory at `offset`. Stops at the first entry
    /// that is out of bounds, with a warning, or when `budget` runs out.
    fn entries(&self, offset: u32, budget: &mut Budget, warnings: &mut Warnings) -> Vec<Entry> {
        let Some(offset) = to_usize(offset) else {
            return Vec::new();
        };
        let (Some(named), Some(ids)) = (
            u16_at(self.bytes, offset.saturating_add(12)),
            u16_at(self.bytes, offset.saturating_add(14)),
        ) else {
            warnings.push(self.file_offset(offset), WarningKind::ResourceOutOfBounds);
            return Vec::new();
        };
        let declared = usize::from(named) + usize::from(ids);
        let first = offset.saturating_add(DIRECTORY_SIZE);
        // Never allocate for more entries than the tree can hold.
        let fits = self.bytes.len().saturating_sub(first) / ENTRY_SIZE;
        let mut out = Vec::with_capacity(declared.min(fits));
        for i in 0..declared {
            let at = first.saturating_add(i.saturating_mul(ENTRY_SIZE));
            let (Some(name_field), Some(target)) = (
                u32_at(self.bytes, at),
                u32_at(self.bytes, at.saturating_add(4)),
            ) else {
                warnings.push(self.file_offset(at), WarningKind::ResourceOutOfBounds);
                break;
            };
            if !budget.take() {
                break;
            }
            out.push(Entry {
                at,
                name_field,
                target,
            });
        }
        out
    }

    /// The ID or name of an entry. Warns and returns `None` when the name is
    /// out of bounds or a numeric ID has bits 16 to 30 set.
    fn entry_id(&self, entry: &Entry, warnings: &mut Warnings) -> Option<ResourceId> {
        let field = entry.name_field;
        if field & HIGH_BIT == 0 {
            if let Ok(id) = u16::try_from(field) {
                return Some(ResourceId::Id(id));
            }
            warnings.push(
                self.file_offset(entry.at),
                WarningKind::ResourceIdInvalid(field),
            );
            return None;
        }
        let name = to_usize(field & !HIGH_BIT).and_then(|at| {
            let units = usize::from(u16_at(self.bytes, at)?).min(MAX_RESOURCE_NAME_UNITS);
            let raw = bytes(self.bytes, at.checked_add(2)?, units.checked_mul(2)?)?;
            Some(ResourceId::Name(utf16_until_nul(raw).text))
        });
        if name.is_none() {
            warnings.push(self.file_offset(entry.at), WarningKind::ResourceOutOfBounds);
        }
        name
    }

    /// Reads the data entry an entry points at.
    fn leaf(
        &self,
        entry: &Entry,
        path: [ResourceId; 3],
        warnings: &mut Warnings,
    ) -> Option<ResourceData> {
        let at = to_usize(entry.target_offset())?;
        let Some(raw) = bytes(self.bytes, at, DATA_ENTRY_SIZE) else {
            warnings.push(self.file_offset(at), WarningKind::ResourceOutOfBounds);
            return None;
        };
        let field = |off| u32_at(raw, off).unwrap_or(0);
        let (rva, size) = (field(0), field(4));
        let [type_id, name, language] = path;
        Some(ResourceData {
            type_id,
            name,
            language,
            rva,
            size,
            code_page: field(8),
            file_offset: self.layout.rva_to_offset(rva, size).map(to_u64),
        })
    }

    /// Every leaf on the standard path type `type_id` → any name → any
    /// language, in tree order, at most [`MAX_KEPT_RESOURCES`]. Entries that
    /// do not have the standard shape (a directory where a leaf belongs, or
    /// the reverse) are skipped, as the OS loader would not use them.
    fn lookup_type(&self, type_id: u16, warnings: &mut Warnings) -> Vec<ResourceData> {
        let mut budget = Budget::new();
        let mut found = Vec::new();
        let root = self.entries(0, &mut budget, warnings);
        let type_dir = root
            .iter()
            .find(|e| e.is_directory() && e.name_field == u32::from(type_id));
        let Some(type_dir) = type_dir else {
            return found;
        };
        'names: for name_entry in self.entries(type_dir.target_offset(), &mut budget, warnings) {
            if !name_entry.is_directory() {
                continue;
            }
            let Some(name) = self.entry_id(&name_entry, warnings) else {
                continue;
            };
            for lang_entry in self.entries(name_entry.target_offset(), &mut budget, warnings) {
                if lang_entry.is_directory() {
                    continue;
                }
                let Some(lang) = self.entry_id(&lang_entry, warnings) else {
                    continue;
                };
                let path = [ResourceId::Id(type_id), name.clone(), lang];
                if let Some(leaf) = self.leaf(&lang_entry, path, warnings) {
                    found.push(leaf);
                    if found.len() >= MAX_KEPT_RESOURCES {
                        break 'names;
                    }
                }
            }
        }
        if budget.exhausted {
            warnings.push(self.base, WarningKind::ResourceEntryLimit);
        }
        found
    }
}

/// Reads the resource tree. Returns `None`, with a warning, if the root
/// directory cannot be located.
pub(super) fn walk(
    data: &[u8],
    layout: Layout<'_>,
    dir: DataDirectory,
    warnings: &mut Warnings,
) -> Option<ResourceSummary> {
    let entry_offset = usize::try_from(dir.entry_offset).unwrap_or(usize::MAX);
    // Offsets in the tree may reach anywhere in the containing section, and
    // some linkers record a directory size that is too small, so the tree is
    // bounded by the file-backed part of the section holding the root, found
    // by RVA as the loader does.
    let Some((start, available)) = layout.backed_extent(dir.virtual_address) else {
        warnings.push(
            entry_offset,
            WarningKind::DirectoryNotMapped(DataDirectoryKind::Resource),
        );
        return None;
    };
    let end = start
        .saturating_add(to_usize(available).unwrap_or(0))
        .min(data.len());
    let tree_bytes = data.get(start..end).unwrap_or_default();
    if tree_bytes.len() < DIRECTORY_SIZE {
        warnings.push(start, WarningKind::ResourceOutOfBounds);
        return None;
    }
    let tree = Tree {
        bytes: tree_bytes,
        base: start,
        layout,
    };

    let version_entries = tree.lookup_type(resource_type::VERSION, warnings);
    let manifest_entries = tree.lookup_type(resource_type::MANIFEST, warnings);
    let version_resource = {
        let standard = || {
            version_entries
                .iter()
                .filter(|e| e.name == ResourceId::Id(VS_VERSION_INFO_ID))
        };
        standard()
            .find(|e| e.language == ResourceId::Id(LANG_NEUTRAL))
            .or_else(|| standard().next())
            .cloned()
    };

    let mut summary = ResourceSummary {
        offset: to_u64(start),
        version_entries,
        version_resource,
        manifest_entries,
        ..ResourceSummary::default()
    };
    let mut general = General {
        tree: &tree,
        budget: Budget::new(),
        stack: Vec::with_capacity(MAX_RESOURCE_DEPTH),
        too_deep: false,
    };
    let mut path = Vec::with_capacity(MAX_RESOURCE_DEPTH);
    general.directory(0, &mut path, &mut summary, warnings);
    summary.entry_count = MAX_RESOURCE_ENTRIES - general.budget.left;
    if general.budget.exhausted {
        warnings.push(start, WarningKind::ResourceEntryLimit);
    }
    if general.too_deep {
        warnings.push(start, WarningKind::ResourceTooDeep);
    }
    Some(summary)
}

/// The general walk, for the summary only.
struct General<'t, 'a> {
    tree: &'t Tree<'a>,
    budget: Budget,
    /// Directory offsets on the current path, to detect loops.
    stack: Vec<u32>,
    too_deep: bool,
}

impl General<'_, '_> {
    fn directory(
        &mut self,
        offset: u32,
        path: &mut Vec<ResourceId>,
        summary: &mut ResourceSummary,
        warnings: &mut Warnings,
    ) {
        if self.stack.len() >= MAX_RESOURCE_DEPTH {
            self.too_deep = true;
            return;
        }
        if self.stack.contains(&offset) {
            warnings.push(
                self.tree
                    .file_offset(to_usize(offset).unwrap_or(usize::MAX)),
                WarningKind::ResourceLoop,
            );
            return;
        }
        self.stack.push(offset);
        for entry in self.tree.entries(offset, &mut self.budget, warnings) {
            let Some(id) = self.tree.entry_id(&entry, warnings) else {
                continue;
            };
            path.push(id);
            if entry.is_directory() {
                self.directory(entry.target_offset(), path, summary, warnings);
            } else {
                record_leaf(path, summary);
            }
            path.pop();
        }
        self.stack.pop();
    }
}

fn record_leaf(path: &[ResourceId], summary: &mut ResourceSummary) {
    let Some(type_id) = path.first() else {
        return;
    };
    if summary.types.len() < MAX_RESOURCE_TYPES || summary.types.contains(type_id) {
        summary.types.insert(type_id.clone());
    }
    if let Some(ResourceId::Id(lang)) = path.get(2) {
        summary.languages.insert(*lang);
    }
    if matches!(
        type_id,
        ResourceId::Id(resource_type::ICON | resource_type::GROUP_ICON)
    ) {
        summary.has_icons = true;
    }
}
