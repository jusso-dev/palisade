//! A bounded walk of the resource tree.
//!
//! The tree is normally three levels deep (type, name, language). The walk
//! allows up to [`MAX_RESOURCE_DEPTH`] directory levels and
//! [`MAX_RESOURCE_ENTRIES`] entries in total, visits each directory once
//! (so loops and shared subtrees cannot multiply work), and keeps only what
//! later stages need: the version and manifest resources, the languages, and
//! whether icons are present.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use super::read::{bytes, to_u64, to_usize, u16_at, u32_at, utf16_until_nul};
use super::{DataDirectory, Section, WarningKind, Warnings, rva_to_offset};

/// Directory levels allowed, counting the root as level 1.
pub const MAX_RESOURCE_DEPTH: usize = 4;
/// Entries (directory entries of any level) visited at most.
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
    /// The name (level 2), if the tree reached that level.
    pub name: Option<ResourceId>,
    /// The language ID (level 3), if numeric.
    pub language: Option<u16>,
    /// RVA of the data.
    pub rva: u32,
    /// Size of the data in bytes.
    pub size: u32,
    /// The code page recorded in the data entry.
    pub code_page: u32,
    /// File offset of the data, if the RVA range maps to raw file data.
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

/// What the resource walk found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResourceSummary {
    /// File offset of the root resource directory.
    pub offset: u64,
    /// Directory entries visited.
    pub entry_count: usize,
    /// Distinct resource types, at most [`MAX_RESOURCE_TYPES`].
    pub types: BTreeSet<ResourceId>,
    /// Distinct numeric language IDs of all leaves.
    pub languages: BTreeSet<u16>,
    /// `RT_VERSION` leaves, in tree order.
    pub version_entries: Vec<ResourceData>,
    /// `RT_MANIFEST` leaves, in tree order. Parsing them is deferred.
    pub manifest_entries: Vec<ResourceData>,
    /// An `RT_ICON` or `RT_GROUP_ICON` resource exists.
    pub has_icons: bool,
}

struct Walk<'a> {
    /// The resource section bytes, starting at the root directory. All
    /// offsets inside the tree are relative to this.
    tree: &'a [u8],
    tree_offset: usize,
    sections: &'a [Section],
    size_of_headers: u32,
    visited: BTreeSet<usize>,
    summary: ResourceSummary,
    entry_limit_hit: bool,
    too_deep: bool,
}

/// Walks the resource tree. Returns `None` if the root cannot be located.
pub(super) fn walk(
    data: &[u8],
    sections: &[Section],
    size_of_headers: u32,
    dir: DataDirectory,
    warnings: &mut Warnings,
) -> Option<ResourceSummary> {
    let start = rva_to_offset(sections, size_of_headers, dir.virtual_address, 0)?;
    // Offsets in the tree may reach anywhere in the containing section, and
    // some linkers record a directory size that is too small, so bound the
    // tree by the section's raw data rather than by `dir.size`.
    let end = sections
        .iter()
        .filter_map(|s| {
            let begin = to_usize(s.pointer_to_raw_data)?;
            let stop = begin.checked_add(to_usize(s.size_of_raw_data)?)?;
            (begin <= start && start < stop).then_some(stop)
        })
        .next()
        .unwrap_or_else(|| start.saturating_add(to_usize(dir.size).unwrap_or(0)))
        .min(data.len());
    let tree = data.get(start..end)?;
    if tree.len() < DIRECTORY_SIZE {
        warnings.push(start, WarningKind::ResourceOutOfBounds);
        return None;
    }
    let mut walk = Walk {
        tree,
        tree_offset: start,
        sections,
        size_of_headers,
        visited: BTreeSet::new(),
        summary: ResourceSummary {
            offset: to_u64(start),
            ..ResourceSummary::default()
        },
        entry_limit_hit: false,
        too_deep: false,
    };
    let mut path = Vec::with_capacity(MAX_RESOURCE_DEPTH);
    walk.directory(0, &mut path, warnings);
    if walk.entry_limit_hit {
        warnings.push(start, WarningKind::ResourceEntryLimit);
    }
    if walk.too_deep {
        warnings.push(start, WarningKind::ResourceTooDeep);
    }
    Some(walk.summary)
}

impl Walk<'_> {
    fn directory(&mut self, offset: usize, path: &mut Vec<ResourceId>, warnings: &mut Warnings) {
        if path.len() >= MAX_RESOURCE_DEPTH {
            self.too_deep = true;
            return;
        }
        if !self.visited.insert(offset) {
            warnings.push(
                self.tree_offset.saturating_add(offset),
                WarningKind::ResourceLoop,
            );
            return;
        }
        let (Some(named), Some(ids)) = (
            u16_at(self.tree, offset.saturating_add(12)),
            u16_at(self.tree, offset.saturating_add(14)),
        ) else {
            warnings.push(
                self.tree_offset.saturating_add(offset),
                WarningKind::ResourceOutOfBounds,
            );
            return;
        };
        let count = usize::from(named) + usize::from(ids);
        let first = offset.saturating_add(DIRECTORY_SIZE);
        for i in 0..count {
            if self.summary.entry_count >= MAX_RESOURCE_ENTRIES {
                self.entry_limit_hit = true;
                return;
            }
            let at = first.saturating_add(i.saturating_mul(ENTRY_SIZE));
            let (Some(name_field), Some(target)) = (
                u32_at(self.tree, at),
                u32_at(self.tree, at.saturating_add(4)),
            ) else {
                warnings.push(
                    self.tree_offset.saturating_add(at),
                    WarningKind::ResourceOutOfBounds,
                );
                return;
            };
            self.summary.entry_count += 1;
            let Some(id) = self.entry_id(name_field) else {
                warnings.push(
                    self.tree_offset.saturating_add(at),
                    WarningKind::ResourceOutOfBounds,
                );
                continue;
            };
            path.push(id);
            let Some(target_offset) = to_usize(target & !HIGH_BIT) else {
                path.pop();
                continue;
            };
            if target & HIGH_BIT != 0 {
                self.directory(target_offset, path, warnings);
            } else {
                self.leaf(target_offset, path, warnings);
            }
            path.pop();
        }
    }

    fn entry_id(&self, name_field: u32) -> Option<ResourceId> {
        if name_field & HIGH_BIT == 0 {
            return Some(ResourceId::Id(u16::try_from(name_field & 0xffff).ok()?));
        }
        let at = to_usize(name_field & !HIGH_BIT)?;
        let units = usize::from(u16_at(self.tree, at)?).min(MAX_RESOURCE_NAME_UNITS);
        let raw = bytes(self.tree, at.checked_add(2)?, units.checked_mul(2)?)?;
        Some(ResourceId::Name(utf16_until_nul(raw).text))
    }

    fn leaf(&mut self, offset: usize, path: &[ResourceId], warnings: &mut Warnings) {
        let Some(entry) = bytes(self.tree, offset, DATA_ENTRY_SIZE) else {
            warnings.push(
                self.tree_offset.saturating_add(offset),
                WarningKind::ResourceOutOfBounds,
            );
            return;
        };
        let field = |at| u32_at(entry, at).unwrap_or(0);
        let Some(type_id) = path.first().cloned() else {
            return;
        };
        let (rva, size) = (field(0), field(4));
        let leaf = ResourceData {
            type_id,
            name: path.get(1).cloned(),
            language: match path.get(2) {
                Some(ResourceId::Id(lang)) => Some(*lang),
                _ => None,
            },
            rva,
            size,
            code_page: field(8),
            file_offset: rva_to_offset(self.sections, self.size_of_headers, rva, size).map(to_u64),
        };
        let summary = &mut self.summary;
        if summary.types.len() < MAX_RESOURCE_TYPES || summary.types.contains(&leaf.type_id) {
            summary.types.insert(leaf.type_id.clone());
        }
        if let Some(lang) = leaf.language {
            summary.languages.insert(lang);
        }
        match leaf.type_id {
            ResourceId::Id(resource_type::ICON | resource_type::GROUP_ICON) => {
                summary.has_icons = true;
            }
            ResourceId::Id(resource_type::VERSION)
                if summary.version_entries.len() < MAX_KEPT_RESOURCES =>
            {
                summary.version_entries.push(leaf);
            }
            ResourceId::Id(resource_type::MANIFEST)
                if summary.manifest_entries.len() < MAX_KEPT_RESOURCES =>
            {
                summary.manifest_entries.push(leaf);
            }
            _ => {}
        }
    }
}
