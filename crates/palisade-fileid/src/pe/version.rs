//! The version resource (`VS_VERSIONINFO`, resource type `RT_VERSION`).
//!
//! [`parse_version_info`] reads the fixed file info (numeric file and product
//! versions, flags, OS and type) and every `StringFileInfo` language block.
//! [`VersionInfo`] then selects one block, gives typed access to the standard
//! keys, and provides the file-name fallback chain that OS-native policy
//! rules use.
//!
//! Only the 32-bit (UTF-16) layout is read; the 16-bit layout used by NE
//! images is rejected with [`VersionIssueKind::BadRootKey`].
//!
//! The resource is untrusted. Its size is at most 64 KiB (`wLength` is a
//! `u16`), every block length is checked against its parent, and the number
//! of language blocks and strings kept is capped.

#![forbid(unsafe_code)]

use std::fmt;

use super::read::{align4, bytes, to_u64, u16_at, u32_at, utf16_until_nul};

/// Language blocks (`StringTable`s) kept at most.
pub const MAX_STRING_TABLES: usize = 64;
/// Strings kept at most per language block.
pub const MAX_STRINGS_PER_TABLE: usize = 256;
/// `Translation` entries kept at most.
pub const MAX_TRANSLATIONS: usize = 64;
/// Child blocks examined at most per parent, so a block full of tiny
/// children cannot cause unbounded work.
const MAX_CHILDREN: usize = 4096;

const BLOCK_HEADER: usize = 6;
const FIXED_INFO_SIZE: usize = 52;
const FIXED_SIGNATURE: u32 = 0xfeef_04bd;
const ROOT_KEY: &str = "VS_VERSION_INFO";

/// The US English language ID, `0x0409`.
pub const LANG_EN_US: u16 = 0x0409;
/// The Unicode (UTF-16) code page, `0x04b0` (1200).
pub const CODE_PAGE_UNICODE: u16 = 0x04b0;

/// A problem in the version resource. `offset` is relative to the start of
/// the resource data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionInfoIssue {
    /// Offset from the start of the resource data.
    pub offset: u64,
    /// What went wrong.
    pub kind: VersionIssueKind,
}

/// The kind of a [`VersionInfoIssue`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum VersionIssueKind {
    /// A block header or key is cut off.
    Truncated,
    /// The root key is not `VS_VERSION_INFO`.
    BadRootKey(String),
    /// The fixed file info has a wrong signature or size; it was ignored.
    BadFixedInfo,
    /// A block's `wLength` runs past its parent; it was cut to fit.
    BlockOverrun,
    /// A `StringTable` key is not eight hex digits (language + code page).
    BadStringTableKey(String),
    /// More than [`MAX_STRING_TABLES`] language blocks; the rest were
    /// skipped.
    TooManyStringTables,
    /// More than [`MAX_STRINGS_PER_TABLE`] strings in one block; the rest
    /// were skipped.
    TooManyStrings,
    /// More child blocks than the walker examines in one parent.
    TooManyChildren,
}

impl fmt::Display for VersionInfoIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:?} at version resource offset {:#x}",
            self.kind, self.offset
        )
    }
}

/// A four-part numeric version, `major.minor.build.revision`.
///
/// Ordering compares the parts numerically from left to right, so
/// `10.0.2.0 > 9.9.9.9`. Version comparisons must use this type, never the
/// version strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct FileVersionQuad(pub u16, pub u16, pub u16, pub u16);

impl FileVersionQuad {
    /// Builds a version from the fixed file info's most and least
    /// significant 32-bit halves.
    #[must_use]
    pub const fn from_ms_ls(ms: u32, ls: u32) -> Self {
        // Each half holds two 16-bit parts, so the shifts and masks cannot
        // lose information.
        #[allow(clippy::cast_possible_truncation)]
        Self(
            (ms >> 16) as u16,
            (ms & 0xffff) as u16,
            (ls >> 16) as u16,
            (ls & 0xffff) as u16,
        )
    }

    /// Parses the leading numeric part of a version string, such as
    /// `"10.0.19041.1 (build.160101-0800)"` or `"1, 2, 3, 4"`.
    ///
    /// One to four parts separated by `.` or `,` are accepted (spaces around
    /// separators are ignored); missing parts are zero. Text after the
    /// numeric part is ignored. Returns `None` if there is no leading number
    /// or a part does not fit in 16 bits.
    #[must_use]
    pub fn parse_prefix(text: &str) -> Option<Self> {
        let mut parts = [0_u16; 4];
        let mut count = 0_usize;
        let mut rest = text.trim_start();
        loop {
            let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
            if digits == 0 {
                break;
            }
            let (number, tail) = rest.split_at(digits);
            let slot = parts.get_mut(count)?;
            *slot = number.parse().ok()?;
            count += 1;
            if count == 4 {
                break;
            }
            let trimmed = tail.trim_start();
            match trimmed.strip_prefix(['.', ',']) {
                Some(after) if after.trim_start().starts_with(|c: char| c.is_ascii_digit()) => {
                    rest = after.trim_start();
                }
                _ => break,
            }
        }
        (count > 0).then(|| {
            let [a, b, c, d] = parts;
            Self(a, b, c, d)
        })
    }
}

impl fmt::Display for FileVersionQuad {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}.{}", self.0, self.1, self.2, self.3)
    }
}

/// `VS_FIXEDFILEINFO`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixedFileInfo {
    /// Offset of the structure from the start of the resource data.
    pub offset: u64,
    /// `dwStrucVersion`.
    pub struct_version: u32,
    /// `dwFileVersionMS` / `dwFileVersionLS`.
    pub file_version: FileVersionQuad,
    /// `dwProductVersionMS` / `dwProductVersionLS`.
    pub product_version: FileVersionQuad,
    /// `dwFileFlagsMask`.
    pub file_flags_mask: u32,
    /// `dwFileFlags` (debug, prerelease, patched, private build, ...).
    pub file_flags: u32,
    /// `dwFileOS`.
    pub file_os: u32,
    /// `dwFileType` (application, DLL, driver, ...).
    pub file_type: u32,
    /// `dwFileSubtype`.
    pub file_subtype: u32,
    /// `dwFileDateMS` and `dwFileDateLS` combined.
    pub file_date: u64,
}

/// A `Translation` entry: a language and code page pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Translation {
    /// Language ID, such as `0x0409`.
    pub language: u16,
    /// Code page, such as `0x04b0`.
    pub code_page: u16,
}

/// One `StringTable`: the strings for one language and code page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StringTable {
    /// Offset of the block from the start of the resource data.
    pub offset: u64,
    /// The block key as stored, normally eight hex digits such as
    /// `"040904B0"`.
    pub key: String,
    /// Language and code page decoded from the key, if it is valid hex.
    pub translation: Option<Translation>,
    /// The strings in file order, as `(key, value)`. Values are cut at the
    /// first NUL, which removes NUL padding; nothing else is changed.
    pub strings: Vec<(String, String)>,
}

impl StringTable {
    /// The value for `key`. Keys compare ASCII case-insensitively; the first
    /// match wins.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.strings
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
            .map(|(_, v)| v.as_str())
    }
}

/// The standard `StringFileInfo` keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VersionField {
    /// `OriginalFilename`: the name the file was built with.
    OriginalFileName,
    /// `InternalName`.
    InternalName,
    /// `FileDescription`.
    FileDescription,
    /// `ProductName`.
    ProductName,
    /// `CompanyName`.
    CompanyName,
    /// `FileVersion` (the string form).
    FileVersion,
    /// `ProductVersion` (the string form).
    ProductVersion,
    /// `LegalCopyright`.
    LegalCopyright,
    /// `LegalTrademarks`.
    LegalTrademarks,
    /// `Comments`.
    Comments,
    /// `PrivateBuild`.
    PrivateBuild,
    /// `SpecialBuild`.
    SpecialBuild,
}

impl VersionField {
    /// Every field.
    pub const ALL: [Self; 12] = [
        Self::OriginalFileName,
        Self::InternalName,
        Self::FileDescription,
        Self::ProductName,
        Self::CompanyName,
        Self::FileVersion,
        Self::ProductVersion,
        Self::LegalCopyright,
        Self::LegalTrademarks,
        Self::Comments,
        Self::PrivateBuild,
        Self::SpecialBuild,
    ];

    /// The file-name fallback chain used by OS-native policy rules.
    pub const FILE_NAME_CHAIN: [Self; 4] = [
        Self::OriginalFileName,
        Self::InternalName,
        Self::FileDescription,
        Self::ProductName,
    ];

    /// The key as stored in the resource. Note `OriginalFilename` with a
    /// lowercase `n`.
    #[must_use]
    pub const fn resource_key(self) -> &'static str {
        match self {
            Self::OriginalFileName => "OriginalFilename",
            Self::InternalName => "InternalName",
            Self::FileDescription => "FileDescription",
            Self::ProductName => "ProductName",
            Self::CompanyName => "CompanyName",
            Self::FileVersion => "FileVersion",
            Self::ProductVersion => "ProductVersion",
            Self::LegalCopyright => "LegalCopyright",
            Self::LegalTrademarks => "LegalTrademarks",
            Self::Comments => "Comments",
            Self::PrivateBuild => "PrivateBuild",
            Self::SpecialBuild => "SpecialBuild",
        }
    }

    /// The field name used in OS audit events, so inventory and events can
    /// be joined. Differs from [`resource_key`](Self::resource_key) only for
    /// `OriginalFileName`.
    #[must_use]
    pub const fn event_name(self) -> &'static str {
        match self {
            Self::OriginalFileName => "OriginalFileName",
            other => other.resource_key(),
        }
    }
}

/// How [`VersionInfo::selected`] was chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LanguageSelection {
    /// The block matches a `Translation` entry (the first such entry wins).
    Translation,
    /// No `Translation` match; the block is US English, Unicode
    /// (`040904B0`).
    EnglishUnicode,
    /// Neither matched; the first block is used.
    First,
}

/// The result of [`VersionInfo::effective_file_name`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EffectiveFileName<'a> {
    /// The field the name came from.
    pub field: VersionField,
    /// The value, as stored.
    pub value: &'a str,
}

/// The parsed version resource.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionInfo {
    /// `VS_FIXEDFILEINFO`, if present and valid.
    pub fixed: Option<FixedFileInfo>,
    /// Every `StringFileInfo` language block, in file order.
    pub all_langs: Vec<StringTable>,
    /// The `VarFileInfo\Translation` entries, in file order.
    pub translations: Vec<Translation>,
    /// Index into [`all_langs`](Self::all_langs) of the selected block.
    pub selected: Option<usize>,
    /// How the block was selected.
    pub selection: Option<LanguageSelection>,
    /// Non-fatal problems.
    pub issues: Vec<VersionInfoIssue>,
}

impl VersionInfo {
    /// The selected language block.
    #[must_use]
    pub fn selected_table(&self) -> Option<&StringTable> {
        self.all_langs.get(self.selected?)
    }

    /// The value of `field` in the selected language block, as stored.
    #[must_use]
    pub fn get(&self, field: VersionField) -> Option<&str> {
        self.selected_table()?.get(field.resource_key())
    }

    /// The file version: from the fixed info when present (it takes
    /// precedence), otherwise parsed from the `FileVersion` string.
    #[must_use]
    pub fn file_version(&self) -> Option<FileVersionQuad> {
        self.fixed.map(|f| f.file_version).or_else(|| {
            self.get(VersionField::FileVersion)
                .and_then(FileVersionQuad::parse_prefix)
        })
    }

    /// The product version, with the same precedence as
    /// [`file_version`](Self::file_version).
    #[must_use]
    pub fn product_version(&self) -> Option<FileVersionQuad> {
        self.fixed.map(|f| f.product_version).or_else(|| {
            self.get(VersionField::ProductVersion)
                .and_then(FileVersionQuad::parse_prefix)
        })
    }

    /// The `FileVersion` string parses to a different version than the fixed
    /// info. `false` when either is missing or the string does not parse.
    #[must_use]
    pub fn file_version_mismatch(&self) -> bool {
        mismatch(
            self.fixed.map(|f| f.file_version),
            self.get(VersionField::FileVersion),
        )
    }

    /// The `ProductVersion` string parses to a different version than the
    /// fixed info.
    #[must_use]
    pub fn product_version_mismatch(&self) -> bool {
        mismatch(
            self.fixed.map(|f| f.product_version),
            self.get(VersionField::ProductVersion),
        )
    }

    /// The file name OS-native policy would match on.
    ///
    /// Walks [`VersionField::FILE_NAME_CHAIN`] (`OriginalFileName`, then
    /// `InternalName`, `FileDescription`, `ProductName`) starting at
    /// `level`, and returns the first field whose value is not empty or
    /// whitespace. Pass [`VersionField::OriginalFileName`] for the full
    /// chain. A `level` outside the chain returns `None`.
    #[must_use]
    pub fn effective_file_name(&self, level: VersionField) -> Option<EffectiveFileName<'_>> {
        let start = VersionField::FILE_NAME_CHAIN
            .iter()
            .position(|f| *f == level)?;
        VersionField::FILE_NAME_CHAIN
            .iter()
            .skip(start)
            .find_map(|field| {
                let value = self.get(*field)?;
                (!value.trim().is_empty()).then_some(EffectiveFileName {
                    field: *field,
                    value,
                })
            })
    }
}

fn mismatch(fixed: Option<FileVersionQuad>, text: Option<&str>) -> bool {
    match (fixed, text.and_then(FileVersionQuad::parse_prefix)) {
        (Some(fixed), Some(parsed)) => fixed != parsed,
        _ => false,
    }
}

/// One block header: `wLength`, `wValueLength`, `wType`, `szKey`.
struct Block {
    start: usize,
    /// End of the block, cut to the parent's end.
    end: usize,
    /// `wValueLength`: in bytes for binary values (`wType` 0), in UTF-16
    /// code units for text values (`wType` 1).
    value_len: u16,
    /// `wType`: 0 for binary data, 1 for text.
    w_type: u16,
    key: String,
    /// Start of the value, after the key and padding.
    value_start: usize,
}

impl Block {
    /// The value bytes, `byte_len` long, cut to the block end.
    fn value<'a>(&self, data: &'a [u8], byte_len: usize) -> &'a [u8] {
        let end = self.value_start.saturating_add(byte_len).min(self.end);
        data.get(self.value_start..end).unwrap_or_default()
    }

    /// The value's length in bytes, as the OS version API computes it:
    /// `wValueLength`, doubled for text values.
    fn value_bytes(&self) -> usize {
        let len = usize::from(self.value_len);
        if self.w_type == 0 {
            len
        } else {
            len.saturating_mul(2)
        }
    }

    /// Start of the children: after the value, whatever block this is, and
    /// 4-byte aligned. Skipping the value the same way for every block, as
    /// the OS does, means bytes hidden inside a value are never read as
    /// child blocks.
    fn children_start(&self) -> usize {
        align4(self.value_start.saturating_add(self.value_bytes()))
            .unwrap_or(usize::MAX)
            .min(self.end)
    }
}

/// Reads the block at `start`, which must end by `limit`. Returns `None` for
/// a zero `wLength` (end-of-children padding), and an issue when the header
/// or key is unreadable.
fn read_block(
    data: &[u8],
    start: usize,
    limit: usize,
    issues: &mut Vec<VersionInfoIssue>,
) -> Result<Option<Block>, VersionInfoIssue> {
    let truncated = VersionInfoIssue {
        offset: to_u64(start),
        kind: VersionIssueKind::Truncated,
    };
    let header =
        bytes(data, start, BLOCK_HEADER).filter(|_| start.saturating_add(BLOCK_HEADER) <= limit);
    let Some(header) = header else {
        return Err(truncated);
    };
    let len = usize::from(u16_at(header, 0).unwrap_or(0));
    if len == 0 {
        return Ok(None);
    }
    if len < BLOCK_HEADER {
        return Err(truncated);
    }
    let mut end = start.saturating_add(len);
    if end > limit {
        issues.push(VersionInfoIssue {
            offset: to_u64(start),
            kind: VersionIssueKind::BlockOverrun,
        });
        end = limit;
    }
    let key_start = start.saturating_add(BLOCK_HEADER);
    let key_area = data.get(key_start..end).unwrap_or_default();
    let key = utf16_until_nul(key_area);
    if !key.terminated {
        return Err(truncated);
    }
    let value_start = align4(key_start.saturating_add(key.consumed))
        .unwrap_or(usize::MAX)
        .min(end);
    Ok(Some(Block {
        start,
        end,
        value_len: u16_at(header, 2).unwrap_or(0),
        w_type: u16_at(header, 4).unwrap_or(0),
        key: key.text,
        value_start,
    }))
}

/// Iterates the child blocks of `parent` starting at `first`, calling `each`
/// for every readable child. Stops at the first unreadable child.
fn for_each_child(
    data: &[u8],
    first: usize,
    parent_end: usize,
    issues: &mut Vec<VersionInfoIssue>,
    mut each: impl FnMut(&Block, &mut Vec<VersionInfoIssue>),
) {
    let mut pos = first;
    for _ in 0..MAX_CHILDREN {
        if pos.saturating_add(BLOCK_HEADER) > parent_end {
            return;
        }
        match read_block(data, pos, parent_end, issues) {
            Ok(Some(child)) => {
                each(&child, issues);
                // `read_block` guarantees `end > start`, so this advances.
                pos = match align4(child.end) {
                    Some(next) if next > pos => next,
                    _ => return,
                };
            }
            Ok(None) => return,
            Err(issue) => {
                issues.push(issue);
                return;
            }
        }
    }
    issues.push(VersionInfoIssue {
        offset: to_u64(pos),
        kind: VersionIssueKind::TooManyChildren,
    });
}

/// Parses a `VS_VERSIONINFO` resource.
///
/// Fails only when the root block is unreadable or its key is not
/// `VS_VERSION_INFO`. Other problems are listed in
/// [`VersionInfo::issues`], and whatever could be read is returned.
pub fn parse_version_info(data: &[u8]) -> Result<VersionInfo, VersionInfoIssue> {
    let mut issues = Vec::new();
    let root = read_block(data, 0, data.len(), &mut issues)?.ok_or(VersionInfoIssue {
        offset: 0,
        kind: VersionIssueKind::Truncated,
    })?;
    // Block keys compare ASCII case-insensitively, as the OS version API
    // does.
    if !root.key.eq_ignore_ascii_case(ROOT_KEY) {
        return Err(VersionInfoIssue {
            offset: 0,
            kind: VersionIssueKind::BadRootKey(root.key),
        });
    }

    let value_bytes = root.value_bytes();
    let fixed = if value_bytes == 0 {
        None
    } else {
        let parsed = parse_fixed(root.value(data, value_bytes), root.value_start);
        if parsed.is_none() {
            issues.push(VersionInfoIssue {
                offset: to_u64(root.value_start),
                kind: VersionIssueKind::BadFixedInfo,
            });
        }
        parsed
    };

    let mut all_langs = Vec::new();
    let mut translations = Vec::new();
    for_each_child(
        data,
        root.children_start(),
        root.end,
        &mut issues,
        |child, issues| {
            if child.key.eq_ignore_ascii_case("StringFileInfo") {
                string_file_info(data, child, &mut all_langs, issues);
            } else if child.key.eq_ignore_ascii_case("VarFileInfo") {
                var_file_info(data, child, &mut translations, issues);
            }
        },
    );

    let (selected, selection) = select_language(&all_langs, &translations);
    Ok(VersionInfo {
        fixed,
        all_langs,
        translations,
        selected,
        selection,
        issues,
    })
}

fn parse_fixed(value: &[u8], offset: usize) -> Option<FixedFileInfo> {
    if value.len() < FIXED_INFO_SIZE || u32_at(value, 0)? != FIXED_SIGNATURE {
        return None;
    }
    let f = |i: usize| u32_at(value, i.saturating_mul(4)).unwrap_or(0);
    Some(FixedFileInfo {
        offset: to_u64(offset),
        struct_version: f(1),
        file_version: FileVersionQuad::from_ms_ls(f(2), f(3)),
        product_version: FileVersionQuad::from_ms_ls(f(4), f(5)),
        file_flags_mask: f(6),
        file_flags: f(7),
        file_os: f(8),
        file_type: f(9),
        file_subtype: f(10),
        file_date: (u64::from(f(11)) << 32) | u64::from(f(12)),
    })
}

fn string_file_info(
    data: &[u8],
    block: &Block,
    tables: &mut Vec<StringTable>,
    issues: &mut Vec<VersionInfoIssue>,
) {
    // `StringFileInfo` has no value; its children start after the key.
    for_each_child(
        data,
        block.children_start(),
        block.end,
        issues,
        |table, issues| {
            if tables.len() >= MAX_STRING_TABLES {
                if !issues
                    .iter()
                    .any(|i| i.kind == VersionIssueKind::TooManyStringTables)
                {
                    issues.push(VersionInfoIssue {
                        offset: to_u64(table.start),
                        kind: VersionIssueKind::TooManyStringTables,
                    });
                }
                return;
            }
            let translation = parse_table_key(&table.key);
            if translation.is_none() {
                issues.push(VersionInfoIssue {
                    offset: to_u64(table.start),
                    kind: VersionIssueKind::BadStringTableKey(table.key.clone()),
                });
            }
            let mut strings = Vec::new();
            let mut overflow = false;
            for_each_child(data, table.children_start(), table.end, issues, |s, _| {
                if strings.len() >= MAX_STRINGS_PER_TABLE {
                    overflow = true;
                    return;
                }
                // `wValueLength` counts UTF-16 units for text values, but some
                // linkers store a byte count or omit the NUL. Reading to the
                // first NUL inside the block handles all of these; a zero
                // `wValueLength` means an empty value.
                let value = if s.value_len == 0 {
                    String::new()
                } else {
                    utf16_until_nul(s.value(data, s.end.saturating_sub(s.value_start))).text
                };
                strings.push((s.key.clone(), value));
            });
            if overflow {
                issues.push(VersionInfoIssue {
                    offset: to_u64(table.start),
                    kind: VersionIssueKind::TooManyStrings,
                });
            }
            tables.push(StringTable {
                offset: to_u64(table.start),
                key: table.key.clone(),
                translation,
                strings,
            });
        },
    );
}

fn var_file_info(
    data: &[u8],
    block: &Block,
    translations: &mut Vec<Translation>,
    issues: &mut Vec<VersionInfoIssue>,
) {
    for_each_child(data, block.children_start(), block.end, issues, |var, _| {
        if !var.key.eq_ignore_ascii_case("Translation") {
            return;
        }
        let value = var.value(data, var.value_bytes());
        for pair in value.chunks_exact(4) {
            if translations.len() >= MAX_TRANSLATIONS {
                break;
            }
            let (Some(language), Some(code_page)) = (u16_at(pair, 0), u16_at(pair, 2)) else {
                break;
            };
            translations.push(Translation {
                language,
                code_page,
            });
        }
    });
}

/// Decodes a `StringTable` key such as `"040904B0"`.
fn parse_table_key(key: &str) -> Option<Translation> {
    if key.len() != 8 || !key.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let language = u16::from_str_radix(key.get(0..4)?, 16).ok()?;
    let code_page = u16::from_str_radix(key.get(4..8)?, 16).ok()?;
    Some(Translation {
        language,
        code_page,
    })
}

fn select_language(
    tables: &[StringTable],
    translations: &[Translation],
) -> (Option<usize>, Option<LanguageSelection>) {
    let find = |want: Translation| tables.iter().position(|t| t.translation == Some(want));
    if let Some(i) = translations.iter().find_map(|t| find(*t)) {
        return (Some(i), Some(LanguageSelection::Translation));
    }
    let english = Translation {
        language: LANG_EN_US,
        code_page: CODE_PAGE_UNICODE,
    };
    if let Some(i) = find(english) {
        return (Some(i), Some(LanguageSelection::EnglishUnicode));
    }
    if tables.is_empty() {
        (None, None)
    } else {
        (Some(0), Some(LanguageSelection::First))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quad_parsing() {
        let q = FileVersionQuad::parse_prefix;
        assert_eq!(
            q("10.0.19041.1 (build.160101-0800)"),
            Some(FileVersionQuad(10, 0, 19041, 1))
        );
        assert_eq!(q("1, 2, 3, 4"), Some(FileVersionQuad(1, 2, 3, 4)));
        assert_eq!(q("5.812"), Some(FileVersionQuad(5, 812, 0, 0)));
        assert_eq!(q("  7"), Some(FileVersionQuad(7, 0, 0, 0)));
        assert_eq!(q("1.2."), Some(FileVersionQuad(1, 2, 0, 0)));
        assert_eq!(q("1.2.3.4.5"), Some(FileVersionQuad(1, 2, 3, 4)));
        assert_eq!(q("v1.2"), None);
        assert_eq!(q(""), None);
        assert_eq!(q("70000.1"), None);
    }

    #[test]
    fn quad_order_is_numeric() {
        assert!(FileVersionQuad(10, 0, 2, 0) > FileVersionQuad(9, 9, 9, 9));
        assert!(FileVersionQuad(5, 812, 10240, 0) > FileVersionQuad(5, 812, 9999, 65535));
        assert_eq!(
            FileVersionQuad::from_ms_ls(0x000a_0000, 0x4a61_0001),
            FileVersionQuad(10, 0, 19041, 1)
        );
        assert_eq!(FileVersionQuad(1, 2, 3, 4).to_string(), "1.2.3.4");
    }

    #[test]
    fn table_keys() {
        assert_eq!(
            parse_table_key("040904B0"),
            Some(Translation {
                language: 0x0409,
                code_page: 0x04b0
            })
        );
        assert_eq!(parse_table_key("040904b"), None);
        assert_eq!(parse_table_key("04090+b0"), None);
        assert_eq!(parse_table_key("0409\u{e9}b0"), None);
    }

    #[test]
    fn field_names() {
        assert_eq!(
            VersionField::OriginalFileName.resource_key(),
            "OriginalFilename"
        );
        assert_eq!(
            VersionField::OriginalFileName.event_name(),
            "OriginalFileName"
        );
        assert_eq!(VersionField::ProductName.event_name(), "ProductName");
    }

    #[test]
    fn rejects_bad_roots() {
        assert!(parse_version_info(&[]).is_err());
        assert!(parse_version_info(&[0, 0, 0, 0, 0, 0]).is_err());
        assert!(parse_version_info(&[3, 0, 0, 0, 0, 0]).is_err());
    }
}
