//! A builder for small synthetic PE images, used only by tests.
//!
//! Every fixture is assembled byte by byte at test time. No third-party
//! binary is ever checked in. The layout is fixed and simple:
//!
//! - 0x000: DOS header, `e_lfanew = 0x40`.
//! - 0x040: PE signature, COFF header, optional header (PE32 or PE32+), all
//!   16 data directories, then the section table.
//! - 0x400: section raw data, each section 0x200-aligned. Section `i` is at
//!   RVA `0x1000 * (i + 1)`.
//! - After the sections: the certificate table (if any), then overlay bytes.

// Test-only code: fixture sizes are small constants, and a failed fixture
// build should panic loudly.
#![allow(dead_code, clippy::cast_possible_truncation, clippy::unwrap_used)]

use std::collections::BTreeMap;

pub const FILE_ALIGNMENT: u32 = 0x200;
pub const SECTION_ALIGNMENT: u32 = 0x1000;
pub const SIZE_OF_HEADERS: u32 = 0x400;
pub const E_LFANEW: usize = 0x40;
pub const COFF_OFFSET: usize = E_LFANEW + 4;
pub const OPT_OFFSET: usize = COFF_OFFSET + 20;

pub const IMAGE_SCN_CNT_CODE: u32 = 0x20;
pub const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x40;
pub const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
pub const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
pub const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

/// A raw section added with [`PeBuilder::section`].
#[derive(Clone)]
pub struct SectionSpec {
    pub name: [u8; 8],
    pub data: Vec<u8>,
    /// `VirtualSize`; defaults to the data length.
    pub virtual_size: Option<u32>,
    pub characteristics: u32,
}

/// Debug directory contents.
#[derive(Clone)]
pub struct DebugSpec {
    pub pdb_guid: [u8; 16],
    pub pdb_age: u32,
    pub pdb_path: String,
    pub repro: bool,
    pub pogo: bool,
}

/// A resource leaf: type, name and language IDs, and the data.
#[derive(Clone)]
pub struct Leaf {
    pub type_id: u16,
    pub name_id: u16,
    pub lang: u16,
    pub data: Vec<u8>,
}

#[derive(Clone)]
pub struct PeBuilder {
    pub pe32_plus: bool,
    pub machine: u16,
    pub characteristics: u16,
    pub timestamp: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub entry_point: u32,
    pub sections: Vec<SectionSpec>,
    pub debug: Option<DebugSpec>,
    pub resources: Vec<Leaf>,
    pub certificate: Option<Vec<u8>>,
    pub overlay: Vec<u8>,
    pub valid_checksum: bool,
}

impl Default for PeBuilder {
    fn default() -> Self {
        Self {
            pe32_plus: true,
            machine: 0x8664,
            characteristics: 0x0022, // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
            timestamp: 0x6000_0000,
            subsystem: 2,                // GUI
            dll_characteristics: 0x8160, // TS_AWARE | NX | DYNAMIC_BASE | HIGH_ENTROPY_VA
            entry_point: 0x1000,
            sections: vec![SectionSpec {
                name: *b".text\0\0\0",
                // `ret` followed by padding, plus a little varied data.
                data: [0xc3_u8].into_iter().chain(0..=255).collect(),
                virtual_size: None,
                characteristics: IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ,
            }],
            debug: None,
            resources: Vec::new(),
            certificate: None,
            overlay: Vec::new(),
            valid_checksum: false,
        }
    }
}

const fn align(value: u32, to: u32) -> u32 {
    value.div_ceil(to) * to
}

fn put16(buf: &mut [u8], at: usize, v: u16) {
    buf[at..at + 2].copy_from_slice(&v.to_le_bytes());
}

fn put32(buf: &mut [u8], at: usize, v: u32) {
    buf[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

fn put64(buf: &mut [u8], at: usize, v: u64) {
    buf[at..at + 8].copy_from_slice(&v.to_le_bytes());
}

fn pad_to(buf: &mut Vec<u8>, to: usize) {
    while !buf.len().is_multiple_of(to) {
        buf.push(0);
    }
}

impl PeBuilder {
    pub fn dll() -> Self {
        Self {
            characteristics: 0x2022,
            entry_point: 0,
            ..Self::default()
        }
    }

    pub fn pe32() -> Self {
        Self {
            pe32_plus: false,
            machine: 0x014c,
            characteristics: 0x0102, // EXECUTABLE_IMAGE | 32BIT_MACHINE
            ..Self::default()
        }
    }

    pub fn section(mut self, name: &str, data: Vec<u8>, characteristics: u32) -> Self {
        let mut raw = [0_u8; 8];
        raw[..name.len()].copy_from_slice(name.as_bytes());
        self.sections.push(SectionSpec {
            name: raw,
            data,
            virtual_size: None,
            characteristics,
        });
        self
    }

    pub fn optional_header_size(&self) -> usize {
        if self.pe32_plus { 112 + 128 } else { 96 + 128 }
    }

    pub fn section_table_offset(&self) -> usize {
        OPT_OFFSET + self.optional_header_size()
    }

    /// File offset of data directory entry `index`.
    pub fn data_directory_offset(&self, index: usize) -> usize {
        OPT_OFFSET + self.optional_header_size() - 128 + index * 8
    }

    pub fn checksum_offset(&self) -> usize {
        OPT_OFFSET + 64
    }

    /// Assembles the image.
    pub fn build(&self) -> Vec<u8> {
        // Collect every section, adding the generated ones last so their
        // RVAs are known.
        let mut specs = self.sections.clone();
        let mut debug_dir = None;
        if let Some(debug) = &self.debug {
            let index = specs.len();
            let rva = SECTION_ALIGNMENT * (index as u32 + 1);
            let file = self.raw_offset_of(&specs, index);
            let (data, dir_size) = debug_section(debug, rva, file);
            debug_dir = Some((rva, dir_size));
            specs.push(SectionSpec {
                name: *b".rdata\0\0",
                data,
                virtual_size: None,
                characteristics: IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
            });
        }
        let mut resource_dir = None;
        if !self.resources.is_empty() {
            let index = specs.len();
            let rva = SECTION_ALIGNMENT * (index as u32 + 1);
            let data = resource_section(rva, &self.resources);
            resource_dir = Some((rva, data.len() as u32));
            specs.push(SectionSpec {
                name: *b".rsrc\0\0\0",
                data,
                virtual_size: None,
                characteristics: IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
            });
        }

        // Every section header must fit in the fixed header area, or the
        // table would be written over the first section's data.
        let table_end = self.section_table_offset() + specs.len() * 40;
        assert!(
            table_end <= SIZE_OF_HEADERS as usize,
            "{} sections need {table_end:#x} bytes of headers; the fixture has {SIZE_OF_HEADERS:#x}",
            specs.len()
        );

        let mut out = vec![0_u8; SIZE_OF_HEADERS as usize];
        out[0] = b'M';
        out[1] = b'Z';
        put32(&mut out, 0x3c, E_LFANEW as u32);
        out[E_LFANEW..E_LFANEW + 4].copy_from_slice(b"PE\0\0");

        // COFF header.
        put16(&mut out, COFF_OFFSET, self.machine);
        put16(&mut out, COFF_OFFSET + 2, specs.len() as u16);
        put32(&mut out, COFF_OFFSET + 4, self.timestamp);
        put16(
            &mut out,
            COFF_OFFSET + 16,
            self.optional_header_size() as u16,
        );
        put16(&mut out, COFF_OFFSET + 18, self.characteristics);

        // Section raw data.
        let mut headers = Vec::new();
        for (i, spec) in specs.iter().enumerate() {
            let raw_ptr = out.len() as u32;
            let raw_size = align(spec.data.len() as u32, FILE_ALIGNMENT);
            out.extend_from_slice(&spec.data);
            out.resize((raw_ptr + raw_size) as usize, 0);
            headers.push((
                spec.name,
                spec.virtual_size.unwrap_or(spec.data.len() as u32),
                SECTION_ALIGNMENT * (i as u32 + 1),
                if spec.data.is_empty() { 0 } else { raw_size },
                if spec.data.is_empty() { 0 } else { raw_ptr },
                spec.characteristics,
            ));
        }
        let size_of_image = SECTION_ALIGNMENT * (specs.len() as u32 + 1);

        // Optional header.
        let o = OPT_OFFSET;
        put16(&mut out, o, if self.pe32_plus { 0x20b } else { 0x10b });
        out[o + 2] = 14;
        out[o + 3] = 36;
        put32(&mut out, o + 4, 0x200);
        put32(&mut out, o + 16, self.entry_point);
        put32(&mut out, o + 20, 0x1000);
        if self.pe32_plus {
            put64(&mut out, o + 24, 0x1_4000_0000);
        } else {
            put32(&mut out, o + 24, 0x2000); // BaseOfData
            put32(&mut out, o + 28, 0x40_0000);
        }
        put32(&mut out, o + 32, SECTION_ALIGNMENT);
        put32(&mut out, o + 36, FILE_ALIGNMENT);
        put16(&mut out, o + 40, 6);
        put16(&mut out, o + 48, 6);
        put32(&mut out, o + 56, size_of_image);
        put32(&mut out, o + 60, SIZE_OF_HEADERS);
        put16(&mut out, o + 68, self.subsystem);
        put16(&mut out, o + 70, self.dll_characteristics);
        if self.pe32_plus {
            put64(&mut out, o + 72, 0x10_0000);
            put64(&mut out, o + 80, 0x1000);
            put64(&mut out, o + 88, 0x10_0000);
            put64(&mut out, o + 96, 0x1000);
            put32(&mut out, o + 108, 16);
        } else {
            put32(&mut out, o + 72, 0x10_0000);
            put32(&mut out, o + 76, 0x1000);
            put32(&mut out, o + 80, 0x10_0000);
            put32(&mut out, o + 84, 0x1000);
            put32(&mut out, o + 92, 16);
        }
        if let Some((rva, size)) = resource_dir {
            let at = self.data_directory_offset(2);
            put32(&mut out, at, rva);
            put32(&mut out, at + 4, size);
        }
        if let Some((rva, size)) = debug_dir {
            let at = self.data_directory_offset(6);
            put32(&mut out, at, rva);
            put32(&mut out, at + 4, size);
        }

        // Section table.
        let table = self.section_table_offset();
        for (i, (name, vsize, rva, raw_size, raw_ptr, chars)) in headers.iter().enumerate() {
            let at = table + i * 40;
            out[at..at + 8].copy_from_slice(name);
            put32(&mut out, at + 8, *vsize);
            put32(&mut out, at + 12, *rva);
            put32(&mut out, at + 16, *raw_size);
            put32(&mut out, at + 20, *raw_ptr);
            put32(&mut out, at + 36, *chars);
        }

        if let Some(cert) = &self.certificate {
            pad_to(&mut out, 8);
            let at = out.len() as u32;
            out.extend_from_slice(cert);
            let dir = self.data_directory_offset(4);
            put32(&mut out, dir, at);
            put32(&mut out, dir + 4, cert.len() as u32);
        }
        out.extend_from_slice(&self.overlay);

        if self.valid_checksum {
            let sum = palisade_fileid::pe::compute_checksum(&out, self.checksum_offset()).unwrap();
            let at = self.checksum_offset();
            put32(&mut out, at, sum);
        }
        out
    }

    fn raw_offset_of(&self, specs: &[SectionSpec], index: usize) -> u32 {
        let mut offset = SIZE_OF_HEADERS;
        for spec in specs.iter().take(index) {
            offset += align(spec.data.len() as u32, FILE_ALIGNMENT);
        }
        offset
    }
}

/// A `.rdata` body holding a debug directory (CodeView, then optional REPRO
/// and POGO entries) followed by the RSDS record. Returns the body and the
/// directory size.
fn debug_section(debug: &DebugSpec, rva: u32, file_offset: u32) -> (Vec<u8>, u32) {
    let mut entries = 1;
    if debug.repro {
        entries += 1;
    }
    if debug.pogo {
        entries += 1;
    }
    let dir_size = entries * 28;
    let mut rsds = b"RSDS".to_vec();
    rsds.extend_from_slice(&debug.pdb_guid);
    rsds.extend_from_slice(&debug.pdb_age.to_le_bytes());
    rsds.extend_from_slice(debug.pdb_path.as_bytes());
    rsds.push(0);

    let mut out = vec![0_u8; dir_size as usize];
    let mut write_entry = |slot: usize, kind: u32, size: u32, data_off: u32| {
        let at = slot * 28;
        put32(&mut out, at + 12, kind);
        put32(&mut out, at + 16, size);
        if size != 0 {
            put32(&mut out, at + 20, rva + data_off);
            put32(&mut out, at + 24, file_offset + data_off);
        }
    };
    write_entry(0, 2, rsds.len() as u32, dir_size);
    let mut slot = 1;
    if debug.repro {
        write_entry(slot, 16, 0, 0);
        slot += 1;
    }
    if debug.pogo {
        write_entry(slot, 13, 0, 0);
    }
    out.extend_from_slice(&rsds);
    (out, dir_size)
}

/// A resource section for `leaves`, laid out as a three-level tree (type,
/// name, language) at section RVA `rva`.
pub fn resource_section(rva: u32, leaves: &[Leaf]) -> Vec<u8> {
    let mut tree: BTreeMap<u16, BTreeMap<u16, Vec<(u16, usize)>>> = BTreeMap::new();
    for (i, leaf) in leaves.iter().enumerate() {
        tree.entry(leaf.type_id)
            .or_default()
            .entry(leaf.name_id)
            .or_default()
            .push((leaf.lang, i));
    }
    // Pass 1: sizes and offsets.
    let dir_size = |n: usize| 16 + 8 * n;
    let mut offset = dir_size(tree.len());
    let mut type_dirs = Vec::new();
    for names in tree.values() {
        type_dirs.push(offset);
        offset += dir_size(names.len());
    }
    let mut name_dirs = Vec::new();
    for names in tree.values() {
        for langs in names.values() {
            name_dirs.push(offset);
            offset += dir_size(langs.len());
        }
    }
    let data_entries_start = offset;
    offset += 16 * leaves.len();
    let mut blob_offsets = Vec::new();
    for leaf in leaves {
        offset = offset.div_ceil(8) * 8;
        blob_offsets.push(offset);
        offset += leaf.data.len();
    }
    let mut out = vec![0_u8; offset];

    // Pass 2: write.
    let write_dir = |out: &mut Vec<u8>, at: usize, entries: &[(u32, u32)]| {
        put16(out, at + 14, entries.len() as u16);
        for (i, (id, target)) in entries.iter().enumerate() {
            put32(out, at + 16 + i * 8, *id);
            put32(out, at + 16 + i * 8 + 4, *target);
        }
    };
    let root: Vec<(u32, u32)> = tree
        .keys()
        .zip(&type_dirs)
        .map(|(id, off)| (u32::from(*id), *off as u32 | 0x8000_0000))
        .collect();
    write_dir(&mut out, 0, &root);
    let mut name_index = 0;
    for (names, type_dir) in tree.values().zip(&type_dirs) {
        let mut entries = Vec::new();
        for (name, langs) in names {
            let dir = name_dirs[name_index];
            name_index += 1;
            entries.push((u32::from(*name), dir as u32 | 0x8000_0000));
            let lang_entries: Vec<(u32, u32)> = langs
                .iter()
                .map(|(lang, leaf)| (u32::from(*lang), (data_entries_start + 16 * leaf) as u32))
                .collect();
            write_dir(&mut out, dir, &lang_entries);
        }
        write_dir(&mut out, *type_dir, &entries);
    }
    for (i, leaf) in leaves.iter().enumerate() {
        let at = data_entries_start + 16 * i;
        put32(&mut out, at, rva + blob_offsets[i] as u32);
        put32(&mut out, at + 4, leaf.data.len() as u32);
        put32(&mut out, at + 8, 0);
        let blob = blob_offsets[i];
        out[blob..blob + leaf.data.len()].copy_from_slice(&leaf.data);
    }
    out
}

fn utf16z(text: &str) -> Vec<u8> {
    text.encode_utf16()
        .chain([0])
        .flat_map(u16::to_le_bytes)
        .collect()
}

/// A version-resource block: header, key, value and children, with the
/// standard 4-byte alignment. `value_len` is written to `wValueLength` as
/// given.
pub fn block(
    key: &str,
    value: &[u8],
    value_len: u16,
    w_type: u16,
    children: &[Vec<u8>],
) -> Vec<u8> {
    let mut out = vec![0_u8; 6];
    out.extend(utf16z(key));
    pad_to(&mut out, 4);
    out.extend_from_slice(value);
    for child in children {
        pad_to(&mut out, 4);
        out.extend_from_slice(child);
    }
    let len = out.len() as u16;
    put16(&mut out, 0, len);
    put16(&mut out, 2, value_len);
    put16(&mut out, 4, w_type);
    out
}

/// A `String` block whose value is `value` plus a NUL.
pub fn string(key: &str, value: &str) -> Vec<u8> {
    let encoded = utf16z(value);
    block(key, &encoded, (encoded.len() / 2) as u16, 1, &[])
}

/// A `String` block with an exact raw value (for padding tests).
pub fn string_raw(key: &str, units: &[u16]) -> Vec<u8> {
    let encoded: Vec<u8> = units.iter().flat_map(|u| u.to_le_bytes()).collect();
    block(key, &encoded, units.len() as u16, 1, &[])
}

/// `VS_FIXEDFILEINFO` with the given versions as `(a, b, c, d)` quads.
pub fn fixed_info(file: (u16, u16, u16, u16), product: (u16, u16, u16, u16)) -> Vec<u8> {
    let ms = |v: (u16, u16, u16, u16)| (u32::from(v.0) << 16) | u32::from(v.1);
    let ls = |v: (u16, u16, u16, u16)| (u32::from(v.2) << 16) | u32::from(v.3);
    let words = [
        0xfeef_04bd,
        0x0001_0000,
        ms(file),
        ls(file),
        ms(product),
        ls(product),
        0x3f,
        0,
        0x0004_0004, // VOS_NT_WINDOWS32
        1,           // VFT_APP
        0,
        0,
        0,
    ];
    words.iter().flat_map(|w: &u32| w.to_le_bytes()).collect()
}

/// A complete `VS_VERSIONINFO` resource.
pub struct VersionSpec<'a> {
    pub fixed: Option<Vec<u8>>,
    pub tables: Vec<(&'a str, Vec<Vec<u8>>)>,
    pub translations: Vec<(u16, u16)>,
}

impl VersionSpec<'_> {
    pub fn build(&self) -> Vec<u8> {
        let mut children = Vec::new();
        if !self.tables.is_empty() {
            let tables: Vec<Vec<u8>> = self
                .tables
                .iter()
                .map(|(key, strings)| block(key, &[], 0, 1, strings))
                .collect();
            children.push(block("StringFileInfo", &[], 0, 1, &tables));
        }
        if !self.translations.is_empty() {
            let value: Vec<u8> = self
                .translations
                .iter()
                .flat_map(|(lang, cp)| lang.to_le_bytes().into_iter().chain(cp.to_le_bytes()))
                .collect();
            let var = block("Translation", &value, value.len() as u16, 0, &[]);
            children.push(block("VarFileInfo", &[], 0, 1, &[var]));
        }
        let fixed = self.fixed.clone().unwrap_or_default();
        block("VS_VERSION_INFO", &fixed, fixed.len() as u16, 0, &children)
    }
}

/// Every standard key with a distinct value.
pub fn all_standard_strings() -> Vec<Vec<u8>> {
    vec![
        string("CompanyName", "Example Org"),
        string("FileDescription", "Example tool"),
        string("FileVersion", "1.2.3.4"),
        string("InternalName", "extool"),
        string("LegalCopyright", "(c) Example Org"),
        string("LegalTrademarks", "None"),
        string("OriginalFilename", "extool.exe"),
        string("ProductName", "Example Suite"),
        string("ProductVersion", "1.2.0.0"),
        string("Comments", "Synthetic test fixture"),
        string("PrivateBuild", "pb-7"),
        string("SpecialBuild", "sb-9"),
    ]
}

/// A builder whose image has a version resource.
pub fn with_version(version: &VersionSpec<'_>) -> PeBuilder {
    PeBuilder {
        resources: vec![Leaf {
            type_id: 16,
            name_id: 1,
            lang: 0x0409,
            data: version.build(),
        }],
        ..PeBuilder::default()
    }
}
