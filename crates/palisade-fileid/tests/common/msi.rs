//! A builder for small synthetic Windows Installer packages, used only by
//! tests and fuzz seeds.
//!
//! [`MsiBuilder`] lays out a string pool, `_Tables`, `_Columns`, tables of
//! string and integer columns, extra streams, nested storages and a
//! summary information stream, and [`Cfb`] writes them as a version 3
//! compound file (512-byte sectors, a mini stream for streams under 4096
//! bytes). Directory entries are written as a right-leaning chain of black
//! nodes, which is a valid red-black tree for the format. Everything is
//! deterministic: the same builder calls give the same bytes.

#![allow(
    dead_code,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::unwrap_used
)]

/// `000C1084-0000-0000-C000-000000000046`.
pub const CLSID_DATABASE: [u8; 16] = clsid(0x000c_1084);
/// `000C1086-...`.
pub const CLSID_PATCH: [u8; 16] = clsid(0x000c_1086);
/// `000C1082-...`.
pub const CLSID_TRANSFORM: [u8; 16] = clsid(0x000c_1082);

const fn clsid(first: u32) -> [u8; 16] {
    let b = first.to_le_bytes();
    [
        b[0], b[1], b[2], b[3], 0, 0, 0, 0, 0xc0, 0, 0, 0, 0, 0, 0, 0x46,
    ]
}

const ENDOFCHAIN: u32 = 0xffff_fffe;
const FREESECT: u32 = 0xffff_ffff;
const FATSECT: u32 = 0xffff_fffd;
const NOSTREAM: u32 = 0xffff_ffff;

/// A node of the storage tree.
#[derive(Clone, Debug)]
pub enum Node {
    Stream {
        name: Vec<u16>,
        data: Vec<u8>,
        times: [u8; 16],
    },
    Storage {
        name: Vec<u16>,
        clsid: [u8; 16],
        times: [u8; 16],
        children: Vec<Node>,
    },
}

impl Node {
    pub fn stream(name: &str, data: Vec<u8>) -> Self {
        Self::Stream {
            name: name.encode_utf16().collect(),
            data,
            times: [0; 16],
        }
    }

    pub fn raw_stream(name: Vec<u16>, data: Vec<u8>) -> Self {
        Self::Stream {
            name,
            data,
            times: [0; 16],
        }
    }

    pub fn name(&self) -> &[u16] {
        match self {
            Self::Stream { name, .. } | Self::Storage { name, .. } => name,
        }
    }
}

/// A compound file to write.
#[derive(Clone, Debug)]
pub struct Cfb {
    pub root_clsid: [u8; 16],
    pub children: Vec<Node>,
}

/// Uppercase-then-length order, the format's sibling order.
fn tree_cmp(a: &[u16], b: &[u16]) -> std::cmp::Ordering {
    let up = |n: &[u16]| -> Vec<u16> {
        n.iter()
            .map(|&u| {
                if (u16::from(b'a')..=u16::from(b'z')).contains(&u) {
                    u - 32
                } else {
                    u
                }
            })
            .collect()
    };
    a.len().cmp(&b.len()).then_with(|| up(a).cmp(&up(b)))
}

struct DirEntry {
    name: Vec<u16>,
    kind: u8,
    left: u32,
    right: u32,
    child: u32,
    clsid: [u8; 16],
    times: [u8; 16],
    start: u32,
    size: u64,
}

impl Cfb {
    /// Writes the compound file.
    pub fn build(&self) -> Vec<u8> {
        // Flatten the tree: entry 0 is the root, then each storage's
        // children follow in tree order, depth first.
        let mut entries: Vec<DirEntry> = vec![DirEntry {
            name: "Root Entry".encode_utf16().collect(),
            kind: 5,
            left: NOSTREAM,
            right: NOSTREAM,
            child: NOSTREAM,
            clsid: self.root_clsid,
            times: [0; 16],
            start: ENDOFCHAIN,
            size: 0,
        }];
        let mut data_of: Vec<Option<Vec<u8>>> = vec![None];
        flatten(&self.children, 0, &mut entries, &mut data_of);

        // Lay out data: small streams in the mini stream, big ones in
        // sectors.
        let mut mini = Vec::new();
        let mut minifat: Vec<u32> = Vec::new();
        let mut big: Vec<(usize, Vec<u8>)> = Vec::new();
        for (i, d) in data_of.iter().enumerate() {
            let Some(d) = d else { continue };
            entries[i].size = d.len() as u64;
            if d.is_empty() {
                entries[i].start = ENDOFCHAIN;
            } else if d.len() < 4096 {
                let first = (mini.len() / 64) as u32;
                let n = d.len().div_ceil(64);
                for k in 0..n {
                    minifat.push(if k + 1 == n {
                        ENDOFCHAIN
                    } else {
                        first + k as u32 + 1
                    });
                }
                mini.extend_from_slice(d);
                mini.resize(mini.len().div_ceil(64) * 64, 0);
                entries[i].start = first;
            } else {
                big.push((i, d.clone()));
            }
        }

        // Sectors: [directory][minifat][mini stream][big streams][FAT].
        let mut sectors: Vec<Vec<u8>> = Vec::new();
        let mut fat: Vec<u32> = Vec::new();
        let alloc = |bytes: &[u8], sectors: &mut Vec<Vec<u8>>, fat: &mut Vec<u32>| -> u32 {
            if bytes.is_empty() {
                return ENDOFCHAIN;
            }
            let first = sectors.len() as u32;
            let n = bytes.len().div_ceil(512);
            for k in 0..n {
                let mut s = bytes[k * 512..((k + 1) * 512).min(bytes.len())].to_vec();
                s.resize(512, 0);
                sectors.push(s);
                fat.push(if k + 1 == n {
                    ENDOFCHAIN
                } else {
                    first + k as u32 + 1
                });
            }
            first
        };
        // The directory is written after the start sectors are known, so
        // reserve its sectors now.
        let dir_sectors = (entries.len() * 128).div_ceil(512);
        let dir_start = alloc(&vec![0; dir_sectors * 512], &mut sectors, &mut fat);
        let mut minifat_bytes: Vec<u8> = minifat.iter().flat_map(|v| v.to_le_bytes()).collect();
        if !minifat_bytes.is_empty() {
            minifat_bytes.resize(minifat_bytes.len().div_ceil(512) * 512, 0xff);
        }
        let minifat_count = minifat_bytes.len() / 512;
        let minifat_start = alloc(&minifat_bytes, &mut sectors, &mut fat);
        let mini_start = alloc(&mini, &mut sectors, &mut fat);
        entries[0].start = mini_start;
        entries[0].size = mini.len() as u64;
        for (i, d) in &big {
            entries[*i].start = alloc(d, &mut sectors, &mut fat);
        }
        // FAT sectors: enough to cover every sector including themselves.
        let mut fat_count = 1;
        while (sectors.len() + fat_count) * 4 > fat_count * 512 {
            fat_count += 1;
        }
        assert!(fat_count <= 109, "fixture too large for the header DIFAT");
        let fat_start = sectors.len() as u32;
        for _ in 0..fat_count {
            fat.push(FATSECT);
            sectors.push(vec![0; 512]);
        }
        fat.resize(fat_count * 128, FREESECT);
        for k in 0..fat_count {
            let bytes: Vec<u8> = fat[k * 128..(k + 1) * 128]
                .iter()
                .flat_map(|v| v.to_le_bytes())
                .collect();
            sectors[fat_start as usize + k] = bytes;
        }
        // Now the directory.
        let mut dir = Vec::with_capacity(dir_sectors * 512);
        for e in &entries {
            dir.extend_from_slice(&dir_entry(e));
        }
        dir.resize(dir_sectors * 512, 0);
        for k in 0..dir_sectors {
            sectors[dir_start as usize + k] = dir[k * 512..(k + 1) * 512].to_vec();
        }
        for k in entries.len()..dir_sectors * 4 {
            // Unused entries: all zero but the sibling and child IDs.
            let s = &mut sectors[dir_start as usize + k / 4];
            let off = (k % 4) * 128;
            s[off + 0x44..off + 0x50].fill(0xff);
        }

        let mut out = vec![0_u8; 512];
        out[..8].copy_from_slice(&[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]);
        out[0x18..0x1a].copy_from_slice(&0x3e_u16.to_le_bytes());
        out[0x1a..0x1c].copy_from_slice(&3_u16.to_le_bytes());
        out[0x1c..0x1e].copy_from_slice(&0xfffe_u16.to_le_bytes());
        out[0x1e..0x20].copy_from_slice(&9_u16.to_le_bytes());
        out[0x20..0x22].copy_from_slice(&6_u16.to_le_bytes());
        out[0x2c..0x30].copy_from_slice(&(fat_count as u32).to_le_bytes());
        out[0x30..0x34].copy_from_slice(&dir_start.to_le_bytes());
        out[0x38..0x3c].copy_from_slice(&4096_u32.to_le_bytes());
        out[0x3c..0x40].copy_from_slice(&minifat_start.to_le_bytes());
        out[0x40..0x44].copy_from_slice(&(minifat_count as u32).to_le_bytes());
        out[0x44..0x48].copy_from_slice(&ENDOFCHAIN.to_le_bytes());
        out[0x48..0x4c].copy_from_slice(&0_u32.to_le_bytes());
        for k in 0..109 {
            let v = if k < fat_count {
                fat_start + k as u32
            } else {
                FREESECT
            };
            out[0x4c + 4 * k..0x50 + 4 * k].copy_from_slice(&v.to_le_bytes());
        }
        for s in sectors {
            out.extend_from_slice(&s);
        }
        out
    }
}

fn flatten(
    children: &[Node],
    parent: usize,
    entries: &mut Vec<DirEntry>,
    data_of: &mut Vec<Option<Vec<u8>>>,
) {
    let mut sorted: Vec<&Node> = children.iter().collect();
    sorted.sort_by(|a, b| tree_cmp(a.name(), b.name()));
    let mut prev: Option<usize> = None;
    for node in sorted {
        let id = entries.len();
        match node {
            Node::Stream { name, data, times } => {
                entries.push(DirEntry {
                    name: name.clone(),
                    kind: 2,
                    left: NOSTREAM,
                    right: NOSTREAM,
                    child: NOSTREAM,
                    clsid: [0; 16],
                    times: *times,
                    start: ENDOFCHAIN,
                    size: 0,
                });
                data_of.push(Some(data.clone()));
            }
            Node::Storage {
                name,
                clsid,
                times,
                children,
            } => {
                entries.push(DirEntry {
                    name: name.clone(),
                    kind: 1,
                    left: NOSTREAM,
                    right: NOSTREAM,
                    child: NOSTREAM,
                    clsid: *clsid,
                    times: *times,
                    start: 0,
                    size: 0,
                });
                data_of.push(None);
                flatten(children, id, entries, data_of);
            }
        }
        match prev {
            None => entries[parent].child = id as u32,
            Some(p) => entries[p].right = id as u32,
        }
        prev = Some(id);
    }
}

fn dir_entry(e: &DirEntry) -> [u8; 128] {
    let mut b = [0_u8; 128];
    for (i, u) in e.name.iter().enumerate() {
        b[2 * i..2 * i + 2].copy_from_slice(&u.to_le_bytes());
    }
    b[0x40..0x42].copy_from_slice(&(((e.name.len() + 1) * 2) as u16).to_le_bytes());
    b[0x42] = e.kind;
    b[0x43] = 1; // black
    b[0x44..0x48].copy_from_slice(&e.left.to_le_bytes());
    b[0x48..0x4c].copy_from_slice(&e.right.to_le_bytes());
    b[0x4c..0x50].copy_from_slice(&e.child.to_le_bytes());
    b[0x50..0x60].copy_from_slice(&e.clsid);
    b[0x64..0x74].copy_from_slice(&e.times);
    b[0x74..0x78].copy_from_slice(&e.start.to_le_bytes());
    b[0x78..0x80].copy_from_slice(&e.size.to_le_bytes());
    b
}

// ---------------------------------------------------------------------------
// MSI tables.

/// Column types: a string column of up to `n` characters, nullable or not.
pub const fn str_col(n: u16, nullable: bool) -> u16 {
    0x0d00 | n | if nullable { 0x1000 } else { 0 }
}
/// A primary-key string column of up to `n` characters.
pub const fn key_col(n: u16) -> u16 {
    0x2d00 | n
}
/// A primary-key 2-byte integer column.
pub const KEY_I2: u16 = 0x2502;
/// A 2-byte integer column.
pub const I2: u16 = 0x0502;
/// A nullable 2-byte integer column.
pub const I2_NULL: u16 = 0x1502;
/// A 4-byte integer column.
pub const I4: u16 = 0x0104;
/// A nullable 4-byte integer column.
pub const I4_NULL: u16 = 0x1104;
/// A binary (stream) column.
pub const BINARY: u16 = 0x0900;

/// A cell to write.
#[derive(Clone, Debug)]
pub enum Cell {
    Null,
    Str(String),
    Int(i32),
    /// A binary column with data present (stored as 1).
    Stream,
}

pub fn s(v: &str) -> Cell {
    Cell::Str(v.to_owned())
}

/// A table to write.
#[derive(Clone, Debug)]
pub struct TableSpec {
    pub name: String,
    pub columns: Vec<(String, u16)>,
    pub rows: Vec<Vec<Cell>>,
}

/// Encodes a stream name the way the installer does.
pub fn encode_name(name: &str, table: bool) -> Vec<u16> {
    fn v(c: u16) -> Option<u16> {
        let b = u8::try_from(c).ok()?;
        Some(u16::from(match b {
            b'0'..=b'9' => b - b'0',
            b'A'..=b'Z' => b - b'A' + 10,
            b'a'..=b'z' => b - b'a' + 36,
            b'.' => 62,
            b'_' => 63,
            _ => return None,
        }))
    }
    let mut out = Vec::new();
    if table {
        out.push(0x4840);
    }
    let u: Vec<u16> = name.encode_utf16().collect();
    let mut i = 0;
    while i < u.len() {
        match (v(u[i]), u.get(i + 1).and_then(|&n| v(n))) {
            (Some(a), Some(b)) => {
                out.push(0x3800 + a + (b << 6));
                i += 2;
            }
            (Some(a), None) => {
                out.push(0x4800 + a);
                i += 1;
            }
            _ => {
                out.push(u[i]);
                i += 1;
            }
        }
    }
    out
}

/// A summary information property to write.
#[derive(Clone, Debug)]
pub enum Prop {
    I2(i16),
    I4(i32),
    Str(String),
    Time(u64),
}

/// Builds a summary information stream from `(id, value)` pairs.
pub fn summary_stream(props: &[(u32, Prop)]) -> Vec<u8> {
    let header = 8 + 8 * props.len();
    let mut values = Vec::new();
    let mut table = Vec::new();
    for (id, p) in props {
        table.extend_from_slice(&id.to_le_bytes());
        table.extend_from_slice(&((header + values.len()) as u32).to_le_bytes());
        match p {
            Prop::I2(v) => {
                values.extend_from_slice(&2_u32.to_le_bytes());
                values.extend_from_slice(&v.to_le_bytes());
                values.extend_from_slice(&[0, 0]);
            }
            Prop::I4(v) => {
                values.extend_from_slice(&3_u32.to_le_bytes());
                values.extend_from_slice(&v.to_le_bytes());
            }
            Prop::Str(s) => {
                values.extend_from_slice(&30_u32.to_le_bytes());
                values.extend_from_slice(&((s.len() + 1) as u32).to_le_bytes());
                values.extend_from_slice(s.as_bytes());
                values.push(0);
                values.resize(values.len().div_ceil(4) * 4, 0);
            }
            Prop::Time(t) => {
                values.extend_from_slice(&64_u32.to_le_bytes());
                values.extend_from_slice(&t.to_le_bytes());
            }
        }
    }
    let mut section = Vec::new();
    section.extend_from_slice(&((header + values.len()) as u32).to_le_bytes());
    section.extend_from_slice(&(props.len() as u32).to_le_bytes());
    section.extend_from_slice(&table);
    section.extend_from_slice(&values);
    let mut out = vec![0xfe, 0xff, 0, 0, 6, 1, 2, 0];
    out.extend_from_slice(&[0; 16]);
    out.extend_from_slice(&1_u32.to_le_bytes());
    out.extend_from_slice(&[
        0xe0, 0x85, 0x9f, 0xf2, 0xf9, 0x4f, 0x68, 0x10, 0xab, 0x91, 0x08, 0x00, 0x2b, 0x27, 0xb3,
        0xd9,
    ]);
    out.extend_from_slice(&48_u32.to_le_bytes());
    out.extend_from_slice(&section);
    out
}

/// A synthetic installer package.
#[derive(Clone, Debug)]
pub struct MsiBuilder {
    pub clsid: [u8; 16],
    pub codepage: u16,
    pub tables: Vec<TableSpec>,
    /// Streams in the root, by plain name (encoded as non-table streams).
    pub streams: Vec<(String, Vec<u8>)>,
    /// Raw nodes added to the root as they are.
    pub extra: Vec<Node>,
    pub summary: Option<Vec<(u32, Prop)>>,
    /// Use 3-byte string references.
    pub long_refs: bool,
}

impl Default for MsiBuilder {
    fn default() -> Self {
        Self {
            clsid: CLSID_DATABASE,
            codepage: 1252,
            tables: Vec::new(),
            streams: Vec::new(),
            extra: Vec::new(),
            summary: None,
            long_refs: false,
        }
    }
}

impl MsiBuilder {
    /// A database with a `Property` table holding `props`, and a summary
    /// with a package code and fixed times.
    pub fn product(props: &[(&str, &str)]) -> Self {
        let mut b = Self::default();
        b.table(
            "Property",
            &[("Property", key_col(72)), ("Value", str_col(0, false))],
            props.iter().map(|(k, v)| vec![s(k), s(v)]).collect(),
        );
        b.summary = Some(vec![
            (1, Prop::I2(1252)),
            (2, Prop::Str("Installation Database".into())),
            (3, Prop::Str("Palisade Test Product".into())),
            (4, Prop::Str("Palisade Tests".into())),
            (7, Prop::Str("x64;1033".into())),
            (
                9,
                Prop::Str("{0B7A6E71-5D0A-4C55-9A0E-1E6C2A3B4C5D}".into()),
            ),
            (12, Prop::Time(0x01d9_0000_0000_0000)),
            (13, Prop::Time(0x01d9_0000_0000_0001)),
            (14, Prop::I4(500)),
            (15, Prop::I4(2)),
            (18, Prop::Str("Palisade test builder".into())),
            (19, Prop::I4(2)),
        ]);
        b
    }

    pub fn table(
        &mut self,
        name: &str,
        columns: &[(&str, u16)],
        rows: Vec<Vec<Cell>>,
    ) -> &mut Self {
        self.tables.push(TableSpec {
            name: name.into(),
            columns: columns.iter().map(|(n, t)| ((*n).into(), *t)).collect(),
            rows,
        });
        self
    }

    pub fn stream(&mut self, name: &str, data: Vec<u8>) -> &mut Self {
        self.streams.push((name.into(), data));
        self
    }

    /// Sets (or replaces) a summary property.
    pub fn summary_prop(&mut self, id: u32, value: Prop) -> &mut Self {
        let props = self.summary.get_or_insert_with(Vec::new);
        props.retain(|(i, _)| *i != id);
        props.push((id, value));
        props.sort_by_key(|(i, _)| *i);
        self
    }

    /// The compound file, before writing.
    pub fn cfb(&self) -> Cfb {
        // String pool: every string, in first-use order.
        let mut strings: Vec<String> = Vec::new();
        let id = |s: &str, strings: &mut Vec<String>| -> u32 {
            if let Some(p) = strings.iter().position(|x| x == s) {
                (p + 1) as u32
            } else {
                strings.push(s.to_owned());
                strings.len() as u32
            }
        };
        let mut tables = self.tables.clone();
        // `_Tables` and `_Columns` describe every user table.
        let mut table_rows = Vec::new();
        let mut column_rows = Vec::new();
        for t in &tables {
            table_rows.push(vec![s(&t.name)]);
            for (i, (n, ty)) in t.columns.iter().enumerate() {
                column_rows.push(vec![
                    s(&t.name),
                    Cell::Int(i as i32 + 1),
                    s(n),
                    Cell::Int(i32::from(*ty)),
                ]);
            }
        }
        tables.push(TableSpec {
            name: "_Tables".into(),
            columns: vec![("Name".into(), str_col(64, false))],
            rows: table_rows,
        });
        tables.push(TableSpec {
            name: "_Columns".into(),
            columns: vec![
                ("Table".into(), str_col(64, false)),
                ("Number".into(), I2),
                ("Name".into(), str_col(64, false)),
                ("Type".into(), I2),
            ],
            rows: column_rows,
        });
        let ref_bytes = if self.long_refs { 3 } else { 2 };
        let mut nodes = Vec::new();
        for t in &tables {
            let mut data = Vec::new();
            for (c, (_, ty)) in t.columns.iter().enumerate() {
                let is_binary = ty & !0x1000 == 0x0900;
                let is_string = ty & 0x0800 != 0;
                let width = if is_binary {
                    2
                } else if is_string {
                    ref_bytes
                } else if ty & 0xff == 4 {
                    4
                } else {
                    2
                };
                for row in &t.rows {
                    let raw: u32 = match &row[c] {
                        Cell::Null => 0,
                        Cell::Str(v) => id(v, &mut strings),
                        Cell::Stream => 1,
                        Cell::Int(v) if width == 2 => (*v + 0x8000) as u32,
                        Cell::Int(v) => (*v as u32) ^ 0x8000_0000,
                    };
                    data.extend_from_slice(&raw.to_le_bytes()[..width]);
                }
            }
            nodes.push(Node::raw_stream(encode_name(&t.name, true), data));
        }
        let mut pool = Vec::new();
        pool.extend_from_slice(&self.codepage.to_le_bytes());
        pool.extend_from_slice(&(if self.long_refs { 0x8000_u16 } else { 0 }).to_le_bytes());
        let mut sdata = Vec::new();
        for st in &strings {
            let bytes = st.as_bytes();
            if bytes.len() >= 0x10000 {
                pool.extend_from_slice(&0_u16.to_le_bytes());
                pool.extend_from_slice(&((bytes.len() >> 16) as u16).to_le_bytes());
                pool.extend_from_slice(&(bytes.len() as u16).to_le_bytes());
                pool.extend_from_slice(&1_u16.to_le_bytes());
            } else {
                pool.extend_from_slice(&(bytes.len() as u16).to_le_bytes());
                pool.extend_from_slice(&1_u16.to_le_bytes());
            }
            sdata.extend_from_slice(bytes);
        }
        nodes.push(Node::raw_stream(encode_name("_StringPool", true), pool));
        nodes.push(Node::raw_stream(encode_name("_StringData", true), sdata));
        for (n, d) in &self.streams {
            nodes.push(Node::raw_stream(encode_name(n, false), d.clone()));
        }
        if let Some(props) = &self.summary {
            nodes.push(Node::stream(
                "\u{5}SummaryInformation",
                summary_stream(props),
            ));
        }
        nodes.extend(self.extra.iter().cloned());
        Cfb {
            root_clsid: self.clsid,
            children: nodes,
        }
    }

    pub fn build(&self) -> Vec<u8> {
        self.cfb().build()
    }
}
