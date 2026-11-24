//! The Windows Installer database inside a compound file: stream names,
//! the string pool and the tables.
//!
//! # Stream names
//!
//! Table and stream names are stored compressed: each pair of characters
//! from `[0-9A-Za-z._]` becomes one code unit in U+3800..U+47FF, a single
//! such character one code unit in U+4800..U+483F, and a table's stream
//! name starts with U+4840. [`decode_stream_name`] reverses that, so the
//! `Property` table is the root stream decoded as `"\u{4840}Property"` and
//! the binary stream `Binary.Icon` is decoded as `"Binary.Icon"`.
//!
//! # String pool
//!
//! `_StringPool` holds a header (the codepage, and bit 31 for 3-byte string
//! references), then one `(length, refcount)` pair of 16-bit values per
//! string. `_StringData` holds the strings back to back. A string of 64 KiB
//! or more takes two pairs: a zero length whose refcount is the high word,
//! then the low word. String 0 is the null string.
//!
//! # Tables
//!
//! `_Tables` lists the table names and `_Columns` each table's columns
//! (table, number, name, type). A table stream holds its rows column by
//! column: every row's first column, then every row's second column, and
//! so on. Integers are stored with the sign bit flipped, so 0 is null;
//! strings are references into the pool (2 or 3 bytes), binary columns
//! 2 bytes.
//!
//! Anything inconsistent (a pool that does not cover `_StringData`, a table
//! stream that is not a whole number of rows, a reference past the pool) is
//! an error for that table, never a guess.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fmt;

use super::cfb::{CompoundFile, Entry};

/// The most strings read from a string pool.
pub const MAX_STRINGS: usize = 1 << 22;
/// The most tables read from `_Tables`.
pub const MAX_TABLES: usize = 4096;
/// The most columns a table may have (the Windows Installer limit).
pub const MAX_COLUMNS: usize = 32;

/// Column type bits.
pub(crate) mod column {
    pub const VALID: u16 = 0x0100;
    pub const STRING: u16 = 0x0800;
    pub const NULLABLE: u16 = 0x1000;
}

/// Why a table could not be read.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TableError {
    /// The string pool is missing, or inconsistent with `_StringData`.
    StringPool(&'static str),
    /// `_Tables` or `_Columns` is missing or inconsistent.
    Catalog(&'static str),
    /// The table's stream is not a whole number of rows.
    RowSize {
        /// The table.
        table: String,
    },
    /// A value refers to a string the pool does not have.
    BadStringRef {
        /// The table.
        table: String,
    },
    /// The table lacks a column this crate reads, or has one of another
    /// type.
    Schema {
        /// The table.
        table: String,
        /// The column.
        column: &'static str,
    },
}

impl fmt::Display for TableError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StringPool(why) => write!(f, "string pool: {why}"),
            Self::Catalog(why) => write!(f, "table catalog: {why}"),
            Self::RowSize { table } => write!(f, "table {table}: not a whole number of rows"),
            Self::BadStringRef { table } => write!(f, "table {table}: bad string reference"),
            Self::Schema { table, column } => {
                write!(f, "table {table}: missing or mistyped column {column}")
            }
        }
    }
}

impl std::error::Error for TableError {}

/// Decodes a compressed stream name (see the module documentation).
#[must_use]
pub fn decode_stream_name(name: &[u16]) -> String {
    let mut out = String::with_capacity(name.len().saturating_mul(2));
    let mut push = |u: u32| {
        out.push(char::from_u32(u).unwrap_or(char::REPLACEMENT_CHARACTER));
    };
    for &unit in name {
        let u = u32::from(unit);
        if (0x3800..0x4800).contains(&u) {
            let v = u - 0x3800;
            push(mime_char(v & 0x3f));
            push(mime_char((v >> 6) & 0x3f));
        } else if (0x4800..0x4840).contains(&u) {
            push(mime_char(u - 0x4800));
        } else {
            push(u);
        }
    }
    // Unpaired surrogates (pushed as U+FFFD above, since `char::from_u32`
    // rejects them) are the only lossy case.
    out
}

/// Encodes `name` as a stream name; `table` adds the U+4840 table prefix.
/// The inverse of [`decode_stream_name`] for names made of the encodable
/// characters (and any others, which are kept as they are).
#[must_use]
pub fn encode_stream_name(name: &str, table: bool) -> Vec<u16> {
    let mut out = Vec::new();
    if table {
        out.push(0x4840);
    }
    let units: Vec<u16> = name.encode_utf16().collect();
    let mut i = 0;
    while let Some(&c) = units.get(i) {
        match mime_value(c) {
            Some(a) => match units.get(i + 1).and_then(|&n| mime_value(n)) {
                Some(b) => {
                    out.push(0x3800 + a + (b << 6));
                    i += 2;
                }
                None => {
                    out.push(0x4800 + a);
                    i += 1;
                }
            },
            None => {
                out.push(c);
                i += 1;
            }
        }
    }
    out
}

fn mime_char(v: u32) -> u32 {
    match v {
        0..=9 => u32::from(b'0') + v,
        10..=35 => u32::from(b'A') + v - 10,
        36..=61 => u32::from(b'a') + v - 36,
        62 => u32::from(b'.'),
        _ => u32::from(b'_'),
    }
}

fn mime_value(c: u16) -> Option<u16> {
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

/// The decoded string pool.
#[derive(Debug, Clone, Default)]
pub(crate) struct StringPool {
    /// The codepage from the pool header.
    pub codepage: u32,
    /// Whether string references are 3 bytes.
    pub long_refs: bool,
    /// String `i` (index 0 is the null string and always `None`).
    strings: Vec<Option<String>>,
    /// Whether any string had bytes that do not decode in the codepage.
    pub lossy: bool,
}

impl StringPool {
    fn parse(pool: &[u8], data: &[u8]) -> Result<Self, TableError> {
        if pool.len() % 4 != 0 {
            return Err(TableError::StringPool("pool length"));
        }
        let word = |i: usize| -> u32 {
            pool.get(2 * i..2 * i + 2)
                .and_then(|b| <[u8; 2]>::try_from(b).ok())
                .map_or(0, |b| u32::from(u16::from_le_bytes(b)))
        };
        let count = pool.len() / 4;
        if count > MAX_STRINGS {
            return Err(TableError::StringPool("too many strings"));
        }
        let (codepage, long_refs) = if count > 0 {
            (word(0) | ((word(1) & 0x7fff) << 16), word(1) & 0x8000 != 0)
        } else {
            (0, false)
        };
        let mut strings: Vec<Option<String>> = Vec::with_capacity(count);
        strings.push(None);
        let mut offset = 0_usize;
        let mut lossy = false;
        let mut i = 1;
        while i < count {
            let len_word = word(2 * i);
            let refs = word(2 * i + 1);
            if len_word == 0 && refs == 0 {
                strings.push(None);
                i += 1;
                continue;
            }
            // A string of 64 KiB or more takes two pool entries (a zero
            // length whose refcount is the high word, then the low word),
            // but only one string ID.
            let len = if len_word == 0 {
                if i + 1 >= count {
                    return Err(TableError::StringPool("long string at the end"));
                }
                let len = (refs << 16) | word(2 * i + 2);
                i += 2;
                len
            } else {
                i += 1;
                len_word
            };
            let len = usize::try_from(len).map_err(|_| TableError::StringPool("length"))?;
            let end = offset
                .checked_add(len)
                .filter(|&e| e <= data.len())
                .ok_or(TableError::StringPool("strings run past _StringData"))?;
            let bytes = data
                .get(offset..end)
                .ok_or(TableError::StringPool("strings run past _StringData"))?;
            let (text, was_lossy) = decode(bytes, codepage);
            lossy |= was_lossy;
            strings.push(Some(text));
            offset = end;
        }
        if offset != data.len() {
            return Err(TableError::StringPool(
                "_StringData is longer than the pool",
            ));
        }
        Ok(Self {
            codepage,
            long_refs,
            strings,
            lossy,
        })
    }

    /// String `id`, or `None` for the null string or an unused entry.
    /// `Err` for an ID past the pool.
    pub fn get(&self, id: u32) -> Result<Option<&str>, ()> {
        let i = usize::try_from(id).map_err(|_| ())?;
        match self.strings.get(i) {
            Some(s) => Ok(s.as_deref()),
            None if id == 0 => Ok(None),
            None => Err(()),
        }
    }

    fn id_of(&self, text: &str) -> Option<u32> {
        self.strings
            .iter()
            .position(|s| s.as_deref() == Some(text))
            .and_then(|i| u32::try_from(i).ok())
    }

    fn ref_bytes(&self) -> usize {
        if self.long_refs { 3 } else { 2 }
    }
}

/// Decodes `bytes` in `codepage`: UTF-8 for 65001, the single-byte
/// Windows-1252 mapping for 0 (the neutral codepage) and 1252, and for any
/// other codepage only ASCII (other bytes become U+FFFD and the result is
/// flagged lossy).
pub(crate) fn decode(bytes: &[u8], codepage: u32) -> (String, bool) {
    match codepage {
        65001 => match std::str::from_utf8(bytes) {
            Ok(s) => (s.to_owned(), false),
            Err(_) => (String::from_utf8_lossy(bytes).into_owned(), true),
        },
        0 | 1252 => {
            let mut lossy = false;
            let s = bytes
                .iter()
                .map(|&b| {
                    let c = cp1252(b);
                    lossy |= c == char::REPLACEMENT_CHARACTER;
                    c
                })
                .collect();
            (s, lossy)
        }
        _ => {
            let mut lossy = false;
            let s = bytes
                .iter()
                .map(|&b| {
                    if b.is_ascii() {
                        char::from(b)
                    } else {
                        lossy = true;
                        char::REPLACEMENT_CHARACTER
                    }
                })
                .collect();
            (s, lossy)
        }
    }
}

fn cp1252(b: u8) -> char {
    const HIGH: [u16; 32] = [
        0x20ac, 0xfffd, 0x201a, 0x0192, 0x201e, 0x2026, 0x2020, 0x2021, 0x02c6, 0x2030, 0x0160,
        0x2039, 0x0152, 0xfffd, 0x017d, 0xfffd, 0xfffd, 0x2018, 0x2019, 0x201c, 0x201d, 0x2022,
        0x2013, 0x2014, 0x02dc, 0x2122, 0x0161, 0x203a, 0x0153, 0xfffd, 0x017e, 0x0178,
    ];
    match b {
        0x80..=0x9f => HIGH
            .get(usize::from(b - 0x80))
            .and_then(|&u| char::from_u32(u32::from(u)))
            .unwrap_or(char::REPLACEMENT_CHARACTER),
        _ => char::from(b),
    }
}

/// One column of a table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Column {
    pub name: String,
    pub ty: u16,
}

impl Column {
    fn width(&self, ref_bytes: usize) -> Option<usize> {
        if self.ty & !column::NULLABLE == column::STRING | column::VALID {
            // A binary (stream) column.
            return Some(2);
        }
        if self.ty & column::STRING != 0 {
            return Some(ref_bytes);
        }
        match self.ty & 0xff {
            0..=2 => Some(2),
            4 => Some(4),
            _ => None,
        }
    }

    fn is_string(&self) -> bool {
        self.ty & column::STRING != 0
    }
}

/// A cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Value {
    /// Null.
    Null,
    /// An integer.
    Int(i32),
    /// A string-pool reference.
    Str(u32),
    /// A binary column's marker (the data is a stream).
    Stream,
}

/// A decoded table.
#[derive(Debug, Clone)]
pub(crate) struct Table {
    pub name: String,
    pub columns: Vec<Column>,
    pub rows: Vec<Vec<Value>>,
}

impl Table {
    /// The index of the column called `name`.
    pub fn column(&self, name: &str) -> Option<usize> {
        self.columns.iter().position(|c| c.name == name)
    }

    /// The index of a column called `name` that is a string column, or a
    /// schema error.
    pub fn string_column(&self, name: &'static str) -> Result<usize, TableError> {
        self.column(name)
            .filter(|&i| self.columns.get(i).is_some_and(Column::is_string))
            .ok_or_else(|| TableError::Schema {
                table: self.name.clone(),
                column: name,
            })
    }

    /// The index of a column called `name` that is an integer column, or a
    /// schema error.
    pub fn int_column(&self, name: &'static str) -> Result<usize, TableError> {
        self.column(name)
            .filter(|&i| self.columns.get(i).is_some_and(|c| !c.is_string()))
            .ok_or_else(|| TableError::Schema {
                table: self.name.clone(),
                column: name,
            })
    }
}

/// A Windows Installer database: the compound file, its streams by decoded
/// name, the string pool and the table list.
#[derive(Debug)]
pub(crate) struct Database<'a> {
    pub cf: CompoundFile<'a>,
    /// Root streams, by decoded name.
    pub streams: BTreeMap<String, &'a Entry>,
    pub strings: Result<StringPool, TableError>,
    /// `_Tables`, in stored order. Empty when it could not be read.
    pub table_names: Vec<String>,
    /// Why the table catalog could not be read, if it could not.
    pub catalog_error: Option<TableError>,
}

/// Which stream name is a table's.
fn table_stream(name: &str) -> String {
    let mut s = String::from('\u{4840}');
    s.push_str(name);
    s
}

impl<'a> Database<'a> {
    pub fn open(cf: CompoundFile<'a>, root: &'a Entry) -> Self {
        let mut streams = BTreeMap::new();
        for child in &root.children {
            if !child.is_storage {
                streams.insert(decode_stream_name(&child.name), child);
            }
        }
        let mut db = Self {
            cf,
            streams,
            strings: Err(TableError::StringPool("not read")),
            table_names: Vec::new(),
            catalog_error: None,
        };
        db.strings = db.load_strings();
        match db.load_table_names() {
            Ok(names) => db.table_names = names,
            Err(e) => db.catalog_error = Some(e),
        }
        db
    }

    pub fn stream_bytes(&self, name: &str) -> Option<Vec<u8>> {
        self.streams.get(name).map(|e| self.cf.stream(e))
    }

    fn load_strings(&self) -> Result<StringPool, TableError> {
        let pool = self
            .stream_bytes(&table_stream("_StringPool"))
            .ok_or(TableError::StringPool("no _StringPool"))?;
        let data = self
            .stream_bytes(&table_stream("_StringData"))
            .ok_or(TableError::StringPool("no _StringData"))?;
        StringPool::parse(&pool, &data)
    }

    fn pool(&self) -> Result<&StringPool, TableError> {
        self.strings.as_ref().map_err(Clone::clone)
    }

    fn load_table_names(&self) -> Result<Vec<String>, TableError> {
        let tables = self.read_raw(
            "_Tables",
            &[Column {
                name: "Name".into(),
                ty: column::VALID | column::STRING | 64,
            }],
        )?;
        let pool = self.pool()?;
        let mut names = Vec::with_capacity(tables.rows.len());
        for row in &tables.rows {
            match row.first() {
                Some(Value::Str(id)) => match pool.get(*id) {
                    Ok(Some(s)) => names.push(s.to_owned()),
                    _ => return Err(TableError::Catalog("_Tables names a bad string")),
                },
                _ => return Err(TableError::Catalog("_Tables has a null name")),
            }
            if names.len() > MAX_TABLES {
                return Err(TableError::Catalog("too many tables"));
            }
        }
        Ok(names)
    }

    /// Whether `_Tables` lists `name`.
    pub fn has_table(&self, name: &str) -> bool {
        self.table_names.iter().any(|t| t == name)
    }

    /// The columns of `table`, from `_Columns`, in number order.
    fn columns(&self, table: &str) -> Result<Vec<Column>, TableError> {
        let catalog = self.read_raw(
            "_Columns",
            &[
                Column {
                    name: "Table".into(),
                    ty: column::VALID | column::STRING | 64,
                },
                Column {
                    name: "Number".into(),
                    ty: column::VALID | 2,
                },
                Column {
                    name: "Name".into(),
                    ty: column::VALID | column::STRING | 64,
                },
                Column {
                    name: "Type".into(),
                    ty: column::VALID | 2,
                },
            ],
        )?;
        let pool = self.pool()?;
        let Some(table_id) = pool.id_of(table) else {
            return Err(TableError::Catalog("table name not in the string pool"));
        };
        let mut found: BTreeMap<i32, Column> = BTreeMap::new();
        for row in &catalog.rows {
            let (Some(Value::Str(t)), Some(&number), Some(&name), Some(&ty)) =
                (row.first(), row.get(1), row.get(2), row.get(3))
            else {
                continue;
            };
            if *t != table_id {
                continue;
            }
            let (Value::Int(number), Value::Str(name), Value::Int(ty)) = (number, name, ty) else {
                return Err(TableError::Catalog("_Columns row with a null field"));
            };
            let name = match pool.get(name) {
                Ok(Some(s)) => s.to_owned(),
                _ => return Err(TableError::Catalog("_Columns names a bad string")),
            };
            let ty = u16::try_from(ty).map_err(|_| TableError::Catalog("column type"))?;
            if found.insert(number, Column { name, ty }).is_some() {
                return Err(TableError::Catalog("duplicate column number"));
            }
        }
        // Numbers must run 1..=n.
        if found.len() > MAX_COLUMNS
            || found
                .keys()
                .enumerate()
                .any(|(i, &n)| usize::try_from(n) != Ok(i + 1))
        {
            return Err(TableError::Catalog("column numbers"));
        }
        if found.is_empty() {
            return Err(TableError::Catalog("table has no columns"));
        }
        Ok(found.into_values().collect())
    }

    /// Reads `table`, or `Ok(None)` if `_Tables` does not list it.
    pub fn table(&self, table: &str) -> Result<Option<Table>, TableError> {
        if let Some(e) = &self.catalog_error {
            return Err(e.clone());
        }
        if !self.has_table(table) {
            return Ok(None);
        }
        let columns = self.columns(table)?;
        self.read_raw(table, &columns).map(Some)
    }

    fn read_raw(&self, table: &str, columns: &[Column]) -> Result<Table, TableError> {
        let pool = self.pool()?;
        let ref_bytes = pool.ref_bytes();
        let widths: Vec<usize> = columns
            .iter()
            .map(|c| c.width(ref_bytes))
            .collect::<Option<_>>()
            .ok_or_else(|| TableError::Schema {
                table: table.to_owned(),
                column: "width",
            })?;
        let row_size: usize = widths.iter().sum();
        // A table the catalog lists but with no stream is empty.
        let data = self.stream_bytes(&table_stream(table)).unwrap_or_default();
        if row_size == 0 || data.len() % row_size != 0 {
            return Err(TableError::RowSize {
                table: table.to_owned(),
            });
        }
        let rows = data.len() / row_size;
        let mut out = vec![Vec::with_capacity(columns.len()); rows];
        let mut base = 0_usize;
        for (col, &width) in columns.iter().zip(&widths) {
            for (i, row) in out.iter_mut().enumerate() {
                let at = base + i * width;
                let raw = data
                    .get(at..at + width)
                    .map(|b| {
                        b.iter()
                            .rev()
                            .fold(0_u32, |acc, &x| (acc << 8) | u32::from(x))
                    })
                    .unwrap_or(0);
                let value = if col.ty & !column::NULLABLE == column::STRING | column::VALID {
                    if raw == 0 { Value::Null } else { Value::Stream }
                } else if col.is_string() {
                    if raw == 0 {
                        Value::Null
                    } else {
                        if pool.get(raw).is_err() {
                            return Err(TableError::BadStringRef {
                                table: table.to_owned(),
                            });
                        }
                        Value::Str(raw)
                    }
                } else if raw == 0 {
                    Value::Null
                } else if width == 2 {
                    // Stored as the value plus 0x8000.
                    Value::Int(i32::try_from(raw).unwrap_or(0) - 0x8000)
                } else {
                    Value::Int(i32::from_ne_bytes((raw ^ 0x8000_0000).to_ne_bytes()))
                };
                row.push(value);
            }
            base += width * rows;
        }
        Ok(Table {
            name: table.to_owned(),
            columns: columns.to_vec(),
            rows: out,
        })
    }

    /// The text of a string cell, `None` for null.
    pub fn text(&self, value: Value) -> Option<&str> {
        match value {
            Value::Str(id) => self.strings.as_ref().ok()?.get(id).ok().flatten(),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_names_round_trip() {
        for (name, table) in [
            ("_StringPool", true),
            ("Property", true),
            ("Binary.Icon_1", false),
            ("a", false),
            ("ab", false),
            ("Media.cab", false),
        ] {
            let encoded = encode_stream_name(name, table);
            let decoded = decode_stream_name(&encoded);
            let expected = if table {
                format!("\u{4840}{name}")
            } else {
                name.to_owned()
            };
            assert_eq!(decoded, expected);
        }
        // Two characters per unit.
        assert_eq!(encode_stream_name("ab", false).len(), 1);
        // A character outside the alphabet is kept.
        assert_eq!(decode_stream_name(&encode_stream_name("a-b", false)), "a-b");
    }

    #[test]
    fn string_pool_decodes_short_and_long_entries() {
        let mut pool = Vec::new();
        pool.extend_from_slice(&1252_u16.to_le_bytes());
        pool.extend_from_slice(&0_u16.to_le_bytes());
        // String 1: "abc".
        pool.extend_from_slice(&3_u16.to_le_bytes());
        pool.extend_from_slice(&1_u16.to_le_bytes());
        // String 2: unused.
        pool.extend_from_slice(&[0, 0, 0, 0]);
        let data = b"abc".to_vec();
        let p = StringPool::parse(&pool, &data).unwrap();
        assert_eq!(p.get(1), Ok(Some("abc")));
        assert_eq!(p.get(2), Ok(None));
        assert_eq!(p.get(0), Ok(None));
        assert!(p.get(9).is_err());
        assert!(!p.long_refs);

        // A pool that does not cover all of the data is rejected.
        assert!(StringPool::parse(&pool, b"abcd").is_err());
        // One that runs past it, too.
        assert!(StringPool::parse(&pool, b"ab").is_err());
    }

    #[test]
    fn cp1252_maps_the_high_range() {
        assert_eq!(decode(&[0x80, b'a'], 1252), ("\u{20ac}a".to_owned(), false));
        assert!(decode(&[0x81], 0).1);
        assert_eq!(decode(&[0xe9], 932), ("\u{fffd}".to_owned(), true));
        assert_eq!(decode("é".as_bytes(), 65001), ("é".to_owned(), false));
    }
}
