//! Writes a serializable value as block-style YAML that every YAML 1.1 and
//! 1.2 reader types the same way.
//!
//! A string is written plain (unquoted) only when it is made of a small set
//! of ASCII characters and [`resolve_plain`] reads it back as the same
//! text. Everything else is double-quoted, with escapes for every character
//! that is not printable or that some readers treat as a line break.

use core::fmt;
use core::fmt::Write as _;

use serde::Serialize;
use serde::ser::{self, Impossible};

use super::parse::{Value, resolve_plain};

/// The serialized form, before it is written as text.
enum Out {
    Null,
    Bool(bool),
    /// An integer, already written in decimal.
    Int(String),
    Str(String),
    Seq(Vec<Out>),
    Map(Vec<(String, Out)>),
}

/// A value could not be written as policy YAML.
#[derive(Debug)]
pub struct WriteError(String);

impl fmt::Display for WriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for WriteError {}

impl ser::Error for WriteError {
    fn custom<T: fmt::Display>(msg: T) -> Self {
        Self(msg.to_string())
    }
}

/// Serializes `value` and writes it as YAML text after `header`.
pub(crate) fn to_string<T: Serialize + ?Sized>(
    value: &T,
    header: &str,
) -> Result<String, WriteError> {
    let out = value.serialize(Serializer)?;
    let mut text = String::from(header);
    match out {
        Out::Map(entries) if !entries.is_empty() => write_map(&mut text, &entries, 0, None),
        Out::Seq(items) if !items.is_empty() => write_seq(&mut text, &items, 0),
        scalar => {
            write_scalar(&mut text, &scalar);
            text.push('\n');
        }
    }
    Ok(text)
}

fn indent(text: &mut String, n: usize) {
    text.extend(core::iter::repeat_n(' ', n));
}

/// Writes map entries at `level`. With `lead`, the first entry goes on the
/// current line after it (a map inside a sequence item).
fn write_map(text: &mut String, entries: &[(String, Out)], level: usize, lead: Option<&str>) {
    for (i, (key, value)) in entries.iter().enumerate() {
        match lead {
            Some(lead) if i == 0 => text.push_str(lead),
            _ => indent(text, level),
        }
        write_str(text, key);
        text.push(':');
        write_value(text, value, level + 2);
    }
}

fn write_seq(text: &mut String, items: &[Out], level: usize) {
    for item in items {
        indent(text, level);
        match item {
            Out::Map(entries) if !entries.is_empty() => {
                write_map(text, entries, level + 2, Some("- "));
            }
            _ => {
                text.push('-');
                write_value(text, item, level + 2);
            }
        }
    }
}

/// Writes what follows `key:` or `-`: a scalar on the same line, or a block
/// collection on the next lines at `level`.
fn write_value(text: &mut String, value: &Out, level: usize) {
    match value {
        Out::Map(entries) if !entries.is_empty() => {
            text.push('\n');
            write_map(text, entries, level, None);
        }
        Out::Seq(items) if !items.is_empty() => {
            text.push('\n');
            write_seq(text, items, level);
        }
        _ => {
            text.push(' ');
            write_scalar(text, value);
            text.push('\n');
        }
    }
}

fn write_scalar(text: &mut String, value: &Out) {
    match value {
        Out::Null => text.push_str("null"),
        Out::Bool(b) => text.push_str(if *b { "true" } else { "false" }),
        Out::Int(n) => text.push_str(n),
        Out::Str(s) => write_str(text, s),
        Out::Seq(_) => text.push_str("[]"),
        Out::Map(_) => text.push_str("{}"),
    }
}

/// Whether `s` can be written without quotes.
///
/// Text made only of digits and the characters of numbers, dates and times
/// (`1.0.0`, `2027-06-30`, `12:30`) is always quoted: the YAML 1.1 type
/// definitions read some of these as floats, timestamps or base-60 numbers.
fn is_plain_safe(s: &str) -> bool {
    let mut chars = s.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    let number_like = s
        .chars()
        .all(|c| c.is_ascii_digit() || matches!(c, '.' | '_' | '-' | '+' | ':' | 'e' | 'E'))
        && first.is_ascii_digit();
    (first.is_ascii_alphanumeric() || matches!(first, '_' | '/' | '\\' | '('))
        && !number_like
        && !s.ends_with(' ')
        && chars.all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(
                    c,
                    ' ' | '_' | '.' | '-' | '/' | '\\' | '(' | ')' | '+' | '=' | '%'
                )
        })
        && matches!(resolve_plain(s), Ok(Value::Str(ref t)) if t == s)
}

fn write_str(text: &mut String, s: &str) {
    if is_plain_safe(s) {
        text.push_str(s);
        return;
    }
    text.push('"');
    for c in s.chars() {
        match c {
            '"' => text.push_str("\\\""),
            '\\' => text.push_str("\\\\"),
            '\n' => text.push_str("\\n"),
            '\t' => text.push_str("\\t"),
            '\r' => text.push_str("\\r"),
            // Not printable in YAML, or a line break or byte order mark to
            // some readers.
            '\u{0}'..='\u{1f}'
            | '\u{7f}'..='\u{9f}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{feff}'
            | '\u{fffe}'
            | '\u{ffff}' => {
                let _ = write!(text, "\\u{:04X}", u32::from(c));
            }
            c => text.push(c),
        }
    }
    text.push('"');
}

struct Serializer;

fn unsupported(what: &str) -> WriteError {
    WriteError(format!("{what} cannot be written as policy YAML"))
}

impl ser::Serializer for Serializer {
    type Ok = Out;
    type Error = WriteError;
    type SerializeSeq = SeqSer;
    type SerializeTuple = SeqSer;
    type SerializeTupleStruct = SeqSer;
    type SerializeTupleVariant = VariantSer<SeqSer>;
    type SerializeMap = MapSer;
    type SerializeStruct = MapSer;
    type SerializeStructVariant = VariantSer<MapSer>;

    fn serialize_bool(self, v: bool) -> Result<Out, WriteError> {
        Ok(Out::Bool(v))
    }
    fn serialize_i8(self, v: i8) -> Result<Out, WriteError> {
        self.serialize_i64(v.into())
    }
    fn serialize_i16(self, v: i16) -> Result<Out, WriteError> {
        self.serialize_i64(v.into())
    }
    fn serialize_i32(self, v: i32) -> Result<Out, WriteError> {
        self.serialize_i64(v.into())
    }
    fn serialize_i64(self, v: i64) -> Result<Out, WriteError> {
        Ok(Out::Int(v.to_string()))
    }
    fn serialize_u8(self, v: u8) -> Result<Out, WriteError> {
        self.serialize_u64(v.into())
    }
    fn serialize_u16(self, v: u16) -> Result<Out, WriteError> {
        self.serialize_u64(v.into())
    }
    fn serialize_u32(self, v: u32) -> Result<Out, WriteError> {
        self.serialize_u64(v.into())
    }
    fn serialize_u64(self, v: u64) -> Result<Out, WriteError> {
        Ok(Out::Int(v.to_string()))
    }
    fn serialize_f32(self, _v: f32) -> Result<Out, WriteError> {
        Err(unsupported("a floating-point number"))
    }
    fn serialize_f64(self, _v: f64) -> Result<Out, WriteError> {
        Err(unsupported("a floating-point number"))
    }
    fn serialize_char(self, v: char) -> Result<Out, WriteError> {
        Ok(Out::Str(v.to_string()))
    }
    fn serialize_str(self, v: &str) -> Result<Out, WriteError> {
        Ok(Out::Str(v.to_owned()))
    }
    fn serialize_bytes(self, _v: &[u8]) -> Result<Out, WriteError> {
        Err(unsupported("a byte string"))
    }
    fn serialize_none(self) -> Result<Out, WriteError> {
        Ok(Out::Null)
    }
    fn serialize_some<T: Serialize + ?Sized>(self, value: &T) -> Result<Out, WriteError> {
        value.serialize(self)
    }
    fn serialize_unit(self) -> Result<Out, WriteError> {
        Ok(Out::Null)
    }
    fn serialize_unit_struct(self, _name: &'static str) -> Result<Out, WriteError> {
        Ok(Out::Null)
    }
    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
    ) -> Result<Out, WriteError> {
        Ok(Out::Str(variant.to_owned()))
    }
    fn serialize_newtype_struct<T: Serialize + ?Sized>(
        self,
        _name: &'static str,
        value: &T,
    ) -> Result<Out, WriteError> {
        value.serialize(self)
    }
    fn serialize_newtype_variant<T: Serialize + ?Sized>(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
        value: &T,
    ) -> Result<Out, WriteError> {
        Ok(Out::Map(vec![(variant.to_owned(), value.serialize(self)?)]))
    }
    fn serialize_seq(self, len: Option<usize>) -> Result<SeqSer, WriteError> {
        Ok(SeqSer(Vec::with_capacity(len.unwrap_or(0))))
    }
    fn serialize_tuple(self, len: usize) -> Result<SeqSer, WriteError> {
        self.serialize_seq(Some(len))
    }
    fn serialize_tuple_struct(self, _name: &'static str, len: usize) -> Result<SeqSer, WriteError> {
        self.serialize_seq(Some(len))
    }
    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<VariantSer<SeqSer>, WriteError> {
        Ok(VariantSer {
            variant,
            inner: SeqSer(Vec::with_capacity(len)),
        })
    }
    fn serialize_map(self, _len: Option<usize>) -> Result<MapSer, WriteError> {
        Ok(MapSer {
            entries: Vec::new(),
            key: None,
        })
    }
    fn serialize_struct(self, _name: &'static str, _len: usize) -> Result<MapSer, WriteError> {
        self.serialize_map(None)
    }
    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
        _len: usize,
    ) -> Result<VariantSer<MapSer>, WriteError> {
        Ok(VariantSer {
            variant,
            inner: MapSer {
                entries: Vec::new(),
                key: None,
            },
        })
    }
}

struct SeqSer(Vec<Out>);

impl ser::SerializeSeq for SeqSer {
    type Ok = Out;
    type Error = WriteError;
    fn serialize_element<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), WriteError> {
        self.0.push(value.serialize(Serializer)?);
        Ok(())
    }
    fn end(self) -> Result<Out, WriteError> {
        Ok(Out::Seq(self.0))
    }
}

impl ser::SerializeTuple for SeqSer {
    type Ok = Out;
    type Error = WriteError;
    fn serialize_element<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), WriteError> {
        ser::SerializeSeq::serialize_element(self, value)
    }
    fn end(self) -> Result<Out, WriteError> {
        ser::SerializeSeq::end(self)
    }
}

impl ser::SerializeTupleStruct for SeqSer {
    type Ok = Out;
    type Error = WriteError;
    fn serialize_field<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), WriteError> {
        ser::SerializeSeq::serialize_element(self, value)
    }
    fn end(self) -> Result<Out, WriteError> {
        ser::SerializeSeq::end(self)
    }
}

struct MapSer {
    entries: Vec<(String, Out)>,
    key: Option<String>,
}

impl ser::SerializeMap for MapSer {
    type Ok = Out;
    type Error = WriteError;
    fn serialize_key<T: Serialize + ?Sized>(&mut self, key: &T) -> Result<(), WriteError> {
        self.key = Some(key.serialize(KeySer)?);
        Ok(())
    }
    fn serialize_value<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), WriteError> {
        let key = self
            .key
            .take()
            .ok_or_else(|| WriteError("a map value was written before its key".to_owned()))?;
        // The model's maps are `BTreeMap`s, so keys are already unique.
        self.entries.push((key, value.serialize(Serializer)?));
        Ok(())
    }
    fn end(self) -> Result<Out, WriteError> {
        Ok(Out::Map(self.entries))
    }
}

impl ser::SerializeStruct for MapSer {
    type Ok = Out;
    type Error = WriteError;
    fn serialize_field<T: Serialize + ?Sized>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), WriteError> {
        self.entries
            .push((key.to_owned(), value.serialize(Serializer)?));
        Ok(())
    }
    fn end(self) -> Result<Out, WriteError> {
        Ok(Out::Map(self.entries))
    }
}

/// An enum variant with content, written as `{variant: content}`.
struct VariantSer<T> {
    variant: &'static str,
    inner: T,
}

impl ser::SerializeTupleVariant for VariantSer<SeqSer> {
    type Ok = Out;
    type Error = WriteError;
    fn serialize_field<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), WriteError> {
        ser::SerializeSeq::serialize_element(&mut self.inner, value)
    }
    fn end(self) -> Result<Out, WriteError> {
        Ok(Out::Map(vec![(
            self.variant.to_owned(),
            Out::Seq(self.inner.0),
        )]))
    }
}

impl ser::SerializeStructVariant for VariantSer<MapSer> {
    type Ok = Out;
    type Error = WriteError;
    fn serialize_field<T: Serialize + ?Sized>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), WriteError> {
        ser::SerializeStruct::serialize_field(&mut self.inner, key, value)
    }
    fn end(self) -> Result<Out, WriteError> {
        Ok(Out::Map(vec![(
            self.variant.to_owned(),
            Out::Map(self.inner.entries),
        )]))
    }
}

/// Serializes a map key, which must be text.
struct KeySer;

fn key_error() -> WriteError {
    WriteError("map keys must be text".to_owned())
}

impl ser::Serializer for KeySer {
    type Ok = String;
    type Error = WriteError;
    type SerializeSeq = Impossible<String, WriteError>;
    type SerializeTuple = Impossible<String, WriteError>;
    type SerializeTupleStruct = Impossible<String, WriteError>;
    type SerializeTupleVariant = Impossible<String, WriteError>;
    type SerializeMap = Impossible<String, WriteError>;
    type SerializeStruct = Impossible<String, WriteError>;
    type SerializeStructVariant = Impossible<String, WriteError>;

    fn serialize_str(self, v: &str) -> Result<String, WriteError> {
        Ok(v.to_owned())
    }
    fn serialize_char(self, v: char) -> Result<String, WriteError> {
        Ok(v.to_string())
    }
    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
    ) -> Result<String, WriteError> {
        Ok(variant.to_owned())
    }
    fn serialize_newtype_struct<T: Serialize + ?Sized>(
        self,
        _name: &'static str,
        value: &T,
    ) -> Result<String, WriteError> {
        value.serialize(self)
    }
    fn serialize_bool(self, _v: bool) -> Result<String, WriteError> {
        Err(key_error())
    }
    fn serialize_i8(self, _v: i8) -> Result<String, WriteError> {
        Err(key_error())
    }
    fn serialize_i16(self, _v: i16) -> Result<String, WriteError> {
        Err(key_error())
    }
    fn serialize_i32(self, _v: i32) -> Result<String, WriteError> {
        Err(key_error())
    }
    fn serialize_i64(self, _v: i64) -> Result<String, WriteError> {
        Err(key_error())
    }
    fn serialize_u8(self, _v: u8) -> Result<String, WriteError> {
        Err(key_error())
    }
    fn serialize_u16(self, _v: u16) -> Result<String, WriteError> {
        Err(key_error())
    }
    fn serialize_u32(self, _v: u32) -> Result<String, WriteError> {
        Err(key_error())
    }
    fn serialize_u64(self, _v: u64) -> Result<String, WriteError> {
        Err(key_error())
    }
    fn serialize_f32(self, _v: f32) -> Result<String, WriteError> {
        Err(key_error())
    }
    fn serialize_f64(self, _v: f64) -> Result<String, WriteError> {
        Err(key_error())
    }
    fn serialize_bytes(self, _v: &[u8]) -> Result<String, WriteError> {
        Err(key_error())
    }
    fn serialize_none(self) -> Result<String, WriteError> {
        Err(key_error())
    }
    fn serialize_some<T: Serialize + ?Sized>(self, _value: &T) -> Result<String, WriteError> {
        Err(key_error())
    }
    fn serialize_unit(self) -> Result<String, WriteError> {
        Err(key_error())
    }
    fn serialize_unit_struct(self, _name: &'static str) -> Result<String, WriteError> {
        Err(key_error())
    }
    fn serialize_newtype_variant<T: Serialize + ?Sized>(
        self,
        _name: &'static str,
        _index: u32,
        _variant: &'static str,
        _value: &T,
    ) -> Result<String, WriteError> {
        Err(key_error())
    }
    fn serialize_seq(self, _len: Option<usize>) -> Result<Self::SerializeSeq, WriteError> {
        Err(key_error())
    }
    fn serialize_tuple(self, _len: usize) -> Result<Self::SerializeTuple, WriteError> {
        Err(key_error())
    }
    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleStruct, WriteError> {
        Err(key_error())
    }
    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleVariant, WriteError> {
        Err(key_error())
    }
    fn serialize_map(self, _len: Option<usize>) -> Result<Self::SerializeMap, WriteError> {
        Err(key_error())
    }
    fn serialize_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStruct, WriteError> {
        Err(key_error())
    }
    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStructVariant, WriteError> {
        Err(key_error())
    }
}
