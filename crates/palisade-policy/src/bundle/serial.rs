//! The policy model through serde, as canonical CBOR values (#43).
//!
//! [`to_value`] writes any `Serialize` model type as a [`Value`], and
//! [`from_value`] reads it back with the type's own `Deserialize`, so the
//! bundle reuses the model's strict readers (unknown fields, duplicate
//! keys, `null` handling) rather than a second copy of them.
//!
//! The mapping:
//!
//! - a struct is a map whose keys are the [registry](super::keys) IDs of
//!   its field names. A field name that is not registered cannot be
//!   written ([`Error::UnregisteredKey`]), so a field added to the model
//!   without a key fails loudly instead of being dropped;
//! - a unit variant is its registered ID; a newtype, tuple or struct
//!   variant is a one-entry map from its ID to its content. Internally
//!   tagged enums (an action's `type`) keep their tag as text, as serde
//!   writes it;
//! - strings are written in Unicode Normalization Form C. Matching already
//!   compares text after NFC ([`crate::ops`]), so this changes no
//!   decision;
//! - floating point is refused ([`Error::Float`]); the model has none;
//! - governance metadata is refused by type ([`Error::ServerOnly`]), as
//!   well as having no keys;
//! - maps of data (such as `mode_by_type`) keep their own keys.
//!
//! An internally tagged or untagged enum is buffered by serde before it is
//! read, and a unit variant inside the buffer arrives as an integer that
//! serde cannot match to a name. Such enums may hold only fields that are
//! not enums; `Action`, the one internally tagged enum in a policy
//! document, has its own reader and is not buffered.
//!
//! When reading a struct, a key whose ID is not registered is skipped if
//! it is ignorable (negative) and refused if it is critical
//! ([`Error::UnknownCriticalKey`]).

use core::fmt;

use serde::de::{self, DeserializeOwned, IntoDeserializer, Visitor};
use serde::ser::{self, Serialize};
use unicode_normalization::UnicodeNormalization;

use super::cbor::{EncodeError, Map, Value};
use super::keys;

/// A value could not be written or read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// A field or variant name has no registered key.
    UnregisteredKey(String),
    /// A struct holds a critical key that this reader does not know.
    UnknownCriticalKey(i64),
    /// A variant ID that this reader does not know.
    UnknownVariant(i64),
    /// A floating-point number.
    Float,
    /// The value has no canonical encoding.
    Encode(EncodeError),
    /// What the type's `Serialize` or `Deserialize` reported.
    Message(String),
    /// A type that holds server-only data, such as governance metadata,
    /// which never goes into a bundle.
    ServerOnly(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnregisteredKey(name) => write!(f, "`{name}` has no bundle key"),
            Self::UnknownCriticalKey(id) => write!(f, "unknown critical key {id}"),
            Self::UnknownVariant(id) => write!(f, "unknown variant {id}"),
            Self::Float => f.write_str("floating point is not allowed"),
            Self::Encode(e) => e.fmt(f),
            Self::Message(m) => f.write_str(m),
            Self::ServerOnly(t) => write!(f, "`{t}` is server-only and never goes into a bundle"),
        }
    }
}

impl std::error::Error for Error {}

impl ser::Error for Error {
    fn custom<T: fmt::Display>(msg: T) -> Self {
        Self::Message(msg.to_string())
    }
}

impl de::Error for Error {
    fn custom<T: fmt::Display>(msg: T) -> Self {
        Self::Message(msg.to_string())
    }
}

/// Structs that hold server-only data. The model leaves an empty one out,
/// so any that reaches the serializer holds something. Refused by type, not
/// only by field name, because their field names are not all unique to
/// them.
const SERVER_ONLY: &[&str] = &["Metadata"];

fn key(name: &str) -> Result<Value, Error> {
    keys::id(name)
        .map(Value::int)
        .ok_or_else(|| Error::UnregisteredKey(name.to_owned()))
}

/// Writes `value` as a canonical CBOR value.
///
/// # Errors
///
/// [`Error`] if a field or variant name is not registered, a number is
/// floating point, or the type's `Serialize` fails.
pub fn to_value<T: Serialize + ?Sized>(value: &T) -> Result<Value, Error> {
    value.serialize(Serializer)
}

/// Reads a `T` from a value written by [`to_value`].
///
/// # Errors
///
/// [`Error`] if the value does not have the shape of a `T`, holds an
/// unknown critical key or variant, or the type's `Deserialize` refuses it.
pub fn from_value<T: DeserializeOwned>(value: Value) -> Result<T, Error> {
    T::deserialize(Deserializer(value))
}

/// The serializer behind [`to_value`].
#[derive(Clone, Copy, Debug)]
pub struct Serializer;

/// Collects the items of a sequence.
#[derive(Debug)]
pub struct Seq {
    variant: Option<Value>,
    items: Vec<Value>,
}

/// Collects the entries of a map or struct.
#[derive(Debug)]
pub struct Entries {
    variant: Option<Value>,
    entries: Vec<(Value, Value)>,
    pending: Option<Value>,
}

fn wrap(variant: Option<Value>, value: Value) -> Result<Value, Error> {
    match variant {
        None => Ok(value),
        Some(v) => Ok(Value::Map(
            Map::new(vec![(v, value)]).map_err(Error::Encode)?,
        )),
    }
}

impl Seq {
    fn finish(self) -> Result<Value, Error> {
        wrap(self.variant, Value::Array(self.items))
    }
}

impl Entries {
    fn new(variant: Option<Value>) -> Self {
        Self {
            variant,
            entries: Vec::new(),
            pending: None,
        }
    }

    fn finish(self) -> Result<Value, Error> {
        let map = Map::new(self.entries).map_err(Error::Encode)?;
        wrap(self.variant, Value::Map(map))
    }
}

impl ser::Serializer for Serializer {
    type Ok = Value;
    type Error = Error;
    type SerializeSeq = Seq;
    type SerializeTuple = Seq;
    type SerializeTupleStruct = Seq;
    type SerializeTupleVariant = Seq;
    type SerializeMap = Entries;
    type SerializeStruct = Entries;
    type SerializeStructVariant = Entries;

    fn serialize_bool(self, v: bool) -> Result<Value, Error> {
        Ok(Value::Bool(v))
    }
    fn serialize_i8(self, v: i8) -> Result<Value, Error> {
        Ok(Value::int(v.into()))
    }
    fn serialize_i16(self, v: i16) -> Result<Value, Error> {
        Ok(Value::int(v.into()))
    }
    fn serialize_i32(self, v: i32) -> Result<Value, Error> {
        Ok(Value::int(v.into()))
    }
    fn serialize_i64(self, v: i64) -> Result<Value, Error> {
        Ok(Value::int(v))
    }
    fn serialize_i128(self, v: i128) -> Result<Value, Error> {
        if let Ok(n) = u64::try_from(v) {
            Ok(Value::Uint(n))
        } else if let Ok(n) = u64::try_from(-1 - v) {
            Ok(Value::Nint(n))
        } else {
            Err(Error::Message(format!("{v} does not fit in 64 bits")))
        }
    }
    fn serialize_u8(self, v: u8) -> Result<Value, Error> {
        Ok(Value::Uint(v.into()))
    }
    fn serialize_u16(self, v: u16) -> Result<Value, Error> {
        Ok(Value::Uint(v.into()))
    }
    fn serialize_u32(self, v: u32) -> Result<Value, Error> {
        Ok(Value::Uint(v.into()))
    }
    fn serialize_u64(self, v: u64) -> Result<Value, Error> {
        Ok(Value::Uint(v))
    }
    fn serialize_u128(self, v: u128) -> Result<Value, Error> {
        u64::try_from(v)
            .map(Value::Uint)
            .map_err(|_| Error::Message(format!("{v} does not fit in 64 bits")))
    }
    fn serialize_f32(self, _: f32) -> Result<Value, Error> {
        Err(Error::Float)
    }
    fn serialize_f64(self, _: f64) -> Result<Value, Error> {
        Err(Error::Float)
    }
    fn serialize_char(self, v: char) -> Result<Value, Error> {
        Ok(Value::Text(v.to_string()))
    }
    fn serialize_str(self, v: &str) -> Result<Value, Error> {
        Ok(Value::Text(v.nfc().collect()))
    }
    fn serialize_bytes(self, v: &[u8]) -> Result<Value, Error> {
        Ok(Value::Bytes(v.to_vec()))
    }
    fn serialize_none(self) -> Result<Value, Error> {
        Ok(Value::Null)
    }
    fn serialize_some<T: Serialize + ?Sized>(self, value: &T) -> Result<Value, Error> {
        value.serialize(self)
    }
    fn serialize_unit(self) -> Result<Value, Error> {
        Ok(Value::Null)
    }
    fn serialize_unit_struct(self, _: &'static str) -> Result<Value, Error> {
        Ok(Value::Null)
    }
    fn serialize_unit_variant(
        self,
        _: &'static str,
        _: u32,
        variant: &'static str,
    ) -> Result<Value, Error> {
        key(variant)
    }
    fn serialize_newtype_struct<T: Serialize + ?Sized>(
        self,
        _: &'static str,
        value: &T,
    ) -> Result<Value, Error> {
        value.serialize(self)
    }
    fn serialize_newtype_variant<T: Serialize + ?Sized>(
        self,
        _: &'static str,
        _: u32,
        variant: &'static str,
        value: &T,
    ) -> Result<Value, Error> {
        wrap(Some(key(variant)?), value.serialize(self)?)
    }
    fn serialize_seq(self, len: Option<usize>) -> Result<Seq, Error> {
        Ok(Seq {
            variant: None,
            items: Vec::with_capacity(len.unwrap_or(0).min(1024)),
        })
    }
    fn serialize_tuple(self, len: usize) -> Result<Seq, Error> {
        self.serialize_seq(Some(len))
    }
    fn serialize_tuple_struct(self, _: &'static str, len: usize) -> Result<Seq, Error> {
        self.serialize_seq(Some(len))
    }
    fn serialize_tuple_variant(
        self,
        _: &'static str,
        _: u32,
        variant: &'static str,
        _: usize,
    ) -> Result<Seq, Error> {
        Ok(Seq {
            variant: Some(key(variant)?),
            items: Vec::new(),
        })
    }
    fn serialize_map(self, _: Option<usize>) -> Result<Entries, Error> {
        Ok(Entries::new(None))
    }
    fn serialize_struct(self, name: &'static str, _: usize) -> Result<Entries, Error> {
        if SERVER_ONLY.contains(&name) {
            return Err(Error::ServerOnly(name));
        }
        Ok(Entries::new(None))
    }
    fn serialize_struct_variant(
        self,
        _: &'static str,
        _: u32,
        variant: &'static str,
        _: usize,
    ) -> Result<Entries, Error> {
        Ok(Entries::new(Some(key(variant)?)))
    }
}

impl ser::SerializeSeq for Seq {
    type Ok = Value;
    type Error = Error;
    fn serialize_element<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Error> {
        self.items.push(to_value(value)?);
        Ok(())
    }
    fn end(self) -> Result<Value, Error> {
        self.finish()
    }
}

impl ser::SerializeTuple for Seq {
    type Ok = Value;
    type Error = Error;
    fn serialize_element<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Error> {
        ser::SerializeSeq::serialize_element(self, value)
    }
    fn end(self) -> Result<Value, Error> {
        self.finish()
    }
}

impl ser::SerializeTupleStruct for Seq {
    type Ok = Value;
    type Error = Error;
    fn serialize_field<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Error> {
        ser::SerializeSeq::serialize_element(self, value)
    }
    fn end(self) -> Result<Value, Error> {
        self.finish()
    }
}

impl ser::SerializeTupleVariant for Seq {
    type Ok = Value;
    type Error = Error;
    fn serialize_field<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Error> {
        ser::SerializeSeq::serialize_element(self, value)
    }
    fn end(self) -> Result<Value, Error> {
        self.finish()
    }
}

impl ser::SerializeMap for Entries {
    type Ok = Value;
    type Error = Error;
    fn serialize_key<T: Serialize + ?Sized>(&mut self, k: &T) -> Result<(), Error> {
        self.pending = Some(to_value(k)?);
        Ok(())
    }
    fn serialize_value<T: Serialize + ?Sized>(&mut self, v: &T) -> Result<(), Error> {
        let k = self
            .pending
            .take()
            .ok_or_else(|| Error::Message("a map value without a key".to_owned()))?;
        self.entries.push((k, to_value(v)?));
        Ok(())
    }
    fn end(self) -> Result<Value, Error> {
        self.finish()
    }
}

impl ser::SerializeStruct for Entries {
    type Ok = Value;
    type Error = Error;
    fn serialize_field<T: Serialize + ?Sized>(
        &mut self,
        name: &'static str,
        value: &T,
    ) -> Result<(), Error> {
        self.entries.push((key(name)?, to_value(value)?));
        Ok(())
    }
    fn end(self) -> Result<Value, Error> {
        self.finish()
    }
}

impl ser::SerializeStructVariant for Entries {
    type Ok = Value;
    type Error = Error;
    fn serialize_field<T: Serialize + ?Sized>(
        &mut self,
        name: &'static str,
        value: &T,
    ) -> Result<(), Error> {
        ser::SerializeStruct::serialize_field(self, name, value)
    }
    fn end(self) -> Result<Value, Error> {
        self.finish()
    }
}

/// The deserializer behind [`from_value`].
#[derive(Debug)]
pub struct Deserializer(pub Value);

/// How the keys of a map are read.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Keys {
    /// A struct with these fields. Every key is an integer ID, read as its
    /// name. An unknown critical key is refused. An ignorable key that is
    /// not one of the fields is skipped, even if it is registered, so a
    /// newer writer may add an ignorable field to any struct.
    Struct(&'static [&'static str]),
    /// A map read without a type, which serde buffers (untagged and
    /// internally tagged enums): integer keys are registered IDs, given to
    /// serde as their names. The struct is not known here, so an unknown
    /// critical key is refused and an unknown ignorable one skipped.
    Named,
    /// A map of data, such as `mode_by_type`, or a struct read by a
    /// hand-written reader: registered and non-integer keys are kept as
    /// they are, and the key's own type reads them.
    Data,
}

/// The entries of a map, read as `keys_are` says.
fn entries(map: Map, keys_are: Keys) -> Result<Vec<(Value, Value)>, Error> {
    let mut out = Vec::with_capacity(map.len());
    for (k, v) in map.into_entries() {
        if keys_are == Keys::Data {
            // Integer keys in the model's data maps are always registered
            // variants (`script_control_by_kind`), and a hand-written reader
            // such as an action's reads a struct through here too. So an
            // unregistered integer key is a field from a newer writer:
            // skipped if ignorable, refused if critical.
            match k.as_i64() {
                Some(id) if keys::name(id).is_none() && id < 0 => {}
                Some(id) if keys::name(id).is_none() => {
                    return Err(Error::UnknownCriticalKey(id));
                }
                _ => out.push((k, v)),
            }
            continue;
        }
        let Some(id) = k.as_i64() else {
            if keys_are == Keys::Named && matches!(k, Value::Text(_)) {
                // An internally tagged enum's tag value is text; its key
                // is an ID like any other, so text here is data.
                out.push((k, v));
                continue;
            }
            return Err(Error::Message(
                "a struct key must be an integer ID".to_owned(),
            ));
        };
        let name = keys::name(id).filter(|name| match keys_are {
            Keys::Struct(fields) => id >= 0 || fields.contains(name),
            Keys::Named | Keys::Data => true,
        });
        match (name, keys_are) {
            (Some(name), Keys::Named) => out.push((Value::Text(name.to_owned()), v)),
            (Some(_), _) => out.push((k, v)),
            (None, _) if id < 0 => {}
            (None, _) => return Err(Error::UnknownCriticalKey(id)),
        }
    }
    Ok(out)
}

struct MapAccess {
    entries: std::vec::IntoIter<(Value, Value)>,
    value: Option<Value>,
}

impl MapAccess {
    fn new(map: Map, keys_are: Keys) -> Result<Self, Error> {
        Ok(Self {
            entries: entries(map, keys_are)?.into_iter(),
            value: None,
        })
    }
}

impl<'de> de::MapAccess<'de> for MapAccess {
    type Error = Error;
    fn next_key_seed<K: de::DeserializeSeed<'de>>(
        &mut self,
        seed: K,
    ) -> Result<Option<K::Value>, Error> {
        match self.entries.next() {
            Some((k, v)) => {
                self.value = Some(v);
                seed.deserialize(Deserializer(k)).map(Some)
            }
            None => Ok(None),
        }
    }
    fn next_value_seed<V: de::DeserializeSeed<'de>>(&mut self, seed: V) -> Result<V::Value, Error> {
        let v = self
            .value
            .take()
            .ok_or_else(|| Error::Message("a map key without a value".to_owned()))?;
        seed.deserialize(Deserializer(v))
    }
    fn size_hint(&self) -> Option<usize> {
        Some(self.entries.len())
    }
}

struct SeqAccess(std::vec::IntoIter<Value>);

impl<'de> de::SeqAccess<'de> for SeqAccess {
    type Error = Error;
    fn next_element_seed<T: de::DeserializeSeed<'de>>(
        &mut self,
        seed: T,
    ) -> Result<Option<T::Value>, Error> {
        self.0
            .next()
            .map(|v| seed.deserialize(Deserializer(v)))
            .transpose()
    }
    fn size_hint(&self) -> Option<usize> {
        Some(self.0.len())
    }
}

/// An enum variant: its name, and its content if it has one.
struct EnumAccess {
    name: &'static str,
    content: Option<Value>,
}

impl<'de> de::EnumAccess<'de> for EnumAccess {
    type Error = Error;
    type Variant = VariantAccess;
    fn variant_seed<V: de::DeserializeSeed<'de>>(
        self,
        seed: V,
    ) -> Result<(V::Value, VariantAccess), Error> {
        let name: de::value::StrDeserializer<'_, Error> = self.name.into_deserializer();
        Ok((seed.deserialize(name)?, VariantAccess(self.content)))
    }
}

struct VariantAccess(Option<Value>);

impl VariantAccess {
    fn content(self) -> Result<Value, Error> {
        self.0
            .ok_or_else(|| Error::Message("a variant without its content".to_owned()))
    }
}

impl<'de> de::VariantAccess<'de> for VariantAccess {
    type Error = Error;
    fn unit_variant(self) -> Result<(), Error> {
        match self.0 {
            None => Ok(()),
            Some(_) => Err(Error::Message("a unit variant with content".to_owned())),
        }
    }
    fn newtype_variant_seed<T: de::DeserializeSeed<'de>>(self, seed: T) -> Result<T::Value, Error> {
        seed.deserialize(Deserializer(self.content()?))
    }
    fn tuple_variant<V: Visitor<'de>>(self, _: usize, visitor: V) -> Result<V::Value, Error> {
        de::Deserializer::deserialize_seq(Deserializer(self.content()?), visitor)
    }
    fn struct_variant<V: Visitor<'de>>(
        self,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Error> {
        match self.content()? {
            Value::Map(m) => visitor.visit_map(MapAccess::new(m, Keys::Struct(fields))?),
            _ => Err(Error::Message("a struct variant must be a map".to_owned())),
        }
    }
}

fn variant(id: &Value) -> Result<&'static str, Error> {
    let id = id
        .as_i64()
        .ok_or_else(|| Error::Message("a variant must be an integer ID".to_owned()))?;
    keys::name(id).ok_or(Error::UnknownVariant(id))
}

impl<'de> de::Deserializer<'de> for Deserializer {
    type Error = Error;

    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        match self.0 {
            Value::Uint(n) => visitor.visit_u64(n),
            Value::Nint(n) => match i64::try_from(n) {
                Ok(n) => visitor.visit_i64(-1 - n),
                Err(_) => visitor.visit_i128(-1 - i128::from(n)),
            },
            Value::Bytes(b) => visitor.visit_byte_buf(b),
            Value::Text(s) => visitor.visit_string(s),
            Value::Array(items) => visitor.visit_seq(SeqAccess(items.into_iter())),
            Value::Map(m) => visitor.visit_map(MapAccess::new(m, Keys::Named)?),
            Value::Bool(b) => visitor.visit_bool(b),
            Value::Null => visitor.visit_unit(),
        }
    }

    fn deserialize_f32<V: Visitor<'de>>(self, _: V) -> Result<V::Value, Error> {
        Err(Error::Float)
    }

    fn deserialize_f64<V: Visitor<'de>>(self, _: V) -> Result<V::Value, Error> {
        Err(Error::Float)
    }

    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        match self.0 {
            Value::Null => visitor.visit_none(),
            v => visitor.visit_some(Self(v)),
        }
    }

    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        _: &'static str,
        visitor: V,
    ) -> Result<V::Value, Error> {
        visitor.visit_newtype_struct(self)
    }

    fn deserialize_map<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        match self.0 {
            Value::Map(m) => visitor.visit_map(MapAccess::new(m, Keys::Data)?),
            other => Self(other).deserialize_any(visitor),
        }
    }

    fn deserialize_struct<V: Visitor<'de>>(
        self,
        _: &'static str,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Error> {
        match self.0 {
            Value::Map(m) => visitor.visit_map(MapAccess::new(m, Keys::Struct(fields))?),
            other => Self(other).deserialize_any(visitor),
        }
    }

    fn deserialize_enum<V: Visitor<'de>>(
        self,
        _: &'static str,
        _: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Error> {
        match self.0 {
            id @ (Value::Uint(_) | Value::Nint(_)) => visitor.visit_enum(EnumAccess {
                name: variant(&id)?,
                content: None,
            }),
            Value::Map(m) if m.len() == 1 => {
                let mut entries = m.into_entries();
                let (id, content) = entries.remove(0);
                visitor.visit_enum(EnumAccess {
                    name: variant(&id)?,
                    content: Some(content),
                })
            }
            _ => Err(Error::Message(
                "an enum must be a variant ID or a one-entry map".to_owned(),
            )),
        }
    }

    fn deserialize_identifier<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        match &self.0 {
            Value::Uint(_) | Value::Nint(_) => visitor.visit_str(variant(&self.0)?),
            _ => self.deserialize_any(visitor),
        }
    }

    fn deserialize_ignored_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        visitor.visit_unit()
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 char str string
        bytes byte_buf unit unit_struct seq tuple tuple_struct
    }
}

#[cfg(test)]
mod tests;
