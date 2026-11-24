//! A serde `Deserializer` over the located tree from [`super::parse`].
//!
//! Every error is tagged with the location and JSON Pointer of the innermost
//! node that raised it, so a model mismatch points at the source.

use core::fmt;

use serde::de::{self, DeserializeSeed, IntoDeserializer, Visitor};

use super::Location;
use super::parse::{Entry, Node, Value};

/// A path from the root, built on the stack as the deserializer descends.
pub(crate) enum Path<'p> {
    Root,
    Key(&'p Path<'p>, &'p str),
    Index(&'p Path<'p>, usize),
}

impl Path<'_> {
    /// The JSON Pointer (RFC 6901) of this path.
    pub(crate) fn pointer(&self) -> String {
        let mut tokens = Vec::new();
        let mut at = self;
        loop {
            match at {
                Path::Root => break,
                Path::Key(parent, key) => {
                    tokens.push(key.replace('~', "~0").replace('/', "~1"));
                    at = parent;
                }
                Path::Index(parent, index) => {
                    tokens.push(index.to_string());
                    at = parent;
                }
            }
        }
        tokens.iter().rev().fold(String::new(), |mut out, t| {
            out.push('/');
            out.push_str(t);
            out
        })
    }
}

/// A model mismatch, with where it happened once known.
#[derive(Debug)]
pub(crate) struct DeError {
    pub(crate) message: String,
    pub(crate) location: Option<Location>,
    pub(crate) pointer: Option<String>,
}

impl DeError {
    /// Records where the error happened, unless a deeper node already did.
    fn locate(mut self, node: &Node, path: &Path<'_>) -> Self {
        if self.location.is_none() {
            self.location = Some(node.location);
            self.pointer = Some(path.pointer());
            // Plain scalars that are not text were typed by the loader. When
            // text was expected, the usual fix is to quote them.
            if !matches!(
                node.value,
                Value::Str(_) | Value::Seq(_) | Value::Map(_) | Value::Null
            ) && self.message.starts_with("invalid type")
                && expects_text(&self.message)
            {
                self.message
                    .push_str("; quote the value if it is meant to be text");
            }
        }
        self
    }

    fn at_key(mut self, location: Location, path: &Path<'_>) -> Self {
        if self.location.is_none() {
            self.location = Some(location);
            self.pointer = Some(path.pointer());
        }
        self
    }
}

/// Whether a serde "invalid type" message says that text was expected.
/// Model types that read text say so: `a string`, `a UUIDv7 ...`, a
/// version, or one of the enum's variant names.
fn expects_text(message: &str) -> bool {
    let Some((_, expected)) = message.split_once(", expected ") else {
        return false;
    };
    // `enum Match` is a tree node, always a one-key map, never a name.
    !(expected.starts_with('u')
        || expected.starts_with('i')
        || expected.starts_with("a boolean")
        || expected.starts_with("a sequence")
        || expected.starts_with("a map")
        || expected.starts_with("struct ")
        || expected == "enum Match")
}

impl fmt::Display for DeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for DeError {}

impl de::Error for DeError {
    fn custom<T: fmt::Display>(msg: T) -> Self {
        Self {
            message: msg.to_string(),
            location: None,
            pointer: None,
        }
    }
}

/// Deserializes one node.
pub(crate) struct De<'de, 'p> {
    pub(crate) node: &'de Node,
    pub(crate) path: &'p Path<'p>,
}

impl<'de> De<'de, '_> {
    fn any<V: Visitor<'de>>(&self, visitor: V) -> Result<V::Value, DeError> {
        match &self.node.value {
            Value::Null => visitor.visit_unit(),
            Value::Bool(b) => visitor.visit_bool(*b),
            Value::UInt(n) => visitor.visit_u64(*n),
            Value::NegInt(n) => visitor.visit_i64(*n),
            Value::Float(f) => visitor.visit_f64(*f),
            // As serde_json does: an integer too large for 64 bits is read
            // as the nearest float, which an integer field then rejects as
            // a float, and a number too large for a float is an error.
            Value::OutOfRange(text) => match text.parse::<f64>() {
                Ok(f) if f.is_finite() => visitor.visit_f64(f),
                _ => Err(de::Error::custom(format_args!(
                    "the number `{text}` is out of range; quote the value if it is meant to be text"
                ))),
            },
            Value::Str(s) => visitor.visit_borrowed_str(s),
            Value::Seq(items) => {
                let mut access = SeqAccess {
                    items: items.iter(),
                    path: self.path,
                    index: 0,
                };
                let value = visitor.visit_seq(&mut access)?;
                if access.items.as_slice().is_empty() {
                    Ok(value)
                } else {
                    Err(de::Error::invalid_length(items.len(), &"fewer elements"))
                }
            }
            Value::Map(map) => {
                let mut access = MapAccess {
                    entries: map.entries.iter(),
                    current: None,
                    path: self.path,
                };
                visitor.visit_map(&mut access)
            }
        }
    }
}

impl<'de> de::Deserializer<'de> for De<'de, '_> {
    type Error = DeError;

    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, DeError> {
        self.any(visitor)
            .map_err(|e| e.locate(self.node, self.path))
    }

    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, DeError> {
        if self.node.value == Value::Null {
            visitor.visit_none()
        } else {
            let (node, path) = (self.node, self.path);
            visitor.visit_some(self).map_err(|e| e.locate(node, path))
        }
    }

    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, DeError> {
        let (node, path) = (self.node, self.path);
        visitor
            .visit_newtype_struct(self)
            .map_err(|e| e.locate(node, path))
    }

    fn deserialize_enum<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, DeError> {
        let result = match &self.node.value {
            // A unit variant, written as its name.
            Value::Str(s) => visitor.visit_enum(de::value::BorrowedStrDeserializer::new(s)),
            // Any other variant: a map with exactly one key, the variant name.
            Value::Map(map) => match map.entries.as_slice() {
                [entry] => visitor.visit_enum(EnumAccess {
                    entry,
                    path: self.path,
                }),
                entries => Err(de::Error::invalid_length(
                    entries.len(),
                    &"a map with exactly one key",
                )),
            },
            _ => self.any(visitor),
        };
        result.map_err(|e| e.locate(self.node, self.path))
    }

    // A struct or map is only read from a map. serde's derived struct
    // readers also accept a sequence and bind its items to fields by
    // position, which neither the JSON Schema nor the documented form allows.
    fn deserialize_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, DeError> {
        self.map_only(visitor)
    }

    fn deserialize_map<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, DeError> {
        self.map_only(visitor)
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
        bytes byte_buf unit unit_struct seq tuple tuple_struct
        identifier ignored_any
    }
}

impl<'de> De<'de, '_> {
    fn map_only<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, DeError> {
        let result = match &self.node.value {
            Value::Map(_) => self.any(visitor),
            Value::Seq(_) => Err(de::Error::invalid_type(de::Unexpected::Seq, &visitor)),
            // Scalars give serde's usual message for the visitor.
            _ => self.any(visitor),
        };
        result.map_err(|e| e.locate(self.node, self.path))
    }
}

struct SeqAccess<'de, 'p> {
    items: core::slice::Iter<'de, Node>,
    path: &'p Path<'p>,
    index: usize,
}

impl<'de> de::SeqAccess<'de> for SeqAccess<'de, '_> {
    type Error = DeError;

    fn next_element_seed<T: DeserializeSeed<'de>>(
        &mut self,
        seed: T,
    ) -> Result<Option<T::Value>, DeError> {
        let Some(node) = self.items.next() else {
            return Ok(None);
        };
        let path = Path::Index(self.path, self.index);
        self.index += 1;
        seed.deserialize(De { node, path: &path })
            .map(Some)
            .map_err(|e| e.locate(node, &path))
    }

    fn size_hint(&self) -> Option<usize> {
        Some(self.items.len())
    }
}

struct MapAccess<'de, 'p> {
    entries: core::slice::Iter<'de, Entry>,
    current: Option<&'de Entry>,
    path: &'p Path<'p>,
}

impl<'de> de::MapAccess<'de> for MapAccess<'de, '_> {
    type Error = DeError;

    fn next_key_seed<K: DeserializeSeed<'de>>(
        &mut self,
        seed: K,
    ) -> Result<Option<K::Value>, DeError> {
        let Some(entry) = self.entries.next() else {
            return Ok(None);
        };
        self.current = Some(entry);
        let path = Path::Key(self.path, &entry.key);
        seed.deserialize(KeyDe { key: &entry.key })
            .map(Some)
            .map_err(|e| e.at_key(entry.key_location, &path))
    }

    fn next_value_seed<V: DeserializeSeed<'de>>(&mut self, seed: V) -> Result<V::Value, DeError> {
        let Some(entry) = self.current.take() else {
            return Err(de::Error::custom("a map value was read before its key"));
        };
        let path = Path::Key(self.path, &entry.key);
        seed.deserialize(De {
            node: &entry.value,
            path: &path,
        })
        .map_err(|e| e.locate(&entry.value, &path))
    }

    fn size_hint(&self) -> Option<usize> {
        Some(self.entries.len())
    }
}

/// Deserializes a map key, which is always text.
struct KeyDe<'de> {
    key: &'de str,
}

impl<'de> de::Deserializer<'de> for KeyDe<'de> {
    type Error = DeError;

    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, DeError> {
        visitor.visit_borrowed_str(self.key)
    }

    fn deserialize_enum<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, DeError> {
        visitor.visit_enum(self.key.into_deserializer())
    }

    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, DeError> {
        visitor.visit_newtype_struct(self)
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
        bytes byte_buf option unit unit_struct seq tuple
        tuple_struct map struct identifier ignored_any
    }
}

/// An enum written as `{variant: value}`.
struct EnumAccess<'de, 'p> {
    entry: &'de Entry,
    path: &'p Path<'p>,
}

impl<'de, 'p> de::EnumAccess<'de> for EnumAccess<'de, 'p> {
    type Error = DeError;
    type Variant = VariantAccess<'de, 'p>;

    fn variant_seed<V: DeserializeSeed<'de>>(
        self,
        seed: V,
    ) -> Result<(V::Value, Self::Variant), DeError> {
        let path = Path::Key(self.path, &self.entry.key);
        let variant = seed
            .deserialize(KeyDe {
                key: &self.entry.key,
            })
            .map_err(|e| e.at_key(self.entry.key_location, &path))?;
        Ok((
            variant,
            VariantAccess {
                entry: self.entry,
                path: self.path,
            },
        ))
    }
}

struct VariantAccess<'de, 'p> {
    entry: &'de Entry,
    path: &'p Path<'p>,
}

impl<'de> VariantAccess<'de, '_> {
    fn value<T>(&self, f: impl FnOnce(De<'de, '_>) -> Result<T, DeError>) -> Result<T, DeError> {
        let path = Path::Key(self.path, &self.entry.key);
        f(De {
            node: &self.entry.value,
            path: &path,
        })
        .map_err(|e| e.locate(&self.entry.value, &path))
    }
}

impl<'de> de::VariantAccess<'de> for VariantAccess<'de, '_> {
    type Error = DeError;

    // A variant reached through a one-key map has a value. A unit variant
    // is only written as its name (`mode: audit`), not `mode: {audit: null}`.
    fn unit_variant(self) -> Result<(), DeError> {
        let message = format!(
            "`{}` takes no value; write it as the plain name `{}`, not as a map",
            self.entry.key, self.entry.key
        );
        self.value(|_| Err(de::Error::custom(message)))
    }

    fn newtype_variant_seed<T: DeserializeSeed<'de>>(self, seed: T) -> Result<T::Value, DeError> {
        self.value(|de| seed.deserialize(de))
    }

    fn tuple_variant<V: Visitor<'de>>(self, _len: usize, visitor: V) -> Result<V::Value, DeError> {
        self.value(|de| de::Deserializer::deserialize_seq(de, visitor))
    }

    fn struct_variant<V: Visitor<'de>>(
        self,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, DeError> {
        self.value(|de| de::Deserializer::deserialize_map(de, visitor))
    }
}
