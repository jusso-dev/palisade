//! A bounded, namespace-aware XML tree for package manifests and block
//! maps.
//!
//! [`parse`] builds a small element tree with every element and attribute
//! name resolved to `(namespace URI, local name)`, so a manifest that binds
//! the schema namespace to an unusual prefix reads the same as one that
//! uses the default namespace, and an attribute with a foreign prefix is
//! never taken for the schema's.
//!
//! Hostile input is refused rather than guessed at: a document type
//! declaration (so no entity can ever be defined, let alone expanded), an
//! undefined entity, an undeclared prefix, an attribute that appears twice
//! after namespace resolution, text outside the root, more than one root,
//! and anything past [`MAX_DEPTH`], [`MAX_ELEMENTS`] or [`MAX_ATTR_LEN`].
//! Input must be UTF-8, optionally with a byte order mark, as app package
//! XML is.

#![forbid(unsafe_code)]

use std::fmt;

use quick_xml::events::{BytesStart, Event};
use quick_xml::name::ResolveResult;
use quick_xml::reader::NsReader;

/// The deepest element nesting accepted.
pub const MAX_DEPTH: usize = 64;
/// The most elements read.
pub const MAX_ELEMENTS: usize = 200_000;
/// The longest attribute value or text kept, in bytes.
pub const MAX_ATTR_LEN: usize = 64 * 1024;

/// Why a document was refused.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct XmlError(pub String);

impl fmt::Display for XmlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "XML: {}", self.0)
    }
}

impl std::error::Error for XmlError {}

fn err<T>(what: impl Into<String>) -> Result<T, XmlError> {
    Err(XmlError(what.into()))
}

/// One element.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Element {
    /// The namespace URI, empty for none.
    pub ns: String,
    /// The local name.
    pub name: String,
    /// Attributes: `(namespace URI, local name, value)`. Unprefixed
    /// attributes have no namespace.
    pub attrs: Vec<(String, String, String)>,
    /// Child elements, in order.
    pub children: Vec<Element>,
    /// Text directly inside, concatenated.
    pub text: String,
}

impl Element {
    /// The unprefixed attribute `name`.
    #[must_use]
    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(ns, n, _)| ns.is_empty() && n == name)
            .map(|(_, _, v)| v.as_str())
    }

    /// Children in namespace `ns` called `name`.
    pub fn children_named<'a>(
        &'a self,
        ns: &'a [&'a str],
        name: &'a str,
    ) -> impl Iterator<Item = &'a Element> + 'a {
        self.children
            .iter()
            .filter(move |c| c.name == name && ns.contains(&c.ns.as_str()))
    }

    /// The first child in namespace `ns` called `name`.
    #[must_use]
    pub fn child(&self, ns: &[&str], name: &str) -> Option<&Element> {
        self.children
            .iter()
            .find(|c| c.name == name && ns.contains(&c.ns.as_str()))
    }

    /// Every element in the tree, depth first, this one included.
    #[must_use]
    pub fn descendants(&self) -> Vec<&Element> {
        let mut out = Vec::new();
        let mut stack = vec![self];
        while let Some(e) = stack.pop() {
            out.push(e);
            for c in e.children.iter().rev() {
                stack.push(c);
            }
        }
        out
    }
}

fn resolved(r: &ResolveResult<'_>) -> Result<String, XmlError> {
    match r {
        ResolveResult::Unbound => Ok(String::new()),
        ResolveResult::Bound(ns) => std::str::from_utf8(ns.as_ref())
            .map(str::to_owned)
            .or_else(|_| err("namespace is not UTF-8")),
        ResolveResult::Unknown(p) => {
            err(format!("undeclared prefix {}", String::from_utf8_lossy(p)))
        }
    }
}

fn is_xml_char(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\r' | '\u{20}'..='\u{D7FF}' | '\u{E000}'..='\u{FFFD}' | '\u{10000}'..='\u{10FFFF}')
}

fn check_chars(s: &str) -> Result<(), XmlError> {
    if s.chars().all(is_xml_char) {
        Ok(())
    } else {
        err("character not allowed in XML")
    }
}

fn element(reader: &NsReader<&[u8]>, e: &BytesStart<'_>) -> Result<Element, XmlError> {
    let (ns, local) = reader.resolver().resolve_element(e.name());
    let ns = resolved(&ns)?;
    let name = std::str::from_utf8(local.as_ref())
        .or_else(|_| err("name is not UTF-8"))?
        .to_owned();
    let mut attrs: Vec<(String, String, String)> = Vec::new();
    for a in e.attributes() {
        let a = a.or_else(|x| err(x.to_string()))?;
        let key = a.key;
        if key.as_ref() == b"xmlns" || key.as_ref().starts_with(b"xmlns:") {
            continue;
        }
        let (ans, alocal) = reader.resolver().resolve_attribute(key);
        let ans = resolved(&ans)?;
        let alocal = std::str::from_utf8(alocal.as_ref())
            .or_else(|_| err("attribute name is not UTF-8"))?
            .to_owned();
        let value = a
            .normalized_value(quick_xml::XmlVersion::Implicit1_0)
            .or_else(|x| err(x.to_string()))?;
        check_chars(&value)?;
        if value.len() > MAX_ATTR_LEN {
            return err("attribute value too long");
        }
        if attrs.iter().any(|(n, l, _)| *n == ans && *l == alocal) {
            return err(format!("attribute {alocal} appears twice"));
        }
        attrs.push((ans, alocal, value.into_owned()));
    }
    Ok(Element {
        ns,
        name,
        attrs,
        children: Vec::new(),
        text: String::new(),
    })
}

/// Parses `data` into its root element.
pub fn parse(data: &[u8]) -> Result<Element, XmlError> {
    let data = data.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(data);
    if data.starts_with(&[0xff, 0xfe]) || data.starts_with(&[0xfe, 0xff]) {
        return err("UTF-16 is not supported");
    }
    let text = std::str::from_utf8(data).or_else(|_| err("not UTF-8"))?;
    let mut reader = NsReader::from_str(text);
    let config = reader.config_mut();
    config.check_end_names = true;
    config.check_comments = true;
    let mut stack: Vec<Element> = Vec::new();
    let mut root: Option<Element> = None;
    let mut count = 0_usize;
    loop {
        let event = reader.read_event().or_else(|e| err(e.to_string()))?;
        match event {
            Event::DocType(_) => return err("document type declarations are not allowed"),
            Event::Start(ref e) | Event::Empty(ref e) => {
                count += 1;
                if count > MAX_ELEMENTS {
                    return err("too many elements");
                }
                if stack.len() >= MAX_DEPTH {
                    return err("too deep");
                }
                if stack.is_empty() && root.is_some() {
                    return err("more than one root element");
                }
                let el = element(&reader, e)?;
                if matches!(event, Event::Empty(_)) {
                    match stack.last_mut() {
                        Some(parent) => parent.children.push(el),
                        None => root = Some(el),
                    }
                } else {
                    stack.push(el);
                }
            }
            Event::End(_) => {
                let Some(el) = stack.pop() else {
                    return err("unbalanced end tag");
                };
                match stack.last_mut() {
                    Some(parent) => parent.children.push(el),
                    None => root = Some(el),
                }
            }
            Event::Text(t) => {
                let raw = t.xml10_content().or_else(|e| err(e.to_string()))?;
                check_chars(&raw)?;
                match stack.last_mut() {
                    Some(top) => {
                        if top.text.len().saturating_add(raw.len()) > MAX_ATTR_LEN {
                            return err("text too long");
                        }
                        top.text.push_str(&raw);
                    }
                    None if raw.chars().all(|c| matches!(c, ' ' | '\t' | '\r' | '\n')) => {}
                    None => return err("text outside the root element"),
                }
            }
            Event::CData(t) => {
                let raw = t.xml10_content().or_else(|e| err(e.to_string()))?;
                check_chars(&raw)?;
                match stack.last_mut() {
                    Some(top) if top.text.len().saturating_add(raw.len()) <= MAX_ATTR_LEN => {
                        top.text.push_str(&raw);
                    }
                    _ => return err("CDATA outside the root or too long"),
                }
            }
            Event::GeneralRef(r) => {
                let resolved = match r.resolve_char_ref() {
                    Ok(Some(c)) if is_xml_char(c) => c.to_string(),
                    Ok(Some(_)) => return err("character reference not allowed in XML"),
                    Ok(None) => {
                        let name = r.decode().or_else(|e| err(e.to_string()))?;
                        quick_xml::escape::resolve_predefined_entity(&name)
                            .map(str::to_owned)
                            .ok_or_else(|| XmlError(format!("undefined entity &{name};")))?
                    }
                    Err(e) => return err(e.to_string()),
                };
                match stack.last_mut() {
                    Some(top) => top.text.push_str(&resolved),
                    None => return err("reference outside the root element"),
                }
            }
            Event::Eof => break,
            Event::Decl(_) | Event::PI(_) | Event::Comment(_) => {}
        }
    }
    if !stack.is_empty() {
        return err("an element is not closed");
    }
    root.ok_or_else(|| XmlError("no root element".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_namespaces_and_refuses_doctypes() {
        let doc = br#"<?xml version="1.0"?><p:Package xmlns:p="urn:x" xmlns:q="urn:q"><p:Identity Name="a&amp;b" q:Name="evil"/></p:Package>"#;
        let root = parse(doc).unwrap();
        assert_eq!((root.ns.as_str(), root.name.as_str()), ("urn:x", "Package"));
        let id = root.child(&["urn:x"], "Identity").unwrap();
        assert_eq!(id.attr("Name"), Some("a&b"));

        let dtd = br#"<!DOCTYPE x [<!ENTITY e "boom">]><x>&e;</x>"#;
        assert!(parse(dtd).is_err());
        assert!(parse(b"<x>&e;</x>").is_err());
        assert!(parse(b"<x y='1' y='2'/>").is_err());
        assert!(parse(b"<p:x/>").is_err());
        assert!(parse(b"<x/><y/>").is_err());
        assert!(parse(b"<x/>text").is_err());
    }

    #[test]
    fn depth_is_bounded() {
        let mut doc = String::new();
        for _ in 0..=MAX_DEPTH {
            doc.push_str("<a>");
        }
        for _ in 0..=MAX_DEPTH {
            doc.push_str("</a>");
        }
        assert!(parse(doc.as_bytes()).is_err());
    }
}
