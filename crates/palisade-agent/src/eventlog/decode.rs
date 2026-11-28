//! Decoding rendered event-log XML into mapping records (#58).
//!
//! The event-log subscription (Windows only) renders each record as XML
//! (`EvtRender` with `EvtRenderEventXml`) and hands over the text. This
//! module turns it into a [`Record`], the input of the data-driven mapping
//! in `palisade_proto::mapping`. It has no `unsafe` code and no OS calls,
//! so it runs, is tested and is fuzzed on every OS.
//!
//! The XML is parsed by the bounded, namespace-aware reader in
//! `palisade_fileid::package::xml`, which refuses a document type
//! declaration (so no entity is ever defined or expanded), undefined
//! entities, undeclared prefixes, more than one root, and anything over
//! its size, depth and element limits.
//!
//! What is read:
//!
//! - `System/EventID`, `System/TimeCreated/@SystemTime`,
//!   `System/EventRecordID`, `System/Channel`, `System/Provider/@Name`,
//!   `System/Correlation/@ActivityID`, `System/Execution/@ProcessID` (as
//!   the field `System.ProcessID`) and `System/Security/@UserID` (as
//!   `System.UserID`).
//! - `EventData/Data[@Name]` (the code integrity and script host events),
//!   or the children of the single element under `UserData` (the
//!   rule-collection events), as fields by name.
//!
//! Field names are normalised to the mapping files' form: the code
//! integrity provider writes names with spaces (`SHA256 Flat Hash`), the
//! template names have none (`SHA256FlatHash`), so spaces are removed.
//!
//! Fail closed (ADR 0018): a record without a parseable event ID or time,
//! a repeated field, more than [`MAX_RECORD_FIELDS`] fields, or a field
//! with child elements is an error, not a partial record.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fmt;

use palisade_fileid::package::xml::{self, Element, XmlError};
use palisade_proto::events::{Guid, Timestamp};
use palisade_proto::mapping::{MAX_RECORD_FIELDS, Record};

/// The largest rendered record accepted: 1 MiB. Event-log records are at
/// most 64 KiB of user data; the rendered XML is larger, but not by this
/// much.
pub const MAX_XML: usize = 1 << 20;

use super::os_ids::EVENT_NS;

/// A decoded record and its provider.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decoded {
    /// The provider name.
    pub provider: String,
    /// The record, ready for mapping.
    pub record: Record,
}

/// Why a rendered record was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// Larger than [`MAX_XML`].
    TooLarge,
    /// Not well-formed or over the reader's limits.
    Xml(XmlError),
    /// The root is not an `Event` in the event schema namespace.
    NotAnEvent,
    /// A required system value is missing or malformed.
    System(&'static str),
    /// A field is malformed: its name and why.
    Field(String, &'static str),
    /// More than [`MAX_RECORD_FIELDS`] fields.
    TooManyFields,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge => write!(f, "record larger than {MAX_XML} bytes"),
            Self::Xml(e) => write!(f, "{e}"),
            Self::NotAnEvent => f.write_str("not an event record"),
            Self::System(what) => write!(f, "bad or missing {what}"),
            Self::Field(name, why) => write!(f, "field {name:?}: {why}"),
            Self::TooManyFields => write!(f, "more than {MAX_RECORD_FIELDS} fields"),
        }
    }
}

impl std::error::Error for DecodeError {}

fn child<'a>(e: &'a Element, name: &str) -> Option<&'a Element> {
    e.child(&[EVENT_NS], name)
}

/// A GUID as the OS writes it: in braces, in either case.
fn os_guid(text: &str) -> Option<Guid> {
    let inner = text.strip_prefix('{')?.strip_suffix('}')?;
    inner.to_ascii_lowercase().parse().ok()
}

/// The field name in the mapping files' form.
fn field_name(raw: &str) -> String {
    raw.chars().filter(|c| !c.is_whitespace()).collect()
}

/// Decodes one rendered record.
///
/// # Errors
///
/// [`DecodeError`] for a record that is not well-formed, lacks its event
/// ID or time, or has malformed fields.
pub fn decode(text: &[u8]) -> Result<Decoded, DecodeError> {
    if text.len() > MAX_XML {
        return Err(DecodeError::TooLarge);
    }
    let root = xml::parse(text).map_err(DecodeError::Xml)?;
    if root.name != "Event" || &*root.ns != EVENT_NS {
        return Err(DecodeError::NotAnEvent);
    }
    let system = child(&root, "System").ok_or(DecodeError::System("System"))?;
    let event_id = child(system, "EventID")
        .and_then(|e| e.text.trim().parse::<u32>().ok())
        .ok_or(DecodeError::System("EventID"))?;
    let time_created = child(system, "TimeCreated")
        .and_then(|e| e.attr("SystemTime"))
        .and_then(|t| Timestamp::parse_utc(t).ok())
        .ok_or(DecodeError::System("TimeCreated"))?;
    let record_id = match child(system, "EventRecordID") {
        Some(e) => Some(
            e.text
                .trim()
                .parse::<u64>()
                .map_err(|_| DecodeError::System("EventRecordID"))?,
        ),
        None => None,
    };
    let channel = child(system, "Channel")
        .map(|e| e.text.trim().to_owned())
        .filter(|c| !c.is_empty());
    let provider = child(system, "Provider")
        .and_then(|e| e.attr("Name"))
        .unwrap_or_default()
        .to_owned();
    let activity_id = match child(system, "Correlation").and_then(|e| e.attr("ActivityID")) {
        Some(text) => Some(os_guid(text).ok_or(DecodeError::System("Correlation ActivityID"))?),
        None => None,
    };

    let mut fields = BTreeMap::new();
    let mut put = |name: &str, value: &str| -> Result<(), DecodeError> {
        let name = field_name(name);
        if name.is_empty() {
            return Err(DecodeError::Field(name, "empty name"));
        }
        if fields.len() == MAX_RECORD_FIELDS {
            return Err(DecodeError::TooManyFields);
        }
        if fields
            .insert(name.clone(), value.trim().to_owned())
            .is_some()
        {
            return Err(DecodeError::Field(name, "repeated"));
        }
        Ok(())
    };
    if let Some(pid) = child(system, "Execution").and_then(|e| e.attr("ProcessID")) {
        put("System.ProcessID", pid)?;
    }
    if let Some(user) = child(system, "Security").and_then(|e| e.attr("UserID")) {
        put("System.UserID", user)?;
    }
    if let Some(data) = child(&root, "EventData") {
        for (i, d) in data.children.iter().enumerate() {
            if d.name != "Data" {
                continue;
            }
            if !d.children.is_empty() {
                return Err(DecodeError::Field(
                    format!("Data[{i}]"),
                    "has child elements",
                ));
            }
            // Unnamed data items (classic providers) are positional.
            let name = d
                .attr("Name")
                .map_or_else(|| format!("Data{i}"), str::to_owned);
            put(&name, &d.text)?;
        }
    }
    if let Some(user_data) = child(&root, "UserData") {
        // One element under `UserData`, whose children are the fields.
        if let Some(body) = user_data.children.first() {
            for f in &body.children {
                if !f.children.is_empty() {
                    return Err(DecodeError::Field(f.name.clone(), "has child elements"));
                }
                put(&f.name, &f.text)?;
            }
        }
    }
    Ok(Decoded {
        provider,
        record: Record {
            event_id,
            time_created,
            record_id,
            channel,
            activity_id,
            fields,
        },
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A rendered code integrity record.
    pub(crate) fn ci_xml(event_id: u32, activity: &str, data: &[(&str, &str)]) -> String {
        let data: String = data
            .iter()
            .map(|(k, v)| format!("<Data Name=\"{k}\">{v}</Data>"))
            .collect();
        format!(
            "<Event xmlns=\"{EVENT_NS}\"><System>\
             <Provider Name=\"X-Windows-CodeIntegrity\" Guid=\"{{4ee76bd8-3cf4-44a0-a0ac-3937643e37a3}}\"/>\
             <EventID>{event_id}</EventID><Version>5</Version>\
             <TimeCreated SystemTime=\"2026-11-24T03:15:22.1234567Z\"/>\
             <EventRecordID>42</EventRecordID>\
             <Correlation ActivityID=\"{activity}\"/>\
             <Execution ProcessID=\"4\" ThreadID=\"8\"/>\
             <Channel>X-Windows-CodeIntegrity/Operational</Channel>\
             <Security UserID=\"S-1-5-18\"/>\
             </System><EventData>{data}</EventData></Event>"
        )
    }

    #[test]
    fn code_integrity_records_decode() {
        let x = ci_xml(
            3076,
            "{A244370E-44C9-4C06-B551-F6016E563076}",
            &[
                ("File Name", "\\Device\\HarddiskVolume3\\t\\a.exe"),
                ("Requested Signing Level", "8"),
                ("SHA256 Flat Hash", "AB12"),
            ],
        );
        let d = decode(x.as_bytes()).unwrap();
        assert_eq!(d.provider, "X-Windows-CodeIntegrity");
        let r = d.record;
        assert_eq!(r.event_id, 3076);
        assert_eq!(r.record_id, Some(42));
        assert_eq!(
            r.channel.as_deref(),
            Some("X-Windows-CodeIntegrity/Operational")
        );
        assert_eq!(
            r.activity_id.unwrap().to_string(),
            "a244370e-44c9-4c06-b551-f6016e563076"
        );
        assert_eq!(r.fields["FileName"], "\\Device\\HarddiskVolume3\\t\\a.exe");
        assert_eq!(r.fields["RequestedSigningLevel"], "8");
        assert_eq!(r.fields["SHA256FlatHash"], "AB12");
        assert_eq!(r.fields["System.ProcessID"], "4");
        assert_eq!(r.fields["System.UserID"], "S-1-5-18");
        assert_eq!(
            r.time_created,
            Timestamp::parse_utc("2026-11-24T03:15:22.123456Z").unwrap()
        );
    }

    #[test]
    fn rule_collection_user_data_decodes() {
        let x = format!(
            "<Event xmlns=\"{EVENT_NS}\"><System><Provider Name=\"X-Windows-RuleCollections\"/>\
             <EventID>8004</EventID><TimeCreated SystemTime=\"2026-11-24T03:15:22.000Z\"/>\
             </System><UserData><RuleAndFileData xmlns=\"urn:x\">\
             <PolicyName>EXE</PolicyName><RuleId>{{00000000-0000-0000-0000-000000000000}}</RuleId>\
             <FilePath>%OSDRIVE%\\t\\a.exe</FilePath><Unnamed/></RuleAndFileData></UserData></Event>"
        );
        let r = decode(x.as_bytes()).unwrap().record;
        assert_eq!(r.event_id, 8004);
        assert_eq!(r.record_id, None);
        assert_eq!(r.activity_id, None);
        assert_eq!(r.channel, None);
        assert_eq!(r.fields["PolicyName"], "EXE");
        assert_eq!(r.fields["FilePath"], "%OSDRIVE%\\t\\a.exe");
        assert_eq!(r.fields["Unnamed"], "");
    }

    #[test]
    fn positional_data_gets_an_index_name() {
        let x = format!(
            "<Event xmlns=\"{EVENT_NS}\"><System><EventID>16387</EventID>\
             <TimeCreated SystemTime=\"2026-11-24T03:15:22Z\"/></System>\
             <EventData><Data>a</Data><Other/><Data>b</Data></EventData></Event>"
        );
        let r = decode(x.as_bytes()).unwrap().record;
        assert_eq!(r.fields["Data0"], "a");
        assert_eq!(r.fields["Data2"], "b");
    }

    #[test]
    fn malformed_records_fail_closed() {
        let bad = |x: String| decode(x.as_bytes()).unwrap_err();
        assert_eq!(
            decode(&vec![b' '; MAX_XML + 1]).unwrap_err(),
            DecodeError::TooLarge
        );
        assert!(matches!(bad("<a".into()), DecodeError::Xml(_)));
        assert!(matches!(
            bad("<!DOCTYPE x [<!ENTITY e \"x\">]><Event/>".into()),
            DecodeError::Xml(_)
        ));
        assert_eq!(bad("<Event/>".into()), DecodeError::NotAnEvent);
        assert_eq!(
            bad(format!("<Event xmlns=\"{EVENT_NS}\"/>")),
            DecodeError::System("System")
        );
        assert_eq!(
            bad(format!(
                "<Event xmlns=\"{EVENT_NS}\"><System><EventID>x</EventID></System></Event>"
            )),
            DecodeError::System("EventID")
        );
        assert_eq!(
            bad(format!(
                "<Event xmlns=\"{EVENT_NS}\"><System><EventID>1</EventID></System></Event>"
            )),
            DecodeError::System("TimeCreated")
        );
        let sys = "<EventID>1</EventID><TimeCreated SystemTime=\"2026-11-24T03:15:22Z\"/>";
        assert_eq!(
            bad(format!(
                "<Event xmlns=\"{EVENT_NS}\"><System>{sys}<EventRecordID>-1</EventRecordID></System></Event>"
            )),
            DecodeError::System("EventRecordID")
        );
        assert_eq!(
            bad(format!(
                "<Event xmlns=\"{EVENT_NS}\"><System>{sys}<Correlation ActivityID=\"a244370e-44c9-4c06-b551-f6016e563076\"/></System></Event>"
            )),
            DecodeError::System("Correlation ActivityID")
        );
        let with_data = |d: &str| {
            format!(
                "<Event xmlns=\"{EVENT_NS}\"><System>{sys}</System><EventData>{d}</EventData></Event>"
            )
        };
        assert_eq!(
            bad(with_data(
                "<Data Name=\"A\">1</Data><Data Name=\"A B\">2</Data><Data Name=\"AB\">3</Data>"
            )),
            DecodeError::Field("AB".into(), "repeated")
        );
        assert_eq!(
            bad(with_data("<Data Name=\" \">1</Data>")),
            DecodeError::Field(String::new(), "empty name")
        );
        assert!(matches!(
            bad(with_data("<Data Name=\"A\"><x/></Data>")),
            DecodeError::Field(_, "has child elements")
        ));
        let many: String = (0..=MAX_RECORD_FIELDS)
            .map(|i| format!("<Data Name=\"F{i}\">x</Data>"))
            .collect();
        assert_eq!(bad(with_data(&many)), DecodeError::TooManyFields);
        assert!(matches!(
            bad(format!(
                "<Event xmlns=\"{EVENT_NS}\"><System>{sys}</System><UserData><R><F><x/></F></R></UserData></Event>"
            )),
            DecodeError::Field(_, "has child elements")
        ));
        for e in [
            DecodeError::TooLarge,
            DecodeError::NotAnEvent,
            DecodeError::System("x"),
            DecodeError::Field("a".into(), "b"),
            DecodeError::TooManyFields,
            DecodeError::Xml(XmlError("x".into())),
        ] {
            assert!(!e.to_string().is_empty());
        }
    }
}
