//! Identifiers the OS matches byte for byte. They name the OS vendor, so
//! this file is excluded from the banned-terms scan (`docs/banned-terms.txt`).

#![forbid(unsafe_code)]

/// The namespace of rendered event-log XML.
pub const EVENT_NS: &str = "http://schemas.microsoft.com/win/2004/08/events/event";
