//! Mark-of-the-web: parsing the `Zone.Identifier` alternate data stream.
//!
//! Browsers, mail clients and archive tools that save a file from the
//! internet attach a `Zone.Identifier` stream to it. The stream is a small
//! INI file:
//!
//! ```text
//! [ZoneTransfer]
//! ZoneId=3
//! ReferrerUrl=https://example.org/downloads
//! HostUrl=https://example.org/tool.zip
//! ```
//!
//! [`parse_zone_identifier`] reads it into a [`Motw`].
//!
//! # Not a trust signal
//!
//! Any process that can write a file can also write, change or delete its
//! `Zone.Identifier` stream, and many tools and file systems drop it (FAT
//! volumes have no streams, and some archive tools do not pass it on). So:
//!
//! - **a mark** says the writer *claims* the file came from that zone and
//!   URL. Policy may use it to treat a file **more** strictly. It must never
//!   make a file more trusted;
//! - **no mark** says nothing: it is not evidence that a file is local.
//!
//! # Parsing rules
//!
//! The stream is untrusted input. The parser never fails; it returns what it
//! could read plus [`MotwWarning`]s.
//!
//! - At most [`MAX_ZONE_IDENTIFIER_BYTES`] are read; anything after is
//!   ignored and reported. A line the limit cuts is not parsed, because
//!   its value may be incomplete (`ZoneId=1` of `ZoneId=13`). At most
//!   [`MAX_MOTW_WARNINGS`] warnings are kept.
//! - UTF-8 (with or without a byte order mark) and UTF-16LE with a byte
//!   order mark are accepted. Invalid sequences, and a final odd byte of
//!   UTF-16LE, are replaced with U+FFFD and reported.
//! - A zone is any run of ASCII digits that fits in a `u32`, leading zeros
//!   included (`ZoneId=003` is the internet zone).
//! - Section names and keys are compared ignoring ASCII case. Whitespace
//!   around keys and values is removed. Lines starting with `;` or `#` are
//!   comments. Only keys in the `[ZoneTransfer]` section count.
//! - If a key appears more than once, the **first** value is used, as the
//!   OS's INI reader does. For `ZoneId` and `AppZoneId` the most restrictive
//!   value seen is also kept, in [`Motw::strictest_zone`], so a caller that
//!   wants to be conservative can use that instead.

#![forbid(unsafe_code)]

use std::fmt;

/// The most bytes of a `Zone.Identifier` stream that are parsed.
pub const MAX_ZONE_IDENTIFIER_BYTES: usize = 64 * 1024;

/// The most warnings kept. Further warnings are dropped.
pub const MAX_MOTW_WARNINGS: usize = 32;

/// The keys this parser reads, lower case. Other keys are ignored and not
/// tracked, so the work per line is bounded.
const KNOWN_KEYS: [&str; 5] = [
    "zoneid",
    "appzoneid",
    "hosturl",
    "referrerurl",
    "lastwriterpackagefamilyname",
];

/// A URL security zone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Zone {
    /// 0: the local computer.
    LocalMachine,
    /// 1: the local intranet.
    Intranet,
    /// 2: trusted sites.
    Trusted,
    /// 3: the internet.
    Internet,
    /// 4: restricted (untrusted) sites.
    Untrusted,
    /// Any other number. Custom zones exist, so the value is kept.
    Other(u32),
}

impl Zone {
    /// The zone for a `ZoneId` number.
    #[must_use]
    pub const fn from_id(id: u32) -> Self {
        match id {
            0 => Self::LocalMachine,
            1 => Self::Intranet,
            2 => Self::Trusted,
            3 => Self::Internet,
            4 => Self::Untrusted,
            n => Self::Other(n),
        }
    }

    /// The `ZoneId` number.
    #[must_use]
    pub const fn id(self) -> u32 {
        match self {
            Self::LocalMachine => 0,
            Self::Intranet => 1,
            Self::Trusted => 2,
            Self::Internet => 3,
            Self::Untrusted => 4,
            Self::Other(n) => n,
        }
    }

    /// How restrictive the zone is, for picking the strictest of several:
    /// local machine < intranet < trusted < internet < untrusted < any other
    /// value. An unknown zone is treated as the most restrictive.
    #[must_use]
    pub const fn strictness(self) -> u8 {
        match self {
            Self::LocalMachine => 0,
            Self::Intranet => 1,
            Self::Trusted => 2,
            Self::Internet => 3,
            Self::Untrusted => 4,
            Self::Other(_) => 5,
        }
    }

    /// True for the internet, restricted and unknown zones: the file claims
    /// to come from outside the organisation.
    #[must_use]
    pub const fn is_external(self) -> bool {
        self.strictness() >= 3
    }
}

impl fmt::Display for Zone {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LocalMachine => f.write_str("local machine (0)"),
            Self::Intranet => f.write_str("intranet (1)"),
            Self::Trusted => f.write_str("trusted (2)"),
            Self::Internet => f.write_str("internet (3)"),
            Self::Untrusted => f.write_str("untrusted (4)"),
            Self::Other(n) => write!(f, "zone {n}"),
        }
    }
}

/// Something unexpected in a `Zone.Identifier` stream.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum MotwWarning {
    /// The stream is longer than [`MAX_ZONE_IDENTIFIER_BYTES`]; the rest
    /// was not parsed.
    Truncated,
    /// The text is not valid UTF-8 or UTF-16LE; bad sequences were replaced.
    InvalidEncoding,
    /// No `[ZoneTransfer]` section.
    MissingSection,
    /// `[ZoneTransfer]` has no `ZoneId`.
    MissingZoneId,
    /// A `ZoneId` or `AppZoneId` value is not a number.
    InvalidZoneId(String),
    /// A key appears more than once in `[ZoneTransfer]`; the first value
    /// was used.
    DuplicateKey(String),
}

/// The parsed mark-of-the-web.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Motw {
    /// `ZoneId`: the zone the file was saved from (first value).
    pub zone: Option<Zone>,
    /// The most restrictive `ZoneId` and `AppZoneId` value in the stream.
    pub strictest_zone: Option<Zone>,
    /// `HostUrl`: where the file was downloaded from.
    pub host_url: Option<String>,
    /// `ReferrerUrl`: the page that linked to it.
    pub referrer_url: Option<String>,
    /// `LastWriterPackageFamilyName`: the packaged app that wrote the mark.
    pub writer_pfn: Option<String>,
    /// `AppZoneId`: a zone set by the writing application.
    pub app_zone: Option<Zone>,
    /// Anything unexpected.
    pub warnings: Vec<MotwWarning>,
}

impl Motw {
    /// True if the mark claims an external origin: the first `ZoneId`,
    /// or the strictest zone value in the stream, is internet, restricted
    /// or unknown.
    #[must_use]
    pub fn claims_external_origin(&self) -> bool {
        self.zone.is_some_and(Zone::is_external)
            || self.strictest_zone.is_some_and(Zone::is_external)
    }
}

/// Decodes the stream bytes to text.
fn decode(bytes: &[u8], warnings: &mut Vec<MotwWarning>) -> String {
    if let Some(rest) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        let units: Vec<u16> = rest
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect();
        let odd = rest.len() % 2 != 0;
        let mut text = String::from_utf16_lossy(&units);
        if odd {
            // An incomplete code unit is replaced, not dropped, so a value
            // it ends cannot look complete.
            text.push(char::REPLACEMENT_CHARACTER);
        }
        if odd || String::from_utf16(&units).is_err() {
            warnings.push(MotwWarning::InvalidEncoding);
        }
        return text;
    }
    let body = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);
    match std::str::from_utf8(body) {
        Ok(s) => s.to_owned(),
        Err(_) => {
            warnings.push(MotwWarning::InvalidEncoding);
            String::from_utf8_lossy(body).into_owned()
        }
    }
}

fn parse_zone(value: &str, warnings: &mut Vec<MotwWarning>) -> Option<Zone> {
    // The stream size limit bounds the length; `parse` rejects overflow.
    if !value.is_empty()
        && value.bytes().all(|b| b.is_ascii_digit())
        && let Ok(n) = value.parse::<u32>()
    {
        return Some(Zone::from_id(n));
    }
    warn(
        warnings,
        MotwWarning::InvalidZoneId(value.chars().take(64).collect()),
    );
    None
}

fn warn(warnings: &mut Vec<MotwWarning>, w: MotwWarning) {
    if warnings.len() < MAX_MOTW_WARNINGS {
        warnings.push(w);
    }
}

fn stricter(a: Option<Zone>, b: Zone) -> Zone {
    match a {
        Some(a) if a.strictness() >= b.strictness() => a,
        _ => b,
    }
}

/// Parses a `Zone.Identifier` stream. See the module documentation.
#[must_use]
pub fn parse_zone_identifier(bytes: &[u8]) -> Motw {
    let mut motw = Motw::default();
    let (input, truncated) = match bytes.get(..MAX_ZONE_IDENTIFIER_BYTES) {
        Some(head) if bytes.len() > MAX_ZONE_IDENTIFIER_BYTES => {
            motw.warnings.push(MotwWarning::Truncated);
            (head, true)
        }
        _ => (bytes, false),
    };
    let mut text = decode(input, &mut motw.warnings);
    if truncated {
        // The limit cut the last line; drop it rather than read part of a
        // value. Complete lines before it are kept.
        let keep = text.rfind('\n').map_or(0, |i| i + 1);
        text.truncate(keep);
    }

    let mut in_section = false;
    let mut saw_section = false;
    let mut seen = [false; KNOWN_KEYS.len()];
    for raw in text.lines() {
        // Some writers leave NUL padding after the text.
        let line = raw.trim_matches(|c: char| c.is_whitespace() || c == '\0');
        if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            in_section = name.trim().eq_ignore_ascii_case("ZoneTransfer");
            saw_section |= in_section;
            continue;
        }
        if !in_section {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim().to_ascii_lowercase();
        let value = value.trim_matches(|c: char| c.is_whitespace() || c == '\0');
        let Some(index) = KNOWN_KEYS.iter().position(|k| *k == key) else {
            continue;
        };
        let Some(slot) = seen.get_mut(index) else {
            continue;
        };
        let first = !*slot;
        if *slot {
            // Each key is reported at most once.
            let reported = motw
                .warnings
                .iter()
                .any(|w| matches!(w, MotwWarning::DuplicateKey(k) if *k == key));
            if !reported {
                warn(&mut motw.warnings, MotwWarning::DuplicateKey(key.clone()));
            }
        }
        *slot = true;
        let text_value = || (!value.is_empty()).then(|| value.to_owned());
        match key.as_str() {
            "zoneid" | "appzoneid" => {
                if let Some(z) = parse_zone(value, &mut motw.warnings) {
                    motw.strictest_zone = Some(stricter(motw.strictest_zone, z));
                    if first {
                        if key == "zoneid" {
                            motw.zone = Some(z);
                        } else {
                            motw.app_zone = Some(z);
                        }
                    }
                }
            }
            "hosturl" if first => motw.host_url = text_value(),
            "referrerurl" if first => motw.referrer_url = text_value(),
            "lastwriterpackagefamilyname" if first => motw.writer_pfn = text_value(),
            _ => {}
        }
    }
    if !saw_section {
        warn(&mut motw.warnings, MotwWarning::MissingSection);
    } else if !seen.first().copied().unwrap_or(false) {
        warn(&mut motw.warnings, MotwWarning::MissingZoneId);
    }
    motw
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typical_browser_download() {
        let m = parse_zone_identifier(
            b"[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://example.org/page\r\nHostUrl=https://example.org/tool.zip\r\n",
        );
        assert_eq!(m.zone, Some(Zone::Internet));
        assert_eq!(m.strictest_zone, Some(Zone::Internet));
        assert_eq!(m.referrer_url.as_deref(), Some("https://example.org/page"));
        assert_eq!(m.host_url.as_deref(), Some("https://example.org/tool.zip"));
        assert!(m.warnings.is_empty(), "{:?}", m.warnings);
        assert!(m.claims_external_origin());
    }

    #[test]
    fn packaged_writer_and_app_zone() {
        let m = parse_zone_identifier(
            b"[ZoneTransfer]\nZoneId=3\nLastWriterPackageFamilyName=Example.App_0a1b2c3d4e5f6\nAppZoneId=4\n",
        );
        assert_eq!(m.writer_pfn.as_deref(), Some("Example.App_0a1b2c3d4e5f6"));
        assert_eq!(m.app_zone, Some(Zone::Untrusted));
        assert_eq!(m.strictest_zone, Some(Zone::Untrusted));
    }

    #[test]
    fn case_whitespace_comments_and_other_sections() {
        let m = parse_zone_identifier(
            b"; comment\n[Other]\nZoneId=4\n[ zonetransfer ]\n  zoneid =  2 \n# x\nHOSTURL= about:internet\n",
        );
        assert_eq!(m.zone, Some(Zone::Trusted));
        assert_eq!(m.strictest_zone, Some(Zone::Trusted));
        assert_eq!(m.host_url.as_deref(), Some("about:internet"));
    }

    #[test]
    fn duplicates_use_first_and_record_strictest() {
        let m = parse_zone_identifier(b"[ZoneTransfer]\nZoneId=0\nZoneId=3\nZoneId=1\n");
        assert_eq!(m.zone, Some(Zone::LocalMachine));
        assert_eq!(m.strictest_zone, Some(Zone::Internet));
        assert_eq!(m.warnings, vec![MotwWarning::DuplicateKey("zoneid".into())]);
        assert!(m.claims_external_origin());
    }

    #[test]
    fn utf16_and_bom() {
        let text = "[ZoneTransfer]\r\nZoneId=3\r\n";
        let mut bytes = vec![0xFF, 0xFE];
        for u in text.encode_utf16() {
            bytes.extend_from_slice(&u.to_le_bytes());
        }
        assert_eq!(parse_zone_identifier(&bytes).zone, Some(Zone::Internet));
        let mut utf8 = vec![0xEF, 0xBB, 0xBF];
        utf8.extend_from_slice(text.as_bytes());
        let m = parse_zone_identifier(&utf8);
        assert_eq!(m.zone, Some(Zone::Internet));
        assert!(m.warnings.is_empty());
        // An odd trailing byte is reported.
        bytes.push(0x41);
        assert!(
            parse_zone_identifier(&bytes)
                .warnings
                .contains(&MotwWarning::InvalidEncoding)
        );
        // ...and replaced, so the value it ends is not accepted as valid,
        // while complete lines before it are kept.
        let text = "[ZoneTransfer]\r\nHostUrl=x\r\nZoneId=3";
        let mut bytes = vec![0xFF, 0xFE];
        for u in text.encode_utf16() {
            bytes.extend_from_slice(&u.to_le_bytes());
        }
        bytes.push(0x41);
        let m = parse_zone_identifier(&bytes);
        assert_eq!(m.zone, None);
        assert_eq!(m.host_url.as_deref(), Some("x"));
        assert!(m.warnings.contains(&MotwWarning::InvalidEncoding));
        assert!(
            m.warnings
                .iter()
                .any(|w| matches!(w, MotwWarning::InvalidZoneId(_)))
        );
    }

    #[test]
    fn leading_zeros_are_accepted() {
        let m = parse_zone_identifier(b"[ZoneTransfer]\nZoneId=00000000003\n");
        assert_eq!(m.zone, Some(Zone::Internet));
        assert!(m.warnings.is_empty(), "{:?}", m.warnings);
        let m = parse_zone_identifier(b"[ZoneTransfer]\nZoneId=0004294967295\n");
        assert_eq!(m.zone, Some(Zone::Other(u32::MAX)));
        let m = parse_zone_identifier(b"[ZoneTransfer]\nZoneId=4294967296\n");
        assert_eq!(m.zone, None);
    }

    #[test]
    fn a_line_cut_by_the_limit_is_not_parsed() {
        // `ZoneId=13` with the `1` as the last byte read.
        let mut bytes = b"[ZoneTransfer]\n".to_vec();
        let pad = MAX_ZONE_IDENTIFIER_BYTES - bytes.len() - "ZoneId=1".len() - 1;
        bytes.extend(std::iter::repeat_n(b';', pad));
        bytes.extend_from_slice(b"\nZoneId=13\n");
        assert_eq!(bytes[MAX_ZONE_IDENTIFIER_BYTES - 1], b'1');
        let m = parse_zone_identifier(&bytes);
        assert_eq!(m.zone, None);
        assert!(m.warnings.contains(&MotwWarning::Truncated));
        // Without the cut, the same line is read.
        let m = parse_zone_identifier(b"[ZoneTransfer]\nZoneId=13");
        assert_eq!(m.zone, Some(Zone::Other(13)));
    }

    #[test]
    fn bad_input_never_fails() {
        let m = parse_zone_identifier(b"");
        assert_eq!(m.zone, None);
        assert_eq!(m.warnings, vec![MotwWarning::MissingSection]);

        let m = parse_zone_identifier(b"[ZoneTransfer]\nZoneId=three\nZoneId=-1\n");
        assert_eq!(m.zone, None);
        assert!(matches!(m.warnings[0], MotwWarning::InvalidZoneId(_)));

        let m = parse_zone_identifier(b"[ZoneTransfer]\nZoneId=99999999999\n");
        assert_eq!(m.zone, None);
        assert!(matches!(m.warnings[0], MotwWarning::InvalidZoneId(_)));

        let m = parse_zone_identifier(&[0x5B, 0xFF, 0xFE, 0x00, 0x80]);
        assert!(m.warnings.contains(&MotwWarning::InvalidEncoding));

        let m = parse_zone_identifier(b"[ZoneTransfer]\nHostUrl=x\n");
        assert_eq!(m.warnings, vec![MotwWarning::MissingZoneId]);
    }

    #[test]
    fn custom_zone_is_strictest() {
        let m = parse_zone_identifier(b"[ZoneTransfer]\nZoneId=1000\n");
        assert_eq!(m.zone, Some(Zone::Other(1000)));
        assert!(m.claims_external_origin());
        assert_eq!(Zone::from_id(3).id(), 3);
    }

    #[test]
    fn nul_padding_is_ignored() {
        let m = parse_zone_identifier(b"[ZoneTransfer]\r\nZoneId=3\0\0");
        assert_eq!(m.zone, Some(Zone::Internet));
        assert!(m.warnings.is_empty(), "{:?}", m.warnings);
    }

    #[test]
    fn warnings_are_capped() {
        let mut text = String::from("[ZoneTransfer]\n");
        for i in 0..10_000 {
            text.push_str(&format!("ZoneId=x{i}\nUnknownKey{i}=1\n"));
        }
        let m = parse_zone_identifier(text.as_bytes());
        assert_eq!(m.warnings.len(), MAX_MOTW_WARNINGS);
    }

    #[test]
    fn oversized_stream_is_truncated() {
        let mut bytes = b"[ZoneTransfer]\nZoneId=3\n".to_vec();
        bytes.resize(MAX_ZONE_IDENTIFIER_BYTES + 10, b' ');
        bytes.extend_from_slice(b"\nZoneId=0\n");
        let m = parse_zone_identifier(&bytes);
        assert_eq!(m.zone, Some(Zone::Internet));
        assert!(m.warnings.contains(&MotwWarning::Truncated));
    }
}
