//! Alternate data streams as file-system context (#54): each named stream
//! with its size, a tag for the streams the OS and common software write
//! for their own bookkeeping, and whether its content looks executable.
//!
//! A benign tag says who usually writes a stream of that name, not that
//! its content is safe: anyone who can write the file can write a stream
//! with any name. So a tagged stream is still listed, and still sniffed.

#![forbid(unsafe_code)]

use super::ntfs::StreamList;

/// Why a stream name is known.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BenignStream {
    /// `Zone.Identifier`: the mark-of-the-web.
    ZoneIdentifier,
    /// The OS download-reputation check's stream. Its exact name is an OS
    /// identifier, matched here as the policy compilers match OS literals
    /// (docs/NAMING.md).
    DownloadReputation,
    /// `encryptable`: the OS thumbnail cache marker.
    Encryptable,
    /// `favicon`: a browser shortcut icon.
    Favicon,
    /// `{4c8cc155-6c1e-11d1-8e41-00c04fb9386d}`: the OS summary-information
    /// property stream (thumbnails and document properties).
    SummaryInformation,
    /// File-sync client metadata, named `com.<name>.attrs`.
    SyncMetadata,
    /// `Palisade.Origin`: Palisade's own provenance tag.
    PalisadeOrigin,
}

impl BenignStream {
    /// The tag for a stream name, compared ignoring ASCII case as NTFS
    /// compares stream names. `None` if the name is not a known one.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        let n = name.to_ascii_lowercase();
        Some(match n.as_str() {
            "zone.identifier" => Self::ZoneIdentifier,
            "smartscreen" => Self::DownloadReputation,
            "encryptable" => Self::Encryptable,
            "favicon" => Self::Favicon,
            "{4c8cc155-6c1e-11d1-8e41-00c04fb9386d}" | "\u{5}summaryinformation" => {
                Self::SummaryInformation
            }
            "palisade.origin" => Self::PalisadeOrigin,
            _ if n
                .strip_prefix("com.")
                .and_then(|r| r.strip_suffix(".attrs"))
                .is_some_and(|mid| !mid.is_empty()) =>
            {
                Self::SyncMetadata
            }
            _ => return None,
        })
    }
}

/// One alternate data stream, as [`FsStreams`] reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamInfo {
    /// The stream name, without the leading `:` or the `:$DATA` type.
    pub name: String,
    /// The size in bytes.
    pub size: u64,
    /// The known name, if it is one.
    pub benign: Option<BenignStream>,
    /// Whether the start of its content looks executable
    /// ([`crate::filetype`]). `None` if it was not read.
    pub is_executable_content: Option<bool>,
}

/// The alternate data streams of one file: `streams` in #54.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FsStreams {
    /// Every named data stream, in the order the OS lists them.
    pub streams: Vec<StreamInfo>,
    /// The OS listed more streams than were read.
    pub truncated: bool,
}

impl FsStreams {
    /// The named data streams of `list`, tagged, with no content read.
    #[must_use]
    pub fn from_list(list: &StreamList) -> Self {
        Self {
            streams: list
                .alternate()
                .map(|s| StreamInfo {
                    name: s.name.clone(),
                    size: s.size,
                    benign: BenignStream::from_name(&s.name),
                    is_executable_content: None,
                })
                .collect(),
            truncated: list.truncated,
        }
    }

    /// Whether any stream is known to hold executable-looking content.
    #[must_use]
    pub fn any_executable(&self) -> bool {
        self.streams
            .iter()
            .any(|s| s.is_executable_content == Some(true))
    }

    /// Whether the streams may hold executable content: one is known to,
    /// one was not sniffed (whatever its name), or the list was cut short.
    /// A missing fact never reads as "no executable content" (ADR 0018).
    #[must_use]
    pub fn may_hide_executable(&self) -> bool {
        self.truncated
            || self
                .streams
                .iter()
                .any(|s| s.is_executable_content != Some(false))
    }

    /// The streams that are not known names.
    pub fn unknown(&self) -> impl Iterator<Item = &StreamInfo> {
        self.streams.iter().filter(|s| s.benign.is_none())
    }
}

/// The most bytes of a stream read to sniff its content: enough for every
/// magic number and structural check in [`crate::filetype`].
pub const SNIFF_BYTES: usize = 64 * 1024;

/// Whether `head`, the first bytes of a stream, looks executable.
#[must_use]
pub fn sniff_executable(head: &[u8]) -> bool {
    crate::filetype::classify_bytes(head, None).is_executable_content()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fsctx::ntfs::StreamEntry;

    fn entry(name: &str, size: u64) -> StreamEntry {
        StreamEntry {
            name: name.to_owned(),
            kind: "$DATA".to_owned(),
            size,
            allocation_size: size,
        }
    }

    #[test]
    fn known_names_are_tagged_in_any_case() {
        for (name, tag) in [
            ("Zone.Identifier", BenignStream::ZoneIdentifier),
            ("ZONE.IDENTIFIER", BenignStream::ZoneIdentifier),
            ("SmartScreen", BenignStream::DownloadReputation),
            ("encryptable", BenignStream::Encryptable),
            ("favicon", BenignStream::Favicon),
            (
                "{4c8cc155-6c1e-11d1-8e41-00c04fb9386d}",
                BenignStream::SummaryInformation,
            ),
            ("\u{5}SummaryInformation", BenignStream::SummaryInformation),
            ("com.example.attrs", BenignStream::SyncMetadata),
            ("palisade.origin", BenignStream::PalisadeOrigin),
        ] {
            assert_eq!(BenignStream::from_name(name), Some(tag), "{name}");
        }
        for name in ["payload", "com.attrs", "zone.identifier2", ""] {
            assert_eq!(BenignStream::from_name(name), None, "{name}");
        }
    }

    #[test]
    fn streams_from_a_list() {
        let list = StreamList {
            streams: vec![
                entry("", 10),
                entry("Zone.Identifier", 26),
                entry("payload", 4096),
                StreamEntry {
                    kind: "$INDEX_ALLOCATION".to_owned(),
                    ..entry("$I30", 0)
                },
            ],
            truncated: false,
        };
        let mut s = FsStreams::from_list(&list);
        // Only named data streams, in order.
        let names: Vec<_> = s.streams.iter().map(|x| x.name.as_str()).collect();
        assert_eq!(names, ["Zone.Identifier", "payload"]);
        assert_eq!(s.unknown().count(), 1);
        // Nothing sniffed yet: may hide code, though none is known.
        assert!(!s.any_executable());
        assert!(s.may_hide_executable());
        for x in &mut s.streams {
            x.is_executable_content = Some(false);
        }
        assert!(!s.may_hide_executable());
        s.streams[1].is_executable_content = Some(true);
        assert!(s.any_executable() && s.may_hide_executable());
        // A cut-short list may hide code past the cut.
        let cut = FsStreams {
            truncated: true,
            ..FsStreams::default()
        };
        assert!(cut.may_hide_executable());
        assert!(!FsStreams::default().may_hide_executable());
    }

    #[test]
    fn sniffing_finds_executable_heads() {
        let mut pe = b"MZ".to_vec();
        pe.resize(512, 0);
        assert!(sniff_executable(&pe));
        assert!(sniff_executable(b"#!/bin/sh\necho hi\n"));
        assert!(!sniff_executable(b"[ZoneTransfer]\r\nZoneId=3\r\n"));
        assert!(!sniff_executable(b""));
    }
}
