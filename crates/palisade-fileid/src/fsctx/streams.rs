//! Alternate data streams as file-system context (#54): each named stream
//! with its size, a tag for the streams the OS and common software write
//! for their own bookkeeping, and whether its content looks executable.
//!
//! A benign tag says who usually writes a stream of that name, not that
//! its content is safe: anyone who can write the file can write a stream
//! with any name. So a tagged stream is still listed, and still sniffed.

#![forbid(unsafe_code)]

use std::ffi::OsStr;
use std::io::{Read, Seek};

use super::ntfs::StreamList;
use crate::filetype::{Classification, classify};

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
    /// Whether its content is executable, or may be: [`sniff_stream`].
    /// `Some(true)` also when the classifier could not establish what the
    /// content is (a parse error), so a damaged or oversized container is
    /// never reported as plain data. `None` if it was not read.
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

/// Whether a classification of a stream's content counts as executable
/// for [`StreamInfo::is_executable_content`]: executable content, or any
/// classification with a parse error. A parse error means the kind was not
/// established (a compound file whose directory could not be read is
/// `OtherCfb`, though it may be an installer), and a missing fact must not
/// make the stream look like data (ADR 0018). `Some(true)` rather than
/// `None` is used for it, so [`FsStreams::any_executable`] fails closed as
/// well as [`FsStreams::may_hide_executable`].
#[must_use]
pub fn counts_as_executable(c: &Classification) -> bool {
    c.is_executable_content() || c.parse_error.is_some()
}

/// Classifies the content of the stream named `name` from `reader`, the
/// open stream, and says whether it [`counts_as_executable`].
///
/// The whole stream is available to the classifier, which bounds its own
/// reads (the first 64 KiB, then a few targeted reads), so a structure past
/// the first 64 KiB, such as an installer's directory, is still found. The
/// stream's own name is the name hint: the classifier uses the extension to
/// tell batch, PowerShell and HTML application content from plain text,
/// and never lets a harmless extension hide content it recognises.
pub fn sniff_stream<R: Read + Seek + ?Sized>(reader: &mut R, name: &str) -> bool {
    counts_as_executable(&classify(reader, Some(OsStr::new(name))))
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

    fn sniff(data: &[u8], name: &str) -> bool {
        sniff_stream(&mut std::io::Cursor::new(data), name)
    }

    #[test]
    fn sniffing_finds_executable_content() {
        let mut pe = b"MZ".to_vec();
        pe.resize(512, 0);
        assert!(sniff(&pe, "payload"));
        assert!(sniff(b"#!/bin/sh\necho hi\n", "payload"));
        assert!(!sniff(b"[ZoneTransfer]\r\nZoneId=3\r\n", "Zone.Identifier"));
        assert!(!sniff(b"", "empty"));
        assert!(!sniff(b"just some words", "notes"));
    }

    /// A version 3 compound file whose directory starts at `sector`, with
    /// `clsid` on its root entry: just the header and the root entry, all
    /// the classifier reads.
    fn compound_file(sector: u32, clsid: [u8; 16]) -> Vec<u8> {
        let offset = (usize::try_from(sector).unwrap() + 1) << 9;
        let mut b = vec![0_u8; offset + 128];
        b[..8].copy_from_slice(&[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]);
        b[0x18..0x1a].copy_from_slice(&0x3e_u16.to_le_bytes());
        b[0x1a..0x1c].copy_from_slice(&3_u16.to_le_bytes());
        b[0x1c..0x1e].copy_from_slice(&0xfffe_u16.to_le_bytes());
        b[0x1e..0x20].copy_from_slice(&9_u16.to_le_bytes());
        b[0x30..0x34].copy_from_slice(&sector.to_le_bytes());
        // The root entry: "Root Entry", type 5, the CLSID.
        let name: Vec<u8> = "Root Entry"
            .encode_utf16()
            .chain([0])
            .flat_map(u16::to_le_bytes)
            .collect();
        b[offset..offset + name.len()].copy_from_slice(&name);
        b[offset + 0x40..offset + 0x42]
            .copy_from_slice(&u16::try_from(name.len()).unwrap().to_le_bytes());
        b[offset + 0x42] = 5;
        b[offset + 0x50..offset + 0x60].copy_from_slice(&clsid);
        b
    }

    /// `{000C1084-0000-0000-C000-000000000046}`, the installer database CLSID.
    const MSI: [u8; 16] = [
        0x84, 0x10, 0x0c, 0x00, 0, 0, 0, 0, 0xc0, 0, 0, 0, 0, 0, 0, 0x46,
    ];

    #[test]
    fn an_installer_whose_directory_is_past_64_kib_is_executable() {
        // The reviewer's case: the directory at sector 200, 100 KiB in.
        let msi = compound_file(200, MSI);
        assert!(msi.len() > 64 * 1024);
        let full = classify(&mut std::io::Cursor::new(&msi[..]), None);
        assert_eq!(
            full.content_kind,
            crate::filetype::FileKind::Msi,
            "{full:?}"
        );
        assert!(sniff(&msi, "payload"));
        // Only the first 64 KiB, as the stream reader used to pass: the
        // directory cannot be read, the kind is `OtherCfb` with a parse
        // error, and that still counts as executable, never as data.
        let head = classify(&mut std::io::Cursor::new(&msi[..64 * 1024]), None);
        assert!(
            head.parse_error.is_some() && !head.is_executable_content(),
            "{head:?}"
        );
        assert!(counts_as_executable(&head));
        assert!(sniff(&msi[..64 * 1024], "payload"));
        // A plain compound file with a readable directory is data.
        let other = compound_file(200, [7; 16]);
        assert!(!sniff(&other, "payload"));
    }

    #[test]
    fn the_stream_name_is_the_name_hint() {
        for (name, content) in [
            ("x.bat", &b"@echo off\r\ncopy a b\r\n"[..]),
            ("x.cmd", &b"@echo off\r\ncopy a b\r\n"[..]),
            ("x.ps1", &b"Get-ChildItem | Remove-Item\r\n"[..]),
            (
                "x.hta",
                &b"<html><head><title>t</title></head><body>hi</body></html>"[..],
            ),
        ] {
            assert!(sniff(content, name), "{name}");
        }
        // A harmless name does not hide content the classifier knows.
        let vbs = b"Set sh = CreateObject(\"WScript.Shell\")\r\nsh.Run \"cmd.exe\"\r\n";
        assert!(sniff(vbs, "notes.txt"));
        assert!(sniff(vbs, "payload"));
    }
}
