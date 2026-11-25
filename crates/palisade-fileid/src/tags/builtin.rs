//! The built-in, read-only tag set.
//!
//! Every rule here matches a structure a format defines: a header, a
//! signature or a marker its own loader looks for. They are written as hex,
//! so no format's own name appears as text. Tags use descriptive, neutral
//! names (docs/NAMING.md). The fixtures in `tests/tags.rs` build a minimal
//! instance of each structure byte by byte; no third-party installer or
//! sample is checked in.
//!
//! A built-in tag is evidence of what a file contains, never of whether it
//! is trustworthy: anyone can build a file with these bytes.

#![forbid(unsafe_code)]

use super::rules::{Condition, Location, PatternSource, RuleSource, StringSource};

/// The version of the built-in rules. It is bumped whenever a change could
/// tag some file differently, so cached results can be thrown away.
pub const BUILTIN_VERSION: u16 = 1;

/// Every built-in tag, in the order the rules are checked and reported.
pub const BUILTIN_TAGS: &[&str] = &[
    INSTALLER_MSI_WRAPPER,
    INSTALLER_SCRIPTED_SETUP,
    INSTALLER_SETUP_LOADER,
    INSTALLER_BUNDLE_BOOTSTRAPPER,
    INSTALLER_SETUP_STREAM,
    ARCHIVE_SELF_EXTRACTING_CAB,
    ARCHIVE_SELF_EXTRACTING_ZIP,
    ARCHIVE_SELF_EXTRACTING_7Z,
    ARCHIVE_EMBEDDED_PE,
    ARCHIVE_EMBEDDED_ARCHIVE,
    SCRIPT_COMPILED_AUTOMATION,
    SCRIPT_FROZEN_PYTHON,
    TEST_MALWARE_TEST_FILE,
];

/// A PE image that carries a Windows Installer database: a compound file
/// header and the installer database root CLSID after it. Installer
/// wrappers and bootstrappers that unpack and run an MSI look like this.
pub const INSTALLER_MSI_WRAPPER: &str = "installer:msi-wrapper";
/// A PE image whose appended data holds the first header of a widely used
/// script-driven installer system: a flags word, the signature
/// `0xDEADBEEF` and the system's 12-byte marker.
pub const INSTALLER_SCRIPTED_SETUP: &str = "installer:scripted-setup";
/// A PE image with a setup loader offset table (a 12-byte ID, then a
/// version number below 16; the known versions are 1 and 2), as a widely
/// used Pascal-scripted setup system's loader stores in a data resource to
/// find its compressed setup program and data.
pub const INSTALLER_SETUP_LOADER: &str = "installer:setup-loader";
/// A bundle bootstrapper that chains installer packages: a PE image with
/// the bootstrapper's 8-byte section name in its section table, and that
/// section's header (magic `0x00F14300`, version 2).
pub const INSTALLER_BUNDLE_BOOTSTRAPPER: &str = "installer:bundle-bootstrapper";
/// A commercial setup-authoring engine's setup stream: its plain or
/// stream-format signature (each a 13-byte name and a NUL) in a PE
/// image's appended data.
pub const INSTALLER_SETUP_STREAM: &str = "installer:setup-stream";
/// A PE image that carries a cabinet (`MSCF` and a zero reserved field)
/// after its start, as self-extracting cabinet packages do (often in a
/// data resource).
pub const ARCHIVE_SELF_EXTRACTING_CAB: &str = "archive:self-extracting-cab";
/// A ZIP local file header in a PE image's appended data.
pub const ARCHIVE_SELF_EXTRACTING_ZIP: &str = "archive:self-extracting-zip";
/// A 7z signature in a PE image's appended data.
pub const ARCHIVE_SELF_EXTRACTING_7Z: &str = "archive:self-extracting-7z";
/// A PE image after the start of any file: `MZ`, then an `e_lfanew` of
/// `0x40` to `0x400` that points at `PE\0\0`. Droppers, installers,
/// archives stored without compression and some documents carry one.
pub const ARCHIVE_EMBEDDED_PE: &str = "archive:embedded-pe";
/// A cabinet, 7z, RAR (4 or 5) or ZIP local header signature after the
/// start of a file that does not itself start with a ZIP signature (a ZIP
/// archive has a local header for every entry).
pub const ARCHIVE_EMBEDDED_ARCHIVE: &str = "archive:embedded-archive";
/// A script compiled into an executable by a desktop automation
/// language's script-to-executable compiler: its 16-byte script marker,
/// in the appended data or a data resource of a PE image.
pub const SCRIPT_COMPILED_AUTOMATION: &str = "script:compiled-automation";
/// A frozen Python application: the 8-byte archive cookie that a widely
/// used freezer appends to its bootloader, in the appended data of a PE
/// image or in the last 64 KiB of any file.
pub const SCRIPT_FROZEN_PYTHON: &str = "script:frozen-python";
/// The industry-standard anti-malware test file: its 68-byte string at the
/// start of a file of at most 128 bytes. It is harmless, and detection
/// products treat it as a test detection.
pub const TEST_MALWARE_TEST_FILE: &str = "test:malware-test-file";

/// The compound file header: signature, a zero CLSID, then a minor
/// version, major version 3 or 4, and the little-endian byte order mark.
const CFB_HEADER: &str =
    "D0 CF 11 E0 A1 B1 1A E1 00000000 00000000 00000000 00000000 ?? 00 0? 00 FE FF";
/// The installer database root CLSID `{000C1084-0000-0000-C000-000000000046}`.
const MSI_CLSID: &str = "84 10 0C 00 00 00 00 00 C0 00 00 00 00 00 00 46";
const CAB: &str = "4D 53 43 46 00 00 00 00";
const ZIP_LOCAL: &str = "50 4B 03 04";
const SEVEN_ZIP: &str = "37 7A BC AF 27 1C";
const RAR4: &str = "52 61 72 21 1A 07 00";
const RAR5: &str = "52 61 72 21 1A 07 01 00";

/// The built-in rules.
pub(super) fn rules() -> Vec<RuleSource> {
    vec![
        rule(
            INSTALLER_MSI_WRAPPER,
            true,
            vec![from(CFB_HEADER, 1), anywhere(MSI_CLSID)],
            Condition::All,
        ),
        rule(
            INSTALLER_SCRIPTED_SETUP,
            true,
            vec![overlay(
                "?? ?? ?? ?? EF BE AD DE 4E 75 6C 6C 73 6F 66 74 49 6E 73 74",
            )],
            Condition::Any,
        ),
        rule(
            INSTALLER_SETUP_LOADER,
            true,
            vec![anywhere("72 44 6C 50 74 53 CD E6 D7 7B 0B 2A 0? 00 00 00")],
            Condition::Any,
        ),
        rule(
            INSTALLER_BUNDLE_BOOTSTRAPPER,
            true,
            vec![
                range("2E 77 69 78 62 75 72 6E", 0, 0x10_0000 + 0x1_0000),
                anywhere("00 43 F1 00 02 00 00 00"),
            ],
            Condition::All,
        ),
        rule(
            INSTALLER_SETUP_STREAM,
            true,
            vec![
                overlay("49 6E 73 74 61 6C 6C 53 68 69 65 6C 64 00"),
                overlay("49 53 53 65 74 75 70 53 74 72 65 61 6D 00"),
            ],
            Condition::Any,
        ),
        rule(
            ARCHIVE_SELF_EXTRACTING_CAB,
            true,
            vec![from(CAB, 1)],
            Condition::Any,
        ),
        rule(
            ARCHIVE_SELF_EXTRACTING_ZIP,
            true,
            vec![overlay(ZIP_LOCAL)],
            Condition::Any,
        ),
        rule(
            ARCHIVE_SELF_EXTRACTING_7Z,
            true,
            vec![overlay(SEVEN_ZIP)],
            Condition::Any,
        ),
        RuleSource {
            tag: ARCHIVE_EMBEDDED_PE.to_owned(),
            require_pe: false,
            max_file_size: None,
            unless_start: None,
            strings: vec![StringSource {
                pattern: PatternSource::PeImage,
                location: Location::From(1),
            }],
            condition: Condition::Any,
        },
        RuleSource {
            unless_start: Some(PatternSource::Hex("50 4B".to_owned())),
            ..rule(
                ARCHIVE_EMBEDDED_ARCHIVE,
                false,
                vec![
                    from(CAB, 1),
                    from(SEVEN_ZIP, 1),
                    from(RAR4, 1),
                    from(RAR5, 1),
                    from(ZIP_LOCAL, 1),
                ],
                Condition::Any,
            )
        },
        rule(
            SCRIPT_COMPILED_AUTOMATION,
            true,
            vec![anywhere("A3 48 4B BE 98 6C 4A A9 99 4C 53 0A 86 D6 48 7D")],
            Condition::Any,
        ),
        rule(
            SCRIPT_FROZEN_PYTHON,
            false,
            vec![
                overlay("4D 45 49 0C 0B 0A 0B 0E"),
                StringSource {
                    pattern: PatternSource::Hex("4D 45 49 0C 0B 0A 0B 0E".to_owned()),
                    location: Location::Tail(64 * 1024),
                },
            ],
            Condition::Any,
        ),
        RuleSource {
            max_file_size: Some(128),
            ..rule(
                TEST_MALWARE_TEST_FILE,
                false,
                vec![StringSource {
                    pattern: PatternSource::Hex(MALWARE_TEST_STRING.to_owned()),
                    location: Location::At(0),
                }],
                Condition::Any,
            )
        },
    ]
}

/// The 68-byte anti-malware test string, as hex, so the source file is
/// never itself taken for the test file.
pub(super) const MALWARE_TEST_STRING: &str = "\
    58 35 4F 21 50 25 40 41 50 5B 34 5C 50 5A 58 35 34 28 50 5E 29 37 43 43 \
    29 37 7D 24 45 49 43 41 52 2D 53 54 41 4E 44 41 52 44 2D 41 4E 54 49 56 \
    49 52 55 53 2D 54 45 53 54 2D 46 49 4C 45 21 24 48 2B 48 2A";

fn rule(
    tag: &str,
    require_pe: bool,
    strings: Vec<StringSource>,
    condition: Condition,
) -> RuleSource {
    RuleSource {
        tag: tag.to_owned(),
        require_pe,
        max_file_size: None,
        unless_start: None,
        strings,
        condition,
    }
}

fn string(hex: &str, location: Location) -> StringSource {
    StringSource {
        pattern: PatternSource::Hex(hex.to_owned()),
        location,
    }
}

fn anywhere(hex: &str) -> StringSource {
    string(hex, Location::Anywhere)
}

fn from(hex: &str, start: u64) -> StringSource {
    string(hex, Location::From(start))
}

fn range(hex: &str, start: u64, end: u64) -> StringSource {
    string(hex, Location::Range { start, end })
}

fn overlay(hex: &str) -> StringSource {
    string(hex, Location::Overlay)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tags_are_listed_in_order() {
        let tags: Vec<String> = rules().into_iter().map(|r| r.tag).collect();
        assert_eq!(tags, BUILTIN_TAGS);
    }

    #[test]
    fn rules_compile() {
        super::super::rules::compile(&rules(), None).unwrap();
    }
}
