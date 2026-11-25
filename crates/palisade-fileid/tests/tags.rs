//! Content tagging (#44, feature `content-rules`).
//!
//! Every fixture is built byte by byte here or by `common::PeBuilder`: a
//! minimal instance of the structure each built-in rule looks for. No
//! third-party installer, archive or sample is checked in.

#![allow(clippy::cast_possible_truncation, clippy::unwrap_used)]
// The fixtures and the fuzz seed writer build without the feature, because
// `cargo xtask fuzz` seeds the corpus with plain `cargo test`; the tests
// themselves need it.
#![cfg_attr(not(feature = "content-rules"), allow(dead_code))]

mod common;

use common::*;

fn hex(h: &str) -> Vec<u8> {
    let digits: Vec<u8> = h.bytes().filter(u8::is_ascii_hexdigit).collect();
    digits
        .chunks(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}

/// A plain executable with `overlay` appended.
fn pe_with_overlay(overlay: &[u8]) -> Vec<u8> {
    PeBuilder {
        overlay: overlay.to_vec(),
        ..PeBuilder::default()
    }
    .build()
}

/// A plain executable with `data` in a second, read-only data section.
fn pe_with_data(data: Vec<u8>) -> Vec<u8> {
    PeBuilder::default()
        .section(
            ".rdata",
            data,
            IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
        )
        .build()
}

/// A plain executable with `data` as a data (`RT_RCDATA`) resource.
fn pe_with_resource(name_id: u16, data: Vec<u8>) -> Vec<u8> {
    let mut b = PeBuilder::default();
    b.resources.push(Leaf {
        type_id: 10,
        name_id,
        lang: 0x0409,
        data,
    });
    b.build()
}

// ---------------------------------------------------------------------------
// Structures the built-in rules look for
// ---------------------------------------------------------------------------

/// A minimal version 3 compound file header and root entry with the
/// installer database CLSID.
fn msi() -> Vec<u8> {
    let mut out = vec![0_u8; 1024];
    out[..8].copy_from_slice(&[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]);
    out[0x18] = 0x3e;
    out[0x1a] = 3;
    out[0x1c..0x1e].copy_from_slice(&[0xfe, 0xff]);
    out[0x1e] = 9;
    out[512 + 0x42] = 5;
    out[512 + 0x50..512 + 0x60]
        .copy_from_slice(&hex("84 10 0C 00 00 00 00 00 C0 00 00 00 00 00 00 46"));
    out
}

/// The scripted installer's first header: flags, signature, marker, then
/// two lengths.
fn scripted_setup_header() -> Vec<u8> {
    let mut h = 0_u32.to_le_bytes().to_vec();
    h.extend_from_slice(&0xdead_beef_u32.to_le_bytes());
    for word in [0x6c6c_754e_u32, 0x7466_6f73, 0x7473_6e49] {
        h.extend_from_slice(&word.to_le_bytes());
    }
    h.extend_from_slice(&0x100_u32.to_le_bytes());
    h.extend_from_slice(&0x200_u32.to_le_bytes());
    h
}

/// The setup loader offset table, version `version`.
fn setup_loader_table(version: u32) -> Vec<u8> {
    let mut t = hex("72 44 6C 50 74 53 CD E6 D7 7B 0B 2A");
    t.extend_from_slice(&version.to_le_bytes());
    t.extend_from_slice(&[0; 40]);
    t
}

/// The bundle bootstrapper's section header: magic, version, a bundle
/// code, then zeroed fields and one container.
fn bundle_section(version: u32) -> Vec<u8> {
    let mut s = 0x00f1_4300_u32.to_le_bytes().to_vec();
    s.extend_from_slice(&version.to_le_bytes());
    s.extend_from_slice(&[0x11; 16]);
    s.extend_from_slice(&[0; 20]);
    s.extend_from_slice(&1_u32.to_le_bytes());
    s.extend_from_slice(&0x400_u32.to_le_bytes());
    s
}

/// A bundle bootstrapper: its own section, named by the bootstrapper's
/// 8-byte section name.
fn bundle(version: u32) -> Vec<u8> {
    let mut b = PeBuilder::default().section(
        "",
        bundle_section(version),
        IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
    );
    b.sections.last_mut().unwrap().name = hex("2E 77 69 78 62 75 72 6E").try_into().unwrap();
    b.build()
}

/// A cabinet header: signature, reserved zero, sizes.
fn cab() -> Vec<u8> {
    let mut c = b"MSCF\0\0\0\0".to_vec();
    c.extend_from_slice(&0x60_u32.to_le_bytes());
    c.extend_from_slice(&[0; 52]);
    c
}

/// A stored ZIP of one empty entry.
fn zip() -> Vec<u8> {
    let mut z = b"PK\x03\x04\x14\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0a".to_vec();
    let dir = z.len() as u32;
    z.extend_from_slice(b"PK\x01\x02\x14\0\x14\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0");
    z.extend_from_slice(b"\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0a");
    let size = z.len() as u32 - dir;
    z.extend_from_slice(b"PK\x05\x06\0\0\0\0\x01\0\x01\0");
    z.extend_from_slice(&size.to_le_bytes());
    z.extend_from_slice(&dir.to_le_bytes());
    z.extend_from_slice(&[0, 0]);
    z
}

fn seven_zip() -> Vec<u8> {
    let mut s = hex("37 7A BC AF 27 1C 00 04");
    s.extend_from_slice(&[0; 24]);
    s
}

/// The compiled automation script marker, then a version tag.
fn automation_script() -> Vec<u8> {
    let mut s = hex("A3 48 4B BE 98 6C 4A A9 99 4C 53 0A 86 D6 48 7D");
    s.extend_from_slice(&[0x11; 8]);
    s.extend_from_slice(&[0x5a; 32]);
    s
}

/// The frozen Python archive cookie, then lengths and a library name.
fn frozen_python_cookie() -> Vec<u8> {
    let mut c = hex("4D 45 49 0C 0B 0A 0B 0E");
    c.extend_from_slice(&0x1000_u32.to_be_bytes());
    c.extend_from_slice(&0x800_u32.to_be_bytes());
    c.extend_from_slice(&0x10_u32.to_be_bytes());
    c.extend_from_slice(&312_u32.to_be_bytes());
    c.extend_from_slice(&[0; 64]);
    c
}

/// The standard anti-malware test file, assembled from hex so that no
/// source file or build artefact is itself the test file.
fn malware_test_file() -> Vec<u8> {
    hex(
        "58 35 4F 21 50 25 40 41 50 5B 34 5C 50 5A 58 35 34 28 50 5E 29 37 43 43 \
         29 37 7D 24 45 49 43 41 52 2D 53 54 41 4E 44 41 52 44 2D 41 4E 54 49 56 \
         49 52 55 53 2D 54 45 53 54 2D 46 49 4C 45 21 24 48 2B 48 2A",
    )
}

// ---------------------------------------------------------------------------
// Fuzz seeds
// ---------------------------------------------------------------------------

fn seeds() -> Vec<Vec<u8>> {
    vec![
        pe_with_overlay(&msi()),
        pe_with_overlay(&scripted_setup_header()),
        pe_with_resource(11111, setup_loader_table(2)),
        bundle(2),
        pe_with_overlay(b"ISSetupStream\0\x02\0"),
        pe_with_resource(1, cab()),
        pe_with_overlay(&zip()),
        pe_with_overlay(&seven_zip()),
        [b"xx".to_vec(), PeBuilder::dll().build()].concat(),
        pe_with_overlay(&automation_script()),
        pe_with_overlay(&frozen_python_cookie()),
        // Not the anti-malware test file: seeds are written to disk, where
        // a local scanner would quarantine it. Its rule is anchored at
        // offset 0, so the fuzzer gains little from it.
        zip(),
        msi(),
    ]
}

#[test]
#[ignore = "writes fuzz seeds; run with PALISADE_FUZZ_SEED_DIR set"]
fn write_tag_fuzz_seeds() {
    let dir = std::env::var_os("PALISADE_FUZZ_SEED_DIR").expect("set PALISADE_FUZZ_SEED_DIR");
    std::fs::create_dir_all(&dir).unwrap();
    for (i, seed) in seeds().iter().enumerate() {
        std::fs::write(
            std::path::Path::new(&dir).join(format!("tag-seed-{i:02}")),
            seed,
        )
        .unwrap();
    }
}

#[cfg(feature = "content-rules")]
mod scanning {
    use super::*;
    use std::io::{self, Cursor, Read, Seek, SeekFrom};
    use std::time::Duration;

    use palisade_fileid::filetype::{self, FileKind};
    use palisade_fileid::tags::{
        self, ARCHIVE_EMBEDDED_ARCHIVE, ARCHIVE_EMBEDDED_PE, ARCHIVE_SELF_EXTRACTING_7Z,
        ARCHIVE_SELF_EXTRACTING_CAB, ARCHIVE_SELF_EXTRACTING_ZIP, BUILTIN_TAGS, BUILTIN_VERSION,
        CONTENT_SCAN_ERROR, CONTENT_SCAN_PARTIAL, CONTENT_SCAN_TIMEOUT, Condition, ContentRules,
        INSTALLER_BUNDLE_BOOTSTRAPPER, INSTALLER_MSI_WRAPPER, INSTALLER_SCRIPTED_SETUP,
        INSTALLER_SETUP_LOADER, INSTALLER_SETUP_STREAM, Location, PatternSource, RuleErrorKind,
        RuleSetSource, RuleSource, SCRIPT_COMPILED_AUTOMATION, SCRIPT_FROZEN_PYTHON, ScanLimits,
        ScanStatus, StringSource, TEST_MALWARE_TEST_FILE, TagReport,
    };
    use proptest::prelude::*;

    /// Deterministic limits: the budgets of the defaults, but no wall clock.
    fn limits() -> ScanLimits {
        ScanLimits {
            timeout: None,
            ..ScanLimits::default()
        }
    }

    fn builtin() -> ContentRules {
        ContentRules::new(None).unwrap()
    }

    fn scan(data: &[u8]) -> TagReport {
        tags::scan_bytes(data, &builtin(), &limits())
    }

    /// The tags of `data`, without the status tag.
    fn tags_of(data: &[u8]) -> Vec<String> {
        let r = scan(data);
        assert_eq!(r.status, ScanStatus::Complete, "{r:?}");
        r.tags
    }

    #[track_caller]
    fn assert_tags(data: &[u8], want: &[&str]) {
        assert_eq!(tags_of(data), want);
    }

    // ---------------------------------------------------------------------------
    // The built-in tag set
    // ---------------------------------------------------------------------------

    #[test]
    fn every_built_in_tag_has_a_fixture() {
        let fixtures: Vec<(&str, Vec<u8>)> = vec![
            (INSTALLER_MSI_WRAPPER, pe_with_overlay(&msi())),
            (
                INSTALLER_SCRIPTED_SETUP,
                pe_with_overlay(&scripted_setup_header()),
            ),
            (
                INSTALLER_SETUP_LOADER,
                pe_with_resource(11111, setup_loader_table(1)),
            ),
            (INSTALLER_BUNDLE_BOOTSTRAPPER, bundle(2)),
            (
                INSTALLER_SETUP_STREAM,
                pe_with_overlay(b"ISSetupStream\0\x02\0"),
            ),
            (ARCHIVE_SELF_EXTRACTING_CAB, pe_with_resource(1, cab())),
            (ARCHIVE_SELF_EXTRACTING_ZIP, pe_with_overlay(&zip())),
            (ARCHIVE_SELF_EXTRACTING_7Z, pe_with_overlay(&seven_zip())),
            (
                ARCHIVE_EMBEDDED_PE,
                [b"payload:".to_vec(), PeBuilder::default().build()].concat(),
            ),
            (
                ARCHIVE_EMBEDDED_ARCHIVE,
                [vec![0x20; 100], seven_zip()].concat(),
            ),
            (
                SCRIPT_COMPILED_AUTOMATION,
                pe_with_overlay(&automation_script()),
            ),
            (
                SCRIPT_FROZEN_PYTHON,
                pe_with_overlay(&frozen_python_cookie()),
            ),
            (TEST_MALWARE_TEST_FILE, malware_test_file()),
        ];
        let covered: Vec<&str> = fixtures.iter().map(|(t, _)| *t).collect();
        assert_eq!(
            covered, BUILTIN_TAGS,
            "one fixture per built-in tag, in order"
        );
        for (tag, data) in &fixtures {
            let r = scan(data);
            assert!(r.has(tag), "{tag}: {r:?}");
            assert_eq!(r.status, ScanStatus::Complete, "{tag}");
        }
    }

    #[test]
    fn installer_engines() {
        assert_tags(&pe_with_overlay(&msi()), &[INSTALLER_MSI_WRAPPER]);
        assert_tags(&pe_with_data(msi()), &[INSTALLER_MSI_WRAPPER]);
        // The header without the installer CLSID is some other compound file.
        let mut other = msi();
        other[512 + 0x50] = 0x86;
        assert_tags(&pe_with_overlay(&other), &[]);
        // A bare installer database is not a wrapper: there is no executable.
        assert_tags(&msi(), &[]);

        assert_tags(
            &pe_with_overlay(&scripted_setup_header()),
            &[INSTALLER_SCRIPTED_SETUP],
        );
        // The header must be in the appended data, not in a section.
        assert_tags(&pe_with_data(scripted_setup_header()), &[]);
        // And after an executable.
        assert_tags(&[vec![0; 512], scripted_setup_header()].concat(), &[]);
        let mut wrong = scripted_setup_header();
        wrong[4] ^= 1;
        assert_tags(&pe_with_overlay(&wrong), &[]);

        for version in [1, 2] {
            assert_tags(
                &pe_with_resource(11111, setup_loader_table(version)),
                &[INSTALLER_SETUP_LOADER],
            );
        }
        assert_tags(&pe_with_resource(11111, setup_loader_table(0x10)), &[]);

        assert_tags(&bundle(2), &[INSTALLER_BUNDLE_BOOTSTRAPPER]);
        assert_tags(&bundle(3), &[]);
        // The magic alone, without the section name, is not enough.
        assert_tags(&pe_with_data(bundle_section(2)), &[]);

        assert_tags(
            &pe_with_overlay(&hex("49 6E 73 74 61 6C 6C 53 68 69 65 6C 64 00 07 00")),
            &[INSTALLER_SETUP_STREAM],
        );
        assert_tags(&pe_with_data(b"ISSetupStream\0".to_vec()), &[]);
    }

    #[test]
    fn self_extracting_and_embedded_archives() {
        assert_tags(
            &pe_with_overlay(&zip()),
            &[ARCHIVE_SELF_EXTRACTING_ZIP, ARCHIVE_EMBEDDED_ARCHIVE],
        );
        assert_tags(
            &pe_with_overlay(&seven_zip()),
            &[ARCHIVE_SELF_EXTRACTING_7Z, ARCHIVE_EMBEDDED_ARCHIVE],
        );
        assert_tags(
            &pe_with_overlay(&cab()),
            &[ARCHIVE_SELF_EXTRACTING_CAB, ARCHIVE_EMBEDDED_ARCHIVE],
        );
        // A cabinet inside the sections, as in a data resource.
        assert_tags(
            &pe_with_resource(1, cab()),
            &[ARCHIVE_SELF_EXTRACTING_CAB, ARCHIVE_EMBEDDED_ARCHIVE],
        );
        // A ZIP local header inside a section is not self-extracting.
        assert_tags(&pe_with_data(zip()), &[ARCHIVE_EMBEDDED_ARCHIVE]);

        // Plain archives are not embedded in anything.
        for archive in [cab(), seven_zip(), zip(), b"Rar!\x1a\x07\x01\0".to_vec()] {
            assert_tags(&archive, &[]);
        }
        // A ZIP has a local header for every entry: not an embedded archive.
        let two = [zip(), zip()].concat();
        assert_tags(&two, &[]);
        // RAR 4 and 5 after the start.
        assert_tags(
            &[b"x".to_vec(), b"Rar!\x1a\x07\0".to_vec()].concat(),
            &[ARCHIVE_EMBEDDED_ARCHIVE],
        );
        assert_tags(
            &[b"x".to_vec(), b"Rar!\x1a\x07\x01\0".to_vec()].concat(),
            &[ARCHIVE_EMBEDDED_ARCHIVE],
        );
        // A cabinet signature with a non-zero reserved field is not one.
        assert_tags(&[b"x".to_vec(), b"MSCF\x01\0\0\0".to_vec()].concat(), &[]);
    }

    #[test]
    fn embedded_executables() {
        let inner = PeBuilder::dll().build();
        assert_tags(
            &[vec![0; 3], inner.clone()].concat(),
            &[ARCHIVE_EMBEDDED_PE],
        );
        // An executable inside an executable's appended data.
        assert_tags(&pe_with_overlay(&inner), &[ARCHIVE_EMBEDDED_PE]);
        // The file itself is not embedded in anything.
        assert_tags(&inner, &[]);
        // `MZ` without a PE header after it is not an image.
        let mut fake = inner.clone();
        fake[E_LFANEW] = b'X';
        assert_tags(&[vec![0; 3], fake].concat(), &[]);
        // `MZ` near the end of the file, with `e_lfanew` past it.
        assert_tags(b"....MZ", &[]);
        // A text file full of `MZ` costs one cheap check per candidate.
        let noise = b"MZ".repeat(100_000);
        let r = scan(&noise);
        assert!(r.tags.is_empty());
        // 100,000 candidates at one step each plus an 8-step check, and the
        // 68-byte check of the test file string at offset 0.
        assert!(r.match_steps <= 9 * 100_000 + 68, "{}", r.match_steps);
    }

    #[test]
    fn compiled_script_markers() {
        assert_tags(
            &pe_with_overlay(&automation_script()),
            &[SCRIPT_COMPILED_AUTOMATION],
        );
        assert_tags(
            &pe_with_resource(1, automation_script()),
            &[SCRIPT_COMPILED_AUTOMATION],
        );
        // The marker outside an executable is not a compiled script.
        assert_tags(&automation_script(), &[]);

        assert_tags(
            &pe_with_overlay(&frozen_python_cookie()),
            &[SCRIPT_FROZEN_PYTHON],
        );
        // The cookie is at the end of the archive, which may be on its own.
        assert_tags(
            &[vec![0x41; 200_000], frozen_python_cookie()].concat(),
            &[SCRIPT_FROZEN_PYTHON],
        );
        // But not far from the end of a file that is not an executable.
        let far = [vec![0x41; 10], frozen_python_cookie(), vec![0x41; 70_000]].concat();
        assert_tags(&far, &[]);
        // Inside an executable's sections it is not appended data.
        assert_tags(
            &[pe_with_data(frozen_python_cookie()), vec![0; 70_000]].concat(),
            &[],
        );
    }

    #[test]
    fn malware_test_file_rule() {
        let file = malware_test_file();
        assert_tags(&file, &[TEST_MALWARE_TEST_FILE]);
        // Trailing whitespace is allowed, up to 128 bytes in all.
        assert_tags(
            &[file.clone(), b"\r\n".to_vec()].concat(),
            &[TEST_MALWARE_TEST_FILE],
        );
        assert_tags(
            &[file.clone(), vec![b' '; 60]].concat(),
            &[TEST_MALWARE_TEST_FILE],
        );
        assert_tags(&[file.clone(), vec![b' '; 61]].concat(), &[]);
        // It must start the file.
        assert_tags(&[b" ".to_vec(), file.clone()].concat(), &[]);
        let mut cut = file;
        cut.pop();
        assert_tags(&cut, &[]);
    }

    #[test]
    fn source_files_do_not_carry_the_test_string() {
        // The test file's string is written as hex everywhere, so no source
        // file is itself the test file (or tagged as it by other scanners).
        let needle = malware_test_file();
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut dirs: Vec<_> = ["src", "tests", "fuzz/fuzz_targets"]
            .iter()
            .map(|d| root.join(d))
            .collect();
        let mut files = 0;
        while let Some(dir) = dirs.pop() {
            for entry in std::fs::read_dir(&dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    dirs.push(path);
                } else {
                    files += 1;
                    let data = std::fs::read(&path).unwrap();
                    assert!(
                        !data.windows(needle.len()).any(|w| w == needle),
                        "{}",
                        path.display()
                    );
                }
            }
        }
        assert!(files > 20, "the walk found the sources");
        // And no seed written to disk is the test file.
        assert!(
            seeds()
                .iter()
                .all(|s| s.windows(needle.len()).all(|w| w != needle))
        );
    }

    #[test]
    fn tags_agree_with_the_classifier_on_pe_images() {
        // `require_pe` rules see a PE image exactly when the classifier does.
        let samples = [
            PeBuilder::default().build(),
            PeBuilder::pe32().build(),
            pe_with_overlay(&zip()),
            msi(),
            zip(),
            b"MZ".to_vec(),
            {
                let mut broken = PeBuilder::default().build();
                broken[COFF_OFFSET + 16] = 0xff;
                broken
            },
        ];
        for data in samples {
            let c = filetype::classify_bytes(&data, None);
            assert_eq!(scan(&data).is_pe, c.content_kind == FileKind::Pe, "{c:?}");
        }
    }

    // ---------------------------------------------------------------------------
    // Organisation rules
    // ---------------------------------------------------------------------------

    fn org_rule(tag: &str, strings: Vec<StringSource>, condition: Condition) -> RuleSource {
        RuleSource {
            tag: tag.to_owned(),
            require_pe: false,
            max_file_size: None,
            unless_start: None,
            strings,
            condition,
        }
    }

    fn s(pattern: PatternSource, location: Location) -> StringSource {
        StringSource { pattern, location }
    }

    fn org(rules: Vec<RuleSource>) -> ContentRules {
        ContentRules::new(Some(&RuleSetSource { version: 3, rules })).unwrap()
    }

    #[test]
    fn organisation_rules() {
        let rules = org(vec![
            org_rule(
                "script:downloads-and-executes",
                vec![
                    s(
                        PatternSource::Text("DownloadFile(".into()),
                        Location::Anywhere,
                    ),
                    s(
                        PatternSource::Text("Start-Process".into()),
                        Location::Anywhere,
                    ),
                    s(
                        PatternSource::WideText("Invoke-Item".into()),
                        Location::Anywhere,
                    ),
                ],
                Condition::AtLeast(2),
            ),
            org_rule(
                "vendor:in-house:signed-build",
                vec![s(
                    PatternSource::Hex("CA FE ?? ?? 0? 99".into()),
                    Location::At(4),
                )],
                Condition::Any,
            ),
            RuleSource {
                require_pe: true,
                ..org_rule(
                    "installer:in-house",
                    vec![s(
                        PatternSource::Text("HOUSE-SETUP".into()),
                        Location::Overlay,
                    )],
                    Condition::Any,
                )
            },
        ]);
        let run = |data: &[u8]| tags::scan_bytes(data, &rules, &limits()).tags;
        assert_eq!(rules.rules_version(), Some(3));
        assert!(rules.rules_digest().is_some());
        assert_eq!(rules.tags().count(), BUILTIN_TAGS.len() + 3);

        let script = b"$c.DownloadFile($u, $p); Start-Process $p";
        assert_eq!(run(script), ["script:downloads-and-executes"]);
        let wide: Vec<u8> = "Invoke-Item x".bytes().flat_map(|b| [b, 0]).collect();
        assert_eq!(
            run(&[b"DownloadFile(".to_vec(), wide].concat()),
            ["script:downloads-and-executes"]
        );
        assert!(run(b"$c.DownloadFile($u, $p)").is_empty(), "one of three");

        assert_eq!(
            run(b"0123\xca\xfe\x00\x00\x05\x99"),
            ["vendor:in-house:signed-build"]
        );
        assert!(
            run(b"0123\xca\xfe\x00\x00\x15\x99").is_empty(),
            "nibble mask"
        );
        assert!(run(b"01234\xca\xfe\x00\x00\x05\x99").is_empty(), "offset");

        assert_eq!(
            run(&pe_with_overlay(b"HOUSE-SETUP")),
            ["installer:in-house"]
        );
        assert!(run(&pe_with_data(b"HOUSE-SETUP".to_vec())).is_empty());
        assert!(run(b"HOUSE-SETUP").is_empty());

        let report = tags::scan_bytes(b"", &rules, &limits());
        assert_eq!(report.rules_version, Some(3));
        assert_eq!(report.builtin_version, BUILTIN_VERSION);
    }

    #[test]
    fn built_in_tags_cannot_be_redefined() {
        let set = RuleSetSource {
            version: 1,
            rules: vec![org_rule(
                ARCHIVE_EMBEDDED_PE,
                vec![s(PatternSource::Text("xyz".into()), Location::Anywhere)],
                Condition::Any,
            )],
        };
        let e = ContentRules::new(Some(&set)).unwrap_err();
        assert_eq!(
            (e.builtin, e.rule, e.kind),
            (false, Some(0), RuleErrorKind::ReservedTag)
        );
    }

    #[test]
    fn rule_sets_round_trip_through_serde() {
        let set = RuleSetSource {
            version: 9,
            rules: vec![org_rule(
                "a:b",
                vec![
                    s(
                        PatternSource::Hex("41 42".into()),
                        Location::Range { start: 1, end: 9 },
                    ),
                    s(PatternSource::PeImage, Location::Tail(100)),
                ],
                Condition::All,
            )],
        };
        let json = serde_json::to_string(&set).unwrap();
        assert_eq!(serde_json::from_str::<RuleSetSource>(&json).unwrap(), set);
        // Unknown fields are rejected, so a typo cannot silently drop a limit.
        let typo = json.replace("\"require_pe\"", "\"requires_pe\"");
        assert!(serde_json::from_str::<RuleSetSource>(&typo).is_err());
    }

    #[test]
    fn matches_across_chunk_boundaries() {
        // 1 MiB chunks: put a string across every boundary, with its atom on
        // either side.
        let rules = org(vec![org_rule(
            "a:boundary",
            vec![s(
                PatternSource::Hex("01 02 03 04 ?? 06 07 08".into()),
                Location::Anywhere,
            )],
            Condition::Any,
        )]);
        let needle = [1, 2, 3, 4, 0xee, 6, 7, 8];
        for shift in 0..needle.len() + 1 {
            let mut data = vec![0_u8; 3 << 20];
            let at = (1 << 20) - shift;
            data[at..at + needle.len()].copy_from_slice(&needle);
            let r = tags::scan_bytes(&data, &rules, &limits());
            assert_eq!(r.tags, ["a:boundary"], "shift {shift}");
        }
        // A string at a fixed offset just before a boundary.
        let rules = org(vec![org_rule(
            "a:fixed",
            vec![s(
                PatternSource::Hex("AA BB CC".into()),
                Location::At((1 << 20) - 1),
            )],
            Condition::Any,
        )]);
        let mut data = vec![0_u8; 2 << 20];
        data[(1 << 20) - 1..(1 << 20) + 2].copy_from_slice(&[0xaa, 0xbb, 0xcc]);
        assert_eq!(tags::scan_bytes(&data, &rules, &limits()).tags, ["a:fixed"]);
    }

    // ---------------------------------------------------------------------------
    // Budgets: tagging never stalls and never errors
    // ---------------------------------------------------------------------------

    /// A sparse virtual file: zeros, with `data` placed at offsets.
    struct Sparse {
        len: u64,
        pos: u64,
        parts: Vec<(u64, Vec<u8>)>,
        read: u64,
        fail_after: Option<u64>,
    }

    impl Sparse {
        fn new(len: u64, parts: Vec<(u64, Vec<u8>)>) -> Self {
            Self {
                len,
                pos: 0,
                parts,
                read: 0,
                fail_after: None,
            }
        }
    }

    impl Read for Sparse {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.fail_after.is_some_and(|n| self.read >= n) {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            let n = (self.len.saturating_sub(self.pos)).min(buf.len() as u64) as usize;
            buf[..n].fill(0);
            for (at, data) in &self.parts {
                for (i, b) in data.iter().enumerate() {
                    let off = at + i as u64;
                    if off >= self.pos && off < self.pos + n as u64 {
                        buf[(off - self.pos) as usize] = *b;
                    }
                }
            }
            self.pos += n as u64;
            self.read += n as u64;
            Ok(n)
        }
    }

    impl Seek for Sparse {
        fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
            self.pos = match pos {
                SeekFrom::Start(p) => p,
                SeekFrom::End(d) => self.len.checked_add_signed(d).unwrap(),
                SeekFrom::Current(d) => self.pos.checked_add_signed(d).unwrap(),
            };
            Ok(self.pos)
        }
    }

    #[test]
    fn a_one_gib_sparse_file_is_scanned_in_part() {
        // The issue's test: a rule over a 1 GiB sparse file ends cleanly, with
        // a status tag, never an error, reading only the bounded start and tail.
        const GIB: u64 = 1 << 30;
        let mut file = Sparse::new(
            GIB,
            vec![
                (100, seven_zip()),
                (GIB - 1000, frozen_python_cookie()),
                (GIB / 2, cab()),
            ],
        );
        let r = tags::scan(&mut file, &builtin(), &ScanLimits::default());
        assert_eq!(r.status, ScanStatus::Partial);
        assert_eq!(r.file_size, GIB);
        // Found at the start and in the tail; the middle is not scanned.
        assert_eq!(
            r.tags,
            [
                ARCHIVE_EMBEDDED_ARCHIVE,
                SCRIPT_FROZEN_PYTHON,
                CONTENT_SCAN_PARTIAL
            ]
        );
        let d = ScanLimits::default();
        assert!(file.read <= d.max_file_size + tags::TAIL_SCAN_LEN + 4096);
        assert!(r.bytes_scanned <= d.max_scan_bytes);
    }

    #[test]
    fn a_one_gib_sparse_file_times_out_cleanly() {
        // With no size limit, the byte budget stops the scan: a timeout
        // tag, never an error, and the tags found before the stop are kept.
        const GIB: u64 = 1 << 30;
        let mut file = Sparse::new(GIB, vec![(100, seven_zip())]);
        let no_size_limit = ScanLimits {
            max_file_size: u64::MAX,
            ..ScanLimits::default()
        };
        let r = tags::scan(&mut file, &builtin(), &no_size_limit);
        assert_eq!(r.status, ScanStatus::Timeout);
        assert_eq!(r.tags, [ARCHIVE_EMBEDDED_ARCHIVE, CONTENT_SCAN_TIMEOUT]);
        assert!(file.read <= no_size_limit.max_scan_bytes);
    }

    #[test]
    fn byte_budget_gives_a_timeout_tag() {
        let mut file = Sparse::new(64 << 20, vec![(10, seven_zip())]);
        let tight = ScanLimits {
            max_file_size: u64::MAX,
            max_scan_bytes: 8 << 20,
            ..limits()
        };
        let r = tags::scan(&mut file, &builtin(), &tight);
        assert_eq!(r.status, ScanStatus::Timeout);
        // What was found before the budget ran out is kept.
        assert_eq!(r.tags, [ARCHIVE_EMBEDDED_ARCHIVE, CONTENT_SCAN_TIMEOUT]);
        assert!(file.read <= 8 << 20);
        assert!(r.bytes_scanned <= 8 << 20);
    }

    #[test]
    fn step_budget_gives_a_timeout_tag() {
        // Pathological input: an atom on every byte, each with a long check.
        let rules = org(vec![org_rule(
            "a:slow",
            vec![s(
                PatternSource::Hex(format!("41 41 {}", "?? ".repeat(250))),
                Location::Anywhere,
            )],
            Condition::Any,
        )]);
        let data = vec![0x41_u8; 4 << 20];
        let r = tags::scan_bytes(&data, &rules, &limits());
        // The default step budget covers it...
        assert_eq!(r.status, ScanStatus::Complete);
        assert!(r.has("a:slow"));
        // ...and one string is checked once it has matched, so a flood of
        // candidates after the first costs one step each.
        assert!(r.match_steps < 2 * data.len() as u64, "{}", r.match_steps);

        // A rule that never matches checks every candidate in full.
        let rules = org(vec![org_rule(
            "a:never",
            vec![s(
                PatternSource::Hex(format!("41 41 {}42", "?? ".repeat(250))),
                Location::Anywhere,
            )],
            Condition::Any,
        )]);
        let tight = ScanLimits {
            max_match_steps: 1 << 20,
            ..limits()
        };
        let r = tags::scan_bytes(&data, &rules, &tight);
        assert_eq!(r.status, ScanStatus::Timeout);
        assert_eq!(r.tags, [CONTENT_SCAN_TIMEOUT]);
        assert!(r.match_steps <= 1 << 20);
    }

    #[test]
    fn wall_clock_gives_a_timeout_tag() {
        let mut file = Sparse::new(16 << 20, vec![]);
        let zero = ScanLimits {
            timeout: Some(Duration::ZERO),
            ..ScanLimits::default()
        };
        let r = tags::scan(&mut file, &builtin(), &zero);
        assert_eq!(r.status, ScanStatus::Timeout);
        assert_eq!(r.tags, [CONTENT_SCAN_TIMEOUT]);
    }

    #[test]
    fn read_errors_give_an_error_tag() {
        let mut file = Sparse::new(4 << 20, vec![(10, seven_zip())]);
        file.fail_after = Some(2 << 20);
        let r = tags::scan(&mut file, &builtin(), &limits());
        assert_eq!(
            r.status,
            ScanStatus::ReadError(io::ErrorKind::PermissionDenied)
        );
        assert_eq!(r.tags, [ARCHIVE_EMBEDDED_ARCHIVE, CONTENT_SCAN_ERROR]);

        struct NoSeek;
        impl Read for NoSeek {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Ok(0)
            }
        }
        impl Seek for NoSeek {
            fn seek(&mut self, _: SeekFrom) -> io::Result<u64> {
                Err(io::ErrorKind::Unsupported.into())
            }
        }
        let r = tags::scan(&mut NoSeek, &builtin(), &limits());
        assert_eq!(r.tags, [CONTENT_SCAN_ERROR]);
    }

    /// Reports `len` from the end seek, but holds only `data`.
    struct Liar(Cursor<Vec<u8>>, u64);
    impl Read for Liar {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.0.read(buf)
        }
    }
    impl Seek for Liar {
        fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
            match pos {
                SeekFrom::End(_) => Ok(self.1),
                other => self.0.seek(other),
            }
        }
    }

    #[test]
    fn a_file_shorter_than_reported_fails_conservative() {
        // The bytes that did arrive are scanned, and their tags kept, but
        // the scan is not called complete: the rest was never seen.
        let data = [vec![1; 50], seven_zip()].concat();
        let mut r = Liar(Cursor::new(data.clone()), 10 << 20);
        let report = tags::scan(&mut r, &builtin(), &limits());
        assert_eq!(
            report.status,
            ScanStatus::ReadError(io::ErrorKind::UnexpectedEof)
        );
        assert_eq!(report.tags, [ARCHIVE_EMBEDDED_ARCHIVE, CONTENT_SCAN_ERROR]);
        // Only the bytes actually read are counted.
        assert!(
            report.bytes_scanned <= 2 * data.len() as u64,
            "{}",
            report.bytes_scanned
        );
        // A file that ends inside its PE headers, or inside a chunk.
        for len in [10, 0x41, 0x100, 0x500] {
            let mut r = Liar(
                Cursor::new(PeBuilder::default().build()[..len].to_vec()),
                1 << 20,
            );
            let report = tags::scan(&mut r, &builtin(), &limits());
            assert_eq!(
                report.status,
                ScanStatus::ReadError(io::ErrorKind::UnexpectedEof),
                "{len}"
            );
            assert_eq!(
                report.tags.last().map(String::as_str),
                Some(CONTENT_SCAN_ERROR)
            );
        }
    }

    #[test]
    fn an_unchecked_start_filter_never_lets_a_rule_through() {
        // The embedded archive rule must not fire on a plain ZIP, whose
        // later entries carry local headers, even when the first bytes of
        // the file are outside the scanned range or the budget runs out.
        let mut archive = zip();
        archive.extend_from_slice(&vec![0; 3 << 20]);
        archive.extend_from_slice(&zip());
        // 1. A size limit smaller than the filter: only the tail is
        //    scanned past it, but the filter is still checked first.
        let tiny = ScanLimits {
            max_file_size: 1,
            ..limits()
        };
        let r = tags::scan_bytes(&archive, &builtin(), &tiny);
        assert_eq!(r.status, ScanStatus::Partial);
        assert_eq!(r.tags, [CONTENT_SCAN_PARTIAL]);
        // 2. A step budget that runs out right after a rule's own string:
        //    the filter was checked before any rule string.
        let rules = org(vec![RuleSource {
            unless_start: Some(PatternSource::Hex("AA BB".into())),
            ..org_rule(
                "a:filtered",
                vec![s(PatternSource::Hex("AA".into()), Location::At(0))],
                Condition::Any,
            )
        }]);
        let data = [vec![0xaa, 0xbb], vec![0; 100]].concat();
        for steps in 0..200 {
            let tight = ScanLimits {
                max_match_steps: steps,
                ..limits()
            };
            let r = tags::scan_bytes(&data, &rules, &tight);
            assert!(!r.has("a:filtered"), "{steps}: {r:?}");
        }
        // Without the filter's bytes, the rule fires.
        let r = tags::scan_bytes(&[0xaa, 0xcc], &rules, &limits());
        assert!(r.has("a:filtered"));
        // A file that ended before the filter could be read decides
        // nothing.
        let mut short = Liar(Cursor::new(vec![0xaa]), 100);
        assert!(!tags::scan(&mut short, &rules, &limits()).has("a:filtered"));
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// No input panics, the budgets hold, and the result is consistent.
        #[test]
        fn scans_are_bounded_and_consistent(
            seed in 0..13_usize,
            edits in prop::collection::vec((any::<usize>(), any::<u8>()), 0..16),
            cut in any::<usize>(),
            max_scan_bytes in 0..300_000_u64,
        ) {
            let mut data = seeds()[seed].clone();
            for (at, b) in edits {
                let len = data.len();
                data[at % len] = b;
            }
            data.truncate(cut % (data.len() + 1));
            let limits = ScanLimits { max_scan_bytes, ..limits() };
            let r = tags::scan_bytes(&data, &builtin(), &limits);
            prop_assert!(r.bytes_scanned <= max_scan_bytes);
            prop_assert!(r.match_steps <= limits.max_match_steps);
            prop_assert_eq!(r.file_size, data.len() as u64);
            let status_tags = r.tags.iter().filter(|t| t.starts_with("content_scan_")).count();
            prop_assert_eq!(status_tags, usize::from(r.status != ScanStatus::Complete));
            if r.status == ScanStatus::Complete {
                // A full scan agrees with the classifier about PE images...
                let c = filetype::classify_bytes(&data, None);
                prop_assert_eq!(r.is_pe, c.content_kind == FileKind::Pe);
                // ...and does not depend on the byte budget.
                prop_assert_eq!(&r, &scan(&data));
            }
        }
    }
}
