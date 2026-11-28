//! Property tests for the file-system context parsers.
//!
//! These run on every platform. The parsers take untrusted input (paths
//! from events and policies, security descriptors and stream contents from
//! files), so no input may panic, and normalisation must be idempotent.

use palisade_fileid::fsctx::acl::{EvaluationOptions, ObjectKind, SecurityDescriptor, evaluate};
use palisade_fileid::fsctx::{normalize_nt, normalize_win32, parse_zone_identifier};
use proptest::prelude::*;

/// Characters that exercise every branch of the path parser.
fn path_strategy() -> impl Strategy<Value = String> {
    let pieces = prop::sample::select(vec![
        "\\",
        "/",
        ".",
        "..",
        " ",
        ":",
        "?",
        "C:",
        "c:",
        "UNC",
        "GLOBALROOT",
        "Device",
        "HarddiskVolume3",
        "HarddiskVolumeShadowCopy1",
        "Volume{b75e2c83-0000-0000-0000-602f00000000}",
        "??",
        "Mup",
        "server",
        "share",
        "a",
        "PROGRA~1",
        "CON",
        "nul.txt",
        "$DATA",
        "$I30",
        "$INDEX_ALLOCATION",
        "ß",
        "é",
        "~",
    ]);
    prop::collection::vec(pieces, 0..24).prop_map(|v| v.concat())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    #[test]
    fn win32_normalisation_is_total_and_idempotent(input in path_strategy()) {
        if let Ok(p) = normalize_win32(&input) {
            let again = normalize_win32(&p.to_win32_string());
            prop_assert!(again.is_ok(), "{input:?} -> {} did not re-parse", p.to_win32_string());
            let again = again.unwrap();
            prop_assert_eq!(again.case_folded(), p.case_folded(), "input {:?}", input);
            prop_assert_eq!(again.stream(), p.stream());
            prop_assert_eq!(again.root(), p.root());
            prop_assert_eq!(again.components(), p.components());
            for c in p.components() {
                prop_assert!(!c.is_empty() && c != "." && c != "..");
            }
            for a in p.ancestors() {
                let a = a.unwrap();
                let again = normalize_win32(&a.to_win32_string());
                prop_assert_eq!(again.as_ref().map(|x| x.case_folded()), Ok(a.case_folded()));
            }
        }
    }

    #[test]
    fn nt_normalisation_never_panics(input in path_strategy()) {
        if let Ok(p) = normalize_nt(&input) {
            prop_assert!(normalize_win32(&p.to_win32_string()).is_ok());
        }
    }

    #[test]
    fn arbitrary_strings_never_panic(input in ".{0,64}") {
        let _ = normalize_win32(&input);
        let _ = normalize_nt(&input);
    }

    #[test]
    fn descriptors_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
        if let Ok(sd) = SecurityDescriptor::from_self_relative(&bytes) {
            let _ = evaluate(&sd, ObjectKind::File, &EvaluationOptions::default());
        }
    }

    #[test]
    fn mutated_descriptors_never_panic(
        flips in prop::collection::vec((0usize..96, any::<u8>()), 1..6)
    ) {
        use palisade_fileid::fsctx::acl::{Ace, mask};
        use palisade_fileid::fsctx::sid::well_known as wk;
        let base = SecurityDescriptor::new(
            Some(wk::ADMINISTRATORS),
            Some(vec![
                Ace::deny(wk::GUESTS, mask::FILE_WRITE_DATA),
                Ace::allow(wk::USERS, 0x0013_01BF),
            ]),
        );
        let mut bytes = base.to_self_relative().unwrap();
        let len = bytes.len();
        for (at, v) in flips {
            if let Some(b) = bytes.get_mut(at % len) {
                *b = v;
            }
        }
        if let Ok(sd) = SecurityDescriptor::from_self_relative(&bytes) {
            let _ = evaluate(&sd, ObjectKind::Directory, &EvaluationOptions::default());
        }
    }

    #[test]
    fn zone_identifier_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
        let m = parse_zone_identifier(&bytes);
        if let (Some(z), Some(s)) = (m.zone, m.strictest_zone) {
            prop_assert!(s.strictness() >= z.strictness());
        }
    }
}

/// Writes seed inputs for the `fsctx_parse` fuzz target into the directory
/// in `PALISADE_FUZZ_SEED_DIR`: Win32 and NT paths, a self-relative
/// security descriptor, a `Zone.Identifier` stream, a `FILE_STREAM_INFO`
/// list, a change-journal record and a journal read.
///
/// ```text
/// PALISADE_FUZZ_SEED_DIR=fuzz/corpus/fsctx_parse \
///     cargo test -p palisade-fileid --test fsctx -- --ignored write_fsctx_fuzz_seeds
/// ```
#[test]
#[ignore = "writes files; run on demand to seed the fuzz corpus"]
fn write_fsctx_fuzz_seeds() {
    use palisade_fileid::fsctx::acl::{Ace, mask};
    use palisade_fileid::fsctx::sid::well_known as wk;
    let dir = std::env::var_os("PALISADE_FUZZ_SEED_DIR").expect("set PALISADE_FUZZ_SEED_DIR");
    let dir = std::path::Path::new(&dir);
    std::fs::create_dir_all(dir).unwrap();
    let paths: [&str; 6] = [
        r"C:\Program Files\Example\bin\tool.exe",
        r"\\?\C:\Users\Public\Downloads\setup.exe:Zone.Identifier",
        r"\\server\share\dir\..\file.txt",
        r"\Device\HarddiskVolume3\Windows\System32\cmd.exe",
        r"\??\UNC\server\share\a.dll",
        r"C:\PROGRA~1\EXAMPL~1\a b\c.ps1",
    ];
    for (i, path) in paths.iter().enumerate() {
        std::fs::write(dir.join(format!("seed-path-{i}")), path).unwrap();
    }
    let sd = SecurityDescriptor::new(
        Some(wk::ADMINISTRATORS),
        Some(vec![
            Ace::deny(wk::GUESTS, mask::FILE_WRITE_DATA),
            Ace::allow(wk::USERS, 0x0013_01BF),
            Ace::allow(wk::EVERYONE, 0x0012_00A9),
        ]),
    );
    std::fs::write(dir.join("seed-descriptor"), sd.to_self_relative().unwrap()).unwrap();
    // A two-record stream list (default stream and a named one), padded as
    // the OS pads it, and a version-2 change-journal record.
    let record = |name: &str| {
        let units: Vec<u16> = name.encode_utf16().collect();
        let mut r = Vec::new();
        r.extend_from_slice(&0_u32.to_le_bytes());
        r.extend_from_slice(&u32::try_from(units.len() * 2).unwrap().to_le_bytes());
        r.extend_from_slice(&7_i64.to_le_bytes());
        r.extend_from_slice(&8_i64.to_le_bytes());
        for u in units {
            r.extend_from_slice(&u.to_le_bytes());
        }
        while r.len() % 8 != 0 {
            r.push(0);
        }
        r
    };
    let mut streams = record("::$DATA");
    let next = u32::try_from(streams.len()).unwrap();
    streams[..4].copy_from_slice(&next.to_le_bytes());
    streams.extend(record(":Zone.Identifier:$DATA"));
    std::fs::write(dir.join("seed-streams"), streams).unwrap();
    let mut usn = vec![0_u8; 64];
    usn[..4].copy_from_slice(&64_u32.to_le_bytes());
    usn[4..6].copy_from_slice(&2_u16.to_le_bytes());
    usn[24..32].copy_from_slice(&12345_i64.to_le_bytes());
    std::fs::write(dir.join("seed-usn"), &usn).unwrap();
    // A journal read: the next USN, then one full version-2 record for
    // `a.exe`.
    let mut read = 99_i64.to_le_bytes().to_vec();
    let mut full = vec![0_u8; 64];
    full[..4].copy_from_slice(&72_u32.to_le_bytes());
    full[4..6].copy_from_slice(&2_u16.to_le_bytes());
    full[24..32].copy_from_slice(&12345_i64.to_le_bytes());
    full[56..58].copy_from_slice(&10_u16.to_le_bytes());
    full[58..60].copy_from_slice(&60_u16.to_le_bytes());
    full.truncate(60);
    for u in "a.exe".encode_utf16() {
        full.extend_from_slice(&u.to_le_bytes());
    }
    full.extend_from_slice(&[0, 0]);
    read.extend_from_slice(&full);
    std::fs::write(dir.join("seed-journal-read"), read).unwrap();
    // A 1 KiB `$UpCase` file record: the update sequence array, an
    // unnamed `$DATA` attribute and a resident `$Info` with the standard
    // CRC, then the end marker.
    let mut upcase = vec![0_u8; 1024];
    upcase[..4].copy_from_slice(b"FILE");
    upcase[4..6].copy_from_slice(&0x30_u16.to_le_bytes());
    upcase[6..8].copy_from_slice(&3_u16.to_le_bytes());
    upcase[20..22].copy_from_slice(&0x38_u16.to_le_bytes());
    let mut at = 0x38;
    for (name, value) in [("", &[][..]), ("$Info", &[0_u8; 32][..])] {
        let units: Vec<u16> = name.encode_utf16().collect();
        let value_at = (24 + units.len() * 2).next_multiple_of(8);
        let len = (value_at + value.len()).next_multiple_of(8);
        upcase[at..at + 4].copy_from_slice(&0x80_u32.to_le_bytes());
        upcase[at + 4..at + 8].copy_from_slice(&u32::try_from(len).unwrap().to_le_bytes());
        upcase[at + 9] = u8::try_from(units.len()).unwrap();
        upcase[at + 10..at + 12].copy_from_slice(&24_u16.to_le_bytes());
        upcase[at + 16..at + 20]
            .copy_from_slice(&u32::try_from(value.len()).unwrap().to_le_bytes());
        upcase[at + 20..at + 22].copy_from_slice(&u16::try_from(value_at).unwrap().to_le_bytes());
        for (i, u) in units.iter().enumerate() {
            upcase[at + 24 + 2 * i..at + 26 + 2 * i].copy_from_slice(&u.to_le_bytes());
        }
        if !value.is_empty() {
            let crc = palisade_fileid::fsctx::STANDARD_UPCASE_CRC.to_le_bytes();
            upcase[at + value_at + 8..at + value_at + 16].copy_from_slice(&crc);
        }
        at += len;
    }
    upcase[at..at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    upcase[24..28].copy_from_slice(&u32::try_from(at + 8).unwrap().to_le_bytes());
    assert_eq!(
        palisade_fileid::fsctx::parse_upcase_info(&upcase),
        Ok(Some(palisade_fileid::fsctx::STANDARD_UPCASE_CRC))
    );
    std::fs::write(dir.join("seed-upcase"), upcase).unwrap();
    std::fs::write(
        dir.join("seed-zone"),
        "[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://example.invalid/\r\nHostUrl=https://example.invalid/setup.exe\r\n",
    )
    .unwrap();
}
