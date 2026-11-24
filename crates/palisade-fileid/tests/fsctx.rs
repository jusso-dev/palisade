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
