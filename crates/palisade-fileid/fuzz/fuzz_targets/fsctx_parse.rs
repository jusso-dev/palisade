//! Fuzzes the file-system context parsers: path normalisation (Win32 and
//! NT forms), self-relative security descriptors with the writability
//! evaluation, and `Zone.Identifier` streams. No input may panic, and a
//! normalised path must normalise to itself again.
#![no_main]

use libfuzzer_sys::fuzz_target;
use palisade_fileid::fsctx::acl::{EvaluationOptions, ObjectKind, SecurityDescriptor, evaluate};
use palisade_fileid::fsctx::{normalize_nt, normalize_win32, parse_zone_identifier};

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        for parsed in [normalize_win32(text), normalize_nt(text)] {
            if let Ok(p) = parsed {
                let again = normalize_win32(&p.to_win32_string()).expect("re-parse");
                assert_eq!(again.case_folded(), p.case_folded());
                assert_eq!(again.components(), p.components());
                assert_eq!(again.stream(), p.stream());
            }
        }
    }
    if let Ok(sd) = SecurityDescriptor::from_self_relative(data) {
        for kind in [ObjectKind::File, ObjectKind::Directory] {
            let w = evaluate(&sd, kind, &EvaluationOptions::default());
            assert!(w.uncertain.difference(w.rights).is_empty());
        }
    }
    let m = parse_zone_identifier(data);
    if let (Some(z), Some(s)) = (m.zone, m.strictest_zone) {
        assert!(s.strictness() >= z.strictness());
    }
});
