//! Fuzzes the file-system context parsers: path normalisation (Win32 and
//! NT forms), self-relative security descriptors with the writability
//! evaluation, `Zone.Identifier` streams, and the stream-list and
//! change-journal records the OS returns, and the storage descriptors the
//! volume backend reads. No input may panic, and a
//! normalised path, and each ancestor that is not too long, must normalise
//! to itself again.
#![no_main]

use libfuzzer_sys::fuzz_target;
use palisade_fileid::fsctx::acl::{EvaluationOptions, ObjectKind, SecurityDescriptor, evaluate};
use palisade_fileid::fsctx::ntfs::{MAX_STREAMS, parse_stream_info, parse_usn_record};
use palisade_fileid::fsctx::{
    normalize_nt, normalize_win32, parse_hotplug_info, parse_storage_device_descriptor,
    parse_zone_identifier,
};

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        for parsed in [normalize_win32(text), normalize_nt(text)] {
            if let Ok(p) = parsed {
                let again = normalize_win32(&p.to_win32_string()).expect("re-parse");
                assert_eq!(again.case_folded(), p.case_folded());
                assert_eq!(again.components(), p.components());
                assert_eq!(again.stream(), p.stream());
                for a in p.ancestors().flatten() {
                    let again = normalize_win32(&a.to_win32_string()).expect("ancestor");
                    assert_eq!(again.case_folded(), a.case_folded());
                }
            }
        }
    }
    if let Ok(sd) = SecurityDescriptor::from_self_relative(data) {
        for kind in [ObjectKind::File, ObjectKind::Directory] {
            let w = evaluate(&sd, kind, &EvaluationOptions::default());
            assert!(w.uncertain.difference(w.rights).is_empty());
        }
    }
    if let Ok(list) = parse_stream_info(data) {
        assert!(list.streams.len() <= MAX_STREAMS);
    }
    if let Ok(usn) = parse_usn_record(data) {
        assert!(matches!(usn.major_version, 2 | 3));
    }
    let _ = parse_storage_device_descriptor(data);
    if let Some(h) = parse_hotplug_info(data) {
        assert_eq!(h.is_hotplug(), h.media_hotplug || h.device_hotplug);
    }
    let m = parse_zone_identifier(data);
    if let (Some(z), Some(s)) = (m.zone, m.strictest_zone) {
        assert!(s.strictness() >= z.strictness());
    }
});
