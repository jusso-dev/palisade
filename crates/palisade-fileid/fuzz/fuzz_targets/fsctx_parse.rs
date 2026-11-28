//! Fuzzes the file-system context parsers: path normalisation (Win32 and
//! NT forms), self-relative security descriptors with the writability
//! evaluation, `Zone.Identifier` streams, and the stream-list and
//! change-journal records the OS returns (one file's record, the journal
//! state, and the record lists of a journal read and an MFT enumeration),
//! the storage descriptors the volume backend reads, reparse data buffers,
//! and the `$UpCase` file record. No input may panic, and a normalised
//! path, and each ancestor that is not too long, must normalise to itself
//! again.
#![no_main]

use libfuzzer_sys::fuzz_target;
use palisade_fileid::fsctx::acl::{EvaluationOptions, ObjectKind, SecurityDescriptor, evaluate};
use palisade_fileid::fsctx::ntfs::{
    MAX_JOURNAL_NAME_UNITS, MAX_STREAMS, parse_enum_usn_data, parse_journal_data,
    parse_read_journal, parse_stream_info, parse_usn_record,
};
use palisade_fileid::fsctx::reparse::{ReparseKind, parse_reparse_point};
use palisade_fileid::fsctx::{
    STANDARD_UPCASE_CRC, VolumeUpcase, normalize_nt, normalize_win32, nt_path_on_network,
    opened_name_on_network, parse_hotplug_info, parse_storage_device_descriptor,
    parse_upcase_info, parse_zone_identifier,
};

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = nt_path_on_network(text);
        for parsed in [normalize_win32(text), normalize_nt(text)] {
            if let Ok(p) = parsed {
                // A path the normaliser calls UNC is always on the network.
                if matches!(p.root(), palisade_fileid::fsctx::Root::Unc { .. }) {
                    assert_eq!(opened_name_on_network(&p), Some(true));
                }
                let again = normalize_win32(&p.to_win32_string()).expect("re-parse");
                assert_eq!(again.case_folded(), p.case_folded());
                assert_eq!(again.components(), p.components());
                assert_eq!(again.stream(), p.stream());
                for a in p.ancestors().flatten() {
                    let again = normalize_win32(&a.to_win32_string()).expect("ancestor");
                    assert_eq!(again.case_folded(), a.case_folded());
                }
                // Moving the path onto a share keeps its tail.
                let onto = normalize_win32(r"\\srv\share").expect("share");
                if let Some(Some(Ok(r))) = p.ancestors().last().map(|root| {
                    root.ok().and_then(|root| p.rebase(&root, &onto))
                }) {
                    assert_eq!(r.components(), p.components());
                    let again = normalize_win32(&r.to_win32_string()).expect("rebased");
                    assert_eq!(again.case_folded(), r.case_folded());
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
    let _ = parse_journal_data(data);
    let records = parse_read_journal(data)
        .map(|(_, r)| r)
        .into_iter()
        .chain(parse_enum_usn_data(data).map(|(_, r)| r));
    for r in records.flatten() {
        assert!(matches!(r.major_version, 2 | 3));
        assert!(!r.name.is_empty() && !r.name.contains(['\0', '\\']));
        assert!(r.name.encode_utf16().count() <= MAX_JOURNAL_NAME_UNITS);
    }
    let _ = parse_storage_device_descriptor(data);
    if let Ok(crc) = parse_upcase_info(data) {
        // Only the standard CRC folds as the standard table.
        assert_eq!(
            VolumeUpcase::from_crc(crc).folds_as_standard(),
            crc == Some(STANDARD_UPCASE_CRC)
        );
    }
    if let Ok(r) = parse_reparse_point(data) {
        assert_eq!(r.kind == ReparseKind::from_tag(r.tag), r.kind != ReparseKind::MountPoint);
        if let Some(a) = r.app_exec_link() {
            assert!(!a.target_path.contains('\0'));
        }
    }
    if let Some(h) = parse_hotplug_info(data) {
        assert_eq!(h.is_hotplug(), h.media_hotplug || h.device_hotplug);
    }
    let m = parse_zone_identifier(data);
    if let (Some(z), Some(s)) = (m.zone, m.strictest_zone) {
        assert!(s.strictness() >= z.strictness());
    }
});
