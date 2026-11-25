//! Fuzzes content tagging: no input may panic, hang or go over its budget,
//! the result must be consistent, and a full scan must agree with the file
//! type classifier on whether the file is a PE image.
#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use palisade_fileid::filetype::{self, FileKind};
use palisade_fileid::tags::{
    self, Condition, ContentRules, Location, PatternSource, RuleSetSource, RuleSource, ScanLimits,
    ScanStatus, StringSource,
};

/// The built-in rules plus organisation rules that use every location and
/// condition, so every code path of the scanner is reachable.
fn rules() -> &'static ContentRules {
    static RULES: OnceLock<ContentRules> = OnceLock::new();
    RULES.get_or_init(|| {
        let s = |pattern, location| StringSource { pattern, location };
        let rule = |tag: &str, strings, condition, require_pe| RuleSource {
            tag: tag.to_owned(),
            require_pe,
            max_file_size: None,
            unless_start: Some(PatternSource::Hex("FF FE".to_owned())),
            strings,
            condition,
        };
        let set = RuleSetSource {
            version: 1,
            rules: vec![
                rule(
                    "fuzz:mixed",
                    vec![
                        s(PatternSource::Hex("50 4B ?? 0?".to_owned()), Location::Range { start: 1, end: 4096 }),
                        s(PatternSource::Text("script".to_owned()), Location::From(2)),
                        s(PatternSource::WideText("run".to_owned()), Location::Tail(512)),
                    ],
                    Condition::AtLeast(2),
                    false,
                ),
                rule(
                    "fuzz:pe",
                    vec![
                        s(PatternSource::Hex("4D 5A".to_owned()), Location::Overlay),
                        s(PatternSource::Hex("?? 45".to_owned()), Location::At(0x81)),
                    ],
                    Condition::All,
                    true,
                ),
            ],
        };
        ContentRules::new(Some(&set)).expect("fuzz rules compile")
    })
}

fuzz_target!(|data: &[u8]| {
    // A byte budget picked by the input, and a small step budget, so both
    // limits are reached as well as a full scan.
    let budget = data.first().map_or(0, |b| u64::from(*b) * 64);
    for limits in [
        ScanLimits {
            timeout: None,
            ..ScanLimits::default()
        },
        ScanLimits {
            max_file_size: 1024,
            max_scan_bytes: budget,
            max_match_steps: 4096,
            timeout: None,
        },
    ] {
        let r = tags::scan_bytes(data, rules(), &limits);
        assert!(r.bytes_scanned <= limits.max_scan_bytes);
        assert!(r.match_steps <= limits.max_match_steps);
        assert_eq!(r.file_size, data.len() as u64);
        // The status tags are last: `content_scan_partial` for a file over
        // the size limit, then the status's own tag if it is different.
        let mut want: Vec<&str> = Vec::new();
        if r.file_size > limits.max_file_size {
            want.push(tags::CONTENT_SCAN_PARTIAL);
        }
        if let Some(tag) = r.status.tag().filter(|t| !want.contains(t)) {
            want.push(tag);
        }
        let status_tags: Vec<&str> = r
            .tags
            .iter()
            .map(String::as_str)
            .filter(|t| t.starts_with("content_scan_"))
            .collect();
        assert_eq!(status_tags, want);
        assert!(r.tags.ends_with(&want.iter().map(|t| t.to_string()).collect::<Vec<_>>()));
        if r.status == ScanStatus::Complete {
            let c = filetype::classify_bytes(data, None);
            assert_eq!(r.is_pe, c.content_kind == FileKind::Pe);
        }
    }
});
