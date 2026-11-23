//! Fuzzes the `VS_VERSIONINFO` parser directly, without a PE around it.
#![no_main]

use libfuzzer_sys::fuzz_target;
use palisade_fileid::pe::version::{VersionField, parse_version_info};

fuzz_target!(|data: &[u8]| {
    if let Ok(v) = parse_version_info(data) {
        let _ = v.file_version();
        let _ = v.product_version_mismatch();
        let _ = v.effective_file_name(VersionField::OriginalFileName);
    }
});
