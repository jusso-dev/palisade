//! Fuzzes the PE parser: no input may panic, hang or allocate without bound.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(info) = palisade_fileid::pe::parse(data) {
        // Touch the derived accessors too.
        let _ = info.timestamp_is_reproducible();
        let _ = info.checksum.is_valid();
        if let Some(v) = &info.version_info {
            let _ = v.file_version_mismatch();
            let _ =
                v.effective_file_name(palisade_fileid::pe::version::VersionField::OriginalFileName);
        }
    }
});
