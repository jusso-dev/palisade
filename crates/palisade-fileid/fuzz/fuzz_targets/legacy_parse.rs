//! Fuzzes the NE, LE and LX identity reader.
#![no_main]

use libfuzzer_sys::fuzz_target;
use palisade_fileid::pe::legacy;

fuzz_target!(|data: &[u8]| {
    if let Ok(info) = legacy::parse(data) {
        for name in [&info.module_name, &info.description].into_iter().flatten() {
            let _ = name.normalized.folded();
        }
    }
});
