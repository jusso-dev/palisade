//! Fuzzes the strict YAML reader of policy documents (#190, #25), which
//! reads files written by people and tools. No input may panic or exhaust
//! memory. A document that reads must write back to YAML that reads as the
//! same document, and validating it locates every finding in the source.
#![no_main]

use libfuzzer_sys::fuzz_target;
use palisade_policy::dsl::{self, Limits};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(loaded) = dsl::from_str(text) else {
        return;
    };
    // The written form may be longer than the input (escapes grow, and a
    // JSON input is not bound by the lookahead limit), so it is read back
    // with room for that. Depth and node count were bounded by the first
    // read.
    let written = dsl::to_string(loaded.document()).unwrap();
    let room = Limits {
        max_bytes: written.len().max(Limits::DEFAULT.max_bytes),
        max_lookahead: written.len().max(Limits::DEFAULT.max_lookahead),
        ..Limits::DEFAULT
    };
    let again = dsl::from_str_with_limits(&written, &room).unwrap();
    assert_eq!(again.document(), loaded.document());
    let _ = loaded.validate();
});
