//! Fuzzes the strict YAML reader of policy documents (#190, #25), which
//! reads files written by people and tools. No input may panic or exhaust
//! memory. A document that reads must write back to YAML that reads as the
//! same document.
#![no_main]

use libfuzzer_sys::fuzz_target;
use palisade_policy::model::PolicyDocument;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(doc) = PolicyDocument::from_yaml(text) else {
        return;
    };
    let written = doc.to_yaml().unwrap();
    assert_eq!(PolicyDocument::from_yaml(&written).unwrap(), doc);
    let _ = doc.validate();
});
