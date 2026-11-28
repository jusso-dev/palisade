//! Fuzzes the command-line splitter (#329). A command line comes from
//! whoever starts a process, so it is untrusted: splitting must not panic,
//! must give at most one argument per byte plus one, and must agree with
//! itself on every argument position.
#![no_main]

use libfuzzer_sys::fuzz_target;
use palisade_policy::context::cmdline::{arg_at, split_args};

fuzz_target!(|data: &[u8]| {
    let Ok(line) = std::str::from_utf8(data) else {
        return;
    };
    let args = split_args(line);
    assert!(args.len() <= line.len() + 1, "more arguments than bytes");
    let n = i16::try_from(args.len()).unwrap_or(i16::MAX);
    for i in 0..n {
        assert_eq!(arg_at(&args, i), arg_at(&args, i - n), "index {i}");
    }
    assert_eq!(arg_at(&args, n), None);
});
