#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

use std::process::ExitCode;

fn main() -> ExitCode {
    eprintln!(
        "pal {}: not implemented yet, see https://github.com/jusso-dev/palisade/issues/15",
        env!("CARGO_PKG_VERSION")
    );
    ExitCode::FAILURE
}
