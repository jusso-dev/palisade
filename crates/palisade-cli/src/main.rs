#![doc = include_str!("../README.md")]

use std::process::ExitCode;

fn main() -> ExitCode {
    eprintln!(
        "pal {}: not implemented yet, see https://github.com/jusso-dev/palisade/issues/15",
        env!("CARGO_PKG_VERSION")
    );
    ExitCode::FAILURE
}
