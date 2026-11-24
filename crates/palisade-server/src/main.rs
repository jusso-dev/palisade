//! The `palisade-server` binary. See the crate README for details.

#![forbid(unsafe_code)]

use std::process::ExitCode;

fn main() -> ExitCode {
    palisade_server::cli::run()
}
