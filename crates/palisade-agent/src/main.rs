//! The `palisade-agent` binary. See the crate README for details.

use std::process::ExitCode;

#[cfg(windows)]
fn main() -> ExitCode {
    eprintln!(
        "palisade-agent {}: not implemented yet, see https://github.com/jusso-dev/palisade/issues/4",
        env!("CARGO_PKG_VERSION")
    );
    ExitCode::FAILURE
}

#[cfg(not(windows))]
fn main() -> ExitCode {
    eprintln!("palisade-agent runs only on Windows; this is a non-Windows stub build");
    ExitCode::FAILURE
}
