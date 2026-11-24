//! The `palisade-agent` binary. See the crate README for details.

#![forbid(unsafe_code)]

use std::process::ExitCode;

use palisade_agent::{
    cli::{self, Mode},
    host,
};

fn main() -> ExitCode {
    let args = match cli::parse(std::env::args_os().skip(1)) {
        Ok(args) => args,
        Err(e) => {
            eprintln!("palisade-agent: {e}\n\n{}", cli::USAGE);
            return ExitCode::from(2);
        }
    };
    match args.mode {
        Mode::Help => {
            println!("{}", cli::USAGE);
            ExitCode::SUCCESS
        }
        Mode::Version => {
            println!("palisade-agent {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Mode::Console => host::run_console(&args),
        #[cfg(windows)]
        Mode::Service => palisade_agent::service::run_service(args),
        #[cfg(not(windows))]
        Mode::Service => {
            eprintln!("palisade-agent: --service is only available on Windows; use --console");
            ExitCode::FAILURE
        }
    }
}
