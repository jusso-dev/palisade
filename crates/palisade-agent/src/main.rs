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
        Mode::Simulate => simulate(&args),
        Mode::StashToken => stash(&args),
    }
}

/// `--stash-enroll-token=<token>`: the installer stores the token.
#[cfg(windows)]
fn stash(args: &cli::Args) -> ExitCode {
    match &args.enroll_token {
        Some(token) => palisade_agent::bootstrap::run_stash(token),
        None => ExitCode::from(2),
    }
}

/// `--stash-enroll-token` off Windows.
#[cfg(not(windows))]
fn stash(_: &cli::Args) -> ExitCode {
    eprintln!("palisade-agent: --stash-enroll-token is only available on Windows");
    ExitCode::FAILURE
}

/// `--simulate`: replays a scenario and prints its events as JSON lines.
#[cfg(feature = "test-util")]
fn simulate(args: &cli::Args) -> ExitCode {
    use palisade_agent::simulate::{self, JsonLines, Scenario};
    let scenario = match &args.scenario {
        Some(path) => Scenario::load(path),
        None => Scenario::from_toml(simulate::scenario::DEFAULT),
    };
    let scenario = match scenario {
        Ok(scenario) => scenario,
        Err(e) => {
            eprintln!("palisade-agent: {e}");
            return ExitCode::from(2);
        }
    };
    let stdout = std::io::stdout();
    let mut sink = JsonLines(stdout.lock());
    match simulate::run(&scenario, &mut sink) {
        Ok(count) => {
            eprintln!("palisade-agent: simulated {count} events");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("palisade-agent: simulation failed: {e}");
            ExitCode::FAILURE
        }
    }
}

/// `--simulate` without the `test-util` feature.
#[cfg(not(feature = "test-util"))]
fn simulate(_: &cli::Args) -> ExitCode {
    eprintln!(
        "palisade-agent: --simulate is a development feature; build with \
         `cargo run -p palisade-agent --features test-util -- --simulate`"
    );
    ExitCode::from(2)
}
