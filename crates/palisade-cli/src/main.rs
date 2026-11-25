#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

use std::process::ExitCode;

use clap::{Parser, Subcommand};

mod fileid;
mod output;

/// Palisade command-line tool.
#[derive(Debug, Parser)]
#[command(name = "pal", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Inspect file identities: hashes, signatures, version information and
    /// the masquerade assessment.
    #[command(alias = "file")]
    Fileid {
        #[command(subcommand)]
        command: fileid::Command,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Fileid { command } => fileid::run(command),
    }
}
