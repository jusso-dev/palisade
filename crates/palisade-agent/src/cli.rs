//! Command-line parsing for the `palisade-agent` binary.

use std::{ffi::OsString, fmt, path::PathBuf};

/// Usage text printed by `--help` and after a usage error.
pub const USAGE: &str = "\
Usage: palisade-agent (--console | --service) [--config <path>]
       palisade-agent --help | --version

Modes:
  --console          Run in the foreground until Ctrl-C (any OS).
  --service          Run under the Windows service control manager.
                     The installer registers the service with this flag.

Options:
  --config <path>    Configuration file. Without it, the agent reads
                     %ProgramData%\\Palisade\\agent.toml on Windows if it
                     exists, and uses built-in defaults otherwise.
  -h, --help         Print this help.
  -V, --version      Print the version.";

/// How the binary was asked to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Foreground run, stopped by Ctrl-C (or `SIGTERM` on Unix).
    Console,
    /// Run under the Windows service control manager.
    Service,
    /// Print usage and exit.
    Help,
    /// Print the version and exit.
    Version,
}

/// Parsed command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Args {
    /// The selected mode.
    pub mode: Mode,
    /// The `--config` path, if given.
    pub config: Option<PathBuf>,
}

/// A command line that could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliError {
    /// Neither `--console` nor `--service` was given.
    NoMode,
    /// More than one mode flag was given.
    ConflictingModes,
    /// An option that needs a value was last on the line.
    MissingValue(&'static str),
    /// An option was given twice.
    Duplicate(&'static str),
    /// An argument that is not recognised.
    Unknown(String),
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoMode => f.write_str("choose a mode: --console or --service"),
            Self::ConflictingModes => f.write_str("--console and --service are mutually exclusive"),
            Self::MissingValue(opt) => write!(f, "{opt} needs a value"),
            Self::Duplicate(opt) => write!(f, "{opt} given more than once"),
            Self::Unknown(arg) => write!(f, "unrecognised argument `{arg}`"),
        }
    }
}

impl std::error::Error for CliError {}

/// Parses the arguments after the program name.
///
/// `--help` and `--version` win over everything after them, so
/// `palisade-agent --help --bogus` still prints help.
pub fn parse<I: IntoIterator<Item = OsString>>(args: I) -> Result<Args, CliError> {
    let mut mode = None;
    let mut config = None;
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("--console") => set_mode(&mut mode, Mode::Console)?,
            Some("--service") => set_mode(&mut mode, Mode::Service)?,
            Some("-h" | "--help") => return Ok(only(Mode::Help)),
            Some("-V" | "--version") => return Ok(only(Mode::Version)),
            Some("--config") => {
                if config.is_some() {
                    return Err(CliError::Duplicate("--config"));
                }
                let value = args.next().ok_or(CliError::MissingValue("--config"))?;
                config = Some(PathBuf::from(value));
            }
            _ => return Err(CliError::Unknown(arg.to_string_lossy().into_owned())),
        }
    }
    Ok(Args {
        mode: mode.ok_or(CliError::NoMode)?,
        config,
    })
}

fn only(mode: Mode) -> Args {
    Args { mode, config: None }
}

fn set_mode(slot: &mut Option<Mode>, mode: Mode) -> Result<(), CliError> {
    if slot.replace(mode).is_some() {
        return Err(CliError::ConflictingModes);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_strs(args: &[&str]) -> Result<Args, CliError> {
        parse(args.iter().map(OsString::from))
    }

    #[test]
    fn console_and_service_modes() {
        assert_eq!(parse_strs(&["--console"]).unwrap(), only(Mode::Console));
        assert_eq!(
            parse_strs(&["--service", "--config", "C:\\x\\agent.toml"]).unwrap(),
            Args {
                mode: Mode::Service,
                config: Some(PathBuf::from("C:\\x\\agent.toml")),
            }
        );
        assert_eq!(
            parse_strs(&["--config", "a.toml", "--console"])
                .unwrap()
                .config,
            Some(PathBuf::from("a.toml"))
        );
    }

    #[test]
    fn help_and_version_short_circuit() {
        assert_eq!(parse_strs(&["--help", "--bogus"]).unwrap().mode, Mode::Help);
        assert_eq!(parse_strs(&["-V"]).unwrap().mode, Mode::Version);
    }

    #[test]
    fn errors() {
        assert_eq!(parse_strs(&[]), Err(CliError::NoMode));
        assert_eq!(
            parse_strs(&["--console", "--service"]),
            Err(CliError::ConflictingModes)
        );
        assert_eq!(
            parse_strs(&["--console", "--console"]),
            Err(CliError::ConflictingModes)
        );
        assert_eq!(
            parse_strs(&["--console", "--config"]),
            Err(CliError::MissingValue("--config"))
        );
        assert_eq!(
            parse_strs(&["--config", "a", "--config", "b", "--console"]),
            Err(CliError::Duplicate("--config"))
        );
        assert_eq!(
            parse_strs(&["--console", "--config=a"]),
            Err(CliError::Unknown("--config=a".into()))
        );
    }
}
