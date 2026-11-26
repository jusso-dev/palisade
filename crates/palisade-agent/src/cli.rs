//! Command-line parsing for the `palisade-agent` binary.

use std::{ffi::OsString, fmt, path::PathBuf};

/// Usage text printed by `--help` and after a usage error.
pub const USAGE: &str = "\
Usage: palisade-agent (--console | --service) [--config <path>]
       palisade-agent --simulate [--scenario <path>]
       palisade-agent --help | --version

Modes:
  --console          Run in the foreground until Ctrl-C (any OS).
  --service          Run under the Windows service control manager.
                     The installer registers the service with this flag.
  --simulate         Development only (built with the `test-util` feature):
                     replay a scripted scenario on the mock platform and
                     write its events to standard output as JSON lines.

Options:
  --config <path>    Configuration file. Without it, the agent reads
                     %ProgramData%\\Palisade\\agent.toml on Windows if it
                     exists, and uses built-in defaults otherwise.
  --scenario <path>  The scenario for --simulate. Without it, the built-in
                     scenario runs.
  -h, --help         Print this help.
  -V, --version      Print the version.";

/// How the binary was asked to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Foreground run, stopped by Ctrl-C (or `SIGTERM` on Unix).
    Console,
    /// Run under the Windows service control manager.
    Service,
    /// Replay a scenario on the mock platform (feature `test-util`).
    Simulate,
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
    /// The `--scenario` path, if given. Only with [`Mode::Simulate`].
    pub scenario: Option<PathBuf>,
}

/// A command line that could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliError {
    /// No mode flag was given.
    NoMode,
    /// More than one mode flag was given.
    ConflictingModes,
    /// An option that needs a value was last on the line.
    MissingValue(&'static str),
    /// An option was given twice.
    Duplicate(&'static str),
    /// An argument that is not recognised.
    Unknown(String),
    /// An option that does not apply to the selected mode.
    WrongMode(&'static str),
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoMode => f.write_str("choose a mode: --console, --service or --simulate"),
            Self::ConflictingModes => {
                f.write_str("--console, --service and --simulate are mutually exclusive")
            }
            Self::MissingValue(opt) => write!(f, "{opt} needs a value"),
            Self::Duplicate(opt) => write!(f, "{opt} given more than once"),
            Self::Unknown(arg) => write!(f, "unrecognised argument `{arg}`"),
            Self::WrongMode(opt) => write!(f, "{opt} does not apply to this mode"),
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
    let mut scenario = None;
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("--console") => set_mode(&mut mode, Mode::Console)?,
            Some("--service") => set_mode(&mut mode, Mode::Service)?,
            Some("--simulate") => set_mode(&mut mode, Mode::Simulate)?,
            Some("-h" | "--help") => return Ok(only(Mode::Help)),
            Some("-V" | "--version") => return Ok(only(Mode::Version)),
            Some("--config") => set_path(&mut config, "--config", args.next())?,
            Some("--scenario") => set_path(&mut scenario, "--scenario", args.next())?,
            _ => return Err(CliError::Unknown(arg.to_string_lossy().into_owned())),
        }
    }
    let mode = mode.ok_or(CliError::NoMode)?;
    if scenario.is_some() && mode != Mode::Simulate {
        return Err(CliError::WrongMode("--scenario"));
    }
    // The simulator reads no agent configuration.
    if config.is_some() && mode == Mode::Simulate {
        return Err(CliError::WrongMode("--config"));
    }
    Ok(Args {
        mode,
        config,
        scenario,
    })
}

fn set_path(
    slot: &mut Option<PathBuf>,
    option: &'static str,
    value: Option<OsString>,
) -> Result<(), CliError> {
    if slot.is_some() {
        return Err(CliError::Duplicate(option));
    }
    let value = value.ok_or(CliError::MissingValue(option))?;
    *slot = Some(PathBuf::from(value));
    Ok(())
}

fn only(mode: Mode) -> Args {
    Args {
        mode,
        config: None,
        scenario: None,
    }
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
                scenario: None,
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

    #[test]
    fn simulate_mode_and_scenario() {
        assert_eq!(parse_strs(&["--simulate"]).unwrap(), only(Mode::Simulate));
        let args = parse_strs(&["--scenario", "s.toml", "--simulate"]).unwrap();
        assert_eq!(args.mode, Mode::Simulate);
        assert_eq!(args.scenario, Some(PathBuf::from("s.toml")));
        assert_eq!(
            parse_strs(&["--console", "--scenario", "s.toml"]),
            Err(CliError::WrongMode("--scenario"))
        );
        assert_eq!(
            parse_strs(&["--simulate", "--config", "a.toml"]),
            Err(CliError::WrongMode("--config"))
        );
        assert_eq!(
            parse_strs(&["--simulate", "--service"]),
            Err(CliError::ConflictingModes)
        );
        assert_eq!(
            parse_strs(&["--simulate", "--scenario"]),
            Err(CliError::MissingValue("--scenario"))
        );
        assert_eq!(
            parse_strs(&["--simulate", "--scenario", "a", "--scenario", "b"]),
            Err(CliError::Duplicate("--scenario"))
        );
        assert!(USAGE.contains("--simulate") && USAGE.contains("--scenario"));
    }
}
