//! Command-line parsing for the `palisade-agent` binary.

#![forbid(unsafe_code)]

use std::{ffi::OsString, fmt, path::PathBuf};

use crate::bootstrap::EnrollToken;

/// Usage text printed by `--help` and after a usage error.
pub const USAGE: &str = "\
Usage: palisade-agent (--console | --service) [--config <path>]
       palisade-agent --simulate [--scenario <path>]
       palisade-agent --stash-enroll-token=<token>
       palisade-agent --seal-image
       palisade-agent --help | --version

Modes:
  --console          Run in the foreground until Ctrl-C (any OS).
  --service          Run under the Windows service control manager.
                     The installer registers the service with this flag.
  --simulate         Development only (built with the `test-util` feature):
                     replay a scripted scenario on the mock platform and
                     write its events to standard output as JSON lines.
  --stash-enroll-token=<token>
                     Run by the installer, as SYSTEM: protect the
                     enrolment token for this machine and store it for
                     the agent's first enrolment. Windows only.
  --seal-image       Windows, as an administrator with the service
                     stopped: remove this device's identity before the
                     image is generalised and captured, so every clone
                     gets its own on first boot.

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
    /// Store an enrolment token for the agent (Windows; the installer).
    StashToken,
    /// Seal a golden image (Windows).
    SealImage,
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
    /// The token of [`Mode::StashToken`]. Its `Debug` never prints it.
    pub enroll_token: Option<EnrollToken>,
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
    /// The enrolment token is not a valid token. The text is not kept.
    BadToken,
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoMode => f.write_str("choose a mode: --console, --service or --simulate"),
            Self::ConflictingModes => f.write_str(
                "--console, --service, --simulate and --seal-image are mutually exclusive",
            ),
            Self::MissingValue(opt) => write!(f, "{opt} needs a value"),
            Self::Duplicate(opt) => write!(f, "{opt} given more than once"),
            Self::Unknown(arg) => write!(f, "unrecognised argument `{arg}`"),
            Self::WrongMode(opt) => write!(f, "{opt} does not apply to this mode"),
            Self::BadToken => f.write_str(
                "--stash-enroll-token needs a token of ASCII letters, digits and -._~+/=:",
            ),
        }
    }
}

impl std::error::Error for CliError {}

/// Parses the arguments after the program name.
///
/// `--help` and `--version` win over everything after them, so
/// `palisade-agent --help --bogus` still prints help.
///
/// `--stash-enroll-token=<token>` must be the only argument. No error
/// repeats an argument that starts with `--stash-enroll-token`, so the
/// token never reaches an error message.
pub fn parse<I: IntoIterator<Item = OsString>>(args: I) -> Result<Args, CliError> {
    let mut mode = None;
    let mut config = None;
    let mut scenario = None;
    let mut args = args.into_iter().peekable();
    if let Some(first) = args.peek()
        && first.to_string_lossy().starts_with(STASH_FLAG)
    {
        return stash(&mut args);
    }
    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("--console") => set_mode(&mut mode, Mode::Console)?,
            Some("--service") => set_mode(&mut mode, Mode::Service)?,
            Some("--simulate") => set_mode(&mut mode, Mode::Simulate)?,
            Some("--seal-image") => set_mode(&mut mode, Mode::SealImage)?,
            Some("-h" | "--help") => return Ok(only(Mode::Help)),
            Some("-V" | "--version") => return Ok(only(Mode::Version)),
            Some("--config") => set_path(&mut config, "--config", args.next())?,
            Some("--scenario") => set_path(&mut scenario, "--scenario", args.next())?,
            _ if arg.to_string_lossy().starts_with(STASH_FLAG) => {
                return Err(CliError::WrongMode(STASH_FLAG));
            }
            _ => return Err(CliError::Unknown(arg.to_string_lossy().into_owned())),
        }
    }
    let mode = mode.ok_or(CliError::NoMode)?;
    if scenario.is_some() && mode != Mode::Simulate {
        return Err(CliError::WrongMode("--scenario"));
    }
    // The simulator and the seal read no agent configuration.
    if config.is_some() && matches!(mode, Mode::Simulate | Mode::SealImage) {
        return Err(CliError::WrongMode("--config"));
    }
    Ok(Args {
        mode,
        config,
        scenario,
        enroll_token: None,
    })
}

const STASH_FLAG: &str = "--stash-enroll-token";

/// `--stash-enroll-token=<token>`, alone on the line.
fn stash(args: &mut impl Iterator<Item = OsString>) -> Result<Args, CliError> {
    let first = args.next().ok_or(CliError::NoMode)?;
    if args.next().is_some() {
        return Err(CliError::WrongMode(STASH_FLAG));
    }
    let text = first.into_string().map_err(|_| CliError::BadToken)?;
    let token = text
        .strip_prefix(STASH_FLAG)
        .and_then(|rest| rest.strip_prefix('='))
        .ok_or(CliError::MissingValue(STASH_FLAG))?;
    let token = EnrollToken::parse(token).map_err(|_| CliError::BadToken)?;
    Ok(Args {
        mode: Mode::StashToken,
        config: None,
        scenario: None,
        enroll_token: Some(token),
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
        enroll_token: None,
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
                enroll_token: None,
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
    fn stash_enroll_token_alone_and_never_echoed() {
        let args = parse_strs(&["--stash-enroll-token=abc-DEF_123"]).unwrap();
        assert_eq!(args.mode, Mode::StashToken);
        assert_eq!(args.enroll_token.as_ref().unwrap().expose(), "abc-DEF_123");
        assert!(!format!("{args:?}").contains("abc-DEF_123"));
        let secret = "s3cret-value";
        for (line, want) in [
            (
                vec![format!("--stash-enroll-token={secret}"), "--console".into()],
                CliError::WrongMode(STASH_FLAG),
            ),
            (
                vec!["--console".into(), format!("--stash-enroll-token={secret}")],
                CliError::WrongMode(STASH_FLAG),
            ),
            (
                vec![format!("--stash-enroll-token{secret}")],
                CliError::MissingValue(STASH_FLAG),
            ),
            (
                vec!["--stash-enroll-token".into()],
                CliError::MissingValue(STASH_FLAG),
            ),
            (
                vec![format!("--stash-enroll-token={secret} \"x")],
                CliError::BadToken,
            ),
            (vec!["--stash-enroll-token=".into()], CliError::BadToken),
        ] {
            let e = parse(line.iter().map(OsString::from)).unwrap_err();
            assert_eq!(e, want, "{line:?}");
            assert!(!e.to_string().contains(secret));
            assert!(!format!("{e:?}").contains(secret));
        }
        assert!(USAGE.contains("--stash-enroll-token"));
    }

    #[test]
    fn seal_image_mode() {
        assert_eq!(
            parse_strs(&["--seal-image"]).unwrap(),
            only(Mode::SealImage)
        );
        assert_eq!(
            parse_strs(&["--seal-image", "--service"]),
            Err(CliError::ConflictingModes)
        );
        assert_eq!(
            parse_strs(&["--seal-image", "--config", "a.toml"]),
            Err(CliError::WrongMode("--config"))
        );
        assert_eq!(
            parse_strs(&["--seal-image", "--scenario", "s.toml"]),
            Err(CliError::WrongMode("--scenario"))
        );
        assert!(USAGE.contains("--seal-image"));
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
