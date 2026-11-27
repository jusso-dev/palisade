//! Checking for the external tools xtask commands run (#29): each command
//! that needs one says which, at which version, and how to install it, and
//! fails with that before doing anything else.
//!
//! A check runs the tool's version command through a [`Probe`] and reads
//! the version from its first line ([`version_in`]). The result is a
//! [`Status`]: present at the expected version, present at another version,
//! or missing (it did not start, or failed). The real probe runs the
//! command; tests use a fake one.

use std::process::{Command, Stdio};

/// The outcome of running a version command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeResult {
    /// It ran and succeeded, printing this on stdout.
    Ran(String),
    /// It could not be started, or exited non-zero.
    Failed,
}

/// Runs a version command.
pub trait Probe {
    /// Runs `command` (program and arguments).
    fn run(&mut self, command: &[String]) -> ProbeResult;
}

/// The probe that runs the command, with its output captured.
pub struct ProcessProbe;

impl Probe for ProcessProbe {
    fn run(&mut self, command: &[String]) -> ProbeResult {
        let Some((program, args)) = command.split_first() else {
            return ProbeResult::Failed;
        };
        match Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
        {
            Ok(out) if out.status.success() => {
                ProbeResult::Ran(String::from_utf8_lossy(&out.stdout).into_owned())
            }
            _ => ProbeResult::Failed,
        }
    }
}

/// What a check found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    /// Installed, at the expected version (or no version is pinned).
    Present,
    /// Installed, at another version (or one that could not be read).
    WrongVersion {
        /// What its version command printed, first line.
        found: String,
    },
    /// Not installed: the version command did not start or failed.
    Missing,
}

/// The version in `output`'s first line: its first word that starts with
/// a digit, without a leading `v`, cut at the first character that is not
/// a digit or a dot. `cargo-nextest 0.9.152 (26ebeda79 2026-11-13)` gives
/// `0.9.152`, `mdbook v0.5.2` gives `0.5.2`, and `1.7.12` gives `1.7.12`.
pub fn version_in(output: &str) -> Option<&str> {
    let first = output.lines().next()?;
    first.split_whitespace().find_map(|word| {
        let word = word.strip_prefix('v').unwrap_or(word);
        if !word.starts_with(|c: char| c.is_ascii_digit()) {
            return None;
        }
        let end = word
            .find(|c: char| !(c.is_ascii_digit() || c == '.'))
            .unwrap_or(word.len());
        word.get(..end).map(|v| v.trim_end_matches('.'))
    })
}

/// Checks the tool whose version command is `command`. With `expected`,
/// the version it prints must be exactly that.
pub fn check(probe: &mut dyn Probe, command: &[String], expected: Option<&str>) -> Status {
    match probe.run(command) {
        ProbeResult::Failed => Status::Missing,
        ProbeResult::Ran(output) => match expected {
            None => Status::Present,
            Some(want) if version_in(&output) == Some(want) => Status::Present,
            Some(_) => Status::WrongVersion {
                found: output.lines().next().unwrap_or("").trim().to_owned(),
            },
        },
    }
}

/// The line reporting a tool that is not [`Status::Present`], or `None`.
/// `name` is what the user knows the tool as; `install` how to get the
/// expected version.
pub fn problem(
    name: &str,
    expected: Option<&str>,
    install: &str,
    status: &Status,
) -> Option<String> {
    let want = expected.map(|v| format!(" {v}")).unwrap_or_default();
    match status {
        Status::Present => None,
        Status::Missing => Some(format!("{name}{want} is not installed: {install}")),
        Status::WrongVersion { found } => Some(format!(
            "{name}{want} is needed, found `{found}`: {install}"
        )),
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::collections::HashMap;

    /// A probe that answers from a table of command lines, and records
    /// every command it was asked to run.
    #[derive(Default)]
    pub struct FakeProbe {
        pub answers: HashMap<String, ProbeResult>,
        pub asked: Vec<String>,
    }

    impl FakeProbe {
        pub fn with(answers: &[(&str, Option<&str>)]) -> Self {
            Self {
                answers: answers
                    .iter()
                    .map(|(cmd, out)| {
                        (
                            (*cmd).to_owned(),
                            out.map_or(ProbeResult::Failed, |o| ProbeResult::Ran(o.to_owned())),
                        )
                    })
                    .collect(),
                asked: Vec::new(),
            }
        }
    }

    impl Probe for FakeProbe {
        fn run(&mut self, command: &[String]) -> ProbeResult {
            let line = command.join(" ");
            self.asked.push(line.clone());
            self.answers
                .get(&line)
                .cloned()
                .unwrap_or(ProbeResult::Failed)
        }
    }

    fn cmd(line: &str) -> Vec<String> {
        line.split(' ').map(str::to_owned).collect()
    }

    #[test]
    fn versions_are_read_from_real_version_lines() {
        // As printed by the tool versions CI pins.
        for (output, version) in [
            ("cargo-nextest 0.9.152 (26ebeda79 2026-11-13)\n", "0.9.152"),
            ("cargo-deny 0.22.0\n", "0.22.0"),
            ("cargo-vet 0.10.3\n", "0.10.3"),
            ("cargo-insta 1.49.0\n", "1.49.0"),
            ("typos-cli 1.52.2\n", "1.52.2"),
            ("mdbook v0.5.2\n", "0.5.2"),
            ("1.7.12\ninstalled by downloading\n", "1.7.12"),
            ("cargo-fuzz 0.13.2\n", "0.13.2"),
            ("lychee 0.24.2\n", "0.24.2"),
            ("tool 2.0.\n", "2.0"),
            ("tool 1.2.3-beta.1\n", "1.2.3"),
        ] {
            assert_eq!(version_in(output), Some(version), "{output:?}");
        }
        for output in [
            "",
            "\n",
            "no version here\n",
            "\n1.2.3 on the second line\n",
        ] {
            assert_eq!(version_in(output), None, "{output:?}");
        }
    }

    #[test]
    fn a_tool_is_present_missing_or_at_the_wrong_version() {
        let mut probe = FakeProbe::with(&[
            (
                "cargo nextest --version",
                Some("cargo-nextest 0.9.152 (x 2026-11-13)\n"),
            ),
            ("cargo deny --version", Some("cargo-deny 0.21.9\n")),
            ("odd --version", Some("garbled\n")),
            ("broken --version", None),
        ]);
        let nextest = cmd("cargo nextest --version");
        // Present, with or without a pinned version.
        assert_eq!(
            check(&mut probe, &nextest, Some("0.9.152")),
            Status::Present
        );
        assert_eq!(check(&mut probe, &nextest, None), Status::Present);
        // A different version, and one that cannot be read, are wrong.
        assert_eq!(
            check(&mut probe, &cmd("cargo deny --version"), Some("0.22.0")),
            Status::WrongVersion {
                found: "cargo-deny 0.21.9".to_owned()
            }
        );
        assert_eq!(
            check(&mut probe, &cmd("odd --version"), Some("1.0.0")),
            Status::WrongVersion {
                found: "garbled".to_owned()
            }
        );
        // A prefix of the pinned version is not it.
        assert_eq!(
            check(&mut probe, &nextest, Some("0.9.15")),
            Status::WrongVersion {
                found: "cargo-nextest 0.9.152 (x 2026-11-13)".to_owned()
            }
        );
        // Failed, and never installed, are both missing.
        assert_eq!(
            check(&mut probe, &cmd("broken --version"), Some("1")),
            Status::Missing
        );
        assert_eq!(
            check(&mut probe, &cmd("absent --version"), None),
            Status::Missing
        );
        assert_eq!(check(&mut probe, &[], None), Status::Missing);
        assert_eq!(
            probe.asked,
            [
                "cargo nextest --version",
                "cargo nextest --version",
                "cargo deny --version",
                "odd --version",
                "cargo nextest --version",
                "broken --version",
                "absent --version",
                ""
            ]
        );
    }

    #[test]
    fn problems_name_the_tool_the_version_and_the_install() {
        let install = "cargo install --locked cargo-deny@0.22.0";
        assert_eq!(
            problem("cargo-deny", Some("0.22.0"), install, &Status::Present),
            None
        );
        assert_eq!(
            problem("cargo-deny", Some("0.22.0"), install, &Status::Missing).unwrap(),
            "cargo-deny 0.22.0 is not installed: cargo install --locked cargo-deny@0.22.0"
        );
        assert_eq!(
            problem(
                "cargo-deny",
                Some("0.22.0"),
                install,
                &Status::WrongVersion {
                    found: "cargo-deny 0.21.9".to_owned()
                }
            )
            .unwrap(),
            "cargo-deny 0.22.0 is needed, found `cargo-deny 0.21.9`: cargo install --locked cargo-deny@0.22.0"
        );
        assert_eq!(
            problem("podman", None, "install podman", &Status::Missing).unwrap(),
            "podman is not installed: install podman"
        );
    }

    #[test]
    fn the_process_probe_reports_a_missing_program_as_failed() {
        let mut probe = ProcessProbe;
        let absent = vec![
            "palisade-xtask-no-such-tool-7f3c".to_owned(),
            "--version".to_owned(),
        ];
        assert_eq!(probe.run(&absent), ProbeResult::Failed);
        assert_eq!(probe.run(&[]), ProbeResult::Failed);
        assert_eq!(check(&mut probe, &absent, None), Status::Missing);
        // The cargo running this test is present.
        let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
        assert!(matches!(
            probe.run(&[cargo, "--version".to_owned()]),
            ProbeResult::Ran(out) if version_in(&out).is_some()
        ));
    }
}
