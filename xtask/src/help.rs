//! Tests of `cargo xtask help` and `cargo xtask <command> --help` (#29).
//!
//! The command line is declared once, with clap, in `src/cli.rs`; clap
//! renders the help. These tests snapshot the help of the top level and of
//! every command and sub-command (`src/snapshots/`), check that every one
//! of them, and every argument, has help text, and check that every way CI
//! and the scripts call xtask still parses to the same command.

#[cfg(test)]
mod tests {
    use clap::CommandFactory as _;

    use crate::cli::Cli;

    /// Every command path, from the top level: `[]`, `["adr"]`,
    /// `["adr", "new"]` and so on, in declaration order.
    fn command_paths() -> Vec<Vec<String>> {
        fn walk(cmd: &clap::Command, path: &mut Vec<String>, out: &mut Vec<Vec<String>>) {
            out.push(path.clone());
            for sub in cmd.get_subcommands() {
                if sub.get_name() == "help" {
                    continue;
                }
                path.push(sub.get_name().to_owned());
                walk(sub, path, out);
                path.pop();
            }
        }
        let mut out = Vec::new();
        walk(&Cli::command(), &mut Vec::new(), &mut out);
        out
    }

    /// The help `cargo xtask <path> --help` prints, as clap renders it
    /// without colour.
    fn help_for(path: &[String]) -> String {
        let mut cmd = Cli::command().term_width(100);
        cmd.build();
        let mut target = &mut cmd;
        for name in path {
            target = target.find_subcommand_mut(name).unwrap();
        }
        target.render_long_help().to_string()
    }

    #[test]
    fn the_command_line_is_well_formed() {
        Cli::command().debug_assert();
    }

    #[test]
    fn every_command_and_argument_has_help() {
        fn check(cmd: &clap::Command, path: &str) {
            if cmd.get_name() != "help" {
                assert!(cmd.get_about().is_some(), "`{path}` has no help text");
            }
            for arg in cmd.get_arguments() {
                let id = arg.get_id().as_str();
                if id == "help" {
                    continue;
                }
                assert!(arg.get_help().is_some(), "`{path} {id}` has no help text");
            }
            for sub in cmd.get_subcommands() {
                check(sub, &format!("{path} {}", sub.get_name()));
            }
        }
        check(&Cli::command(), "cargo xtask");
    }

    #[test]
    fn every_command_help_is_snapshotted() {
        let paths = command_paths();
        // The top level, 28 commands and 15 sub-commands.
        assert_eq!(paths.len(), 44, "{paths:?}");
        for path in paths {
            let name = if path.is_empty() {
                "help".to_owned()
            } else {
                format!("help_{}", path.join("_"))
            };
            insta::assert_snapshot!(name, help_for(&path));
        }
    }

    fn parse(words: &[&str]) -> Result<crate::cli::Command, clap::Error> {
        use clap::Parser as _;
        Cli::try_parse_from(std::iter::once("xtask").chain(words.iter().copied()))
            .map(|c| c.command)
    }

    /// Every command line the workflows, scripts and docs use, as each
    /// command's own module receives it.
    #[test]
    fn every_command_line_ci_uses_still_parses() {
        use crate::cli::{
            AdrCommand as A, Command as C, DistCommand, DocsCommand as D, ReleaseCommand as R,
        };
        for words in [
            &["adr", "lint"][..],
            &["adr", "index"],
            &["audit"],
            &["check-banned-terms"],
            &["check-deps"],
            &["check-fuzz-locks"],
            &["check-manifests"],
            &["check-supply-chain"],
            &["check-testdata"],
            &["check-unsafe"],
            &["check-workflows"],
            &["ci"],
            &["fixtures"],
            &["golden"],
            &["sbom"],
            &["threat-coverage"],
            &["docs", "check"],
            &["docs", "generate"],
            &["release", "provenance"],
            &["deps-report"],
        ] {
            assert!(parse(words).is_ok(), "{words:?}");
        }
        assert!(matches!(parse(&["ci", "--fast"]), Ok(C::Ci { fast: true })));
        assert!(matches!(
            parse(&["golden", "--update"]),
            Ok(C::Golden { update: true })
        ));
        assert!(
            matches!(parse(&["adr", "new", "A title"]), Ok(C::Adr(A::New { title })) if title == "A title")
        );
        assert!(matches!(
            parse(&["check-banned-terms", "--digest", "x"]),
            Ok(C::CheckBannedTerms { digest: Some(d) }) if d == "x"
        ));
        assert!(matches!(
            parse(&["check-commit-msg", "m.txt"]),
            Ok(C::CheckCommitMsg { .. })
        ));
        for words in [
            ["coverage-gate", "--base", "abc"],
            ["bench-compare", "--base", "abc"],
            ["deps-report", "--base", "abc"],
        ] {
            assert!(parse(&words).is_ok(), "{words:?}");
        }
        assert!(matches!(
            parse(&["test-summary", "postgres", "target/nextest/ci/junit.xml"]),
            Ok(C::TestSummary { label, .. }) if label == "postgres"
        ));
        assert!(matches!(
            parse(&["coverage-summary", "linux", "c.json"]),
            Ok(C::CoverageSummary { .. })
        ));
        assert!(matches!(
            parse(&["docs", "build", "--site-url", "/palisade/latest/"]),
            Ok(C::Docs(D::Build { site_url: Some(_) }))
        ));
        assert!(matches!(
            parse(&["docs", "build"]),
            Ok(C::Docs(D::Build { site_url: None }))
        ));
        assert!(matches!(
            parse(&["docs", "serve"]),
            Ok(C::Docs(D::Serve {
                port: None,
                open: false
            }))
        ));
        assert!(matches!(
            parse(&["docs", "serve", "--open", "--port", "8080"]),
            Ok(C::Docs(D::Serve { port: Some(p), open: true })) if p == "8080"
        ));
        assert!(matches!(
            parse(&["docs", "assemble", "site", "--version", "latest"]),
            Ok(C::Docs(D::Assemble { .. }))
        ));
        assert!(matches!(
            parse(&["docs", "version-for-ref", "refs/heads/main"]),
            Ok(C::Docs(D::VersionForRef { .. }))
        ));
        for (words, ok) in [
            (&["release", "check-tag", "v0.1.0"][..], true),
            (&["release", "notes", "0.1.0"], true),
            (&["release", "prepare", "0.2.0"], true),
            (&["release", "checksums", "target/final"], true),
            (&["release", "verify-checksums", "target/verify"], true),
        ] {
            assert_eq!(matches!(parse(words), Ok(C::Release(_))), ok, "{words:?}");
        }
        assert!(matches!(
            parse(&[
                "release",
                "verify",
                "target/dist/signed",
                "--allow-untimestamped"
            ]),
            Ok(C::Release(R::Verify {
                allow_untimestamped: true,
                ..
            }))
        ));
        assert!(matches!(
            parse(&["release", "verify", "target/verify-arch"]),
            Ok(C::Release(R::Verify {
                allow_untimestamped: false,
                ..
            }))
        ));
        assert!(
            matches!(parse(&["dist", "driver"]), Ok(C::Dist(a)) if matches!(a.command, Some(DistCommand::Driver)))
        );

        // The words each module's own parser receives, which checks the
        // values as before.
        let dist = |words: &[&str]| match parse(words) {
            Ok(C::Dist(a)) => a.to_words(),
            other => panic!("{words:?}: {other:?}"),
        };
        assert_eq!(
            dist(&[
                "dist",
                "--target",
                "aarch64-pc-windows-msvc",
                "--msi",
                "--from",
                "target/unsigned/arm64",
                "--sign",
                "pfx",
                "--no-timestamp",
                "--out",
                "o"
            ]),
            [
                "--target",
                "aarch64-pc-windows-msvc",
                "--sign",
                "pfx",
                "--out",
                "o",
                "--from",
                "target/unsigned/arm64",
                "--msi",
                "--no-timestamp"
            ]
        );
        assert_eq!(
            dist(&["dist", "--msi", "--bump-patch", "--out", "n"]),
            ["--out", "n", "--msi", "--bump-patch"]
        );
        assert_eq!(
            dist(&[
                "dist",
                "--out",
                "target/release",
                "--compare-sizes",
                "s.json"
            ]),
            ["--out", "target/release", "--compare-sizes", "s.json"]
        );
        assert!(dist(&["dist"]).is_empty());
        let sign = |words: &[&str]| match parse(words) {
            Ok(C::Sign(a)) => a.to_args().unwrap(),
            other => panic!("{words:?}: {other:?}"),
        };
        let a = sign(&[
            "sign",
            "--signer",
            "none",
            "--verify",
            "--no-timestamp",
            "a.exe",
        ]);
        assert!(a.verify_only && a.no_timestamp);
        assert_eq!(a.files, [std::path::PathBuf::from("a.exe")]);
        let a = sign(&["sign", "a.exe", "--signer", "pfx", "b.msi"]);
        assert!(!a.verify_only);
        assert_eq!(a.files, [std::path::PathBuf::from("a.exe"), "b.msi".into()]);
        // An unknown signer is refused when the arguments are built.
        match parse(&["sign", "--signer", "x", "a.exe"]) {
            Ok(C::Sign(a)) => assert!(a.to_args().is_err()),
            other => panic!("{other:?}"),
        }
        // A file operand after `--` stays a file, even one that looks like a
        // flag: it must never switch the run to verify-only.
        let a = sign(&["sign", "--signer", "pfx", "--", "--verify", "a.exe"]);
        assert!(!a.verify_only, "{a:?}");
        assert_eq!(
            a.files,
            [std::path::PathBuf::from("--verify"), "a.exe".into()]
        );
        let fuzz = |words: &[&str]| match parse(words) {
            Ok(C::Fuzz(a)) => a.to_words(),
            other => panic!("{words:?}: {other:?}"),
        };
        assert!(fuzz(&["fuzz"]).is_empty());
        assert_eq!(fuzz(&["fuzz", "--shard", "2/6"]), ["--shard", "2/6"]);
        assert_eq!(
            fuzz(&["fuzz", "--seconds", "1800", "--target", "pe_parse"]),
            ["--seconds", "1800", "--target", "pe_parse"]
        );
    }

    #[test]
    fn bad_command_lines_are_errors() {
        use clap::error::ErrorKind as K;
        for (words, kind) in [
            (&[][..], K::DisplayHelpOnMissingArgumentOrSubcommand),
            (&["nope"], K::InvalidSubcommand),
            (&["ci", "--slow"], K::UnknownArgument),
            (&["coverage-gate"], K::MissingRequiredArgument),
            (&["sign", "a.exe"], K::MissingRequiredArgument),
            (&["sign", "--signer", "none"], K::MissingRequiredArgument),
            (
                &["fuzz", "--target", "a", "--shard", "0/2"],
                K::ArgumentConflict,
            ),
            (&["dist", "driver", "--msi"], K::UnknownArgument),
            (&["docs"], K::DisplayHelpOnMissingArgumentOrSubcommand),
            (&["docs", "assemble", "d"], K::MissingRequiredArgument),
            (&["release", "verify"], K::MissingRequiredArgument),
            (&["adr", "new"], K::MissingRequiredArgument),
            (&["test-summary", "label"], K::MissingRequiredArgument),
            (&["golden", "extra"], K::UnknownArgument),
            (
                &["docs", "serve", "--hostname", "0.0.0.0"],
                K::UnknownArgument,
            ),
            (&["docs", "serve", "--port"], K::InvalidValue),
        ] {
            let error = parse(words).map(|_| ()).unwrap_err();
            assert_eq!(error.kind(), kind, "{words:?}: {error}");
        }
        // `--help` and `help <command>` are help, not errors.
        for words in [
            &["--help"][..],
            &["help"],
            &["fuzz", "--help"],
            &["help", "fuzz"],
            &["docs", "build", "-h"],
        ] {
            let error = parse(words).map(|_| ()).unwrap_err();
            assert_eq!(error.kind(), K::DisplayHelp, "{words:?}");
        }
    }
}
