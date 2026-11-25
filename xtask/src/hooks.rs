//! Tests for the opt-in Git hooks in `.githooks/` (#29).
//!
//! Each test runs a real hook script with Bash, against stub `cargo` and
//! `typos` programs on `PATH` that record how they were called and exit
//! with a chosen status. So the tests check the hooks' wiring (what runs,
//! in which directory, and what blocks a commit) without recursing into
//! Cargo. Unix only: they need Bash and executable stubs.

#[cfg(test)]
#[cfg(unix)]
mod tests {
    use std::{
        os::unix::fs::PermissionsExt,
        path::{Path, PathBuf},
        process::{Command, Output},
    };

    struct Sandbox {
        dir: PathBuf,
    }

    impl Sandbox {
        /// A Git repository with stub tools in `bin/`. `cargo_status` is the
        /// exit status of every stub `cargo` call except `cargo xtask help`,
        /// which prints `help` (whether it lists `check-banned-terms`
        /// depends on `banned_terms`).
        fn new(tag: &str, cargo_status: i32, typos: Option<i32>, banned_terms: bool) -> Self {
            Self::with_help(tag, cargo_status, typos, banned_terms, 0)
        }

        /// As [`Sandbox::new`], with `cargo xtask help` exiting with
        /// `help_status` (non-zero: xtask does not build).
        fn with_help(
            tag: &str,
            cargo_status: i32,
            typos: Option<i32>,
            banned_terms: bool,
            help_status: i32,
        ) -> Self {
            let dir =
                std::env::temp_dir().join(format!("palisade-hooks-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(dir.join("bin")).unwrap();
            let git = Command::new("git")
                .args(["init", "-q"])
                .current_dir(&dir)
                .status()
                .unwrap();
            assert!(git.success());
            let help = if banned_terms {
                "  check-banned-terms  ...\n"
            } else {
                "  check-deps  ...\n"
            };
            stub(
                &dir.join("bin/cargo"),
                &format!(
                    "echo \"cargo $* @ $PWD\" >> \"{log}\"\n\
                     if [ \"$1 $2\" = \"xtask help\" ]; then printf '{help}'; exit {help_status}; fi\n\
                     exit {cargo_status}\n",
                    log = dir.join("calls.log").display(),
                ),
            );
            if let Some(status) = typos {
                stub(
                    &dir.join("bin/typos"),
                    &format!(
                        "echo \"typos $*\" >> \"{}\"\nexit {status}\n",
                        dir.join("calls.log").display()
                    ),
                );
            }
            Self { dir }
        }

        fn run(&self, hook: &str, args: &[&str]) -> Output {
            let script = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../.githooks")
                .join(hook);
            // Only the stubs and the basic system tools are on PATH.
            let path = format!("{}:/usr/bin:/bin", self.dir.join("bin").display());
            Command::new("bash")
                .arg(script)
                .args(args)
                .current_dir(&self.dir)
                .env("PATH", path)
                .output()
                .unwrap()
        }

        fn calls(&self) -> Vec<String> {
            std::fs::read_to_string(self.dir.join("calls.log"))
                .unwrap_or_default()
                .lines()
                .map(|l| {
                    l.replace(
                        &*self.dir.canonicalize().unwrap().to_string_lossy(),
                        "<repo>",
                    )
                })
                .map(|l| l.replace(&*self.dir.to_string_lossy(), "<repo>"))
                .collect()
        }
    }

    impl Drop for Sandbox {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn stub(path: &Path, body: &str) {
        std::fs::write(path, format!("#!/bin/sh\n{body}")).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn stderr(out: &Output) -> String {
        String::from_utf8_lossy(&out.stderr).into_owned()
    }

    #[test]
    fn pre_commit_runs_every_check_from_the_repository_root() {
        let sandbox = Sandbox::new("all", 0, Some(0), true);
        let out = sandbox.run("pre-commit", &[]);
        assert!(out.status.success(), "{}", stderr(&out));
        assert_eq!(
            sandbox.calls(),
            [
                "cargo fmt --all --check @ <repo>",
                "typos ",
                "cargo xtask help @ <repo>",
                "cargo xtask check-banned-terms @ <repo>",
            ]
        );
    }

    #[test]
    fn pre_commit_skips_missing_tools_and_says_so() {
        let sandbox = Sandbox::new("skip", 0, None, false);
        let out = sandbox.run("pre-commit", &[]);
        assert!(out.status.success(), "{}", stderr(&out));
        let err = stderr(&out);
        assert!(err.contains("skipped typos"), "{err}");
        assert!(err.contains("skipped check-banned-terms"), "{err}");
        assert_eq!(
            sandbox.calls(),
            [
                "cargo fmt --all --check @ <repo>",
                "cargo xtask help @ <repo>"
            ]
        );
    }

    #[test]
    fn pre_commit_blocks_on_any_failure_but_runs_every_check() {
        let fmt = Sandbox::new("fmt", 1, Some(0), true);
        let out = fmt.run("pre-commit", &[]);
        assert!(!out.status.success());
        assert!(stderr(&out).contains("cargo fmt --all"));
        // A formatting failure does not hide the other problems.
        assert_eq!(fmt.calls().len(), 4);

        let typos = Sandbox::new("typos", 0, Some(2), false);
        let out = typos.run("pre-commit", &[]);
        assert!(!out.status.success());
        assert!(stderr(&out).contains("spelling"));
    }

    #[test]
    fn pre_commit_fails_when_xtask_cannot_run() {
        let sandbox = Sandbox::with_help("broken", 0, Some(0), true, 101);
        let out = sandbox.run("pre-commit", &[]);
        assert!(!out.status.success());
        let err = stderr(&out);
        assert!(err.contains("cargo xtask does not run"), "{err}");
        assert!(!err.contains("skipped check-banned-terms"), "{err}");
    }

    #[test]
    fn commit_msg_hands_the_message_file_to_xtask() {
        let sandbox = Sandbox::new("msg", 0, None, false);
        let out = sandbox.run("commit-msg", &[".git/COMMIT_EDITMSG"]);
        assert!(out.status.success(), "{}", stderr(&out));
        assert_eq!(
            sandbox.calls(),
            ["cargo xtask check-commit-msg <repo>/.git/COMMIT_EDITMSG @ <repo>"]
        );

        let failing = Sandbox::new("msg-fail", 1, None, false);
        assert!(!failing.run("commit-msg", &["m"]).status.success());
        let usage = failing.run("commit-msg", &[]);
        assert_eq!(usage.status.code(), Some(2));
    }

    #[test]
    fn hooks_are_executable_and_documented() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../.githooks");
        let readme = std::fs::read_to_string(dir.join("README.md")).unwrap();
        for hook in ["pre-commit", "commit-msg"] {
            let mode = std::fs::metadata(dir.join(hook))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o111, 0o111, "{hook} is not executable");
            assert!(readme.contains(hook), "README does not describe {hook}");
        }
        assert!(readme.contains("git config core.hooksPath .githooks"));
    }
}
