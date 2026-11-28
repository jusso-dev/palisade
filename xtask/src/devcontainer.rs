//! Keeps the dev container (`.devcontainer/`, #29) in step with CI: its
//! toolchain, targets, components and tool versions must be the ones
//! `rust-toolchain.toml` and `.github/workflows/ci.yml` use. Tests only.

#[cfg(test)]
mod tests {
    use std::path::Path;

    fn read(relative: &str) -> String {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join(relative);
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
    }

    /// The value of `ARG <name>=<value>` in the Dockerfile.
    fn arg(dockerfile: &str, name: &str) -> String {
        dockerfile
            .lines()
            .find_map(|l| l.strip_prefix(&format!("ARG {name}=")))
            .unwrap_or_else(|| panic!("no ARG {name}"))
            .to_owned()
    }

    #[test]
    fn toolchain_components_and_targets_match_rust_toolchain_toml() {
        let dockerfile = read(".devcontainer/Dockerfile");
        let toolchain: toml::Table = read("rust-toolchain.toml").parse().unwrap();
        let toolchain = &toolchain["toolchain"];
        assert_eq!(
            arg(&dockerfile, "RUST_TOOLCHAIN"),
            toolchain["channel"].as_str().unwrap()
        );
        // The base image is the official image for the same release.
        let channel = toolchain["channel"].as_str().unwrap();
        assert!(
            dockerfile.contains(&format!("# rust:{channel}-")),
            "the base image comment names another release"
        );
        for key in ["components", "targets"] {
            for item in toolchain[key].as_array().unwrap() {
                let item = item.as_str().unwrap();
                assert!(
                    dockerfile.contains(item),
                    "the Dockerfile does not install {key} entry {item}"
                );
            }
        }
        assert_eq!(arg(&dockerfile, "FUZZ_TOOLCHAIN"), crate::fuzz::TOOLCHAIN);
        assert!(dockerfile.contains(crate::fuzz::CARGO_FUZZ));
    }

    /// `cargo xtask ci` checks every tool before it runs a step, so the
    /// image must have all of them, including the MSRV toolchain and
    /// actionlint, which are not cargo-installed.
    /// Programs the workspace's tests spawn on Linux that the slim base
    /// image lacks, with the Debian package that provides each.
    const TEST_PROGRAMS: &[(&str, &str)] = &[("kill", "procps")];
    /// Programs the tests spawn on Linux that the base image already has
    /// (`coreutils`, which every Debian image includes).
    const IN_BASE_IMAGE: &[&str] = &["mkfifo"];
    /// Programs only the Windows tests spawn; they never run in the image.
    const WINDOWS_ONLY: &[&str] = &[
        "attrib",
        "certutil",
        "cmd",
        "cmd.exe",
        "diskpart",
        "fsutil",
        "icacls",
        "net",
        "powershell",
        "powershell.exe",
    ];

    #[test]
    fn the_image_has_every_program_the_tests_spawn() {
        let dockerfile = read(".devcontainer/Dockerfile");
        let install = dockerfile
            .split("apt-get install")
            .nth(1)
            .and_then(|rest| rest.split("&& rm -rf").next())
            .unwrap();
        for (program, package) in TEST_PROGRAMS {
            assert!(
                install.split_whitespace().any(|w| w == *package),
                "the image must install {package} for `{program}`, which the tests run"
            );
        }
        // Every program a test spawns by a literal name is either listed
        // above or a Rust tool, so a new one cannot be missed.
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let mut spawned = std::collections::BTreeSet::new();
        for entry in std::fs::read_dir(root.join("crates")).unwrap() {
            let tests = entry.unwrap().path().join("tests");
            let Ok(files) = std::fs::read_dir(&tests) else {
                continue;
            };
            for file in files {
                let path = file.unwrap().path();
                if path.extension().is_none_or(|e| e != "rs") {
                    continue;
                }
                let text = std::fs::read_to_string(&path).unwrap();
                for piece in text.split("Command::new(\"").skip(1) {
                    if let Some((name, _)) = piece.split_once('"') {
                        spawned.insert(name.to_owned());
                    }
                }
            }
        }
        assert!(spawned.contains("kill"), "{spawned:?}");
        for name in &spawned {
            let known = TEST_PROGRAMS.iter().any(|(p, _)| p == name)
                || IN_BASE_IMAGE.contains(&name.as_str())
                || WINDOWS_ONLY.contains(&name.as_str());
            assert!(
                known,
                "a test spawns `{name}`: add it to TEST_PROGRAMS with the Debian package the image must install, or to IN_BASE_IMAGE or WINDOWS_ONLY"
            );
        }
    }

    #[test]
    fn the_image_has_every_tool_xtask_ci_needs() {
        let dockerfile = read(".devcontainer/Dockerfile");
        let cargo: toml::Table = read("Cargo.toml").parse().unwrap();
        let rust_version = cargo["workspace"]["package"]["rust-version"]
            .as_str()
            .unwrap();
        assert_eq!(
            arg(&dockerfile, "MSRV_TOOLCHAIN"),
            crate::ci::msrv_toolchain(rust_version)
        );
        let ci = read(".github/workflows/ci.yml");
        let ci_env = |name: &str| {
            ci.lines()
                .find_map(|l| l.trim().strip_prefix(&format!("{name}: ")))
                .unwrap()
                .trim_matches('"')
                .to_owned()
        };
        assert_eq!(
            arg(&dockerfile, "ACTIONLINT_VERSION"),
            ci_env("ACTIONLINT_VERSION")
        );
        assert_eq!(
            arg(&dockerfile, "ACTIONLINT_SHA256_AMD64"),
            ci_env("ACTIONLINT_SHA256")
        );
        assert!(dockerfile.contains("sha256sum --check --strict"));
        for step in crate::ci::STEPS {
            let Some(tool) = step.tool else { continue };
            // The image is Linux: Windows-only steps never run in it.
            if step.only_on == Some("windows") {
                continue;
            }
            let program = tool.check[0];
            // The server-image steps build and run an image, which needs a
            // container runtime on the host, not one nested in the dev
            // container (docs/dev/unix.md). `--fast` skips them.
            if program == "podman" {
                assert!(step.slow, "{}", step.command);
                continue;
            }
            let covered = match program {
                "cargo" => {
                    let sub = tool
                        .check
                        .iter()
                        .find(|w| !w.starts_with('+') && **w != "cargo");
                    let sub = sub.unwrap();
                    dockerfile.contains(&format!("cargo-{sub}@"))
                }
                other => dockerfile.contains(other),
            };
            assert!(covered, "the image lacks the tool for `{}`", step.command);
        }
    }

    #[test]
    fn tool_versions_match_ci() {
        let dockerfile = read(".devcontainer/Dockerfile");
        let ci = read(".github/workflows/ci.yml");
        let mut checked = 0;
        for line in ci.lines() {
            let Some(tools) = line.trim().strip_prefix("tool: ") else {
                continue;
            };
            for tool in tools.split(',') {
                // cargo-fuzz is installed on the fuzz toolchain, checked above.
                // The install action names typos by its binary; the crate is
                // typos-cli.
                let tool = tool.trim().replacen("typos@", "typos-cli@", 1);
                assert!(
                    dockerfile.contains(&tool),
                    "ci.yml installs {tool}, the Dockerfile does not"
                );
                checked += 1;
            }
        }
        assert!(checked >= 7, "found only {checked} tools in ci.yml");
    }

    #[test]
    fn postgres_service_uses_the_ci_image() {
        let compose = read(".devcontainer/compose.yaml");
        let ci = read(".github/workflows/ci.yml");
        let image = |source: &str| {
            source
                .lines()
                .find_map(|l| l.trim().strip_prefix("image: postgres@"))
                .map(str::to_owned)
                .unwrap()
        };
        assert_eq!(image(&compose), image(&ci));
    }

    /// compose.yaml mounts a named volume over the build directory; the
    /// image must create it owned by the non-root user, or a fresh volume
    /// is owned by root and every build fails.
    #[test]
    fn volume_mount_points_belong_to_the_container_user() {
        let dockerfile = read(".devcontainer/Dockerfile");
        let compose = read(".devcontainer/compose.yaml");
        let user = dockerfile
            .lines()
            .find_map(|l| l.strip_prefix("USER "))
            .unwrap()
            .trim();
        for line in compose.lines() {
            let Some(mount) = line.trim().strip_prefix("- ") else {
                continue;
            };
            let Some((source, target)) = mount.split_once(':') else {
                continue;
            };
            // Named volumes only; bind mounts start with `.` or `/`.
            if source.starts_with(['.', '/']) {
                continue;
            }
            let target = target.split(':').next().unwrap();
            assert!(
                dockerfile.contains(&format!("mkdir -p {target}")),
                "the Dockerfile does not create {target}"
            );
            let workspace = target.rsplit_once('/').unwrap().0;
            let chown = dockerfile
                .lines()
                .find(|l| l.contains(&format!("chown -R {user}")))
                .unwrap();
            assert!(
                chown.contains(target) || chown.contains(workspace),
                "{target} is not chowned to {user}"
            );
        }
    }

    #[test]
    fn the_container_does_not_enable_the_git_hooks() {
        // The hooks are opt-in (#29): nothing may set core.hooksPath for the
        // developer.
        for file in [
            ".devcontainer/devcontainer.json",
            ".devcontainer/Dockerfile",
            ".devcontainer/compose.yaml",
        ] {
            assert!(!read(file).contains("core.hooksPath"), "{file}");
        }
    }
}
