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
                assert!(
                    dockerfile.contains(tool.trim()),
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
