//! Keeps the Clippy configurations consistent (#29). Clippy reads only the
//! `clippy.toml` nearest each crate, so `crates/palisade-policy/clippy.toml`
//! replaces the root file for that crate. These tests check that it repeats
//! every root setting, that both files hold the bans #29 requires, and that
//! the MSRV matches `rust-version`. Tests only.

#[cfg(test)]
mod tests {
    use std::path::Path;

    use toml::{Table, Value};

    fn load(relative: &str) -> Table {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join(relative);
        std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
            .parse()
            .unwrap()
    }

    fn banned(config: &Table) -> Vec<String> {
        config["disallowed-methods"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| {
                let path = m["path"].as_str().unwrap();
                assert!(
                    m.get("reason").and_then(Value::as_str).is_some(),
                    "{path} has no reason"
                );
                path.to_owned()
            })
            .collect()
    }

    #[test]
    fn msrv_matches_rust_version() {
        let cargo = load("Cargo.toml");
        let rust_version = cargo["workspace"]["package"]["rust-version"]
            .as_str()
            .unwrap();
        for file in ["clippy.toml", "crates/palisade-policy/clippy.toml"] {
            assert_eq!(load(file)["msrv"].as_str(), Some(rust_version), "{file}");
        }
    }

    #[test]
    fn the_policy_config_repeats_the_root_one_and_adds_bans() {
        let root = load("clippy.toml");
        let policy = load("crates/palisade-policy/clippy.toml");
        for (key, value) in &root {
            if key == "disallowed-methods" {
                continue;
            }
            assert_eq!(
                policy.get(key),
                Some(value),
                "policy clippy.toml lacks {key}"
            );
        }
        let root_bans = banned(&root);
        let policy_bans = banned(&policy);
        for ban in &root_bans {
            assert!(policy_bans.contains(ban), "policy clippy.toml lacks {ban}");
        }
        assert!(root_bans.contains(&"std::time::SystemTime::now".to_owned()));
        assert!(policy_bans.contains(&"std::process::Command::new".to_owned()));
    }

    /// No other crate has its own `clippy.toml`, which would silently drop
    /// the root settings for it.
    #[test]
    fn only_the_policy_crate_overrides_the_root_config() {
        let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("../crates");
        for entry in std::fs::read_dir(&crates).unwrap() {
            let dir = entry.unwrap().path();
            let name = dir.file_name().unwrap().to_string_lossy().into_owned();
            for file in ["clippy.toml", ".clippy.toml"] {
                let exists = dir.join(file).exists();
                assert_eq!(
                    exists,
                    name == "palisade-policy" && file == "clippy.toml",
                    "{name}/{file}"
                );
            }
        }
        assert!(
            !Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("clippy.toml")
                .exists()
        );
    }
}
