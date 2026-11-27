//! `cargo xtask check-deps`: the allowed dependency directions between crates.
//!
//! The layering is `core` <- `fileid` <- `policy` <- `proto` <- {`agent`,
//! `server`, `cli`, `tray`}. `console` may use only `proto`, and `driver` may
//! use only `core` without its `std` feature. Every workspace crate must have
//! an entry in [`ALLOWED`], so a new crate cannot skip the rules. Crates in
//! [`NO_THIRD_PARTY`] may have no third-party dependencies of any kind.
//!
//! Workspace edges are checked for every dependency kind (normal, build and
//! dev). The banned third-party crates in [`BANNED`] are checked over the
//! whole transitive graph of normal dependencies, for every target platform.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

/// For each workspace crate, the workspace crates it may depend on directly.
const ALLOWED: &[(&str, &[&str])] = &[
    ("palisade-core", &[]),
    ("palisade-fileid", &["palisade-core"]),
    ("palisade-policy", &["palisade-core", "palisade-fileid"]),
    (
        "palisade-proto",
        &["palisade-core", "palisade-fileid", "palisade-policy"],
    ),
    ("palisade-agent", PROTO_USERS),
    ("palisade-server", PROTO_USERS),
    ("palisade-cli", PROTO_USERS),
    ("palisade-tray", PROTO_USERS),
    ("palisade-console", &["palisade-proto"]),
    ("palisade-driver", &["palisade-core"]),
    ("xtask", &[]),
];

/// The workspace crates and the crates each may depend on, in layering
/// order. The docs crate map is generated from this.
pub fn allowed_rules() -> &'static [(&'static str, &'static [&'static str])] {
    ALLOWED
}

const PROTO_USERS: &[&str] = &[
    "palisade-core",
    "palisade-fileid",
    "palisade-policy",
    "palisade-proto",
];

/// Workspace crates that may not depend on any third-party crate (any kind).
/// The kernel driver's trusted computing base is kept to workspace code.
const NO_THIRD_PARTY: &[&str] = &["palisade-driver"];

/// Crates that must never appear anywhere in a workspace crate's runtime
/// dependency tree, with the reason.
const BANNED: &[(&str, &[&str], &str)] = &[
    (
        "palisade-policy",
        &["tokio", "reqwest", "windows", "windows-sys"],
        "policy evaluation must stay pure, portable and free of I/O",
    ),
    (
        "palisade-agent",
        &[
            "palisade-server",
            "axum",
            "actix-web",
            "warp",
            "rocket",
            "poem",
            "tide",
            "sqlx",
            "diesel",
            "tokio-postgres",
        ],
        "the privileged agent must not carry a server or database stack",
    ),
];

/// Checks parsed `cargo metadata --format-version 1` output (with the
/// resolve graph). Returns one message per violation.
pub fn check(metadata: &Value) -> Result<Vec<String>, String> {
    let graph = Graph::parse(metadata)?;
    let mut violations = Vec::new();

    for (id, name) in &graph.members {
        let Some(allowed) = lookup(ALLOWED, name) else {
            violations.push(format!(
                "{name} has no entry in the dependency rules (xtask/src/deps.rs); add one"
            ));
            continue;
        };
        for (dep_id, kinds) in graph.deps.get(id).into_iter().flatten() {
            let Some(dep_name) = graph.members.get(dep_id) else {
                if NO_THIRD_PARTY.contains(&name.as_str()) {
                    violations.push(format!(
                        "{name} must not depend on third-party crate {} ({kinds} dependency)",
                        graph.name(dep_id)
                    ));
                }
                continue;
            };
            if !allowed.contains(&dep_name.as_str()) {
                violations.push(format!(
                    "{name} must not depend on {dep_name} ({kinds} dependency)"
                ));
            }
        }
    }

    for (crate_name, banned, reason) in BANNED {
        let Some(id) = graph.member_id(crate_name) else {
            continue;
        };
        for (path_ids, dep_name) in graph.runtime_closure(id) {
            if banned.contains(&dep_name.as_str()) {
                let path: Vec<&str> = path_ids.iter().map(|i| graph.name(i)).collect();
                violations.push(format!(
                    "{crate_name} must not depend on {dep_name}: {reason} (via {})",
                    path.join(" -> ")
                ));
            }
        }
    }

    violations.extend(check_driver_core_features(metadata)?);
    Ok(violations)
}

/// The driver is `no_std`, so its `palisade-core` dependency must not turn on
/// the `std` feature, directly or through default features.
fn check_driver_core_features(metadata: &Value) -> Result<Vec<String>, String> {
    let packages = array(metadata, "packages")?;
    let Some(driver) = packages.iter().find(|p| p["name"] == "palisade-driver") else {
        return Ok(Vec::new());
    };
    let mut violations = Vec::new();
    for dep in array(driver, "dependencies")? {
        if dep["name"] != "palisade-core" {
            continue;
        }
        let defaults = dep["uses_default_features"].as_bool().unwrap_or(true);
        let std_feature = dep["features"]
            .as_array()
            .is_some_and(|f| f.iter().any(|x| x == "std"));
        if defaults || std_feature {
            violations.push(
                "palisade-driver must use palisade-core with default-features = false and without the std feature"
                    .to_owned(),
            );
        }
    }
    Ok(violations)
}

/// Paths of every workspace member's `Cargo.toml`.
pub fn member_manifest_paths(metadata: &Value) -> Result<Vec<String>, String> {
    let members: BTreeSet<&str> = array(metadata, "workspace_members")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let mut paths = Vec::new();
    for package in array(metadata, "packages")? {
        if package["id"]
            .as_str()
            .is_some_and(|id| members.contains(id))
        {
            let path = package["manifest_path"]
                .as_str()
                .ok_or("package without manifest_path in cargo metadata")?;
            paths.push(path.to_owned());
        }
    }
    Ok(paths)
}

/// `(crate name, target kind, source path)` of every library, binary and
/// proc-macro target of the workspace members.
pub fn member_targets(metadata: &Value) -> Result<Vec<(String, String, String)>, String> {
    let members: BTreeSet<&str> = array(metadata, "workspace_members")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let mut targets = Vec::new();
    for package in array(metadata, "packages")? {
        if !package["id"]
            .as_str()
            .is_some_and(|id| members.contains(id))
        {
            continue;
        }
        let name = package["name"]
            .as_str()
            .ok_or("package without name in cargo metadata")?;
        for target in array(package, "targets")? {
            let kinds: Vec<&str> = array(target, "kind")?
                .iter()
                .filter_map(Value::as_str)
                .collect();
            let Some(kind) = kinds.iter().find(|k| {
                matches!(
                    **k,
                    "lib" | "rlib" | "dylib" | "cdylib" | "staticlib" | "bin" | "proc-macro"
                )
            }) else {
                continue;
            };
            let src_path = target["src_path"]
                .as_str()
                .ok_or("target without src_path in cargo metadata")?;
            targets.push((name.to_owned(), (*kind).to_owned(), src_path.to_owned()));
        }
    }
    Ok(targets)
}

/// For each workspace crate, how many distinct third-party crates its
/// normal (runtime) dependency tree reaches, on every platform.
pub fn runtime_third_party_counts(metadata: &Value) -> Result<Vec<(String, usize)>, String> {
    let graph = Graph::parse(metadata)?;
    let mut counts = Vec::new();
    for (id, name) in &graph.members {
        let reached: BTreeSet<String> = graph
            .runtime_closure(id)
            .into_iter()
            .filter_map(|(path, _)| path.last().cloned())
            .filter(|dep| !graph.members.contains_key(dep))
            .map(|dep| graph.name(&dep).to_owned())
            .collect();
        counts.push((name.clone(), reached.len()));
    }
    counts.sort();
    Ok(counts)
}

fn lookup<T: Copy>(table: &[(&str, T)], name: &str) -> Option<T> {
    table.iter().find(|(n, _)| *n == name).map(|(_, v)| *v)
}

fn array<'a>(value: &'a Value, key: &str) -> Result<&'a Vec<Value>, String> {
    value[key]
        .as_array()
        .ok_or_else(|| format!("cargo metadata: missing array `{key}`"))
}

/// The resolved dependency graph, keyed by package ID.
struct Graph {
    /// Workspace member ID to crate name.
    members: BTreeMap<String, String>,
    /// Every package ID to crate name.
    names: BTreeMap<String, String>,
    /// Package ID to (dependency ID, dependency kinds such as "normal, dev").
    deps: BTreeMap<String, Vec<(String, String)>>,
}

impl Graph {
    fn parse(metadata: &Value) -> Result<Self, String> {
        let names: BTreeMap<String, String> = array(metadata, "packages")?
            .iter()
            .filter_map(|p| Some((p["id"].as_str()?.to_owned(), p["name"].as_str()?.to_owned())))
            .collect();
        let mut members = BTreeMap::new();
        for id in array(metadata, "workspace_members")? {
            let id = id
                .as_str()
                .ok_or("cargo metadata: non-string workspace member")?;
            let name = names
                .get(id)
                .ok_or_else(|| format!("cargo metadata: unknown member {id}"))?;
            members.insert(id.to_owned(), name.clone());
        }
        let resolve = &metadata["resolve"];
        if resolve.is_null() {
            return Err("cargo metadata has no resolve graph (do not pass --no-deps)".to_owned());
        }
        let mut deps = BTreeMap::new();
        for node in array(resolve, "nodes")? {
            let id = node["id"]
                .as_str()
                .ok_or("cargo metadata: node without id")?;
            let mut edges = Vec::new();
            for dep in array(node, "deps")? {
                let dep_id = dep["pkg"]
                    .as_str()
                    .ok_or("cargo metadata: dependency without pkg")?;
                let kinds: Vec<&str> = array(dep, "dep_kinds")?
                    .iter()
                    .map(|k| k["kind"].as_str().unwrap_or("normal"))
                    .collect();
                edges.push((dep_id.to_owned(), kinds.join(", ")));
            }
            deps.insert(id.to_owned(), edges);
        }
        Ok(Self {
            members,
            names,
            deps,
        })
    }

    fn member_id(&self, name: &str) -> Option<&String> {
        self.members
            .iter()
            .find(|(_, n)| *n == name)
            .map(|(id, _)| id)
    }

    fn name<'a>(&'a self, id: &'a str) -> &'a str {
        self.names.get(id).map_or(id, String::as_str)
    }

    /// Every package reachable from `root` through normal (runtime)
    /// dependencies, with the path that first reached it.
    fn runtime_closure(&self, root: &str) -> Vec<(Vec<String>, String)> {
        let mut seen = BTreeSet::from([root.to_owned()]);
        let mut queue = vec![vec![root.to_owned()]];
        let mut reached = Vec::new();
        while let Some(path) = queue.pop() {
            let Some(current) = path.last() else { continue };
            for (dep_id, kinds) in self.deps.get(current).into_iter().flatten() {
                let runtime = kinds.split(", ").any(|k| k == "normal");
                if runtime && seen.insert(dep_id.clone()) {
                    let mut next = path.clone();
                    next.push(dep_id.clone());
                    reached.push((next.clone(), self.name(dep_id).to_owned()));
                    queue.push(next);
                }
            }
        }
        reached
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::check;

    /// One package in a fixture: (name, is workspace member, deps as (name, kind)).
    type Pkg<'a> = (&'a str, bool, &'a [(&'a str, &'a str)]);

    /// Builds a minimal `cargo metadata` document. Kind "normal" is encoded as
    /// `null`, as cargo does.
    fn metadata(packages: &[Pkg<'_>]) -> Value {
        let id = |name: &str| format!("id#{name}");
        let pkgs: Vec<Value> = packages
            .iter()
            .map(|(name, _, deps)| {
                let declared: Vec<Value> = deps
                    .iter()
                    .map(|(d, _)| json!({"name": d, "uses_default_features": false, "features": []}))
                    .collect();
                json!({"id": id(name), "name": name, "manifest_path": format!("/{name}/Cargo.toml"), "dependencies": declared})
            })
            .collect();
        let members: Vec<String> = packages.iter().filter(|p| p.1).map(|p| id(p.0)).collect();
        let nodes: Vec<Value> = packages
            .iter()
            .map(|(name, _, deps)| {
                let edges: Vec<Value> = deps
                    .iter()
                    .map(|(d, kind)| {
                        let kind = if *kind == "normal" {
                            Value::Null
                        } else {
                            json!(kind)
                        };
                        json!({"pkg": id(d), "dep_kinds": [{"kind": kind, "target": null}]})
                    })
                    .collect();
                json!({"id": id(name), "deps": edges})
            })
            .collect();
        json!({"packages": pkgs, "workspace_members": members, "resolve": {"nodes": nodes}})
    }

    /// The real layering, which must pass.
    fn good() -> Vec<Pkg<'static>> {
        vec![
            ("palisade-core", true, &[]),
            ("palisade-fileid", true, &[("palisade-core", "normal")]),
            (
                "palisade-policy",
                true,
                &[("palisade-core", "normal"), ("palisade-fileid", "normal")],
            ),
            ("palisade-proto", true, &[("palisade-policy", "normal")]),
            (
                "palisade-agent",
                true,
                &[("palisade-proto", "normal"), ("palisade-core", "normal")],
            ),
            ("palisade-console", true, &[("palisade-proto", "normal")]),
            ("palisade-driver", true, &[("palisade-core", "normal")]),
            ("xtask", true, &[("serde_json", "normal")]),
            ("serde_json", false, &[]),
        ]
    }

    fn with(
        mut pkgs: Vec<Pkg<'static>>,
        name: &str,
        deps: &'static [(&'static str, &'static str)],
    ) -> Vec<Pkg<'static>> {
        for p in &mut pkgs {
            if p.0 == name {
                p.2 = deps;
            }
        }
        pkgs
    }

    #[test]
    fn real_layering_passes() {
        assert_eq!(check(&metadata(&good())).unwrap(), Vec::<String>::new());
    }

    #[test]
    fn upward_edge_fails() {
        let pkgs = with(good(), "palisade-core", &[("palisade-policy", "normal")]);
        let v = check(&metadata(&pkgs)).unwrap();
        assert_eq!(
            v,
            ["palisade-core must not depend on palisade-policy (normal dependency)"]
        );
    }

    #[test]
    fn dev_dependency_edges_are_checked_too() {
        let pkgs = with(good(), "palisade-policy", &[("palisade-proto", "dev")]);
        let v = check(&metadata(&pkgs)).unwrap();
        assert_eq!(
            v,
            ["palisade-policy must not depend on palisade-proto (dev dependency)"]
        );
    }

    #[test]
    fn console_may_use_only_proto() {
        let pkgs = with(good(), "palisade-console", &[("palisade-core", "normal")]);
        assert_eq!(check(&metadata(&pkgs)).unwrap().len(), 1);
    }

    #[test]
    fn crate_without_rules_fails() {
        let mut pkgs = good();
        pkgs.push(("palisade-new", true, &[]));
        let v = check(&metadata(&pkgs)).unwrap();
        assert_eq!(v.len(), 1);
        assert!(v[0].starts_with("palisade-new has no entry"), "{v:?}");
    }

    #[test]
    fn policy_depending_on_tokio_fails() {
        let mut pkgs = with(
            good(),
            "palisade-policy",
            &[("palisade-core", "normal"), ("tokio", "normal")],
        );
        pkgs.push(("tokio", false, &[]));
        let v = check(&metadata(&pkgs)).unwrap();
        assert_eq!(v.len(), 1);
        assert!(
            v[0].starts_with("palisade-policy must not depend on tokio"),
            "{v:?}"
        );
    }

    #[test]
    fn banned_crate_is_found_transitively_with_its_path() {
        let mut pkgs = with(good(), "palisade-policy", &[("helper", "normal")]);
        pkgs.push(("helper", false, &[("windows-sys", "normal")]));
        pkgs.push(("windows-sys", false, &[]));
        let v = check(&metadata(&pkgs)).unwrap();
        assert_eq!(v.len(), 1);
        assert!(
            v[0].ends_with("(via palisade-policy -> helper -> windows-sys)"),
            "{v:?}"
        );
    }

    #[test]
    fn banned_crate_as_dev_dependency_is_allowed() {
        let mut pkgs = with(good(), "palisade-policy", &[("tokio", "dev")]);
        pkgs.push(("tokio", false, &[]));
        assert_eq!(check(&metadata(&pkgs)).unwrap(), Vec::<String>::new());
    }

    #[test]
    fn agent_must_not_reach_a_server_stack() {
        let mut pkgs = with(
            good(),
            "palisade-agent",
            &[("palisade-proto", "normal"), ("axum", "normal")],
        );
        pkgs.push(("axum", false, &[]));
        let v = check(&metadata(&pkgs)).unwrap();
        assert_eq!(v.len(), 1);
        assert!(
            v[0].starts_with("palisade-agent must not depend on axum"),
            "{v:?}"
        );
    }

    #[test]
    fn driver_must_not_enable_core_std() {
        let mut doc = metadata(&good());
        let packages = doc["packages"].as_array_mut().unwrap();
        let driver = packages
            .iter_mut()
            .find(|p| p["name"] == "palisade-driver")
            .unwrap();
        driver["dependencies"][0]["uses_default_features"] = json!(true);
        let v = check(&doc).unwrap();
        assert_eq!(v.len(), 1);
        assert!(
            v[0].starts_with(
                "palisade-driver must use palisade-core with default-features = false"
            )
        );
    }

    #[test]
    fn driver_must_not_enable_core_std_feature_explicitly() {
        let mut doc = metadata(&good());
        let packages = doc["packages"].as_array_mut().unwrap();
        let driver = packages
            .iter_mut()
            .find(|p| p["name"] == "palisade-driver")
            .unwrap();
        driver["dependencies"][0]["features"] = json!(["std"]);
        assert_eq!(check(&doc).unwrap().len(), 1);
    }

    #[test]
    fn driver_must_not_have_third_party_dependencies() {
        let mut pkgs = with(
            good(),
            "palisade-driver",
            &[("palisade-core", "normal"), ("tiny-nostd", "build")],
        );
        pkgs.push(("tiny-nostd", false, &[]));
        let v = check(&metadata(&pkgs)).unwrap();
        assert_eq!(
            v,
            ["palisade-driver must not depend on third-party crate tiny-nostd (build dependency)"]
        );
    }

    #[test]
    fn member_targets_lists_lib_bin_and_proc_macro_roots_of_members_only() {
        let doc = json!({
            "workspace_members": ["id#a"],
            "packages": [
                {"id": "id#a", "name": "a", "targets": [
                    {"kind": ["lib"], "src_path": "/a/src/lib.rs"},
                    {"kind": ["bin"], "src_path": "/a/src/main.rs"},
                    {"kind": ["test"], "src_path": "/a/tests/t.rs"},
                    {"kind": ["custom-build"], "src_path": "/a/build.rs"},
                ]},
                {"id": "id#dep", "name": "dep", "targets": [
                    {"kind": ["proc-macro"], "src_path": "/dep/src/lib.rs"},
                ]},
            ],
        });
        assert_eq!(
            super::member_targets(&doc).unwrap(),
            [
                ("a".to_owned(), "lib".to_owned(), "/a/src/lib.rs".to_owned()),
                (
                    "a".to_owned(),
                    "bin".to_owned(),
                    "/a/src/main.rs".to_owned()
                ),
            ]
        );
    }

    #[test]
    fn runtime_third_party_counts_follow_normal_edges_only() {
        let mut pkgs = with(
            good(),
            "palisade-policy",
            &[
                ("palisade-core", "normal"),
                ("helper", "normal"),
                ("tool", "dev"),
            ],
        );
        pkgs.push(("helper", false, &[("leaf", "normal")]));
        pkgs.push(("leaf", false, &[]));
        pkgs.push(("tool", false, &[]));
        let counts = super::runtime_third_party_counts(&metadata(&pkgs)).unwrap();
        let policy = counts.iter().find(|(n, _)| n == "palisade-policy").unwrap();
        assert_eq!(policy.1, 2);
        let core = counts.iter().find(|(n, _)| n == "palisade-core").unwrap();
        assert_eq!(core.1, 0);
    }

    #[test]
    fn metadata_without_resolve_is_an_error() {
        let mut doc = metadata(&good());
        doc["resolve"] = Value::Null;
        assert!(check(&doc).is_err());
    }
}
