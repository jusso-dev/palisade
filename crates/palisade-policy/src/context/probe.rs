//! Probed context: environment variables, the registry and the file system
//! (#33, #329).
//!
//! `env.var`, `reg.key`, `reg.value`, `fs.file` and `fs.folder` criteria
//! name a `target` to look at. The agent collects what the policy's
//! criteria name ([`probe_targets`]) into a [`Probes`] table before the
//! decision: evaluation never reads the system. Every lookup is keyed by the
//! canonical target ([`canonical_target`]), so the agent and the evaluator
//! agree on what one target is.
//!
//! A target the agent did not look at is absent from the table, and every
//! criterion on it is `Unknown`, negations included. A target it looked at
//! and found missing is [`Probe::Absent`]: then `exists` is `NoMatch`,
//! `not_exists` is `Match`, and every comparison is `NoMatch` (there is
//! nothing to compare), so `not_equals` on an absent value is `Match`.
//!
//! # User-controlled context
//!
//! A user sets their own environment, writes their own registry hives
//! (`HKCU`, `HKU`, and `HKCR`, which merges the user's classes over the
//! machine's) and creates or deletes files wherever they can write. A
//! policy cannot see which locations those are, so every `env.*` and
//! `fs.*` criterion, and every `reg.*` criterion outside the machine hive,
//! is user-controlled ([`is_user_controlled`]). Validation keeps such a
//! criterion from being the reason an allow matches (`user_controlled_context`),
//! and the decision trace marks every rule that read one.

use std::collections::BTreeMap;

use crate::model::{Criterion, Field, Match};

/// What the agent found at one target.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Probe {
    /// The agent looked, and nothing is there.
    Absent,
    /// A registry key, a file or a folder is there.
    Present,
    /// An environment variable or a text registry value
    /// (`REG_SZ`, `REG_EXPAND_SZ` unexpanded, or `REG_MULTI_SZ` joined with
    /// a line feed).
    Text(String),
    /// A `REG_DWORD` or `REG_QWORD` registry value.
    Number(u64),
    /// A value of another type, such as `REG_BINARY`: it exists, but no
    /// comparison applies, so each is `Unknown`.
    Other,
}

/// The probed facts of one evaluation, by field and canonical target.
///
/// Keyed by one string per target ([`probe_key`]), so a compiled criterion
/// looks its probe up without allocating.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Probes {
    entries: BTreeMap<String, Probe>,
}

impl Probes {
    /// No probes: every probed criterion is unknown.
    pub const EMPTY: Self = Self {
        entries: BTreeMap::new(),
    };

    /// Records what the agent found. `value_name` is only for
    /// `reg.value`; `None` is the key's default value. Returns `false`, and
    /// records nothing, if `field` is not a probed field or `target` is not
    /// a valid target for it.
    pub fn insert(
        &mut self,
        field: Field,
        target: &str,
        value_name: Option<&str>,
        probe: Probe,
    ) -> bool {
        match probe_key(field, target, value_name) {
            Some(k) => {
                self.entries.insert(k, probe);
                true
            }
            None => false,
        }
    }

    /// Records what the agent found, and returns the table.
    #[must_use]
    pub fn with(
        mut self,
        field: Field,
        target: &str,
        value_name: Option<&str>,
        probe: Probe,
    ) -> Self {
        self.insert(field, target, value_name, probe);
        self
    }

    /// What the agent found at a target, or `None` if it did not look.
    #[must_use]
    pub fn get(&self, field: Field, target: &str, value_name: Option<&str>) -> Option<&Probe> {
        self.entries.get(&probe_key(field, target, value_name)?)
    }

    /// What the agent found at the target with this [`probe_key`].
    pub(crate) fn get_by_key(&self, key: &str) -> Option<&Probe> {
        self.entries.get(key)
    }

    /// Whether the table is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Every entry, in key order, for hashing.
    pub(crate) fn iter(&self) -> impl Iterator<Item = (&String, &Probe)> {
        self.entries.iter()
    }
}

/// The canonical parts of a probe: its field, target and, for
/// `reg.value`, its lowercase value name.
fn parts(
    field: Field,
    target: &str,
    value_name: Option<&str>,
) -> Option<(Field, String, Option<String>)> {
    if !field.is_probe() {
        return None;
    }
    let target = canonical_target(field, target).ok()?;
    let name = if field == Field::RegValue {
        value_name.map(str::to_lowercase)
    } else {
        None
    };
    Some((field, target, name))
}

/// The key of one probe in a [`Probes`] table: the field's name, the
/// canonical target and the value name, separated by NUL characters, which
/// none of them holds. `None` if the target is not valid for the field.
#[must_use]
pub fn probe_key(field: Field, target: &str, value_name: Option<&str>) -> Option<String> {
    let (field, target, name) = parts(field, target, value_name)?;
    let tag = match field {
        Field::EnvVar => "env.var",
        Field::RegKey => "reg.key",
        Field::RegValue => "reg.value",
        Field::FsFile => "fs.file",
        _ => "fs.folder",
    };
    Some(match name {
        Some(n) => format!("{tag}\0{target}\0={n}"),
        None => format!("{tag}\0{target}\0"),
    })
}

/// One thing a policy probes, as the agent collects it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProbeTarget {
    /// The field: `env.var`, `reg.key`, `reg.value`, `fs.file` or
    /// `fs.folder`.
    pub field: Field,
    /// The canonical target ([`canonical_target`]).
    pub target: String,
    /// For `reg.value`, the value's name, lowercase; `None` is the
    /// default value.
    pub value_name: Option<String>,
}

/// Every target the criteria of `trees` probe, each once, in order. The
/// agent collects these before a decision. A criterion whose target is not
/// valid is left out; validation rejects it.
#[must_use]
pub fn probe_targets<'t>(trees: impl IntoIterator<Item = &'t Match>) -> Vec<ProbeTarget> {
    let mut out = std::collections::BTreeSet::new();
    for tree in trees {
        let mut stack = vec![tree];
        while let Some(node) = stack.pop() {
            stack.extend(node.children());
            if let Match::Criterion(c) = node
                && let Some((field, target, value_name)) = c
                    .target
                    .as_deref()
                    .and_then(|t| parts(c.field, t, c.value_name.as_deref()))
            {
                out.insert(ProbeTarget {
                    field,
                    target,
                    value_name,
                });
            }
        }
    }
    out.into_iter().collect()
}

/// The registry hives a target may start with, long name first, each with
/// its short form and whether a user controls it.
const HIVES: [(&str, &str, bool); 4] = [
    ("HKEY_LOCAL_MACHINE", "HKLM", false),
    ("HKEY_CURRENT_USER", "HKCU", true),
    ("HKEY_USERS", "HKU", true),
    ("HKEY_CLASSES_ROOT", "HKCR", true),
];

/// The canonical form of a target for `field`:
///
/// - an environment variable: its name, uppercase (Windows names are
///   case-insensitive), 1 to 255 characters without `=` or a NUL;
/// - a registry key: the short hive (`HKLM`, `HKCU`, `HKU`, `HKCR`), then
///   each subkey after one `\`, lowercase, with no empty subkey;
/// - a file or folder: the normalised drive or UNC path, with no wildcard,
///   variable or alternate data stream.
///
/// # Errors
///
/// Returns why the target is not valid for the field.
pub fn canonical_target(field: Field, target: &str) -> Result<String, String> {
    if target.len() > crate::model::limits::MAX_VALUE_BYTES {
        return Err(format!(
            "a target is at most {} bytes",
            crate::model::limits::MAX_VALUE_BYTES
        ));
    }
    match field {
        Field::EnvVar => {
            if target.is_empty() || target.chars().count() > 255 {
                return Err("an environment variable's name is 1 to 255 characters".to_owned());
            }
            if target.contains(['=', '\0']) || target.chars().any(char::is_control) {
                return Err(
                    "an environment variable's name has no `=` or control characters".to_owned(),
                );
            }
            Ok(target.to_uppercase())
        }
        Field::RegKey | Field::RegValue => {
            let mut parts = target.split('\\');
            let hive = parts.next().unwrap_or_default();
            let Some((_, short, _)) = HIVES.iter().find(|(long, short, _)| {
                hive.eq_ignore_ascii_case(long) || hive.eq_ignore_ascii_case(short)
            }) else {
                return Err(
                    "a registry key starts with `HKLM`, `HKCU`, `HKU` or `HKCR` (or the long hive names)"
                        .to_owned(),
                );
            };
            let mut out = (*short).to_owned();
            for part in parts {
                if part.is_empty() || part.chars().any(char::is_control) {
                    return Err(
                        "a registry key has no empty subkey and no control characters".to_owned(),
                    );
                }
                out.push('\\');
                out.push_str(&part.to_lowercase());
            }
            Ok(out)
        }
        Field::FsFile | Field::FsFolder => {
            if target.contains(['*', '?', '%']) {
                return Err(
                    "a file-system target is a literal drive or UNC path, with no wildcard or variable"
                        .to_owned(),
                );
            }
            let p = palisade_core::path::normalize(target);
            if !p.is_resolved() || p.stream().is_some() {
                return Err(
                    "a file-system target is a drive or UNC path, such as `C:\\\\Tools\\\\flag.txt`, with no stream"
                        .to_owned(),
                );
            }
            Ok(crate::ops::fold(p.as_str(), false))
        }
        _ => Err("this field takes no `target`".to_owned()),
    }
}

/// Whether a criterion reads context a user controls (#33, #329): every
/// `env.*` and `fs.*` criterion, and a `reg.*` criterion outside `HKLM`.
#[must_use]
pub fn is_user_controlled(c: &Criterion) -> bool {
    match c.field {
        Field::EnvVar | Field::FsFile | Field::FsFolder => true,
        Field::RegKey | Field::RegValue => {
            let hive = c
                .target
                .as_deref()
                .and_then(|t| t.split('\\').next())
                .unwrap_or_default();
            // An unreadable hive is rejected by validation; until then it
            // counts as user-controlled.
            HIVES
                .iter()
                .find(|(long, short, _)| {
                    hive.eq_ignore_ascii_case(long) || hive.eq_ignore_ascii_case(short)
                })
                .is_none_or(|(_, _, user)| *user)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests;
