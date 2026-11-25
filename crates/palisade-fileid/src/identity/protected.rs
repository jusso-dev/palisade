//! The protected-binary and protected-vendor lists the masquerade
//! assessment checks against.
//!
//! Both are policy content: the server ships them in the signed, versioned
//! policy bundle (#43, #225), and the agent passes them in through
//! [`super::IdentityContext`]. [`ProtectedList::defaults`] is the built-in
//! list, used until a bundle provides one. It covers the interpreters and
//! proxy-execution binaries of the recommended user-mode blocklist, with
//! their expected locations and signer.
//!
//! An expected signer is never a name in the code. [`ExpectedSigner::OsVendor`]
//! means "a trusted signer whose chain ends at a root in the policy's
//! well-known OS root table" ([`crate::authenticode::TrustConfig`]), so the
//! defaults name no vendor. The protected-vendor list is empty by default
//! for the same reason; an organisation adds the vendors it relies on.

#![forbid(unsafe_code)]

use serde::Serialize;

use crate::fsctx::{PathVariable, fold_case};

use super::record::TrustedSigner;

/// The version of [`ProtectedList::defaults`]. Raised whenever the
/// built-in list changes.
pub const DEFAULT_LIST_VERSION: u32 = 1;

/// Who must have signed a protected binary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum ExpectedSigner {
    /// A trusted signer whose chain ends at a well-known OS root (the
    /// policy's well-known root table).
    OsVendor,
    /// A trusted signer whose chain reaches the trust anchor with this
    /// label.
    Anchor(String),
    /// A trusted signer with this publisher name, compared
    /// case-insensitively.
    Publisher(String),
}

impl ExpectedSigner {
    /// Whether `trust` holds what [`Self::matches`] needs: the well-known
    /// root table for [`Self::OsVendor`], the named anchor for
    /// [`Self::Anchor`]. Without it, a trusted signer cannot be told apart
    /// from the expected one.
    #[must_use]
    pub fn checkable(&self, trust: &crate::authenticode::TrustConfig) -> bool {
        match self {
            Self::OsVendor => !trust.well_known_roots().is_empty(),
            Self::Anchor(label) => trust.anchors().iter().any(|a| &a.label == label),
            Self::Publisher(_) => true,
        }
    }

    /// Whether `signer`, a trusted signer of the file, is this one.
    #[must_use]
    pub fn matches(&self, signer: &TrustedSigner) -> bool {
        match self {
            Self::OsVendor => signer.well_known_root_id.is_some(),
            Self::Anchor(label) => signer.anchored_to.as_deref() == Some(label.as_str()),
            Self::Publisher(name) => signer
                .publisher_name
                .as_deref()
                .is_some_and(|p| fold_case(p.trim()) == fold_case(name.trim())),
        }
    }
}

/// A folder a protected binary is expected in: a path variable and the
/// components below it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExpectedDir {
    /// The known folder, serialised as its token (`%SYSTEM32%`).
    #[serde(serialize_with = "serialize_variable")]
    pub variable: PathVariable,
    /// The folders below it, in order (empty for the folder itself).
    pub below: Vec<String>,
}

fn serialize_variable<S: serde::Serializer>(v: &PathVariable, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(v.token())
}

impl ExpectedDir {
    fn new(variable: PathVariable, below: &[&str]) -> Self {
        Self {
            variable,
            below: below.iter().map(|s| (*s).to_owned()).collect(),
        }
    }
}

/// One protected binary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProtectedBinary {
    /// The `OriginalFilename` values it carries, compared
    /// case-insensitively, with any `.mui` suffix dropped.
    pub original_names: Vec<String>,
    /// The on-disk names it is installed under. Any other name is a
    /// rename.
    pub file_names: Vec<String>,
    /// The folders it is installed in. Empty means its location is not
    /// checked.
    pub expected_dirs: Vec<ExpectedDir>,
    /// Who signs it.
    pub signer: ExpectedSigner,
}

/// A vendor whose name in a version resource must be backed by its
/// signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProtectedVendor {
    /// The names it appears under in `CompanyName` and `ProductName`.
    pub names: Vec<String>,
    /// Who signs its files.
    pub signer: ExpectedSigner,
}

/// The protected-binary and protected-vendor lists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProtectedList {
    /// The list's version, from the policy bundle.
    pub version: u32,
    /// The protected binaries.
    pub binaries: Vec<ProtectedBinary>,
    /// The protected vendors.
    pub vendors: Vec<ProtectedVendor>,
}

impl Default for ProtectedList {
    fn default() -> Self {
        Self::defaults()
    }
}

impl ProtectedList {
    /// An empty list: nothing is protected.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            version: 0,
            binaries: Vec::new(),
            vendors: Vec::new(),
        }
    }

    /// The built-in list (version [`DEFAULT_LIST_VERSION`]).
    ///
    /// Every binary here is an OS component signed by the OS vendor. The
    /// .NET Framework tools (`msbuild`, `installutil`, `regasm`,
    /// `regsvcs`) are installed under versioned folders, so only their
    /// names are checked; policy content can add their folders.
    #[must_use]
    pub fn defaults() -> Self {
        use PathVariable::{ProgramFiles, System32, WinDir};
        let os = |names: &[&str], dirs: Vec<ExpectedDir>| {
            let file_names: Vec<String> = names.iter().map(|s| (*s).to_owned()).collect();
            ProtectedBinary {
                original_names: file_names.clone(),
                file_names,
                expected_dirs: dirs,
                signer: ExpectedSigner::OsVendor,
            }
        };
        let sys32 = || vec![ExpectedDir::new(System32, &[])];
        let mut binaries = vec![
            os(
                &["powershell.exe"],
                vec![ExpectedDir::new(System32, &["WindowsPowerShell", "v1.0"])],
            ),
            os(
                &["powershell_ise.exe"],
                vec![ExpectedDir::new(System32, &["WindowsPowerShell", "v1.0"])],
            ),
            os(&["cmd.exe"], sys32()),
            os(&["cscript.exe"], sys32()),
            os(&["wscript.exe"], sys32()),
            os(&["mshta.exe"], sys32()),
            os(&["rundll32.exe"], sys32()),
            os(&["regsvr32.exe"], sys32()),
            os(&["certutil.exe"], sys32()),
            os(&["bitsadmin.exe"], sys32()),
            os(&["cmstp.exe"], sys32()),
            os(&["odbcconf.exe"], sys32()),
            os(&["forfiles.exe"], sys32()),
            os(&["wmic.exe"], vec![ExpectedDir::new(System32, &["wbem"])]),
            os(&["hh.exe"], vec![ExpectedDir::new(WinDir, &[])]),
            os(&["msbuild.exe"], Vec::new()),
            os(&["installutil.exe"], Vec::new()),
            os(&["regasm.exe"], Vec::new()),
            os(&["regsvcs.exe"], Vec::new()),
        ];
        // PowerShell 7 is installed separately; its `OriginalFilename` is
        // that of the managed entry point.
        binaries.push(ProtectedBinary {
            original_names: vec!["pwsh.dll".to_owned(), "pwsh.exe".to_owned()],
            file_names: vec!["pwsh.exe".to_owned()],
            expected_dirs: vec![ExpectedDir::new(ProgramFiles, &["PowerShell", "7"])],
            signer: ExpectedSigner::OsVendor,
        });
        Self {
            version: DEFAULT_LIST_VERSION,
            binaries,
            vendors: Vec::new(),
        }
    }

    /// The protected binaries whose original names include `original`
    /// (compared case-insensitively, with a `.mui` suffix dropped).
    pub fn binaries_named<'a>(
        &'a self,
        original: &str,
    ) -> impl Iterator<Item = &'a ProtectedBinary> + 'a {
        let key = original_name_key(original);
        self.binaries
            .iter()
            .filter(move |b| b.original_names.iter().any(|n| original_name_key(n) == key))
    }
}

/// An `OriginalFilename` for comparison: trimmed, case-folded, with a
/// trailing `.mui` (the resource-only satellite's name) dropped.
pub(crate) fn original_name_key(name: &str) -> String {
    let folded = fold_case(name.trim());
    folded
        .strip_suffix(".MUI")
        .map(str::to_owned)
        .unwrap_or(folded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_cover_the_blocklist_interpreters() {
        let list = ProtectedList::defaults();
        for name in [
            "PowerShell.EXE",
            "pwsh.dll",
            "Cmd.Exe",
            "cscript.exe",
            "wscript.exe",
            "MSHTA.EXE",
            "RUNDLL32.EXE",
            "REGSVR32.EXE",
            "MSBuild.exe",
            "InstallUtil.exe",
            "CertUtil.exe",
            "bitsadmin.exe",
            "wmic.exe",
            "powershell.exe.mui",
        ] {
            assert_eq!(list.binaries_named(name).count(), 1, "{name}");
        }
        assert_eq!(list.binaries_named("notepad.exe").count(), 0);
        assert!(list.vendors.is_empty());
        assert!(
            list.binaries
                .iter()
                .all(|b| b.signer == ExpectedSigner::OsVendor)
        );
    }
}
