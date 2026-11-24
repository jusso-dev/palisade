//! Observed facts about one object, as criteria see them (#31).
//!
//! The agent and the file-identity parser (#3, #4) compute facts. This
//! module only defines their shape, so evaluation stays pure: nothing here
//! reads a file or calls the OS. A fact that was not computed is absent,
//! and every criterion on an absent fact evaluates to
//! [`Tri::Unknown`](crate::ops::Tri::Unknown), never to a match.

use std::collections::BTreeMap;

use palisade_core::path::{NormalizedPath, VolumeMap, normalize_with};

use crate::model::{Field, FieldClass};

/// Every fact about one object that the criteria of this version can test.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ObjectFacts {
    /// Hash, version-resource and version facts, by field. Signer and path
    /// fields are not stored here; see [`Self::signers`] and [`Self::path`].
    values: BTreeMap<Field, String>,
    /// The object's path, if known.
    pub path: Option<PathFact>,
    /// Every signature on the object, embedded or from a catalog, if the
    /// signatures were examined. `Some(vec![])` means the object is known
    /// to be unsigned; `None` means nobody looked.
    pub signers: Option<Vec<SignerFact>>,
}

impl ObjectFacts {
    /// No facts at all.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records the value of a hash, version-resource or version field.
    /// Hash values are hex digits in either case.
    ///
    /// Returns `false`, and records nothing, for a path or signer field:
    /// those come from [`Self::path`] and [`Self::signers`].
    pub fn set(&mut self, field: Field, value: impl Into<String>) -> bool {
        if is_stored(field) {
            self.values.insert(field, value.into());
            true
        } else {
            false
        }
    }

    /// The same as [`Self::set`], for building facts in one expression.
    /// A path or signer field is ignored.
    #[must_use]
    pub fn with(mut self, field: Field, value: impl Into<String>) -> Self {
        self.set(field, value);
        self
    }

    /// The same facts, with the path set.
    #[must_use]
    pub fn with_path(mut self, path: PathFact) -> Self {
        self.path = Some(path);
        self
    }

    /// The same facts, with the signatures set. An empty list means the
    /// object is known to be unsigned.
    #[must_use]
    pub fn with_signers(mut self, signers: Vec<SignerFact>) -> Self {
        self.signers = Some(signers);
        self
    }

    /// The recorded value of a hash, version-resource or version field.
    #[must_use]
    pub fn get(&self, field: Field) -> Option<&str> {
        self.values.get(&field).map(String::as_str)
    }
}

/// Whether a field's fact is stored in [`ObjectFacts::set`]'s map.
const fn is_stored(field: Field) -> bool {
    !matches!(
        field,
        Field::SignerPublisher | Field::SignerIssuer | Field::SignerLeafThumbprint
    ) && !matches!(field.class(), FieldClass::Path | FieldClass::FileName)
}

/// The path of an object, normalised, with the facts that decide whether
/// the path can be trusted as an identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathFact {
    /// The final path, after symbolic links and junctions are resolved, with
    /// 8.3 short names expanded by the agent (#4).
    pub path: NormalizedPath,
    /// The same file under another name that rules may be written against:
    /// the UNC form of a path on a mapped network drive, or the drive form
    /// of a UNC path. Path criteria match if either form matches.
    pub alias: Option<NormalizedPath>,
    /// The agent could not expand an 8.3 short name in the path. Path
    /// criteria then evaluate to unknown, because the short name could be
    /// a spelling that a rule does not recognise.
    pub short_name_unresolved: bool,
    /// Whether any non-administrative principal can write the file or any
    /// directory above it, or change their permissions (#3, #4). `None`
    /// means it was not determined. A path only identifies an object
    /// when this is `Some(false)`.
    pub user_writable: Option<bool>,
}

impl PathFact {
    /// A path fact for `raw`, normalised with `volumes`. The ACL facts are
    /// unknown and the short name is taken as resolved.
    #[must_use]
    pub fn new(raw: &str, volumes: &VolumeMap) -> Self {
        Self {
            path: normalize_with(raw, volumes),
            alias: None,
            short_name_unresolved: false,
            user_writable: None,
        }
    }

    /// The same fact, with `user_writable` set.
    #[must_use]
    pub const fn with_user_writable(mut self, writable: bool) -> Self {
        self.user_writable = Some(writable);
        self
    }
}

/// One signature on an object, with the facts about its signer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignerFact {
    /// The result of verifying the signature and its chain.
    pub status: SignerStatus,
    /// Where the signature came from.
    pub source: SignatureSource,
    /// The common name of the leaf certificate's subject.
    pub publisher: Option<String>,
    /// The common name of the leaf certificate's issuer.
    pub issuer: Option<String>,
    /// The SHA-256 thumbprint of the leaf certificate, as hex.
    pub leaf_thumbprint_sha256: Option<String>,
}

/// The result of verifying one signature (#31, #48). An unsigned object
/// has no [`SignerFact`] at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SignerStatus {
    /// The signature and chain verify, and the certificate is in date.
    Valid,
    /// The certificate has expired, but a trusted timestamp shows that the
    /// signature was made while it was valid.
    ValidExpiredTimestamped,
    /// The signature verifies through a signed catalog.
    CatalogSigned,
    /// The certificate has expired, with no trusted timestamp.
    Expired,
    /// The certificate has been revoked.
    Revoked,
    /// The chain ends at a root that is not trusted.
    UntrustedRoot,
    /// The file's content does not match the signed digest.
    DigestMismatch,
}

impl SignerStatus {
    /// Whether the signer may vouch for an object's identity: the default
    /// accepted statuses of #31.
    #[must_use]
    pub const fn is_trusted(self) -> bool {
        matches!(
            self,
            Self::Valid | Self::ValidExpiredTimestamped | Self::CatalogSigned
        )
    }
}

/// Where a signature came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SignatureSource {
    /// Embedded in the file.
    Embedded,
    /// From a signed catalog that lists the file's hash.
    Catalog,
}

/// A path variable that a criterion value may start with, such as
/// `%PROGRAMFILES%` (#31).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PathVariable {
    /// `%WINDIR%`: the Windows directory.
    Windir,
    /// `%SYSTEM32%`: the native and the 32-bit system directories.
    System32,
    /// `%PROGRAMFILES%`: both program-files directories.
    ProgramFiles,
    /// `%PROGRAMDATA%`.
    ProgramData,
    /// `%OSDRIVE%`: the drive Windows is installed on.
    OsDrive,
    /// `%USERPROFILE%`, for the user the process runs as.
    UserProfile,
    /// `%APPDATA%`, for the user the process runs as.
    AppData,
    /// `%LOCALAPPDATA%`, for the user the process runs as.
    LocalAppData,
    /// `%TEMP%` or `%TMP%`, for the user the process runs as.
    Temp,
    /// `%PUBLIC%`: the shared user profile.
    Public,
}

impl PathVariable {
    /// Every variable.
    pub const ALL: [Self; 10] = [
        Self::Windir,
        Self::System32,
        Self::ProgramFiles,
        Self::ProgramData,
        Self::OsDrive,
        Self::UserProfile,
        Self::AppData,
        Self::LocalAppData,
        Self::Temp,
        Self::Public,
    ];

    /// The variable with this name, without the `%` signs, in any case.
    /// `TMP` is another name for `TEMP`.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        let upper = name.to_ascii_uppercase();
        Some(match upper.as_str() {
            "WINDIR" => Self::Windir,
            "SYSTEM32" => Self::System32,
            "PROGRAMFILES" => Self::ProgramFiles,
            "PROGRAMDATA" => Self::ProgramData,
            "OSDRIVE" => Self::OsDrive,
            "USERPROFILE" => Self::UserProfile,
            "APPDATA" => Self::AppData,
            "LOCALAPPDATA" => Self::LocalAppData,
            "TEMP" | "TMP" => Self::Temp,
            "PUBLIC" => Self::Public,
            _ => return None,
        })
    }
}

/// What each path variable expands to, for one evaluation. Per-user
/// variables hold the values for the user the process runs as.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PathVariables {
    values: BTreeMap<PathVariable, Vec<NormalizedPath>>,
}

impl PathVariables {
    /// No variables: every criterion that uses one evaluates to unknown.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets what `variable` expands to. A variable may have several values
    /// (`%PROGRAMFILES%` names both program-files directories), and a
    /// criterion matches if any of them matches. Values that are not drive
    /// or UNC paths, or that name a stream, are ignored, and an empty list
    /// unsets the variable.
    pub fn set(&mut self, variable: PathVariable, values: &[&str]) {
        let values: Vec<NormalizedPath> = values
            .iter()
            .map(|v| palisade_core::path::normalize(v))
            .filter(|p| p.is_resolved() && p.stream().is_none())
            .collect();
        if values.is_empty() {
            self.values.remove(&variable);
        } else {
            self.values.insert(variable, values);
        }
    }

    /// The same, for building variables in one expression.
    #[must_use]
    pub fn with(mut self, variable: PathVariable, values: &[&str]) -> Self {
        self.set(variable, values);
        self
    }

    /// What `variable` expands to; empty if it is not set.
    #[must_use]
    pub fn get(&self, variable: PathVariable) -> &[NormalizedPath] {
        self.values.get(&variable).map_or(&[], Vec::as_slice)
    }
}
