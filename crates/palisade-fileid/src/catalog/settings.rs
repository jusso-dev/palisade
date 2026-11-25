//! Catalog lookup settings (#51): whether lookups run, which sources they
//! use, and which paths they skip.

#![forbid(unsafe_code)]

use super::store::CatalogSource;
use crate::fsctx::NormalizedPath;

/// Which catalog sources a lookup uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum CatalogScope {
    /// The OS catalog store only.
    System,
    /// The OS catalog store and the driver store.
    SystemAndDriverStore,
    /// Both, and catalogs delivered with policy (the default).
    #[default]
    All,
}

impl CatalogScope {
    /// The sources this scope covers.
    #[must_use]
    pub const fn sources(self) -> &'static [CatalogSource] {
        match self {
            Self::System => &[CatalogSource::System],
            Self::SystemAndDriverStore => &[CatalogSource::System, CatalogSource::DriverStore],
            Self::All => &[
                CatalogSource::System,
                CatalogSource::DriverStore,
                CatalogSource::Policy,
            ],
        }
    }
}

/// The catalog lookup settings, from policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogSettings {
    /// Whether catalog lookups run at all. Default `true`.
    pub catalog_lookup_enabled: bool,
    /// Which sources a lookup uses. Default [`CatalogScope::All`].
    pub catalog_scope: CatalogScope,
    /// Paths under which no lookup runs, for performance (normalised, so a
    /// path cannot dodge an entry by being spelt differently). A skipped
    /// lookup is reported as [`LookupSkipped::PathExcluded`], to be logged:
    /// the file is then judged without catalog signatures, never as
    /// catalog-signed.
    pub skip_catalog_for_paths: Vec<NormalizedPath>,
}

impl Default for CatalogSettings {
    fn default() -> Self {
        Self {
            catalog_lookup_enabled: true,
            catalog_scope: CatalogScope::All,
            skip_catalog_for_paths: Vec::new(),
        }
    }
}

/// Why a lookup did not run.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum LookupSkipped {
    /// [`CatalogSettings::catalog_lookup_enabled`] is off.
    Disabled,
    /// The file is under this [`CatalogSettings::skip_catalog_for_paths`]
    /// entry (its index).
    PathExcluded(usize),
}

/// The outcome of a lookup under [`CatalogSettings`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CatalogLookup<T> {
    /// The lookup ran.
    Done(T),
    /// The lookup did not run; the file is judged without catalogs.
    Skipped(LookupSkipped),
    /// The index is still being built and holds no match: whether a
    /// catalog lists the file is not known yet. Policy must treat this as
    /// indeterminate, never as "not catalog-signed" (#51, E02).
    Indeterminate,
}

impl<T> CatalogLookup<T> {
    /// The result, if the lookup ran and gave one.
    pub fn done(self) -> Option<T> {
        match self {
            Self::Done(t) => Some(t),
            _ => None,
        }
    }
}

impl CatalogSettings {
    /// Why a lookup for a file at `path` would not run, if it would not.
    /// With no path, only [`Self::catalog_lookup_enabled`] applies.
    #[must_use]
    pub fn skip_reason(&self, path: Option<&NormalizedPath>) -> Option<LookupSkipped> {
        if !self.catalog_lookup_enabled {
            return Some(LookupSkipped::Disabled);
        }
        let path = path?;
        self.skip_catalog_for_paths
            .iter()
            .position(|prefix| path.starts_with(prefix))
            .map(LookupSkipped::PathExcluded)
    }

    /// Runs `lookup` unless these settings skip it.
    pub(crate) fn gate<T>(
        &self,
        path: Option<&NormalizedPath>,
        lookup: impl FnOnce() -> T,
    ) -> CatalogLookup<T> {
        match self.skip_reason(path) {
            Some(why) => CatalogLookup::Skipped(why),
            None => CatalogLookup::Done(lookup()),
        }
    }
}
