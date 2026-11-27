//! Presets: match trees for the recommended rule forms (#31).
//!
//! A preset builds an ordinary match tree, so a policy that uses one is
//! validated, evaluated and ranked by precedence like any other.

use super::{Criterion, Field, Match, Operator};

/// The publisher rule `publisher_product` (#31, ISM-1471): a signer's
/// publisher **and** a product name, optionally narrowed by the original
/// file name and a file-version range. This is the recommended form of an
/// allow rule: a publisher alone trusts everything the publisher signs.
///
/// ```
/// use palisade_policy::model::preset::PublisherProduct;
///
/// let tree = PublisherProduct::new("Example Software Ltd", "Example Editor")
///     .original_filename("editor.exe")
///     .min_version("2.0")
///     .into_match();
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
#[must_use]
pub struct PublisherProduct {
    /// `signer.publisher equals`: the leaf subject's common name.
    pub publisher: String,
    /// `meta.product_name equals`.
    pub product_name: String,
    /// `meta.original_filename equals`, if set.
    pub original_filename: Option<String>,
    /// The lowest `meta.file_version`, inclusive, if set.
    pub min_version: Option<String>,
    /// The highest `meta.file_version`, inclusive, if set.
    pub max_version: Option<String>,
}

impl PublisherProduct {
    /// A publisher and a product name.
    pub fn new(publisher: impl Into<String>, product_name: impl Into<String>) -> Self {
        Self {
            publisher: publisher.into(),
            product_name: product_name.into(),
            original_filename: None,
            min_version: None,
            max_version: None,
        }
    }

    /// Also requires this original file name.
    pub fn original_filename(mut self, name: impl Into<String>) -> Self {
        self.original_filename = Some(name.into());
        self
    }

    /// Also requires a file version of at least `version`.
    pub fn min_version(mut self, version: impl Into<String>) -> Self {
        self.min_version = Some(version.into());
        self
    }

    /// Also requires a file version of at most `version`.
    pub fn max_version(mut self, version: impl Into<String>) -> Self {
        self.max_version = Some(version.into());
        self
    }

    /// The match tree: an `all` of the publisher, the product name, then
    /// the original file name and the version test that are set. Values are
    /// not checked here; validating the policy checks them.
    #[must_use]
    pub fn into_match(self) -> Match {
        let test = |field, operator, values: Vec<String>| {
            Match::Criterion(Criterion::new(field, operator, values))
        };
        let mut all = vec![
            test(
                Field::SignerPublisher,
                Operator::Equals,
                vec![self.publisher],
            ),
            test(
                Field::MetaProductName,
                Operator::Equals,
                vec![self.product_name],
            ),
        ];
        if let Some(name) = self.original_filename {
            all.push(test(
                Field::MetaOriginalFilename,
                Operator::Equals,
                vec![name],
            ));
        }
        let version = match (self.min_version, self.max_version) {
            (Some(min), Some(max)) => Some((Operator::VersionBetween, vec![min, max])),
            (Some(min), None) => Some((Operator::VersionGe, vec![min])),
            (None, Some(max)) => Some((Operator::VersionLe, vec![max])),
            (None, None) => None,
        };
        if let Some((operator, values)) = version {
            all.push(test(Field::MetaFileVersion, operator, values));
        }
        Match::All(all)
    }
}
