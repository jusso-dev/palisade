//! Presets: match trees for the recommended rule forms (#31, #33).
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
    /// the original file name and the version test that are set. Values
    /// are trimmed of leading and trailing white space, which a copied name
    /// often carries and a fact never matches. Values are not otherwise
    /// checked here: validating the policy rejects an empty value or a
    /// malformed version, as for any criterion.
    #[must_use]
    pub fn into_match(self) -> Match {
        let test = |field, operator, values: Vec<String>| {
            let values = values.into_iter().map(|v| v.trim().to_owned());
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

/// Why a preset could not be built.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PresetError {
    /// A `metarule` must start with a positive identity criterion (#33).
    NotAnIdentity,
    /// A `metarule` takes at most [`MAX_METARULE_CONTEXT`] context
    /// criteria.
    TooManyContextCriteria(usize),
    /// A `metarule`'s other criteria must be context criteria.
    NotContext(usize),
}

impl core::fmt::Display for PresetError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotAnIdentity => {
                f.write_str("a metarule starts with a positive identity criterion")
            }
            Self::TooManyContextCriteria(n) => write!(
                f,
                "{n} context criteria; a metarule takes at most {MAX_METARULE_CONTEXT}"
            ),
            Self::NotContext(i) => write!(f, "criterion {i} is not a context criterion"),
        }
    }
}

impl std::error::Error for PresetError {}

/// The most context criteria a [`metarule`] adds to its identity.
pub const MAX_METARULE_CONTEXT: usize = 4;

/// The preset `metarule` (#33): one positive identity criterion, AND-ed
/// with up to four context criteria, the one-to-five criterion form other
/// products call metadata rules. The tree is an `all` of the identity,
/// then the context criteria in order; with no context it is the
/// identity alone.
///
/// ```
/// use palisade_policy::model::preset::metarule;
/// use palisade_policy::model::{Criterion, Field, Operator};
///
/// let tree = metarule(
///     Criterion::new(Field::SignerPublisher, Operator::Equals, ["Example Ltd"]),
///     vec![Criterion::new(Field::UserIsAdmin, Operator::IsTrue, Vec::<String>::new())],
/// )
/// .unwrap();
/// ```
///
/// # Errors
///
/// [`PresetError`] if the first criterion is not a positive identity, a
/// later one is not context, or there are more than four.
pub fn metarule(identity: Criterion, context: Vec<Criterion>) -> Result<Match, PresetError> {
    if identity.field.is_context() || !identity.operator.is_positive() {
        return Err(PresetError::NotAnIdentity);
    }
    if context.len() > MAX_METARULE_CONTEXT {
        return Err(PresetError::TooManyContextCriteria(context.len()));
    }
    if let Some(i) = context.iter().position(|c| !c.field.is_context()) {
        return Err(PresetError::NotContext(i));
    }
    if context.is_empty() {
        return Ok(Match::Criterion(identity));
    }
    let mut all = vec![Match::Criterion(identity)];
    all.extend(context.into_iter().map(Match::Criterion));
    Ok(Match::All(all))
}

/// The preset `signed_in_directory` (#33): files under a directory, at
/// any depth, that a publisher signed, optionally narrowed to one product.
/// The tree is an `all` of `path.directory starts_with` the directory
/// (which ends at a component boundary, so `C:\Tools` does not cover
/// `C:\ToolsX`), `signer.publisher equals` the publisher, and
/// `meta.product_name equals` the product if set. A path only identifies a
/// file in an allow where users cannot write it (#31), so the signer is
/// what the rule rests on there.
#[must_use]
pub fn signed_in_directory(
    directory: impl Into<String>,
    publisher: impl Into<String>,
    product: Option<String>,
) -> Match {
    let test = |field, value: String| {
        Match::Criterion(Criterion::new(
            field,
            Operator::Equals,
            [value.trim().to_owned()],
        ))
    };
    let mut all = vec![
        Match::Criterion(Criterion::new(
            Field::PathDirectory,
            Operator::StartsWith,
            [directory.into().trim().to_owned()],
        )),
        test(Field::SignerPublisher, publisher.into()),
    ];
    if let Some(product) = product {
        all.push(test(Field::MetaProductName, product));
    }
    Match::All(all)
}

/// The preset `publisher_product_version` (#33): [`PublisherProduct`] with
/// a lowest file version, so a rule allows a product from a release on.
#[must_use]
pub fn publisher_product_version(
    publisher: impl Into<String>,
    product_name: impl Into<String>,
    min_version: impl Into<String>,
) -> Match {
    PublisherProduct::new(publisher, product_name)
        .min_version(min_version)
        .into_match()
}
