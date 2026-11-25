//! The recommended rule level for a file, with the reasons: what
//! `pal fileid explain` prints, and what offline discovery (#73) uses to
//! propose rules.
//!
//! The order of preference follows the strength classes
//! ([`super::strength`]): a signer rule when a trusted signer vouches for
//! the file (it survives updates), otherwise a hash rule on the
//! authoritative digest. A path rule is never recommended while the path's
//! writability is unknown or user-writable, and nothing is recommended for
//! an empty file or a file that looks like a masquerade.

#![forbid(unsafe_code)]

use serde::Serialize;

use super::record::{CatalogState, EmbeddedState, Field, FileIdentity, SigningStateKind};

/// A rule level, narrowest last.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleLevel {
    /// The trusted publisher, any product.
    Publisher,
    /// The trusted publisher and product.
    PublisherProduct,
    /// Publisher, product, file name and minimum version.
    FilePublisher,
    /// The Authenticode SHA-256 of a conformant image.
    AuthenticodeHash,
    /// The flat SHA-256.
    Hash,
    /// The file's path.
    Path,
    /// No rule: the file has no usable identity, or should be looked at
    /// first.
    None,
}

/// The recommendation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Recommendation {
    /// The level to use.
    pub level: RuleLevel,
    /// The value or values the rule would match.
    pub values: Vec<(String, String)>,
    /// Why, one line each, for reading.
    pub rationale: Vec<String>,
    /// Levels that were considered and refused, with why.
    pub refused: Vec<(RuleLevel, String)>,
}

/// Masquerade scores at or above this stop any recommendation.
pub const MASQUERADE_THRESHOLD: u8 = 50;

/// Recommends a rule level for `id`.
#[must_use]
pub fn recommend(id: &FileIdentity) -> Recommendation {
    let mut rec = Recommendation {
        level: RuleLevel::None,
        values: Vec::new(),
        rationale: Vec::new(),
        refused: Vec::new(),
    };

    if id.masquerade.score >= MASQUERADE_THRESHOLD {
        rec.rationale.push(format!(
            "masquerade score {} (at least {MASQUERADE_THRESHOLD}): investigate before allowing anything",
            id.masquerade.score
        ));
        return rec;
    }

    let signing = id.signing_state.computed();
    // A file whose signature was broken after signing, or whose hash is
    // revoked, gets no allow rule of any kind.
    if let Some(s) = signing.filter(|s| s.state == SigningStateKind::Invalid) {
        rec.rationale.push(format!(
            "the file is invalid ({}): it was changed after signing, or its hash is revoked, so no allow rule is recommended",
            s.verification_error.as_str()
        ));
        return rec;
    }
    let signer = id.trusted_signer();
    match (signing.map(|s| s.state), signer) {
        (Some(SigningStateKind::Trusted), Some(s)) => {
            let source = match s.source {
                super::record::TrustSource::Embedded => "an embedded signature",
                super::record::TrustSource::Catalog => "a trusted catalog",
            };
            let publisher = s.publisher_name.clone();
            let product = s.product_name.clone();
            let file_name = id
                .derived
                .effective_file_name
                .as_ref()
                .filter(|n| n.source != "file_name");
            let version = id.version().and_then(|v| v.file_version_quad.clone());
            if let Some(publisher) = publisher {
                rec.rationale
                    .push(format!("signed by {publisher:?}, through {source}"));
                rec.values.push(("publisher".to_owned(), publisher));
                rec.level = RuleLevel::Publisher;
                if let Some(product) = product {
                    rec.rationale.push(format!(
                        "product {product:?}, so a publisher and product rule covers its updates"
                    ));
                    rec.values.push(("product".to_owned(), product));
                    rec.level = RuleLevel::PublisherProduct;
                    if let (Some(name), Some(version)) = (file_name, version) {
                        rec.rationale.push(format!(
                            "for this file only, narrow it to {:?} ({}) at version {version} or later",
                            name.value, name.source
                        ));
                        rec.values
                            .push(("file_name".to_owned(), name.value.clone()));
                        rec.values.push(("min_version".to_owned(), version));
                        rec.level = RuleLevel::FilePublisher;
                    }
                } else {
                    rec.rationale.push(
                        "no product name: a publisher rule would allow everything this signer signs"
                            .to_owned(),
                    );
                }
            } else {
                rec.refused.push((
                    RuleLevel::Publisher,
                    "the trusted signer has no usable name".to_owned(),
                ));
            }
        }
        (Some(SigningStateKind::Untrusted), _) => rec.refused.push((
            RuleLevel::Publisher,
            "the signature is valid but its signer is not trusted by policy".to_owned(),
        )),
        (Some(SigningStateKind::Unverified), _) => rec.refused.push((
            RuleLevel::Publisher,
            match signing.map(|s| (s.embedded, s.catalog)) {
                // A PE whose signatures could not be read (too large, say).
                _ if matches!(id.signatures, Field::Unavailable(_)) => {
                    let why = match &id.signatures {
                        Field::Unavailable(why) => why.as_str(),
                        _ => "",
                    };
                    format!("its signatures could not be read: {why}")
                }
                Some((EmbeddedState::NotChecked, _)) => {
                    "this file type's signatures are not read yet (#52, #53)".to_owned()
                }
                Some((_, CatalogState::NotChecked)) => {
                    "no embedded signature, and no catalogs were given to look it up in (use --catroot)"
                        .to_owned()
                }
                _ => "the signer could not be verified".to_owned(),
            },
        )),
        (Some(_), _) => rec.refused.push((
            RuleLevel::Publisher,
            "no trusted signer vouches for the file".to_owned(),
        )),
        (None, _) => rec.refused.push((
            RuleLevel::Publisher,
            "signatures were not examined (request the trust tier)".to_owned(),
        )),
    }

    if rec.level == RuleLevel::None {
        match id.hashes.computed() {
            Some(h) if h.empty => rec.refused.push((
                RuleLevel::Hash,
                "the file is empty: its digest matches every empty file".to_owned(),
            )),
            Some(h) => {
                let image = h
                    .authenticode
                    .computed()
                    .filter(|a| a.conformant)
                    .and_then(|a| a.sha256.clone());
                if let Some(digest) = image {
                    rec.level = RuleLevel::AuthenticodeHash;
                    rec.rationale.push(
                        "unsigned or untrusted, so a hash rule; the Authenticode hash survives re-signing"
                            .to_owned(),
                    );
                    rec.values.push(("authenticode_sha256".to_owned(), digest));
                } else if let Some(digest) = h.sha256.clone() {
                    rec.level = RuleLevel::Hash;
                    rec.rationale.push(
                        "unsigned or untrusted, so a hash rule on the flat SHA-256".to_owned(),
                    );
                    if h.authenticode.computed().is_some_and(|a| !a.conformant) {
                        rec.refused.push((
                            RuleLevel::AuthenticodeHash,
                            "the image does not conform to the Authenticode specification"
                                .to_owned(),
                        ));
                    }
                    rec.values.push(("sha256".to_owned(), digest));
                }
            }
            None => rec.refused.push((
                RuleLevel::Hash,
                "the file was not hashed (request the hash tier)".to_owned(),
            )),
        }
    }

    // Path rules are never recommended until writability is known (#54).
    if id.fs.path.computed().is_some_and(|p| !p.claimed) {
        rec.refused.push((
            RuleLevel::Path,
            "path rule refused: the path's writability by non-administrators is not known, so it is treated as user-writable".to_owned(),
        ));
    }
    rec
}
