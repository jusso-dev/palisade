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

use palisade_core::VerificationError;

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

/// Masquerade checks that, when they could not be made, stop any
/// recommendation: each could have found a renamed or impersonating
/// binary.
pub const BLOCKING_UNASSESSED: [&str; 3] = [
    "known_binary_relocated",
    "signer_impersonation",
    "name_mismatch",
];

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

    // A masquerade check that could not run is not a clean result (ADR
    // 0018): a file that may be a renamed or impersonating binary gets no
    // allow rule until the check can be made.
    if let Some(check) = id
        .masquerade
        .unassessed
        .iter()
        .find(|c| BLOCKING_UNASSESSED.contains(c))
    {
        rec.rationale.push(format!(
            "the {check} check could not be made (see masquerade.unassessed), so no allow rule is recommended until it can"
        ));
        return rec;
    }
    // A file whose version resource claims a protected binary's name is
    // allowed only through that binary's own trusted signer: a hash rule
    // would allow an impostor or a copy outside its folders.
    if let Some(original) = id.masquerade.claims_protected.as_deref()
        && id.trusted_signer().is_none()
    {
        rec.rationale.push(format!(
                "its OriginalFilename {original:?} names a protected binary and no trusted signer vouches for it, so no allow rule is recommended"
            ));
        return rec;
    }

    let signing = id.signing_state.computed();
    // A file whose signature was broken after signing, or whose hash or
    // signer is revoked, gets no allow rule of any kind; nor does a signed
    // file whose signature failed any other validity check (expired, a
    // weak key), which a hash rule would otherwise wave through. A valid
    // signature whose signer policy simply does not trust (no trusted
    // root, or no chain to one) is not a failure: such a file may get a
    // hash rule.
    if let Some(s) = signing.filter(|s| s.state == SigningStateKind::Invalid) {
        rec.rationale.push(format!(
            "the file is invalid ({}): it was changed after signing, or its hash or signer is revoked, so no allow rule is recommended",
            s.verification_error.as_str()
        ));
        return rec;
    }
    if let Some(s) = signing.filter(|s| {
        s.embedded != EmbeddedState::Unsigned
            && s.embedded != EmbeddedState::NotChecked
            && s.signer.is_none()
            && !matches!(
                s.verification_error,
                VerificationError::Ok
                    | VerificationError::NotSigned
                    | VerificationError::UntrustedRoot
                    | VerificationError::ChainIncomplete
            )
    }) {
        rec.rationale.push(format!(
            "its signature failed validation ({}), so no allow rule is recommended",
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
            if signing.is_some_and(|s| s.embedded_sha1_only) {
                "the signature rests on SHA-1, which vouches for nothing (ADR 0008)".to_owned()
            } else {
                "the signature is valid but its signer is not trusted by policy".to_owned()
            },
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
                    "this file type's signatures are not read".to_owned()
                }
                Some((_, CatalogState::NotChecked))
                    if id.errors.iter().any(|e| e.code == "catalog_index_truncated") =>
                {
                    "no embedded signature, and the catalog index is incomplete, so it may be catalog-signed"
                        .to_owned()
                }
                // A script or installer whose catalog lookup cannot prove
                // a miss: the digests its catalogs list are not yet checked
                // against catalogs made by OS tooling (#51).
                Some((_, CatalogState::NotChecked))
                    if ctx_had_catalogs(id) =>
                {
                    "no embedded signature, and a catalog lookup of this file type cannot show it is not catalog-signed"
                        .to_owned()
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

    // A path rule is never the recommendation: a content or signer rule
    // always exists when this is reached. It is refused outright where
    // non-administrators can write the path, or its writability is not
    // known (ISM-1392).
    if id.fs.path.computed().is_some_and(|p| !p.claimed) {
        let why = match id.fs.user_writable.computed() {
            Some(w) if !w.path_user_writable && !w.change_perms_by_non_admin => {
                "path rule not recommended: the path is not writable by non-administrators, but a content or signer rule identifies the file itself"
            }
            Some(_) => {
                "path rule refused: the file or a folder above it is writable by non-administrators"
            }
            None => {
                "path rule refused: the path's writability by non-administrators is not known, so it is treated as user-writable"
            }
        };
        rec.refused.push((RuleLevel::Path, why.to_owned()));
    }
    rec
}

/// Whether a catalog store was given: the record lists the matches it found
/// (possibly none) only then.
fn ctx_had_catalogs(id: &FileIdentity) -> bool {
    id.catalog_matches.is_computed()
}
