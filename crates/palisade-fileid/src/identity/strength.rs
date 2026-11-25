//! How strong each attribute of a [`FileIdentity`] is as a rule identity.
//!
//! Rule tooling (policy lint, the guardrails on generated rules) must know
//! which attributes an attacker can change. The classes, from the issue
//! (#55) and ADR 0008:
//!
//! | Class | Attributes |
//! |---|---|
//! | Strong | flat SHA-256 (and SHA-384, SHA-512); Authenticode SHA-256 of a conformant image; the chain identity (thumbprints, TBS hashes) of a trusted signer |
//! | Medium | a trusted publisher, alone or with product, file name and version; `OriginalFilename` under a trusted signature; the SHA-256 page hash value; a path that is not user-writable |
//! | Weak | `CompanyName`, `ProductName`, `FileDescription` and `InternalName`; `OriginalFilename` on a file no trusted signer covers; an untrusted signer; the file name; a user-writable path, or one whose writability is unknown |
//! | Insecure | SHA-1 and MD5 digests of any kind; the digest of an empty file; the Authenticode digest of a non-conformant image; a catalog match that relies on SHA-1 |
//!
//! An attribute that is not in the record has no entry. The normalised
//! MSI and script hashes (Medium) and the package family name (Medium on a
//! signed package) get entries when #52 and #53 fill them in.

#![forbid(unsafe_code)]

use serde::Serialize;

use super::record::{FileIdentity, SigningStateKind, TrustSource};

/// How far a rule can rely on an attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityStrength {
    /// Must not be the only identity in an allow rule.
    Insecure,
    /// Anyone who can write the file, or choose its name, controls it.
    Weak,
    /// Bound to a trusted signer or a protected location, but shared by
    /// many files or versions.
    Medium,
    /// Identifies one file's content, or one signer, cryptographically.
    Strong,
}

/// One attribute's strength.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AttributeStrength {
    /// The attribute, as named in rules and in the record.
    pub attribute: &'static str,
    /// Its class.
    pub strength: IdentityStrength,
    /// Why, for reading.
    pub reason: &'static str,
}

const fn entry(
    attribute: &'static str,
    strength: IdentityStrength,
    reason: &'static str,
) -> AttributeStrength {
    AttributeStrength {
        attribute,
        strength,
        reason,
    }
}

/// The strength of every attribute `id` holds.
#[must_use]
pub fn classify(id: &FileIdentity) -> Vec<AttributeStrength> {
    use IdentityStrength::{Insecure, Medium, Strong, Weak};
    let mut out = Vec::new();

    if let Some(h) = id.hashes.computed() {
        let flat = [
            ("sha256", h.sha256.is_some(), Strong),
            ("sha384", h.sha384.is_some(), Strong),
            ("sha512", h.sha512.is_some(), Strong),
            ("sha1", h.sha1.is_some(), Insecure),
            ("md5", h.md5.is_some(), Insecure),
        ];
        for (name, present, strength) in flat {
            if !present {
                continue;
            }
            if h.empty {
                out.push(entry(
                    name,
                    Insecure,
                    "the digest of an empty file is shared by every empty file",
                ));
            } else if strength == Insecure {
                out.push(entry(name, Insecure, "not collision resistant (ADR 0008)"));
            } else {
                out.push(entry(name, Strong, "identifies the file's exact content"));
            }
        }
        if let Some(a) = h.authenticode.computed() {
            if a.sha256.is_some() {
                out.push(if a.conformant {
                    entry(
                        "authenticode_sha256",
                        Strong,
                        "identifies the image independently of its signature",
                    )
                } else {
                    entry(
                        "authenticode_sha256",
                        Insecure,
                        "the image does not conform to the Authenticode specification, so the digest is not authoritative; use sha256",
                    )
                });
            }
            if a.sha1.is_some() {
                out.push(entry(
                    "authenticode_sha1",
                    Insecure,
                    "not collision resistant (ADR 0008)",
                ));
            }
            if a.page_sha256.is_some() {
                out.push(entry(
                    "page_sha256",
                    Medium,
                    "covers only the header page; pair it with authenticode_sha256",
                ));
            }
            if a.page_sha1.is_some() {
                out.push(entry(
                    "page_sha1",
                    Insecure,
                    "not collision resistant (ADR 0008)",
                ));
            }
        }
    }

    let signing = id.signing_state.computed();
    let signer = signing.and_then(|s| s.signer.as_ref());
    if let Some(s) = signing {
        match (s.state, signer) {
            (SigningStateKind::Trusted, Some(signer)) => {
                out.push(entry(
                    "signer_chain",
                    Strong,
                    "the certificates of a trusted signer, by thumbprint and TBS hash",
                ));
                if signer.publisher_name.is_some() {
                    out.push(entry(
                        "publisher",
                        Medium,
                        "a trusted signer's name: every file it signs matches",
                    ));
                }
                if id.derived.publisher_product.is_some() {
                    out.push(entry(
                        "publisher_product",
                        Medium,
                        "a trusted signer and the product its signature covers",
                    ));
                }
                if id.derived.publisher_product.is_some()
                    && id
                        .derived
                        .effective_file_name
                        .as_ref()
                        .is_some_and(|n| n.source != "file_name")
                    && id
                        .version()
                        .is_some_and(|v| v.file_version_quad.is_some())
                {
                    out.push(entry(
                        "publisher_product_file_name_version",
                        Medium,
                        "the narrowest signer rule: publisher, product, file name and minimum version",
                    ));
                }
                if signer.source == TrustSource::Catalog {
                    out.push(entry(
                        "catalog_match",
                        Strong,
                        "a trusted catalog lists the file's SHA-256 digest",
                    ));
                }
            }
            (SigningStateKind::Untrusted, _) => out.push(entry(
                "signer_chain",
                Weak,
                "the signature is valid, but its signer is not trusted: anyone can make such a certificate",
            )),
            _ => {}
        }
        if s.catalog == super::record::CatalogState::ListedTrustedSha1Only {
            out.push(entry(
                "catalog_match",
                Insecure,
                "the only trusted catalog match relies on SHA-1 (ADR 0008)",
            ));
        }
    }
    let trusted = signing.is_some_and(|s| s.state == SigningStateKind::Trusted);

    if let Some(v) = id.version() {
        // A blank field is no attribute.
        let set = |f: &Option<String>| f.as_deref().is_some_and(|s| !s.trim().is_empty());
        if set(&v.original_file_name) {
            out.push(if trusted {
                entry(
                    "original_file_name",
                    Medium,
                    "covered by a trusted signature; survives renaming",
                )
            } else {
                entry(
                    "original_file_name",
                    Weak,
                    "no trusted signature covers it, so anyone can set it",
                )
            });
        }
        for (name, present) in [
            ("internal_name", set(&v.internal_name)),
            ("company_name", set(&v.company_name)),
            ("product_name", set(&v.product_name)),
            ("file_description", set(&v.file_description)),
        ] {
            if present {
                out.push(entry(
                    name,
                    Weak,
                    "free text that the file's author chooses; use a publisher rule instead",
                ));
            }
        }
    }

    if id.name.file_name.is_some() {
        out.push(entry(
            "file_name",
            Weak,
            "anyone who can copy the file can rename it",
        ));
    }
    if id.fs.path.computed().is_some_and(|p| !p.claimed) {
        // Writability is #54. Until it is read, every path counts as
        // user-writable, which is the conservative reading.
        out.push(match id.fs.user_writable.computed() {
            Some(never) => match *never {},
            None => entry(
                "path",
                Weak,
                "its writability by non-administrators is not known, so it is treated as user-writable",
            ),
        });
    }
    out
}
