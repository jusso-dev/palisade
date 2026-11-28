//! How strong each attribute of a [`FileIdentity`] is as a rule identity.
//!
//! Rule tooling (policy lint, the guardrails on generated rules) must know
//! which attributes an attacker can change. The classes, from the issue
//! (#55) and ADR 0008:
//!
//! | Class | Attributes |
//! |---|---|
//! | Strong | flat SHA-256 (and SHA-384, SHA-512); Authenticode SHA-256 of a conformant image; the chain identity (thumbprints, TBS hashes) of a trusted signer |
//! | Medium | a trusted publisher, alone or with product, file name and version; `OriginalFilename` under a trusted signature; the SHA-256 page hash value; the normalised MSI hash; the package family name of a package whose valid signature a trusted signer made; a path on a local fixed disk that is not user-writable |
//! | Weak | `CompanyName`, `ProductName`, `FileDescription` and `InternalName`; `OriginalFilename` on a file no trusted signer covers; an untrusted signer; the file name; the normalised script hash; the package family name of a package no trusted signer binds; an installer's product and upgrade codes and `Manufacturer`; a user-writable path, one whose writability is unknown, or one on a network, removable or unknown volume |
//! | Insecure | SHA-1 and MD5 digests of any kind; the digest of an empty file; the Authenticode digest of a non-conformant image; a catalog match that relies on SHA-1 |
//!
//! An attribute that is not in the record has no entry.

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

    if let Some(h) = id.hashes.computed() {
        if h.msi_normalised_sha256.is_computed() {
            out.push(entry(
                "msi_normalised_sha256",
                Medium,
                "the package's content without its timestamps: copies that differ only in timestamps match",
            ));
        }
        if h.script_normalised_sha256.is_computed() {
            out.push(entry(
                "script_normalised_sha256",
                Weak,
                "tolerant of re-encoding, line endings and re-signing: for explicit opt-in rules only; use sha256",
            ));
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

    if let Some(p) = id.package.computed() {
        // The family name hashes `Identity@Publisher`, which anyone can
        // write: it names a publisher only when a trusted signer's valid
        // signature binds the manifest's publisher to its own subject.
        out.push(if trusted && p.signature_valid {
            entry(
                "package_family_name",
                Medium,
                "a trusted signer's package: every version of the app matches",
            )
        } else {
            entry(
                "package_family_name",
                Weak,
                "no trusted signer binds the manifest's publisher, so anyone can claim it",
            )
        });
    }
    if let Some(i) = id.installer.computed() {
        for (name, present) in [
            ("product_code", i.product_code.is_some()),
            ("upgrade_code", i.upgrade_code.is_some()),
            ("manufacturer", i.manufacturer.is_some()),
        ] {
            if present {
                out.push(entry(
                    name,
                    Weak,
                    "set by the package's author; use a publisher rule or a hash instead",
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
        // Medium only when the access check proved that no
        // non-administrator can write the file or any folder above it on
        // its real or lexical chain. Unknown counts as user-writable.
        // The ACL is only worth something on a local fixed disk: a network
        // share's server, or whoever holds a removable disk, decides what
        // its folders hold whatever they say.
        let local = id
            .fs
            .volume
            .computed()
            .is_some_and(|v| matches!(v.location.as_str(), "os_volume" | "other_fixed"));
        out.push(match id.fs.user_writable.computed() {
            Some(w) if !w.path_user_writable && !w.change_perms_by_non_admin && !local => entry(
                "path",
                Weak,
                "the volume is not a local fixed disk (or its kind is not known), so its permissions do not protect the path",
            ),
            Some(w) if !w.path_user_writable && !w.change_perms_by_non_admin => entry(
                "path",
                Medium,
                "neither the file nor any folder above it is writable by non-administrators",
            ),
            Some(_) => entry(
                "path",
                Weak,
                "the file or a folder above it is writable by non-administrators",
            ),
            None => entry(
                "path",
                Weak,
                "its writability by non-administrators is not known, so it is treated as user-writable",
            ),
        });
    }
    out
}
