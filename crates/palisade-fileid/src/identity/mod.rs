//! The unified file identity record (#55).
//!
//! [`identify`] and [`identify_bytes`] run the other modules of this crate
//! over one file and fold their outputs into one [`FileIdentity`]:
//!
//! | Group | From | Tier |
//! |---|---|---|
//! | `size`, `timestamps`, `fs.path` | the opened handle, [`crate::fsctx`] (#54) | stat (T0) |
//! | `kind` | [`crate::filetype`] (#44) | classify (T1) |
//! | `pe` | [`crate::pe`] (#45) | classify (T1) |
//! | `hashes` | [`crate::hash`] (#46), [`crate::authenticode`] image and page hashes (#47) | hash (T2) |
//! | `signing_state`, `signatures` | [`crate::authenticode`] signatures, chains, validity (#48, #49, #50) | trust (T3) |
//! | `catalog_matches` | [`crate::catalog`] (#51) | trust (T3) |
//! | `fs.motw`, `fs.path_variables` | [`crate::fsctx`] (#54) | context (T4) |
//! | `derived`, `masquerade`, `strengths` | this module | always |
//!
//! Groups other issues still deliver are present in the schema now, so the
//! record's shape does not change when they land, and hold
//! [`Field::NotYetSupported`] with the issue numbers: `script` and the
//! normalised script hash (#52), `installer`, `package`
//! and the normalised MSI hash (#53), and the owner, writability, streams,
//! reparse points, file ID, volume and provenance in `fs` (#54).
//!
//! # Signing state
//!
//! The record folds embedded signatures and catalogs into one verdict,
//! [`SigningStateKind`]. It is `trusted` only when a trusted signer vouches
//! for the file: an embedded signature that passed every #48, #49 and #50
//! check, or a catalog whose signer is trusted and whose match does not
//! rely on SHA-1 (ADR 0008). It is `unsigned` only when the file has no
//! embedded signature and a catalog lookup found nothing. A file whose
//! format's embedded signatures are not read yet (anything but a PE image,
//! until #52 and #53), or that was not looked up in any catalog, is
//! `unverified`, never `unsigned`.
//!
//! # Fail-conservative
//!
//! Nothing in the record is guessed. A tier that fails leaves its fields
//! [`Field::Unavailable`] and an entry in [`FileIdentity::errors`]; it
//! never turns into "unsigned", "not a driver" or "clean". A masquerade
//! check that could not run is listed in [`Masquerade::unassessed`]. A path
//! counts as user-writable until #54 reads its ACLs.
//!
//! # Serialised form and evolution
//!
//! [`FileIdentity`] serialises with serde: `snake_case` field and variant
//! names, digests as lowercase hex, times as seconds since the Unix epoch.
//! Each [`Field`] is `{"status": "computed", "value": ...}` or a status
//! without a value (`not_requested`, `not_applicable`, `unavailable` with a
//! reason, `not_yet_supported` with the issue numbers). The schema is
//! `fileid.v1` ([`SCHEMA_VERSION`]). Within `fileid.v1`:
//!
//! - fields and enum variants are only ever added, never renamed, removed
//!   or given a new meaning;
//! - a consumer must ignore fields and variants it does not know;
//! - a breaking change is a new schema version, `fileid.v2`.
//!
//! The protobuf form for the agent-server protocol is `palisade-proto`'s
//! (#55, follow-up), with the same field names; protobuf field numbers,
//! once assigned, are never reused or renumbered.

#![forbid(unsafe_code)]

mod compose;
pub mod masquerade;
pub mod protected;
mod recommend;
mod record;
pub mod strength;
mod tier;

pub use compose::{IdentifyError, IdentityContext, MAX_IN_MEMORY, identify, identify_bytes};
pub use protected::{
    DEFAULT_LIST_VERSION, ExpectedDir, ExpectedSigner, ProtectedBinary, ProtectedList,
    ProtectedVendor,
};
pub use recommend::{MASQUERADE_THRESHOLD, Recommendation, RuleLevel, recommend};
pub use record::{
    AuthenticodeSummary, CatalogMatchSummary, CatalogState, CertBrief, ChainSummary, Derived,
    EffectiveName, ElevationSummary, EmbeddedState, ExportSummary, Field, FileIdentity, FsInfo,
    Hashes, IdentityError, ManifestSummary, Masquerade, MasqueradeReason, MotwSummary, NameInfo,
    NotYetDefined, PathInfo, PdbSummary, PeSummary, Pending, PublisherProduct, SCHEMA_VERSION,
    SectionSummary, SignatureSummary, SigningState, SigningStateKind, Timestamps, TrustSource,
    TrustedSigner, VersionSummary,
};
pub use strength::{AttributeStrength, IdentityStrength};
pub use tier::{Tier, TierParseError, Tiers};

impl FileIdentity {
    /// Folds `other`, a record of the same file computed for other tiers,
    /// into this one: the agent computes T0 to T3 at execution and T4 and
    /// T5 later. A field takes `other`'s value when it says more (a value
    /// beats a reason, a reason beats "not requested"). The derived
    /// attributes, masquerade assessment and strengths are recomputed with
    /// `ctx`.
    ///
    /// Returns `false`, and changes nothing, when the records are shown to
    /// describe different files or versions: a different path or name hint,
    /// a different final path, size, last-write or creation time, or
    /// different flat SHA-256 digests. An attribute only one record has is
    /// not compared. Until #54 adds the file ID and change journal stamp,
    /// that is the strongest check available; a file rewritten in place
    /// with the same size and restored times is not detected.
    pub fn merge(&mut self, other: Self, ctx: &IdentityContext<'_>) -> bool {
        fn differ<T: PartialEq>(a: Option<T>, b: Option<T>) -> bool {
            matches!((a, b), (Some(a), Some(b)) if a != b)
        }
        let digest = |id: &Self| id.hashes.computed().and_then(|h| h.sha256.clone());
        let final_path = |id: &Self| id.fs.path.computed().and_then(|p| p.final_path.clone());
        let times = |id: &Self| id.timestamps.computed().copied();
        let disproven = self.path != other.path
            || self.name_hint != other.name_hint
            || differ(self.size.computed(), other.size.computed())
            || differ(digest(self), digest(&other))
            || differ(final_path(self), final_path(&other))
            || differ(
                times(self).and_then(|t| t.modified),
                times(&other).and_then(|t| t.modified),
            )
            || differ(
                times(self).and_then(|t| t.created),
                times(&other).and_then(|t| t.created),
            );
        if disproven {
            return false;
        }
        self.requested_tiers = self.requested_tiers.union(other.requested_tiers);
        self.computed_tiers = self.computed_tiers.union(other.computed_tiers);
        self.size.absorb(other.size);
        self.timestamps.absorb(other.timestamps);
        self.kind.absorb(other.kind);
        self.pe.absorb(other.pe);
        self.hashes.absorb(other.hashes);
        self.signing_state.absorb(other.signing_state);
        self.signatures.absorb(other.signatures);
        self.catalog_matches.absorb(other.catalog_matches);
        self.installer.absorb(other.installer);
        self.package.absorb(other.package);
        self.script.absorb(other.script);
        self.fs.absorb(other.fs);
        for e in other.errors {
            if !self.errors.contains(&e) {
                self.errors.push(e);
            }
        }
        self.derived = compose::derived_for(self);
        self.masquerade =
            masquerade::assess(self, ctx.protected, ctx.code_trust, ctx.known_folders);
        self.strengths = strength::classify(self);
        true
    }
}

/// One difference between two identities, from [`compare`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Difference {
    /// The attribute.
    pub attribute: &'static str,
    /// Its value in the first record.
    pub a: Option<String>,
    /// Its value in the second record.
    pub b: Option<String>,
}

/// The rule-relevant attributes in which `a` and `b` differ: content
/// hashes, signing state, publisher, product, signer certificates, file
/// names and versions. An update that keeps its publisher and product
/// shows differences only in hashes and versions.
#[must_use]
pub fn compare(a: &FileIdentity, b: &FileIdentity) -> Vec<Difference> {
    fn attrs(id: &FileIdentity) -> Vec<(&'static str, Option<String>)> {
        let h = id.hashes.computed();
        let v = id.version();
        let s = id.trusted_signer();
        vec![
            ("sha256", h.and_then(|h| h.sha256.clone())),
            (
                "authenticode_sha256",
                h.and_then(|h| h.authenticode.computed())
                    .and_then(|a| a.sha256.clone()),
            ),
            (
                "signing_state",
                id.signing_state
                    .computed()
                    .map(|s| format!("{:?}", s.state).to_lowercase()),
            ),
            ("publisher", s.and_then(|s| s.publisher_name.clone())),
            ("publisher_dn", s.and_then(|s| s.publisher_dn.clone())),
            (
                "signer_leaf_sha256_thumbprint",
                s.and_then(|s| s.leaf.as_ref())
                    .map(|c| c.sha256_thumbprint.clone()),
            ),
            (
                "signer_pca_tbs_hash",
                s.and_then(|s| s.pca.as_ref())
                    .and_then(|c| c.tbs_hash.clone()),
            ),
            ("product_name", v.and_then(|v| v.product_name.clone())),
            ("company_name", v.and_then(|v| v.company_name.clone())),
            (
                "original_file_name",
                v.and_then(|v| v.original_file_name.clone()),
            ),
            ("file_version", v.and_then(|v| v.file_version_quad.clone())),
            (
                "product_version",
                v.and_then(|v| v.product_version_quad.clone()),
            ),
            ("file_name", id.name.file_name.clone()),
            ("size", id.size.computed().map(ToString::to_string)),
        ]
    }
    attrs(a)
        .into_iter()
        .zip(attrs(b))
        .filter(|((_, x), (_, y))| x != y)
        .map(|((attribute, x), (_, y))| Difference {
            attribute,
            a: x,
            b: y,
        })
        .collect()
}
