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
//! | `signing_state`, `signatures` of scripts, installers and packages | [`crate::script`] (#52), [`crate::installer`], [`crate::package`] (#53) | trust (T3) |
//! | `hashes.script_normalised_sha256`, `hashes.msi_normalised_sha256` | [`crate::script`], [`crate::installer`] | hash (T2), when T3 or T5 read the content |
//! | `fs.motw`, `fs.path_variables` | [`crate::fsctx`] (#54) | context (T4) |
//! | `script`, `installer`, `package` | [`crate::script`], [`crate::installer`], [`crate::package`] | deep (T5) |
//! | `content_tags` | `crate::tags` (#44, feature `content-rules`) | deep (T5) |
//! | `os_cross_check` | [`crate::authenticode::cross_check`] and the OS trust API (#48, Windows, `os-trust`), **diagnostic only** | trust (T3), files on disk |
//! | `derived`, `masquerade`, `strengths` | this module | always |
//!
//! Which reader runs is decided by the content the classifier saw, never by
//! the name alone: a PE image named `.ps1` or `.msix` is judged only as a
//! PE, so no script or package signature can vouch for it. The context
//! tier reads the file ID, volume, owner, writability, streams and reparse
//! point from the Windows file system (`os-trust`, #54); elsewhere they are
//! [`Field::Unavailable`]. The provenance tag has no reader yet, so it holds
//! [`Field::NotYetSupported`] with the issue number (#54).
//!
//! # Signing state
//!
//! The record folds embedded signatures and catalogs into one verdict,
//! [`SigningStateKind`]. It is `trusted` only when a trusted signer vouches
//! for the file: an embedded signature that passed every #48, #49 and #50
//! check, or a catalog whose signer is trusted and whose match does not
//! rely on SHA-1 (ADR 0008). It is `unsigned` only when the file has no
//! embedded signature and a catalog lookup found nothing. A script, an
//! installer and an app package are judged by their own signatures with
//! the same trust and validity evaluation as a PE image's; a package whose
//! manifest names another publisher than its signer, a script or package
//! changed after signing, and a container the strict reader refuses are
//! `invalid`. A file whose format's signatures are not read (a cabinet, an
//! encoded script, a file over a reader's limit), or that was not looked
//! up in any catalog, is `unverified`, never `unsigned`. So is a script or
//! installer that no catalog lists: which digest catalogs made by OS
//! tooling list them under is not yet checked (#51), so a miss proves
//! nothing.
//!
//! # Diagnostics never decide
//!
//! `os_cross_check` records how the OS trust-verification API's verdict on
//! a PE image's embedded signatures compares with this library's. It is a
//! diagnostic (ADR 0018): `signing_state`, the masquerade assessment, the
//! strengths and [`recommend`] never read it, so an OS that accepts or
//! rejects a signature cannot change a verdict. `content_tags` are
//! descriptive in the same way.
//!
//! # Fail-conservative
//!
//! Nothing in the record is guessed. A tier that fails leaves its fields
//! [`Field::Unavailable`] and an entry in [`FileIdentity::errors`]; it
//! never turns into "unsigned", "not a driver" or "clean". A masquerade
//! check that could not run is listed in [`Masquerade::unassessed`]. A path
//! counts as user-writable unless the access check proved that no
//! non-administrator can write it or any folder above it.
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

pub use compose::{
    ContentRules, IdentifyError, IdentityContext, MAX_IN_MEMORY, identify, identify_bytes,
};
pub use protected::{
    DEFAULT_LIST_VERSION, ExpectedDir, ExpectedSigner, ProtectedBinary, ProtectedList,
    ProtectedVendor,
};
pub use recommend::{MASQUERADE_THRESHOLD, Recommendation, RuleLevel, recommend};
pub use record::{
    AuthenticodeSummary, CatalogMatchSummary, CatalogState, CertBrief, ChainSummary,
    ContentTagsSummary, Derived, EffectiveName, ElevationSummary, EmbeddedState, ExportSummary,
    Field, FileIdSummary, FileIdentity, FsInfo, Hashes, IdentityError, InstallerSummary,
    ManifestSummary, Masquerade, MasqueradeReason, MotwSummary, NameInfo, NotYetDefined,
    OsComparisonSummary, OsCrossCheckSummary, OwnerSummary, PackageSummary, PathInfo, PdbSummary,
    PeSummary, Pending, PublisherProduct, ReparseSummary, SCHEMA_VERSION, ScriptSummary,
    SectionSummary, SignatureSummary, SigningState, SigningStateKind, StreamSummary,
    StreamsSummary, Timestamps, TrustSource, TrustedSigner, VersionSummary, VolumeSummary,
    WritableSummary,
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
    /// a different final path, file ID or change journal stamp, size,
    /// last-write or creation time, or a different content digest; and when
    /// both records hold attributes derived from the content, unless both
    /// carry the same content digest. Otherwise an attribute only one record
    /// has is not compared.
    ///
    /// The file ID and change journal stamp are read by the context tier
    /// only, so they are compared only between two records that both ran
    /// it. What joins an execution-time record (T0 to T3) to a later one
    /// (T4 and T5) is the content digest: the deep tier reads the content
    /// too, so both carry one and must agree. A later record of the context
    /// tier alone carries no digest, and is joined on the path, final path,
    /// size and times; a file rewritten in place with the same size and
    /// restored times is not detected then.
    pub fn merge(&mut self, other: Self, ctx: &IdentityContext<'_>) -> bool {
        fn differ<T: PartialEq>(a: Option<T>, b: Option<T>) -> bool {
            matches!((a, b), (Some(a), Some(b)) if a != b)
        }
        let final_path = |id: &Self| id.fs.path.computed().and_then(|p| p.final_path.clone());
        let times = |id: &Self| id.timestamps.computed().copied();
        let fid = |id: &Self| id.fs.file_id.computed().cloned();
        let (a_id, b_id) = (fid(self), fid(&other));
        // Each part of the file key is compared on its own: a part only one
        // record knows is not compared, and a known part that differs
        // refuses the merge.
        let key_differs = {
            let a = a_id.as_ref();
            let b = b_id.as_ref();
            differ(
                a.and_then(|f| f.volume_serial),
                b.and_then(|f| f.volume_serial),
            ) || differ(
                a.and_then(|f| f.file_id.clone()),
                b.and_then(|f| f.file_id.clone()),
            ) || differ(
                a.and_then(|f| f.usn_journal_id),
                b.and_then(|f| f.usn_journal_id),
            ) || differ(a.and_then(|f| f.usn), b.and_then(|f| f.usn))
        };
        // Attributes derived from the content (classify, hash, trust) are
        // joined only when both records carry the digest of the content
        // they read, and it is the same: two records of the same size and
        // name may still be of different content.
        let reads_content = |id: &Self| {
            [Tier::Classify, Tier::Hash, Tier::Trust, Tier::Deep]
                .iter()
                .any(|t| id.computed_tiers.contains(*t))
        };
        let content_unproven = reads_content(self)
            && reads_content(&other)
            && match (&self.content_sha256, &other.content_sha256) {
                (Some(a), Some(b)) => a != b,
                _ => true,
            };
        let disproven = self.path != other.path
            || self.name_hint != other.name_hint
            || differ(self.size.computed(), other.size.computed())
            || differ(self.content_sha256.as_ref(), other.content_sha256.as_ref())
            || content_unproven
            || differ(final_path(self), final_path(&other))
            || key_differs
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
        if self.content_sha256.is_none() {
            self.content_sha256 = other.content_sha256;
        }
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
        self.content_tags.absorb(other.content_tags);
        self.os_cross_check.absorb(other.os_cross_check);
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
