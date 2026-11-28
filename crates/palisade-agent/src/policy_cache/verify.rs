//! The seam where envelope verification (#325) plugs in.
//!
//! A cache file holds one signed envelope (ADR 0007). Before anything past
//! its header is decoded, an [`EnvelopeVerifier`] checks it in #225's
//! order and says where the bundle bytes are. The cache then decodes and
//! validates only those bytes, and only when the signature verified or the
//! signature mode tolerates that it did not.
//!
//! Until #325 lands, [`BareBundles`] reads a file as a bare bundle with no
//! signature. Its result always says the signature is not valid, so in the
//! default `enforce` mode no bundle ever loads: the agent stays on the
//! first-install or emergency policy. That is the fail-closed default; a
//! development build can opt into `audit` mode to load bare bundles.

use std::{fmt, ops::Range};

use palisade_policy::bundle::{AgentVersion, BundleLimits, TargetScope, decode_header};
use palisade_proto::{
    events::{HostId, TenantId},
    policy_bundle::{BundleMeta, Examined, Scope, Target, content_hash},
};

/// What a verifier found in one cache file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Examination {
    /// #225 steps 1, 2 and 5 as checked, and step 6 as far as the header
    /// tells. The cache clears `schema_supported` if the bundle body then
    /// fails to decode, validate or compile.
    pub examined: Examined,
    /// Where the canonical bundle bytes are in the file. Meaningful only
    /// when `examined` is [`Examined::Parsed`]; the cache refuses a range
    /// outside the file.
    pub bundle: Range<usize>,
}

impl Examination {
    /// An unreadable file.
    pub const UNREADABLE: Self = Self {
        examined: Examined::Unreadable,
        bundle: 0..0,
    };
}

/// Checks a cache file's envelope (#325).
///
/// An implementation must not decode anything past the bundle header until
/// a signature verifies (#225). It reports what it found; the decisions
/// (signature mode, target, anti-rollback) are made by
/// [`palisade_proto::policy_bundle::select`].
pub trait EnvelopeVerifier: Send + Sync + fmt::Debug {
    /// Examines one file's bytes.
    fn examine(&self, file: &[u8]) -> Examination;
}

/// This agent's version, for `min_agent_version` (#225 step 5). A version
/// that does not parse reads as 0.0.0, which only refuses more bundles.
pub fn agent_version() -> AgentVersion {
    let part = |s: &str| s.parse().unwrap_or(0);
    AgentVersion::new(
        part(env!("CARGO_PKG_VERSION_MAJOR")),
        part(env!("CARGO_PKG_VERSION_MINOR")),
        part(env!("CARGO_PKG_VERSION_PATCH")),
    )
}

/// Reads a file as a bare bundle, with no envelope and so no signature.
/// The stand-in until #325's envelope; see the module docs.
#[derive(Clone, Copy, Debug)]
pub struct BareBundles {
    /// The size and item limits.
    pub limits: BundleLimits,
    /// The agent version that `min_agent_version` is checked against.
    pub agent: AgentVersion,
}

impl Default for BareBundles {
    fn default() -> Self {
        Self {
            limits: BundleLimits::DEFAULT,
            agent: agent_version(),
        }
    }
}

impl EnvelopeVerifier for BareBundles {
    fn examine(&self, file: &[u8]) -> Examination {
        examine_bundle(file, 0..file.len(), false, &self.limits, self.agent)
    }
}

/// Examines the bundle at `range` in `file` from its header, given whether
/// the envelope's signature verified. For verifiers whose envelope wraps
/// the bundle bytes unchanged.
pub fn examine_bundle(
    file: &[u8],
    range: Range<usize>,
    signature_valid: bool,
    limits: &BundleLimits,
    agent: AgentVersion,
) -> Examination {
    let Some(bundle) = file.get(range.clone()) else {
        return Examination::UNREADABLE;
    };
    let Ok(header) = decode_header(bundle, limits) else {
        return Examination::UNREADABLE;
    };
    let scope = match header.target.scope {
        TargetScope::Group(id) => Scope::Group(id),
        TargetScope::Device(id) => Scope::Device(HostId(id)),
    };
    Examination {
        examined: Examined::Parsed {
            meta: BundleMeta {
                target: Target {
                    tenant: TenantId(header.target.tenant),
                    scope,
                },
                version: header.policy_version,
                sha256: content_hash(bundle),
            },
            signature_valid,
            agent_supported: header.supports_agent(agent),
            schema_supported: header.schema_supported(),
        },
        bundle: range,
    }
}
