//! Envelope verification (#325): what a cache file holds, and whether it is
//! trusted.
//!
//! A cache file holds one signed bundle envelope
//! ([`palisade_proto::policy_bundle::envelope`]). Before anything past the
//! bundle header is decoded, an [`EnvelopeVerifier`] checks it in #225's
//! order and says where the bundle bytes are. The cache then loads only
//! those bytes, and only when the signature verified or the signature mode
//! tolerates that it did not.
//!
//! [`SignedEnvelopes`] is the verifier the agent runs: it calls
//! [`envelope::verify`] against the device's current trust set. A cache
//! file that is not an envelope, or whose signatures are not from a policy
//! key the trust set lists inside its validity window, never verifies, so
//! in the default `enforce` mode it never loads.

use std::{fmt, ops::Range, sync::Arc};

use arc_swap::ArcSwap;
use palisade_policy::bundle::{AgentVersion, BundleLimits};
use palisade_proto::{
    events::Timestamp,
    pki::{SkewTolerance, TrustSet},
    policy_bundle::{
        EffectiveMode, Examined,
        envelope::{self, Agent},
    },
};

/// What a verifier found in one cache file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Examination {
    /// #225 steps 1, 2 and 5 as checked, and step 6 as far as the verifier
    /// decoded. The cache clears `schema_supported` if the bundle then
    /// fails to load (validate or compile).
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
/// a signature verifies, unless `mode` tolerates an invalid signature
/// (#225). It reports what it found; the decisions (signature mode, target,
/// anti-rollback) are made by [`palisade_proto::policy_bundle::select`].
pub trait EnvelopeVerifier: Send + Sync + fmt::Debug {
    /// Examines one file's bytes at `now` (trusted time, #220), in the
    /// signature mode in force.
    fn examine(&self, file: &[u8], now: Timestamp, mode: EffectiveMode) -> Examination;
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

/// The device's trust set, shared with whatever keeps it current (the
/// trust-set update path of #224). A new set is swapped in whole; every
/// examination reads one set from start to end.
pub type SharedTrust = Arc<ArcSwap<TrustSet>>;

/// Verifies signed bundle envelopes against the device's trust set with
/// [`envelope::verify`].
#[derive(Clone, Debug)]
pub struct SignedEnvelopes {
    trust: SharedTrust,
    /// The agent version that `min_agent_version` is checked against.
    pub agent: AgentVersion,
    /// The size and item limits.
    pub limits: BundleLimits,
    /// The clock-skew tolerance for key validity windows.
    pub skew: SkewTolerance,
}

impl SignedEnvelopes {
    /// A verifier reading `trust`, with this agent's version, the default
    /// limits and the default skew tolerance.
    pub fn new(trust: SharedTrust) -> Self {
        Self {
            trust,
            agent: agent_version(),
            limits: BundleLimits::DEFAULT,
            skew: SkewTolerance::DEFAULT,
        }
    }

    /// The trust set it reads.
    pub const fn trust(&self) -> &SharedTrust {
        &self.trust
    }
}

impl EnvelopeVerifier for SignedEnvelopes {
    fn examine(&self, file: &[u8], now: Timestamp, mode: EffectiveMode) -> Examination {
        let trust = self.trust.load();
        let agent = Agent {
            version: self.agent,
            limits: self.limits,
            skew: self.skew,
            mode,
        };
        let verified = envelope::verify(file, &trust, &agent, now);
        match verified.examined() {
            Examined::Unreadable => Examination::UNREADABLE,
            examined @ Examined::Parsed { .. } => match payload_range(file) {
                Some(bundle) => Examination { examined, bundle },
                // `verify` decoded the envelope, so this cannot happen;
                // if it did, nothing loads.
                None => Examination::UNREADABLE,
            },
        }
    }
}

/// Where the payload of an envelope that decoded is: after the version and
/// kind bytes and the 4-byte big-endian length (see the format in
/// [`envelope`]). `None` if the length runs past the file.
fn payload_range(file: &[u8]) -> Option<Range<usize>> {
    const START: usize = 1 + 1 + 4;
    let len: [u8; 4] = file.get(2..START)?.try_into().ok()?;
    let end = START.checked_add(usize::try_from(u32::from_be_bytes(len)).ok()?)?;
    file.get(START..end).map(|_| START..end)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_range_stays_inside_the_file() {
        assert_eq!(payload_range(&[1, 1, 0, 0, 0, 2, 9, 9, 0]), Some(6..8));
        assert_eq!(payload_range(&[1, 1, 0, 0, 0, 4, 9, 9]), None);
        assert_eq!(payload_range(&[1, 1, 0]), None);
        assert_eq!(payload_range(&[]), None);
    }

    #[test]
    fn the_agent_version_is_this_crate_s() {
        let v = agent_version();
        assert_eq!(
            v,
            AgentVersion::new(
                env!("CARGO_PKG_VERSION_MAJOR").parse().unwrap(),
                env!("CARGO_PKG_VERSION_MINOR").parse().unwrap(),
                env!("CARGO_PKG_VERSION_PATCH").parse().unwrap(),
            )
        );
    }
}
