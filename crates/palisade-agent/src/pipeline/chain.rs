//! Sequence numbers and the hash chain (#63, #197).
//!
//! Every event the pipeline keeps gets the device's next sequence number
//! and `prev_hash`, the chain value of the event before it. The chain value
//! of an event is the SHA-256 of its canonical JSON
//! ([`Event::to_canonical_json`]), which includes its own `seq` and
//! `prev_hash`, so changing, removing or reordering any event the server
//! has seen breaks the chain from there on.
//!
//! One chain per device, across every class (#63's proposal: simpler to
//! verify). Classes are uploaded in their own queues, so the server
//! reorders by `seq` before verifying.
//!
//! The keyed chain (a MAC under a device key) belongs to #220 and #202;
//! [`Chainer`] is where it plugs in, and the server-side verifier is #202.
//! The chain head survives restarts in the spool's state file.

#![forbid(unsafe_code)]

use palisade_proto::events::{Event, Sha256Hex};

/// The chain value of an event's canonical form.
#[must_use]
pub fn chain_value(canonical: &[u8]) -> [u8; 32] {
    use sha2::Digest as _;
    sha2::Sha256::digest(canonical).into()
}

/// Numbers and chains events.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Chainer {
    head: Option<(u64, [u8; 32])>,
}

/// A numbered, chained event, ready to spool.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stamped {
    /// The event, with `seq` and `prev_hash` set.
    pub event: Event,
    /// Its canonical JSON.
    pub canonical: Vec<u8>,
    /// Its chain value.
    pub chain: [u8; 32],
}

impl Chainer {
    /// A chainer that continues from `head` (the last sequence number
    /// issued and its chain value), or starts a new chain at 0.
    #[must_use]
    pub const fn resume(head: Option<(u64, [u8; 32])>) -> Self {
        Self { head }
    }

    /// The last sequence number issued and its chain value.
    #[must_use]
    pub const fn head(&self) -> Option<(u64, [u8; 32])> {
        self.head
    }

    /// The next sequence number.
    #[must_use]
    pub fn next_seq(&self) -> u64 {
        self.head.map_or(0, |(s, _)| s.saturating_add(1))
    }

    /// Numbers and chains `event`, and advances the head.
    ///
    /// # Errors
    ///
    /// Serialisation failed (these types never fail), or the sequence
    /// space is exhausted; the head does not move.
    pub fn stamp(&mut self, mut event: Event) -> Result<Stamped, ChainError> {
        if self.head.is_some_and(|(s, _)| s == u64::MAX) {
            return Err(ChainError::Exhausted);
        }
        event.seq = self.next_seq();
        event.prev_hash = self.head.map(|(_, c)| Sha256Hex::from_bytes(c));
        let canonical = event
            .to_canonical_json()
            .map_err(|_| ChainError::Encode)?
            .into_bytes();
        let chain = chain_value(&canonical);
        self.head = Some((event.seq, chain));
        Ok(Stamped {
            event,
            canonical,
            chain,
        })
    }
}

/// Why an event could not be stamped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainError {
    /// The event did not serialise.
    Encode,
    /// Every sequence number has been used.
    Exhausted,
}

impl std::fmt::Display for ChainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Encode => f.write_str("the event did not serialise"),
            Self::Exhausted => f.write_str("the event sequence space is exhausted"),
        }
    }
}

impl std::error::Error for ChainError {}

/// Checks that `events` form a chain continuing from `head`: consecutive
/// sequence numbers, each `prev_hash` the chain value of the one before.
/// The server's check (#202) is the same; this is for tests and the
/// agent's own self-check.
#[must_use]
pub fn verify(head: Option<(u64, [u8; 32])>, events: &[Event]) -> bool {
    let mut prev = head;
    for event in events {
        let want_seq = prev.map_or(0, |(s, _)| s.wrapping_add(1));
        let want_prev = prev.map(|(_, c)| Sha256Hex::from_bytes(c));
        if event.seq != want_seq || event.prev_hash != want_prev {
            return false;
        }
        let Ok(canonical) = event.to_canonical_json() else {
            return false;
        };
        prev = Some((event.seq, chain_value(canonical.as_bytes())));
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline::testing::event;
    use palisade_proto::events::{EventType, Outcome};

    #[test]
    fn events_are_numbered_and_chained() {
        let mut chainer = Chainer::default();
        assert_eq!(chainer.next_seq(), 0);
        let a = chainer
            .stamp(event(EventType::ExecDecision, Outcome::Blocked, 1))
            .unwrap();
        assert_eq!((a.event.seq, a.event.prev_hash), (0, None));
        assert_eq!(a.event.validate(), Ok(()));
        let b = chainer
            .stamp(event(EventType::ExecDecision, Outcome::Allowed, 2))
            .unwrap();
        assert_eq!(b.event.seq, 1);
        assert_eq!(b.event.prev_hash, Some(Sha256Hex::from_bytes(a.chain)));
        assert_eq!(b.event.validate(), Ok(()));
        assert_eq!(chain_value(&b.canonical), b.chain);
        assert_eq!(chainer.head(), Some((1, b.chain)));
        assert!(verify(None, &[a.event.clone(), b.event.clone()]));
        // Any change, removal or reordering breaks it.
        let mut changed = a.event.clone();
        changed.severity = palisade_proto::events::Severity::new(9).unwrap();
        assert!(!verify(None, &[changed, b.event.clone()]));
        assert!(!verify(None, std::slice::from_ref(&b.event)));
        assert!(!verify(None, &[b.event.clone(), a.event.clone()]));
        // A chain resumed from a head continues it.
        let mut resumed = Chainer::resume(chainer.head());
        let c = resumed
            .stamp(event(EventType::AgentStarted, Outcome::Info, 3))
            .unwrap();
        assert_eq!(c.event.seq, 2);
        assert!(verify(Some((1, b.chain)), &[c.event]));
    }

    #[test]
    fn the_sequence_space_ends_cleanly() {
        let mut chainer = Chainer::resume(Some((u64::MAX, [0; 32])));
        assert_eq!(
            chainer.stamp(event(EventType::AgentStarted, Outcome::Info, 1)),
            Err(ChainError::Exhausted)
        );
        assert_eq!(chainer.head(), Some((u64::MAX, [0; 32])));
        assert!(ChainError::Exhausted.to_string().contains("exhausted"));
        assert!(ChainError::Encode.to_string().contains("serialise"));
    }
}
