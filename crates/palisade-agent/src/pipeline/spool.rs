//! The durable event spool (#63, #197): an append-only segmented log, one
//! chain of segments per [`Class`], with caps, eviction by priority, and
//! acknowledgement.
//!
//! - **Append**: a record goes to its class's newest segment, or a new
//!   one when that would pass [`SpoolLimits::segment_bytes`]. Appending
//!   does not flush; [`Spool::sync`] does, and the pipeline calls it per
//!   batch and at once for priority events, so a crash loses at most the
//!   records appended since the last sync.
//! - **Recovery** ([`SegmentSpool::open`]): every segment is read and
//!   checked ([`segment::decode`]). A torn or damaged tail is cut off, and
//!   reported, never silently: [`Recovery::damaged`].
//! - **Caps**: [`SpoolLimits::max_bytes`] in total. Unprotected classes
//!   ([`Class::is_protected`]) may fill only
//!   [`SpoolLimits::soft_percent`] of it. To make room, the spool deletes
//!   whole segments, oldest first, of the lowest class that has any
//!   (diagnostics, then summaries, allowed, information, audit). Blocked
//!   and security events are given up only when the spool is physically
//!   full of them. A record that cannot be placed is refused. Every
//!   deletion and refusal is returned as a [`Dropped`], for the pipeline's
//!   `agent.dropped` event (ADR 0018: a loss is never silent).
//! - **Age**: unprotected segments whose newest record is older than
//!   [`SpoolLimits::max_age`] are deleted by [`Spool::expire`], and
//!   reported the same way.
//! - **Acknowledgement**: the uploader reads a class's records in order
//!   ([`Spool::pending`]) and acknowledges them up to a sequence number
//!   ([`Spool::ack`]). Segments wholly acknowledged are deleted.
//!
//! The state file keeps, per class, the highest acknowledged sequence
//! number, and the chain head (the last sequence number and chain value
//! the agent issued). It is written before any segment is deleted, so the
//! head survives even when every segment is gone. A state file that is
//! damaged is reported ([`StateStatus::Damaged`]); the spool then
//! re-sends what it still has (the server de-duplicates by sequence
//! number), and the pipeline raises a tamper event.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::io;
use std::time::Duration;

use super::crc32c::crc32c;
use super::segment::{self, Class, MAGIC, StoredRecord, Tail};
use super::storage::{SegmentId, Storage};

/// The spool's size and age limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpoolLimits {
    /// A segment is closed once it would pass this size. Default 4 MiB
    /// (#63).
    pub segment_bytes: u64,
    /// The total size of every segment. Default 512 MiB (#63).
    pub max_bytes: u64,
    /// The share of `max_bytes`, in percent, that unprotected classes may
    /// fill. Default 95 (#63: blocked and security events are never given
    /// up until 95% of the cap).
    pub soft_percent: u8,
    /// Unprotected events older than this are given up. Default 30 days.
    pub max_age: Duration,
}

impl Default for SpoolLimits {
    fn default() -> Self {
        Self {
            segment_bytes: 4 << 20,
            max_bytes: 512 << 20,
            soft_percent: 95,
            max_age: Duration::from_secs(30 * 24 * 60 * 60),
        }
    }
}

impl SpoolLimits {
    /// The size unprotected classes may fill.
    #[must_use]
    pub fn soft_bytes(&self) -> u64 {
        let soft = u128::from(self.max_bytes) * u128::from(self.soft_percent.min(100)) / 100;
        u64::try_from(soft).unwrap_or(self.max_bytes)
    }
}

/// Why events were given up.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DropReason {
    /// The spool was at its cap.
    SpoolFull,
    /// They were older than the age cap.
    Expired,
    /// Their records were damaged or could not be written.
    Corrupt,
}

/// Events the spool gave up: never silent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Dropped {
    /// Their class.
    pub class: Class,
    /// Why.
    pub reason: DropReason,
    /// How many.
    pub count: u64,
    /// The lowest sequence number given up.
    pub from_seq: u64,
    /// The highest sequence number given up.
    pub to_seq: u64,
}

/// A segment whose tail was cut off on recovery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Damaged {
    /// The segment.
    pub segment: SegmentId,
    /// How it ended.
    pub tail: Tail,
    /// The bytes cut off.
    pub bytes: u64,
    /// The sequence number of the last record kept, if any.
    pub last_kept: Option<u64>,
}

/// What the state file held.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StateStatus {
    /// There was none: a new spool.
    Absent,
    /// It was read.
    Intact,
    /// It did not pass its check. Acknowledgements are lost, so what is
    /// left is sent again, and the chain head is taken from the segments.
    Damaged,
}

/// What [`SegmentSpool::open`] found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Recovery {
    /// The state file.
    pub state: StateStatus,
    /// Segments whose tail was cut off, or that were removed whole.
    pub damaged: Vec<Damaged>,
    /// The chain head: the last sequence number issued and its chain
    /// value, if any event was ever issued.
    pub head: Option<(u64, [u8; 32])>,
    /// Records waiting for upload.
    pub pending: u64,
}

/// A spool error.
#[derive(Debug)]
pub enum SpoolError {
    /// The storage failed.
    Io(io::Error),
    /// A record's sequence number is not above the last one issued.
    OutOfOrder {
        /// The record's sequence number.
        seq: u64,
        /// The last one issued.
        head: u64,
    },
    /// The record is larger than a record may be, or than the spool.
    TooLarge,
}

impl fmt::Display for SpoolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "spool storage: {e}"),
            Self::OutOfOrder { seq, head } => {
                write!(
                    f,
                    "sequence number {seq} is not above the last issued, {head}"
                )
            }
            Self::TooLarge => f.write_str("the record is too large for the spool"),
        }
    }
}

impl std::error::Error for SpoolError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for SpoolError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// What an append did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Appended {
    /// Whether the record was stored. `false` when there was no room for
    /// it; it is then also in `dropped`.
    pub stored: bool,
    /// Everything given up to make room, and the record itself if it was
    /// refused.
    pub dropped: Vec<Dropped>,
}

/// Counts for health and metrics (#63).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SpoolStats {
    /// The bytes in every segment.
    pub bytes: u64,
    /// Records waiting for upload, per class.
    pub pending: BTreeMap<Class, u64>,
    /// The time of the oldest record waiting, in microseconds since the
    /// Unix epoch.
    pub oldest_pending: Option<i64>,
    /// Records appended but not yet synced.
    pub unsynced: u64,
}

impl SpoolStats {
    /// Records waiting for upload, in every class.
    #[must_use]
    pub fn total_pending(&self) -> u64 {
        self.pending.values().sum()
    }
}

/// The spool, as the pipeline uses it. [`SegmentSpool`] is the
/// implementation; the agent local store (ADR 0007) may replace it.
pub trait Spool: Send {
    /// Stores a record, giving up older ones if the caps need it.
    ///
    /// # Errors
    ///
    /// The record is out of order or too large, or the storage failed;
    /// it was not stored.
    fn append(&mut self, record: StoredRecord) -> Result<Appended, SpoolError>;

    /// Makes every appended record durable.
    ///
    /// # Errors
    ///
    /// The storage failed.
    fn sync(&mut self) -> Result<(), SpoolError>;

    /// Up to `max_records` records of `class`, totalling at most
    /// `max_bytes` of payload (at least one record), with sequence numbers
    /// above `after` and above what is acknowledged, oldest first.
    ///
    /// # Errors
    ///
    /// The storage failed.
    fn pending(
        &mut self,
        class: Class,
        after: Option<u64>,
        max_records: usize,
        max_bytes: usize,
    ) -> Result<Vec<StoredRecord>, SpoolError>;

    /// Marks every record of `class` up to `seq` delivered.
    ///
    /// # Errors
    ///
    /// The storage failed; the acknowledgement may be repeated.
    fn ack(&mut self, class: Class, seq: u64) -> Result<(), SpoolError>;

    /// Gives up unprotected events older than the age cap, at `now`
    /// (microseconds since the Unix epoch).
    ///
    /// # Errors
    ///
    /// The storage failed.
    fn expire(&mut self, now: i64) -> Result<Vec<Dropped>, SpoolError>;

    /// The chain head.
    fn head(&self) -> Option<(u64, [u8; 32])>;

    /// Counts for health and metrics.
    fn stats(&self) -> SpoolStats;
}

/// One segment's index.
#[derive(Clone, Debug)]
struct Segment {
    id: SegmentId,
    bytes: u64,
    /// The sequence numbers of its records, ascending.
    seqs: Vec<u64>,
    /// The time of its newest record.
    newest: i64,
    /// The time of its oldest record.
    oldest: i64,
}

impl Segment {
    fn last_seq(&self) -> Option<u64> {
        self.seqs.last().copied()
    }

    /// Records above `seq`.
    fn above(&self, seq: Option<u64>) -> usize {
        seq.map_or(self.seqs.len(), |s| {
            self.seqs.len() - self.seqs.partition_point(|&x| x <= s)
        })
    }
}

/// The state file: magic, head flag, head seq, head chain, then per class
/// an ack flag and seq, then a CRC-32C of everything before it.
const STATE_MAGIC: [u8; 10] = *b"PALSTATE\x00\x01";
const STATE_LEN: usize = STATE_MAGIC.len() + 1 + 8 + 32 + Class::ALL.len() * 9 + 4;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct State {
    head: Option<(u64, [u8; 32])>,
    acks: [Option<u64>; 7],
}

impl State {
    fn encode(&self) -> Vec<u8> {
        let mut out = STATE_MAGIC.to_vec();
        let (flag, seq, chain) = self.head.map_or((0, 0, [0; 32]), |(s, c)| (1, s, c));
        out.push(flag);
        out.extend_from_slice(&seq.to_le_bytes());
        out.extend_from_slice(&chain);
        for ack in self.acks {
            out.push(u8::from(ack.is_some()));
            out.extend_from_slice(&ack.unwrap_or(0).to_le_bytes());
        }
        let crc = crc32c(&out);
        out.extend_from_slice(&crc.to_le_bytes());
        out
    }

    fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != STATE_LEN || bytes.get(..STATE_MAGIC.len())? != STATE_MAGIC {
            return None;
        }
        let (body, crc) = bytes.split_at(STATE_LEN - 4);
        if crc32c(body) != u32::from_le_bytes(crc.try_into().ok()?) {
            return None;
        }
        let u64_at = |at: usize| -> Option<u64> {
            Some(u64::from_le_bytes(body.get(at..at + 8)?.try_into().ok()?))
        };
        let flag = |at: usize| -> Option<bool> {
            match body.get(at)? {
                0 => Some(false),
                1 => Some(true),
                _ => None,
            }
        };
        let mut at = STATE_MAGIC.len();
        let head = if flag(at)? {
            Some((u64_at(at + 1)?, body.get(at + 9..at + 41)?.try_into().ok()?))
        } else {
            None
        };
        at += 41;
        let mut acks = [None; 7];
        for ack in &mut acks {
            *ack = flag(at)?.then_some(u64_at(at + 1)?);
            at += 9;
        }
        Some(Self { head, acks })
    }
}

/// The length of a segment's magic.
const MAGIC_LEN: u64 = MAGIC.len() as u64;

const fn index(class: Class) -> usize {
    class.code() as usize
}

/// The segmented spool over a [`Storage`].
pub struct SegmentSpool<S> {
    storage: S,
    limits: SpoolLimits,
    segments: [VecDeque<Segment>; 7],
    /// Whether each class's newest segment may take more records. A write
    /// that failed closes it, so its damaged tail is never appended to.
    open: [bool; 7],
    state: State,
    /// The state last written.
    saved: Option<State>,
    /// Segments with unsynced records.
    dirty: BTreeSet<SegmentId>,
    unsynced: u64,
    bytes: u64,
}

impl<S> fmt::Debug for SegmentSpool<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SegmentSpool")
            .field("bytes", &self.bytes)
            .field("head", &self.state.head.map(|(s, _)| s))
            .finish_non_exhaustive()
    }
}

impl<S: Storage> SegmentSpool<S> {
    /// Opens the spool on `storage`, recovering what is there.
    ///
    /// # Errors
    ///
    /// The storage failed. Damaged data is not an error: it is cut off
    /// and reported in [`Recovery`].
    pub fn open(mut storage: S, limits: SpoolLimits) -> Result<(Self, Recovery), SpoolError> {
        let (state, status) = match storage.read_state()? {
            None => (State::default(), StateStatus::Absent),
            Some(bytes) => match State::decode(&bytes) {
                Some(state) => (state, StateStatus::Intact),
                None => (State::default(), StateStatus::Damaged),
            },
        };
        let mut spool = Self {
            storage,
            limits,
            segments: Default::default(),
            open: [true; 7],
            state,
            saved: (status == StateStatus::Intact).then_some(state),
            dirty: BTreeSet::new(),
            unsynced: 0,
            bytes: 0,
        };
        let mut damaged = Vec::new();
        let mut ids = spool.storage.list()?;
        ids.sort();
        for id in ids {
            spool.recover_segment(id, &mut damaged)?;
        }
        // The head is the newest of the state's and the segments'.
        let newest = spool
            .segments
            .iter()
            .filter_map(|segments| segments.back())
            .filter_map(|seg| Some((seg.last_seq()?, seg.id)))
            .max();
        if let Some((last, id)) = newest
            && spool.state.head.is_none_or(|(h, _)| last > h)
            && let Some(r) = spool.read_segment(id)?.pop()
        {
            spool.state.head = Some((r.seq, r.chain));
        }
        // Drop what is already acknowledged.
        for class in Class::ALL {
            if let Some(ack) = spool.state.acks[index(class)] {
                spool.delete_acked(class, ack)?;
            }
        }
        let recovery = Recovery {
            state: status,
            damaged,
            head: spool.state.head,
            pending: spool.stats().total_pending(),
        };
        Ok((spool, recovery))
    }

    fn read_segment(&mut self, id: SegmentId) -> Result<Vec<StoredRecord>, SpoolError> {
        Ok(segment::decode(&self.storage.read(id)?, id.class).records)
    }

    fn recover_segment(
        &mut self,
        id: SegmentId,
        damaged: &mut Vec<Damaged>,
    ) -> Result<(), SpoolError> {
        let bytes = self.storage.read(id)?;
        let decoded = segment::decode(&bytes, id.class);
        let class = index(id.class);
        let previous = self.segments[class].back().and_then(Segment::last_seq);
        // The name must match the first record, and the segment must
        // follow the one before it.
        let in_order = decoded
            .records
            .first()
            .is_none_or(|r| r.seq == id.first_seq && previous.is_none_or(|p| r.seq > p));
        let total = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        if decoded.records.is_empty() || !in_order {
            self.storage.remove(id)?;
            if decoded.tail != Tail::Clean || !in_order || total > MAGIC_LEN {
                damaged.push(Damaged {
                    segment: id,
                    tail: if in_order {
                        decoded.tail
                    } else {
                        Tail::Corrupt
                    },
                    bytes: total,
                    last_kept: None,
                });
            }
            return Ok(());
        }
        let valid = u64::try_from(decoded.valid_len).unwrap_or(u64::MAX);
        if decoded.tail != Tail::Clean {
            self.storage.truncate(id, valid)?;
            damaged.push(Damaged {
                segment: id,
                tail: decoded.tail,
                bytes: total.saturating_sub(valid),
                last_kept: decoded.records.last().map(|r| r.seq),
            });
        }
        let seg = Segment {
            id,
            bytes: valid,
            seqs: decoded.records.iter().map(|r| r.seq).collect(),
            newest: decoded.records.iter().map(|r| r.time).max().unwrap_or(0),
            oldest: decoded.records.iter().map(|r| r.time).min().unwrap_or(0),
        };
        self.bytes = self.bytes.saturating_add(seg.bytes);
        self.segments[class].push_back(seg);
        Ok(())
    }

    fn sync_segments(&mut self) -> Result<(), SpoolError> {
        while let Some(id) = self.dirty.first().copied() {
            self.storage.sync(id)?;
            self.dirty.remove(&id);
        }
        self.unsynced = 0;
        Ok(())
    }

    /// Writes `state`, then adopts it. Appended records are synced first,
    /// so the state never names a head that a crash could lose.
    fn write_state(&mut self, state: State) -> Result<(), SpoolError> {
        self.sync_segments()?;
        if self.saved != Some(state) {
            self.storage.write_state(&state.encode())?;
            self.saved = Some(state);
        }
        self.state = state;
        Ok(())
    }

    fn save_state(&mut self) -> Result<(), SpoolError> {
        self.write_state(self.state)
    }

    fn remove_segment(&mut self, class: Class, front: bool) -> Result<Option<Segment>, SpoolError> {
        // The head must outlive the segment that holds it.
        self.save_state()?;
        let segments = &mut self.segments[index(class)];
        let seg = if front {
            segments.pop_front()
        } else {
            segments.pop_back()
        };
        if let Some(seg) = &seg {
            self.storage.remove(seg.id)?;
            self.bytes = self.bytes.saturating_sub(seg.bytes);
            if self.dirty.remove(&seg.id) {
                self.unsynced = self
                    .unsynced
                    .saturating_sub(u64::try_from(seg.seqs.len()).unwrap_or(u64::MAX));
            }
            if self.segments[index(class)].is_empty() {
                self.open[index(class)] = true;
            }
        }
        Ok(seg)
    }

    fn delete_acked(&mut self, class: Class, ack: u64) -> Result<(), SpoolError> {
        while self.segments[index(class)]
            .front()
            .and_then(Segment::last_seq)
            .is_some_and(|last| last <= ack)
        {
            self.remove_segment(class, true)?;
        }
        Ok(())
    }

    /// The lowest class that has a segment to give up for room, among the
    /// unprotected classes, or every class when `protected` is set.
    fn victim(&self, protected: bool) -> Option<Class> {
        Class::ALL
            .into_iter()
            .filter(|c| protected || !c.is_protected())
            .find(|c| !self.segments[index(*c)].is_empty())
    }

    fn evict(&mut self, class: Class, reason: DropReason) -> Result<Option<Dropped>, SpoolError> {
        let ack = self.state.acks[index(class)];
        let Some(seg) = self.remove_segment(class, true)? else {
            return Ok(None);
        };
        let lost: Vec<u64> = seg
            .seqs
            .iter()
            .copied()
            .filter(|&s| ack.is_none_or(|a| s > a))
            .collect();
        Ok(match (lost.first(), lost.last()) {
            (Some(&from), Some(&to)) => Some(Dropped {
                class,
                reason,
                count: u64::try_from(lost.len()).unwrap_or(u64::MAX),
                from_seq: from,
                to_seq: to,
            }),
            _ => None,
        })
    }

    /// Gives up segments until `need` more bytes fit, for a record of
    /// `class`. Returns whether they fit.
    fn make_room(
        &mut self,
        class: Class,
        need: u64,
        dropped: &mut Vec<Dropped>,
    ) -> Result<bool, SpoolError> {
        let protected = class.is_protected();
        let cap = if protected {
            self.limits.max_bytes
        } else {
            self.limits.soft_bytes()
        };
        if need > cap {
            return Ok(false);
        }
        while self.bytes.saturating_add(need) > cap {
            // Unprotected classes may only displace lower or equal classes;
            // protected ones displace everything, unprotected first.
            let victim = self
                .victim(false)
                .filter(|v| protected || *v <= class)
                .or_else(|| protected.then(|| self.victim(true)).flatten());
            let Some(victim) = victim else {
                return Ok(false);
            };
            if let Some(d) = self.evict(victim, DropReason::SpoolFull)? {
                dropped.push(d);
            }
        }
        Ok(true)
    }
}

impl<S: Storage> Spool for SegmentSpool<S> {
    fn append(&mut self, record: StoredRecord) -> Result<Appended, SpoolError> {
        if let Some((head, _)) = self.state.head
            && record.seq <= head
        {
            return Err(SpoolError::OutOfOrder {
                seq: record.seq,
                head,
            });
        }
        let mut encoded = Vec::with_capacity(record.encoded_len());
        segment::encode(&record, &mut encoded).map_err(|_| SpoolError::TooLarge)?;
        let len = u64::try_from(encoded.len()).unwrap_or(u64::MAX);
        let class = record.class;
        let i = index(class);
        let roll = !self.open[i]
            || self.segments[i].back().is_none_or(|seg| {
                seg.bytes.saturating_add(len) > self.limits.segment_bytes && !seg.seqs.is_empty()
            });
        let need = len + if roll { MAGIC_LEN } else { 0 };
        let mut appended = Appended::default();
        let mut fits = self.make_room(class, need, &mut appended.dropped)?;
        // Making room may have removed the segment the record was to go
        // to; then a new one needs room for its magic as well.
        if fits && !roll && self.segments[i].is_empty() {
            fits = self.make_room(class, len + MAGIC_LEN, &mut appended.dropped)?;
        }
        if !fits {
            appended.dropped.push(Dropped {
                class,
                reason: DropReason::SpoolFull,
                count: 1,
                from_seq: record.seq,
                to_seq: record.seq,
            });
            // The record is given up, but its number is issued: the next
            // event chains to it, and the loss report explains the gap.
            self.state.head = Some((record.seq, record.chain));
            return Ok(appended);
        }
        // Eviction may have removed the open segment.
        let roll = roll || self.segments[i].is_empty();
        if roll {
            let id = SegmentId {
                class,
                first_seq: record.seq,
            };
            self.storage.create(id, &MAGIC)?;
            self.open[i] = true;
            self.bytes = self.bytes.saturating_add(MAGIC_LEN);
            self.segments[i].push_back(Segment {
                id,
                bytes: MAGIC_LEN,
                seqs: Vec::new(),
                newest: record.time,
                oldest: record.time,
            });
        }
        let Some(seg) = self.segments[i].back_mut() else {
            return Err(SpoolError::Io(io::Error::other("no open segment")));
        };
        let id = seg.id;
        if let Err(e) = self.storage.append(id, &encoded) {
            // Never append after a partial write; recovery cuts it off.
            self.open[i] = false;
            return Err(e.into());
        }
        seg.bytes = seg.bytes.saturating_add(len);
        seg.seqs.push(record.seq);
        seg.newest = seg.newest.max(record.time);
        seg.oldest = seg.oldest.min(record.time);
        self.bytes = self.bytes.saturating_add(len);
        self.dirty.insert(id);
        self.unsynced = self.unsynced.saturating_add(1);
        self.state.head = Some((record.seq, record.chain));
        appended.stored = true;
        Ok(appended)
    }

    fn sync(&mut self) -> Result<(), SpoolError> {
        // The head is saved with the records, so a damaged or deleted
        // segment can never make the agent issue a sequence number again.
        self.save_state()
    }

    fn pending(
        &mut self,
        class: Class,
        after: Option<u64>,
        max_records: usize,
        max_bytes: usize,
    ) -> Result<Vec<StoredRecord>, SpoolError> {
        let bound = match (after, self.state.acks[index(class)]) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (a, b) => a.or(b),
        };
        let ids: Vec<SegmentId> = self.segments[index(class)]
            .iter()
            .filter(|s| s.above(bound) > 0)
            .map(|s| s.id)
            .collect();
        let mut out = Vec::new();
        let mut bytes = 0usize;
        for id in ids {
            for record in self.read_segment(id)? {
                if bound.is_some_and(|b| record.seq <= b) {
                    continue;
                }
                if out.len() >= max_records
                    || (!out.is_empty() && bytes.saturating_add(record.payload.len()) > max_bytes)
                {
                    return Ok(out);
                }
                bytes = bytes.saturating_add(record.payload.len());
                out.push(record);
            }
        }
        Ok(out)
    }

    fn ack(&mut self, class: Class, seq: u64) -> Result<(), SpoolError> {
        if self.state.acks[index(class)].is_some_and(|a| a >= seq) {
            return Ok(());
        }
        let mut state = self.state;
        state.acks[index(class)] = Some(seq);
        self.write_state(state)?;
        self.delete_acked(class, seq)
    }

    fn expire(&mut self, now: i64) -> Result<Vec<Dropped>, SpoolError> {
        let age = i64::try_from(self.limits.max_age.as_micros()).unwrap_or(i64::MAX);
        let cutoff = now.saturating_sub(age);
        let mut dropped = Vec::new();
        for class in Class::ALL.into_iter().filter(|c| !c.is_protected()) {
            while self.segments[index(class)]
                .front()
                .is_some_and(|s| s.newest < cutoff)
            {
                if let Some(d) = self.evict(class, DropReason::Expired)? {
                    dropped.push(d);
                }
            }
        }
        Ok(dropped)
    }

    fn head(&self) -> Option<(u64, [u8; 32])> {
        self.state.head
    }

    fn stats(&self) -> SpoolStats {
        let mut stats = SpoolStats {
            bytes: self.bytes,
            unsynced: self.unsynced,
            ..SpoolStats::default()
        };
        for class in Class::ALL {
            let ack = self.state.acks[index(class)];
            let mut count = 0u64;
            for seg in &self.segments[index(class)] {
                let above = seg.above(ack);
                count = count.saturating_add(u64::try_from(above).unwrap_or(u64::MAX));
                if above > 0 {
                    stats.oldest_pending = Some(
                        stats
                            .oldest_pending
                            .map_or(seg.oldest, |o| o.min(seg.oldest)),
                    );
                }
            }
            if count > 0 {
                stats.pending.insert(class, count);
            }
        }
        stats
    }
}

#[cfg(test)]
mod tests;
