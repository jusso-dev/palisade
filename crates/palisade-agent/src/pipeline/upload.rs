//! Delivery to the server (#63, #197), ready for the server
//! communication of #62 to plug in.
//!
//! - [`Uploader`] is the transport: it sends one [`Batch`] and returns the
//!   server's [`Ack`]. #62 implements it over gRPC with the HTTPS
//!   fallback (ADR 0015). [`RecordingUploader`] is the test double.
//! - [`Delivery`] decides what to send. Priority classes go first
//!   ([`Class::UPLOAD_ORDER`]), so a large backlog of allowed events never
//!   delays a block (#63). Batches hold up to 1,000 events or 1 MiB of
//!   payload. The server acknowledges the highest sequence number it has
//!   stored contiguously for the batch; anything after it is sent again
//!   (at-least-once; the server de-duplicates by `(host, seq)`).
//! - A backlog is replayed oldest first within each class, rate-limited
//!   to [`DeliverySettings::replay_per_sec`] (default 2,000 events a
//!   second) and to the server's `Throttle` answers, so a fleet that
//!   reconnects at once does not stampede the server. Priority classes are
//!   not held back by the replay limit.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use super::segment::{Class, StoredRecord};
use super::spool::Spool;

/// One upload: events of one class, in sequence order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Batch {
    /// Their class.
    pub class: Class,
    /// The events, in canonical JSON, with their sequence numbers.
    pub events: Vec<StoredRecord>,
}

impl Batch {
    /// The highest sequence number in the batch.
    #[must_use]
    pub fn last_seq(&self) -> Option<u64> {
        self.events.last().map(|r| r.seq)
    }

    /// The payload bytes.
    #[must_use]
    pub fn bytes(&self) -> usize {
        self.events.iter().map(|r| r.payload.len()).sum()
    }
}

/// The server's answer to a batch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ack {
    /// The batch's events up to and including `seq` are stored, in batch
    /// order without a gap. Events after it were not, and are sent again.
    UpTo(u64),
    /// None of the batch's events was stored; it is sent again later.
    Nothing,
    /// Nothing was stored; try again after `retry_after`.
    Throttle {
        /// How long to wait.
        retry_after: Duration,
    },
}

/// Why a batch was not delivered.
#[derive(Debug)]
pub enum UploadError {
    /// There is no connection to the server (offline, or not enrolled).
    Offline,
    /// The transport failed; it may be retried.
    Transport(String),
}

impl fmt::Display for UploadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Offline => f.write_str("no connection to the server"),
            Self::Transport(e) => write!(f, "upload failed: {e}"),
        }
    }
}

impl std::error::Error for UploadError {}

/// The transport to the server (#62).
pub trait Uploader: Send + Sync {
    /// Sends one batch. Must be idempotent: the same events may be sent
    /// again after a failure or a partial acknowledgement.
    ///
    /// # Errors
    ///
    /// The batch was not delivered.
    fn upload(&self, batch: &Batch) -> Result<Ack, UploadError>;
}

/// The uploader until server communication (#62) exists: always offline,
/// so the spool keeps everything.
#[derive(Clone, Copy, Debug, Default)]
pub struct OfflineUploader;

impl Uploader for OfflineUploader {
    fn upload(&self, _batch: &Batch) -> Result<Ack, UploadError> {
        Err(UploadError::Offline)
    }
}

/// Delivery settings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeliverySettings {
    /// Events per batch, at most. Default 1,000.
    pub batch_events: usize,
    /// Payload bytes per batch, at most (a single larger event still goes
    /// alone). Default 1 MiB.
    pub batch_bytes: usize,
    /// Non-priority events replayed per second, at most. Default 2,000.
    /// 0 removes the limit.
    pub replay_per_sec: u32,
}

impl Default for DeliverySettings {
    fn default() -> Self {
        Self {
            batch_events: 1000,
            batch_bytes: 1 << 20,
            replay_per_sec: 2000,
        }
    }
}

/// What one [`Delivery::pump`] did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Pumped {
    /// Events acknowledged, per class.
    pub acked: BTreeMap<Class, u64>,
    /// Batches sent.
    pub batches: u64,
    /// The pump stopped because the server or the transport is not
    /// available; try again later.
    pub offline: bool,
    /// The server asked to wait this long.
    pub throttled: Option<Duration>,
    /// The spool failed.
    pub spool_error: Option<String>,
}

/// Delivery state: what is in flight and the replay budget.
#[derive(Debug)]
pub struct Delivery {
    settings: DeliverySettings,
    /// Replay tokens, refilled per second of monotonic time.
    tokens: f64,
    /// The monotonic time of the last refill, in microseconds.
    refilled: Option<u64>,
    /// Do not send before this monotonic time (a server `Throttle`).
    hold_until: u64,
}

impl Delivery {
    /// Delivery with `settings`.
    #[must_use]
    pub fn new(settings: DeliverySettings) -> Self {
        Self {
            settings,
            tokens: f64::from(settings.replay_per_sec),
            refilled: None,
            hold_until: 0,
        }
    }

    fn refill(&mut self, now: u64) {
        let rate = f64::from(self.settings.replay_per_sec);
        if let Some(then) = self.refilled {
            #[expect(
                clippy::cast_precision_loss,
                reason = "elapsed microseconds; precision past 2^53 is irrelevant"
            )]
            let elapsed = now.saturating_sub(then) as f64 / 1e6;
            self.tokens = (self.tokens + elapsed * rate).min(rate);
        }
        self.refilled = Some(now);
    }

    /// Sends what is waiting in `spool` through `uploader`, priority
    /// classes first, until everything is sent, the replay budget is used,
    /// or the server is unavailable. `now` is monotonic time in
    /// microseconds.
    pub fn pump(&mut self, spool: &mut dyn Spool, uploader: &dyn Uploader, now: u64) -> Pumped {
        let mut out = Pumped::default();
        if now < self.hold_until {
            out.throttled = Some(Duration::from_micros(self.hold_until - now));
            return out;
        }
        self.refill(now);
        for class in Class::UPLOAD_ORDER {
            loop {
                let limited = !class.is_priority() && self.settings.replay_per_sec > 0;
                let mut max = self.settings.batch_events.max(1);
                if limited {
                    if self.tokens < 1.0 {
                        break;
                    }
                    #[expect(
                        clippy::cast_possible_truncation,
                        clippy::cast_sign_loss,
                        reason = "tokens is in 1..=replay_per_sec"
                    )]
                    let budget = self.tokens as usize;
                    max = max.min(budget.max(1));
                }
                let events = match spool.pending(class, None, max, self.settings.batch_bytes) {
                    Ok(events) => events,
                    Err(e) => {
                        out.spool_error = Some(e.to_string());
                        return out;
                    }
                };
                if events.is_empty() {
                    break;
                }
                let batch = Batch { class, events };
                out.batches = out.batches.saturating_add(1);
                match uploader.upload(&batch) {
                    Ok(Ack::Nothing) => {
                        // Try later rather than loop on it.
                        out.offline = true;
                        return out;
                    }
                    Ok(Ack::UpTo(seq)) => {
                        let acked = batch.events.iter().filter(|r| r.seq <= seq).count();
                        if acked == 0 {
                            out.offline = true;
                            return out;
                        }
                        if let Err(e) = spool.ack(class, seq) {
                            out.spool_error = Some(e.to_string());
                            return out;
                        }
                        let n = u64::try_from(acked).unwrap_or(u64::MAX);
                        *out.acked.entry(class).or_default() += n;
                        if limited {
                            #[expect(
                                clippy::cast_precision_loss,
                                reason = "a batch count is far below 2^53"
                            )]
                            let spent = acked as f64;
                            self.tokens = (self.tokens - spent).max(0.0);
                        }
                    }
                    Ok(Ack::Throttle { retry_after }) => {
                        let wait = u64::try_from(retry_after.as_micros()).unwrap_or(u64::MAX);
                        self.hold_until = now.saturating_add(wait);
                        out.throttled = Some(retry_after);
                        return out;
                    }
                    Err(_) => {
                        out.offline = true;
                        return out;
                    }
                }
            }
        }
        out
    }
}

/// A test double for [`Uploader`]: records every batch, and answers from a
/// script, then with full acknowledgements.
#[derive(Debug, Default)]
pub struct RecordingUploader {
    inner: std::sync::Mutex<Recording>,
}

#[derive(Debug, Default)]
struct Recording {
    batches: Vec<Batch>,
    script: std::collections::VecDeque<Scripted>,
    offline: bool,
}

/// One scripted answer of [`RecordingUploader`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scripted {
    /// Acknowledge the whole batch.
    All,
    /// Acknowledge the first `n` events of the batch.
    First(usize),
    /// Answer `Throttle`.
    Throttle(Duration),
    /// Fail with a transport error.
    Fail,
}

impl RecordingUploader {
    fn lock(&self) -> std::sync::MutexGuard<'_, Recording> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Queues answers for the next batches.
    pub fn script(&self, answers: impl IntoIterator<Item = Scripted>) {
        self.lock().script.extend(answers);
    }

    /// Goes offline (`true`) or back online.
    pub fn set_offline(&self, offline: bool) {
        self.lock().offline = offline;
    }

    /// Every batch sent so far, including ones that failed.
    #[must_use]
    pub fn batches(&self) -> Vec<Batch> {
        self.lock().batches.clone()
    }
}

impl Uploader for RecordingUploader {
    fn upload(&self, batch: &Batch) -> Result<Ack, UploadError> {
        let mut inner = self.lock();
        if inner.offline {
            return Err(UploadError::Offline);
        }
        inner.batches.push(batch.clone());
        let answer = inner.script.pop_front().unwrap_or(Scripted::All);
        let last = batch.last_seq().unwrap_or(0);
        match answer {
            Scripted::All => Ok(Ack::UpTo(last)),
            Scripted::First(n) => Ok(n
                .checked_sub(1)
                .and_then(|i| batch.events.get(i))
                .map_or(Ack::Nothing, |r| Ack::UpTo(r.seq))),
            Scripted::Throttle(retry_after) => Ok(Ack::Throttle { retry_after }),
            Scripted::Fail => Err(UploadError::Transport("scripted failure".into())),
        }
    }
}

#[cfg(test)]
mod tests;
