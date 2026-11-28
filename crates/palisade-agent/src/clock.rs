//! Wall-clock jump detection (ISM-0988).
//!
//! Every timestamp the agent records is UTC from
//! [`Clock::now_utc`], paired with
//! [`Clock::monotonic`] where
//! order matters. The wall clock can be set by a local administrator; the
//! monotonic clock cannot. Between two samples both should move by the same
//! amount. When they differ by more than [`JUMP_THRESHOLD`], the wall clock
//! was changed (or corrected by a large amount), and the agent reports it.
//!
//! [`ClockJumpDetector`] is the pure comparison. [`ClockMonitor`] is the
//! `clock` subsystem that runs it: it samples every [`SAMPLE_INTERVAL`] and
//! at once on [`HostEvent::TimeChange`]. Around a suspend it starts again
//! from a new baseline without reporting, because on some platforms the
//! monotonic clock stops while the machine sleeps and the wall clock does
//! not. Jumps are logged and published through [`ClockMonitor::subscribe`];
//! the event pipeline (#63) turns them into events.

#![forbid(unsafe_code)]

use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use palisade_core::platform::{Clock, MonotonicTime, UtcTime};
use tokio::sync::{broadcast, watch};

use crate::{
    control::{HostEvent, PowerChange},
    subsystem::{BoxFuture, Criticality, Subsystem, SubsystemContext, SubsystemError},
};

/// A disagreement between the clocks larger than this is a jump: 5 minutes.
pub const JUMP_THRESHOLD: Duration = Duration::from_secs(5 * 60);
/// How often [`ClockMonitor`] compares the clocks.
pub const SAMPLE_INTERVAL: Duration = Duration::from_secs(30);

/// A detected change of the wall clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClockJump {
    /// The wall-clock time of the previous sample.
    pub before: UtcTime,
    /// The wall-clock time of this sample.
    pub after: UtcTime,
    /// How far the wall clock moved beyond the elapsed monotonic time, in
    /// microseconds: positive forwards, negative backwards.
    pub skew_micros: i64,
}

/// Compares consecutive clock samples.
#[derive(Debug, Clone, Default)]
pub struct ClockJumpDetector {
    last: Option<(UtcTime, MonotonicTime)>,
}

impl ClockJumpDetector {
    /// A detector with no baseline yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Forgets the baseline, so the next sample only sets a new one.
    pub fn rebaseline(&mut self) {
        self.last = None;
    }

    /// Records a sample and returns the jump since the previous one, if the
    /// clocks disagree by more than [`JUMP_THRESHOLD`].
    pub fn observe(&mut self, utc: UtcTime, monotonic: MonotonicTime) -> Option<ClockJump> {
        let previous = self.last.replace((utc, monotonic));
        let (before, then) = previous?;
        let wall = i128::from(utc.0) - i128::from(before.0);
        let elapsed = i128::from(monotonic.0.saturating_sub(then.0));
        let skew = wall - elapsed;
        let threshold = i128::try_from(JUMP_THRESHOLD.as_micros()).unwrap_or(i128::MAX);
        (skew.abs() > threshold).then(|| ClockJump {
            before,
            after: utc,
            skew_micros: i64::try_from(skew).unwrap_or(if skew < 0 { i64::MIN } else { i64::MAX }),
        })
    }
}

/// The `clock` subsystem: watches for wall-clock jumps.
pub struct ClockMonitor<C> {
    clock: C,
    jumps: watch::Sender<Option<ClockJump>>,
    count: AtomicU64,
}

impl<C> std::fmt::Debug for ClockMonitor<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClockMonitor")
            .field("jumps", &self.count.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl<C: Clock + Send + Sync + 'static> ClockMonitor<C> {
    /// The subsystem's name.
    pub const NAME: &'static str = "clock";

    /// A monitor reading `clock`.
    pub fn new(clock: C) -> Self {
        Self {
            clock,
            jumps: watch::channel(None).0,
            count: AtomicU64::new(0),
        }
    }

    /// A receiver that sees the latest jump.
    pub fn subscribe(&self) -> watch::Receiver<Option<ClockJump>> {
        self.jumps.subscribe()
    }

    /// How many jumps have been detected since the agent started.
    pub fn jumps(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }

    fn sample(&self, detector: &mut ClockJumpDetector) {
        let utc = self.clock.now_utc();
        let monotonic = self.clock.monotonic();
        if let Some(jump) = detector.observe(utc, monotonic) {
            self.count.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(
                before_unix = jump.before.unix_secs(),
                after_unix = jump.after.unix_secs(),
                skew_secs = jump.skew_micros / 1_000_000,
                "the system clock jumped"
            );
            self.jumps.send_replace(Some(jump));
        }
    }
}

impl<C: Clock + Send + Sync + 'static> Subsystem for ClockMonitor<C> {
    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn criticality(&self) -> Criticality {
        Criticality::NonCritical
    }

    fn run(self: Arc<Self>, ctx: SubsystemContext) -> BoxFuture<Result<(), SubsystemError>> {
        Box::pin(async move {
            let mut events = ctx.host_events();
            let mut detector = ClockJumpDetector::new();
            self.sample(&mut detector);
            let mut ticks = tokio::time::interval(SAMPLE_INTERVAL);
            ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            ctx.set_ready();
            loop {
                tokio::select! {
                    _ = ctx.stopped() => return Ok(()),
                    _ = ticks.tick() => self.sample(&mut detector),
                    event = events.recv() => match event {
                        Ok(HostEvent::TimeChange) => self.sample(&mut detector),
                        Ok(HostEvent::Power(PowerChange::Suspend)) => detector.rebaseline(),
                        Ok(HostEvent::Power(PowerChange::Resume)) => {
                            detector.rebaseline();
                            self.sample(&mut detector);
                        }
                        Ok(_) => {}
                        // Missed events may include a time change: check now.
                        Err(broadcast::error::RecvError::Lagged(_)) => self.sample(&mut detector),
                        Err(broadcast::error::RecvError::Closed) => {
                            ctx.stopped().await;
                            return Ok(());
                        }
                    },
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIN: i64 = 60 * 1_000_000;

    fn at(utc_min: i64, mono_min: u64) -> (UtcTime, MonotonicTime) {
        (
            UtcTime(1_700_000_000_000_000 + utc_min * MIN),
            MonotonicTime(mono_min * 60 * 1_000_000),
        )
    }

    fn observe(d: &mut ClockJumpDetector, sample: (UtcTime, MonotonicTime)) -> Option<ClockJump> {
        d.observe(sample.0, sample.1)
    }

    #[test]
    fn clocks_that_agree_never_jump() {
        let mut d = ClockJumpDetector::new();
        assert_eq!(observe(&mut d, at(0, 0)), None);
        assert_eq!(observe(&mut d, at(10, 10)), None);
        // Up to the threshold, in either direction, is drift or correction.
        assert_eq!(observe(&mut d, at(25, 20)), None);
        assert_eq!(observe(&mut d, at(20, 20)), None);
    }

    #[test]
    fn a_change_beyond_five_minutes_is_a_jump_both_ways() {
        let mut d = ClockJumpDetector::new();
        observe(&mut d, at(0, 0));
        let jump = observe(&mut d, at(7, 1)).unwrap();
        assert_eq!(jump.skew_micros, 6 * MIN);
        assert_eq!(jump.before, at(0, 0).0);
        assert_eq!(jump.after, at(7, 1).0);
        // The new sample is the baseline for the next comparison.
        assert_eq!(observe(&mut d, at(8, 2)), None);
        let back = observe(&mut d, at(-60, 3)).unwrap();
        assert_eq!(back.skew_micros, -69 * MIN);
        // Exactly the threshold is not a jump.
        assert_eq!(observe(&mut d, at(-54, 4)), None);
    }

    #[test]
    fn rebaseline_drops_the_previous_sample() {
        let mut d = ClockJumpDetector::new();
        observe(&mut d, at(0, 0));
        d.rebaseline();
        assert_eq!(observe(&mut d, at(600, 1)), None);
        assert_eq!(observe(&mut d, at(601, 2)), None);
    }

    #[test]
    fn extreme_values_saturate_instead_of_overflowing() {
        let mut d = ClockJumpDetector::new();
        d.observe(UtcTime(i64::MIN), MonotonicTime(u64::MAX));
        // The monotonic clock going "backwards" counts as no time elapsed.
        let jump = d.observe(UtcTime(i64::MAX), MonotonicTime(0)).unwrap();
        assert_eq!(jump.skew_micros, i64::MAX);
        let jump = d.observe(UtcTime(i64::MIN), MonotonicTime(0)).unwrap();
        assert_eq!(jump.skew_micros, i64::MIN);
    }
}
