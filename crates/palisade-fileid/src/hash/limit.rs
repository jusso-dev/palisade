//! A bound on how many files are hashed at once (`max_parallel_hashes`,
//! #46).

#![forbid(unsafe_code)]

use std::sync::{Condvar, Mutex, PoisonError};

/// The default number of hashes allowed at once: half the CPUs, at least
/// one. The agent's CPU budget (#65) may set a lower limit.
#[must_use]
pub fn default_max_parallel_hashes() -> usize {
    let cpus = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
    (cpus / 2).max(1)
}

/// A counting semaphore for hashing. Each hash holds a [`HashPermit`] for
/// as long as it reads; [`Self::acquire`] waits while the limit is reached.
#[derive(Debug)]
pub struct HashLimiter {
    max: usize,
    running: Mutex<usize>,
    freed: Condvar,
}

impl HashLimiter {
    /// A limiter allowing `max` hashes at once (at least 1).
    #[must_use]
    pub fn new(max: usize) -> Self {
        Self {
            max: max.max(1),
            running: Mutex::new(0),
            freed: Condvar::new(),
        }
    }

    /// The limit.
    #[must_use]
    pub const fn max(&self) -> usize {
        self.max
    }

    /// Hashes running now.
    #[must_use]
    pub fn running(&self) -> usize {
        *self.running.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Waits for a free slot and takes it.
    pub fn acquire(&self) -> HashPermit<'_> {
        let mut running = self.running.lock().unwrap_or_else(PoisonError::into_inner);
        while *running >= self.max {
            running = self
                .freed
                .wait(running)
                .unwrap_or_else(PoisonError::into_inner);
        }
        *running += 1;
        HashPermit { limiter: self }
    }

    /// Takes a free slot if there is one, without waiting.
    pub fn try_acquire(&self) -> Option<HashPermit<'_>> {
        let mut running = self.running.lock().unwrap_or_else(PoisonError::into_inner);
        if *running >= self.max {
            return None;
        }
        *running += 1;
        Some(HashPermit { limiter: self })
    }
}

impl Default for HashLimiter {
    fn default() -> Self {
        Self::new(default_max_parallel_hashes())
    }
}

/// A slot taken from a [`HashLimiter`], given back when dropped.
#[derive(Debug)]
pub struct HashPermit<'a> {
    limiter: &'a HashLimiter,
}

impl Drop for HashPermit<'_> {
    fn drop(&mut self) {
        let mut running = self
            .limiter
            .running
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        *running = running.saturating_sub(1);
        drop(running);
        self.limiter.freed.notify_one();
    }
}
