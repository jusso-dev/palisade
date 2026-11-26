//! DFS namespace resolution (#54): a path in a DFS namespace
//! (`\\domain\dfs\apps\tool.exe`) names a file on a target share
//! (`\\server\apps\tool.exe`), and rules about the file should match
//! either.
//!
//! The lookup itself is the OS's (`palisade_fileid::win::paths::OsDfs`)
//! and can block on the network for a long time, so it goes through a
//! [`DfsResolver`] and a [`DfsCache`] that:
//!
//! - gives up after a timeout ([`DEFAULT_TIMEOUT`], 2 s, as #54 asks). A
//!   lookup that times out keeps running on its own thread, so at most
//!   [`DfsCache::max_in_flight`] such threads exist at once; past that, a
//!   new lookup is reported as timed out without starting;
//! - caches each referral (namespace prefix to target) for
//!   [`DfsCache::ttl`], and each failure or "not DFS" answer per share for
//!   [`DfsCache::negative_ttl`], so a slow or missing server is not asked
//!   again on every file;
//! - follows a target that is itself in a namespace up to [`MAX_HOPS`]
//!   times.
//!
//! A cached referral answers for every path under its entry. DFS does not
//! allow a link below another link in one namespace, so no deeper referral
//! can be missed that way; a link whose target is another namespace is a
//! further hop.
//!
//! A timeout or failure is reported as such, never as "not DFS": a caller
//! must not treat an unresolved namespace path as matching no rule.

#![forbid(unsafe_code)]

use std::collections::{HashMap, VecDeque};
use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

use super::path::{NormalizedPath, Root};

/// The lookup timeout #54 asks for.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(2);

/// The most namespace-to-target steps followed for one path.
pub const MAX_HOPS: usize = 4;

/// One DFS referral: paths under `entry` are on `target`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DfsReferral {
    /// The namespace path the referral covers (`\\domain\dfs\apps`).
    pub entry: NormalizedPath,
    /// The active target it leads to (`\\server\apps`).
    pub target: NormalizedPath,
}

/// The OS lookup behind a [`DfsCache`].
pub trait DfsResolver: Send + Sync + 'static {
    /// The referral that covers the UNC path `path`, or `Ok(None)` if it
    /// is not in a DFS namespace. May block.
    fn referral(&self, path: &NormalizedPath) -> io::Result<Option<DfsReferral>>;
}

/// The result of [`DfsCache::resolve`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DfsOutcome {
    /// The path is not in a DFS namespace (or is not a UNC path).
    NotDfs,
    /// The target path.
    Resolved(NormalizedPath),
    /// The lookup did not finish in time.
    TimedOut,
    /// The lookup failed, or the target chain was too long or looped.
    Failed(String),
}

/// A cached negative answer for one share.
#[derive(Debug, Clone)]
enum Negative {
    NotDfs,
    TimedOut,
    Failed(String),
}

/// Timed, cached DFS resolution. See the module documentation.
pub struct DfsCache<R: DfsResolver> {
    resolver: Arc<R>,
    /// How long one lookup may take.
    pub timeout: Duration,
    /// How long a referral is kept.
    pub ttl: Duration,
    /// How long a "not DFS", timeout or failure is kept, per share.
    pub negative_ttl: Duration,
    /// The most timed-out lookups left running at once.
    pub max_in_flight: usize,
    /// The most entries kept (referrals and negatives together).
    pub max_entries: usize,
    referrals: Vec<(Instant, DfsReferral)>,
    negatives: HashMap<String, (Instant, Negative)>,
    order: VecDeque<String>,
    in_flight: Arc<AtomicUsize>,
}

impl<R: DfsResolver> std::fmt::Debug for DfsCache<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DfsCache")
            .field("timeout", &self.timeout)
            .field("referrals", &self.referrals.len())
            .field("negatives", &self.negatives.len())
            .finish_non_exhaustive()
    }
}

/// The share (`\\server\share`) of a UNC path, folded, as the negative
/// cache key.
fn share_key(path: &NormalizedPath) -> Option<String> {
    match path.root() {
        Root::Unc { .. } => {
            let mut key = path.case_folded();
            // `\\SERVER\SHARE\…`: everything before the fourth backslash.
            if let Some((i, _)) = key.match_indices('\\').nth(3) {
                key.truncate(i);
            }
            Some(key)
        }
        _ => None,
    }
}

impl<R: DfsResolver> DfsCache<R> {
    /// A cache over `resolver` with the defaults: a 2 s timeout, referrals
    /// kept for 5 minutes and negative answers for 1 minute, at most 4
    /// lookups left running and 1024 entries.
    #[must_use]
    pub fn new(resolver: R) -> Self {
        Self {
            resolver: Arc::new(resolver),
            timeout: DEFAULT_TIMEOUT,
            ttl: Duration::from_secs(300),
            negative_ttl: Duration::from_secs(60),
            max_in_flight: 4,
            max_entries: 1024,
            referrals: Vec::new(),
            negatives: HashMap::new(),
            order: VecDeque::new(),
            in_flight: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Drops every cached answer.
    pub fn clear(&mut self) {
        self.referrals.clear();
        self.negatives.clear();
        self.order.clear();
    }

    /// The target of `path`, following up to [`MAX_HOPS`] referrals.
    pub fn resolve(&mut self, path: &NormalizedPath) -> DfsOutcome {
        self.resolve_at(path, Instant::now())
    }

    /// As [`Self::resolve`], at the time `now` (for tests).
    pub fn resolve_at(&mut self, path: &NormalizedPath, now: Instant) -> DfsOutcome {
        let mut current = path.clone();
        // One more step than hops, to see that the last target is final.
        for hop in 0..=MAX_HOPS {
            match self.step(&current, now) {
                Ok(Some(next)) => current = next,
                Ok(None) | Err(Negative::NotDfs) if hop == 0 => return DfsOutcome::NotDfs,
                Ok(None) | Err(Negative::NotDfs) => return DfsOutcome::Resolved(current),
                Err(Negative::TimedOut) => return DfsOutcome::TimedOut,
                Err(Negative::Failed(e)) => return DfsOutcome::Failed(e),
            }
        }
        DfsOutcome::Failed("DFS referral chain too long or looping".into())
    }

    /// One referral step: the rebased path, `Ok(None)` if `path` is not
    /// in a namespace.
    fn step(
        &mut self,
        path: &NormalizedPath,
        now: Instant,
    ) -> Result<Option<NormalizedPath>, Negative> {
        let Some(share) = share_key(path) else {
            return Ok(None);
        };
        // Fresh referrals only; the longest covering entry wins.
        self.referrals
            .retain(|(at, _)| now.saturating_duration_since(*at) < self.ttl);
        let hit = self
            .referrals
            .iter()
            .filter(|(_, r)| path.starts_with(&r.entry))
            .max_by_key(|(_, r)| r.entry.components().len())
            .map(|(_, r)| r.clone());
        if let Some(r) = hit {
            return rebase(path, &r);
        }
        if let Some((at, neg)) = self.negatives.get(&share) {
            if now.saturating_duration_since(*at) < self.negative_ttl {
                return match neg {
                    Negative::NotDfs => Ok(None),
                    other => Err(other.clone()),
                };
            }
        }
        match self.lookup(path) {
            Ok(Some(r)) if path.starts_with(&r.entry) => {
                self.remember(share, None);
                self.referrals.push((now, r.clone()));
                rebase(path, &r)
            }
            Ok(Some(_)) => {
                let neg = Negative::Failed("DFS referral does not cover the path".into());
                self.remember(share, Some((now, neg.clone())));
                Err(neg)
            }
            Ok(None) => {
                self.remember(share, Some((now, Negative::NotDfs)));
                Ok(None)
            }
            Err(neg) => {
                self.remember(share, Some((now, neg.clone())));
                Err(neg)
            }
        }
    }

    /// Records a negative answer for `share` (or, with `None`, only
    /// counts a referral), evicting the oldest entries past the bound.
    fn remember(&mut self, share: String, negative: Option<(Instant, Negative)>) {
        if let Some(n) = negative {
            if self.negatives.insert(share.clone(), n).is_none() {
                self.order.push_back(share);
            }
        }
        while self.negatives.len() + self.referrals.len() > self.max_entries.max(1) {
            if let Some(old) = self.order.pop_front() {
                self.negatives.remove(&old);
            } else if !self.referrals.is_empty() {
                self.referrals.remove(0);
            } else {
                break;
            }
        }
    }

    /// The OS lookup, on its own thread, waited for at most `timeout`.
    fn lookup(&self, path: &NormalizedPath) -> Result<Option<DfsReferral>, Negative> {
        if self.in_flight.load(Ordering::Acquire) >= self.max_in_flight.max(1) {
            return Err(Negative::TimedOut);
        }
        self.in_flight.fetch_add(1, Ordering::AcqRel);
        let (tx, rx) = mpsc::channel();
        let resolver = Arc::clone(&self.resolver);
        let in_flight = Arc::clone(&self.in_flight);
        let p = path.clone();
        let spawned = std::thread::Builder::new()
            .name("palisade-dfs".into())
            .spawn(move || {
                let r = resolver.referral(&p);
                in_flight.fetch_sub(1, Ordering::AcqRel);
                let _ = tx.send(r);
            });
        if let Err(e) = spawned {
            self.in_flight.fetch_sub(1, Ordering::AcqRel);
            return Err(Negative::Failed(e.to_string()));
        }
        match rx.recv_timeout(self.timeout) {
            Ok(Ok(r)) => Ok(r),
            Ok(Err(e)) => Err(Negative::Failed(e.to_string())),
            Err(mpsc::RecvTimeoutError::Timeout) => Err(Negative::TimedOut),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                Err(Negative::Failed("DFS lookup thread ended".into()))
            }
        }
    }
}

fn rebase(path: &NormalizedPath, r: &DfsReferral) -> Result<Option<NormalizedPath>, Negative> {
    match path.rebase(&r.entry, &r.target) {
        Some(Ok(p)) => Ok(Some(p)),
        Some(Err(e)) => Err(Negative::Failed(e.to_string())),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fsctx::normalize_win32;
    use std::sync::Mutex;

    fn p(s: &str) -> NormalizedPath {
        normalize_win32(s).unwrap()
    }

    /// A fake namespace: referrals by entry, a call counter, and an
    /// optional delay.
    struct Fake {
        referrals: Vec<(&'static str, &'static str)>,
        delay: Duration,
        calls: Arc<Mutex<usize>>,
        fail: bool,
    }

    impl DfsResolver for Fake {
        fn referral(&self, path: &NormalizedPath) -> io::Result<Option<DfsReferral>> {
            *self.calls.lock().unwrap() += 1;
            std::thread::sleep(self.delay);
            if self.fail {
                return Err(io::Error::other("server unreachable"));
            }
            Ok(self
                .referrals
                .iter()
                .map(|(e, t)| (p(e), p(t)))
                .filter(|(e, _)| path.starts_with(e))
                .max_by_key(|(e, _)| e.components().len())
                .map(|(entry, target)| DfsReferral { entry, target }))
        }
    }

    fn fake(referrals: Vec<(&'static str, &'static str)>) -> (Fake, Arc<Mutex<usize>>) {
        let calls = Arc::new(Mutex::new(0));
        (
            Fake {
                referrals,
                delay: Duration::ZERO,
                calls: Arc::clone(&calls),
                fail: false,
            },
            calls,
        )
    }

    #[test]
    fn resolves_and_caches() {
        let (f, calls) = fake(vec![
            (r"\\corp\dfs\apps", r"\\srv1\apps$"),
            (r"\\corp\dfs\tools", r"\\srv2\x64"),
        ]);
        let mut c = DfsCache::new(f);
        let now = Instant::now();
        assert_eq!(
            c.resolve_at(&p(r"\\corp\dfs\apps\Tool\a.exe"), now),
            DfsOutcome::Resolved(p(r"\\srv1\apps$\Tool\a.exe"))
        );
        // A sibling link has its own referral.
        assert_eq!(
            c.resolve_at(&p(r"\\corp\dfs\tools\b.exe"), now),
            DfsOutcome::Resolved(p(r"\\srv2\x64\b.exe"))
        );
        let before = *calls.lock().unwrap();
        // Same prefix, different case: served from the cache.
        assert_eq!(
            c.resolve_at(&p(r"\\CORP\DFS\APPS\Other\c.exe"), now),
            DfsOutcome::Resolved(p(r"\\srv1\apps$\Other\c.exe"))
        );
        assert_eq!(*calls.lock().unwrap(), before);
        // Not DFS, and not a UNC path.
        assert_eq!(
            c.resolve_at(&p(r"\\plain\share\x.exe"), now),
            DfsOutcome::NotDfs
        );
        assert_eq!(c.resolve_at(&p(r"C:\x.exe"), now), DfsOutcome::NotDfs);
        // The negative answer is cached per share.
        let before = *calls.lock().unwrap();
        assert_eq!(
            c.resolve_at(&p(r"\\plain\share\y.exe"), now),
            DfsOutcome::NotDfs
        );
        assert_eq!(*calls.lock().unwrap(), before);
        // After the TTL, it is asked again.
        let later = now + c.negative_ttl + Duration::from_secs(1);
        assert_eq!(
            c.resolve_at(&p(r"\\plain\share\y.exe"), later),
            DfsOutcome::NotDfs
        );
        assert_eq!(*calls.lock().unwrap(), before + 1);
    }

    #[test]
    fn chained_and_looping_namespaces() {
        let (f, _) = fake(vec![
            (r"\\corp\dfs\apps", r"\\corp\inner\apps"),
            (r"\\corp\inner\apps", r"\\srv\apps"),
        ]);
        let mut c = DfsCache::new(f);
        assert_eq!(
            c.resolve(&p(r"\\corp\dfs\apps\a.exe")),
            DfsOutcome::Resolved(p(r"\\srv\apps\a.exe"))
        );
        let (f, _) = fake(vec![
            (r"\\a\dfs\x", r"\\b\dfs\x"),
            (r"\\b\dfs\x", r"\\a\dfs\x"),
        ]);
        let mut c = DfsCache::new(f);
        assert!(matches!(
            c.resolve(&p(r"\\a\dfs\x\f.exe")),
            DfsOutcome::Failed(_)
        ));
    }

    #[test]
    fn slow_and_failing_servers() {
        let (mut f, calls) = fake(vec![(r"\\corp\dfs\apps", r"\\srv\apps")]);
        f.delay = Duration::from_millis(500);
        let mut c = DfsCache::new(f);
        c.timeout = Duration::from_millis(20);
        let now = Instant::now();
        let started = Instant::now();
        assert_eq!(
            c.resolve_at(&p(r"\\corp\dfs\apps\a.exe"), now),
            DfsOutcome::TimedOut
        );
        assert!(started.elapsed() < Duration::from_millis(400));
        // The timeout is cached for the share: no second slow call.
        assert_eq!(
            c.resolve_at(&p(r"\\corp\dfs\apps\b.exe"), now),
            DfsOutcome::TimedOut
        );
        assert_eq!(*calls.lock().unwrap(), 1);
        // Lookups left running are bounded.
        c.max_in_flight = 1;
        assert_eq!(
            c.resolve_at(&p(r"\\other\dfs\c.exe"), now),
            DfsOutcome::TimedOut
        );
        assert_eq!(*calls.lock().unwrap(), 1, "no new thread past the bound");

        let (mut f, _) = fake(vec![]);
        f.fail = true;
        let mut c = DfsCache::new(f);
        assert!(matches!(
            c.resolve(&p(r"\\corp\dfs\a.exe")),
            DfsOutcome::Failed(_)
        ));
    }

    #[test]
    fn the_cache_is_bounded() {
        let (f, _) = fake(vec![]);
        let mut c = DfsCache::new(f);
        c.max_entries = 3;
        let now = Instant::now();
        for i in 0..10 {
            let s = format!(r"\\srv{i}\share\x.exe");
            assert_eq!(c.resolve_at(&p(&s), now), DfsOutcome::NotDfs);
        }
        assert!(c.negatives.len() + c.referrals.len() <= 3);
        c.clear();
        assert!(c.negatives.is_empty());
    }
}
