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
//! - caches referrals for [`DfsCache::ttl`], and "not DFS", timeouts and
//!   failures for [`DfsCache::negative_ttl`];
//! - follows a target that is itself in a namespace up to [`MAX_HOPS`]
//!   times.
//!
//! What a cached answer may stand for is limited, so two spellings of one
//! file never resolve differently because of what was asked first:
//!
//! - A **link** referral (`\\domain\dfs\apps`) answers for every path
//!   under its entry: DFS does not allow a link below another link in one
//!   namespace. A link whose target is another namespace is a further hop.
//! - A **root** referral (`\\domain\dfs` itself) answers only for the path
//!   that was looked up. Links live below the root, so a cached root must
//!   not stand in for an unseen descendant, which may be under a link.
//! - "Not DFS" is cached for the path that was looked up, never for its
//!   share: one path outside every link says nothing about another path
//!   on the same share. No resolver gives share-wide evidence today. So
//!   each new file reached through a link costs one lookup of its target
//!   path, to see that the target is final.
//! - A timeout or failure is cached for the whole share, so a slow or dead
//!   server is not asked again on every file.
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

impl DfsReferral {
    /// Whether this is the referral of a namespace root (`\\domain\dfs`,
    /// an entry with no folder below the share) rather than of a link.
    /// See the module documentation for what each may be cached for.
    #[must_use]
    pub fn is_root(&self) -> bool {
        self.entry.components().is_empty()
    }
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

/// A cached timeout or failure, for a share.
#[derive(Debug, Clone)]
enum Negative {
    TimedOut,
    Failed(String),
}

/// A cached answer for exactly one looked-up path.
#[derive(Debug, Clone)]
enum Exact {
    /// The namespace root's referral.
    Root(Box<DfsReferral>),
    /// Not in a namespace.
    NotDfs,
}

/// A key in the eviction order.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Slot {
    Share(String),
    Path(String),
}

/// Timed, cached DFS resolution. See the module documentation.
pub struct DfsCache<R: DfsResolver> {
    resolver: Arc<R>,
    /// How long one lookup may take.
    pub timeout: Duration,
    /// How long a referral is kept.
    pub ttl: Duration,
    /// How long a "not DFS" (per path), timeout or failure (per share) is
    /// kept.
    pub negative_ttl: Duration,
    /// The most timed-out lookups left running at once.
    pub max_in_flight: usize,
    /// The most entries kept (of every kind together).
    pub max_entries: usize,
    /// Link referrals, each covering every path under its entry.
    referrals: Vec<(Instant, DfsReferral)>,
    /// Answers for exactly one path, by its folded form.
    exact: HashMap<String, (Instant, Exact)>,
    /// Timeouts and failures, by folded share.
    negatives: HashMap<String, (Instant, Negative)>,
    order: VecDeque<Slot>,
    in_flight: Arc<AtomicUsize>,
}

impl<R: DfsResolver> std::fmt::Debug for DfsCache<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DfsCache")
            .field("timeout", &self.timeout)
            .field("referrals", &self.referrals.len())
            .field("exact", &self.exact.len())
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
            exact: HashMap::new(),
            negatives: HashMap::new(),
            order: VecDeque::new(),
            in_flight: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Drops every cached answer.
    pub fn clear(&mut self) {
        self.referrals.clear();
        self.exact.clear();
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
                Ok(None) if hop == 0 => return DfsOutcome::NotDfs,
                Ok(None) => return DfsOutcome::Resolved(current),
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
        // A fresh link referral covers every path under it; the longest
        // covering entry wins.
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
        let key = path.case_folded();
        if let Some((at, answer)) = self.exact.get(&key) {
            let ttl = match answer {
                Exact::Root(_) => self.ttl,
                Exact::NotDfs => self.negative_ttl,
            };
            if now.saturating_duration_since(*at) < ttl {
                return match answer.clone() {
                    Exact::Root(r) => rebase(path, &r),
                    Exact::NotDfs => Ok(None),
                };
            }
        }
        if let Some((at, neg)) = self.negatives.get(&share) {
            if now.saturating_duration_since(*at) < self.negative_ttl {
                return Err(neg.clone());
            }
        }
        match self.lookup(path) {
            Ok(Some(r)) if path.starts_with(&r.entry) => {
                if r.is_root() {
                    self.remember(
                        Slot::Path(key),
                        Some((now, Exact::Root(Box::new(r.clone())))),
                        None,
                    );
                } else {
                    self.referrals.push((now, r.clone()));
                    self.remember(Slot::Path(key), None, None);
                }
                rebase(path, &r)
            }
            Ok(Some(_)) => {
                let neg = Negative::Failed("DFS referral does not cover the path".into());
                self.remember(Slot::Share(share), None, Some((now, neg.clone())));
                Err(neg)
            }
            Ok(None) => {
                self.remember(Slot::Path(key), Some((now, Exact::NotDfs)), None);
                Ok(None)
            }
            Err(neg) => {
                self.remember(Slot::Share(share), None, Some((now, neg.clone())));
                Err(neg)
            }
        }
    }

    /// Records an answer for one path or a share (or nothing, only
    /// counting a new link referral), evicting the oldest entries past
    /// the bound.
    fn remember(
        &mut self,
        slot: Slot,
        exact: Option<(Instant, Exact)>,
        negative: Option<(Instant, Negative)>,
    ) {
        let new = match (&slot, exact, negative) {
            (Slot::Path(k), Some(e), _) => self.exact.insert(k.clone(), e).is_none(),
            (Slot::Share(k), _, Some(n)) => self.negatives.insert(k.clone(), n).is_none(),
            _ => false,
        };
        if new {
            self.order.push_back(slot);
        }
        let len = |c: &Self| c.exact.len() + c.negatives.len() + c.referrals.len();
        while len(self) > self.max_entries.max(1) {
            match self.order.pop_front() {
                Some(Slot::Path(k)) => {
                    self.exact.remove(&k);
                }
                Some(Slot::Share(k)) => {
                    self.negatives.remove(&k);
                }
                None if !self.referrals.is_empty() => {
                    self.referrals.remove(0);
                }
                None => break,
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
        /// Every path looked up, folded.
        asked: Arc<Mutex<Vec<String>>>,
        fail: bool,
    }

    impl DfsResolver for Fake {
        fn referral(&self, path: &NormalizedPath) -> io::Result<Option<DfsReferral>> {
            *self.calls.lock().unwrap() += 1;
            self.asked.lock().unwrap().push(path.case_folded());
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
                asked: Arc::new(Mutex::new(Vec::new())),
                fail: false,
            },
            calls,
        )
    }

    /// How many lookups of paths under `prefix` (folded) the fake saw.
    fn asked_under(log: &Arc<Mutex<Vec<String>>>, prefix: &str) -> usize {
        log.lock()
            .unwrap()
            .iter()
            .filter(|p| p.starts_with(prefix))
            .count()
    }

    #[test]
    fn resolves_and_caches() {
        let (f, calls) = fake(vec![
            (r"\\corp\dfs\apps", r"\\srv1\apps$"),
            (r"\\corp\dfs\tools", r"\\srv2\x64"),
        ]);
        let log = Arc::clone(&f.asked);
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
        let before = asked_under(&log, r"\\CORP\");
        // Same prefix, different case: the namespace is not asked again.
        // (The target path is checked once, to see that it is final.)
        assert_eq!(
            c.resolve_at(&p(r"\\CORP\DFS\APPS\Other\c.exe"), now),
            DfsOutcome::Resolved(p(r"\\srv1\apps$\Other\c.exe"))
        );
        assert_eq!(asked_under(&log, r"\\CORP\"), before);
        // Not DFS, and not a UNC path.
        assert_eq!(
            c.resolve_at(&p(r"\\plain\share\x.exe"), now),
            DfsOutcome::NotDfs
        );
        assert_eq!(c.resolve_at(&p(r"C:\x.exe"), now), DfsOutcome::NotDfs);
        // The negative answer is cached for that path, in any case.
        let before = *calls.lock().unwrap();
        assert_eq!(
            c.resolve_at(&p(r"\\PLAIN\SHARE\X.EXE"), now),
            DfsOutcome::NotDfs
        );
        assert_eq!(*calls.lock().unwrap(), before);
        // After the TTL, it is asked again.
        let later = now + c.negative_ttl + Duration::from_secs(1);
        assert_eq!(
            c.resolve_at(&p(r"\\plain\share\x.exe"), later),
            DfsOutcome::NotDfs
        );
        assert_eq!(*calls.lock().unwrap(), before + 1);
    }

    #[test]
    fn a_cached_root_does_not_hide_a_child_link() {
        // The reviewer's scenario: a root and a link below it.
        let (f, calls) = fake(vec![
            (r"\\corp\dfs", r"\\ns\root"),
            (r"\\corp\dfs\apps", r"\\srv\apps"),
        ]);
        let log = Arc::clone(&f.asked);
        let mut c = DfsCache::new(f);
        let now = Instant::now();
        assert_eq!(
            c.resolve_at(&p(r"\\corp\dfs"), now),
            DfsOutcome::Resolved(p(r"\\ns\root"))
        );
        let before = *calls.lock().unwrap();
        // The link is looked up, not answered by the cached root.
        assert_eq!(
            c.resolve_at(&p(r"\\corp\dfs\apps\f"), now),
            DfsOutcome::Resolved(p(r"\\srv\apps\f"))
        );
        assert!(*calls.lock().unwrap() > before);
        // The root's own answer is still cached for the root itself.
        let before = *calls.lock().unwrap();
        assert_eq!(
            c.resolve_at(&p(r"\\CORP\DFS"), now),
            DfsOutcome::Resolved(p(r"\\ns\root"))
        );
        assert_eq!(*calls.lock().unwrap(), before);
        // A folder under the root but outside every link goes to the root
        // target, looked up for its own path.
        assert_eq!(
            c.resolve_at(&p(r"\\corp\dfs\docs\g"), now),
            DfsOutcome::Resolved(p(r"\\ns\root\docs\g"))
        );
        // The link referral now covers its subtree without a namespace
        // lookup.
        let before = asked_under(&log, r"\\CORP\");
        assert_eq!(
            c.resolve_at(&p(r"\\corp\dfs\apps\deeper\h"), now),
            DfsOutcome::Resolved(p(r"\\srv\apps\deeper\h"))
        );
        assert_eq!(asked_under(&log, r"\\CORP\"), before);
        assert!(
            DfsReferral {
                entry: p(r"\\corp\dfs"),
                target: p(r"\\ns\root")
            }
            .is_root()
        );
    }

    #[test]
    fn not_dfs_for_one_path_is_not_share_wide() {
        // The reviewer's scenario: only `apps` is a link.
        let (f, calls) = fake(vec![(r"\\corp\dfs\apps", r"\\srv\apps")]);
        let log = Arc::clone(&f.asked);
        let mut c = DfsCache::new(f);
        let now = Instant::now();
        assert_eq!(
            c.resolve_at(&p(r"\\corp\dfs\other\f"), now),
            DfsOutcome::NotDfs
        );
        let before = asked_under(&log, r"\\CORP\");
        assert_eq!(
            c.resolve_at(&p(r"\\corp\dfs\apps\f"), now),
            DfsOutcome::Resolved(p(r"\\srv\apps\f"))
        );
        // The second path was looked up itself, not answered by the first.
        assert_eq!(asked_under(&log, r"\\CORP\"), before + 1);
        // The first path's answer is still cached for itself.
        let before = *calls.lock().unwrap();
        assert_eq!(
            c.resolve_at(&p(r"\\corp\dfs\other\f"), now),
            DfsOutcome::NotDfs
        );
        assert_eq!(*calls.lock().unwrap(), before);
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
        assert!(c.exact.len() + c.negatives.len() + c.referrals.len() <= 3);
        assert_eq!(c.order.len(), c.exact.len() + c.negatives.len());
        c.clear();
        assert!(c.negatives.is_empty() && c.exact.is_empty());
    }
}
