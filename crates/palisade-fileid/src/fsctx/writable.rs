//! Cached and streaming writability assessment (#54).
//!
//! [`super::acl::assess_path`] needs every ancestor's descriptor up front.
//! This module adds what a scanner needs on top:
//!
//! - [`WritabilityCache`]: the result of [`super::acl::evaluate`] for each
//!   distinct security descriptor, keyed by the SHA-256 of its
//!   self-relative bytes and the object kind. Folders that inherit the same
//!   ACL (most of a volume) share one entry, so each distinct descriptor is
//!   evaluated once. A security-change journal record (#60) evicts by
//!   descriptor hash ([`WritabilityCache::evict`]) or clears the cache.
//! - [`assess_ancestors`]: [`super::acl::assess_path`] over an iterator of
//!   ancestors, with the cache, so the chain is not built first, and with
//!   [`AssessOptions::stop_at_first_writable`] it stops at the first
//!   user-writable folder.
//! - [`enumerate_user_writable_dirs`]: the folders under some roots that a
//!   principal set may write to, for the E8 self-test and path scanner
//!   (#17), and the path-rule guardrails (#212). It walks through a
//!   [`DirectorySource`], so it is portable and tested here; the Windows
//!   backend provides the source that reads real folders.
//!
//! Everything here is pure: no file system access happens in this module.

#![forbid(unsafe_code)]

use std::collections::{BTreeSet, HashMap, VecDeque};

use sha2::{Digest as _, Sha256};

use super::acl::{
    Ancestor, EvaluationOptions, ObjectKind, ObjectWritability, Principal, SecurityDescriptor,
    Writability, WriteRights, evaluate,
};

/// The default bound on cached descriptors.
pub const DEFAULT_CACHE_ENTRIES: usize = 4096;

/// The SHA-256 of a descriptor's self-relative bytes: the cache key.
pub type DescriptorHash = [u8; 32];

/// The cache key of `bytes`, a self-relative security descriptor as the OS
/// returned it.
#[must_use]
pub fn descriptor_hash(bytes: &[u8]) -> DescriptorHash {
    Sha256::digest(bytes).into()
}

/// A security descriptor as read from the OS, with its hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadDescriptor {
    /// The parsed descriptor.
    pub descriptor: SecurityDescriptor,
    /// [`descriptor_hash`] of the bytes it was parsed from.
    pub hash: DescriptorHash,
}

impl ReadDescriptor {
    /// Parses `bytes`. `None` if they do not parse, which a caller must
    /// treat as unreadable (possibly writable).
    #[must_use]
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        let descriptor = SecurityDescriptor::from_self_relative(bytes).ok()?;
        Some(Self {
            descriptor,
            hash: descriptor_hash(bytes),
        })
    }
}

/// Evaluation results by descriptor hash and object kind.
///
/// The results depend on the [`EvaluationOptions`] too, so a cache belongs
/// to one set of options: [`Self::evaluate`] clears it when it is called
/// with different ones.
#[derive(Debug, Clone)]
pub struct WritabilityCache {
    entries: HashMap<(DescriptorHash, ObjectKind), ObjectWritability>,
    order: VecDeque<(DescriptorHash, ObjectKind)>,
    max_entries: usize,
    options: Option<EvaluationOptions>,
    hits: u64,
    misses: u64,
}

impl Default for WritabilityCache {
    fn default() -> Self {
        Self::new(DEFAULT_CACHE_ENTRIES)
    }
}

impl WritabilityCache {
    /// A cache holding at most `max_entries` results (at least 1). The
    /// oldest entry is evicted first.
    #[must_use]
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: HashMap::new(),
            order: VecDeque::new(),
            max_entries: max_entries.max(1),
            options: None,
            hits: 0,
            misses: 0,
        }
    }

    /// [`evaluate`] of `sd` for `kind`, from the cache when possible.
    pub fn evaluate(
        &mut self,
        sd: &ReadDescriptor,
        kind: ObjectKind,
        options: &EvaluationOptions,
    ) -> ObjectWritability {
        if self.options.as_ref() != Some(options) {
            self.clear();
            self.options = Some(options.clone());
        }
        let key = (sd.hash, kind);
        if let Some(w) = self.entries.get(&key) {
            self.hits = self.hits.saturating_add(1);
            return w.clone();
        }
        self.misses = self.misses.saturating_add(1);
        let w = evaluate(&sd.descriptor, kind, options);
        if self.entries.len() >= self.max_entries {
            if let Some(old) = self.order.pop_front() {
                self.entries.remove(&old);
            }
        }
        self.entries.insert(key, w.clone());
        self.order.push_back(key);
        w
    }

    /// Drops every result for the descriptor with this hash, as a
    /// security-change journal record for a file using it requires (#60).
    pub fn evict(&mut self, hash: &DescriptorHash) {
        self.entries.retain(|(h, _), _| h != hash);
        self.order.retain(|(h, _)| h != hash);
    }

    /// Drops everything.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.order.clear();
    }

    /// The number of cached results.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the cache is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Lookups answered from the cache, and lookups that evaluated.
    #[must_use]
    pub const fn stats(&self) -> (u64, u64) {
        (self.hits, self.misses)
    }

    fn result(
        &mut self,
        sd: Option<&ReadDescriptor>,
        kind: ObjectKind,
        options: &EvaluationOptions,
    ) -> ObjectWritability {
        match sd {
            Some(sd) => self.evaluate(sd, kind, options),
            None => ObjectWritability::unreadable(kind),
        }
    }
}

/// Options for [`assess_ancestors`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AssessOptions {
    /// Stop reading ancestors once one is user-writable. The result then
    /// lists only the ancestors read, and [`Writability::principals_with_write`]
    /// and [`Writability::change_perms_by_non_admin`] cover only those; the
    /// answer to "is a path rule here safe?" is already no.
    pub stop_at_first_writable: bool,
}

/// One ancestor folder, as [`assess_ancestors`] reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AncestorRead {
    /// The folder's path, for reporting.
    pub path: String,
    /// Its descriptor, or `None` if it could not be read (counted as
    /// user-writable).
    pub descriptor: Option<ReadDescriptor>,
}

impl From<AncestorRead> for Ancestor {
    fn from(a: AncestorRead) -> Self {
        Self {
            path: a.path,
            descriptor: a.descriptor.map(|d| d.descriptor),
        }
    }
}

/// [`super::acl::assess_path`] over ancestors read one at a time (immediate
/// parent first, the volume root last), evaluated through `cache`. The
/// result is the same as `assess_path` over the same ancestors, unless
/// [`AssessOptions::stop_at_first_writable`] stopped early.
pub fn assess_ancestors<I>(
    target: Option<&ReadDescriptor>,
    kind: ObjectKind,
    ancestors: I,
    options: &EvaluationOptions,
    assess: AssessOptions,
    cache: &mut WritabilityCache,
) -> Writability
where
    I: IntoIterator<Item = AncestorRead>,
{
    let target_w = cache.result(target, kind, options);
    let mut ancestor_w = Vec::new();
    let mut first_user_writable_ancestor = None;
    for a in ancestors {
        let w = cache.result(a.descriptor.as_ref(), ObjectKind::Directory, options);
        let writable = w.user_writable();
        ancestor_w.push(w);
        if writable && first_user_writable_ancestor.is_none() {
            first_user_writable_ancestor = Some(a.path);
            if assess.stop_at_first_writable {
                break;
            }
        }
    }
    let change_perms_by_non_admin = std::iter::once(&target_w)
        .chain(&ancestor_w)
        .any(|w| w.rights.intersects(WriteRights::CHANGE_PERMISSIONS));
    let principals_with_write: Vec<Principal> = std::iter::once(&target_w)
        .chain(&ancestor_w)
        .flat_map(|w| w.principals.iter().map(|p| p.principal))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    Writability {
        file_user_writable: target_w.user_writable(),
        owner_trust_blockers: target_w
            .rights
            .intersection(WriteRights::OWNER_TRUST_BLOCKING),
        target: target_w,
        ancestors: ancestor_w,
        first_user_writable_ancestor,
        change_perms_by_non_admin,
        principals_with_write,
    }
}

/// Where [`enumerate_user_writable_dirs`] reads folders from.
pub trait DirectorySource {
    /// The error the source reports.
    type Error;

    /// The descriptor of the folder at `path`. `Ok(None)` if it cannot be
    /// read (counted as writable); `Err` stops the walk.
    fn descriptor(&mut self, path: &str) -> Result<Option<ReadDescriptor>, Self::Error>;

    /// The subfolders of `path`, as full paths. Links, junctions and mount
    /// points must not be listed: following them could leave the root or
    /// loop. A folder that cannot be listed has no subfolders here.
    fn subdirectories(&mut self, path: &str) -> Result<Vec<String>, Self::Error>;
}

/// Bounds for [`enumerate_user_writable_dirs`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnumerateOptions {
    /// The deepest level below a root that is read (the root is 0).
    pub max_depth: usize,
    /// The most folders read in total.
    pub max_dirs: usize,
    /// Do not descend into a folder found writable: everything below it is
    /// unsafe for a path rule anyway, so one entry covers it.
    pub prune_writable: bool,
}

impl Default for EnumerateOptions {
    fn default() -> Self {
        Self {
            max_depth: 32,
            max_dirs: 100_000,
            prune_writable: true,
        }
    }
}

/// One folder some principal in the set may write to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WritableDir {
    /// The folder's path.
    pub path: String,
    /// The rights the principal set may hold on it.
    pub rights: WriteRights,
    /// The subset of `rights` that is uncertain.
    pub uncertain: WriteRights,
    /// The descriptor could not be read, so writability is assumed.
    pub unreadable: bool,
}

/// The result of [`enumerate_user_writable_dirs`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WritableDirs {
    /// The writable folders, in the order found (breadth first).
    pub dirs: Vec<WritableDir>,
    /// Folders read.
    pub visited: usize,
    /// A bound in [`EnumerateOptions`] stopped the walk before every
    /// folder was read.
    pub truncated: bool,
}

/// The folders under `roots` (each a folder path, read first) that the
/// principal set in `options` may write to, as the synthetic standard user
/// of [`EvaluationOptions::standard_user`] holds them. Pass options whose
/// `standard_user` is a single user's SIDs for per-user evaluation.
///
/// A folder counts when [`ObjectWritability::standard_user`] holds any
/// write-type right, including uncertain ones. The walk is breadth first
/// and bounded by [`EnumerateOptions`]; descriptors are evaluated through
/// `cache`.
pub fn enumerate_user_writable_dirs<S: DirectorySource>(
    roots: &[String],
    source: &mut S,
    options: &EvaluationOptions,
    bounds: &EnumerateOptions,
    cache: &mut WritabilityCache,
) -> Result<WritableDirs, S::Error> {
    let mut out = WritableDirs::default();
    let mut queue: VecDeque<(String, usize)> = roots.iter().map(|r| (r.clone(), 0)).collect();
    while let Some((path, depth)) = queue.pop_front() {
        if out.visited >= bounds.max_dirs {
            out.truncated = true;
            break;
        }
        out.visited += 1;
        let sd = source.descriptor(&path)?;
        let w = cache.result(sd.as_ref(), ObjectKind::Directory, options);
        let writable = !w.standard_user.is_empty();
        if writable {
            out.dirs.push(WritableDir {
                path: path.clone(),
                rights: w.standard_user,
                uncertain: w.standard_user_uncertain,
                unreadable: w.unreadable,
            });
            if bounds.prune_writable {
                continue;
            }
        }
        if depth >= bounds.max_depth {
            if !source.subdirectories(&path)?.is_empty() {
                out.truncated = true;
            }
            continue;
        }
        for child in source.subdirectories(&path)? {
            queue.push_back((child, depth + 1));
        }
    }
    if !queue.is_empty() {
        out.truncated = true;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fsctx::acl::{Ace, assess_path, mask};
    use crate::fsctx::sid::well_known as wk;

    const RX: u32 = 0x0012_00A9;
    const MODIFY: u32 = 0x0013_01BF;

    fn read(sd: &SecurityDescriptor) -> ReadDescriptor {
        ReadDescriptor::parse(&sd.to_self_relative().unwrap()).unwrap()
    }

    fn locked() -> SecurityDescriptor {
        SecurityDescriptor::new(
            Some(wk::ADMINISTRATORS),
            Some(vec![
                Ace::allow(wk::ADMINISTRATORS, mask::FILE_ALL_ACCESS),
                Ace::allow(wk::USERS, RX),
            ]),
        )
    }

    fn open() -> SecurityDescriptor {
        SecurityDescriptor::new(
            Some(wk::ADMINISTRATORS),
            Some(vec![Ace::allow(wk::USERS, MODIFY)]),
        )
    }

    #[test]
    fn same_descriptor_is_evaluated_once() {
        let mut cache = WritabilityCache::default();
        let opts = EvaluationOptions::default();
        let a = read(&locked());
        let b = read(&locked());
        assert_eq!(a.hash, b.hash);
        let w1 = cache.evaluate(&a, ObjectKind::Directory, &opts);
        let w2 = cache.evaluate(&b, ObjectKind::Directory, &opts);
        assert_eq!(w1, w2);
        assert_eq!(cache.stats(), (1, 1));
        // Another kind is another entry.
        cache.evaluate(&a, ObjectKind::File, &opts);
        assert_eq!(cache.len(), 2);
        // Eviction by hash, as a security-change record asks.
        cache.evict(&a.hash);
        assert!(cache.is_empty());
        // Other options clear the cache.
        cache.evaluate(&a, ObjectKind::File, &opts);
        let strict = EvaluationOptions {
            admins: crate::fsctx::acl::AdminSids::os_documented(),
            ..EvaluationOptions::default()
        };
        cache.evaluate(&a, ObjectKind::File, &strict);
        assert_eq!(cache.len(), 1);
        // The bound holds.
        let mut small = WritabilityCache::new(1);
        small.evaluate(&a, ObjectKind::File, &opts);
        small.evaluate(&read(&open()), ObjectKind::File, &opts);
        assert_eq!(small.len(), 1);
        assert!(ReadDescriptor::parse(b"junk").is_none());
    }

    #[test]
    fn streaming_assessment_matches_assess_path() {
        let opts = EvaluationOptions::default();
        let chain = [
            ("C:\\a\\b", Some(locked())),
            ("C:\\a", Some(open())),
            ("C:\\", None),
        ];
        let ancestors: Vec<Ancestor> = chain
            .iter()
            .map(|(p, sd)| Ancestor {
                path: (*p).to_owned(),
                descriptor: sd.clone(),
            })
            .collect();
        let target = locked();
        let expected = assess_path(Some(&target), ObjectKind::File, &ancestors, &opts);
        let reads = chain.iter().map(|(p, sd)| AncestorRead {
            path: (*p).to_owned(),
            descriptor: sd.as_ref().map(read),
        });
        let mut cache = WritabilityCache::default();
        let got = assess_ancestors(
            Some(&read(&target)),
            ObjectKind::File,
            reads,
            &opts,
            AssessOptions::default(),
            &mut cache,
        );
        assert_eq!(got, expected);
        assert_eq!(got.first_user_writable_ancestor.as_deref(), Some("C:\\a"));

        // Stopping early reads nothing past the first writable folder.
        let mut read_count = 0;
        let reads = chain.iter().map(|(p, sd)| {
            read_count += 1;
            AncestorRead {
                path: (*p).to_owned(),
                descriptor: sd.as_ref().map(read),
            }
        });
        let early = assess_ancestors(
            Some(&read(&target)),
            ObjectKind::File,
            reads,
            &opts,
            AssessOptions {
                stop_at_first_writable: true,
            },
            &mut cache,
        );
        assert_eq!(read_count, 2);
        assert_eq!(early.ancestors.len(), 2);
        assert!(early.path_user_writable());
    }

    /// An in-memory folder tree.
    struct Tree(Vec<(&'static str, Option<SecurityDescriptor>)>);

    impl DirectorySource for Tree {
        type Error = ();
        fn descriptor(&mut self, path: &str) -> Result<Option<ReadDescriptor>, ()> {
            Ok(self
                .0
                .iter()
                .find(|(p, _)| *p == path)
                .and_then(|(_, sd)| sd.as_ref().map(read)))
        }
        fn subdirectories(&mut self, path: &str) -> Result<Vec<String>, ()> {
            let prefix = format!("{path}\\");
            Ok(self
                .0
                .iter()
                .filter(|(p, _)| {
                    p.strip_prefix(&prefix)
                        .is_some_and(|rest| !rest.is_empty() && !rest.contains('\\'))
                })
                .map(|(p, _)| (*p).to_owned())
                .collect())
        }
    }

    fn tree() -> Tree {
        Tree(vec![
            ("C:\\PF", Some(locked())),
            ("C:\\PF\\App", Some(locked())),
            ("C:\\PF\\App\\logs", Some(open())),
            ("C:\\PF\\App\\logs\\old", Some(locked())),
            ("C:\\PF\\Other", None),
            ("C:\\PF\\Safe", Some(locked())),
        ])
    }

    #[test]
    fn writable_dirs_are_found_and_pruned() {
        let mut cache = WritabilityCache::default();
        let opts = EvaluationOptions::default();
        let r = enumerate_user_writable_dirs(
            &["C:\\PF".to_owned()],
            &mut tree(),
            &opts,
            &EnumerateOptions::default(),
            &mut cache,
        )
        .unwrap();
        let paths: Vec<_> = r.dirs.iter().map(|d| d.path.as_str()).collect();
        assert_eq!(paths, ["C:\\PF\\Other", "C:\\PF\\App\\logs"]);
        assert!(r.dirs[0].unreadable);
        assert!(r.dirs[1].rights.contains(WriteRights::WRITE_DATA));
        // `logs\old` is below a writable folder, so it is not read.
        assert_eq!(r.visited, 5);
        assert!(!r.truncated);
        // The locked descriptor was evaluated once for four folders.
        assert_eq!(cache.stats().1, 2);

        // Without pruning, the folder below is read too (it is not writable).
        let r = enumerate_user_writable_dirs(
            &["C:\\PF".to_owned()],
            &mut tree(),
            &opts,
            &EnumerateOptions {
                prune_writable: false,
                ..EnumerateOptions::default()
            },
            &mut cache,
        )
        .unwrap();
        assert_eq!(r.visited, 6);
        assert_eq!(r.dirs.len(), 2);
    }

    #[test]
    fn bounds_are_reported() {
        let mut cache = WritabilityCache::default();
        let opts = EvaluationOptions::default();
        let r = enumerate_user_writable_dirs(
            &["C:\\PF".to_owned()],
            &mut tree(),
            &opts,
            &EnumerateOptions {
                max_dirs: 2,
                ..EnumerateOptions::default()
            },
            &mut cache,
        )
        .unwrap();
        assert_eq!(r.visited, 2);
        assert!(r.truncated);
        let r = enumerate_user_writable_dirs(
            &["C:\\PF".to_owned()],
            &mut tree(),
            &opts,
            &EnumerateOptions {
                max_depth: 0,
                ..EnumerateOptions::default()
            },
            &mut cache,
        )
        .unwrap();
        assert_eq!(r.visited, 1);
        assert!(r.truncated);
    }
}
