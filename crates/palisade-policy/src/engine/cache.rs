//! The decision cache (#42).
//!
//! A bounded, sharded LRU cache of decisions. Repeated launches of the same
//! file by the same principal in the same context skip evaluation.
//!
//! # Key
//!
//! [`CacheKey`] is `(file identity, object type, subject key, context key,
//! policy key)`:
//!
//! - **File identity** ([`FileIdentity`]): the volume serial, file ID,
//!   change stamp (change journal USN or last-write time) and size, or the
//!   SHA-256 when known. Any write changes the stamp, so a modified file
//!   gets a new key even before its change notification arrives.
//! - **Subject key**: a hash of the token SIDs that the policy's principal
//!   rules test, and nothing else ([`KeyPlan`]). A policy without principal
//!   rules gives every user the same key, so one entry serves them all.
//! - **Context key**: a hash of only the context facts the policy reads:
//!   the other user, device and session facts, if any rule tests them,
//!   and the device state (mode, connectivity, lockdown). Schedule slots
//!   and network location (#38) join it when they exist.
//! - **Object key**: a hash of the object's facts that do not follow from
//!   the file's identity: its path (one file can have several, through
//!   hard links), the path's alias and ACL, and the path variables. The
//!   file's content facts (hashes, signatures, version resource) follow
//!   from its identity and change stamp, and are not hashed again.
//! - **Policy key**: the snapshot's generation, which changes on every
//!   policy swap, so an entry for an older policy can never be found.
//!   The bundle's decision hash (#43) becomes this key once bundles exist.
//!
//! # Not cached
//!
//! [`cacheable`] leaves out a decision that rests on an unknown fact, one
//! with a prompt (an approval request, a custom notification, a reason
//! prompt or a re-authentication), one made during an override session,
//! one in `learning` (which must be seen by the learning pipeline every
//! time, #5), and every decision while the clock is not trusted
//! ([`super::Clock`]). Instance limits and condition timeouts (#33) are not
//! modelled by the engine yet; when they are, they join this list.
//!
//! # Invalidation
//!
//! - On a policy swap: the generation changes, and the whole cache is
//!   purged.
//! - On a write, rename or delete notification for a file
//!   ([`super::Engine::invalidate_file`]): every entry for that file.
//! - On logoff ([`super::Engine::invalidate_session`]): every entry made in
//!   that session.
//! - At a deadline ([`super::Engine::evaluate`] takes one, such as the next
//!   schedule boundary): the entry expires then.
//! - After the policy's `decision_cache_ttl_secs` (at most 86400).
//!
//! Expiry uses the monotonic clock, so setting the wall clock back cannot
//! extend an entry.
//!
//! # Size
//!
//! Each shard holds at most its share of [`CacheConfig::max_bytes`],
//! counted with [`ENTRY_OVERHEAD`] plus the heap size of the decision. The
//! least recently used entries are evicted first. Hits, misses, inserts,
//! evictions and invalidations are counted ([`CacheStats`]).

use std::collections::HashMap;
use std::hash::{BuildHasher, Hash, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::decision::{Decision, Directives};
use crate::model::{Mode, Notify, ObjectType};

/// The identity of the file a decision is about.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FileIdentity {
    /// The file on its volume, as it is now.
    File {
        /// The volume serial number.
        volume_serial: u64,
        /// The file ID on the volume (128 bits on ReFS).
        file_id: u128,
        /// The change journal USN or last-write time: anything that a write
        /// changes.
        change_stamp: u64,
        /// The size in bytes.
        size: u64,
    },
    /// The SHA-256 of the content, when it is already known.
    Sha256([u8; 32]),
}

impl FileIdentity {
    /// The volume and file ID, which identify the file across writes, for
    /// per-file invalidation. `None` for a content hash.
    #[must_use]
    pub const fn file_key(&self) -> Option<(u64, u128)> {
        match self {
            Self::File {
                volume_serial,
                file_id,
                ..
            } => Some((*volume_serial, *file_id)),
            Self::Sha256(_) => None,
        }
    }
}

/// The key of one cached decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CacheKey {
    /// The file.
    pub file: FileIdentity,
    /// The object type.
    pub object_type: ObjectType,
    /// A hash of the token SIDs the policy tests ([`KeyPlan::subject_key`]).
    pub subject: u64,
    /// A hash of the context facts the policy reads ([`KeyPlan::context_key`])
    /// and the device state.
    pub context: u64,
    /// A hash of the object's path facts ([`object_key`]).
    pub object: u64,
    /// The policy snapshot's generation.
    pub policy: u64,
}

/// Sizes and lifetimes of the cache.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CacheConfig {
    /// The most memory the entries may use, in bytes. The default is
    /// 32 MiB.
    pub max_bytes: usize,
    /// The number of shards, each with its own lock. Rounded up to a power
    /// of two.
    pub shards: usize,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_bytes: 32 << 20,
            shards: 16,
        }
    }
}

/// What the cache has done, for the hit-ratio metrics.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CacheStats {
    /// Lookups that found a live entry.
    pub hits: u64,
    /// Lookups that did not.
    pub misses: u64,
    /// Entries added.
    pub inserts: u64,
    /// Entries removed to stay within the size limit.
    pub evictions: u64,
    /// Entries removed by an invalidation or expiry.
    pub invalidations: u64,
    /// Entries held now.
    pub entries: u64,
    /// Bytes counted for the entries held now.
    pub bytes: u64,
}

impl CacheStats {
    /// Hits as a share of lookups, from 0 to 1; 0 before any lookup.
    #[must_use]
    pub fn hit_ratio(&self) -> f64 {
        let lookups = self.hits.saturating_add(self.misses);
        if lookups == 0 {
            0.0
        } else {
            // Counters stay far below 2^52, where the conversion is exact.
            #[allow(clippy::cast_precision_loss)]
            let ratio = self.hits as f64 / lookups as f64;
            ratio
        }
    }
}

/// The bytes counted for one entry besides its decision: the slot (key,
/// links, expiry), the map's entry and its control bytes, and the `Arc`
/// header, rounded up.
pub const ENTRY_OVERHEAD: usize = 2 * core::mem::size_of::<Slot>() + 64;

/// Whether a decision may be cached. See the module documentation.
#[must_use]
pub fn cacheable(decision: &Decision, rests_on_unknown: bool, session_active: bool) -> bool {
    // A decision of the unknown-application policy (#39) reads the
    // object's origin and location class and the session and device
    // state, which the key does not hold; a prompt waits for the user.
    if rests_on_unknown
        || session_active
        || decision.mode() == Mode::Learning
        || decision.unhandled()
        || decision.directives().prompt.is_some()
    {
        return false;
    }
    let d: &Directives = decision.directives();
    let prompts = d.request.is_some()
        || d.elevation.as_ref().is_some_and(|e| {
            e.reason_prompt.is_some() || e.auth != crate::model::ElevationAuth::None
        })
        || decision.effects().notify == Notify::Custom;
    !prompts
}

/// The bytes a cached decision holds: the decision itself (in its `Arc`),
/// its rule lists where they spilled to the heap, and its strings.
pub(crate) fn decision_bytes(d: &Decision) -> usize {
    let refs = core::mem::size_of::<crate::decision::RuleRef>();
    let strings =
        |v: &[String]| v.iter().map(String::capacity).sum::<usize>() + core::mem::size_of_val(v);
    let e = d.effects();
    let dir = d.directives();
    let spilled = |n: usize| {
        if n > crate::decision::RULE_REFS_INLINE {
            n * refs
        } else {
            0
        }
    };
    core::mem::size_of::<Decision>()
        + spilled(d.overridden().len())
        + spilled(d.annotations().len())
        + e.notification_text.as_ref().map_or(0, String::capacity)
        + e.help_url.as_ref().map_or(0, String::capacity)
        + strings(&e.tags)
        + dir
            .trust_sources
            .iter()
            .map(|g| core::mem::size_of_val(g) + strings(&g.scope_paths))
            .sum::<usize>()
        + dir
            .elevation
            .as_ref()
            .and_then(|e| e.reason_prompt.as_ref())
            .map_or(0, String::capacity)
}

const NIL: u32 = u32::MAX;

#[derive(Debug)]
struct Slot {
    key: CacheKey,
    decision: Arc<Decision>,
    session: Option<u32>,
    /// Monotonic microseconds at which the entry expires.
    expires: u64,
    bytes: usize,
    prev: u32,
    next: u32,
}

/// One shard: a map into an arena of slots, with an LRU list through
/// them. The most recently used slot is the head.
#[derive(Debug, Default)]
struct Shard {
    map: HashMap<CacheKey, u32>,
    slots: Vec<Option<Slot>>,
    free: Vec<u32>,
    head: u32,
    tail: u32,
    bytes: usize,
}

impl Shard {
    fn new() -> Self {
        Self {
            head: NIL,
            tail: NIL,
            ..Self::default()
        }
    }

    fn slot(&mut self, i: u32) -> Option<&mut Slot> {
        self.slots.get_mut(i as usize).and_then(Option::as_mut)
    }

    fn unlink(&mut self, i: u32) {
        let Some((prev, next)) = self.slot(i).map(|s| (s.prev, s.next)) else {
            return;
        };
        match self.slot(prev) {
            Some(p) => p.next = next,
            None => self.head = next,
        }
        match self.slot(next) {
            Some(n) => n.prev = prev,
            None => self.tail = prev,
        }
    }

    fn push_front(&mut self, i: u32) {
        let head = self.head;
        if let Some(s) = self.slot(i) {
            s.prev = NIL;
            s.next = head;
        }
        match self.slot(head) {
            Some(h) => h.prev = i,
            None => self.tail = i,
        }
        self.head = i;
    }

    fn remove(&mut self, i: u32) -> Option<Slot> {
        self.unlink(i);
        let slot = self.slots.get_mut(i as usize)?.take()?;
        self.map.remove(&slot.key);
        self.bytes = self.bytes.saturating_sub(slot.bytes);
        self.free.push(i);
        Some(slot)
    }

    fn get(&mut self, key: &CacheKey, now: u64) -> Lookup {
        let Some(&i) = self.map.get(key) else {
            return Lookup::Miss;
        };
        let expired = self.slot(i).is_none_or(|s| s.expires <= now);
        if expired {
            self.remove(i);
            return Lookup::Expired;
        }
        self.unlink(i);
        self.push_front(i);
        self.slot(i)
            .map_or(Lookup::Miss, |s| Lookup::Hit(Arc::clone(&s.decision)))
    }

    /// Inserts, evicting from the tail to stay within `budget`. Returns
    /// the number evicted, or `None` if the entry alone is larger than the
    /// budget and was not stored (nothing is evicted for it).
    fn insert(&mut self, slot: Slot, budget: usize) -> Option<u64> {
        if slot.bytes > budget {
            return None;
        }
        if let Some(&old) = self.map.get(&slot.key) {
            self.remove(old);
        }
        let mut evicted = 0;
        while self.bytes.saturating_add(slot.bytes) > budget && self.tail != NIL {
            let tail = self.tail;
            self.remove(tail);
            evicted += 1;
        }
        self.bytes = self.bytes.saturating_add(slot.bytes);
        let key = slot.key;
        let i = match self.free.pop() {
            Some(i) => {
                if let Some(s) = self.slots.get_mut(i as usize) {
                    *s = Some(slot);
                }
                i
            }
            None => {
                self.slots.push(Some(slot));
                u32::try_from(self.slots.len() - 1).unwrap_or(NIL)
            }
        };
        self.map.insert(key, i);
        self.push_front(i);
        Some(evicted)
    }

    fn retain(&mut self, mut keep: impl FnMut(&Slot) -> bool) -> u64 {
        let doomed: Vec<u32> = self
            .map
            .values()
            .copied()
            .filter(|&i| {
                self.slots
                    .get(i as usize)
                    .and_then(Option::as_ref)
                    .is_some_and(|s| !keep(s))
            })
            .collect();
        for i in &doomed {
            self.remove(*i);
        }
        u64::try_from(doomed.len()).unwrap_or(u64::MAX)
    }
}

enum Lookup {
    Hit(Arc<Decision>),
    Miss,
    Expired,
}

/// The cache. Shared by every thread that evaluates.
#[derive(Debug)]
pub struct DecisionCache {
    shards: Box<[Mutex<Shard>]>,
    budget: usize,
    hasher: std::collections::hash_map::RandomState,
    hits: AtomicU64,
    misses: AtomicU64,
    inserts: AtomicU64,
    evictions: AtomicU64,
    invalidations: AtomicU64,
}

impl DecisionCache {
    /// An empty cache.
    #[must_use]
    pub fn new(config: CacheConfig) -> Self {
        let n = config.shards.clamp(1, 1024).next_power_of_two();
        Self {
            shards: (0..n).map(|_| Mutex::new(Shard::new())).collect(),
            budget: config.max_bytes / n,
            hasher: std::collections::hash_map::RandomState::new(),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            inserts: AtomicU64::new(0),
            evictions: AtomicU64::new(0),
            invalidations: AtomicU64::new(0),
        }
    }

    fn shard(&self, key: &CacheKey) -> &Mutex<Shard> {
        // By file, so the entries of one file share a shard. The number of
        // shards is a power of two.
        let h = self.hasher.hash_one(key.file);
        let mask = u64::try_from(self.shards.len() - 1).unwrap_or(0);
        let i = usize::try_from(h & mask).unwrap_or(0);
        &self.shards[i]
    }

    fn with_shard<R>(&self, key: &CacheKey, f: impl FnOnce(&mut Shard) -> R) -> R {
        let mut guard = match self.shard(key).lock() {
            Ok(g) => g,
            // A panic while holding the lock leaves a consistent shard:
            // every mutation is completed before anything can panic.
            Err(poisoned) => poisoned.into_inner(),
        };
        f(&mut guard)
    }

    /// The live decision for `key`, if any. `now` is monotonic
    /// microseconds.
    /// Returns a shared reference, so a hit does not allocate.
    pub fn get(&self, key: &CacheKey, now: u64) -> Option<Arc<Decision>> {
        match self.with_shard(key, |s| s.get(key, now)) {
            Lookup::Hit(d) => {
                self.hits.fetch_add(1, Ordering::Relaxed);
                Some(d)
            }
            Lookup::Expired => {
                self.invalidations.fetch_add(1, Ordering::Relaxed);
                self.misses.fetch_add(1, Ordering::Relaxed);
                None
            }
            Lookup::Miss => {
                self.misses.fetch_add(1, Ordering::Relaxed);
                None
            }
        }
    }

    /// Stores a decision until `expires` (monotonic microseconds), made in
    /// `session` if it is per-session. A decision larger than one shard's
    /// share of the budget is not stored.
    pub fn insert(
        &self,
        key: CacheKey,
        decision: Arc<Decision>,
        session: Option<u32>,
        expires: u64,
    ) {
        let bytes = ENTRY_OVERHEAD.saturating_add(decision_bytes(&decision));
        let slot = Slot {
            key,
            decision,
            session,
            expires,
            bytes,
            prev: NIL,
            next: NIL,
        };
        let budget = self.budget;
        if let Some(evicted) = self.with_shard(&key, |s| s.insert(slot, budget)) {
            self.inserts.fetch_add(1, Ordering::Relaxed);
            self.evictions.fetch_add(evicted, Ordering::Relaxed);
        }
    }

    fn retain_all(&self, keep: impl Fn(&Slot) -> bool) {
        let mut removed = 0;
        for shard in &*self.shards {
            let mut guard = match shard.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            removed += guard.retain(&keep);
        }
        self.invalidations.fetch_add(removed, Ordering::Relaxed);
    }

    /// Removes every entry.
    pub fn purge(&self) {
        self.retain_all(|_| false);
    }

    /// Removes every entry for the file `(volume_serial, file_id)`, under
    /// any change stamp.
    pub fn invalidate_file(&self, volume_serial: u64, file_id: u128) {
        self.retain_all(|s| s.key.file.file_key() != Some((volume_serial, file_id)));
    }

    /// Removes every entry whose content hash is `sha256`.
    pub fn invalidate_hash(&self, sha256: &[u8; 32]) {
        self.retain_all(|s| s.key.file != FileIdentity::Sha256(*sha256));
    }

    /// Removes every entry made in `session`.
    pub fn invalidate_session(&self, session: u32) {
        self.retain_all(|s| s.session != Some(session));
    }

    /// Removes every entry of another policy generation than `current`.
    pub fn retain_generation(&self, current: u64) {
        self.retain_all(|s| s.key.policy == current);
    }

    /// The counters and current size.
    #[must_use]
    pub fn stats(&self) -> CacheStats {
        let mut entries = 0u64;
        let mut bytes = 0u64;
        for shard in &*self.shards {
            let guard = match shard.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            entries += u64::try_from(guard.map.len()).unwrap_or(u64::MAX);
            bytes += u64::try_from(guard.bytes).unwrap_or(u64::MAX);
        }
        CacheStats {
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            inserts: self.inserts.load(Ordering::Relaxed),
            evictions: self.evictions.load(Ordering::Relaxed),
            invalidations: self.invalidations.load(Ordering::Relaxed),
            entries,
            bytes,
        }
    }
}

/// A hash of the facts of an object that its file identity does not fix:
/// the path, its alias, whether its short name was resolved, its ACL
/// fact, and the path variables that path criteria expand.
#[must_use]
pub fn object_key(
    facts: &crate::facts::ObjectFacts,
    variables: &crate::facts::PathVariables,
    seed: &KeySeed,
) -> u64 {
    let mut h = seed.hasher(1);
    match &facts.path {
        None => 0u8.hash(&mut h),
        Some(p) => {
            (
                1u8,
                p.path.as_str(),
                p.short_name_unresolved,
                p.user_writable,
            )
                .hash(&mut h);
            p.alias
                .as_ref()
                .map(palisade_core::path::NormalizedPath::as_str)
                .hash(&mut h);
        }
    }
    for v in crate::facts::PathVariable::ALL {
        for base in variables.get(v) {
            base.as_str().hash(&mut h);
        }
        0xffu8.hash(&mut h);
    }
    h.finish()
}

/// What parts of the context a policy reads, so the cache key covers
/// exactly those (#42).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KeyPlan {
    /// The canonical SIDs and object IDs that principal criteria name,
    /// sorted.
    principals: Vec<String>,
    /// The principal fields that criteria test with a list of IDs.
    principal_fields: Vec<crate::model::Field>,
    /// Whether a criterion tests a principal with something other than a
    /// fixed list of IDs, so the whole principal context is keyed.
    all_principals: bool,
    /// The other context fields criteria read.
    fields: Vec<crate::model::Field>,
}

impl KeyPlan {
    /// The plan for the rules of a policy.
    #[must_use]
    pub fn of<'r>(rules: impl IntoIterator<Item = &'r crate::model::Rule>) -> Self {
        use crate::context::{normalize_principal, normalize_sid};
        use crate::model::{Field, Match, Operator};
        let mut plan = Self::default();
        let mut fields = std::collections::BTreeSet::new();
        for rule in rules {
            let mut stack = vec![&rule.match_];
            while let Some(node) = stack.pop() {
                stack.extend(node.children());
                let Match::Criterion(c) = node else {
                    continue;
                };
                if !c.field.is_context() {
                    continue;
                }
                match c.field {
                    Field::UserSid | Field::UserPrimaryGroup
                        if matches!(c.operator, Operator::Equals | Operator::NotEquals) =>
                    {
                        plan.principals
                            .extend(c.values.iter().filter_map(|v| normalize_sid(v)));
                        plan.principal_fields.push(c.field);
                    }
                    Field::UserGroups | Field::DeviceGroups
                        if matches!(c.operator, Operator::MemberOf | Operator::NotMemberOf) =>
                    {
                        plan.principals
                            .extend(c.values.iter().filter_map(|v| normalize_principal(v)));
                        plan.principal_fields.push(c.field);
                        // A member that is neither a SID nor an object ID
                        // makes `not_member_of` unknown, so whether one is
                        // present is keyed too.
                        fields.insert(c.field);
                    }
                    Field::UserSid
                    | Field::UserPrimaryGroup
                    | Field::UserGroups
                    | Field::DeviceGroups => plan.all_principals = true,
                    other => {
                        fields.insert(other);
                    }
                }
            }
        }
        plan.principals.sort();
        plan.principals.dedup();
        plan.principal_fields.sort();
        plan.principal_fields.dedup();
        plan.fields = fields.into_iter().collect();
        plan
    }

    /// A hash of the policy's principals that the context holds, and
    /// whether each principal fact was collected. Two contexts with the
    /// same key decide every principal criterion of the policy the same
    /// way. Does not allocate once the thread's buffers are warm.
    #[must_use]
    pub fn subject_key(&self, ctx: &crate::context::EvaluationContext, seed: &KeySeed) -> u64 {
        use crate::context::{normalize_principal_into, normalize_sid_into};
        use crate::model::Field;
        use crate::ops::scratch::with_buffer;
        let mut h = seed.hasher(3);
        let u = &ctx.user;
        let d = &ctx.device;
        if self.all_principals {
            with_buffer(|canon| {
                for v in [&u.sid, &u.primary_group] {
                    match v {
                        None => 0u8.hash(&mut h),
                        Some(v) if normalize_sid_into(v, canon) => {
                            (1u8, canon.as_str()).hash(&mut h)
                        }
                        Some(_) => 2u8.hash(&mut h),
                    }
                }
                for set in [&u.groups, &d.groups] {
                    match set {
                        None => 0u8.hash(&mut h),
                        Some(members) => {
                            // The set's order does not matter: combine
                            // the members' hashes with a commutative sum.
                            let mut sum = 0u64;
                            for m in members {
                                let mut e = seed.hasher(4);
                                if normalize_principal_into(m, canon) {
                                    canon.as_str().hash(&mut e);
                                } else {
                                    0xffu8.hash(&mut e);
                                }
                                sum = sum.wrapping_add(e.finish());
                            }
                            (1u8, sum, members.len()).hash(&mut h);
                        }
                    }
                }
            });
            return h.finish();
        }
        if self.principal_fields.is_empty() {
            return h.finish();
        }
        // For each principal field a criterion tests: whether it was
        // collected, whether it is malformed, and which of the named
        // principals it holds. That decides every `equals`, `not_equals`,
        // `member_of` and `not_member_of` on those principals, whatever
        // else the token holds.
        with_buffer(|canon| {
            for field in &self.principal_fields {
                match field {
                    Field::UserSid | Field::UserPrimaryGroup => {
                        let v = if *field == Field::UserSid {
                            &u.sid
                        } else {
                            &u.primary_group
                        };
                        match v {
                            None => 0u8.hash(&mut h),
                            Some(v) if normalize_sid_into(v, canon) => {
                                // Which named principal it is, if any.
                                let at = self
                                    .principals
                                    .binary_search_by(|p| p.as_str().cmp(canon))
                                    .ok();
                                (1u8, at).hash(&mut h);
                            }
                            Some(_) => 2u8.hash(&mut h),
                        }
                    }
                    _ => {
                        let set = if *field == Field::UserGroups {
                            &u.groups
                        } else {
                            &d.groups
                        };
                        match set {
                            None => 0u8.hash(&mut h),
                            Some(members) => {
                                // A bit per named principal, whether the
                                // set holds it, and whether a member is
                                // malformed. Setting a bit is idempotent, so
                                // duplicate members change nothing.
                                let mut malformed = false;
                                with_bits(self.principals.len(), |held| {
                                    for m in members {
                                        if !normalize_principal_into(m, canon) {
                                            malformed = true;
                                            continue;
                                        }
                                        if let Ok(i) = self
                                            .principals
                                            .binary_search_by(|p| p.as_str().cmp(canon))
                                            && let Some(word) = held.get_mut(i / 64)
                                        {
                                            *word |= 1 << (i % 64);
                                        }
                                    }
                                    (1u8, &*held, malformed).hash(&mut h);
                                });
                            }
                        }
                    }
                }
            }
        });
        h.finish()
    }

    /// A hash of the context facts the policy reads besides principals.
    /// Does not allocate.
    #[must_use]
    pub fn context_key(&self, ctx: &crate::context::EvaluationContext, seed: &KeySeed) -> u64 {
        use crate::model::Field;
        let mut h = seed.hasher(2);
        for field in &self.fields {
            field.hash(&mut h);
            match field {
                // The members the policy names are in the subject key, and
                // whether one is malformed too.
                Field::UserGroups | Field::DeviceGroups => {}
                // Probed facts (#329) are keyed by target, not by field:
                // the whole table is hashed, once.
                f if f.is_probe() => {}
                _ => hash_context_fact(ctx, *field, seed, &mut h),
            }
        }
        if self.fields.iter().any(|f| f.is_probe()) {
            for (key, probe) in ctx.probes.iter() {
                (key, probe).hash(&mut h);
            }
        }
        h.finish()
    }
}

fn hash_context_fact(
    ctx: &crate::context::EvaluationContext,
    field: crate::model::Field,
    seed: &KeySeed,
    h: &mut KeyHasher,
) {
    use crate::context::ContextFact;
    match ctx.fact(field) {
        None => 0u8.hash(h),
        Some(ContextFact::Text(t)) => (1u8, t).hash(h),
        Some(ContextFact::Names(a, b)) => (2u8, a, b).hash(h),
        Some(ContextFact::Set(s)) => {
            // Order-independent: a commutative sum of the members' hashes.
            let sum = s.iter().fold(0u64, |acc, m| {
                let mut e = seed.hasher(4);
                m.hash(&mut e);
                acc.wrapping_add(e.finish())
            });
            (3u8, sum, s.len()).hash(h);
        }
        Some(ContextFact::Bool(b)) => (4u8, b).hash(h),
        Some(ContextFact::Session(t)) => (5u8, t).hash(h),
        // The facts of #33's numeric, network and time criteria (#32).
        Some(ContextFact::Number(n)) => (6u8, n).hash(h),
        Some(ContextFact::Level(l)) => (7u8, l).hash(h),
        Some(ContextFact::Ip(ip)) => (8u8, ip).hash(h),
        Some(ContextFact::Ips(ips)) => (9u8, ips).hash(h),
        Some(ContextFact::Macs(macs)) => (10u8, macs).hash(h),
        Some(ContextFact::Weekday(d)) => (11u8, d).hash(h),
        Some(ContextFact::Minute(m)) => (12u8, m).hash(h),
        Some(ContextFact::Date(d)) => (13u8, d).hash(h),
        Some(ContextFact::Args(a)) => (14u8, a).hash(h),
    }
}

thread_local! {
    static BITS: core::cell::RefCell<Vec<u64>> = const { core::cell::RefCell::new(Vec::new()) };
}

/// Runs `f` with a zeroed bitset of at least `n` bits from the thread's
/// buffer, so it does not allocate once warm.
fn with_bits<R>(n: usize, f: impl FnOnce(&mut [u64]) -> R) -> R {
    let words = n.div_ceil(64);
    let mut buf = BITS.try_with(|b| b.take()).unwrap_or_default();
    buf.clear();
    buf.resize(words, 0);
    let out = f(&mut buf);
    // A huge principal list does not pin memory for the thread's life.
    if buf.capacity() <= 8 * 1024 {
        let _ = BITS.try_with(|b| *b.borrow_mut() = buf);
    }
    out
}

/// The secret key of the cache-key hashes: SipHash with a random 128-bit
/// key chosen when the engine starts, so a crafted context cannot be built
/// to collide with another.
#[derive(Clone, Debug)]
pub struct KeySeed(std::collections::hash_map::RandomState);

impl KeySeed {
    /// A new random key.
    #[must_use]
    pub fn new() -> Self {
        Self(std::collections::hash_map::RandomState::new())
    }

    /// A hasher for one part of a key; `domain` keeps the parts apart.
    fn hasher(&self, domain: u8) -> KeyHasher {
        let mut h = self.0.build_hasher();
        domain.hash(&mut h);
        KeyHasher(h)
    }
}

impl Default for KeySeed {
    fn default() -> Self {
        Self::new()
    }
}

/// A keyed 64-bit hasher for cache keys.
struct KeyHasher(std::collections::hash_map::DefaultHasher);

impl Hasher for KeyHasher {
    fn finish(&self) -> u64 {
        self.0.finish()
    }

    fn write(&mut self, bytes: &[u8]) {
        self.0.write(bytes);
    }
}
