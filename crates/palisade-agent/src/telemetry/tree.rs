//! The in-memory process tree (#59).
//!
//! Every process is keyed by its [`ProcessKey`]: the process ID **and** its
//! creation time, so a reused process ID never makes an unrelated process
//! look like a parent or an ancestor. Where the OS supplies process
//! sequence numbers (unique per boot), they are used first.
//!
//! A parent is linked only when it is provably the parent:
//!
//! - its sequence number is the one the child's start event names; or
//! - it has the parent ID the child names, was created no later than the
//!   child, and had not exited when the child was created.
//!
//! Otherwise the child has no parent in the tree. Unknown ancestry is
//! reported as unknown, never guessed (ADR 0018).
//!
//! Exited processes stay for a retention period (10 minutes by default) so
//! late events (the OS code integrity log, #58) can still be correlated,
//! then are evicted. The tree holds at most a fixed number of processes
//! (200,000 by default). When it is full, the process that exited first is
//! evicted early; if every process is still running, the new one is not
//! recorded and [`ProcessTree::rejected`] counts it.

#![forbid(unsafe_code)]

use std::collections::{HashMap, VecDeque};
use std::time::Duration;

use palisade_core::platform::{
    Elevation, GroupMembership, IntegrityLevel, MAX_ANCESTRY, ProcessKey, SessionKind, UtcTime,
};

/// The default for [`ProcessTree::new`]'s capacity.
pub const DEFAULT_CAPACITY: usize = 200_000;
/// The default retention of exited processes.
pub const DEFAULT_RETENTION: Duration = Duration::from_secs(600);

/// Whether a command line was captured, and if not, why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CommandLine {
    /// Captured, after redaction. `truncated` is set when it was cut to the
    /// length limit.
    Captured {
        /// The redacted text.
        text: String,
        /// Whether it was cut.
        truncated: bool,
    },
    /// Capture is turned off by policy.
    Disabled,
    /// The OS did not supply it (the process exited first, or refused it).
    Unavailable,
}

impl CommandLine {
    /// The text, if captured.
    #[must_use]
    pub fn text(&self) -> Option<&str> {
        match self {
            Self::Captured { text, .. } => Some(text),
            _ => None,
        }
    }
}

/// What the token of a process said, where it could be read.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TokenFacts {
    /// The user SID.
    pub user_sid: Option<String>,
    /// The token's groups.
    pub groups: Option<Vec<GroupMembership>>,
    /// The session kind.
    pub session_kind: Option<SessionKind>,
    /// The integrity level.
    pub integrity: Option<IntegrityLevel>,
    /// The elevation type.
    pub elevation: Option<Elevation>,
    /// Whether the token is elevated.
    pub elevated: Option<bool>,
}

/// One process.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcInfo {
    /// The process ID and creation time.
    pub key: ProcessKey,
    /// The OS's process sequence number, where known.
    pub sequence: Option<u64>,
    /// The parent process ID the OS recorded.
    pub parent_pid: u32,
    /// The parent, when it is provably in the tree.
    pub parent: Option<ProcessKey>,
    /// The process that created it, when that is not the recorded parent
    /// (re-parenting, or parent process ID spoofing).
    pub creator: Option<ProcessKey>,
    /// The image path as the OS reported it (usually an NT device path).
    pub image_path: String,
    /// The image path with the device resolved to a drive, where possible.
    pub image_path_normalised: Option<String>,
    /// The command line.
    pub command_line: CommandLine,
    /// The session ID.
    pub session_id: Option<u32>,
    /// Token facts.
    pub token: TokenFacts,
    /// The package full name, for packaged processes.
    pub package_full_name: Option<String>,
    /// The image header checksum, from the start event.
    pub image_checksum: Option<u32>,
    /// The image header time stamp, from the start event.
    pub time_date_stamp: Option<u32>,
    /// When it exited.
    pub end_time: Option<UtcTime>,
    /// Its exit code.
    pub exit_code: Option<u32>,
    /// Whether the agent saw it start. `false` for processes found by the
    /// startup snapshot.
    pub observed_start: bool,
}

impl ProcInfo {
    /// A process with only its identity and image known.
    #[must_use]
    pub fn new(key: ProcessKey, parent_pid: u32, image_path: String) -> Self {
        Self {
            key,
            sequence: None,
            parent_pid,
            parent: None,
            creator: None,
            image_path,
            image_path_normalised: None,
            command_line: CommandLine::Unavailable,
            session_id: None,
            token: TokenFacts::default(),
            package_full_name: None,
            image_checksum: None,
            time_date_stamp: None,
            end_time: None,
            exit_code: None,
            observed_start: false,
        }
    }

    /// The stable process key used in events: unique on the device even
    /// when the process ID is reused.
    #[must_use]
    pub fn process_key(&self) -> String {
        key_text(self.key)
    }

    /// Whether the process was running at `time`.
    #[must_use]
    pub fn alive_at(&self, time: UtcTime) -> bool {
        self.key.created <= time && self.end_time.is_none_or(|end| end >= time)
    }
}

/// The text form of a process key: `<pid>-<creation time in microseconds>`.
#[must_use]
pub fn key_text(key: ProcessKey) -> String {
    format!("{}-{}", key.pid, key.created.0)
}

/// The process tree.
#[derive(Debug)]
pub struct ProcessTree {
    procs: HashMap<ProcessKey, ProcInfo>,
    by_pid: HashMap<u32, Vec<ProcessKey>>,
    by_sequence: HashMap<u64, ProcessKey>,
    exited: VecDeque<(UtcTime, ProcessKey)>,
    capacity: usize,
    retention_micros: i64,
    rejected: u64,
}

/// The outcome of [`ProcessTree::insert`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Inserted {
    /// Recorded.
    New,
    /// Already recorded (a start event and the snapshot both saw it); the
    /// record was completed from the new one.
    Merged,
    /// The tree is full of running processes; not recorded.
    Rejected,
}

impl ProcessTree {
    /// An empty tree holding at most `capacity` processes (at least 1),
    /// keeping exited ones for `retention`.
    #[must_use]
    pub fn new(capacity: usize, retention: Duration) -> Self {
        Self {
            procs: HashMap::new(),
            by_pid: HashMap::new(),
            by_sequence: HashMap::new(),
            exited: VecDeque::new(),
            capacity: capacity.max(1),
            retention_micros: i64::try_from(retention.as_micros()).unwrap_or(i64::MAX),
            rejected: 0,
        }
    }

    /// How many processes are recorded.
    #[must_use]
    pub fn len(&self) -> usize {
        self.procs.len()
    }

    /// Whether the tree is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.procs.is_empty()
    }

    /// How many processes were not recorded because the tree was full.
    #[must_use]
    pub const fn rejected(&self) -> u64 {
        self.rejected
    }

    /// The process `key`.
    #[must_use]
    pub fn get(&self, key: ProcessKey) -> Option<&ProcInfo> {
        self.procs.get(&key)
    }

    /// The process with ID `pid` that was running at `time`, if exactly
    /// which one is known. Of several candidates (which only happens with
    /// inconsistent data), the latest created is the only one that can
    /// still have been running, so it is chosen.
    #[must_use]
    pub fn alive_at(&self, pid: u32, time: UtcTime) -> Option<&ProcInfo> {
        self.by_pid
            .get(&pid)?
            .iter()
            .filter_map(|k| self.procs.get(k))
            .filter(|p| p.alive_at(time))
            .max_by_key(|p| p.key.created)
    }

    /// The parent of a process created at `created` that names
    /// `parent_pid` (and `parent_sequence`, if known) as its parent.
    #[must_use]
    pub fn find_parent(
        &self,
        parent_pid: u32,
        parent_sequence: Option<u64>,
        created: UtcTime,
    ) -> Option<ProcessKey> {
        if parent_pid == 0 {
            return None;
        }
        if let Some(seq) = parent_sequence.filter(|&s| s != 0)
            && let Some(&key) = self.by_sequence.get(&seq)
        {
            // A sequence number is unique per boot; it still must agree
            // with the process ID, or the data is inconsistent.
            return (key.pid == parent_pid && key.created <= created).then_some(key);
        }
        self.alive_at(parent_pid, created).map(|p| p.key)
    }

    /// Records a process. Its `parent` and `creator` are kept as given; use
    /// [`ProcessTree::find_parent`] first.
    pub fn insert(&mut self, info: ProcInfo) -> Inserted {
        if let Some(existing) = self.procs.get_mut(&info.key) {
            merge(existing, info);
            if let Some(seq) = existing.sequence {
                self.by_sequence.insert(seq, existing.key);
            }
            return Inserted::Merged;
        }
        if self.procs.len() >= self.capacity && !self.evict_oldest_exited() {
            self.rejected = self.rejected.saturating_add(1);
            return Inserted::Rejected;
        }
        let key = info.key;
        if let Some(seq) = info.sequence {
            self.by_sequence.insert(seq, key);
        }
        if let Some(end) = info.end_time {
            self.exited.push_back((end, key));
        }
        self.by_pid.entry(key.pid).or_default().push(key);
        self.procs.insert(key, info);
        Inserted::New
    }

    /// Records that process `key` exited. Returns it, or `None` if it is not
    /// in the tree (or has already exited).
    pub fn exit(&mut self, key: ProcessKey, at: UtcTime, code: u32) -> Option<&ProcInfo> {
        let info = self.procs.get_mut(&key)?;
        if info.end_time.is_some() {
            return None;
        }
        info.end_time = Some(at);
        info.exit_code = Some(code);
        self.exited.push_back((at, key));
        self.procs.get(&key)
    }

    /// The ancestors of `key`, parent first, up to [`MAX_ANCESTRY`]. The
    /// walk stops at the first ancestor not in the tree, and at a loop.
    #[must_use]
    pub fn ancestry(&self, key: ProcessKey) -> Vec<ProcessKey> {
        let mut out: Vec<ProcessKey> = Vec::new();
        let mut current = self.procs.get(&key).and_then(|p| p.parent);
        while let Some(parent) = current {
            if out.len() == MAX_ANCESTRY || parent == key || out.contains(&parent) {
                break;
            }
            let Some(info) = self.procs.get(&parent) else {
                break;
            };
            out.push(parent);
            current = info.parent;
        }
        out
    }

    /// Evicts exited processes whose retention has passed at `now`.
    /// Returns how many were evicted.
    pub fn evict_expired(&mut self, now: UtcTime) -> usize {
        let mut evicted = 0;
        while let Some(&(end, key)) = self.exited.front() {
            if end.0.saturating_add(self.retention_micros) > now.0 {
                break;
            }
            self.exited.pop_front();
            if self.remove(key) {
                evicted += 1;
            }
        }
        evicted
    }

    fn evict_oldest_exited(&mut self) -> bool {
        while let Some((_, key)) = self.exited.pop_front() {
            if self.remove(key) {
                return true;
            }
        }
        false
    }

    fn remove(&mut self, key: ProcessKey) -> bool {
        let Some(info) = self.procs.remove(&key) else {
            return false;
        };
        if let Some(keys) = self.by_pid.get_mut(&key.pid) {
            keys.retain(|k| *k != key);
            if keys.is_empty() {
                self.by_pid.remove(&key.pid);
            }
        }
        if let Some(seq) = info.sequence
            && self.by_sequence.get(&seq) == Some(&key)
        {
            self.by_sequence.remove(&seq);
        }
        true
    }
}

/// Completes `existing` from `new`: a start event's facts replace the
/// snapshot's, and nothing known is ever replaced by unknown.
fn merge(existing: &mut ProcInfo, new: ProcInfo) {
    existing.observed_start |= new.observed_start;
    existing.sequence = existing.sequence.or(new.sequence);
    existing.parent = existing.parent.or(new.parent);
    existing.creator = existing.creator.or(new.creator);
    existing.image_path_normalised = existing
        .image_path_normalised
        .take()
        .or(new.image_path_normalised);
    if matches!(existing.command_line, CommandLine::Unavailable) {
        existing.command_line = new.command_line;
    }
    existing.session_id = existing.session_id.or(new.session_id);
    let t = &mut existing.token;
    t.user_sid = t.user_sid.take().or(new.token.user_sid);
    t.groups = t.groups.take().or(new.token.groups);
    t.session_kind = t.session_kind.or(new.token.session_kind);
    t.integrity = t.integrity.or(new.token.integrity);
    t.elevation = t.elevation.or(new.token.elevation);
    t.elevated = t.elevated.or(new.token.elevated);
    existing.package_full_name = existing.package_full_name.take().or(new.package_full_name);
    existing.image_checksum = existing.image_checksum.or(new.image_checksum);
    existing.time_date_stamp = existing.time_date_stamp.or(new.time_date_stamp);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(pid: u32, created: i64) -> ProcessKey {
        ProcessKey {
            pid,
            created: UtcTime(created),
        }
    }

    fn proc(pid: u32, created: i64, parent_pid: u32) -> ProcInfo {
        ProcInfo::new(key(pid, created), parent_pid, format!("p{pid}.exe"))
    }

    fn tree() -> ProcessTree {
        ProcessTree::new(DEFAULT_CAPACITY, DEFAULT_RETENTION)
    }

    /// Inserts with the parent found by the tree's own rule.
    fn spawn(t: &mut ProcessTree, pid: u32, created: i64, parent_pid: u32) -> ProcessKey {
        let mut p = proc(pid, created, parent_pid);
        p.parent = t.find_parent(parent_pid, None, UtcTime(created));
        let k = p.key;
        assert_eq!(t.insert(p), Inserted::New);
        k
    }

    #[test]
    fn ancestry_follows_parents() {
        let mut t = tree();
        let a = spawn(&mut t, 10, 1, 0);
        let b = spawn(&mut t, 20, 2, 10);
        let c = spawn(&mut t, 30, 3, 20);
        assert_eq!(t.ancestry(c), [b, a]);
        assert_eq!(t.get(c).unwrap().parent, Some(b));
        assert_eq!(t.ancestry(a), []);
        assert_eq!(t.len(), 3);
        assert!(!t.is_empty());
    }

    #[test]
    fn a_reused_parent_id_is_never_the_parent() {
        let mut t = tree();
        let old = spawn(&mut t, 100, 1, 0);
        t.exit(old, UtcTime(5), 0).unwrap();
        // A new process takes ID 100 later.
        let reused = spawn(&mut t, 100, 10, 0);
        // A child created between the exit and the reuse names 100: it has
        // no provable parent.
        let orphan = spawn(&mut t, 200, 7, 100);
        assert_eq!(t.get(orphan).unwrap().parent, None);
        // A child created after the reuse gets the new process.
        let child = spawn(&mut t, 201, 11, 100);
        assert_eq!(t.get(child).unwrap().parent, Some(reused));
        // A child created while the old one ran (a late event) gets it.
        assert_eq!(t.find_parent(100, None, UtcTime(3)), Some(old));
        // A parent created after the child is never its parent.
        assert_eq!(t.find_parent(100, None, UtcTime(0)), None);
        assert_eq!(t.find_parent(0, None, UtcTime(3)), None);
    }

    #[test]
    fn sequence_numbers_win_and_must_agree() {
        let mut t = tree();
        let mut a = proc(100, 1, 0);
        a.sequence = Some(7);
        t.insert(a);
        assert_eq!(t.find_parent(100, Some(7), UtcTime(2)), Some(key(100, 1)));
        // A sequence number that names another process ID is inconsistent.
        assert_eq!(t.find_parent(101, Some(7), UtcTime(2)), None);
        // Or a process created later.
        assert_eq!(t.find_parent(100, Some(7), UtcTime(0)), None);
        // An unknown sequence falls back to the time rule; 0 is "none".
        assert_eq!(t.find_parent(100, Some(9), UtcTime(2)), Some(key(100, 1)));
        assert_eq!(t.find_parent(100, Some(0), UtcTime(2)), Some(key(100, 1)));
    }

    #[test]
    fn loops_and_depth_are_bounded() {
        let mut t = tree();
        let mut a = proc(1, 1, 2);
        a.parent = Some(key(2, 1));
        let mut b = proc(2, 1, 1);
        b.parent = Some(key(1, 1));
        t.insert(a);
        t.insert(b);
        assert_eq!(t.ancestry(key(1, 1)), [key(2, 1)]);
        let mut self_parent = proc(3, 1, 3);
        self_parent.parent = Some(key(3, 1));
        t.insert(self_parent);
        assert_eq!(t.ancestry(key(3, 1)), []);

        let mut t = tree();
        let mut prev = spawn(&mut t, 1000, 0, 0);
        for i in 1..50 {
            prev = spawn(&mut t, 1000 + i, i64::from(i), 1000 + i - 1);
        }
        assert_eq!(t.ancestry(prev).len(), MAX_ANCESTRY);
        // An ancestor missing from the tree ends the walk.
        let mut orphan = proc(5, 1, 6);
        orphan.parent = Some(key(6, 0));
        t.insert(orphan);
        assert_eq!(t.ancestry(key(5, 1)), []);
        assert_eq!(t.ancestry(key(9999, 0)), []);
    }

    #[test]
    fn exited_processes_are_kept_then_evicted() {
        let mut t = ProcessTree::new(10, Duration::from_micros(100));
        let a = spawn(&mut t, 1, 0, 0);
        let b = spawn(&mut t, 2, 0, 0);
        assert!(t.exit(a, UtcTime(10), 3).is_some());
        assert_eq!(t.get(a).unwrap().exit_code, Some(3));
        // A second exit for the same process is ignored.
        assert!(t.exit(a, UtcTime(20), 4).is_none());
        assert!(t.exit(key(9, 9), UtcTime(20), 0).is_none());
        assert_eq!(t.evict_expired(UtcTime(109)), 0);
        assert!(t.alive_at(1, UtcTime(5)).is_some());
        assert!(t.alive_at(1, UtcTime(11)).is_none());
        assert_eq!(t.evict_expired(UtcTime(110)), 1);
        assert!(t.get(a).is_none());
        assert!(t.get(b).is_some());
        assert!(t.alive_at(1, UtcTime(5)).is_none());
    }

    #[test]
    fn a_full_tree_evicts_the_oldest_exited_or_rejects() {
        let mut t = ProcessTree::new(2, DEFAULT_RETENTION);
        let a = spawn(&mut t, 1, 0, 0);
        let mut b = proc(2, 0, 0);
        b.sequence = Some(5);
        t.insert(b);
        t.exit(a, UtcTime(1), 0);
        // Full: the exited process makes room.
        let c = spawn(&mut t, 3, 2, 0);
        assert!(t.get(a).is_none());
        assert!(t.get(c).is_some());
        // Full of running processes: rejected and counted.
        assert_eq!(t.insert(proc(4, 3, 0)), Inserted::Rejected);
        assert_eq!(t.rejected(), 1);
        // A removed process's sequence number is forgotten.
        t.exit(key(2, 0), UtcTime(4), 0);
        assert_eq!(t.evict_expired(UtcTime(i64::MAX)), 1);
        assert_eq!(t.find_parent(2, Some(5), UtcTime(9)), None);
        // An exited process inserted directly is also retained.
        let mut d = proc(6, 0, 0);
        d.end_time = Some(UtcTime(1));
        assert_eq!(t.insert(d), Inserted::New);
        assert_eq!(t.evict_expired(UtcTime(i64::MAX)), 1);
    }

    #[test]
    fn evicting_an_already_removed_entry_is_harmless() {
        let mut t = ProcessTree::new(1, DEFAULT_RETENTION);
        let a = spawn(&mut t, 1, 0, 0);
        t.exit(a, UtcTime(1), 0);
        // Merged duplicate exit entries in the queue are skipped.
        t.exited.push_back((UtcTime(1), key(77, 0)));
        t.exited.push_front((UtcTime(0), key(77, 0)));
        assert_eq!(t.insert(proc(2, 0, 0)), Inserted::New);
        assert_eq!(t.evict_expired(UtcTime(i64::MAX)), 0);
    }

    #[test]
    fn a_duplicate_merges_without_losing_facts() {
        let mut t = tree();
        let mut snap = proc(1, 1, 0);
        snap.command_line = CommandLine::Unavailable;
        snap.token.user_sid = Some("S-1-5-18".into());
        t.insert(snap);
        let mut seen = proc(1, 1, 0);
        seen.observed_start = true;
        seen.sequence = Some(3);
        seen.command_line = CommandLine::Captured {
            text: "a".into(),
            truncated: false,
        };
        seen.token.integrity = Some(IntegrityLevel::System);
        assert_eq!(t.insert(seen), Inserted::Merged);
        let p = t.get(key(1, 1)).unwrap();
        assert!(p.observed_start);
        assert_eq!(p.command_line.text(), Some("a"));
        assert_eq!(p.token.user_sid.as_deref(), Some("S-1-5-18"));
        assert_eq!(p.token.integrity, Some(IntegrityLevel::System));
        assert_eq!(t.find_parent(1, Some(3), UtcTime(2)), Some(key(1, 1)));
        // A merge with a sequence-less record keeps the index.
        assert_eq!(t.insert(proc(1, 1, 0)), Inserted::Merged);
        // A captured command line is not replaced.
        let mut other = proc(1, 1, 0);
        other.command_line = CommandLine::Disabled;
        t.insert(other);
        assert_eq!(t.get(key(1, 1)).unwrap().command_line.text(), Some("a"));
    }

    #[test]
    fn keys_have_a_stable_text_form() {
        let p = proc(42, 1_795_000_000_000_000, 0);
        assert_eq!(p.process_key(), "42-1795000000000000");
        assert_eq!(CommandLine::Disabled.text(), None);
    }
}
