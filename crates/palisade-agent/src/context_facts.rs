//! The context-fact collector (#415): the probed facts (`env.*`, `reg.*`,
//! `fs.*`) and the command line a policy's rules read, collected within
//! `settings.condition_budget_ms` and the criteria's `evaluate:` cadences
//! (#329, #411).
//!
//! `palisade_policy` only evaluates the facts it is given
//! ([`EvaluationContext`], [`Probe`]); it never reads the system (ADR
//! 0003). This module is the agent's half: [`ContextCollector::collect`]
//! fills an [`EvaluationContext`] with exactly what the current policy's
//! rules reference ([`probe_targets`]), before the decision.
//!
//! # The budget
//!
//! `condition_budget_ms` is the most time collecting one rule's warm and
//! cold facts may take. Every probe of a decision starts at once, from one
//! start time, so each rule's facts are collected within one budget of it,
//! and the decision waits at most one budget however many rules probe:
//!
//! - **Cold** reads (`fs.*`, which may wait on a disk or an unavailable
//!   share) start first, each on a worker thread, never on the decision
//!   thread. The decision thread waits for them until the deadline and then
//!   stops waiting: the read is abandoned and its late result dropped. One
//!   read per target is in flight at a time (a later decision that needs
//!   the same target waits for that read), and at most
//!   [`MAX_COLD_IN_FLIGHT`] are, so a hung share cannot pile up threads.
//! - **Warm** reads (environment variables, the registry) run on the
//!   decision thread while the cold reads proceed. None starts after the
//!   deadline, and one that finishes after it is not used.
//!
//! A fact not collected by the deadline is [`Probe::TimedOut`], never
//! absent or false, so every criterion on it is unknown with the trace note
//! `condition_timeout`, and the decision is not cached (ADR 0018). A read
//! that fails (access denied, a malformed path, an unreadable hive) is left
//! out of the table, so its criteria are unknown too, without the note.
//!
//! # Cadences
//!
//! A probe whose criteria name an `evaluate:` cadence is cached until the
//! cadence says to refresh it ([`Cadence`]):
//!
//! - `once_per_session`: per logon session. [`ContextCollector::invalidate_session`]
//!   drops a session's entries at logoff, so a reused session ID starts
//!   again. Without a session ID nothing is cached.
//! - `once_per_boot`: for the life of the agent process, which a boot
//!   always restarts.
//! - `on_policy_change`: until another policy is collected for.
//!
//! A probe without a cadence is read for every decision. A probe the user
//! controls per user (environment variables, `HKCU` and `HKCR`) is cached
//! per user SID as well, and not at all when the SID is not known. A
//! timed-out or failed probe is never cached, so the next decision tries
//! again.
//!
//! # Registry hives
//!
//! `HKLM` and `HKU` are read as named. `HKCU` is the process user's hive,
//! `HKU\<sid>`. `HKCR` merges the user's classes over the machine's, as
//! Windows does per key: if `HKU\<sid>\Software\Classes\<key>` exists, it
//! answers; otherwise `HKLM\Software\Classes\<key>` does. Both need the
//! user's SID ([`UserContext::sid`](palisade_policy::context::UserContext)),
//! and without it their probes are left out.
//!
//! # Where the agent calls it
//!
//! The execution path is not wired yet (#58, #59, #113). Its seam: before
//! [`crate::policy_cache::Active::evaluate`], call
//! [`ContextCollector::collect`] with [`Active::policy`](crate::policy_cache::Active::policy),
//! the context so far, and the process's environment block and the
//! registry ([`Sources`]). If the policy is swapped between the two, the
//! new policy's probes are simply not in the table, so they are unknown.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError, Weak};
use std::time::{Duration, Instant};

use palisade_core::platform::{
    Environment, ErrorKind, FileSystem, Hive, OpenFile, Registry, RegistryValue,
    Result as PlatformResult,
};
use palisade_policy::context::probe::probe_key;
use palisade_policy::context::{
    EvaluationContext, Probe, ProbeTarget, ProcessContext, normalize_sid, probe_targets,
};
use palisade_policy::engine::Snapshot;
use palisade_policy::model::{Cadence, CostClass, Field, Match};

/// Most cold reads in flight at once. A read that cannot start is
/// [`Probe::TimedOut`].
pub const MAX_COLD_IN_FLIGHT: usize = 16;
/// Most cached probes. When full, the cache is emptied and fills again.
pub const MAX_CACHED_PROBES: usize = 4_096;
/// Longest text a probe records, in bytes. A longer environment variable or
/// registry value is [`Probe::Other`]: it exists, but no comparison applies.
pub const MAX_PROBE_TEXT_BYTES: usize = 32 * 1024;

/// What is at a file-system path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FsKind {
    /// A file.
    File,
    /// A folder.
    Folder,
}

/// The cold reads: whether a file-system path exists. Runs on worker
/// threads, so it is `Send + Sync`.
pub trait FileProbe: Send + Sync {
    /// What is at `path`, or `None` if nothing is.
    ///
    /// # Errors
    ///
    /// Any failure other than "not found": the probe is then unknown.
    fn kind(&self, path: &str) -> PlatformResult<Option<FsKind>>;
}

/// A [`FileProbe`] over a platform [`FileSystem`], such as
/// [`StdFileSystem`](crate::platform::StdFileSystem) or the Windows one.
#[derive(Clone, Copy, Debug, Default)]
pub struct Files<F>(pub F);

impl<F: FileSystem + Send + Sync> FileProbe for Files<F> {
    fn kind(&self, path: &str) -> PlatformResult<Option<FsKind>> {
        match self.0.open(path) {
            Ok(file) => Ok(Some(if file.metadata()?.is_dir {
                FsKind::Folder
            } else {
                FsKind::File
            })),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }
}

/// The warm sources of one decision.
#[derive(Clone, Copy)]
pub struct Sources<'a> {
    /// The environment block of the process being decided.
    pub env: &'a dyn Environment,
    /// The registry.
    pub registry: &'a dyn Registry,
    /// The command line of the process being decided, as captured. Used
    /// only when a rule reads `process.command_line` or `process.argv`
    /// and the context has none yet.
    pub command_line: Option<&'a str>,
}

impl core::fmt::Debug for Sources<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Sources").finish_non_exhaustive()
    }
}

/// What one [`ContextCollector::collect`] did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Collected {
    /// Probes read now.
    pub read: usize,
    /// Probes answered from the cadence cache.
    pub cached: usize,
    /// Probes recorded as [`Probe::TimedOut`], in plan order.
    pub timed_out: Vec<ProbeTarget>,
    /// Probes whose read failed, left out of the table.
    pub failed: usize,
    /// Whether the command line was filled in.
    pub command_line: bool,
}

/// What the current policy's rules read.
#[derive(Debug)]
struct Plan {
    targets: Vec<ProbeTarget>,
    process: bool,
    budget: Duration,
}

impl Plan {
    fn of(snapshot: &Snapshot) -> Self {
        let doc = snapshot.policy().document();
        // The rules the evaluator uses: enabled rules of the rule sets the
        // policy references.
        let trees: Vec<&Match> = doc
            .rule_sets
            .iter()
            .filter(|s| doc.policy.rule_sets.contains(&s.id))
            .flat_map(|s| &s.rules)
            .filter(|r| r.enabled)
            .map(|r| &r.match_)
            .collect();
        let process = trees.iter().any(|t| {
            let mut stack = vec![*t];
            while let Some(node) = stack.pop() {
                stack.extend(node.children());
                if let Match::Criterion(c) = node
                    && matches!(c.field, Field::ProcessCommandLine | Field::ProcessArgv)
                {
                    return true;
                }
            }
            false
        });
        Self {
            targets: probe_targets(trees),
            process,
            budget: Duration::from_millis(u64::from(
                doc.policy.settings.condition_budget_ms.max(1),
            )),
        }
    }
}

/// How long a cached probe is good for.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum Scope {
    Session(u32),
    Boot,
    Policy(u64),
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct CacheKey {
    probe: String,
    scope: Scope,
    /// The user, for a probe each user controls.
    sid: Option<String>,
}

/// The current policy: a weak reference keeps its allocation, so a later
/// snapshot can never be mistaken for it.
#[derive(Debug)]
struct Current {
    snapshot: Weak<Snapshot>,
    epoch: u64,
    plan: Arc<Plan>,
}

/// The outcome of one cold read.
type ColdResult = Option<Probe>;

#[derive(Debug, Default)]
struct Slot {
    result: Mutex<Option<ColdResult>>,
    ready: Condvar,
}

type InFlight = Arc<Mutex<HashMap<String, Arc<Slot>>>>;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Collects context facts for decisions. Shared by every decision thread.
pub struct ContextCollector {
    files: Arc<dyn FileProbe>,
    in_flight: InFlight,
    current: Mutex<Option<Current>>,
    cache: Mutex<HashMap<CacheKey, Probe>>,
}

impl core::fmt::Debug for ContextCollector {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ContextCollector")
            .field("in_flight", &lock(&self.in_flight).len())
            .field("cached", &lock(&self.cache).len())
            .finish_non_exhaustive()
    }
}

impl ContextCollector {
    /// A collector whose cold reads go to `files`.
    pub fn new(files: Arc<dyn FileProbe>) -> Self {
        Self {
            files,
            in_flight: Arc::default(),
            current: Mutex::new(None),
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Fills `ctx` with the facts `snapshot`'s rules read, within its
    /// `condition_budget_ms`.
    pub fn collect(
        &self,
        snapshot: &Arc<Snapshot>,
        ctx: &mut EvaluationContext,
        sources: Sources<'_>,
    ) -> Collected {
        let start = Instant::now();
        let (plan, epoch) = self.plan(snapshot);
        let deadline = start + plan.budget;
        let mut out = Collected::default();

        // The command line is already in memory: no budget applies.
        if plan.process
            && ctx.process.command_line.is_none()
            && let Some(line) = sources.command_line
        {
            ctx.process = ProcessContext::with_command_line(line);
            out.command_line = true;
        }

        let sid = ctx.user.sid.as_deref().and_then(normalize_sid);
        let session = ctx.session.id;
        let mut found: Vec<(&ProbeTarget, Probe)> = Vec::with_capacity(plan.targets.len());
        let mut warm = Vec::new();
        let mut cold = Vec::new();
        for target in &plan.targets {
            let key = cache_key(target, epoch, session, sid.as_deref());
            if let Some(probe) = key.as_ref().and_then(|k| lock(&self.cache).get(k).cloned()) {
                out.cached += 1;
                found.push((target, probe));
                continue;
            }
            if target.cost == CostClass::Cold {
                match self.start_cold(target) {
                    Some(slot) => cold.push((target, key, slot)),
                    None => found.push((target, Probe::TimedOut)),
                }
            } else {
                warm.push((target, key));
            }
        }

        for (target, key) in warm {
            if Instant::now() >= deadline {
                found.push((target, Probe::TimedOut));
                continue;
            }
            let probe = read_warm(target, sid.as_deref(), sources);
            if Instant::now() > deadline {
                found.push((target, Probe::TimedOut));
                continue;
            }
            match probe {
                Some(p) => {
                    out.read += 1;
                    self.store(key, &p);
                    found.push((target, p));
                }
                None => out.failed += 1,
            }
        }

        for (target, key, slot) in cold {
            match wait(&slot, deadline) {
                None => found.push((target, Probe::TimedOut)),
                Some(None) => out.failed += 1,
                Some(Some(p)) => {
                    out.read += 1;
                    self.store(key, &p);
                    found.push((target, p));
                }
            }
        }

        for (target, probe) in found {
            if probe == Probe::TimedOut {
                out.timed_out.push(target.clone());
            }
            ctx.probes.insert(
                target.field,
                &target.target,
                target.value_name.as_deref(),
                probe,
            );
        }
        if !out.timed_out.is_empty() {
            tracing::debug!(
                timed_out = out.timed_out.len(),
                budget_ms = plan.budget.as_millis(),
                "context facts not collected within condition_budget_ms"
            );
        }
        out
    }

    /// Drops the `once_per_session` probes of `session`, at logoff.
    pub fn invalidate_session(&self, session: u32) {
        lock(&self.cache).retain(|k, _| k.scope != Scope::Session(session));
    }

    /// How many probes are cached.
    pub fn cached_len(&self) -> usize {
        lock(&self.cache).len()
    }

    /// The plan for `snapshot`, and its policy epoch. A new policy drops
    /// the `on_policy_change` probes of the old one.
    fn plan(&self, snapshot: &Arc<Snapshot>) -> (Arc<Plan>, u64) {
        let mut current = lock(&self.current);
        if let Some(c) = current.as_ref()
            && Weak::ptr_eq(&c.snapshot, &Arc::downgrade(snapshot))
        {
            return (Arc::clone(&c.plan), c.epoch);
        }
        let epoch = current.as_ref().map_or(0, |c| c.epoch.wrapping_add(1));
        let plan = Arc::new(Plan::of(snapshot));
        *current = Some(Current {
            snapshot: Arc::downgrade(snapshot),
            epoch,
            plan: Arc::clone(&plan),
        });
        drop(current);
        lock(&self.cache).retain(|k, _| !matches!(k.scope, Scope::Policy(e) if e != epoch));
        (plan, epoch)
    }

    fn store(&self, key: Option<CacheKey>, probe: &Probe) {
        let Some(key) = key else { return };
        if *probe == Probe::TimedOut {
            return;
        }
        let mut cache = lock(&self.cache);
        if cache.len() >= MAX_CACHED_PROBES && !cache.contains_key(&key) {
            cache.clear();
        }
        cache.insert(key, probe.clone());
    }

    /// Starts the read of a cold target, or joins the one in flight.
    /// `None` if it cannot start.
    fn start_cold(&self, target: &ProbeTarget) -> Option<Arc<Slot>> {
        let key = probe_key(target.field, &target.target, None)?;
        let mut in_flight = lock(&self.in_flight);
        if let Some(slot) = in_flight.get(&key) {
            return Some(Arc::clone(slot));
        }
        if in_flight.len() >= MAX_COLD_IN_FLIGHT {
            return None;
        }
        let slot = Arc::new(Slot::default());
        in_flight.insert(key.clone(), Arc::clone(&slot));
        drop(in_flight);

        let files = Arc::clone(&self.files);
        let registry = Arc::clone(&self.in_flight);
        let worker = Arc::clone(&slot);
        let field = target.field;
        let path = target.target.clone();
        let spawned = std::thread::Builder::new()
            .name("palisade-fs-probe".into())
            .spawn(move || {
                let result = read_cold(files.as_ref(), field, &path);
                *lock(&worker.result) = Some(result);
                worker.ready.notify_all();
                let mut map = lock(&registry);
                if map.get(&key).is_some_and(|s| Arc::ptr_eq(s, &worker)) {
                    map.remove(&key);
                }
            });
        match spawned {
            Ok(_) => Some(slot),
            Err(e) => {
                tracing::warn!(error = %e, "could not start a file-system probe");
                let mut map = lock(&self.in_flight);
                if let Some(k) = probe_key(target.field, &target.target, None)
                    && map.get(&k).is_some_and(|s| Arc::ptr_eq(s, &slot))
                {
                    map.remove(&k);
                }
                None
            }
        }
    }
}

/// Waits for a cold read until `deadline`. `None` if it has not finished.
fn wait(slot: &Slot, deadline: Instant) -> Option<ColdResult> {
    let mut result = lock(&slot.result);
    loop {
        if let Some(r) = result.as_ref() {
            return Some(r.clone());
        }
        let now = Instant::now();
        if now >= deadline {
            return None;
        }
        result = slot
            .ready
            .wait_timeout(result, deadline - now)
            .unwrap_or_else(PoisonError::into_inner)
            .0;
    }
}

/// The cache key of a probe, or `None` if it is not cached.
fn cache_key(
    target: &ProbeTarget,
    epoch: u64,
    session: Option<u32>,
    sid: Option<&str>,
) -> Option<CacheKey> {
    let scope = match target.cadence? {
        Cadence::OncePerSession => Scope::Session(session?),
        Cadence::OncePerBoot => Scope::Boot,
        Cadence::OnPolicyChange => Scope::Policy(epoch),
    };
    let sid = if per_user(target) {
        Some(sid?.to_owned())
    } else {
        None
    };
    Some(CacheKey {
        probe: probe_key(target.field, &target.target, target.value_name.as_deref())?,
        scope,
        sid,
    })
}

/// Whether a probe's answer depends on the process's user.
fn per_user(target: &ProbeTarget) -> bool {
    match target.field {
        Field::EnvVar => true,
        Field::RegKey | Field::RegValue => {
            let hive = target.target.split('\\').next().unwrap_or_default();
            hive == "HKCU" || hive == "HKCR"
        }
        _ => false,
    }
}

fn read_cold(files: &dyn FileProbe, field: Field, path: &str) -> ColdResult {
    let kind = files.kind(path).ok()?;
    Some(match (field, kind) {
        (Field::FsFile, Some(FsKind::File)) | (Field::FsFolder, Some(FsKind::Folder)) => {
            Probe::Present
        }
        // A folder is not a file, nor a file a folder.
        _ => Probe::Absent,
    })
}

/// A warm read, or `None` if it failed.
fn read_warm(target: &ProbeTarget, sid: Option<&str>, sources: Sources<'_>) -> Option<Probe> {
    match target.field {
        Field::EnvVar => Some(match sources.env.var(&target.target) {
            None => Probe::Absent,
            Some(v) => text(v),
        }),
        Field::RegKey => {
            let exists = registry_lookup(&target.target, sid, |hive, path| {
                sources.registry.key_exists(hive, path)
            })?;
            Some(if exists.is_some() {
                Probe::Present
            } else {
                Probe::Absent
            })
        }
        Field::RegValue => {
            let name = target.value_name.as_deref().unwrap_or("");
            let key = registry_lookup(&target.target, sid, |hive, path| {
                sources.registry.key_exists(hive, path)
            })?;
            let Some((hive, path)) = key else {
                return Some(Probe::Absent);
            };
            Some(match sources.registry.value(hive, &path, name).ok()? {
                None => Probe::Absent,
                Some(v) => registry_probe(v),
            })
        }
        _ => None,
    }
}

/// Finds the key `target` names: `Some(Some((hive, path)))` for the key
/// that answers, `Some(None)` if none exists, `None` if it cannot be read.
/// `exists` says whether a key exists.
fn registry_lookup(
    target: &str,
    sid: Option<&str>,
    exists: impl Fn(Hive, &str) -> PlatformResult<bool>,
) -> Option<Option<(Hive, String)>> {
    let (hive, rest) = target.split_once('\\').unwrap_or((target, ""));
    let join = |prefix: &str| -> String {
        match (prefix.is_empty(), rest.is_empty()) {
            (true, _) => rest.to_owned(),
            (false, true) => prefix.to_owned(),
            (false, false) => format!("{prefix}\\{rest}"),
        }
    };
    let candidates: Vec<(Hive, String)> = match hive {
        "HKLM" => vec![(Hive::LocalMachine, join(""))],
        "HKU" => vec![(Hive::Users, join(""))],
        "HKCU" => vec![(Hive::Users, join(sid?))],
        "HKCR" => vec![
            (Hive::Users, join(&format!("{}\\software\\classes", sid?))),
            (Hive::LocalMachine, join("software\\classes")),
        ],
        _ => return None,
    };
    for (hive, path) in candidates {
        if exists(hive, &path).ok()? {
            return Some(Some((hive, path)));
        }
    }
    Some(None)
}

fn text(v: String) -> Probe {
    if v.len() > MAX_PROBE_TEXT_BYTES {
        Probe::Other
    } else {
        Probe::Text(v)
    }
}

fn registry_probe(v: RegistryValue) -> Probe {
    match v {
        RegistryValue::String(s) | RegistryValue::ExpandString(s) => text(s),
        RegistryValue::MultiString(parts) => text(parts.join("\n")),
        RegistryValue::Dword(n) => Probe::Number(u64::from(n)),
        RegistryValue::Qword(n) => Probe::Number(n),
        RegistryValue::Binary(_) => Probe::Other,
    }
}

#[cfg(test)]
mod tests;
