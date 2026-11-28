#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use std::sync::atomic::{AtomicUsize, Ordering};

use palisade_core::platform::Hive;
use palisade_core::test_util::{MockEnvironment, MockFile, MockFileSystem, MockRegistry};
use palisade_policy::decision::Outcome as DecisionOutcome;
use palisade_policy::demand::FactSet;
use palisade_policy::engine::{Engine, EngineConfig, FileIdentity, Outcome, Request, SystemClock};
use palisade_policy::evaluate::Subject;
use palisade_policy::facts::PathVariables;
use palisade_policy::mode::DeviceState;
use palisade_policy::model::{Criterion, ObjectType, Operator};
use palisade_policy::test_util::{
    PolicyBuilder, RuleBuilder, RuleSetBuilder, TRACE, all, criterion, facts, hash,
};
use palisade_policy::trace::{TraceLevel, TraceOptions, Tracer, WarningCode};
use palisade_policy::validate::ValidatedPolicy;

use super::*;

const SID: &str = "S-1-5-21-1-2-3-1001";

fn probe(field: Field, op: Operator, target: &str, cadence: Option<Cadence>) -> Match {
    let values: &[&str] = if matches!(op, Operator::Equals | Operator::Ge) {
        &["1"]
    } else {
        &[]
    };
    let mut c = Criterion::new(field, op, values.iter().copied());
    c.target = Some(target.to_owned());
    c.evaluate = cadence;
    Match::Criterion(c)
}

fn reg_value(target: &str, name: &str, value: &str) -> Match {
    let mut c = Criterion::new(Field::RegValue, Operator::Equals, [value]);
    c.target = Some(target.to_owned());
    c.value_name = Some(name.to_owned());
    Match::Criterion(c)
}

/// An allow for hash `a` that also needs `extra`, with this budget.
fn policy(extra: Vec<Match>, budget_ms: u16) -> ValidatedPolicy {
    let mut children = vec![hash('a')];
    children.extend(extra);
    let mut doc = PolicyBuilder::new()
        .rule_set(RuleSetBuilder::allowlist(1).rule(RuleBuilder::allow(1, all(children))))
        .build();
    doc.policy.settings.condition_budget_ms = budget_ms;
    doc.validate().unwrap()
}

fn snapshot(p: ValidatedPolicy) -> Arc<Snapshot> {
    Arc::new(Snapshot::new(p, 1).unwrap())
}

fn ctx() -> EvaluationContext {
    let mut c = EvaluationContext::default();
    c.user.sid = Some(SID.to_owned());
    c.session.id = Some(1);
    c
}

struct Mocks {
    env: MockEnvironment,
    reg: MockRegistry,
}

impl Mocks {
    fn new() -> Self {
        Self {
            env: MockEnvironment::new(),
            reg: MockRegistry::new(),
        }
    }

    fn sources(&self) -> Sources<'_> {
        Sources {
            env: &self.env,
            registry: &self.reg,
            command_line: Some("tool.exe --flag"),
        }
    }
}

/// A file probe that answers from a map, counting reads.
#[derive(Default)]
struct MapFiles {
    files: Mutex<HashMap<String, FsKind>>,
    reads: AtomicUsize,
}

impl MapFiles {
    fn with(self, path: &str, kind: FsKind) -> Self {
        lock(&self.files).insert(path.to_owned(), kind);
        self
    }
}

impl FileProbe for MapFiles {
    fn kind(&self, path: &str) -> PlatformResult<Option<FsKind>> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        Ok(lock(&self.files).get(path).copied())
    }
}

/// The slow-probe harness: a file probe that hangs, as a read of an
/// unavailable share does, until released.
#[derive(Default)]
struct HungFiles {
    released: Mutex<bool>,
    wake: Condvar,
    reads: AtomicUsize,
}

impl HungFiles {
    fn release(&self) {
        *lock(&self.released) = true;
        self.wake.notify_all();
    }
}

impl FileProbe for HungFiles {
    fn kind(&self, _path: &str) -> PlatformResult<Option<FsKind>> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        let mut released = lock(&self.released);
        while !*released {
            released = self
                .wake
                .wait(released)
                .unwrap_or_else(PoisonError::into_inner);
        }
        Ok(Some(FsKind::File))
    }
}

fn collector(files: Arc<dyn FileProbe>) -> ContextCollector {
    ContextCollector::new(files)
}

#[test]
fn collects_only_what_the_rules_reference() {
    let p = snapshot(policy(
        vec![
            probe(Field::EnvVar, Operator::Equals, "BUILD", None),
            probe(
                Field::RegKey,
                Operator::Exists,
                "HKLM\\Software\\Approved",
                None,
            ),
            probe(
                Field::FsFile,
                Operator::Exists,
                "C:\\flag.txt",
                Some(Cadence::OncePerBoot),
            ),
            criterion(Field::ProcessCommandLine, Operator::Contains, &["--flag"]),
        ],
        1_000,
    ));
    let mut m = Mocks::new();
    m.env.set_var("build", "1");
    m.env.set_var("OTHER", "x");
    m.reg.create_key(Hive::LocalMachine, "SOFTWARE\\Approved");
    let files = Arc::new(MapFiles::default().with("C:\\FLAG.TXT", FsKind::File));
    let c = collector(files.clone());
    let mut cx = ctx();
    let got = c.collect(&p, &mut cx, m.sources());
    assert_eq!(got.read, 3);
    assert!(got.timed_out.is_empty());
    assert!(got.command_line);
    assert_eq!(
        cx.probes.get(Field::EnvVar, "BUILD", None),
        Some(&Probe::Text("1".into()))
    );
    // Only the variable a rule names.
    assert_eq!(cx.probes.get(Field::EnvVar, "OTHER", None), None);
    assert_eq!(
        cx.probes
            .get(Field::RegKey, "HKLM\\Software\\Approved", None),
        Some(&Probe::Present)
    );
    assert_eq!(
        cx.probes.get(Field::FsFile, "C:\\flag.txt", None),
        Some(&Probe::Present)
    );
    assert_eq!(
        cx.process.args.as_deref(),
        Some(&["tool.exe".to_owned(), "--flag".to_owned()][..])
    );
}

#[test]
fn a_policy_without_probes_reads_nothing() {
    let p = snapshot(policy(vec![], 50));
    let m = Mocks::new();
    let files = Arc::new(MapFiles::default());
    let c = collector(files.clone());
    let mut cx = ctx();
    let got = c.collect(&p, &mut cx, m.sources());
    assert_eq!(got, Collected::default());
    assert!(cx.probes.is_empty());
    assert_eq!(cx.process, ProcessContext::default());
    assert_eq!(files.reads.load(Ordering::SeqCst), 0);
}

#[test]
fn an_existing_command_line_is_kept() {
    let p = snapshot(policy(
        vec![criterion(Field::ProcessArgv, Operator::Contains, &["x"])],
        50,
    ));
    let m = Mocks::new();
    let c = collector(Arc::new(MapFiles::default()));
    let mut cx = ctx();
    cx.process = ProcessContext::with_command_line("a.exe x");
    assert!(!c.collect(&p, &mut cx, m.sources()).command_line);
    assert_eq!(cx.process.command_line.as_deref(), Some("a.exe x"));
}

#[test]
fn missing_things_are_absent_and_kinds_must_match() {
    let p = snapshot(policy(
        vec![
            probe(Field::EnvVar, Operator::Exists, "NOPE", None),
            probe(
                Field::RegKey,
                Operator::Exists,
                "HKLM\\Software\\Nope",
                None,
            ),
            reg_value("HKLM\\Software\\Nope", "v", "1"),
            probe(
                Field::FsFile,
                Operator::Exists,
                "C:\\dir",
                Some(Cadence::OncePerBoot),
            ),
            probe(
                Field::FsFolder,
                Operator::Exists,
                "C:\\file.txt",
                Some(Cadence::OncePerBoot),
            ),
        ],
        1_000,
    ));
    let m = Mocks::new();
    let files = MapFiles::default()
        .with("C:\\DIR", FsKind::Folder)
        .with("C:\\FILE.TXT", FsKind::File);
    let c = collector(Arc::new(files));
    let mut cx = ctx();
    c.collect(&p, &mut cx, m.sources());
    for (field, target, name) in [
        (Field::EnvVar, "NOPE", None),
        (Field::RegKey, "HKLM\\Software\\Nope", None),
        (Field::RegValue, "HKLM\\Software\\Nope", Some("v")),
        (Field::FsFile, "C:\\dir", None),
        (Field::FsFolder, "C:\\file.txt", None),
    ] {
        assert_eq!(
            cx.probes.get(field, target, name),
            Some(&Probe::Absent),
            "{field:?} {target}"
        );
    }
}

#[test]
fn registry_values_map_to_probes() {
    let p = snapshot(policy(
        vec![
            reg_value("HKLM\\Software\\V", "s", "x"),
            reg_value("HKLM\\Software\\V", "e", "x"),
            reg_value("HKLM\\Software\\V", "m", "x"),
            reg_value("HKLM\\Software\\V", "d", "x"),
            reg_value("HKLM\\Software\\V", "q", "x"),
            reg_value("HKLM\\Software\\V", "b", "x"),
            reg_value("HKLM\\Software\\V", "long", "x"),
            reg_value("HKLM\\Software\\V", "missing", "x"),
        ],
        1_000,
    ));
    let mut m = Mocks::new();
    let k = "SOFTWARE\\V";
    m.reg.set_value(
        Hive::LocalMachine,
        k,
        "S",
        RegistryValue::String("a".into()),
    );
    m.reg.set_value(
        Hive::LocalMachine,
        k,
        "e",
        RegistryValue::ExpandString("%X%".into()),
    );
    m.reg.set_value(
        Hive::LocalMachine,
        k,
        "m",
        RegistryValue::MultiString(vec!["a".into(), "b".into()]),
    );
    m.reg
        .set_value(Hive::LocalMachine, k, "d", RegistryValue::Dword(7));
    m.reg
        .set_value(Hive::LocalMachine, k, "q", RegistryValue::Qword(1 << 40));
    m.reg
        .set_value(Hive::LocalMachine, k, "b", RegistryValue::Binary(vec![1]));
    m.reg.set_value(
        Hive::LocalMachine,
        k,
        "long",
        RegistryValue::String("x".repeat(MAX_PROBE_TEXT_BYTES + 1)),
    );
    let c = collector(Arc::new(MapFiles::default()));
    let mut cx = ctx();
    c.collect(&p, &mut cx, m.sources());
    let get = |n: &str| {
        cx.probes
            .get(Field::RegValue, "HKLM\\Software\\V", Some(n))
            .cloned()
    };
    assert_eq!(get("s"), Some(Probe::Text("a".into())));
    assert_eq!(get("e"), Some(Probe::Text("%X%".into())));
    assert_eq!(get("m"), Some(Probe::Text("a\nb".into())));
    assert_eq!(get("d"), Some(Probe::Number(7)));
    assert_eq!(get("q"), Some(Probe::Number(1 << 40)));
    assert_eq!(get("b"), Some(Probe::Other));
    assert_eq!(get("long"), Some(Probe::Other));
    assert_eq!(get("missing"), Some(Probe::Absent));
}

#[test]
fn a_long_environment_variable_is_other() {
    let p = snapshot(policy(
        vec![probe(Field::EnvVar, Operator::Exists, "BIG", None)],
        1_000,
    ));
    let mut m = Mocks::new();
    m.env.set_var("BIG", &"x".repeat(MAX_PROBE_TEXT_BYTES + 1));
    let c = collector(Arc::new(MapFiles::default()));
    let mut cx = ctx();
    c.collect(&p, &mut cx, m.sources());
    assert_eq!(
        cx.probes.get(Field::EnvVar, "BIG", None),
        Some(&Probe::Other)
    );
}

#[test]
fn user_hives_resolve_through_the_sid() {
    let p = snapshot(policy(
        vec![
            probe(
                Field::RegKey,
                Operator::Exists,
                "HKCU\\Software\\Mine",
                None,
            ),
            probe(Field::RegKey, Operator::Exists, "HKCR\\.user", None),
            probe(Field::RegKey, Operator::Exists, "HKCR\\.machine", None),
            reg_value("HKCR\\.both", "", "user"),
            probe(
                Field::RegKey,
                Operator::Exists,
                &format!("HKU\\{SID}\\Software\\Mine"),
                None,
            ),
        ],
        1_000,
    ));
    let mut m = Mocks::new();
    let user = |p: &str| format!("{}\\{p}", SID.to_lowercase());
    m.reg.create_key(Hive::Users, &user("software\\mine"));
    m.reg
        .create_key(Hive::Users, &user("software\\classes\\.user"));
    m.reg
        .create_key(Hive::LocalMachine, "software\\classes\\.machine");
    m.reg.set_value(
        Hive::Users,
        &user("software\\classes\\.both"),
        "",
        RegistryValue::String("user".into()),
    );
    m.reg.set_value(
        Hive::LocalMachine,
        "software\\classes\\.both",
        "",
        RegistryValue::String("machine".into()),
    );
    let c = collector(Arc::new(MapFiles::default()));
    let mut cx = ctx();
    c.collect(&p, &mut cx, m.sources());
    for t in [
        "HKCU\\Software\\Mine",
        "HKCR\\.user",
        "HKCR\\.machine",
        &format!("HKU\\{SID}\\Software\\Mine"),
    ] {
        assert_eq!(
            cx.probes.get(Field::RegKey, t, None),
            Some(&Probe::Present),
            "{t}"
        );
    }
    // The user's classes win over the machine's.
    assert_eq!(
        cx.probes.get(Field::RegValue, "HKCR\\.both", Some("")),
        Some(&Probe::Text("user".into()))
    );

    // Without the SID the user's hives cannot be read: unknown, not absent.
    let mut cx = EvaluationContext::default();
    let got = c.collect(&p, &mut cx, m.sources());
    assert_eq!(
        cx.probes.get(Field::RegKey, "HKCU\\Software\\Mine", None),
        None
    );
    assert_eq!(cx.probes.get(Field::RegKey, "HKCR\\.user", None), None);
    assert_eq!(got.failed, 4);
    assert_eq!(
        cx.probes
            .get(Field::RegKey, &format!("HKU\\{SID}\\Software\\Mine"), None),
        Some(&Probe::Present)
    );
}

/// A file probe whose reads fail.
struct DeniedFiles;

impl FileProbe for DeniedFiles {
    fn kind(&self, path: &str) -> PlatformResult<Option<FsKind>> {
        Err(palisade_core::platform::PlatformError::new(
            ErrorKind::AccessDenied,
            path,
        ))
    }
}

#[test]
fn a_failed_read_is_left_out_and_not_cached() {
    let p = snapshot(policy(
        vec![probe(
            Field::FsFile,
            Operator::Exists,
            "C:\\x",
            Some(Cadence::OncePerBoot),
        )],
        1_000,
    ));
    let m = Mocks::new();
    let c = collector(Arc::new(DeniedFiles));
    let mut cx = ctx();
    let got = c.collect(&p, &mut cx, m.sources());
    assert_eq!(got.failed, 1);
    assert!(got.timed_out.is_empty());
    assert_eq!(cx.probes.get(Field::FsFile, "C:\\x", None), None);
    assert_eq!(c.cached_len(), 0);
}

#[test]
fn a_registry_read_error_is_left_out() {
    // A key path the registry refuses (a NUL would be cut short).
    assert_eq!(
        registry_lookup("HKLM\\a", None, |_, _| Err(
            palisade_core::platform::PlatformError::new(ErrorKind::AccessDenied, "x")
        )),
        None
    );
    assert_eq!(registry_lookup("HKXX\\a", None, |_, _| Ok(true)), None);
    assert_eq!(
        registry_lookup("HKLM", None, |_, _| Ok(true)),
        Some(Some((Hive::LocalMachine, String::new())))
    );
}

#[test]
fn files_reports_kinds_over_a_platform_file_system() {
    let mut fs = MockFileSystem::new();
    fs.insert("C:\\a.txt", MockFile::new(b"x".to_vec()));
    fs.insert("C:\\dir", MockFile::directory());
    let f = Files(fs);
    assert_eq!(f.kind("C:\\a.txt").unwrap(), Some(FsKind::File));
    assert_eq!(f.kind("C:\\dir").unwrap(), Some(FsKind::Folder));
    assert_eq!(f.kind("C:\\none").unwrap(), None);
    // A relative path is an error, not "not found".
    assert!(Files(crate::platform::StdFileSystem).kind("rel").is_err());
}

// --- Cadences ---------------------------------------------------------------

fn cadence_policy(cadence: Option<Cadence>) -> Arc<Snapshot> {
    snapshot(policy(
        vec![
            probe(
                Field::RegKey,
                Operator::Exists,
                "HKLM\\Software\\K",
                cadence,
            ),
            probe(
                Field::FsFile,
                Operator::Exists,
                "C:\\f",
                Some(cadence.unwrap_or(Cadence::OncePerBoot)),
            ),
        ],
        1_000,
    ))
}

#[test]
fn no_cadence_reads_every_decision() {
    let p = cadence_policy(None);
    let mut m = Mocks::new();
    let c = collector(Arc::new(MapFiles::default()));
    let mut cx = ctx();
    c.collect(&p, &mut cx, m.sources());
    assert_eq!(
        cx.probes.get(Field::RegKey, "HKLM\\Software\\K", None),
        Some(&Probe::Absent)
    );
    m.reg.create_key(Hive::LocalMachine, "software\\k");
    let mut cx = ctx();
    c.collect(&p, &mut cx, m.sources());
    assert_eq!(
        cx.probes.get(Field::RegKey, "HKLM\\Software\\K", None),
        Some(&Probe::Present)
    );
}

#[test]
fn once_per_boot_is_cached_for_the_process() {
    let p = cadence_policy(Some(Cadence::OncePerBoot));
    let mut m = Mocks::new();
    let files = Arc::new(MapFiles::default());
    let c = collector(files.clone());
    c.collect(&p, &mut ctx(), m.sources());
    m.reg.create_key(Hive::LocalMachine, "software\\k");
    let mut cx = ctx();
    cx.session.id = Some(2);
    let got = c.collect(&p, &mut cx, m.sources());
    assert_eq!(got.cached, 2);
    assert_eq!(
        cx.probes.get(Field::RegKey, "HKLM\\Software\\K", None),
        Some(&Probe::Absent)
    );
    assert_eq!(files.reads.load(Ordering::SeqCst), 1);
}

#[test]
fn once_per_session_is_cached_per_session_until_logoff() {
    let p = cadence_policy(Some(Cadence::OncePerSession));
    let mut m = Mocks::new();
    let c = collector(Arc::new(MapFiles::default()));
    c.collect(&p, &mut ctx(), m.sources());
    m.reg.create_key(Hive::LocalMachine, "software\\k");
    let key = |cx: &EvaluationContext| {
        cx.probes
            .get(Field::RegKey, "HKLM\\Software\\K", None)
            .cloned()
    };
    // Same session: cached.
    let mut cx = ctx();
    c.collect(&p, &mut cx, m.sources());
    assert_eq!(key(&cx), Some(Probe::Absent));
    // Another session reads again.
    let mut cx = ctx();
    cx.session.id = Some(2);
    c.collect(&p, &mut cx, m.sources());
    assert_eq!(key(&cx), Some(Probe::Present));
    // No session: never cached.
    let mut cx = ctx();
    cx.session.id = None;
    let got = c.collect(&p, &mut cx, m.sources());
    assert_eq!(got.cached, 0);
    // Logoff drops the session's entries.
    c.invalidate_session(1);
    let mut cx = ctx();
    c.collect(&p, &mut cx, m.sources());
    assert_eq!(key(&cx), Some(Probe::Present));
}

#[test]
fn on_policy_change_is_cached_until_another_policy() {
    let p = cadence_policy(Some(Cadence::OnPolicyChange));
    let mut m = Mocks::new();
    let c = collector(Arc::new(MapFiles::default()));
    c.collect(&p, &mut ctx(), m.sources());
    m.reg.create_key(Hive::LocalMachine, "software\\k");
    let mut cx = ctx();
    assert_eq!(c.collect(&p, &mut cx, m.sources()).cached, 2);
    assert_eq!(
        cx.probes.get(Field::RegKey, "HKLM\\Software\\K", None),
        Some(&Probe::Absent)
    );
    // The same document loaded again is another policy.
    let q = cadence_policy(Some(Cadence::OnPolicyChange));
    let mut cx = ctx();
    let got = c.collect(&q, &mut cx, m.sources());
    assert_eq!(got.cached, 0);
    assert_eq!(
        cx.probes.get(Field::RegKey, "HKLM\\Software\\K", None),
        Some(&Probe::Present)
    );
    // The old policy's entries are gone.
    assert_eq!(c.cached_len(), 2);
}

#[test]
fn per_user_probes_are_cached_per_user() {
    let p = snapshot(policy(
        vec![probe(
            Field::EnvVar,
            Operator::Exists,
            "TOOL",
            Some(Cadence::OncePerBoot),
        )],
        1_000,
    ));
    let mut m = Mocks::new();
    let c = collector(Arc::new(MapFiles::default()));
    c.collect(&p, &mut ctx(), m.sources());
    m.env.set_var("TOOL", "1");
    // The same user: cached.
    let mut cx = ctx();
    assert_eq!(c.collect(&p, &mut cx, m.sources()).cached, 1);
    // Another user reads their own.
    let mut cx = ctx();
    cx.user.sid = Some("S-1-5-21-1-2-3-1002".into());
    c.collect(&p, &mut cx, m.sources());
    assert_eq!(
        cx.probes.get(Field::EnvVar, "TOOL", None),
        Some(&Probe::Text("1".into()))
    );
    // No SID: read, never cached.
    let mut cx = ctx();
    cx.user.sid = None;
    let got = c.collect(&p, &mut cx, m.sources());
    assert_eq!((got.cached, got.read), (0, 1));
}

#[test]
fn the_cache_is_bounded() {
    let c = collector(Arc::new(MapFiles::default()));
    let target = |n: usize| ProbeTarget {
        field: Field::RegKey,
        target: format!("HKLM\\k{n}"),
        value_name: None,
        cost: CostClass::Warm,
        cadence: Some(Cadence::OncePerBoot),
    };
    for n in 0..=MAX_CACHED_PROBES {
        c.store(cache_key(&target(n), 0, None, None), &Probe::Present);
    }
    assert_eq!(c.cached_len(), 1);
    // A timed-out probe is never stored.
    c.store(cache_key(&target(0), 0, None, None), &Probe::TimedOut);
    assert_eq!(c.cached_len(), 1);
}

// --- The budget: the slow-probe harness ------------------------------------

const BUDGET_MS: u16 = 50;
/// Margin for a loaded CI runner on top of the budget.
const MARGIN: Duration = Duration::from_millis(450);

fn slow_policy() -> ValidatedPolicy {
    policy(
        vec![probe(
            Field::FsFile,
            Operator::Exists,
            "\\\\offline\\share\\flag.txt",
            Some(Cadence::OncePerBoot),
        )],
        BUDGET_MS,
    )
}

#[test]
fn a_hung_cold_read_times_out_at_the_deadline_and_is_never_cached() {
    let p = snapshot(slow_policy());
    let m = Mocks::new();
    let files = Arc::new(HungFiles::default());
    let c = collector(files.clone());
    let mut cx = ctx();
    let start = Instant::now();
    let got = c.collect(&p, &mut cx, m.sources());
    let took = start.elapsed();
    assert!(
        took >= Duration::from_millis(u64::from(BUDGET_MS)),
        "{took:?}"
    );
    assert!(
        took < Duration::from_millis(u64::from(BUDGET_MS)) + MARGIN,
        "{took:?}"
    );
    assert_eq!(got.timed_out.len(), 1);
    assert_eq!(
        cx.probes
            .get(Field::FsFile, "\\\\offline\\share\\flag.txt", None),
        Some(&Probe::TimedOut)
    );
    assert_eq!(c.cached_len(), 0);

    // The next decision joins the read in flight rather than starting
    // another, and times out again.
    let mut cx = ctx();
    let got = c.collect(&p, &mut cx, m.sources());
    assert_eq!(got.timed_out.len(), 1);
    assert_eq!(files.reads.load(Ordering::SeqCst), 1);

    // Once the share answers, the result is used and cached.
    files.release();
    let deadline = Instant::now() + Duration::from_secs(10);
    let cx = loop {
        let mut cx = ctx();
        let got = c.collect(&p, &mut cx, m.sources());
        if got.timed_out.is_empty() || Instant::now() > deadline {
            break cx;
        }
    };
    assert_eq!(
        cx.probes
            .get(Field::FsFile, "\\\\offline\\share\\flag.txt", None),
        Some(&Probe::Present)
    );
    assert_eq!(c.cached_len(), 1);
}

#[test]
fn hung_reads_are_bounded() {
    let targets: Vec<Match> = (0..=MAX_COLD_IN_FLIGHT)
        .map(|n| {
            probe(
                Field::FsFile,
                Operator::Exists,
                &format!("\\\\offline\\share\\f{n}"),
                Some(Cadence::OncePerBoot),
            )
        })
        .collect();
    // An `any` keeps the tree within the criteria-per-rule limit.
    let mut doc = PolicyBuilder::new()
        .rule_set(RuleSetBuilder::allowlist(1).rule(RuleBuilder::allow(
            1,
            all(vec![hash('a'), palisade_policy::test_util::any(targets)]),
        )))
        .build();
    doc.policy.settings.condition_budget_ms = 20;
    doc.policy.settings.max_criteria_per_rule = 25;
    let p = snapshot(doc.validate().unwrap());
    let m = Mocks::new();
    let files = Arc::new(HungFiles::default());
    let c = collector(files.clone());
    let mut cx = ctx();
    let got = c.collect(&p, &mut cx, m.sources());
    assert_eq!(got.timed_out.len(), MAX_COLD_IN_FLIGHT + 1);
    assert_eq!(files.reads.load(Ordering::SeqCst), MAX_COLD_IN_FLIGHT);
    files.release();
}

#[test]
fn warm_reads_after_the_deadline_are_timed_out() {
    /// An environment whose reads take longer than the budget.
    struct SlowEnv(MockEnvironment);
    impl Environment for SlowEnv {
        fn hostname(&self) -> PlatformResult<String> {
            self.0.hostname()
        }
        fn domain(&self) -> PlatformResult<Option<String>> {
            self.0.domain()
        }
        fn os_version(&self) -> PlatformResult<palisade_core::platform::OsVersion> {
            self.0.os_version()
        }
        fn architecture(&self) -> palisade_core::platform::Architecture {
            self.0.architecture()
        }
        fn addresses(&self) -> PlatformResult<Vec<palisade_core::platform::InterfaceAddress>> {
            self.0.addresses()
        }
        fn connection_type(&self) -> PlatformResult<palisade_core::platform::ConnectionType> {
            self.0.connection_type()
        }
        fn var(&self, name: &str) -> Option<String> {
            std::thread::sleep(Duration::from_millis(30));
            self.0.var(name)
        }
    }
    let p = snapshot(policy(
        vec![
            probe(
                Field::EnvVar,
                Operator::Exists,
                "A",
                Some(Cadence::OncePerBoot),
            ),
            probe(
                Field::EnvVar,
                Operator::Exists,
                "B",
                Some(Cadence::OncePerBoot),
            ),
        ],
        10,
    ));
    let env = SlowEnv(MockEnvironment::new());
    let reg = MockRegistry::new();
    let c = collector(Arc::new(MapFiles::default()));
    let mut cx = ctx();
    let got = c.collect(
        &p,
        &mut cx,
        Sources {
            env: &env,
            registry: &reg,
            command_line: None,
        },
    );
    // The first read finished after the deadline, so it is not used; the
    // second never started.
    assert_eq!(got.timed_out.len(), 2);
    assert_eq!(got.read, 0);
    assert_eq!(
        cx.probes.get(Field::EnvVar, "A", None),
        Some(&Probe::TimedOut)
    );
    assert_eq!(
        cx.probes.get(Field::EnvVar, "B", None),
        Some(&Probe::TimedOut)
    );
    assert_eq!(c.cached_len(), 0);
}

#[test]
fn the_decision_returns_by_the_deadline_unknown_traced_and_uncached() {
    let validated = slow_policy();
    let engine = Engine::new(validated.clone(), EngineConfig::default()).unwrap();
    let m = Mocks::new();
    let files = Arc::new(HungFiles::default());
    let c = collector(files.clone());
    let object = facts().sha256('a').path("C:\\Apps\\tool.exe").build();
    let vars = PathVariables::new();
    let state = DeviceState::of(&validated.document().policy);
    let clock = SystemClock::new();

    for _ in 0..2 {
        let start = Instant::now();
        let mut cx = ctx();
        c.collect(&engine.snapshot(), &mut cx, m.sources());
        let subject = Subject {
            object_type: ObjectType::Executable,
            facts: &object,
            variables: &vars,
            context: &cx,
        };
        let request = Request {
            subject,
            computed: FactSet::ALL,
            state: &state,
            trace_id: TRACE,
            file: Some(FileIdentity::Sha256([0xaa; 32])),
            session: Some(1),
            expires_before: None,
        };
        let outcome = engine.evaluate(&request, &clock);
        let took = start.elapsed();
        assert!(
            took < Duration::from_millis(u64::from(BUDGET_MS)) + MARGIN,
            "{took:?}"
        );
        // The allow needs the file: unknown, so it does not apply, and the
        // object is blocked (ADR 0018).
        let Outcome::Decided(Some(d)) = outcome else {
            panic!("{outcome:?}")
        };
        assert_eq!(d.outcome(), DecisionOutcome::Blocked);
        // Not cached: the second round decides afresh.
        assert_eq!(engine.cache_stats().inserts, 0);
        assert_eq!(engine.cache_stats().hits, 0);

        let trace = Tracer::new(&validated).unwrap().trace(
            &subject,
            &palisade_policy::trace::ObjectExtras::default(),
            &state,
            TRACE,
            &TraceOptions::at(TraceLevel::Full),
        );
        assert!(
            trace
                .warnings
                .iter()
                .any(|w| w.code == WarningCode::ConditionTimeout),
            "{:?}",
            trace.warnings
        );
        assert!(
            trace
                .unknown_facts
                .iter()
                .any(|u| { u.field == Field::FsFile && u.notes.contains(&"condition_timeout") })
        );
    }
    files.release();
}

#[test]
fn a_collected_probe_decides_and_is_cached() {
    // The control for the test above: the same policy with the file there.
    let validated = slow_policy();
    let engine = Engine::new(validated.clone(), EngineConfig::default()).unwrap();
    let m = Mocks::new();
    let files = MapFiles::default().with("\\\\OFFLINE\\SHARE\\FLAG.TXT", FsKind::File);
    let c = collector(Arc::new(files));
    let object = facts().sha256('a').path("C:\\Apps\\tool.exe").build();
    let vars = PathVariables::new();
    let state = DeviceState::of(&validated.document().policy);
    let mut cx = ctx();
    c.collect(&engine.snapshot(), &mut cx, m.sources());
    let request = Request {
        subject: Subject {
            object_type: ObjectType::Executable,
            facts: &object,
            variables: &vars,
            context: &cx,
        },
        computed: FactSet::ALL,
        state: &state,
        trace_id: TRACE,
        file: Some(FileIdentity::Sha256([0xaa; 32])),
        session: Some(1),
        expires_before: None,
    };
    let Outcome::Decided(Some(d)) = engine.evaluate(&request, &SystemClock::new()) else {
        panic!()
    };
    assert_eq!(d.outcome(), DecisionOutcome::Allowed);
    assert_eq!(engine.cache_stats().inserts, 1);
}
