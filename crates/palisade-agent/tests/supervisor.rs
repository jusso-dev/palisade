//! Supervisor behaviour: start order, readiness, restart with backoff, the
//! panic circuit breaker, agent state and shutdown deadlines.
//!
//! Every test runs on a paused tokio clock, so backoffs of minutes take no
//! real time and timings are exact.

// Test code: helpers outside `#[test]` functions may unwrap, since a failure
// there should fail the test loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicU32, Ordering},
    },
    time::Duration,
};

use palisade_agent::{
    lifecycle::AgentState,
    subsystem::{BoxFuture, Criticality, Health, Subsystem, SubsystemContext, SubsystemError},
    supervisor::{
        RestartPolicy, StopOutcome, SubsystemStatus, Supervisor, SupervisorError, SupervisorHandle,
    },
};
use tokio::time::{Instant, sleep, timeout};

#[derive(Clone, Copy, Debug)]
enum Behaviour {
    /// Ready at once, stops on request.
    Normal,
    /// Waits this long before becoming ready.
    SlowReady(Duration),
    /// Panics on the first `n` runs, then behaves normally.
    PanicFirst(u32),
    /// Panics after becoming ready, on every run.
    PanicAfterReady,
    /// Returns an error on every run, before becoming ready.
    Fail,
    /// Returns `Ok` before a stop is requested.
    ExitEarly,
    /// Never calls `set_ready`.
    NeverReady,
    /// Takes this long to stop.
    SlowStop(Duration),
    /// Panics while stopping.
    PanicOnStop,
}

type Log = Arc<Mutex<Vec<(String, Instant)>>>;

struct Probe {
    name: &'static str,
    criticality: Criticality,
    deps: Vec<&'static str>,
    behaviour: Behaviour,
    runs: AtomicU32,
    log: Log,
}

impl Probe {
    fn new(name: &'static str, behaviour: Behaviour, log: &Log) -> Self {
        Self {
            name,
            criticality: Criticality::NonCritical,
            deps: Vec::new(),
            behaviour,
            runs: AtomicU32::new(0),
            log: Arc::clone(log),
        }
    }

    fn critical(mut self) -> Self {
        self.criticality = Criticality::Critical;
        self
    }

    fn after(mut self, deps: &[&'static str]) -> Self {
        self.deps = deps.to_vec();
        self
    }

    fn record(&self, event: &str) {
        self.log
            .lock()
            .unwrap()
            .push((format!("{event}:{}", self.name), Instant::now()));
    }
}

impl Subsystem for Probe {
    fn name(&self) -> &'static str {
        self.name
    }

    fn criticality(&self) -> Criticality {
        self.criticality
    }

    fn dependencies(&self) -> &[&'static str] {
        &self.deps
    }

    fn stop_timeout(&self) -> Duration {
        Duration::from_secs(2)
    }

    fn start_timeout(&self) -> Duration {
        Duration::from_secs(30)
    }

    fn health(&self) -> Health {
        Health::Degraded(format!("runs={}", self.runs.load(Ordering::SeqCst)))
    }

    fn run(self: Arc<Self>, ctx: SubsystemContext) -> BoxFuture<Result<(), SubsystemError>> {
        Box::pin(async move {
            let run = self.runs.fetch_add(1, Ordering::SeqCst) + 1;
            self.record("start");
            match self.behaviour {
                Behaviour::SlowReady(d) => sleep(d).await,
                Behaviour::PanicFirst(n) if run <= n => panic!("injected panic {run}"),
                Behaviour::Fail => return Err(SubsystemError::new("cannot open store")),
                Behaviour::NeverReady => {
                    ctx.stopped().await;
                    return Ok(());
                }
                _ => {}
            }
            ctx.set_ready();
            self.record("ready");
            match self.behaviour {
                Behaviour::PanicAfterReady => {
                    sleep(Duration::from_secs(1)).await;
                    panic!("injected panic after ready");
                }
                Behaviour::ExitEarly => return Ok(()),
                _ => {}
            }
            let deadline = ctx.stopped().await;
            assert_eq!(ctx.stop_deadline(), Some(deadline));
            self.record("stop");
            match self.behaviour {
                Behaviour::SlowStop(d) => sleep(d).await,
                Behaviour::PanicOnStop => panic!("injected panic on stop"),
                _ => {}
            }
            self.record("stopped");
            Ok(())
        })
    }
}

fn arc(probe: Probe) -> Arc<dyn Subsystem> {
    Arc::new(probe)
}

fn events(log: &Log) -> Vec<String> {
    log.lock().unwrap().iter().map(|(e, _)| e.clone()).collect()
}

fn at(log: &Log, event: &str) -> Instant {
    log.lock()
        .unwrap()
        .iter()
        .find(|(e, _)| e == event)
        .unwrap_or_else(|| panic!("no {event} in {:?}", events(log)))
        .1
}

async fn wait_state(handle: &SupervisorHandle, pred: impl Fn(&AgentState) -> bool) -> AgentState {
    let mut rx = handle.subscribe();
    timeout(Duration::from_secs(3600), rx.wait_for(|s| pred(s)))
        .await
        .expect("state not reached")
        .expect("supervisor gone")
        .clone()
}

fn status_of(handle: &SupervisorHandle, name: &str) -> SubsystemStatus {
    handle
        .report()
        .subsystems
        .into_iter()
        .find(|s| s.name == name)
        .unwrap()
        .status
}

fn names_err(err: SupervisorError) -> String {
    err.to_string()
}

#[test]
fn start_order_follows_dependencies_then_registration() {
    let log = Log::default();
    let sup = Supervisor::new(
        vec![
            arc(Probe::new("comms", Behaviour::Normal, &log).after(&["policy", "config"])),
            arc(Probe::new("config", Behaviour::Normal, &log)),
            arc(Probe::new("policy", Behaviour::Normal, &log).after(&["store"])),
            arc(Probe::new("store", Behaviour::Normal, &log).after(&["config", "config"])),
            arc(Probe::new("events", Behaviour::Normal, &log)),
        ],
        RestartPolicy::default(),
    )
    .unwrap();
    assert_eq!(
        sup.start_order(),
        ["config", "store", "policy", "comms", "events"]
    );
}

#[test]
fn invalid_subsystem_sets_are_rejected() {
    let log = Log::default();
    let p = RestartPolicy::default();
    let dup = Supervisor::new(
        vec![
            arc(Probe::new("a", Behaviour::Normal, &log)),
            arc(Probe::new("a", Behaviour::Normal, &log)),
        ],
        p,
    )
    .unwrap_err();
    assert_eq!(dup, SupervisorError::DuplicateName("a"));

    let unknown = Supervisor::new(
        vec![arc(Probe::new("a", Behaviour::Normal, &log).after(&["b"]))],
        p,
    )
    .unwrap_err();
    assert_eq!(
        unknown,
        SupervisorError::UnknownDependency {
            subsystem: "a",
            dependency: "b"
        }
    );

    let cycle = Supervisor::new(
        vec![
            arc(Probe::new("root", Behaviour::Normal, &log)),
            arc(Probe::new("a", Behaviour::Normal, &log).after(&["c"])),
            arc(Probe::new("b", Behaviour::Normal, &log).after(&["a"])),
            arc(Probe::new("c", Behaviour::Normal, &log).after(&["b", "root"])),
        ],
        p,
    )
    .unwrap_err();
    assert_eq!(cycle, SupervisorError::DependencyCycle(vec!["a", "b", "c"]));
    assert!(names_err(cycle).contains("a, b, c"));

    let self_loop = Supervisor::new(
        vec![arc(Probe::new("a", Behaviour::Normal, &log).after(&["a"]))],
        p,
    )
    .unwrap_err();
    assert_eq!(self_loop, SupervisorError::DependencyCycle(vec!["a"]));
}

#[tokio::test(start_paused = true)]
async fn dependents_start_after_dependencies_are_ready() {
    let log = Log::default();
    let handle = Supervisor::new(
        vec![
            arc(Probe::new("policy", Behaviour::Normal, &log).after(&["store"])),
            arc(Probe::new(
                "store",
                Behaviour::SlowReady(Duration::from_secs(3)),
                &log,
            )),
        ],
        RestartPolicy::default(),
    )
    .unwrap()
    .start();
    assert_eq!(handle.state(), AgentState::Starting);
    wait_state(&handle, |s| *s == AgentState::Running).await;
    assert!(at(&log, "start:policy") >= at(&log, "ready:store"));
    assert_eq!(
        at(&log, "ready:store").duration_since(at(&log, "start:store")),
        Duration::from_secs(3)
    );
    let report = handle.report();
    assert_eq!(report.state, AgentState::Running);
    assert!(report.subsystems.iter().all(|s| s.restarts == 0
        && s.status == SubsystemStatus::Running
        && matches!(s.health, Some(Health::Degraded(_)))));

    let shutdown = handle.shutdown(Duration::from_secs(20)).await;
    assert!(shutdown.is_clean());
    let names: Vec<_> = shutdown.outcomes.iter().map(|(n, _)| *n).collect();
    assert_eq!(names, ["policy", "store"]);
    assert!(at(&log, "stopped:policy") <= at(&log, "stop:store"));
}

#[tokio::test(start_paused = true)]
async fn a_panic_restarts_only_that_subsystem() {
    let log = Log::default();
    let healthy = Arc::new(Probe::new("events", Behaviour::Normal, &log));
    let flaky = Arc::new(Probe::new("inventory", Behaviour::PanicFirst(2), &log));
    let handle = Supervisor::new(
        vec![
            Arc::clone(&healthy) as Arc<dyn Subsystem>,
            Arc::clone(&flaky) as Arc<dyn Subsystem>,
        ],
        RestartPolicy::default(),
    )
    .unwrap()
    .start();

    let state = wait_state(&handle, |s| matches!(s, AgentState::Degraded(_))).await;
    let AgentState::Degraded(reasons) = state else {
        unreachable!()
    };
    assert!(reasons[0].contains("inventory restarting after: panicked: injected panic 1"));

    wait_state(&handle, |s| *s == AgentState::Running).await;
    assert_eq!(healthy.runs.load(Ordering::SeqCst), 1);
    assert_eq!(flaky.runs.load(Ordering::SeqCst), 3);
    // Backoff: 1 s after the first panic, 2 s after the second.
    let starts: Vec<Instant> = log
        .lock()
        .unwrap()
        .iter()
        .filter(|(e, _)| e == "start:inventory")
        .map(|(_, t)| *t)
        .collect();
    assert_eq!(starts[1] - starts[0], Duration::from_secs(1));
    assert_eq!(starts[2] - starts[1], Duration::from_secs(2));

    let report = handle.report();
    let row = &report.subsystems[1];
    assert_eq!(
        (row.name, row.restarts, row.recent_panics),
        ("inventory", 2, 2)
    );
    assert!(handle.shutdown(Duration::from_secs(20)).await.is_clean());
}

#[tokio::test(start_paused = true)]
async fn three_panics_in_ten_minutes_fail_a_non_critical_subsystem() {
    let log = Log::default();
    let handle = Supervisor::new(
        vec![
            arc(Probe::new("config", Behaviour::Normal, &log).critical()),
            arc(Probe::new("inventory", Behaviour::PanicAfterReady, &log)),
        ],
        RestartPolicy::default(),
    )
    .unwrap()
    .start();
    let state = wait_state(&handle, |_| {
        matches!(
            status_of(&handle, "inventory"),
            SubsystemStatus::Failed { .. }
        )
    })
    .await;
    let AgentState::Degraded(reasons) = state else {
        panic!("expected degraded, got {state}");
    };
    assert_eq!(reasons.len(), 1);
    assert!(reasons[0].starts_with("inventory failed: 3 panics within"));
    let row = handle.report().subsystems[1].clone();
    assert_eq!((row.restarts, row.recent_panics, row.health), (2, 3, None));

    // Never restarted again.
    sleep(Duration::from_secs(3600)).await;
    assert_eq!(
        events(&log)
            .iter()
            .filter(|e| *e == "start:inventory")
            .count(),
        3
    );
    assert_eq!(status_of(&handle, "config"), SubsystemStatus::Running);

    let shutdown = handle.shutdown(Duration::from_secs(20)).await;
    assert_eq!(
        shutdown.outcomes,
        [
            ("inventory", StopOutcome::NotRunning),
            ("config", StopOutcome::Clean)
        ]
    );
    assert!(shutdown.is_clean());
}

#[tokio::test(start_paused = true)]
async fn panics_outside_the_window_do_not_trip_the_breaker() {
    let log = Log::default();
    let policy = RestartPolicy {
        // Each run is ready for 1 s, then the backoff resets; with
        // `stable_after` = 1 s the delays stay at 1 s, so panics are about
        // 2 s apart. A 3 s window holds at most 2 of them.
        stable_after: Duration::from_secs(1),
        panic_window: Duration::from_secs(3),
        ..RestartPolicy::default()
    };
    let probe = Arc::new(Probe::new("etw", Behaviour::PanicAfterReady, &log));
    let handle = Supervisor::new(vec![Arc::clone(&probe) as Arc<dyn Subsystem>], policy)
        .unwrap()
        .start();
    sleep(Duration::from_secs(60)).await;
    assert!(probe.runs.load(Ordering::SeqCst) >= 20);
    assert!(matches!(
        status_of(&handle, "etw"),
        SubsystemStatus::Restarting { .. } | SubsystemStatus::Running
    ));
    assert!(handle.report().subsystems[0].recent_panics <= 2);
    handle.shutdown(Duration::from_secs(1)).await;
}

#[tokio::test(start_paused = true)]
async fn a_failed_critical_subsystem_forces_fail_safe() {
    let log = Log::default();
    let handle = Supervisor::new(
        vec![
            arc(Probe::new("policy", Behaviour::PanicAfterReady, &log).critical()),
            arc(Probe::new("events", Behaviour::Normal, &log)),
        ],
        RestartPolicy::default(),
    )
    .unwrap()
    .start();
    let state = wait_state(&handle, |s| matches!(s, AgentState::FailSafe(_))).await;
    assert!(
        state
            .to_string()
            .contains("critical subsystem policy failed")
    );
    // Fail-safe is sticky: the healthy subsystem does not bring it back.
    sleep(Duration::from_secs(600)).await;
    assert!(matches!(handle.state(), AgentState::FailSafe(_)));
    assert_eq!(status_of(&handle, "events"), SubsystemStatus::Running);
    handle.shutdown(Duration::from_secs(5)).await;
}

#[tokio::test(start_paused = true)]
async fn errors_retry_with_capped_backoff_and_never_trip_the_breaker() {
    let log = Log::default();
    let handle = Supervisor::new(
        vec![
            arc(Probe::new("store", Behaviour::Fail, &log).critical()),
            arc(Probe::new("policy", Behaviour::Normal, &log).after(&["store"])),
        ],
        RestartPolicy::default(),
    )
    .unwrap()
    .start();
    // The dependent never starts, but startup still settles.
    let state = wait_state(&handle, |s| matches!(s, AgentState::Degraded(_))).await;
    assert_eq!(
        state,
        AgentState::Degraded(vec![
            "store restarting after: cannot open store".into(),
            "policy waiting for dependencies".into(),
        ])
    );
    sleep(Duration::from_secs(3 * 3600)).await;
    let starts: Vec<Instant> = log
        .lock()
        .unwrap()
        .iter()
        .filter(|(e, _)| e == "start:store")
        .map(|(_, t)| *t)
        .collect();
    let gaps: Vec<u64> = starts.windows(2).map(|w| (w[1] - w[0]).as_secs()).collect();
    assert_eq!(gaps[..10], [1, 2, 4, 8, 16, 32, 64, 128, 256, 300]);
    assert!(gaps[10..].iter().all(|&g| g == 300));
    assert!(!events(&log).contains(&"start:policy".to_string()));
    assert!(matches!(handle.state(), AgentState::Degraded(_)));
    assert!(handle.shutdown(Duration::from_secs(5)).await.is_clean());
}

#[tokio::test(start_paused = true)]
async fn exiting_early_is_a_failure() {
    let log = Log::default();
    let handle = Supervisor::new(
        vec![arc(Probe::new("scheduler", Behaviour::ExitEarly, &log))],
        RestartPolicy::default(),
    )
    .unwrap()
    .start();
    let state = wait_state(&handle, |s| matches!(s, AgentState::Degraded(_))).await;
    assert!(
        state
            .to_string()
            .contains("exited before a stop was requested")
    );
    sleep(Duration::from_secs(10)).await;
    assert!(
        events(&log)
            .iter()
            .filter(|e| *e == "start:scheduler")
            .count()
            > 2
    );
    handle.shutdown(Duration::from_secs(5)).await;
}

#[tokio::test(start_paused = true)]
async fn a_subsystem_that_never_becomes_ready_is_restarted() {
    let log = Log::default();
    let handle = Supervisor::new(
        vec![
            arc(Probe::new("comms", Behaviour::NeverReady, &log)),
            arc(Probe::new("repo_sync", Behaviour::Normal, &log).after(&["comms"])),
        ],
        RestartPolicy::default(),
    )
    .unwrap()
    .start();
    let state = wait_state(&handle, |s| matches!(s, AgentState::Degraded(_))).await;
    assert!(state.to_string().contains("not ready within 30s"));
    let first = at(&log, "start:comms");
    sleep(Duration::from_secs(40)).await;
    let starts: Vec<Instant> = log
        .lock()
        .unwrap()
        .iter()
        .filter(|(e, _)| e == "start:comms")
        .map(|(_, t)| *t)
        .collect();
    assert_eq!(starts[1] - first, Duration::from_secs(31));
    handle.shutdown(Duration::from_secs(5)).await;
}

#[tokio::test(start_paused = true)]
async fn shutdown_aborts_subsystems_that_miss_their_deadline() {
    let log = Log::default();
    let handle = Supervisor::new(
        vec![
            arc(Probe::new("store", Behaviour::PanicOnStop, &log)),
            arc(
                Probe::new("events", Behaviour::SlowStop(Duration::from_secs(60)), &log)
                    .after(&["store"]),
            ),
            arc(
                Probe::new("ipc", Behaviour::SlowStop(Duration::from_secs(1)), &log)
                    .after(&["events"]),
            ),
        ],
        RestartPolicy::default(),
    )
    .unwrap()
    .start();
    wait_state(&handle, |s| *s == AgentState::Running).await;
    let mut states = handle.subscribe();
    let begin = Instant::now();
    let report = handle.shutdown(Duration::from_secs(20)).await;
    let took = begin.elapsed();
    assert_eq!(
        report.outcomes,
        [
            ("ipc", StopOutcome::Clean),
            ("events", StopOutcome::Aborted),
            (
                "store",
                StopOutcome::Panicked("injected panic on stop".into())
            ),
        ]
    );
    assert!(!report.is_clean());
    // ipc 1 s + events at its 2 s stop timeout + store immediately.
    assert_eq!(took, Duration::from_secs(3));
    assert!(!events(&log).contains(&"stopped:events".to_string()));
    assert_eq!(*states.borrow_and_update(), AgentState::Stopped);
}

#[tokio::test(start_paused = true)]
async fn shutdown_never_exceeds_the_overall_budget() {
    let log = Log::default();
    let slow = || Behaviour::SlowStop(Duration::from_secs(60));
    let handle = Supervisor::new(
        vec![
            arc(Probe::new("a", slow(), &log)),
            arc(Probe::new("b", slow(), &log)),
            arc(Probe::new("c", slow(), &log)),
        ],
        RestartPolicy::default(),
    )
    .unwrap()
    .start();
    wait_state(&handle, |s| *s == AgentState::Running).await;
    let begin = Instant::now();
    let report = handle.shutdown(Duration::from_secs(3)).await;
    assert!(begin.elapsed() <= Duration::from_secs(3));
    assert!(
        report
            .outcomes
            .iter()
            .all(|(_, o)| *o == StopOutcome::Aborted)
    );
}

#[tokio::test(start_paused = true)]
async fn shutdown_during_backoff_or_while_waiting_is_immediate() {
    let log = Log::default();
    let handle = Supervisor::new(
        vec![
            arc(Probe::new("store", Behaviour::Fail, &log)),
            arc(Probe::new("policy", Behaviour::Normal, &log).after(&["store"])),
        ],
        RestartPolicy::default(),
    )
    .unwrap()
    .start();
    wait_state(&handle, |s| matches!(s, AgentState::Degraded(_))).await;
    let begin = Instant::now();
    let report = handle.shutdown(Duration::from_secs(20)).await;
    assert_eq!(begin.elapsed(), Duration::ZERO);
    assert_eq!(
        report.outcomes,
        [
            ("policy", StopOutcome::NotRunning),
            ("store", StopOutcome::NotRunning)
        ]
    );
}

#[tokio::test(start_paused = true)]
async fn dropping_the_handle_aborts_subsystems() {
    let log = Log::default();
    let probe = Arc::new(Probe::new("a", Behaviour::Normal, &log));
    let handle = Supervisor::new(
        vec![Arc::clone(&probe) as Arc<dyn Subsystem>],
        RestartPolicy::default(),
    )
    .unwrap()
    .start();
    wait_state(&handle, |s| *s == AgentState::Running).await;
    drop(handle);
    sleep(Duration::from_secs(1)).await;
    // The run, and the supervisor that held it, are gone.
    assert_eq!(Arc::strong_count(&probe), 1);
}

#[tokio::test(start_paused = true)]
async fn nothing_restarts_while_shutting_down() {
    let log = Log::default();
    let handle = Supervisor::new(
        vec![
            arc(Probe::new("store", Behaviour::Fail, &log)),
            arc(Probe::new(
                "events",
                Behaviour::SlowStop(Duration::from_millis(1500)),
                &log,
            )),
        ],
        RestartPolicy::default(),
    )
    .unwrap()
    .start();
    wait_state(&handle, |s| matches!(s, AgentState::Degraded(_))).await;
    let before = events(&log).iter().filter(|e| *e == "start:store").count();
    // `events` takes 1.5 s to stop; `store`'s 1 s backoff ends meanwhile.
    let report = handle.shutdown(Duration::from_secs(20)).await;
    sleep(Duration::from_secs(10)).await;
    let after = events(&log).iter().filter(|e| *e == "start:store").count();
    assert_eq!(before, after);
    assert_eq!(
        report.outcomes,
        [
            ("events", StopOutcome::Clean),
            ("store", StopOutcome::NotRunning)
        ]
    );
}

#[tokio::test(start_paused = true)]
async fn a_cancelled_shutdown_still_stops_everything() {
    let log = Log::default();
    let store = Arc::new(Probe::new("store", Behaviour::Normal, &log));
    let events_probe = Arc::new(Probe::new(
        "events",
        Behaviour::SlowStop(Duration::from_secs(60)),
        &log,
    ));
    let handle = Supervisor::new(
        vec![
            Arc::clone(&store) as Arc<dyn Subsystem>,
            Arc::clone(&events_probe) as Arc<dyn Subsystem>,
        ],
        RestartPolicy::default(),
    )
    .unwrap()
    .start();
    wait_state(&handle, |s| *s == AgentState::Running).await;
    // Cancel while `events` is still stopping, before `store` is asked. The
    // dropped handle gives `store` an immediate deadline, and `events` keeps
    // the 2 s deadline it already had.
    let cancelled = timeout(
        Duration::from_millis(500),
        handle.shutdown(Duration::from_secs(20)),
    )
    .await;
    assert!(cancelled.is_err());
    sleep(Duration::from_secs(3)).await;
    // Every run and runner is gone, so only the test holds the probes.
    assert_eq!(Arc::strong_count(&store), 1);
    assert_eq!(Arc::strong_count(&events_probe), 1);
    assert_eq!(store.runs.load(Ordering::SeqCst), 1);
}
