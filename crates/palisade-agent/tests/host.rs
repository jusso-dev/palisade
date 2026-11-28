//! The platform-independent host loop and the console binary.

// Test code: helpers outside `#[test]` functions may unwrap or expect, since
// a failure there should fail the test loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{process::Command, time::Duration};

use palisade_agent::{
    config::{AgentConfig, LoadedConfig, RuntimeConfig},
    host::{self, StopReason, StopRequest},
    lifecycle::AgentState,
    supervisor::StopOutcome,
};

#[tokio::test(start_paused = true)]
async fn run_until_starts_then_stops_on_request() {
    let loaded = LoadedConfig {
        config: AgentConfig::default(),
        source: None,
    };
    let supervisor = host::supervisor(&loaded).unwrap();
    assert_eq!(
        supervisor.start_order(),
        [
            "config",
            "clock",
            "event-pipeline",
            "inventory",
            "policy_cache"
        ]
    );
    let mut started = false;
    let (request, report) = host::run_until(supervisor, || started = true, async {
        tokio::time::sleep(Duration::from_secs(5)).await;
        StopRequest::SYSTEM_SHUTDOWN
    })
    .await;
    assert!(started);
    assert_eq!(request.reason, StopReason::SystemShutdown);
    assert_eq!(request.budget, host::SHUTDOWN_BUDGET);
    assert_eq!(
        report.outcomes,
        [
            ("policy_cache", StopOutcome::Clean),
            ("inventory", StopOutcome::Clean),
            ("event-pipeline", StopOutcome::Clean),
            ("clock", StopOutcome::Clean),
            ("config", StopOutcome::Clean)
        ]
    );
}

#[test]
fn budgets_match_the_service_contract() {
    assert_eq!(StopRequest::REQUESTED.budget, Duration::from_secs(20));
    assert_eq!(StopRequest::SYSTEM_SHUTDOWN.budget, Duration::from_secs(10));
}

#[test]
fn runtime_rejects_zero_sizes_instead_of_panicking() {
    for runtime in [
        RuntimeConfig {
            worker_threads: Some(0),
            ..RuntimeConfig::default()
        },
        RuntimeConfig {
            max_blocking_threads: 0,
            ..RuntimeConfig::default()
        },
    ] {
        let err = host::build_runtime(&runtime).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }
}

#[test]
fn runtime_uses_the_configured_sizes() {
    let config = AgentConfig::from_toml("[runtime]\nworker_threads = 2\n").unwrap();
    let runtime = host::build_runtime(&config.runtime).unwrap();
    assert_eq!(runtime.metrics().num_workers(), 2);
    let state = runtime.block_on(async {
        let handle = host::supervisor(&LoadedConfig {
            config,
            source: None,
        })
        .unwrap()
        .start();
        let mut rx = handle.subscribe();
        let state = rx
            .wait_for(|s| *s != AgentState::Starting)
            .await
            .unwrap()
            .clone();
        handle.shutdown(Duration::from_secs(1)).await;
        state
    });
    assert_eq!(state, AgentState::Running);
}

fn agent() -> Command {
    Command::new(env!("CARGO_BIN_EXE_palisade-agent"))
}

#[test]
fn binary_help_version_and_usage_errors() {
    let help = agent().arg("--help").output().unwrap();
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stdout).contains("--console"));

    let version = agent().arg("--version").output().unwrap();
    assert_eq!(
        String::from_utf8_lossy(&version.stdout).trim(),
        format!("palisade-agent {}", env!("CARGO_PKG_VERSION"))
    );

    let none = agent().output().unwrap();
    assert_eq!(none.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&none.stderr).contains("choose a mode"));
}

#[test]
fn binary_rejects_a_bad_config_file() {
    let dir = std::env::temp_dir().join(format!("palisade-agent-host-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("agent.toml");
    std::fs::write(&path, "fail_mode = \"maybe\"\n").unwrap();
    let out = agent()
        .args(["--console", "--config"])
        .arg(&path)
        .output()
        .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("invalid configuration"));
}

#[cfg(not(windows))]
#[test]
fn service_mode_is_windows_only() {
    let out = agent().arg("--service").output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("only available on Windows"));
}

#[cfg(windows)]
#[test]
fn service_mode_outside_the_scm_explains_itself() {
    let out = agent().arg("--service").output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("--console"));
}

/// Console mode runs until `SIGINT` (Ctrl-C) or `SIGTERM` and then stops
/// cleanly. The signal is sent the moment `Running` is logged, so this also
/// checks that the handlers are installed before supervision starts. Signals
/// cannot be sent to a child process portably, so this test is Unix-only.
#[cfg(unix)]
#[test]
fn console_mode_runs_until_terminated() {
    for signal in ["-TERM", "-INT"] {
        console_mode_stops_on(signal);
    }
}

#[cfg(unix)]
fn console_mode_stops_on(signal: &str) {
    use std::{
        io::{BufRead, BufReader},
        process::Stdio,
    };

    let mut child = agent()
        .arg("--console")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stderr = child.stderr.take().unwrap();
    let mut lines = BufReader::new(stderr).lines();
    let mut seen = Vec::new();
    for line in lines.by_ref() {
        let line = line.unwrap();
        // Wait for the agent state, not just the banner, so the signal
        // cannot arrive before the subsystems are ready.
        let running = line.contains("to=running");
        seen.push(line);
        if running {
            break;
        }
    }
    let pid = child.id().to_string();
    let killed = Command::new("kill")
        .args([signal, &pid])
        .status()
        .expect("`kill` must be installed to send the signal (procps on Debian)");
    assert!(killed.success());
    seen.extend(lines.map_while(Result::ok));
    let status = child.wait().unwrap();
    assert!(status.success(), "{signal}: exit {status}: {seen:#?}");
    let log = seen.join("\n");
    assert!(log.contains("configuration loaded"), "{log}");
    assert!(log.contains("running in console mode"), "{log}");
    assert!(log.contains("subsystem ready"), "{log}");
    assert!(log.contains("to=running"), "{log}");
    assert!(log.contains("to=stopped"), "{log}");
}

#[cfg(not(feature = "test-util"))]
#[test]
fn simulate_needs_the_test_util_feature() {
    let out = agent().arg("--simulate").output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
    assert!(String::from_utf8_lossy(&out.stderr).contains("--features test-util"));
}

#[cfg(feature = "test-util")]
#[test]
fn simulate_prints_one_event_per_line() {
    let out = agent().arg("--simulate").output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8(out.stdout).unwrap();
    let events: Vec<palisade_proto::events::Event> = text
        .lines()
        .map(|l| palisade_proto::events::Event::from_json(l).unwrap())
        .collect();
    assert_eq!(events.len(), 7);
    assert!(events.iter().all(|e| e.validate().is_ok()));

    let bad = agent()
        .args(["--simulate", "--scenario", "does-not-exist.toml"])
        .output()
        .unwrap();
    assert_eq!(bad.status.code(), Some(2));
}

mod controls {
    use std::sync::{Arc, Mutex};

    use palisade_agent::{
        config::{FailMode, LogLevel},
        control::{AllowStop, Control, HostEvent, PowerChange, SessionChange, TamperGuard},
        host::ConfigSubsystem,
        subsystem::{BoxFuture, Criticality, Subsystem, SubsystemContext, SubsystemError},
        supervisor::{RestartPolicy, Supervisor},
    };
    use tokio::sync::{mpsc, watch};

    use super::*;

    /// Records every host event it sees, and is ready once subscribed.
    struct Listener {
        seen: Arc<Mutex<Vec<HostEvent>>>,
    }

    impl Subsystem for Listener {
        fn name(&self) -> &'static str {
            "listener"
        }

        fn criticality(&self) -> Criticality {
            Criticality::NonCritical
        }

        fn run(self: Arc<Self>, ctx: SubsystemContext) -> BoxFuture<Result<(), SubsystemError>> {
            Box::pin(async move {
                let mut events = ctx.host_events();
                ctx.set_ready();
                loop {
                    tokio::select! {
                        _ = ctx.stopped() => return Ok(()),
                        Ok(event) = events.recv() => self.seen.lock().unwrap().push(event),
                    }
                }
            })
        }
    }

    struct Gate(watch::Sender<bool>);

    impl TamperGuard for Gate {
        fn stop_permission(&self) -> watch::Receiver<bool> {
            self.0.subscribe()
        }
    }

    #[tokio::test(start_paused = true)]
    async fn controls_reach_subsystems_and_a_stop_ends_the_run() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let supervisor = Supervisor::new(
            vec![Arc::new(Listener {
                seen: Arc::clone(&seen),
            })],
            RestartPolicy::default(),
        )
        .unwrap();
        let events = supervisor.host_events();
        let handle = supervisor.start();
        handle
            .subscribe()
            .wait_for(|s| *s == AgentState::Running)
            .await
            .unwrap();

        let (tx, rx) = mpsc::unbounded_channel();
        let guard = Gate(watch::channel(false).0);
        let permissions = Arc::new(Mutex::new(Vec::new()));
        let record = Arc::clone(&permissions);
        let sent = [
            HostEvent::Session {
                change: SessionChange::Logon,
                session_id: 2,
            },
            HostEvent::Power(PowerChange::Resume),
            HostEvent::TimeChange,
        ];
        for event in sent {
            tx.send(Control::Event(event)).unwrap();
        }
        let stopper = {
            let tx = tx.clone();
            let flip = guard.0.clone();
            async move {
                tokio::time::sleep(Duration::from_secs(1)).await;
                flip.send_replace(true);
                tokio::time::sleep(Duration::from_secs(1)).await;
                tx.send(Control::Stop(StopRequest::SYSTEM_SHUTDOWN))
                    .unwrap();
            }
        };
        let (request, ()) = tokio::join!(
            host::serve_controls(rx, events, &guard, move |allowed| record
                .lock()
                .unwrap()
                .push(allowed)),
            stopper
        );
        assert_eq!(request, StopRequest::SYSTEM_SHUTDOWN);
        assert_eq!(*permissions.lock().unwrap(), [false, true]);
        handle.shutdown(Duration::from_secs(1)).await;
        assert_eq!(*seen.lock().unwrap(), sent);
    }

    /// A guard whose sender is already gone.
    struct Orphan;

    impl TamperGuard for Orphan {
        fn stop_permission(&self) -> watch::Receiver<bool> {
            watch::channel(false).1
        }
    }

    #[tokio::test]
    async fn a_closed_channel_is_a_stop_and_a_dropped_guard_keeps_the_permission() {
        let supervisor = Supervisor::new(Vec::new(), RestartPolicy::default()).unwrap();
        let (tx, rx) = mpsc::unbounded_channel::<Control>();
        let permissions = Mutex::new(Vec::new());
        let serve = host::serve_controls(rx, supervisor.host_events(), &Orphan, |allowed| {
            permissions.lock().unwrap().push(allowed)
        });
        let close = async {
            tokio::task::yield_now().await;
            drop(tx);
        };
        let (request, ()) = tokio::join!(serve, close);
        assert_eq!(request.reason, StopReason::ChannelClosed);
        assert_eq!(request.budget, host::STOP_BUDGET);
        assert_eq!(*permissions.lock().unwrap(), [false]);
        // Nothing subscribed: publishing reaches nobody, without an error.
        assert_eq!(supervisor.host_events().publish(HostEvent::ParamChange), 0);
        assert!(*AllowStop::default().stop_permission().borrow());
    }

    struct TempConfig(std::path::PathBuf);

    impl TempConfig {
        fn new(tag: &str, text: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "palisade-agent-reload-{tag}-{}",
                std::process::id()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.join("agent.toml");
            std::fs::write(&path, text).unwrap();
            Self(path)
        }

        fn write(&self, text: &str) {
            std::fs::write(&self.0, text).unwrap();
        }
    }

    impl Drop for TempConfig {
        fn drop(&mut self) {
            if let Some(dir) = self.0.parent() {
                let _ = std::fs::remove_dir_all(dir);
            }
        }
    }

    #[test]
    fn reload_applies_a_valid_file_and_keeps_the_last_good_one() {
        let file = TempConfig::new("direct", "fail_mode = \"fail_closed\"\n");
        let config = ConfigSubsystem::new(palisade_agent::config::load(Some(&file.0)).unwrap());
        let mut changes = config.subscribe();
        assert_eq!(config.config().fail_mode, FailMode::FailClosed);
        // Unchanged: no change published.
        assert!(!config.reload().unwrap());
        assert!(!changes.has_changed().unwrap());

        file.write("fail_mode = \"fail_closed\"\n[log]\nlevel = \"debug\"\n");
        assert!(config.reload().unwrap());
        assert!(changes.has_changed().unwrap());
        assert_eq!(
            changes.borrow_and_update().config.log_level,
            LogLevel::Debug
        );

        // An invalid file, or a missing one, never falls back to defaults.
        file.write("fail_mode = \"sometimes\"\n");
        assert!(config.reload().is_err());
        std::fs::remove_file(&file.0).unwrap();
        assert!(config.reload().is_err());
        assert_eq!(config.config().fail_mode, FailMode::FailClosed);
        assert_eq!(config.config().log_level, LogLevel::Debug);

        // Runtime sizes are recorded, to apply at the next start.
        file.write("fail_mode = \"fail_closed\"\n[runtime]\nworker_threads = 2\n");
        assert!(config.reload().unwrap());
        assert_eq!(config.config().runtime.worker_threads, Some(2));
        assert_eq!(config.config().log_level, LogLevel::Info);
    }

    #[test]
    fn defaults_reload_as_defaults_off_windows() {
        let config = ConfigSubsystem::new(LoadedConfig {
            config: AgentConfig::default(),
            source: None,
        });
        // Off Windows there is no install-time path, so a reload reads the
        // defaults again. On Windows it reads the install-time file.
        #[cfg(not(windows))]
        assert!(!config.reload().unwrap());
        assert_eq!(config.config().fail_mode, FailMode::FailOpen);
    }

    #[tokio::test]
    async fn param_change_reloads_the_running_config_subsystem() {
        let file = TempConfig::new("event", "");
        let config = Arc::new(ConfigSubsystem::new(
            palisade_agent::config::load(Some(&file.0)).unwrap(),
        ));
        let mut changes = config.subscribe();
        let supervisor = Supervisor::new(vec![config.clone()], RestartPolicy::default()).unwrap();
        let events = supervisor.host_events();
        let handle = supervisor.start();
        handle
            .subscribe()
            .wait_for(|s| *s == AgentState::Running)
            .await
            .unwrap();
        // Other events are ignored.
        events.publish(HostEvent::TimeChange);
        file.write("fail_mode = \"sometimes\"\n");
        events.publish(HostEvent::ParamChange);
        file.write("fail_mode = \"fail_closed\"\n");
        // The bad file may or may not be read before the good one is
        // written; either way the published change is the good one.
        events.publish(HostEvent::ParamChange);
        let loaded = tokio::time::timeout(
            Duration::from_secs(30),
            changes.wait_for(|l| l.config.fail_mode == FailMode::FailClosed),
        )
        .await
        .unwrap()
        .unwrap()
        .clone();
        assert_eq!(loaded.source.as_deref(), Some(file.0.as_path()));
        let report = handle.shutdown(Duration::from_secs(5)).await;
        assert!(report.is_clean());
    }

    #[test]
    fn set_log_level_needs_the_agent_subscriber() {
        // Test binaries do not install it, so there is nothing to change.
        assert!(!host::set_log_level(LogLevel::Debug));
    }
}

mod boot_and_clock {
    use std::sync::{Arc, Mutex};

    use palisade_agent::{
        boot::BootMode,
        clock::{ClockMonitor, SAMPLE_INTERVAL},
        control::{HostEvent, PowerChange},
        supervisor::{RestartPolicy, Supervisor},
    };
    use palisade_core::platform::{Clock, MonotonicTime, UtcTime};

    use super::*;

    #[tokio::test(start_paused = true)]
    async fn a_safe_mode_boot_reports_safe_mode() {
        let loaded = LoadedConfig {
            config: AgentConfig::default(),
            source: None,
        };
        for (mode, expected) in [
            (BootMode::Normal, AgentState::Running),
            (BootMode::SafeMinimal, AgentState::SafeMode),
            (BootMode::SafeNetwork, AgentState::SafeMode),
        ] {
            let handle = host::supervisor_for(&loaded, mode).unwrap().start();
            let state = handle
                .subscribe()
                .wait_for(|s| *s != AgentState::Starting)
                .await
                .unwrap()
                .clone();
            assert_eq!(state, expected, "{mode:?}");
            // Every subsystem still runs in safe mode.
            assert!(
                handle
                    .report()
                    .subsystems
                    .iter()
                    .all(|r| r.status == palisade_agent::supervisor::SubsystemStatus::Running)
            );
            assert!(handle.shutdown(Duration::from_secs(5)).await.is_clean());
        }
    }

    /// A clock the test moves; shared with the monitor.
    #[derive(Clone, Default)]
    struct SharedClock(Arc<Mutex<(i64, u64)>>);

    impl SharedClock {
        fn advance(&self, secs: u64) {
            let mut t = self.0.lock().unwrap();
            t.0 += i64::try_from(secs).unwrap() * 1_000_000;
            t.1 += secs * 1_000_000;
        }

        fn set_wall_by(&self, secs: i64) {
            self.0.lock().unwrap().0 += secs * 1_000_000;
        }
    }

    impl Clock for SharedClock {
        fn now_utc(&self) -> UtcTime {
            UtcTime(self.0.lock().unwrap().0)
        }

        fn monotonic(&self) -> MonotonicTime {
            MonotonicTime(self.0.lock().unwrap().1)
        }
    }

    async fn settle() {
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test(start_paused = true)]
    async fn the_clock_monitor_reports_jumps_and_ignores_sleep() {
        let clock = SharedClock::default();
        let monitor = Arc::new(ClockMonitor::new(clock.clone()));
        let mut jumps = monitor.subscribe();
        let supervisor = Supervisor::new(vec![monitor.clone()], RestartPolicy::default()).unwrap();
        let events = supervisor.host_events();
        let handle = supervisor.start();
        handle
            .subscribe()
            .wait_for(|s| *s == AgentState::Running)
            .await
            .unwrap();

        // Time passing normally is not a jump.
        clock.advance(60);
        tokio::time::sleep(SAMPLE_INTERVAL).await;
        settle().await;
        assert_eq!(monitor.jumps(), 0);

        // Setting the clock back an hour is reported on TIMECHANGE.
        clock.set_wall_by(-3600);
        events.publish(HostEvent::TimeChange);
        jumps.changed().await.unwrap();
        let jump = jumps.borrow_and_update().unwrap();
        assert_eq!(jump.skew_micros, -3600 * 1_000_000);
        assert_eq!(monitor.jumps(), 1);

        // A suspend: the wall clock moves a day while the monotonic clock
        // stood still. Not a jump.
        events.publish(HostEvent::Power(PowerChange::Suspend));
        settle().await;
        clock.set_wall_by(86_400);
        events.publish(HostEvent::Power(PowerChange::Resume));
        settle().await;
        tokio::time::sleep(SAMPLE_INTERVAL).await;
        settle().await;
        assert_eq!(monitor.jumps(), 1);

        // A forward jump found by the periodic sample.
        clock.set_wall_by(600);
        tokio::time::sleep(SAMPLE_INTERVAL).await;
        jumps.changed().await.unwrap();
        assert_eq!(monitor.jumps(), 2);
        assert!(format!("{monitor:?}").contains("jumps: 2"));
        assert!(handle.shutdown(Duration::from_secs(5)).await.is_clean());
    }
}
