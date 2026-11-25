//! The platform-independent host loop and the console binary.

// Test code: helpers outside `#[test]` functions may unwrap, since a failure
// there should fail the test loudly.
#![allow(clippy::unwrap_used)]

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
    assert_eq!(supervisor.start_order(), ["config"]);
    let mut started = false;
    let (request, report) = host::run_until(supervisor, || started = true, async {
        tokio::time::sleep(Duration::from_secs(5)).await;
        StopRequest::SYSTEM_SHUTDOWN
    })
    .await;
    assert!(started);
    assert_eq!(request.reason, StopReason::SystemShutdown);
    assert_eq!(request.budget, host::SHUTDOWN_BUDGET);
    assert_eq!(report.outcomes, [("config", StopOutcome::Clean)]);
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
    let killed = Command::new("kill").args([signal, &pid]).status().unwrap();
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
