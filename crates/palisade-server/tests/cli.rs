//! End-to-end tests of the `palisade-server` binary.

// Test helpers outside `#[test]` functions unwrap freely.
#![allow(clippy::unwrap_used)]

mod common;

use std::process::Command;

use common::*;

const BIN: &str = env!("CARGO_BIN_EXE_palisade-server");

fn config_body(admin: u16, agent: u16, extra: &str) -> String {
    format!(
        "[listen.admin]\nbind = \"127.0.0.1\"\nport = {admin}\npublic_url = \"https://localhost:{admin}\"\n\
         [listen.agent]\nbind = \"127.0.0.1\"\nport = {agent}\nclient_ca_file = \"agent-ca.crt\"\n{extra}"
    )
}

fn run(args: &[&str], env: &[(&str, &str)]) -> (i32, String, String) {
    let mut cmd = Command::new(BIN);
    cmd.args(args);
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.output().unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn version_prints_the_crate_version() {
    let (code, out, _) = run(&["version"], &[]);
    assert_eq!(code, 0);
    assert_eq!(
        out.trim(),
        format!("palisade-server {}", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn check_config_prints_effective_config_without_secrets() {
    let pki = pki("cli-ok", &["localhost"]);
    let path = write_config(&pki, &config_body(1, 2, "[log]\nlevel = \"warn\"\n"));
    let key = std::fs::read_to_string(&pki.server_key).unwrap();
    let key_body: String = key.lines().nth(1).unwrap().to_owned();
    let (code, out, err) = run(
        &["check-config", "--config", path.to_str().unwrap()],
        &[("PALISADE_LISTEN__ADMIN__PORT", "1443")],
    );
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("configuration OK"), "{err}");
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["listen"]["admin"]["port"], 1443, "env override applies");
    assert_eq!(v["log"]["level"], "warn");
    assert!(
        v["tls"]["key_file"]
            .as_str()
            .unwrap()
            .contains("never shown")
    );
    assert!(!out.contains(&key_body) && !err.contains(&key_body));
    assert!(!out.contains("PRIVATE KEY") && !err.contains("PRIVATE KEY"));
}

#[test]
fn check_config_uses_env_for_the_path_and_reports_all_problems() {
    let pki = pki("cli-bad", &["localhost"]);
    let path = write_config(
        &pki,
        "[listen.admin]\nbind = \"0.0.0.0:1\"\nport = 0\n[log]\nlevel = \"noisy\"\n",
    );
    let (code, _, err) = run(
        &["check-config"],
        &[("PALISADE_CONFIG", path.to_str().unwrap())],
    );
    assert_eq!(code, 2, "{err}");
    for needle in [
        "listen.admin.bind",
        "listen.admin.port",
        "listen.agent",
        "log.level",
    ] {
        assert!(err.contains(needle), "missing {needle}: {err}");
    }
}

#[test]
fn check_config_rejects_a_public_url_outside_the_sans() {
    let pki = pki("cli-san", &["palisade-server.overlay.test"]);
    let path = write_config(&pki, &config_body(1, 2, ""));
    let (code, _, err) = run(&["check-config", "-c", path.to_str().unwrap()], &[]);
    assert_eq!(code, 2, "{err}");
    assert!(err.contains("listen.admin.public_url"), "{err}");
    assert!(err.contains("subject alternative names"), "{err}");
}

#[test]
fn check_config_warns_about_public_exposure_under_overlay() {
    let pki = pki("cli-overlay", &["localhost"]);
    let path = write_config(
        &pki,
        &config_body(1, 2, "[deployment]\nprofile = \"overlay\"\n").replacen(
            "bind = \"127.0.0.1\"",
            "bind = \"0.0.0.0\"",
            1,
        ),
    );
    let (code, _, err) = run(&["check-config", "-c", path.to_str().unwrap()], &[]);
    assert_eq!(code, 0, "{err}");
    assert!(
        err.contains("warning: listen.admin: binds every interface"),
        "{err}"
    );
}

#[cfg(unix)]
#[test]
fn group_readable_key_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let pki = pki("cli-perm", &["localhost"]);
    std::fs::set_permissions(&pki.server_key, std::fs::Permissions::from_mode(0o640)).unwrap();
    let path = write_config(&pki, &config_body(1, 2, ""));
    let (code, _, err) = run(&["check-config", "-c", path.to_str().unwrap()], &[]);
    assert_eq!(code, 2, "{err}");
    assert!(err.contains("chmod 600"), "{err}");
}

#[test]
fn missing_config_is_a_usage_error() {
    let (code, _, err) = run(&["check-config"], &[]);
    assert_eq!(code, 2, "{err}");
    assert!(err.contains("--config"), "{err}");
}

#[cfg(unix)]
fn send_signal(child: &std::process::Child, sig: &str) {
    let status = Command::new("kill")
        .args([sig, &child.id().to_string()])
        .status()
        .unwrap();
    assert!(status.success());
}

#[cfg(unix)]
fn wait_for_line(
    rx: &std::sync::mpsc::Receiver<String>,
    lines: &mut Vec<String>,
    needle: &str,
    count: usize,
) {
    use std::time::{Duration, Instant};
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut seen = lines.iter().filter(|l| l.contains(needle)).count();
    while seen < count && Instant::now() < deadline {
        if let Ok(line) = rx.recv_timeout(Duration::from_millis(100)) {
            if line.contains(needle) {
                seen += 1;
            }
            lines.push(line);
        }
    }
    assert!(seen >= count, "never saw {count} x {needle}: {lines:#?}");
}

#[cfg(unix)]
#[test]
fn second_signal_during_drain_exits_one() {
    use std::io::{BufRead, BufReader};
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    // A long grace period and a connection held open: the drain cannot
    // finish, so only the second signal ends the process, with exit 1.
    let pki = pki("cli-second", &["localhost"]);
    let [admin, agent] = free_ports();
    let path = write_config(
        &pki,
        &config_body(admin, agent, "[shutdown]\ngrace_secs = 600\n"),
    );
    let mut child = Command::new(BIN)
        .args(["serve", "--config", path.to_str().unwrap()])
        .stderr(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    let stderr = child.stderr.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    let mut lines = Vec::new();
    wait_for_line(&rx, &mut lines, "\"listening\"", 2);

    // A TLS connection with half a request head keeps the drain waiting:
    // HTTP/1.1 graceful shutdown lets a request that has started finish.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let held = rt.block_on(async {
        use tokio::io::AsyncWriteExt;
        let cfg = client_config(&pki, &[&rustls::version::TLS13], None, &[b"http/1.1"]);
        let addr = std::net::SocketAddr::from(([127, 0, 0, 1], admin));
        let mut s = connect(cfg, addr, "localhost").await.unwrap();
        s.write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n")
            .await
            .unwrap();
        s.flush().await.unwrap();
        s
    });
    std::thread::sleep(Duration::from_millis(200));

    send_signal(&child, "-TERM");
    wait_for_line(&rx, &mut lines, "shutdown started", 1);
    send_signal(&child, "-INT");
    let deadline = Instant::now() + Duration::from_secs(10);
    let code = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break s.code();
        }
        assert!(
            Instant::now() < deadline,
            "second signal did not end the process"
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    while let Ok(line) = rx.recv_timeout(Duration::from_millis(300)) {
        lines.push(line);
    }
    assert_eq!(code, Some(1), "{lines:#?}");
    assert!(
        lines.iter().any(|l| l.contains("second shutdown signal")),
        "{lines:#?}"
    );
    drop(held);
}

#[cfg(unix)]
#[test]
fn serve_logs_json_and_exits_zero_on_sigterm() {
    use std::io::{BufRead, BufReader};
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    let pki = pki("cli-serve", &["localhost"]);
    let [admin, agent] = free_ports();
    let path = write_config(&pki, &config_body(admin, agent, ""));
    let key = std::fs::read_to_string(&pki.server_key).unwrap();
    let key_body: String = key.lines().nth(1).unwrap().to_owned();

    let mut child = Command::new(BIN)
        .args(["serve", "--config", path.to_str().unwrap()])
        .stderr(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    let stderr = child.stderr.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });

    let mut lines = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut listening = 0;
    while listening < 2 && Instant::now() < deadline {
        if let Ok(line) = rx.recv_timeout(Duration::from_millis(100)) {
            if line.contains("\"listening\"") {
                listening += 1;
            }
            lines.push(line);
        }
    }
    assert_eq!(listening, 2, "both listeners must bind: {lines:#?}");

    let status = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .unwrap();
    assert!(status.success());
    let deadline = Instant::now() + Duration::from_secs(10);
    let code = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break s.code();
        }
        assert!(
            Instant::now() < deadline,
            "server did not exit after SIGTERM"
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    while let Ok(line) = rx.recv_timeout(Duration::from_millis(500)) {
        lines.push(line);
    }
    assert_eq!(code, Some(0), "{lines:#?}");

    for line in &lines {
        let v: serde_json::Value = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("not a JSON log line ({e}): {line}"));
        assert!(
            v["timestamp"].is_string() && v["level"].is_string(),
            "{line}"
        );
        assert!(
            !line.contains(&key_body) && !line.contains("PRIVATE KEY"),
            "{line}"
        );
    }
    let all = lines.join("\n");
    assert!(all.contains("shutdown signal received"), "{all}");
    assert!(all.contains("shutdown complete"), "{all}");
}
