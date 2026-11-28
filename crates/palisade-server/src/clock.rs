//! The clock health check (#224, ISM-0988).
//!
//! Certificate, token and trust-set validity all depend on the server's
//! clock. Every `clock.check_interval_secs` the server asks the configured
//! NTP servers for the time over SNTP (`palisade_proto::sntp`), in order,
//! and uses the first valid reply. Health then reports:
//!
//! - nothing, when the offset is at most `clock.max_offset_ms` (1 s by
//!   default);
//! - `clock_offset` (status `degraded`, still ready) when it is larger, with
//!   a warning in the log;
//! - `clock_unknown` (status `degraded`, still ready) when no server gave a
//!   valid reply, so an unmeasured clock is never reported as good.
//!
//! The check only reports. It never steps or slews the clock: that is the
//! operating system's NTP client's job. A bad clock degrades rather than
//! fails readiness, because taking every listener out of service would
//! strand agents for a problem the server cannot fix by itself.
//!
//! Without `clock.ntp_servers` the check does not run and health carries no
//! clock indicator; `serve` logs that the clock is unmonitored.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use palisade_proto::pki::{Clock, SystemClock};
use palisade_proto::sntp::{self, NtpTimestamp, Reply};
use tokio::net::UdpSocket;

use crate::config::ClockSettings;
use crate::health::{ClockHealth, Health};

/// How long one server has to answer.
const QUERY_TIMEOUT: Duration = Duration::from_secs(2);

/// The local clock, in microseconds since 1970.
pub type LocalClock = Arc<dyn Fn() -> i64 + Send + Sync>;

/// The system clock, read through the PKI's [`Clock`].
#[must_use]
pub fn system_clock() -> LocalClock {
    Arc::new(|| SystemClock.now().unix_micros())
}

/// One measurement: the offset (positive when the local clock is behind)
/// and the round-trip delay, both in microseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Measurement {
    /// Offset of the local clock from the server's.
    pub offset_micros: i64,
    /// Round-trip delay.
    pub delay_micros: i64,
}

/// Asks one NTP server for the time.
///
/// # Errors
///
/// A message naming the server and the problem: resolution, I/O, a
/// timeout, or a reply that `sntp::Reply::parse` refuses.
pub async fn query(server: &str, clock: &LocalClock) -> Result<Measurement, String> {
    let target = resolve(server).await?;
    let bind: SocketAddr = if target.is_ipv6() {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    } else {
        (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
    };
    let socket = UdpSocket::bind(bind)
        .await
        .map_err(|e| format!("NTP server {server}: cannot open a socket: {e}"))?;
    socket
        .connect(target)
        .await
        .map_err(|e| format!("NTP server {server}: {e}"))?;
    let t1 = clock();
    let sent = NtpTimestamp::from_unix_micros(t1);
    socket
        .send(&sntp::request(sent))
        .await
        .map_err(|e| format!("NTP server {server}: cannot send: {e}"))?;
    // One byte more than a packet, so a longer datagram is seen as such.
    let mut buf = [0u8; sntp::PACKET_LEN + 1];
    let deadline = tokio::time::Instant::now() + QUERY_TIMEOUT;
    loop {
        let n = tokio::time::timeout_at(deadline, socket.recv(&mut buf))
            .await
            .map_err(|_| format!("NTP server {server}: no reply within {QUERY_TIMEOUT:?}"))?
            .map_err(|e| format!("NTP server {server}: cannot receive: {e}"))?;
        let t4 = clock();
        match Reply::parse(buf.get(..n).unwrap_or_default(), sent) {
            Ok(reply) => {
                return Ok(Measurement {
                    offset_micros: reply.offset_micros(t1, t4),
                    delay_micros: reply.delay_micros(t1, t4),
                });
            }
            // A stray or stale datagram: keep waiting for ours.
            Err(sntp::SntpError::NotOurs) => {}
            Err(e) => return Err(format!("NTP server {server}: {e}")),
        }
    }
}

async fn resolve(server: &str) -> Result<SocketAddr, String> {
    let with_port = if has_port(server) {
        server.to_owned()
    } else if server.starts_with('[') {
        format!("{server}:{}", sntp::PORT)
    } else if server.contains(':') {
        format!("[{server}]:{}", sntp::PORT)
    } else {
        format!("{server}:{}", sntp::PORT)
    };
    tokio::net::lookup_host(&with_port)
        .await
        .map_err(|e| format!("NTP server {server}: cannot resolve: {e}"))?
        .next()
        .ok_or_else(|| format!("NTP server {server}: no address"))
}

/// Whether `server` already names a port: `host:port` or `[v6]:port`.
fn has_port(server: &str) -> bool {
    if server.starts_with('[') {
        server.contains("]:")
    } else {
        server.matches(':').count() == 1
    }
}

/// One check: the first server that answers decides. Returns the health
/// to record and, for the log, why each failing server failed.
pub async fn check(settings: &ClockSettings, clock: &LocalClock) -> (ClockHealth, Vec<String>) {
    let mut failures = Vec::new();
    for server in &settings.ntp_servers {
        match query(server, clock).await {
            Ok(m) => return (classify(m.offset_micros, settings.max_offset), failures),
            Err(e) => failures.push(e),
        }
    }
    (ClockHealth::Unknown, failures)
}

/// The health for a measured offset.
#[must_use]
pub fn classify(offset_micros: i64, max: Duration) -> ClockHealth {
    let max = i64::try_from(max.as_micros()).unwrap_or(i64::MAX);
    if offset_micros.unsigned_abs() > max.unsigned_abs() {
        ClockHealth::Skewed { offset_micros }
    } else {
        ClockHealth::Synced { offset_micros }
    }
}

/// Runs the check every `settings.interval` and records the result. Logs
/// only when the state changes between synced, skewed and unknown, so a
/// steady problem does not flood the log.
pub async fn watch(settings: ClockSettings, health: Arc<Health>, clock: LocalClock) {
    let mut last: Option<std::mem::Discriminant<ClockHealth>> = None;
    loop {
        let (state, failures) = check(&settings, &clock).await;
        let kind = std::mem::discriminant(&state);
        if last != Some(kind) {
            match state {
                ClockHealth::Synced { offset_micros } => {
                    tracing::info!(
                        offset_ms = offset_micros / 1000,
                        "clock synchronised with NTP"
                    );
                }
                ClockHealth::Skewed { offset_micros } => tracing::warn!(
                    offset_ms = offset_micros / 1000,
                    max_offset_ms =
                        u64::try_from(settings.max_offset.as_millis()).unwrap_or(u64::MAX),
                    "clock offset from NTP is above the limit; check the operating system's time synchronisation"
                ),
                ClockHealth::Unknown => tracing::warn!(
                    reasons = %failures.join("; "),
                    "clock offset unknown: no NTP server gave a valid reply"
                ),
            }
        }
        last = Some(kind);
        health.set_clock(state);
        tokio::time::sleep(settings.interval).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECOND: i64 = 1_000_000;
    /// 2026-11-24T00:00:00Z.
    const NOW: i64 = 1_795_478_400 * SECOND;

    fn fixed(t: i64) -> LocalClock {
        Arc::new(move || t)
    }

    fn settings(servers: Vec<String>) -> ClockSettings {
        ClockSettings {
            ntp_servers: servers,
            max_offset: Duration::from_secs(1),
            interval: Duration::from_secs(16),
        }
    }

    /// A one-shot SNTP server on loopback whose clock is `server_time`.
    /// `mangle` may alter the reply.
    async fn fake_server(server_time: i64, mangle: fn(&mut [u8; sntp::PACKET_LEN])) -> SocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 64];
            let (n, from) = socket.recv_from(&mut buf).await.unwrap();
            assert_eq!(n, sntp::PACKET_LEN);
            let mut reply = [0u8; sntp::PACKET_LEN];
            reply[0] = (4 << 3) | 4;
            reply[1] = 1;
            reply[24..32].copy_from_slice(&buf[40..48]);
            let t = NtpTimestamp::from_unix_micros(server_time).0.to_be_bytes();
            reply[32..40].copy_from_slice(&t);
            reply[40..48].copy_from_slice(&t);
            mangle(&mut reply);
            socket.send_to(&reply, from).await.unwrap();
        });
        addr
    }

    #[tokio::test]
    async fn measures_offset_from_a_server() {
        let addr = fake_server(NOW + 3 * SECOND, |_| {}).await;
        let m = query(&addr.to_string(), &fixed(NOW)).await.unwrap();
        assert_eq!(m.offset_micros, 3 * SECOND);
        assert_eq!(m.delay_micros, 0);
    }

    #[tokio::test]
    async fn check_classifies_and_falls_back() {
        // The first server refuses (port with nothing listening may or may
        // not answer, so use a server that sends a bad reply), the second
        // answers within the limit.
        let bad = fake_server(NOW, |r| r[1] = 0).await;
        let good = fake_server(NOW + 500_000, |_| {}).await;
        let (state, failures) = check(
            &settings(vec![bad.to_string(), good.to_string()]),
            &fixed(NOW),
        )
        .await;
        assert_eq!(
            state,
            ClockHealth::Synced {
                offset_micros: 500_000
            }
        );
        assert_eq!(failures.len(), 1);
        assert!(failures[0].contains("kiss-o'-death"), "{failures:?}");

        let skewed = fake_server(NOW - 2 * SECOND, |_| {}).await;
        let (state, _) = check(&settings(vec![skewed.to_string()]), &fixed(NOW)).await;
        assert_eq!(
            state,
            ClockHealth::Skewed {
                offset_micros: -2 * SECOND
            }
        );
    }

    #[tokio::test]
    async fn no_valid_reply_is_unknown() {
        let unsynced = fake_server(NOW, |r| r[0] |= 0b11 << 6).await;
        let (state, failures) = check(
            &settings(vec![unsynced.to_string(), "host.invalid".to_owned()]),
            &fixed(NOW),
        )
        .await;
        assert_eq!(state, ClockHealth::Unknown);
        assert_eq!(failures.len(), 2);
        assert!(failures[0].contains("not synchronised"), "{failures:?}");
        assert!(failures[1].contains("host.invalid"), "{failures:?}");
        let (state, failures) = check(&settings(vec![]), &fixed(NOW)).await;
        assert_eq!(state, ClockHealth::Unknown);
        assert!(failures.is_empty());
    }

    #[tokio::test]
    async fn a_reply_to_another_request_is_ignored_until_timeout() {
        let foreign = fake_server(NOW, |r| r[31] ^= 1).await;
        let e = query(&foreign.to_string(), &fixed(NOW)).await.unwrap_err();
        assert!(e.contains("no reply"), "{e}");
    }

    #[test]
    fn classify_bounds() {
        let max = Duration::from_secs(1);
        assert_eq!(
            classify(SECOND, max),
            ClockHealth::Synced {
                offset_micros: SECOND
            }
        );
        assert_eq!(
            classify(-SECOND, max),
            ClockHealth::Synced {
                offset_micros: -SECOND
            }
        );
        assert_eq!(
            classify(SECOND + 1, max),
            ClockHealth::Skewed {
                offset_micros: SECOND + 1
            }
        );
        assert_eq!(
            classify(-SECOND - 1, max),
            ClockHealth::Skewed {
                offset_micros: -SECOND - 1
            }
        );
        assert_eq!(
            classify(i64::MIN, max),
            ClockHealth::Skewed {
                offset_micros: i64::MIN
            }
        );
    }

    #[test]
    fn port_detection() {
        assert!(has_port("pool.example.org:123"));
        assert!(!has_port("pool.example.org"));
        assert!(has_port("[::1]:123"));
        assert!(!has_port("[::1]"));
        assert!(!has_port("::1"));
    }

    #[test]
    fn system_clock_is_after_2020() {
        assert!(system_clock()() > 1_577_836_800 * SECOND);
    }
}
