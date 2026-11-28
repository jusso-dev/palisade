//! The SNTP packet codec (RFC 4330, the client side of RFC 5905): builds a
//! request, checks a reply and computes the clock offset.
//!
//! The server uses it for its clock health check (#224: warn when the
//! offset from NTP is over 1 s, ISM-0988), and the agent can use it for its
//! trusted-time checks (#220). It does no I/O: the caller sends the
//! request, receives the reply and reads its own clock.
//!
//! A reply is untrusted network input, so [`Reply::parse`] checks every
//! field it uses and refuses everything else:
//!
//! - exactly 48 bytes (no extension fields or MAC, which SNTP clients do
//!   not use);
//! - version 3 or 4, mode 4 (server);
//! - leap indicator not 3 (the server's clock is not synchronised);
//! - stratum 1 to 15: 0 is a kiss-o'-death or unspecified, 16 and above
//!   unsynchronised;
//! - the originate timestamp equals the transmit timestamp of the request,
//!   so a reply to someone else's request, or a replayed one, is refused;
//! - receive and transmit timestamps are non-zero, and the server did not
//!   send before it received.
//!
//! NTP timestamps are seconds since 1900 in 32.32 fixed point and wrap
//! every 2^32 seconds (in 2036). Each is placed in the era that puts it
//! closest to the local clock, so the codec keeps working across the wrap
//! as long as the local clock is within 68 years of the truth.

#![forbid(unsafe_code)]

use std::fmt;

/// The length of an SNTP packet without extensions.
pub const PACKET_LEN: usize = 48;

/// The NTP port.
pub const PORT: u16 = 123;

/// Seconds from 1900-01-01 (the NTP epoch) to 1970-01-01 (the Unix epoch).
const NTP_UNIX_OFFSET: i128 = 2_208_988_800;
const MICROS_PER_SECOND: i128 = 1_000_000;
/// One NTP era, 2^32 seconds, in microseconds.
const ERA_MICROS: i128 = (1_i128 << 32) * MICROS_PER_SECOND;

const LI_UNSYNCHRONISED: u8 = 3;
const MODE_CLIENT: u8 = 3;
const MODE_SERVER: u8 = 4;
const VERSION: u8 = 4;

/// A 64-bit NTP timestamp: seconds since 1900 in the high 32 bits, the
/// fraction in the low 32.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NtpTimestamp(pub u64);

impl NtpTimestamp {
    /// The NTP timestamp of `unix_micros` (microseconds since 1970),
    /// wrapped into its era. [`Self::to_unix_micros`] gives back exactly
    /// `unix_micros`.
    #[must_use]
    pub fn from_unix_micros(unix_micros: i64) -> Self {
        let ntp_micros = i128::from(unix_micros) + NTP_UNIX_OFFSET * MICROS_PER_SECOND;
        let in_era = ntp_micros.rem_euclid(ERA_MICROS);
        let seconds = in_era / MICROS_PER_SECOND;
        let micros = in_era % MICROS_PER_SECOND;
        // Rounded up, so `to_unix_micros` (which rounds down) gives back
        // the same microsecond. micros < 10^6, so the fraction stays below
        // 2^32.
        let fraction = ((micros << 32) + MICROS_PER_SECOND - 1) / MICROS_PER_SECOND;
        let raw = (seconds << 32) | fraction;
        Self(u64::try_from(raw).unwrap_or(u64::MAX))
    }

    /// Microseconds since 1970, in the era that puts the result closest to
    /// `near_unix_micros`. The fraction is rounded down to a microsecond.
    #[must_use]
    pub fn to_unix_micros(self, near_unix_micros: i64) -> i64 {
        let seconds = i128::from(self.0 >> 32);
        let fraction = i128::from(self.0 & 0xffff_ffff);
        let in_era = seconds * MICROS_PER_SECOND + ((fraction * MICROS_PER_SECOND) >> 32);
        let near = i128::from(near_unix_micros) + NTP_UNIX_OFFSET * MICROS_PER_SECOND;
        // The era whose start is closest below `near - ERA/2`.
        let era = (near - in_era + ERA_MICROS / 2).div_euclid(ERA_MICROS);
        let unix = in_era + era * ERA_MICROS - NTP_UNIX_OFFSET * MICROS_PER_SECOND;
        i64::try_from(unix).unwrap_or(if unix < 0 { i64::MIN } else { i64::MAX })
    }
}

/// An SNTP client request whose transmit timestamp is `transmit`. Keep
/// `transmit`: the reply must echo it.
#[must_use]
pub fn request(transmit: NtpTimestamp) -> [u8; PACKET_LEN] {
    let mut packet = [0u8; PACKET_LEN];
    let [first, .., t0, t1, t2, t3, t4, t5, t6, t7] = &mut packet;
    *first = (VERSION << 3) | MODE_CLIENT;
    for (slot, byte) in [t0, t1, t2, t3, t4, t5, t6, t7]
        .into_iter()
        .zip(transmit.0.to_be_bytes())
    {
        *slot = byte;
    }
    packet
}

/// A checked server reply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reply {
    /// The server's stratum, 1 to 15.
    pub stratum: u8,
    /// When the server received the request.
    pub receive: NtpTimestamp,
    /// When the server sent the reply.
    pub transmit: NtpTimestamp,
}

impl Reply {
    /// Checks `packet` as the reply to the request sent with `sent`.
    ///
    /// # Errors
    ///
    /// [`SntpError`] for each rule in the module docs.
    pub fn parse(packet: &[u8], sent: NtpTimestamp) -> Result<Self, SntpError> {
        let packet: &[u8; PACKET_LEN] = packet.try_into().map_err(|_| SntpError::Length)?;
        let [first, stratum, ..] = *packet;
        let leap = first >> 6;
        let version = (first >> 3) & 0b111;
        let mode = first & 0b111;
        if !matches!(version, 3 | 4) {
            return Err(SntpError::Version(version));
        }
        if mode != MODE_SERVER {
            return Err(SntpError::Mode(mode));
        }
        if stratum == 0 {
            return Err(SntpError::KissOfDeath);
        }
        if leap == LI_UNSYNCHRONISED || stratum > 15 {
            return Err(SntpError::Unsynchronised);
        }
        let ts = |at: usize| {
            let mut b = [0u8; 8];
            if let Some(field) = packet.get(at..at.saturating_add(8)) {
                b.copy_from_slice(field);
            }
            NtpTimestamp(u64::from_be_bytes(b))
        };
        let originate = ts(24);
        let receive = ts(32);
        let transmit = ts(40);
        if originate != sent {
            return Err(SntpError::NotOurs);
        }
        if receive.0 == 0 || transmit.0 == 0 {
            return Err(SntpError::ZeroTimestamp);
        }
        // Within one era a later time has a larger raw value; across the
        // 2036 wrap the wrapping difference is still small and positive.
        if transmit.0.wrapping_sub(receive.0) > (1 << 63) {
            return Err(SntpError::SentBeforeReceived);
        }
        Ok(Self {
            stratum,
            receive,
            transmit,
        })
    }

    /// The local clock's offset from the server in microseconds, positive
    /// when the local clock is behind: `((T2 - T1) + (T3 - T4)) / 2`, with
    /// `t1` the local time the request was sent and `t4` the local time the
    /// reply arrived, both microseconds since 1970.
    #[must_use]
    pub fn offset_micros(&self, t1: i64, t4: i64) -> i64 {
        let t2 = i128::from(self.receive.to_unix_micros(t1));
        let t3 = i128::from(self.transmit.to_unix_micros(t4));
        let offset = ((t2 - i128::from(t1)) + (t3 - i128::from(t4))) / 2;
        i64::try_from(offset).unwrap_or(if offset < 0 { i64::MIN } else { i64::MAX })
    }

    /// The round-trip delay in microseconds, `(T4 - T1) - (T3 - T2)`,
    /// never below zero.
    #[must_use]
    pub fn delay_micros(&self, t1: i64, t4: i64) -> i64 {
        let t2 = i128::from(self.receive.to_unix_micros(t1));
        let t3 = i128::from(self.transmit.to_unix_micros(t4));
        let delay = (i128::from(t4) - i128::from(t1)) - (t3 - t2);
        i64::try_from(delay.max(0)).unwrap_or(i64::MAX)
    }
}

/// Why a reply was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SntpError {
    /// Not exactly [`PACKET_LEN`] bytes.
    Length,
    /// Not version 3 or 4.
    Version(u8),
    /// Not mode 4 (server).
    Mode(u8),
    /// Stratum 0: a kiss-o'-death (the server asks the client to stop or
    /// slow down) or unspecified.
    KissOfDeath,
    /// The server's clock is not synchronised (leap indicator 3, or
    /// stratum 16 or above).
    Unsynchronised,
    /// The originate timestamp is not the one the request sent.
    NotOurs,
    /// The receive or transmit timestamp is zero.
    ZeroTimestamp,
    /// The transmit timestamp is before the receive timestamp.
    SentBeforeReceived,
}

impl fmt::Display for SntpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Length => write!(f, "the reply is not {PACKET_LEN} bytes"),
            Self::Version(v) => write!(f, "unsupported NTP version {v}"),
            Self::Mode(m) => write!(f, "the reply has mode {m}, not server (4)"),
            Self::KissOfDeath => f.write_str("the server sent a kiss-o'-death (stratum 0)"),
            Self::Unsynchronised => f.write_str("the server's clock is not synchronised"),
            Self::NotOurs => f.write_str("the reply does not answer this request"),
            Self::ZeroTimestamp => f.write_str("the reply has a zero timestamp"),
            Self::SentBeforeReceived => f.write_str("the reply was sent before it was received"),
        }
    }
}

impl std::error::Error for SntpError {}

#[cfg(test)]
mod tests {
    // Tests may index: a panic is a test failure.
    #![allow(clippy::indexing_slicing)]

    use super::*;

    const SECOND: i64 = 1_000_000;
    /// 2026-11-24T00:00:00Z.
    const NOW: i64 = 1_795_478_400 * SECOND;

    /// A valid reply to `sent`, with the server's receive and transmit
    /// times at `t2` and `t3` (Unix microseconds).
    fn reply(sent: NtpTimestamp, t2: i64, t3: i64) -> [u8; PACKET_LEN] {
        let mut p = [0u8; PACKET_LEN];
        p[0] = (VERSION << 3) | MODE_SERVER;
        p[1] = 2;
        p[24..32].copy_from_slice(&sent.0.to_be_bytes());
        p[32..40].copy_from_slice(&NtpTimestamp::from_unix_micros(t2).0.to_be_bytes());
        p[40..48].copy_from_slice(&NtpTimestamp::from_unix_micros(t3).0.to_be_bytes());
        p
    }

    #[test]
    fn known_timestamps() {
        // The Unix epoch is NTP second 2,208,988,800.
        assert_eq!(NtpTimestamp::from_unix_micros(0).0, 2_208_988_800 << 32);
        // Half a second is fraction 2^31 (exact, so not rounded).
        assert_eq!(
            NtpTimestamp::from_unix_micros(SECOND / 2).0,
            (2_208_988_800 << 32) | (1 << 31)
        );
        assert_eq!(
            NtpTimestamp((2_208_988_800 << 32) | (1 << 31)).to_unix_micros(0),
            SECOND / 2
        );
    }

    #[test]
    fn timestamps_round_trip_across_the_2036_wrap() {
        // 2036-02-07T06:28:16Z is where NTP era 0 ends.
        let wrap = (1_i64 << 32) * SECOND - 2_208_988_800 * SECOND;
        for t in [
            NOW,
            0,
            -SECOND,
            wrap - 1,
            wrap,
            wrap + 1,
            wrap + 10 * 365 * 86_400 * SECOND,
            NOW + 123_456,
        ] {
            let ntp = NtpTimestamp::from_unix_micros(t);
            assert_eq!(ntp.to_unix_micros(t), t, "{t}");
            // A local clock a few hours off still picks the right era.
            assert_eq!(ntp.to_unix_micros(t + 3 * 3600 * SECOND), t, "{t}");
            assert_eq!(ntp.to_unix_micros(t - 3 * 3600 * SECOND), t, "{t}");
        }
        assert_eq!(NtpTimestamp::from_unix_micros(wrap).0 >> 32, 0);
        // Extreme inputs saturate instead of overflowing.
        let _ = NtpTimestamp(u64::MAX).to_unix_micros(i64::MAX);
        let _ = NtpTimestamp(0).to_unix_micros(i64::MIN);
        let _ = NtpTimestamp::from_unix_micros(i64::MIN);
    }

    #[test]
    fn request_layout() {
        let sent = NtpTimestamp::from_unix_micros(NOW);
        let r = request(sent);
        assert_eq!(r[0], 0b00_100_011);
        assert!(r[1..40].iter().all(|&b| b == 0));
        assert_eq!(&r[40..], &sent.0.to_be_bytes());
    }

    #[test]
    fn offset_and_delay() {
        let t1 = NOW;
        let sent = NtpTimestamp::from_unix_micros(t1);
        // The local clock is 1.5 s behind; 40 ms each way; 10 ms in the server.
        let behind = 1_500_000;
        let t2 = t1 + 40_000 + behind;
        let t3 = t2 + 10_000;
        let t4 = t1 + 90_000;
        let r = Reply::parse(&reply(sent, t2, t3), sent).unwrap();
        assert_eq!(r.stratum, 2);
        assert_eq!(r.offset_micros(t1, t4), behind);
        assert_eq!(r.delay_micros(t1, t4), 80_000);
        // Ahead by 2 s.
        let r = Reply::parse(&reply(sent, t1 - 2 * SECOND, t1 - 2 * SECOND), sent).unwrap();
        assert_eq!(r.offset_micros(t1, t1), -2 * SECOND);
        // A reply that claims more server time than the round trip has no
        // negative delay.
        let r = Reply::parse(&reply(sent, t1, t1 + SECOND), sent).unwrap();
        assert_eq!(r.delay_micros(t1, t1), 0);
    }

    #[test]
    fn every_rule_is_checked() {
        let sent = NtpTimestamp::from_unix_micros(NOW);
        let good = reply(sent, NOW, NOW);
        Reply::parse(&good, sent).unwrap();
        let with = |f: fn(&mut [u8; PACKET_LEN])| {
            let mut p = good;
            f(&mut p);
            Reply::parse(&p, sent)
        };
        assert_eq!(Reply::parse(&good[..47], sent), Err(SntpError::Length));
        assert_eq!(
            Reply::parse(&[good.as_slice(), &[0]].concat(), sent),
            Err(SntpError::Length)
        );
        assert_eq!(with(|p| p[0] = (2 << 3) | 4), Err(SntpError::Version(2)));
        assert_eq!(with(|p| p[0] = (5 << 3) | 4), Err(SntpError::Version(5)));
        with(|p| p[0] = (3 << 3) | 4).unwrap();
        assert_eq!(with(|p| p[0] = (4 << 3) | 3), Err(SntpError::Mode(3)));
        assert_eq!(with(|p| p[0] = (4 << 3) | 5), Err(SntpError::Mode(5)));
        assert_eq!(with(|p| p[1] = 0), Err(SntpError::KissOfDeath));
        assert_eq!(with(|p| p[1] = 16), Err(SntpError::Unsynchronised));
        with(|p| p[1] = 15).unwrap();
        assert_eq!(with(|p| p[0] |= 0b11 << 6), Err(SntpError::Unsynchronised));
        // Leap second warnings (1 and 2) are fine.
        with(|p| p[0] |= 0b01 << 6).unwrap();
        with(|p| p[0] |= 0b10 << 6).unwrap();
        assert_eq!(with(|p| p[31] ^= 1), Err(SntpError::NotOurs));
        assert_eq!(with(|p| p[32..40].fill(0)), Err(SntpError::ZeroTimestamp));
        assert_eq!(with(|p| p[40..48].fill(0)), Err(SntpError::ZeroTimestamp));
        let sent_early = reply(sent, NOW, NOW - SECOND);
        assert_eq!(
            Reply::parse(&sent_early, sent),
            Err(SntpError::SentBeforeReceived)
        );
        for e in [
            SntpError::Length,
            SntpError::Version(2),
            SntpError::Mode(3),
            SntpError::KissOfDeath,
            SntpError::Unsynchronised,
            SntpError::NotOurs,
            SntpError::ZeroTimestamp,
            SntpError::SentBeforeReceived,
        ] {
            assert!(!e.to_string().is_empty());
        }
    }
}
