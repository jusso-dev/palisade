//! IP addresses, address ranges, octet wildcards and MAC addresses (#32).
//!
//! These are the values of the network operators (`ip_in_cidr`,
//! `ip_between`, `ip_wildcard`) and of `net.mac`. They are public so that
//! scopes (#38) parse and compare addresses exactly as criteria do.
//!
//! An IPv4 address written in IPv6 form (`::ffff:192.0.2.1`) is the IPv4
//! address: [`canonical`] maps it, on both sides, so a rule written for one
//! form matches a fact in the other. A CIDR block is checked in the form it
//! is written in, so `::ffff:10.0.0.0/104` is `10.0.0.0/8` and
//! `::ffff:10.0.0.0/8` is rejected for its host bits. An IPv6 block wider
//! than `::ffff:0:0/96`, such as `::/0`, or an explicit IPv6 range
//! (`ip_between`) that spans part of `::ffff:0:0/96`, holds the IPv4
//! addresses it covers in mapped form: every IPv6 range tests an IPv4
//! address by its mapped form. Otherwise IPv4 and IPv6 never match each
//! other.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// `ip` with an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) replaced by the
/// IPv4 address.
#[must_use]
pub fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        IpAddr::V4(_) => ip,
    }
}

/// Reads one IPv4 or IPv6 address in its standard text form, in
/// [`canonical`] form. No surrounding spaces, ports, brackets or zone IDs.
#[must_use]
pub fn parse_ip(s: &str) -> Option<IpAddr> {
    s.parse::<IpAddr>().ok().map(canonical)
}

/// An inclusive range of addresses of one family.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IpRange {
    first: IpAddr,
    last: IpAddr,
}

impl IpRange {
    /// A range from `first` to `last`, both included. `None` if they are of
    /// different families or `last` is below `first`.
    #[must_use]
    pub fn new(first: IpAddr, last: IpAddr) -> Option<Self> {
        let (first, last) = (canonical(first), canonical(last));
        let ordered = match (first, last) {
            (IpAddr::V4(a), IpAddr::V4(b)) => a <= b,
            (IpAddr::V6(a), IpAddr::V6(b)) => a <= b,
            _ => false,
        };
        ordered.then_some(Self { first, last })
    }

    /// Reads a CIDR block such as `10.0.0.0/8` or `2001:db8::/32`. The
    /// address must be the first of the block: `10.1.2.3/8` is rejected,
    /// because the bits after the prefix would be silently ignored.
    ///
    /// # Errors
    ///
    /// Returns why the text is not a CIDR block.
    pub fn parse_cidr(s: &str) -> Result<Self, String> {
        let (addr, prefix) = s
            .split_once('/')
            .ok_or_else(|| "expected an address, `/` and a prefix length".to_owned())?;
        // The prefix applies to the address as written; an IPv4-mapped
        // IPv6 block is mapped to IPv4 only after it is checked.
        let written: IpAddr = addr
            .parse()
            .map_err(|_| format!("`{addr}` is not an IP address"))?;
        let bits: u32 = if written.is_ipv4() { 32 } else { 128 };
        let prefix: u32 = Some(prefix)
            .filter(|p| !p.is_empty() && p.len() <= 3 && p.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|p| p.parse().ok())
            .filter(|p| *p <= bits)
            .ok_or_else(|| format!("the prefix length must be 0 to {bits}"))?;
        let block = match written {
            IpAddr::V4(v4) => {
                let n = u32::from(v4);
                let mask = u32::MAX.checked_shl(32 - prefix).unwrap_or(0);
                if n & !mask != 0 {
                    return Err(format!(
                        "bits after the prefix are set; the block is `{}/{prefix}`",
                        Ipv4Addr::from(n & mask)
                    ));
                }
                Self {
                    first: written,
                    last: IpAddr::V4(Ipv4Addr::from(n | !mask)),
                }
            }
            IpAddr::V6(v6) => {
                let n = u128::from(v6);
                let mask = u128::MAX.checked_shl(128 - prefix).unwrap_or(0);
                if n & !mask != 0 {
                    return Err(format!(
                        "bits after the prefix are set; the block is `{}/{prefix}`",
                        Ipv6Addr::from(n & mask)
                    ));
                }
                Self {
                    first: written,
                    last: IpAddr::V6(Ipv6Addr::from(n | !mask)),
                }
            }
        };
        // A block within `::ffff:0:0/96` is IPv4. One that is wider, such as
        // `::/0`, stays IPv6, and `contains` tests an IPv4 address against
        // it in its mapped form.
        let (first, last) = (canonical(block.first), canonical(block.last));
        if first.is_ipv4() == last.is_ipv4() {
            Ok(Self { first, last })
        } else {
            Ok(block)
        }
    }

    /// Reads a range written as two addresses, `192.168.1.10-192.168.1.20`,
    /// or, for IPv4, as an address and the last octet of the end,
    /// `192.168.1.10-20`. Both ends are included.
    ///
    /// # Errors
    ///
    /// Returns why the text is not a range.
    pub fn parse_range(s: &str) -> Result<Self, String> {
        let (a, b) = s
            .split_once('-')
            .ok_or_else(|| "expected `first-last`, such as `192.168.1.10-20`".to_owned())?;
        let first = parse_ip(a).ok_or_else(|| format!("`{a}` is not an IP address"))?;
        let last = match (first, b.parse::<u8>()) {
            // The octet shorthand: digits only, at most 3 of them.
            (IpAddr::V4(v4), Ok(octet))
                if !b.is_empty() && b.len() <= 3 && b.bytes().all(|c| c.is_ascii_digit()) =>
            {
                let [x, y, z, _] = v4.octets();
                IpAddr::V4(Ipv4Addr::new(x, y, z, octet))
            }
            _ => parse_ip(b).ok_or_else(|| format!("`{b}` is not an IP address or an octet"))?,
        };
        Self::new(first, last)
            .ok_or_else(|| "the end must be of the same family and not below the start".to_owned())
    }

    /// Whether the range holds `ip`. An IPv4 address is in an IPv6 range,
    /// whether it came from a CIDR block or from two explicit endpoints,
    /// if its mapped form (`::ffff:a.b.c.d`) is.
    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.first, self.last, canonical(ip)) {
            (IpAddr::V4(a), IpAddr::V4(b), IpAddr::V4(x)) => a <= x && x <= b,
            (IpAddr::V6(a), IpAddr::V6(b), IpAddr::V6(x)) => a <= x && x <= b,
            (IpAddr::V6(a), IpAddr::V6(b), IpAddr::V4(x)) => {
                let x = x.to_ipv6_mapped();
                a <= x && x <= b
            }
            _ => false,
        }
    }

    /// The first address.
    #[must_use]
    pub const fn first(&self) -> IpAddr {
        self.first
    }

    /// The last address.
    #[must_use]
    pub const fn last(&self) -> IpAddr {
        self.last
    }
}

/// An IPv4 pattern with whole-octet wildcards, such as `10.*.*.*` or
/// `192.168.*.1`. It never matches an IPv6 address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IpWildcard([Option<u8>; 4]);

impl IpWildcard {
    /// Reads four dot-separated parts, each a decimal octet or `*`.
    ///
    /// # Errors
    ///
    /// Returns why the text is not such a pattern.
    pub fn parse(s: &str) -> Result<Self, String> {
        let mut octets = [None; 4];
        let mut parts = s.split('.');
        for octet in &mut octets {
            let part = parts
                .next()
                .ok_or_else(|| "expected four parts, such as `10.*.*.*`".to_owned())?;
            *octet = match part {
                "*" => None,
                p if !p.is_empty() && p.len() <= 3 && p.bytes().all(|b| b.is_ascii_digit()) => {
                    Some(
                        p.parse::<u8>()
                            .map_err(|_| format!("`{p}` is not an octet"))?,
                    )
                }
                p => return Err(format!("`{p}` is not an octet or `*`")),
            };
        }
        if parts.next().is_some() {
            return Err("expected four parts, such as `10.*.*.*`".to_owned());
        }
        Ok(Self(octets))
    }

    /// Whether the pattern matches `ip`.
    #[must_use]
    pub fn matches(&self, ip: IpAddr) -> bool {
        match canonical(ip) {
            IpAddr::V4(v4) => self
                .0
                .iter()
                .zip(v4.octets())
                .all(|(want, have)| want.is_none_or(|w| w == have)),
            IpAddr::V6(_) => false,
        }
    }
}

/// Reads a MAC address: six hex octets separated by `:` or `-`, or twelve
/// hex digits, in either case.
#[must_use]
pub fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let digits: String = if s.len() == 17 {
        let sep = s.as_bytes()[2];
        if !matches!(sep, b':' | b'-') {
            return None;
        }
        let mut out = String::with_capacity(12);
        for (i, part) in s.split(char::from(sep)).enumerate() {
            if i >= 6 || part.len() != 2 {
                return None;
            }
            out.push_str(part);
        }
        out
    } else {
        s.to_owned()
    };
    if digits.len() != 12 || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut mac = [0u8; 6];
    for (i, byte) in mac.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&digits[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(mac)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        parse_ip(s).unwrap()
    }

    #[test]
    fn cidr_blocks() {
        let r = IpRange::parse_cidr("10.0.0.0/8").unwrap();
        assert!(r.contains(ip("10.255.0.1")));
        assert!(!r.contains(ip("11.0.0.0")));
        assert!(r.contains(ip("::ffff:10.1.2.3")));
        assert!(
            IpRange::parse_cidr("0.0.0.0/0")
                .unwrap()
                .contains(ip("255.255.255.255"))
        );
        assert!(
            IpRange::parse_cidr("192.0.2.7/32")
                .unwrap()
                .contains(ip("192.0.2.7"))
        );
        let v6 = IpRange::parse_cidr("2001:db8::/32").unwrap();
        assert!(v6.contains(ip("2001:db8:ffff::1")));
        assert!(!v6.contains(ip("2001:db9::")));
        assert!(!v6.contains(ip("10.0.0.1")));
        assert!(IpRange::parse_cidr("::/0").unwrap().contains(ip("fe80::1")));
        for bad in [
            "10.1.2.3/8",
            "10.0.0.0/33",
            "10.0.0.0",
            "10.0.0.0/+8",
            "x/8",
            "::1/129",
            "10.0.0.0/",
        ] {
            assert!(IpRange::parse_cidr(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn cidr_blocks_are_checked_as_written() {
        // IPv4-mapped IPv6 blocks (`/96` and narrower) are IPv4 blocks.
        for (mapped, v4) in [
            ("::ffff:10.0.0.0/104", "10.0.0.0/8"),
            ("::ffff:0:0/96", "0.0.0.0/0"),
            ("::ffff:192.0.2.1/128", "192.0.2.1/32"),
        ] {
            let r = IpRange::parse_cidr(mapped).unwrap();
            assert_eq!(r, IpRange::parse_cidr(v4).unwrap(), "{mapped}");
            assert!(r.first().is_ipv4() && r.last().is_ipv4(), "{mapped}");
        }
        let mapped = IpRange::parse_cidr("::ffff:10.0.0.0/104").unwrap();
        assert!(mapped.contains(ip("10.1.1.1")));
        assert!(mapped.contains(ip("::ffff:10.1.1.1")));
        assert!(!mapped.contains(ip("11.0.0.0")));
        // The prefix applies to the address as written, so these have bits
        // set after it in their IPv6 form, or after the prefix itself.
        for bad in [
            "::ffff:10.0.0.0/8",
            "::ffff:0.0.0.0/0",
            "::ffff:0:0/95",
            "::ffff:10.1.2.3/104",
            "2001:db8::1/32",
            "10.0.0.0/08x",
        ] {
            assert!(IpRange::parse_cidr(bad).is_err(), "{bad}");
        }
        // An IPv6 block wider than the mapped range stays IPv6, and holds
        // the IPv4 addresses it covers in their mapped form.
        for wide in ["::/0", "::/80", "::fffe:0:0/95"] {
            let r = IpRange::parse_cidr(wide).unwrap();
            assert!(r.first().is_ipv6() && r.last().is_ipv6(), "{wide}");
            assert!(r.contains(ip("10.0.0.1")), "{wide}");
            assert!(r.contains(ip("::ffff:10.0.0.1")), "{wide}");
        }
        // Disjoint IPv6 blocks hold no IPv4 address.
        for disjoint in ["::/95", "2001:db8::/32", "fe80::/10"] {
            let r = IpRange::parse_cidr(disjoint).unwrap();
            assert!(!r.contains(ip("10.0.0.1")), "{disjoint}");
        }
        assert!(IpRange::parse_cidr("::/80").unwrap().contains(ip("::1")));
    }

    #[test]
    fn ranges() {
        let r = IpRange::parse_range("192.168.1.10-20").unwrap();
        assert!(r.contains(ip("192.168.1.10")));
        assert!(r.contains(ip("192.168.1.20")));
        assert!(!r.contains(ip("192.168.1.21")));
        assert!(!r.contains(ip("192.168.2.15")));
        let r = IpRange::parse_range("10.0.0.250-10.0.1.5").unwrap();
        assert!(r.contains(ip("10.0.0.255")));
        assert!(r.contains(ip("10.0.1.0")));
        let r = IpRange::parse_range("2001:db8::1-2001:db8::ff").unwrap();
        assert!(r.contains(ip("2001:db8::80")));
        for bad in [
            "192.168.1.20-10",
            "10.0.0.1-::1",
            "10.0.0.1",
            "10.0.0.1-256",
            "10.0.0.1-x",
        ] {
            assert!(IpRange::parse_range(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn explicit_ipv6_ranges_hold_the_ipv4_addresses_they_span_in_mapped_form() {
        // A range spanning `::ffff:0:0/96` holds the IPv4 addresses inside
        // it, as a wide CIDR block does; a disjoint IPv6 range holds none.
        let spanning = IpRange::parse_range("::fffe:ffff:ffff-::1:0:0:0").unwrap();
        assert!(spanning.contains(ip("255.255.0.0")));
        assert!(spanning.contains(ip("::ffff:10.0.0.1")));
        let disjoint = IpRange::parse_range("2001:db8::-2001:db8::ffff").unwrap();
        assert!(!disjoint.contains(ip("255.255.0.0")));
        assert!(!disjoint.contains(ip("10.0.0.1")));
    }

    #[test]
    fn wildcards() {
        let w = IpWildcard::parse("10.*.*.*").unwrap();
        assert!(w.matches(ip("10.200.3.4")));
        assert!(!w.matches(ip("11.0.0.0")));
        assert!(!w.matches(ip("::1")));
        assert!(
            IpWildcard::parse("192.168.*.1")
                .unwrap()
                .matches(ip("192.168.77.1"))
        );
        for bad in [
            "10.*.*",
            "10.*.*.*.*",
            "10.*.256.*",
            "10.**.*.*",
            "10..*.*",
            "1a.*.*.*",
        ] {
            assert!(IpWildcard::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn macs() {
        let want = Some([0xaa, 0xbb, 0xcc, 0x01, 0x02, 0x03]);
        for s in ["aa:bb:cc:01:02:03", "AA-BB-CC-01-02-03", "aabbcc010203"] {
            assert_eq!(parse_mac(s), want, "{s}");
        }
        for bad in [
            "aa:bb-cc:01:02:03",
            "aa:bb:cc:01:02",
            "aabbcc01020",
            "gg:bb:cc:01:02:03",
            "aa:bb:cc:01:02:03:04",
        ] {
            assert_eq!(parse_mac(bad), None, "{bad}");
        }
    }
}
