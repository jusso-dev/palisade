//! Bind address resolution and network placement checks.
//!
//! A listener binds either to a literal address or to a named interface
//! (for example an overlay VPN interface such as `overlay0`). A named
//! interface is resolved to its current addresses when the listener starts,
//! and again on every supervisor tick, so an interface that comes up after
//! the server (a common boot-order race with overlay networks) is picked up
//! without a restart.
//!
//! The placement check backs `deployment.profile = "overlay"`: under that
//! profile every listener is expected on private, overlay or loopback
//! addresses only, and anything reachable on a public address is reported.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::config::BindTarget;

/// One address of one interface on this host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostAddr {
    /// Interface name. On Windows this is the friendly name.
    pub interface: String,
    /// The address.
    pub ip: IpAddr,
    /// IPv6 scope (interface index), needed to bind link-local addresses.
    pub scope_id: u32,
}

/// Lists the addresses of every interface that is currently up.
pub fn host_addrs() -> std::io::Result<Vec<HostAddr>> {
    Ok(if_addrs::get_if_addrs()?
        .into_iter()
        .filter(|i| {
            // Some platforms report `Unknown` for virtual interfaces that
            // carry traffic; only an explicit `Down` is skipped.
            i.oper_status != if_addrs::IfOperStatus::Down
        })
        .map(|i| HostAddr {
            scope_id: i.index.unwrap_or(0),
            ip: i.ip(),
            interface: i.name,
        })
        .collect())
}

/// The socket addresses `target` resolves to, given the host's current
/// addresses. A literal resolves to itself. An interface resolves to each of
/// its addresses; an empty result means the interface is absent or has no
/// address yet.
pub fn resolve(target: &BindTarget, port: u16, host: &[HostAddr]) -> BTreeSet<SocketAddr> {
    match target {
        BindTarget::Ip(ip) => BTreeSet::from([SocketAddr::new(*ip, port)]),
        BindTarget::Interface(name) => host
            .iter()
            .filter(|a| a.interface == *name)
            .map(|a| match a.ip {
                IpAddr::V4(v4) => SocketAddr::new(IpAddr::V4(v4), port),
                IpAddr::V6(v6) => {
                    let scope = if is_v6_link_local(v6) { a.scope_id } else { 0 };
                    SocketAddr::V6(std::net::SocketAddrV6::new(v6, port, 0, scope))
                }
            })
            .collect(),
    }
}

/// The addresses a bound socket address is reachable on. A wildcard
/// (`0.0.0.0` or `::`) is reachable on every host address of its family
/// (and, for `::`, IPv4 too unless the socket is IPv6-only; Palisade always
/// sets IPv6-only).
pub fn reachable_on(bound: &SocketAddr, host: &[HostAddr]) -> Vec<IpAddr> {
    let ip = bound.ip();
    if !ip.is_unspecified() {
        return vec![ip];
    }
    host.iter()
        .map(|a| a.ip)
        .filter(|a| a.is_ipv4() == ip.is_ipv4())
        .collect()
}

/// Whether `ip` is a publicly routable address: not loopback, private
/// (RFC 1918), shared/overlay (RFC 6598 `100.64.0.0/10`), link-local, unique
/// local (`fc00::/7`), documentation, benchmarking or otherwise reserved.
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => is_public_v4(v4),
            None => is_public_v6(v6),
        },
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    let reserved = a == 0
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_multicast()
        // RFC 6598 shared address space, used by overlay networks.
        || (a == 100 && (b & 0xC0) == 64)
        // RFC 6890 IETF protocol assignments.
        || (a == 192 && b == 0 && c == 0)
        // RFC 2544 benchmarking.
        || (a == 198 && (b & 0xFE) == 18)
        // RFC 1112 reserved for future use.
        || a >= 240;
    !reserved
}

fn is_v6_link_local(ip: Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xFFC0) == 0xFE80
}

fn is_public_v6(ip: Ipv6Addr) -> bool {
    let s0 = ip.segments()[0];
    let s1 = ip.segments()[1];
    let reserved = ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        // Unique local, fc00::/7.
        || (s0 & 0xFE00) == 0xFC00
        || is_v6_link_local(ip)
        // Deprecated site-local, fec0::/10.
        || (s0 & 0xFFC0) == 0xFEC0
        // Benchmarking, 2001:2::/48 (RFC 5180).
        || (s0 == 0x2001 && s1 == 0x0002 && ip.segments()[2] == 0)
        // Documentation, 2001:db8::/32 and 3fff::/20.
        || (s0 == 0x2001 && s1 == 0x0DB8)
        || (s0 == 0x3FFF && (s1 & 0xF000) == 0)
        // Discard-only, 100::/64.
        || (s0 == 0x0100 && s1 == 0 && ip.segments()[2] == 0 && ip.segments()[3] == 0);
    !reserved
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn host() -> Vec<HostAddr> {
        vec![
            HostAddr {
                interface: "lo".into(),
                ip: ip("127.0.0.1"),
                scope_id: 1,
            },
            HostAddr {
                interface: "eth0".into(),
                ip: ip("203.0.113.9"),
                scope_id: 2,
            },
            HostAddr {
                interface: "eth0".into(),
                ip: ip("8.8.4.4"),
                scope_id: 2,
            },
            HostAddr {
                interface: "overlay0".into(),
                ip: ip("100.64.0.7"),
                scope_id: 3,
            },
            HostAddr {
                interface: "overlay0".into(),
                ip: ip("fd7a:115c:a1e0::7"),
                scope_id: 3,
            },
            HostAddr {
                interface: "overlay0".into(),
                ip: ip("fe80::1"),
                scope_id: 3,
            },
        ]
    }

    #[test]
    fn classification() {
        for private in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "100.64.0.1",
            "100.127.255.254",
            "169.254.1.1",
            "192.0.2.1",
            "198.18.0.1",
            "0.0.0.0",
            "0.1.2.3",
            "240.0.0.1",
            "::1",
            "::",
            "fd00::1",
            "fc00::1",
            "fe80::1",
            "fec0::1",
            "2001:db8::1",
            "2001:2::1",
            "::ffff:10.0.0.1",
            "ff02::1",
        ] {
            assert!(!is_public(ip(private)), "{private} should not be public");
        }
        for public in [
            "8.8.8.8",
            "100.128.0.1",
            "100.63.255.255",
            "1.1.1.1",
            "2600::1",
            "::ffff:8.8.8.8",
        ] {
            assert!(is_public(ip(public)), "{public} should be public");
        }
    }

    #[test]
    fn literal_resolves_to_itself() {
        let r = resolve(&BindTarget::Ip(ip("10.0.0.1")), 443, &host());
        assert_eq!(r, BTreeSet::from([SocketAddr::new(ip("10.0.0.1"), 443)]));
    }

    #[test]
    fn interface_resolves_to_all_its_addresses() {
        let r = resolve(&BindTarget::Interface("overlay0".into()), 8443, &host());
        assert_eq!(r.len(), 3);
        assert!(r.contains(&SocketAddr::new(ip("100.64.0.7"), 8443)));
        let ll = r.iter().find(|a| a.ip() == ip("fe80::1")).unwrap();
        let SocketAddr::V6(ll) = ll else { panic!() };
        assert_eq!(ll.scope_id(), 3, "link-local needs its scope");
        assert!(resolve(&BindTarget::Interface("missing".into()), 1, &host()).is_empty());
    }

    #[test]
    fn wildcard_is_reachable_on_every_address_of_its_family() {
        let r = reachable_on(&SocketAddr::new(ip("0.0.0.0"), 1), &host());
        assert_eq!(r.len(), 4);
        assert!(r.iter().any(|a| is_public(*a)));
        let r = reachable_on(&SocketAddr::new(ip("::"), 1), &host());
        assert_eq!(r.len(), 2);
        let r = reachable_on(&SocketAddr::new(ip("100.64.0.7"), 1), &host());
        assert_eq!(r, vec![ip("100.64.0.7")]);
    }
}
