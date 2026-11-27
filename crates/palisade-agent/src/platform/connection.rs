//! The device's primary connection type (`Environment::connection_type`).
//!
//! The Windows backend asks the OS, for IPv4 and for IPv6, which interface
//! it would route an internet-bound packet through (`GetBestRoute2`, to a
//! documentation address that is never contacted), and reads that
//! interface's row by its LUID (`GetIfEntry2`) through
//! `palisade_agent::ffi`. The answers are classified here, in portable code
//! that is tested on every OS.
//!
//! [`ConnectionType::Vpn`] means only that the route leaves through a
//! tunnel: some tunnel, not the organisation's network. Whether a network
//! is trusted is the network-location scope's question (#38), never this
//! one's.
//!
//! Fail closed (ADR 0018): anything not clearly one kind is
//! [`ConnectionType::Unknown`], never a guess. [`ConnectionType::Offline`]
//! is reported only when the OS says that neither IPv4 nor IPv6 has a
//! route; any other failure is `Unknown`.

// Compiled everywhere so the tests run on every CI runner; only the
// Windows backend uses it.
#![cfg_attr(not(windows), allow(dead_code))]

use palisade_core::platform::ConnectionType;

/// `IF_TYPE_ETHERNET_CSMACD`.
pub(crate) const IF_TYPE_ETHERNET: u32 = 6;
/// `IF_TYPE_PPP`: dial-up, PPPoE, and some tunnels.
pub(crate) const IF_TYPE_PPP: u32 = 23;
/// `IF_TYPE_PROP_VIRTUAL`: a vendor's virtual adapter.
pub(crate) const IF_TYPE_PROP_VIRTUAL: u32 = 53;
/// `IF_TYPE_IEEE80211`.
pub(crate) const IF_TYPE_WIFI: u32 = 71;
/// `IF_TYPE_TUNNEL`.
pub(crate) const IF_TYPE_TUNNEL: u32 = 131;
/// `IF_TYPE_WWANPP` and `IF_TYPE_WWANPP2`: mobile broadband.
pub(crate) const IF_TYPE_WWAN: [u32; 2] = [243, 244];

/// `NdisPhysicalMediumUnspecified`: no physical medium, a virtual adapter.
pub(crate) const MEDIUM_UNSPECIFIED: i32 = 0;
/// `NdisPhysicalMediumWirelessWan`.
pub(crate) const MEDIUM_WIRELESS_WAN: i32 = 8;
/// `NdisPhysicalMediumNative802_11`.
pub(crate) const MEDIUM_WIFI: i32 = 9;
/// `NdisPhysicalMedium802_3`.
pub(crate) const MEDIUM_ETHERNET: i32 = 14;

/// `TUNNEL_TYPE_NONE`: the interface is not a tunnel.
pub(crate) const TUNNEL_NONE: i32 = 0;

/// `IfOperStatusUp`.
pub(crate) const OPER_UP: i32 = 1;
/// `MediaConnectStateConnected`.
pub(crate) const MEDIA_CONNECTED: i32 = 1;

/// `ERROR_NETWORK_UNREACHABLE` and `ERROR_HOST_UNREACHABLE`.
const NO_ROUTE_STATUS: [u32; 2] = [1231, 1232];
/// `ERROR_NOT_FOUND`, which `GetBestRoute2` returns when no route matches.
const NOT_FOUND_STATUS: u32 = 1168;

/// The fields of an interface row (`MIB_IF_ROW2`) the classification reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct InterfaceRow {
    /// `Type`: the `IF_TYPE_*` value.
    pub if_type: u32,
    /// `PhysicalMediumType`: the `NdisPhysicalMedium*` value.
    pub physical_medium: i32,
    /// `TunnelType`: `TUNNEL_TYPE_NONE` (0) unless the interface is a
    /// tunnel.
    pub tunnel_type: i32,
    /// `InterfaceAndOperStatusFlags.HardwareInterface` (bit 0): a physical
    /// adapter, not a virtual one.
    pub hardware: bool,
    /// `OperStatus`.
    pub oper_status: i32,
    /// `MediaConnectState`.
    pub media_connect_state: i32,
}

/// What a route lookup for one address family found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Route {
    /// The OS routes internet-bound traffic through this interface.
    Through(InterfaceRow),
    /// The OS says there is no route for this family.
    Unreachable,
    /// The lookup failed for another reason.
    Failed,
}

/// What a route lookup's status says before the interface is read:
/// `Some(Unreachable)` for "no route", `Some(Failed)` for any other
/// failure, and `None` for success (read the interface next).
pub(crate) fn route_from_status(status: u32) -> Option<Route> {
    match status {
        0 => None,
        s if NO_ROUTE_STATUS.contains(&s) || s == NOT_FOUND_STATUS => Some(Route::Unreachable),
        _ => Some(Route::Failed),
    }
}

/// The connection type for one interface.
///
/// A physical kind (wired, wireless, cellular) needs every piece of
/// evidence to agree: a hardware interface, not a tunnel, whose interface
/// type and physical medium match. Virtual adapters that present an
/// Ethernet medium (virtual switches, some VPN clients, USB tethering) are
/// not hardware or report a tunnel, so they are `Unknown`, not wired.
///
/// [`ConnectionType::Vpn`] needs a virtual interface (no hardware, no
/// physical medium) that is a tunnel by its type (`IF_TYPE_TUNNEL`) or
/// reports a tunnel type. A PPP or vendor-virtual interface alone is
/// `Unknown`: direct PPPoE and dial-up are PPP too.
///
/// An interface that is not up and connected is `Unknown`, not `Offline`,
/// because the OS still chose it as the route.
pub(crate) fn classify_interface(row: InterfaceRow) -> ConnectionType {
    if row.oper_status != OPER_UP || row.media_connect_state != MEDIA_CONNECTED {
        return ConnectionType::Unknown;
    }
    let physical = row.hardware && row.tunnel_type == TUNNEL_NONE;
    match (row.if_type, row.physical_medium) {
        (IF_TYPE_ETHERNET, MEDIUM_ETHERNET) if physical => ConnectionType::Wired,
        (IF_TYPE_WIFI, MEDIUM_WIFI) if physical => ConnectionType::Wireless,
        (t, MEDIUM_WIRELESS_WAN) if physical && IF_TYPE_WWAN.contains(&t) => {
            ConnectionType::Cellular
        }
        (t, MEDIUM_UNSPECIFIED)
            if !row.hardware
                && (t == IF_TYPE_TUNNEL
                    || ([IF_TYPE_PPP, IF_TYPE_PROP_VIRTUAL].contains(&t)
                        && row.tunnel_type != TUNNEL_NONE)) =>
        {
            ConnectionType::Vpn
        }
        _ => ConnectionType::Unknown,
    }
}

/// The connection type from the IPv4 and IPv6 route lookups.
///
/// `Offline` only when both families are unreachable. When only one has a
/// route, that route's interface decides. When both have one, they must
/// agree (they usually leave through the same interface); otherwise the
/// answer is `Unknown`. A failed lookup for either family is `Unknown`,
/// because the other family's answer may not be the device's route.
pub(crate) fn classify(v4: Route, v6: Route) -> ConnectionType {
    match (v4, v6) {
        (Route::Unreachable, Route::Unreachable) => ConnectionType::Offline,
        (Route::Failed, _) | (_, Route::Failed) => ConnectionType::Unknown,
        (Route::Through(row), Route::Unreachable) | (Route::Unreachable, Route::Through(row)) => {
            classify_interface(row)
        }
        (Route::Through(a), Route::Through(b)) => {
            let (a, b) = (classify_interface(a), classify_interface(b));
            if a == b { a } else { ConnectionType::Unknown }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(if_type: u32, physical_medium: i32, hardware: bool, tunnel_type: i32) -> InterfaceRow {
        InterfaceRow {
            if_type,
            physical_medium,
            tunnel_type,
            hardware,
            oper_status: OPER_UP,
            media_connect_state: MEDIA_CONNECTED,
        }
    }

    /// A hardware, non-tunnel interface.
    fn hw(if_type: u32, physical_medium: i32) -> InterfaceRow {
        row(if_type, physical_medium, true, TUNNEL_NONE)
    }

    /// `TUNNEL_TYPE_OTHER`, any tunnel type but none.
    const SOME_TUNNEL: i32 = 1;

    #[test]
    fn each_physical_kind_needs_hardware_its_type_and_its_medium() {
        assert_eq!(
            classify_interface(hw(IF_TYPE_ETHERNET, MEDIUM_ETHERNET)),
            ConnectionType::Wired
        );
        assert_eq!(
            classify_interface(hw(IF_TYPE_WIFI, MEDIUM_WIFI)),
            ConnectionType::Wireless
        );
        for t in IF_TYPE_WWAN {
            assert_eq!(
                classify_interface(hw(t, MEDIUM_WIRELESS_WAN)),
                ConnectionType::Cellular
            );
        }
    }

    #[test]
    fn virtual_adapters_with_a_physical_medium_are_unknown() {
        // A virtual switch or VPN client presenting Ethernet, USB tethering
        // presenting Ethernet, and tunnels over any medium.
        for r in [
            row(IF_TYPE_ETHERNET, MEDIUM_ETHERNET, false, TUNNEL_NONE),
            row(IF_TYPE_ETHERNET, MEDIUM_ETHERNET, true, SOME_TUNNEL),
            row(IF_TYPE_ETHERNET, MEDIUM_ETHERNET, false, SOME_TUNNEL),
            row(IF_TYPE_WIFI, MEDIUM_WIFI, false, TUNNEL_NONE),
            row(IF_TYPE_WIFI, MEDIUM_WIFI, true, SOME_TUNNEL),
            row(IF_TYPE_WWAN[0], MEDIUM_WIRELESS_WAN, false, TUNNEL_NONE),
        ] {
            assert_eq!(classify_interface(r), ConnectionType::Unknown, "{r:?}");
        }
    }

    #[test]
    fn vpn_needs_a_virtual_tunnel() {
        assert_eq!(
            classify_interface(row(IF_TYPE_TUNNEL, MEDIUM_UNSPECIFIED, false, TUNNEL_NONE)),
            ConnectionType::Vpn
        );
        assert_eq!(
            classify_interface(row(IF_TYPE_TUNNEL, MEDIUM_UNSPECIFIED, false, SOME_TUNNEL)),
            ConnectionType::Vpn
        );
        for t in [IF_TYPE_PPP, IF_TYPE_PROP_VIRTUAL] {
            // With a tunnel type: a tunnel.
            assert_eq!(
                classify_interface(row(t, MEDIUM_UNSPECIFIED, false, SOME_TUNNEL)),
                ConnectionType::Vpn,
                "{t}"
            );
            // Alone, as direct PPPoE or dial-up reports it: not a VPN.
            assert_eq!(
                classify_interface(row(t, MEDIUM_UNSPECIFIED, false, TUNNEL_NONE)),
                ConnectionType::Unknown,
                "{t}"
            );
            // On real hardware, or with a real medium: not a VPN.
            assert_eq!(
                classify_interface(row(t, MEDIUM_UNSPECIFIED, true, SOME_TUNNEL)),
                ConnectionType::Unknown,
                "{t}"
            );
            for medium in [MEDIUM_ETHERNET, MEDIUM_WIFI, MEDIUM_WIRELESS_WAN] {
                assert_eq!(
                    classify_interface(row(t, medium, false, SOME_TUNNEL)),
                    ConnectionType::Unknown,
                    "{t} {medium}"
                );
            }
        }
        // A tunnel type on hardware is not a VPN.
        assert_eq!(
            classify_interface(row(IF_TYPE_TUNNEL, MEDIUM_UNSPECIFIED, true, SOME_TUNNEL)),
            ConnectionType::Unknown
        );
    }

    #[test]
    fn disagreement_or_an_unknown_value_is_unknown() {
        for r in [
            hw(IF_TYPE_WIFI, MEDIUM_ETHERNET),
            hw(IF_TYPE_ETHERNET, MEDIUM_WIFI),
            hw(IF_TYPE_ETHERNET, MEDIUM_UNSPECIFIED),
            hw(IF_TYPE_ETHERNET, MEDIUM_WIRELESS_WAN),
            hw(IF_TYPE_WIFI, MEDIUM_WIRELESS_WAN),
            hw(IF_TYPE_TUNNEL, MEDIUM_ETHERNET),
            hw(IF_TYPE_WWAN[0], MEDIUM_WIFI),
            hw(1, MEDIUM_ETHERNET),
            hw(IF_TYPE_ETHERNET, 99),
            hw(u32::MAX, i32::MIN),
        ] {
            assert_eq!(classify_interface(r), ConnectionType::Unknown, "{r:?}");
        }
    }

    #[test]
    fn an_interface_that_is_not_up_and_connected_is_unknown() {
        for (oper_status, media_connect_state) in
            [(2, MEDIA_CONNECTED), (OPER_UP, 2), (OPER_UP, 0), (7, 0)]
        {
            let r = InterfaceRow {
                oper_status,
                media_connect_state,
                ..hw(IF_TYPE_ETHERNET, MEDIUM_ETHERNET)
            };
            assert_eq!(classify_interface(r), ConnectionType::Unknown, "{r:?}");
        }
    }

    #[test]
    fn statuses_map_to_routes() {
        assert_eq!(route_from_status(0), None);
        assert_eq!(route_from_status(1231), Some(Route::Unreachable));
        assert_eq!(route_from_status(1232), Some(Route::Unreachable));
        assert_eq!(route_from_status(1168), Some(Route::Unreachable));
        // Access denied, invalid parameter, not supported, and anything else.
        for status in [5, 87, 50, 1, u32::MAX] {
            assert_eq!(route_from_status(status), Some(Route::Failed), "{status}");
        }
    }

    #[test]
    fn offline_needs_both_families_unreachable() {
        let wired = Route::Through(hw(IF_TYPE_ETHERNET, MEDIUM_ETHERNET));
        let wifi = Route::Through(hw(IF_TYPE_WIFI, MEDIUM_WIFI));
        assert_eq!(
            classify(Route::Unreachable, Route::Unreachable),
            ConnectionType::Offline
        );
        // IPv6-only, or IPv4-only: the reachable family decides.
        assert_eq!(classify(Route::Unreachable, wired), ConnectionType::Wired);
        assert_eq!(classify(wifi, Route::Unreachable), ConnectionType::Wireless);
        // Both, agreeing or not.
        assert_eq!(classify(wired, wired), ConnectionType::Wired);
        assert_eq!(classify(wired, wifi), ConnectionType::Unknown);
        // A failed lookup on either side is never offline, nor a guess.
        for (a, b) in [
            (Route::Failed, Route::Unreachable),
            (Route::Unreachable, Route::Failed),
            (Route::Failed, wired),
            (wired, Route::Failed),
            (Route::Failed, Route::Failed),
        ] {
            assert_eq!(classify(a, b), ConnectionType::Unknown, "{a:?} {b:?}");
        }
    }
}
