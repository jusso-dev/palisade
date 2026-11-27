//! The device's primary connection type (`Environment::connection_type`).
//!
//! The Windows backend asks the OS which interface it would route an
//! internet-bound packet through (`GetBestInterface`), then reads that
//! interface's row (`GetIfEntry2`) through `palisade_agent::ffi`. The
//! row's numbers are classified here, in portable code that is tested on
//! every OS.
//!
//! Fail closed (ADR 0018): anything not clearly one kind is
//! [`ConnectionType::Unknown`], never a guess. A route that does not exist
//! is [`ConnectionType::Offline`] only when the OS says there is no route;
//! any other failure is `Unknown`.

// Compiled everywhere so the tests run on every CI runner; only the
// Windows backend uses it.
#![cfg_attr(not(windows), allow(dead_code))]

use palisade_core::platform::ConnectionType;

/// `IF_TYPE_ETHERNET_CSMACD`.
pub(crate) const IF_TYPE_ETHERNET: u32 = 6;
/// `IF_TYPE_PPP`, which dial-up and many VPN clients present.
pub(crate) const IF_TYPE_PPP: u32 = 23;
/// `IF_TYPE_PROP_VIRTUAL`, which many VPN clients present.
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

/// `IfOperStatusUp`.
pub(crate) const OPER_UP: i32 = 1;
/// `MediaConnectStateConnected`.
pub(crate) const MEDIA_CONNECTED: i32 = 1;

/// The fields of an interface row (`MIB_IF_ROW2`) the classification reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct InterfaceRow {
    /// `Type`: the `IF_TYPE_*` value.
    pub if_type: u32,
    /// `PhysicalMediumType`: the `NdisPhysicalMedium*` value.
    pub physical_medium: i32,
    /// `OperStatus`.
    pub oper_status: i32,
    /// `MediaConnectState`.
    pub media_connect_state: i32,
}

/// What the route lookup found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Route {
    /// The OS routes internet-bound traffic through this interface.
    Through(InterfaceRow),
    /// The OS says there is no route at all.
    Unreachable,
    /// The lookup failed for another reason.
    Failed,
}

/// The connection type a route lookup gives.
///
/// A tunnel or virtual adapter is [`ConnectionType::Vpn`]: the default route
/// leaves through it, so traffic goes through the tunnel whatever carries
/// it underneath. The interface type and the physical medium must agree:
/// a Wi-Fi interface type on an Ethernet medium, or an Ethernet type on an
/// unknown medium other than "unspecified", is `Unknown`. An interface
/// that is not up and connected is `Unknown`, not `Offline`, because the OS
/// still chose it as the route.
pub(crate) fn classify(route: Route) -> ConnectionType {
    let row = match route {
        Route::Through(row) => row,
        Route::Unreachable => return ConnectionType::Offline,
        Route::Failed => return ConnectionType::Unknown,
    };
    if row.oper_status != OPER_UP || row.media_connect_state != MEDIA_CONNECTED {
        return ConnectionType::Unknown;
    }
    match (row.if_type, row.physical_medium) {
        (IF_TYPE_TUNNEL | IF_TYPE_PPP | IF_TYPE_PROP_VIRTUAL, MEDIUM_UNSPECIFIED) => {
            ConnectionType::Vpn
        }
        (IF_TYPE_ETHERNET, MEDIUM_ETHERNET) => ConnectionType::Wired,
        (IF_TYPE_WIFI, MEDIUM_WIFI) => ConnectionType::Wireless,
        (t, MEDIUM_WIRELESS_WAN) if IF_TYPE_WWAN.contains(&t) => ConnectionType::Cellular,
        _ => ConnectionType::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn up(if_type: u32, physical_medium: i32) -> Route {
        Route::Through(InterfaceRow {
            if_type,
            physical_medium,
            oper_status: OPER_UP,
            media_connect_state: MEDIA_CONNECTED,
        })
    }

    #[test]
    fn each_kind_needs_its_type_and_medium() {
        assert_eq!(
            classify(up(IF_TYPE_ETHERNET, MEDIUM_ETHERNET)),
            ConnectionType::Wired
        );
        assert_eq!(
            classify(up(IF_TYPE_WIFI, MEDIUM_WIFI)),
            ConnectionType::Wireless
        );
        for t in IF_TYPE_WWAN {
            assert_eq!(
                classify(up(t, MEDIUM_WIRELESS_WAN)),
                ConnectionType::Cellular
            );
        }
        for t in [IF_TYPE_TUNNEL, IF_TYPE_PPP, IF_TYPE_PROP_VIRTUAL] {
            assert_eq!(
                classify(up(t, MEDIUM_UNSPECIFIED)),
                ConnectionType::Vpn,
                "{t}"
            );
        }
    }

    #[test]
    fn disagreement_or_an_unknown_value_is_unknown() {
        for route in [
            // Type and medium disagree.
            up(IF_TYPE_WIFI, MEDIUM_ETHERNET),
            up(IF_TYPE_ETHERNET, MEDIUM_WIFI),
            up(IF_TYPE_ETHERNET, MEDIUM_UNSPECIFIED),
            up(IF_TYPE_TUNNEL, MEDIUM_ETHERNET),
            up(IF_TYPE_WWAN[0], MEDIUM_WIFI),
            // Values this module does not know.
            up(1, MEDIUM_ETHERNET),
            up(IF_TYPE_ETHERNET, 99),
            up(u32::MAX, i32::MIN),
        ] {
            assert_eq!(classify(route), ConnectionType::Unknown, "{route:?}");
        }
    }

    #[test]
    fn a_route_that_is_not_up_and_connected_is_unknown() {
        for (oper_status, media_connect_state) in
            [(2, MEDIA_CONNECTED), (OPER_UP, 2), (OPER_UP, 0), (7, 0)]
        {
            let route = Route::Through(InterfaceRow {
                if_type: IF_TYPE_ETHERNET,
                physical_medium: MEDIUM_ETHERNET,
                oper_status,
                media_connect_state,
            });
            assert_eq!(classify(route), ConnectionType::Unknown, "{route:?}");
        }
    }

    #[test]
    fn only_no_route_is_offline() {
        assert_eq!(classify(Route::Unreachable), ConnectionType::Offline);
        assert_eq!(classify(Route::Failed), ConnectionType::Unknown);
    }
}
