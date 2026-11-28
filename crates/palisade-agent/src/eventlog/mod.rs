//! OS code integrity and rule-collection event-log ingestion (#58).
//!
//! The event log is the source of truth for what OS-native enforcement
//! allowed, audited and blocked, and for which OS-native policies are
//! active. Everything that reads the untrusted record text is portable,
//! has no `unsafe` code, and is tested (and fuzzed) on every OS:
//!
//! - [`decode`] turns rendered event XML into a mapping `Record`.
//! - [`correlate`] groups each decision with its per-signature records,
//!   behind a token-bucket rate limit.
//! - [`ingest`] runs the chain: decode, rate limit, correlate, map through
//!   `palisade_proto::mapping`, add the process from the #59 process tree,
//!   keep the policy inventory, and emit into a sink.
//! - [`inventory`] is the per-device table of active OS-native policies
//!   from policy activation events (3099).
//!
//! The Windows subscription (`EvtSubscribe` with persisted bookmarks)
//! comes with the agent local store (ADR 0007), which keeps the bookmarks.

#![forbid(unsafe_code)]

pub mod correlate;
pub mod decode;
pub mod ingest;
pub mod inventory;
pub mod os_ids;

/// The channels the agent reads, by the suffix of their resolved name
/// (#58). The OS vendor prefix is resolved at run time by enumerating the
/// channels, so it is not written here.
pub const CHANNEL_SUFFIXES: &[ChannelSpec] = &[
    ChannelSpec {
        suffix: "-Windows-CodeIntegrity/Operational",
        source: Source::CodeIntegrity,
        optional: false,
    },
    ChannelSpec {
        suffix: "-Windows-CodeIntegrity/Verbose",
        source: Source::CodeIntegrity,
        optional: true,
    },
    ChannelSpec {
        suffix: "/EXE and DLL",
        source: Source::RuleCollection,
        optional: false,
    },
    ChannelSpec {
        suffix: "/MSI and Script",
        source: Source::RuleCollection,
        // Absent on Server Core.
        optional: true,
    },
    ChannelSpec {
        suffix: "/Packaged app-Deployment",
        source: Source::RuleCollection,
        optional: true,
    },
    ChannelSpec {
        suffix: "/Packaged app-Execution",
        source: Source::RuleCollection,
        optional: true,
    },
    ChannelSpec {
        suffix: "PowerShellCore/Analytic",
        source: Source::PowerShell,
        optional: true,
    },
];

/// Which mapping a channel's records go through.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// The OS code integrity log.
    CodeIntegrity,
    /// The legacy rule-collection logs.
    RuleCollection,
    /// The PowerShell logs.
    PowerShell,
}

/// One channel the agent reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChannelSpec {
    /// The end of the channel's full name.
    pub suffix: &'static str,
    /// Its records' source.
    pub source: Source,
    /// Whether the agent starts without it (absent, or off by policy).
    pub optional: bool,
}

/// The channel spec whose suffix `channel` ends with, ASCII
/// case-insensitively.
#[must_use]
pub fn spec_for(channel: &str) -> Option<&'static ChannelSpec> {
    let lower = channel.to_ascii_lowercase();
    CHANNEL_SUFFIXES
        .iter()
        .find(|s| lower.ends_with(&s.suffix.to_ascii_lowercase()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channels_resolve_by_suffix() {
        assert_eq!(
            spec_for("X-Windows-CodeIntegrity/Operational").map(|s| s.source),
            Some(Source::CodeIntegrity)
        );
        assert!(
            spec_for("X-Windows-RuleCollections/MSI AND SCRIPT")
                .unwrap()
                .optional
        );
        assert!(
            !spec_for("X-Windows-RuleCollections/EXE and DLL")
                .unwrap()
                .optional
        );
        assert_eq!(
            spec_for("PowerShellCore/Analytic").map(|s| s.source),
            Some(Source::PowerShell)
        );
        assert_eq!(spec_for("Security"), None);
    }
}
