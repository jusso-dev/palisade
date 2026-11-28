//! The inventory record ([`InvEntry`]) and its summary of a file's
//! identity.

#![forbid(unsafe_code)]

use palisade_core::platform::UtcTime;
use palisade_fileid::identity::{Field, FileIdentity};

/// The most earlier paths an entry keeps ([`InvEntry::path_history`]).
pub const MAX_PATH_HISTORY: usize = 10;

/// Identifies a file for the life of its inventory entry: the volume's
/// serial number and the file's 128-bit ID. A rename or move within the
/// volume keeps it; a copy, or a move to another volume, is a new file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EntryKey {
    /// The 64-bit volume serial number.
    pub volume_serial: u64,
    /// The file ID (an NTFS file reference zero-extended, or a ReFS ID).
    pub file_id: [u8; 16],
}

/// How the agent first learnt of a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Discovery {
    /// The initial scan: the file existed when the agent was installed.
    InitialScan,
    /// A change the agent tracked.
    Change,
    /// An execution event (#59).
    Execution,
    /// A scan of a removable volume on arrival.
    Removable,
    /// A reconciliation or consistency rescan.
    Rescan,
}

/// Whether the file is there and readable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EntryState {
    /// Present, and its identity is current.
    Present,
    /// Deleted at [`InvEntry::deleted_at`]; kept until the retention ends.
    Deleted,
    /// Present, but it could not be read or identified. Never treated as
    /// known content.
    Unreadable,
    /// Present, and deliberately not read yet (a cloud placeholder, or
    /// work deferred by the resource budget, #65).
    Deferred,
}

/// The identity facts the inventory keeps per file. The full record lives
/// in the file repository cache (#64); this is the compact summary.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IdentitySummary {
    /// The content kind (`pe`, `msi`, `script` and so on).
    pub kind: Option<String>,
    /// Whether the content can run code. `None` if it was not classified.
    pub executable_content: Option<bool>,
    /// The size in bytes.
    pub size: Option<u64>,
    /// The flat SHA-256, hex.
    pub sha256: Option<String>,
    /// The Authenticode SHA-256 of a conformant PE image, hex.
    pub authenticode_sha256: Option<String>,
    /// The signing state (`trusted`, `unsigned` and so on).
    pub signing_state: Option<String>,
    /// The trusted signer's publisher name.
    pub signer: Option<String>,
    /// The product name from the version resource.
    pub product: Option<String>,
    /// The file version from the version resource.
    pub version: Option<String>,
    /// The original file name from the version resource.
    pub original_name: Option<String>,
    /// The package family name of an app package.
    pub package_family: Option<String>,
    /// The product code of an installer package.
    pub msi_product: Option<String>,
}

impl IdentitySummary {
    /// The summary of a computed identity. Fields its tiers did not compute
    /// stay `None`.
    #[must_use]
    pub fn from_identity(id: &FileIdentity) -> Self {
        let kind = id.kind.computed();
        let hashes = id.hashes.computed();
        let version = id.version();
        Self {
            kind: kind.map(|k| k.content_kind.clone()),
            executable_content: kind.map(|k| k.executable_content),
            size: id.size.computed().copied(),
            sha256: hashes.and_then(|h| h.sha256.clone()),
            authenticode_sha256: hashes
                .and_then(|h| h.authenticode.computed())
                .filter(|a| a.conformant)
                .and_then(|a| a.sha256.clone()),
            signing_state: id
                .signing_state
                .computed()
                .map(|s| format!("{:?}", s.state).to_ascii_lowercase()),
            signer: id.trusted_signer().and_then(|s| s.publisher_name.clone()),
            product: version.and_then(|v| v.product_name.clone()),
            version: version.and_then(|v| v.file_version.clone()),
            original_name: version.and_then(|v| v.original_file_name.clone()),
            package_family: match &id.package {
                Field::Computed(p) => Some(p.pfn.clone()),
                _ => None,
            },
            msi_product: id.installer.computed().and_then(|i| i.product_code.clone()),
        }
    }
}

/// One file in the inventory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvEntry {
    /// The file's key.
    pub key: EntryKey,
    /// Its current path.
    pub path: String,
    /// Its earlier paths, oldest first, at most [`MAX_PATH_HISTORY`].
    pub path_history: Vec<String>,
    /// Its identity summary, once identified.
    pub identity: Option<IdentitySummary>,
    /// When the agent first saw it.
    pub first_seen: UtcTime,
    /// When its content last changed, as far as the agent knows.
    pub last_modified: Option<UtcTime>,
    /// When it last ran (#59).
    pub last_executed: Option<UtcTime>,
    /// How the agent first learnt of it.
    pub discovery: Discovery,
    /// It was found by the initial scan, so it existed at install (E05's
    /// implicit baseline).
    pub existing_at_install: bool,
    /// Whether a non-administrator can write the file or a folder above
    /// it. `None` when not assessed; see
    /// [`InvEntry::in_user_writable_location`].
    pub user_writable_location: Option<bool>,
    /// Whether it is there and readable.
    pub state: EntryState,
    /// When it was deleted, for [`EntryState::Deleted`].
    pub deleted_at: Option<UtcTime>,
    /// Its content or metadata changed since `identity` was computed, so
    /// the identity must not be relied on until it is computed again.
    pub stale: bool,
}

impl InvEntry {
    /// A new entry, not yet identified.
    #[must_use]
    pub fn new(key: EntryKey, path: String, now: UtcTime, discovery: Discovery) -> Self {
        Self {
            key,
            path,
            path_history: Vec::new(),
            identity: None,
            first_seen: now,
            last_modified: None,
            last_executed: None,
            discovery,
            existing_at_install: discovery == Discovery::InitialScan,
            user_writable_location: None,
            state: EntryState::Present,
            deleted_at: None,
            stale: true,
        }
    }

    /// Whether the file counts as being in a user-writable location. Not
    /// assessed counts as writable (ADR 0018: a missing fact never relaxes
    /// a decision).
    #[must_use]
    pub fn in_user_writable_location(&self) -> bool {
        self.user_writable_location.unwrap_or(true)
    }

    /// The identity, only while it describes the file's current content.
    #[must_use]
    pub fn current_identity(&self) -> Option<&IdentitySummary> {
        match self.state {
            EntryState::Present if !self.stale => self.identity.as_ref(),
            _ => None,
        }
    }

    /// Moves the entry to `path`, keeping the old path in the history.
    /// Returns whether the path changed.
    pub fn move_to(&mut self, path: String) -> bool {
        if path == self.path {
            return false;
        }
        let old = std::mem::replace(&mut self.path, path);
        self.path_history.push(old);
        if self.path_history.len() > MAX_PATH_HISTORY {
            let extra = self.path_history.len() - MAX_PATH_HISTORY;
            self.path_history.drain(..extra);
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use palisade_fileid::identity::{IdentityContext, Tier, Tiers, identify_bytes};

    pub(crate) fn key(n: u8) -> EntryKey {
        EntryKey {
            volume_serial: 1,
            file_id: [n; 16],
        }
    }

    #[test]
    fn history_is_capped_and_ordered() {
        let mut e = InvEntry::new(key(1), "p0".into(), UtcTime(0), Discovery::Change);
        assert!(!e.existing_at_install);
        assert!(!e.move_to("p0".into()), "same path");
        for i in 1..=12 {
            assert!(e.move_to(format!("p{i}")));
        }
        assert_eq!(e.path, "p12");
        assert_eq!(e.path_history.len(), MAX_PATH_HISTORY);
        assert_eq!(e.path_history.first().map(String::as_str), Some("p2"));
        assert_eq!(e.path_history.last().map(String::as_str), Some("p11"));
    }

    #[test]
    fn missing_facts_fail_closed() {
        let mut e = InvEntry::new(key(1), "a".into(), UtcTime(0), Discovery::InitialScan);
        assert!(e.existing_at_install);
        assert!(e.in_user_writable_location(), "not assessed is writable");
        e.user_writable_location = Some(false);
        assert!(!e.in_user_writable_location());
        // No identity, or a stale or unreadable one, is never current.
        assert_eq!(e.current_identity(), None);
        e.identity = Some(IdentitySummary::default());
        assert_eq!(e.current_identity(), None, "stale");
        e.stale = false;
        assert!(e.current_identity().is_some());
        for state in [
            EntryState::Deleted,
            EntryState::Unreadable,
            EntryState::Deferred,
        ] {
            e.state = state;
            assert_eq!(e.current_identity(), None, "{state:?}");
        }
    }

    #[test]
    fn summary_of_an_identity() {
        let ctx = IdentityContext::untrusted(0);
        let tiers = Tiers::only(Tier::Classify).union(Tiers::only(Tier::Hash));
        let id = identify_bytes(b"@echo off\r\necho hi\r\n", Some("a.cmd"), tiers, &ctx);
        let s = IdentitySummary::from_identity(&id);
        assert_eq!(s.kind.as_deref(), Some("script"));
        assert_eq!(s.executable_content, Some(true));
        assert_eq!(s.size, Some(20));
        assert_eq!(s.sha256.as_ref().map(String::len), Some(64));
        assert_eq!(s.authenticode_sha256, None);
        assert_eq!(s.signing_state, None, "trust tier not requested");
        assert_eq!((s.package_family, s.msi_product), (None, None));
    }
}
