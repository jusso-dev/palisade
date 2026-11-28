//! The Windows inventory backend: each fixed NTFS or ReFS volume's master
//! file table and change journal (`palisade_fileid::win::journal`), and
//! identities computed by `palisade_fileid` (#55).
//!
//! Every file is reached by its ID, never by a path a user could swap
//! (T-agent-13). Paths come from the opened handle's own final path, and an
//! identity is kept only if the file it describes has the ID that was
//! asked for.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::path::Path;

use palisade_core::platform::Clock as _;
use palisade_fileid::fsctx::ntfs::JournalData;
use palisade_fileid::hash::{HashPurpose, skip_for_inventory};
use palisade_fileid::identity::{Field, IdentityContext, Tier, Tiers, identify};
use palisade_fileid::win::journal::JournalVolume;
use palisade_fileid::win::links::{final_path_of, read_meta};

use super::changes_from_journal;
use super::engine::{Identified, Identifier, Listed, SourceError, VolumeSource};
use super::entry::{EntryKey, IdentitySummary};
use super::scope::{InventoryScope, VolumeScope};
use super::store::JournalCursor;
use super::subsystem::{Volume, VolumeProvider};
use super::track::Change;
use crate::platform::SystemClock;

/// `ERROR_JOURNAL_DELETE_IN_PROGRESS`.
const JOURNAL_DELETE_IN_PROGRESS: i32 = 1178;
/// `ERROR_JOURNAL_NOT_ACTIVE`.
const JOURNAL_NOT_ACTIVE: i32 = 1179;
/// `ERROR_JOURNAL_ENTRY_DELETED`.
const JOURNAL_ENTRY_DELETED: i32 = 1181;

/// The fixed volumes with drive letters, by their volume GUID path.
#[derive(Debug, Default, Clone, Copy)]
pub struct FixedVolumes;

impl VolumeProvider for FixedVolumes {
    fn volumes(&self, scope: &InventoryScope) -> Vec<Volume> {
        let mut roots = BTreeMap::new();
        for letter in 'A'..='Z' {
            let root = format!(r"{letter}:\");
            let Ok(dir) = std::fs::File::open(&root) else {
                continue;
            };
            let info = palisade_fileid::win::volume::read_volume(&dir);
            let fixed = matches!(
                info.location_class(),
                palisade_fileid::fsctx::volume::LocationClass::OsVolume
                    | palisade_fileid::fsctx::volume::LocationClass::OtherFixed
            );
            let wanted = match scope.volumes {
                VolumeScope::OsOnly => info.is_os_volume == Some(true),
                VolumeScope::AllFixed | VolumeScope::AllFixedAndRemovable => fixed,
                VolumeScope::Custom => false,
            };
            if !wanted || info.supports_usn != Some(true) {
                continue;
            }
            let Some(serial) = read_meta(&dir).ok().and_then(|m| m.volume_serial) else {
                continue;
            };
            match JournalVolume::of_file(&dir) {
                Ok(v) => {
                    roots.entry(v.root().to_owned()).or_insert((v, serial));
                }
                Err(e) => {
                    tracing::warn!(%root, error = %e, "cannot open the volume for the inventory")
                }
            }
        }
        roots
            .into_values()
            .map(|(v, serial)| {
                let v = std::sync::Arc::new(v);
                Volume {
                    source: Box::new(JournalSource {
                        volume: std::sync::Arc::clone(&v),
                        serial,
                    }),
                    identifier: Box::new(FileidIdentifier { volume: v }),
                }
            })
            .collect()
    }
}

/// One volume's journal and file table.
struct JournalSource {
    volume: std::sync::Arc<JournalVolume>,
    serial: u64,
}

fn other(e: &std::io::Error) -> SourceError {
    SourceError::Other(e.to_string())
}

impl VolumeSource for JournalSource {
    fn serial(&self) -> u64 {
        self.serial
    }

    fn journal(&mut self) -> Result<Option<JournalData>, SourceError> {
        match self.volume.query() {
            Ok(j) => Ok(Some(j)),
            Err(e)
                if matches!(
                    e.raw_os_error(),
                    Some(JOURNAL_NOT_ACTIVE | JOURNAL_DELETE_IN_PROGRESS)
                ) =>
            {
                Ok(None)
            }
            Err(e) => Err(other(&e)),
        }
    }

    fn list(
        &mut self,
        start: u64,
        high_usn: i64,
    ) -> Result<Option<(u64, Vec<Listed>)>, SourceError> {
        let Some((next, records)) = self
            .volume
            .enumerate(start, high_usn)
            .map_err(|e| other(&e))?
        else {
            return Ok(None);
        };
        let listed = records
            .into_iter()
            .map(|r| {
                // The path is read from the file's own handle, opened by
                // ID; a file that cannot be opened is listed without one
                // and skipped.
                let path = self
                    .volume
                    .open_entry_by_id(r.file_reference)
                    .ok()
                    .and_then(|f| final_path_of(&f).ok())
                    .map(|p| p.to_win32_string());
                Listed {
                    file_id: r.file_reference,
                    path,
                    directory: r.is_directory(),
                }
            })
            .collect();
        Ok(Some((next, listed)))
    }

    fn changes(&mut self, cursor: JournalCursor) -> Result<(i64, Vec<Change>), SourceError> {
        match self.volume.read(cursor.journal_id, cursor.next_usn) {
            Ok((next, records)) => Ok((
                next,
                records
                    .iter()
                    .filter_map(|r| changes_from_journal(self.serial, r))
                    .collect(),
            )),
            Err(e)
                if matches!(
                    e.raw_os_error(),
                    Some(JOURNAL_ENTRY_DELETED | JOURNAL_NOT_ACTIVE | JOURNAL_DELETE_IN_PROGRESS)
                ) =>
            {
                Err(SourceError::CursorLost)
            }
            Err(e) => Err(other(&e)),
        }
    }

    fn resolve(&mut self, file_id: [u8; 16]) -> Option<String> {
        let f = self.volume.open_entry_by_id(file_id).ok()?;
        final_path_of(&f).ok().map(|p| p.to_win32_string())
    }
}

/// Identifies files through `palisade_fileid`, after opening them by ID.
struct FileidIdentifier {
    volume: std::sync::Arc<JournalVolume>,
}

impl Identifier for FileidIdentifier {
    fn identify(&mut self, key: EntryKey) -> Identified {
        let file = match self.volume.open_file_by_id(key.file_id) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Identified::Gone,
            Err(e) => return Identified::Unreadable(e.to_string()),
        };
        // A cloud placeholder is not read: `identify` reopens by path, which
        // would download it.
        match read_meta(&file) {
            Ok(m) if skip_for_inventory(m.attributes.0, HashPurpose::Inventory).is_some() => {
                return Identified::Deferred;
            }
            Ok(_) => {}
            Err(e) => return Identified::Unreadable(e.to_string()),
        }
        let path = match final_path_of(&file) {
            Ok(p) => p.to_win32_string(),
            Err(e) => return Identified::Unreadable(e.to_string()),
        };
        // The trust anchors and catalogs come with the policy cache (#61);
        // until then nothing is trusted, which only fails closed.
        let ctx = IdentityContext::untrusted(SystemClock.now_utc().unix_secs());
        let tiers = Tiers::only(Tier::Classify)
            .union(Tiers::only(Tier::Hash))
            .union(Tiers::only(Tier::Trust))
            .union(Tiers::only(Tier::Context));
        let id = match identify(Path::new(&path), tiers, &ctx) {
            Ok(id) => id,
            Err(e) => return Identified::Unreadable(e.to_string()),
        };
        // The identity must describe the file asked for: the path could
        // have been swapped between the open by ID and `identify`.
        let want: String = key.file_id.iter().map(|b| format!("{b:02x}")).collect();
        let same = match &id.fs.file_id {
            Field::Computed(f) => f.file_id.as_deref() == Some(want.as_str()),
            _ => false,
        };
        if !same {
            return Identified::Unreadable("the path no longer names the file".into());
        }
        drop(file);
        let user_writable = id.fs.user_writable.computed().map(|w| w.path_user_writable);
        Identified::Known {
            summary: Box::new(IdentitySummary::from_identity(&id)),
            user_writable,
        }
    }
}
