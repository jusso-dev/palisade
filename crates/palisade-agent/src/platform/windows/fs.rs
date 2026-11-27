//! [`FileSystem`] on Windows: the standard-library reads, with the
//! Windows-only context (owners, security descriptors, streams, file IDs,
//! USNs) through `palisade_fileid::win`.

use std::fs::File;
use std::path::Path;

use palisade_core::platform::{
    ErrorKind, FileMetadata, FileSystem, OpenFile, PlatformError, Result, StreamInfo,
};
use palisade_fileid::fsctx::SecurityDescriptor;
use palisade_fileid::win::access::open_for_security;
use palisade_fileid::win::file::{FileFacts, list_streams};
use palisade_fileid::win::security::read_descriptor;
use palisade_fileid::win::volume::read_volume_opened_as;

use super::os_error;
use crate::platform::{StdFile, StdFileSystem, absolute};

/// File reads and file-system context through the OS.
///
/// Reads, sizes, times and the directory flag are [`StdFileSystem`]'s.
/// On top of that:
///
/// - **Metadata** adds the 128-bit file ID, the 64-bit volume serial and
///   the USN, read from the same open handle as the data, so they describe
///   the file the reads come from. A file system that has none, or a
///   named stream (whose IDs are its host file's), leaves them `None`.
/// - **Owners** are read only where they can be relied on: a local NTFS or
///   ReFS volume on a physical disk (`VolumeInfo::supports_owner`).
///   Elsewhere (FAT, exFAT, network shares, virtual disks) the owner is
///   `None`: "no owner", never a guessed one.
/// - **Security descriptors** are the owner, group and DACL, checked by
///   `palisade_fileid::fsctx::SecurityDescriptor` before they are returned,
///   on the same volumes as owners, and `None` elsewhere. One that does
///   not parse is an error. Either way a caller treats the object as
///   possibly writable.
/// - **Streams** are the named data streams. A stream list the OS cut short
///   is [`ErrorKind::TooLarge`], so a caller never treats it as complete.
///
/// Owners and descriptors are read without following a final link or
/// junction (`open_for_security`), so they describe the object at `path`.
/// Like every open here, they use the agent's security context; the
/// hardened, handle-based reads of the file inventory (#60, threat
/// T-agent-13) build on these.
#[derive(Clone, Copy, Debug, Default)]
pub struct WindowsFileSystem;

/// A file opened by [`WindowsFileSystem`].
#[derive(Debug)]
pub struct WindowsFile {
    inner: StdFile,
}

impl FileSystem for WindowsFileSystem {
    type File = WindowsFile;

    fn open(&self, path: &str) -> Result<WindowsFile> {
        Ok(WindowsFile {
            inner: StdFileSystem.open(path)?,
        })
    }

    fn owner_sid(&self, path: &str) -> Result<Option<String>> {
        let file = open_security(path)?;
        if !read_volume_opened_as(path, &file).supports_owner() {
            return Ok(None);
        }
        Ok(parse_descriptor(&file, path)?.owner.map(|s| s.to_string()))
    }

    fn security_descriptor(&self, path: &str) -> Result<Option<Vec<u8>>> {
        let file = open_security(path)?;
        // Where owners cannot be relied on, neither can the DACL (FAT and
        // exFAT have none; a share or virtual disk reports another
        // machine's). `None` makes a writability check treat the object as
        // possibly writable, which only over-reports.
        if !read_volume_opened_as(path, &file).supports_owner() {
            return Ok(None);
        }
        let bytes = read_descriptor(&file).map_err(|e| os_error(&e, path))?;
        SecurityDescriptor::from_self_relative(&bytes).map_err(|e| {
            PlatformError::new(
                ErrorKind::Other,
                format!("{path}: malformed security descriptor: {e}"),
            )
        })?;
        Ok(Some(bytes))
    }

    fn streams(&self, path: &str) -> Result<Vec<StreamInfo>> {
        let file = open_security(path)?;
        let list = list_streams(&file).map_err(|e| os_error(&e, path))?;
        if list.truncated {
            return Err(PlatformError::new(
                ErrorKind::TooLarge,
                format!("{path} has more streams than are listed"),
            ));
        }
        Ok(list
            .alternate()
            .map(|s| StreamInfo {
                name: s.name.clone(),
                size: s.size,
            })
            .collect())
    }
}

fn open_security(path: &str) -> Result<File> {
    let p: &Path = absolute(path)?;
    open_for_security(p).map_err(|e| os_error(&e, path))
}

fn parse_descriptor(file: &File, path: &str) -> Result<SecurityDescriptor> {
    let bytes = read_descriptor(file).map_err(|e| os_error(&e, path))?;
    SecurityDescriptor::from_self_relative(&bytes).map_err(|e| {
        PlatformError::new(
            ErrorKind::Other,
            format!("{path}: malformed security descriptor: {e}"),
        )
    })
}

impl OpenFile for WindowsFile {
    fn metadata(&self) -> Result<FileMetadata> {
        let mut meta = self.inner.metadata()?;
        let facts = FileFacts::read(self.inner.file()).map_err(|e| os_error(&e, "file facts"))?;
        // A named stream's file ID and USN are its host file's, so they do
        // not identify the stream: leave them out.
        if !facts.named_stream {
            if let Some((volume, id)) = facts.file_id {
                meta.file_id = Some(u128::from_le_bytes(id));
                meta.volume_serial = Some(volume);
            }
            meta.usn = facts.usn.map(|(_, usn)| usn);
        }
        Ok(meta)
    }

    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        self.inner.read_at(offset, buf)
    }
}
