//! [`ProcessInfo`] through the OS.

use palisade_core::platform::{PlatformError, ProcessInfo, ProcessKey, ProcessRecord, Result};

use super::os_error;
use crate::ffi::Process;
use crate::platform::nt::{self, Record};

/// Process queries through the OS.
///
/// Each query opens the process once and reads everything through that
/// handle. An open handle keeps the process object, and so its ID, from
/// being reused, so the creation time, parent, image path and command line
/// all describe the same process. A process that has exited is
/// [`ErrorKind::NotFound`], even while something still holds a handle to
/// it.
///
/// The command line is `None` when the OS refuses it (a protected
/// process); every other field must be read, or the query fails.
#[derive(Clone, Copy, Debug, Default)]
pub struct WindowsProcesses;

/// Opens `pid`, if it is still running.
pub(super) fn open_running(pid: u32) -> Result<Process> {
    let process = Process::open(pid).map_err(|e| os_error(&e, "open process"))?;
    if process
        .has_exited()
        .map_err(|e| os_error(&e, "process state"))?
    {
        return Err(PlatformError::not_found(format!(
            "process {pid} has exited"
        )));
    }
    Ok(process)
}

/// The key of the open `process`, whose ID is `pid`.
pub(super) fn key_of(process: &Process, pid: u32) -> Result<ProcessKey> {
    let created = process
        .creation_time()
        .map_err(|e| os_error(&e, "process creation time"))?;
    Ok(ProcessKey {
        pid,
        created: nt::filetime_to_utc(created),
    })
}

/// Opens the process `key`: running, and created at `key.created`.
pub(super) fn open_key(key: ProcessKey) -> Result<Process> {
    let process = open_running(key.pid)?;
    if key_of(&process, key.pid)? != key {
        return Err(PlatformError::not_found(format!(
            "process {} is now a different process",
            key.pid
        )));
    }
    Ok(process)
}

/// Reads the record of the open `process`, then checks on the same handle
/// that it is still running: a process that exited while it was read is
/// [`ErrorKind::NotFound`](palisade_core::platform::ErrorKind::NotFound),
/// whether the reads succeeded or failed.
fn record(process: &Process, key: ProcessKey) -> Result<ProcessRecord> {
    let read = read_record(process, key);
    if process
        .has_exited()
        .map_err(|e| os_error(&e, "process state"))?
    {
        return Err(PlatformError::not_found(format!(
            "process {} exited while it was read",
            key.pid
        )));
    }
    read
}

fn read_record(process: &Process, key: ProcessKey) -> Result<ProcessRecord> {
    let basic = process
        .basic_information()
        .map_err(|e| os_error(&e, "process basic information"))?;
    let parent_pid = nt::parent_pid(Record::new(&basic.bytes, basic.base))?;
    let image_path = process
        .image_path()
        .map_err(|e| os_error(&e, "process image path"))?;
    // Only the command line may be missing: protected processes refuse it.
    let command_line = match process.command_line() {
        Ok(raw) => Some(nt::unicode_string(
            Record::new(&raw.bytes, raw.base),
            "command line",
        )?),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => None,
        Err(e) => return Err(os_error(&e, "process command line")),
    };
    Ok(ProcessRecord {
        key,
        parent_pid,
        image_path,
        command_line,
    })
}

impl ProcessInfo for WindowsProcesses {
    fn by_pid(&self, pid: u32) -> Result<ProcessRecord> {
        let process = open_running(pid)?;
        let key = key_of(&process, pid)?;
        record(&process, key)
    }

    fn get(&self, key: ProcessKey) -> Result<ProcessRecord> {
        let process = open_key(key)?;
        record(&process, key)
    }
}
