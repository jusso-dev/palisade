//! Walking a process's ancestry safely when process IDs are reused.

use alloc::vec::Vec;

use super::{ErrorKind, ProcessInfo, ProcessKey, ProcessRecord, Result};

/// The most ancestors [`ancestry`] returns (#59 records up to 32).
pub const MAX_ANCESTRY: usize = 32;

/// The ancestors of `process`, parent first, up to [`MAX_ANCESTRY`].
///
/// The walk stops at the first ancestor that cannot be trusted to be the
/// real parent:
///
/// - the recorded parent ID has no running process (the parent exited);
/// - the process now using that ID was created **after** the child, so it
///   reused the ID of the real, exited parent;
/// - the chain loops back to a process already visited.
///
/// So a reused process ID never makes an unrelated process look like an
/// ancestor. Errors other than [`ErrorKind::NotFound`] (such as access
/// denied) are returned, because they say nothing about whether the
/// ancestor exists.
///
/// # Errors
///
/// Any error of [`ProcessInfo::get`] for `process` itself, and errors other
/// than [`ErrorKind::NotFound`] while walking.
pub fn ancestry<P: ProcessInfo + ?Sized>(
    processes: &P,
    process: ProcessKey,
) -> Result<Vec<ProcessRecord>> {
    let mut out: Vec<ProcessRecord> = Vec::new();
    let mut child = processes.get(process)?;
    while out.len() < MAX_ANCESTRY {
        let Some(parent_pid) = child.parent_pid else {
            break;
        };
        let parent = match processes.by_pid(parent_pid) {
            Ok(parent) => parent,
            Err(e) if e.kind() == ErrorKind::NotFound => break,
            Err(e) => return Err(e),
        };
        // A parent is always created before its child. A process created
        // later took over the exited parent's ID.
        if parent.key.created > child.key.created {
            break;
        }
        if parent.key == process || out.iter().any(|a| a.key == parent.key) {
            break;
        }
        out.push(parent.clone());
        child = parent;
    }
    Ok(out)
}
