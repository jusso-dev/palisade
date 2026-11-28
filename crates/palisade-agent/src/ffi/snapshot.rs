//! The process list and the drive-to-device map, for the process
//! monitor's startup snapshot and path normalisation (#59).

#![allow(unsafe_code)]

use std::io;

use windows_sys::Win32::Storage::FileSystem::QueryDosDeviceW;
use windows_sys::Win32::System::ProcessStatus::K32EnumProcesses;

/// The most process IDs [`process_ids`] returns.
const MAX_PROCESSES: usize = 1 << 20;

/// The IDs of every running process.
pub(crate) fn process_ids() -> io::Result<Vec<u32>> {
    let mut len = 4096_usize;
    loop {
        let mut ids = vec![0_u32; len];
        let cap = u32::try_from(ids.len() * 4).unwrap_or(u32::MAX);
        let mut used = 0_u32;
        // SAFETY: `ids` is a live, writable buffer of `cap` bytes, the size
        // passed; `used` is a live local the OS writes.
        let ok = unsafe { K32EnumProcesses(ids.as_mut_ptr(), cap, &raw mut used) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        let n = usize::try_from(used).unwrap_or(usize::MAX) / 4;
        // A full buffer may mean the list was cut: grow and ask again.
        if n < ids.len() {
            ids.truncate(n);
            return Ok(ids);
        }
        if len >= MAX_PROCESSES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "more processes than the limit",
            ));
        }
        len = (len * 4).min(MAX_PROCESSES);
    }
}

/// The NT device that drive `letter` maps to (for example
/// `\Device\HarddiskVolume3`), or `None` if the drive is not mapped.
pub(crate) fn drive_device(letter: char) -> Option<String> {
    let name: Vec<u16> = format!("{letter}:").encode_utf16().chain([0]).collect();
    let mut buf = vec![0_u16; 1024];
    let cap = u32::try_from(buf.len()).unwrap_or(0);
    // SAFETY: `name` is NUL-terminated; `buf` is a live, writable buffer of
    // `cap` UTF-16 units, the size passed.
    let n = unsafe { QueryDosDeviceW(name.as_ptr(), buf.as_mut_ptr(), cap) };
    if n == 0 {
        return None;
    }
    // The result is a list of NUL-terminated strings; the first is the
    // current mapping.
    let first = buf.split(|&u| u == 0).next()?;
    String::from_utf16(first).ok().filter(|s| !s.is_empty())
}
