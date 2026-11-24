//! Thin, safe wrappers over the Windows file and volume calls that
//! `palisade_fileid::win` needs (#46, #54). This is the one place those
//! calls are made, so every `unsafe` block for them is here, each with a
//! `// SAFETY:` comment, and the rest of `win` stays free of `unsafe`.
//!
//! Each wrapper takes a borrowed, open [`File`] (or a NUL-free path), owns
//! every buffer it hands to the OS, and returns plain Rust values. Variable
//! length results are returned as bytes for the portable parsers in
//! [`crate::fsctx::ntfs`]. Nothing here interprets attacker-controlled file
//! content.

#![allow(unsafe_code)]

use std::fs::File;
use std::io;
use std::os::windows::io::AsRawHandle as _;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_BASIC_INFO, FILE_ID_INFO, FILE_INFO_BY_HANDLE_CLASS, FILE_STANDARD_INFO, FileBasicInfo,
    FileIdInfo, FileStandardInfo, FileStreamInfo, GetFileInformationByHandleEx,
    GetFinalPathNameByHandleW, GetVolumeInformationByHandleW,
};
use windows_sys::Win32::System::IO::DeviceIoControl;
use windows_sys::Win32::System::Ioctl::{
    FSCTL_QUERY_USN_JOURNAL, FSCTL_READ_FILE_USN_DATA, READ_FILE_USN_DATA, USN_JOURNAL_DATA_V0,
};
use windows_sys::Win32::System::Memory::{
    CreateFileMappingW, FILE_MAP_READ, MEMORY_MAPPED_VIEW_ADDRESS, MapViewOfFile, PAGE_READONLY,
    UnmapViewOfFile,
};
use windows_sys::Win32::System::ProcessStatus::{K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

/// The largest buffer any variable-length query here grows to: 1 MiB. A
/// stream list or path longer than this is reported as an error, never
/// allocated without bound.
const MAX_QUERY_BYTES: usize = 1 << 20;

/// `ERROR_MORE_DATA`.
const ERROR_MORE_DATA: i32 = 234;
/// `ERROR_HANDLE_EOF`, which `FileStreamInfo` returns for a file with no
/// streams.
const ERROR_HANDLE_EOF: i32 = 38;

fn handle(file: &File) -> HANDLE {
    file.as_raw_handle()
}

/// `size_of::<T>()` as a `u32`. Every structure here is tiny.
fn size_u32<T>() -> u32 {
    u32::try_from(size_of::<T>()).unwrap_or(u32::MAX)
}

/// Reads a fixed-size `FILE_*_INFO` structure for `class`.
///
/// # Safety
///
/// `T` must be the plain-data structure the OS writes for `class`: a
/// `#[repr(C)]` type for which every bit pattern is valid (integers and
/// arrays of integers only).
unsafe fn info_by_handle<T: Default>(
    file: &File,
    class: FILE_INFO_BY_HANDLE_CLASS,
) -> io::Result<T> {
    let mut out = T::default();
    // SAFETY: `out` is a live, writable `T` of exactly `size_of::<T>()`
    // bytes, which is the size passed. The caller guarantees `T` is the
    // structure for `class` and that any bytes the OS writes form a valid
    // `T`. `handle(file)` is an open handle borrowed for the call.
    let ok = unsafe {
        GetFileInformationByHandleEx(handle(file), class, (&raw mut out).cast(), size_u32::<T>())
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(out)
}

/// `FILE_ID_INFO`: the 64-bit volume serial number and the 128-bit file ID.
pub(crate) fn file_id_info(file: &File) -> io::Result<FILE_ID_INFO> {
    // SAFETY: `FILE_ID_INFO` is the structure for `FileIdInfo`: a `u64` and
    // a 16-byte array, valid for every bit pattern.
    unsafe { info_by_handle(file, FileIdInfo) }
}

/// `FILE_BASIC_INFO`: the four timestamps and the attributes.
pub(crate) fn basic_info(file: &File) -> io::Result<FILE_BASIC_INFO> {
    // SAFETY: `FILE_BASIC_INFO` is the structure for `FileBasicInfo`: four
    // `i64` and a `u32`, valid for every bit pattern.
    unsafe { info_by_handle(file, FileBasicInfo) }
}

/// The plain-data shape of `FILE_STANDARD_INFO`. The `windows-sys` type
/// has two `bool` fields, and a `bool` with any value but 0 or 1 is
/// undefined behaviour, so the OS is given this layout-identical structure
/// with `u8` fields instead.
#[repr(C)]
#[derive(Default)]
struct StandardInfoRaw {
    allocation_size: i64,
    end_of_file: i64,
    number_of_links: u32,
    delete_pending: u8,
    directory: u8,
}

const _: () = assert!(size_of::<StandardInfoRaw>() == size_of::<FILE_STANDARD_INFO>());
const _: () = assert!(align_of::<StandardInfoRaw>() == align_of::<FILE_STANDARD_INFO>());

/// What `FILE_STANDARD_INFO` says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct StandardInfo {
    pub(crate) end_of_file: u64,
    pub(crate) number_of_links: u32,
    pub(crate) delete_pending: bool,
    pub(crate) directory: bool,
}

/// `FILE_STANDARD_INFO`: the size, link count and directory flag.
pub(crate) fn standard_info(file: &File) -> io::Result<StandardInfo> {
    // SAFETY: `StandardInfoRaw` has the size and alignment of
    // `FILE_STANDARD_INFO` (checked at compile time above) and the same
    // field order, with `u8` in place of `BOOLEAN`, so every bit pattern
    // the OS writes is valid.
    let raw: StandardInfoRaw = unsafe { info_by_handle(file, FileStandardInfo) }?;
    Ok(StandardInfo {
        end_of_file: u64::try_from(raw.end_of_file).unwrap_or(0),
        number_of_links: raw.number_of_links,
        delete_pending: raw.delete_pending != 0,
        directory: raw.directory != 0,
    })
}

/// A byte buffer with 8-byte alignment, for the OS to fill with records
/// whose fields are 8-byte aligned.
fn aligned_buffer(bytes: usize) -> Vec<u64> {
    vec![0_u64; bytes.div_ceil(8)]
}

fn as_bytes(words: &[u64], len: usize) -> Vec<u8> {
    words
        .iter()
        .flat_map(|w| w.to_le_bytes())
        .take(len)
        .collect()
}

/// The raw `FILE_STREAM_INFO` list of the file, for
/// [`crate::fsctx::ntfs::parse_stream_info`]. Empty if the file has no
/// streams.
pub(crate) fn stream_info_bytes(file: &File) -> io::Result<Vec<u8>> {
    let mut bytes = 4096_usize;
    loop {
        let mut buf = aligned_buffer(bytes);
        let len = u32::try_from(buf.len() * 8).unwrap_or(u32::MAX);
        // SAFETY: `buf` is a live, writable allocation of `len` bytes, the
        // size passed. The OS writes at most that many bytes of
        // `FILE_STREAM_INFO` records into it, which are read back only as
        // bytes. `handle(file)` is an open handle borrowed for the call.
        let ok = unsafe {
            GetFileInformationByHandleEx(handle(file), FileStreamInfo, buf.as_mut_ptr().cast(), len)
        };
        if ok != 0 {
            // The list ends at the record whose `NextEntryOffset` is 0; the
            // parser stops there, so the whole buffer is handed over.
            return Ok(as_bytes(&buf, buf.len() * 8));
        }
        let e = io::Error::last_os_error();
        match e.raw_os_error() {
            Some(ERROR_HANDLE_EOF) => return Ok(Vec::new()),
            Some(ERROR_MORE_DATA) if bytes < MAX_QUERY_BYTES => bytes *= 4,
            _ => return Err(e),
        }
    }
}

/// `GetFinalPathNameByHandleW` with `flags` (a `VOLUME_NAME_*` value, with
/// `FILE_NAME_NORMALIZED`).
pub(crate) fn final_path_by_handle(file: &File, flags: u32) -> io::Result<String> {
    let mut units = 512_usize;
    loop {
        let mut buf = vec![0_u16; units];
        let cap = u32::try_from(buf.len()).unwrap_or(u32::MAX);
        // SAFETY: `buf` is a live, writable buffer of `cap` UTF-16 units,
        // the length passed. The OS writes at most that many units, and
        // reports a larger required size instead if the path does not fit.
        let n = unsafe { GetFinalPathNameByHandleW(handle(file), buf.as_mut_ptr(), cap, flags) };
        let n = usize::try_from(n).unwrap_or(usize::MAX);
        if n == 0 {
            return Err(io::Error::last_os_error());
        }
        if n < buf.len() {
            buf.truncate(n);
            return String::from_utf16(&buf).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "final path is not valid UTF-16")
            });
        }
        // `n` is the size needed, including the terminating NUL.
        if n > MAX_QUERY_BYTES / 2 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "final path is too long",
            ));
        }
        units = n.saturating_add(1);
    }
}

/// What `GetVolumeInformationByHandleW` reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VolumeFacts {
    pub(crate) serial: u32,
    pub(crate) flags: u32,
    pub(crate) fs_name: String,
}

/// The serial, flags and file-system name of the volume `file` is on.
pub(crate) fn volume_information(file: &File) -> io::Result<VolumeFacts> {
    let mut fs_name = [0_u16; 64];
    let (mut serial, mut max_component, mut flags) = (0_u32, 0_u32, 0_u32);
    let cap = u32::try_from(fs_name.len()).unwrap_or(0);
    // SAFETY: every out pointer is to a live local of the right type, and
    // `fs_name` is a writable buffer of `cap` UTF-16 units, the size
    // passed. The volume name buffer is null with size 0, which the API
    // allows. `handle(file)` is an open handle borrowed for the call.
    let ok = unsafe {
        GetVolumeInformationByHandleW(
            handle(file),
            std::ptr::null_mut(),
            0,
            &raw mut serial,
            &raw mut max_component,
            &raw mut flags,
            fs_name.as_mut_ptr(),
            cap,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    let len = fs_name
        .iter()
        .position(|&u| u == 0)
        .unwrap_or(fs_name.len());
    let name = fs_name.get(..len).unwrap_or_default();
    Ok(VolumeFacts {
        serial,
        flags,
        fs_name: String::from_utf16_lossy(name),
    })
}

/// Sends a buffered `FSCTL_*` request with input `input` and returns the
/// bytes the OS wrote, up to `out_bytes`.
///
/// # Safety
///
/// `code` must be a buffered (`METHOD_BUFFERED`) control code that reads
/// at most `size_of::<I>()` bytes from the input and writes at most
/// `out_bytes` bytes to the output, and `I` must be the plain-data input
/// structure it expects.
unsafe fn fsctl<I>(
    file: &File,
    code: u32,
    input: Option<&I>,
    out_bytes: usize,
) -> io::Result<Vec<u8>> {
    let mut out = aligned_buffer(out_bytes);
    let out_len = u32::try_from(out.len() * 8).unwrap_or(u32::MAX);
    let (in_ptr, in_len) = match input {
        Some(i) => (std::ptr::from_ref(i).cast(), size_u32::<I>()),
        None => (std::ptr::null(), 0),
    };
    let mut returned = 0_u32;
    // SAFETY: the input, if any, is a live `I` of `in_len` bytes that the
    // OS only reads; `out` is a live, writable buffer of `out_len` bytes,
    // the size passed; `returned` is a live local. No `OVERLAPPED` is
    // passed, so the call completes before it returns. The caller
    // guarantees the control code reads and writes within those sizes.
    let ok = unsafe {
        DeviceIoControl(
            handle(file),
            code,
            in_ptr,
            in_len,
            out.as_mut_ptr().cast(),
            out_len,
            &raw mut returned,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    let n = usize::try_from(returned).unwrap_or(0).min(out.len() * 8);
    Ok(as_bytes(&out, n))
}

/// The file's change-journal record (`FSCTL_READ_FILE_USN_DATA`), version
/// 2 or 3, for [`crate::fsctx::ntfs::parse_usn_record`].
pub(crate) fn read_file_usn_bytes(file: &File) -> io::Result<Vec<u8>> {
    let input = READ_FILE_USN_DATA {
        MinMajorVersion: 2,
        MaxMajorVersion: 3,
    };
    // SAFETY: `FSCTL_READ_FILE_USN_DATA` is buffered, reads a
    // `READ_FILE_USN_DATA` and writes one `USN_RECORD_V2` or `V3` with its
    // file name, which fits in 1 KiB (a 255-unit name plus the header).
    unsafe { fsctl(file, FSCTL_READ_FILE_USN_DATA, Some(&input), 1024) }
}

/// The journal ID of the change journal of the volume `file` is on
/// (`FSCTL_QUERY_USN_JOURNAL`).
pub(crate) fn usn_journal_id(file: &File) -> io::Result<u64> {
    // SAFETY: `FSCTL_QUERY_USN_JOURNAL` is buffered, takes no input and
    // writes a `USN_JOURNAL_DATA_V0` (or a larger later version, of which
    // the first fields are the same); 128 bytes holds every version.
    let bytes = unsafe { fsctl::<()>(file, FSCTL_QUERY_USN_JOURNAL, None, 128) }?;
    let id = bytes
        .get(..8)
        .and_then(|b| b.try_into().ok())
        .map(u64::from_le_bytes)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "short journal data"))?;
    const _: () = assert!(size_of::<USN_JOURNAL_DATA_V0>() <= 128);
    Ok(id)
}

/// The system's allocation granularity, which every mapped view offset
/// must be a multiple of.
pub(crate) fn allocation_granularity() -> u64 {
    let mut info = SYSTEM_INFO::default();
    // SAFETY: `info` is a live, writable `SYSTEM_INFO`, which the call
    // fills in; it cannot fail.
    unsafe { GetSystemInfo(&raw mut info) };
    u64::from(info.dwAllocationGranularity).max(4096)
}

/// The peak working set of this process, in bytes.
pub(crate) fn peak_working_set() -> io::Result<u64> {
    let mut counters = PROCESS_MEMORY_COUNTERS {
        cb: size_u32::<PROCESS_MEMORY_COUNTERS>(),
        ..PROCESS_MEMORY_COUNTERS::default()
    };
    // SAFETY: `GetCurrentProcess` returns a pseudo-handle that needs no
    // closing. `counters` is a live, writable `PROCESS_MEMORY_COUNTERS`
    // whose `cb` is its size, the size passed.
    let ok =
        unsafe { K32GetProcessMemoryInfo(GetCurrentProcess(), &raw mut counters, counters.cb) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(u64::try_from(counters.PeakWorkingSetSize).unwrap_or(u64::MAX))
}

/// A read-only mapping of a whole file, from which views are mapped one
/// window at a time.
pub(crate) struct Mapping {
    handle: HANDLE,
}

// SAFETY: a file-mapping handle is a kernel object handle that can be used
// and closed from any thread.
unsafe impl Send for Mapping {}

impl Mapping {
    /// Maps `file`, which must be open for reading and not empty.
    pub(crate) fn new(file: &File) -> io::Result<Self> {
        // SAFETY: `handle(file)` is an open handle borrowed for the call. A
        // null security descriptor and a null name create an unnamed
        // mapping with default security; size 0 maps the whole file.
        // `PAGE_READONLY` matches a handle opened for reading.
        let h = unsafe {
            CreateFileMappingW(
                handle(file),
                std::ptr::null(),
                PAGE_READONLY,
                0,
                0,
                std::ptr::null(),
            )
        };
        if h.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { handle: h })
    }

    /// Maps `len` bytes from `offset`, which must be a multiple of
    /// [`allocation_granularity`] and lie within the file.
    pub(crate) fn view(&self, offset: u64, len: usize) -> io::Result<View> {
        let high = u32::try_from(offset >> 32).unwrap_or(u32::MAX);
        let low = u32::try_from(offset & 0xFFFF_FFFF).unwrap_or(0);
        // SAFETY: `self.handle` is the live mapping created in `new`. The
        // OS validates the offset and length against the mapping and fails
        // rather than map past it. The view is unmapped by `View::drop`.
        let addr = unsafe { MapViewOfFile(self.handle, FILE_MAP_READ, high, low, len) };
        if addr.Value.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(View { addr, len })
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        // SAFETY: `self.handle` is the mapping handle `new` created and
        // owns; it is closed once, here. Views hold their own reference.
        let _ = unsafe { CloseHandle(self.handle) };
    }
}

/// One mapped window of a file.
pub(crate) struct View {
    addr: MEMORY_MAPPED_VIEW_ADDRESS,
    len: usize,
}

impl View {
    /// The mapped bytes.
    ///
    /// Another process may change the file while it is mapped, so the
    /// bytes can change under the slice. They are only ever fed to a hash,
    /// which reads each byte once, and a change is caught afterwards by the
    /// stamp check in [`crate::hash::hash_through`]; nothing here relies on
    /// the bytes staying the same.
    pub(crate) fn bytes(&self) -> &[u8] {
        // SAFETY: `MapViewOfFile` returned a readable view of `self.len`
        // bytes at `self.addr`, which stays mapped until `self` is dropped,
        // so the slice is valid for `&self`'s lifetime. The memory is never
        // written through this process (the view is read-only). Writes by
        // other processes are tolerated as described above: `u8` has no
        // invalid bit patterns.
        unsafe { std::slice::from_raw_parts(self.addr.Value.cast::<u8>(), self.len) }
    }
}

impl Drop for View {
    fn drop(&mut self) {
        // SAFETY: `self.addr` is the base address `MapViewOfFile` returned,
        // unmapped once, here.
        let _ = unsafe { UnmapViewOfFile(self.addr) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_file(name: &str, content: &[u8]) -> (std::path::PathBuf, File) {
        let dir =
            std::env::temp_dir().join(format!("palisade-win-sys-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("f.bin");
        std::fs::write(&path, content).unwrap();
        let file = File::open(&path).unwrap();
        (dir, file)
    }

    #[test]
    fn handle_information() {
        let (dir, file) = temp_file("info", b"hello");
        let std = standard_info(&file).unwrap();
        assert_eq!(std.end_of_file, 5);
        assert_eq!(std.number_of_links, 1);
        assert!(!std.directory && !std.delete_pending);
        let basic = basic_info(&file).unwrap();
        assert!(basic.LastWriteTime > 0 && basic.CreationTime > 0);
        let id = file_id_info(&file).unwrap();
        assert_ne!(id.FileId.Identifier, [0; 16]);
        let vol = volume_information(&file).unwrap();
        assert!(!vol.fs_name.is_empty());
        assert_eq!(u64::from(vol.serial), id.VolumeSerialNumber & 0xFFFF_FFFF);
        let path = final_path_by_handle(&file, 0).unwrap();
        assert!(path.ends_with("f.bin"), "{path}");
        drop(file);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn streams_and_usn() {
        let (dir, file) = temp_file("streams", b"x");
        let bytes = stream_info_bytes(&file).unwrap();
        let list = crate::fsctx::ntfs::parse_stream_info(&bytes).unwrap();
        assert!(list.streams.iter().any(|s| s.is_default() && s.size == 1));
        // The temporary folder on the CI runners is NTFS with a journal.
        match read_file_usn_bytes(&file) {
            Ok(b) => {
                let facts = crate::fsctx::ntfs::parse_usn_record(&b).unwrap();
                assert!(facts.usn >= 0);
                assert!(usn_journal_id(&file).is_ok());
            }
            Err(e) => eprintln!("no change journal here: {e}"),
        }
        drop(file);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn mapping_windows() {
        let content: Vec<u8> = (0..200_000_u32).map(|i| (i % 251) as u8).collect();
        let (dir, file) = temp_file("map", &content);
        let g = allocation_granularity();
        assert!(g.is_power_of_two());
        let map = Mapping::new(&file).unwrap();
        let first = map.view(0, 1000).unwrap();
        assert_eq!(first.bytes(), &content[..1000]);
        let off = usize::try_from(g).unwrap();
        let second = map.view(g, 100).unwrap();
        assert_eq!(second.bytes(), &content[off..off + 100]);
        // Past the end fails rather than mapping.
        assert!(map.view(g * 1000, 10).is_err());
        drop((first, second, map, file));
        let _ = std::fs::remove_dir_all(dir);
    }
}
