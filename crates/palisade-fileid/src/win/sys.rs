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

use windows_sys::Win32::Foundation::{CloseHandle, ERROR_IO_PENDING, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::NetworkManagement::NetManagement::NetApiBufferFree;
use windows_sys::Win32::NetworkManagement::WNet::WNetGetConnectionW;
use windows_sys::Win32::Storage::DistributedFileSystem::{
    DFS_INFO_3, DFS_STORAGE_INFO, DFS_STORAGE_STATE_ACTIVE, NetDfsGetClientInfo,
};
use windows_sys::Win32::Storage::FileSystem::{
    ExtendedFileIdType, FILE_BASIC_INFO, FILE_CASE_SENSITIVE_INFO, FILE_ID_128, FILE_ID_DESCRIPTOR,
    FILE_ID_DESCRIPTOR_0, FILE_ID_INFO, FILE_INFO_BY_HANDLE_CLASS, FILE_REMOTE_PROTOCOL_INFO,
    FILE_STANDARD_INFO, FILE_TYPE_DISK, FileBasicInfo, FileCaseSensitiveInfo, FileIdInfo,
    FileRemoteProtocolInfo, FileStandardInfo, FileStreamInfo, FindClose, FindExInfoBasic,
    FindExSearchNameMatch, FindFirstFileExW, FindFirstFileNameW, FindNextFileNameW, GetDriveTypeW,
    GetFileInformationByHandleEx, GetFileType, GetFinalPathNameByHandleW,
    GetVolumeInformationByHandleW, OpenFileById, WIN32_FIND_DATAW,
};
use windows_sys::Win32::System::IO::{DeviceIoControl, GetOverlappedResult, OVERLAPPED};
use windows_sys::Win32::System::Ioctl::{
    FSCTL_ENUM_USN_DATA, FSCTL_GET_REPARSE_POINT, FSCTL_QUERY_USN_JOURNAL,
    FSCTL_READ_FILE_USN_DATA, FSCTL_READ_USN_JOURNAL, IOCTL_STORAGE_GET_HOTPLUG_INFO,
    IOCTL_STORAGE_QUERY_PROPERTY, MFT_ENUM_DATA_V1, PropertyStandardQuery, READ_FILE_USN_DATA,
    READ_USN_JOURNAL_DATA_V1, STORAGE_PROPERTY_QUERY, StorageDeviceProperty, USN_JOURNAL_DATA_V0,
};
use windows_sys::Win32::System::Memory::{
    CreateFileMappingW, FILE_MAP_READ, MEMORY_MAPPED_VIEW_ADDRESS, MapViewOfFile, PAGE_READONLY,
    UnmapViewOfFile,
};
use windows_sys::Win32::System::ProcessStatus::{K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
use windows_sys::Win32::System::SystemInformation::{
    GetSystemInfo, GetSystemWindowsDirectoryW, SYSTEM_INFO,
};
use windows_sys::Win32::System::Threading::{CreateEventW, GetCurrentProcess};

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

/// Whether the handle is a file or directory on disk (`FILE_TYPE_DISK`),
/// not a pipe, console or character device.
pub(crate) fn is_disk_file(file: &File) -> bool {
    // SAFETY: `handle(file)` is an open handle borrowed for the call;
    // `GetFileType` only reads it.
    unsafe { GetFileType(handle(file)) == FILE_TYPE_DISK }
}

/// The `WNNC_NET_*` protocol `FileRemoteProtocolInfo` reports for the
/// handle, or the error the call failed with. The call succeeds only for
/// files opened through a network redirector, but a failure is not proof
/// of a local file; see `win::volume::network_evidence`.
pub(crate) fn remote_protocol(file: &File) -> io::Result<u32> {
    // SAFETY: `FILE_REMOTE_PROTOCOL_INFO` is the structure for
    // `FileRemoteProtocolInfo`: integers and unions of integer arrays only,
    // valid for every bit pattern.
    unsafe { info_by_handle::<FILE_REMOTE_PROTOCOL_INFO>(file, FileRemoteProtocolInfo) }
        .map(|info| info.Protocol)
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

/// An unnamed, manual-reset event, closed on drop.
struct Event(HANDLE);

impl Event {
    fn new() -> io::Result<Self> {
        // SAFETY: null security attributes and a null name create an
        // unnamed event with default security; nothing is borrowed.
        let h = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
        if h.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(h))
    }
}

impl Drop for Event {
    fn drop(&mut self) {
        // SAFETY: `self.0` is the event `new` created and owns, closed once.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

/// Sends an `FSCTL_*` request with input `input` and returns the bytes the
/// OS wrote, up to `out_bytes`.
///
/// The request always carries an `OVERLAPPED` with its own event, and waits
/// for it if the OS completes it later. So it is sound whether `file` was
/// opened for synchronous or for overlapped I/O: the buffers stay alive and
/// borrowed until the OS has finished with them.
///
/// # Safety
///
/// `code` must be a control code that reads at most `size_of::<I>()` bytes
/// from the input buffer and writes at most `out_bytes` bytes to the output
/// buffer, whatever its transfer method (`METHOD_BUFFERED` or
/// `METHOD_NEITHER`), and `I` must be the plain-data input structure it
/// expects.
unsafe fn fsctl<I>(
    file: &File,
    code: u32,
    input: Option<&I>,
    out_bytes: usize,
) -> io::Result<Vec<u8>> {
    let (in_ptr, in_len) = match input {
        Some(i) => (std::ptr::from_ref(i).cast(), size_u32::<I>()),
        None => (std::ptr::null(), 0),
    };
    // SAFETY: `in_ptr` is null with length 0, or points to the live `I`
    // borrowed for this call, of `in_len` bytes. The caller's guarantee
    // about `code` carries over.
    unsafe { fsctl_raw(file, code, in_ptr, in_len, out_bytes) }
}

/// As [`fsctl`], with an input of `in_len` bytes at `in_ptr`.
///
/// # Safety
///
/// `in_ptr` must be null with `in_len` 0, or point to `in_len` readable
/// bytes that stay alive and unchanged for the call. `code` must read at
/// most `in_len` bytes of input and write at most `out_bytes` bytes of
/// output, whatever its transfer method.
unsafe fn fsctl_raw(
    file: &File,
    code: u32,
    in_ptr: *const std::ffi::c_void,
    in_len: u32,
    out_bytes: usize,
) -> io::Result<Vec<u8>> {
    let mut out = aligned_buffer(out_bytes);
    let out_len = u32::try_from(out.len() * 8).unwrap_or(u32::MAX);
    let event = Event::new()?;
    let mut overlapped = OVERLAPPED {
        hEvent: event.0,
        ..OVERLAPPED::default()
    };
    let mut returned = 0_u32;
    // SAFETY: the input, if any, is `in_len` live bytes that the OS only
    // reads (the caller's guarantee); `out` is a live, writable buffer of `out_len` bytes,
    // the size passed; `returned`, `overlapped` and its event are live
    // locals. If the request completes later (`ERROR_IO_PENDING`), the wait
    // below blocks until it has, so none of them is dropped or moved while
    // the OS can still write to it. The caller guarantees the control code
    // reads and writes within those sizes.
    let ok = unsafe {
        DeviceIoControl(
            handle(file),
            code,
            in_ptr,
            in_len,
            out.as_mut_ptr().cast(),
            out_len,
            &raw mut returned,
            &raw mut overlapped,
        )
    };
    if ok == 0 {
        let e = io::Error::last_os_error();
        if e.raw_os_error() != i32::try_from(ERROR_IO_PENDING).ok() {
            return Err(e);
        }
        // SAFETY: `overlapped` is the structure the pending request uses,
        // still alive; waiting (`bWait = TRUE`) returns only once the
        // request has completed, after which the OS no longer touches the
        // buffers.
        let done = unsafe {
            GetOverlappedResult(handle(file), &raw const overlapped, &raw mut returned, 1)
        };
        if done == 0 {
            return Err(io::Error::last_os_error());
        }
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
    // SAFETY: `FSCTL_READ_FILE_USN_DATA` (`METHOD_NEITHER`) reads a
    // `READ_FILE_USN_DATA` from the input buffer and writes one
    // `USN_RECORD_V2` or `V3` with the file name into the output buffer,
    // within its stated length; a record with a 255-unit name and the V3
    // header is under 1 KiB.
    unsafe { fsctl(file, FSCTL_READ_FILE_USN_DATA, Some(&input), 1024) }
}

/// The journal ID of the change journal of a volume
/// (`FSCTL_QUERY_USN_JOURNAL`). `volume` must be a handle to the volume
/// itself, such as `\\?\Volume{GUID}` opened without a trailing
/// separator.
pub(crate) fn usn_journal_id(volume: &File) -> io::Result<u64> {
    let file = volume;
    // SAFETY: `FSCTL_QUERY_USN_JOURNAL` (`METHOD_BUFFERED`) takes no input
    // and writes a `USN_JOURNAL_DATA_V0`, `V1` or `V2`, the first fields of
    // which are the same, within the output length; 128 bytes holds every
    // version.
    let bytes = unsafe { fsctl::<()>(file, FSCTL_QUERY_USN_JOURNAL, None, 128) }?;
    let id = bytes
        .get(..8)
        .and_then(|b| b.try_into().ok())
        .map(u64::from_le_bytes)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "short journal data"))?;
    const _: () = assert!(size_of::<USN_JOURNAL_DATA_V0>() <= 128);
    Ok(id)
}

/// The raw `USN_JOURNAL_DATA` of the volume (`FSCTL_QUERY_USN_JOURNAL`),
/// for [`crate::fsctx::ntfs::parse_journal_data`]. `volume` must be a
/// handle to the volume itself (or a file on it, which the OS also
/// accepts for this code).
pub(crate) fn usn_journal_bytes(volume: &File) -> io::Result<Vec<u8>> {
    // SAFETY: as in `usn_journal_id`: no input, and a `USN_JOURNAL_DATA`
    // of any version fits in 128 bytes.
    unsafe { fsctl::<()>(volume, FSCTL_QUERY_USN_JOURNAL, None, 128) }
}

/// The largest buffer one journal read or enumeration asks for: 64 KiB,
/// the size the OS documentation uses, so one call returns a bounded batch.
pub(crate) const JOURNAL_BATCH_BYTES: usize = 64 * 1024;

/// Reads change-journal records from `start_usn` (`FSCTL_READ_USN_JOURNAL`)
/// for the journal `journal_id`, without waiting for new ones. Returns the
/// raw output for [`crate::fsctx::ntfs::parse_read_journal`]. `volume` must
/// be a handle to the volume device, opened with read access (which needs
/// administrator rights).
pub(crate) fn read_usn_journal_bytes(
    volume: &File,
    journal_id: u64,
    start_usn: i64,
    reason_mask: u32,
) -> io::Result<Vec<u8>> {
    let input = READ_USN_JOURNAL_DATA_V1 {
        StartUsn: start_usn,
        ReasonMask: reason_mask,
        ReturnOnlyOnClose: 0,
        Timeout: 0,
        BytesToWaitFor: 0,
        UsnJournalID: journal_id,
        MinMajorVersion: 2,
        MaxMajorVersion: 3,
    };
    // SAFETY: `FSCTL_READ_USN_JOURNAL` (`METHOD_NEITHER`) reads one
    // `READ_USN_JOURNAL_DATA_V1` from the input buffer and writes the next
    // USN followed by whole records into the output buffer, never more
    // than its length. `BytesToWaitFor` of 0 makes it return at once.
    unsafe {
        fsctl(
            volume,
            FSCTL_READ_USN_JOURNAL,
            Some(&input),
            JOURNAL_BATCH_BYTES,
        )
    }
}

/// Lists the files and folders of the volume's master file table from the
/// file reference `start` (`FSCTL_ENUM_USN_DATA`), one batch per call,
/// with USNs up to `high_usn`. Returns the raw output for
/// [`crate::fsctx::ntfs::parse_enum_usn_data`]; `ERROR_HANDLE_EOF` (no more
/// files) is an empty buffer. `volume` must be a handle to the volume
/// device opened with read access.
pub(crate) fn enum_usn_data_bytes(volume: &File, start: u64, high_usn: i64) -> io::Result<Vec<u8>> {
    let input = MFT_ENUM_DATA_V1 {
        StartFileReferenceNumber: start,
        LowUsn: 0,
        HighUsn: high_usn,
        MinMajorVersion: 2,
        MaxMajorVersion: 3,
    };
    // SAFETY: `FSCTL_ENUM_USN_DATA` (`METHOD_NEITHER`) reads one
    // `MFT_ENUM_DATA_V1` from the input buffer and writes the next file
    // reference followed by whole records, within the output length.
    match unsafe {
        fsctl(
            volume,
            FSCTL_ENUM_USN_DATA,
            Some(&input),
            JOURNAL_BATCH_BYTES,
        )
    } {
        Err(e) if e.raw_os_error() == Some(ERROR_HANDLE_EOF) => Ok(Vec::new()),
        other => other,
    }
}

/// Opens the file with the 128-bit ID `file_id` on the volume `volume`
/// (`OpenFileById` with `ExtendedFileIdType`), without following a
/// reparse point. `access` and `flags` are passed through, with
/// `SECURITY_SQOS_PRESENT | SECURITY_ANONYMOUS` added so the handle can
/// never lend the caller's identity to a pipe server.
pub(crate) fn open_by_id(
    volume: &File,
    file_id: [u8; 16],
    access: u32,
    flags: u32,
) -> io::Result<File> {
    use std::os::windows::io::FromRawHandle as _;
    /// `FILE_FLAG_OPEN_REPARSE_POINT`.
    const OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    /// `SECURITY_SQOS_PRESENT | SECURITY_ANONYMOUS`.
    const SQOS_ANONYMOUS: u32 = 0x0010_0000;
    let descriptor = FILE_ID_DESCRIPTOR {
        dwSize: size_u32::<FILE_ID_DESCRIPTOR>(),
        Type: ExtendedFileIdType,
        Anonymous: FILE_ID_DESCRIPTOR_0 {
            ExtendedFileId: FILE_ID_128 {
                Identifier: file_id,
            },
        },
    };
    // SAFETY: `handle(volume)` is an open handle borrowed for the call, as
    // the volume hint; `descriptor` is a live, initialised
    // `FILE_ID_DESCRIPTOR` whose `dwSize` is its own size; a null security
    // attributes pointer means the default. The OS reads nothing else.
    let h = unsafe {
        OpenFileById(
            handle(volume),
            &raw const descriptor,
            access,
            FILE_SHARE_READ_WRITE_DELETE,
            std::ptr::null(),
            flags | OPEN_REPARSE_POINT | SQOS_ANONYMOUS,
        )
    };
    if h == INVALID_HANDLE_VALUE || h.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `h` is a valid handle `OpenFileById` just returned, owned by
    // nothing else; the `File` takes ownership and closes it once on drop.
    Ok(unsafe { File::from_raw_handle(h.cast()) })
}

/// `FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE`.
const FILE_SHARE_READ_WRITE_DELETE: u32 = 0x7;

/// The `STORAGE_DEVICE_DESCRIPTOR` of the disk behind `volume`
/// (`IOCTL_STORAGE_QUERY_PROPERTY`, `StorageDeviceProperty`), for
/// [`crate::fsctx::volume::parse_storage_device_descriptor`]. `volume` is a
/// handle to the volume device itself, which may be opened with no access
/// rights.
pub(crate) fn storage_device_bytes(volume: &File) -> io::Result<Vec<u8>> {
    let query = STORAGE_PROPERTY_QUERY {
        PropertyId: StorageDeviceProperty,
        QueryType: PropertyStandardQuery,
        AdditionalParameters: [0],
    };
    // SAFETY: `IOCTL_STORAGE_QUERY_PROPERTY` (`METHOD_BUFFERED`) reads one
    // `STORAGE_PROPERTY_QUERY` from the input buffer and writes at most the
    // output length; a descriptor longer than that is truncated, with its
    // full size in `Size`, which the parser handles.
    unsafe { fsctl(volume, IOCTL_STORAGE_QUERY_PROPERTY, Some(&query), 1024) }
}

/// The `STORAGE_HOTPLUG_INFO` of the disk behind `volume`
/// (`IOCTL_STORAGE_GET_HOTPLUG_INFO`), for
/// [`crate::fsctx::volume::parse_hotplug_info`].
pub(crate) fn hotplug_bytes(volume: &File) -> io::Result<Vec<u8>> {
    // SAFETY: `IOCTL_STORAGE_GET_HOTPLUG_INFO` (`METHOD_BUFFERED`) takes no
    // input and writes one 8-byte `STORAGE_HOTPLUG_INFO`, within the
    // 16-byte output length.
    unsafe { fsctl::<()>(volume, IOCTL_STORAGE_GET_HOTPLUG_INFO, None, 16) }
}

/// UTF-16 with a terminating NUL, for a path passed to the OS. Fails on
/// an interior NUL, which would make the OS read a different, shorter path.
pub(crate) fn wide(text: &str) -> io::Result<Vec<u16>> {
    if text.contains('\0') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path contains NUL",
        ));
    }
    Ok(text.encode_utf16().chain(std::iter::once(0)).collect())
}

/// `GetDriveTypeW` of `root`, a volume root with a trailing separator
/// (`C:\`, `\\?\Volume{GUID}\`).
pub(crate) fn drive_type(root: &str) -> io::Result<u32> {
    let w = wide(root)?;
    // SAFETY: `w` is a live, NUL-terminated UTF-16 string that the call
    // only reads.
    Ok(unsafe { GetDriveTypeW(w.as_ptr()) })
}

/// Whether the open directory `dir` is marked case-sensitive
/// (`FileCaseSensitiveInfo`, `FILE_CS_FLAG_CASE_SENSITIVE_DIR`). Fails on
/// a file system or OS that does not support the flag.
pub(crate) fn case_sensitive_dir(dir: &File) -> io::Result<bool> {
    // SAFETY: `FILE_CASE_SENSITIVE_INFO` is the structure for
    // `FileCaseSensitiveInfo`: one `u32`, valid for every bit pattern.
    let info: FILE_CASE_SENSITIVE_INFO = unsafe { info_by_handle(dir, FileCaseSensitiveInfo) }?;
    Ok(info.Flags & 1 != 0)
}

/// `WNetGetConnectionW` of `drive` (`Z:`): the remote name (`\\server\share`
/// or `\\server\share\dir`) the drive letter is mapped to in **this
/// process's logon session**. `Ok(None)` if the letter is not a network
/// connection.
pub(crate) fn mapped_drive_target(drive: char) -> io::Result<Option<String>> {
    let local = wide(&format!("{drive}:"))?;
    let mut units = 512_u32;
    loop {
        let mut buf = vec![0_u16; usize::try_from(units).unwrap_or(0)];
        let mut len = units;
        // SAFETY: `local` is a live, NUL-terminated UTF-16 string the call
        // only reads; `buf` is a live, writable buffer of `len` units and
        // `len` a live local that says so. On `ERROR_MORE_DATA` the OS
        // writes the size needed to `len` and nothing to `buf`.
        let r = unsafe { WNetGetConnectionW(local.as_ptr(), buf.as_mut_ptr(), &raw mut len) };
        match r {
            0 => {
                let end = buf.iter().position(|&u| u == 0).unwrap_or(buf.len());
                let text = buf.get(..end).unwrap_or_default();
                return String::from_utf16(text)
                    .map(Some)
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "not valid UTF-16"));
            }
            // ERROR_NOT_CONNECTED, ERROR_BAD_DEVICE: not a network drive.
            2250 | 1200 => return Ok(None),
            // ERROR_MORE_DATA.
            234 if len > units
                && usize::try_from(len).unwrap_or(usize::MAX) <= MAX_QUERY_BYTES / 2 =>
            {
                units = len;
            }
            e => return Err(io::Error::from_raw_os_error(i32::try_from(e).unwrap_or(-1))),
        }
    }
}

/// The long name of the single entry `path` names (`FindFirstFileExW`,
/// `cFileName`). `path` must not contain wildcards; the caller checks.
pub(crate) fn find_long_name(path: &str) -> io::Result<String> {
    let w = wide(path)?;
    let mut data = WIN32_FIND_DATAW::default();
    // SAFETY: `w` is a live, NUL-terminated UTF-16 string the call only
    // reads; `data` is a live, writable `WIN32_FIND_DATAW`, the structure
    // `FindExInfoBasic` fills. The search filter is null and the flags 0,
    // as `FindExSearchNameMatch` requires.
    let h = unsafe {
        FindFirstFileExW(
            w.as_ptr(),
            FindExInfoBasic,
            (&raw mut data).cast(),
            FindExSearchNameMatch,
            std::ptr::null(),
            0,
        )
    };
    if h == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `h` is the search handle just returned, closed once, here.
    let _ = unsafe { FindClose(h) };
    let end = data
        .cFileName
        .iter()
        .position(|&u| u == 0)
        .unwrap_or(data.cFileName.len());
    String::from_utf16(data.cFileName.get(..end).unwrap_or_default())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "not valid UTF-16"))
}

/// A buffer `NetDfsGetClientInfo` allocated, freed once on drop.
struct NetBuf(*mut u8);

impl Drop for NetBuf {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: `self.0` is the buffer the OS allocated for this call
            // and handed over; it is freed once, here.
            let _ = unsafe { NetApiBufferFree(self.0.cast()) };
        }
    }
}

/// Reads a NUL-terminated UTF-16 string the OS returned, capped at 32,767
/// units.
///
/// # Safety
///
/// `p` must be null or point to a NUL-terminated UTF-16 string that stays
/// alive for the call.
unsafe fn read_pwstr(p: *const u16) -> Option<String> {
    if p.is_null() {
        return None;
    }
    let mut len = 0_usize;
    // SAFETY: the caller guarantees a NUL-terminated string; the loop stops
    // at the NUL or the cap, so it never reads past the terminator.
    while len < 32_767 && unsafe { *p.add(len) } != 0 {
        len += 1;
    }
    // SAFETY: the `len` units before the NUL were just read, so they are
    // valid to read as a slice; it is copied out at once.
    let units = unsafe { std::slice::from_raw_parts(p, len) };
    String::from_utf16(units).ok()
}

/// The DFS referral that covers `path` (`NetDfsGetClientInfo`, level 3):
/// the entry path and the active target as `\\server\share`. `Ok(None)` if
/// `path` is not in a DFS namespace, and an error if no storage is marked
/// active. May block on the network.
pub(crate) fn dfs_client_info(path: &str) -> io::Result<Option<(String, String)>> {
    let w = wide(path)?;
    let mut buf: *mut u8 = std::ptr::null_mut();
    // SAFETY: `w` is a live, NUL-terminated UTF-16 string the call only
    // reads; the server and share are null (looked up from the path);
    // `buf` is a live local the OS sets to a buffer it allocates, owned by
    // `NetBuf` below.
    let r = unsafe {
        NetDfsGetClientInfo(
            w.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            3,
            &raw mut buf,
        )
    };
    let owned = NetBuf(buf);
    match r {
        0 => {}
        // NERR_DfsNoSuchVolume, ERROR_NOT_FOUND, ERROR_FILE_NOT_FOUND,
        // ERROR_BAD_NETPATH: the path is not in a namespace.
        2662 | 1168 | 2 | 53 => return Ok(None),
        e => return Err(io::Error::from_raw_os_error(i32::try_from(e).unwrap_or(-1))),
    }
    if owned.0.is_null() {
        return Ok(None);
    }
    // SAFETY: on success, level 3 returns one `DFS_INFO_3` at `buf`, with
    // `Storage` pointing at `NumberOfStorages` `DFS_STORAGE_INFO`, all in
    // the buffer `owned` keeps alive until the end of this function. Every
    // string is copied out before it is freed.
    unsafe {
        let info = &*owned.0.cast::<DFS_INFO_3>();
        let Some(entry) = read_pwstr(info.EntryPath) else {
            return Ok(None);
        };
        let n = usize::try_from(info.NumberOfStorages).unwrap_or(0).min(64);
        if info.Storage.is_null() {
            return Ok(None);
        }
        let storages: &[DFS_STORAGE_INFO] = std::slice::from_raw_parts(info.Storage, n);
        // Only the storage the client marked active is its target. The
        // `DFS_STORAGE_INFO` reference says "It is possible that no targets
        // will be marked active"; another storage is then not the client's
        // target, so the lookup is unresolved, never a guessed target.
        let Some(s) = storages
            .iter()
            .find(|s| s.State & DFS_STORAGE_STATE_ACTIVE != 0)
        else {
            return Err(io::Error::other(
                "DFS referral has no active target in the client cache",
            ));
        };
        match (read_pwstr(s.ServerName), read_pwstr(s.ShareName)) {
            (Some(server), Some(share)) => Ok(Some((entry, format!(r"\\{server}\{share}")))),
            _ => Ok(None),
        }
    }
}

/// The raw reparse data buffer of the open `file`
/// (`FSCTL_GET_REPARSE_POINT`), for
/// [`crate::fsctx::reparse::parse_reparse_point`]. `file` must have been
/// opened with `FILE_FLAG_OPEN_REPARSE_POINT`.
pub(crate) fn reparse_point_bytes(file: &File) -> io::Result<Vec<u8>> {
    // SAFETY: `FSCTL_GET_REPARSE_POINT` (`METHOD_BUFFERED`) takes no input
    // and writes at most the output length, 16 KiB, the largest reparse
    // data buffer the OS allows.
    unsafe {
        fsctl::<()>(
            file,
            FSCTL_GET_REPARSE_POINT,
            None,
            crate::fsctx::reparse::MAX_REPARSE_BYTES,
        )
    }
}

/// Sets the reparse point of the open `file` to `data`, a whole reparse
/// data buffer (`FSCTL_SET_REPARSE_POINT`). Only the tests use it, to make
/// reparse fixtures (an app execution alias) that no tool on the runners
/// creates.
#[cfg(test)]
pub(crate) fn set_reparse_point(file: &File, data: &[u8]) -> io::Result<()> {
    if data.len() > crate::fsctx::reparse::MAX_REPARSE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "reparse data is too long",
        ));
    }
    let len = u32::try_from(data.len()).unwrap_or(u32::MAX);
    // SAFETY: `data` is a live slice of `len` bytes borrowed for the call.
    // `FSCTL_SET_REPARSE_POINT` (`METHOD_BUFFERED`) reads at most `len`
    // input bytes and writes no output.
    unsafe {
        fsctl_raw(
            file,
            windows_sys::Win32::System::Ioctl::FSCTL_SET_REPARSE_POINT,
            data.as_ptr().cast(),
            len,
            0,
        )
    }
    .map(|_| ())
}

/// A `FindFirstFileNameW` search handle, closed on drop.
struct FindNames(HANDLE);

impl Drop for FindNames {
    fn drop(&mut self) {
        // SAFETY: `self.0` is the search handle `FindFirstFileNameW`
        // returned, closed once, here.
        let _ = unsafe { FindClose(self.0) };
    }
}

/// Up to `max` of the hard-link names of the file at `path`
/// (`FindFirstFileNameW`, `FindNextFileNameW`), each relative to the volume
/// root. The flag says whether the list is complete.
pub(crate) fn hard_link_names(path: &str, max: usize) -> io::Result<(Vec<String>, bool)> {
    const UNITS: u32 = 32_768;
    let w = wide(path)?;
    let mut buf = vec![0_u16; UNITS as usize];
    let mut len = UNITS;
    // SAFETY: `w` is a live, NUL-terminated UTF-16 string the call only
    // reads; `buf` is a live, writable buffer of `len` units and `len` a
    // live local that says so. Flags must be 0.
    let h = unsafe { FindFirstFileNameW(w.as_ptr(), 0, &raw mut len, buf.as_mut_ptr()) };
    if h == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let search = FindNames(h);
    let take = |buf: &[u16], len: u32| -> Option<String> {
        let n = usize::try_from(len).ok()?.min(buf.len());
        let units = buf.get(..n)?;
        let end = units.iter().position(|&u| u == 0).unwrap_or(units.len());
        String::from_utf16(units.get(..end)?).ok()
    };
    let mut names = Vec::new();
    let mut complete = true;
    match take(&buf, len) {
        Some(n) => names.push(n),
        None => complete = false,
    }
    loop {
        if names.len() >= max {
            complete = false;
            break;
        }
        len = UNITS;
        // SAFETY: `search.0` is the live search handle; `buf` is a live,
        // writable buffer of `len` units and `len` a live local.
        let ok = unsafe { FindNextFileNameW(search.0, &raw mut len, buf.as_mut_ptr()) };
        if ok == 0 {
            // ERROR_HANDLE_EOF ends the list; anything else cuts it short.
            if io::Error::last_os_error().raw_os_error() != Some(ERROR_HANDLE_EOF) {
                complete = false;
            }
            break;
        }
        match take(&buf, len) {
            Some(n) => names.push(n),
            None => complete = false,
        }
    }
    Ok((names, complete))
}

/// The system Windows directory (`GetSystemWindowsDirectoryW`), which is
/// on the OS volume.
pub(crate) fn windows_directory() -> io::Result<String> {
    let mut buf = [0_u16; 1024];
    let cap = u32::try_from(buf.len()).unwrap_or(0);
    // SAFETY: `buf` is a live, writable buffer of `cap` UTF-16 units, the
    // size passed; the OS reports a larger required size instead of
    // writing past it.
    let n = unsafe { GetSystemWindowsDirectoryW(buf.as_mut_ptr(), cap) };
    let n = usize::try_from(n).unwrap_or(usize::MAX);
    if n == 0 {
        return Err(io::Error::last_os_error());
    }
    let units = buf
        .get(..n)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "path too long"))?;
    String::from_utf16(units)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "not valid UTF-16"))
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
    /// Maps the first `size` bytes of `file`, which must be open for
    /// reading, and at least that long. The section is exactly `size` bytes,
    /// so the file cannot be truncated below it while the mapping exists,
    /// and the OS refuses to create it if the file is already shorter.
    pub(crate) fn new(file: &File, size: u64) -> io::Result<Self> {
        if size == 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty mapping"));
        }
        let high = u32::try_from(size >> 32).unwrap_or(u32::MAX);
        let low = u32::try_from(size & 0xFFFF_FFFF).unwrap_or(0);
        // SAFETY: `handle(file)` is an open handle borrowed for the call. A
        // null security descriptor and a null name create an unnamed
        // mapping with default security, `size` bytes long. `PAGE_READONLY`
        // matches a handle opened for reading.
        let h = unsafe {
            CreateFileMappingW(
                handle(file),
                std::ptr::null(),
                PAGE_READONLY,
                high,
                low,
                std::ptr::null(),
            )
        };
        if h.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { handle: h })
    }

    /// Maps `len` bytes from `offset`, which must be a multiple of
    /// [`allocation_granularity`] and lie within the file. `len` must not be
    /// zero (the OS would map to the end of the file instead).
    pub(crate) fn view(&self, offset: u64, len: usize) -> io::Result<View> {
        if len == 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty view"));
        }
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
    /// The view's length in bytes.
    pub(crate) fn len(&self) -> usize {
        self.len
    }

    /// Copies `out.len()` bytes from `offset` in the view into `out`.
    ///
    /// Another process may write the file while it is mapped, so the mapped
    /// memory is shared and can change at any time. No Rust reference is
    /// ever made to it: the bytes are copied out with a raw-pointer copy
    /// into memory this process owns, and only the copy is used. A change
    /// mid-copy can make the copy a mix of old and new bytes, which the
    /// stamp check in [`crate::hash::hash_through`] catches afterwards.
    pub(crate) fn copy_to(&self, offset: usize, out: &mut [u8]) -> io::Result<()> {
        let end = offset.checked_add(out.len()).filter(|&e| e <= self.len);
        if end.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "copy past the view",
            ));
        }
        // SAFETY: `offset + out.len() <= self.len` (checked above), so the
        // source range lies inside the readable view `MapViewOfFile`
        // returned, which stays mapped while `self` is alive. `out` is a
        // distinct, writable buffer of exactly that length, so the ranges do
        // not overlap. A raw byte copy is valid for any bytes, and no
        // reference to the shared memory is created.
        unsafe {
            std::ptr::copy_nonoverlapping(
                self.addr.Value.cast::<u8>().cast_const().add(offset),
                out.as_mut_ptr(),
                out.len(),
            );
        }
        Ok(())
    }
}

impl Drop for View {
    fn drop(&mut self) {
        // SAFETY: `self.addr` is the base address `MapViewOfFile` returned,
        // unmapped once, here.
        let _ = unsafe { UnmapViewOfFile(self.addr) };
    }
}

// ---------------------------------------------------------------------------
// Installed packages (#333).

/// `ERROR_INSUFFICIENT_BUFFER`.
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
/// The most packages one family query returns.
const MAX_FAMILY_PACKAGES: u32 = 256;

/// `FindPackagesByPackageFamily` for the current user: the full name and
/// `PACKAGE_PROPERTY_*` flags of each package of `family` that matches
/// `filters`. Empty when none is installed.
pub(crate) fn packages_by_family(family: &str, filters: u32) -> io::Result<Vec<(String, u32)>> {
    use windows_sys::Win32::Storage::Packaging::Appx::FindPackagesByPackageFamily;
    let w = wide(family)?;
    let mut count = 0_u32;
    let mut len = 0_u32;
    // SAFETY: the sizing call: `w` is a live NUL-terminated string the call
    // reads; `count` and `len` are live locals it writes; the three output
    // arrays are null with zero sizes, which the call documents as the way
    // to ask for the sizes.
    let rc = unsafe {
        FindPackagesByPackageFamily(
            w.as_ptr(),
            filters,
            &raw mut count,
            std::ptr::null_mut(),
            &raw mut len,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    match rc {
        0 if count == 0 => return Ok(Vec::new()),
        0 | ERROR_INSUFFICIENT_BUFFER => {}
        e => return Err(io::Error::from_raw_os_error(i32::try_from(e).unwrap_or(-1))),
    }
    let len_units = usize::try_from(len).unwrap_or(usize::MAX);
    if count > MAX_FAMILY_PACKAGES || len_units > MAX_QUERY_BYTES / 2 {
        return Err(io::Error::other("too many packages in the family"));
    }
    let n = usize::try_from(count).unwrap_or(0);
    let mut names: Vec<windows_sys::core::PWSTR> = vec![std::ptr::null_mut(); n];
    let mut buffer = vec![0_u16; len_units];
    let mut props = vec![0_u32; n];
    let (mut count2, mut len2) = (count, len);
    // SAFETY: `names` and `props` hold `count` entries and `buffer` `len`
    // UTF-16 units, the sizes passed in `count2` and `len2`; all are live,
    // writable and outlive the call. The OS fills `names` with pointers
    // into `buffer`, which are only read below after a bounds check.
    let rc = unsafe {
        FindPackagesByPackageFamily(
            w.as_ptr(),
            filters,
            &raw mut count2,
            names.as_mut_ptr(),
            &raw mut len2,
            buffer.as_mut_ptr(),
            props.as_mut_ptr(),
        )
    };
    if rc != 0 {
        return Err(io::Error::from_raw_os_error(
            i32::try_from(rc).unwrap_or(-1),
        ));
    }
    let got = usize::try_from(count2).unwrap_or(0).min(n);
    let base = buffer.as_ptr() as usize;
    let mut out = Vec::with_capacity(got);
    for (p, flags) in names.iter().zip(&props).take(got) {
        // Each pointer must fall inside `buffer`, on a unit boundary; the
        // string is read from the buffer itself, up to its NUL.
        let at = (*p as usize)
            .checked_sub(base)
            .filter(|off| off % 2 == 0)
            .map(|off| off / 2)
            .filter(|&i| i < buffer.len())
            .ok_or_else(|| io::Error::other("package name outside the buffer"))?;
        let tail = buffer.get(at..).unwrap_or_default();
        let end = tail.iter().position(|&u| u == 0).unwrap_or(tail.len());
        let name = String::from_utf16(tail.get(..end).unwrap_or_default())
            .map_err(|_| io::Error::other("package name is not valid UTF-16"))?;
        out.push((name, *flags));
    }
    Ok(out)
}

/// `GetPackagePathByFullName`: the install folder of the package
/// `full_name`, for the current user.
pub(crate) fn package_path(full_name: &str) -> io::Result<String> {
    use windows_sys::Win32::Storage::Packaging::Appx::GetPackagePathByFullName;
    let w = wide(full_name)?;
    let mut len = 0_u32;
    // SAFETY: the sizing call: `w` is a live NUL-terminated string; `len`
    // is a live local; the output buffer is null with a zero length.
    let rc = unsafe { GetPackagePathByFullName(w.as_ptr(), &raw mut len, std::ptr::null_mut()) };
    if rc != ERROR_INSUFFICIENT_BUFFER && rc != 0 {
        return Err(io::Error::from_raw_os_error(
            i32::try_from(rc).unwrap_or(-1),
        ));
    }
    let units = usize::try_from(len).unwrap_or(usize::MAX);
    if units == 0 || units > MAX_QUERY_BYTES / 2 {
        return Err(io::Error::other("package path length out of range"));
    }
    let mut buf = vec![0_u16; units];
    let mut len2 = len;
    // SAFETY: `buf` holds `len` writable units, the size passed in `len2`,
    // and outlives the call.
    let rc = unsafe { GetPackagePathByFullName(w.as_ptr(), &raw mut len2, buf.as_mut_ptr()) };
    if rc != 0 {
        return Err(io::Error::from_raw_os_error(
            i32::try_from(rc).unwrap_or(-1),
        ));
    }
    let end = buf.iter().position(|&u| u == 0).unwrap_or(buf.len());
    String::from_utf16(buf.get(..end).unwrap_or_default())
        .map_err(|_| io::Error::other("package path is not valid UTF-16"))
}

/// `GetStagedPackageOrigin`: how the staged package `full_name` was signed
/// (`PackageOrigin_*`).
pub(crate) fn package_origin(full_name: &str) -> io::Result<i32> {
    use windows_sys::Win32::Storage::Packaging::Appx::GetStagedPackageOrigin;
    let w = wide(full_name)?;
    let mut origin = 0_i32;
    // SAFETY: `w` is a live NUL-terminated string the call reads; `origin`
    // is a live local it writes.
    let rc = unsafe { GetStagedPackageOrigin(w.as_ptr(), &raw mut origin) };
    if rc != 0 {
        return Err(io::Error::from_raw_os_error(
            i32::try_from(rc).unwrap_or(-1),
        ));
    }
    Ok(origin)
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
        let guid = final_path_by_handle(&file, 1).unwrap();
        assert!(guid.starts_with(r"\\?\Volume{"), "{guid}");
        assert!(is_disk_file(&file));
        assert!(remote_protocol(&file).is_err());
        drop(file);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn streams_and_usn() {
        let (dir, file) = temp_file("streams", b"x");
        let bytes = stream_info_bytes(&file).unwrap();
        let list = crate::fsctx::ntfs::parse_stream_info(&bytes).unwrap();
        assert!(list.streams.iter().any(|s| s.is_default() && s.size == 1));
        // The temporary folder on the CI runners is on the system volume,
        // NTFS with an active change journal.
        let b = read_file_usn_bytes(&file).unwrap();
        let facts = crate::fsctx::ntfs::parse_usn_record(&b).unwrap();
        assert!(facts.usn >= 0);
        drop(file);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn mapping_windows() {
        let content: Vec<u8> = (0..200_000_u32).map(|i| (i % 251) as u8).collect();
        let (dir, file) = temp_file("map", &content);
        let g = allocation_granularity();
        assert!(g.is_power_of_two());
        let map = Mapping::new(&file, 200_000).unwrap();
        assert!(Mapping::new(&file, 0).is_err());
        assert!(
            Mapping::new(&file, 400_000).is_err(),
            "longer than the file"
        );
        let first = map.view(0, 1000).unwrap();
        let mut buf = vec![0_u8; 1000];
        first.copy_to(0, &mut buf).unwrap();
        assert_eq!(buf, &content[..1000]);
        let mut tail = vec![0_u8; 10];
        first.copy_to(990, &mut tail).unwrap();
        assert_eq!(tail, &content[990..1000]);
        assert!(first.copy_to(991, &mut tail).is_err(), "past the view");
        let off = usize::try_from(g).unwrap();
        let second = map.view(g, 100).unwrap();
        let mut buf = vec![0_u8; 100];
        second.copy_to(0, &mut buf).unwrap();
        assert_eq!(buf, &content[off..off + 100]);
        // Past the end, or empty, fails rather than mapping.
        assert!(map.view(g * 1000, 10).is_err());
        assert!(map.view(0, 0).is_err());
        drop((first, second, map, file));
        let _ = std::fs::remove_dir_all(dir);
    }
}
