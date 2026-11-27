//! Thin, safe wrappers over the Windows process, token, session and
//! local-group calls the agent's platform backends need (#29). This is the
//! one place in the agent where those calls are made, so every `unsafe`
//! block is here, each with a `// SAFETY:` comment (ADR 0011).
//!
//! Each wrapper owns every buffer it hands to the OS and returns plain Rust
//! values or raw bytes. Variable-length records (token groups, the process
//! command line) are returned as bytes, with the address the OS wrote them
//! at, for the portable decoders in `platform::nt`, which are tested on
//! every OS. Nothing here interprets those records.
//!
//! Every handle is closed on drop. Every call uses the agent's own
//! security context; no call follows a path.

#![allow(unsafe_code)]

use std::io;

use windows_sys::Wdk::System::Threading::{
    NtQueryInformationProcess, PROCESSINFOCLASS, ProcessBasicInformation,
    ProcessCommandLineInformation,
};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_PARAMETER, ERROR_MORE_DATA, FILETIME,
    HANDLE, NTSTATUS, STATUS_ACCESS_DENIED, STATUS_BUFFER_OVERFLOW, STATUS_BUFFER_TOO_SMALL,
    STATUS_INFO_LENGTH_MISMATCH, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::NetworkManagement::NetManagement::{
    LOCALGROUP_MEMBERS_INFO_0, MAX_PREFERRED_LENGTH, NERR_Success, NetApiBufferFree,
    NetLocalGroupGetMembers,
};
use windows_sys::Win32::Security::{
    GetLengthSid, GetTokenInformation, LookupAccountNameW, SID_NAME_USE, TOKEN_INFORMATION_CLASS,
    TOKEN_QUERY,
};
use windows_sys::Win32::System::RemoteDesktop::{
    WTS_CURRENT_SERVER_HANDLE, WTSClientProtocolType, WTSFreeMemory, WTSQuerySessionInformationW,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetProcessTimes, OpenProcess, OpenProcessToken,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, QueryFullProcessImageNameW,
    WaitForSingleObject,
};

/// The largest record any query here grows its buffer to: 1 MiB. A larger
/// answer is an error, never an unbounded allocation.
const MAX_RECORD_BYTES: usize = 1 << 20;

/// The most members [`local_group_members`] returns.
pub(crate) const MAX_GROUP_MEMBERS: usize = 100_000;

/// A record the OS wrote: its bytes, and the address of the buffer they
/// were written to, so pointers inside the record can be turned into
/// offsets (`platform::nt::Record`).
pub(crate) struct RawRecord {
    pub(crate) bytes: Vec<u8>,
    pub(crate) base: usize,
}

/// A buffer of `bytes` bytes aligned for pointers, as every record here
/// needs.
fn aligned(bytes: usize) -> Vec<usize> {
    vec![0_usize; bytes.div_ceil(size_of::<usize>())]
}

/// The first `len` bytes of `words`, in memory order.
fn to_bytes(words: &[usize], len: usize) -> Vec<u8> {
    words
        .iter()
        .flat_map(|w| w.to_ne_bytes())
        .take(len)
        .collect()
}

fn u32_len(bytes: usize) -> u32 {
    u32::try_from(bytes).unwrap_or(u32::MAX)
}

fn nt_error(status: NTSTATUS, what: &str) -> io::Error {
    if status == STATUS_ACCESS_DENIED {
        return io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{what}: access denied"),
        );
    }
    io::Error::other(format!("{what}: NTSTATUS {:#010x}", status.cast_unsigned()))
}

// ---------------------------------------------------------------------------
// Processes
// ---------------------------------------------------------------------------

/// An open process handle, closed on drop. Holding it keeps the process
/// object alive, so its ID cannot be reused while the handle is open.
pub(crate) struct Process {
    handle: HANDLE,
    /// The pseudo-handle of the current process, which is never closed.
    pseudo: bool,
}

impl Process {
    /// Opens process `pid` with `PROCESS_QUERY_LIMITED_INFORMATION` and
    /// `SYNCHRONIZE`. A process ID with no process object fails with
    /// [`io::ErrorKind::NotFound`].
    pub(crate) fn open(pid: u32) -> io::Result<Self> {
        // SAFETY: plain values in, a new handle (or null) out; nothing is
        // borrowed.
        let handle = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                0,
                pid,
            )
        };
        if handle.is_null() {
            let e = io::Error::last_os_error();
            // The OS reports an unused process ID as an invalid parameter.
            if e.raw_os_error() == i32::try_from(ERROR_INVALID_PARAMETER).ok() {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("no process {pid}"),
                ));
            }
            return Err(e);
        }
        Ok(Self {
            handle,
            pseudo: false,
        })
    }

    /// The calling process.
    pub(crate) fn current() -> Self {
        Self {
            // SAFETY: no arguments; returns a pseudo-handle that needs no
            // closing and is valid for the life of the process.
            handle: unsafe { GetCurrentProcess() },
            pseudo: true,
        }
    }

    /// Whether the process has exited. A process object outlives its
    /// process while any handle to it is open.
    pub(crate) fn has_exited(&self) -> io::Result<bool> {
        // SAFETY: `self.handle` is an open process handle with
        // `SYNCHRONIZE`; a zero timeout only polls its state.
        match unsafe { WaitForSingleObject(self.handle, 0) } {
            WAIT_OBJECT_0 => Ok(true),
            WAIT_TIMEOUT => Ok(false),
            _ => Err(io::Error::last_os_error()),
        }
    }

    /// The creation time, as a `FILETIME` value.
    pub(crate) fn creation_time(&self) -> io::Result<u64> {
        let mut times = [FILETIME::default(); 4];
        let [created, exited, kernel, user] = &mut times;
        // SAFETY: `self.handle` is an open process handle with
        // `PROCESS_QUERY_LIMITED_INFORMATION`; the four out pointers are
        // distinct, live, writable `FILETIME`s.
        let ok = unsafe {
            GetProcessTimes(
                self.handle,
                std::ptr::from_mut(created),
                std::ptr::from_mut(exited),
                std::ptr::from_mut(kernel),
                std::ptr::from_mut(user),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        let [created, ..] = times;
        Ok(u64::from(created.dwHighDateTime) << 32 | u64::from(created.dwLowDateTime))
    }

    /// The full Win32 path of the process's image.
    pub(crate) fn image_path(&self) -> io::Result<String> {
        let mut units = 512_usize;
        loop {
            let mut buf = vec![0_u16; units];
            let mut len = u32_len(buf.len());
            // SAFETY: `self.handle` is an open process handle with
            // `PROCESS_QUERY_LIMITED_INFORMATION`; `buf` is a live,
            // writable buffer of `len` UTF-16 units, the size passed, and
            // `len` a live local the OS updates.
            let ok = unsafe {
                QueryFullProcessImageNameW(self.handle, 0, buf.as_mut_ptr(), &raw mut len)
            };
            if ok != 0 {
                buf.truncate(usize::try_from(len).unwrap_or(0).min(buf.len()));
                return String::from_utf16(&buf).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "image path is not valid UTF-16")
                });
            }
            let e = io::Error::last_os_error();
            if e.raw_os_error() != i32::try_from(ERROR_INSUFFICIENT_BUFFER).ok()
                || units * 2 > MAX_RECORD_BYTES
            {
                return Err(e);
            }
            units *= 4;
        }
    }

    /// `NtQueryInformationProcess` for `class`, into a buffer that grows
    /// from `initial` bytes while the OS says it is too small.
    fn query(&self, class: PROCESSINFOCLASS, initial: usize, what: &str) -> io::Result<RawRecord> {
        let mut bytes = initial;
        loop {
            let mut buf = aligned(bytes);
            let cap = buf.len() * size_of::<usize>();
            let mut needed = 0_u32;
            // SAFETY: `self.handle` is an open process handle with
            // `PROCESS_QUERY_LIMITED_INFORMATION`, which both classes used
            // here need; `buf` is a live, writable, pointer-aligned buffer
            // of `cap` bytes, the size passed; `needed` is a live local.
            let status = unsafe {
                NtQueryInformationProcess(
                    self.handle,
                    class,
                    buf.as_mut_ptr().cast(),
                    u32_len(cap),
                    &raw mut needed,
                )
            };
            if status >= 0 {
                let len = usize::try_from(needed).unwrap_or(cap).min(cap);
                let base = buf.as_ptr().addr();
                return Ok(RawRecord {
                    bytes: to_bytes(&buf, len),
                    base,
                });
            }
            let grow = matches!(
                status,
                STATUS_INFO_LENGTH_MISMATCH | STATUS_BUFFER_TOO_SMALL | STATUS_BUFFER_OVERFLOW
            );
            let next = usize::try_from(needed).unwrap_or(usize::MAX).max(cap * 2);
            if !grow || next > MAX_RECORD_BYTES {
                return Err(nt_error(status, what));
            }
            bytes = next;
        }
    }

    /// The raw `PROCESS_BASIC_INFORMATION`.
    pub(crate) fn basic_information(&self) -> io::Result<RawRecord> {
        // Six pointer-sized fields.
        self.query(
            ProcessBasicInformation,
            6 * size_of::<usize>(),
            "ProcessBasicInformation",
        )
    }

    /// The raw `UNICODE_STRING` record of the command line, its buffer
    /// following it in the same record.
    pub(crate) fn command_line(&self) -> io::Result<RawRecord> {
        self.query(
            ProcessCommandLineInformation,
            1024,
            "ProcessCommandLineInformation",
        )
    }

    /// The process's primary token, opened for `TOKEN_QUERY`.
    pub(crate) fn token(&self) -> io::Result<Token> {
        let mut handle: HANDLE = std::ptr::null_mut();
        // SAFETY: `self.handle` is an open process handle with
        // `PROCESS_QUERY_LIMITED_INFORMATION`, which opening the token
        // needs; `handle` is a live local the OS writes a new handle into.
        let ok = unsafe { OpenProcessToken(self.handle, TOKEN_QUERY, &raw mut handle) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Token(handle))
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        if !self.pseudo {
            // SAFETY: `self.handle` was opened by `open`, is owned by this
            // value and is closed once, here.
            let _ = unsafe { CloseHandle(self.handle) };
        }
    }
}

// ---------------------------------------------------------------------------
// Tokens
// ---------------------------------------------------------------------------

/// An access token opened for `TOKEN_QUERY`, closed on drop.
pub(crate) struct Token(HANDLE);

impl Token {
    /// `GetTokenInformation` for `class`, as raw bytes.
    pub(crate) fn information(&self, class: TOKEN_INFORMATION_CLASS) -> io::Result<RawRecord> {
        let mut bytes = 256_usize;
        loop {
            let mut buf = aligned(bytes);
            let cap = buf.len() * size_of::<usize>();
            let mut needed = 0_u32;
            // SAFETY: `self.0` is an open token handle with `TOKEN_QUERY`;
            // `buf` is a live, writable, pointer-aligned buffer of `cap`
            // bytes, the size passed; `needed` is a live local.
            let ok = unsafe {
                GetTokenInformation(
                    self.0,
                    class,
                    buf.as_mut_ptr().cast(),
                    u32_len(cap),
                    &raw mut needed,
                )
            };
            if ok != 0 {
                let len = usize::try_from(needed).unwrap_or(cap).min(cap);
                let base = buf.as_ptr().addr();
                return Ok(RawRecord {
                    bytes: to_bytes(&buf, len),
                    base,
                });
            }
            let e = io::Error::last_os_error();
            let next = usize::try_from(needed).unwrap_or(usize::MAX).max(cap * 2);
            if e.raw_os_error() != i32::try_from(ERROR_INSUFFICIENT_BUFFER).ok()
                || next > MAX_RECORD_BYTES
            {
                return Err(e);
            }
            bytes = next;
        }
    }
}

impl Drop for Token {
    fn drop(&mut self) {
        // SAFETY: `self.0` was opened by `Process::token`, is owned by
        // this value and is closed once, here.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

/// The client protocol of session `session_id` (`WTSClientProtocolType`):
/// 0 for the console, 2 for a remote desktop session.
pub(crate) fn session_protocol(session_id: u32) -> io::Result<u16> {
    let mut buf: *mut u16 = std::ptr::null_mut();
    let mut len = 0_u32;
    // SAFETY: the local server handle and plain values in; the OS writes a
    // pointer to a buffer it allocates into `buf`, and its size into `len`,
    // both live locals.
    let ok = unsafe {
        WTSQuerySessionInformationW(
            WTS_CURRENT_SERVER_HANDLE,
            session_id,
            WTSClientProtocolType,
            &raw mut buf,
            &raw mut len,
        )
    };
    if ok == 0 || buf.is_null() {
        return Err(io::Error::last_os_error());
    }
    let value = if usize::try_from(len).unwrap_or(0) >= size_of::<u16>() {
        // SAFETY: the OS returned a buffer of `len` bytes, at least two,
        // holding the protocol as a `USHORT`; its allocation is aligned
        // for any type.
        Ok(unsafe { buf.read() })
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "short WTSClientProtocolType",
        ))
    };
    // SAFETY: `buf` was allocated by `WTSQuerySessionInformationW` and is
    // freed once, here, after the value was copied out.
    unsafe { WTSFreeMemory(buf.cast()) };
    value
}

// ---------------------------------------------------------------------------
// Accounts
// ---------------------------------------------------------------------------

/// The binary SID and the `SID_NAME_USE` of the account `name` (such as
/// `BUILTIN\Administrators`), with `LookupAccountNameW` on the local
/// computer.
pub(crate) fn lookup_account_name(name: &str) -> io::Result<(Vec<u8>, i32)> {
    if name.contains('\0') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "account name contains a NUL character",
        ));
    }
    let wide: Vec<u16> = name.encode_utf16().chain([0]).collect();
    // A SID is at most 68 bytes; 256 leaves room. `u32` words keep it
    // aligned as the OS's `SID` structure requires.
    let mut sid = [0_u32; 64];
    let mut sid_len = u32_len(size_of_val(&sid));
    let mut domain = [0_u16; 256];
    let mut domain_len = u32_len(domain.len());
    let mut use_: SID_NAME_USE = 0;
    // SAFETY: `wide` is a NUL-terminated UTF-16 name, alive for the call;
    // a null system name is the local computer. `sid` and `domain` are
    // live, writable buffers of `sid_len` bytes and `domain_len` UTF-16
    // units, the sizes passed, and the lengths and `use_` live locals.
    let ok = unsafe {
        LookupAccountNameW(
            std::ptr::null(),
            wide.as_ptr(),
            sid.as_mut_ptr().cast(),
            &raw mut sid_len,
            domain.as_mut_ptr(),
            &raw mut domain_len,
            &raw mut use_,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    let len = usize::try_from(sid_len).unwrap_or(0).min(size_of_val(&sid));
    let bytes: Vec<u8> = sid.iter().flat_map(|w| w.to_ne_bytes()).take(len).collect();
    Ok((bytes, use_))
}

// ---------------------------------------------------------------------------
// Local groups
// ---------------------------------------------------------------------------

/// A buffer the network management API allocated, freed on drop.
struct NetBuffer(*mut u8);

impl Drop for NetBuffer {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: `self.0` was allocated by `NetLocalGroupGetMembers`
            // and is freed once, here.
            let _ = unsafe { NetApiBufferFree(self.0.cast_const().cast()) };
        }
    }
}

/// The binary SIDs of the direct members of the local group `name` (its
/// name, without a domain), with `NetLocalGroupGetMembers`. Fails with the
/// network management status as the OS error code, such as
/// `NERR_GroupNotFound`, or with [`io::ErrorKind::OutOfMemory`] past
/// [`MAX_GROUP_MEMBERS`].
pub(crate) fn local_group_members(name: &str) -> io::Result<Vec<Vec<u8>>> {
    if name.contains('\0') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "group name contains a NUL character",
        ));
    }
    let wide: Vec<u16> = name.encode_utf16().chain([0]).collect();
    let mut members = Vec::new();
    let mut resume = 0_usize;
    loop {
        let mut buf = NetBuffer(std::ptr::null_mut());
        let (mut read, mut total) = (0_u32, 0_u32);
        // SAFETY: `wide` is a NUL-terminated UTF-16 name, alive for the
        // call; a null server name is the local computer. The OS writes a
        // buffer it allocates into `buf.0` (freed by `NetBuffer`), and the
        // counts and the resume handle into live locals.
        let status = unsafe {
            NetLocalGroupGetMembers(
                std::ptr::null(),
                wide.as_ptr(),
                0,
                &raw mut buf.0,
                MAX_PREFERRED_LENGTH,
                &raw mut read,
                &raw mut total,
                &raw mut resume,
            )
        };
        if status != NERR_Success && status != ERROR_MORE_DATA {
            return Err(io::Error::from_raw_os_error(
                i32::try_from(status).unwrap_or(i32::MAX),
            ));
        }
        let count = usize::try_from(read).unwrap_or(0);
        if !buf.0.is_null() && count > 0 {
            let entries: *const LOCALGROUP_MEMBERS_INFO_0 = buf.0.cast_const().cast();
            for i in 0..count {
                // SAFETY: the OS returned `read` contiguous, aligned
                // `LOCALGROUP_MEMBERS_INFO_0` entries at `buf.0`, alive
                // until `buf` is dropped; `i < read`.
                let psid = unsafe { entries.add(i).read() }.lgrmi0_sid;
                if psid.is_null() {
                    continue;
                }
                // SAFETY: `psid` is a valid SID inside the OS's buffer,
                // alive until `buf` is dropped.
                let len = usize::try_from(unsafe { GetLengthSid(psid) }).unwrap_or(0);
                // SAFETY: a valid SID is `len` contiguous bytes at `psid`,
                // inside the OS's buffer; they are copied out at once.
                let sid =
                    unsafe { std::slice::from_raw_parts(psid.cast::<u8>().cast_const(), len) };
                members.push(sid.to_vec());
            }
        }
        if members.len() > MAX_GROUP_MEMBERS {
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "too many group members",
            ));
        }
        if status == NERR_Success {
            return Ok(members);
        }
        if count == 0 {
            return Err(io::Error::other(
                "the OS reported more members but returned none",
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_current_process() {
        let me = Process::current();
        assert!(!me.has_exited().unwrap());
        assert!(me.creation_time().unwrap() > 0);
        // The same file as the one the standard library names, whatever
        // spelling each uses.
        let exe = std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
        let image = std::fs::canonicalize(me.image_path().unwrap()).unwrap();
        assert_eq!(image, exe);
        let basic = me.basic_information().unwrap();
        assert_eq!(basic.bytes.len(), 6 * size_of::<usize>());
        let cmd = me.command_line().unwrap();
        assert!(cmd.bytes.len() > 2 * size_of::<usize>());
        let opened = Process::open(std::process::id()).unwrap();
        assert_eq!(opened.creation_time().unwrap(), me.creation_time().unwrap());
    }

    #[test]
    fn an_unused_process_id_is_not_found() {
        // Process IDs are multiples of 4, so this one is never in use.
        let e = Process::open(0xFFFF_FFF1).err().unwrap();
        assert_eq!(e.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn token_records() {
        use windows_sys::Win32::Security::{TokenGroups, TokenUser};
        let token = Process::current().token().unwrap();
        let user = token.information(TokenUser).unwrap();
        assert!(user.bytes.len() > 2 * size_of::<usize>());
        let groups = token.information(TokenGroups).unwrap();
        assert!(groups.bytes.len() > size_of::<usize>());
    }

    #[test]
    fn administrators_has_members() {
        // `BUILTIN\Administrators`, by SID, so the test does not depend
        // on the display language.
        let admins = palisade_fileid::fsctx::Sid::new(5, &[32, 544]).unwrap();
        let name = palisade_fileid::win::security::account_name(&admins).unwrap();
        let (sid, kind) = lookup_account_name(&name).unwrap();
        assert_eq!(sid, admins.to_bytes());
        assert_eq!(kind, windows_sys::Win32::Security::SidTypeAlias);
        let short = name.rsplit('\\').next().unwrap();
        let members = local_group_members(short).unwrap();
        assert!(!members.is_empty());
        let e = local_group_members("No Such Palisade Group").unwrap_err();
        assert!(e.raw_os_error().is_some());
        assert!(local_group_members("a\0b").is_err());
    }
}
