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
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetBestRoute2, GetIfEntry2, MIB_IF_ROW2, MIB_IPFORWARD_ROW2,
};
use windows_sys::Win32::NetworkManagement::NetManagement::{
    LOCALGROUP_MEMBERS_INFO_0, MAX_PREFERRED_LENGTH, NERR_Success, NetApiBufferFree,
    NetLocalGroupGetMembers,
};
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, IN_ADDR, IN_ADDR_0, IN6_ADDR, IN6_ADDR_0, SOCKADDR_IN, SOCKADDR_IN6,
    SOCKADDR_INET,
};
use windows_sys::Win32::Security::{
    GetLengthSid, GetTokenInformation, LookupAccountNameW, LookupAccountSidW, SID_NAME_USE,
    TOKEN_INFORMATION_CLASS, TOKEN_QUERY,
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
            if e.raw_os_error() != i32::try_from(ERROR_INSUFFICIENT_BUFFER).ok() {
                return Err(e);
            }
            // Grow within the cap: the last try is exactly
            // `MAX_RECORD_BYTES`, never more.
            let cap_units = MAX_RECORD_BYTES / 2;
            if units >= cap_units {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "image path is longer than the record limit",
                ));
            }
            units = units.saturating_mul(4).min(cap_units);
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
    /// `GetTokenInformation` for a class whose record is one `DWORD`
    /// (`TokenSessionId`, `TokenElevationType`, `TokenElevation`). Some
    /// such classes accept only a buffer of exactly that size
    /// (`ERROR_BAD_LENGTH` otherwise).
    pub(crate) fn dword(&self, class: TOKEN_INFORMATION_CLASS) -> io::Result<u32> {
        let mut value = 0_u32;
        let mut needed = 0_u32;
        // SAFETY: `self.0` is an open token handle with `TOKEN_QUERY`;
        // `value` is a live, writable `u32` and its size is the length
        // passed; `needed` is a live local.
        let ok = unsafe {
            GetTokenInformation(
                self.0,
                class,
                (&raw mut value).cast(),
                u32_len(size_of::<u32>()),
                &raw mut needed,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        if usize::try_from(needed).ok() != Some(size_of::<u32>()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "token record is not one DWORD",
            ));
        }
        Ok(value)
    }

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
// Network
// ---------------------------------------------------------------------------

/// The interface the OS routes a packet for `dest` through
/// (`GetBestRoute2`), and that interface's row (`GetIfEntry2`), joined by
/// the interface LUID the route names, so an index reused in between
/// cannot name another interface.
pub(crate) fn best_route(dest: std::net::IpAddr) -> crate::platform::connection::Route {
    use crate::platform::connection::{InterfaceRow, Route, route_from_status};
    let mut destination = SOCKADDR_INET::default();
    match dest {
        std::net::IpAddr::V4(a) => {
            destination.Ipv4 = SOCKADDR_IN {
                sin_family: AF_INET,
                sin_addr: IN_ADDR {
                    S_un: IN_ADDR_0 {
                        S_addr: u32::from_ne_bytes(a.octets()),
                    },
                },
                ..SOCKADDR_IN::default()
            };
        }
        std::net::IpAddr::V6(a) => {
            destination.Ipv6 = SOCKADDR_IN6 {
                sin6_family: AF_INET6,
                sin6_addr: IN6_ADDR {
                    u: IN6_ADDR_0 { Byte: a.octets() },
                },
                ..SOCKADDR_IN6::default()
            };
        }
    }
    let mut route = MIB_IPFORWARD_ROW2::default();
    let mut source = SOCKADDR_INET::default();
    // SAFETY: `destination` is a live, initialised `SOCKADDR_INET` of the
    // address's family; no interface is named (a null LUID and index 0)
    // and no source address is given (null), as the API allows. `route`
    // and `source` are live, writable locals the OS fills; both are plain
    // integers, unions of integer arrays and booleans the OS writes as 0
    // or 1.
    let status = unsafe {
        GetBestRoute2(
            std::ptr::null(),
            0,
            std::ptr::null(),
            &raw const destination,
            0,
            &raw mut route,
            &raw mut source,
        )
    };
    if let Some(route) = route_from_status(status) {
        return route;
    }
    let mut row = MIB_IF_ROW2 {
        InterfaceLuid: route.InterfaceLuid,
        ..MIB_IF_ROW2::default()
    };
    // SAFETY: `row` is a live, writable `MIB_IF_ROW2` with only
    // `InterfaceLuid` set, as the call requires (it reads the LUID when it
    // is non-zero); the OS fills the rest of the structure, which is plain
    // integers, arrays and GUIDs.
    if unsafe { GetIfEntry2(&raw mut row) } != 0 {
        return Route::Failed;
    }
    Route::Through(InterfaceRow {
        if_type: row.Type,
        physical_medium: row.PhysicalMediumType,
        tunnel_type: row.TunnelType,
        // `HardwareInterface` is bit 0 of the flags byte.
        hardware: row.InterfaceAndOperStatusFlags._bitfield & 1 != 0,
        oper_status: row.OperStatus,
        media_connect_state: row.MediaConnectState,
    })
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
    // On success the OS leaves `sid_len` as the buffer size, so the SID's
    // own length is read from it.
    // SAFETY: the call succeeded, so `sid` holds a valid SID, alive and
    // aligned for the call.
    let len = usize::try_from(unsafe { GetLengthSid(sid.as_mut_ptr().cast()) }).unwrap_or(0);
    if len == 0 || len > size_of_val(&sid) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bad SID length"));
    }
    let bytes: Vec<u8> = sid.iter().flat_map(|w| w.to_ne_bytes()).take(len).collect();
    Ok((bytes, use_))
}

/// `ERROR_NONE_MAPPED`: no account has this SID (or name).
const NONE_MAPPED: i32 = 1332;

/// The account name of `sid` (a binary SID), as `(domain, name)`, with
/// `LookupAccountSidW`. `Ok(None)` only when no account has the SID
/// (`ERROR_NONE_MAPPED`); any other failure, such as an unreachable domain
/// controller, is an error.
pub(crate) fn lookup_account_sid(sid: &[u8]) -> io::Result<Option<(String, String)>> {
    // `u32` words keep the SID aligned as the OS's `SID` structure needs.
    let mut words = vec![0_u32; sid.len().div_ceil(4)];
    for (w, c) in words.iter_mut().zip(sid.chunks(4)) {
        let mut b = [0_u8; 4];
        if let Some(p) = b.get_mut(..c.len()) {
            p.copy_from_slice(c);
        }
        *w = u32::from_ne_bytes(b);
    }
    let psid = words.as_mut_ptr().cast();
    let mut name = vec![0_u16; 256];
    let mut domain = vec![0_u16; 256];
    loop {
        let (mut nl, mut dl) = (u32_len(name.len()), u32_len(domain.len()));
        let mut use_: SID_NAME_USE = 0;
        // SAFETY: `psid` points at `words`, a binary SID (the caller's
        // bytes, from `Sid::to_bytes`), 4-byte aligned and alive for the
        // call; a null system name is the local computer. `name` and
        // `domain` are live, writable buffers of `nl` and `dl` UTF-16
        // units, the lengths passed, and the lengths and `use_` are live
        // locals.
        let ok = unsafe {
            LookupAccountSidW(
                std::ptr::null(),
                psid,
                name.as_mut_ptr(),
                &raw mut nl,
                domain.as_mut_ptr(),
                &raw mut dl,
                &raw mut use_,
            )
        };
        if ok != 0 {
            let text = |b: &[u16], n: u32| {
                let n = usize::try_from(n).unwrap_or(0).min(b.len());
                String::from_utf16(b.get(..n).unwrap_or_default()).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "account name is not UTF-16")
                })
            };
            return Ok(Some((text(&domain, dl)?, text(&name, nl)?)));
        }
        let e = io::Error::last_os_error();
        match e.raw_os_error() {
            Some(NONE_MAPPED) => return Ok(None),
            Some(c) if c == i32::try_from(ERROR_INSUFFICIENT_BUFFER).unwrap_or(-1) => {
                let need = |n: u32, cur: usize| usize::try_from(n).unwrap_or(usize::MAX).max(cur);
                let (n, d) = (need(nl, name.len()), need(dl, domain.len()));
                if n > 4096 || d > 4096 || (n == name.len() && d == domain.len()) {
                    return Err(e);
                }
                name.resize(n, 0);
                domain.resize(d, 0);
            }
            _ => return Err(e),
        }
    }
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

/// Why [`local_group_members`] failed.
#[derive(Debug)]
pub(crate) enum MembersError {
    /// The group has more than [`MAX_GROUP_MEMBERS`] members. The
    /// enumeration was still run to its end.
    TooMany,
    /// The OS call failed, with the network management status as the OS
    /// error code (such as `NERR_GroupNotFound`).
    Os(io::Error),
}

/// The binary SIDs of the direct members of the local group `name` (its
/// name, without a domain), with `NetLocalGroupGetMembers`.
pub(crate) fn local_group_members(name: &str) -> Result<Vec<Vec<u8>>, MembersError> {
    if name.contains('\0') {
        return Err(MembersError::Os(io::Error::new(
            io::ErrorKind::InvalidInput,
            "group name contains a NUL character",
        )));
    }
    let wide: Vec<u16> = name.encode_utf16().chain([0]).collect();
    let mut members = Vec::new();
    let mut over_limit = false;
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
            return Err(MembersError::Os(io::Error::from_raw_os_error(
                i32::try_from(status).unwrap_or(i32::MAX),
            )));
        }
        let count = usize::try_from(read).unwrap_or(0);
        // Past the limit, stop copying but keep paging to the end: an
        // enumeration abandoned at `ERROR_MORE_DATA` can leak its RPC
        // connection. Each page is freed by `NetBuffer` as it drops.
        if !over_limit && !buf.0.is_null() && count > 0 {
            let entries: *const LOCALGROUP_MEMBERS_INFO_0 = buf.0.cast_const().cast();
            for i in 0..count {
                // SAFETY: the OS returned `read` contiguous, aligned
                // `LOCALGROUP_MEMBERS_INFO_0` entries at `buf.0`, alive
                // until `buf` is dropped; `i < read`.
                let psid = unsafe { entries.add(i).read() }.lgrmi0_sid;
                if psid.is_null() {
                    continue;
                }
                if members.len() == MAX_GROUP_MEMBERS {
                    // One more member would pass the limit: copy no more
                    // of this page, and keep paging only to free the rest.
                    over_limit = true;
                    members = Vec::new();
                    break;
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
        if status == NERR_Success {
            return if over_limit {
                Err(MembersError::TooMany)
            } else {
                Ok(members)
            };
        }
        if count == 0 {
            return Err(MembersError::Os(io::Error::other(
                "the OS reported more members but returned none",
            )));
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
    fn the_best_route_reads_an_interface_or_reports_no_route() {
        use crate::platform::connection::Route;
        // The documentation addresses (RFC 5737, RFC 3849) the backend
        // uses: routed, never contacted. The hosted runners have an IPv4
        // default route; IPv6 may have none.
        let v4 = best_route("192.0.2.1".parse().unwrap());
        let v6 = best_route("2001:db8::1".parse().unwrap());
        eprintln!("IPv4 route: {v4:?}\nIPv6 route: {v6:?}");
        match v4 {
            Route::Through(row) => assert_ne!(row.if_type, 0, "{row:?}"),
            other => panic!("no IPv4 route on the runner: {other:?}"),
        }
        assert_ne!(v6, Route::Failed);
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
        let (domain, bare) = lookup_account_sid(&admins.to_bytes()).unwrap().unwrap();
        assert_eq!(format!("{domain}\\{bare}"), name);
        // A well-formed SID no account has.
        let nobody = palisade_fileid::fsctx::Sid::new(5, &[21, 1, 2, 3, 999_999]).unwrap();
        assert_eq!(lookup_account_sid(&nobody.to_bytes()).unwrap(), None);
        let e = local_group_members("No Such Palisade Group").unwrap_err();
        assert!(
            matches!(e, MembersError::Os(ref e) if e.raw_os_error().is_some()),
            "{e:?}"
        );
        assert!(local_group_members("a\0b").is_err());
    }
}
