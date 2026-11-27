//! Standard-library implementations: the clock, file reads and the
//! environment.

use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{Read, Seek, SeekFrom},
    net::IpAddr,
    path::Path,
    sync::OnceLock,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use palisade_core::platform::{
    Architecture, Clock, ConnectionType, Environment, ErrorKind, FileMetadata, FileSystem,
    InterfaceAddress, MonotonicTime, OpenFile, OsVersion, PlatformError, Result, StreamInfo,
    UtcTime,
};

use super::io_error;

// ---------------------------------------------------------------------------
// Clock
// ---------------------------------------------------------------------------

/// The operating system's clocks.
///
/// The monotonic origin is the first reading in this process, so monotonic
/// time is "time since the agent first read the clock".
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

fn origin() -> Instant {
    static ORIGIN: OnceLock<Instant> = OnceLock::new();
    *ORIGIN.get_or_init(Instant::now)
}

/// `time` as microseconds since the Unix epoch, saturating.
fn utc_micros(time: SystemTime) -> i64 {
    match time.duration_since(UNIX_EPOCH) {
        Ok(after) => i64::try_from(after.as_micros()).unwrap_or(i64::MAX),
        Err(before) => {
            i64::try_from(before.duration().as_micros()).map_or(i64::MIN, i64::saturating_neg)
        }
    }
}

impl Clock for SystemClock {
    fn now_utc(&self) -> UtcTime {
        #[expect(
            clippy::disallowed_methods,
            reason = "the Clock implementation is the one place that reads the wall clock"
        )]
        let now = SystemTime::now();
        UtcTime(utc_micros(now))
    }

    fn monotonic(&self) -> MonotonicTime {
        let elapsed = origin().elapsed().as_micros();
        MonotonicTime(u64::try_from(elapsed).unwrap_or(u64::MAX))
    }
}

// ---------------------------------------------------------------------------
// File system
// ---------------------------------------------------------------------------

/// File reads through `std::fs`.
///
/// `open`, `read_at` and `metadata` (size, directory flag and times) work on
/// every OS. Owner SIDs, security descriptors, alternate data streams, file
/// IDs, volume serials and USNs need Windows APIs: here `owner_sid` and
/// `security_descriptor` return [`ErrorKind::Unsupported`], `streams` does
/// too on Windows, and the metadata leaves those fields `None`. On Windows,
/// `windows::WindowsFileSystem` adds them through `palisade_fileid::win`.
///
/// This is not yet the hardened reader the privileged agent needs: like
/// any `std::fs` open, it follows reparse points (symbolic links and
/// junctions) and accepts UNC and device paths (threat T-agent-13). The
/// file inventory replaces it with handle-based reads through
/// `palisade_fileid::win` (#54, #60). Until then it serves development,
/// tests and the simulator only.
#[derive(Clone, Copy, Debug, Default)]
pub struct StdFileSystem;

/// A file opened by [`StdFileSystem`].
#[derive(Debug)]
pub struct StdFile {
    file: File,
    is_dir: bool,
}

fn unsupported(what: &str) -> PlatformError {
    PlatformError::new(
        ErrorKind::Unsupported,
        format!("{what} needs the Windows file-system backend (#54, #60)"),
    )
}

/// Whether `path` names a named data stream (`file:name` or
/// `file:name:$DATA`, on Windows): those are data even on a directory.
/// `file::$DATA` and other stream types, such as a directory's
/// `::$INDEX_ALLOCATION`, do not count, nor does a drive letter's colon.
pub(crate) fn names_a_stream(path: &str) -> bool {
    if !cfg!(windows) {
        return false;
    }
    let name_start = path.rfind(['\\', '/']).map_or(0, |i| i + 1);
    let name = path.get(name_start..).unwrap_or_default();
    let Some(i) = name.find(':').filter(|&i| !(name_start == 0 && i == 1)) else {
        return false;
    };
    let rest = name.get(i + 1..).unwrap_or_default();
    match rest.split_once(':') {
        None => !rest.is_empty(),
        Some((stream, kind)) => !stream.is_empty() && kind.eq_ignore_ascii_case("$DATA"),
    }
}

/// The path must be absolute, so a relative path cannot be resolved against
/// the agent's working directory.
pub(crate) fn absolute(path: &str) -> Result<&Path> {
    let p = Path::new(path);
    if p.is_absolute() {
        Ok(p)
    } else {
        Err(PlatformError::new(
            ErrorKind::InvalidInput,
            format!("not an absolute path: {path}"),
        ))
    }
}

impl FileSystem for StdFileSystem {
    type File = StdFile;

    fn open(&self, path: &str) -> Result<StdFile> {
        let p = absolute(path)?;
        let file = open_shared(p).map_err(|e| io_error(&e, path))?;
        // On Windows a handle to a directory's named stream still reports
        // the directory attribute, but the stream is data: decide from the
        // path, as `palisade_core::test_util::MockFileSystem` does.
        let is_dir =
            !names_a_stream(path) && file.metadata().map_err(|e| io_error(&e, path))?.is_dir();
        Ok(StdFile { file, is_dir })
    }

    fn owner_sid(&self, path: &str) -> Result<Option<String>> {
        absolute(path)?;
        Err(unsupported("the owner SID"))
    }

    fn security_descriptor(&self, path: &str) -> Result<Option<Vec<u8>>> {
        absolute(path)?;
        Err(unsupported("the security descriptor"))
    }

    fn streams(&self, path: &str) -> Result<Vec<StreamInfo>> {
        let p = absolute(path)?;
        fs::symlink_metadata(p).map_err(|e| io_error(&e, path))?;
        if cfg!(windows) {
            Err(unsupported("listing alternate data streams"))
        } else {
            // Other file systems have no alternate data streams.
            Ok(Vec::new())
        }
    }
}

/// Opens for reading, letting other processes read, write and delete the
/// file meanwhile, so the agent never blocks a program or an installer.
#[cfg(windows)]
pub(crate) fn open_shared(path: &Path) -> std::io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_SHARE_READ: u32 = 0x1;
    const FILE_SHARE_WRITE: u32 = 0x2;
    const FILE_SHARE_DELETE: u32 = 0x4;
    // Lets a directory be opened, so `metadata` works on directories as it
    // does on other OSes.
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    // If the path names a named pipe (`\\.\pipe\...`, or a link to one),
    // the pipe's server must not be able to impersonate the agent, which
    // runs as LocalSystem: connect at the anonymous impersonation level.
    const SECURITY_SQOS_PRESENT: u32 = 0x0010_0000;
    const SECURITY_ANONYMOUS: u32 = 0;
    fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .security_qos_flags(SECURITY_SQOS_PRESENT | SECURITY_ANONYMOUS)
        .open(path)
}

/// Opens for reading. The agent ships for Windows; on other OSes this
/// backend serves development and tests.
#[cfg(not(windows))]
pub(crate) fn open_shared(path: &Path) -> std::io::Result<File> {
    File::open(path)
}

impl StdFile {
    /// The open file.
    #[cfg_attr(not(windows), allow(dead_code))]
    pub(crate) const fn file(&self) -> &File {
        &self.file
    }
}

impl OpenFile for StdFile {
    fn metadata(&self) -> Result<FileMetadata> {
        let m = self.file.metadata().map_err(|e| io_error(&e, "metadata"))?;
        Ok(FileMetadata {
            size: if self.is_dir { 0 } else { m.len() },
            is_dir: self.is_dir,
            created: m.created().ok().map(|t| UtcTime(utc_micros(t))),
            modified: m.modified().ok().map(|t| UtcTime(utc_micros(t))),
            file_id: None,
            volume_serial: None,
            usn: None,
        })
    }

    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        if self.is_dir {
            return Err(PlatformError::new(
                ErrorKind::InvalidInput,
                "cannot read a directory",
            ));
        }
        // The OS cannot seek past `i64::MAX`, and no file is that long:
        // such an offset is past the end, as it is for the mocks.
        if i64::try_from(offset).is_err() {
            return Ok(0);
        }
        self.file
            .seek(SeekFrom::Start(offset))
            .map_err(|e| io_error(&e, "seek"))?;
        loop {
            match self.file.read(buf) {
                Ok(n) => return Ok(n),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(io_error(&e, "read")),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Environment
// ---------------------------------------------------------------------------

/// The device and the agent's own process environment.
///
/// The variables, host name, domain and OS version are captured once, when
/// this is built, so every lookup in one evaluation sees the same values,
/// and a lookup is a map read. The interface addresses and the connection
/// type are read live, on each call. Variable names are case-insensitive,
/// as on Windows.
///
/// On Windows the host name and domain come from the registry and the
/// version from the OS (`platform::windows`), and the connection type from
/// the IPv4 and IPv6 default routes (`platform::connection`). Elsewhere
/// (development only) the host name comes from the environment or
/// `/etc/hostname`, the domain and version are [`ErrorKind::Unsupported`],
/// and the connection type is [`ConnectionType::Unknown`]. Whether a
/// network is trusted is defined by the network-location scope (#38).
#[derive(Clone, Debug)]
pub struct StdEnvironment {
    vars: BTreeMap<String, String>,
    hostname: Option<String>,
    /// `None`: the domain cannot be read on this OS.
    domain: Option<Option<String>>,
    os_version: Option<OsVersion>,
}

impl Default for StdEnvironment {
    fn default() -> Self {
        Self::capture()
    }
}

fn fold(s: &str) -> String {
    s.chars().flat_map(char::to_uppercase).collect()
}

impl StdEnvironment {
    /// Captures the device facts and the current process environment.
    /// Variables whose name or value is not valid Unicode are skipped.
    #[must_use]
    pub fn capture() -> Self {
        let mut env = Self::from_vars(
            std::env::vars_os()
                .filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?))),
        );
        #[cfg(windows)]
        {
            env.hostname = super::windows::hostname().or(env.hostname);
            env.domain = Some(super::windows::domain());
            env.os_version = Some(super::windows::os_version());
        }
        #[cfg(not(windows))]
        if env.hostname.is_none() {
            env.hostname = fs::read_to_string("/etc/hostname")
                .ok()
                .map(|s| s.trim().to_owned())
                .filter(|s| !s.is_empty());
        }
        env
    }

    /// An environment with exactly these variables, and the host name from
    /// `COMPUTERNAME` or `HOSTNAME` among them. On a duplicate name in
    /// another letter case, the first wins.
    pub fn from_vars(vars: impl IntoIterator<Item = (String, String)>) -> Self {
        let mut map = BTreeMap::new();
        for (k, v) in vars {
            map.entry(fold(&k)).or_insert(v);
        }
        let hostname = ["COMPUTERNAME", "HOSTNAME"]
            .iter()
            .find_map(|n| map.get(*n).filter(|v| !v.is_empty()).cloned());
        Self {
            vars: map,
            hostname,
            domain: None,
            os_version: None,
        }
    }
}

impl Environment for StdEnvironment {
    fn hostname(&self) -> Result<String> {
        self.hostname
            .clone()
            .ok_or_else(|| PlatformError::new(ErrorKind::Unsupported, "the host name is not known"))
    }

    fn domain(&self) -> Result<Option<String>> {
        self.domain.clone().ok_or_else(|| {
            PlatformError::new(ErrorKind::Unsupported, "the domain is only read on Windows")
        })
    }

    fn os_version(&self) -> Result<OsVersion> {
        self.os_version.ok_or_else(|| {
            PlatformError::new(
                ErrorKind::Unsupported,
                "the OS version is only read on Windows",
            )
        })
    }

    fn architecture(&self) -> Architecture {
        match std::env::consts::ARCH {
            "x86_64" => Architecture::X64,
            "aarch64" => Architecture::Arm64,
            "x86" => Architecture::X86,
            _ => Architecture::Other,
        }
    }

    fn addresses(&self) -> Result<Vec<InterfaceAddress>> {
        let interfaces = if_addrs::get_if_addrs().map_err(|e| io_error(&e, "interfaces"))?;
        Ok(interfaces
            .into_iter()
            // Up, or a virtual or tunnel interface that reports no state.
            .filter(|i| {
                !i.is_loopback()
                    && matches!(
                        i.oper_status,
                        if_addrs::IfOperStatus::Up | if_addrs::IfOperStatus::Unknown
                    )
            })
            .map(|i| {
                let (addr, prefix_len) = match i.addr {
                    if_addrs::IfAddr::V4(a) => (IpAddr::V4(a.ip), a.prefixlen),
                    if_addrs::IfAddr::V6(a) => (IpAddr::V6(a.ip), a.prefixlen),
                };
                InterfaceAddress { addr, prefix_len }
            })
            .collect())
    }

    /// The interfaces the OS routes internet-bound IPv4 and IPv6 traffic
    /// through, as classified by `platform::connection` (Windows), read on
    /// each call. `Unknown` elsewhere, and on Windows whenever the answer is
    /// not clear (ADR 0018).
    fn connection_type(&self) -> Result<ConnectionType> {
        #[cfg(windows)]
        {
            // Documentation addresses (RFC 5737, RFC 3849): never
            // contacted, only routed, so each answer is that family's
            // default route.
            let v4 = crate::ffi::best_route(std::net::IpAddr::from([192, 0, 2, 1]));
            let v6 =
                crate::ffi::best_route(std::net::IpAddr::from([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1]));
            Ok(super::connection::classify(v4, v6))
        }
        #[cfg(not(windows))]
        Ok(ConnectionType::Unknown)
    }

    fn var(&self, name: &str) -> Option<String> {
        self.vars.get(&fold(name)).cloned()
    }
}
