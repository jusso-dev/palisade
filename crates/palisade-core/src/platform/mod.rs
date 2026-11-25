//! The platform abstraction (#29): traits for everything the agent reads
//! from the operating system.
//!
//! Decision logic (evaluation-context building, rule expiry, schedules, OTP
//! windows) reads the system only through these traits, so it runs in unit
//! tests on any OS against in-memory mocks (`palisade_core::test_util`, with
//! the `test-util` feature). The Windows implementations live in the agent.
//!
//! The traits are deliberately small: each method is one OS query, returns
//! plain data, and does no caching. Caches (the directory group cache, the
//! process tree) belong to the agent, which builds the resolved context that
//! evaluation receives. New methods are added under ADR review, as consumers
//! need them.
//!
//! The hot evaluation path is generic over [`Platform`] (static dispatch,
//! for the evaluation budget in #42). Every trait except [`FileSystem`] is
//! also object safe, for code where dynamic dispatch is fine.
//!
//! Paths are Windows paths as text (`C:\Windows\System32\cmd.exe`), and SIDs
//! are in their canonical text form (`S-1-5-18`). Both are compared
//! case-insensitively by the Windows implementations, and by the mocks.

mod env;
mod process;

use alloc::{string::String, vec::Vec};
use core::{fmt, net::IpAddr};

pub use env::{ExpandError, MAX_EXPANDED_CHARS, expand_env_vars};
pub use process::{MAX_ANCESTRY, ancestry};

use crate::VerificationError;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// What kind of failure a platform query had.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ErrorKind {
    /// The object (file, key, process, user) does not exist.
    NotFound,
    /// The caller may not read it.
    AccessDenied,
    /// The query is not available on this OS or file system.
    Unsupported,
    /// An argument is malformed, such as a path that is not absolute.
    InvalidInput,
    /// The answer would exceed a size limit.
    TooLarge,
    /// Any other OS error.
    Other,
}

/// A platform query failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlatformError {
    kind: ErrorKind,
    message: String,
}

impl PlatformError {
    /// An error of `kind`, with a message for logs.
    #[must_use]
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    /// A [`ErrorKind::NotFound`] error.
    #[must_use]
    pub fn not_found(what: impl Into<String>) -> Self {
        Self::new(ErrorKind::NotFound, what)
    }

    /// The kind of failure.
    #[must_use]
    pub const fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// The message.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for PlatformError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.kind, self.message)
    }
}

impl core::error::Error for PlatformError {}

/// The result of a platform query.
pub type Result<T> = core::result::Result<T, PlatformError>;

// ---------------------------------------------------------------------------
// Clock
// ---------------------------------------------------------------------------

/// A wall-clock instant: microseconds since 1970-01-01T00:00:00Z.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UtcTime(pub i64);

impl UtcTime {
    /// Whole seconds since the epoch, rounded towards negative infinity.
    #[must_use]
    pub const fn unix_secs(self) -> i64 {
        self.0.div_euclid(1_000_000)
    }

    /// This instant plus `micros`, saturating at the `i64` range.
    #[must_use]
    pub const fn saturating_add_micros(self, micros: i64) -> Self {
        Self(self.0.saturating_add(micros))
    }
}

/// A monotonic instant: microseconds since an arbitrary origin (usually
/// boot). It never goes backwards while the process runs, and is unaffected
/// by changes to the wall clock.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MonotonicTime(pub u64);

impl MonotonicTime {
    /// Whole seconds since the origin.
    #[must_use]
    pub const fn secs(self) -> u64 {
        self.0 / 1_000_000
    }
}

/// The source of time. Rule expiry, schedules, time boxes and OTP windows
/// read time only through this trait; `clippy.toml` forbids
/// `SystemTime::now()` everywhere else.
pub trait Clock {
    /// The current wall-clock time, in UTC. A local administrator can change
    /// it; code that must resist that pairs it with [`Clock::monotonic`].
    fn now_utc(&self) -> UtcTime;
    /// The current monotonic time.
    fn monotonic(&self) -> MonotonicTime;
}

// ---------------------------------------------------------------------------
// File system
// ---------------------------------------------------------------------------

/// What [`OpenFile::metadata`] reports. Fields the file system does not
/// provide are `None`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FileMetadata {
    /// The size in bytes.
    pub size: u64,
    /// Whether it is a directory.
    pub is_dir: bool,
    /// When it was created.
    pub created: Option<UtcTime>,
    /// When its data was last written.
    pub modified: Option<UtcTime>,
    /// The file ID, unique on its volume (128 bits on ReFS, 64 on NTFS).
    pub file_id: Option<u128>,
    /// The serial number of the volume it is on.
    pub volume_serial: Option<u64>,
    /// The update sequence number of its last change-journal record.
    pub usn: Option<i64>,
}

/// An alternate data stream of a file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamInfo {
    /// The stream name, without the leading `:` and the `:$DATA` type, such
    /// as `Zone.Identifier`.
    pub name: String,
    /// Its size in bytes.
    pub size: u64,
}

/// A file opened for reading.
pub trait OpenFile {
    /// The metadata of the open file, so it describes the same file the
    /// reads come from, even if the path is replaced meanwhile.
    fn metadata(&self) -> Result<FileMetadata>;
    /// Reads up to `buf.len()` bytes at `offset`. Returns the number read,
    /// 0 at the end of the file.
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize>;
}

/// File reads.
///
/// Not object safe (the open file is an associated type); code that holds a
/// file system is generic over it.
pub trait FileSystem {
    /// An open file.
    type File: OpenFile;

    /// Opens `path` for reading, sharing read, write and delete with other
    /// processes. `path:stream` opens an alternate data stream.
    fn open(&self, path: &str) -> Result<Self::File>;

    /// The owner SID of `path`, or `None` on file systems without owners
    /// (FAT, exFAT, network shares that do not report one).
    fn owner_sid(&self, path: &str) -> Result<Option<String>>;

    /// The self-relative security descriptor of `path` (owner and DACL), for
    /// the writable-path checks, or `None` where the file system has none.
    /// `palisade_fileid::fsctx::acl` parses and evaluates it.
    fn security_descriptor(&self, path: &str) -> Result<Option<Vec<u8>>>;

    /// The alternate data streams of `path`, without the unnamed main
    /// stream. Empty on file systems without streams.
    fn streams(&self, path: &str) -> Result<Vec<StreamInfo>>;
}

// ---------------------------------------------------------------------------
// Signatures
// ---------------------------------------------------------------------------

/// Where a signature was found.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SignatureSource {
    /// Embedded in the file (Authenticode).
    Embedded,
    /// In a security catalog that lists the file's hash.
    Catalog,
}

/// One certificate of a chain, as decisions and events need it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertificateSummary {
    /// The subject common name.
    pub subject: String,
    /// The issuer common name.
    pub issuer: String,
    /// The SHA-256 of the certificate's DER encoding.
    pub sha256: [u8; 32],
}

/// The result of validating one signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignatureResult {
    /// Where it was found.
    pub source: SignatureSource,
    /// [`VerificationError::Ok`] when the signature and its chain are valid.
    pub status: VerificationError,
    /// The chain, leaf first. May be partial when validation failed.
    pub chain: Vec<CertificateSummary>,
    /// The trusted signing time (from a timestamp), if any.
    pub signing_time: Option<UtcTime>,
}

/// Signature lookup and chain validation.
pub trait SignatureVerifier {
    /// The embedded signatures of `path`, primary first. Empty if unsigned.
    fn embedded(&self, path: &str) -> Result<Vec<SignatureResult>>;
    /// The catalog signature covering `path`, if a catalog lists its hash.
    fn catalog(&self, path: &str) -> Result<Option<SignatureResult>>;
}

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

/// How a logon session was started.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SessionKind {
    /// The physical console.
    Console,
    /// A remote desktop session.
    RemoteDesktop,
    /// Session 0, where services run.
    Services,
    /// The OS could not say.
    Unknown,
}

/// The mandatory integrity level of a token.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IntegrityLevel {
    /// Untrusted.
    Untrusted,
    /// Low (sandboxed).
    Low,
    /// Medium (a standard user).
    Medium,
    /// Medium-plus.
    MediumPlus,
    /// High (elevated).
    High,
    /// System.
    System,
    /// Protected process.
    Protected,
}

/// The UAC elevation type of a token.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Elevation {
    /// UAC is off, or the user is not an administrator.
    Default,
    /// The elevated half of a split token.
    Full,
    /// The filtered half of a split token.
    Limited,
}

/// One group in a token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupMembership {
    /// The group SID.
    pub sid: String,
    /// The group is present only to deny access (filtered admin token).
    pub deny_only: bool,
}

/// What a process token says about its user.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenInfo {
    /// The user SID.
    pub user_sid: String,
    /// Every group in the token, including nested directory groups.
    pub groups: Vec<GroupMembership>,
    /// The logon session ID.
    pub session_id: u32,
    /// How the session was started.
    pub session_kind: SessionKind,
    /// The integrity level.
    pub integrity: IntegrityLevel,
    /// The elevation type.
    pub elevation: Elevation,
    /// Whether the token is elevated.
    pub elevated: bool,
}

/// Directory groups of a user that a token does not carry (cloud-directory
/// groups), with when they were last fetched (#38).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectoryGroups {
    /// The groups, as SIDs or directory object IDs.
    pub groups: Vec<String>,
    /// When they were fetched; callers judge staleness.
    pub fetched_at: UtcTime,
}

/// The name of an account, as `DOMAIN\\name`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountName {
    /// The domain, or the computer name for a local account. `None` for
    /// well-known accounts that have none.
    pub domain: Option<String>,
    /// The account name.
    pub name: String,
}

/// Users, groups and sessions.
pub trait IdentityProvider {
    /// The token of the process `process`.
    fn token(&self, process: ProcessKey) -> Result<TokenInfo>;
    /// The token of the calling process (the agent itself).
    fn current(&self) -> Result<TokenInfo>;
    /// The name of the account `sid`, or `None` if it cannot be resolved.
    /// Names are for display only; policy targets SIDs (#204).
    fn account_name(&self, sid: &str) -> Result<Option<AccountName>>;
    /// The direct members of the local group `group_sid`, as SIDs.
    fn local_group_members(&self, group_sid: &str) -> Result<Vec<String>>;
    /// The directory groups of `user_sid` that tokens do not carry, from
    /// the agent's cache. `None` if nothing is cached.
    fn directory_groups(&self, user_sid: &str) -> Result<Option<DirectoryGroups>>;
}

// ---------------------------------------------------------------------------
// Processes
// ---------------------------------------------------------------------------

/// A process, identified so that a reused process ID cannot be mistaken for
/// it: the ID and the creation time together (#59).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProcessKey {
    /// The process ID.
    pub pid: u32,
    /// When the process was created.
    pub created: UtcTime,
}

/// What the OS reports about a process.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessRecord {
    /// The process.
    pub key: ProcessKey,
    /// The process ID the OS records as the parent. The parent may have
    /// exited, and its ID may have been reused: [`ancestry`] checks.
    pub parent_pid: Option<u32>,
    /// The full image path.
    pub image_path: String,
    /// The command line, where it may be read.
    pub command_line: Option<String>,
}

/// Process queries.
pub trait ProcessInfo {
    /// The running process with ID `pid`.
    fn by_pid(&self, pid: u32) -> Result<ProcessRecord>;
    /// The process `key`. Fails with [`ErrorKind::NotFound`] if it has
    /// exited, or if its ID now belongs to a different process.
    fn get(&self, key: ProcessKey) -> Result<ProcessRecord>;
}

// ---------------------------------------------------------------------------
// Environment
// ---------------------------------------------------------------------------

/// The processor architecture.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Architecture {
    /// 64-bit x86.
    X64,
    /// 64-bit ARM.
    Arm64,
    /// 32-bit x86.
    X86,
    /// Anything else.
    Other,
}

/// The operating system version, as `major.minor.build.revision`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OsVersion {
    /// Major version.
    pub major: u32,
    /// Minor version.
    pub minor: u32,
    /// Build number.
    pub build: u32,
    /// Update build revision.
    pub revision: u32,
}

impl fmt::Display for OsVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}.{}.{}.{}",
            self.major, self.minor, self.build, self.revision
        )
    }
}

/// How the device is connected to the network.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ConnectionType {
    /// Wired Ethernet.
    Wired,
    /// Wireless LAN.
    Wireless,
    /// Mobile broadband.
    Cellular,
    /// Only through a VPN tunnel.
    Vpn,
    /// Not connected.
    Offline,
    /// The OS could not say.
    Unknown,
}

/// An address assigned to a network interface.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct InterfaceAddress {
    /// The address.
    pub addr: IpAddr,
    /// The prefix length of its network.
    pub prefix_len: u8,
}

/// The device and the agent's process environment.
pub trait Environment {
    /// The host name.
    fn hostname(&self) -> Result<String>;
    /// The DNS domain the device is joined to, if any.
    fn domain(&self) -> Result<Option<String>>;
    /// The OS version.
    fn os_version(&self) -> Result<OsVersion>;
    /// The processor architecture.
    fn architecture(&self) -> Architecture;
    /// The addresses of every interface that is up, without loopback.
    fn addresses(&self) -> Result<Vec<InterfaceAddress>>;
    /// The primary connection type.
    fn connection_type(&self) -> Result<ConnectionType>;
    /// The environment variable `name` (case-insensitive, as on Windows).
    fn var(&self, name: &str) -> Option<String>;
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

/// A registry root key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Hive {
    /// `HKEY_LOCAL_MACHINE`.
    LocalMachine,
    /// `HKEY_USERS`. A user's hive is the key named by the user's SID.
    Users,
}

/// A registry value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RegistryValue {
    /// `REG_SZ`.
    String(String),
    /// `REG_EXPAND_SZ`, unexpanded.
    ExpandString(String),
    /// `REG_MULTI_SZ`.
    MultiString(Vec<String>),
    /// `REG_DWORD`.
    Dword(u32),
    /// `REG_QWORD`.
    Qword(u64),
    /// `REG_BINARY`, and any other type, as raw bytes.
    Binary(Vec<u8>),
}

/// Registry reads, for registry conditions (#33).
pub trait Registry {
    /// Whether the key `path` (such as `SOFTWARE\Palisade`) exists.
    fn key_exists(&self, hive: Hive, path: &str) -> Result<bool>;
    /// The value `name` of the key `path`. `None` if the key or the value
    /// does not exist. The empty name is the key's default value.
    fn value(&self, hive: Hive, path: &str, name: &str) -> Result<Option<RegistryValue>>;
    /// The names of the subkeys of `path`.
    fn subkeys(&self, hive: Hive, path: &str) -> Result<Vec<String>>;
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

/// Where the agent emits its events. Generic over the event type, which
/// `palisade-proto` defines.
pub trait EventSink<E> {
    /// Emits one event. Fails if the event cannot be accepted (a full
    /// buffer, a closed output).
    fn emit(&mut self, event: E) -> Result<()>;
}

// ---------------------------------------------------------------------------
// The bundle
// ---------------------------------------------------------------------------

/// Every platform service, as one type parameter for code that needs
/// several. `palisade_core::test_util::MockPlatform` implements it with
/// mocks; the agent implements it with the OS.
pub trait Platform {
    /// The clock.
    type Clock: Clock;
    /// The file system.
    type FileSystem: FileSystem;
    /// The signature verifier.
    type Signatures: SignatureVerifier;
    /// Users, groups and sessions.
    type Identity: IdentityProvider;
    /// Processes.
    type Processes: ProcessInfo;
    /// The environment.
    type Environment: Environment;
    /// The registry.
    type Registry: Registry;

    /// The clock.
    fn clock(&self) -> &Self::Clock;
    /// The file system.
    fn file_system(&self) -> &Self::FileSystem;
    /// The signature verifier.
    fn signatures(&self) -> &Self::Signatures;
    /// Users, groups and sessions.
    fn identity(&self) -> &Self::Identity;
    /// Processes.
    fn processes(&self) -> &Self::Processes;
    /// The environment.
    fn environment(&self) -> &Self::Environment;
    /// The registry.
    fn registry(&self) -> &Self::Registry;
}
