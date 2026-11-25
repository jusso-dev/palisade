//! In-memory mocks of the [`platform`](crate::platform) traits, and
//! contract checks shared with the real implementations (#29).
//!
//! Only for tests and the agent's simulator: the `test-util` feature is never
//! on in a release build (`cargo xtask check-manifests` enforces that no
//! normal dependency turns it on).
//!
//! Each mock is plain data with `&self` queries, so a test sets it up, hands
//! it to the code under test, and asserts. [`MockPlatform`] bundles one of
//! each. Paths, SIDs, registry paths and variable names are compared
//! case-insensitively, as on Windows (with simple Unicode upper-casing, not
//! the file system's exact case table).
//!
//! [`contract`] holds the checks every implementation must pass, mock or
//! real, so the two cannot drift.

pub mod contract;

use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    vec::Vec,
};
use core::cell::{Cell, RefCell};

use crate::platform::{
    AccountName, Architecture, Clock, ConnectionType, DirectoryGroups, Environment, ErrorKind,
    EventSink, FileMetadata, FileSystem, Hive, IdentityProvider, InterfaceAddress, MonotonicTime,
    OpenFile, OsVersion, Platform, PlatformError, ProcessInfo, ProcessKey, ProcessRecord, Registry,
    RegistryValue, Result, SignatureResult, SignatureVerifier, StreamInfo, TokenInfo, UtcTime,
};

/// The case-insensitive comparison key of a name.
fn fold(s: &str) -> String {
    s.chars().flat_map(char::to_uppercase).collect()
}

// ---------------------------------------------------------------------------
// Clock
// ---------------------------------------------------------------------------

/// A clock that only moves when told to.
#[derive(Debug, Default)]
pub struct MockClock {
    utc: Cell<i64>,
    monotonic: Cell<u64>,
}

impl MockClock {
    /// A clock reading `utc` and `monotonic`.
    #[must_use]
    pub const fn new(utc: UtcTime, monotonic: MonotonicTime) -> Self {
        Self {
            utc: Cell::new(utc.0),
            monotonic: Cell::new(monotonic.0),
        }
    }

    /// Sets the wall clock, as an administrator could: it may go backwards.
    /// The monotonic clock is unaffected.
    pub fn set_utc(&self, utc: UtcTime) {
        self.utc.set(utc.0);
    }

    /// Lets `micros` pass: both clocks move forwards.
    pub fn advance(&self, micros: u64) {
        self.monotonic
            .set(self.monotonic.get().saturating_add(micros));
        let signed = i64::try_from(micros).unwrap_or(i64::MAX);
        self.utc.set(self.utc.get().saturating_add(signed));
    }
}

impl Clock for MockClock {
    fn now_utc(&self) -> UtcTime {
        UtcTime(self.utc.get())
    }

    fn monotonic(&self) -> MonotonicTime {
        MonotonicTime(self.monotonic.get())
    }
}

// ---------------------------------------------------------------------------
// File system
// ---------------------------------------------------------------------------

/// A file (or directory) in a [`MockFileSystem`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MockFile {
    /// The contents of the main stream.
    pub data: Vec<u8>,
    /// The metadata. `size` is set from `data` when the file is added.
    pub metadata: FileMetadata,
    /// The owner SID.
    pub owner: Option<String>,
    /// The self-relative security descriptor.
    pub descriptor: Option<Vec<u8>>,
    /// Alternate data streams, by name.
    pub streams: BTreeMap<String, Vec<u8>>,
}

impl MockFile {
    /// A file with these contents.
    #[must_use]
    pub fn new(data: impl Into<Vec<u8>>) -> Self {
        Self {
            data: data.into(),
            ..Self::default()
        }
    }

    /// A directory.
    #[must_use]
    pub fn directory() -> Self {
        Self {
            metadata: FileMetadata {
                is_dir: true,
                ..FileMetadata::default()
            },
            ..Self::default()
        }
    }

    /// Sets the owner SID.
    #[must_use]
    pub fn owner(mut self, sid: &str) -> Self {
        self.owner = Some(sid.to_string());
        self
    }

    /// Sets the security descriptor.
    #[must_use]
    pub fn descriptor(mut self, bytes: impl Into<Vec<u8>>) -> Self {
        self.descriptor = Some(bytes.into());
        self
    }

    /// Adds an alternate data stream.
    #[must_use]
    pub fn stream(mut self, name: &str, data: impl Into<Vec<u8>>) -> Self {
        self.streams.insert(name.to_string(), data.into());
        self
    }

    /// Sets the metadata other than the size and the directory flag.
    #[must_use]
    pub fn metadata(mut self, metadata: FileMetadata) -> Self {
        let is_dir = self.metadata.is_dir;
        self.metadata = FileMetadata { is_dir, ..metadata };
        self
    }
}

/// An in-memory file system.
#[derive(Debug, Default)]
pub struct MockFileSystem {
    files: BTreeMap<String, MockFile>,
}

/// An open [`MockFile`] stream: a snapshot of its contents.
#[derive(Clone, Debug)]
pub struct MockOpenFile {
    data: Vec<u8>,
    metadata: FileMetadata,
}

impl MockFileSystem {
    /// An empty file system.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds or replaces the file at `path`.
    pub fn insert(&mut self, path: &str, mut file: MockFile) {
        file.metadata.size = u64::try_from(file.data.len()).unwrap_or(u64::MAX);
        self.files.insert(fold(path), file);
    }

    /// Removes the file at `path`.
    pub fn remove(&mut self, path: &str) -> Option<MockFile> {
        self.files.remove(&fold(path))
    }

    fn file(&self, path: &str) -> Result<&MockFile> {
        self.files
            .get(&fold(path))
            .ok_or_else(|| PlatformError::not_found(path))
    }
}

/// Splits `C:\dir\file:stream` into the file and the stream name. The colon
/// of a drive letter is not a stream separator.
fn split_stream(path: &str) -> (&str, Option<&str>) {
    let name_start = path.rfind(['\\', '/']).map_or(0, |i| i + 1);
    let name = path.get(name_start..).unwrap_or_default();
    match name.find(':') {
        Some(i) if !(name_start == 0 && i == 1) => {
            let at = name_start + i;
            let stream = path.get(at + 1..).unwrap_or_default();
            let stream = stream
                .strip_suffix(":$DATA")
                .or_else(|| stream.strip_suffix(":$data"))
                .unwrap_or(stream);
            (path.get(..at).unwrap_or_default(), Some(stream))
        }
        _ => (path, None),
    }
}

impl FileSystem for MockFileSystem {
    type File = MockOpenFile;

    fn open(&self, path: &str) -> Result<MockOpenFile> {
        let (base, stream) = split_stream(path);
        let file = self.file(base)?;
        let data = match stream {
            None | Some("") => {
                if file.metadata.is_dir {
                    return Err(PlatformError::new(
                        ErrorKind::InvalidInput,
                        "cannot read a directory",
                    ));
                }
                file.data.clone()
            }
            Some(name) => file
                .streams
                .iter()
                .find(|(n, _)| fold(n) == fold(name))
                .map(|(_, d)| d.clone())
                .ok_or_else(|| PlatformError::not_found(path))?,
        };
        let metadata = FileMetadata {
            size: u64::try_from(data.len()).unwrap_or(u64::MAX),
            ..file.metadata.clone()
        };
        Ok(MockOpenFile { data, metadata })
    }

    fn owner_sid(&self, path: &str) -> Result<Option<String>> {
        Ok(self.file(path)?.owner.clone())
    }

    fn security_descriptor(&self, path: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.file(path)?.descriptor.clone())
    }

    fn streams(&self, path: &str) -> Result<Vec<StreamInfo>> {
        Ok(self
            .file(path)?
            .streams
            .iter()
            .map(|(name, data)| StreamInfo {
                name: name.clone(),
                size: u64::try_from(data.len()).unwrap_or(u64::MAX),
            })
            .collect())
    }
}

impl OpenFile for MockOpenFile {
    fn metadata(&self) -> Result<FileMetadata> {
        Ok(self.metadata.clone())
    }

    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let start = usize::try_from(offset).unwrap_or(usize::MAX);
        let rest = self.data.get(start..).unwrap_or_default();
        let n = rest.len().min(buf.len());
        if let (Some(dst), Some(src)) = (buf.get_mut(..n), rest.get(..n)) {
            dst.copy_from_slice(src);
        }
        Ok(n)
    }
}

// ---------------------------------------------------------------------------
// Signatures
// ---------------------------------------------------------------------------

/// Scripted signature results, by path. Unknown paths are unsigned.
#[derive(Debug, Default)]
pub struct MockSignatures {
    embedded: BTreeMap<String, Vec<SignatureResult>>,
    catalog: BTreeMap<String, SignatureResult>,
}

impl MockSignatures {
    /// No signed files.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Scripts the embedded signatures of `path`.
    pub fn set_embedded(&mut self, path: &str, results: Vec<SignatureResult>) {
        self.embedded.insert(fold(path), results);
    }

    /// Scripts the catalog signature of `path`.
    pub fn set_catalog(&mut self, path: &str, result: SignatureResult) {
        self.catalog.insert(fold(path), result);
    }
}

impl SignatureVerifier for MockSignatures {
    fn embedded(&self, path: &str) -> Result<Vec<SignatureResult>> {
        Ok(self.embedded.get(&fold(path)).cloned().unwrap_or_default())
    }

    fn catalog(&self, path: &str) -> Result<Option<SignatureResult>> {
        Ok(self.catalog.get(&fold(path)).cloned())
    }
}

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

/// Scripted tokens, local groups and the directory group cache.
#[derive(Debug, Default)]
pub struct MockIdentity {
    current: Option<TokenInfo>,
    tokens: BTreeMap<ProcessKey, TokenInfo>,
    names: BTreeMap<String, AccountName>,
    local_groups: BTreeMap<String, Vec<String>>,
    directory: BTreeMap<String, DirectoryGroups>,
}

impl MockIdentity {
    /// Nothing known.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the token [`IdentityProvider::current`] returns.
    pub fn set_current(&mut self, token: TokenInfo) {
        self.current = Some(token);
    }

    /// Sets the token of `process`.
    pub fn set_token(&mut self, process: ProcessKey, token: TokenInfo) {
        self.tokens.insert(process, token);
    }

    /// Sets the name of an account.
    pub fn set_account_name(&mut self, sid: &str, name: AccountName) {
        self.names.insert(fold(sid), name);
    }

    /// Sets the members of a local group.
    pub fn set_local_group(&mut self, group_sid: &str, members: Vec<String>) {
        self.local_groups.insert(fold(group_sid), members);
    }

    /// Sets the cached directory groups of a user.
    pub fn set_directory_groups(&mut self, user_sid: &str, groups: DirectoryGroups) {
        self.directory.insert(fold(user_sid), groups);
    }
}

impl IdentityProvider for MockIdentity {
    fn token(&self, process: ProcessKey) -> Result<TokenInfo> {
        self.tokens
            .get(&process)
            .cloned()
            .ok_or_else(|| PlatformError::not_found("no token for that process"))
    }

    fn current(&self) -> Result<TokenInfo> {
        self.current
            .clone()
            .ok_or_else(|| PlatformError::not_found("no current token"))
    }

    fn account_name(&self, sid: &str) -> Result<Option<AccountName>> {
        Ok(self.names.get(&fold(sid)).cloned())
    }

    fn local_group_members(&self, group_sid: &str) -> Result<Vec<String>> {
        self.local_groups
            .get(&fold(group_sid))
            .cloned()
            .ok_or_else(|| PlatformError::not_found(group_sid))
    }

    fn directory_groups(&self, user_sid: &str) -> Result<Option<DirectoryGroups>> {
        Ok(self.directory.get(&fold(user_sid)).cloned())
    }
}

// ---------------------------------------------------------------------------
// Processes
// ---------------------------------------------------------------------------

/// A process table. Starting a process with the ID of a running one
/// replaces it, which is how tests model process ID reuse.
#[derive(Debug, Default)]
pub struct MockProcesses {
    running: RefCell<BTreeMap<u32, ProcessRecord>>,
}

impl MockProcesses {
    /// No processes.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Starts `record`, replacing any running process with its ID.
    pub fn start(&self, record: ProcessRecord) {
        self.running.borrow_mut().insert(record.key.pid, record);
    }

    /// Ends the process with ID `pid`.
    pub fn exit(&self, pid: u32) {
        self.running.borrow_mut().remove(&pid);
    }
}

impl ProcessInfo for MockProcesses {
    fn by_pid(&self, pid: u32) -> Result<ProcessRecord> {
        self.running
            .borrow()
            .get(&pid)
            .cloned()
            .ok_or_else(|| PlatformError::not_found("no such process"))
    }

    fn get(&self, key: ProcessKey) -> Result<ProcessRecord> {
        self.by_pid(key.pid)
            .ok()
            .filter(|r| r.key == key)
            .ok_or_else(|| PlatformError::not_found("the process has exited"))
    }
}

// ---------------------------------------------------------------------------
// Environment
// ---------------------------------------------------------------------------

/// A scripted device. Every field is public; the defaults describe an x64
/// workstation called `DEV-0001` with no network.
#[derive(Debug)]
pub struct MockEnvironment {
    /// The host name.
    pub hostname: String,
    /// The domain.
    pub domain: Option<String>,
    /// The OS version.
    pub os_version: OsVersion,
    /// The architecture.
    pub architecture: Architecture,
    /// The interface addresses.
    pub addresses: Vec<InterfaceAddress>,
    /// The connection type.
    pub connection_type: ConnectionType,
    vars: BTreeMap<String, String>,
}

impl Default for MockEnvironment {
    fn default() -> Self {
        Self {
            hostname: "DEV-0001".to_string(),
            domain: None,
            os_version: OsVersion {
                major: 10,
                minor: 0,
                build: 26100,
                revision: 1,
            },
            architecture: Architecture::X64,
            addresses: Vec::new(),
            connection_type: ConnectionType::Offline,
            vars: BTreeMap::new(),
        }
    }
}

impl MockEnvironment {
    /// The defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets an environment variable.
    pub fn set_var(&mut self, name: &str, value: &str) {
        self.vars.insert(fold(name), value.to_string());
    }
}

impl Environment for MockEnvironment {
    fn hostname(&self) -> Result<String> {
        Ok(self.hostname.clone())
    }

    fn domain(&self) -> Result<Option<String>> {
        Ok(self.domain.clone())
    }

    fn os_version(&self) -> Result<OsVersion> {
        Ok(self.os_version)
    }

    fn architecture(&self) -> Architecture {
        self.architecture
    }

    fn addresses(&self) -> Result<Vec<InterfaceAddress>> {
        Ok(self.addresses.clone())
    }

    fn connection_type(&self) -> Result<ConnectionType> {
        Ok(self.connection_type)
    }

    fn var(&self, name: &str) -> Option<String> {
        self.vars.get(&fold(name)).cloned()
    }
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

/// A registry as a map. Setting a value creates its key and every parent.
/// The root of each hive always exists.
#[derive(Debug, Default)]
pub struct MockRegistry {
    /// `(hive, folded key path)` to the key as first written, and its values.
    keys: BTreeMap<(HiveKey, String), RegistryKey>,
}

#[derive(Debug, Default)]
struct RegistryKey {
    /// The path as first written, for subkey names.
    path: String,
    values: BTreeMap<String, RegistryValue>,
}

/// [`Hive`] as a map key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum HiveKey {
    LocalMachine,
    Users,
}

impl From<Hive> for HiveKey {
    fn from(hive: Hive) -> Self {
        match hive {
            Hive::LocalMachine => Self::LocalMachine,
            Hive::Users => Self::Users,
        }
    }
}

/// `a\\b\` and `a\b` are the same key.
fn key_path(path: &str) -> String {
    let parts: Vec<&str> = path.split('\\').filter(|p| !p.is_empty()).collect();
    parts.join("\\")
}

impl MockRegistry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates the key `path` and its parents.
    pub fn create_key(&mut self, hive: Hive, path: &str) {
        let path = key_path(path);
        let mut prefix = String::new();
        for part in path.split('\\').filter(|p| !p.is_empty()) {
            if !prefix.is_empty() {
                prefix.push('\\');
            }
            prefix.push_str(part);
            self.keys
                .entry((hive.into(), fold(&prefix)))
                .or_insert_with(|| RegistryKey {
                    path: prefix.clone(),
                    values: BTreeMap::new(),
                });
        }
    }

    /// Sets the value `name` of the key `path`, creating the key. A value
    /// with the same name in another letter case is replaced.
    pub fn set_value(&mut self, hive: Hive, path: &str, name: &str, value: RegistryValue) {
        self.create_key(hive, path);
        let values = if key_path(path).is_empty() {
            &mut self
                .keys
                .entry((hive.into(), String::new()))
                .or_default()
                .values
        } else {
            match self.keys.get_mut(&(hive.into(), fold(&key_path(path)))) {
                Some(key) => &mut key.values,
                None => return,
            }
        };
        values.retain(|n, _| fold(n) != fold(name));
        values.insert(name.to_string(), value);
    }

    /// The values of `path`, or `None` if the key does not exist. The hive
    /// root always exists.
    fn find(&self, hive: Hive, path: &str) -> Option<Option<&BTreeMap<String, RegistryValue>>> {
        let folded = fold(&key_path(path));
        match self.keys.get(&(hive.into(), folded.clone())) {
            Some(key) => Some(Some(&key.values)),
            None if folded.is_empty() => Some(None),
            None => None,
        }
    }
}

impl Registry for MockRegistry {
    fn key_exists(&self, hive: Hive, path: &str) -> Result<bool> {
        Ok(self.find(hive, path).is_some())
    }

    fn value(&self, hive: Hive, path: &str, name: &str) -> Result<Option<RegistryValue>> {
        Ok(self.find(hive, path).flatten().and_then(|values| {
            values
                .iter()
                .find(|(n, _)| fold(n) == fold(name))
                .map(|(_, v)| v.clone())
        }))
    }

    fn subkeys(&self, hive: Hive, path: &str) -> Result<Vec<String>> {
        if self.find(hive, path).is_none() {
            return Err(PlatformError::not_found(path));
        }
        let parent = fold(&key_path(path));
        let mut out = Vec::new();
        for ((h, folded), key) in &self.keys {
            if *h != HiveKey::from(hive) || folded.is_empty() {
                continue;
            }
            let rest = if parent.is_empty() {
                Some(folded.as_str())
            } else {
                folded
                    .strip_prefix(parent.as_str())
                    .and_then(|r| r.strip_prefix('\\'))
            };
            if rest.is_some_and(|r| !r.is_empty() && !r.contains('\\'))
                && let Some(name) = key.path.rsplit('\\').next()
            {
                out.push(name.to_string());
            }
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

/// Captures emitted events for assertions. With a capacity, it refuses
/// events once full, to test back-pressure.
#[derive(Debug)]
pub struct RecordingSink<E> {
    events: Vec<E>,
    capacity: Option<usize>,
}

impl<E> Default for RecordingSink<E> {
    fn default() -> Self {
        Self {
            events: Vec::new(),
            capacity: None,
        }
    }
}

impl<E> RecordingSink<E> {
    /// An unbounded sink.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A sink that accepts at most `capacity` events.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            events: Vec::new(),
            capacity: Some(capacity),
        }
    }

    /// The events emitted so far, in order.
    #[must_use]
    pub fn events(&self) -> &[E] {
        &self.events
    }

    /// Takes the events emitted so far.
    pub fn take(&mut self) -> Vec<E> {
        core::mem::take(&mut self.events)
    }
}

impl<E> EventSink<E> for RecordingSink<E> {
    fn emit(&mut self, event: E) -> Result<()> {
        if self.capacity.is_some_and(|c| self.events.len() >= c) {
            return Err(PlatformError::new(ErrorKind::TooLarge, "the sink is full"));
        }
        self.events.push(event);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// The bundle
// ---------------------------------------------------------------------------

/// One mock of each platform service.
#[derive(Debug, Default)]
pub struct MockPlatform {
    /// The clock.
    pub clock: MockClock,
    /// The file system.
    pub fs: MockFileSystem,
    /// The signature verifier.
    pub signatures: MockSignatures,
    /// Users, groups and sessions.
    pub identity: MockIdentity,
    /// Processes.
    pub processes: MockProcesses,
    /// The environment.
    pub environment: MockEnvironment,
    /// The registry.
    pub registry: MockRegistry,
}

impl MockPlatform {
    /// Defaults throughout.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl Platform for MockPlatform {
    type Clock = MockClock;
    type FileSystem = MockFileSystem;
    type Signatures = MockSignatures;
    type Identity = MockIdentity;
    type Processes = MockProcesses;
    type Environment = MockEnvironment;
    type Registry = MockRegistry;

    fn clock(&self) -> &MockClock {
        &self.clock
    }

    fn file_system(&self) -> &MockFileSystem {
        &self.fs
    }

    fn signatures(&self) -> &MockSignatures {
        &self.signatures
    }

    fn identity(&self) -> &MockIdentity {
        &self.identity
    }

    fn processes(&self) -> &MockProcesses {
        &self.processes
    }

    fn environment(&self) -> &MockEnvironment {
        &self.environment
    }

    fn registry(&self) -> &MockRegistry {
        &self.registry
    }
}

#[cfg(test)]
mod tests;
