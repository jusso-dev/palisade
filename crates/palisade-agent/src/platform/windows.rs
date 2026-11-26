//! Windows implementations: the registry, and the device facts the
//! environment reports.
//!
//! These go through safe wrapper crates (`windows-registry`,
//! `windows-version`), so the agent still forbids `unsafe` code (ADR 0011).
//! The agent is a native 64-bit process, so registry reads see the 64-bit
//! view.

use palisade_core::platform::{
    ErrorKind, Hive, OsVersion, PlatformError, Registry, RegistryValue, Result,
};
use windows_registry::{Key, LOCAL_MACHINE, Type, USERS};

/// `HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)`.
const NOT_FOUND: i32 = 0x8007_0002_u32.cast_signed();
/// `HRESULT_FROM_WIN32(ERROR_PATH_NOT_FOUND)`.
const PATH_NOT_FOUND: i32 = 0x8007_0003_u32.cast_signed();
/// `HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED)`.
const ACCESS_DENIED: i32 = 0x8007_0005_u32.cast_signed();

/// Where the TCP/IP stack keeps the host name and the primary DNS suffix.
const TCPIP_PARAMETERS: &str = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters";

fn kind(code: i32) -> ErrorKind {
    match code {
        NOT_FOUND | PATH_NOT_FOUND => ErrorKind::NotFound,
        ACCESS_DENIED => ErrorKind::AccessDenied,
        _ => ErrorKind::Other,
    }
}

fn error(code: i32, context: &str) -> PlatformError {
    PlatformError::new(kind(code), format!("{context}: HRESULT {code:#010x}"))
}

fn root(hive: Hive) -> &'static Key {
    match hive {
        Hive::LocalMachine => LOCAL_MACHINE,
        Hive::Users => USERS,
    }
}

/// Rejects a name with a NUL character: the OS would read it only up to
/// the NUL, so it would name a different, shorter key or value.
fn no_nul(text: &str) -> Result<()> {
    if text.contains('\0') {
        Err(PlatformError::new(
            ErrorKind::InvalidInput,
            "a registry name contains a NUL character",
        ))
    } else {
        Ok(())
    }
}

/// Rejects what the OS rejects as a bad path (a leading `\\`, or an empty
/// component such as `a\\\\b`) with `InvalidInput`, like the mock, instead
/// of passing on the OS's `ERROR_BAD_PATHNAME`.
fn key_path_ok(path: &str) -> Result<()> {
    no_nul(path)?;
    let trimmed = path.strip_suffix('\\').unwrap_or(path);
    if path.starts_with('\\') || (!trimmed.is_empty() && trimmed.split('\\').any(str::is_empty)) {
        return Err(PlatformError::new(
            ErrorKind::InvalidInput,
            "a registry key path has an empty component",
        ));
    }
    Ok(())
}

/// Opens `path` for reading. `Ok(None)` if it does not exist.
fn open(hive: Hive, path: &str) -> Result<Option<Key>> {
    key_path_ok(path)?;
    match root(hive).open(path) {
        Ok(key) => Ok(Some(key)),
        Err(e) if kind(e.code().0) == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(error(e.code().0, path)),
    }
}

/// Registry reads through the OS.
///
/// A value is read in full, whatever its size: the safe wrapper has no
/// size-capped read, and capping one needs FFI. Registry conditions (#33,
/// #59), which read user-writable hives, add the cap when they wire this
/// in.
#[derive(Clone, Copy, Debug, Default)]
pub struct WindowsRegistry;

impl Registry for WindowsRegistry {
    fn key_exists(&self, hive: Hive, path: &str) -> Result<bool> {
        Ok(open(hive, path)?.is_some())
    }

    fn value(&self, hive: Hive, path: &str, name: &str) -> Result<Option<RegistryValue>> {
        no_nul(name)?;
        let Some(key) = open(hive, path)? else {
            return Ok(None);
        };
        let value = match key.get_value(name) {
            Ok(value) => value,
            Err(e) if kind(e.code().0) == ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(error(e.code().0, name)),
        };
        let converted = match value.ty() {
            Type::U32 => u32::try_from(value).map(RegistryValue::Dword),
            Type::U64 => u64::try_from(value).map(RegistryValue::Qword),
            Type::String => String::try_from(value).map(RegistryValue::String),
            Type::ExpandString => String::try_from(value).map(RegistryValue::ExpandString),
            Type::MultiString => Vec::<String>::try_from(value).map(|mut items| {
                // The list ends with an empty string before the final NUL.
                while items.last().is_some_and(String::is_empty) {
                    items.pop();
                }
                RegistryValue::MultiString(items)
            }),
            Type::Bytes | Type::Other(_) => Ok(RegistryValue::Binary(value.to_vec())),
        };
        converted.map(Some).map_err(|e| {
            PlatformError::new(
                ErrorKind::Other,
                format!(
                    "{path}\\{name}: malformed value: HRESULT {:#010x}",
                    e.code().0
                ),
            )
        })
    }

    fn subkeys(&self, hive: Hive, path: &str) -> Result<Vec<String>> {
        let key = open(hive, path)?.ok_or_else(|| PlatformError::not_found(path))?;
        let keys = key.keys().map_err(|e| error(e.code().0, path))?;
        Ok(keys.collect())
    }
}

fn string_value(path: &str, name: &str) -> Option<String> {
    match WindowsRegistry.value(Hive::LocalMachine, path, name) {
        Ok(Some(RegistryValue::String(s))) if !s.is_empty() => Some(s),
        _ => None,
    }
}

/// The host name, as the TCP/IP stack has it.
pub fn hostname() -> Option<String> {
    string_value(TCPIP_PARAMETERS, "Hostname")
}

/// The primary DNS suffix, or `None` when the device has none.
pub fn domain() -> Option<String> {
    string_value(TCPIP_PARAMETERS, "Domain")
}

/// The running OS version, with the update build revision.
pub fn os_version() -> OsVersion {
    let v = windows_version::OsVersion::current();
    OsVersion {
        major: v.major,
        minor: v.minor,
        build: v.build,
        revision: windows_version::revision(),
    }
}
