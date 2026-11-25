//! Behaviour every implementation of a platform trait must have.
//!
//! Each function checks one trait against a fixture the caller has set up,
//! and returns `Err` with a description of the first broken rule. The mocks
//! run them in this crate's tests. The agent runs the same functions against
//! its OS implementations (on Windows CI for the Windows ones), so the mocks
//! cannot drift from real behaviour.

use alloc::{format, string::String, vec::Vec};

use crate::platform::{
    Clock, Environment, ErrorKind, FileSystem, Hive, OpenFile, ProcessInfo, ProcessKey,
    ProcessRecord, Registry, RegistryValue, ancestry, expand_env_vars,
};

/// The result of a contract check.
pub type Outcome = Result<(), String>;

fn ensure(ok: bool, message: impl FnOnce() -> String) -> Outcome {
    if ok { Ok(()) } else { Err(message()) }
}

/// Two readings of `clock`: the monotonic clock does not go backwards, and
/// the wall clock is a plausible date (after 2020-01-01 and before 2200).
///
/// # Errors
///
/// The first rule `clock` breaks.
pub fn clock<C: Clock + ?Sized>(clock: &C) -> Outcome {
    let m1 = clock.monotonic();
    let utc = clock.now_utc();
    let m2 = clock.monotonic();
    ensure(m2 >= m1, || {
        format!("monotonic went backwards: {m1:?} then {m2:?}")
    })?;
    // 2020-01-01T00:00:00Z and 2200-01-01T00:00:00Z.
    let plausible = 1_577_836_800..7_258_118_400;
    ensure(plausible.contains(&utc.unix_secs()), || {
        format!("implausible wall clock: {} s", utc.unix_secs())
    })
}

/// File reads, for a file system where `path` is a regular file holding
/// exactly `contents`, and `missing` does not exist:
///
/// - opening `missing` fails with [`ErrorKind::NotFound`];
/// - the open file's size is the length of `contents`;
/// - reading in small chunks returns `contents`, then 0 at the end;
/// - a read at an offset past the end returns 0;
/// - the alternate data streams, if listed, have non-empty names without a
///   `:`. An implementation that cannot list them yet may answer
///   [`ErrorKind::Unsupported`].
///
/// # Errors
///
/// The first rule `fs` breaks.
pub fn file_system<F: FileSystem + ?Sized>(
    fs: &F,
    path: &str,
    contents: &[u8],
    missing: &str,
) -> Outcome {
    match fs.open(missing) {
        Err(e) => ensure(e.kind() == ErrorKind::NotFound, || {
            format!("opening {missing} gave {e}, not NotFound")
        })?,
        Ok(_) => return Err(format!("opening {missing} succeeded")),
    }
    let mut file = fs.open(path).map_err(|e| format!("open {path}: {e}"))?;
    let metadata = file.metadata().map_err(|e| format!("metadata: {e}"))?;
    let len = u64::try_from(contents.len()).unwrap_or(u64::MAX);
    ensure(metadata.size == len && !metadata.is_dir, || {
        format!("metadata {metadata:?} does not describe a {len}-byte file")
    })?;
    let mut read = Vec::new();
    let mut buf = [0u8; 7];
    let mut offset = 0u64;
    loop {
        let n = file
            .read_at(offset, &mut buf)
            .map_err(|e| format!("read at {offset}: {e}"))?;
        if n == 0 {
            break;
        }
        ensure(n <= buf.len(), || format!("read returned {n} bytes"))?;
        read.extend_from_slice(buf.get(..n).unwrap_or_default());
        offset = offset.saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
        ensure(read.len() <= contents.len(), || {
            "read past the end of the file".into()
        })?;
    }
    ensure(read == contents, || "read different contents".into())?;
    let past = file
        .read_at(len.saturating_add(100), &mut buf)
        .map_err(|e| format!("read past the end: {e}"))?;
    ensure(past == 0, || format!("read past the end returned {past}"))?;
    let streams = match fs.streams(path) {
        Ok(streams) => streams,
        Err(e) if e.kind() == ErrorKind::Unsupported => Vec::new(),
        Err(e) => return Err(format!("streams: {e}")),
    };
    for s in &streams {
        ensure(!s.name.is_empty() && !s.name.contains(':'), || {
            format!("bad stream name {:?}", s.name)
        })?;
    }
    Ok(())
}

/// A directory, for a file system where `path` is one: it opens, its
/// metadata says it is a directory with size 0, and reading it fails with
/// [`ErrorKind::InvalidInput`].
///
/// # Errors
///
/// The first rule `fs` breaks.
pub fn directory<F: FileSystem + ?Sized>(fs: &F, path: &str) -> Outcome {
    let mut dir = fs.open(path).map_err(|e| format!("open {path}: {e}"))?;
    let metadata = dir.metadata().map_err(|e| format!("metadata: {e}"))?;
    ensure(metadata.is_dir && metadata.size == 0, || {
        format!("{path}: metadata {metadata:?} does not describe a directory")
    })?;
    match dir.read_at(0, &mut [0u8; 8]) {
        Err(e) => ensure(e.kind() == ErrorKind::InvalidInput, || {
            format!("reading a directory gave {e}, not InvalidInput")
        }),
        Ok(n) => Err(format!("reading a directory returned {n} bytes")),
    }
}

/// Environment queries, for an environment where `var` is set to `value`
/// and `unset` is not set:
///
/// - the host name is non-empty;
/// - `var` is found in any letter case, `unset` is not;
/// - [`expand_env_vars`] with this environment substitutes `var` and leaves
///   `unset` as written.
///
/// # Errors
///
/// The first rule `env` breaks.
pub fn environment<E: Environment + ?Sized>(
    env: &E,
    var: &str,
    value: &str,
    unset: &str,
) -> Outcome {
    let host = env.hostname().map_err(|e| format!("hostname: {e}"))?;
    ensure(!host.is_empty(), || "empty host name".into())?;
    for name in [
        String::from(var),
        var.to_ascii_lowercase(),
        var.to_ascii_uppercase(),
    ] {
        ensure(env.var(&name).as_deref() == Some(value), || {
            format!("{name} is not {value:?}")
        })?;
    }
    ensure(env.var(unset).is_none(), || format!("{unset} is set"))?;
    let template = format!("a%{var}%b%{unset}%c");
    let expanded =
        expand_env_vars(&template, |n| env.var(n)).map_err(|e| format!("expand: {e}"))?;
    let expected = format!("a{value}b%{unset}%c");
    ensure(expanded == expected, || {
        format!("{template} expanded to {expanded:?}, not {expected:?}")
    })
}

/// Process queries, for a process table where `process` is running:
///
/// - [`ProcessInfo::get`] and [`ProcessInfo::by_pid`] return a record with
///   key `process`;
/// - [`ProcessInfo::get`] with the same ID and a different creation time
///   (a reused ID) fails with [`ErrorKind::NotFound`];
/// - every ancestor [`ancestry`] returns was created no later than its
///   child.
///
/// # Errors
///
/// The first rule `processes` breaks.
pub fn processes<P: ProcessInfo + ?Sized>(processes: &P, process: ProcessKey) -> Outcome {
    let record = processes.get(process).map_err(|e| format!("get: {e}"))?;
    ensure(record.key == process, || {
        format!("get returned {:?}", record.key)
    })?;
    let by_pid = processes
        .by_pid(process.pid)
        .map_err(|e| format!("by_pid: {e}"))?;
    ensure(by_pid.key == process, || {
        format!("by_pid returned {:?}", by_pid.key)
    })?;
    let reused = ProcessKey {
        pid: process.pid,
        created: process.created.saturating_add_micros(1),
    };
    match processes.get(reused) {
        Err(e) => ensure(e.kind() == ErrorKind::NotFound, || {
            format!("a reused key gave {e}, not NotFound")
        })?,
        Ok(_) => return Err("a key with the wrong creation time matched".into()),
    }
    let chain = ancestry(processes, process).map_err(|e| format!("ancestry: {e}"))?;
    let mut child: &ProcessRecord = &record;
    for parent in &chain {
        ensure(parent.key.created <= child.key.created, || {
            format!("{:?} is older than its parent {:?}", child.key, parent.key)
        })?;
        child = parent;
    }
    Ok(())
}

/// Registry reads, for a registry where the key `key` in `hive` holds the
/// value `name` equal to `value`, and has at least one subkey:
///
/// - the key exists, in any letter case, and with a trailing `\\`;
/// - `name` reads as `value`, in any letter case;
/// - a value and a key that do not exist read as `None` and `false`, not
///   as errors;
/// - the subkeys are listed, and listing a missing key fails with
///   [`ErrorKind::NotFound`];
/// - a key path or value name with a NUL character fails with
///   [`ErrorKind::InvalidInput`], so it can never be read as a shorter,
///   different name.
///
/// # Errors
///
/// The first rule `registry` breaks.
pub fn registry<R: Registry + ?Sized>(
    registry: &R,
    hive: Hive,
    key: &str,
    name: &str,
    value: &RegistryValue,
) -> Outcome {
    let missing = format!("{key}\\Palisade-contract-missing");
    for k in [
        String::from(key),
        key.to_ascii_lowercase(),
        format!("{key}\\"),
    ] {
        let exists = registry
            .key_exists(hive, &k)
            .map_err(|e| format!("key_exists {k}: {e}"))?;
        ensure(exists, || format!("{k} does not exist"))?;
    }
    for n in [String::from(name), name.to_ascii_uppercase()] {
        let got = registry
            .value(hive, key, &n)
            .map_err(|e| format!("value {n}: {e}"))?;
        ensure(got.as_ref() == Some(value), || {
            format!("{key}\\{n} is {got:?}, not {value:?}")
        })?;
    }
    let none = registry
        .value(hive, key, "Palisade-contract-missing")
        .map_err(|e| format!("missing value: {e}"))?;
    ensure(none.is_none(), || {
        format!("a missing value read as {none:?}")
    })?;
    let none = registry
        .value(hive, &missing, name)
        .map_err(|e| format!("value in a missing key: {e}"))?;
    ensure(none.is_none(), || {
        "a value of a missing key was found".into()
    })?;
    let exists = registry
        .key_exists(hive, &missing)
        .map_err(|e| format!("key_exists {missing}: {e}"))?;
    ensure(!exists, || format!("{missing} exists"))?;
    let subkeys = registry
        .subkeys(hive, key)
        .map_err(|e| format!("subkeys {key}: {e}"))?;
    ensure(!subkeys.is_empty(), || format!("{key} has no subkeys"))?;
    ensure(
        subkeys.iter().all(|s| !s.is_empty() && !s.contains('\\')),
        || format!("bad subkey names {subkeys:?}"),
    )?;
    match registry.subkeys(hive, &missing) {
        Err(e) => ensure(e.kind() == ErrorKind::NotFound, || {
            format!("listing {missing} gave {e}, not NotFound")
        })?,
        Ok(_) => return Err(format!("listing {missing} succeeded")),
    }
    let nul_key = format!("{key}\0suffix");
    let nul_name = format!("{name}\0suffix");
    let checks: [(&str, Result<(), ErrorKind>); 4] = [
        (
            "key_exists with a NUL",
            registry
                .key_exists(hive, &nul_key)
                .map(drop)
                .map_err(|e| e.kind()),
        ),
        (
            "value with a NUL in the key",
            registry
                .value(hive, &nul_key, name)
                .map(drop)
                .map_err(|e| e.kind()),
        ),
        (
            "value with a NUL in the name",
            registry
                .value(hive, key, &nul_name)
                .map(drop)
                .map_err(|e| e.kind()),
        ),
        (
            "subkeys with a NUL",
            registry
                .subkeys(hive, &nul_key)
                .map(drop)
                .map_err(|e| e.kind()),
        ),
    ];
    for (what, result) in checks {
        ensure(result == Err(ErrorKind::InvalidInput), || {
            format!("{what} gave {result:?}, not InvalidInput")
        })?;
    }
    Ok(())
}
