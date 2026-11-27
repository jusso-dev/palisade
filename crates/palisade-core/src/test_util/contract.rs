//! Behaviour every implementation of a platform trait must have.
//!
//! Each function checks one trait against a fixture the caller has set up,
//! and returns `Err` with a description of the first broken rule. The mocks
//! run them in this crate's tests. The agent runs the same functions against
//! its OS implementations (on Windows CI for the Windows ones), so the mocks
//! cannot drift from real behaviour.

use alloc::{format, string::String, vec, vec::Vec};

use crate::platform::{
    Clock, Elevation, Environment, ErrorKind, FileSystem, Hive, IdentityProvider, OpenFile,
    ProcessInfo, ProcessKey, ProcessRecord, Registry, RegistryValue, SessionKind, TokenInfo,
    ancestry, expand_env_vars,
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
/// - a read at an offset past the end returns 0, up to `u64::MAX`;
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
    for offset in [len.saturating_add(100), 1 << 63, u64::MAX] {
        let past = file
            .read_at(offset, &mut buf)
            .map_err(|e| format!("read at {offset}, past the end: {e}"))?;
        ensure(past == 0, || {
            format!("read at {offset}, past the end, returned {past}")
        })?;
    }
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

/// Whether `sid` has the shape of a SID in text form: `S-1-`, the
/// authority (decimal, or `0x` and hexadecimal), then decimal
/// sub-authorities.
fn looks_like_sid(sid: &str) -> bool {
    let Some(rest) = sid.strip_prefix("S-1-") else {
        return false;
    };
    let decimal = |n: &str| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit());
    let mut parts = rest.split('-');
    let authority = parts.next().unwrap_or_default();
    let hex = authority
        .strip_prefix("0x")
        .is_some_and(|h| !h.is_empty() && h.bytes().all(|b| b.is_ascii_hexdigit()));
    (decimal(authority) || hex) && parts.all(decimal)
}

/// The rules every token must keep, whoever reads it.
fn token_rules(token: &TokenInfo, what: &str) -> Outcome {
    ensure(looks_like_sid(&token.user_sid), || {
        format!("{what}: user {:?} is not a SID", token.user_sid)
    })?;
    for group in &token.groups {
        ensure(looks_like_sid(&group.sid), || {
            format!("{what}: group {:?} is not a SID", group.sid)
        })?;
        // The integrity label (S-1-16-*) is the integrity level, not a
        // group.
        ensure(!group.sid.starts_with("S-1-16-"), || {
            format!(
                "{what}: the integrity label {} is listed as a group",
                group.sid
            )
        })?;
    }
    ensure(
        (token.session_id == 0) == (token.session_kind == SessionKind::Services),
        || {
            format!(
                "{what}: session {} is {:?}",
                token.session_id, token.session_kind
            )
        },
    )?;
    let consistent = match token.elevation {
        Elevation::Full => token.elevated,
        Elevation::Limited => !token.elevated,
        Elevation::Default => true,
    };
    ensure(consistent, || {
        format!(
            "{what}: elevation {:?} but elevated is {}",
            token.elevation, token.elevated
        )
    })
}

/// Identity queries, for a provider where `process` is running with a
/// readable token, and the local group `group` has `member` as a direct
/// member:
///
/// - [`IdentityProvider::current`] and [`IdentityProvider::token`] of
///   `process` return tokens whose user and groups are SIDs, without the
///   integrity label among the groups, whose session is
///   [`SessionKind::Services`] exactly when its ID is 0, and whose
///   elevation type agrees with `elevated` (`Full` is elevated, `Limited`
///   is not);
/// - the token of `process` under a different creation time (a reused ID)
///   fails with [`ErrorKind::NotFound`];
/// - the members of `group` include `member`, in any letter case of
///   `group`;
/// - a SID argument that is not a SID fails with
///   [`ErrorKind::InvalidInput`] or reads as nothing (`None`, or
///   [`ErrorKind::NotFound`]), never as some other account.
///
/// # Errors
///
/// The first rule `identity` breaks.
pub fn identity<I: IdentityProvider + ?Sized>(
    identity: &I,
    process: ProcessKey,
    group: &str,
    member: &str,
) -> Outcome {
    let current = identity.current().map_err(|e| format!("current: {e}"))?;
    token_rules(&current, "current")?;
    let token = identity.token(process).map_err(|e| format!("token: {e}"))?;
    token_rules(&token, "token")?;
    let reused = ProcessKey {
        pid: process.pid,
        created: process.created.saturating_add_micros(1),
    };
    match identity.token(reused) {
        Err(e) => ensure(e.kind() == ErrorKind::NotFound, || {
            format!("the token of a reused key gave {e}, not NotFound")
        })?,
        Ok(_) => return Err("the token of a key with the wrong creation time was read".into()),
    }
    for name in [String::from(group), group.to_ascii_lowercase()] {
        let members = identity
            .local_group_members(&name)
            .map_err(|e| format!("members of {name}: {e}"))?;
        ensure(
            members.iter().any(|m| m.eq_ignore_ascii_case(member)),
            || format!("{member} is not among the members of {name}: {members:?}"),
        )?;
    }
    for bad in ["", "Administrators", "S-1"] {
        match identity.local_group_members(bad) {
            Err(e) => ensure(
                matches!(e.kind(), ErrorKind::InvalidInput | ErrorKind::NotFound),
                || format!("members of {bad:?} gave {e}"),
            )?,
            Ok(m) => return Err(format!("{bad:?} listed members {m:?}")),
        }
        match identity.account_name(bad) {
            Ok(None) => {}
            Err(e) => ensure(e.kind() == ErrorKind::InvalidInput, || {
                format!("the name of {bad:?} gave {e}")
            })?,
            Ok(Some(n)) => return Err(format!("{bad:?} has the name {n:?}")),
        }
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
///   different name; so does a key path with a leading `\\` or an empty
///   component (`a\\\\b`).
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
    let doubled = key.replacen('\\', "\\\\", 1);
    let mut bad = vec![format!("\\{key}")];
    if doubled != key {
        bad.push(doubled);
    }
    for path in bad {
        let got = registry.key_exists(hive, &path).map_err(|e| e.kind());
        ensure(got == Err(ErrorKind::InvalidInput), || {
            format!("key_exists {path:?} gave {got:?}, not InvalidInput")
        })?;
    }
    Ok(())
}
