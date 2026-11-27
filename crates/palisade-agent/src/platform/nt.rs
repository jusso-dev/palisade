//! Decoding the raw records Windows returns for tokens and processes.
//!
//! `palisade_agent::ffi` copies each record into a buffer it owns and
//! hands over the bytes, with the address the OS wrote them at. Records
//! such as `TOKEN_GROUPS` point into themselves (each group's SID pointer
//! points further into the same buffer), so a pointer is turned into an
//! offset by subtracting that address, and checked to lie inside the
//! bytes, instead of being dereferenced. That keeps this module free of
//! `unsafe` code and lets it run, and be tested, on every OS.
//!
//! Fail closed (ADR 0018): a record that is short, points outside itself,
//! or holds a value this module does not know is an error, never a
//! guessed default.

// Compiled everywhere so the tests run on every CI runner; only the
// Windows backends use it.
#![cfg_attr(not(windows), allow(dead_code))]

use std::str::FromStr as _;

use palisade_core::platform::{
    Elevation, ErrorKind, GroupMembership, IntegrityLevel, PlatformError, Result, SessionKind,
    UtcTime,
};
use palisade_fileid::fsctx::Sid;

/// The pointer size of this process, which is the layout the OS used for
/// every record it returned to it.
pub(crate) const PTR: usize = size_of::<usize>();

/// A record the OS wrote: its bytes, the address of their first byte when
/// the OS wrote them, and the pointer size of that layout.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Record<'a> {
    pub(crate) bytes: &'a [u8],
    pub(crate) base: usize,
    pub(crate) ptr: usize,
}

impl<'a> Record<'a> {
    /// A record in this process's own layout.
    pub(crate) fn new(bytes: &'a [u8], base: usize) -> Self {
        Self {
            bytes,
            base,
            ptr: PTR,
        }
    }

    fn u16_at(&self, offset: usize) -> Option<u16> {
        let b = self.bytes.get(offset..offset.checked_add(2)?)?;
        Some(u16::from_le_bytes(b.try_into().ok()?))
    }

    fn u32_at(&self, offset: usize) -> Option<u32> {
        let b = self.bytes.get(offset..offset.checked_add(4)?)?;
        Some(u32::from_le_bytes(b.try_into().ok()?))
    }

    /// A pointer-sized value at `offset`.
    fn ptr_at(&self, offset: usize) -> Option<usize> {
        let b = self.bytes.get(offset..offset.checked_add(self.ptr)?)?;
        let mut word = [0_u8; 8];
        word.get_mut(..b.len())?.copy_from_slice(b);
        usize::try_from(u64::from_le_bytes(word)).ok()
    }

    /// The bytes from the address `pointer` to the end of the record.
    fn tail_at(&self, pointer: usize) -> Option<&'a [u8]> {
        self.bytes.get(pointer.checked_sub(self.base)?..)
    }

    /// The SID that `pointer` points at, inside the record.
    fn sid_at(&self, pointer: usize, what: &str) -> Result<Sid> {
        let tail = self
            .tail_at(pointer)
            .ok_or_else(|| malformed(what, "the SID pointer is outside the record"))?;
        Sid::from_bytes(tail)
            .map(|(sid, _)| sid)
            .map_err(|e| malformed(what, &format!("bad SID: {e}")))
    }

    /// A `SID_AND_ATTRIBUTES` at `offset`: the SID and the attributes.
    fn sid_and_attributes(&self, offset: usize, what: &str) -> Result<(Sid, u32)> {
        let truncated = || malformed(what, "truncated");
        let pointer = self.ptr_at(offset).ok_or_else(truncated)?;
        let attributes = offset
            .checked_add(self.ptr)
            .and_then(|o| self.u32_at(o))
            .ok_or_else(truncated)?;
        Ok((self.sid_at(pointer, what)?, attributes))
    }
}

fn malformed(what: &str, why: &str) -> PlatformError {
    PlatformError::new(ErrorKind::Other, format!("malformed {what}: {why}"))
}

/// Parses a SID argument in its text form.
pub(crate) fn parse_sid(text: &str) -> Result<Sid> {
    Sid::from_str(text).map_err(|e| {
        PlatformError::new(ErrorKind::InvalidInput, format!("not a SID: {text:?}: {e}"))
    })
}

// ---------------------------------------------------------------------------
// Tokens
// ---------------------------------------------------------------------------

/// `SE_GROUP_ENABLED`.
const SE_GROUP_ENABLED: u32 = 0x0000_0004;
/// `SE_GROUP_USE_FOR_DENY_ONLY`.
const SE_GROUP_USE_FOR_DENY_ONLY: u32 = 0x0000_0010;
/// `SE_GROUP_INTEGRITY`: the entry is the token's integrity label.
const SE_GROUP_INTEGRITY: u32 = 0x0000_0020;

/// `SECURITY_MANDATORY_LABEL_AUTHORITY`: the authority of integrity SIDs.
const MANDATORY_LABEL_AUTHORITY: u64 = 16;

/// The user SID, from a `TOKEN_USER` record.
pub(crate) fn token_user(record: Record<'_>) -> Result<String> {
    let (sid, _) = record.sid_and_attributes(0, "TOKEN_USER")?;
    Ok(sid.to_string())
}

/// The groups, from a `TOKEN_GROUPS` record.
///
/// The integrity label is left out: it is not a group, and
/// [`token_integrity`] reads it. A group that is not enabled is reported
/// as deny-only, like a group UAC marked deny-only: the OS does not use it
/// to grant access, so policy must not read it as plain membership
/// (`palisade_policy::scope` evaluates a deny-only group both ways and
/// takes the safer reading).
pub(crate) fn token_groups(record: Record<'_>) -> Result<Vec<GroupMembership>> {
    const WHAT: &str = "TOKEN_GROUPS";
    let count = record
        .u32_at(0)
        .ok_or_else(|| malformed(WHAT, "truncated"))?;
    let count = usize::try_from(count).map_err(|_| malformed(WHAT, "group count"))?;
    // The array starts at the first pointer-aligned offset after the
    // count, and each entry is a pointer and a `DWORD`, padded to pointer
    // alignment.
    let entry = record.ptr.checked_mul(2);
    let end = entry
        .and_then(|e| e.checked_mul(count))
        .and_then(|n| n.checked_add(record.ptr));
    if end.is_none_or(|end| end > record.bytes.len()) {
        return Err(malformed(WHAT, "more groups than the record holds"));
    }
    let entry = entry.unwrap_or_default();
    let mut groups = Vec::with_capacity(count);
    for i in 0..count {
        let offset = record.ptr + i * entry;
        let (sid, attributes) = record.sid_and_attributes(offset, WHAT)?;
        if attributes & SE_GROUP_INTEGRITY != 0 {
            continue;
        }
        groups.push(GroupMembership {
            sid: sid.to_string(),
            deny_only: attributes & SE_GROUP_USE_FOR_DENY_ONLY != 0
                || attributes & SE_GROUP_ENABLED == 0,
        });
    }
    Ok(groups)
}

/// The integrity level, from a `TOKEN_MANDATORY_LABEL` record.
pub(crate) fn token_integrity(record: Record<'_>) -> Result<IntegrityLevel> {
    const WHAT: &str = "TOKEN_MANDATORY_LABEL";
    let (sid, _) = record.sid_and_attributes(0, WHAT)?;
    match (sid.authority(), sid.sub_authorities()) {
        (MANDATORY_LABEL_AUTHORITY, [rid]) => Ok(integrity_from_rid(*rid)),
        _ => Err(malformed(WHAT, &format!("{sid} is not an integrity SID"))),
    }
}

/// The integrity level of the mandatory label RID `rid`.
///
/// A RID between the standard levels is rounded down to the level below:
/// the OS compares labels as numbers, so such a token has none of the
/// access the next level up would give it.
pub(crate) const fn integrity_from_rid(rid: u32) -> IntegrityLevel {
    match rid {
        0x0000..0x1000 => IntegrityLevel::Untrusted,
        0x1000..0x2000 => IntegrityLevel::Low,
        0x2000..0x2100 => IntegrityLevel::Medium,
        0x2100..0x3000 => IntegrityLevel::MediumPlus,
        0x3000..0x4000 => IntegrityLevel::High,
        0x4000..0x5000 => IntegrityLevel::System,
        _ => IntegrityLevel::Protected,
    }
}

/// The elevation type, from a `TOKEN_ELEVATION_TYPE` value.
pub(crate) fn elevation_type(value: u32) -> Result<Elevation> {
    match value {
        1 => Ok(Elevation::Default),
        2 => Ok(Elevation::Full),
        3 => Ok(Elevation::Limited),
        other => Err(malformed(
            "TOKEN_ELEVATION_TYPE",
            &format!("unknown value {other}"),
        )),
    }
}

/// `WTS_PROTOCOL_TYPE_CONSOLE`.
const PROTOCOL_CONSOLE: u16 = 0;
/// `WTS_PROTOCOL_TYPE_RDP`.
const PROTOCOL_RDP: u16 = 2;

/// How session `session_id` was started, from its client protocol type,
/// or `None` if the OS could not say.
pub(crate) const fn session_kind(session_id: u32, protocol: Option<u16>) -> SessionKind {
    if session_id == 0 {
        return SessionKind::Services;
    }
    match protocol {
        Some(PROTOCOL_CONSOLE) => SessionKind::Console,
        Some(PROTOCOL_RDP) => SessionKind::RemoteDesktop,
        _ => SessionKind::Unknown,
    }
}

// ---------------------------------------------------------------------------
// Processes
// ---------------------------------------------------------------------------

/// 100-ns intervals from 1601-01-01 (the `FILETIME` epoch) to 1970-01-01.
const FILETIME_UNIX_EPOCH: i128 = 116_444_736_000_000_000;

/// A `FILETIME` as microseconds since the Unix epoch, rounded down.
pub(crate) fn filetime_to_utc(filetime: u64) -> UtcTime {
    let micros = (i128::from(filetime) - FILETIME_UNIX_EPOCH).div_euclid(10);
    UtcTime(i64::try_from(micros).unwrap_or(i64::MAX))
}

/// The parent process ID, from a `PROCESS_BASIC_INFORMATION` record
/// (`InheritedFromUniqueProcessId`, the sixth pointer-sized field). 0 is
/// "no parent".
pub(crate) fn parent_pid(record: Record<'_>) -> Result<Option<u32>> {
    const WHAT: &str = "PROCESS_BASIC_INFORMATION";
    let value = record
        .ptr
        .checked_mul(5)
        .and_then(|o| record.ptr_at(o))
        .ok_or_else(|| malformed(WHAT, "truncated"))?;
    if value == 0 {
        return Ok(None);
    }
    u32::try_from(value)
        .map(Some)
        .map_err(|_| malformed(WHAT, &format!("parent process ID {value} out of range")))
}

/// The text of a `UNICODE_STRING` record whose buffer follows it in the
/// same record (`ProcessCommandLineInformation`). Text that is not valid
/// UTF-16 is an error, not replaced: a rule must never match a guess.
pub(crate) fn unicode_string(record: Record<'_>, what: &str) -> Result<String> {
    let truncated = || malformed(what, "truncated");
    // The whole header (`Length`, `MaximumLength`, padding, `Buffer`) must
    // be present, even for an empty string.
    let header = record.ptr.checked_mul(2).ok_or_else(truncated)?;
    if record.bytes.len() < header {
        return Err(truncated());
    }
    let len = usize::from(record.u16_at(0).ok_or_else(truncated)?);
    let capacity = usize::from(record.u16_at(2).ok_or_else(truncated)?);
    if len % 2 != 0 {
        return Err(malformed(what, "odd length"));
    }
    if len > capacity {
        return Err(malformed(what, "the length exceeds the maximum length"));
    }
    if len == 0 {
        return Ok(String::new());
    }
    let pointer = record.ptr_at(record.ptr).ok_or_else(truncated)?;
    let start = pointer
        .checked_sub(record.base)
        .ok_or_else(|| malformed(what, "the buffer is outside the record"))?;
    if start < header {
        return Err(malformed(what, "the buffer overlaps the header"));
    }
    let text = record
        .bytes
        .get(start..)
        .and_then(|t| t.get(..len))
        .ok_or_else(|| malformed(what, "the buffer is outside the record"))?;
    let units: Vec<u16> = text
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16(&units).map_err(|_| malformed(what, "not valid UTF-16"))
}

/// Whether a local group whose name resolves to `local` (the SID and
/// `SID_NAME_USE` of the **bare** name that `NetLocalGroupGetMembers` will
/// enumerate) is the group `requested`: a local group (an alias) with
/// exactly that SID. Anything else must not be listed in its place.
pub(crate) fn is_requested_local_group(requested: &Sid, local: &[u8], kind: i32) -> bool {
    /// `SidTypeAlias`.
    const ALIAS: i32 = 4;
    kind == ALIAS && Sid::from_bytes(local).is_ok_and(|(s, n)| s == *requested && n == local.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: usize = 0x10_0000;

    /// A record being built, in the layout of pointer size `ptr`.
    struct Builder {
        bytes: Vec<u8>,
        ptr: usize,
    }

    impl Builder {
        fn new(ptr: usize) -> Self {
            Self {
                bytes: Vec::new(),
                ptr,
            }
        }
        fn u16(&mut self, v: u16) -> &mut Self {
            self.bytes.extend_from_slice(&v.to_le_bytes());
            self
        }
        fn u32(&mut self, v: u32) -> &mut Self {
            self.bytes.extend_from_slice(&v.to_le_bytes());
            self
        }
        fn pad(&mut self) -> &mut Self {
            while !self.bytes.len().is_multiple_of(self.ptr) {
                self.bytes.push(0);
            }
            self
        }
        fn pointer(&mut self, address: usize) -> &mut Self {
            let b = (address as u64).to_le_bytes();
            self.bytes.extend_from_slice(&b[..self.ptr]);
            self
        }
        fn here(&self) -> usize {
            BASE + self.bytes.len()
        }
        fn raw(&mut self, b: &[u8]) -> &mut Self {
            self.bytes.extend_from_slice(b);
            self
        }
        fn record(&self) -> Record<'_> {
            Record {
                bytes: &self.bytes,
                base: BASE,
                ptr: self.ptr,
            }
        }
    }

    fn sid(text: &str) -> Vec<u8> {
        Sid::from_str(text).unwrap().to_bytes()
    }

    /// A `SID_AND_ATTRIBUTES` header followed by the SID.
    fn sid_and_attributes(ptr: usize, text: &str, attributes: u32) -> Builder {
        let mut b = Builder::new(ptr);
        let sid_at = BASE + 2 * ptr;
        b.pointer(sid_at).u32(attributes).pad().raw(&sid(text));
        b
    }

    fn groups(ptr: usize, entries: &[(&str, u32)]) -> Builder {
        let mut b = Builder::new(ptr);
        b.u32(u32::try_from(entries.len()).unwrap()).pad();
        let header = b.bytes.len() + entries.len() * 2 * ptr;
        let mut sid_at = BASE + header;
        let mut sids = Vec::new();
        for (text, attributes) in entries {
            b.pointer(sid_at).u32(*attributes).pad();
            let s = sid(text);
            sid_at += s.len();
            sids.extend(s);
        }
        b.raw(&sids);
        b
    }

    #[test]
    fn user_sid_in_both_layouts() {
        for ptr in [4, 8] {
            let b = sid_and_attributes(ptr, "S-1-5-21-1-2-3-1001", 0);
            assert_eq!(token_user(b.record()).unwrap(), "S-1-5-21-1-2-3-1001");
        }
    }

    #[test]
    fn groups_map_their_attributes() {
        for ptr in [4, 8] {
            let b = groups(
                ptr,
                &[
                    ("S-1-1-0", SE_GROUP_ENABLED | 0x3),
                    ("S-1-5-32-544", SE_GROUP_USE_FOR_DENY_ONLY),
                    ("S-1-5-32-545", 0x3),
                    ("S-1-16-8192", SE_GROUP_INTEGRITY | SE_GROUP_ENABLED),
                ],
            );
            let g = token_groups(b.record()).unwrap();
            let summary: Vec<(&str, bool)> =
                g.iter().map(|g| (g.sid.as_str(), g.deny_only)).collect();
            assert_eq!(
                summary,
                [
                    ("S-1-1-0", false),
                    ("S-1-5-32-544", true),
                    // Present but not enabled: never plain membership.
                    ("S-1-5-32-545", true),
                ],
                "ptr {ptr}"
            );
        }
        let empty = groups(8, &[]);
        assert!(token_groups(empty.record()).unwrap().is_empty());
    }

    #[test]
    fn malformed_groups_are_errors() {
        // More groups than the record holds.
        let mut b = groups(8, &[("S-1-1-0", SE_GROUP_ENABLED)]);
        b.bytes[..4].copy_from_slice(&1000_u32.to_le_bytes());
        assert_eq!(
            token_groups(b.record()).unwrap_err().kind(),
            ErrorKind::Other
        );
        let mut b = groups(8, &[("S-1-1-0", SE_GROUP_ENABLED)]);
        b.bytes[..4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(token_groups(b.record()).is_err());
        // A SID pointer before the record, past it, or at a truncated SID.
        for bad in [BASE - 1, 0, BASE + 4096] {
            let mut b = Builder::new(8);
            b.u32(1).pad().pointer(bad).u32(SE_GROUP_ENABLED).pad();
            assert!(token_groups(b.record()).is_err(), "{bad:#x}");
        }
        let mut b = Builder::new(8);
        let at = BASE + 24;
        b.u32(1).pad().pointer(at).u32(SE_GROUP_ENABLED).pad();
        b.raw(&sid("S-1-5-21-1-2-3")[..10]);
        assert!(token_groups(b.record()).is_err());
        assert!(token_groups(Builder::new(8).record()).is_err());
    }

    #[test]
    fn integrity_levels() {
        for (rid, level) in [
            (0x0000, IntegrityLevel::Untrusted),
            (0x1000, IntegrityLevel::Low),
            (0x2000, IntegrityLevel::Medium),
            (0x2100, IntegrityLevel::MediumPlus),
            (0x3000, IntegrityLevel::High),
            (0x4000, IntegrityLevel::System),
            (0x5000, IntegrityLevel::Protected),
            // Between the standard levels: the level below.
            (0x0FFF, IntegrityLevel::Untrusted),
            (0x2FFF, IntegrityLevel::MediumPlus),
            (0x3010, IntegrityLevel::High),
        ] {
            assert_eq!(integrity_from_rid(rid), level, "{rid:#x}");
        }
        let b = sid_and_attributes(8, "S-1-16-12288", SE_GROUP_INTEGRITY);
        assert_eq!(token_integrity(b.record()).unwrap(), IntegrityLevel::High);
        // Not an integrity SID.
        for text in ["S-1-5-18", "S-1-16-8192-1", "S-1-16"] {
            let b = sid_and_attributes(8, text, SE_GROUP_INTEGRITY);
            assert!(token_integrity(b.record()).is_err(), "{text}");
        }
    }

    #[test]
    fn elevation_types() {
        assert_eq!(elevation_type(1).unwrap(), Elevation::Default);
        assert_eq!(elevation_type(2).unwrap(), Elevation::Full);
        assert_eq!(elevation_type(3).unwrap(), Elevation::Limited);
        // An unknown value is never read as "not elevated".
        assert!(elevation_type(0).is_err());
        assert!(elevation_type(4).is_err());
    }

    #[test]
    fn session_kinds() {
        assert_eq!(session_kind(0, Some(0)), SessionKind::Services);
        assert_eq!(session_kind(0, None), SessionKind::Services);
        assert_eq!(session_kind(1, Some(0)), SessionKind::Console);
        assert_eq!(session_kind(2, Some(2)), SessionKind::RemoteDesktop);
        // ICA, an unknown protocol, or a failed query.
        assert_eq!(session_kind(3, Some(1)), SessionKind::Unknown);
        assert_eq!(session_kind(3, Some(9)), SessionKind::Unknown);
        assert_eq!(session_kind(3, None), SessionKind::Unknown);
    }

    #[test]
    fn file_times_convert_to_utc() {
        assert_eq!(filetime_to_utc(116_444_736_000_000_000), UtcTime(0));
        // 2025-01-01T00:00:00.1234567Z: sub-microsecond ticks round down.
        assert_eq!(
            filetime_to_utc(133_801_632_001_234_567),
            UtcTime(1_735_689_600_123_456)
        );
        // Before 1970, rounding towards negative infinity.
        assert_eq!(filetime_to_utc(116_444_735_999_999_999), UtcTime(-1));
        assert_eq!(filetime_to_utc(0), UtcTime(-11_644_473_600_000_000));
        assert!(filetime_to_utc(u64::MAX).0 > 0);
    }

    #[test]
    fn parent_process_ids() {
        for ptr in [4, 8] {
            let mut b = Builder::new(ptr);
            b.u32(0).pad();
            for value in [0x1234, 1, 2, 4, 772] {
                b.pointer(value);
            }
            assert_eq!(parent_pid(b.record()).unwrap(), Some(772), "ptr {ptr}");
            let mut none = Builder::new(ptr);
            none.u32(0).pad();
            for value in [0, 0, 0, 4, 0] {
                none.pointer(value);
            }
            assert_eq!(parent_pid(none.record()).unwrap(), None);
            let mut short = Builder::new(ptr);
            short.u32(0).pad().pointer(0);
            assert!(parent_pid(short.record()).is_err());
        }
        let mut wide = Builder::new(8);
        wide.u32(0).pad();
        for value in [0, 0, 0, 4, 1 << 33] {
            wide.pointer(value);
        }
        assert!(parent_pid(wide.record()).is_err());
    }

    fn unicode(ptr: usize, text: &[u16]) -> Builder {
        let mut b = Builder::new(ptr);
        let len = u16::try_from(text.len() * 2).unwrap();
        b.u16(len).u16(len + 2).pad();
        let at = b.here() + ptr;
        b.pointer(at);
        for u in text {
            b.u16(*u);
        }
        b.u16(0);
        b
    }

    #[test]
    fn command_lines() {
        for ptr in [4, 8] {
            let text: Vec<u16> = r#""C:\Tools\a b.exe" /x ü"#.encode_utf16().collect();
            let b = unicode(ptr, &text);
            assert_eq!(
                unicode_string(b.record(), "cmd").unwrap(),
                r#""C:\Tools\a b.exe" /x ü"#
            );
            let empty = unicode(ptr, &[]);
            assert_eq!(unicode_string(empty.record(), "cmd").unwrap(), "");
        }
        // A lone surrogate is an error, not U+FFFD.
        let b = unicode(8, &[0x61, 0xD800, 0x62]);
        assert!(unicode_string(b.record(), "cmd").is_err());
        // A length past the record, an odd length, a buffer outside it.
        let mut b = unicode(8, &[0x61]);
        b.bytes[..2].copy_from_slice(&400_u16.to_le_bytes());
        assert!(unicode_string(b.record(), "cmd").is_err());
        let mut b = unicode(8, &[0x61]);
        b.bytes[..2].copy_from_slice(&1_u16.to_le_bytes());
        assert!(unicode_string(b.record(), "cmd").is_err());
        let mut b = Builder::new(8);
        b.u16(2).u16(4).pad().pointer(BASE - 64);
        assert!(unicode_string(b.record(), "cmd").is_err());
        assert!(unicode_string(Builder::new(8).record(), "cmd").is_err());
    }

    #[test]
    fn unicode_string_headers_are_checked() {
        for ptr in [4, 8] {
            // Only `Length`, or `Length` and `MaximumLength`: truncated,
            // even when the length is zero.
            for short in [&[0_u8, 0][..], &[0, 0, 0, 0]] {
                let mut b = Builder::new(ptr);
                b.raw(short);
                assert!(unicode_string(b.record(), "cmd").is_err(), "{short:?}");
            }
            // A complete header with length zero is the empty string.
            let mut b = Builder::new(ptr);
            b.u16(0).u16(0).pad().pointer(0);
            assert_eq!(unicode_string(b.record(), "cmd").unwrap(), "");
            // `Length` above `MaximumLength`.
            let mut b = unicode(ptr, &[0x61, 0x62]);
            b.bytes[2..4].copy_from_slice(&2_u16.to_le_bytes());
            assert!(unicode_string(b.record(), "cmd").is_err());
            // A buffer pointing into the header.
            for into in [0, 2, ptr] {
                let mut b = Builder::new(ptr);
                b.u16(4)
                    .u16(4)
                    .pad()
                    .pointer(BASE + into)
                    .raw(&[0x61, 0, 0x62, 0]);
                assert!(
                    unicode_string(b.record(), "cmd").is_err(),
                    "ptr {ptr} at {into}"
                );
            }
        }
    }

    #[test]
    fn local_group_matches_only_the_requested_alias() {
        let ops = Sid::from_str("S-1-5-21-1-2-3-1100").unwrap();
        let other = Sid::from_str("S-1-5-21-9-9-9-1100").unwrap();
        assert!(is_requested_local_group(&ops, &ops.to_bytes(), 4));
        // A local `Ops` with another SID (`DOMAIN\Ops` resolved, but the
        // bare name is a different local group).
        assert!(!is_requested_local_group(&ops, &other.to_bytes(), 4));
        // The right SID, but not a local group (a user, a domain group).
        for kind in [1, 2, 5] {
            assert!(!is_requested_local_group(&ops, &ops.to_bytes(), kind));
        }
        // Malformed, or with trailing bytes.
        assert!(!is_requested_local_group(&ops, &[], 4));
        let mut long = ops.to_bytes();
        long.push(0);
        assert!(!is_requested_local_group(&ops, &long, 4));
    }

    #[test]
    fn sid_arguments() {
        assert_eq!(parse_sid("S-1-5-18").unwrap().to_string(), "S-1-5-18");
        for bad in ["", "S-1", "Administrators", "S-1-5-18\0"] {
            assert_eq!(
                parse_sid(bad).unwrap_err().kind(),
                ErrorKind::InvalidInput,
                "{bad:?}"
            );
        }
    }
}
