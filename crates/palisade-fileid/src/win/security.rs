//! Security descriptor reads and the OS access check (#54).
//!
//! - [`read_descriptor`]: the owner, group and DACL of an open file or
//!   folder (`GetSecurityInfo`), as the self-relative bytes
//!   [`crate::fsctx::SecurityDescriptor::from_self_relative`] parses.
//! - [`account_name`]: `DOMAIN\name` for a SID (`LookupAccountSidW`), with
//!   [`NameCache`] so each SID is looked up once.
//! - [`access_check`]: the rights a synthetic token of chosen SIDs is
//!   granted on a descriptor, by the OS's own access check
//!   (`AuthzAccessCheck`). It is the authoritative answer on Windows, and
//!   [`crate::win::access::cross_check_writability`] compares it with the
//!   portable evaluator.
//! - [`set_security_sddl`]: replaces a file's DACL, and its owner when the
//!   SDDL names one, from SDDL text, for building test fixtures and for the
//!   agent's own data directory (#61).
//!
//! The access check never touches the file: it evaluates the descriptor
//! bytes it is given against a token made from SIDs alone
//! (`AUTHZ_SKIP_TOKEN_GROUPS`), so no real account has to exist or log on.

#![allow(unsafe_code)]

use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::os::windows::io::AsRawHandle as _;

use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, LUID, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    AUTHZ_ACCESS_REPLY, AUTHZ_ACCESS_REQUEST, AUTHZ_CLIENT_CONTEXT_HANDLE,
    AUTHZ_RESOURCE_MANAGER_HANDLE, AUTHZ_RM_FLAG_NO_AUDIT, AUTHZ_SKIP_TOKEN_GROUPS,
    AuthzAccessCheck, AuthzAddSidsToContext, AuthzFreeContext, AuthzFreeResourceManager,
    AuthzInitializeContextFromSid, AuthzInitializeResourceManager,
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
    SE_FILE_OBJECT, SetSecurityInfo,
};
use windows_sys::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, GetSecurityDescriptorDacl,
    GetSecurityDescriptorLength, GetSecurityDescriptorOwner, LookupAccountSidW,
    OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    SID_AND_ATTRIBUTES, SID_NAME_USE,
};

use crate::fsctx::Sid;

/// `MAXIMUM_ALLOWED`: ask the access check for every right it would grant.
const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
/// `SE_GROUP_ENABLED`.
const SE_GROUP_ENABLED: u32 = 0x0000_0004;

/// Memory the OS allocated with `LocalAlloc`, freed on drop.
struct LocalBuf(*mut core::ffi::c_void);

impl Drop for LocalBuf {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: `self.0` was returned by an OS call that allocates
            // with `LocalAlloc` and hands ownership to the caller; it is
            // freed once, here.
            let _ = unsafe { LocalFree(self.0) };
        }
    }
}

/// Copies the self-relative descriptor at `sd` into owned bytes.
///
/// # Safety
///
/// `sd` must point to a valid self-relative security descriptor that stays
/// alive for the call.
unsafe fn descriptor_bytes(sd: PSECURITY_DESCRIPTOR) -> Vec<u8> {
    // SAFETY: the caller guarantees `sd` is a valid self-relative
    // descriptor; the call only reads its header to compute the length.
    let len = unsafe { GetSecurityDescriptorLength(sd) };
    let len = usize::try_from(len).unwrap_or(0);
    // SAFETY: a valid self-relative descriptor is `len` contiguous bytes
    // starting at `sd`, alive for the call; they are copied out at once.
    unsafe { std::slice::from_raw_parts(sd.cast::<u8>().cast_const(), len) }.to_vec()
}

/// The owner, group and DACL of the open `file` (a file or a folder), as
/// self-relative bytes.
///
/// `file` must have been opened with `READ_CONTROL`, which a normal read
/// open includes. The SACL (and so the integrity label) is not read; the
/// writability model ignores it, which can only over-report.
pub fn read_descriptor(file: &File) -> io::Result<Vec<u8>> {
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: `file` is an open handle borrowed for the call. The owner,
    // group, DACL and SACL out-pointers are null, which the API allows when
    // only the whole descriptor is wanted. `sd` is a live local the OS sets
    // to a `LocalAlloc` buffer, owned by `LocalBuf` below.
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &raw mut sd,
        )
    };
    let _owned = LocalBuf(sd);
    if status != 0 {
        return Err(io::Error::from_raw_os_error(
            i32::try_from(status).unwrap_or(i32::MAX),
        ));
    }
    if sd.is_null() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "no descriptor"));
    }
    // SAFETY: `GetSecurityInfo` returned a valid self-relative descriptor in
    // `sd`, which `_owned` keeps alive until the end of this function.
    Ok(unsafe { descriptor_bytes(sd) })
}

/// A self-relative descriptor parsed from SDDL by the OS, owned.
struct SddlDescriptor(LocalBuf);

impl SddlDescriptor {
    fn parse(sddl: &str) -> io::Result<Self> {
        let wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
        if wide.iter().rev().skip(1).any(|&u| u == 0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SDDL contains a NUL",
            ));
        }
        let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: `wide` is a NUL-terminated UTF-16 string alive for the
        // call. `sd` is a live local the OS sets to a `LocalAlloc` buffer,
        // owned by the returned value; the size out-pointer is null, which
        // the API allows.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                SDDL_REVISION_1,
                &raw mut sd,
                std::ptr::null_mut(),
            )
        };
        let owned = Self(LocalBuf(sd));
        if ok == 0 || sd.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(owned)
    }

    fn ptr(&self) -> PSECURITY_DESCRIPTOR {
        self.0.0
    }
}

/// The self-relative bytes of the descriptor in `sddl`, as the OS parses
/// it. For tests and fixtures.
pub fn sddl_to_bytes(sddl: &str) -> io::Result<Vec<u8>> {
    let sd = SddlDescriptor::parse(sddl)?;
    // SAFETY: `sd` holds a valid self-relative descriptor the OS just
    // built, alive for the call.
    Ok(unsafe { descriptor_bytes(sd.ptr()) })
}

/// Replaces the DACL of the open `file` with the DACL in `sddl` (for
/// example `O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)`), protected from inheritance,
/// and its owner with the owner in `sddl` if there is one.
///
/// `file` must have been opened with `WRITE_DAC`, and with `WRITE_OWNER`
/// when an owner is set; the new owner must be a SID the caller's token may
/// assign.
pub fn set_security_sddl(file: &File, sddl: &str) -> io::Result<()> {
    let sd = SddlDescriptor::parse(sddl)?;
    let mut owner: PSID = std::ptr::null_mut();
    let mut owner_defaulted = 0;
    // SAFETY: `sd` holds a valid descriptor; the out-pointers are live
    // locals. `owner` is set to point inside `sd`'s buffer (or to null),
    // which stays alive until `sd` is dropped at the end of this function.
    let ok =
        unsafe { GetSecurityDescriptorOwner(sd.ptr(), &raw mut owner, &raw mut owner_defaulted) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    let (mut present, mut defaulted) = (0, 0);
    let mut dacl: *mut ACL = std::ptr::null_mut();
    // SAFETY: `sd` holds a valid descriptor; the out-pointers are live
    // locals. `dacl` is set to point inside `sd`'s buffer, which stays
    // alive until `sd` is dropped at the end of this function.
    let ok = unsafe {
        GetSecurityDescriptorDacl(
            sd.ptr(),
            &raw mut present,
            &raw mut dacl,
            &raw mut defaulted,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    if present == 0 || dacl.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "SDDL has no DACL",
        ));
    }
    let mut info = DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION;
    if !owner.is_null() {
        info |= OWNER_SECURITY_INFORMATION;
    }
    // SAFETY: `file` is an open handle borrowed for the call, and `dacl`
    // and `owner` (when not null) point into `sd`'s live buffer (see above).
    // Group and SACL are null and not set.
    let status = unsafe {
        SetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            info,
            owner,
            std::ptr::null_mut(),
            dacl,
            std::ptr::null(),
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(
            i32::try_from(status).unwrap_or(i32::MAX),
        ));
    }
    Ok(())
}

/// The account name of `sid`, as `DOMAIN\name` (or just `name` when there
/// is no domain), or `None` if the OS cannot map it. A lookup of a domain
/// SID can contact a domain controller, so cache the results
/// ([`NameCache`]).
pub fn account_name(sid: &Sid) -> Option<String> {
    let mut bytes = sid.to_bytes();
    let psid: PSID = bytes.as_mut_ptr().cast();
    let (mut name_len, mut domain_len) = (0_u32, 0_u32);
    let mut use_: SID_NAME_USE = 0;
    // SAFETY: `bytes` is a valid binary SID (from `Sid::to_bytes`) alive
    // for the call. With null buffers and zero lengths the OS only writes
    // the needed lengths into the two live locals.
    let ok = unsafe {
        LookupAccountSidW(
            std::ptr::null(),
            psid,
            std::ptr::null_mut(),
            &raw mut name_len,
            std::ptr::null_mut(),
            &raw mut domain_len,
            &raw mut use_,
        )
    };
    let e = io::Error::last_os_error();
    if ok != 0 || e.raw_os_error() != i32::try_from(ERROR_INSUFFICIENT_BUFFER).ok() {
        return None;
    }
    let cap = |n: u32| usize::try_from(n).ok().filter(|&n| n > 0 && n <= 1024);
    let mut name = vec![0_u16; cap(name_len)?];
    let mut domain = vec![0_u16; cap(domain_len).unwrap_or(1)];
    let (mut nl, mut dl) = (
        u32::try_from(name.len()).ok()?,
        u32::try_from(domain.len()).ok()?,
    );
    // SAFETY: as above, with `name` and `domain` live, writable buffers of
    // `nl` and `dl` UTF-16 units, the lengths passed.
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
    if ok == 0 {
        return None;
    }
    let text = |b: &[u16], n: u32| {
        let n = usize::try_from(n).unwrap_or(0).min(b.len());
        String::from_utf16_lossy(b.get(..n).unwrap_or_default())
    };
    let (name, domain) = (text(&name, nl), text(&domain, dl));
    Some(if domain.is_empty() {
        name
    } else {
        format!("{domain}\\{name}")
    })
}

/// [`account_name`] results by SID, including failed lookups, so each SID
/// is looked up once.
#[derive(Debug, Default, Clone)]
pub struct NameCache(HashMap<Sid, Option<String>>);

impl NameCache {
    /// The account name of `sid`, looked up on first use.
    pub fn name(&mut self, sid: &Sid) -> Option<String> {
        self.0
            .entry(*sid)
            .or_insert_with(|| account_name(sid))
            .clone()
    }
}

struct ResourceManager(AUTHZ_RESOURCE_MANAGER_HANDLE);

impl Drop for ResourceManager {
    fn drop(&mut self) {
        // SAFETY: the handle was created by `AuthzInitializeResourceManager`
        // and is freed once, here, after every context made from it.
        let _ = unsafe { AuthzFreeResourceManager(self.0) };
    }
}

struct ClientContext(AUTHZ_CLIENT_CONTEXT_HANDLE);

impl Drop for ClientContext {
    fn drop(&mut self) {
        // SAFETY: the handle was created by an `AuthzInitializeContext*` or
        // `AuthzAddSidsToContext` call and is freed once, here.
        let _ = unsafe { AuthzFreeContext(self.0) };
    }
}

/// The access mask the OS access check grants a token holding exactly
/// `sids` (the first is the user, the rest enabled groups) on the
/// self-relative descriptor `descriptor`.
///
/// The token is synthetic (`AUTHZ_SKIP_TOKEN_GROUPS`): its groups are only
/// those given, none are looked up. If one of `sids` is the descriptor's
/// owner, the owner's implicit rights apply, as for a real token.
pub fn access_check(descriptor: &[u8], sids: &[Sid]) -> io::Result<u32> {
    let (user, groups) = sids
        .split_first()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no SIDs"))?;
    // The descriptor must be a valid self-relative descriptor before the OS
    // reads it; the portable parser checks every offset.
    let mut parsed = crate::fsctx::SecurityDescriptor::from_self_relative(descriptor)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    // The OS access check needs an owner and a group. A missing owner is
    // given the NULL SID, which no token holds, so no owner rights apply
    // (the portable model reports the unknown owner's rights as uncertain).
    // A missing group is set to the owner; the group affects only ACEs for
    // CREATOR GROUP, which never apply to an existing object.
    let rebuilt;
    let descriptor = if parsed.owner.is_none() || parsed.group.is_none() {
        let owner = parsed.owner.unwrap_or(crate::fsctx::sid::well_known::NULL);
        parsed.owner = Some(owner);
        parsed.group = parsed.group.or(Some(owner));
        rebuilt = parsed.to_self_relative().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "descriptor cannot be rebuilt")
        })?;
        rebuilt.as_slice()
    } else {
        descriptor
    };
    // An owned, 8-byte aligned copy, as the OS expects.
    let mut sd: Vec<u64> = descriptor
        .chunks(8)
        .map(|c| {
            let mut word = [0_u8; 8];
            if let Some(prefix) = word.get_mut(..c.len()) {
                prefix.copy_from_slice(c);
            }
            u64::from_le_bytes(word)
        })
        .collect();

    let mut rm: AUTHZ_RESOURCE_MANAGER_HANDLE = std::ptr::null_mut();
    // SAFETY: no callbacks and no name; `rm` is a live local the OS sets to
    // a handle owned by `ResourceManager` below.
    let ok = unsafe {
        AuthzInitializeResourceManager(
            AUTHZ_RM_FLAG_NO_AUDIT,
            None,
            None,
            None,
            std::ptr::null(),
            &raw mut rm,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    let rm = ResourceManager(rm);

    let mut user_bytes = user.to_bytes();
    let mut ctx: AUTHZ_CLIENT_CONTEXT_HANDLE = std::ptr::null_mut();
    // SAFETY: `user_bytes` is a valid binary SID alive for the call; `rm` is
    // the live resource manager; `ctx` is a live local set to a handle owned
    // by `ClientContext` below. No expiry and no dynamic groups.
    let ok = unsafe {
        AuthzInitializeContextFromSid(
            AUTHZ_SKIP_TOKEN_GROUPS,
            user_bytes.as_mut_ptr().cast(),
            rm.0,
            std::ptr::null(),
            LUID {
                LowPart: 0,
                HighPart: 0,
            },
            std::ptr::null(),
            &raw mut ctx,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut ctx = ClientContext(ctx);

    if !groups.is_empty() {
        let mut group_bytes: Vec<Vec<u8>> = groups.iter().map(Sid::to_bytes).collect();
        let attrs: Vec<SID_AND_ATTRIBUTES> = group_bytes
            .iter_mut()
            .map(|b| SID_AND_ATTRIBUTES {
                Sid: b.as_mut_ptr().cast(),
                Attributes: SE_GROUP_ENABLED,
            })
            .collect();
        let count = u32::try_from(attrs.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "too many SIDs"))?;
        let mut with_groups: AUTHZ_CLIENT_CONTEXT_HANDLE = std::ptr::null_mut();
        // SAFETY: `attrs` holds `count` entries, each pointing into a
        // binary SID in `group_bytes`, all alive for the call (the OS copies
        // them into the new context). No restricted SIDs. `with_groups` is a
        // live local set to a new handle owned below.
        let ok = unsafe {
            AuthzAddSidsToContext(
                ctx.0,
                attrs.as_ptr(),
                count,
                std::ptr::null(),
                0,
                &raw mut with_groups,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        ctx = ClientContext(with_groups);
    }

    let request = AUTHZ_ACCESS_REQUEST {
        DesiredAccess: MAXIMUM_ALLOWED,
        ..AUTHZ_ACCESS_REQUEST::default()
    };
    let mut granted = 0_u32;
    let mut error = 0_u32;
    let mut reply = AUTHZ_ACCESS_REPLY {
        ResultListLength: 1,
        GrantedAccessMask: &raw mut granted,
        SaclEvaluationResults: std::ptr::null_mut(),
        Error: &raw mut error,
    };
    // SAFETY: `ctx` is the live client context; `request` asks for
    // `MAXIMUM_ALLOWED` with no object types; `sd` is an owned, aligned
    // copy of a descriptor the portable parser accepted, alive for the
    // call; no extra descriptors and no audit event. `reply` has one result
    // whose mask and error point at live locals. No result handle is asked
    // for.
    let ok = unsafe {
        AuthzAccessCheck(
            0,
            ctx.0,
            &raw const request,
            std::ptr::null_mut(),
            sd.as_mut_ptr().cast(),
            std::ptr::null(),
            0,
            &raw mut reply,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    drop(ctx);
    drop(rm);
    Ok(granted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fsctx::sid::well_known as wk;
    use crate::fsctx::{SecurityDescriptor, acl::mask};

    const FILE_WRITE_DATA: u32 = 0x2;

    #[test]
    fn access_check_matches_simple_dacls() {
        let user = Sid::new(5, &[21, 1, 2, 3, 1001]).unwrap();
        let token = [user, wk::EVERYONE, wk::USERS, wk::AUTHENTICATED_USERS];
        // Users may modify.
        let open = sddl_to_bytes("O:BAD:(A;;0x1301BF;;;BU)").unwrap();
        let g = access_check(&open, &token).unwrap();
        assert_ne!(g & FILE_WRITE_DATA, 0, "{g:#x}");
        // Users read only.
        let locked = sddl_to_bytes("O:BAD:(A;;FA;;;BA)(A;;0x1200A9;;;BU)").unwrap();
        let g = access_check(&locked, &token).unwrap();
        assert_eq!(g & FILE_WRITE_DATA, 0, "{g:#x}");
        // A deny before an allow wins.
        let denied = sddl_to_bytes("O:BAD:(D;;WD;;;WD)(A;;0x1301BF;;;BU)").unwrap();
        let g = access_check(&denied, &token).unwrap();
        assert_eq!(g & FILE_WRITE_DATA, 0, "{g:#x}");
        // The owner gets WRITE_DAC implicitly.
        let owned = sddl_to_bytes("D:(A;;0x1200A9;;;WD)").unwrap();
        let mut sd = SecurityDescriptor::from_self_relative(&owned).unwrap();
        sd.owner = Some(user);
        let g = access_check(&sd.to_self_relative().unwrap(), &token).unwrap();
        assert_ne!(g & mask::WRITE_DAC, 0, "{g:#x}");
        // Garbage is rejected before the OS sees it.
        assert!(access_check(b"junk", &token).is_err());
        assert!(access_check(&open, &[]).is_err());
    }

    #[test]
    fn names_and_descriptors() {
        let mut names = NameCache::default();
        let system = names.name(&wk::LOCAL_SYSTEM).unwrap();
        assert!(system.to_ascii_uppercase().contains("SYSTEM"), "{system}");
        assert_eq!(names.name(&wk::LOCAL_SYSTEM), Some(system));
        let unknown = Sid::new(5, &[21, 9, 9, 9, 4242]).unwrap();
        assert_eq!(names.name(&unknown), None);

        let dir = std::env::temp_dir().join(format!("palisade-win-sec-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("f.txt");
        std::fs::write(&path, b"x").unwrap();
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        set_security_sddl(
            &file,
            "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)(A;;0x1301BF;;;BU)",
        )
        .unwrap();
        let bytes = read_descriptor(&file).unwrap();
        let sd = SecurityDescriptor::from_self_relative(&bytes).unwrap();
        assert!(sd.owner.is_some());
        let aces = sd.dacl.unwrap();
        assert!(aces.iter().any(|a| a.sid == Some(wk::USERS)));
        assert!(set_security_sddl(&file, "not sddl").is_err());
        drop(file);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
