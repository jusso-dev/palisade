//! [`IdentityProvider`] through the OS.

use std::collections::BTreeMap;
use std::sync::{PoisonError, RwLock};

use palisade_core::platform::{
    AccountName, DirectoryGroups, ErrorKind, IdentityProvider, PlatformError, ProcessKey, Result,
    TokenInfo,
};
use palisade_fileid::fsctx::Sid;
use palisade_fileid::win::security::account_name;
use windows_sys::Win32::Foundation::ERROR_NO_SUCH_ALIAS;
use windows_sys::Win32::NetworkManagement::NetManagement::NERR_GroupNotFound as NERR_GROUP_NOT_FOUND;
use windows_sys::Win32::Security::{
    SidTypeAlias, TokenElevation, TokenElevationType, TokenGroups, TokenIntegrityLevel,
    TokenSessionId, TokenUser,
};

use super::os_error;
use super::process::open_key;
use crate::ffi::{self, Process, Token};
use crate::platform::nt::{self, Record};

/// Users, groups and sessions through the OS.
///
/// Tokens are read in full or not at all: if any part of a token cannot be
/// read (the user, the groups, the integrity level, the elevation type),
/// the query fails, so a caller never sees a token with a part guessed
/// (ADR 0018). The one exception is the session kind, which is
/// [`SessionKind::Unknown`](palisade_core::platform::SessionKind::Unknown)
/// when the OS cannot say how a session was started.
///
/// A group that is present in a token but not enabled is reported as
/// deny-only, like a group UAC filtered: the OS does not use it to grant
/// access.
///
/// Directory groups (#38) come from a cache the directory sync fills
/// through [`WindowsIdentity::cache_directory_groups`].
#[derive(Debug, Default)]
pub struct WindowsIdentity {
    directory: RwLock<BTreeMap<Sid, DirectoryGroups>>,
}

impl WindowsIdentity {
    /// An identity provider with an empty directory group cache.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Caches the directory groups of `user_sid`, replacing any cached
    /// before.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::InvalidInput`] if `user_sid` is not a SID.
    pub fn cache_directory_groups(&self, user_sid: &str, groups: DirectoryGroups) -> Result<()> {
        let sid = nt::parse_sid(user_sid)?;
        self.directory
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(sid, groups);
        Ok(())
    }
}

/// Reads every part of `token`.
fn token_info(token: &Token) -> Result<TokenInfo> {
    let read = |class, what: &str| token.information(class).map_err(|e| os_error(&e, what));
    let user = read(TokenUser, "token user")?;
    let groups = read(TokenGroups, "token groups")?;
    let integrity = read(TokenIntegrityLevel, "token integrity level")?;
    let session = read(TokenSessionId, "token session")?;
    let elevation_type = read(TokenElevationType, "token elevation type")?;
    let elevation = read(TokenElevation, "token elevation")?;

    let session_id = nt::dword(&session.bytes, "TokenSessionId")?;
    Ok(TokenInfo {
        user_sid: nt::token_user(Record::new(&user.bytes, user.base))?,
        groups: nt::token_groups(Record::new(&groups.bytes, groups.base))?,
        session_id,
        // A failed protocol query is "unknown", never the console.
        session_kind: nt::session_kind(session_id, ffi::session_protocol(session_id).ok()),
        integrity: nt::token_integrity(Record::new(&integrity.bytes, integrity.base))?,
        elevation: nt::elevation_type(nt::dword(&elevation_type.bytes, "TokenElevationType")?)?,
        elevated: nt::dword(&elevation.bytes, "TokenElevation")? != 0,
    })
}

fn not_a_local_group(sid: &Sid) -> PlatformError {
    PlatformError::not_found(format!("{sid} is not a local group"))
}

impl IdentityProvider for WindowsIdentity {
    fn token(&self, process: ProcessKey) -> Result<TokenInfo> {
        // The token is read through the handle that `open_key` checked, so
        // it belongs to `process`, not to a later process with its ID.
        let token = open_key(process)?
            .token()
            .map_err(|e| os_error(&e, "open process token"))?;
        token_info(&token)
    }

    fn current(&self) -> Result<TokenInfo> {
        let token = Process::current()
            .token()
            .map_err(|e| os_error(&e, "open own token"))?;
        token_info(&token)
    }

    fn account_name(&self, sid: &str) -> Result<Option<AccountName>> {
        let sid = nt::parse_sid(sid)?;
        Ok(account_name(&sid).map(|full| match full.split_once('\\') {
            Some((domain, name)) => AccountName {
                domain: Some(domain.to_owned()),
                name: name.to_owned(),
            },
            None => AccountName {
                domain: None,
                name: full,
            },
        }))
    }

    /// The OS lists a local group's members by name, so the SID is turned
    /// into a name and the name back into a SID first. Members are only
    /// listed if that name is a local group (an alias) with exactly this
    /// SID, so an account of another kind that shares the name is never
    /// listed in its place.
    fn local_group_members(&self, group_sid: &str) -> Result<Vec<String>> {
        let sid = nt::parse_sid(group_sid)?;
        let full = account_name(&sid).ok_or_else(|| not_a_local_group(&sid))?;
        let (resolved, kind) = ffi::lookup_account_name(&full).map_err(|e| os_error(&e, &full))?;
        let same = Sid::from_bytes(&resolved).is_ok_and(|(s, _)| s == sid);
        if !same || kind != SidTypeAlias {
            return Err(not_a_local_group(&sid));
        }
        let name = full.rsplit('\\').next().unwrap_or(&full);
        let members = ffi::local_group_members(name).map_err(|e| {
            match e.raw_os_error().and_then(|c| u32::try_from(c).ok()) {
                Some(NERR_GROUP_NOT_FOUND | ERROR_NO_SUCH_ALIAS) => not_a_local_group(&sid),
                _ => os_error(&e, "local group members"),
            }
        })?;
        members
            .iter()
            .map(|bytes| match Sid::from_bytes(bytes) {
                Ok((member, _)) => Ok(member.to_string()),
                Err(e) => Err(PlatformError::new(
                    ErrorKind::Other,
                    format!("malformed member SID of {sid}: {e}"),
                )),
            })
            .collect()
    }

    fn directory_groups(&self, user_sid: &str) -> Result<Option<DirectoryGroups>> {
        let sid = nt::parse_sid(user_sid)?;
        Ok(self
            .directory
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&sid)
            .cloned())
    }
}
