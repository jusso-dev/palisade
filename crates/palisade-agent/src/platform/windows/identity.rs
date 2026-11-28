//! [`IdentityProvider`] through the OS.

use std::collections::BTreeMap;
use std::sync::{PoisonError, RwLock};

use palisade_core::platform::{
    AccountName, DirectoryGroups, ErrorKind, IdentityProvider, PlatformError, ProcessKey, Result,
    TokenInfo,
};
use palisade_fileid::fsctx::Sid;
use windows_sys::Win32::Foundation::{ERROR_NO_SUCH_ALIAS, ERROR_NONE_MAPPED};
use windows_sys::Win32::NetworkManagement::NetManagement::NERR_GroupNotFound as NERR_GROUP_NOT_FOUND;
use windows_sys::Win32::Security::{
    TokenElevation, TokenElevationType, TokenGroups, TokenIntegrityLevel, TokenSessionId, TokenUser,
};

use super::os_error;
use super::process::open_key;
use crate::ffi::{self, MembersError, Process, Token};
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
    let dword = |class, what: &str| token.dword(class).map_err(|e| os_error(&e, what));
    let session_id = dword(TokenSessionId, "token session")?;
    let elevation_type = dword(TokenElevationType, "token elevation type")?;
    let elevated = dword(TokenElevation, "token elevation")?;

    Ok(TokenInfo {
        user_sid: nt::token_user(Record::new(&user.bytes, user.base))?,
        groups: nt::token_groups(Record::new(&groups.bytes, groups.base))?,
        session_id,
        // A failed protocol query is "unknown", never the console.
        session_kind: nt::session_kind(session_id, ffi::session_protocol(session_id).ok()),
        integrity: nt::token_integrity(Record::new(&integrity.bytes, integrity.base))?,
        elevation: nt::elevation_type(elevation_type)?,
        elevated: elevated != 0,
    })
}

/// `ERROR_NONE_MAPPED`, as `std::io::Error::raw_os_error` reports it.
const ERROR_NONE_MAPPED_CODE: i32 = ERROR_NONE_MAPPED.cast_signed();

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

    /// `None` only when no account has the SID. A lookup that fails for
    /// any other reason (an unreachable domain controller, say) is an
    /// error, so a transient failure is never read as "no such account".
    fn account_name(&self, sid: &str) -> Result<Option<AccountName>> {
        let sid = nt::parse_sid(sid)?;
        let found = ffi::lookup_account_sid(&sid.to_bytes())
            .map_err(|e| os_error(&e, &format!("account name of {sid}")))?;
        Ok(found.map(|(domain, name)| AccountName {
            domain: (!domain.is_empty()).then_some(domain),
            name,
        }))
    }

    /// The OS lists a local group's members by its bare name, so the SID
    /// is turned into a name first. Members are only listed if that bare
    /// name, resolved on this computer, is a local group (an alias) with
    /// exactly this SID. So neither an account of another kind, nor a
    /// different local group that shares the name of a domain group
    /// (`DOMAIN\Ops` against a local `Ops`), is ever listed in its place.
    fn local_group_members(&self, group_sid: &str) -> Result<Vec<String>> {
        let sid = nt::parse_sid(group_sid)?;
        let (_, name) = ffi::lookup_account_sid(&sid.to_bytes())
            .map_err(|e| os_error(&e, &format!("account name of {sid}")))?
            .ok_or_else(|| not_a_local_group(&sid))?;
        if !names_requested_group(&sid, &name)? {
            return Err(not_a_local_group(&sid));
        }
        let members = ffi::local_group_members(&name).map_err(|e| match e {
            MembersError::TooMany => PlatformError::new(
                ErrorKind::TooLarge,
                format!("{sid} has more than {} members", ffi::MAX_GROUP_MEMBERS),
            ),
            MembersError::Os(e) => match e.raw_os_error().and_then(|c| u32::try_from(c).ok()) {
                Some(NERR_GROUP_NOT_FOUND | ERROR_NO_SUCH_ALIAS) => not_a_local_group(&sid),
                _ => os_error(&e, "local group members"),
            },
        })?;
        // The enumeration took a name, not the SID: if the group was
        // renamed meanwhile and another took its name, the members read
        // may be the other group's. Check the name again, and fail rather
        // than return members that might not be this group's (#60, the
        // race left open in #322). A rename and a restore both inside the
        // window still pass; only an administrator can rename a local
        // group, and an administrator can change its members directly.
        if !names_requested_group(&sid, &name)? {
            return Err(PlatformError::new(
                ErrorKind::Other,
                format!("{sid} was renamed while its members were read"),
            ));
        }
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

/// Whether the bare `name`, resolved on this computer, is a local group
/// (an alias) with exactly the SID `sid`. A name that maps to nothing is
/// `false`; any other lookup failure is an error.
fn names_requested_group(sid: &Sid, name: &str) -> Result<bool> {
    match ffi::lookup_account_name(name) {
        Ok((local, kind)) => Ok(nt::is_requested_local_group(sid, &local, kind)),
        Err(e) if e.raw_os_error() == Some(ERROR_NONE_MAPPED_CODE) => Ok(false),
        Err(e) => Err(os_error(&e, name)),
    }
}
