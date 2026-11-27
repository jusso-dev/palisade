//! Security descriptors, ownership and the writability decision.
//!
//! The OS layer reads a file's security descriptor (owner and DACL) as the
//! self-relative bytes `GetSecurityInfo` / `GetFileSecurityW` return, and
//! [`SecurityDescriptor::from_self_relative`] turns them into an abstract
//! model. Everything after that is pure and runs on every OS:
//!
//! - [`evaluate`] works out which write-type rights any **non-administrator**
//!   principal may hold on one object;
//! - [`assess_path`] does that for a file and every ancestor folder up to the
//!   volume root and produces a [`Writability`] summary;
//! - [`OwnerInfo`] classifies the owner SID.
//!
//! # How the evaluation works
//!
//! The DACL is walked **in stored order**, as the OS access check does (a
//! non-canonical order is evaluated as stored and also reported). For a
//! token, each applicable ACE whose SID is in the token either grants the
//! bits not already denied, or denies the bits not already granted. ACEs
//! marked inherit-only apply only to future children and are skipped;
//! inherited ACEs are already materialised in the DACL and count like any
//! other.
//!
//! The tokens evaluated are:
//!
//! - one per distinct non-administrator SID named by an applicable allow ACE,
//!   holding that SID plus `Everyone`. This over-approximates every real
//!   non-administrator token that holds `Everyone`: take the first allow ACE
//!   that grants a right to a real token. No deny ACE before it applied to
//!   the real token, so none applied to the smaller token of that ACE's SID
//!   either, and that token is granted the right too. An anonymous token
//!   lacks `Everyone` by default and may hold `ANONYMOUS LOGON` and
//!   `NETWORK`, so `ANONYMOUS LOGON` is evaluated alone, and `NETWORK` both
//!   alone and with `Everyone`. A deny for `Everyone` is then not assumed
//!   to stop either;
//! - the object's owner, if it is not an administrator, with the owner's
//!   implicit `READ_CONTROL` and `WRITE_DAC` (which a deny ACE cannot
//!   remove), unless the DACL has an unconditional `OWNER RIGHTS`
//!   allow ACE, which then replaces them. A descriptor with no owner is
//!   treated as an unknown, possibly non-administrator owner;
//! - a synthetic standard user (by default `Everyone`, `Authenticated Users`,
//!   `BUILTIN\Users`, `INTERACTIVE` and `LOCAL`), reported on its own.
//!
//! # Conservative by construction
//!
//! When the model cannot tell, it reports the right as possibly held:
//!
//! - **Conditional (callback) allow ACEs** and **object allow ACEs** may
//!   apply; their rights are reported, and also listed as `uncertain`.
//!   Conditional and object **deny** ACEs are assumed not to apply when
//!   working out what may be held. They are assumed to apply when working
//!   out what is held for certain, so a right that such a deny may remove
//!   is `uncertain`, not certain.
//! - **Generic rights** (`GENERIC_WRITE`, `GENERIC_ALL`) in an allow ACE are
//!   mapped to the file rights they stand for. The OS access check does not
//!   map generic bits stored in an ACE, so such an ACE may in fact grant
//!   nothing; mapping it can only over-report, and a right that only a
//!   generic bit grants is `uncertain`. In a deny ACE they are not mapped,
//!   so they deny nothing, as in the OS.
//! - **ACE types the model does not know** grant every right, as uncertain,
//!   to an unknown principal.
//! - **A NULL or absent DACL** grants everyone everything.
//! - **An object whose descriptor could not be read** counts as writable.
//! - **Mandatory integrity labels** (in the SACL) are ignored. A label can
//!   only take rights away, so ignoring it only over-reports.
//!
//! The Windows access-check API (`AuthzAccessCheck` with a synthetic token)
//! is the authoritative method on Windows, with this evaluator as the
//! fallback and cross-check: `palisade_fileid::win::access::cross_check_writability`
//! compares the two on any descriptor (with the `os-trust` feature).
//!
//! # Owner-based trust needs the DACL too
//!
//! NTFS keeps a file's owner when its content is overwritten in place; the
//! owner only changes when a new file is created. So an administrator owner
//! says nothing about the content if a non-administrator can write to the
//! file (threat model T-engine-11, AT-19.5b). [`Writability::owner_trust_blockers`]
//! reports the rights (write, append, delete, `WRITE_DAC`, `WRITE_OWNER`)
//! that must be absent before owner-based trust (#117) may rely on the owner.
//! This module only provides the attributes; the trust decision is #9's.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fmt;

use super::sid::{Sid, SidError, well_known};

/// Access-mask bits used here (`winnt.h` values).
pub mod mask {
    /// `FILE_WRITE_DATA`; on a directory, `FILE_ADD_FILE`.
    pub const FILE_WRITE_DATA: u32 = 0x0000_0002;
    /// `FILE_APPEND_DATA`; on a directory, `FILE_ADD_SUBDIRECTORY`.
    pub const FILE_APPEND_DATA: u32 = 0x0000_0004;
    /// `FILE_WRITE_EA`: write extended attributes.
    pub const FILE_WRITE_EA: u32 = 0x0000_0010;
    /// `FILE_DELETE_CHILD`: delete any child of a directory, whatever the
    /// child's own DACL says.
    pub const FILE_DELETE_CHILD: u32 = 0x0000_0040;
    /// `FILE_WRITE_ATTRIBUTES`.
    pub const FILE_WRITE_ATTRIBUTES: u32 = 0x0000_0100;
    /// `DELETE`.
    pub const DELETE: u32 = 0x0001_0000;
    /// `READ_CONTROL`.
    pub const READ_CONTROL: u32 = 0x0002_0000;
    /// `WRITE_DAC`: change the DACL.
    pub const WRITE_DAC: u32 = 0x0004_0000;
    /// `WRITE_OWNER`: change the owner.
    pub const WRITE_OWNER: u32 = 0x0008_0000;
    /// `GENERIC_ALL`.
    pub const GENERIC_ALL: u32 = 0x1000_0000;
    /// `GENERIC_WRITE`.
    pub const GENERIC_WRITE: u32 = 0x4000_0000;
    /// `FILE_GENERIC_WRITE`, what `GENERIC_WRITE` maps to for files.
    pub const FILE_GENERIC_WRITE: u32 = 0x0012_0116;
    /// `FILE_ALL_ACCESS`, what `GENERIC_ALL` maps to for files.
    pub const FILE_ALL_ACCESS: u32 = 0x001F_01FF;
}

/// Whether an object is a file or a directory. Some bits mean different
/// things on each, and `FILE_DELETE_CHILD` only matters on a directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ObjectKind {
    /// A file (or a named stream).
    File,
    /// A directory.
    Directory,
}

/// A set of write-type rights, as an access mask restricted to
/// [`WriteRights::ALL`].
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct WriteRights(u32);

impl WriteRights {
    /// No rights.
    pub const NONE: Self = Self(0);
    /// Write data, or add a file to a directory.
    pub const WRITE_DATA: Self = Self(mask::FILE_WRITE_DATA);
    /// Append data, or add a subdirectory to a directory.
    pub const APPEND_DATA: Self = Self(mask::FILE_APPEND_DATA);
    /// Write extended attributes.
    pub const WRITE_EA: Self = Self(mask::FILE_WRITE_EA);
    /// Delete any child of a directory.
    pub const DELETE_CHILD: Self = Self(mask::FILE_DELETE_CHILD);
    /// Write basic attributes (timestamps, read-only, hidden and so on).
    pub const WRITE_ATTRIBUTES: Self = Self(mask::FILE_WRITE_ATTRIBUTES);
    /// Delete, or rename, the object.
    pub const DELETE: Self = Self(mask::DELETE);
    /// Change the DACL.
    pub const WRITE_DAC: Self = Self(mask::WRITE_DAC);
    /// Change the owner.
    pub const WRITE_OWNER: Self = Self(mask::WRITE_OWNER);

    /// Every right this module tracks.
    pub const ALL: Self = Self(
        mask::FILE_WRITE_DATA
            | mask::FILE_APPEND_DATA
            | mask::FILE_WRITE_EA
            | mask::FILE_DELETE_CHILD
            | mask::FILE_WRITE_ATTRIBUTES
            | mask::DELETE
            | mask::WRITE_DAC
            | mask::WRITE_OWNER,
    );

    /// `WRITE_DAC` and `WRITE_OWNER`: whoever holds either can change who
    /// else may write.
    pub const CHANGE_PERMISSIONS: Self = Self(mask::WRITE_DAC | mask::WRITE_OWNER);

    /// The rights that let a non-administrator change a file's content (or
    /// gain the means to) while NTFS keeps its owner (threat model
    /// T-engine-11): write, append, delete, `WRITE_DAC` and `WRITE_OWNER`.
    pub const OWNER_TRUST_BLOCKING: Self = Self(
        mask::FILE_WRITE_DATA
            | mask::FILE_APPEND_DATA
            | mask::DELETE
            | mask::WRITE_DAC
            | mask::WRITE_OWNER,
    );

    /// The rights that count for an object of this kind. A file has no
    /// children, so `FILE_DELETE_CHILD` is left out for files.
    #[must_use]
    pub const fn relevant(kind: ObjectKind) -> Self {
        match kind {
            ObjectKind::File => Self(Self::ALL.0 & !mask::FILE_DELETE_CHILD),
            ObjectKind::Directory => Self::ALL,
        }
    }

    /// The rights in an access mask (bits outside [`WriteRights::ALL`] are
    /// dropped).
    #[must_use]
    pub const fn from_mask(access_mask: u32) -> Self {
        Self(access_mask & Self::ALL.0)
    }

    /// The access-mask bits.
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// True if no right is set.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// True if every right in `other` is set.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// True if any right in `other` is set.
    #[must_use]
    pub const fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }

    /// The rights in either set.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// The rights in both sets.
    #[must_use]
    pub const fn intersection(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    /// The rights in `self` and not in `other`.
    #[must_use]
    pub const fn difference(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }

    /// The `winnt.h` name of each right that is set, in bit order. Bits
    /// 0x2 and 0x4 use their file names (`FILE_WRITE_DATA`,
    /// `FILE_APPEND_DATA`), which on a directory mean "add file" and "add
    /// subdirectory".
    #[must_use]
    pub fn names(self) -> Vec<&'static str> {
        const NAMES: [(u32, &str); 8] = [
            (mask::FILE_WRITE_DATA, "FILE_WRITE_DATA"),
            (mask::FILE_APPEND_DATA, "FILE_APPEND_DATA"),
            (mask::FILE_WRITE_EA, "FILE_WRITE_EA"),
            (mask::FILE_DELETE_CHILD, "FILE_DELETE_CHILD"),
            (mask::FILE_WRITE_ATTRIBUTES, "FILE_WRITE_ATTRIBUTES"),
            (mask::DELETE, "DELETE"),
            (mask::WRITE_DAC, "WRITE_DAC"),
            (mask::WRITE_OWNER, "WRITE_OWNER"),
        ];
        NAMES
            .iter()
            .filter(|(bit, _)| self.0 & bit != 0)
            .map(|(_, name)| *name)
            .collect()
    }
}

impl fmt::Debug for WriteRights {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "WriteRights({})", self)
    }
}

impl fmt::Display for WriteRights {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty() {
            return f.write_str("none");
        }
        f.write_str(&self.names().join("|"))
    }
}

/// ACE header flags (`AceFlags`).
pub mod ace_flags {
    /// Inherited by child files.
    pub const OBJECT_INHERIT: u8 = 0x01;
    /// Inherited by child directories.
    pub const CONTAINER_INHERIT: u8 = 0x02;
    /// Inherited by immediate children only.
    pub const NO_PROPAGATE_INHERIT: u8 = 0x04;
    /// Applies only to children, not to this object.
    pub const INHERIT_ONLY: u8 = 0x08;
    /// Inherited from a parent rather than set on this object.
    pub const INHERITED: u8 = 0x10;
}

/// What an ACE does, as far as this model is concerned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AceKind {
    /// `ACCESS_ALLOWED_ACE` (type 0).
    Allow,
    /// `ACCESS_DENIED_ACE` (type 1).
    Deny,
    /// A callback (conditional) allow ACE, types 9 and 11. Whether it
    /// applies depends on an expression the model does not evaluate.
    AllowConditional,
    /// A callback (conditional) deny ACE, types 10 and 12.
    DenyConditional,
    /// An object allow ACE (type 5), which may be limited to an object type.
    AllowObject,
    /// An object deny ACE (type 6).
    DenyObject,
    /// Any other ACE type. Its layout is unknown, so it has no SID or mask.
    Unknown(u8),
}

impl AceKind {
    fn is_allow(self) -> bool {
        matches!(
            self,
            Self::Allow | Self::AllowConditional | Self::AllowObject
        )
    }

    fn is_deny(self) -> bool {
        matches!(self, Self::Deny | Self::DenyConditional | Self::DenyObject)
    }
}

/// One access control entry.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Ace {
    /// The ACE type.
    pub kind: AceKind,
    /// The header flags (see [`ace_flags`]).
    pub flags: u8,
    /// The access mask. Zero for [`AceKind::Unknown`].
    pub mask: u32,
    /// The trustee. `None` only for [`AceKind::Unknown`].
    pub sid: Option<Sid>,
}

impl Ace {
    /// An `ACCESS_ALLOWED_ACE` with no flags.
    #[must_use]
    pub fn allow(sid: Sid, mask: u32) -> Self {
        Self {
            kind: AceKind::Allow,
            flags: 0,
            mask,
            sid: Some(sid),
        }
    }

    /// An `ACCESS_DENIED_ACE` with no flags.
    #[must_use]
    pub fn deny(sid: Sid, mask: u32) -> Self {
        Self {
            kind: AceKind::Deny,
            flags: 0,
            mask,
            sid: Some(sid),
        }
    }

    /// The same ACE with these header flags.
    #[must_use]
    pub fn with_flags(mut self, flags: u8) -> Self {
        self.flags = flags;
        self
    }

    /// True if the ACE applies to this object (it is not inherit-only).
    #[must_use]
    pub fn applies_to_object(&self) -> bool {
        self.flags & ace_flags::INHERIT_ONLY == 0
    }

    /// True if the ACE was inherited.
    #[must_use]
    pub fn is_inherited(&self) -> bool {
        self.flags & ace_flags::INHERITED != 0
    }
}

/// The parts of a security descriptor the writability check uses.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SecurityDescriptor {
    /// The owner. `None` if the descriptor has none.
    pub owner: Option<Sid>,
    /// The primary group. Not used by the evaluation.
    pub group: Option<Sid>,
    /// The DACL entries in stored order. `None` means there is no DACL (it
    /// is absent or NULL), which grants everyone every right. `Some` of an
    /// empty list grants nothing, apart from the owner's implicit rights.
    pub dacl: Option<Vec<Ace>>,
    /// The `SECURITY_DESCRIPTOR_CONTROL` bits, for diagnostics.
    pub control: u16,
}

/// `SECURITY_DESCRIPTOR_CONTROL` bits used here.
pub mod control {
    /// `SE_DACL_PRESENT`.
    pub const DACL_PRESENT: u16 = 0x0004;
    /// `SE_DACL_PROTECTED`: the DACL does not inherit from the parent.
    pub const DACL_PROTECTED: u16 = 0x1000;
    /// `SE_SELF_RELATIVE`.
    pub const SELF_RELATIVE: u16 = 0x8000;
}

/// The largest security descriptor accepted. The OS caps a self-relative
/// descriptor well below this; the limit bounds work on hostile input.
pub const MAX_DESCRIPTOR_BYTES: usize = 1 << 20;

impl SecurityDescriptor {
    /// A descriptor with this owner and DACL, and no group.
    #[must_use]
    pub fn new(owner: Option<Sid>, dacl: Option<Vec<Ace>>) -> Self {
        let control = if dacl.is_some() {
            control::SELF_RELATIVE | control::DACL_PRESENT
        } else {
            control::SELF_RELATIVE
        };
        Self {
            owner,
            group: None,
            dacl,
            control,
        }
    }

    /// Serialises to the self-relative form [`Self::from_self_relative`]
    /// reads: header, owner, group, then the DACL (revision 2, or 4 when it
    /// holds object ACEs). It is for building fixtures, not for
    /// round-tripping hostile input.
    ///
    /// Returns `None` if the DACL would exceed the 64 KiB an ACL can hold,
    /// or holds an ACE of unknown type, which cannot be serialised.
    #[must_use]
    pub fn to_self_relative(&self) -> Option<Vec<u8>> {
        let owner = self.owner.map(|s| s.to_bytes()).unwrap_or_default();
        let group = self.group.map(|s| s.to_bytes()).unwrap_or_default();
        let dacl = match &self.dacl {
            Some(aces) => Some(write_acl(aces)?),
            None => None,
        };
        let mut out = vec![0u8; 20];
        let mut control = self.control | control::SELF_RELATIVE;
        // With no DACL the offset stays zero. `DACL_PRESENT` is kept as
        // given: set, it is a NULL DACL; clear, the DACL is absent. Both
        // grant everyone everything.
        if dacl.is_some() {
            control |= control::DACL_PRESENT;
        }
        let put = |out: &mut Vec<u8>, at: usize, part: &[u8]| -> Option<()> {
            if part.is_empty() {
                return Some(());
            }
            let offset = u32::try_from(out.len()).ok()?;
            out.get_mut(at..at + 4)?
                .copy_from_slice(&offset.to_le_bytes());
            out.extend_from_slice(part);
            Some(())
        };
        put(&mut out, 4, &owner)?;
        put(&mut out, 8, &group)?;
        if let Some(d) = &dacl {
            put(&mut out, 16, d)?;
        }
        *out.get_mut(0)? = 1;
        out.get_mut(2..4)?.copy_from_slice(&control.to_le_bytes());
        Some(out)
    }
}

fn write_acl(aces: &[Ace]) -> Option<Vec<u8>> {
    let mut body = Vec::new();
    let mut count = 0u16;
    for ace in aces {
        let ace_type = match ace.kind {
            AceKind::Allow => 0x00,
            AceKind::Deny => 0x01,
            AceKind::AllowConditional => 0x09,
            AceKind::DenyConditional => 0x0A,
            AceKind::AllowObject => 0x05,
            AceKind::DenyObject => 0x06,
            // An unknown ACE cannot be written back; dropping it would
            // silently remove a fail-closed entry.
            AceKind::Unknown(_) => return None,
        };
        let sid = ace.sid?.to_bytes();
        let mut entry = vec![ace_type, ace.flags, 0, 0];
        entry.extend_from_slice(&ace.mask.to_le_bytes());
        if matches!(ace.kind, AceKind::AllowObject | AceKind::DenyObject) {
            // Object flags 0: no object-type GUIDs.
            entry.extend_from_slice(&0u32.to_le_bytes());
        }
        entry.extend_from_slice(&sid);
        while entry.len() % 4 != 0 {
            entry.push(0);
        }
        let size = u16::try_from(entry.len()).ok()?;
        entry.get_mut(2..4)?.copy_from_slice(&size.to_le_bytes());
        body.extend_from_slice(&entry);
        count = count.checked_add(1)?;
    }
    let size = u16::try_from(body.len().checked_add(8)?).ok()?;
    // Object ACEs need `ACL_REVISION_DS` (4).
    let revision = if aces
        .iter()
        .any(|a| matches!(a.kind, AceKind::AllowObject | AceKind::DenyObject))
    {
        4
    } else {
        2
    };
    let mut out = vec![revision, 0];
    out.extend_from_slice(&size.to_le_bytes());
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(&body);
    Some(out)
}

/// Rebuilds a self-relative descriptor from the owner, group and DACL of
/// `bytes`, for handing to an OS API that takes no length.
///
/// The result has no SACL (`SE_SACL_PRESENT` cleared, offset zero), so no
/// unvalidated offset reaches the OS; the owner defaults to `NULL SID`
/// (which no token holds) and the group to the owner; and the DACL is the
/// original DACL bytes, byte for byte, which [`SecurityDescriptor::from_self_relative`]
/// has bounded and checked ACE by ACE. Every part is 4-byte aligned. An
/// absent DACL and a NULL DACL both become a NULL DACL (`SE_DACL_PRESENT`
/// set, offset zero): both grant everyone everything, and the OS access
/// check accepts only the second. `Err` if `bytes` does not parse.
pub fn sanitized_self_relative(bytes: &[u8]) -> Result<Vec<u8>, DescriptorError> {
    let sd = SecurityDescriptor::from_self_relative(bytes)?;
    let header = bytes.get(..20).ok_or(DescriptorError::Truncated)?;
    let dacl_offset = to_index(read_u32(header, 16)?)?;
    let dacl_bytes: Option<&[u8]> = if sd.dacl.is_some() && dacl_offset != 0 {
        let size = usize::from(read_u16(bytes, dacl_offset + 2)?);
        Some(
            bytes
                .get(
                    dacl_offset
                        ..dacl_offset
                            .checked_add(size)
                            .ok_or(DescriptorError::BadAcl)?,
                )
                .ok_or(DescriptorError::Truncated)?,
        )
    } else {
        None
    };
    let owner = sd.owner.unwrap_or(well_known::NULL).to_bytes();
    let group = sd.group.or(sd.owner).unwrap_or(well_known::NULL).to_bytes();
    let pad = |v: &mut Vec<u8>| {
        while !v.len().is_multiple_of(4) {
            v.push(0);
        }
    };
    let mut out = vec![0_u8; 20];
    let mut control = (sd.control & !0x0010) | control::SELF_RELATIVE;
    let put = |out: &mut Vec<u8>, at: usize, part: &[u8]| -> Result<(), DescriptorError> {
        let offset = u32::try_from(out.len()).map_err(|_| DescriptorError::BadOffset)?;
        out.get_mut(at..at + 4)
            .ok_or(DescriptorError::BadOffset)?
            .copy_from_slice(&offset.to_le_bytes());
        out.extend_from_slice(part);
        Ok(())
    };
    put(&mut out, 4, &owner)?;
    pad(&mut out);
    put(&mut out, 8, &group)?;
    pad(&mut out);
    match dacl_bytes {
        Some(d) => {
            control |= control::DACL_PRESENT;
            put(&mut out, 16, d)?;
        }
        // A NULL DACL (present, offset zero), or an absent one.
        None => control |= control::DACL_PRESENT,
    }
    if let Some(b) = out.get_mut(0) {
        *b = 1;
    }
    out.get_mut(2..4)
        .ok_or(DescriptorError::Truncated)?
        .copy_from_slice(&control.to_le_bytes());
    Ok(out)
}

impl SecurityDescriptor {
    /// Parses a self-relative `SECURITY_DESCRIPTOR` (revision 1), as
    /// returned by `GetFileSecurityW` or `MakeSelfRelativeSD`.
    ///
    /// The input is treated as untrusted: every offset and size is checked,
    /// and nothing is allocated from a count the input declares beyond what
    /// its length can hold. Any malformation is an error. A caller that
    /// gets an error must treat the object as possibly writable (pass
    /// `None` to [`assess_path`]).
    pub fn from_self_relative(bytes: &[u8]) -> Result<Self, DescriptorError> {
        if bytes.len() > MAX_DESCRIPTOR_BYTES {
            return Err(DescriptorError::TooLarge);
        }
        let header = bytes.get(..20).ok_or(DescriptorError::Truncated)?;
        let revision = read_u8(header, 0)?;
        if revision != 1 {
            return Err(DescriptorError::UnsupportedRevision(revision));
        }
        let control = read_u16(header, 2)?;
        if control & control::SELF_RELATIVE == 0 {
            return Err(DescriptorError::NotSelfRelative);
        }
        let owner = read_sid_at(bytes, read_u32(header, 4)?)?;
        let group = read_sid_at(bytes, read_u32(header, 8)?)?;
        let dacl_offset = read_u32(header, 16)?;
        let dacl = if control & control::DACL_PRESENT == 0 {
            // The self-relative format requires a zero offset here.
            if dacl_offset != 0 {
                return Err(DescriptorError::BadOffset);
            }
            None
        } else if dacl_offset == 0 {
            // A NULL DACL.
            None
        } else {
            Some(read_acl(bytes, dacl_offset)?)
        };
        Ok(Self {
            owner,
            group,
            dacl,
            control,
        })
    }
}

fn read_u8(b: &[u8], at: usize) -> Result<u8, DescriptorError> {
    b.get(at).copied().ok_or(DescriptorError::Truncated)
}

fn read_u16(b: &[u8], at: usize) -> Result<u16, DescriptorError> {
    let end = at.checked_add(2).ok_or(DescriptorError::Truncated)?;
    let s = b.get(at..end).ok_or(DescriptorError::Truncated)?;
    let mut a = [0u8; 2];
    a.copy_from_slice(s);
    Ok(u16::from_le_bytes(a))
}

fn read_u32(b: &[u8], at: usize) -> Result<u32, DescriptorError> {
    let end = at.checked_add(4).ok_or(DescriptorError::Truncated)?;
    let s = b.get(at..end).ok_or(DescriptorError::Truncated)?;
    let mut a = [0u8; 4];
    a.copy_from_slice(s);
    Ok(u32::from_le_bytes(a))
}

fn to_index(offset: u32) -> Result<usize, DescriptorError> {
    usize::try_from(offset).map_err(|_| DescriptorError::BadOffset)
}

fn read_sid_at(bytes: &[u8], offset: u32) -> Result<Option<Sid>, DescriptorError> {
    if offset == 0 {
        return Ok(None);
    }
    let start = to_index(offset)?;
    if start < 20 {
        return Err(DescriptorError::BadOffset);
    }
    let tail = bytes.get(start..).ok_or(DescriptorError::BadOffset)?;
    let (sid, _) = Sid::from_bytes(tail).map_err(DescriptorError::Sid)?;
    Ok(Some(sid))
}

fn read_acl(bytes: &[u8], offset: u32) -> Result<Vec<Ace>, DescriptorError> {
    let start = to_index(offset)?;
    // An ACL starts on a DWORD boundary.
    if start < 20 || start % 4 != 0 {
        return Err(DescriptorError::BadOffset);
    }
    let header = bytes
        .get(start..start.checked_add(8).ok_or(DescriptorError::BadOffset)?)
        .ok_or(DescriptorError::Truncated)?;
    let revision = read_u8(header, 0)?;
    if revision != 2 && revision != 4 {
        return Err(DescriptorError::UnsupportedAclRevision(revision));
    }
    let acl_size = usize::from(read_u16(header, 2)?);
    let ace_count = usize::from(read_u16(header, 4)?);
    if acl_size < 8 {
        return Err(DescriptorError::BadAcl);
    }
    let acl = bytes
        .get(start..start.checked_add(acl_size).ok_or(DescriptorError::BadAcl)?)
        .ok_or(DescriptorError::Truncated)?;
    // Each ACE is at least 8 bytes, so the ACL size bounds the count.
    if ace_count > (acl_size - 8) / 8 {
        return Err(DescriptorError::BadAcl);
    }
    let mut aces = Vec::with_capacity(ace_count);
    let mut pos = 8usize;
    for _ in 0..ace_count {
        let ace_type = read_u8(acl, pos)?;
        let flags = read_u8(acl, pos + 1)?;
        let size = usize::from(read_u16(acl, pos + 2)?);
        if size < 8 || size % 4 != 0 {
            return Err(DescriptorError::BadAce);
        }
        let end = pos.checked_add(size).ok_or(DescriptorError::BadAce)?;
        let body = acl.get(pos..end).ok_or(DescriptorError::BadAce)?;
        aces.push(parse_ace(ace_type, flags, body)?);
        pos = end;
    }
    Ok(aces)
}

fn parse_ace(ace_type: u8, flags: u8, body: &[u8]) -> Result<Ace, DescriptorError> {
    let kind = match ace_type {
        0x00 => AceKind::Allow,
        0x01 => AceKind::Deny,
        0x05 => AceKind::AllowObject,
        0x06 => AceKind::DenyObject,
        0x09 | 0x0B => AceKind::AllowConditional,
        0x0A | 0x0C => AceKind::DenyConditional,
        other => {
            return Ok(Ace {
                kind: AceKind::Unknown(other),
                flags,
                mask: 0,
                sid: None,
            });
        }
    };
    let mask = read_u32(body, 4)?;
    let sid_start = if matches!(ace_type, 0x05 | 0x06 | 0x0B | 0x0C) {
        // ACCESS_*_OBJECT_ACE: Flags, then each GUID only if its flag is set.
        let object_flags = read_u32(body, 8)?;
        let mut at = 12usize;
        if object_flags & 0x1 != 0 {
            at += 16;
        }
        if object_flags & 0x2 != 0 {
            at += 16;
        }
        at
    } else {
        8
    };
    let sid_bytes = body.get(sid_start..).ok_or(DescriptorError::BadAce)?;
    let (sid, _) = Sid::from_bytes(sid_bytes).map_err(DescriptorError::Sid)?;
    Ok(Ace {
        kind,
        flags,
        mask,
        sid: Some(sid),
    })
}

/// Why a security descriptor could not be parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DescriptorError {
    /// The input ends inside a structure.
    Truncated,
    /// The input is larger than [`MAX_DESCRIPTOR_BYTES`].
    TooLarge,
    /// The descriptor revision is not 1.
    UnsupportedRevision(u8),
    /// `SE_SELF_RELATIVE` is not set, so the offsets would be pointers.
    NotSelfRelative,
    /// An owner, group or DACL offset points into the header or past the
    /// end, the DACL offset is not a multiple of 4, or it is nonzero while
    /// `SE_DACL_PRESENT` is clear.
    BadOffset,
    /// The ACL revision is not 2 or 4.
    UnsupportedAclRevision(u8),
    /// The ACL size or ACE count is inconsistent.
    BadAcl,
    /// An ACE size is too small, not a multiple of 4, or overruns the ACL.
    BadAce,
    /// A SID is malformed.
    Sid(SidError),
}

impl fmt::Display for DescriptorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("security descriptor ends early"),
            Self::TooLarge => write!(
                f,
                "security descriptor larger than {MAX_DESCRIPTOR_BYTES} bytes"
            ),
            Self::UnsupportedRevision(r) => {
                write!(f, "unsupported security descriptor revision {r}")
            }
            Self::NotSelfRelative => f.write_str("security descriptor is not self-relative"),
            Self::BadOffset => f.write_str("security descriptor offset out of range"),
            Self::UnsupportedAclRevision(r) => write!(f, "unsupported ACL revision {r}"),
            Self::BadAcl => f.write_str("ACL size or ACE count is inconsistent"),
            Self::BadAce => f.write_str("ACE size is invalid"),
            Self::Sid(e) => write!(f, "bad SID in security descriptor: {e}"),
        }
    }
}

impl std::error::Error for DescriptorError {}

/// The SIDs treated as administrators: rights they hold do not make an
/// object "user-writable".
///
/// Matching is exact, with no group expansion: a custom group of
/// administrators is still a non-administrator here, as it is for the OS
/// path-rule check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminSids(BTreeSet<Sid>);

impl AdminSids {
    /// Exactly the list the OS documents for its runtime path-rule
    /// protection: `CREATOR OWNER`, `SYSTEM`, `LOCAL SERVICE`,
    /// `NETWORK SERVICE`, and the built-in Administrators, Server
    /// Operators, Print Operators, Backup Operators, RDS Management
    /// Servers, Performance Log Users and web worker groups, plus the two
    /// OS app-capability SIDs for system components.
    #[must_use]
    pub fn os_documented() -> Self {
        Self(
            [
                well_known::CREATOR_OWNER,
                well_known::LOCAL_SYSTEM,
                well_known::LOCAL_SERVICE,
                well_known::NETWORK_SERVICE,
                well_known::ADMINISTRATORS,
                well_known::SERVER_OPERATORS,
                well_known::PRINT_OPERATORS,
                well_known::BACKUP_OPERATORS,
                well_known::REMOTE_DESKTOP_MANAGEMENT_SERVERS,
                well_known::PERFORMANCE_LOG_USERS,
                well_known::WEB_WORKERS,
                well_known::OS_APP_CAPABILITY_1,
                well_known::OS_APP_CAPABILITY_2,
            ]
            .into_iter()
            .collect(),
        )
    }

    /// An explicit set.
    #[must_use]
    pub fn from_sids(sids: impl IntoIterator<Item = Sid>) -> Self {
        Self(sids.into_iter().collect())
    }

    /// The same set with `sid` added.
    #[must_use]
    pub fn with(mut self, sid: Sid) -> Self {
        self.0.insert(sid);
        self
    }

    /// True if `sid` is in the set.
    #[must_use]
    pub fn contains(&self, sid: &Sid) -> bool {
        self.0.contains(sid)
    }

    /// The SIDs, in order.
    pub fn iter(&self) -> impl Iterator<Item = &Sid> {
        self.0.iter()
    }
}

impl Default for AdminSids {
    /// [`AdminSids::os_documented`] plus the `TrustedInstaller` service SID.
    ///
    /// The OS documentation does not list `TrustedInstaller`, but it holds
    /// full control of nearly every OS file and only the servicing stack
    /// (running as `SYSTEM`) has it in its token. Without it, every file
    /// under `%WINDIR%` would be reported user-writable. Use
    /// [`AdminSids::os_documented`] for the exact documented list.
    fn default() -> Self {
        Self::os_documented().with(well_known::TRUSTED_INSTALLER)
    }
}

/// Settings for [`evaluate`] and [`assess_path`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvaluationOptions {
    /// SIDs whose rights do not count.
    pub admins: AdminSids,
    /// The groups of the synthetic standard user.
    pub standard_user: Vec<Sid>,
}

impl Default for EvaluationOptions {
    fn default() -> Self {
        Self {
            admins: AdminSids::default(),
            standard_user: vec![
                well_known::EVERYONE,
                well_known::AUTHENTICATED_USERS,
                well_known::USERS,
                well_known::INTERACTIVE,
                well_known::LOCAL,
            ],
        }
    }
}

/// Who holds a right.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Principal {
    /// A SID named in the DACL, or the owner.
    Sid(Sid),
    /// The trustee of an ACE whose type the model does not know.
    Unknown,
}

impl fmt::Display for Principal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sid(s) => s.fmt(f),
            Self::Unknown => f.write_str("unknown principal"),
        }
    }
}

/// The rights one non-administrator principal may hold on one object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrincipalRights {
    /// The principal.
    pub principal: Principal,
    /// Every right it may hold, including uncertain ones.
    pub rights: WriteRights,
    /// The subset that depends on a conditional, object or unknown ACE.
    pub uncertain: WriteRights,
    /// True if this principal is the owner and holds the owner's implicit
    /// `WRITE_DAC` (no `OWNER RIGHTS` ACE replaced it).
    pub implicit_owner_rights: bool,
}

/// The result of [`evaluate`] for one object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectWritability {
    /// The object kind evaluated.
    pub kind: ObjectKind,
    /// Every right some non-administrator may hold.
    pub rights: WriteRights,
    /// The subset of `rights` that is uncertain: it depends on a
    /// conditional, object or unknown ACE, or the descriptor was unreadable.
    pub uncertain: WriteRights,
    /// The rights of the synthetic standard user
    /// ([`EvaluationOptions::standard_user`]), including owner rights when
    /// the owner is one of its SIDs, and anything an unknown owner or ACE
    /// type might grant.
    pub standard_user: WriteRights,
    /// The subset of `standard_user` that is uncertain for the standard
    /// user itself.
    pub standard_user_uncertain: WriteRights,
    /// Each non-administrator principal that may hold at least one right,
    /// in SID order (an unknown principal last).
    pub principals: Vec<PrincipalRights>,
    /// True if the explicit ACEs are not in canonical order (an explicit
    /// deny after an explicit allow, or an explicit ACE after an inherited
    /// one). The OS evaluates the order as stored, and so does this model,
    /// but such a DACL is worth reporting.
    pub non_canonical: bool,
    /// True if the descriptor could not be read, so every right was assumed.
    pub unreadable: bool,
}

impl ObjectWritability {
    /// True if some non-administrator may hold any right.
    #[must_use]
    pub fn user_writable(&self) -> bool {
        !self.rights.is_empty()
    }

    /// The result for an object whose descriptor could not be read: every
    /// right, all uncertain.
    #[must_use]
    pub fn unreadable(kind: ObjectKind) -> Self {
        let all = WriteRights::relevant(kind);
        Self {
            kind,
            rights: all,
            uncertain: all,
            standard_user: all,
            standard_user_uncertain: all,
            principals: vec![PrincipalRights {
                principal: Principal::Unknown,
                rights: all,
                uncertain: all,
                implicit_owner_rights: false,
            }],
            non_canonical: false,
            unreadable: true,
        }
    }
}

/// Maps the generic rights in an allow ACE to file rights.
fn map_generic_allow(access_mask: u32) -> u32 {
    let mut m = access_mask;
    if m & mask::GENERIC_ALL != 0 {
        m |= mask::FILE_ALL_ACCESS;
    }
    if m & mask::GENERIC_WRITE != 0 {
        m |= mask::FILE_GENERIC_WRITE;
    }
    m
}

/// Which question a DACL walk answers.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Walk {
    /// What the token may hold: every allow ACE that might apply does, with
    /// generic bits mapped, and only unconditional deny ACEs apply.
    Possible,
    /// What the token holds for certain: only unconditional allow ACEs
    /// apply, without generic mapping, and every deny ACE that might apply
    /// does.
    Definite,
}

/// Walks the DACL in stored order for a token and returns the bits granted.
fn walk(aces: &[Ace], in_token: &dyn Fn(&Sid) -> bool, mode: Walk) -> u32 {
    let possible = mode == Walk::Possible;
    let mut granted = 0u32;
    let mut denied = 0u32;
    for ace in aces.iter().filter(|a| a.applies_to_object()) {
        let Some(sid) = &ace.sid else { continue };
        if !in_token(sid) {
            continue;
        }
        let deny_applies = match ace.kind {
            // A deny for `OWNER RIGHTS` is ignored when working out what may
            // be held, so that whether or not the OS applies it to the
            // owner, rights can only be over-reported.
            AceKind::Deny => !possible || *sid != well_known::OWNER_RIGHTS,
            AceKind::DenyConditional | AceKind::DenyObject => !possible,
            _ => false,
        };
        match ace.kind {
            AceKind::Allow if possible => granted |= map_generic_allow(ace.mask) & !denied,
            AceKind::Allow => granted |= ace.mask & !denied,
            AceKind::AllowConditional | AceKind::AllowObject if possible => {
                granted |= map_generic_allow(ace.mask) & !denied;
            }
            _ if deny_applies => denied |= ace.mask & !granted,
            _ => {}
        }
    }
    granted
}

/// Rights for one token: (all, uncertain).
fn token_rights(
    aces: &[Ace],
    in_token: &dyn Fn(&Sid) -> bool,
    relevant: WriteRights,
) -> (WriteRights, WriteRights) {
    let definite =
        WriteRights::from_mask(walk(aces, in_token, Walk::Definite)).intersection(relevant);
    let possible =
        WriteRights::from_mask(walk(aces, in_token, Walk::Possible)).intersection(relevant);
    // `possible` is a superset of `definite`: the possible walk applies more
    // allow ACEs and fewer deny ACEs, so it grants each bit no later.
    (possible.union(definite), possible.difference(definite))
}

fn is_non_canonical(aces: &[Ace]) -> bool {
    let mut seen_inherited = false;
    let mut seen_explicit_allow = false;
    for ace in aces {
        if ace.is_inherited() {
            seen_inherited = true;
            continue;
        }
        if seen_inherited {
            return true;
        }
        if ace.kind.is_allow() {
            seen_explicit_allow = true;
        } else if ace.kind.is_deny() && seen_explicit_allow {
            return true;
        }
    }
    false
}

/// Works out which write-type rights any non-administrator principal may
/// hold on one object. See the module documentation for the method.
#[must_use]
pub fn evaluate(
    sd: &SecurityDescriptor,
    kind: ObjectKind,
    options: &EvaluationOptions,
) -> ObjectWritability {
    let relevant = WriteRights::relevant(kind);
    let admins = &options.admins;
    let Some(aces) = &sd.dacl else {
        // No DACL: everyone has every right.
        return ObjectWritability {
            kind,
            rights: relevant,
            uncertain: WriteRights::NONE,
            standard_user: relevant,
            standard_user_uncertain: WriteRights::NONE,
            principals: vec![PrincipalRights {
                principal: Principal::Sid(well_known::EVERYONE),
                rights: relevant,
                uncertain: WriteRights::NONE,
                implicit_owner_rights: false,
            }],
            non_canonical: false,
            unreadable: false,
        };
    };

    let owner = sd.owner.filter(|o| !admins.contains(o));
    // Only an unconditional allow ACE for `OWNER RIGHTS` is taken to replace
    // the owner's implicit rights. A conditional or object ACE may not
    // apply, and a deny is ignored (see `walk`), so in those cases the
    // implicit `WRITE_DAC` is still reported.
    let owner_rights_ace = aces.iter().any(|a| {
        a.applies_to_object() && a.kind == AceKind::Allow && a.sid == Some(well_known::OWNER_RIGHTS)
    });

    // Candidate principals: every non-admin SID named by an applicable
    // allow ACE, plus a non-admin owner. Placeholders never match a token,
    // and OWNER RIGHTS stands for the owner, who is handled separately.
    let mut candidates: BTreeSet<Sid> = aces
        .iter()
        .filter(|a| a.applies_to_object() && a.kind.is_allow())
        .filter_map(|a| a.sid)
        .filter(|s| {
            !admins.contains(s)
                && !well_known::is_creator_placeholder(s)
                && *s != well_known::OWNER_RIGHTS
        })
        .collect();
    if let Some(o) = owner {
        candidates.insert(o);
    }

    let mut principals = Vec::new();
    for sid in candidates {
        let is_owner = owner == Some(sid);
        // An anonymous token does not hold `Everyone` by default, so a deny
        // for `Everyone` must not be assumed to stop it. It may hold
        // `NETWORK`, which is therefore evaluated both with and without
        // `Everyone`.
        let everyone_variants: &[bool] = if sid == well_known::ANONYMOUS {
            &[false]
        } else if sid == well_known::NETWORK {
            &[true, false]
        } else {
            &[true]
        };
        let mut rights = WriteRights::NONE;
        let mut definite = WriteRights::NONE;
        for &with_everyone in everyone_variants {
            let in_token = |s: &Sid| {
                *s == sid
                    || (with_everyone && *s == well_known::EVERYONE)
                    || (is_owner && *s == well_known::OWNER_RIGHTS)
            };
            let (r, u) = token_rights(aces, &in_token, relevant);
            rights = rights.union(r);
            definite = definite.union(r.difference(u));
        }
        let mut uncertain = rights.difference(definite);
        let implicit = is_owner && !owner_rights_ace;
        if implicit {
            // The owner's implicit READ_CONTROL | WRITE_DAC cannot be
            // removed by a deny ACE, and is certain.
            rights = rights.union(WriteRights::WRITE_DAC);
            uncertain = uncertain.difference(WriteRights::WRITE_DAC);
        }
        if !rights.is_empty() {
            principals.push(PrincipalRights {
                principal: Principal::Sid(sid),
                rights,
                uncertain,
                implicit_owner_rights: implicit,
            });
        }
    }

    // An unknown owner (the descriptor has none) may be a non-administrator:
    // it may hold the implicit `WRITE_DAC` and whatever `OWNER RIGHTS` ACEs
    // grant. Both are reported as uncertain, for an unknown principal.
    let mut unknown = WriteRights::NONE;
    if sd.owner.is_none() {
        // Only `OWNER RIGHTS`: the unknown owner might not hold `Everyone`,
        // so a deny for `Everyone` is not assumed to stop it, and grants to
        // `Everyone` are already reported for `Everyone`.
        let in_owner_token = |s: &Sid| *s == well_known::OWNER_RIGHTS;
        let (r, _) = token_rights(aces, &in_owner_token, relevant);
        unknown = r.union(if owner_rights_ace {
            WriteRights::NONE
        } else {
            WriteRights::WRITE_DAC
        });
    }
    // ACE types whose layout is unknown might grant anything to anyone.
    if aces
        .iter()
        .any(|a| a.applies_to_object() && matches!(a.kind, AceKind::Unknown(_)))
    {
        unknown = relevant;
    }
    if !unknown.is_empty() {
        principals.push(PrincipalRights {
            principal: Principal::Unknown,
            rights: unknown,
            uncertain: unknown,
            implicit_owner_rights: false,
        });
    }

    // The synthetic standard user is the owner if the owner SID is one of
    // its groups, as the OS access check decides ownership against every
    // SID in a token.
    let standard: BTreeSet<Sid> = options.standard_user.iter().copied().collect();
    let standard_is_owner = owner.is_some_and(|o| standard.contains(&o));
    let in_standard = |s: &Sid| {
        (standard.contains(s) && !admins.contains(s))
            || (standard_is_owner && *s == well_known::OWNER_RIGHTS)
    };
    let (mut standard_user, mut standard_uncertain) = token_rights(aces, &in_standard, relevant);
    if standard_is_owner && !owner_rights_ace {
        standard_user = standard_user.union(WriteRights::WRITE_DAC);
        standard_uncertain = standard_uncertain.difference(WriteRights::WRITE_DAC);
    }
    // What an unknown owner or an unknown ACE type might grant may reach
    // the standard user too.
    let unknown_new = unknown.difference(standard_user);
    standard_user = standard_user.union(unknown);
    standard_uncertain = standard_uncertain.union(unknown_new);

    let mut rights = standard_user;
    let mut uncertain = standard_uncertain;
    for p in &principals {
        rights = rights.union(p.rights);
        uncertain = uncertain.union(p.uncertain);
    }
    // A right is only uncertain overall if no principal holds it for sure.
    let definite = principals
        .iter()
        .map(|p| p.rights.difference(p.uncertain))
        .fold(
            standard_user.difference(standard_uncertain),
            WriteRights::union,
        );
    uncertain = uncertain.difference(definite);

    ObjectWritability {
        kind,
        rights,
        uncertain,
        standard_user,
        standard_user_uncertain: standard_uncertain,
        principals,
        non_canonical: is_non_canonical(aces),
        unreadable: false,
    }
}

/// One ancestor folder of the object being assessed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ancestor {
    /// The folder's path, for reporting.
    pub path: String,
    /// Its security descriptor, or `None` if it could not be read. An
    /// unreadable ancestor counts as user-writable.
    pub descriptor: Option<SecurityDescriptor>,
}

/// Writability of a file (or folder) and of every folder above it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Writability {
    /// The object itself.
    pub target: ObjectWritability,
    /// Each ancestor, in the order given (immediate parent first).
    pub ancestors: Vec<ObjectWritability>,
    /// Some non-administrator may hold a write-type right on the object.
    pub file_user_writable: bool,
    /// The nearest ancestor on which some non-administrator may hold a
    /// write-type right. Such a principal can add, delete or replace
    /// entries below it (directly, or by changing the DACL first), so a
    /// path rule anywhere below it is unsafe.
    pub first_user_writable_ancestor: Option<String>,
    /// Some non-administrator may hold `WRITE_DAC` or `WRITE_OWNER` on the
    /// object or on an ancestor.
    pub change_perms_by_non_admin: bool,
    /// Every principal that may hold a right on the object or an ancestor,
    /// in order, without duplicates.
    pub principals_with_write: Vec<Principal>,
    /// The rights on the object itself that rule out owner-based trust (see
    /// the module documentation). Empty means a non-administrator cannot
    /// change the content while NTFS keeps its owner.
    pub owner_trust_blockers: WriteRights,
}

impl Writability {
    /// True if the object or any ancestor is user-writable, so a path rule
    /// for this object is not safe (ISM-1392, ISM-1746).
    #[must_use]
    pub fn path_user_writable(&self) -> bool {
        self.file_user_writable || self.first_user_writable_ancestor.is_some()
    }
}

/// Assesses an object and its ancestors.
///
/// `target` is the object's descriptor (`None` if unreadable) and kind.
/// `ancestors` lists every folder from the immediate parent up to and
/// including the volume root. The caller must list them all: a missing
/// ancestor cannot be detected here.
#[must_use]
pub fn assess_path(
    target: Option<&SecurityDescriptor>,
    kind: ObjectKind,
    ancestors: &[Ancestor],
    options: &EvaluationOptions,
) -> Writability {
    let target_w = match target {
        Some(sd) => evaluate(sd, kind, options),
        None => ObjectWritability::unreadable(kind),
    };
    let ancestor_w: Vec<ObjectWritability> = ancestors
        .iter()
        .map(|a| match &a.descriptor {
            Some(sd) => evaluate(sd, ObjectKind::Directory, options),
            None => ObjectWritability::unreadable(ObjectKind::Directory),
        })
        .collect();

    let first_user_writable_ancestor = ancestors
        .iter()
        .zip(&ancestor_w)
        .find(|(_, w)| w.user_writable())
        .map(|(a, _)| a.path.clone());
    let change_perms_by_non_admin = std::iter::once(&target_w)
        .chain(&ancestor_w)
        .any(|w| w.rights.intersects(WriteRights::CHANGE_PERMISSIONS));
    let principals_with_write: Vec<Principal> = std::iter::once(&target_w)
        .chain(&ancestor_w)
        .flat_map(|w| w.principals.iter().map(|p| p.principal))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();

    Writability {
        file_user_writable: target_w.user_writable(),
        owner_trust_blockers: target_w
            .rights
            .intersection(WriteRights::OWNER_TRUST_BLOCKING),
        target: target_w,
        ancestors: ancestor_w,
        first_user_writable_ancestor,
        change_perms_by_non_admin,
        principals_with_write,
    }
}

/// How far the owner SID can be trusted. The trust decision itself is #9's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OwnerTrustClass {
    /// `SYSTEM`, `BUILTIN\Administrators` or the `TrustedInstaller` service.
    AdminEquivalent,
    /// Any other owner.
    NonAdmin,
    /// No owner is known: the file system does not record one, or it could
    /// not be read.
    Unknown,
}

/// The owner attributes of a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerInfo {
    /// The owner SID, if known.
    pub owner_sid: Option<Sid>,
    /// False on file systems that do not record owners (FAT, exFAT, UDF,
    /// CDFS) and on network locations, where the owner is not reliable.
    pub owner_supported: bool,
    /// The class of the owner.
    pub owner_trust_class: OwnerTrustClass,
    /// The owner's account name (`DOMAIN\name`), if it was looked up.
    pub owner_name: Option<String>,
}

impl OwnerInfo {
    /// Classifies an owner read from a file system that records owners.
    #[must_use]
    pub fn from_owner(owner: Option<Sid>) -> Self {
        let class = match owner {
            None => OwnerTrustClass::Unknown,
            Some(s)
                if s == well_known::LOCAL_SYSTEM
                    || s == well_known::ADMINISTRATORS
                    || s == well_known::TRUSTED_INSTALLER =>
            {
                OwnerTrustClass::AdminEquivalent
            }
            Some(_) => OwnerTrustClass::NonAdmin,
        };
        Self {
            owner_sid: owner,
            owner_supported: true,
            owner_trust_class: class,
            owner_name: None,
        }
    }

    /// The attributes for a location that does not record owners.
    #[must_use]
    pub fn unsupported() -> Self {
        Self {
            owner_sid: None,
            owner_supported: false,
            owner_trust_class: OwnerTrustClass::Unknown,
            owner_name: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use well_known as wk;

    const RX: u32 = 0x0012_00A9;
    const MODIFY: u32 = 0x0013_01BF;

    fn user(rid: u32) -> Sid {
        Sid::new(5, &[21, 1, 2, 3, rid]).unwrap()
    }

    fn sd(owner: Sid, aces: Vec<Ace>) -> SecurityDescriptor {
        SecurityDescriptor::new(Some(owner), Some(aces))
    }

    fn eval_file(sd: &SecurityDescriptor) -> ObjectWritability {
        evaluate(sd, ObjectKind::File, &EvaluationOptions::default())
    }

    #[test]
    fn sanitized_descriptors_drop_the_sacl_and_keep_the_dacl() {
        let d = sd(
            wk::ADMINISTRATORS,
            vec![
                Ace::allow(wk::USERS, MODIFY),
                Ace::deny(wk::GUESTS, mask::FILE_WRITE_DATA),
            ],
        );
        let mut bytes = d.to_self_relative().unwrap();
        // Claim a SACL at an offset far past the end.
        let c = u16::from_le_bytes([bytes[2], bytes[3]]) | 0x0010;
        bytes[2..4].copy_from_slice(&c.to_le_bytes());
        bytes[12..16].copy_from_slice(&0x1000_0000_u32.to_le_bytes());
        let clean = sanitized_self_relative(&bytes).unwrap();
        assert_eq!(u32::from_le_bytes(clean[12..16].try_into().unwrap()), 0);
        assert_eq!(u16::from_le_bytes([clean[2], clean[3]]) & 0x0010, 0);
        let back = SecurityDescriptor::from_self_relative(&clean).unwrap();
        assert_eq!(back.owner, Some(wk::ADMINISTRATORS));
        assert_eq!(back.group, Some(wk::ADMINISTRATORS));
        assert_eq!(back.dacl, d.dacl);
        // Every offset is 4-byte aligned.
        for at in [4, 8, 16] {
            assert_eq!(
                u32::from_le_bytes(clean[at..at + 4].try_into().unwrap()) % 4,
                0
            );
        }
        // No owner: NULL SID owner and group. No DACL: a NULL DACL, which
        // means the same.
        let bare = SecurityDescriptor::new(None, None)
            .to_self_relative()
            .unwrap();
        let clean_bytes = sanitized_self_relative(&bare).unwrap();
        let clean = SecurityDescriptor::from_self_relative(&clean_bytes).unwrap();
        assert_eq!(clean.owner, Some(wk::NULL));
        assert_eq!(clean.dacl, None);
        assert_ne!(clean.control & control::DACL_PRESENT, 0);
        assert_eq!(
            evaluate(&clean, ObjectKind::File, &EvaluationOptions::default()).rights,
            WriteRights::relevant(ObjectKind::File)
        );
        assert!(sanitized_self_relative(b"junk").is_err());
    }

    #[test]
    fn system32_style_dacl_is_not_user_writable() {
        let d = sd(
            wk::TRUSTED_INSTALLER,
            vec![
                Ace::allow(wk::TRUSTED_INSTALLER, mask::FILE_ALL_ACCESS),
                Ace::allow(wk::ADMINISTRATORS, RX),
                Ace::allow(wk::LOCAL_SYSTEM, RX),
                Ace::allow(wk::USERS, RX),
            ],
        );
        let w = eval_file(&d);
        assert!(!w.user_writable(), "{w:?}");
        assert!(w.principals.is_empty());
        // With the exact documented list, TrustedInstaller counts.
        let strict = EvaluationOptions {
            admins: AdminSids::os_documented(),
            ..EvaluationOptions::default()
        };
        assert!(evaluate(&d, ObjectKind::File, &strict).user_writable());
    }

    #[test]
    fn users_modify_is_user_writable() {
        let d = sd(wk::ADMINISTRATORS, vec![Ace::allow(wk::USERS, MODIFY)]);
        let w = eval_file(&d);
        assert!(w.rights.contains(WriteRights::WRITE_DATA));
        assert!(w.rights.contains(WriteRights::DELETE));
        assert!(!w.rights.intersects(WriteRights::CHANGE_PERMISSIONS));
        assert_eq!(w.standard_user, w.rights);
        assert_eq!(w.principals.len(), 1);
        assert_eq!(w.principals[0].principal, Principal::Sid(wk::USERS));
    }

    #[test]
    fn deny_before_allow_wins_and_order_matters() {
        let deny_first = sd(
            wk::ADMINISTRATORS,
            vec![
                Ace::deny(wk::EVERYONE, mask::FILE_WRITE_DATA | mask::FILE_APPEND_DATA),
                Ace::allow(wk::USERS, mask::FILE_WRITE_DATA | mask::FILE_APPEND_DATA),
            ],
        );
        assert!(!eval_file(&deny_first).user_writable());

        // The same ACEs the other way round: the allow is seen first.
        let allow_first = sd(
            wk::ADMINISTRATORS,
            vec![
                Ace::allow(wk::USERS, mask::FILE_WRITE_DATA),
                Ace::deny(wk::EVERYONE, mask::FILE_WRITE_DATA),
            ],
        );
        let w = eval_file(&allow_first);
        assert_eq!(w.rights, WriteRights::WRITE_DATA);
        assert!(w.non_canonical);
    }

    #[test]
    fn deny_on_other_group_is_not_assumed() {
        // A deny for Authenticated Users does not stop a SID that might not
        // be a member: the per-principal token holds only the SID and
        // Everyone, so this over-reports, as intended.
        let d = sd(
            wk::ADMINISTRATORS,
            vec![
                Ace::deny(wk::AUTHENTICATED_USERS, mask::FILE_WRITE_DATA),
                Ace::allow(wk::USERS, mask::FILE_WRITE_DATA),
            ],
        );
        let w = eval_file(&d);
        assert_eq!(w.rights, WriteRights::WRITE_DATA);
        // The synthetic standard user is in both groups and is denied.
        assert_eq!(w.standard_user, WriteRights::NONE);
    }

    #[test]
    fn inherit_only_aces_do_not_apply() {
        let d = sd(
            wk::ADMINISTRATORS,
            vec![
                Ace::allow(wk::USERS, MODIFY)
                    .with_flags(ace_flags::INHERIT_ONLY | ace_flags::OBJECT_INHERIT),
                Ace::allow(wk::CREATOR_OWNER, mask::FILE_ALL_ACCESS),
            ],
        );
        assert!(!eval_file(&d).user_writable());
    }

    #[test]
    fn non_admin_owner_has_implicit_write_dac() {
        let u = user(1001);
        let d = sd(u, vec![Ace::allow(wk::USERS, RX)]);
        let w = eval_file(&d);
        assert_eq!(w.rights, WriteRights::WRITE_DAC);
        assert!(w.principals[0].implicit_owner_rights);
        // A deny ACE cannot remove it.
        let d = sd(u, vec![Ace::deny(u, mask::WRITE_DAC)]);
        assert_eq!(eval_file(&d).rights, WriteRights::WRITE_DAC);
    }

    #[test]
    fn owner_rights_ace_replaces_implicit_rights() {
        let u = user(1001);
        let d = sd(u, vec![Ace::allow(wk::OWNER_RIGHTS, RX)]);
        assert!(!eval_file(&d).user_writable());
        let d = sd(u, vec![Ace::allow(wk::OWNER_RIGHTS, mask::FILE_WRITE_DATA)]);
        let w = eval_file(&d);
        assert_eq!(w.rights, WriteRights::WRITE_DATA);
        assert!(!w.principals[0].implicit_owner_rights);
        // OWNER RIGHTS for an admin owner grants a non-admin nothing.
        let d = sd(
            wk::ADMINISTRATORS,
            vec![Ace::allow(wk::OWNER_RIGHTS, mask::FILE_ALL_ACCESS)],
        );
        assert!(!eval_file(&d).user_writable());
    }

    #[test]
    fn owner_rights_edge_cases_fail_closed() {
        let u = user(1001);
        // A deny for OWNER RIGHTS neither removes the implicit WRITE_DAC
        // nor blocks a later grant to the owner.
        let d = sd(
            u,
            vec![
                Ace::deny(wk::OWNER_RIGHTS, mask::FILE_WRITE_DATA | mask::WRITE_DAC),
                Ace::allow(u, mask::FILE_WRITE_DATA),
            ],
        );
        let w = eval_file(&d);
        assert_eq!(
            w.rights,
            WriteRights::WRITE_DATA.union(WriteRights::WRITE_DAC)
        );
        assert!(w.principals[0].implicit_owner_rights);
        // A conditional OWNER RIGHTS allow does not remove the implicit right.
        let d = sd(
            u,
            vec![Ace {
                kind: AceKind::AllowConditional,
                flags: 0,
                mask: RX,
                sid: Some(wk::OWNER_RIGHTS),
            }],
        );
        let w = eval_file(&d);
        assert_eq!(w.rights, WriteRights::WRITE_DAC);
        assert_eq!(w.uncertain, WriteRights::NONE);
        // No owner: the unknown owner may hold WRITE_DAC and the OWNER
        // RIGHTS grants, as uncertain.
        let d = SecurityDescriptor::new(
            None,
            Some(vec![Ace::allow(wk::OWNER_RIGHTS, mask::FILE_WRITE_DATA)]),
        );
        let w = eval_file(&d);
        assert_eq!(w.rights, WriteRights::WRITE_DATA);
        assert_eq!(w.uncertain, WriteRights::WRITE_DATA);
        assert_eq!(w.principals[0].principal, Principal::Unknown);
        let d = SecurityDescriptor::new(None, Some(vec![]));
        assert_eq!(eval_file(&d).rights, WriteRights::WRITE_DAC);
    }

    #[test]
    fn standard_user_includes_owner_and_unknown_rights() {
        // The owner is a group the standard user is in.
        let d = sd(wk::USERS, vec![Ace::allow(wk::USERS, RX)]);
        let w = eval_file(&d);
        assert_eq!(w.standard_user, WriteRights::WRITE_DAC);
        let d = sd(
            wk::USERS,
            vec![Ace::allow(wk::OWNER_RIGHTS, mask::FILE_WRITE_DATA)],
        );
        assert_eq!(eval_file(&d).standard_user, WriteRights::WRITE_DATA);
        // An unknown ACE type reaches the standard user too.
        let d = sd(
            wk::ADMINISTRATORS,
            vec![Ace {
                kind: AceKind::Unknown(0x13),
                flags: 0,
                mask: 0,
                sid: None,
            }],
        );
        let w = eval_file(&d);
        assert_eq!(w.standard_user, WriteRights::relevant(ObjectKind::File));
        assert_eq!(w.uncertain, w.rights);
        // A deny for Everyone does not hide OWNER RIGHTS grants from an
        // unknown owner.
        let d = SecurityDescriptor::new(
            None,
            Some(vec![
                Ace::deny(wk::EVERYONE, mask::FILE_WRITE_DATA),
                Ace::allow(wk::OWNER_RIGHTS, mask::FILE_WRITE_DATA),
            ]),
        );
        assert!(eval_file(&d).rights.contains(WriteRights::WRITE_DATA));
    }

    #[test]
    fn serialising_unknown_aces_fails() {
        let d = sd(
            wk::ADMINISTRATORS,
            vec![Ace {
                kind: AceKind::Unknown(0x13),
                flags: 0,
                mask: 0,
                sid: None,
            }],
        );
        assert_eq!(d.to_self_relative(), None);
    }

    #[test]
    fn null_dacl_grants_everything() {
        let d = SecurityDescriptor::new(Some(wk::ADMINISTRATORS), None);
        let w = eval_file(&d);
        assert_eq!(w.rights, WriteRights::relevant(ObjectKind::File));
        let w = evaluate(&d, ObjectKind::Directory, &EvaluationOptions::default());
        assert_eq!(w.rights, WriteRights::ALL);
    }

    #[test]
    fn empty_dacl_grants_nothing() {
        let d = sd(wk::LOCAL_SYSTEM, vec![]);
        assert!(!eval_file(&d).user_writable());
    }

    #[test]
    fn generic_rights_map_in_allow_but_not_in_deny() {
        let d = sd(
            wk::ADMINISTRATORS,
            vec![Ace::allow(wk::USERS, mask::GENERIC_WRITE)],
        );
        let w = eval_file(&d);
        assert!(w.rights.contains(WriteRights::WRITE_DATA));
        assert!(w.rights.contains(WriteRights::WRITE_ATTRIBUTES));
        // The OS may not map a generic bit stored in an ACE, so a right that
        // only a generic bit grants is not certain.
        assert!(w.uncertain.contains(WriteRights::WRITE_DATA));
        assert_eq!(w.uncertain, w.rights);
        // A file-specific grant of the same right makes it certain again.
        let d = sd(
            wk::ADMINISTRATORS,
            vec![
                Ace::allow(wk::USERS, mask::GENERIC_WRITE),
                Ace::allow(wk::USERS, mask::FILE_WRITE_DATA),
            ],
        );
        let w = eval_file(&d);
        assert!(!w.uncertain.contains(WriteRights::WRITE_DATA));
        assert!(w.uncertain.contains(WriteRights::WRITE_ATTRIBUTES));

        let d = sd(
            wk::ADMINISTRATORS,
            vec![
                Ace::deny(wk::USERS, mask::GENERIC_WRITE),
                Ace::allow(wk::USERS, mask::FILE_WRITE_DATA),
            ],
        );
        assert_eq!(eval_file(&d).rights, WriteRights::WRITE_DATA);
    }

    #[test]
    fn conditional_and_object_aces_are_uncertain() {
        let cond = Ace {
            kind: AceKind::AllowConditional,
            flags: 0,
            mask: mask::FILE_WRITE_DATA,
            sid: Some(wk::USERS),
        };
        let w = eval_file(&sd(wk::ADMINISTRATORS, vec![cond.clone()]));
        assert_eq!(w.rights, WriteRights::WRITE_DATA);
        assert_eq!(w.uncertain, WriteRights::WRITE_DATA);

        // A certain grant of the same right elsewhere removes the doubt.
        let w = eval_file(&sd(
            wk::ADMINISTRATORS,
            vec![cond, Ace::allow(user(7), mask::FILE_WRITE_DATA)],
        ));
        assert_eq!(w.uncertain, WriteRights::NONE);

        // A conditional deny is assumed not to apply.
        let d = sd(
            wk::ADMINISTRATORS,
            vec![
                Ace {
                    kind: AceKind::DenyConditional,
                    flags: 0,
                    mask: mask::FILE_WRITE_DATA,
                    sid: Some(wk::USERS),
                },
                Ace::allow(wk::USERS, mask::FILE_WRITE_DATA),
            ],
        );
        let w = eval_file(&d);
        assert_eq!(w.rights, WriteRights::WRITE_DATA);
        // ...but it might apply, so the right is not certain.
        assert_eq!(w.uncertain, WriteRights::WRITE_DATA);

        // A conditional deny after an unconditional allow cannot take the
        // right back, so it stays certain.
        let d = sd(
            wk::ADMINISTRATORS,
            vec![
                Ace::allow(wk::USERS, mask::FILE_WRITE_DATA),
                Ace {
                    kind: AceKind::DenyConditional,
                    flags: 0,
                    mask: mask::FILE_WRITE_DATA,
                    sid: Some(wk::USERS),
                },
            ],
        );
        let w = eval_file(&d);
        assert_eq!(w.rights, WriteRights::WRITE_DATA);
        assert_eq!(w.uncertain, WriteRights::NONE);

        // The same for an object deny.
        let d = sd(
            wk::ADMINISTRATORS,
            vec![
                Ace {
                    kind: AceKind::DenyObject,
                    flags: 0,
                    mask: mask::FILE_WRITE_DATA,
                    sid: Some(wk::USERS),
                },
                Ace::allow(wk::USERS, mask::FILE_WRITE_DATA),
            ],
        );
        assert_eq!(eval_file(&d).uncertain, WriteRights::WRITE_DATA);
    }

    #[test]
    fn unknown_ace_type_grants_everything_uncertain() {
        let d = sd(
            wk::ADMINISTRATORS,
            vec![Ace {
                kind: AceKind::Unknown(0x04),
                flags: 0,
                mask: 0,
                sid: None,
            }],
        );
        let w = eval_file(&d);
        assert_eq!(w.rights, WriteRights::relevant(ObjectKind::File));
        assert_eq!(w.uncertain, w.rights);
        assert_eq!(w.principals[0].principal, Principal::Unknown);
    }

    #[test]
    fn delete_child_counts_only_on_directories() {
        let d = sd(
            wk::ADMINISTRATORS,
            vec![Ace::allow(wk::USERS, mask::FILE_DELETE_CHILD)],
        );
        assert!(!eval_file(&d).user_writable());
        let w = evaluate(&d, ObjectKind::Directory, &EvaluationOptions::default());
        assert_eq!(w.rights, WriteRights::DELETE_CHILD);
    }

    #[test]
    fn assess_path_reports_first_writable_ancestor() {
        let locked = sd(wk::ADMINISTRATORS, vec![Ace::allow(wk::USERS, RX)]);
        let open = sd(
            wk::ADMINISTRATORS,
            vec![Ace::allow(wk::AUTHENTICATED_USERS, mask::FILE_WRITE_DATA)],
        );
        let w = assess_path(
            Some(&locked),
            ObjectKind::File,
            &[
                Ancestor {
                    path: r"C:\Program Files\App".into(),
                    descriptor: Some(locked.clone()),
                },
                Ancestor {
                    path: r"C:\Program Files".into(),
                    descriptor: Some(open),
                },
                Ancestor {
                    path: r"C:\".into(),
                    descriptor: None,
                },
            ],
            &EvaluationOptions::default(),
        );
        assert!(!w.file_user_writable);
        assert_eq!(
            w.first_user_writable_ancestor.as_deref(),
            Some(r"C:\Program Files")
        );
        assert!(w.path_user_writable());
        // The unreadable root contributes an unknown principal with every
        // right, so permission changes are possible as far as we know.
        assert!(w.change_perms_by_non_admin);
        assert!(w.principals_with_write.contains(&Principal::Unknown));
        assert!(w.owner_trust_blockers.is_empty());
    }

    #[test]
    fn owner_trust_blockers_follow_the_threat_model() {
        // Admin-owned file whose DACL lets users write: NTFS keeps the
        // owner on an in-place overwrite, so the owner is no evidence.
        let d = sd(
            wk::ADMINISTRATORS,
            vec![Ace::allow(
                wk::USERS,
                mask::FILE_WRITE_DATA | mask::FILE_WRITE_EA,
            )],
        );
        let w = assess_path(
            Some(&d),
            ObjectKind::File,
            &[],
            &EvaluationOptions::default(),
        );
        assert_eq!(w.owner_trust_blockers, WriteRights::WRITE_DATA);
        assert_eq!(
            OwnerInfo::from_owner(d.owner).owner_trust_class,
            OwnerTrustClass::AdminEquivalent
        );
        // Write-attributes alone does not change the content.
        let d = sd(
            wk::ADMINISTRATORS,
            vec![Ace::allow(wk::USERS, mask::FILE_WRITE_ATTRIBUTES)],
        );
        let w = assess_path(
            Some(&d),
            ObjectKind::File,
            &[],
            &EvaluationOptions::default(),
        );
        assert!(w.file_user_writable);
        assert!(w.owner_trust_blockers.is_empty());
    }

    #[test]
    fn owner_classes() {
        assert_eq!(
            OwnerInfo::from_owner(Some(wk::TRUSTED_INSTALLER)).owner_trust_class,
            OwnerTrustClass::AdminEquivalent
        );
        assert_eq!(
            OwnerInfo::from_owner(Some(wk::LOCAL_SYSTEM)).owner_trust_class,
            OwnerTrustClass::AdminEquivalent
        );
        // Exact match only: a backup operator owner is not admin-equivalent.
        assert_eq!(
            OwnerInfo::from_owner(Some(wk::BACKUP_OPERATORS)).owner_trust_class,
            OwnerTrustClass::NonAdmin
        );
        assert_eq!(
            OwnerInfo::from_owner(None).owner_trust_class,
            OwnerTrustClass::Unknown
        );
        let u = OwnerInfo::unsupported();
        assert!(!u.owner_supported);
        assert_eq!(u.owner_trust_class, OwnerTrustClass::Unknown);
    }

    #[test]
    fn self_relative_round_trip() {
        let mut d = sd(
            wk::ADMINISTRATORS,
            vec![
                Ace::deny(user(5), mask::FILE_WRITE_DATA).with_flags(ace_flags::INHERITED),
                Ace::allow(wk::USERS, RX)
                    .with_flags(ace_flags::INHERITED | ace_flags::OBJECT_INHERIT),
                Ace {
                    kind: AceKind::AllowConditional,
                    flags: 0,
                    mask: mask::FILE_WRITE_DATA,
                    sid: Some(wk::AUTHENTICATED_USERS),
                },
                Ace {
                    kind: AceKind::AllowObject,
                    flags: 0,
                    mask: mask::DELETE,
                    sid: Some(wk::INTERACTIVE),
                },
            ],
        );
        d.group = Some(wk::LOCAL_SYSTEM);
        let bytes = d.to_self_relative().unwrap();
        assert_eq!(SecurityDescriptor::from_self_relative(&bytes), Ok(d));

        let null = SecurityDescriptor::new(Some(wk::LOCAL_SYSTEM), None);
        let bytes = null.to_self_relative().unwrap();
        assert_eq!(SecurityDescriptor::from_self_relative(&bytes), Ok(null));

        // A present-but-NULL DACL keeps its flag through a round trip.
        let mut present_null = SecurityDescriptor::new(Some(wk::LOCAL_SYSTEM), None);
        present_null.control |= control::DACL_PRESENT;
        let bytes = present_null.to_self_relative().unwrap();
        assert_eq!(&bytes[16..20], &[0, 0, 0, 0]);
        let parsed = SecurityDescriptor::from_self_relative(&bytes).unwrap();
        assert_eq!(parsed, present_null);
        assert_ne!(parsed.control & control::DACL_PRESENT, 0);
        assert!(eval_file(&parsed).user_writable());
    }

    #[test]
    fn known_descriptor_bytes() {
        // O:BAD:(A;;0x1301bf;;;BU), built by hand from the documented layout.
        let mut b = vec![1, 0, 0x04, 0x80];
        b.extend_from_slice(&20u32.to_le_bytes()); // owner
        b.extend_from_slice(&0u32.to_le_bytes()); // group
        b.extend_from_slice(&0u32.to_le_bytes()); // SACL
        b.extend_from_slice(&36u32.to_le_bytes()); // DACL
        b.extend_from_slice(&[1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 0x20, 2, 0, 0]);
        b.extend_from_slice(&[2, 0, 32, 0, 1, 0, 0, 0]);
        b.extend_from_slice(&[0, 0, 24, 0]);
        b.extend_from_slice(&MODIFY.to_le_bytes());
        b.extend_from_slice(&[1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 0x21, 2, 0, 0]);
        let d = SecurityDescriptor::from_self_relative(&b).unwrap();
        assert_eq!(d.owner, Some(wk::ADMINISTRATORS));
        assert_eq!(d.dacl, Some(vec![Ace::allow(wk::USERS, MODIFY)]));
        assert!(eval_file(&d).user_writable());
    }

    #[test]
    fn hostile_descriptors_are_errors() {
        let good = sd(wk::ADMINISTRATORS, vec![Ace::allow(wk::USERS, RX)])
            .to_self_relative()
            .unwrap();
        assert_eq!(
            SecurityDescriptor::from_self_relative(&good[..10]),
            Err(DescriptorError::Truncated)
        );
        let mut b = good.clone();
        b[0] = 2;
        assert_eq!(
            SecurityDescriptor::from_self_relative(&b),
            Err(DescriptorError::UnsupportedRevision(2))
        );
        let mut b = good.clone();
        b[3] &= 0x7F;
        assert_eq!(
            SecurityDescriptor::from_self_relative(&b),
            Err(DescriptorError::NotSelfRelative)
        );
        let mut b = good.clone();
        b[4..8].copy_from_slice(&4u32.to_le_bytes());
        assert_eq!(
            SecurityDescriptor::from_self_relative(&b),
            Err(DescriptorError::BadOffset)
        );
        let mut b = good.clone();
        b[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(SecurityDescriptor::from_self_relative(&b).is_err());
        // An ACE count larger than the ACL can hold.
        let dacl = usize::try_from(u32::from_le_bytes(good[16..20].try_into().unwrap())).unwrap();
        let mut b = good.clone();
        b[dacl + 4..dacl + 6].copy_from_slice(&u16::MAX.to_le_bytes());
        assert_eq!(
            SecurityDescriptor::from_self_relative(&b),
            Err(DescriptorError::BadAcl)
        );
        // An ACE size that is not a multiple of 4.
        let mut b = good.clone();
        b[dacl + 10] = 7;
        assert_eq!(
            SecurityDescriptor::from_self_relative(&b),
            Err(DescriptorError::BadAce)
        );
        // An unknown ACE type is kept as unknown, and evaluated as granting
        // everything.
        let mut b = good;
        b[dacl + 8] = 0x11;
        let d = SecurityDescriptor::from_self_relative(&b).unwrap();
        assert!(matches!(
            d.dacl.as_ref().unwrap()[0].kind,
            AceKind::Unknown(0x11)
        ));
        assert!(eval_file(&d).user_writable());
        assert_eq!(
            SecurityDescriptor::from_self_relative(&vec![0u8; MAX_DESCRIPTOR_BYTES + 1]),
            Err(DescriptorError::TooLarge)
        );
    }

    #[test]
    fn dacl_offset_must_match_the_flag_and_be_aligned() {
        let good = sd(wk::ADMINISTRATORS, vec![Ace::allow(wk::USERS, RX)])
            .to_self_relative()
            .unwrap();
        // A nonzero DACL offset with `DACL_PRESENT` clear.
        let mut b = good.clone();
        b[2] &= !0x04;
        assert_eq!(
            SecurityDescriptor::from_self_relative(&b),
            Err(DescriptorError::BadOffset)
        );
        // Both valid zero-offset forms still parse.
        for flags in [0x80, 0x80 | 0x04] {
            let mut b = vec![1, 0, 0, flags];
            b.extend_from_slice(&[0; 16]);
            let d = SecurityDescriptor::from_self_relative(&b).unwrap();
            assert_eq!(d.dacl, None);
        }
        // A misaligned DACL: an empty ACL two bytes after an administrator
        // owner. It would otherwise parse and report no write rights.
        let mut b = vec![1, 0, 0x04, 0x80];
        b.extend_from_slice(&20u32.to_le_bytes()); // owner
        b.extend_from_slice(&0u32.to_le_bytes()); // group
        b.extend_from_slice(&0u32.to_le_bytes()); // SACL
        b.extend_from_slice(&38u32.to_le_bytes()); // DACL, not a multiple of 4
        b.extend_from_slice(&[1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 0x20, 2, 0, 0]);
        b.extend_from_slice(&[0, 0]);
        b.extend_from_slice(&[2, 0, 8, 0, 0, 0, 0, 0]);
        assert_eq!(
            SecurityDescriptor::from_self_relative(&b),
            Err(DescriptorError::BadOffset)
        );
        // The same ACL aligned, with unused bytes after it, is accepted.
        let mut b = vec![1, 0, 0x04, 0x80];
        b.extend_from_slice(&20u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&36u32.to_le_bytes());
        b.extend_from_slice(&[1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 0x20, 2, 0, 0]);
        b.extend_from_slice(&[2, 0, 16, 0, 0, 0, 0, 0]);
        b.extend_from_slice(&[0; 8]);
        let d = SecurityDescriptor::from_self_relative(&b).unwrap();
        assert_eq!(d.dacl, Some(vec![]));
    }

    #[test]
    fn anonymous_is_not_assumed_to_hold_everyone() {
        let d = sd(
            wk::ADMINISTRATORS,
            vec![
                Ace::deny(wk::EVERYONE, mask::FILE_WRITE_DATA),
                Ace::allow(wk::ANONYMOUS, mask::FILE_WRITE_DATA),
            ],
        );
        assert_eq!(eval_file(&d).rights, WriteRights::WRITE_DATA);
    }

    #[test]
    fn network_is_also_evaluated_without_everyone() {
        // An anonymous network token holds `NETWORK` but not `Everyone`.
        let d = sd(
            wk::ADMINISTRATORS,
            vec![
                Ace::deny(wk::EVERYONE, mask::FILE_WRITE_DATA),
                Ace::allow(wk::NETWORK, mask::FILE_WRITE_DATA),
            ],
        );
        let w = eval_file(&d);
        assert_eq!(w.rights, WriteRights::WRITE_DATA);
        assert_eq!(w.uncertain, WriteRights::NONE);
        assert!(
            w.principals
                .iter()
                .any(|p| p.principal == Principal::Sid(wk::NETWORK))
        );
        let a = assess_path(
            Some(&d),
            ObjectKind::File,
            &[],
            &EvaluationOptions::default(),
        );
        assert!(a.owner_trust_blockers.contains(WriteRights::WRITE_DATA));
        // With `Everyone` the deny still counts for `NETWORK`.
        let d = sd(
            wk::ADMINISTRATORS,
            vec![
                Ace::deny(wk::NETWORK, mask::FILE_WRITE_DATA),
                Ace::allow(wk::NETWORK, mask::FILE_WRITE_DATA),
            ],
        );
        assert!(!eval_file(&d).user_writable());
    }

    #[test]
    fn rights_display() {
        assert_eq!(WriteRights::NONE.to_string(), "none");
        assert_eq!(
            WriteRights::CHANGE_PERMISSIONS.to_string(),
            "WRITE_DAC|WRITE_OWNER"
        );
    }
}
