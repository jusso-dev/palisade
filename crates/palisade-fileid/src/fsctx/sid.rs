//! Security identifiers (SIDs).
//!
//! [`Sid`] is a plain value type: string form (`S-1-5-32-544`) and binary
//! form (as stored in a security descriptor) both parse into it, and it
//! formats back to the string form. Nothing here calls the OS, so name
//! lookup (`owner_name`) is left to the Windows backend.
//!
//! The well-known SIDs this crate needs are constants in [`well_known`].

#![forbid(unsafe_code)]

use std::fmt;
use std::str::FromStr;

/// The most sub-authorities a SID can have (`SID_MAX_SUB_AUTHORITIES`).
pub const MAX_SUB_AUTHORITIES: usize = 15;

/// The largest identifier authority: it is a 48-bit value.
const MAX_AUTHORITY: u64 = (1 << 48) - 1;

/// A security identifier, revision 1.
///
/// Equality is exact: two SIDs are equal only when their identifier
/// authority and every sub-authority are equal. There is no group
/// expansion here; that is the job of the evaluator that knows a token.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Sid {
    authority: u64,
    count: u8,
    // Entries at and after `count` are always zero, so the derived
    // comparisons only see the meaningful part.
    subs: [u32; MAX_SUB_AUTHORITIES],
}

impl Sid {
    /// Builds a SID from its identifier authority and sub-authorities.
    ///
    /// Returns `None` if the authority does not fit in 48 bits or there are
    /// more than [`MAX_SUB_AUTHORITIES`] sub-authorities.
    #[must_use]
    pub fn new(authority: u64, sub_authorities: &[u32]) -> Option<Self> {
        if authority > MAX_AUTHORITY || sub_authorities.len() > MAX_SUB_AUTHORITIES {
            return None;
        }
        let mut subs = [0u32; MAX_SUB_AUTHORITIES];
        for (slot, value) in subs.iter_mut().zip(sub_authorities) {
            *slot = *value;
        }
        Some(Self {
            authority,
            count: u8::try_from(sub_authorities.len()).ok()?,
            subs,
        })
    }

    /// Compile-time constructor for the constants in [`well_known`].
    /// Evaluating it with more than 15 sub-authorities is a compile error.
    const fn constant(authority: u64, sub_authorities: &[u32]) -> Self {
        assert!(sub_authorities.len() <= MAX_SUB_AUTHORITIES);
        assert!(authority <= MAX_AUTHORITY);
        let mut subs = [0u32; MAX_SUB_AUTHORITIES];
        let mut i = 0;
        while i < sub_authorities.len() {
            // Const code cannot use iterators. The assertion above keeps
            // `i` in bounds for both slices.
            #[allow(clippy::indexing_slicing)]
            {
                subs[i] = sub_authorities[i];
            }
            i += 1;
        }
        // The assertion above bounds the length to 15.
        #[allow(clippy::cast_possible_truncation)]
        let count = sub_authorities.len() as u8;
        Self {
            authority,
            count,
            subs,
        }
    }

    /// The 48-bit identifier authority (5 for `NT AUTHORITY`).
    #[must_use]
    pub const fn authority(&self) -> u64 {
        self.authority
    }

    /// The sub-authorities, in order.
    #[must_use]
    pub fn sub_authorities(&self) -> &[u32] {
        self.subs.get(..usize::from(self.count)).unwrap_or(&[])
    }

    /// Parses the binary form used inside security descriptors: revision
    /// (1), sub-authority count, 6-byte big-endian identifier authority, then
    /// that many little-endian `u32` sub-authorities.
    ///
    /// Returns the SID and the number of bytes it used. Trailing bytes are
    /// left for the caller.
    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, usize), SidError> {
        let [revision, count, rest @ ..] = bytes else {
            return Err(SidError::Truncated);
        };
        if *revision != 1 {
            return Err(SidError::UnsupportedRevision(*revision));
        }
        let count = usize::from(*count);
        if count > MAX_SUB_AUTHORITIES {
            return Err(SidError::TooManySubAuthorities);
        }
        let Some((auth, rest)) = rest.split_first_chunk::<6>() else {
            return Err(SidError::Truncated);
        };
        let authority = auth.iter().fold(0u64, |acc, b| (acc << 8) | u64::from(*b));
        let mut subs = [0u32; MAX_SUB_AUTHORITIES];
        let mut rest = rest;
        for slot in subs.iter_mut().take(count) {
            let Some((chunk, tail)) = rest.split_first_chunk::<4>() else {
                return Err(SidError::Truncated);
            };
            *slot = u32::from_le_bytes(*chunk);
            rest = tail;
        }
        let sid = Self::new(authority, subs.get(..count).unwrap_or(&[]))
            .ok_or(SidError::TooManySubAuthorities)?;
        Ok((sid, 8 + 4 * count))
    }

    /// The binary form (see [`Sid::from_bytes`]).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + 4 * usize::from(self.count));
        out.push(1);
        out.push(self.count);
        out.extend_from_slice(self.authority.to_be_bytes().get(2..).unwrap_or(&[]));
        for sub in self.sub_authorities() {
            out.extend_from_slice(&sub.to_le_bytes());
        }
        out
    }
}

impl fmt::Display for Sid {
    /// The string form. As the OS does, an authority below 2^32 is decimal
    /// and a larger one is 12 hexadecimal digits with a `0x` prefix.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.authority < (1 << 32) {
            write!(f, "S-1-{}", self.authority)?;
        } else {
            write!(f, "S-1-0x{:012X}", self.authority)?;
        }
        for sub in self.sub_authorities() {
            write!(f, "-{sub}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Sid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sid({self})")
    }
}

impl FromStr for Sid {
    type Err = SidError;

    /// Parses `S-1-<authority>(-<sub-authority>)*`. The `S` may be either
    /// case. Every number must be plain ASCII digits (no sign, no spaces);
    /// the authority may instead be `0x` and 1 to 12 hex digits.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.split('-');
        match parts.next() {
            Some("S" | "s") => {}
            _ => return Err(SidError::Syntax),
        }
        match parts.next() {
            Some("1") => {}
            Some(r) => {
                return Err(match parse_decimal(r) {
                    // The only supported revision must be written `1`;
                    // `01` is a syntax error, not an unsupported revision.
                    Some(1) | None => SidError::Syntax,
                    Some(v) => SidError::UnsupportedRevision(u8::try_from(v).unwrap_or(u8::MAX)),
                });
            }
            None => return Err(SidError::Syntax),
        }
        let authority = match parts.next() {
            Some(a) => parse_authority(a).ok_or(SidError::Syntax)?,
            None => return Err(SidError::Syntax),
        };
        let mut subs = Vec::new();
        for part in parts {
            if subs.len() == MAX_SUB_AUTHORITIES {
                return Err(SidError::TooManySubAuthorities);
            }
            let v = parse_decimal(part).ok_or(SidError::Syntax)?;
            subs.push(u32::try_from(v).map_err(|_| SidError::Syntax)?);
        }
        Self::new(authority, &subs).ok_or(SidError::Syntax)
    }
}

/// Parses 1 to 20 ASCII digits.
fn parse_decimal(s: &str) -> Option<u64> {
    if s.is_empty() || s.len() > 20 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

fn parse_authority(s: &str) -> Option<u64> {
    let v = match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(hex) => {
            if hex.is_empty() || hex.len() > 12 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                return None;
            }
            u64::from_str_radix(hex, 16).ok()?
        }
        None => parse_decimal(s)?,
    };
    (v <= MAX_AUTHORITY).then_some(v)
}

/// Why a SID could not be parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SidError {
    /// The string is not `S-1-…` with numeric parts.
    Syntax,
    /// The revision is not 1.
    UnsupportedRevision(u8),
    /// More than [`MAX_SUB_AUTHORITIES`] sub-authorities.
    TooManySubAuthorities,
    /// The binary form ends early.
    Truncated,
}

impl fmt::Display for SidError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Syntax => f.write_str("not a SID string"),
            Self::UnsupportedRevision(r) => write!(f, "unsupported SID revision {r}"),
            Self::TooManySubAuthorities => {
                write!(f, "a SID has at most {MAX_SUB_AUTHORITIES} sub-authorities")
            }
            Self::Truncated => f.write_str("SID bytes end early"),
        }
    }
}

impl std::error::Error for SidError {}

/// Well-known SIDs used by the writability and owner checks.
pub mod well_known {
    use super::Sid;

    /// `NULL SID` (S-1-0-0). In no ordinary token.
    pub const NULL: Sid = Sid::constant(0, &[0]);
    /// `Everyone` (S-1-1-0). In every token except anonymous ones.
    pub const EVERYONE: Sid = Sid::constant(1, &[0]);
    /// `LOCAL` (S-1-2-0): users logged on locally.
    pub const LOCAL: Sid = Sid::constant(2, &[0]);
    /// `CONSOLE LOGON` (S-1-2-1).
    pub const CONSOLE_LOGON: Sid = Sid::constant(2, &[1]);
    /// `CREATOR OWNER` (S-1-3-0): a placeholder in inheritable ACEs,
    /// replaced by the creator's SID when an object inherits the ACE.
    pub const CREATOR_OWNER: Sid = Sid::constant(3, &[0]);
    /// `CREATOR GROUP` (S-1-3-1): a placeholder, like `CREATOR OWNER`.
    pub const CREATOR_GROUP: Sid = Sid::constant(3, &[1]);
    /// `CREATOR OWNER SERVER` (S-1-3-2): a placeholder.
    pub const CREATOR_OWNER_SERVER: Sid = Sid::constant(3, &[2]);
    /// `CREATOR GROUP SERVER` (S-1-3-3): a placeholder.
    pub const CREATOR_GROUP_SERVER: Sid = Sid::constant(3, &[3]);
    /// `OWNER RIGHTS` (S-1-3-4): an ACE for it applies to the object's
    /// current owner and replaces the owner's implicit rights.
    pub const OWNER_RIGHTS: Sid = Sid::constant(3, &[4]);
    /// `NETWORK` (S-1-5-2): users logged on over the network. An anonymous
    /// network logon holds it without `Everyone`.
    pub const NETWORK: Sid = Sid::constant(5, &[2]);
    /// `INTERACTIVE` (S-1-5-4).
    pub const INTERACTIVE: Sid = Sid::constant(5, &[4]);
    /// `ANONYMOUS LOGON` (S-1-5-7).
    pub const ANONYMOUS: Sid = Sid::constant(5, &[7]);
    /// `Authenticated Users` (S-1-5-11).
    pub const AUTHENTICATED_USERS: Sid = Sid::constant(5, &[11]);
    /// `SYSTEM` (`LocalSystem`, S-1-5-18).
    pub const LOCAL_SYSTEM: Sid = Sid::constant(5, &[18]);
    /// `LOCAL SERVICE` (S-1-5-19).
    pub const LOCAL_SERVICE: Sid = Sid::constant(5, &[19]);
    /// `NETWORK SERVICE` (S-1-5-20).
    pub const NETWORK_SERVICE: Sid = Sid::constant(5, &[20]);
    /// `BUILTIN\Administrators` (S-1-5-32-544).
    pub const ADMINISTRATORS: Sid = Sid::constant(5, &[32, 544]);
    /// `BUILTIN\Users` (S-1-5-32-545).
    pub const USERS: Sid = Sid::constant(5, &[32, 545]);
    /// `BUILTIN\Guests` (S-1-5-32-546).
    pub const GUESTS: Sid = Sid::constant(5, &[32, 546]);
    /// `BUILTIN\Server Operators` (S-1-5-32-549).
    pub const SERVER_OPERATORS: Sid = Sid::constant(5, &[32, 549]);
    /// `BUILTIN\Print Operators` (S-1-5-32-550).
    pub const PRINT_OPERATORS: Sid = Sid::constant(5, &[32, 550]);
    /// `BUILTIN\Backup Operators` (S-1-5-32-551).
    pub const BACKUP_OPERATORS: Sid = Sid::constant(5, &[32, 551]);
    /// `BUILTIN\Performance Log Users` (S-1-5-32-559).
    pub const PERFORMANCE_LOG_USERS: Sid = Sid::constant(5, &[32, 559]);
    /// The built-in web server worker group (S-1-5-32-568).
    pub const WEB_WORKERS: Sid = Sid::constant(5, &[32, 568]);
    /// `BUILTIN\RDS Management Servers` (S-1-5-32-577).
    pub const REMOTE_DESKTOP_MANAGEMENT_SERVERS: Sid = Sid::constant(5, &[32, 577]);
    /// The `TrustedInstaller` service SID
    /// (`NT SERVICE\TrustedInstaller`), which owns and services OS files.
    pub const TRUSTED_INSTALLER: Sid = Sid::constant(
        5,
        &[
            80,
            956_008_885,
            3_418_522_649,
            1_831_038_044,
            1_853_292_631,
            2_271_478_464,
        ],
    );
    /// The first of the two app-capability SIDs that OS path-rule
    /// protection lists for system components.
    pub const OS_APP_CAPABILITY_1: Sid = Sid::constant(
        15,
        &[
            2,
            1_430_448_594,
            2_639_229_838,
            973_813_799,
            439_329_657,
            1_197_984_847,
            4_069_167_804,
            1_277_922_394,
        ],
    );
    /// The second of the two app-capability SIDs that OS path-rule
    /// protection lists for system components.
    pub const OS_APP_CAPABILITY_2: Sid = Sid::constant(
        15,
        &[
            2,
            95_739_096,
            486_727_260,
            2_033_287_795,
            3_853_587_803,
            1_685_597_119,
            444_378_811,
            2_746_676_523,
        ],
    );

    /// True for the `CREATOR …` placeholders (S-1-3-0 to S-1-3-3). They
    /// are never in a token, so an ACE for one that applies to the object
    /// itself (not inherit-only) grants nobody anything.
    #[must_use]
    pub fn is_creator_placeholder(sid: &Sid) -> bool {
        *sid == CREATOR_OWNER
            || *sid == CREATOR_GROUP
            || *sid == CREATOR_OWNER_SERVER
            || *sid == CREATOR_GROUP_SERVER
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_round_trip() {
        for s in [
            "S-1-0-0",
            "S-1-1-0",
            "S-1-5-18",
            "S-1-5-32-544",
            "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
            "S-1-15-2-1430448594-2639229838-973813799-439329657-1197984847-4069167804-1277922394",
            "S-1-5",
            "S-1-0x000100000000-1",
            "S-1-4294967295-1",
        ] {
            let sid: Sid = s.parse().unwrap();
            assert_eq!(sid.to_string(), s);
        }
        assert_eq!(
            "s-1-5-32-544".parse::<Sid>().unwrap(),
            well_known::ADMINISTRATORS
        );
        // A small authority given in hex prints in decimal, as the OS does.
        assert_eq!("S-1-0x5-18".parse::<Sid>().unwrap().to_string(), "S-1-5-18");
    }

    #[test]
    fn constants_match_their_string_forms() {
        assert_eq!(well_known::LOCAL_SYSTEM.to_string(), "S-1-5-18");
        assert_eq!(well_known::USERS.to_string(), "S-1-5-32-545");
        assert_eq!(
            well_known::TRUSTED_INSTALLER.to_string(),
            "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
        );
        assert_eq!(
            well_known::OS_APP_CAPABILITY_2.to_string(),
            "S-1-15-2-95739096-486727260-2033287795-3853587803-1685597119-444378811-2746676523"
        );
    }

    #[test]
    fn rejects_bad_strings() {
        for s in [
            "",
            "S",
            "S-1",
            "S-2-5-18",
            "X-1-5-18",
            "S-1--18",
            "S-1-5-",
            "S-1-5-+18",
            "S-1-5- 18",
            "S-1-5-4294967296",
            "S-1-281474976710656",
            "S-1-0x1000000000000",
            "S-1-0x",
            "S-1-5-1-2-3-4-5-6-7-8-9-10-11-12-13-14-15-16",
        ] {
            assert!(s.parse::<Sid>().is_err(), "{s:?} should not parse");
        }
        assert_eq!(
            "S-1-5-1-2-3-4-5-6-7-8-9-10-11-12-13-14-15-16".parse::<Sid>(),
            Err(SidError::TooManySubAuthorities)
        );
        assert_eq!(
            "S-2-5".parse::<Sid>(),
            Err(SidError::UnsupportedRevision(2))
        );
        assert_eq!(
            "S-2-5-18".parse::<Sid>(),
            Err(SidError::UnsupportedRevision(2))
        );
        for s in ["S-01-5-18", "S-001-5-18"] {
            assert_eq!(s.parse::<Sid>(), Err(SidError::Syntax), "{s}");
        }
    }

    #[test]
    fn binary_round_trip() {
        let sid = well_known::TRUSTED_INSTALLER;
        let mut bytes = sid.to_bytes();
        assert_eq!(bytes.len(), 8 + 4 * 6);
        assert_eq!(&bytes[..8], &[1, 6, 0, 0, 0, 0, 0, 5]);
        bytes.extend_from_slice(&[0xAA, 0xBB]);
        assert_eq!(Sid::from_bytes(&bytes), Ok((sid, 32)));
    }

    #[test]
    fn binary_rejects_bad_input() {
        assert_eq!(Sid::from_bytes(&[]), Err(SidError::Truncated));
        assert_eq!(
            Sid::from_bytes(&[2, 0, 0, 0, 0, 0, 0, 5]),
            Err(SidError::UnsupportedRevision(2))
        );
        assert_eq!(
            Sid::from_bytes(&[1, 16, 0, 0, 0, 0, 0, 5]),
            Err(SidError::TooManySubAuthorities)
        );
        assert_eq!(
            Sid::from_bytes(&[1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0]),
            Err(SidError::Truncated)
        );
        assert_eq!(Sid::from_bytes(&[1, 0, 0, 0, 0]), Err(SidError::Truncated));
    }

    #[test]
    fn equality_is_exact() {
        let a: Sid = "S-1-5-32-544".parse().unwrap();
        let b: Sid = "S-1-5-32-544-0".parse().unwrap();
        assert_ne!(a, b);
        assert_eq!(Sid::new(5, &[32, 544]), Some(a));
        assert_eq!(Sid::new(1 << 48, &[]), None);
        assert_eq!(Sid::new(5, &[0; 16]), None);
    }
}
