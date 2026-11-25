//! Package identity strings: the publisher ID, the package family name and
//! the package full name.
//!
//! # The publisher ID
//!
//! The OS derives a 13-character ID from the publisher's distinguished name
//! string exactly as written in the manifest's `Identity@Publisher`:
//!
//! 1. Encode the string as UTF-16LE (no byte order mark, no terminator).
//! 2. Take the SHA-256 of those bytes and keep the first 8 bytes.
//! 3. Read those 64 bits as a big-endian bit string, pad it with one zero
//!    bit to 65 bits, and split it into 13 groups of 5 bits.
//! 4. Map each group to Crockford's base32 alphabet in lowercase:
//!    `0123456789abcdefghjkmnpqrstvwxyz` (no `i`, `l`, `o`, `u`).
//!
//! The package family name is `{Name}_{PublisherId}` and the package full
//! name `{Name}_{Version}_{Architecture}_{ResourceId}_{PublisherId}`, with
//! the architecture in lowercase (`neutral` when none is given) and an empty
//! resource ID for none, so `Name_1.0.0.0_x64__8wekyb3d8bbwe`. A bundle's
//! resource ID is `~`: `Bundle_1.0.0.0_neutral_~_8wekyb3d8bbwe`.

#![forbid(unsafe_code)]

use std::fmt;

use crate::hash::sha256_of;

const CROCKFORD: &[u8; 32] = b"0123456789abcdefghjkmnpqrstvwxyz";

/// The publisher ID of a publisher DN string.
#[must_use]
pub fn publisher_id(publisher: &str) -> String {
    let utf16: Vec<u8> = publisher
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let digest = sha256_of(&utf16);
    let mut first = [0_u8; 8];
    for (slot, b) in first.iter_mut().zip(digest.as_bytes()) {
        *slot = *b;
    }
    // 64 bits, then one zero bit of padding: 65 bits in 13 groups of 5.
    let bits = u128::from(u64::from_be_bytes(first)) << 1;
    (0..13)
        .map(|i| {
            let shift = 5 * (12 - i);
            let v = usize::try_from((bits >> shift) & 0x1f).unwrap_or(0);
            char::from(CROCKFORD.get(v).copied().unwrap_or(b'0'))
        })
        .collect()
}

/// A package version, `major.minor.build.revision`, each part 0 to 65535.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct PackageVersion(pub u16, pub u16, pub u16, pub u16);

impl PackageVersion {
    /// Parses exactly four dot-separated decimal parts, as the manifest
    /// schema requires. Leading zeros are allowed (`01` is 1); signs,
    /// spaces, empty parts and values over 65535 are not.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let mut parts = [0_u16; 4];
        let mut it = text.split('.');
        for slot in &mut parts {
            let p = it.next()?;
            if p.is_empty() || p.len() > 5 || !p.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            *slot = p.parse().ok()?;
        }
        if it.next().is_some() {
            return None;
        }
        let [a, b, c, d] = parts;
        Some(Self(a, b, c, d))
    }
}

impl fmt::Display for PackageVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}.{}", self.0, self.1, self.2, self.3)
    }
}

/// The package family name.
#[must_use]
pub fn family_name(name: &str, publisher_id: &str) -> String {
    format!("{name}_{publisher_id}")
}

/// The package full name. `arch` is lowercased, and `neutral` when empty.
#[must_use]
pub fn full_name(
    name: &str,
    version: PackageVersion,
    arch: &str,
    resource_id: &str,
    publisher_id: &str,
) -> String {
    let arch = if arch.is_empty() {
        "neutral".to_owned()
    } else {
        arch.to_ascii_lowercase()
    };
    format!("{name}_{version}_{arch}_{resource_id}_{publisher_id}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions() {
        assert_eq!(
            PackageVersion::parse("1.2.3.4"),
            Some(PackageVersion(1, 2, 3, 4))
        );
        assert_eq!(
            PackageVersion::parse("65535.0.01.0"),
            Some(PackageVersion(65535, 0, 1, 0))
        );
        for bad in [
            "1.2.3",
            "1.2.3.4.5",
            "1.2.3.65536",
            "1.2.3.-1",
            "1..2.3",
            " 1.2.3.4",
            "a.b.c.d",
        ] {
            assert_eq!(PackageVersion::parse(bad), None, "{bad}");
        }
        assert!(PackageVersion(10, 0, 0, 0) > PackageVersion(9, 9, 9, 9));
    }

    #[test]
    fn full_names() {
        assert_eq!(
            full_name("A.B", PackageVersion(1, 0, 0, 0), "X64", "", "abc"),
            "A.B_1.0.0.0_x64__abc"
        );
        assert_eq!(
            full_name("A", PackageVersion(1, 0, 0, 0), "", "en-us", "abc"),
            "A_1.0.0.0_neutral_en-us_abc"
        );
    }
}
