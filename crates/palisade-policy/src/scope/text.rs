//! Parsing and matching of the text forms scopes use: address blocks and
//! ranges, hardware addresses, DNS suffixes, wildcards and distinguished
//! names. Validation and compilation share these, so a value that
//! validates always compiles to the same test.

use std::net::IpAddr;

use crate::ops::fold;

use super::model::limits::MAX_SCOPE_VALUE_BYTES;

/// An inclusive range of addresses of one family.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IpRange {
    first: u128,
    last: u128,
    v6: bool,
}

impl IpRange {
    /// Parses an address block, `10.0.0.0/8` or `2001:db8::/32`. The
    /// address must be the block's first address (no host bits set).
    pub fn cidr(s: &str) -> Result<Self, String> {
        let (addr, len) = s
            .split_once('/')
            .ok_or_else(|| format!("`{s}` is not an address block such as `10.0.0.0/8`"))?;
        let addr: IpAddr = addr
            .parse()
            .map_err(|_| format!("`{addr}` is not an IP address"))?;
        let (value, bits, v6) = split(addr);
        let len: u32 = (!len.is_empty() && len.bytes().all(|b| b.is_ascii_digit()))
            .then(|| len.parse().ok())
            .flatten()
            .filter(|l| *l <= bits)
            .ok_or_else(|| format!("`/{len}` is not a prefix length from 0 to {bits}"))?;
        let host_bits = bits - len;
        let mask: u128 = if host_bits == 128 {
            u128::MAX
        } else {
            (1u128 << host_bits) - 1
        };
        if value & mask != 0 {
            return Err(format!(
                "`{s}` has host bits set; the block starts at its first address"
            ));
        }
        Ok(Self {
            first: value,
            last: value | mask,
            v6,
        })
    }

    /// Parses an inclusive range, `10.0.0.10-10.0.0.99`. Both ends are the
    /// same family, and the first is not after the last.
    pub fn range(s: &str) -> Result<Self, String> {
        let (a, b) = s
            .split_once('-')
            .ok_or_else(|| format!("`{s}` is not a range such as `10.0.0.1-10.0.0.9`"))?;
        let parse = |t: &str| {
            t.parse::<IpAddr>()
                .map_err(|_| format!("`{t}` is not an IP address"))
        };
        let (a, b) = (split(parse(a)?), split(parse(b)?));
        if a.2 != b.2 {
            return Err(format!("`{s}` mixes IPv4 and IPv6"));
        }
        if a.0 > b.0 {
            return Err(format!("`{s}` ends before it starts"));
        }
        Ok(Self {
            first: a.0,
            last: b.0,
            v6: a.2,
        })
    }

    /// A block or a range, whichever `s` is.
    pub fn block_or_range(s: &str) -> Result<Self, String> {
        if s.contains('/') {
            Self::cidr(s)
        } else {
            Self::range(s)
        }
    }

    /// Whether `addr` is in the range. An IPv4 address and the
    /// IPv4-mapped IPv6 address `::ffff:a.b.c.d` are the same address, so
    /// either form is in an IPv4 range that holds it and in an IPv6 range
    /// that holds its mapped form (`::ffff:10.0.0.0/104` is `10.0.0.0/8`,
    /// and `::/0` holds every address).
    #[must_use]
    pub fn contains(&self, addr: IpAddr) -> bool {
        let v4 = match addr {
            IpAddr::V4(a) => Some(a),
            IpAddr::V6(a) => a.to_ipv4_mapped(),
        };
        let within = |a: IpAddr| {
            let (value, _, v6) = split(a);
            v6 == self.v6 && self.first <= value && value <= self.last
        };
        match v4 {
            Some(a) => within(IpAddr::V4(a)) || within(IpAddr::V6(a.to_ipv6_mapped())),
            None => within(addr),
        }
    }
}

/// An address as a number, its width in bits, and whether it is IPv6.
fn split(addr: IpAddr) -> (u128, u32, bool) {
    match addr {
        IpAddr::V4(a) => (u128::from(u32::from(a)), 32, false),
        IpAddr::V6(a) => (u128::from(a), 128, true),
    }
}

/// Parses a hardware address: six pairs of hex digits separated by `-` or
/// `:`, in either case.
pub fn mac(s: &str) -> Result<[u8; 6], String> {
    let err = || format!("`{s}` is not a hardware address such as `00-1a-2b-3c-4d-5e`");
    let sep = if s.contains(':') { ':' } else { '-' };
    let mut out = [0u8; 6];
    let mut parts = s.split(sep);
    for byte in &mut out {
        let part = parts.next().ok_or_else(err)?;
        if part.len() != 2 || !part.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(err());
        }
        *byte = u8::from_str_radix(part, 16).map_err(|_| err())?;
    }
    if parts.next().is_some() {
        return Err(err());
    }
    Ok(out)
}

/// The canonical form of a DNS suffix: lowercase ASCII, without a leading
/// or trailing dot. Each label is 1 to 63 letters, digits or hyphens, not
/// starting or ending with a hyphen, and the whole is at most 253 bytes.
pub fn dns_suffix(s: &str) -> Result<String, String> {
    let t = s.strip_prefix('.').unwrap_or(s);
    let t = t.strip_suffix('.').unwrap_or(t);
    let ok = !t.is_empty()
        && t.len() <= 253
        && t.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        });
    if ok {
        Ok(t.to_ascii_lowercase())
    } else {
        Err(format!(
            "`{s}` is not a DNS name such as `corp.example.org`"
        ))
    }
}

/// Whether the fact `name` is `suffix` or a name below it. `suffix` is
/// canonical ([`dns_suffix`]).
#[must_use]
pub fn dns_within(name: &str, suffix: &str) -> bool {
    let name = name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase();
    name == suffix
        || name
            .strip_suffix(suffix)
            .is_some_and(|head| head.ends_with('.'))
}

/// Checks a free-text scope value: not empty, at most
/// [`MAX_SCOPE_VALUE_BYTES`] bytes, no control characters, and not
/// starting or ending with whitespace.
pub fn plain(s: &str) -> Result<(), String> {
    if s.is_empty() {
        Err("must not be empty".to_owned())
    } else if s.len() > MAX_SCOPE_VALUE_BYTES {
        Err(format!(
            "{} bytes; at most {MAX_SCOPE_VALUE_BYTES} are allowed",
            s.len()
        ))
    } else if s.chars().any(|c| c.is_control() || is_bidi_control(c)) {
        Err("must not contain control or bidirectional formatting characters".to_owned())
    } else if s.trim() != s {
        Err("must not start or end with whitespace".to_owned())
    } else {
        Ok(())
    }
}

/// Unicode bidirectional formatting characters, which can make a value
/// read differently from what it contains.
const fn is_bidi_control(c: char) -> bool {
    matches!(c, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}

/// A wildcard: `*` matches any run of characters (including none) and `?`
/// exactly one. Compared without case (Unicode simple case folding, after
/// NFC), unless built case-sensitive.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Wildcard {
    pattern: Vec<char>,
    case_sensitive: bool,
}

impl Wildcard {
    /// Compiles a pattern. It must pass [`plain`].
    pub fn new(pattern: &str, case_sensitive: bool) -> Result<Self, String> {
        plain(pattern)?;
        Ok(Self {
            pattern: fold(pattern, case_sensitive).chars().collect(),
            case_sensitive,
        })
    }

    /// Whether `text` matches the whole pattern.
    ///
    /// The usual greedy matcher with one backtrack point: on a mismatch it
    /// retries from the last `*`, consuming one more character. That is
    /// at most `pattern × text` steps, and both are bounded.
    #[must_use]
    pub fn matches(&self, text: &str) -> bool {
        let text: Vec<char> = fold(text, self.case_sensitive).chars().collect();
        let p = &self.pattern;
        let (mut ti, mut pi) = (0usize, 0usize);
        let mut star: Option<(usize, usize)> = None;
        while ti < text.len() {
            match p.get(pi) {
                Some('*') => {
                    star = Some((pi, ti));
                    pi += 1;
                }
                Some(&c) if c == '?' || c == text[ti] => {
                    pi += 1;
                    ti += 1;
                }
                _ => match star {
                    Some((sp, st)) => {
                        pi = sp + 1;
                        ti = st + 1;
                        star = Some((sp, st + 1));
                    }
                    None => return false,
                },
            }
        }
        p[pi..].iter().all(|&c| c == '*')
    }
}

/// A distinguished name as its relative names, each trimmed and folded to
/// lowercase, from the object up. `None` if `s` is not one.
///
/// Commas escaped with `\` stay inside a name. Directory names compare
/// without case, so `OU=Finance,DC=Corp` equals `ou=finance, dc=corp`.
#[must_use]
pub fn dn(s: &str) -> Option<Vec<String>> {
    // A directory name fact may be longer than a policy value; the
    // directory allows far more than 512 bytes.
    if s.is_empty() || s.len() > MAX_DN_BYTES || s.chars().any(char::is_control) {
        return None;
    }
    let mut rdns = Vec::new();
    let mut current = String::new();
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                current.push(c);
                current.push(chars.next()?);
            }
            ',' => rdns.push(core::mem::take(&mut current)),
            _ => current.push(c),
        }
    }
    rdns.push(current);
    rdns.into_iter()
        .map(|rdn| {
            let (attr, value) = rdn.split_once('=')?;
            let (attr, value) = (attr.trim(), value.trim());
            let attr_ok = !attr.is_empty()
                && attr
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.');
            (attr_ok && !value.is_empty())
                .then(|| format!("{}={}", attr.to_ascii_lowercase(), fold_lower(value)))
        })
        .collect()
}

/// The longest distinguished name read, in bytes.
pub const MAX_DN_BYTES: usize = 16 * 1024;

/// Lowercase, after NFC, for directory names.
fn fold_lower(s: &str) -> String {
    use unicode_normalization::UnicodeNormalization;
    s.nfc().flat_map(char::to_lowercase).collect()
}

/// Whether the object named `object` is directly in the OU `ou`, or with
/// `sub` anywhere below it. Both are parsed with [`dn`].
#[must_use]
pub fn in_ou(object: &[String], ou: &[String], sub: bool) -> bool {
    let Some((_, parent)) = object.split_first() else {
        return false;
    };
    if sub {
        parent.ends_with(ou)
    } else {
        parent == ou
    }
}

/// A local group name, folded for comparison.
#[must_use]
pub fn group_name(s: &str) -> String {
    fold(s, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_and_ranges() {
        let block = IpRange::cidr("10.20.0.0/16").unwrap();
        assert!(block.contains("10.20.255.1".parse().unwrap()));
        assert!(!block.contains("10.21.0.0".parse().unwrap()));
        assert!(block.contains("::ffff:10.20.1.1".parse().unwrap()));
        assert!(!block.contains("2001:db8::1".parse().unwrap()));
        assert!(IpRange::cidr("10.20.0.1/16").is_err());
        assert!(IpRange::cidr("10.0.0.0/33").is_err());
        assert!(IpRange::cidr("10.0.0.0/").is_err());
        assert!(
            IpRange::cidr("0.0.0.0/0")
                .unwrap()
                .contains("1.2.3.4".parse().unwrap())
        );
        let all6 = IpRange::cidr("::/0").unwrap();
        assert!(all6.contains("2001:db8::1".parse().unwrap()));
        let v6 = IpRange::cidr("2001:db8::/32").unwrap();
        assert!(v6.contains("2001:db8:ffff::1".parse().unwrap()));
        let range = IpRange::range("10.0.0.10-10.0.0.99").unwrap();
        assert!(range.contains("10.0.0.10".parse().unwrap()));
        assert!(range.contains("10.0.0.99".parse().unwrap()));
        assert!(!range.contains("10.0.0.100".parse().unwrap()));
        assert!(IpRange::range("10.0.0.9-10.0.0.1").is_err());
        assert!(IpRange::range("10.0.0.1-::1").is_err());
        // IPv4-mapped forms are the same addresses.
        let mapped = IpRange::cidr("::ffff:10.20.0.0/112").unwrap();
        assert!(mapped.contains("10.20.3.4".parse().unwrap()));
        assert!(mapped.contains("::ffff:10.20.3.4".parse().unwrap()));
        assert!(!mapped.contains("10.21.0.0".parse().unwrap()));
        let mapped_range = IpRange::range("::ffff:10.0.0.1-::ffff:10.0.0.9").unwrap();
        assert!(mapped_range.contains("10.0.0.1".parse().unwrap()));
        assert!(mapped_range.contains("::ffff:10.0.0.9".parse().unwrap()));
        assert!(all6.contains("::ffff:10.20.1.1".parse().unwrap()));
        assert!(all6.contains("10.20.1.1".parse().unwrap()));
    }

    #[test]
    fn macs_and_suffixes() {
        assert_eq!(
            mac("00-1A-2b-3c-4d-5e").unwrap(),
            [0, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e]
        );
        assert_eq!(
            mac("00:1a:2b:3c:4d:5e").unwrap(),
            [0, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e]
        );
        assert!(mac("00-1a-2b-3c-4d").is_err());
        assert!(mac("00-1a-2b-3c-4d-5e-6f").is_err());
        assert!(mac("0-1a-2b-3c-4d-5e").is_err());
        assert!(mac("+0-1a-2b-3c-4d-5e").is_err());
        assert!(mac("00-+a-2b-3c-4d-5e").is_err());
        assert_eq!(
            dns_suffix(".Corp.Example.org.").unwrap(),
            "corp.example.org"
        );
        assert!(dns_suffix("corp..example").is_err());
        assert!(dns_suffix("-corp.example").is_err());
        assert!(dns_within("WS1.corp.example.org.", "corp.example.org"));
        assert!(dns_within("corp.example.org", "corp.example.org"));
        assert!(!dns_within("evilcorp.example.org", "corp.example.org"));
    }

    #[test]
    fn wildcards() {
        let w = Wildcard::new("*\\svc_*", false).unwrap();
        assert!(w.matches("CORP\\SVC_backup"));
        assert!(!w.matches("CORP\\alice"));
        let h = Wildcard::new("FIN-??", false).unwrap();
        assert!(h.matches("fin-01"));
        assert!(!h.matches("fin-001"));
        assert!(Wildcard::new("a*b*c", false).unwrap().matches("aXXbYYc"));
        assert!(!Wildcard::new("a*b*c", false).unwrap().matches("aXXbYY"));
        assert!(Wildcard::new("*", false).unwrap().matches(""));
        assert!(!Wildcard::new("A", true).unwrap().matches("a"));
        assert!(Wildcard::new("", false).is_err());
        assert!(Wildcard::new("FIN-\u{202e}*", false).is_err());
    }

    #[test]
    fn distinguished_names() {
        let ou = dn("OU=Finance, DC=corp,DC=Example").unwrap();
        let direct = dn("CN=WS1,ou=finance,dc=corp,dc=example").unwrap();
        let below = dn("CN=WS2,OU=Laptops,OU=Finance,DC=corp,DC=example").unwrap();
        assert!(in_ou(&direct, &ou, false));
        assert!(!in_ou(&below, &ou, false));
        assert!(in_ou(&below, &ou, true));
        let escaped = dn(r"CN=Smith\, J,OU=Finance,DC=corp,DC=example").unwrap();
        assert!(in_ou(&escaped, &ou, false));
        assert!(dn("Finance").is_none());
        assert!(dn("OU=,DC=x").is_none());
    }
}
