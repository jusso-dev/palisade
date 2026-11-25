//! Minimal DER encoding for the fixture generator: just enough to build
//! X.509 certificates, CRLs and PKCS#7 SignedData. Every function returns a
//! complete TLV.

pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|b| **b == 0).count();
        out.push(0x80 | (bytes.len() - skip) as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
    out.extend_from_slice(content);
    out
}

pub fn seq(parts: &[&[u8]]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}

/// A DER `SET OF`: elements sorted by their encodings (X.690 11.6).
pub fn set(parts: &[&[u8]]) -> Vec<u8> {
    let mut sorted = parts.to_vec();
    sorted.sort_unstable();
    tlv(0x31, &sorted.concat())
}

pub fn octets(bytes: &[u8]) -> Vec<u8> {
    tlv(0x04, bytes)
}

pub fn null() -> Vec<u8> {
    vec![0x05, 0x00]
}

pub fn boolean(v: bool) -> Vec<u8> {
    vec![0x01, 0x01, if v { 0xff } else { 0x00 }]
}

/// A non-negative INTEGER from big-endian magnitude bytes.
pub fn uint(bytes: &[u8]) -> Vec<u8> {
    let skip = bytes.iter().take_while(|b| **b == 0).count();
    let mut content = bytes[skip.min(bytes.len().saturating_sub(1))..].to_vec();
    if content.is_empty() {
        content.push(0);
    }
    if content[0] & 0x80 != 0 {
        content.insert(0, 0);
    }
    tlv(0x02, &content)
}

pub fn int(v: u64) -> Vec<u8> {
    uint(&v.to_be_bytes())
}

pub fn oid(dotted: &str) -> Vec<u8> {
    let arcs: Vec<u64> = dotted.split('.').map(|a| a.parse().unwrap()).collect();
    let mut out = vec![(arcs[0] * 40 + arcs[1]) as u8];
    for &arc in &arcs[2..] {
        let mut stack = vec![(arc & 0x7f) as u8];
        let mut v = arc >> 7;
        while v > 0 {
            stack.push(0x80 | (v & 0x7f) as u8);
            v >>= 7;
        }
        out.extend(stack.iter().rev());
    }
    tlv(0x06, &out)
}

/// A BIT STRING with no unused bits.
pub fn bits(bytes: &[u8]) -> Vec<u8> {
    let mut content = vec![0];
    content.extend_from_slice(bytes);
    tlv(0x03, &content)
}

pub fn utf8(text: &str) -> Vec<u8> {
    tlv(0x0c, text.as_bytes())
}

/// `[n] EXPLICIT`.
pub fn explicit(n: u8, inner: &[u8]) -> Vec<u8> {
    tlv(0xa0 | n, inner)
}

/// A UTCTime (years 1950..2049) or GeneralizedTime for a Unix time.
pub fn time(unix: i64) -> Vec<u8> {
    let (y, mo, d, h, mi, s) = civil(unix);
    if (1950..2050).contains(&y) {
        tlv(
            0x17,
            format!("{:02}{mo:02}{d:02}{h:02}{mi:02}{s:02}Z", y % 100).as_bytes(),
        )
    } else {
        tlv(
            0x18,
            format!("{y:04}{mo:02}{d:02}{h:02}{mi:02}{s:02}Z").as_bytes(),
        )
    }
}

/// Unix seconds to UTC `(year, month, day, hour, minute, second)`.
fn civil(unix: i64) -> (i64, u32, u32, u32, u32, u32) {
    // Every value below is in range by construction (days 1..=31, months
    // 1..=12, seconds of a day), so the conversions cannot fail.
    let small = |v: i64| u32::try_from(v).expect("a small non-negative value");
    let days = unix.div_euclid(86_400);
    let secs = unix.rem_euclid(86_400);
    // Howard Hinnant's days-from-civil, inverted.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = small(doy - (153 * mp + 2) / 5 + 1);
    let m = small(if mp < 10 { mp + 3 } else { mp - 9 });
    let y = yoe + era * 400 + i64::from(m <= 2);
    (
        y,
        m,
        d,
        small(secs / 3600),
        small(secs / 60 % 60),
        small(secs % 60),
    )
}

/// `AlgorithmIdentifier { oid, NULL }`.
pub fn alg(dotted: &str) -> Vec<u8> {
    seq(&[&oid(dotted), &null()])
}

/// `AlgorithmIdentifier { oid }` with absent parameters (ECDSA).
pub fn alg_no_params(dotted: &str) -> Vec<u8> {
    seq(&[&oid(dotted)])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times_encode_in_the_right_form() {
        // 2023-11-14 22:13:20 UTC.
        assert_eq!(time(1_700_000_000), tlv(0x17, b"231114221320Z"));
        // 2050-01-01 00:00:00 UTC needs GeneralizedTime.
        assert_eq!(time(2_524_608_000), tlv(0x18, b"20500101000000Z"));
        assert_eq!(time(0), tlv(0x17, b"700101000000Z"));
    }

    #[test]
    fn integers_are_minimal_and_positive() {
        assert_eq!(int(0), vec![0x02, 0x01, 0x00]);
        assert_eq!(int(0x80), vec![0x02, 0x02, 0x00, 0x80]);
        assert_eq!(uint(&[0, 0, 1]), vec![0x02, 0x01, 0x01]);
    }

    #[test]
    fn oids_and_long_lengths_encode() {
        assert_eq!(
            oid("1.2.840.113549"),
            vec![0x06, 0x06, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d]
        );
        let long = tlv(0x04, &[0; 300]);
        assert_eq!(&long[..4], &[0x04, 0x82, 0x01, 0x2c]);
    }
}
