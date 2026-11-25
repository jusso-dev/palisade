//! A minimal ZIP writer: stored (uncompressed) entries, UTF-8 names and one
//! fixed timestamp, so the same input always gives the same bytes. Used for
//! the symbols archive, which needs no compression to be useful and is read
//! by any unzip tool.

/// One file in the archive: its path inside the archive (with `/`
/// separators) and its contents.
pub struct Entry {
    pub name: String,
    pub data: Vec<u8>,
}

/// General purpose flag bit 11: the name is UTF-8.
const FLAG_UTF8: u16 = 0x0800;
/// Version needed to extract a stored entry: 1.0.
const VERSION_NEEDED: u16 = 10;

/// Writes `entries` as a ZIP archive with every timestamp set to
/// `unix_seconds` (UTC). Fails past the classic ZIP limits (4 GiB, 65535
/// entries), which symbols never reach.
pub fn write(entries: &[Entry], unix_seconds: i64) -> Result<Vec<u8>, String> {
    let (time, date) = dos_date_time(unix_seconds);
    let count = u16::try_from(entries.len()).map_err(|_| "zip: too many entries".to_owned())?;
    let mut out = Vec::new();
    let mut central = Vec::new();
    for entry in entries {
        let unsafe_name = entry.name.is_empty()
            || entry.name.starts_with('/')
            || entry.name.contains(['\\', '\0', ':'])
            || entry
                .name
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..");
        if unsafe_name {
            return Err(format!("zip: invalid entry name `{}`", entry.name));
        }
        let offset = u32_len(out.len())?;
        let size = u32_len(entry.data.len())?;
        let name_len =
            u16::try_from(entry.name.len()).map_err(|_| "zip: entry name too long".to_owned())?;
        let crc = crc32(&entry.data);

        put32(&mut out, 0x0403_4b50);
        put16(&mut out, VERSION_NEEDED);
        put16(&mut out, FLAG_UTF8);
        put16(&mut out, 0); // stored
        put16(&mut out, time);
        put16(&mut out, date);
        put32(&mut out, crc);
        put32(&mut out, size);
        put32(&mut out, size);
        put16(&mut out, name_len);
        put16(&mut out, 0); // extra field length
        out.extend_from_slice(entry.name.as_bytes());
        out.extend_from_slice(&entry.data);

        put32(&mut central, 0x0201_4b50);
        put16(&mut central, VERSION_NEEDED); // version made by
        put16(&mut central, VERSION_NEEDED);
        put16(&mut central, FLAG_UTF8);
        put16(&mut central, 0);
        put16(&mut central, time);
        put16(&mut central, date);
        put32(&mut central, crc);
        put32(&mut central, size);
        put32(&mut central, size);
        put16(&mut central, name_len);
        put16(&mut central, 0); // extra
        put16(&mut central, 0); // comment
        put16(&mut central, 0); // disk number
        put16(&mut central, 0); // internal attributes
        put32(&mut central, 0); // external attributes
        put32(&mut central, offset);
        central.extend_from_slice(entry.name.as_bytes());
    }
    let central_offset = u32_len(out.len())?;
    let central_size = u32_len(central.len())?;
    out.extend_from_slice(&central);
    put32(&mut out, 0x0605_4b50);
    put16(&mut out, 0);
    put16(&mut out, 0);
    put16(&mut out, count);
    put16(&mut out, count);
    put32(&mut out, central_size);
    put32(&mut out, central_offset);
    put16(&mut out, 0); // comment length
    u32_len(out.len())?;
    Ok(out)
}

fn u32_len(len: usize) -> Result<u32, String> {
    u32::try_from(len).map_err(|_| "zip: archive larger than 4 GiB".to_owned())
}

fn put16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

/// CRC-32 (IEEE 802.3, reflected), as ZIP uses.
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0_u32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

/// MS-DOS `(time, date)` for a Unix time, in UTC. DOS dates start in 1980
/// and end in 2107, so earlier or later times are clamped.
pub fn dos_date_time(unix_seconds: i64) -> (u16, u16) {
    const MIN: i64 = 315_532_800; // 1980-01-01T00:00:00Z
    const MAX: i64 = 4_354_819_198; // 2107-12-31T23:59:58Z
    let t = unix_seconds.clamp(MIN, MAX);
    let days = t.div_euclid(86_400);
    let secs = t.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let field = |v: i64| u16::try_from(v).unwrap_or(0);
    let time = (field(secs / 3600) << 11) | (field(secs / 60 % 60) << 5) | field(secs % 60 / 2);
    let date = (field(year - 1980) << 9) | (field(month) << 5) | field(day);
    (time, date)
}

/// `(year, month, day)` for days since 1970-01-01 (Howard Hinnant's
/// `civil_from_days`).
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_matches_the_standard_check_value() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn dos_timestamps() {
        // 2026-11-25T13:45:30Z
        let (time, date) = dos_date_time(1_795_614_330);
        assert_eq!(date >> 9, 2026 - 1980);
        assert_eq!((date >> 5) & 0xf, 11);
        assert_eq!(date & 0x1f, 25);
        assert_eq!(time >> 11, 13);
        assert_eq!((time >> 5) & 0x3f, 45);
        assert_eq!((time & 0x1f) * 2, 30);
        assert_eq!(dos_date_time(0), dos_date_time(315_532_800));
        // 1980-01-01: year offset 0, month 1, day 1.
        assert_eq!(dos_date_time(0).1, (1 << 5) | 1);
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(19_782), (2024, 2, 29));
    }

    fn word(b: &[u8], at: usize) -> u16 {
        u16::from_le_bytes([b[at], b[at + 1]])
    }
    fn dword(b: &[u8], at: usize) -> u32 {
        u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
    }

    #[test]
    fn archive_layout_reads_back() {
        let entries = vec![
            Entry {
                name: "a.pdb/ABC1/a.pdb".into(),
                data: b"hello".to_vec(),
            },
            Entry {
                name: "b.txt".into(),
                data: Vec::new(),
            },
        ];
        let zip = write(&entries, 1_700_000_000).unwrap();
        assert_eq!(zip, write(&entries, 1_700_000_000).unwrap());
        let eocd = zip.len() - 22;
        assert_eq!(dword(&zip, eocd), 0x0605_4b50);
        assert_eq!(word(&zip, eocd + 10), 2);
        let cd_size = dword(&zip, eocd + 12) as usize;
        let cd_offset = dword(&zip, eocd + 16) as usize;
        assert_eq!(cd_offset + cd_size, eocd);
        let mut at = cd_offset;
        for entry in &entries {
            assert_eq!(dword(&zip, at), 0x0201_4b50);
            assert_eq!(dword(&zip, at + 16), crc32(&entry.data));
            let name_len = word(&zip, at + 28) as usize;
            let local = dword(&zip, at + 42) as usize;
            assert_eq!(&zip[at + 46..at + 46 + name_len], entry.name.as_bytes());
            assert_eq!(dword(&zip, local), 0x0403_4b50);
            let data_at = local + 30 + name_len;
            assert_eq!(&zip[data_at..data_at + entry.data.len()], entry.data);
            at += 46 + name_len;
        }
    }

    #[test]
    fn rejects_unsafe_names() {
        for bad in [
            "", "/abs", "a\\b", "../x", "a/../b", "a/./b", "a//b", "a\0b", "c:x", "a/",
        ] {
            let entry = Entry {
                name: bad.into(),
                data: Vec::new(),
            };
            assert!(write(&[entry], 0).is_err(), "{bad}");
        }
    }
}
