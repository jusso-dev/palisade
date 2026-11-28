//! The NTFS upcase table (#332).
//!
//! NTFS compares two names by upper-casing each UTF-16 code unit through
//! the volume's upcase table (`$UpCase`), written when the volume is
//! formatted. [`upcase_unit`] is the table that Windows 7 and every later
//! version write, and that the OS itself upper-cases with
//! (`RtlUpcaseUnicodeChar`; `palisade-fileid`'s Windows tests check every
//! unit against it). [`fold`] upper-cases a name with it.
//!
//! It is not Unicode's upper-case mapping. It never maps a character
//! outside ASCII into ASCII (`ı`, `ſ` and the Kelvin sign stay as they
//! are, so `ſetup.exe` and `SETUP.EXE` are two names), it leaves
//! characters outside the Basic Multilingual Plane alone, and it predates
//! case pairs that later Unicode versions added. A volume formatted by an
//! older Windows holds an older table; telling those apart is
//! `palisade-fileid`'s job.
//!
//! Pure and `no_std`.

use alloc::string::String;

/// The CRC-64 that NTFS records in `$UpCase:$Info` for the table
/// [`upcase_unit`] implements: the one Windows 7 and later write when they
/// format a volume.
pub const STANDARD_UPCASE_CRC: u64 = 0xDADC_7E77_6B1B_690C;

/// The upcase table as runs `(first, last, step, add)`: every unit `u` in
/// `first..=last` with `(u - first) % step == 0` upper-cases to
/// `u + add` (wrapping); every other unit to itself. Sorted, and the runs
/// do not overlap. Generated from the Windows 7 default table that
/// ntfs-3g's `ntfs_upcase_table_build` reproduces; the tests check its
/// CRC against [`STANDARD_UPCASE_CRC`].
#[rustfmt::skip]
const RUNS: [(u16, u16, u16, u16); 134] = [
    (0x0061, 0x007A, 1, 0xFFE0),
    (0x00E0, 0x00F6, 1, 0xFFE0),
    (0x00F8, 0x00FE, 1, 0xFFE0),
    (0x00FF, 0x00FF, 1, 0x0079),
    (0x0101, 0x012F, 2, 0xFFFF),
    (0x0133, 0x0137, 2, 0xFFFF),
    (0x013A, 0x0148, 2, 0xFFFF),
    (0x014B, 0x0177, 2, 0xFFFF),
    (0x017A, 0x017E, 2, 0xFFFF),
    (0x0180, 0x0180, 1, 0x00C3),
    (0x0183, 0x0185, 2, 0xFFFF),
    (0x0188, 0x0188, 1, 0xFFFF),
    (0x018C, 0x018C, 1, 0xFFFF),
    (0x0192, 0x0192, 1, 0xFFFF),
    (0x0195, 0x0195, 1, 0x0061),
    (0x0199, 0x0199, 1, 0xFFFF),
    (0x019A, 0x019A, 1, 0x00A3),
    (0x019E, 0x019E, 1, 0x0082),
    (0x01A1, 0x01A5, 2, 0xFFFF),
    (0x01A8, 0x01A8, 1, 0xFFFF),
    (0x01AD, 0x01AD, 1, 0xFFFF),
    (0x01B0, 0x01B0, 1, 0xFFFF),
    (0x01B4, 0x01B6, 2, 0xFFFF),
    (0x01B9, 0x01B9, 1, 0xFFFF),
    (0x01BD, 0x01BD, 1, 0xFFFF),
    (0x01BF, 0x01BF, 1, 0x0038),
    (0x01C6, 0x01C6, 1, 0xFFFE),
    (0x01C9, 0x01C9, 1, 0xFFFE),
    (0x01CC, 0x01CC, 1, 0xFFFE),
    (0x01CE, 0x01DC, 2, 0xFFFF),
    (0x01DD, 0x01DD, 1, 0xFFB1),
    (0x01DF, 0x01EF, 2, 0xFFFF),
    (0x01F3, 0x01F3, 1, 0xFFFE),
    (0x01F5, 0x01F5, 1, 0xFFFF),
    (0x01F9, 0x021F, 2, 0xFFFF),
    (0x0223, 0x0233, 2, 0xFFFF),
    (0x023C, 0x023C, 1, 0xFFFF),
    (0x0242, 0x0242, 1, 0xFFFF),
    (0x0247, 0x024F, 2, 0xFFFF),
    (0x0250, 0x0250, 1, 0x2A1F),
    (0x0251, 0x0251, 1, 0x2A1C),
    (0x0253, 0x0253, 1, 0xFF2E),
    (0x0254, 0x0254, 1, 0xFF32),
    (0x0256, 0x0257, 1, 0xFF33),
    (0x0259, 0x0259, 1, 0xFF36),
    (0x025B, 0x025B, 1, 0xFF35),
    (0x0260, 0x0260, 1, 0xFF33),
    (0x0263, 0x0263, 1, 0xFF31),
    (0x0268, 0x0268, 1, 0xFF2F),
    (0x0269, 0x0269, 1, 0xFF2D),
    (0x026B, 0x026B, 1, 0x29F7),
    (0x026F, 0x026F, 1, 0xFF2D),
    (0x0271, 0x0271, 1, 0x29FD),
    (0x0272, 0x0272, 1, 0xFF2B),
    (0x0275, 0x0275, 1, 0xFF2A),
    (0x027D, 0x027D, 1, 0x29E7),
    (0x0280, 0x0280, 1, 0xFF26),
    (0x0283, 0x0283, 1, 0xFF26),
    (0x0288, 0x0288, 1, 0xFF26),
    (0x0289, 0x0289, 1, 0xFFBB),
    (0x028A, 0x028B, 1, 0xFF27),
    (0x028C, 0x028C, 1, 0xFFB9),
    (0x0292, 0x0292, 1, 0xFF25),
    (0x0371, 0x0373, 2, 0xFFFF),
    (0x0377, 0x0377, 1, 0xFFFF),
    (0x037B, 0x037D, 1, 0x0082),
    (0x03AC, 0x03AC, 1, 0xFFDA),
    (0x03AD, 0x03AF, 1, 0xFFDB),
    (0x03B1, 0x03C1, 1, 0xFFE0),
    (0x03C3, 0x03CB, 1, 0xFFE0),
    (0x03CC, 0x03CC, 1, 0xFFC0),
    (0x03CD, 0x03CE, 1, 0xFFC1),
    (0x03D7, 0x03D7, 1, 0xFFF8),
    (0x03D9, 0x03EF, 2, 0xFFFF),
    (0x03F2, 0x03F2, 1, 0x0007),
    (0x03F8, 0x03F8, 1, 0xFFFF),
    (0x03FB, 0x03FB, 1, 0xFFFF),
    (0x0430, 0x044F, 1, 0xFFE0),
    (0x0450, 0x045F, 1, 0xFFB0),
    (0x0461, 0x0481, 2, 0xFFFF),
    (0x048B, 0x04BF, 2, 0xFFFF),
    (0x04C2, 0x04CE, 2, 0xFFFF),
    (0x04CF, 0x04CF, 1, 0xFFF1),
    (0x04D1, 0x0523, 2, 0xFFFF),
    (0x0561, 0x0586, 1, 0xFFD0),
    (0x1D79, 0x1D79, 1, 0x8A04),
    (0x1D7D, 0x1D7D, 1, 0x0EE6),
    (0x1E01, 0x1E95, 2, 0xFFFF),
    (0x1EA1, 0x1EFF, 2, 0xFFFF),
    (0x1F00, 0x1F07, 1, 0x0008),
    (0x1F10, 0x1F15, 1, 0x0008),
    (0x1F20, 0x1F27, 1, 0x0008),
    (0x1F30, 0x1F37, 1, 0x0008),
    (0x1F40, 0x1F45, 1, 0x0008),
    (0x1F51, 0x1F57, 2, 0x0008),
    (0x1F60, 0x1F67, 1, 0x0008),
    (0x1F70, 0x1F71, 1, 0x004A),
    (0x1F72, 0x1F75, 1, 0x0056),
    (0x1F76, 0x1F77, 1, 0x0064),
    (0x1F78, 0x1F79, 1, 0x0080),
    (0x1F7A, 0x1F7B, 1, 0x0070),
    (0x1F7C, 0x1F7D, 1, 0x007E),
    (0x1F80, 0x1F87, 1, 0x0008),
    (0x1F90, 0x1F97, 1, 0x0008),
    (0x1FA0, 0x1FA7, 1, 0x0008),
    (0x1FB0, 0x1FB1, 1, 0x0008),
    (0x1FB3, 0x1FB3, 1, 0x0009),
    (0x1FC3, 0x1FC3, 1, 0x0009),
    (0x1FD0, 0x1FD1, 1, 0x0008),
    (0x1FE0, 0x1FE1, 1, 0x0008),
    (0x1FE5, 0x1FE5, 1, 0x0007),
    (0x1FF3, 0x1FF3, 1, 0x0009),
    (0x214E, 0x214E, 1, 0xFFE4),
    (0x2170, 0x217F, 1, 0xFFF0),
    (0x2184, 0x2184, 1, 0xFFFF),
    (0x24D0, 0x24E9, 1, 0xFFE6),
    (0x2C30, 0x2C5E, 1, 0xFFD0),
    (0x2C61, 0x2C61, 1, 0xFFFF),
    (0x2C65, 0x2C65, 1, 0xD5D5),
    (0x2C66, 0x2C66, 1, 0xD5D8),
    (0x2C68, 0x2C6C, 2, 0xFFFF),
    (0x2C73, 0x2C73, 1, 0xFFFF),
    (0x2C76, 0x2C76, 1, 0xFFFF),
    (0x2C81, 0x2CE3, 2, 0xFFFF),
    (0x2D00, 0x2D25, 1, 0xE3A0),
    (0xA641, 0xA65F, 2, 0xFFFF),
    (0xA663, 0xA66D, 2, 0xFFFF),
    (0xA681, 0xA697, 2, 0xFFFF),
    (0xA723, 0xA72F, 2, 0xFFFF),
    (0xA733, 0xA76F, 2, 0xFFFF),
    (0xA77A, 0xA77C, 2, 0xFFFF),
    (0xA77F, 0xA787, 2, 0xFFFF),
    (0xA78C, 0xA78C, 1, 0xFFFF),
    (0xFF41, 0xFF5A, 1, 0xFFE0),
];

/// Upper-cases one UTF-16 code unit with the standard NTFS table.
#[must_use]
pub fn upcase_unit(unit: u16) -> u16 {
    let i = RUNS.partition_point(|&(first, ..)| first <= unit);
    let Some(&(first, last, step, add)) = i.checked_sub(1).and_then(|i| RUNS.get(i)) else {
        return unit;
    };
    if unit <= last && (unit - first).is_multiple_of(step) {
        unit.wrapping_add(add)
    } else {
        unit
    }
}

/// Upper-cases one character with [`upcase_unit`]. A character outside
/// the Basic Multilingual Plane is unchanged, as NTFS leaves each half of
/// its surrogate pair unchanged.
#[must_use]
pub fn upcase_char(c: char) -> char {
    u16::try_from(u32::from(c))
        .ok()
        .and_then(|u| char::from_u32(u32::from(upcase_unit(u))))
        .unwrap_or(c)
}

/// Upper-cases every character of `s` with [`upcase_char`]: the form two
/// names that NTFS treats as one share.
#[must_use]
pub fn fold(s: &str) -> String {
    s.chars().map(upcase_char).collect()
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;

    /// The CRC-64 NTFS records in `$UpCase:$Info` (`mkntfs`'s `crc64`):
    /// reflected, polynomial `0x9A6C9329AC4BC9B5`, initial value and final
    /// XOR all ones.
    fn crc64(data: &[u8]) -> u64 {
        let mut crc = u64::MAX;
        for &b in data {
            crc ^= u64::from(b);
            for _ in 0..8 {
                crc = if crc & 1 == 1 {
                    0x9A6C_9329_AC4B_C9B5 ^ (crc >> 1)
                } else {
                    crc >> 1
                };
            }
        }
        !crc
    }

    fn table() -> Vec<u16> {
        (0..=u16::MAX).map(upcase_unit).collect()
    }

    #[test]
    fn the_table_is_the_one_windows_records() {
        let bytes: Vec<u8> = table().iter().flat_map(|u| u.to_le_bytes()).collect();
        assert_eq!(crc64(&bytes), STANDARD_UPCASE_CRC);
        assert_eq!(crc64(b""), 0);
    }

    #[test]
    fn runs_are_sorted_and_disjoint() {
        for w in RUNS.windows(2) {
            assert!(w[0].1 < w[1].0, "{w:?}");
        }
        for (first, last, step, _) in RUNS {
            assert!(first <= last && step >= 1);
        }
    }

    #[test]
    fn upcasing_is_stable_and_keeps_ascii_apart() {
        let t = table();
        for u in 0..=u16::MAX {
            let up = t[usize::from(u)];
            // Upper-casing an upper-case unit changes nothing.
            assert_eq!(t[usize::from(up)], up, "{u:04X}");
            // ASCII upper-cases as ASCII, and nothing else reaches it.
            match u8::try_from(u) {
                Ok(b) if b.is_ascii() => assert_eq!(up, u16::from(b.to_ascii_uppercase())),
                _ => assert!(up >= 0x80, "{u:04X}"),
            }
            // Surrogates are left alone.
            if (0xD800..0xE000).contains(&u) {
                assert_eq!(up, u);
            }
        }
    }

    #[test]
    fn examples() {
        assert_eq!(fold("Stra\u{df}e.exe"), "STRA\u{df}E.EXE");
        assert_eq!(fold("\u{1c6}"), "\u{1c4}");
        assert_eq!(fold("\u{fb01}"), "\u{fb01}");
        assert_eq!(fold("\u{e9}"), "\u{c9}");
        assert_eq!(fold("\u{ff}"), "\u{178}");
        assert_eq!(fold("\u{ff41}"), "\u{ff21}");
        // Greek with a combining iota: NTFS folds these, though Unicode's
        // full upper case is two characters.
        assert_eq!(fold("\u{1f80}"), "\u{1f88}");
        assert_eq!(fold("\u{1ff3}"), "\u{1ffc}");
        // Unicode maps these into ASCII; NTFS does not.
        assert_eq!(fold("\u{131}\u{17f}\u{212a}"), "\u{131}\u{17f}\u{212a}");
        // Outside the Basic Multilingual Plane: unchanged.
        assert_eq!(fold("\u{10428}"), "\u{10428}");
        assert_eq!(upcase_char('\u{10428}'), '\u{10428}');
        assert_eq!(upcase_unit(0), 0);
        assert_eq!(upcase_unit(0xFFFF), 0xFFFF);
        assert_eq!(upcase_unit(0x149), 0x149);
    }
}
