//! CRC-32C (Castagnoli), the per-record check of the spool's segment
//! files (#197). It detects torn writes and media errors, not tampering:
//! the hash chain does that.

#![forbid(unsafe_code)]

/// The reflected Castagnoli polynomial.
const POLY: u32 = 0x82F6_3B78;

const fn table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        // `i` is below 256, so the conversion is exact.
        #[expect(clippy::cast_possible_truncation, reason = "i < 256")]
        let mut crc = i as u32;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ POLY
            } else {
                crc >> 1
            };
            bit += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
}

static TABLE: [u32; 256] = table();

/// An incremental CRC-32C.
#[derive(Clone, Copy, Debug)]
pub struct Crc32c(u32);

impl Default for Crc32c {
    fn default() -> Self {
        Self::new()
    }
}

impl Crc32c {
    /// A new, empty checksum.
    #[must_use]
    pub const fn new() -> Self {
        Self(!0)
    }

    /// Adds `data`.
    pub fn update(&mut self, data: &[u8]) {
        let mut crc = self.0;
        for &byte in data {
            let index = usize::from((crc.to_le_bytes()[0]) ^ byte);
            crc = (crc >> 8) ^ TABLE.get(index).copied().unwrap_or(0);
        }
        self.0 = crc;
    }

    /// The checksum of everything added.
    #[must_use]
    pub const fn finish(self) -> u32 {
        !self.0
    }
}

/// The CRC-32C of `data`.
#[must_use]
pub fn crc32c(data: &[u8]) -> u32 {
    let mut crc = Crc32c::new();
    crc.update(data);
    crc.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_answers() {
        // RFC 3720 appendix B.4 and the common check value.
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
        assert_eq!(crc32c(&[0u8; 32]), 0x8A91_36AA);
        assert_eq!(crc32c(&[0xFFu8; 32]), 0x62A8_AB43);
        let ascending: Vec<u8> = (0u8..32).collect();
        assert_eq!(crc32c(&ascending), 0x46DD_794E);
        assert_eq!(crc32c(b""), 0);
    }

    #[test]
    fn incremental_matches_one_shot() {
        let mut crc = Crc32c::default();
        crc.update(b"1234");
        crc.update(b"56789");
        assert_eq!(crc.finish(), crc32c(b"123456789"));
    }
}
