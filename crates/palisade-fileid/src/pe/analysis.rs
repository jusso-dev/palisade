//! The PE checksum and per-section Shannon entropy.

#![forbid(unsafe_code)]

/// Computes the PE image checksum with the standard algorithm.
///
/// The file is summed as little-endian 16-bit words with end-around carry,
/// with the 4-byte `CheckSum` field at `checksum_offset` read as zeros. An
/// odd final byte is treated as if followed by a zero byte. The 16-bit sum
/// is then added to the file length.
///
/// Returns `None` when the file length does not fit in 32 bits, because the
/// algorithm is undefined there.
#[must_use]
pub fn compute_checksum(data: &[u8], checksum_offset: usize) -> Option<u32> {
    let file_len = u32::try_from(data.len()).ok()?;
    let skip = checksum_offset..checksum_offset.saturating_add(4);
    let byte = |offset: usize, value: u8| {
        if skip.contains(&offset) {
            0
        } else {
            u16::from(value)
        }
    };
    let mut sum: u32 = 0;
    for (index, pair) in data.chunks(2).enumerate() {
        let offset = index.saturating_mul(2);
        let word = match pair {
            [lo, hi] => byte(offset, *lo) | (byte(offset.saturating_add(1), *hi) << 8),
            [lo] => byte(offset, *lo),
            _ => 0,
        };
        // Fold the carry back in so the sum never exceeds 17 bits.
        sum += u32::from(word);
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum = (sum & 0xffff) + (sum >> 16);
    (sum & 0xffff).checked_add(file_len)
}

/// Shannon entropy of `data` in bits per byte, from 0.0 (one repeated value)
/// to 8.0 (uniformly random). Returns 0.0 for empty input.
#[must_use]
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0_u64; 256];
    for byte in data {
        if let Some(slot) = counts.get_mut(usize::from(*byte)) {
            *slot = slot.saturating_add(1);
        }
    }
    // Counts above 2^53 would lose precision as f64, which is irrelevant for
    // an advisory entropy figure.
    let total = data.len() as f64;
    counts
        .iter()
        .filter(|c| **c != 0)
        .map(|c| {
            let p = *c as f64 / total;
            -p * p.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_of_simple_inputs() {
        // Words 0x0201 + 0x0403 = 0x0604, plus length 4.
        assert_eq!(compute_checksum(&[1, 2, 3, 4], 100), Some(0x0604 + 4));
        // The checksum field is skipped.
        assert_eq!(
            compute_checksum(&[1, 2, 3, 4, 9, 9, 9, 9], 4),
            Some(0x0604 + 8)
        );
        // A checksum field at an odd offset zeroes the bytes it covers.
        assert_eq!(
            compute_checksum(&[1, 2, 3, 4, 5, 6], 1),
            Some(0x0001 + 0x0600 + 6)
        );
        // An odd trailing byte counts as a low byte.
        assert_eq!(compute_checksum(&[1, 2, 7], 100), Some(0x0201 + 7 + 3));
        // Carries fold back in: 0xffff + 0x0001 = 0x1_0000 -> 0x0001.
        assert_eq!(compute_checksum(&[0xff, 0xff, 1, 0], 100), Some(1 + 4));
        assert_eq!(compute_checksum(&[], 0), Some(0));
    }

    #[test]
    fn entropy_bounds() {
        assert!(shannon_entropy(&[]).abs() < f64::EPSILON);
        assert!(shannon_entropy(&[7; 100]).abs() < f64::EPSILON);
        let all: Vec<u8> = (0..=255).collect();
        assert!((shannon_entropy(&all) - 8.0).abs() < 1e-9);
        assert!((shannon_entropy(&[0, 1]) - 1.0).abs() < 1e-9);
    }
}
