//! Bounds-checked little-endian reads from untrusted bytes.
//!
//! Every helper returns `None` instead of panicking when the requested range
//! does not fit, and all offset arithmetic is checked.

#![forbid(unsafe_code)]

/// `len` bytes at `offset`, or `None` if the range does not fit in `data`.
pub(crate) fn bytes(data: &[u8], offset: usize, len: usize) -> Option<&[u8]> {
    data.get(offset..offset.checked_add(len)?)
}

fn array<const N: usize>(data: &[u8], offset: usize) -> Option<[u8; N]> {
    bytes(data, offset, N)?.try_into().ok()
}

pub(crate) fn u8_at(data: &[u8], offset: usize) -> Option<u8> {
    data.get(offset).copied()
}

pub(crate) fn u16_at(data: &[u8], offset: usize) -> Option<u16> {
    array(data, offset).map(u16::from_le_bytes)
}

pub(crate) fn u32_at(data: &[u8], offset: usize) -> Option<u32> {
    array(data, offset).map(u32::from_le_bytes)
}

pub(crate) fn u64_at(data: &[u8], offset: usize) -> Option<u64> {
    array(data, offset).map(u64::from_le_bytes)
}

/// A `u32` from the file as a `usize`. Always succeeds on the 32- and 64-bit
/// targets Palisade supports.
pub(crate) fn to_usize(value: u32) -> Option<usize> {
    usize::try_from(value).ok()
}

/// A `usize` offset as a `u64`, for reporting.
pub(crate) fn to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

/// Rounds `value` up to a multiple of four.
pub(crate) fn align4(value: usize) -> Option<usize> {
    Some(value.checked_add(3)? & !3)
}

/// UTF-16LE text read up to a NUL unit.
pub(crate) struct Utf16Text {
    /// The text. Unpaired surrogates are replaced with U+FFFD.
    pub text: String,
    /// Bytes consumed, including the NUL unit if one was found.
    pub consumed: usize,
    /// Whether a NUL terminator was found before the end of the input.
    pub terminated: bool,
}

/// Reads UTF-16LE code units from `data` up to the first NUL unit or the end
/// of `data`. An odd trailing byte is ignored. Allocates only for the units
/// before the terminator.
pub(crate) fn utf16_until_nul(data: &[u8]) -> Utf16Text {
    let pairs = data.as_chunks::<2>().0;
    let available = pairs.len();
    let len = pairs
        .iter()
        .position(|p| u16::from_le_bytes(*p) == 0)
        .unwrap_or(available);
    let terminated = len < available;
    let units: Vec<u16> = pairs
        .iter()
        .take(len)
        .map(|p| u16::from_le_bytes(*p))
        .collect();
    Utf16Text {
        text: String::from_utf16_lossy(&units),
        consumed: len
            .saturating_add(usize::from(terminated))
            .saturating_mul(2),
        terminated,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_are_bounded() {
        let data = [1_u8, 2, 3, 4, 5, 6, 7, 8];
        assert_eq!(u8_at(&data, 7), Some(8));
        assert_eq!(u8_at(&data, 8), None);
        assert_eq!(u16_at(&data, 0), Some(0x0201));
        assert_eq!(u32_at(&data, 4), Some(0x0807_0605));
        assert_eq!(u64_at(&data, 0), Some(0x0807_0605_0403_0201));
        assert_eq!(u16_at(&data, 7), None);
        assert_eq!(u32_at(&data, usize::MAX), None);
        assert_eq!(bytes(&data, usize::MAX, 2), None);
        assert_eq!(bytes(&data, 8, 0), Some(&[][..]));
    }

    #[test]
    fn alignment() {
        assert_eq!(align4(0), Some(0));
        assert_eq!(align4(1), Some(4));
        assert_eq!(align4(4), Some(4));
        assert_eq!(align4(usize::MAX), None);
    }

    #[test]
    fn utf16_reading() {
        let text: Vec<u8> = "ab\0c".encode_utf16().flat_map(u16::to_le_bytes).collect();
        let full = utf16_until_nul(&text);
        assert_eq!(
            (full.text.as_str(), full.consumed, full.terminated),
            ("ab", 6, true)
        );
        let cut = utf16_until_nul(text.get(..4).unwrap());
        assert_eq!(
            (cut.text.as_str(), cut.consumed, cut.terminated),
            ("ab", 4, false)
        );
        // An odd trailing byte is ignored, a lone surrogate is replaced.
        let odd = utf16_until_nul(&[0x00, 0xD8, 0x41]);
        assert_eq!((odd.text.as_str(), odd.consumed), ("\u{FFFD}", 2));
    }
}
