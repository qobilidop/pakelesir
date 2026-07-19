//! Bit-granular big-endian reads. This is the *reference* implementation:
//! clarity wins over speed, deliberately bit-by-bit.

/// Read `n` bits (1..=64) starting at absolute bit offset `bit_off`,
/// MSB-first within each byte, big-endian across bytes. `None` if the
/// read would run past `avail_bits` (the input's bit-granular length).
pub(crate) fn read_bits(bytes: &[u8], avail_bits: usize, bit_off: usize, n: usize) -> Option<u64> {
    debug_assert!((1..=64).contains(&n));
    debug_assert!(avail_bits <= bytes.len() * 8);
    if bit_off.checked_add(n)? > avail_bits {
        return None;
    }
    let mut out = 0u64;
    for i in 0..n {
        let pos = bit_off + i;
        let bit = (bytes[pos / 8] >> (7 - pos % 8)) & 1;
        out = (out << 1) | u64::from(bit);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::read_bits;

    #[test]
    fn reads_msb_first() {
        let b = [0xAB, 0xCD];
        assert_eq!(read_bits(&b, 16, 0, 4).unwrap(), 0xA);
        assert_eq!(read_bits(&b, 16, 4, 8).unwrap(), 0xBC);
        assert_eq!(read_bits(&b, 16, 0, 16).unwrap(), 0xABCD);
        assert_eq!(read_bits(&b, 16, 15, 1).unwrap(), 0x1);
    }

    #[test]
    fn oob_is_none() {
        assert!(read_bits(&[0xFF], 8, 4, 8).is_none());
        assert!(read_bits(&[], 0, 0, 1).is_none());
    }

    #[test]
    fn bit_granular_limit_respected() {
        let b = [0xFF, 0xFF];
        assert_eq!(read_bits(&b, 12, 8, 4).unwrap(), 0xF);
        assert!(read_bits(&b, 12, 8, 5).is_none());
    }
}
