//! CRC-32C (Castagnoli), table-driven, no new dependency.
//!
//! `crc32fast` would be faster and is one more supply-chain line. `deny.toml` sets
//! `multiple-versions = "deny"` and `wildcards = "deny"`, so every added crate is a review item;
//! at ~3,645 records/sec over payloads of a few hundred bytes the table version is not the
//! bottleneck. Revisit only with a profile that says otherwise.

const POLY: u32 = 0x82F6_3B78; // CRC-32C, reversed representation

/// Built once at first use. 1 KiB.
static TABLE: std::sync::OnceLock<[u32; 256]> = std::sync::OnceLock::new();

fn table() -> &'static [u32; 256] {
    TABLE.get_or_init(|| {
        let mut table = [0u32; 256];
        let mut i = 0usize;
        while i < 256 {
            let mut crc = i as u32;
            let mut bit = 0;
            while bit < 8 {
                crc = if crc & 1 != 0 { (crc >> 1) ^ POLY } else { crc >> 1 };
                bit += 1;
            }
            table[i] = crc;
            i += 1;
        }
        table
    })
}

/// CRC-32C over `bytes`.
pub fn crc32c(bytes: &[u8]) -> u32 {
    let table = table();
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in bytes {
        let index = ((crc ^ u32::from(byte)) & 0xFF) as usize;
        crc = (crc >> 8) ^ table[index];
    }
    !crc
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::crc32c;

    // Known-answer, so a mistyped polynomial cannot pass. CRC-32C of the nine ASCII digits.
    #[test]
    fn matches_the_known_answer_vector() {
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
    }

    #[test]
    fn empty_input_is_zero() {
        assert_eq!(crc32c(b""), 0);
    }

    // A single flipped bit anywhere must change the value; this is the only property the spool
    // relies on.
    #[test]
    fn one_flipped_bit_changes_the_value() {
        let clean = b"perch spool record payload".to_vec();
        let mut dirty = clean.clone();
        dirty[7] ^= 0b0000_0100;
        assert_ne!(crc32c(&clean), crc32c(&dirty));
    }
}
