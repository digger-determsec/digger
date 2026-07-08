//! Deterministic, version-independent content digest (FNV-1a/64 hex).
//! Used for content-addressing and reproducibility keys. Chosen over
//! std DefaultHasher because the latter is NOT stable across toolchains,
//! which would violate determinism (Principle 1).

/// FNV-1a 64-bit over raw bytes, lower-hex, zero-padded to 16 chars.
pub fn fnv1a_64(bytes: &[u8]) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{:016x}", hash)
}

/// Convenience digest over a string slice.
pub fn digest_str(s: &str) -> String {
    fnv1a_64(s.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn deterministic() {
        assert_eq!(fnv1a_64(b"abc"), fnv1a_64(b"abc"));
        assert_ne!(fnv1a_64(b"abc"), fnv1a_64(b"abd"));
        // known FNV-1a/64 vector for empty input
        assert_eq!(fnv1a_64(b""), "cbf29ce484222325");
    }
}
