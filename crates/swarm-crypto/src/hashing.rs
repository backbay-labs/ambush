//! Cryptographic hashing helpers.

use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha256};

use crate::error::{Error, Result};

/// A 32-byte hash value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Hash {
    #[serde(with = "hash_serde")]
    bytes: [u8; 32],
}

mod hash_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("0x{}", hex::encode(bytes)))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> std::result::Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let hex_str = String::deserialize(deserializer)?;
        let hex_str = hex_str.strip_prefix("0x").unwrap_or(&hex_str);
        let bytes = hex::decode(hex_str).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("hash must be 32 bytes"))
    }
}

impl Hash {
    /// Create from raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    /// Create from hex string, with or without a `0x` prefix.
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        let bytes = hex::decode(hex_str).map_err(|error| Error::InvalidHex(error.to_string()))?;

        if bytes.len() != 32 {
            return Err(Error::InvalidHashLength {
                expected: 32,
                actual: bytes.len(),
            });
        }

        let mut arr = [0_u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self::from_bytes(arr))
    }

    /// Borrow the underlying bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Render as lowercase hexadecimal without a prefix.
    pub fn to_hex(&self) -> String {
        hex::encode(self.bytes)
    }

    /// Render as lowercase hexadecimal with a `0x` prefix.
    pub fn to_hex_prefixed(&self) -> String {
        format!("0x{}", self.to_hex())
    }

    /// Return the zero hash.
    pub fn zero() -> Self {
        Self { bytes: [0_u8; 32] }
    }
}

impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl std::fmt::Display for Hash {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "0x{}", self.to_hex())
    }
}

/// Compute a SHA-256 hash over the provided bytes.
pub fn sha256(data: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();

    let mut bytes = [0_u8; 32];
    bytes.copy_from_slice(&result);
    Hash::from_bytes(bytes)
}

/// Compute SHA-256 and return it as `0x`-prefixed hex.
pub fn sha256_hex(data: &[u8]) -> String {
    sha256(data).to_hex_prefixed()
}

/// Compute an RFC 2104 HMAC-SHA256 over the provided bytes.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Hash {
    const BLOCK_SIZE: usize = 64;

    let normalized_key = if key.len() > BLOCK_SIZE {
        sha256(key).as_bytes().to_vec()
    } else {
        key.to_vec()
    };

    let mut padded_key = [0_u8; BLOCK_SIZE];
    padded_key[..normalized_key.len()].copy_from_slice(&normalized_key);

    let mut inner_pad = [0_u8; BLOCK_SIZE];
    let mut outer_pad = [0_u8; BLOCK_SIZE];
    for (index, byte) in padded_key.iter().enumerate() {
        inner_pad[index] = byte ^ 0x36;
        outer_pad[index] = byte ^ 0x5c;
    }

    let mut inner_hasher = Sha256::new();
    inner_hasher.update(inner_pad);
    inner_hasher.update(data);
    let inner_digest = inner_hasher.finalize();

    let mut outer_hasher = Sha256::new();
    outer_hasher.update(outer_pad);
    outer_hasher.update(inner_digest);
    let outer_digest = outer_hasher.finalize();

    let mut bytes = [0_u8; 32];
    bytes.copy_from_slice(&outer_digest);
    Hash::from_bytes(bytes)
}

/// Compute HMAC-SHA256 and return it as lowercase hex without a prefix.
pub fn hmac_sha256_hex(key: &[u8], data: &[u8]) -> String {
    hmac_sha256(key, data).to_hex()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256() {
        let hash = sha256(b"hello");
        assert_eq!(
            hash.to_hex(),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn test_sha256_hex() {
        let hash = sha256_hex(b"hello");
        assert!(hash.starts_with("0x"));
        assert_eq!(hash.len(), 66);
    }

    #[test]
    fn test_hash_from_hex() {
        let original = sha256(b"test");
        let from_hex = Hash::from_hex(&original.to_hex()).unwrap();
        let from_hex_prefixed = Hash::from_hex(&original.to_hex_prefixed()).unwrap();

        assert_eq!(original, from_hex);
        assert_eq!(original, from_hex_prefixed);
    }

    #[test]
    fn test_hash_serde() {
        let hash = sha256(b"test");
        let json = serde_json::to_string(&hash).unwrap();
        let restored: Hash = serde_json::from_str(&json).unwrap();

        assert_eq!(hash, restored);
        assert!(json.contains("0x"));
    }

    #[test]
    fn test_concat_hashes() {
        fn concat_hashes(left: &Hash, right: &Hash) -> Hash {
            let mut combined = [0_u8; 64];
            combined[..32].copy_from_slice(left.as_bytes());
            combined[32..].copy_from_slice(right.as_bytes());
            sha256(&combined)
        }

        let left = sha256(b"left");
        let right = sha256(b"right");
        let combined = concat_hashes(&left, &right);
        let combined_again = concat_hashes(&left, &right);

        assert_eq!(combined, combined_again);
        assert_ne!(combined, concat_hashes(&right, &left));
    }

    #[test]
    fn test_hmac_sha256_matches_known_vector() {
        let digest = hmac_sha256_hex(b"key", b"The quick brown fox jumps over the lazy dog");
        assert_eq!(
            digest,
            "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
        );
    }
}
