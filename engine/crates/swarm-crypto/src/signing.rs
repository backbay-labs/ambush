//! Ed25519 signing helpers.

use ed25519_dalek::{
    Signature as DalekSignature, Signer as DalekSigner, SigningKey, Verifier, VerifyingKey,
};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Signing interface used by swarm-crypto.
pub trait Signer {
    fn public_key(&self) -> PublicKey;
    fn sign(&self, message: &[u8]) -> Result<Signature>;
}

/// An Ed25519 keypair used for signing.
#[derive(Clone, Debug)]
pub struct Keypair {
    signing_key: SigningKey,
}

impl Keypair {
    /// Generate a new random keypair.
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self { signing_key }
    }

    /// Create a keypair from a raw 32-byte seed.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(seed);
        Self { signing_key }
    }

    /// Create a keypair from hex-encoded seed material.
    pub fn from_hex(hex_seed: &str) -> Result<Self> {
        let hex_seed = hex_seed.strip_prefix("0x").unwrap_or(hex_seed);
        let bytes = hex::decode(hex_seed).map_err(|error| Error::InvalidHex(error.to_string()))?;

        if bytes.len() != 32 {
            return Err(Error::InvalidPrivateKey);
        }

        let mut seed = [0_u8; 32];
        seed.copy_from_slice(&bytes);
        Ok(Self::from_seed(&seed))
    }

    /// Return the corresponding public key.
    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            verifying_key: self.signing_key.verifying_key(),
        }
    }

    /// Sign a message.
    pub fn sign(&self, message: &[u8]) -> Signature {
        let signature = self.signing_key.sign(message);
        Signature { inner: signature }
    }

    /// Export the seed as hex.
    pub fn to_hex(&self) -> String {
        hex::encode(self.signing_key.to_bytes())
    }
}

impl Signer for Keypair {
    fn public_key(&self) -> PublicKey {
        Keypair::public_key(self)
    }

    fn sign(&self, message: &[u8]) -> Result<Signature> {
        Ok(Keypair::sign(self, message))
    }
}

/// An Ed25519 public key used for verification.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PublicKey {
    #[serde(with = "pubkey_serde")]
    verifying_key: VerifyingKey,
}

mod pubkey_serde {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(key: &VerifyingKey, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(key.to_bytes()))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> std::result::Result<VerifyingKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        let hex_str = String::deserialize(deserializer)?;
        let hex_str = hex_str.strip_prefix("0x").unwrap_or(&hex_str);
        let bytes = hex::decode(hex_str).map_err(serde::de::Error::custom)?;
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("public key must be 32 bytes"))?;
        VerifyingKey::from_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}

impl PublicKey {
    /// Create from raw bytes.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self> {
        let verifying_key = VerifyingKey::from_bytes(bytes)
            .map_err(|error| Error::InvalidPublicKey(error.to_string()))?;
        Ok(Self { verifying_key })
    }

    /// Create from hex-encoded bytes.
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        let bytes = hex::decode(hex_str).map_err(|error| Error::InvalidHex(error.to_string()))?;

        if bytes.len() != 32 {
            return Err(Error::InvalidPublicKey(format!(
                "expected 32 bytes, got {}",
                bytes.len()
            )));
        }

        let mut arr = [0_u8; 32];
        arr.copy_from_slice(&bytes);
        Self::from_bytes(&arr)
    }

    /// Verify a signature over the supplied message.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        self.verifying_key.verify(message, &signature.inner).is_ok()
    }

    /// Export as unprefixed hex.
    pub fn to_hex(&self) -> String {
        hex::encode(self.verifying_key.to_bytes())
    }

    /// Export as `0x`-prefixed hex.
    pub fn to_hex_prefixed(&self) -> String {
        format!("0x{}", self.to_hex())
    }

    /// Borrow the underlying bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.verifying_key.as_bytes()
    }
}

/// An Ed25519 signature.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Signature {
    #[serde(with = "sig_serde")]
    inner: DalekSignature,
}

mod sig_serde {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(
        signature: &DalekSignature,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(signature.to_bytes()))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> std::result::Result<DalekSignature, D::Error>
    where
        D: Deserializer<'de>,
    {
        let hex_str = String::deserialize(deserializer)?;
        let hex_str = hex_str.strip_prefix("0x").unwrap_or(&hex_str);
        let bytes = hex::decode(hex_str).map_err(serde::de::Error::custom)?;
        let bytes: [u8; 64] = bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("signature must be 64 bytes"))?;
        Ok(DalekSignature::from_bytes(&bytes))
    }
}

impl Signature {
    /// Create from raw bytes.
    pub fn from_bytes(bytes: &[u8; 64]) -> Self {
        Self {
            inner: DalekSignature::from_bytes(bytes),
        }
    }

    /// Create from hex-encoded bytes.
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        let bytes = hex::decode(hex_str).map_err(|error| Error::InvalidHex(error.to_string()))?;

        if bytes.len() != 64 {
            return Err(Error::InvalidSignature);
        }

        let mut arr = [0_u8; 64];
        arr.copy_from_slice(&bytes);
        Ok(Self::from_bytes(&arr))
    }

    /// Export as unprefixed hex.
    pub fn to_hex(&self) -> String {
        hex::encode(self.inner.to_bytes())
    }

    /// Export as `0x`-prefixed hex.
    pub fn to_hex_prefixed(&self) -> String {
        format!("0x{}", self.to_hex())
    }

    /// Copy the raw signature bytes.
    pub fn to_bytes(&self) -> [u8; 64] {
        self.inner.to_bytes()
    }
}

/// Verify a signature over a message.
pub fn verify_signature(public_key: &PublicKey, message: &[u8], signature: &Signature) -> bool {
    public_key.verify(message, signature)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_verify() {
        let keypair = Keypair::generate();
        let message = b"Hello, swarm!";
        let signature = keypair.sign(message);

        assert!(keypair.public_key().verify(message, &signature));
    }

    #[test]
    fn test_sign_verify_wrong_message() {
        let keypair = Keypair::generate();
        let signature = keypair.sign(b"Hello, swarm!");

        assert!(!keypair.public_key().verify(b"Wrong message", &signature));
    }

    #[test]
    fn test_keypair_from_seed() {
        let seed = [42_u8; 32];
        let kp1 = Keypair::from_seed(&seed);
        let kp2 = Keypair::from_seed(&seed);

        assert_eq!(kp1.public_key().to_hex(), kp2.public_key().to_hex());
    }

    #[test]
    fn test_hex_roundtrip() {
        let keypair = Keypair::generate();
        let pubkey_hex = keypair.public_key().to_hex();
        let restored = PublicKey::from_hex(&pubkey_hex).unwrap();

        assert_eq!(keypair.public_key(), restored);
    }

    #[test]
    fn test_signature_hex_roundtrip() {
        let keypair = Keypair::generate();
        let signature = keypair.sign(b"test");
        let sig_hex = signature.to_hex();
        let restored = Signature::from_hex(&sig_hex).unwrap();

        assert_eq!(signature.to_bytes(), restored.to_bytes());
    }

    #[test]
    fn test_serde_roundtrip() {
        let keypair = Keypair::generate();
        let public_key = keypair.public_key();
        let signature = keypair.sign(b"test");

        let public_key_json = serde_json::to_string(&public_key).unwrap();
        let signature_json = serde_json::to_string(&signature).unwrap();

        let public_key_restored: PublicKey = serde_json::from_str(&public_key_json).unwrap();
        let signature_restored: Signature = serde_json::from_str(&signature_json).unwrap();

        assert_eq!(public_key, public_key_restored);
        assert!(public_key.verify(b"test", &signature_restored));
    }
}
