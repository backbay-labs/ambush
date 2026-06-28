//! RFC 6962-compatible Merkle tree utilities.

use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha256};

use crate::error::{Error, Result};
use crate::hashing::Hash;

/// Compute a leaf hash per RFC 6962: `SHA256(0x00 || leaf)`.
pub fn leaf_hash(leaf_bytes: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update([0x00]);
    hasher.update(leaf_bytes);
    let result = hasher.finalize();

    let mut bytes = [0_u8; 32];
    bytes.copy_from_slice(&result);
    Hash::from_bytes(bytes)
}

/// Compute a node hash per RFC 6962: `SHA256(0x01 || left || right)`.
pub fn node_hash(left: &Hash, right: &Hash) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update([0x01]);
    hasher.update(left.as_bytes());
    hasher.update(right.as_bytes());
    let result = hasher.finalize();

    let mut bytes = [0_u8; 32];
    bytes.copy_from_slice(&result);
    Hash::from_bytes(bytes)
}

/// RFC 6962-compatible Merkle tree.
#[derive(Clone, Debug)]
pub struct MerkleTree {
    levels: Vec<Vec<Hash>>,
}

impl MerkleTree {
    /// Build a Merkle tree from leaf data.
    pub fn from_leaves<T: AsRef<[u8]>>(leaves: &[T]) -> Result<Self> {
        if leaves.is_empty() {
            return Err(Error::EmptyTree);
        }

        let mut levels = Vec::new();
        let mut current: Vec<Hash> = leaves.iter().map(|leaf| leaf_hash(leaf.as_ref())).collect();
        levels.push(current.clone());

        while current.len() > 1 {
            let mut next = Vec::with_capacity(current.len().div_ceil(2));
            let mut index = 0;
            while index < current.len() {
                if index + 1 < current.len() {
                    next.push(node_hash(&current[index], &current[index + 1]));
                } else {
                    next.push(current[index]);
                }
                index += 2;
            }
            levels.push(next.clone());
            current = next;
        }

        Ok(Self { levels })
    }

    /// Build a Merkle tree from pre-hashed leaves.
    pub fn from_hashes(leaf_hashes: Vec<Hash>) -> Result<Self> {
        if leaf_hashes.is_empty() {
            return Err(Error::EmptyTree);
        }

        let mut levels = Vec::new();
        let mut current = leaf_hashes;
        levels.push(current.clone());

        while current.len() > 1 {
            let mut next = Vec::with_capacity(current.len().div_ceil(2));
            let mut index = 0;
            while index < current.len() {
                if index + 1 < current.len() {
                    next.push(node_hash(&current[index], &current[index + 1]));
                } else {
                    next.push(current[index]);
                }
                index += 2;
            }
            levels.push(next.clone());
            current = next;
        }

        Ok(Self { levels })
    }

    /// Return the number of leaves in the tree.
    pub fn leaf_count(&self) -> usize {
        self.levels.first().map_or(0, Vec::len)
    }

    /// Return the root hash.
    pub fn root(&self) -> Hash {
        self.levels
            .last()
            .and_then(|level| level.first().copied())
            .unwrap_or_else(Hash::zero)
    }

    /// Generate an inclusion proof for a leaf index.
    pub fn inclusion_proof(&self, leaf_index: usize) -> Result<MerkleProof> {
        let tree_size = self.leaf_count();
        if leaf_index >= tree_size {
            return Err(Error::InvalidProofIndex {
                index: leaf_index,
                leaves: tree_size,
            });
        }

        let mut audit_path = Vec::new();
        let mut index = leaf_index;

        for level in &self.levels {
            if level.len() <= 1 {
                break;
            }

            if index.is_multiple_of(2) {
                let sibling = index + 1;
                if sibling < level.len() {
                    audit_path.push(level[sibling]);
                }
            } else {
                audit_path.push(level[index - 1]);
            }

            index /= 2;
        }

        Ok(MerkleProof {
            tree_size,
            leaf_index,
            audit_path,
        })
    }
}

/// Merkle inclusion proof.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerkleProof {
    pub tree_size: usize,
    pub leaf_index: usize,
    pub audit_path: Vec<Hash>,
}

impl MerkleProof {
    /// Compute the root from leaf bytes and the proof.
    pub fn compute_root(&self, leaf_bytes: &[u8]) -> Result<Hash> {
        self.compute_root_from_hash(leaf_hash(leaf_bytes))
    }

    /// Compute the root from a pre-hashed leaf.
    pub fn compute_root_from_hash(&self, leaf_hash: Hash) -> Result<Hash> {
        if self.tree_size == 0 || self.leaf_index >= self.tree_size {
            return Err(Error::MerkleProofFailed);
        }

        let mut hash = leaf_hash;
        let mut index = self.leaf_index;
        let mut size = self.tree_size;
        let mut path_index = 0_usize;

        while size > 1 {
            if index.is_multiple_of(2) {
                if index + 1 < size {
                    if path_index >= self.audit_path.len() {
                        return Err(Error::MerkleProofFailed);
                    }
                    let sibling = &self.audit_path[path_index];
                    path_index += 1;
                    hash = node_hash(&hash, sibling);
                }
            } else {
                if path_index >= self.audit_path.len() {
                    return Err(Error::MerkleProofFailed);
                }
                let sibling = &self.audit_path[path_index];
                path_index += 1;
                hash = node_hash(sibling, &hash);
            }

            index /= 2;
            size = size.div_ceil(2);
        }

        if path_index != self.audit_path.len() {
            return Err(Error::MerkleProofFailed);
        }

        Ok(hash)
    }

    /// Verify the proof against the expected root.
    pub fn verify(&self, leaf_bytes: &[u8], expected_root: &Hash) -> bool {
        self.compute_root(leaf_bytes)
            .is_ok_and(|computed| &computed == expected_root)
    }

    /// Verify a pre-hashed leaf against the expected root.
    pub fn verify_hash(&self, leaf_hash: Hash, expected_root: &Hash) -> bool {
        self.compute_root_from_hash(leaf_hash)
            .is_ok_and(|computed| &computed == expected_root)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn tree_hash_recursive(level0: &[Hash]) -> Hash {
        match level0.len() {
            0 => Hash::zero(),
            1 => level0[0],
            n => {
                let split = largest_power_of_two_less_than(n);
                let left = tree_hash_recursive(&level0[..split]);
                let right = tree_hash_recursive(&level0[split..]);
                node_hash(&left, &right)
            }
        }
    }

    fn largest_power_of_two_less_than(n: usize) -> usize {
        let mut power = 1_usize;
        while (power << 1) < n {
            power <<= 1;
        }
        power
    }

    #[test]
    fn root_matches_recursive_reference() {
        for count in 1..32_usize {
            let leaves: Vec<Vec<u8>> = (0..count)
                .map(|index| format!("leaf-{index}").into_bytes())
                .collect();
            let tree = MerkleTree::from_leaves(&leaves).unwrap();
            let leaf_hashes: Vec<Hash> = leaves.iter().map(|leaf| leaf_hash(leaf)).collect();
            let expected = tree_hash_recursive(&leaf_hashes);

            assert_eq!(tree.root(), expected, "n={count}");
        }
    }

    #[test]
    fn inclusion_proofs_roundtrip() {
        let leaves: Vec<Vec<u8>> = (0..25_usize)
            .map(|index| format!("leaf-{index}").into_bytes())
            .collect();
        let tree = MerkleTree::from_leaves(&leaves).unwrap();
        let root = tree.root();

        for (index, leaf) in leaves.iter().enumerate() {
            let proof = tree.inclusion_proof(index).unwrap();
            assert!(proof.verify(leaf, &root), "idx={index}");
        }
    }

    #[test]
    fn inclusion_proof_rejects_wrong_leaf() {
        let leaves: Vec<Vec<u8>> = (0..10_usize)
            .map(|index| format!("leaf-{index}").into_bytes())
            .collect();
        let tree = MerkleTree::from_leaves(&leaves).unwrap();
        let root = tree.root();

        let proof = tree.inclusion_proof(3).unwrap();
        assert!(!proof.verify(b"wrong", &root));
    }

    #[test]
    fn single_leaf_tree() {
        let tree = MerkleTree::from_leaves(&[b"single"]).unwrap();
        assert_eq!(tree.leaf_count(), 1);
        assert_eq!(tree.root(), leaf_hash(b"single"));

        let proof = tree.inclusion_proof(0).unwrap();
        assert!(proof.verify(b"single", &tree.root()));
        assert!(proof.audit_path.is_empty());
    }

    #[test]
    fn two_leaf_tree() {
        let leaves: Vec<&[u8]> = vec![b"left", b"right"];
        let tree = MerkleTree::from_leaves(&leaves).unwrap();

        assert_eq!(
            tree.root(),
            node_hash(&leaf_hash(b"left"), &leaf_hash(b"right"))
        );
    }

    #[test]
    fn empty_tree_fails() {
        let leaves: Vec<Vec<u8>> = Vec::new();
        assert!(matches!(
            MerkleTree::from_leaves(&leaves),
            Err(Error::EmptyTree)
        ));
    }

    #[test]
    fn proof_serialization_roundtrip() {
        let leaves: Vec<Vec<u8>> = (0..8_usize)
            .map(|index| format!("leaf-{index}").into_bytes())
            .collect();
        let tree = MerkleTree::from_leaves(&leaves).unwrap();
        let proof = tree.inclusion_proof(5).unwrap();
        let serialized = serde_json::to_string(&proof).unwrap();
        let restored: MerkleProof = serde_json::from_str(&serialized).unwrap();

        assert!(restored.verify(&leaves[5], &tree.root()));
    }
}
