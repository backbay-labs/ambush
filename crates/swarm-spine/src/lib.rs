//! Signed envelope protocol and Merkle audit trail.
//!
//! Vendored and adapted from ClawdStrike's spine crate.
//! Every swarm action is wrapped in a signed envelope and
//! anchored in the Merkle checkpoint trail.
//!
//! Schema: `swarm.spine.envelope.v1`

// TODO: Vendor from clawdstrike/crates/libs/spine/src/
// - Signed envelope build/verify
// - Checkpoint statements with witness co-signatures
// - NATS JetStream helpers (ensure_stream, ensure_kv)
// - Merkle tree construction and proof verification
