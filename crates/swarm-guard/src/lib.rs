//! Guard pipeline and Spider Sense embedding detection.
//!
//! Vendored and adapted from ClawdStrike's guard system.
//! Provides the middleware layer that enforces policy on every swarm action.
//!
//! Spider Sense (cosine similarity over threat embeddings) serves as
//! the Whisker's primary fast-path detection mechanism.

// TODO: Vendor from clawdstrike/crates/libs/clawdstrike/src/
// - Guard trait + GuardResult + GuardAction
// - Spider Sense detector (cosine similarity, pattern DB)
// - Policy loading and guard instantiation
// - Middleware integration for the swarm pipeline
