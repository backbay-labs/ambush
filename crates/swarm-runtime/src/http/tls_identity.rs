//! The mTLS peer identity attached to an inbound request.
//!
//! # Placement (SPLIT-01, phase 282)
//!
//! This type is produced by the TLS accept loop, which now lives in
//! `swarm-runtime-http` (`serve::serve_with_listener` inserts it into the
//! request extensions), and consumed here in the composition root, where
//! `ingest/platform_api.rs` reads it back out for the `tls_client_identity`
//! field of the authenticated-request log line.
//!
//! Axum extensions are keyed by `TypeId`, so producer and consumer must name
//! the SAME type. It therefore has to be defined at or below `swarm-runtime`,
//! and it has to be constructible from above it. That is the whole reason
//! `new` exists and is `pub`: it is the narrowest thing that lets the transport
//! crate build a value whose representation stays private. Widening the tuple
//! field to `pub` would have kept the diff smaller and exposed the `Arc<str>`
//! representation to every consumer of the crate; a constructor does not.
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct TlsClientIdentity(Arc<str>);

impl TlsClientIdentity {
    /// Wrap a verified peer identity. Called by the TLS accept loop in
    /// `swarm-runtime-http`; see the module doc for why this crosses the crate
    /// boundary.
    pub fn new(identity: Arc<str>) -> Self {
        Self(identity)
    }

    pub fn as_str(&self) -> &str {
        self.0.as_ref()
    }
}
