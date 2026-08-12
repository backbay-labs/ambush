//! Transport crate for the Ambush runtime: the authenticated operator HTTP
//! surface and the TLS-capable server loop that carries it.
//!
//! # Why this is a separate crate (SPLIT-01, phase 282)
//!
//! `swarm-runtime` is the composition root. Everything that links it -- replay,
//! evolution, the offline evidence lanes -- paid for `hyper`, `hyper-util`,
//! `rustls-pemfile`, `tokio-rustls` and `x509-parser` whether or not it ever
//! opened a socket. Those five dependencies live here now, above the runtime,
//! so the dependency runs `swarm-runtime-http -> swarm-runtime` and never back.
//!
//! Nothing in `swarm-runtime` may depend on this crate. If a runtime module
//! needs something from here, the item is in the wrong crate.
