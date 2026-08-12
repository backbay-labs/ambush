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
//!
//! `result_large_err` is allowed crate-wide here for the same reason it is
//! allowed in `swarm-runtime`, whose `lib.rs` carries the identical attribute:
//! the operator handlers return `Result<_, OperatorHttpError>` and that enum
//! wraps the runtime's own large error types by `#[from]`. The moved code is
//! byte-identical to what compiled under that allow before the split, so the
//! allow moves with it rather than the error types being reshaped here.
#![allow(clippy::result_large_err)]

// `cli::core` is `crates/swarm-cli/src/core.inc`, pulled in by `#[path]` rather
// than by a crate dependency (see `cli/mod.rs`). It resolves the runtime modules
// it uses as `crate::<name>`, which in `swarm-cli` are the facade modules in
// that crate's `lib.rs`. These aliases give the same names the same meaning
// here. They are `pub(crate)`, NOT `pub`: the shared source needs the paths to
// resolve inside this crate, and nothing outside it should reach `swarm-runtime`
// through `swarm-runtime-http` when it can depend on `swarm-runtime` directly.
pub(crate) use swarm_runtime::{
    agent_identity, approval, canary, config, control, drafting, evidence, evolution,
    evolution_status, governance_prep, mutation, operator_maintenance, portfolio, promotion,
    replay, review_workbench, selection, strategy,
};

pub mod cli;
pub mod http;
pub mod operator_http;
