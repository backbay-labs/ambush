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
//! # What did NOT move, and why `axum` is still below this line
//!
//! `axum` is still a direct dependency of `swarm-runtime`, and this crate did
//! not change that. `ingest/` -- `mod.rs`, `health.rs`, `demo.rs`,
//! `platform_api.rs`, `providence_handlers.rs`, `soar_verdict_handlers.rs` --
//! builds axum routers and handlers in NON-TEST code, and `swarm-runtime`'s own
//! `control.rs` and `anti_tamper.rs` consume `crate::ingest` in non-test code
//! in turn. Lifting `ingest` up here would invert those two edges, which is a
//! trait-boundary change, not a code move. Until that happens the runtime keeps
//! `axum`; the five heavier transport crates above are gone either way, and
//! `rustls-pemfile` and `x509-parser` are now unreachable from
//! `cargo tree -p swarm-runtime` entirely.
//!
//! That leaves SPLIT-01's six-dependency clause one dependency short, which is a
//! scope question rather than a code one. It is recorded in
//! `docs/decisions/0002-split-01-open-until-split-05.md`: SPLIT-01 stays open
//! until SPLIT-05 deletes the `axum` line. `swarm_runtime::http`'s module doc
//! carries the per-file measurement behind that decision.
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
    agent_identity, approval, canary, config, control, drafting, evolution, evolution_status,
    governance_prep, mutation, portfolio, promotion, replay, selection, strategy,
};
// `evidence` and `operator_maintenance` left `swarm-runtime` with SPLIT-04, and
// `review_workbench` left with SPLIT-02. Same aliases, new homes, so
// `cli::core`'s `crate::evidence::...`, `crate::operator_maintenance::...` and
// `crate::review_workbench::...` paths resolve unchanged.
pub(crate) use swarm_evolution::{evidence, operator_maintenance};
pub(crate) use swarm_runtime_workbench::review_workbench;

pub mod cli;
pub mod http;
pub mod operator_http;
pub mod serve;
