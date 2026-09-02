#![cfg_attr(not(test), forbid(unsafe_code))]

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
//! # Where `axum` ended up
//!
//! `swarm-runtime`'s manifest no longer carries `axum` as a normal dependency:
//! it is a `[dev-dependencies]` entry there, and no lib or bin target in the
//! composition root names it. The other five -- `hyper`, `hyper-util`,
//! `rustls-pemfile`, `tokio-rustls`, `x509-parser` -- are gone from that
//! manifest entirely.
//!
//! One NORMAL edge to `axum` survives and cannot be removed here, because it
//! does not run through this crate at all:
//!
//! ```text
//! $ cargo tree -p swarm-runtime -e normal -i axum
//! axum v0.8.9
//! └── tonic v0.13.1
//!     └── swarm-ingest-tetragon
//!         └── swarm-runtime
//! ```
//!
//! So `axum` is still COMPILED for the composition root's normal profile, and
//! the manifest change is a naming boundary rather than a graph removal. That
//! distinction is the whole subject of
//! `docs/decisions/0008-split-01-axum-edge-is-now-dev-only.md`, which supersedes
//! ADR 0002 and retracts its forecast that SPLIT-05 would delete the line --
//! the blocker was never in `ingest/`, so extracting `ingest/` could not have
//! reached it. Do not follow ADR 0002's verification step; a bare
//! `grep '^axum' crates/swarm-runtime/Cargo.toml` cannot see manifest sections
//! and reports the dev-dependency as though the requirement were still open.
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
pub(crate) use swarm_ingest_runtime::control;
pub(crate) use swarm_runtime::{
    agent_identity, approval, canary, config, drafting, evolution, evolution_status, mutation,
    promotion, replay, selection, strategy,
};
// `evidence`, `governance_prep`, `operator_maintenance` and `portfolio` left
// `swarm-runtime`
// with SPLIT-04, and
// `review_workbench` left with SPLIT-02. Same aliases, new homes, so
// `cli::core`'s `crate::evidence::...`, `crate::operator_maintenance::...` and
// `crate::review_workbench::...` paths resolve unchanged.
pub(crate) use swarm_evolution::{evidence, governance_prep, operator_maintenance, portfolio};
pub(crate) use swarm_runtime_workbench::review_workbench;

/// Narrow facade used by the shared CLI source for the explicit offline
/// governance-lock migration command.
pub mod governance_migration {
    pub use swarm_agents::tom_agent::{
        GovernanceLockMigrationReport, GovernancePersistenceError, GovernancePolicy,
        GovernancePolicyConfig,
    };
}

pub mod cli;
pub mod http;
pub mod operator_http;
pub mod serve;
