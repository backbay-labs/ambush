//! The authenticated operator surface for containment leases: list them, and
//! release one early.
//!
//! # Why this is an HTTP route and not a `swarmctl` subcommand (QRT-04)
//!
//! `.planning/REQUIREMENTS.md` writes QRT-04 as `swarmctl quarantine release
//! <lease_id>`, and a subcommand that opened the state itself would fork two
//! audit chains. `GovernancePersistence::save` (`swarm-agents`,
//! `tom_agent.rs`) is tmp-write plus rename with no lock and the daemon holds
//! `previous_commit_hash` and `receipt_counter` in memory, so a CLI release
//! while `swarm_detect --serve` runs would advance a chain the daemon cannot
//! see. `FileContainmentLeaseStore` has the same shape one layer down: its
//! `locked()` is a `std::sync::Mutex` inside one process, so two processes
//! read-modify-writing the same lease document lose each other's writes.
//!
//! So the CLI is a client and the daemon is the only writer. `swarmctl
//! quarantine release` sends a request here.
//!
//! # Why the router is built here but mounted by `swarm_detect`
//!
//! The routes need the SAME [`ContainmentSweep`] the TTL task holds --
//! `state.current_containment_store()`'s `Arc`, not a store rebuilt from
//! config. With `runtime.containment.lease_store_path` unset the store is a
//! `MemoryContainmentLeaseStore`, and a second instance is a different map: a
//! handler built from config would answer "no open containment lease `x`" for
//! every lease the daemon is actually holding, which is a check reporting over
//! a region it never inspected.
//!
//! `LocalOperatorSurface` builds its own `DefaultControlPlane` in its own
//! process and therefore has exactly that problem, which is why these routes
//! are NOT merged into it. `swarm_detect` -- the process that opens leases,
//! sweeps them, and holds the governance authority -- mounts them with the
//! object it already has.
//!
//! Owns: the operator-facing containment routes and their authorization.
//!
//! Does not own: releasing (that is `swarm_runtime::containment::release_lease`,
//! reached through [`ContainmentSweep::release`]), attesting (that is the
//! governance authority the sweep carries), or deciding when a lease expires.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Extension, Path as RoutePath, Query, State};
use axum::routing::{get, post};
use axum::{Router, middleware};
use serde::{Deserialize, Serialize};
use swarm_core::config::{OperatorScope, SwarmConfig};
use swarm_core::http_rate_limit::HttpRateLimiter;
use swarm_ingest_runtime::control::CURRENT_OPERATOR_API_SCHEMA_VERSION;
use swarm_response::containment::ContainmentLease;
use swarm_response::rollback::RollbackReceipt;
use swarm_runtime::containment::{
    ContainmentReleaseError, ContainmentSweep, verify_release_attestation,
};

use super::auth::{
    AuthenticatedOperatorPrincipal, OperatorAuthState, require_bearer_auth,
    require_operator_api_scope, require_supported_operator_api_schema_version,
};
use super::error::OperatorApiError;
use super::helpers::now_ms;
use super::state::{OperatorHttpError, OperatorRequestGuardState};

/// State the containment routes run against.
#[derive(Clone)]
pub(super) struct ContainmentHttpState {
    sweep: Arc<ContainmentSweep>,
}

/// One open lease, as an operator reads it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainmentLeaseView {
    pub lease: ContainmentLease,
    /// Milliseconds left before the TTL sweep would release this lease on its
    /// own, at `observed_at_ms`.
    ///
    /// `ContainmentLease::remaining_ms` SATURATES AT ZERO, so this field alone
    /// cannot distinguish "expires in an instant" from "expired an hour ago and
    /// the sweep has not managed to release it". [`Self::expired`] is the field
    /// that answers that, which is why both are here rather than one.
    pub remaining_ms: i64,
    /// Whether the lease was already past its expiry at `observed_at_ms`. A
    /// `true` here on a lease that is still listed means the sweep has tried
    /// and failed to release it -- see `release_lease`, which keeps such a
    /// lease open rather than abandoning a host that is still contained.
    pub expired: bool,
}

/// Response of `GET /v1/operator/containment/leases`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainmentLeaseListResponse {
    pub schema_version: u32,
    pub observed_at_ms: i64,
    pub open_leases: Vec<ContainmentLeaseView>,
}

/// Query of `GET /v1/operator/containment/leases`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContainmentLeaseListQuery {
    /// The instant to compute `remaining_ms` and `expired` against. Absent
    /// means "now".
    ///
    /// Same shape as `threat_intel_entry_lookup_handler`'s `now`, and for the
    /// same reason: those two fields are the only ones on this response that a
    /// clock can move, so a caller that needs a reproducible answer -- a test,
    /// a replay -- states the instant instead of racing the wall clock.
    pub now_ms: Option<i64>,
}

/// Optional body of a release request.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContainmentReleaseRequest {
    /// The instant to release at. Absent means "now".
    ///
    /// Present so a test, a replay, or an operator reconstructing an incident
    /// can drive the release at a stated instant instead of whatever the wall
    /// clock happens to say. It does not let a caller pretend a lease expired:
    /// [`ContainmentSweep::release`] releases the named lease regardless of
    /// expiry -- that is what "early release" means -- and the receipt records
    /// the instant it was told to act at.
    pub now_ms: Option<i64>,
}

/// Response of `POST /v1/operator/containment/leases/{lease_id}/release`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainmentReleaseResponse {
    pub schema_version: u32,
    pub receipt: RollbackReceipt,
    /// Whether the lease is now closed. FALSE when the inverse was attempted
    /// and failed: `release_lease` deliberately keeps such a lease open for the
    /// next sweep to retry, and the response has to say so rather than let a
    /// 200 read as "released".
    pub lease_closed: bool,
    /// Whether the pre-containment state was actually restored.
    pub fully_reversed: bool,
    /// Whether the attached governance attestation verified against this
    /// receipt.
    pub attestation_verified: bool,
    /// Why it did not, when it did not. `None` only when `attestation_verified`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation_error: Option<String>,
}

fn map_release_error(error: ContainmentReleaseError) -> OperatorApiError {
    match error {
        ContainmentReleaseError::UnknownLease { .. } => {
            OperatorApiError::not_found(error.to_string())
        }
        ContainmentReleaseError::Store(_) | ContainmentReleaseError::Rollback { .. } => {
            OperatorApiError::internal(error.to_string())
        }
    }
}

async fn containment_lease_list_handler(
    State(state): State<ContainmentHttpState>,
    Query(query): Query<ContainmentLeaseListQuery>,
) -> Result<Json<ContainmentLeaseListResponse>, OperatorApiError> {
    let observed_at_ms = query.now_ms.unwrap_or_else(now_ms);
    let open_leases = state
        .sweep
        .open_leases()
        .map_err(|error| OperatorApiError::internal(error.to_string()))?;
    let mut open_leases: Vec<ContainmentLeaseView> = open_leases
        .into_iter()
        .map(|lease| ContainmentLeaseView {
            remaining_ms: lease.remaining_ms(observed_at_ms),
            expired: lease.is_expired(observed_at_ms),
            lease,
        })
        .collect();
    // Stable order. `open_leases()` walks a `BTreeMap` for the file store but a
    // caller should not have to know that, and a listing whose order depends on
    // the store implementation makes two operators' screens disagree.
    open_leases.sort_by(|left, right| {
        left.lease
            .expires_at_ms()
            .cmp(&right.lease.expires_at_ms())
            .then_with(|| left.lease.lease_id().cmp(right.lease.lease_id()))
    });
    Ok(Json(ContainmentLeaseListResponse {
        schema_version: CURRENT_OPERATOR_API_SCHEMA_VERSION,
        observed_at_ms,
        open_leases,
    }))
}

async fn containment_lease_release_handler(
    Extension(principal): Extension<AuthenticatedOperatorPrincipal>,
    State(state): State<ContainmentHttpState>,
    RoutePath(lease_id): RoutePath<String>,
    body: Option<Json<ContainmentReleaseRequest>>,
) -> Result<Json<ContainmentReleaseResponse>, OperatorApiError> {
    require_operator_api_scope(&principal, OperatorScope::Maintenance, "maintenance")?;
    if lease_id.trim().is_empty() {
        return Err(OperatorApiError::bad_request(
            "containment release requires a non-empty lease id",
        ));
    }
    let now_ms = body
        .and_then(|Json(request)| request.now_ms)
        .unwrap_or_else(now_ms);

    // THE SHARED PATH. `ContainmentSweep::release` calls
    // `swarm_runtime::containment::release_lease` -- the same function
    // `ContainmentSweep::sweep` calls for every expired lease, on the same
    // `Arc<ContainmentSweep>` this handler and the TTL task both hold. Manual
    // and automatic release differ in exactly one argument, `RollbackTrigger`,
    // and there is no second implementation for them to drift apart in.
    let receipt = state
        .sweep
        .release(&lease_id, now_ms)
        .await
        .map_err(map_release_error)?;

    // ANCHORED TO THE AUTHORITY THAT SIGNED IT. The sweep's own governance
    // authority is the trust anchor, so `attestation_verified: true` now means
    // "a governor this process recognizes signed this exact body" rather than
    // "this receipt is internally consistent" (ADR 0011). With no authority
    // installed the answer is `false` with a stated reason, never `true`.
    let (attestation_verified, attestation_error) =
        match verify_release_attestation(&receipt, state.sweep.governance()) {
            Ok(_) => (true, None),
            Err(error) => (false, Some(error.to_string())),
        };
    let lease_closed = state
        .sweep
        .open_leases()
        .map(|leases| !leases.iter().any(|lease| lease.lease_id() == lease_id))
        .unwrap_or(false);

    tracing::info!(
        module = module_path!(),
        operator_id = %principal.operator_id,
        lease_id = %lease_id,
        rollback_id = %receipt.rollback_id,
        lease_closed,
        attestation_verified,
        "operator released a containment lease early"
    );

    Ok(Json(ContainmentReleaseResponse {
        schema_version: CURRENT_OPERATOR_API_SCHEMA_VERSION,
        lease_closed,
        fully_reversed: receipt.fully_reversed(),
        receipt,
        attestation_verified,
        attestation_error,
    }))
}

/// Build the authenticated containment routes over an already-composed sweep.
///
/// Takes the `Arc<ContainmentSweep>` rather than building one, because the
/// point of the whole module is that these routes act on the process's ONE
/// sweep. See the module doc.
pub fn containment_operator_router(
    config: &SwarmConfig,
    sweep: Arc<ContainmentSweep>,
) -> Result<Router, OperatorHttpError> {
    let auth = OperatorAuthState::from_config(config)?;
    let rate_limiter =
        HttpRateLimiter::new("operator-containment", config.operator.rate_limit.clone());
    let state = ContainmentHttpState { sweep };
    Ok(Router::new()
        .route(
            "/v1/operator/containment/leases",
            get(containment_lease_list_handler),
        )
        .route(
            "/v1/operator/containment/leases/{lease_id}/release",
            post(containment_lease_release_handler),
        )
        .with_state(state)
        .layer(middleware::from_fn_with_state(
            OperatorRequestGuardState { auth, rate_limiter },
            require_bearer_auth,
        ))
        .layer(middleware::from_fn(
            require_supported_operator_api_schema_version,
        )))
}
