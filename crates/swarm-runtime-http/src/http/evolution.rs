use super::error::{OperatorApiError, map_governance_prep_error, map_portfolio_error};
use super::helpers::{
    governance_harness, limit_packet_set_list, limit_portfolio_history_list, limit_portfolio_list,
    parse_portfolio_review_state, portfolio_harness,
};
use super::state::OperatorHttpState;
use axum::Json;
use axum::extract::{Path as RoutePath, Query, State};
use serde::Deserialize;
use swarm_evolution::governance_prep::{
    EvolutionGovernancePacketSetList, EvolutionPortfolioHistoryList,
};
use swarm_runtime::portfolio::EvolutionPortfolioList;

#[derive(Debug, Deserialize)]
pub(super) struct PortfolioListQuery {
    cohort: Option<String>,
    review_state: Option<String>,
    limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub(super) struct CohortListQuery {
    cohort: Option<String>,
    limit: Option<usize>,
}

pub(super) async fn portfolio_handler(
    State(state): State<OperatorHttpState>,
    RoutePath(portfolio_id): RoutePath<String>,
) -> Result<Json<swarm_runtime::portfolio::EvolutionPortfolioReport>, OperatorApiError> {
    let harness = portfolio_harness(&state)?;
    let lookup = harness
        .load_portfolio(&portfolio_id)
        .map_err(map_portfolio_error)?
        .ok_or_else(|| {
            OperatorApiError::not_found(format!("portfolio `{portfolio_id}` was not found"))
        })?;
    Ok(Json(lookup.report))
}

pub(super) async fn portfolio_list_handler(
    State(state): State<OperatorHttpState>,
    Query(query): Query<PortfolioListQuery>,
) -> Result<Json<EvolutionPortfolioList>, OperatorApiError> {
    let harness = portfolio_harness(&state)?;
    let review_state = query
        .review_state
        .as_deref()
        .map(parse_portfolio_review_state)
        .transpose()?;
    let list = harness
        .list_portfolios(query.cohort.as_deref(), review_state)
        .map_err(map_portfolio_error)?;
    Ok(Json(limit_portfolio_list(
        list,
        query.limit,
        state.max_list_results,
    )))
}

pub(super) async fn governance_packet_handler(
    State(state): State<OperatorHttpState>,
    RoutePath(packet_id): RoutePath<String>,
) -> Result<Json<swarm_runtime::portfolio::EvolutionGovernanceReviewPacketReport>, OperatorApiError>
{
    let harness = portfolio_harness(&state)?;
    let lookup = harness
        .load_governance_review_packet(&packet_id)
        .map_err(map_portfolio_error)?
        .ok_or_else(|| {
            OperatorApiError::not_found(format!("governance packet `{packet_id}` was not found"))
        })?;
    Ok(Json(lookup.report))
}

pub(super) async fn packet_set_handler(
    State(state): State<OperatorHttpState>,
    RoutePath(packet_set_id): RoutePath<String>,
) -> Result<
    Json<swarm_evolution::governance_prep::EvolutionGovernancePacketSetReport>,
    OperatorApiError,
> {
    let harness = governance_harness(&state)?;
    let lookup = harness
        .load_packet_set(&packet_set_id)
        .map_err(map_governance_prep_error)?
        .ok_or_else(|| {
            OperatorApiError::not_found(format!("packet set `{packet_set_id}` was not found"))
        })?;
    Ok(Json(lookup.report))
}

pub(super) async fn packet_set_list_handler(
    State(state): State<OperatorHttpState>,
    Query(query): Query<CohortListQuery>,
) -> Result<Json<EvolutionGovernancePacketSetList>, OperatorApiError> {
    let harness = governance_harness(&state)?;
    let list = harness
        .list_packet_sets(query.cohort.as_deref())
        .map_err(map_governance_prep_error)?;
    Ok(Json(limit_packet_set_list(
        list,
        query.limit,
        state.max_list_results,
    )))
}

pub(super) async fn portfolio_history_handler(
    State(state): State<OperatorHttpState>,
    RoutePath(history_id): RoutePath<String>,
) -> Result<Json<swarm_evolution::governance_prep::EvolutionPortfolioHistoryReport>, OperatorApiError>
{
    let harness = governance_harness(&state)?;
    let lookup = harness
        .load_portfolio_history(&history_id)
        .map_err(map_governance_prep_error)?
        .ok_or_else(|| {
            OperatorApiError::not_found(format!("portfolio history `{history_id}` was not found"))
        })?;
    Ok(Json(lookup.report))
}

pub(super) async fn portfolio_history_list_handler(
    State(state): State<OperatorHttpState>,
    Query(query): Query<CohortListQuery>,
) -> Result<Json<EvolutionPortfolioHistoryList>, OperatorApiError> {
    let harness = governance_harness(&state)?;
    let list = harness
        .list_portfolio_history(query.cohort.as_deref())
        .map_err(map_governance_prep_error)?;
    Ok(Json(limit_portfolio_history_list(
        list,
        query.limit,
        state.max_list_results,
    )))
}
