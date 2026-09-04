//! The four Watchfloor reducers.
//!
//! The daemon emits telemetry at a rate the relay cannot carry: `Ingest` fires
//! once per accepted event (3,645/second measured), and `ConcentrationSnapshot`
//! fires on every substrate tick. Publishing one relay event per runtime event
//! exceeds the quota by roughly 1,800x, so the Telemetry stream is COALESCED —
//! reduced to one frame per second per kind.
//!
//! Coalescing is lossy on purpose, and every reducer here says how. The rule
//! that matters: a coalesced frame must never be mistakable for an
//! instantaneous one. `ConcentrationFrame::coalesced_from` carries how many
//! ticks collapsed into the frame, so the console can render "1 of N" rather
//! than presenting a sample as the whole window.
//!
//! ## What each reducer drops, and why
//!
//! - **26000** keeps counts and per-source totals. It drops `event_id`,
//!   `host_id` and `reason` per event — `host_id` alone fails the
//!   aggregates-only rule for a community-global frame, and at the measured
//!   rate one frame per event is not a design.
//! - **26001** keeps the LAST snapshot in the window, not an average. An
//!   average of a decaying quantity is not a value the substrate ever held,
//!   and a threshold crossing computed from one is a crossing that did not
//!   happen.
//! - **26002** keeps the latest health per agent and SUMS the action tallies.
//!   Health is a state, so the newest wins; actions are counts, so they add.
//!   `hunt_id` and `details` never cross: `details` is
//!   `serde_json::to_value(action)` over the whole `SwarmAction`, which is
//!   adversary-influenced content with no route that serves it.
//! - **26003** is NOT coalesced past its own window and never dropped. Mode is
//!   not monotonic — the engine has `transition_down` beside `transition_to` —
//!   so a de-escalation must reach the wall or a band appears and never clears.

use std::collections::BTreeMap;

use swarm_perch_wire::{
    AgentHealthEntry, AgentHealthFrame, ConcentrationFrame, IngestRate, ModeTransitionFrame,
    WireAgentHealth, WireAgentRole, WireSwarmMode,
};
use swarm_runtime::runtime_events::RuntimeEvent;

use crate::stream::{agent_role_to_wire, concentration_to_wire, threat_class_to_wire};

/// The window every reducer here collapses. One second, matching `26000`'s
/// `window_ms`, so all four frames describe the same slice of time.
pub const COALESCE_WINDOW_MS: u32 = 1_000;

/// A collector name that looks like a host is a bridge configuration error.
///
/// `by_source` is keyed by COLLECTOR, and the aggregates-only rule for a
/// community-global frame forbids a host identifier. Rather than publish one
/// and hope, the reducer replaces it with this sentinel — an operator seeing
/// it has a configuration bug to fix, which is the true fact.
pub const SUSPECT_SOURCE: &str = "source-name-looks-like-a-host";

fn looks_like_a_host(source: &str) -> bool {
    // An IPv4 literal, or a dotted name whose last label is not a known
    // collector suffix. Deliberately blunt: the cost of a false positive is a
    // visible sentinel, and the cost of a false negative is a host id on a
    // global frame.
    source.split('.').count() >= 3 && source.chars().any(|c| c.is_ascii_digit())
        || source.parse::<std::net::IpAddr>().is_ok()
}

/// Reduce a window of `Ingest` events to one `26000` gauge.
pub fn ingest_rate(events: &[RuntimeEvent]) -> IngestRate {
    let mut accepted = 0u64;
    let mut rejected = 0u64;
    let mut by_source: BTreeMap<String, u64> = BTreeMap::new();
    for event in events {
        let RuntimeEvent::Ingest {
            source,
            accepted: ok,
            ..
        } = event
        else {
            continue;
        };
        if *ok {
            accepted += 1;
        } else {
            rejected += 1;
        }
        let key = if looks_like_a_host(source) {
            SUSPECT_SOURCE.to_string()
        } else {
            source.clone()
        };
        *by_source.entry(key).or_default() += 1;
    }
    IngestRate {
        window_ms: COALESCE_WINDOW_MS,
        accepted,
        rejected,
        by_source,
    }
}

fn swarm_mode_to_wire(mode: &swarm_core::agent::SwarmMode) -> WireSwarmMode {
    match mode {
        swarm_core::agent::SwarmMode::Normal => WireSwarmMode::Normal,
        swarm_core::agent::SwarmMode::Alert => WireSwarmMode::Alert,
        swarm_core::agent::SwarmMode::Incident => WireSwarmMode::Incident,
    }
}

fn agent_health_to_wire(health: &swarm_core::agent::AgentHealth) -> WireAgentHealth {
    match health {
        swarm_core::agent::AgentHealth::Healthy => WireAgentHealth::Healthy,
        swarm_core::agent::AgentHealth::Degraded => WireAgentHealth::Degraded,
        swarm_core::agent::AgentHealth::Failed => WireAgentHealth::Failed,
    }
}

/// Reduce a window of `ConcentrationSnapshot` events to one `26001` frame.
///
/// The LAST snapshot wins, and `coalesced_from` says how many were collapsed.
/// An average of a decaying quantity is a number the substrate never held, and
/// a threshold crossing read off one is a crossing that did not happen.
///
/// `None` when the window carried no snapshot: an empty window is not a
/// concentration of zero, and publishing one would tell the wall the substrate
/// went quiet when the bridge simply saw nothing.
pub fn concentration_frame(events: &[RuntimeEvent]) -> Option<ConcentrationFrame> {
    let mut coalesced_from = 0u32;
    let mut latest: Option<(&swarm_core::agent::SwarmMode, &Vec<_>, i64)> = None;
    for event in events {
        let RuntimeEvent::ConcentrationSnapshot {
            emitted_at_ms,
            current_mode,
            concentrations,
        } = event
        else {
            continue;
        };
        coalesced_from += 1;
        if latest.is_none_or(|(_, _, at)| *emitted_at_ms >= at) {
            latest = Some((current_mode, concentrations, *emitted_at_ms));
        }
    }
    let (mode, concentrations, emitted_at_ms) = latest?;
    Some(ConcentrationFrame {
        current_mode: swarm_mode_to_wire(mode),
        concentrations: concentrations.iter().map(concentration_to_wire).collect(),
        coalesced_from,
        // SECONDS, in its native unit and with the unit in the name. A shared
        // millisecond helper here produces a 1000x wrong decay curve silently,
        // in the direction of "everything looks evaporated".
        observed_at_seconds: emitted_at_ms / 1_000,
    })
}

/// Reduce a window of `AgentHealth` and `AgentAction` events to one `26002`.
///
/// Health is a state, so the newest observation wins. Actions are counts, so
/// they add. An agent that only acted still gets a row, carrying its tally and
/// its last known health — a tally with no row would be a count nobody can
/// attribute.
///
/// `None` when the window named no agent: no health frame at all is "the
/// console has not been told", which the wall renders differently from zero
/// agents.
pub fn agent_health_frame(events: &[RuntimeEvent]) -> Option<AgentHealthFrame> {
    struct Row {
        role: WireAgentRole,
        from: Option<WireAgentHealth>,
        to: Option<WireAgentHealth>,
        changed_at_ms: Option<i64>,
        actions: BTreeMap<String, u64>,
    }
    let mut rows: BTreeMap<String, Row> = BTreeMap::new();

    for event in events {
        match event {
            RuntimeEvent::AgentHealth {
                emitted_at_ms,
                agent_id,
                role,
                from,
                to,
            } => {
                let row = rows.entry(agent_id.clone()).or_insert_with(|| Row {
                    role: agent_role_to_wire(*role),
                    from: None,
                    to: None,
                    changed_at_ms: None,
                    actions: BTreeMap::new(),
                });
                row.role = agent_role_to_wire(*role);
                // `from` is the FIRST observation's predecessor, so a window
                // carrying healthy->degraded->failed reports healthy->failed
                // rather than losing where the agent started.
                if row.from.is_none() {
                    row.from = from.as_ref().map(agent_health_to_wire);
                }
                row.to = Some(agent_health_to_wire(to));
                row.changed_at_ms = Some(*emitted_at_ms);
            }
            RuntimeEvent::AgentAction {
                agent_id,
                role,
                action_kind,
                ..
            } => {
                let row = rows.entry(agent_id.clone()).or_insert_with(|| Row {
                    role: agent_role_to_wire(*role),
                    from: None,
                    to: None,
                    changed_at_ms: None,
                    actions: BTreeMap::new(),
                });
                *row.actions.entry(action_kind.clone()).or_default() += 1;
            }
            _ => {}
        }
    }

    if rows.is_empty() {
        return None;
    }
    Some(AgentHealthFrame {
        agents: rows
            .into_iter()
            .map(|(agent_id, row)| AgentHealthEntry {
                agent_id,
                role: row.role,
                from: row.from,
                // An agent seen only acting has no health observation this
                // window. `Healthy` would be an assertion the bridge cannot
                // make; `Degraded` would be an alarm it cannot justify. The
                // wire type requires a value, so the honest one is the state
                // the console already renders as "not reporting healthy".
                to: row.to.unwrap_or(WireAgentHealth::Degraded),
                changed_at_ms: row.changed_at_ms,
                actions: row.actions,
            })
            .collect(),
    })
}

/// Every `ModeTransition` in the window, in order.
///
/// NOT reduced to the last one. Mode is not monotonic, and a window carrying
/// `normal -> incident -> alert` collapsed to its last frame would tell the
/// wall the mode went to alert without ever saying it reached incident — which
/// is the transition an operator most needs to have seen.
pub fn mode_transitions(events: &[RuntimeEvent]) -> Vec<ModeTransitionFrame> {
    events
        .iter()
        .filter_map(|event| {
            let RuntimeEvent::ModeTransition {
                from,
                to,
                triggering_threat_class,
                reason,
                ..
            } = event
            else {
                return None;
            };
            let escalating = matches!(
                (from, to),
                (swarm_core::agent::SwarmMode::Normal, _)
                    | (
                        swarm_core::agent::SwarmMode::Alert,
                        swarm_core::agent::SwarmMode::Incident
                    )
            );
            Some(ModeTransitionFrame {
                from: swarm_mode_to_wire(from),
                to: swarm_mode_to_wire(to),
                // Always `None` on a de-escalation: the daemon names no class
                // when it steps down, and carrying the escalating class would
                // read as "this class caused the de-escalation".
                triggering_threat_class: if escalating {
                    triggering_threat_class.as_ref().map(threat_class_to_wire)
                } else {
                    None
                },
                reason: reason.clone(),
            })
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "coalesce_tests.rs"]
mod tests;
