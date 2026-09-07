//! The stealth budget: a deterministic post-plan cap on red's own excess (ATKSCORE-02, SC 2).
//!
//! The 288 planner proposes as many steps as its six operators produce, up
//! to the campaign's `max_steps` -- but nothing in it stops a genome from
//! buying fitness with sheer volume: hammering one technique until a
//! detector's signature is a certainty, sprawling across every host in the
//! graph, or replaying far more events in one generation than any real
//! operator would risk in the field. [`StealthBudget`] is the pass that runs
//! *after* the planner and bounds a finished plan's steps against three
//! independent caps, so `AttackScorer::score`'s `stealth` factor (Task 4)
//! rewards genuine evasion rather than noise.
//!
//! [`StealthBudget::apply`] never reorders or rewrites a step's payload --
//! it only decides how much of the plan's tail to keep, and binds each
//! surviving step's `host_slot` ([`GeneStep`]'s doc notes the 288 planner
//! leaves it at the placeholder `0`). It is a pure function of
//! `(steps, budget)`: no RNG draw, no wall clock, no I/O, and nothing that
//! reaches response authority -- this module has no adapter, no
//! broadcaster, and no dependency on the response crate.
//!
//! # Truncation
//!
//! Steps are walked in their final-plan order, each admitted only if, after
//! it, all three caps still hold:
//!
//!   - `max_events_per_generation` bounds the running sum of admitted steps'
//!     `event_indices.len()`;
//!   - `max_technique_repeats` bounds how many admitted steps may name the
//!     same `technique`;
//!   - `max_distinct_hosts` bounds how many distinct host slots the plan may
//!     bind (see "Host binding" below).
//!
//! The **first** step that would breach any cap stops admission outright:
//! that step and every step after it are dropped, so the surviving plan is
//! always a contiguous prefix of the original order, never a step removed
//! from the middle. This mirrors the 288 planner's own tail-skip semantics
//! and keeps the result trivial to reason about: a caller can always find
//! the truncation point by comparing lengths.
//!
//! # Host binding
//!
//! A step's `host_slot` is derived from its `technique`, never drawn or
//! looked up against any host inventory: the first admitted step to name a
//! given technique claims the next unused slot (`0`, then `1`, ...); every
//! later step naming that *same* technique reuses it. The narrative this
//! encodes is that repeating a technique is what an operator does *from* a
//! host they already hold, while a technique they have not used yet models
//! pivoting to a new foothold -- so `max_distinct_hosts` bounds how many
//! distinct footholds the plan spans, a different question from
//! `max_technique_repeats`'s "how hard does it hammer any one of them".
//!
//! A technique is only ever handed a slot while doing so keeps the
//! distinct-host count at or under `max_distinct_hosts`; a step whose
//! technique has not been seen before, arriving once the cap is already
//! saturated, breaches the host cap and truncates exactly like the other two
//! caps. Because a slot is only ever assigned while under the cap, the
//! assigned value itself can never reach `max_distinct_hosts` -- binding
//! cannot breach the cap it is measured against.
//!
//! # Stealth
//!
//! `stealth` is `admitted_events / proposed_events` -- the share of the
//! plan's proposed event volume that survived the budget -- clamped into
//! `(0.0, 1.0]`. A plan nothing was dropped from has `admitted == proposed`,
//! so `stealth` is exactly `1.0`; a heavily truncated plan approaches `0.0`
//! but is floored at [`MIN_STEALTH`] rather than allowed to reach it exactly,
//! because `AttackScorer::score` (Task 4) multiplies `evasion_rate` by this
//! factor -- an exact `0.0` would zero out `red_fitness` regardless of
//! `evasion_rate`, erasing the evasion signal a truncated-but-otherwise
//! -evasive plan still carries. An input with no proposed events at all
//! (`steps` is empty) has nothing to have been truncated from, so it is
//! defined as fully stealthy (`1.0`) rather than a `0.0 / 0.0`.

use super::genome::GeneStep;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The floor `stealth` is clamped to so a maximally truncated plan still
/// carries a strictly positive, if minimal, signal forward -- see the
/// module doc's "Stealth" section for why an exact `0.0` is unusable.
const MIN_STEALTH: f64 = 1e-6;

/// Deterministic caps a finished plan's steps must fit within before they
/// count toward red's fitness (ATKSCORE-02).
///
/// All three caps are independent -- a plan can breach any one of them
/// without regard to the other two -- and [`StealthBudget::apply`] enforces
/// all three in a single pass. See the module doc for the exact admission
/// rule and the host-binding narrative.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct StealthBudget {
    /// Ceiling on the running sum of admitted steps' `event_indices.len()`.
    pub max_events_per_generation: u32,
    /// Ceiling on how many distinct host slots the plan may bind (see the
    /// module doc's "Host binding" section).
    pub max_distinct_hosts: u8,
    /// Ceiling on how many admitted steps may name the same `technique`.
    pub max_technique_repeats: u8,
}

impl StealthBudget {
    /// Bounds generous enough that the 288 planner's default campaign
    /// (`CampaignParams::DEFAULT_MAX_STEPS` steps, currently `24`) always
    /// passes through [`StealthBudget::apply`] untruncated, so SC 1's
    /// unbudgeted fixtures stay unbudgeted and a *tighter* budget built by a
    /// test or a caller is what actually drives truncation.
    ///
    /// `max_distinct_hosts` and `max_technique_repeats` are set to that same
    /// `24`: neither the number of distinct techniques nor the repeat count
    /// of any single technique in a plan can ever exceed the plan's own step
    /// count, so this is not merely generous headroom but a bound that holds
    /// for *any* 24-step plan regardless of its technique distribution.
    /// `max_events_per_generation` cannot be pinned down quite as tightly --
    /// nothing bounds how many events one scenario may carry -- so it is set
    /// from the corpus instead: the largest catalogued scenario currently
    /// carries 10 events, and `24 * 10 == 240` is comfortably under `1_000`.
    ///
    /// If the planner's default step budget grows, this constant should grow
    /// with it.
    pub const DEFAULT: StealthBudget = StealthBudget {
        max_events_per_generation: 1_000,
        max_distinct_hosts: 24,
        max_technique_repeats: 24,
    };

    /// Bounds `steps` against this budget (ATKSCORE-02).
    ///
    /// Pure and deterministic: identical `(steps, self)` always produces a
    /// [`BudgetOutcome`] with identical `steps` -- including an identical
    /// truncation point and identical `host_slot` bindings. See the module
    /// doc for the admission rule, the host-binding rule, and the `stealth`
    /// formula this computes.
    pub fn apply(&self, steps: Vec<GeneStep>) -> BudgetOutcome {
        let proposed_events = steps
            .iter()
            .map(proposed_event_count)
            .fold(0u32, |total, count| total.saturating_add(count));

        let mut admitted = Vec::with_capacity(steps.len());
        let mut emitted_events: u32 = 0;
        let mut technique_repeats: BTreeMap<String, u32> = BTreeMap::new();
        let mut host_slots: BTreeMap<String, u8> = BTreeMap::new();
        let mut truncated = false;

        for mut candidate in steps {
            let candidate_events = proposed_event_count(&candidate);
            let prospective_events = emitted_events.saturating_add(candidate_events);

            let prior_repeats = technique_repeats
                .get(&candidate.technique)
                .copied()
                .unwrap_or(0);
            let prospective_repeats = prior_repeats.saturating_add(1);

            let existing_slot = host_slots.get(&candidate.technique).copied();
            let prospective_hosts = match existing_slot {
                Some(_) => host_slots.len(),
                None => host_slots.len().saturating_add(1),
            };

            let breaches_events = prospective_events > self.max_events_per_generation;
            let breaches_repeats = prospective_repeats > u32::from(self.max_technique_repeats);
            let breaches_hosts = prospective_hosts > usize::from(self.max_distinct_hosts);
            if breaches_events || breaches_repeats || breaches_hosts {
                truncated = true;
                break;
            }

            let host_slot = match existing_slot {
                Some(slot) => slot,
                None => {
                    // `prospective_hosts <= max_distinct_hosts as usize` was
                    // just checked above, so `host_slots.len()` -- this
                    // technique's new slot, before it is inserted -- is
                    // strictly less than `max_distinct_hosts`, which fits in
                    // a `u8`: the cast below cannot lose a real value.
                    let slot = host_slots.len() as u8;
                    host_slots.insert(candidate.technique.clone(), slot);
                    slot
                }
            };

            emitted_events = prospective_events;
            technique_repeats.insert(candidate.technique.clone(), prospective_repeats);
            candidate.host_slot = host_slot;
            admitted.push(candidate);
        }

        let stealth = if proposed_events == 0 {
            // Nothing was proposed, so nothing could have been truncated --
            // the same vacuous "fully stealthy" case as an untouched budget,
            // not a `0.0 / 0.0`.
            1.0
        } else {
            (f64::from(emitted_events) / f64::from(proposed_events)).clamp(MIN_STEALTH, 1.0)
        };

        BudgetOutcome {
            steps: admitted,
            events_emitted: emitted_events,
            stealth,
            truncated,
        }
    }
}

/// The result of running one plan's steps through a [`StealthBudget`]
/// (ATKSCORE-02).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct BudgetOutcome {
    /// The admitted steps, in their original order, with `host_slot` bound.
    /// A contiguous prefix of the input -- see the module doc's "Truncation"
    /// section for why it can never be anything else.
    pub steps: Vec<GeneStep>,
    /// The sum of `event_indices.len()` over `steps` -- always
    /// `<= budget.max_events_per_generation`.
    pub events_emitted: u32,
    /// The budget-headroom factor `AttackScorer::score` (Task 4) multiplies
    /// `evasion_rate` by. `1.0` when nothing was truncated; otherwise a
    /// value in `(0.0, 1.0)` -- see the module doc's "Stealth" section for
    /// the exact formula.
    pub stealth: f64,
    /// Whether any step of the input was dropped.
    pub truncated: bool,
}

/// The number of telemetry events one step would contribute if admitted.
///
/// `event_indices.len()` is a `usize`; on the practically unreachable chance
/// it exceeds `u32::MAX`, this saturates instead of silently wrapping, so an
/// absurdly large step forces a budget breach rather than being undercounted
/// into a false admission.
fn proposed_event_count(step: &GeneStep) -> u32 {
    u32::try_from(step.event_indices.len()).unwrap_or(u32::MAX)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::super::genome::{OperatorRole, StepIntent};
    use super::super::graph::ScenarioRef;
    use super::*;
    use swarm_core::pheromone::ThreatClass;

    /// A step naming `technique`, carrying `event_count` synthetic event
    /// indices and an otherwise fixed, arbitrary payload -- these tests only
    /// exercise `technique` and `event_indices`, mirroring the fixture style
    /// `scoring.rs`'s tests use for the same reason.
    fn step(technique: &str, event_count: usize) -> GeneStep {
        GeneStep {
            operator: OperatorRole::Recon,
            technique: technique.to_string(),
            threat_class: ThreatClass::Execution,
            scenario: ScenarioRef {
                suite: "test-suite".to_string(),
                scenario: format!("{technique}_scenario"),
                event_count,
            },
            event_indices: (0..event_count).collect(),
            host_slot: 0,
            offset_ms: 0,
            intent: StepIntent::Probe,
        }
    }

    /// `n` steps naming distinct techniques `T0..T{n-1}`, each carrying
    /// `events_per_step` events -- for tests that want several unrelated
    /// techniques without spelling each one out.
    fn distinct_steps(n: usize, events_per_step: usize) -> Vec<GeneStep> {
        (0..n)
            .map(|index| step(&format!("T{index}"), events_per_step))
            .collect()
    }

    #[test]
    fn a_plan_over_the_event_cap_truncates_to_the_exact_prefix_that_fits() {
        let steps = distinct_steps(5, 3); // 15 proposed events total
        let budget = StealthBudget {
            max_events_per_generation: 7,
            max_distinct_hosts: 10,
            max_technique_repeats: 10,
        };

        let outcome = budget.apply(steps.clone());

        assert!(outcome.truncated);
        assert!(outcome.events_emitted <= budget.max_events_per_generation);
        assert_eq!(outcome.events_emitted, 6);
        assert_eq!(outcome.steps.len(), 2);
        assert_eq!(outcome.steps[0].technique, steps[0].technique);
        assert_eq!(outcome.steps[1].technique, steps[1].technique);
    }

    #[test]
    fn a_repeated_apply_call_produces_identical_output_for_identical_input() {
        let steps = distinct_steps(6, 4);
        let budget = StealthBudget {
            max_events_per_generation: 10,
            max_distinct_hosts: 2,
            max_technique_repeats: 10,
        };

        let first = budget.apply(steps.clone());
        let second = budget.apply(steps);

        assert_eq!(first.steps, second.steps);
        assert_eq!(first.events_emitted, second.events_emitted);
        assert_eq!(first.truncated, second.truncated);
        assert_eq!(first.stealth, second.stealth);
    }

    #[test]
    fn a_technique_repeated_past_its_cap_truncates_at_the_repeat() {
        let steps: Vec<GeneStep> = (0..5).map(|_| step("T1", 1)).collect();
        let budget = StealthBudget {
            max_events_per_generation: 100,
            max_distinct_hosts: 100,
            max_technique_repeats: 3,
        };

        let outcome = budget.apply(steps);

        assert!(outcome.truncated);
        assert_eq!(outcome.steps.len(), 3);
        assert!(
            outcome
                .steps
                .iter()
                .all(|admitted| admitted.technique == "T1")
        );
    }

    #[test]
    fn a_plan_that_would_touch_too_many_hosts_truncates_at_the_new_host() {
        let steps = distinct_steps(4, 1);
        let budget = StealthBudget {
            max_events_per_generation: 100,
            max_distinct_hosts: 2,
            max_technique_repeats: 100,
        };

        let outcome = budget.apply(steps);

        assert!(outcome.truncated);
        assert_eq!(outcome.steps.len(), 2);
        assert_eq!(outcome.steps[0].technique, "T0");
        assert_eq!(outcome.steps[1].technique, "T1");
    }

    #[test]
    fn a_repeated_technique_reuses_its_host_slot_while_staying_in_bounds() {
        let steps = vec![
            step("T1", 1),
            step("T2", 1),
            step("T1", 1),
            step("T3", 1),
            step("T2", 1),
            step("T4", 1),
        ];
        let budget = StealthBudget {
            max_events_per_generation: 100,
            max_distinct_hosts: 3,
            max_technique_repeats: 100,
        };

        let outcome = budget.apply(steps.clone());

        assert!(outcome.truncated); // T4 is the 4th distinct technique
        assert_eq!(outcome.steps.len(), 5);
        let slots: Vec<u8> = outcome
            .steps
            .iter()
            .map(|admitted| admitted.host_slot)
            .collect();
        assert_eq!(slots, vec![0, 1, 0, 2, 1]);
        assert!(slots.iter().all(|slot| *slot < budget.max_distinct_hosts));

        let repeat = budget.apply(steps);
        let repeat_slots: Vec<u8> = repeat
            .steps
            .iter()
            .map(|admitted| admitted.host_slot)
            .collect();
        assert_eq!(repeat_slots, slots);
    }

    #[test]
    fn the_default_budget_admits_a_full_twenty_four_step_campaign_untruncated() {
        let steps = distinct_steps(24, 10);

        let outcome = StealthBudget::DEFAULT.apply(steps);

        assert!(!outcome.truncated);
        assert_eq!(outcome.steps.len(), 24);
        assert_eq!(outcome.events_emitted, 240);
        assert_eq!(outcome.stealth, 1.0);
    }

    #[test]
    fn stealth_is_one_when_nothing_is_truncated() {
        let steps = distinct_steps(3, 2);
        let budget = StealthBudget {
            max_events_per_generation: 100,
            max_distinct_hosts: 10,
            max_technique_repeats: 10,
        };

        let outcome = budget.apply(steps);

        assert!(!outcome.truncated);
        assert_eq!(outcome.stealth, 1.0);
    }

    #[test]
    fn stealth_is_strictly_between_zero_and_one_when_some_steps_are_dropped() {
        let steps = distinct_steps(5, 3);
        let budget = StealthBudget {
            max_events_per_generation: 7,
            max_distinct_hosts: 10,
            max_technique_repeats: 10,
        };

        let outcome = budget.apply(steps);

        assert!(outcome.truncated);
        assert!(outcome.stealth > 0.0);
        assert!(outcome.stealth < 1.0);
    }

    #[test]
    fn stealth_stays_positive_when_the_entire_plan_is_dropped() {
        let steps = distinct_steps(3, 5);
        let budget = StealthBudget {
            max_events_per_generation: 0,
            max_distinct_hosts: 10,
            max_technique_repeats: 10,
        };

        let outcome = budget.apply(steps);

        assert!(outcome.truncated);
        assert_eq!(outcome.steps.len(), 0);
        assert_eq!(outcome.events_emitted, 0);
        assert!(outcome.stealth > 0.0);
    }

    #[test]
    fn an_empty_plan_is_untruncated_and_fully_stealthy() {
        let outcome = StealthBudget::DEFAULT.apply(Vec::new());

        assert!(!outcome.truncated);
        assert!(outcome.steps.is_empty());
        assert_eq!(outcome.events_emitted, 0);
        assert_eq!(outcome.stealth, 1.0);
    }

    #[test]
    fn a_plan_admits_every_step_when_its_total_events_equal_the_cap_exactly() {
        let steps = distinct_steps(4, 2); // 8 proposed events total
        let budget = StealthBudget {
            max_events_per_generation: 8,
            max_distinct_hosts: 10,
            max_technique_repeats: 10,
        };

        let outcome = budget.apply(steps);

        assert!(!outcome.truncated);
        assert_eq!(outcome.steps.len(), 4);
        assert_eq!(outcome.events_emitted, 8);
        assert_eq!(outcome.stealth, 1.0);
    }

    #[test]
    fn a_plan_truncates_at_the_step_that_would_cross_the_event_cap() {
        // Same plan as the exact-boundary test above, but the cap is one
        // event short of the plan's total: the running sum after each step
        // is 2, 4, 6, 8, so the fourth step is the first to cross a cap of
        // 7, and it alone -- not a partial step -- is dropped.
        let steps = distinct_steps(4, 2); // 8 proposed events total
        let budget = StealthBudget {
            max_events_per_generation: 7,
            max_distinct_hosts: 10,
            max_technique_repeats: 10,
        };

        let outcome = budget.apply(steps);

        assert!(outcome.truncated);
        assert_eq!(outcome.steps.len(), 3);
        assert_eq!(outcome.events_emitted, 6);
    }

    #[test]
    fn a_budget_admits_nothing_when_max_distinct_hosts_is_zero() {
        let steps = distinct_steps(3, 1);
        let budget = StealthBudget {
            max_events_per_generation: 100,
            max_distinct_hosts: 0,
            max_technique_repeats: 100,
        };

        // Must not panic: with no hosts available, the first candidate step
        // breaches the host cap and the loop breaks before it ever reaches
        // the `host_slots.len() as u8` cast.
        let outcome = budget.apply(steps);

        assert!(outcome.truncated);
        assert!(outcome.steps.is_empty());
        assert_eq!(outcome.events_emitted, 0);
    }

    #[test]
    fn a_budget_admits_nothing_when_max_technique_repeats_is_zero() {
        let steps = distinct_steps(3, 1);
        let budget = StealthBudget {
            max_events_per_generation: 100,
            max_distinct_hosts: 100,
            max_technique_repeats: 0,
        };

        let outcome = budget.apply(steps);

        assert!(outcome.truncated);
        assert!(outcome.steps.is_empty());
        assert_eq!(outcome.events_emitted, 0);
    }

    #[test]
    fn a_budget_admits_nothing_when_max_events_per_generation_is_zero() {
        let steps = distinct_steps(3, 1);
        let budget = StealthBudget {
            max_events_per_generation: 0,
            max_distinct_hosts: 100,
            max_technique_repeats: 100,
        };

        let outcome = budget.apply(steps);

        assert!(outcome.truncated);
        assert!(outcome.steps.is_empty());
        assert_eq!(outcome.events_emitted, 0);
    }
}
