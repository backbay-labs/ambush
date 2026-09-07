//! [`TechniqueWeights`]: per-technique selection weights for
//! [`super::genome::RedGenome::plan_weighted`] (COEVOLVE-01's read side of
//! Phase 289's memory).
//!
//! [`super::pattern_db::AttackPatternDb`] remembers, per technique, what share
//! of its recorded steps evaded detection
//! ([`super::pattern_db::AttackPatternDb::technique_success_rate`]). This
//! module turns that history into the one artifact the weighted planner
//! needs: a snapshot of those rates over the techniques one
//! [`super::graph::TargetGraph`] actually carries, taken once per generation
//! rather than re-queried per draw, so a plan's bytes depend only on the
//! snapshot it was built with -- never on when during planning the db
//! happened to be read.
//!
//! `BTreeMap`, never `HashMap`: the weighted draw
//! ([`super::operators::choose_distinct`]) is part of the red lane's
//! reproducibility contract (SC 2), so nothing that feeds it may iterate in
//! hash order.

use super::graph::TargetGraph;
use super::pattern_db::AttackPatternDb;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A snapshot of technique -> success-rate weights, read once from an
/// [`AttackPatternDb`] over a [`TargetGraph`]'s own techniques.
///
/// The weight is exactly [`AttackPatternDb::technique_success_rate`]'s
/// number for that technique -- the share of recorded observations that
/// evaded detection, `1.0` for a technique the db has never seen -- copied at
/// construction time rather than re-derived some other way, so
/// [`Self::weight_for`] never disagrees with the db it was snapshotted from.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TechniqueWeights(BTreeMap<String, f64>);

impl TechniqueWeights {
    /// Snapshot `db`'s success rate for every technique `graph` carries.
    ///
    /// Scoped to the graph's own techniques -- rather than every technique
    /// `db` has ever recorded -- so the snapshot never outgrows the plan it
    /// will bias and never carries a technique a step could not reference
    /// anyway. Deterministic: `graph.techniques()` iterates a `BTreeMap` in
    /// id order and `db`'s rate is a pure count over its own records, so two
    /// snapshots built from equal `(db, graph)` are equal.
    pub fn from_pattern_db(db: &AttackPatternDb, graph: &TargetGraph) -> Self {
        let mut weights = BTreeMap::new();
        for node in graph.techniques() {
            weights.insert(node.id.clone(), db.technique_success_rate(&node.id));
        }
        Self(weights)
    }

    /// The weight for `technique`: its snapshotted success rate, or `1.0` --
    /// neutral, the same optimistic value
    /// [`AttackPatternDb::technique_success_rate`] gives an unrecorded
    /// technique -- when `technique` is absent from this snapshot. Absence
    /// is never a penalty, only "no opinion".
    pub fn weight_for(&self, technique: &str) -> f64 {
        self.0.get(technique).copied().unwrap_or(1.0)
    }
}

#[cfg(test)]
impl TechniqueWeights {
    /// Test-only constructor: build a snapshot directly from `(technique,
    /// weight)` pairs, without needing an [`AttackPatternDb`] or a
    /// [`TargetGraph`]. Used by tests (in this module and in
    /// [`super::operators`]) that want to hand the weighted draw a specific,
    /// hand-picked weight map rather than assembling one through the real
    /// constructor.
    pub(crate) fn for_test<I, K>(pairs: I) -> Self
    where
        I: IntoIterator<Item = (K, f64)>,
        K: Into<String>,
    {
        Self(pairs.into_iter().map(|(k, v)| (k.into(), v)).collect())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::evasion_coverage::{
        EvasionTechniqueCatalog, EvasionTechniqueCatalogDetector, EvasionTechniqueGap,
    };
    use crate::red_swarm::graph::LoadedSuite;
    use crate::red_swarm::pattern_db::AttackPatternRecord;
    use swarm_core::pheromone::ThreatClass;

    /// A graph carrying exactly one technique node, `T1000`, and no suites --
    /// enough for [`TechniqueWeights::from_pattern_db`], which reads node ids
    /// off the graph and never touches a scenario.
    fn one_technique_graph() -> TargetGraph {
        let catalog = EvasionTechniqueCatalog {
            schema_version: 1,
            suite: "scenario-suites/synthetic.yaml".to_string(),
            detectors: vec![EvasionTechniqueCatalogDetector {
                detector: "det".to_string(),
                intentionally_uncovered: vec![EvasionTechniqueGap {
                    technique: "T1000".to_string(),
                    threat_class: ThreatClass::Discovery,
                    rationale: "synthetic".to_string(),
                }],
            }],
        };
        let suites: Vec<LoadedSuite> = Vec::new();
        TargetGraph::from_parts(&catalog, &suites)
    }

    #[test]
    fn a_technique_with_no_recorded_history_gets_the_neutral_weight() {
        let graph = one_technique_graph();
        let db = AttackPatternDb::default();

        let weights = TechniqueWeights::from_pattern_db(&db, &graph);

        assert_eq!(weights.weight_for("T1000"), 1.0);
    }

    #[test]
    fn a_recorded_technique_gets_its_exact_success_rate() {
        let graph = one_technique_graph();
        let mut db = AttackPatternDb::default();
        db.append(AttackPatternRecord {
            generation: 0,
            technique: "T1000".to_string(),
            detector: "det".to_string(),
            detected: true,
        });
        db.append(AttackPatternRecord {
            generation: 1,
            technique: "T1000".to_string(),
            detector: "det".to_string(),
            detected: false,
        });

        let weights = TechniqueWeights::from_pattern_db(&db, &graph);

        assert_eq!(
            weights.weight_for("T1000"),
            db.technique_success_rate("T1000")
        );
        assert_eq!(weights.weight_for("T1000"), 0.5);
    }

    #[test]
    fn a_technique_absent_from_the_snapshot_is_neutral_not_penalised() {
        let graph = one_technique_graph();
        let db = AttackPatternDb::default();

        let weights = TechniqueWeights::from_pattern_db(&db, &graph);

        assert_eq!(weights.weight_for("T-not-in-graph-or-db"), 1.0);
    }

    #[test]
    fn two_snapshots_built_from_equal_inputs_are_equal() {
        let graph = one_technique_graph();
        let mut db = AttackPatternDb::default();
        db.append(AttackPatternRecord {
            generation: 0,
            technique: "T1000".to_string(),
            detector: "det".to_string(),
            detected: false,
        });

        let first = TechniqueWeights::from_pattern_db(&db, &graph);
        let second = TechniqueWeights::from_pattern_db(&db, &graph);

        assert_eq!(first, second);
    }
}
