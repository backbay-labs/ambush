//! The red swarm's target graph (OPFOR-02).
//!
//! The red lane recombines catalogued techniques rather than inventing payload
//! shapes, so it needs a bounded, explicit model of what "catalogued" means.
//! The `TargetGraph` is that model: the fixed world an operator is allowed to
//! plan within. Its nodes are the eleven detectors the evasion catalog scores,
//! the techniques those detectors declare intentionally uncovered together with
//! every technique the tracked adversarial scenarios declare, and the threat
//! classes that appear on either. A technique node carries its own edges --
//! the classes it belongs to, the scenarios whose events realise it, and the
//! detectors that named it a gap -- so a later planner never has to reconstruct
//! them.
//!
//! The graph is built from the same files the coverage evaluator reads
//! (`rulesets/evasion/attack-technique-catalog.yaml` and the suites under
//! `scenario-suites/`) through the same loaders, so the red lane and the blue
//! lane cannot disagree about what the corpus contains. A scenario that omits
//! an explicit `metadata.threat_class` is classified exactly as
//! `evasion_coverage::load_adversarial_scenarios` classifies it -- by its first
//! event's payload -- rather than by a second rule that could drift.
//!
//! The graph exposes a 32-byte `fingerprint` over its canonical JSON so a plan
//! can name the precise graph it was planned against; two graphs built from the
//! same corpus fingerprint identically, and adding a single technique changes
//! every byte that follows it in the digest.

use super::RedSwarmError;
use crate::evasion_coverage::{
    EvasionTechniqueCatalog, parse_evasion_technique_catalog, threat_class_from_payload,
};
use crate::replay::{
    LoadedReplayScenario, ReplayScenarioClass, ReplayScenarioInput, load_replay_suite_manifest,
    load_scenario_manifest, resolve_manifest_relative_path,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use swarm_core::pheromone::ThreatClass;

/// A node in the target graph, named the three ways OPFOR-02 requires: a
/// detector the catalog scores, a technique the corpus contains, or a threat
/// class that appears on either. The rich per-technique record lives in
/// [`TechniqueNode`]; this enum is the lightweight way to enumerate the graph's
/// vertices.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Node {
    /// One of the eleven catalogued detectors, by its stable id.
    Detector(String),
    /// A technique the corpus declares, by its ATT&CK-style id.
    Technique(String),
    /// A threat class that appears on a catalog gap or an adversarial scenario.
    ThreatClass(ThreatClass),
}

/// A reference from a technique to one scenario that realises it, and how many
/// of that scenario's events are available. Phase 289 binds these events to
/// hosts and timestamps; here the reference is enough for a planner to know the
/// technique has real material behind it and where to find it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ScenarioRef {
    /// The suite that includes the scenario (a scenario shared by two suites is
    /// referenced once per suite, so the reference is never ambiguous).
    pub suite: String,
    /// The scenario's own name, as declared in its manifest.
    pub scenario: String,
    /// The number of events the scenario contributes, in manifest order.
    pub event_count: usize,
}

/// A technique node and its edges. The technique belongs to one or more threat
/// classes, is realised by zero or more scenarios, and may have been declared
/// intentionally uncovered by one or more detectors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TechniqueNode {
    /// The technique's ATT&CK-style id, e.g. `T1059.001`.
    pub id: String,
    /// Every threat class the technique belongs to, from catalog gaps and from
    /// the scenarios that declare it. Never empty for a graph built from the
    /// repository corpus.
    pub threat_classes: BTreeSet<ThreatClass>,
    /// Every scenario that realises the technique, sorted so the node's identity
    /// does not depend on suite iteration order.
    pub scenarios: Vec<ScenarioRef>,
    /// The detectors that declared this technique intentionally uncovered, if
    /// any, sorted for the same reason.
    pub declared_uncovered_by: Vec<String>,
}

impl TechniqueNode {
    fn new(id: &str) -> Self {
        Self {
            id: id.to_string(),
            threat_classes: BTreeSet::new(),
            scenarios: Vec::new(),
            declared_uncovered_by: Vec::new(),
        }
    }
}

/// A replay suite loaded far enough for the target graph: its declared name and
/// every scenario manifest it references, in suite order. [`TargetGraph::from_repo`]
/// builds these from disk; tests build them directly so the graph can be
/// exercised without a repository tree.
#[derive(Debug, Clone)]
pub struct LoadedSuite {
    /// The suite's name, as declared in its manifest.
    pub name: String,
    /// Every scenario the suite references, loaded, in the order listed.
    pub scenarios: Vec<LoadedReplayScenario>,
}

impl LoadedSuite {
    fn from_path(suite_path: &Path) -> Result<Self, RedSwarmError> {
        let manifest = load_replay_suite_manifest(suite_path)?;
        let mut scenarios = Vec::with_capacity(manifest.scenarios.len());
        for scenario_ref in &manifest.scenarios {
            let scenario_path = resolve_manifest_relative_path(suite_path, scenario_ref);
            scenarios.push(load_scenario_manifest(&scenario_path)?);
        }
        Ok(Self {
            name: manifest.name,
            scenarios,
        })
    }
}

/// The bounded world the red operators plan within (OPFOR-02).
///
/// Stored as three collections whose orderings are canonical: detectors in
/// catalog order (which is meaningful), techniques keyed by id in a
/// `BTreeMap`, and threat classes in a `BTreeSet`. That canonical form is what
/// makes [`TargetGraph::fingerprint`] a stable name for the graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetGraph {
    detectors: Vec<String>,
    techniques: BTreeMap<String, TechniqueNode>,
    threat_classes: BTreeSet<ThreatClass>,
}

impl TargetGraph {
    /// Build the graph from the repository: the evasion technique catalog and a
    /// set of replay suites. The catalog is read through `evasion_coverage`'s
    /// parser and the suites through the replay loaders, so no file is parsed by
    /// a schema this module owns.
    pub fn from_repo(catalog_path: &Path, suite_paths: &[PathBuf]) -> Result<Self, RedSwarmError> {
        let catalog = parse_evasion_technique_catalog(catalog_path)?;
        let mut suites = Vec::with_capacity(suite_paths.len());
        for suite_path in suite_paths {
            suites.push(LoadedSuite::from_path(suite_path)?);
        }
        Ok(Self::from_parts(&catalog, &suites))
    }

    /// Build the graph from already-loaded parts. This is the whole of the
    /// construction logic; [`TargetGraph::from_repo`] only supplies the parts.
    ///
    /// Techniques come from two sources, unioned: every technique a catalog
    /// detector declares intentionally uncovered, and every technique an
    /// adversarial scenario declares. Benign scenarios are not adversary
    /// material and so are not sources of events; they contribute nothing the
    /// adversarial scenarios and catalog do not already carry. A catalog gap
    /// contributes its detector and its threat class to the technique; a
    /// scenario contributes a scenario reference and its own threat class.
    pub fn from_parts(catalog: &EvasionTechniqueCatalog, suites: &[LoadedSuite]) -> Self {
        let detectors = catalog
            .detectors
            .iter()
            .map(|detector| detector.detector.clone())
            .collect();

        let mut techniques: BTreeMap<String, TechniqueNode> = BTreeMap::new();
        let mut threat_classes: BTreeSet<ThreatClass> = BTreeSet::new();

        for detector in &catalog.detectors {
            for gap in &detector.intentionally_uncovered {
                let node = techniques
                    .entry(gap.technique.clone())
                    .or_insert_with(|| TechniqueNode::new(&gap.technique));
                node.threat_classes.insert(gap.threat_class.clone());
                if !node
                    .declared_uncovered_by
                    .iter()
                    .any(|declared| declared == &detector.detector)
                {
                    node.declared_uncovered_by.push(detector.detector.clone());
                }
                threat_classes.insert(gap.threat_class.clone());
            }
        }

        for suite in suites {
            for scenario in &suite.scenarios {
                if scenario.manifest.metadata.class != ReplayScenarioClass::Adversarial {
                    continue;
                }
                let class = scenario_threat_class(scenario);
                if let Some(class) = &class {
                    threat_classes.insert(class.clone());
                }
                let scenario_ref = ScenarioRef {
                    suite: suite.name.clone(),
                    scenario: scenario.manifest.name.clone(),
                    event_count: scenario_event_count(scenario),
                };
                for technique in &scenario.manifest.metadata.techniques {
                    let node = techniques
                        .entry(technique.clone())
                        .or_insert_with(|| TechniqueNode::new(technique));
                    if let Some(class) = &class {
                        node.threat_classes.insert(class.clone());
                    }
                    node.scenarios.push(scenario_ref.clone());
                }
            }
        }

        // Canonicalise the orderings that carry no meaning, so a graph's
        // identity -- and its fingerprint -- depends on its content and not on
        // the order suites were passed in.
        for node in techniques.values_mut() {
            node.scenarios.sort();
            node.declared_uncovered_by.sort();
        }

        Self {
            detectors,
            techniques,
            threat_classes,
        }
    }

    /// The eleven catalogued detectors, in catalog order.
    pub fn detectors(&self) -> &[String] {
        &self.detectors
    }

    /// Every technique node, ordered by id.
    pub fn techniques(&self) -> impl Iterator<Item = &TechniqueNode> {
        self.techniques.values()
    }

    /// The technique node with the given id, if the graph contains it.
    pub fn technique(&self, id: &str) -> Option<&TechniqueNode> {
        self.techniques.get(id)
    }

    /// Whether the graph contains a technique with the given id. A planner asks
    /// this to prove a step names a real technique before it emits it (OPFOR-04).
    pub fn is_technique(&self, id: &str) -> bool {
        self.techniques.contains_key(id)
    }

    /// Every threat class that appears on a catalog gap or an adversarial
    /// scenario, in sorted order.
    pub fn threat_classes(&self) -> impl Iterator<Item = &ThreatClass> {
        self.threat_classes.iter()
    }

    /// Every technique that belongs to the given threat class, ordered by id.
    pub fn techniques_for<'a>(
        &'a self,
        class: &'a ThreatClass,
    ) -> impl Iterator<Item = &'a TechniqueNode> {
        self.techniques
            .values()
            .filter(move |node| node.threat_classes.contains(class))
    }

    /// Every node in the graph, as [`Node`] values: detectors in catalog order,
    /// then techniques by id, then threat classes in sorted order.
    pub fn nodes(&self) -> Vec<Node> {
        let mut nodes = Vec::with_capacity(
            self.detectors.len() + self.techniques.len() + self.threat_classes.len(),
        );
        nodes.extend(self.detectors.iter().cloned().map(Node::Detector));
        nodes.extend(self.techniques.keys().cloned().map(Node::Technique));
        nodes.extend(self.threat_classes.iter().cloned().map(Node::ThreatClass));
        nodes
    }

    /// A 32-byte SHA-256 over the graph's canonical JSON, so a plan can record
    /// the exact graph it was planned against. The canonical form comes from the
    /// `BTreeMap`/`BTreeSet` orderings and the per-node sorting done at build
    /// time; identical corpora fingerprint identically, and one added technique
    /// changes the digest.
    pub fn fingerprint(&self) -> [u8; 32] {
        // serialization of these plain types cannot fail in practice; an empty
        // buffer on the impossible error keeps this total and still deterministic
        // rather than reaching for a panic the runtime contract forbids.
        let canonical = serde_json::to_vec(self).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(&canonical);
        hasher.finalize().into()
    }
}

/// A scenario's threat class: its explicit `metadata.threat_class` when it
/// declares one, otherwise the class implied by its first event's payload. This
/// is the exact fallback `evasion_coverage::load_adversarial_scenarios` uses, so
/// the two lanes classify a scenario the same way.
fn scenario_threat_class(scenario: &LoadedReplayScenario) -> Option<ThreatClass> {
    scenario
        .manifest
        .metadata
        .threat_class
        .clone()
        .or_else(|| match &scenario.manifest.input {
            ReplayScenarioInput::Events { events } => events
                .first()
                .map(|step| threat_class_from_payload(&step.event.payload)),
            ReplayScenarioInput::ReplayBundles { .. } => None,
        })
}

/// How many events a scenario contributes. Replay-bundle scenarios carry no
/// inline events, so they contribute none.
fn scenario_event_count(scenario: &LoadedReplayScenario) -> usize {
    match &scenario.manifest.input {
        ReplayScenarioInput::Events { events } => events.len(),
        ReplayScenarioInput::ReplayBundles { .. } => 0,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::evasion_coverage::{EvasionTechniqueCatalogDetector, EvasionTechniqueGap};
    use crate::replay::{ReplayExpectations, ReplayScenarioManifest, ReplayScenarioMetadata};

    fn repo_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    fn catalog_path() -> PathBuf {
        repo_root().join("rulesets/evasion/attack-technique-catalog.yaml")
    }

    fn suite_paths() -> Vec<PathBuf> {
        [
            "scenario-suites/command-line-deobfuscation-v1.yaml",
            "scenario-suites/evasion-breadth-v1.yaml",
            "scenario-suites/hellcat-office-v1.yaml",
            "scenario-suites/kill-chain-sequences-v1.yaml",
        ]
        .iter()
        .map(|rel| repo_root().join(rel))
        .collect()
    }

    /// The union computed by hand from the loaded corpus, independent of
    /// `TargetGraph`'s own builder. `adversarial_only` mirrors what the graph
    /// does; the full union (including benign scenarios) is used to prove the
    /// two are the same set for this corpus.
    fn union_from_corpus(adversarial_only: bool) -> BTreeSet<String> {
        let catalog = parse_evasion_technique_catalog(&catalog_path()).unwrap();
        let mut techniques = BTreeSet::new();
        for detector in &catalog.detectors {
            for gap in &detector.intentionally_uncovered {
                techniques.insert(gap.technique.clone());
            }
        }
        for suite_path in suite_paths() {
            let manifest = load_replay_suite_manifest(&suite_path).unwrap();
            for scenario_ref in &manifest.scenarios {
                let scenario_path = resolve_manifest_relative_path(&suite_path, scenario_ref);
                let scenario = load_scenario_manifest(&scenario_path).unwrap();
                if adversarial_only
                    && scenario.manifest.metadata.class != ReplayScenarioClass::Adversarial
                {
                    continue;
                }
                for technique in &scenario.manifest.metadata.techniques {
                    techniques.insert(technique.clone());
                }
            }
        }
        techniques
    }

    /// A synthetic loaded scenario, so the fingerprint tests do not depend on
    /// the repository corpus. `class` drives whether the graph includes it, and
    /// an explicit threat class classifies it without needing events, so the
    /// synthetic scenarios carry none and the red lane's tests never name a
    /// response type.
    fn scenario(
        name: &str,
        class: ReplayScenarioClass,
        threat_class: Option<ThreatClass>,
        techniques: &[&str],
    ) -> LoadedReplayScenario {
        LoadedReplayScenario {
            path: PathBuf::from(format!("test/{name}.yaml")),
            manifest: ReplayScenarioManifest {
                name: name.to_string(),
                description: "synthetic".to_string(),
                seed_time_ms: 0,
                requested_by: "test".to_string(),
                receipt_chain: Vec::new(),
                metadata: ReplayScenarioMetadata {
                    class,
                    threat_class,
                    campaign: None,
                    techniques: techniques.iter().map(|t| t.to_string()).collect(),
                    tags: Vec::new(),
                },
                input: ReplayScenarioInput::Events { events: Vec::new() },
                expectations: ReplayExpectations::default(),
            },
        }
    }

    fn gap(technique: &str, threat_class: ThreatClass) -> EvasionTechniqueGap {
        EvasionTechniqueGap {
            technique: technique.to_string(),
            threat_class,
            rationale: "synthetic".to_string(),
        }
    }

    fn detector(name: &str, gaps: Vec<EvasionTechniqueGap>) -> EvasionTechniqueCatalogDetector {
        EvasionTechniqueCatalogDetector {
            detector: name.to_string(),
            intentionally_uncovered: gaps,
        }
    }

    fn small_catalog(detectors: Vec<EvasionTechniqueCatalogDetector>) -> EvasionTechniqueCatalog {
        EvasionTechniqueCatalog {
            schema_version: 1,
            suite: "scenario-suites/synthetic.yaml".to_string(),
            detectors,
        }
    }

    #[test]
    fn the_graph_technique_set_is_the_union_of_catalog_and_suite_techniques() {
        let graph = TargetGraph::from_repo(&catalog_path(), &suite_paths()).unwrap();

        // The technique-node set is exactly the corpus union (SC 1). The graph
        // is built from adversarial scenarios; assert it equals that union and
        // that the union over ALL scenarios is the same set, so benign
        // scenarios are proven to contribute no technique the graph would drop.
        let graph_ids: BTreeSet<String> = graph.techniques().map(|node| node.id.clone()).collect();
        assert_eq!(graph_ids, union_from_corpus(true));
        assert_eq!(union_from_corpus(true), union_from_corpus(false));

        // The detector set is exactly the eleven catalogued detectors in order.
        let expected_detectors = [
            "suspicious_process_tree",
            "fileless_execution",
            "behavioral_anomaly",
            "dns_exfiltration",
            "lateral_movement",
            "credential_access",
            "suspicious_scripting",
            "persistence",
            "supply_chain",
            "network_connect",
            "infrastructure_anomaly",
        ];
        assert_eq!(graph.detectors(), expected_detectors);

        // Every technique carries at least one threat class.
        for node in graph.techniques() {
            assert!(
                !node.threat_classes.is_empty(),
                "technique {} has no threat class",
                node.id
            );
        }

        // T1059.003 appears only in pdf-lolbin-execution, which declares no
        // explicit threat class, so its class must come from that scenario's
        // first (process-start) event: the metadata-or-first-event fallback.
        let t1059_003 = graph
            .technique("T1059.003")
            .expect("T1059.003 is declared by pdf-lolbin-execution");
        assert!(t1059_003.threat_classes.contains(&ThreatClass::Execution));
    }

    #[test]
    fn a_technique_declared_uncovered_names_the_detector_that_declared_it() {
        let graph = TargetGraph::from_repo(&catalog_path(), &suite_paths()).unwrap();

        // T1071.001 is declared intentionally uncovered by two detectors.
        let t1071_001 = graph
            .technique("T1071.001")
            .expect("T1071.001 is a catalogued gap");
        assert!(
            t1071_001
                .declared_uncovered_by
                .contains(&"dns_exfiltration".to_string())
        );
        assert!(
            t1071_001
                .declared_uncovered_by
                .contains(&"network_connect".to_string())
        );

        // A technique that only appears in scenarios names no detector.
        let t1059_001 = graph
            .technique("T1059.001")
            .expect("T1059.001 is declared by several scenarios");
        assert!(t1059_001.declared_uncovered_by.is_empty());

        // A scenario reference records the suite, the scenario, and how many
        // events back it: pdf-lolbin-execution is one process-start event in the
        // hellcat office suite, and it realises T1204.002.
        let t1204_002 = graph
            .technique("T1204.002")
            .expect("T1204.002 is declared by the office scenarios");
        assert!(t1204_002.scenarios.contains(&ScenarioRef {
            suite: "hellcat_office_v1".to_string(),
            scenario: "pdf_lolbin_execution".to_string(),
            event_count: 1,
        }));
    }

    #[test]
    fn the_graph_fingerprint_is_stable_and_changes_with_one_technique() {
        let catalog = small_catalog(vec![detector(
            "suspicious_process_tree",
            vec![gap("T1204.001", ThreatClass::InitialAccess)],
        )]);
        let suites = vec![LoadedSuite {
            name: "synthetic_v1".to_string(),
            scenarios: vec![scenario(
                "exec",
                ReplayScenarioClass::Adversarial,
                Some(ThreatClass::Execution),
                &["T1059.001"],
            )],
        }];

        // Same inputs, twice, fingerprint identically.
        let first = TargetGraph::from_parts(&catalog, &suites);
        let second = TargetGraph::from_parts(&catalog, &suites);
        assert_eq!(first.fingerprint(), second.fingerprint());

        // One added technique changes the fingerprint.
        let mut suites_plus = suites.clone();
        suites_plus.push(LoadedSuite {
            name: "synthetic_v2".to_string(),
            scenarios: vec![scenario(
                "extra",
                ReplayScenarioClass::Adversarial,
                Some(ThreatClass::Persistence),
                &["T1547.001"],
            )],
        });
        let with_extra = TargetGraph::from_parts(&catalog, &suites_plus);
        assert_ne!(first.fingerprint(), with_extra.fingerprint());
    }
}
