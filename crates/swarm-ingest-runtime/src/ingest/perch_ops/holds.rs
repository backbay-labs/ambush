//! B1's interception point, and (Tasks 10 and 13) the hold reads and the decide engine.
//!
//! Owns: turning a `RequireHuman` audit trail into a durable `HeldAction`, and
//! publishing `RuntimeEvent::ResponseHeld`.
//!
//! Does not own: the store (`swarm_runtime::held_action`), the routes
//! (`swarm_runtime_http::http::perch::holds`), or any authorization decision.

use std::sync::Arc;

use swarm_core::config::ResponseHoldSettings;
use swarm_core::types::ResponseRehearsalPreview;
use swarm_policy::{ActionRequest, PolicyDecision, PolicyVerdict};
use swarm_runtime::held_action::{HeldAction, HeldActionStore, HoldState, mint_hold_id};
use swarm_runtime::runtime_events::{RuntimeEvent, RuntimeEventBroadcaster};
use swarm_spine::{AuditResponseRecord, AuditTrail};
use swarm_whisker::DetectionFinding;

use crate::ingest::threat_class_slug;

/// Everything `route_request` needs to make a hold durable after the runtime
/// has returned its `Skipped` trail.
#[derive(Clone)]
pub struct HoldCapture {
    store: Arc<dyn HeldActionStore>,
    events: Option<RuntimeEventBroadcaster>,
    settings: ResponseHoldSettings,
}

impl HoldCapture {
    /// Bundle the daemon's one store, its broadcaster and the hold settings.
    pub fn new(
        store: Arc<dyn HeldActionStore>,
        events: Option<RuntimeEventBroadcaster>,
        settings: ResponseHoldSettings,
    ) -> Self {
        Self {
            store,
            events,
            settings,
        }
    }

    /// The store handle, for the reads and the decide engine.
    pub fn store(&self) -> &Arc<dyn HeldActionStore> {
        &self.store
    }

    /// The configured settings.
    pub fn settings(&self) -> &ResponseHoldSettings {
        &self.settings
    }

    /// Capture iff BOTH clauses hold: `verdict == RequireHuman` AND
    /// `response == Skipped`. `Skipped` alone has four producers (Deny,
    /// RequireHuman-in-live, containment-refused, the guard path) and matching
    /// it alone would turn denied actions into holds an operator could grant.
    pub fn capture_hold(
        &self,
        request: &ActionRequest,
        detection: &DetectionFinding,
        audit: &AuditTrail,
        rehearsal: Option<ResponseRehearsalPreview>,
        now_ms: i64,
    ) -> Option<HeldAction> {
        if !matches!(audit.policy.verdict, PolicyVerdict::RequireHuman)
            || !matches!(audit.response, AuditResponseRecord::Skipped { .. })
        {
            return None;
        }
        let decision = PolicyDecision {
            verdict: audit.policy.verdict,
            rule_name: audit.policy.rule_name.clone(),
            reason: audit.policy.reason.clone(),
        };
        let slug = request
            .evidence
            .get("escalation")
            .and_then(|value| value.get("threat_class"))
            .cloned()
            .and_then(|value| serde_json::from_value(value).ok())
            .map(|class| threat_class_slug(&class))
            .unwrap_or_else(|| "execution".to_string());
        let ttl_ms = i64::try_from(self.settings.hold_ttl_ms_for(&slug)).unwrap_or(i64::MAX);
        let hold = HeldAction::new(
            mint_hold_id(),
            request.clone(),
            detection.clone(),
            decision,
            rehearsal,
            now_ms,
            now_ms.saturating_add(ttl_ms),
            Some(audit.trail_id.clone()),
        );
        if let Err(error) = self.store.create(hold.clone()) {
            tracing::error!(
                module = module_path!(),
                hold_id = %hold.hold_id,
                reason = %error,
                "hold could not be stored; the action was NOT taken and is NOT queued"
            );
            return None;
        }
        self.publish_state(&hold, HoldState::Created, now_ms);
        Some(hold)
    }

    /// One `ResponseHeld` per state change. Called by capture and by the sweep.
    pub fn publish_state(&self, hold: &HeldAction, state: HoldState, now_ms: i64) {
        if let Some(events) = &self.events {
            events.publish(RuntimeEvent::ResponseHeld {
                emitted_at_ms: now_ms,
                hold_id: hold.hold_id.clone(),
                hunt_id: hold.action_request.hunt_id.0.clone(),
                action_kind: hold.action_request.action.kind().to_string(),
                severity: hold.action_request.severity,
                expires_at_ms: hold.expires_at_ms,
                state,
            });
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use swarm_core::types::{AgentId, HuntId, ResponseAction, Severity};
    use swarm_policy::{ActionRequest, PolicyVerdict};
    use swarm_runtime::held_action::{HoldState, MemoryHeldActionStore};
    use swarm_runtime::runtime_events::RuntimeEventBroadcaster;
    use swarm_spine::{AuditResponseRecord, AuditTrail, PolicyRecord};

    const T0: i64 = 1_773_739_200_000;

    fn request() -> ActionRequest {
        ActionRequest {
            hunt_id: HuntId("hunt-evt-1".into()),
            requested_by: AgentId::from_public_key_hex(&"18".repeat(32)),
            action: ResponseAction::IsolateHost {
                host_id: "host-ops-1".into(),
            },
            severity: Severity::Critical,
            evidence: serde_json::json!({ "escalation": { "threat_class": "execution" } }),
        }
    }

    fn trail(verdict: PolicyVerdict, response: AuditResponseRecord) -> AuditTrail {
        let request = request();
        AuditTrail {
            trail_id: "trail-1".into(),
            hunt_id: request.hunt_id.0.clone(),
            related_receipt_ids: vec![],
            detection: crate::ingest::routed_detection_from_request(&request),
            policy: PolicyRecord {
                verdict,
                rule_name: "static.human_gate".into(),
                reason: "authorized but held for human approval".into(),
                lease: None,
            },
            response,
            created_at_ms: T0,
        }
    }

    fn capture() -> (
        HoldCapture,
        Arc<MemoryHeldActionStore>,
        tokio::sync::broadcast::Receiver<RuntimeEvent>,
    ) {
        let store = Arc::new(MemoryHeldActionStore::default());
        let events = RuntimeEventBroadcaster::new(16);
        let rx = events.subscribe();
        let capture = HoldCapture::new(
            store.clone(),
            Some(events),
            swarm_core::config::ResponseHoldSettings::default(),
        );
        (capture, store, rx)
    }

    #[test]
    fn exactly_one_of_the_four_skipped_producers_becomes_a_hold() {
        let skipped = || AuditResponseRecord::Skipped { reason: "r".into() };
        let cases = [
            ("deny", trail(PolicyVerdict::Deny, skipped()), false),
            (
                "require_human",
                trail(PolicyVerdict::RequireHuman, skipped()),
                true,
            ),
            (
                "containment_refused",
                trail(
                    PolicyVerdict::Allow,
                    AuditResponseRecord::Skipped {
                        reason: "no containment lease store is configured".into(),
                    },
                ),
                false,
            ),
            (
                "guard",
                trail(
                    PolicyVerdict::Allow,
                    AuditResponseRecord::GuardRejected {
                        guard_name: "g".into(),
                        reason: "r".into(),
                    },
                ),
                false,
            ),
        ];
        for (label, audit, expect_hold) in cases {
            let (capture, store, mut rx) = capture();
            let request = request();
            let detection = crate::ingest::routed_detection_from_request(&request);
            let captured = capture.capture_hold(&request, &detection, &audit, None, T0);
            assert_eq!(captured.is_some(), expect_hold, "{label}");
            assert_eq!(
                store.list(true, 10).unwrap().len(),
                usize::from(expect_hold),
                "{label}"
            );
            if expect_hold {
                let hold = captured.unwrap();
                assert_eq!(hold.state, HoldState::Created);
                assert_eq!(hold.expires_at_ms, T0 + 3_600_000);
                assert_eq!(hold.audit_trail_id.as_deref(), Some("trail-1"));
                assert_eq!(
                    hold.rationale.threat_class,
                    swarm_core::pheromone::ThreatClass::Execution
                );
                match rx.try_recv().unwrap() {
                    RuntimeEvent::ResponseHeld {
                        hold_id,
                        state,
                        action_kind,
                        ..
                    } => {
                        assert_eq!(hold_id, hold.hold_id);
                        assert_eq!(state, HoldState::Created);
                        assert_eq!(action_kind, "isolate_host");
                    }
                    other => panic!("expected ResponseHeld, got {other:?}"),
                }
            } else {
                assert!(rx.try_recv().is_err(), "{label} published an event");
            }
        }
    }

    /// A `Deny` verdict that also reports `Skipped` is the shape a
    /// single-clause match would have turned into a grantable hold. Asserted
    /// separately from the table because it is the whole reason both clauses
    /// are checked.
    #[test]
    fn a_denied_action_is_never_stored_as_a_holdable_row() {
        let (capture, store, mut rx) = capture();
        let request = request();
        let detection = crate::ingest::routed_detection_from_request(&request);
        let audit = trail(
            PolicyVerdict::Deny,
            AuditResponseRecord::Skipped {
                reason: "policy denied".into(),
            },
        );
        assert!(
            capture
                .capture_hold(&request, &detection, &audit, None, T0)
                .is_none()
        );
        assert!(store.list(true, 10).unwrap().is_empty());
        assert!(store.get("hold_anything").unwrap().is_none());
        assert!(rx.try_recv().is_err());
    }

    /// A store that refuses the write produces no hold, no event and no
    /// queue row: nothing downstream can act on an action that was not
    /// recorded. This is the "durable store before any queue" property.
    #[test]
    fn a_hold_the_store_refuses_is_not_published() {
        let dir = std::env::temp_dir().join(format!(
            "hold-capture-persist-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        // A file where the store wants its directory: every write fails.
        let store_path = dir.join("holds");
        std::fs::write(&store_path, b"not a directory").unwrap();

        let settings = swarm_core::config::ResponseHoldSettings {
            hold_store_path: Some(store_path.display().to_string()),
            ..Default::default()
        };
        let store = swarm_runtime::held_action::ConfiguredHeldActionStore::from_settings(
            &settings,
            std::path::Path::new("."),
        );
        assert!(store.is_err(), "opening a store over a file should fail");

        // And with a store that opens but cannot persist, capture returns None
        // and publishes nothing.
        let good_dir = dir.join("real-holds");
        let store =
            Arc::new(swarm_runtime::held_action::FileHeldActionStore::open(&good_dir).unwrap());
        let events = RuntimeEventBroadcaster::new(16);
        let mut rx = events.subscribe();
        let capture = HoldCapture::new(
            store.clone(),
            Some(events),
            swarm_core::config::ResponseHoldSettings::default(),
        );
        // Block every temp write by making the directory unusable for new
        // files: replace it with a read-only one is uid-dependent, so instead
        // pre-create a directory at the exact temp path the next mint would
        // use. That is not knowable in advance, so drive the failure through a
        // store whose directory was deleted out from under it.
        std::fs::remove_dir_all(&good_dir).unwrap();
        std::fs::write(&good_dir, b"now a file").unwrap();

        let request = request();
        let detection = crate::ingest::routed_detection_from_request(&request);
        let audit = trail(
            PolicyVerdict::RequireHuman,
            AuditResponseRecord::Skipped {
                reason: "held".into(),
            },
        );
        assert!(
            capture
                .capture_hold(&request, &detection, &audit, None, T0)
                .is_none(),
            "a hold that could not be persisted was returned as captured"
        );
        assert!(
            rx.try_recv().is_err(),
            "a hold that could not be persisted was announced"
        );
        assert!(store.list(true, 10).unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_ttl_honours_the_threat_class_override() {
        let store = Arc::new(MemoryHeldActionStore::default());
        let mut settings = swarm_core::config::ResponseHoldSettings::default();
        settings
            .hold_ttl_ms_by_threat_class
            .insert("execution".into(), 900_000);
        let capture = HoldCapture::new(store, None, settings);
        let request = request();
        let detection = crate::ingest::routed_detection_from_request(&request);
        let audit = trail(
            PolicyVerdict::RequireHuman,
            AuditResponseRecord::Skipped { reason: "r".into() },
        );
        let hold = capture
            .capture_hold(&request, &detection, &audit, None, T0)
            .unwrap();
        assert_eq!(hold.expires_at_ms, T0 + 900_000);
    }
}
