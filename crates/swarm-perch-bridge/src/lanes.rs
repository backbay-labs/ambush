//! Lane topic writes, EDGE-TRIGGERED.
//!
//! A topic write is a durable relay-signed `kind:9002` plus a `kind:40099`
//! audit row. Twelve lanes rewritten at 1 Hz is several times one identity's
//! write quota, and every one of those writes would say the same thing as the
//! last. The topic changes only when the escalation level does, which the
//! de-escalation cooldown already bounds.

use std::collections::BTreeMap;

use swarm_core::pheromone::ThreatClass;
use swarm_runtime::runtime_events::EscalationLevel;

use crate::stream::threat_class_slug;

/// One topic write the pacer publishes as a `kind:9002` edit on the lane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopicWrite {
    pub threat_class: ThreatClass,
    pub topic: String,
}

/// Per-class last level. `None` means "below `alert_threshold`".
#[derive(Debug, Default)]
pub struct LaneTopicEdge {
    last: BTreeMap<String, Option<EscalationLevel>>,
}

impl LaneTopicEdge {
    /// Observe the level the escalation stream reports for a class.
    ///
    /// `None` is "below `alert_threshold`". A write comes back only on a
    /// CHANGE, and never for a class that has never been above threshold —
    /// announcing "still quiet" on a lane that was always quiet is a write
    /// nobody asked for and an audit row nobody can act on.
    pub fn observe(
        &mut self,
        threat_class: &ThreatClass,
        level: Option<EscalationLevel>,
    ) -> Option<TopicWrite> {
        let slug = threat_class_slug(threat_class);
        let seen = self.last.contains_key(&slug);
        let previous = self.last.get(&slug).copied().flatten();
        if !seen && level.is_none() {
            return None;
        }
        if seen && previous == level {
            return None;
        }
        self.last.insert(slug.clone(), level);
        let topic = match level {
            Some(EscalationLevel::Alert) => format!("{slug} · ALERT · escalated"),
            Some(EscalationLevel::Incident) => format!("{slug} · INCIDENT · escalated"),
            None => format!("{slug} · below alert_threshold"),
        };
        Some(TopicWrite {
            threat_class: threat_class.clone(),
            topic,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// The whole point: a level that has not changed writes nothing.
    #[test]
    fn only_a_change_produces_a_write() {
        let mut edge = LaneTopicEdge::default();
        let class = ThreatClass::Execution;

        let first = edge
            .observe(&class, Some(EscalationLevel::Alert))
            .expect("the first crossing writes");
        assert_eq!(first.topic, "execution · ALERT · escalated");

        assert!(
            edge.observe(&class, Some(EscalationLevel::Alert)).is_none(),
            "a repeat of the same level is the 1 Hz rewrite this design removed"
        );

        let up = edge
            .observe(&class, Some(EscalationLevel::Incident))
            .expect("a level change writes");
        assert_eq!(up.topic, "execution · INCIDENT · escalated");

        let down = edge.observe(&class, None).expect("falling below writes");
        assert_eq!(down.topic, "execution · below alert_threshold");
        assert!(
            edge.observe(&class, None).is_none(),
            "still below threshold is not a change"
        );
    }

    /// A class that was never above threshold gets no "still quiet" write.
    #[test]
    fn a_class_never_seen_above_threshold_is_never_announced() {
        let mut edge = LaneTopicEdge::default();
        assert!(edge.observe(&ThreatClass::Execution, None).is_none());
        assert!(edge.observe(&ThreatClass::Execution, None).is_none());
        // But once it crosses, the fall back down IS a change worth writing.
        assert!(
            edge.observe(&ThreatClass::Execution, Some(EscalationLevel::Alert))
                .is_some()
        );
        assert!(edge.observe(&ThreatClass::Execution, None).is_some());
    }

    /// Classes are tracked apart; one lane's edge is not another's.
    #[test]
    fn each_class_keeps_its_own_level() {
        let mut edge = LaneTopicEdge::default();
        assert!(
            edge.observe(&ThreatClass::Execution, Some(EscalationLevel::Alert))
                .is_some()
        );
        assert!(
            edge.observe(&ThreatClass::DefenseEvasion, Some(EscalationLevel::Alert))
                .is_some(),
            "a second class at the same level is its own first crossing"
        );
        assert!(
            edge.observe(&ThreatClass::Execution, Some(EscalationLevel::Alert))
                .is_none()
        );
    }
}
