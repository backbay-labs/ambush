#!/usr/bin/env node
/**
 * viz/dataviz-fixture.mjs — the specimen fixture for prototypes/dataviz.html.
 *
 * WHAT THIS IS. `fixtures/perch-demo-fixture.json` (22-DEMO-FIXTURE.md) is the
 * ONE canonical scenario. This file does two things and nothing else:
 *
 *   1. READS the canonical fixture and re-derives the five concentration
 *      checkpoints from `strength_at`'s closed form, asserting they reproduce
 *      the canonical numbers to 6 decimal places. If the canonical fixture
 *      changes, this fails loudly rather than drifting.
 *   2. DERIVES the EXTENSION — the deposits, hosts, agents and incident members
 *      the canonical scenario deliberately does not have (it is single-host,
 *      single-class, two-detector by design) and that VIZ-2, VIZ-3 and VIZ-6
 *      cannot be drawn without. Every extension id uses the SAME public
 *      derivation as fixtures/derive-ids.mjs:
 *
 *          id = sha256("perch-demo-fixture/v1/" + label)
 *
 *      under an `ext/` label prefix, so no extension label can collide with a
 *      canonical one and every extension id is regenerable by a reviewer.
 *
 * THE INVARIANT THAT MAKES THE EXTENSION SAFE. `concentration_for`
 * (AMB crates/swarm-pheromone/src/substrate.rs:1268-1304, called on every
 * concentration-monitor tick inside `swarm_detect --serve`, reducing one threat
 * class's deposit set to a PheromoneConcentration) filters by threat class at
 * :1281 before it sums. EVERY extension deposit is therefore placed in a threat
 * class OTHER than `execution`, which makes it arithmetically impossible for the
 * extension to move the canonical lane's numbers. Assertion A5 below proves it
 * by recomputing the checkpoints with the extension loaded.
 *
 * Usage:  node viz/dataviz-fixture.mjs            # assert + print the table
 *         node viz/dataviz-fixture.mjs --json     # emit the object the page bakes
 */

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const HERE = dirname(fileURLToPath(import.meta.url));
const CANON = JSON.parse(
  readFileSync(join(HERE, "..", "fixtures", "perch-demo-fixture.json"), "utf8"),
);

const DOMAIN = "perch-demo-fixture/v1/";
const h = (label, bytes = 32) =>
  createHash("sha256").update(DOMAIN + label).digest("hex").slice(0, bytes * 2);
const token = (prefix, label, n = 8) => `${prefix}${h(label).slice(0, n)}`;

/* ---------------------------------------------------------------- closed form
 * AMB crates/swarm-core/src/pheromone.rs:280-287, PheromoneDeposit::strength_at.
 * Transcribed verbatim including the `now <= timestamp` early return, which is
 * what render rule CR-4 exists to compensate for in a replayed series. */
export const strengthAt = (d, now) =>
  now <= d.timestamp
    ? d.confidence
    : d.confidence * Math.pow(0.5, (now - d.timestamp) / d.decay_half_life);

/** concentration_for's reduction, restricted to deposits that existed at `now`. */
export function concentrationAt(deposits, threatClass, now, policy, suppression) {
  let total = 0, peak = 0;
  const sources = new Set(), agents = new Set(), contributing = [];
  for (const d of deposits) {
    if (d.threat_class !== threatClass) continue;                 // substrate.rs:1281
    if (d.timestamp > now) continue;                              // CR-4
    if (suppression && suppression.at <= now &&
        d.event_id === suppression.event_id &&
        suppression.at >= d.timestamp) continue;                  // substrate.rs:1367-1380
    const s = strengthAt(d, now);
    if (s < policy.evaporation_threshold) continue;               // substrate.rs:1283
    if (s <= 0) continue;                                         // substrate.rs:1290
    total += s;
    peak = Math.max(peak, d.confidence);
    sources.add(d.agent_id);                                      // substrate.rs:1295
    agents.add(agentBaseOf(d.agent_id));
    contributing.push({ d, s });
  }
  return {
    total_strength: total,
    distinct_sources: sources.size,
    real_agents: agents.size,
    peak_confidence: peak,
    sourceIds: [...sources].sort(),
    agentIds: [...agents].sort(),
    contributing,
  };
}

/** The strategy suffix is the LAST colon segment; everything before it is the
 *  agent. `strategy_scoped_agent_id` (AMB crates/swarm-whisker/src/stream.rs:20-22,
 *  called from resolve_deposits at pipeline.rs:573 inside the daemon's detection
 *  lane) is `format!("{}:{strategy_id}", base.0)`, so this split is exact. */
export const agentBaseOf = (id) => id.split(":").slice(0, -1).join(":");

/* -------------------------------------------------------------- canonical spine */
const P = CANON.constants.policy;
const POLICY = {
  threat_class: "execution",
  half_life_secs: P.half_life_secs,
  evaporation_threshold: P.evaporation_threshold,
  min_sources_for_escalation: P.min_sources_for_escalation,
  alert_threshold: P.alert_threshold,
  incident_threshold: P.incident_threshold,
};

const CANON_DEPOSITS = CANON.deposits.map((d) => ({
  agent_id: d.agent_id,
  strategy_id: d.strategy_id,
  threat_class: "execution",
  confidence: d.confidence,
  timestamp: d.timestamp,
  decay_half_life: POLICY.half_life_secs,
  event_id: d.event_id,
  host_id: d.host_id,
  severity: "CRITICAL",
  origin: "canonical",
}));

const T = CANON.clock.timestamps;
const DISMISS = {
  event_id: "hunt-evt-1",
  threat_class: "execution",
  at: Math.floor(T.dismiss_applied_ms / 1000),
  operator: CANON.cast.operator.operator_id,
};

/* ------------------------------------------------------------------ extension */
const EXT_AGENT = `swarm:ed25519:${h("ext/ed25519/whisker-1")}:whisker-2c19`;
const EXT_AGENT_2 = `swarm:ed25519:${h("ext/ed25519/stalker-1")}:stalker-4e77`;

const ext = (base, strategy, threatClass, tOffsetS, confidence, host, eventLabel) => ({
  agent_id: `${base}:${strategy}`,
  strategy_id: strategy,
  threat_class: threatClass,
  confidence,
  timestamp: Math.floor(CANON.clock.demo_now_ms / 1000) + tOffsetS,
  decay_half_life: POLICY.half_life_secs,
  event_id: token("evt-", `ext/telemetry/${eventLabel}`, 6),
  host_id: host,
  severity: confidence >= 0.7 ? "HIGH" : "MEDIUM",
  origin: "extension",
});

// Every one of these is in a threat class OTHER than `execution`. See the header.
const EXT_DEPOSITS = [
  ext(EXT_AGENT,   "lsass_handle",    "credential_access",    -520, 0.62, "host-ops-2", "lsass-1"),
  ext(EXT_AGENT,   "lsass_handle",    "credential_access",    -190, 0.44, "host-ops-3", "lsass-2"),
  ext(EXT_AGENT_2, "beacon_jitter",   "command_and_control",  -410, 0.55, "host-ops-2", "beacon-1"),
  ext(EXT_AGENT_2, "beacon_jitter",   "command_and_control",   -95, 0.31, "host-ops-4", "beacon-2"),
  ext(EXT_AGENT_2, "smb_admin_share", "lateral_movement",     -300, 0.48, "host-ops-3", "smb-1"),
  ext(EXT_AGENT,   "sched_task_persist", "persistence",       -240, 0.37, "host-ops-4", "sched-1"),
  // host_id resolves to None: deposit_host_id (AMB swarm-pheromone/src/substrate.rs:1336-1348,
  // called by the deposits route while shaping each row) finds neither
  // indicator["host_id"] nor /evidence/host_metadata/host_id and returns None.
  ext(EXT_AGENT_2, "dns_tunnel_entropy", "data_exfiltration", -150, 0.29, null, "dns-1"),
];

/* ------------------------------------------------------- extension containment leases
 * The canonical scenario has ONE containment lease, in ONE state. VIZ-5 draws
 * five states and four of them are undrawable without these three. TTL is
 * runtime.containment.lease_ttl_ms = 900,000 ms
 * (AMB crates/swarm-core/src/config/defaults.rs:23-27), never the 60,000 ms
 * capability-lease TTL. Only 4 of the 12 destructive actions mint one at all
 * (is_containment_action, AMB crates/swarm-runtime/src/containment.rs:54-63,
 * called by prepare_containment before execute), and of those four
 * TerminateUserSession resolves to InverseGap::Irreversible
 * (crates/swarm-response/src/rollback.rs:181-189). */
const NOW_MS = CANON.clock.demo_now_ms;
const TTL = CANON.constants.containment_lease_ttl_ms;
const EXT_LEASES = [
  { lease_id: token("cl_", "ext/containment-lease/host-ops-2"), action: "quarantine_file",
    scope: "host-ops-2", issued_at_ms: NOW_MS - TTL + 11_000, expires_at_ms: NOW_MS + 11_000,
    expired: false, undo: "release_quarantined_file", state: "expiring" },
  { lease_id: token("cl_", "ext/containment-lease/host-ops-3"), action: "suspend_process",
    scope: "host-ops-3", issued_at_ms: NOW_MS - TTL - 3_540_000, expires_at_ms: NOW_MS - 3_540_000,
    expired: true, undo: "resume_process", state: "expired-still-listed" },
  { lease_id: token("cl_", "ext/containment-lease/host-ops-4"), action: "terminate_user_session",
    scope: "host-ops-4", issued_at_ms: NOW_MS - 438_000, expires_at_ms: NOW_MS + 462_000,
    expired: false, undo: null, state: "open, no inverse" },
];

/* ---------------------------------------------------- extension incident members
 * Reason grammars are the runtime's own:
 *   included  — AMB crates/swarm-runtime/src/correlation.rs:495-506
 *   rejected  — :468-479 (no supporting evidence) and :481-493 (weighted score)
 * built by score_breakdown (:455-466) and shared_keys_summary (:447-453). */
const EXT_REJECTED = [
  {
    finding_id: h("ext/finding/rejected/beacon-jitter", 16),
    strategy_id: "beacon_jitter",
    host_id: "host-ops-2",
    confidence_score: 0.41,
    shared_keys: ["strategy:beacon_jitter"],
    dimensions: ["semantic"],
    reason:
      "requires at least one entity or causal link before semantic evidence can reinforce correlation; shared strategy:beacon_jitter",
  },
  {
    finding_id: h("ext/finding/rejected/lsass-handle", 16),
    strategy_id: "lsass_handle",
    host_id: "host-ops-3",
    confidence_score: 0.28,
    shared_keys: ["strategy:lsass_handle", "user:alice"],
    dimensions: ["semantic", "entity"],
    reason:
      "weighted_score=0.6 below threshold 2 from shared strategy:lsass_handle, user:alice (semantic=0.35, entity=0.25)",
  },
];

/* ------------------------------------------------------------------ assertions */
const round6 = (x) => Math.round(x * 1e6) / 1e6;
const ALL = [...CANON_DEPOSITS, ...EXT_DEPOSITS];

const CHECKPOINTS = [
  ["below",           Math.floor(T.tick_below_ms / 1000),            null],
  ["crossing",        T.cross_s,                                     null],
  ["at_open_row",     Math.floor(T.open_row_ms / 1000),              null],
  ["before_dismiss",  Math.floor(T.dismiss_leg1_ms / 1000),          null],
  ["after_dismiss",   T.tick_after_dismiss_s,                        DISMISS],
];

export function assertCanonical() {
  const fails = [];
  for (const [name, at, sup] of CHECKPOINTS) {
    const want = CANON.concentration[name];
    // A1..A4: canonical lane, canonical deposits only.
    const gotCanon = concentrationAt(CANON_DEPOSITS, "execution", at, POLICY, sup);
    // A5: the SAME checkpoint with the extension loaded. Must be identical.
    const gotAll = concentrationAt(ALL, "execution", at, POLICY, sup);
    if (round6(gotCanon.total_strength) !== round6(want.total_strength))
      fails.push(`${name}: total ${round6(gotCanon.total_strength)} != ${want.total_strength}`);
    if (gotCanon.distinct_sources !== want.distinct_sources)
      fails.push(`${name}: sources ${gotCanon.distinct_sources} != ${want.distinct_sources}`);
    if (round6(gotCanon.peak_confidence) !== round6(want.peak_confidence))
      fails.push(`${name}: peak ${gotCanon.peak_confidence} != ${want.peak_confidence}`);
    if (round6(gotAll.total_strength) !== round6(gotCanon.total_strength))
      fails.push(`${name}: EXTENSION PERTURBED the canonical lane (${round6(gotAll.total_strength)})`);
    if (gotAll.distinct_sources !== gotCanon.distinct_sources)
      fails.push(`${name}: EXTENSION changed distinct_sources`);
  }
  return fails;
}

export const FIXTURE = {
  policy: POLICY,
  clock: {
    demo_now_s: Math.floor(CANON.clock.demo_now_ms / 1000),
    shift_start_s: Math.floor(CANON.clock.shift_start_ms / 1000),
    window_start_s: Math.floor(CANON.clock.demo_now_ms / 1000) - 600,
    cross_s: T.cross_s,
    hold_a_ms: T.hold_a_ms,
    lease_ms: T.lease_ms,
    receipt_ms: T.receipt_ms,
    rollback_ms: T.rollback_ms,
    incident_ms: T.incident_ms,
    open_row_ms: T.open_row_ms,
    leg1_ms: T.leg1_ms,
    decide_ms: T.decide_ms,
  },
  channels: CANON.channels,
  operator: CANON.cast.operator,
  incident_id: CANON.incident_id,
  holds: {
    a: {
      hold_id: CANON.holds.a.hold_id, action_kind: CANON.holds.a.action_kind,
      severity: CANON.holds.a.severity, state: CANON.holds.a.state,
      held_at_ms: CANON.holds.a.held_at_ms, expires_at_ms: CANON.holds.a.expires_at_ms,
      leases_a_containment: CANON.holds.a.leases_a_containment,
      hunt_id: CANON.holds.a.action_request.hunt_id,
      host_id: CANON.holds.a.action_request.action.host_id,
    },
    b: {
      hold_id: CANON.holds.b.hold_id, action_kind: CANON.holds.b.action_kind,
      severity: CANON.holds.b.severity, state: CANON.holds.b.state,
      held_at_ms: CANON.holds.b.held_at_ms, expires_at_ms: CANON.holds.b.expires_at_ms,
      leases_a_containment: CANON.holds.b.leases_a_containment,
      hunt_id: CANON.holds.b.action_request.hunt_id,
      target: CANON.holds.b.action_request.action.target,
    },
  },
  capability_lease: CANON.capability_lease,
  containment_lease_id: CANON.containment_lease_id,
  receipt_id: CANON.receipt_id,
  ttl: {
    capability_ms: CANON.constants.capability_lease_ttl_ms,
    containment_ms: CANON.constants.containment_lease_ttl_ms,
    contingency_ms: CANON.constants.contingency_lease_ttl_ms,
    hold_ms: CANON.constants.perch_hold_ttl_ms,
  },
  deposits: CANON_DEPOSITS,
  extension_deposits: EXT_DEPOSITS,
  dismiss: DISMISS,
  ext_rejected: EXT_REJECTED,
  ext_leases: EXT_LEASES,
  ext_agents: { whisker: EXT_AGENT, stalker: EXT_AGENT_2 },
  canonical_concentration: CANON.concentration,
  nostr_event_ids: CANON.nostr_event_ids,
};

if (import.meta.url === `file://${process.argv[1]}`) {
  const fails = assertCanonical();
  if (process.argv.includes("--json")) {
    process.stdout.write(JSON.stringify(FIXTURE, null, 2) + "\n");
  } else {
    console.log("canonical checkpoints (execution threat class, canonical deposits only):");
    for (const [name, at, sup] of CHECKPOINTS) {
      const g = concentrationAt(CANON_DEPOSITS, "execution", at, POLICY, sup);
      console.log(
        "  " + name.padEnd(15),
        round6(g.total_strength).toFixed(6).padStart(10),
        `${g.distinct_sources} source${g.distinct_sources === 1 ? "" : "s"} / ` +
          `${g.real_agents} agent${g.real_agents === 1 ? "" : "s"}`,
        "peak " + g.peak_confidence.toFixed(2),
      );
    }
    console.log("\nextension ids (regenerable: sha256(\"" + DOMAIN + "\" + label)):");
    console.log("  ext/ed25519/whisker-1 ", EXT_AGENT);
    console.log("  ext/ed25519/stalker-1 ", EXT_AGENT_2);
    for (const d of EXT_DEPOSITS)
      console.log("  " + d.event_id.padEnd(12), d.threat_class.padEnd(20), (d.host_id ?? "«no host_id»").padEnd(14), d.confidence);
    for (const r of EXT_REJECTED) console.log("  rejected " + r.finding_id, r.strategy_id);
    for (const l of EXT_LEASES)
      console.log("  " + l.lease_id.padEnd(12), l.action.padEnd(22), l.scope.padEnd(12), l.state);
  }
  if (fails.length) { console.error("\nFAIL:\n  " + fails.join("\n  ")); process.exit(1); }
  console.error("\nOK — 5 canonical checkpoints reproduced; extension perturbs none of them.");
}
