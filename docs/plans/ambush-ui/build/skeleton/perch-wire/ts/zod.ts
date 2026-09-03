/**
 * SKELETON. Lands as BUZZ `desktop/src/features/perch/wire/zod.ts`.
 *
 * The runtime gate. **The only place a `Card` or a `Frame` may be constructed
 * from an untrusted string.**
 *
 * # Why zod, when Buzz's own precedent is a hand-written guard
 *
 * `zod@4.4.3` is already a desktop dependency (`desktop/package.json:88`,
 * resolved in `pnpm-lock.yaml:3737`), used in exactly two files today
 * (`src/shared/features/manifest.ts`, `src/features/agents/ui/modelCapabilities.ts`),
 * and `manifest.ts:27-37` is the pattern this file copies: `safeParse`, a
 * `console.warn` naming the failure, and a safe fallback — "The app keeps
 * working; gated UI stays hidden; nothing accidentally leaks."
 *
 * Buzz's OTHER wire-payload parser, `configNudge.ts:172-182`, is a hand-written
 * type guard instead. That is the right call for a five-field payload with one
 * union. It is the wrong call here: the seven card facts are ~120 fields across
 * three internally-tagged Rust enums, and a hand-written guard for that is a
 * file nobody keeps correct. What matters is that the zod parse happens ONCE,
 * at admission, and never in a render path — see the perf note below.
 *
 * # Where the parse runs, and where it must not
 *
 * ONCE per event, at admission, before the card enters React Query's cache.
 * NEVER inside `MessageRow`, whose `React.memo` comparator has sixty explicit
 * prop clauses (`MessageRow.tsx:935-995`) and whose `renderBody` runs on every
 * parent render. `CLAUDE.md` gotcha 6 is the house rule: one unstable prop —
 * and a fresh `safeParse` result object is one — defeats the memo for every row
 * in the timeline. The admission function returns a frozen object that is
 * reference-stable for the life of the event id.
 *
 * # zod 4 API notes
 *
 * `z.strictObject` is zod 4's spelling of an object that rejects unknown keys;
 * `z.object().strict()` is deprecated. `z.record` takes two arguments. Neither
 * appears in the two existing consumers, so this file is the first use of
 * either and a reviewer should check both against the resolved version rather
 * than against memory.
 */

import { z } from "zod";

import {
  AGENT_ROLES,
  RESPONSE_ACTION_KINDS,
  SEVERITIES,
  STANDARD_THREAT_CLASSES,
} from "./types";
import type { Card, Frame } from "./types";

// ──────────────────────────────────────────────────────────────── scalars

/**
 * 64 LOWERCASE hex. Not case-insensitive: `insert_mentions` lowercases before
 * insert and drops anything that is not exactly 64 ASCII-hex with a
 * `tracing::debug!` (`BUZZ crates/buzz-db/src/runtime/mod.rs:65-81`), and it
 * runs on a separate transaction after commit with failure downgraded to
 * `warn!` (`:943-948`). A stored-but-unmentioned hold is invisible to
 * `query_needs_action` forever, and a republish is deduplicated by event id, so
 * the hole is not self-healing.
 */
export const hex64 = z.string().regex(/^[0-9a-f]{64}$/);

/** `0x`-prefixed lowercase hex, as `swarm_crypto::hashing::sha256_hex` emits. */
export const hexPrefixed = z.string().regex(/^0x[0-9a-f]+$/);

/**
 * `extract_channel_id` parses the `h` tag with `val.parse::<Uuid>()` and returns
 * `None` on failure (`BUZZ crates/buzz-relay/src/handlers/ingest.rs:549-561`),
 * which after the fork means the event is rejected rather than stored globally.
 */
export const uuid = z
  .string()
  .regex(
    /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/,
  );

/** `swarm:ed25519:<64 hex>`, the form `parse_issuer_pubkey_hex` requires. */
export const spineIssuer = z.string().regex(/^swarm:ed25519:[0-9a-fA-F]{64}$/);

const unixMillis = z.number().int();
const unixSeconds = z.number().int();

// ────────────────────────────────────────────────────────────────── enums

export const severity = z.enum(SEVERITIES);
export const agentRole = z.enum(AGENT_ROLES);
export const responseActionKind = z.enum(RESPONSE_ACTION_KINDS);
export const swarmMode = z.enum(["normal", "alert", "incident"]);
export const agentHealthState = z.enum(["healthy", "degraded", "failed"]);
export const policyVerdict = z.enum(["deny", "allow", "require_human"]);
export const executionMode = z.enum(["dry_run", "enforced"]);
export const responseStatus = z.enum(["simulated", "executed", "timeout", "failed"]);
export const rollbackStepStatus = z.enum([
  "reversed",
  "simulated",
  "irreversible",
  "unsupported",
  "failed",
]);
export const rollbackTrigger = z.enum(["manual", "expiry"]);
export const partitionState = z.enum([
  "healthy",
  "degraded",
  "partitioned",
  "healing",
]);
export const escalationLevel = z.enum(["alert", "incident"]);

/**
 * The one enum shape a hand-written type gets wrong.
 *
 * `ThreatClass` is EXTERNALLY tagged with twelve unit variants and one newtype
 * variant (`AMB crates/swarm-core/src/pheromone.rs:13-30`), so serde emits a
 * bare string for the twelve and `{"custom":"..."}` for the thirteenth. Two
 * production agents mint Custom classes — Sphinx at `sphinx_agent.rs:610` and
 * Calico at `calico_agent.rs:440` — so this union is reachable, not theoretical.
 */
export const threatClass = z.union([
  z.enum(STANDARD_THREAT_CLASSES),
  z.strictObject({ custom: z.string().min(1) }),
]);

// ─────────────────────────────────────────────────────────── structural

/**
 * INTERNALLY tagged on `type`
 * (`AMB crates/swarm-core/src/types.rs:416-467`), so the variant payload sits
 * beside the tag. Deliberately permissive on the payload: Perch reads this type
 * and never constructs it, and enumerating fifteen shapes would be fifteen
 * things to keep in sync for no reader benefit.
 */
export const responseAction = z
  .object({ type: responseActionKind })
  .catchall(z.unknown());

export const policyDecision = z.strictObject({
  verdict: policyVerdict,
  rule_name: z.string(),
  reason: z.string(),
});

export const detachedSignature = z.strictObject({
  algorithm: z.string(),
  key_id: z.string(),
  public_key_hex: z.string(),
  signature_hex: z.string(),
});

/**
 * WHO PRODUCED THE FACT. `role` is NULLABLE AND REQUIRED — `.nullable()`, never
 * `.nullish()` and never `.optional()`.
 *
 * `WhiskerAgent::tick` passes `Some(AgentRole::Whisker)` explicitly
 * (`AMB crates/swarm-agents/src/whisker_agent.rs:150-156`), while
 * `infer_agent_role`
 * (`AMB crates/swarm-runtime/src/detection/pipeline.rs:583-604`) prefix-matches
 * and returns `None` for every `swarm:ed25519:<hex>` identity the HTTP ingest
 * lane uses. Both shapes are real, so both must decode. A MISSING key stays a
 * decode error: collapsing "absent" into "null" would let a truncated body pass
 * as an unattributed fact. `13-WIRE-SCHEMAS.md` amendment `W-A1`.
 */
/**
 * `common.schema.json#/$defs/HoldId`.
 *
 * URL-safe because it is a path parameter on
 * `POST /v1/response/holds/{hold_id}/decide`, and COLON-FREE so the forbidden
 * `hold:{hunt_id}:{held_at_ms}` derived form fails admission: `hunt_id` is the
 * telemetry event id (`AMB crates/swarm-runtime/src/service/runtime_service.rs:391`),
 * a join key into detection data, and the hold id rides a `kind:26006` frame that
 * every Approve-scoped operator receives. Six incompatible hold-id formats were in
 * circulation across the wave-2 artifact set and two used the colon prefix; this
 * is the one place the shape is decided.
 */
export const holdId = z
  .string()
  .regex(/^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$/, "hold_id must be an opaque URL-safe token");

export const factIssuer = z.strictObject({
  swarm_agent_id: z.string().min(1),
  role: agentRole.nullable(),
  nostr_pubkey: hex64.nullish(),
});

/**
 * WHO PRODUCED THE FACT, when the producer is a PERSON. `ambush:verdict:v1` only.
 *
 * `role: z.null()` is the point. `AgentRole` has no human member and
 * `AgentRole.Tom` is the governance/veto actor
 * (`AMB crates/swarm-core/src/agent.rs:26-27`); `APPENDIX-NORMATIVE.md` §7 rules
 * that governance's veto and the operator's refuse are never conflated. A
 * verdict card arriving with `role: "tom"` fails admission here rather than
 * rendering a human decision under the governance agent's role.
 */
export const operatorFactIssuer = z.strictObject({
  swarm_agent_id: z.string().min(1),
  role: z.null(),
  nostr_pubkey: hex64.nullish(),
});

export const threatConcentration = z.strictObject({
  threat_class: threatClass,
  total_strength: z.number(),
  distinct_sources: z.number().int().nonnegative(),
  peak_confidence: z.number().min(0).max(1),
});

/**
 * `AMB crates/swarm-policy/src/lib.rs:134-146` (the struct at `:137`).
 *
 * `expires_at_ms` is `context.now_ms + policy.lease_ttl_ms` = **60 seconds**
 * (`AMB crates/swarm-policy/src/static_gate.rs:307-324`, TTL at
 * `AMB rulesets/default.yaml:94`). That is the CAPABILITY lease's authorization
 * window, checked by `ensure_active_lease`
 * (`AMB crates/swarm-runtime/src/lib.rs:1369-1379`). It is NOT the countdown an
 * operator watches on `/leases`, which is a `ContainmentLease` with a 900_000 ms
 * default (`AMB crates/swarm-core/src/config/defaults.rs:23-27`). Rendering one
 * beside the other is wrong by 15x.
 */
export const capabilityLease = z.strictObject({
  capability_id: z.string(),
  expires_at_ms: unixMillis,
  action: z.string(),
  scope: z.string().nullish(),
});

/**
 * Render law 1's BLAST RADIUS slot, typed.
 * `AMB crates/swarm-core/src/types.rs:505-513`; its `impact` enum has one
 * variant per `ResponseAction`, fifteen in all (`:485-503`).
 */
export const responseBlastRadiusPreview = z.strictObject({
  scope_kind: z.enum([
    "network_target",
    "host",
    "credential",
    "user_session",
    "file",
    "process",
    "user_account",
    "scheduled_task",
    "zone",
    "operator_queue",
  ]),
  scope_value: z.string(),
  impact: z.enum([
    "network_egress_blocked",
    "host_connectivity_isolated",
    "credential_access_revoked",
    "dns_resolution_sinkholed",
    "user_session_terminated",
    "host_scan_triggered",
    "host_firewall_policy_changed",
    "file_quarantined",
    "process_terminated",
    "process_suspended",
    "user_account_disabled",
    "password_reset_enforced",
    "scheduled_task_removed",
    "deception_coverage_changed",
    "operator_escalation_only",
  ]),
  max_affected_scopes: z.number().int().nonnegative(),
  affected_capabilities: z.array(z.string()),
  summary: z.string(),
});

/**
 * Render law 1's IF YOU UNDO slot, typed.
 * `AMB crates/swarm-core/src/types.rs:541-546`.
 */
export const responseRollbackPreview = z.strictObject({
  required: z.boolean(),
  summary: z.string(),
  steps: z.array(z.strictObject({ kind: z.string(), summary: z.string() })),
});

/**
 * `AMB crates/swarm-core/src/types.rs:548-556`. `simulated_only` is hardcoded
 * `true` on every preview (`AMB crates/swarm-runtime/src/service/preview.rs:111`),
 * hence the literal: a `false` here would mean the daemon changed and the
 * console must refuse the card rather than render a rehearsal that ran.
 */
export const responseRehearsalPreview = z.strictObject({
  rehearsal_id: z.string(),
  source_bundle_id: z.string(),
  prepared_at_ms: unixMillis,
  simulated_only: z.literal(true),
  blast_radius: responseBlastRadiusPreview,
  rollback: responseRollbackPreview,
});

/**
 * The stored outcome of a decision, as it appears on a TERMINAL hold card.
 *
 * Modelled rather than left as `unknown` because `INV-33` requires the three
 * post-decision states to render as three distinct things and `dispatched` is
 * what separates "refused" from "granted but refused late" — the latter is a
 * NORMAL OUTCOME naming a rule, never a client error (`INV-28`).
 */
export const holdDecisionRecord = z.strictObject({
  decision: z.enum(["grant", "refuse"]),
  operator_id: z.string(),
  decided_at_ms: unixMillis,
  nostr_intent_event_id: hex64,
  signature: detachedSignature.nullish(),
  rationale: z.string().nullish(),
  outcome: z.string(),
  dispatched: z.boolean(),
  receipt_id: z.string().nullish(),
  refusal: z.unknown().nullish(),
});

const locatorBase = { emitted_at_ms: unixMillis, issuer: factIssuer };

// ─────────────────────────────────────────────────────────── card facts

export const findingFact = z.strictObject({
  schema: z.literal("ambush.perch.finding.v1"),
  ...locatorBase,
  locator: z.strictObject({
    finding_id: z.string(),
    event_id: z.string(),
    strategy_id: z.string(),
    host_id: z.string().nullish(),
    lane_channel: uuid,
  }),
  finding: z.strictObject({
    schema: z.literal("swarm_finding"),
    finding_id: z.string(),
    event_id: z.string(),
    strategy_id: z.string(),
    threat_class: threatClass,
    severity,
    confidence: z.number().min(0).max(1),
    // `serde_json::Value`, unconstrained, built from adversary-shaped telemetry.
    // Validating its SHAPE here would be a lie; INV-14's `<AdversaryString>`
    // wrapper is what makes it safe to render.
    evidence: z.unknown(),
    evidence_truncated: z
      .strictObject({ bytes: z.number().int().nonnegative(), sha256: hexPrefixed })
      .optional(),
  }),
});

export const escalationFact = z.strictObject({
  schema: z.literal("ambush.perch.escalation.v1"),
  ...locatorBase,
  locator: z.strictObject({
    lane_channel: uuid,
    case_channel: uuid.nullish(),
  }),
  escalation: z.discriminatedUnion("cause", [
    z.strictObject({
      cause: z.literal("concentration_crossing"),
      threat_class: threatClass,
      level: escalationLevel,
      total_strength: z.number(),
      distinct_sources: z.number().int().nonnegative(),
      // The STRATEGY-SCOPED agent id, not the agent instance. resolve_deposits
      // writes agent_id: strategy_scoped_agent_id(agent_id, &finding.strategy_id)
      // onto every deposit (AMB crates/swarm-runtime/src/detection/pipeline.rs:573)
      // and concentration_for counts those strings
      // (AMB crates/swarm-pheromone/src/substrate.rs:1295), over a base that is
      // already instance-scoped (whisker_agent.rs:148-149). One Whisker with two
      // detectors is TWO sources / ONE agent. The earlier literal "agent_instance_id" was
      // factually wrong and would have REJECTED a truthful bridge at admission;
      // 13-WIRE-SCHEMAS.md amendment W-10 records the withdrawal.
      distinct_sources_counts: z.literal("strategy_scoped_agent_id"),
      source_ids: z.array(z.string().min(1)).min(1).readonly().nullable(),
      // Exactly one of source_ids / source_ids_absent_reason is null. Enforced
      // by the .refine() below, so an unnamed absence cannot reach a component.
      source_ids_absent_reason: z
        .literal("not_carried_by_runtime_event")
        .nullable(),
      peak_confidence: z.number().min(0).max(1),
      mode_changed: z.boolean(),
      current_mode: swarmMode,
      dedupe_key: z.string(),
    }),
    z.strictObject({
      cause: z.literal("mode_transition"),
      from: swarmMode,
      to: z.literal("incident"),
      triggering_threat_class: threatClass.nullish(),
      reason: z.string(),
    }),
    z.strictObject({
      cause: z.literal("tamper_fail_closed"),
      debugger_attached: z.boolean(),
      tracer_pid: z.number().int().nullish(),
      unexpected_library_count: z.number().int().nonnegative(),
      unexpected_library_sha256: hexPrefixed,
      unexpected_library_loads: z.array(z.string()),
      fail_closed: z.literal(true),
      details: z.string(),
    }),
  ]),
})
  // Exactly one of source_ids / source_ids_absent_reason is null. Applied at the
  // FACT level rather than on the union branch: a `.refine` wrapper on a branch
  // is not an object schema and z.discriminatedUnion will not take it.
  //
  // Why the assertion is worth a refine at all: render law 2's `M agents` half
  // has NO data source on any Phase-1 card, and the failure mode of leaving that
  // as a bare null is a component that fabricates a number or spins forever.
  // Making the absence a named value the decoder insists on is what turns
  // "we don't have it yet" into something a screen can say out loud.
  .refine(
    (fact) =>
      fact.escalation.cause !== "concentration_crossing" ||
      (fact.escalation.source_ids === null) !==
        (fact.escalation.source_ids_absent_reason === null),
    {
      message:
        "escalation.source_ids and escalation.source_ids_absent_reason: exactly one must be null",
      path: ["escalation", "source_ids_absent_reason"],
    },
  );

export const holdFact = z.strictObject({
  schema: z.literal("ambush.perch.hold.v1"),
  ...locatorBase,
  locator: z.strictObject({
    hold_id: holdId,
    case_channel: uuid,
    hunt_id: z.string(),
    finding_card_id: hex64.nullish(),
  }),
  hold: z.strictObject({
    hold_id: holdId,
    state: z.enum([
      "created",
      "notified",
      "armed",
      "deciding",
      "granted",
      "refused",
      "expired",
      "executed",
      "failed",
    ]),
    action_kind: responseActionKind,
    severity,
    held_at_ms: unixMillis,
    expires_at_ms: unixMillis,
    action_request: z.strictObject({
      hunt_id: z.string(),
      requested_by: z.string(),
      action: responseAction,
      severity,
      evidence: z.record(z.string(), z.unknown()),
    }),
    policy_decision: policyDecision,
    rationale: z.strictObject({
      rule_name: z.string(),
      reason: z.string(),
      threat_class: threatClass,
      severity,
      request_carried_fields: z.array(z.string()),
      concentration_at_hold: threatConcentration.nullish(),
      escalation_level: escalationLevel.nullish(),
      governance_receipt_present: z.boolean(),
    }),
    leases_a_containment: z.boolean(),
    rehearsal: responseRehearsalPreview.nullish(),
    inverse_resolution: z.array(
      z.strictObject({
        step_kind: z.string(),
        verdict: z.enum(["executable", "irreversible", "unmapped"]),
        reason: z.string().nullish(),
      }),
    ),
    decision: holdDecisionRecord.nullish(),
  }),
});

export const verdictFact = z.strictObject({
  schema: z.literal("ambush.perch.verdict.v1"),
  emitted_at_ms: unixMillis,
  issuer: operatorFactIssuer,
  locator: z.strictObject({
    hold_id: holdId,
    case_channel: uuid,
    hold_card_id: hex64,
  }),
  decision: z.strictObject({
    decision: z.enum(["grant", "refuse"]),
    hold_id: holdId,
    decided_at_ms: unixMillis,
    operator_id: z.string().min(1),
    rationale: z.string().nullish(),
  }),
  signature: detachedSignature,
  // TWO OPERATORS, ONE HOLD. Both consoles publish a signed leg-1 card; the
  // daemon's compare-and-set picks one and 409s the other; the loser publishes an
  // update card with state "superseded" naming the winner's leg-1 event id. Without
  // the discriminated shape a `superseded` card could omit its winner, which leaves
  // the reconciler and the Ledger export with two unqualified human-decision records
  // for one hold. See 13-WIRE-SCHEMAS.md section 3.5.
  leg2: z
    .discriminatedUnion("state", [
      z.strictObject({
        state: z.enum(["sending", "recorded", "acknowledged", "refused_late"]),
        receipt_id: z.string().nullish(),
        refusal_check: z.string().nullish(),
        superseded_by: z.null().nullish(),
        superseded_at_ms: z.null().nullish(),
      }),
      z.strictObject({
        state: z.literal("superseded"),
        receipt_id: z.string().nullish(),
        refusal_check: z.string().nullish(),
        superseded_by: hex64,
        superseded_at_ms: unixMillis,
      }),
    ])
    .optional(),
});

export const receiptFact = z.strictObject({
  schema: z.literal("ambush.perch.receipt.v1"),
  ...locatorBase,
  locator: z.strictObject({
    trail_id: z.string(),
    hunt_id: z.string(),
    case_channel: uuid,
    receipt_id: z.string().nullish(),
    verdict_card_id: hex64.nullish(),
  }),
  audit_trail: z.strictObject({
    trail_id: z.string(),
    hunt_id: z.string(),
    related_receipt_ids: z.array(z.string()),
    detection: z.unknown(),
    policy: z.strictObject({
      verdict: policyVerdict,
      rule_name: z.string(),
      reason: z.string(),
      lease: capabilityLease.nullish(),
    }),
    // `AuditResponseRecord` is `#[serde(tag = "kind")]` over four variants, two
    // of them NEWTYPE variants whose inner struct's fields sit BESIDE the tag
    // (`AMB crates/swarm-spine/src/lib.rs:102-110`). A success arm therefore
    // carries `ResponseReceipt`'s seven fields at the same level as `kind`, and
    // `catchall` is what admits them.
    response: z
      .object({
        kind: z.enum(["success", "failure", "skipped", "guard_rejected"]),
      })
      .catchall(z.unknown()),
    created_at_ms: unixMillis,
  }),
});

export const leaseFact = z.strictObject({
  schema: z.literal("ambush.perch.lease.v1"),
  ...locatorBase,
  locator: z.strictObject({
    lease_id: z.string(),
    case_channel: uuid,
    origin_receipt_id: z.string(),
    receipt_card_id: hex64.nullish(),
  }),
  lease: z.strictObject({
    schema_version: z.number().int(),
    lease_id: z.string(),
    action: responseAction,
    origin_receipt_id: z.string(),
    governance_receipt_id: z.string().nullish(),
    blast_radius: responseBlastRadiusPreview,
    rollback: responseRollbackPreview,
    issued_at_ms: unixMillis,
    expires_at_ms: unixMillis,
  }),
  ttl_source: z.literal("runtime.containment.lease_ttl_ms"),
});

export const rollbackFact = z.strictObject({
  schema: z.literal("ambush.perch.rollback.v1"),
  ...locatorBase,
  locator: z.strictObject({
    rollback_id: z.string(),
    lease_id: z.string(),
    case_channel: uuid,
    lease_card_id: hex64,
  }),
  rollback_receipt: z.strictObject({
    rollback_id: z.string(),
    lease_id: z.string(),
    origin_receipt_id: z.string(),
    governance_receipt_id: z.string().nullish(),
    trigger: rollbackTrigger,
    mode: executionMode,
    status: responseStatus,
    steps: z.array(
      z.strictObject({
        kind: z.string(),
        status: rollbackStepStatus,
        detail: z.string(),
      }),
    ),
    completed_at_ms: unixMillis,
    summary: z.string(),
    governance_attestation: z.unknown().optional(),
  }),
  release_response: z
    .strictObject({
      lease_closed: z.boolean(),
      fully_reversed: z.boolean(),
      attestation_verified: z.boolean(),
      attestation_error: z.string().nullish(),
    })
    .optional(),
  partition_state_at_execution: partitionState.nullish(),
});

export const cardFact = z.discriminatedUnion("schema", [
  findingFact,
  escalationFact,
  holdFact,
  verdictFact,
  receiptFact,
  leaseFact,
  rollbackFact,
]);

/**
 * The envelope.
 *
 * `signature` is `.optional()` and NOT `.nullable()`: present-as-null is a
 * different fact from absent, and B6's signing preimage excludes the field
 * entirely (`AMB crates/swarm-spine/src/envelope.rs:86-93` builds the unsigned
 * map without it). `envelope_hash` is REQUIRED because
 * `compute_envelope_hash_hex` takes no keypair (`:47-51`).
 */
export const cardEnvelope = z.strictObject({
  schema: z.literal("swarm.spine.envelope.v1"),
  issuer: spineIssuer,
  seq: z.number().int().positive(),
  prev_envelope_hash: hexPrefixed.nullable(),
  issued_at: z.string().regex(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/),
  capability_token: z.null(),
  fact: cardFact,
  envelope_hash: hexPrefixed,
  signature: hexPrefixed.optional(),
});

// ────────────────────────────────────────────────────────────────── frames

const frameHeader = {
  issuer: spineIssuer,
  emitted_at_ms: unixMillis,
  seq: z.number().int().positive(),
};

export const frame = z.discriminatedUnion("schema", [
  z.strictObject({
    schema: z.literal("ambush.perch.frame.ingest_rate.v1"),
    kind: z.literal(26000),
    ...frameHeader,
    window_ms: z.literal(1000),
    accepted: z.number().int().nonnegative(),
    rejected: z.number().int().nonnegative(),
    by_source: z.record(z.string(), z.number().int().nonnegative()),
  }),
  z.strictObject({
    schema: z.literal("ambush.perch.frame.concentration.v1"),
    kind: z.literal(26001),
    ...frameHeader,
    current_mode: swarmMode,
    concentrations: z.array(threatConcentration).min(12),
    coalesced_from: z.number().int().positive(),
    observed_at_seconds: unixSeconds,
  }),
  z.strictObject({
    schema: z.literal("ambush.perch.frame.agent_health.v1"),
    kind: z.literal(26002),
    ...frameHeader,
    agents: z.array(
      z.strictObject({
        agent_id: z.string(),
        role: agentRole,
        from: agentHealthState.nullish(),
        to: agentHealthState,
        changed_at_ms: unixMillis.nullish(),
        actions: z.record(z.string(), z.number().int().nonnegative()),
      }),
    ),
  }),
  z.strictObject({
    schema: z.literal("ambush.perch.frame.mode_transition.v1"),
    kind: z.literal(26003),
    ...frameHeader,
    from: swarmMode,
    to: swarmMode,
    triggering_threat_class: threatClass.nullish(),
    reason: z.string(),
  }),
  z.strictObject({
    schema: z.literal("ambush.perch.frame.governance_status.v1"),
    kind: z.literal(26004),
    ...frameHeader,
    partition_state: partitionState,
    total_governors: z.number().int().nonnegative(),
    healthy_governors: z.number().int().nonnegative(),
    quorum_threshold: z.number().int().nonnegative(),
    active_contingency_leases: z.number().int().nonnegative(),
    unauthorized_partition_actions: z.number().int().nonnegative(),
    last_transition_at_ms: unixMillis.nullish(),
    last_reconciliation_report_id: z.string().nullish(),
    contingency_lease_ttl_ms: z.number().int(),
  }),
  z.strictObject({
    schema: z.literal("ambush.perch.frame.tamper_alert.v1"),
    kind: z.literal(26005),
    ...frameHeader,
    debugger_attached: z.boolean(),
    tracer_pid: z.number().int().nullish(),
    unexpected_library_count: z.number().int().nonnegative(),
    unexpected_library_sha256: hexPrefixed,
    fail_closed: z.boolean(),
  }),
  z.strictObject({
    schema: z.literal("ambush.perch.frame.hold_alarm.v1"),
    kind: z.literal(26006),
    ...frameHeader,
    hold_id: holdId,
    action_kind: responseActionKind,
    severity,
    case_channel: uuid,
    expires_at_ms: unixMillis,
  }),
]);

// ──────────────────────────────────────────────────────────────── admission

/** Why a card or frame was not admitted. Counted, and the count is visible. */
export type AdmissionFailure =
  | "not-a-card"
  | "unadmitted-issuer"
  | "malformed-json"
  | "schema-mismatch";

/**
 * Admit one card body. **Never throws.**
 *
 * `signerPubkey` is the RAW EVENT SIGNER, not the display author. The
 * distinction is Buzz's own and its doc comment states why:
 * `getConfigNudgeAuthorPubkey`
 * (`desktop/src/features/messages/ui/configNudgeAuthPubkey.ts:22-34`)
 * authenticates against `message.signerPubkey` because `message.pubkey` "may be
 * a relay-delegated display author".
 *
 * INV-15 requires BOTH clauses: the marker must be the whole first line AND the
 * signer must resolve to an admitted bridge identity. A card that fails either
 * renders as untrusted prose through the ordinary markdown path.
 */
export function admitCard(
  json: string,
  signerPubkey: string | undefined,
  isAdmittedIssuer: (pubkey: string) => boolean,
): { ok: true; card: Card } | { ok: false; reason: AdmissionFailure } {
  if (!signerPubkey || !isAdmittedIssuer(signerPubkey)) {
    return { ok: false, reason: "unadmitted-issuer" };
  }
  let raw: unknown;
  try {
    raw = JSON.parse(json);
  } catch {
    return { ok: false, reason: "malformed-json" };
  }
  const parsed = cardEnvelope.safeParse(raw);
  if (!parsed.success) {
    return { ok: false, reason: "schema-mismatch" };
  }
  return { ok: true, card: Object.freeze(parsed.data) as unknown as Card };
}

/** Admit one ephemeral frame. Same two clauses, same never-throws contract. */
export function admitFrame(
  json: string,
  signerPubkey: string | undefined,
  isAdmittedIssuer: (pubkey: string) => boolean,
): { ok: true; frame: Frame } | { ok: false; reason: AdmissionFailure } {
  if (!signerPubkey || !isAdmittedIssuer(signerPubkey)) {
    return { ok: false, reason: "unadmitted-issuer" };
  }
  let raw: unknown;
  try {
    raw = JSON.parse(json);
  } catch {
    return { ok: false, reason: "malformed-json" };
  }
  const parsed = frame.safeParse(raw);
  if (!parsed.success) {
    return { ok: false, reason: "schema-mismatch" };
  }
  return { ok: true, frame: Object.freeze(parsed.data) as unknown as Frame };
}

/**
 * Verification tier, from the envelope alone.
 *
 * `08` §6.2 owns the taxonomy: tier 0 is "a secp256k1 Nostr signature over the
 * transport event, and nothing over the body"; tier 1 is "a detached Ed25519
 * signature over the body"; tier 2 is "a `build_signed_envelope` wrapper with
 * `seq` and `prev_envelope_hash`" — a signature AND a chain.
 *
 * The presence of `envelope_hash` does NOT raise the tier. It is keyless, so it
 * is a continuity fact and not an authorship fact, and a surface that reads it
 * as verification would be exactly the green check that document exists to
 * prevent.
 */
export function envelopeTier(card: Card): 0 | 1 | 2 {
  if (!card.signature) return 0;
  return card.prev_envelope_hash === null && card.seq === 1 ? 1 : 2;
}
