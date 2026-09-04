/**
 * SKELETON. Lands as BUZZ `desktop/src/features/perch/wire/types.ts`.
 *
 * The mirrored TypeScript types. These are the shapes the renderer holds; `zod.ts`
 * is the runtime gate that produces them and is the only place a `Card` or a
 * `Frame` may be constructed from an untrusted string.
 *
 * # This file may not live in `shared/api/`
 *
 * `desktop/src/shared/api/types.ts` is at EXACTLY 1000 gate-lines, and the
 * file-size gate (`BUZZ scripts/check-file-sizes-core.mjs:24-33`) counts
 * `content.split(/\r?\n/).length` — `wc -l` plus one for a newline-terminated
 * file — and sets `limit = max(baseLines, 1000)`, so an at-or-over-cap file is
 * FROZEN and cannot take one added line. `shared/api/tauri.ts` (1108) and
 * `shared/api/relayClientSession.ts` (1084) are in the same state. All three sit
 * in a governed root (`desktop/scripts/check-file-sizes.mjs:10-55` governs
 * `src/shared/api`). Perch's wire types therefore live under
 * `src/features/perch/`, which is also governed but empty.
 *
 * # Two clock domains, typed apart
 *
 * Pheromone timestamps are UNIX SECONDS — `PheromoneDeposit::timestamp`,
 * `decay_half_life`, and the `now` argument to `strength_at` / `is_evaporated` /
 * `query_concentration`, all produced by `unix_timestamp_secs`
 * (`AMB crates/swarm-runtime/src/escalation.rs:407-410`). Everything else is
 * UNIX MILLISECONDS, produced by `now_ms`
 * (`AMB crates/swarm-runtime/src/runtime_events.rs:341-346`). A shared `now()`
 * helper produces a 1000x wrong decay curve, silently, in the direction of
 * "everything looks evaporated".
 *
 * The brands below are the whole mitigation. **No conversion helper is
 * exported**, deliberately: crossing domains requires naming the conversion at
 * the call site.
 */

// ─────────────────────────────────────────────────────────── clock domains

declare const unixMillisBrand: unique symbol;
declare const unixSecondsBrand: unique symbol;

/** Milliseconds since the unix epoch. Ambush's default clock domain. */
export type UnixMillis = number & { readonly [unixMillisBrand]: true };
/** Seconds since the unix epoch. The pheromone substrate's domain, and only it. */
export type UnixSeconds = number & { readonly [unixSecondsBrand]: true };

// ───────────────────────────────────────────────────────────────── enums
//
// Every one of these was read from the Rust type and its serde attribute this
// session. `common.schema.json` carries the same values with the source line
// range for each; `check:perch-wire` asserts the three agree.

/**
 * `AMB crates/swarm-core/src/types.rs:406-414` —
 * `#[serde(rename_all = "SCREAMING_SNAKE_CASE")]`, THE ONLY ENUM IN THE
 * WORKSPACE THAT DOES. Roughly forty siblings are snake_case, so any codegen
 * that lowercases uniformly breaks exactly this field. Also the `l` tag's value.
 */
export const SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"] as const;
export type Severity = (typeof SEVERITIES)[number];

/** The twelve standard classes (`AMB crates/swarm-runtime/src/escalation.rs:315-330`). */
export const STANDARD_THREAT_CLASSES = [
  "lateral_movement",
  "data_exfiltration",
  "privilege_escalation",
  "command_and_control",
  "initial_access",
  "persistence",
  "supply_chain",
  "defense_evasion",
  "credential_access",
  "discovery",
  "execution",
  "impact",
] as const;

/**
 * `AMB crates/swarm-core/src/pheromone.rs:13-30` — twelve unit variants plus
 * `Custom(String)`, EXTERNALLY tagged. Serde makes the unit variants bare
 * strings and the newtype variant the single-key object `{"custom": "..."}`.
 *
 * A parser that assumes this is always a string throws on a Custom class, and
 * two production agents mint them: Sphinx (`sphinx_agent.rs:610`) and Calico
 * (`calico_agent.rs:440`).
 */
export type ThreatClass =
  | (typeof STANDARD_THREAT_CLASSES)[number]
  | { readonly custom: string };

/** `AMB crates/swarm-core/src/agent.rs:14-34`, a closed eight-variant enum. */
export const AGENT_ROLES = [
  "whisker",
  "stalker",
  "weaver",
  "pouncer",
  "tom",
  "kitten",
  "sphinx",
  "calico",
] as const;
export type AgentRole = (typeof AGENT_ROLES)[number];

/** `AMB crates/swarm-core/src/agent.rs:36-45`. */
export type AgentHealthState = "healthy" | "degraded" | "failed";

/**
 * `AMB crates/swarm-core/src/agent.rs:109-119`. NOT MONOTONIC:
 * `transition_down` (`:148-155`) exists beside `transition_to` (`:137-146`), so
 * every surface must render de-escalation.
 */
export type SwarmMode = "normal" | "alert" | "incident";

/** `AMB crates/swarm-policy/src/lib.rs:84-90`. */
export type PolicyVerdict = "deny" | "allow" | "require_human";

/** `AMB crates/swarm-response/src/lib.rs:88-96`. */
export type ExecutionMode = "dry_run" | "enforced";

/** `AMB crates/swarm-response/src/lib.rs:143-152`. */
export type ResponseStatus = "simulated" | "executed" | "timeout" | "failed";

/**
 * `ResponseAction::kind()` (`AMB crates/swarm-core/src/types.rs:558-576`).
 *
 * Fifteen values. Twelve are destructive and human-gated
 * (`AMB crates/swarm-policy/src/static_gate.rs:37-53`); of those twelve only
 * FOUR are containment actions and therefore ever mint a containment lease
 * (`AMB crates/swarm-runtime/src/containment.rs:54-63`); of those four only
 * THREE have an executable inverse
 * (`AMB crates/swarm-response/src/rollback.rs:66-78`).
 * **12 → 4 → 3.** The eight unleased destructive kinds open no containment lease, no TTL, no
 * countdown and no rollback receipt, so a hold card for one of them must not
 * render a pending containment-lease slot.
 */
export const RESPONSE_ACTION_KINDS = [
  "block_egress",
  "isolate_host",
  "revoke_credential",
  "sinkhole_dns",
  "terminate_user_session",
  "trigger_edr_scan",
  "inject_firewall_rule",
  "quarantine_file",
  "kill_process",
  "suspend_process",
  "disable_user_account",
  "force_password_reset",
  "remove_scheduled_task",
  "deploy_decoy",
  "escalate",
] as const;
export type ResponseActionKind = (typeof RESPONSE_ACTION_KINDS)[number];

/** The four of the twelve that mint a containment lease. */
export const CONTAINMENT_ACTION_KINDS = [
  "quarantine_file",
  "suspend_process",
  "isolate_host",
  "terminate_user_session",
] as const satisfies readonly ResponseActionKind[];

/** `AMB crates/swarm-response/src/rollback.rs:208-223` — exactly five. */
export type RollbackStepStatus =
  | "reversed"
  | "simulated"
  | "irreversible"
  | "unsupported"
  | "failed";

/** `AMB crates/swarm-response/src/rollback.rs:40-48`. */
export type RollbackTrigger = "manual" | "expiry";

/** `AMB crates/swarm-policy/src/governance.rs:46-54` — exactly four. */
export type PartitionState = "healthy" | "degraded" | "partitioned" | "healing";

/** `AMB crates/swarm-runtime/src/runtime_events.rs:184-189`. */
export type EscalationLevel = "alert" | "incident";

// ───────────────────────────────────────────────────────── structural types

/**
 * `ResponseAction`, `#[serde(tag = "type", rename_all = "snake_case")]` at
 * `AMB crates/swarm-core/src/types.rs:416-467` — INTERNALLY tagged, so it is
 * `{"type":"isolate_host","host_id":"web-04"}` and never
 * `{"isolate_host":{...}}`. The variant payload sits beside the tag.
 *
 * Left open rather than enumerated as fifteen shapes because Perch is a READER
 * of this type and never an author: the decide route takes only a `hold_id`.
 */
export type ResponseAction = {
  readonly type: ResponseActionKind;
  readonly [field: string]: unknown;
};

/** `AMB crates/swarm-policy/src/lib.rs:73-83`. */
export type PolicyDecision = {
  readonly verdict: PolicyVerdict;
  readonly rule_name: string;
  readonly reason: string;
};

/** `AMB crates/swarm-crypto/src/lib.rs:48-55` — the Ed25519 chain. */
export type DetachedSignature = {
  readonly algorithm: string;
  readonly key_id: string;
  readonly public_key_hex: string;
  readonly signature_hex: string;
};

/**
 * WHO PRODUCED THE FACT. Distinct from the envelope's `issuer`, which is WHO
 * PUBLISHED IT. `nostr_pubkey` is null in every deployment today: no Ambush
 * agent holds a Nostr keypair and no config field carries one
 * (`AMB crates/swarm-core/src/config/operator.rs:116-129` has
 * `deny_unknown_fields` and no such field).
 */
/**
 * An opaque hold token, `^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$`
 * (`common.schema.json#/$defs/HoldId`). URL-safe because it is a path parameter
 * on `POST /v1/response/holds/{hold_id}/decide`, and COLON-FREE so the forbidden
 * `hold:{hunt_id}:{held_at_ms}` derived form cannot be published. A nominal alias
 * rather than a branded type: the runtime check lives in `zod.ts`'s `holdId`, and
 * `tsc` cannot enforce a regex.
 */
export type HoldId = string;

export type FactIssuer = {
  readonly swarm_agent_id: string;
  /**
   * NULLABLE AND REQUIRED, and both words matter.
   *
   * Two production paths fill this and they disagree. `WhiskerAgent::tick`
   * passes `Some(AgentRole::Whisker)` explicitly into
   * `detect_and_deposit_with_role`
   * (`AMB crates/swarm-agents/src/whisker_agent.rs:150-156`, inside
   * `swarm_detect --serve`), so a finding produced there carries a role. But
   * `infer_agent_role`
   * (`AMB crates/swarm-runtime/src/detection/pipeline.rs:583-604`) is a prefix
   * match over `whisker-` / `stalker-` / `weaver-` / `pounce(r)-` / `tom-` /
   * `kitten-` / `sphinx-` / `calico-` and returns `None` for anything else —
   * including every `swarm:ed25519:<hex>` identity the HTTP ingest lane uses.
   *
   * `null` means "the producing path could not name a role", NOT "no agent". A
   * component renders the absence; it never substitutes a role.
   *
   * Required, not optional: a MISSING key must be a decode error while a genuine
   * absence is an explicit `null`. `13-WIRE-SCHEMAS.md` amendment `W-A1`.
   */
  readonly role: AgentRole | null;
  readonly nostr_pubkey?: string | null;
};

/**
 * WHO PRODUCED THE FACT, when the producer is a PERSON.
 *
 * Used by `swarm:verdict:v1` and nothing else — the one card in the registry a
 * human, not the bridge, publishes. `role` is `null` and cannot be anything
 * else: `AgentRole` is a closed eight-variant enum of SWARM agents
 * (`AMB crates/swarm-core/src/agent.rs:14-34`) with no human member, and
 * `AgentRole.Tom` is "Governance — enforces policy, manages lifecycle"
 * (`agent.rs:26-27`) — the VETO actor. Stamping `tom` on an operator's own
 * decision conflates the human's *refuse* with governance's *veto*, which
 * `APPENDIX-NORMATIVE.md` §7 forbids and `adr/0016` spends a document keeping
 * apart. A distinct type makes the conflation a `tsc` error.
 */
export type OperatorFactIssuer = {
  readonly swarm_agent_id: string;
  readonly role: null;
  /** The operator's OWN Nostr pubkey — the signer of the leg-1 event. */
  readonly nostr_pubkey?: string | null;
};

/**
 * The `swarm.spine.envelope.v1` wrapper
 * (`AMB crates/swarm-spine/src/envelope.rs:71-101`).
 *
 * `signature` is absent until B6, and its absence pins the card at verification
 * tier 0 regardless of `envelope_hash` — a keyless hash is a continuity fact,
 * not an authorship fact, and `08` §6.2 defines tier 1 as a detached Ed25519
 * signature over the body.
 */
export type CardEnvelope<F> = {
  readonly schema: "swarm.spine.envelope.v1";
  readonly issuer: string;
  readonly seq: number;
  readonly prev_envelope_hash: string | null;
  readonly issued_at: string;
  readonly capability_token: null;
  readonly fact: F;
  readonly envelope_hash: string;
  readonly signature?: string;
};

/** `AMB crates/swarm-runtime/src/runtime_events.rs:191-196`. */
export type ThreatConcentration = {
  readonly threat_class: ThreatClass;
  readonly total_strength: number;
  /**
   * **Never render bare.** Counts AGENT INSTANCE ids —
   * `sources.insert(deposit.agent_id.0.clone())`
   * (`AMB crates/swarm-pheromone/src/substrate.rs:1295`), reported as
   * `sources.len()` at `:1301` — while `WhiskerAgent::tick` derives ONE id per
   * agent (`AMB crates/swarm-agents/src/whisker_agent.rs:148-149`). One Whisker
   * running four detectors is ONE source and FAILS
   * `min_sources_for_escalation: 2`.
   */
  readonly distinct_sources: number;
  readonly peak_confidence: number;
};

// ───────────────────────────────────────────────────────────── card facts
//
// One type per marker. Full field lists live in the JSON Schemas; these mirror
// them and `check:perch-wire` asserts the field sets are equal.

export type FindingFact = {
  readonly schema: "swarm.perch.finding.v1";
  readonly issuer: FactIssuer;
  readonly emitted_at_ms: UnixMillis;
  readonly locator: {
    readonly finding_id: string;
    /** The TELEMETRY event id — half of the Dismiss suppression key. */
    readonly event_id: string;
    readonly strategy_id: string;
    /** From the `RuntimeEvent::Finding` WRAPPER, not from the envelope. */
    readonly host_id?: string | null;
    readonly lane_channel: string;
  };
  readonly finding: {
    readonly schema: "swarm_finding";
    readonly finding_id: string;
    readonly event_id: string;
    readonly strategy_id: string;
    readonly threat_class: ThreatClass;
    readonly severity: Severity;
    readonly confidence: number;
    /** ADVERSARY-SHAPED. Every string reached from here needs `<AdversaryString>` (INV-14). */
    readonly evidence: unknown;
    readonly evidence_truncated?: { readonly bytes: number; readonly sha256: string };
  };
};

export type EscalationFact = {
  readonly schema: "swarm.perch.escalation.v1";
  readonly issuer: FactIssuer;
  readonly emitted_at_ms: UnixMillis;
  readonly locator: {
    readonly lane_channel: string;
    readonly case_channel?: string | null;
  };
  readonly escalation:
    | {
        readonly cause: "concentration_crossing";
        readonly threat_class: ThreatClass;
        readonly level: EscalationLevel;
        readonly total_strength: number;
        /**
         * Never render this bare. See `distinct_sources_counts` for the unit and
         * `source_ids_absent_reason` for why the other half of render law 2 is
         * not derivable in Phase 1.
         */
        readonly distinct_sources: number;
        /**
         * The counting unit: the STRATEGY-SCOPED agent id
         * `{derived_identity}:{agent_id}:{strategy_id}`, NOT the agent instance.
         * `resolve_deposits` sets every deposit's
         * `agent_id: strategy_scoped_agent_id(agent_id, &finding.strategy_id)`
         * (`AMB crates/swarm-runtime/src/detection/pipeline.rs:573`, reached from
         * `detect_and_deposit_with_role` at `:80`), `strategy_scoped_agent_id` is
         * `format!("{}:{strategy_id}", base.0)`
         * (`AMB crates/swarm-whisker/src/stream.rs:20-22`), and
         * `concentration_for` inserts that string into the sources set
         * (`AMB crates/swarm-pheromone/src/substrate.rs:1295`). The base is
         * ALREADY instance-scoped (`whisker_agent.rs:148-149`), so the count is
         * per detector: one Whisker with two detectors is TWO sources / ONE agent.
         *
         * CONSEQUENCE: `APPENDIX-NORMATIVE.md` §8 render law 2 stands exactly as
         * written and `N sources / M agents` is two different numbers.
         */
        readonly distinct_sources_counts: "strategy_scoped_agent_id";
        /**
         * The ids themselves, or `null` with a NAMED reason in the sibling field.
         * `null` on every Phase-1 card: `RuntimeEvent::Escalation` carries a count
         * and no ids (`AMB crates/swarm-runtime/src/runtime_events.rs:288-296`)
         * and the bridge holds no substrate handle. Only B4 (Phase 2) can serve
         * them. Post-B4 a consumer derives the agent half by dropping the last
         * colon-separated segment and counting the distinct remainder.
         */
        readonly source_ids: readonly string[] | null;
        /**
         * Why `source_ids` is null, as a value rather than an implication.
         * Exactly one of this and `source_ids` is null. A component renders THIS
         * REASON — never a fabricated agent count, never a spinner.
         */
        readonly source_ids_absent_reason: SourceIdsAbsentReason | null;
        readonly peak_confidence: number;
        readonly mode_changed: boolean;
        readonly current_mode: SwarmMode;
        readonly dedupe_key: string;
      }
    | {
        readonly cause: "mode_transition";
        readonly from: SwarmMode;
        readonly to: "incident";
        readonly triggering_threat_class?: ThreatClass | null;
        readonly reason: string;
      }
    | {
        readonly cause: "tamper_fail_closed";
        readonly debugger_attached: boolean;
        readonly tracer_pid?: number | null;
        readonly unexpected_library_count: number;
        readonly unexpected_library_sha256: string;
        /** Card only. Never on the global `26005` frame. */
        readonly unexpected_library_loads: readonly string[];
        readonly fail_closed: true;
        /** Card only. */
        readonly details: string;
      };
};

export type HoldState =
  | "created"
  | "notified"
  | "armed"
  | "deciding"
  | "granted"
  | "refused"
  | "expired"
  | "executed"
  | "failed";

/** `grant` | `refuse`. **Never `deny`** — appendix §7 keeps the three verbs apart. */
export type Decision = "grant" | "refuse";

export type HoldFact = {
  readonly schema: "swarm.perch.hold.v1";
  readonly issuer: FactIssuer;
  readonly emitted_at_ms: UnixMillis;
  readonly locator: {
    /** Opaque random token. Never derived from `hunt_id`. */
    readonly hold_id: string;
    readonly case_channel: string;
    readonly hunt_id: string;
    readonly finding_card_id?: string | null;
  };
  readonly hold: {
    readonly hold_id: string;
    readonly state: HoldState;
    readonly action_kind: ResponseActionKind;
    readonly severity: Severity;
    readonly held_at_ms: UnixMillis;
    readonly expires_at_ms: UnixMillis;
    readonly action_request: {
      readonly hunt_id: string;
      /** An Ambush AgentId. NOT a Nostr pubkey; no mapping to one exists. */
      readonly requested_by: string;
      readonly action: ResponseAction;
      /** REQUEST-CARRIED. The agent that wants the action sets this. */
      readonly severity: Severity;
      readonly evidence: Record<string, unknown>;
    };
    readonly policy_decision: PolicyDecision;
    readonly rationale: {
      readonly rule_name: string;
      readonly reason: string;
      readonly threat_class: ThreatClass;
      readonly severity: Severity;
      readonly request_carried_fields: readonly string[];
      readonly concentration_at_hold?: ThreatConcentration | null;
      readonly escalation_level?: EscalationLevel | null;
      readonly governance_receipt_present: boolean;
    };
    /**
     * `is_containment_action` (`AMB crates/swarm-runtime/src/containment.rs:54-63`).
     * FALSE means render NO pending containment-lease slot, not an empty one.
     */
    readonly leases_a_containment: boolean;
    readonly rehearsal?: unknown | null;
    /** DERIVED, NOT SERVED. The console names `resolve_inverse` beside the row. */
    readonly inverse_resolution: readonly {
      readonly step_kind: string;
      readonly verdict: "executable" | "irreversible" | "unmapped";
      readonly reason?: string | null;
    }[];
    readonly decision?: unknown | null;
  };
};

/** Why `source_ids` is absent. Exactly one reason exists today. */
export type SourceIdsAbsentReason = "not_carried_by_runtime_event";

/**
 * The five leg-2 outcomes. Closed; a sixth is a wire change.
 *
 * `superseded` is the two-operator case. `APPENDIX-NORMATIVE.md` §4 layer 1
 * `p`-tags EVERY `OperatorScope.Approve` principal, so two consoles can hold the
 * same open hold; leg 1 is published BEFORE leg 2 is POSTed, the relay has no
 * compare-and-set, and a `kind:9` event is immutable — so both signed cards land
 * in the case channel forever. `12-BACKEND-BILL-API.md` §4.4 resolves the daemon
 * side (409); this value is the relay side, published by whichever console gets
 * the 409.
 */
export type Leg2Outcome =
  | "sending"
  | "recorded"
  | "acknowledged"
  | "refused_late"
  | "superseded";

export type VerdictFact = {
  readonly schema: "swarm.perch.verdict.v1";
  /** A PERSON produced this fact. See `OperatorFactIssuer` for why it is its own type. */
  readonly issuer: OperatorFactIssuer;
  readonly emitted_at_ms: UnixMillis;
  readonly locator: {
    readonly hold_id: HoldId;
    readonly case_channel: string;
    readonly hold_card_id: string;
  };
  readonly decision: {
    readonly decision: Decision;
    readonly hold_id: string;
    readonly decided_at_ms: UnixMillis;
    readonly operator_id: string;
    /** SHA-256 of the UTF-8 rationale, or JSON `null` when absent. */
    readonly rationale_sha256: string | null;
    readonly rationale?: string | null;
  };
  /**
   * Ed25519 over the canonical form of
   * `{decided_at_ms, decision, hold_id, rationale_sha256}` —
   * exactly the decide route's preimage, so one signature serves both legs.
   */
  readonly signature: DetachedSignature;
  readonly leg2?:
    | {
        readonly state: Exclude<Leg2Outcome, "superseded">;
        readonly receipt_id?: string | null;
        readonly refusal_check?: string | null;
        readonly superseded_by?: null;
        readonly superseded_at_ms?: null;
      }
    | {
        readonly state: "superseded";
        readonly receipt_id?: string | null;
        readonly refusal_check?: string | null;
        /**
         * The WINNING leg-1 card's Nostr event id — the `nostr_intent_event_id`
         * the daemon recorded, read out of the 409 body. Non-optional on this
         * branch so a reader can always link the loser to the winner.
         */
        readonly superseded_by: string;
        /** When THIS console learned it had lost. Its own clock at the 409. */
        readonly superseded_at_ms: UnixMillis;
      };
};

export type ReceiptFact = {
  readonly schema: "swarm.perch.receipt.v1";
  readonly issuer: FactIssuer;
  readonly emitted_at_ms: UnixMillis;
  readonly locator: {
    readonly trail_id: string;
    readonly hunt_id: string;
    readonly case_channel: string;
    readonly receipt_id?: string | null;
    readonly verdict_card_id?: string | null;
  };
  /**
   * `AuditTrail` (`AMB crates/swarm-spine/src/lib.rs:112-122`).
   *
   * `response` is `AuditResponseRecord`, `#[serde(tag = "kind")]` over four
   * variants, TWO OF WHICH ARE NEWTYPE VARIANTS: a success arm is
   * `{"kind":"success", ...ResponseReceipt's seven fields}`, flattened beside
   * the tag, NOT `{"kind":"success","0":{...}}` and not `{"success":{...}}`.
   */
  readonly audit_trail: {
    readonly trail_id: string;
    readonly hunt_id: string;
    readonly related_receipt_ids: readonly string[];
    readonly detection: unknown;
    readonly policy: {
      readonly verdict: PolicyVerdict;
      readonly rule_name: string;
      readonly reason: string;
      readonly lease?: unknown | null;
    };
    readonly response: { readonly kind: "success" | "failure" | "skipped" | "guard_rejected" } & Record<
      string,
      unknown
    >;
    readonly created_at_ms: UnixMillis;
  };
};

export type LeaseFact = {
  readonly schema: "swarm.perch.lease.v1";
  readonly issuer: FactIssuer;
  readonly emitted_at_ms: UnixMillis;
  readonly locator: {
    readonly lease_id: string;
    readonly case_channel: string;
    readonly origin_receipt_id: string;
    readonly receipt_card_id?: string | null;
  };
  /**
   * `ContainmentLeaseRecord` — the persisted form, NOT `ContainmentLeaseView`.
   * `remaining_ms` and `expired` are clock-derived and the card is immutable;
   * the console recomputes both and renders them as two elements (INV-06).
   */
  readonly lease: {
    readonly schema_version: number;
    readonly lease_id: string;
    readonly action: ResponseAction;
    readonly origin_receipt_id: string;
    readonly governance_receipt_id?: string | null;
    readonly blast_radius: unknown;
    readonly rollback: unknown;
    readonly issued_at_ms: UnixMillis;
    readonly expires_at_ms: UnixMillis;
  };
  /** Which config key the TTL came from. 900_000 default, NOT the 60_000 policy one. */
  readonly ttl_source: "runtime.containment.lease_ttl_ms";
};

export type RollbackFact = {
  readonly schema: "swarm.perch.rollback.v1";
  readonly issuer: FactIssuer;
  readonly emitted_at_ms: UnixMillis;
  readonly locator: {
    readonly rollback_id: string;
    readonly lease_id: string;
    readonly case_channel: string;
    readonly lease_card_id: string;
  };
  readonly rollback_receipt: {
    readonly rollback_id: string;
    readonly lease_id: string;
    readonly origin_receipt_id: string;
    readonly governance_receipt_id?: string | null;
    readonly trigger: RollbackTrigger;
    readonly mode: ExecutionMode;
    readonly status: ResponseStatus;
    readonly steps: readonly {
      readonly kind: string;
      readonly status: RollbackStepStatus;
      readonly detail: string;
    }[];
    readonly completed_at_ms: UnixMillis;
    readonly summary: string;
    /** Opaque. Only `verify_release_attestation` may decide whether it is valid. */
    readonly governance_attestation?: unknown;
  };
  /** Present only for `trigger === "manual"`. Read `lease_closed`, never the HTTP status. */
  readonly release_response?: {
    readonly lease_closed: boolean;
    readonly fully_reversed: boolean;
    readonly attestation_verified: boolean;
    readonly attestation_error?: string | null;
  };
  /** `partitioned` or `healing` means `UNATTESTED — BY DESIGN` (INV-08). */
  readonly partition_state_at_execution?: PartitionState | null;
};

/** Every card fact, discriminated on `schema`. */
export type CardFact =
  | FindingFact
  | EscalationFact
  | HoldFact
  | VerdictFact
  | ReceiptFact
  | LeaseFact
  | RollbackFact;

/** A parsed, admitted card. */
export type Card = CardEnvelope<CardFact>;

// ────────────────────────────────────────────────────────────────── frames

export type FrameHeader = {
  readonly kind: number;
  /** Display only. The admission check reads the EVENT's `pubkey`. */
  readonly issuer: string;
  readonly emitted_at_ms: UnixMillis;
  readonly seq: number;
};

export type Frame =
  | (FrameHeader & {
      readonly schema: "swarm.perch.frame.ingest_rate.v1";
      readonly kind: 26000;
      readonly window_ms: 1000;
      readonly accepted: number;
      readonly rejected: number;
      readonly by_source: Readonly<Record<string, number>>;
    })
  | (FrameHeader & {
      readonly schema: "swarm.perch.frame.concentration.v1";
      readonly kind: 26001;
      readonly current_mode: SwarmMode;
      readonly concentrations: readonly ThreatConcentration[];
      /** Derived marker: the console is showing 1 of N snapshots and says so. */
      readonly coalesced_from: number;
      /** SECONDS, in its native unit, with the unit in the name. */
      readonly observed_at_seconds: UnixSeconds;
    })
  | (FrameHeader & {
      readonly schema: "swarm.perch.frame.agent_health.v1";
      readonly kind: 26002;
      readonly agents: readonly {
        readonly agent_id: string;
        readonly role: AgentRole;
        readonly from?: AgentHealthState | null;
        readonly to: AgentHealthState;
        readonly changed_at_ms?: UnixMillis | null;
        /** `AgentAction` tallies. `details` and `hunt_id` never cross the wire. */
        readonly actions: Readonly<Record<string, number>>;
      }[];
    })
  | (FrameHeader & {
      readonly schema: "swarm.perch.frame.mode_transition.v1";
      readonly kind: 26003;
      readonly from: SwarmMode;
      readonly to: SwarmMode;
      readonly triggering_threat_class?: ThreatClass | null;
      readonly reason: string;
    })
  | (FrameHeader & {
      readonly schema: "swarm.perch.frame.governance_status.v1";
      readonly kind: 26004;
      readonly partition_state: PartitionState;
      readonly total_governors: number;
      readonly healthy_governors: number;
      readonly quorum_threshold: number;
      readonly active_contingency_leases: number;
      readonly unauthorized_partition_actions: number;
      readonly last_transition_at_ms?: UnixMillis | null;
      readonly last_reconciliation_report_id?: string | null;
      /** 300_000 default, not 60_000. `06` §2.2 cites a test fixture. */
      readonly contingency_lease_ttl_ms: number;
    })
  | (FrameHeader & {
      readonly schema: "swarm.perch.frame.tamper_alert.v1";
      readonly kind: 26005;
      readonly debugger_attached: boolean;
      readonly tracer_pid?: number | null;
      /** COUNTS, NOT PATHS. The paths ride the durable lane-channel card. */
      readonly unexpected_library_count: number;
      readonly unexpected_library_sha256: string;
      readonly fail_closed: boolean;
    })
  | (FrameHeader & {
      readonly schema: "swarm.perch.frame.hold_alarm.v1";
      readonly kind: 26006;
      readonly hold_id: string;
      readonly action_kind: ResponseActionKind;
      readonly severity: Severity;
      readonly case_channel: string;
      readonly expires_at_ms: UnixMillis;
    });
