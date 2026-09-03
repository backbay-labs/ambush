// Target path in BUZZ: desktop/src/shared/api/tauriPerch.ts  (NEW file)
//
// Why a new file and not an edit to shared/api/tauri.ts: that file is 1108
// gate-lines and `allowedLineCount` (BUZZ scripts/check-file-sizes-core.mjs:31-33)
// pins an over-cap file's limit to its own size, so it cannot take one added
// line. Forty sibling files under shared/api already import `invokeTauri` from
// "./tauri" and export their own wrappers (measured this session).
//
// `invokeTauri` (BUZZ desktop/src/shared/api/tauri.ts:296-309) runs in the
// renderer, delegates to @tauri-apps/api/core `invoke`, normalises string /
// {message} / arbitrary-JSON rejections into TauriInvokeError, and sniffs the
// "relay rate-limited:" prefix so the TS relay client backs off in the same
// window. Perch inherits all of that unchanged.
//
// ---------------------------------------------------------------------------
// THE PROCESS BOUNDARY IS THE PRODUCT.
//
// Every function below crosses into the Tauri Rust process, which holds two
// secrets the webview must never see: the Ambush daemon bearer token, and the
// operator's Ed25519 signing key. INV-22 requires neither to appear in any
// value crossing back into the webview; INV-01 requires the set of non-GET
// requests the console issues to an Ambush host to be ENUMERABLE and to equal
// exactly five. Both are only enforceable if the HTTP path is a Rust constant.
//
// So: NO GENERIC PASSTHROUGH. There is deliberately no
// `perchDaemonRequest(method, path, body)`. One command per route, route
// string compiled into Rust. A grep over commands/perch_writes.rs is then a
// complete and honest answer to "what can this console do to the daemon".
// ---------------------------------------------------------------------------
//
// THE COMMAND COUNT, STATED THE WAY IT ACTUALLY ADDS UP.
//
//   7 reads          -> commands/perch_reads.rs   (GET, INV-01 does not gate)
//   5 daemon writes  -> commands/perch_writes.rs  (non-GET, INV-01's closed set)
//   1 relay write    -> commands/perch_verdict.rs (leg 1; INV-RF1's closed set)
//   ------------------------------------------------------------------------
//  13 new Tauri commands.
//
// An earlier draft of 14-CLIENT-ARCHITECTURE.md said "eleven … 7 reads + 5
// writes", which is neither eleven nor complete: it omitted
// `perch_record_verdict` entirely, and `perch_record_verdict` is the ONLY way
// leg 1 can be published. `perch_sign_gate` (16-INVARIANT-TESTS.md, INV-29)
// refuses every `ambush:<slug>:v<n>` marker through the generic `sign_event`
// command, so without this command the console as specified cannot publish
// leg 1 at all — a two-legged write with one leg. Corrected here and in 14 §7.3.
//
// Gate-line budget: 1000. Targets ~330.

import { invokeTauri } from "./tauri";

// --- shapes -----------------------------------------------------------------
// Field names mirror build/openapi/perch-operator-v1.yaml, which is the wire
// contract; only the ones this module needs to name are declared here, and
// every one is `readonly` so a caller cannot mutate a cached daemon answer in
// place.

/**
 * The pinned hold identifier: `hold_` plus a lowercase RFC 4122 v4 UUID, 41
 * characters (openapi/perch-operator-v1.yaml `HoldId`). Not derived from
 * `hunt_id` and not a v7 UUID — either would put investigation structure or
 * `held_at_ms` inside a token that rides the global `26006` frame.
 *
 * TypeScript cannot express the pattern, so the branded alias exists to make a
 * bare `string` at a call site visible in review; `isPerchHoldId` is the
 * runtime check the decoder runs once, at admission.
 */
export type PerchHoldId = string & { readonly __perchHoldId: unique symbol };

const HOLD_ID_RE =
  /^hold_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

export function isPerchHoldId(value: string): value is PerchHoldId {
  return HOLD_ID_RE.test(value);
}

export type PerchHoldSummary = {
  readonly hold_id: PerchHoldId;
  readonly action_kind: string;
  readonly severity: string;
  readonly case_channel: string;
  readonly held_at_ms: number;
  readonly expires_at_ms: number;
};

export type PerchDecision = "grant" | "refuse";

/**
 * `swarm_crypto::DetachedSignature`, the Ed25519 chain — NOT the secp256k1
 * Schnorr signature on the leg-1 relay card. ADR 0016 keeps the two chains
 * apart and every verification surface must say which one it checked.
 *
 * `public_key_hex` is load-bearing on the wire: the decide route derives
 * `voter_id` from it with `voter_id_from_public_key`
 * (AMB crates/swarm-runtime/src/approval.rs:1783-1785) and returns 403 unless
 * it binds to the authenticated principal. A bare signature string cannot
 * carry that, which is why this is an object.
 *
 * The PRIVATE half never appears in this file, in any return type, or in any
 * value crossing IPC — see commands/perch_verdict.rs.
 */
export type PerchDetachedSignature = {
  readonly algorithm: string;
  readonly key_id: string;
  readonly public_key_hex: string;
  readonly signature_hex: string;
};

export type PerchDecideOutcome = {
  /** Typed daemon outcome. `refused_late` is a NORMAL outcome, not an error. */
  readonly outcome:
    | "dispatched"
    | "refused_late"
    | "refused_late_governance"
    | "expired"
    | "unknown_hold"
    | "superseded";
  /** Populated on every refusal; rendered verbatim, never summarised. */
  readonly reason: string | null;
  readonly receipt_id: string | null;
  readonly decided_at_ms: number;
  /**
   * Present ONLY on `superseded`: the `nostr_intent_event_id` of the verdict
   * card whose decision the daemon actually executed. Two consoles can both
   * hold one open hold (APPENDIX-NORMATIVE.md §4 layer 1 `p`-tags every
   * `OperatorScope::Approve` principal), the daemon's compare-and-set picks
   * one, and this is how the loser learns which. See 14 §7.6.
   */
  readonly superseded_by: string | null;
};

export type PerchContainmentView = {
  readonly lease_id: string;
  readonly action_kind: string;
  readonly issued_at_ms: number;
  readonly expires_at_ms: number;
  /** Saturates at zero. Rendered on its own line, NEVER merged with `expired`. */
  readonly remaining_ms: number;
  /** True on a still-listed row means the sweep tried and failed. */
  readonly expired: boolean;
};

export type PerchReleaseOutcome = {
  /** Read this, not the HTTP status. */
  readonly lease_closed: boolean;
  readonly fully_reversed: boolean;
  readonly attestation_verified: boolean;
  readonly attestation_error: string | null;
  readonly steps: ReadonlyArray<{
    readonly step: string;
    /** One of exactly five: Reversed|Simulated|Irreversible|Unsupported|Failed. */
    readonly status: string;
  }>;
};

export type PerchFindingAction = "confirm" | "dismiss" | "investigate";

// ===========================================================================
// READS (7). Unconstrained by INV-01 (it gates non-GET only), but still one
// command per route for the same enumerability reason.
// ===========================================================================

/** B2r · GET /v1/response/holds. The queue's authority. */
export function perchListHolds() {
  return invokeTauri<PerchHoldSummary[]>("perch_list_holds");
}

/** B2r · GET /v1/response/holds/{hold_id}. Full record for the verdict pane. */
export function perchGetHold(holdId: PerchHoldId) {
  return invokeTauri<unknown>("perch_get_hold", { holdId });
}

/** GET /v1/operator/containment/leases. */
export function perchListContainments() {
  return invokeTauri<PerchContainmentView[]>("perch_list_containments");
}

/** B3r · GET /v1/operator/findings/reviewed?since_ms=. The served review map. */
export function perchReviewedFindings(sinceMs: number) {
  return invokeTauri<Record<string, unknown>>("perch_reviewed_findings", {
    sinceMs,
  });
}

/** B4 · GET /v1/operator/pheromone/deposits — post-suppression, post-evaporation. */
export function perchDeposits(threatClass: string) {
  return invokeTauri<unknown>("perch_deposits", { threatClass });
}

/** GET /v1/operator/status — alert_tuning + false_positive_tracking. */
export function perchOperatorStatus() {
  return invokeTauri<unknown>("perch_operator_status");
}

/**
 * Re-fetch one artifact and return the daemon's canonical bytes so the
 * PROVENANCE block can diff them against what the relay delivered. The Rust
 * side returns bytes, not a parsed object: INV-26's byte-identity claim cannot
 * survive a reserialize.
 */
export function perchVerifyArtifact(artifactId: string) {
  return invokeTauri<{ readonly canonical_bytes_b64: string }>(
    "perch_verify_artifact",
    { artifactId },
  );
}

export const PERCH_READ_COMMANDS = [
  "perch_list_holds",
  "perch_get_hold",
  "perch_list_containments",
  "perch_reviewed_findings",
  "perch_deposits",
  "perch_operator_status",
  "perch_verify_artifact",
] as const;

// ===========================================================================
// LEG 1 — THE RELAY WRITE (1). Lives in commands/perch_verdict.rs, deliberately
// NOT in perch_writes.rs, so `check-perch-write-allowlist.sh` reads exactly
// five daemon routes from that file and INV-RF1's relay allowlist reads exactly
// one publisher from this one. Two closed sets, two files, no arithmetic.
// ===========================================================================

/**
 * Build, sign and publish the leg-1 `swarm:verdict:v1` card, and return the
 * three values leg 2 needs.
 *
 * WHY THIS IS A COMMAND AND NOT RENDERER CODE. `perch_sign_gate`
 * (16-INVARIANT-TESTS.md INV-29) refuses any `kind:9` whose first line is an
 * `ambush:<slug>:v<n>` marker through the generic `sign_event` command
 * (BUZZ desktop/src-tauri/src/commands/identity.rs:107-135, Tauri Rust
 * process, signs with `state.signing_keys()` and returns the event JSON). That
 * refusal only means something if a sanctioned path exists, and this is it.
 *
 * WHAT THE RUST SIDE DOES, in order, in the Tauri process:
 *   1. GET the hold from the daemon by id (a read; INV-01 gates non-GET only)
 *      and refuse locally if it is not decidable. The card body is built from
 *      THAT answer, never from renderer-supplied fields, so a compromised
 *      webview cannot forge an ACTION sentence or a blast radius.
 *   2. Stamp `decided_at_ms` from the Rust clock.
 *   3. Sign the RFC 8785 canonical form of
 *      `{decided_at_ms, decision, hold_id, rationale_sha256}` with the
 *      operator's Ed25519 key. That is byte-identical to what the decide route
 *      verifies, so ONE signature serves both legs.
 *   4. Build the card (marker line, human line, blank line, fenced JSON
 *      envelope), sign the `kind:9` event with the Nostr secp256k1 identity,
 *      publish it, and return.
 *
 * `rationale` is inside the preimage as its SHA-256, which is why it is a
 * parameter here and not something the renderer can substitute later.
 */
export function perchRecordVerdict(input: {
  holdId: PerchHoldId;
  decision: PerchDecision;
  /** Free text the operator typed. Hashed into the signature preimage. */
  rationale: string | null;
  /** When the grant control was armed. Advisory, outside the preimage. */
  armedAtMs: number | null;
}) {
  return invokeTauri<{
    /** The published card's event id — leg 2's idempotency key. */
    readonly nostr_intent_event_id: string;
    readonly decided_at_ms: number;
    readonly signature: PerchDetachedSignature;
  }>("perch_record_verdict", input);
}

export const PERCH_RELAY_WRITE_COMMANDS = ["perch_record_verdict"] as const;

// ===========================================================================
// DAEMON WRITES (5). INV-01 asserts this set is closed; adding a sixth without
// amending the invariant fails the gate.
//
//   1 perch_decide_hold          POST /v1/response/holds/{id}/decide       (B2)
//   2 perch_finding_feedback     POST /v1/operator/findings/{id}/feedback  (B3)
//   3 perch_mint_incident        the incident-minting write behind promote (B3i)
//   4 perch_release_containment  POST /v1/operator/containment/leases/{id}/release
//   5 perch_create_review_session POST /v1/operator/review/sessions
// ===========================================================================

/**
 * LEG 2. The only call in this console that can cause an action to run, and it
 * goes to the daemon, never through the relay.
 *
 * EVERY FIELD HERE IS REQUIRED BY THE WIRE CONTRACT. `HoldDecisionRequest`
 * (openapi/perch-operator-v1.yaml) is
 * `required: [decision, decided_at_ms, nostr_intent_event_id, signature]` with
 * `additionalProperties: false`, and the daemon canonicalizes
 * `{decided_at_ms, decision, hold_id, rationale_sha256}` before verifying. An
 * earlier draft of this file omitted `decided_at_ms` and typed `signature` as a
 * bare string; every such request would have 422'd, and the 403 `voter_id`
 * binding could not have been derived at all.
 *
 * All three of `decidedAtMs`, `signature` and `nostrIntentEventId` come back
 * from `perchRecordVerdict` and are passed through unmodified. The renderer
 * does not compute them and cannot.
 */
export function perchDecideHold(input: {
  holdId: PerchHoldId;
  decision: PerchDecision;
  /** Verbatim from perchRecordVerdict. Its digest is inside the preimage. */
  rationale: string | null;
  /** Verbatim from perchRecordVerdict. Inside the preimage. */
  decidedAtMs: number;
  /** Verbatim from perchRecordVerdict. The idempotency key. */
  nostrIntentEventId: string;
  /** Verbatim from perchRecordVerdict. */
  signature: PerchDetachedSignature;
  /** Advisory, outside the preimage; the daemon does not enforce the dwell. */
  armedAtMs: number | null;
}) {
  return invokeTauri<PerchDecideOutcome>("perch_decide_hold", input);
}

/** B3 · POST /v1/operator/findings/{id}/feedback. analyst_id comes from the
 *  authenticated principal in Rust, NEVER from this body — the shipped handler
 *  takes it from the request body (AMB providence_handlers.rs:473-495) and B3
 *  changes that. */
export function perchFindingFeedback(input: {
  findingId: string;
  incidentId: string;
  action: PerchFindingAction;
  note: string | null;
}) {
  return invokeTauri<{ readonly recorded_at_ms: number }>(
    "perch_finding_feedback",
    input,
  );
}

/**
 * B3i · Mint a single-member IncidentRecord so a verdict on an uncorrelated
 * finding has somewhere to land. Without it the feedback route 404s forever
 * and promote-to-case leaves the verdict controls disabled permanently.
 */
export function perchMintIncident(input: {
  findingId: string;
  caseChannel: string;
  summary: string;
}) {
  return invokeTauri<{ readonly incident_id: string }>("perch_mint_incident", input);
}

/** POST /v1/operator/containment/leases/{id}/release. Read `lease_closed` from
 *  the returned body; a 200 does not mean released. */
export function perchReleaseContainment(leaseId: string) {
  return invokeTauri<PerchReleaseOutcome>("perch_release_containment", {
    leaseId,
  });
}

/** POST /v1/operator/review/sessions — the End-watch artifact. */
export function perchCreateReviewSession(input: {
  notes: string;
  caseChannels: readonly string[];
}) {
  return invokeTauri<{ readonly session_id: string }>(
    "perch_create_review_session",
    input,
  );
}

/**
 * The closed DAEMON write set, exported so INV-01's gate has a single import to
 * read rather than a regex over call sites. A command literal appearing in a
 * write position and absent from here is the failure the gate reports.
 *
 * `perch_record_verdict` is deliberately NOT in this array: it writes to the
 * relay, not to the daemon, and INV-RF1's relay allowlist is the invariant that
 * closes it. Merging the two sets would make INV-01's "exactly five non-GET
 * requests to an Ambush host" read six and be wrong.
 */
export const PERCH_DAEMON_WRITE_COMMANDS = [
  "perch_decide_hold",
  "perch_finding_feedback",
  "perch_mint_incident",
  "perch_release_containment",
  "perch_create_review_session",
] as const;

/**
 * Every Perch Tauri command, in one place, so the E2E mock bridge's delegated
 * module (14 §7.4) can assert it answers all of them and the count in 14 §7.3
 * cannot drift from the file.
 */
export const PERCH_TAURI_COMMANDS = [
  ...PERCH_READ_COMMANDS,
  ...PERCH_RELAY_WRITE_COMMANDS,
  ...PERCH_DAEMON_WRITE_COMMANDS,
] as const;
