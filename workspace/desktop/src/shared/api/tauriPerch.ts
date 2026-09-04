import { invokeTauri } from "./tauri";

/**
 * The console's whole Tauri surface for the operator daemon and for leg 1.
 *
 * A new file rather than an edit to `tauri.ts`: that file is at the file-size
 * ratchet's ceiling and cannot take a line.
 *
 * # The process boundary is the product
 *
 * Every function here crosses into the Tauri Rust process, which holds two
 * secrets the webview must never see: the daemon bearer token and the
 * operator's Ed25519 signing key. Neither appears in any value crossing back.
 *
 * INV-01 requires the set of non-GET requests this console can issue to a
 * daemon host to be enumerable and to equal exactly five. That is only
 * enforceable if the HTTP path is a Rust constant, so there is deliberately no
 * `perchDaemonRequest(method, path, body)`: one command per route, the route
 * string compiled into Rust. First card implements two of the five daemon
 * writes; `tools/check-perch-write-allowlist.sh` reads the table.
 */

/** `confirm | dismiss | investigate` — the three verdicts a finding admits. */
export type PerchFindingAction = "confirm" | "dismiss" | "investigate";

/**
 * The Ed25519 chain, not the secp256k1 Schnorr signature on the leg-1 relay
 * card. Every verification surface must say which chain it checked.
 *
 * `public_key_hex` is load-bearing on the wire: the daemon derives the voter
 * id from it and refuses a signature that does not bind to the authenticated
 * principal. The private half never appears in this file, in any return type,
 * or in any value crossing IPC.
 */
export type PerchDetachedSignature = {
  readonly algorithm: string;
  readonly key_id: string;
  readonly public_key_hex: string;
  readonly signature_hex: string;
};

/** One finding the daemon has already ruled on (B3r). */
export type PerchReviewedFinding = {
  readonly finding_id: string;
  readonly reviewed_at_ms: number;
  readonly action: PerchFindingAction;
  readonly analyst_id: string;
  readonly false_positive: boolean;
  readonly incident_id: string;
  readonly strategy_id: string;
  readonly host_id: string | null;
};

/**
 * B3r's honest window: what the daemon has ruled on, and how much of its own
 * record that window actually covers.
 */
export type PerchReviewedFindingsResponse = {
  readonly schema_version: number;
  readonly observed_at_ms: number;
  readonly reviewed: readonly PerchReviewedFinding[];
  readonly window_incident_count: number;
  readonly window_is_truncated: boolean;
  readonly window_oldest_incident_at_ms: number | null;
  readonly store_durable: boolean;
};

/** The admitted bridge identities and the lane channel ids (D-FC-2). */
export type PerchAdmittedIssuers = {
  readonly issuers: readonly string[];
  readonly lanes: Readonly<Record<string, string>>;
  readonly colony_id: string;
};

/** What B3 records once leg 2 lands. */
export type PerchFindingFeedbackResponse = {
  readonly schema_version: number;
  readonly feedback_id: string;
  readonly action: PerchFindingAction;
  readonly incident_id: string;
  readonly finding_id: string;
  readonly analyst_id: string;
  readonly false_positive: boolean;
  readonly replayed: boolean;
  readonly outcome: unknown;
};

/** What B3i answers: the minted incident and the case it opened. */
export type PerchMintIncidentResponse = {
  readonly schema_version: number;
  readonly incident_id: string;
  readonly case_id: string;
  readonly created: boolean;
  readonly degraded: readonly string[];
  readonly record: unknown;
};

/**
 * Everything B3i needs, mirroring the Rust `MintIncidentInput` field for
 * field. `threatClass` is a standard slug or `{ custom: "…" }`; there is no
 * `caseId`, because the daemon mints it.
 */
export type PerchMintIncidentInput = {
  findingId: string;
  huntId: string;
  eventId: string;
  strategyId: string;
  threatClass: unknown;
  severity: string;
  createdAtMs: number;
  summary: string;
  hostId: string | null;
  correlationKeys: readonly string[];
};

// ===========================================================================
// READS. GETs, which INV-01 does not gate — still one command per route, for
// the same enumerability reason.
// ===========================================================================

/** B3r. The daemon's review window, so the console can show what its own
 *  verdicts did. */
export function perchReviewedFindings(sinceMs?: number, limit?: number) {
  return invokeTauri<PerchReviewedFindingsResponse>("perch_reviewed_findings", {
    sinceMs,
    limit,
  });
}

/** D-FC-2. The admitted bridge identities and the twelve lane channel ids.
 *  Unauthenticated on the daemon side: public keys and lane ids only. */
export function perchAdmittedIssuers() {
  return invokeTauri<PerchAdmittedIssuers>("perch_admitted_issuers");
}

/**
 * Every open containment lease the daemon still lists.
 *
 * A 503 comes back as a thrown error, not an empty array: "no containment
 * lease store is configured" and "nothing is contained" are different facts,
 * and a board that rendered them the same would tell an operator the world is
 * clear when nothing is watching it.
 */
export function perchListContainments() {
  return invokeTauri<unknown>("perch_list_containments");
}

/**
 * What the detectors deliberately do not see, served whole.
 *
 * The console renders each gap's own rationale rather than a paraphrase: a
 * summary would be this console asserting a limit it did not measure.
 */
export function perchEvasionCoverage() {
  return invokeTauri<unknown>("perch_evasion_coverage");
}

/** The read commands, named once so the E2E bridge can assert it answers all
 *  of them. */
export const PERCH_READ_COMMANDS = [
  "perch_reviewed_findings",
  "perch_admitted_issuers",
  "perch_list_holds",
  "perch_get_hold",
  "perch_configure_daemon",
  "perch_list_containments",
  "perch_evasion_coverage",
] as const;

// ===========================================================================
// LEG 1 — THE RELAY WRITE. In `commands/perch_verdict.rs`, deliberately not in
// `perch_writes.rs`, so the allowlist gate reads exactly five daemon routes
// from that file and the relay's publisher set reads exactly one from this
// one. Two closed sets, two files, no arithmetic.
// ===========================================================================

/**
 * Build, sign and publish the leg-1 `swarm:verdict:v1` card, and return the
 * values leg 2 needs.
 *
 * The generic signing command refuses any kind:9 whose line 0 is a swarm
 * marker, and that refusal only means something because a sanctioned path
 * exists. This is it, and it is the only one.
 *
 * The Rust side queries the relay for the finding card by id, refuses it
 * unless its signer is an admitted bridge identity, and builds the card body
 * from THAT event — never from renderer-supplied copies. The renderer chooses
 * the decision and types the rationale; it supplies no other content.
 */
export function perchRecordVerdict(input: {
  findingCardId: string;
  caseChannel: string;
  incidentId: string;
  decision: PerchFindingAction;
  /** Free text the operator typed. Hashed into the signature preimage. */
  rationale: string | null;
}) {
  return invokeTauri<{
    /** The published card's event id — leg 2's idempotency key. */
    readonly nostr_intent_event_id: string;
    readonly decided_at_ms: number;
    readonly signature: PerchDetachedSignature;
    /** Read from the admitted card's own body, not from the input. */
    readonly finding_id: string;
  }>("perch_record_verdict", { input });
}

/**
 * The relay-published set: three commands, one kind, one marker.
 *
 * All three publish the SAME marker — a `swarm:verdict:v1` card. Leg 1 of a
 * FINDING verdict and leg 1 of a HOLD decision are separate commands because
 * they take different inputs and read different daemon records, and
 * `perch_publish_verdict_update` replies to its own leg-1 card. The set of
 * commands grew; the set of markers the operator's key can publish did not,
 * and a Rust test asserts that.
 */
export const PERCH_RELAY_WRITE_COMMANDS = [
  "perch_record_verdict",
  "perch_record_hold_verdict",
  "perch_publish_verdict_update",
] as const;

// ===========================================================================
// DAEMON WRITES. INV-01 asserts the set is closed at five; First card
// implements two and `PERCH_DAEMON_WRITES` in Rust lists all five.
// ===========================================================================

/**
 * Leg 2 of a finding verdict (B3). `analystId` is not a parameter: the daemon
 * takes it from the authenticated principal, so the console cannot claim to
 * be somebody else.
 */
export function perchFindingFeedback(input: {
  findingId: string;
  incidentId: string;
  action: PerchFindingAction;
  /** Verbatim from `perchRecordVerdict`. The idempotency key. */
  verdictEventId: string;
  reason: string | null;
}) {
  return invokeTauri<PerchFindingFeedbackResponse>(
    "perch_finding_feedback",
    input,
  );
}

/**
 * B3i. Promote a finding: the daemon mints the incident and its case id, and
 * publishes the runtime event the bridge turns into a case channel.
 */
export function perchMintIncident(input: PerchMintIncidentInput) {
  return invokeTauri<PerchMintIncidentResponse>("perch_mint_incident", {
    input,
  });
}

/**
 * Ask the daemon to run a containment's inverse now rather than at its TTL.
 *
 * The caller reads `lease_closed` from the BODY and never the HTTP status. The
 * daemon answers 200 for a release whose inverse failed, because the request
 * was understood and carried out — the world simply did not change.
 */
export function perchReleaseContainment(leaseId: string) {
  return invokeTauri<unknown>("perch_release_containment", { leaseId });
}

/** The daemon-bound write commands this milestone implements. */
export const PERCH_DAEMON_WRITE_COMMANDS = [
  "perch_finding_feedback",
  "perch_mint_incident",
  "perch_decide_hold",
  "perch_release_containment",
] as const;

/**
 * Every perch Tauri command, in one place, so the E2E mock bridge can assert
 * it answers all of them and no count drifts from the file.
 */
/**
 * Local process control for the laptop demo's `swarm_detect`.
 *
 * A THIRD list, kept apart from the reads and the two write lists on purpose.
 * These issue no request to any Ambush host, so they are outside INV-01 — and
 * folding them into the daemon-write list would make that table read as six
 * routes when the claim it carries is about five.
 */
export const PERCH_LOCAL_COMMANDS = [
  "perch_export_bundle",
  "perch_verify_envelope",
  "perch_sidecar_start",
  "perch_sidecar_stop",
  "perch_sidecar_status",
] as const;

/** Why a link did or did not continue its chain. Four outcomes, never a bool. */
export type PerchChainLinkVerdict =
  | "valid"
  | "issuer_mismatch"
  | "sequence_gap"
  | "hash_mismatch";

/** The last envelope this console saw from one issuer. */
export type PerchIssuerChainHead = {
  readonly issuer: string;
  readonly seq: number;
  readonly envelope_hash: string;
};

/**
 * What the console learned about one envelope.
 *
 * Three independent facts rather than a boolean, because there are three ways
 * reliance can fail and they need different responses: re-fetch the body,
 * distrust the issuer, or go looking for a missing card. `tier` is derived in
 * Rust so a renderer cannot compute one that disagrees with the badge.
 */
export type PerchEnvelopeVerification = {
  readonly hash_matches: boolean;
  readonly signature_present: boolean;
  /** `null` when there is no signature: absent and failed stay apart. */
  readonly signature_valid: boolean | null;
  /** `null` when no earlier card from this issuer has been seen. */
  readonly chain: PerchChainLinkVerdict | null;
  readonly tier: 0 | 1 | 2;
  readonly reason: string;
};

/** What the export actually wrote, so a caller reports that rather than intent. */
export type PerchExportOutcome = {
  readonly directory: string;
  readonly written: readonly string[];
  readonly bytes: number;
};

/**
 * Write an evidence bundle into a directory the operator chose.
 *
 * Bytes are base64 because a `Uint8Array` across IPC becomes a JSON array of
 * numbers, and a twelve-megabyte bundle would be a hundred megabytes of
 * digits. They are the daemon's and the relay's bytes VERBATIM — the Rust side
 * writes what it is handed and re-serializes nothing, because re-serializing
 * changes the digest of a signed record.
 */
export function perchExportBundle(
  directory: string,
  files: readonly { path: string; bytes: Uint8Array }[],
) {
  return invokeTauri<PerchExportOutcome>("perch_export_bundle", {
    directory,
    files: files.map((file) => ({
      path: file.path,
      bytes_b64: bytesToBase64(file.bytes),
    })),
  });
}

/** Base64 without a data URL round-trip; chunked so a large bundle cannot blow the stack. */
function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  const chunk = 0x8000;
  for (let index = 0; index < bytes.length; index += chunk) {
    binary += String.fromCharCode(...bytes.subarray(index, index + chunk));
  }
  return btoa(binary);
}

/**
 * Verify a spine envelope in this process. Local computation, no host request,
 * so it is outside INV-01.
 */
export function perchVerifyEnvelope(
  envelope: unknown,
  head?: PerchIssuerChainHead,
) {
  return invokeTauri<PerchEnvelopeVerification>("perch_verify_envelope", {
    envelope,
    head,
  });
}

export const PERCH_TAURI_COMMANDS = [
  ...PERCH_READ_COMMANDS,
  ...PERCH_RELAY_WRITE_COMMANDS,
  ...PERCH_DAEMON_WRITE_COMMANDS,
  ...PERCH_LOCAL_COMMANDS,
] as const;

/** Seeds are reported as PRESENT or absent. A value never crosses IPC. */
export type PerchSidecarStatus = {
  readonly pid: number;
  readonly started_at_ms: number;
  readonly healthz: "starting" | "ready" | "unhealthy" | "stopped";
  readonly profile_path: string;
  readonly seeds_present: { readonly nostr: boolean; readonly spine: boolean };
};

/** Start the bundled daemon under a config the Rust side re-resolves. */
export function perchSidecarStart(configPath: string) {
  return invokeTauri<PerchSidecarStatus>("perch_sidecar_start", { configPath });
}

export function perchSidecarStop() {
  return invokeTauri<null>("perch_sidecar_stop");
}

/** `null` means the sidecar has never run — not that it is stopped. */
export function perchSidecarStatus() {
  return invokeTauri<PerchSidecarStatus | null>("perch_sidecar_status");
}

// ===========================================================================
// B2r — THE HOLD READS. The reconciliation authority.
//
// Every type below was measured against the daemon's own serialiser, not
// transcribed from a plan: `src/testing/perch/daemonHoldFixture.json` holds
// the bytes `HoldListResponse` and `HeldActionView` actually produce
// (`crates/swarm-runtime-http/src/http/perch/holds.rs`), and
// `tauriPerch.test.mjs` fails if a field appears on one side and not the
// other. Four fields the wave-2 drafts did not have are real and load-bearing:
// `notice_event_id` (W3-26), `schema_version` and `truncated` on the envelope,
// and `policy_decision.verdict`.
// ===========================================================================

/** `LOW | MEDIUM | HIGH | CRITICAL`. SCREAMING_SNAKE on the wire. */
export type PerchSeverity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

/**
 * The hold state machine. `expired` is a SEPARATE fact from `state`: one is a
 * stored transition and the other is a reading of the clock, and a view that
 * collapsed them would hide which claim the daemon is making.
 */
export type PerchHoldState =
  | "created"
  | "notified"
  | "armed"
  | "deciding"
  | "granted"
  | "refused"
  | "expired"
  | "executed"
  | "failed";

/** `grant | refuse`. Never `deny`: `refuse` is the operator's word. */
export type PerchHoldDecision = "grant" | "refuse";

/**
 * A standard taxonomy slug, or `{ custom: "…" }` for one outside it. The
 * externally-tagged Rust enum serialises the custom arm as an object, so a
 * consumer that assumed `string` would render `[object Object]` on exactly
 * the threat class nobody has seen before.
 */
export type PerchThreatClass = string | { readonly custom: string };

/** The ACTION, verbatim, as the requesting agent asked for it. */
export type PerchActionRequest = {
  readonly hunt_id: string;
  readonly requested_by: string;
  readonly action: Readonly<Record<string, unknown>> & {
    readonly type: string;
  };
  readonly severity: PerchSeverity;
  readonly evidence: Readonly<Record<string, unknown>>;
};

/** The verdict that held the action. `verdict` is `require_human` for a hold. */
export type PerchPolicyDecision = {
  readonly verdict: string;
  readonly rule_name: string;
  readonly reason: string;
};

/** WHY WE ARE ASKING — the context `policy_decision` alone cannot give. */
export type PerchHoldRationale = {
  readonly rule_name: string;
  readonly reason: string;
  readonly threat_class: PerchThreatClass;
  readonly severity: PerchSeverity;
  readonly request_carried_fields: readonly string[];
  readonly concentration_at_hold: Readonly<Record<string, unknown>> | null;
  readonly escalation_level: string | null;
  /** Whether a receipt was PRESENT at hold time. Not a verification result. */
  readonly governance_receipt_present: boolean;
};

/** BLAST RADIUS: what granting would reach. */
export type PerchBlastRadiusPreview = {
  readonly scope_kind: string;
  readonly scope_value: string;
  readonly impact: string;
  readonly max_affected_scopes: number;
  readonly affected_capabilities: readonly string[];
  readonly summary: string;
};

/** The rollback the response planned, before anyone asked whether it works. */
export type PerchRollbackPreview = {
  readonly required: boolean;
  readonly summary: string;
  readonly steps: ReadonlyArray<{
    readonly kind: string;
    readonly summary: string;
  }>;
};

/** The rehearsal, when one could be built. */
export type PerchRehearsalPreview = {
  readonly rehearsal_id: string;
  readonly source_bundle_id: string;
  readonly prepared_at_ms: number;
  readonly simulated_only: boolean;
  readonly blast_radius: PerchBlastRadiusPreview;
  readonly rollback: PerchRollbackPreview;
};

/**
 * IF YOU UNDO: per planned rollback step, what `resolve_inverse` said.
 *
 * `step_kind` is the Rust variant's `Debug` name (`RestoreHostConnectivity`),
 * NOT the snake_case the same enum uses inside `rehearsal.rollback.steps[].kind`
 * — the daemon builds it with `format!("{:?}")`. Joining the two lists on this
 * string without normalising is the obvious bug, so neither is derived from
 * the other here.
 *
 * `reason` is ABSENT rather than null when the refusing layer had no words.
 */
export type PerchInverseResolution = {
  readonly step_kind: string;
  readonly verdict: "executable" | "irreversible" | "unmapped";
  readonly reason?: string;
  /** Render law 4: the console names the function that produced the verdict. */
  readonly derived_by: string;
};

/** Why a grant did not become an action. */
export type PerchHoldRefusal = {
  readonly rule: string;
  readonly reason: string;
};

/**
 * The authoritative decision record. `nostr_intent_event_id` is what makes
 * one leg-1 card THE decision: a verdict card whose id this record does not
 * name is not the decision, whatever it claims about itself.
 */
export type PerchHoldDecisionRecord = {
  readonly decision: PerchHoldDecision;
  readonly operator_id: string;
  readonly voter_id: string;
  readonly rationale_sha256: string | null;
  readonly hold_notice_published: boolean;
  readonly governance_clearance:
    | "not_required"
    | "partition_authorized"
    | "receipt_signature_ok"
    | "receipt_subject_bound";
  readonly decided_at_ms: number;
  readonly nostr_intent_event_id: string;
  readonly signature: PerchDetachedSignature | null;
  readonly rationale: string | null;
  readonly outcome:
    | "granted_executed"
    | "granted_simulated"
    | "granted_failed"
    | "refused_by_operator"
    | "refused_late"
    | "guard_rejected";
  /** Whether the runtime ATTEMPTED the response. Not whether it succeeded. */
  readonly dispatched: boolean;
  readonly receipt_id: string | null;
  readonly audit_trail_id: string | null;
  readonly refusal: PerchHoldRefusal | null;
};

/** One hold as an operator reads it. */
export type PerchHeldActionView = {
  readonly hold_id: string;
  readonly state: PerchHoldState;
  readonly notified_at_ms: number | null;
  readonly deciding_intent_event_id: string | null;
  readonly case_channel: string | null;
  readonly notice_event_id: string | null;
  readonly card_event_id: string | null;
  readonly action_kind: string;
  readonly severity: PerchSeverity;
  readonly held_at_ms: number;
  readonly expires_at_ms: number;
  /** Saturates at zero. A clock reading, not a decision about it. */
  readonly remaining_ms: number;
  /** The decision about that reading. Kept apart on purpose. */
  readonly expired: boolean;
  readonly action_request: PerchActionRequest;
  readonly policy_decision: PerchPolicyDecision;
  readonly rationale: PerchHoldRationale;
  readonly leases_a_containment: boolean;
  readonly rehearsal: PerchRehearsalPreview | null;
  readonly inverse_resolution: readonly PerchInverseResolution[];
  readonly decision: PerchHoldDecisionRecord | null;
};

/**
 * `GET /v1/response/holds`.
 *
 * `store_durable: false` means a restart forgot every open hold, and the queue
 * renders it: the difference between "no holds" and "no memory of holds" is
 * the whole of INV-35. `open_count` counts the STORE, not this page, so a
 * truncated page still reports the real depth.
 */
export type PerchHoldListResponse = {
  readonly schema_version: number;
  readonly observed_at_ms: number;
  readonly holds: readonly PerchHeldActionView[];
  readonly open_count: number;
  readonly truncated: boolean;
  readonly deciding_stalled_count: number;
  readonly store_durable: boolean;
};

/** `GET /v1/response/holds/{hold_id}`. */
export type PerchHoldDetailResponse = {
  readonly schema_version: number;
  readonly observed_at_ms: number;
  readonly hold: PerchHeldActionView;
};

/**
 * A `Record<keyof T, true>` literal is a compile error when a key is missing
 * or invented, so these maps make the type list checkable at runtime without
 * letting it drift from the type. `tauriPerch.test.mjs` compares them to the
 * daemon's real bytes.
 */
const HELD_ACTION_VIEW_KEYS: Record<keyof PerchHeldActionView, true> = {
  hold_id: true,
  state: true,
  notified_at_ms: true,
  deciding_intent_event_id: true,
  case_channel: true,
  notice_event_id: true,
  card_event_id: true,
  action_kind: true,
  severity: true,
  held_at_ms: true,
  expires_at_ms: true,
  remaining_ms: true,
  expired: true,
  action_request: true,
  policy_decision: true,
  rationale: true,
  leases_a_containment: true,
  rehearsal: true,
  inverse_resolution: true,
  decision: true,
};

const HOLD_LIST_RESPONSE_KEYS: Record<keyof PerchHoldListResponse, true> = {
  schema_version: true,
  observed_at_ms: true,
  holds: true,
  open_count: true,
  truncated: true,
  deciding_stalled_count: true,
  store_durable: true,
};

const HOLD_DECISION_RECORD_KEYS: Record<keyof PerchHoldDecisionRecord, true> = {
  decision: true,
  operator_id: true,
  voter_id: true,
  rationale_sha256: true,
  hold_notice_published: true,
  governance_clearance: true,
  decided_at_ms: true,
  nostr_intent_event_id: true,
  signature: true,
  rationale: true,
  outcome: true,
  dispatched: true,
  receipt_id: true,
  audit_trail_id: true,
  refusal: true,
};

const HOLD_RATIONALE_KEYS: Record<keyof PerchHoldRationale, true> = {
  rule_name: true,
  reason: true,
  threat_class: true,
  severity: true,
  request_carried_fields: true,
  concentration_at_hold: true,
  escalation_level: true,
  governance_receipt_present: true,
};

/** The daemon DTO field lists this file claims to cover, by DTO name. */
export const PERCH_HOLD_DTO_KEYS = {
  HeldActionView: Object.keys(HELD_ACTION_VIEW_KEYS),
  HoldListResponse: Object.keys(HOLD_LIST_RESPONSE_KEYS),
  HoldDecisionRecord: Object.keys(HOLD_DECISION_RECORD_KEYS),
  HoldRationale: Object.keys(HOLD_RATIONALE_KEYS),
} as const satisfies Readonly<Record<string, readonly string[]>>;

/**
 * B2r. Every hold this daemon is holding, decided and expired ones included.
 *
 * The queue's authority. An error here is rendered as an error: an empty list
 * is a claim about the world and an unreachable daemon is not in a position to
 * make it, which is why nothing in this path substitutes `[]` for a failure.
 */
export function perchListHolds() {
  return invokeTauri<PerchHoldListResponse>("perch_list_holds");
}

/**
 * B2r. One hold.
 *
 * Also the way out of a `409` (W3-17): the console learns which decision won
 * by RE-READING this route, never from the conflict's error body. The error
 * body says which KIND of conflict happened; only this says what is true.
 */
export function perchGetHold(holdId: string) {
  return invokeTauri<PerchHoldDetailResponse>("perch_get_hold", { holdId });
}

/**
 * Store the daemon base URL and this operator's credential in the OS keyring.
 *
 * One-directional: values go in and there is no command that reads either back
 * out (INV-22). Debug builds seed the same keys from the environment at
 * startup (D-FC-4).
 */
export function perchConfigureDaemon(base_url: string, credential: string) {
  return invokeTauri<void>("perch_configure_daemon", { base_url, credential });
}

// ===========================================================================
// LEG 2 — THE DAEMON DECIDE, and the supersession card leg 1 gets when it
// loses. `perch_decide_hold` and the hold arm of `perch_record_verdict` are
// implemented by the decide/verdict track (plan Tasks 20 and 21); the shapes
// below are the plan's documented interface, which the write reducer and the
// mock bridge are both built against.
// ===========================================================================

/** `grant | refuse`. Never `deny`: `refuse` is the operator's word. */
export type PerchHoldVerdict = "grant" | "refuse";

/**
 * What leg 2 reports. Six outcomes; a seventh is a wire change.
 *
 * `superseded` carries `superseded_by` and `winning_decision` as TYPED fields.
 * The daemon's 409 body is `{error, message}` and nothing else (W3-17), so the
 * Tauri command fills these by RE-READING `GET /v1/response/holds/{id}` — the
 * error body says which KIND of conflict happened, and only the re-read says
 * what is true.
 */
export type PerchDecideOutcome = {
  readonly outcome:
    | "dispatched"
    | "refused_late"
    | "refused_late_governance"
    | "superseded"
    | "expired"
    | "unknown_hold";
  readonly rule: string | null;
  readonly reason: string | null;
  readonly receipt_id: string | null;
  readonly decided_at_ms: number;
  /** The winning intent's event id, from the re-read. */
  readonly superseded_by: string | null;
  /** The winning decision, from the re-read. Never parsed out of `reason`. */
  readonly winning_decision: PerchHoldVerdict | "unknown" | null;
  /** True when this call replayed an existing record rather than deciding. */
  readonly replayed: boolean;
};

/**
 * Leg 2. The one route that can turn a held destructive action into a real one.
 *
 * `nostr_intent_event_id` is leg 1's card id and is the daemon's idempotency
 * key, so a retry re-sends THIS call unchanged and never re-signs leg 1.
 */
export function perchDecideHold(input: {
  holdId: string;
  decision: PerchHoldVerdict;
  /** Verbatim from `perchRecordVerdict`. */
  nostrIntentEventId: string;
  rationale: string | null;
  armedAtMs: number | null;
}) {
  return invokeTauri<PerchDecideOutcome>("perch_decide_hold", input);
}

/**
 * Publish the supersession update: a NIP-10 reply to this console's OWN leg-1
 * card, marking it `leg2.state: "superseded"`.
 *
 * Published rather than left silent because the losing card is a genuine
 * signed decision that will sit in the case channel forever. A reader who finds
 * it later must be able to see, from the channel alone, that it did not run.
 * The case channel comes from the daemon's hold record, never from the
 * renderer.
 */
export function perchPublishVerdictUpdate(input: {
  holdId: string;
  ownIntentEventId: string;
  supersededBy: string;
  supersededAtMs: number;
}) {
  return invokeTauri<{ readonly nostr_intent_event_id: string }>(
    "perch_publish_verdict_update",
    { input },
  );
}

/**
 * Leg 1 for a HOLD subject (D-FC-3's `subject: "hold"` discriminator).
 *
 * The same command as the finding verdict, with a hold-shaped input. The Rust
 * side re-reads the hold from the daemon and builds the card body from THAT
 * answer, so the renderer chooses the decision and types the rationale and
 * supplies no other content.
 */
export function perchRecordHoldVerdict(input: {
  holdId: string;
  decision: PerchHoldVerdict;
  /** Free text the operator typed. Hashed into the signature preimage. */
  rationale: string | null;
}) {
  return invokeTauri<{
    /** The published card's event id — leg 2's idempotency key. */
    readonly nostr_intent_event_id: string;
    readonly decided_at_ms: number;
    readonly signature: PerchDetachedSignature;
    /** Read from the daemon's own hold record, not from the input. */
    readonly hold_id: string;
  }>("perch_record_hold_verdict", { input });
}
