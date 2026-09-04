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

/** The read commands, named once so the E2E bridge can assert it answers all
 *  of them. */
export const PERCH_READ_COMMANDS = [
  "perch_reviewed_findings",
  "perch_admitted_issuers",
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

/** The relay-published set: one command, one kind, one marker. */
export const PERCH_RELAY_WRITE_COMMANDS = ["perch_record_verdict"] as const;

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

/** The daemon-bound write commands this milestone implements. */
export const PERCH_DAEMON_WRITE_COMMANDS = [
  "perch_finding_feedback",
  "perch_mint_incident",
] as const;

/**
 * Every perch Tauri command, in one place, so the E2E mock bridge can assert
 * it answers all of them and no count drifts from the file.
 */
export const PERCH_TAURI_COMMANDS = [
  ...PERCH_READ_COMMANDS,
  ...PERCH_RELAY_WRITE_COMMANDS,
  ...PERCH_DAEMON_WRITE_COMMANDS,
] as const;
