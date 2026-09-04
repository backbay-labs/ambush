import { useCallback, useSyncExternalStore } from "react";

import type { FindingFact } from "@/features/perch/wire";
import { perchKeys } from "@/shared/api/perchKeys";
import {
  perchFindingFeedback,
  perchMintIncident,
  perchRecordVerdict,
  type PerchFindingAction,
} from "@/shared/api/tauriPerch";

import { caseFor, rememberCase, type PerchCaseRef } from "./perchCaseIndex";
import { setVerdictWriteState } from "./verdictWriteState";

/**
 * The two verbs on a finding card, as a state machine with no optimism in it.
 *
 * # Why the two legs are two calls and never one
 *
 * Leg 1 publishes the operator's SIGNED INTENT to the relay: a durable record
 * that this person decided this, which survives a daemon that is down, wiped
 * or lying. Leg 2 tells the DAEMON, which owns the tuning consequence — the
 * suppression, the false-positive rate, the reviewed window.
 *
 * They fail independently, and the console must never let one stand for the
 * other. A checkmark after leg 1 would tell an operator their dismissal
 * changed the detector's behaviour when it changed nothing; a retry that
 * re-ran leg 1 would put a second signed decision on the relay for one human
 * act. So: leg 1's exact output is kept verbatim, leg 2 is the only thing a
 * retry re-sends, and only the daemon's own answer advances the row to
 * acknowledged.
 *
 * # Promotion is not a verdict
 *
 * `E` mints an incident and its case (W3-14: the DAEMON mints both ids) and
 * publishes nothing. It is the step that gives a later verdict somewhere to
 * be published, which is why a dismissal before it is `not-yet-correlated`
 * rather than an error.
 */

/**
 * What the flow may read off a finding. The fact comes from the ADMITTED card
 * (`admitCard`, INV-15) — never from renderer-supplied copies of its
 * identifiers, because everything below is built from it.
 */
export type FindingCardSubject = {
  /** The relay event id of the finding card being acted on, 64 lowercase hex. */
  readonly cardEventId: string;
  readonly fact: FindingFact;
};

/** Leg 2's request, stored verbatim so a retry re-sends exactly these bytes. */
export type FindingFeedbackIntent = {
  readonly findingId: string;
  readonly incidentId: string;
  readonly action: PerchFindingAction;
  /** Leg 1's published event id. The daemon's idempotency key. */
  readonly verdictEventId: string;
  readonly reason: string | null;
};

/** Everything the flow reaches outside itself, so a test can supply all of it. */
export type FindingVerdictFlowDeps = {
  mintIncident: typeof perchMintIncident;
  recordVerdict: typeof perchRecordVerdict;
  findingFeedback: typeof perchFindingFeedback;
  /** React Query invalidation. The UI binds this; the flow names the keys. */
  invalidate: (keys: readonly (readonly unknown[])[]) => void;
  /** Open the case the daemon just minted. */
  navigate: (caseId: string) => void;
};

const DEFAULT_DEPS: FindingVerdictFlowDeps = {
  mintIncident: perchMintIncident,
  recordVerdict: perchRecordVerdict,
  findingFeedback: perchFindingFeedback,
  invalidate: () => {},
  navigate: () => {},
};

function withDefaults(
  overrides?: Partial<FindingVerdictFlowDeps>,
): FindingVerdictFlowDeps {
  return overrides ? { ...DEFAULT_DEPS, ...overrides } : DEFAULT_DEPS;
}

/** `["daemon", "reviewed-findings"]`, derived so it cannot drift from the factory. */
const REVIEWED_FINDINGS_PREFIX = perchKeys.reviewedFindings(0).slice(0, 2);

// ---------------------------------------------------------------------------
// Leg-1 records
// ---------------------------------------------------------------------------

type LegOneRecord = {
  readonly intent: FindingFeedbackIntent;
  acknowledged: boolean;
};

const legOne = new Map<string, LegOneRecord>();
const listeners = new Set<() => void>();
let version = 0;

function emit(): void {
  version += 1;
  for (const listener of listeners) listener();
}

/** Subscribe to any leg-1 record change. Returns the unsubscribe function. */
export function subscribeFindingVerdictFlow(listener: () => void): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

/**
 * Leg 1's stored request for one finding, or null when nothing has been
 * published for it. Non-null means an Ambush record exists, whatever the
 * daemon has or has not said.
 */
export function findingVerdictIntent(
  findingId: string,
): FindingFeedbackIntent | null {
  return legOne.get(findingId)?.intent ?? null;
}

/** Every leg-1 record the daemon has not yet acknowledged. */
export function pendingFindingVerdicts(): FindingFeedbackIntent[] {
  return [...legOne.values()]
    .filter((record) => !record.acknowledged)
    .map((record) => record.intent);
}

const getVersion = (): number => version;
const getServerVersion = (): number => 0;

/**
 * Leg 1's record for one finding, for React. Its presence is what lets a row
 * render "recorded on Ambush" without claiming the daemon agreed.
 */
export function useFindingVerdictIntent(
  findingId: string,
): FindingFeedbackIntent | null {
  const read = useCallback(() => findingVerdictIntent(findingId), [findingId]);
  useSyncExternalStore(
    subscribeFindingVerdictFlow,
    getVersion,
    getServerVersion,
  );
  return read();
}

/** Community-switch fence. Registered in the typed reset registry. */
export function resetFindingVerdictFlow(): void {
  legOne.clear();
  emit();
}

// ---------------------------------------------------------------------------
// Promotion
// ---------------------------------------------------------------------------

/**
 * The hunt id B3i requires, which the finding card does not carry.
 *
 * `RuntimeEvent::Finding` has no hunt field and neither does
 * `swarm.perch.finding.v1`, so there is no hunt id to copy; the daemon only
 * refuses a blank one and files it in `included_hunt_ids`. Naming the finding
 * the case was promoted from is the one thing the console actually knows, and
 * it reads correctly in that record.
 */
function huntIdFor(findingId: string): string {
  return `swarm:finding:${findingId}`;
}

/** The human sentence B3i files as the incident summary. */
function summaryFor(fact: FindingFact): string {
  const { finding, locator } = fact;
  const threat =
    typeof finding.threat_class === "string"
      ? finding.threat_class
      : `custom:${finding.threat_class.custom}`;
  return `${finding.severity} ${threat} on ${locator.host_id ?? "an unnamed host"}, finding ${locator.finding_id} from ${locator.strategy_id}`;
}

/**
 * Promote a finding to an incident and open its case.
 *
 * The daemon mints both the incident id and the case id (W3-14) and publishes
 * `RuntimeEvent::CasePromoted`, which is what makes the bridge create the case
 * channel. The console supplies no id and invents none; it records the answer
 * so a later verdict knows where it belongs.
 *
 * @throws whatever B3i refused with. Nothing is remembered on a failure.
 */
export async function promoteFinding(
  card: FindingCardSubject,
  overrides?: Partial<FindingVerdictFlowDeps>,
): Promise<PerchCaseRef> {
  const deps = withDefaults(overrides);
  const { fact } = card;
  const findingId = fact.locator.finding_id;
  const answer = await deps.mintIncident({
    findingId,
    huntId: huntIdFor(findingId),
    eventId: fact.locator.event_id,
    strategyId: fact.locator.strategy_id,
    threatClass: fact.finding.threat_class,
    severity: fact.finding.severity,
    createdAtMs: fact.emitted_at_ms,
    summary: summaryFor(fact),
    hostId: fact.locator.host_id ?? null,
    correlationKeys: [`finding:${findingId}`],
  });
  const ref: PerchCaseRef = {
    caseId: answer.case_id,
    incidentId: answer.incident_id,
  };
  rememberCase(findingId, ref);
  deps.invalidate([perchKeys.caseList(), REVIEWED_FINDINGS_PREFIX]);
  deps.navigate(ref.caseId);
  return ref;
}

// ---------------------------------------------------------------------------
// The verdict, in two legs
// ---------------------------------------------------------------------------

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/**
 * Which write state a leg-2 refusal is.
 *
 * B3's 404 means the daemon has not joined this finding to an incident yet —
 * a state the operator can wait out and retry, not a failure. An unreachable
 * or unconfigured daemon is the honest "your record stands, the tuning has
 * not moved" case. Everything else is a refusal the daemon meant, and it
 * stays visible as a failure rather than being smoothed into a retryable one.
 */
function leg2Phase(
  message: string,
): "not-yet-correlated" | "daemon-unreachable" | "failed" {
  if (message.startsWith("not-yet-correlated")) return "not-yet-correlated";
  if (
    message.startsWith("daemon unreachable") ||
    message.startsWith("daemon not configured")
  ) {
    return "daemon-unreachable";
  }
  return "failed";
}

/** Send one stored leg-2 intent and move the row to whatever the daemon said. */
async function sendLegTwo(
  intent: FindingFeedbackIntent,
  deps: FindingVerdictFlowDeps,
): Promise<void> {
  try {
    const answer = await deps.findingFeedback({
      findingId: intent.findingId,
      incidentId: intent.incidentId,
      action: intent.action,
      verdictEventId: intent.verdictEventId,
      reason: intent.reason,
    });
    const record = legOne.get(intent.findingId);
    if (record) record.acknowledged = true;
    emit();
    setVerdictWriteState(intent.findingId, {
      phase: "acknowledged",
      atMs: Date.now(),
      feedbackId: answer.feedback_id,
    });
    // The daemon owns the suppression calculation, so `deposits` is NOT
    // invalidated here: the console re-reading its own guess would be the
    // optimism this whole path refuses.
    deps.invalidate([REVIEWED_FINDINGS_PREFIX, perchKeys.operatorStatus()]);
  } catch (error) {
    const reason = messageOf(error);
    const phase = leg2Phase(reason);
    setVerdictWriteState(
      intent.findingId,
      phase === "not-yet-correlated" ? { phase } : { phase, reason },
    );
  }
}

/**
 * Record a verdict on a finding: leg 1 to the relay, then leg 2 to the daemon.
 *
 * Requires the case the daemon minted at promotion. Without it the finding is
 * not correlated to an incident, there is nothing for the daemon to file the
 * feedback against, and no card has a channel to be published into — so
 * neither leg runs and the row says so.
 *
 * Never throws: every outcome is a rendered state, because a governance write
 * that disappeared into a rejected promise is a write nobody can see failed.
 */
export async function recordFindingVerdict(
  card: FindingCardSubject,
  decision: PerchFindingAction,
  rationale: string | null = null,
  overrides?: Partial<FindingVerdictFlowDeps>,
): Promise<void> {
  const deps = withDefaults(overrides);
  const findingId = card.fact.locator.finding_id;
  const ref = caseFor(findingId);
  if (!ref) {
    setVerdictWriteState(findingId, { phase: "not-yet-correlated" });
    return;
  }

  setVerdictWriteState(findingId, { phase: "sending" });
  let published: Awaited<ReturnType<typeof perchRecordVerdict>>;
  try {
    published = await deps.recordVerdict({
      findingCardId: card.cardEventId,
      caseChannel: ref.caseId,
      incidentId: ref.incidentId,
      decision,
      rationale,
    });
  } catch (error) {
    // No signed record exists, so there is nothing to tell the daemon about.
    setVerdictWriteState(findingId, {
      phase: "failed",
      reason: messageOf(error),
    });
    return;
  }

  const intent: FindingFeedbackIntent = Object.freeze({
    // The daemon's own answer for which finding this was, read off the
    // admitted card in the Tauri process rather than from this renderer.
    findingId: published.finding_id,
    incidentId: ref.incidentId,
    action: decision,
    verdictEventId: published.nostr_intent_event_id,
    reason: rationale,
  });
  legOne.set(intent.findingId, { intent, acknowledged: false });
  emit();
  setVerdictWriteState(intent.findingId, {
    phase: "recorded",
    atMs: published.decided_at_ms,
  });

  await sendLegTwo(intent, deps);
}

/**
 * Re-send leg 2 for one finding, and only leg 2.
 *
 * The stored intent is replayed byte for byte, so the daemon sees the same
 * idempotency key and the relay sees nothing at all. Returns false when there
 * is no leg-1 record to retry against.
 */
export async function retryFindingFeedback(
  findingId: string,
  overrides?: Partial<FindingVerdictFlowDeps>,
): Promise<boolean> {
  const record = legOne.get(findingId);
  if (!record) return false;
  setVerdictWriteState(findingId, { phase: "recorded", atMs: Date.now() });
  await sendLegTwo(record.intent, withDefaults(overrides));
  return true;
}
