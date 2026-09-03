// Target path in BUZZ: desktop/src/shared/api/perchEphemeralStore.ts  (NEW file)
//
// The 26000-26006 frames land here, NOT in the React Query cache. Read with
// `useSyncExternalStore`, which gives every consumer a stable snapshot
// reference between frames — the property React.memo needs and the property
// a query cache does not provide (a React Query result object is a new
// identity every render; BUZZ AGENTS.md gotcha 6 names it as one of two repeat
// offenders).
//
// Three properties this store must have and a cache cannot:
//   1. LAST-WINS PER SUBJECT, not append. A 1 Hz ConcentrationSnapshot is a
//      replacement, not an event; keeping history would grow without bound on
//      a wallboard that runs for years.
//   2. NO INVALIDATION SEMANTICS. `invalidateQueries` on reconnect must not
//      look like it can recover telemetry. Ephemerals are not replayed. A
//      Perch that was disconnected when a frame fired MISSED it, and every
//      consumer names its authoritative re-read instead.
//   3. REFERENTIAL STABILITY UNDER NO-CHANGE. Eleven of twelve threat classes
//      are usually unchanged between snapshots; the store keeps the previous
//      per-class object identity when the values match, so eleven rows bail
//      out of re-render. Same mechanism as BUZZ
//      desktop/src/shared/hooks/useStableReference.ts:9-25 (`useStableMap`),
//      applied at write time instead of render time so it works for a
//      non-React reader too.
//
// Gate-line budget: 1000. Targets ~200.

import type { PerchEphemeralKind } from "./perchSubscriptions";

// ---------------------------------------------------------------------------
// §1 Admitted-issuer gate. INV-15.
// ---------------------------------------------------------------------------
//
// The relay does NOT enforce `#p` on delivery of a channel-less ephemeral:
// filter_fanout_by_access (BUZZ crates/buzz-relay/src/handlers/event.rs:115-222,
// relay process, the single guarded send chokepoint for local WS delivery)
// applies only the receiver tenant label (:126-131), AUTHOR_ONLY_KINDS
// (:139-152) and SHARED_GATED_KINDS (:157-175) to a channel-less event, then
// returns every match at :177-179 without consulting p tags. And the ephemeral
// ingest gate is a single scope test (event.rs:698-707) that every chat-capable
// member passes.
//
// Consequence, stated plainly because it is a disclosure and a forgery
// surface: TODAY, any authenticated community member can both READ every alarm
// frame and PUBLISH a fabricated one.
//
// THE FORGERY HALF is closed here, client-side, by the admitted-issuer set
// below. Without it any member could publish a fabricated 26003 and page the
// rotation.
//
// THE DISCLOSURE HALF is closed in the relay, and the decision is now made:
// 26006 joins `P_GATED_KINDS` (BUZZ crates/buzz-core/src/kind.rs:159-169 —
// which already carries KIND_AGENT_OBSERVER_FRAME, an ephemeral, present for
// exactly this filter-layer enforcement). `p_gated_filters_authorized`
// (crates/buzz-relay/src/handlers/req.rs:1182-1216, relay process) then refuses
// at REQ REGISTRATION (:219-226) any global filter naming a p-gated kind whose
// `#p` values are not all the authenticated pubkey, so `{kinds:[26006]}` and
// `{kinds:[26006],"#p":[someone_else]}` both get
// `CLOSED "restricted: p-gated events require #p matching your pubkey"` and no
// subscription exists to deliver to. See perchSubscriptions.ts's watch-alarm
// filter for why the alternative (an `h` tag) would have put 26006 permanently
// outside that gate — it applies only when `channel_id.is_none()`.
//
// UNTIL THAT LINE LANDS the client behaves identically and the disclosure is
// open. The client cannot fix it, this file does not pretend to, and the count
// below is not a substitute for it.

let admittedIssuers: ReadonlySet<string> = new Set();
let unadmittedFrames = 0;

export function setPerchAdmittedIssuers(next: ReadonlySet<string>): void {
  admittedIssuers = next;
}

/** Exported so the governance strip can render the count, per the rule that
 *  rejected frames are counted and dropped, never silently dropped. */
export function perchUnadmittedFrameCount(): number {
  return unadmittedFrames;
}

// ---------------------------------------------------------------------------
// §2 The snapshot
// ---------------------------------------------------------------------------

export type PerchConcentration = {
  readonly threatClass: string;
  readonly totalStrength: number;
  readonly distinctSources: number;
  readonly peakConfidence: number;
};

export type PerchAgentFrame = {
  readonly agentId: string;
  readonly role: string;
  readonly health: string;
  readonly actionTallies: Readonly<Record<string, number>>;
};

export type PerchEphemeralSnapshot = {
  /** Wall-clock ms at which each kind was last received. Absence is a state. */
  readonly receivedAtMs: Readonly<Partial<Record<PerchEphemeralKind, number>>>;
  readonly ingest: { readonly accepted: number; readonly rejected: number } | null;
  readonly concentrations: ReadonlyMap<string, PerchConcentration>;
  readonly agents: ReadonlyMap<string, PerchAgentFrame>;
  readonly mode: { readonly from: string; readonly to: string } | null;
  readonly governance: Readonly<Record<string, unknown>> | null;
  readonly tamper: Readonly<Record<string, number | boolean>> | null;
  /** Alarm frames since the last drain. Alarms are a QUEUE, never last-wins. */
  readonly alarms: readonly Readonly<Record<string, unknown>>[];
};

const EMPTY: PerchEphemeralSnapshot = {
  receivedAtMs: {},
  ingest: null,
  concentrations: new Map(),
  agents: new Map(),
  mode: null,
  governance: null,
  tamper: null,
  alarms: [],
};

let snapshot: PerchEphemeralSnapshot = EMPTY;
const listeners = new Set<() => void>();

export function subscribePerchEphemeral(listener: () => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

/** `getSnapshot` for useSyncExternalStore. Stable between frames. */
export function getPerchEphemeralSnapshot(): PerchEphemeralSnapshot {
  return snapshot;
}

function commit(next: PerchEphemeralSnapshot): void {
  if (next === snapshot) return;
  snapshot = next;
  for (const listener of listeners) listener();
}

function sameConcentration(
  a: PerchConcentration | undefined,
  b: PerchConcentration,
): boolean {
  return (
    a !== undefined &&
    a.totalStrength === b.totalStrength &&
    a.distinctSources === b.distinctSources &&
    a.peakConfidence === b.peakConfidence
  );
}

/**
 * Merge one 26001 frame, preserving per-class object identity where nothing
 * moved. Returns the same Map instance when NO class changed, so the whole
 * lane list bails out of re-render on a quiet tick — which is most ticks.
 */
function mergeConcentrations(
  current: ReadonlyMap<string, PerchConcentration>,
  incoming: readonly PerchConcentration[],
): ReadonlyMap<string, PerchConcentration> {
  let changed = false;
  const next = new Map(current);
  for (const item of incoming) {
    if (sameConcentration(current.get(item.threatClass), item)) continue;
    next.set(item.threatClass, item);
    changed = true;
  }
  return changed ? next : current;
}

// ---------------------------------------------------------------------------
// §3 Ingest
// ---------------------------------------------------------------------------

export type PerchEphemeralFrame = {
  kind: PerchEphemeralKind;
  pubkey: string;
  receivedAtMs: number;
  body: Record<string, unknown>;
};

/**
 * The single entry point. Called from the Perch event sink for any kind in
 * 26000-26006. Returns false when the frame was dropped, so the caller can
 * count it rather than assume delivery.
 */
export function applyPerchEphemeralFrame(frame: PerchEphemeralFrame): boolean {
  if (!admittedIssuers.has(frame.pubkey)) {
    unadmittedFrames += 1;
    return false;
  }

  const receivedAtMs = { ...snapshot.receivedAtMs, [frame.kind]: frame.receivedAtMs };

  switch (frame.kind) {
    case 26000:
      commit({
        ...snapshot,
        receivedAtMs,
        ingest: frame.body as PerchEphemeralSnapshot["ingest"],
      });
      return true;
    case 26001: {
      const incoming = (frame.body.concentrations ?? []) as PerchConcentration[];
      commit({
        ...snapshot,
        receivedAtMs,
        concentrations: mergeConcentrations(snapshot.concentrations, incoming),
      });
      return true;
    }
    case 26002: {
      const agent = frame.body as unknown as PerchAgentFrame;
      const agents = new Map(snapshot.agents);
      agents.set(agent.agentId, agent);
      commit({ ...snapshot, receivedAtMs, agents });
      return true;
    }
    case 26003:
      commit({
        ...snapshot,
        receivedAtMs,
        mode: frame.body as PerchEphemeralSnapshot["mode"],
      });
      return true;
    case 26004:
      commit({ ...snapshot, receivedAtMs, governance: frame.body });
      return true;
    case 26005:
      commit({
        ...snapshot,
        receivedAtMs,
        tamper: frame.body as PerchEphemeralSnapshot["tamper"],
        alarms: [...snapshot.alarms, frame.body],
      });
      return true;
    case 26006:
      // Never coalesced, never shed. The alarm is a nudge with no authority:
      // the caller must re-read the daemon hold list before a row appears, and
      // a hold that the list does not confirm renders NOTHING — an alarm alone
      // never produces a decidable row. That is also what makes a duplicate
      // alarm harmless: two frames for one hold_id collapse into one re-read.
      commit({
        ...snapshot,
        receivedAtMs,
        alarms: [...snapshot.alarms, frame.body],
      });
      return true;
  }
}

/** Drain alarms after the caller has acted on them (re-read the daemon). */
export function drainPerchAlarms(): readonly Readonly<Record<string, unknown>>[] {
  const drained = snapshot.alarms;
  if (drained.length === 0) return drained;
  commit({ ...snapshot, alarms: [] });
  return drained;
}

/**
 * Staleness, which is a rendered state rather than a hidden one. A strip that
 * says `healthy` from a snapshot received 41 minutes ago is worse than one
 * that says nothing.
 */
export function perchTelemetryAgeMs(
  kind: PerchEphemeralKind,
  nowMs: number,
): number | null {
  const at = snapshot.receivedAtMs[kind];
  return at === undefined ? null : nowMs - at;
}

/**
 * Colony-switch fence. Registered in the typed reset registry.
 *
 * Deliberately does NOT clear `listeners`. Subscribers are React-managed and
 * unsubscribe through effect cleanup when the `key={colonyKey}` boundary
 * remounts (BUZZ App.tsx:407, applied at :630 and :640); clearing the set here
 * would strand any component that survives the remount — it would never be
 * notified again and would render the previous colony's numbers forever. The
 * `commit` call is what matters: it publishes the empty snapshot so anything
 * still mounted repaints as absent rather than as stale.
 */
export function resetPerchEphemeralStore(): void {
  admittedIssuers = new Set();
  unadmittedFrames = 0;
  commit(EMPTY);
}
