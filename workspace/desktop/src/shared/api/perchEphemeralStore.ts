// The 26000-26006 ephemeral frames, held OUTSIDE the React Query cache.
//
// `perchSubscriptions.ts` §2 owns the argument and this file is the other half
// of it: a stored kind:9 has an authority to reconcile against and belongs in
// the query cache; an ephemeral frame has none, is never replayed on
// reconnect, and putting it in a cache that reconnect healing invalidates
// would make `invalidateQueries` look like it can recover telemetry. It
// cannot. A console that was disconnected when an alarm fired MISSED it — so
// every consumer here also names its authoritative re-read, and for the hold
// alarm that re-read is `GET /v1/response/holds` (see `perchHoldAlarm.ts`).
//
// Three outcomes that look alike and are not:
//   `unadmittedFrames`  a well-formed 26xxx from an issuer this console does
//                       not admit (INV-15). Counted and dropped, never
//                       silently dropped.
//   `droppedFrames`     a 26xxx whose content did not decode to an object.
//                       Nobody's admission decision: the bridge sent bytes
//                       this console cannot read, and the operator is told so
//                       rather than shown a frame with no body in it.
//   a refused KIND      not counted here at all: a kind:9 arriving on an
//                       ephemeral path is a routing bug, not an admission
//                       decision, and folding the two would make the
//                       governance strip's number mean two things.
//
// And one that is not an outcome yet: a frame that arrives before the admitted
// set does is HELD, neither rendered nor counted, until the daemon's answer
// says which it was. See `PERCH_PREADMISSION_BUFFER_CAP`.
//
// Gate-line budget: 1000 (src/shared/api is a governed root).

import {
  isPerchEphemeralKind,
  perchStreamFor,
  type PerchEphemeralKind,
} from "./perchSubscriptions";

/**
 * One ephemeral frame as the store receives it: the relay envelope's kind and
 * signer, the instant it arrived, and whatever its content decoded to.
 *
 * `body` is `unknown` because the caller is a `JSON.parse` and the relay is
 * not the record: the sink hands over what it got, and deciding that a body is
 * not a body at all belongs here, beside the counter that reports it. Past that
 * one check this module admits and routes; it does not validate a frame's
 * schema, because a frame whose shape this console does not recognise is still
 * evidence that something is happening, and the consumer that needs a typed
 * field is the one that should refuse a malformed one.
 */
export type PerchEphemeralFrame = {
  readonly kind: number;
  readonly pubkey: string;
  readonly receivedAtMs: number;
  readonly body: unknown;
};

/** A drained alarm payload. Untyped for the reason above. */
export type PerchAlarmBody = Readonly<Record<string, unknown>>;

/** The latest frame seen for one telemetry kind, with its arrival instant. */
export type PerchTelemetryEntry = {
  readonly kind: PerchEphemeralKind;
  readonly pubkey: string;
  readonly receivedAtMs: number;
  readonly body: PerchAlarmBody;
};

/**
 * How many undrained alarms are kept.
 *
 * Bounded because an unbounded queue turns a misbehaving bridge into a memory
 * leak, and drop-OLDEST because the newest alarm is the one that has not been
 * acted on yet. An alarm is not a log line: losing the oldest costs a
 * duplicate re-read of a hold the console has almost certainly already seen,
 * while losing the newest costs the hold nobody has looked at.
 */
export const PERCH_ALARM_QUEUE_CAP = 256;

/**
 * How many frames are held while this console has no admitted set yet.
 *
 * The set is a daemon read that resolves in milliseconds while the bridge
 * publishes at 1 Hz across seven kinds, so this window is normally a handful of
 * frames — thirty-two is several seconds of it. Drop-OLDEST for the same reason
 * as the alarm queue: the newest frame is the one that describes now, and the
 * telemetry class coalesces on arrival anyway, so an evicted telemetry frame is
 * one the next second replaces. An evicted ALARM costs a nudge and never a
 * hold: `GET /v1/response/holds` is the authority and is re-read on connect.
 *
 * The buffer is bounded because a daemon that never answers must not turn a
 * chatty bridge into a memory leak, and it is a hold rather than a refusal
 * because "we have not been told whom to trust" is not a refusal this console
 * is entitled to make (`admittedIssuersKnown` says the same thing about
 * markers).
 */
export const PERCH_PREADMISSION_BUFFER_CAP = 32;

/**
 * The immutable view `useSyncExternalStore` reads. A new object is built only
 * when something actually changed, so `getPerchEphemeralSnapshot()` is
 * reference-stable between changes and React does not loop.
 */
export type PerchEphemeralSnapshot = {
  readonly alarms: readonly PerchAlarmBody[];
  readonly telemetry: ReadonlyMap<PerchEphemeralKind, PerchTelemetryEntry>;
  readonly unadmittedFrames: number;
  readonly droppedFrames: number;
  readonly droppedAlarms: number;
};

const EMPTY_ALARMS: readonly PerchAlarmBody[] = Object.freeze([]);
const EMPTY_TELEMETRY: ReadonlyMap<PerchEphemeralKind, PerchTelemetryEntry> =
  new Map();

let admitted: ReadonlySet<string> = new Set();
/** Whether the daemon's identities answer has landed at all. */
let admittedKnown = false;
let held: PerchEphemeralFrame[] = [];
let alarms: PerchAlarmBody[] = [];
let telemetry = new Map<PerchEphemeralKind, PerchTelemetryEntry>();
let unadmittedFrames = 0;
let droppedFrames = 0;
let droppedAlarms = 0;
let snapshot: PerchEphemeralSnapshot = {
  alarms: EMPTY_ALARMS,
  telemetry: EMPTY_TELEMETRY,
  unadmittedFrames: 0,
  droppedFrames: 0,
  droppedAlarms: 0,
};
const listeners = new Set<() => void>();

function publish(): void {
  snapshot = {
    alarms: alarms.length === 0 ? EMPTY_ALARMS : Object.freeze([...alarms]),
    telemetry: new Map(telemetry),
    unadmittedFrames,
    droppedFrames,
    droppedAlarms,
  };
  for (const listener of listeners) listener();
}

/**
 * Replace the set of issuers whose frames this store accepts (INV-15).
 *
 * The default is EMPTY, so nothing is admitted until the daemon's identities
 * answer arrives. That is deliberate: the set loads asynchronously, and a
 * store that trusted frames before it knew whom to trust would render a
 * stranger's alarm during boot. Mirrors, and is fed from,
 * `features/perch-evidence/lib/admittedIssuers.ts` — `shared/` may not import
 * `features/`, so the sync is an explicit call at The Watch's mount rather
 * than an import, and the daemon stays the single source.
 */
export function setPerchAdmittedIssuers(pubkeys: Iterable<string>): void {
  admitted = new Set([...pubkeys].map((pubkey) => pubkey.toLowerCase()));
  admittedKnown = true;
  if (held.length === 0) return;
  const replay = held;
  held = [];
  for (const frame of replay) admit(frame);
  publish();
}

/** A decoded content that is a frame body, or null for everything else. */
function asBody(value: unknown): PerchAlarmBody | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return null;
  }
  return value as PerchAlarmBody;
}

/**
 * Route one frame whose kind, body and issuer have all been settled. Does not
 * publish: the two callers batch their own, so one arrival is one snapshot and
 * a replayed buffer is one snapshot rather than thirty-two.
 */
function admit(frame: PerchEphemeralFrame): boolean {
  const body = asBody(frame.body);
  if (body === null) return false;
  if (!admitted.has(frame.pubkey.toLowerCase())) {
    unadmittedFrames += 1;
    return false;
  }
  if (perchStreamFor(frame.kind as PerchEphemeralKind) === "alarm") {
    alarms.push(body);
    while (alarms.length > PERCH_ALARM_QUEUE_CAP) {
      alarms.shift();
      droppedAlarms += 1;
    }
  } else {
    // The telemetry class coalesces on-change: only the latest frame per kind
    // is a fact about now, and keeping the history here would duplicate the
    // daemon's own counters with a worse copy.
    telemetry.set(frame.kind as PerchEphemeralKind, {
      kind: frame.kind as PerchEphemeralKind,
      pubkey: frame.pubkey,
      receivedAtMs: frame.receivedAtMs,
      body,
    });
  }
  return true;
}

/**
 * Admit one ephemeral frame. Returns whether it was stored.
 *
 * `false` means one of four different things, and nothing folds them together:
 *   - a kind outside 26000-26006 never belonged here (a routing bug, uncounted);
 *   - the content did not decode to an object (`droppedFrames`);
 *   - the issuer is not admitted (`unadmittedFrames`, INV-15);
 *   - the admitted set has not arrived, so the frame is HELD and will be put
 *     through this same check the moment `setPerchAdmittedIssuers` runs.
 *
 * Never throws. This runs on every frame of a 1 Hz stream from a process the
 * console does not control.
 */
export function applyPerchEphemeralFrame(frame: PerchEphemeralFrame): boolean {
  if (!isPerchEphemeralKind(frame.kind)) return false;
  // Decodability is decided first and once, so the hold buffer can never fill
  // with bytes that were never going to be rendered by anyone.
  if (asBody(frame.body) === null) {
    droppedFrames += 1;
    publish();
    return false;
  }
  if (!admittedKnown) {
    held.push(frame);
    while (held.length > PERCH_PREADMISSION_BUFFER_CAP) held.shift();
    return false;
  }
  const stored = admit(frame);
  publish();
  return stored;
}

/**
 * Take every queued alarm and empty the queue.
 *
 * Draining is the ONLY way an alarm leaves this store, so exactly one
 * consumer may drain: two would race for the same frame and each would see
 * half the alarms. `useHoldAlarmRefetch` is that consumer.
 */
export function drainPerchAlarms(): readonly PerchAlarmBody[] {
  if (alarms.length === 0) return EMPTY_ALARMS;
  const drained = alarms;
  alarms = [];
  publish();
  return drained;
}

/** The latest coalesced telemetry frame for one kind, if any has arrived. */
export function perchLatestTelemetry(
  kind: PerchEphemeralKind,
): PerchTelemetryEntry | undefined {
  return telemetry.get(kind);
}

/**
 * Frames dropped because their signer is not an admitted bridge identity.
 * Rendered as `perch_frame_unadmitted_total`; never folded into any other
 * number.
 */
export function perchUnadmittedFrameCount(): number {
  return unadmittedFrames;
}

/**
 * Frames whose content this console could not decode into a body. Rendered as
 * `perch_frame_undecodable_total`; never folded into the unadmitted number,
 * which is an accusation this one does not make.
 */
export function perchDroppedFrameCount(): number {
  return droppedFrames;
}

/** Alarms discarded by the queue cap. Non-zero means the bridge is flooding. */
export function perchDroppedAlarmCount(): number {
  return droppedAlarms;
}

/** The current snapshot. Reference-stable until something changes. */
export function getPerchEphemeralSnapshot(): PerchEphemeralSnapshot {
  return snapshot;
}

/** Server snapshot for `useSyncExternalStore`. There is no server. */
export function getPerchEphemeralServerSnapshot(): PerchEphemeralSnapshot {
  return snapshot;
}

/** Subscribe to any change. Returns the unsubscribe function. */
export function subscribePerchEphemeral(listener: () => void): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

/**
 * Community-switch fence, registered in the typed reset registry
 * (`features/communities/communityScopedRegistry.ts`).
 *
 * Clears the admitted set too: issuers are per-colony, and carrying one
 * colony's admitted bridge into the next would admit frames from a daemon
 * this console is no longer talking to.
 */
export function resetPerchEphemeralStore(): void {
  admitted = new Set();
  admittedKnown = false;
  held = [];
  alarms = [];
  telemetry = new Map();
  unadmittedFrames = 0;
  droppedFrames = 0;
  droppedAlarms = 0;
  publish();
}
