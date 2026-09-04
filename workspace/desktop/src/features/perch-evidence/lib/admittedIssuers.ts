import { useSyncExternalStore } from "react";

/**
 * The admitted-issuer set (INV-15) and the counters beside it.
 *
 * A card renders only when its raw signer resolves to an admitted bridge
 * identity; an unadmitted well-formed marker renders as prose and is counted
 * here. The set comes from the daemon's `GET /metrics/perch/identities`
 * (D-FC-2) through the `perch_admitted_issuers` Tauri command; until that
 * read lands the set is fed by tests and by the E2E fixture. The same read
 * carries the twelve lane channel ids, which the subscription manager rides
 * on one REQ.
 *
 * Module-level on purpose: `isAdmittedIssuer` must be reference-stable or
 * it defeats the memo on every evidence card. Fenced on a community switch
 * by `resetPerchAdmittedIssuers` in the typed reset registry.
 */

/** The counters this module exposes; the name keeps call sites honest. */
export type PerchCounterName = "perch_marker_unadmitted_total";

/** How long a loaded set is trusted before `ensureAdmittedIssuersLoaded` reloads it. */
export const ADMITTED_ISSUERS_RELOAD_MS = 5 * 60_000;
/** How soon a failed load may be retried; shorter than the reload window so a boot-time hiccup heals. */
export const ADMITTED_ISSUERS_RETRY_MS = 30_000;

const EMPTY_LANES: readonly string[] = Object.freeze([]);
const NO_LANES: Readonly<Record<string, string>> = Object.freeze({});

let admitted: ReadonlySet<string> = new Set();
let known = false;
let lanes: Readonly<Record<string, string>> = NO_LANES;
let laneIds: readonly string[] = EMPTY_LANES;
const countedEvents = new Set<string>();
let unadmittedTotal = 0;
let version = 0;
let loadedAt: number | null = null;
let loading: Promise<void> | null = null;
const listeners = new Set<() => void>();

function emit(): void {
  version += 1;
  for (const listener of listeners) listener();
}

/**
 * Replace the admitted set and the lane map. Pubkeys are lowercased so the
 * predicate compares hex case-insensitively; lane ids are deduplicated and
 * frozen so `perchLaneChannelIds()` is reference-stable until the next set.
 */
export function setAdmittedIssuers(
  pubkeys: readonly string[],
  nextLanes: Readonly<Record<string, string>>,
): void {
  known = true;
  admitted = new Set(pubkeys.map((pubkey) => pubkey.toLowerCase()));
  lanes = Object.freeze({ ...nextLanes });
  const ids = Array.from(
    new Set(
      Object.values(nextLanes).filter(
        (id): id is string => typeof id === "string" && id.length > 0,
      ),
    ),
  );
  laneIds = ids.length === 0 ? EMPTY_LANES : Object.freeze(ids);
  emit();
}

/**
 * Whether this console has an authoritative admitted set at all.
 *
 * Before the daemon's answer arrives (D-FC-2) the set is empty, so every
 * well-formed marker looks unadmitted. Counting those would put the cold-start
 * window into `perch_marker_unadmitted_total`, and that counter is read as
 * "somebody tried to plant a card" — a number inflated by every launch is a
 * number nobody can act on. A failed load leaves this false: the console has
 * no answer, and refusing on the strength of a missing answer is not a
 * refusal it is entitled to make.
 */
export function admittedIssuersKnown(): boolean {
  return known;
}

/**
 * Whether `pubkey` is an admitted bridge identity. A module-level function,
 * never a closure: its identity never changes, which is what lets every
 * evidence card memoise on it.
 */
export function isAdmittedIssuer(pubkey: string): boolean {
  return admitted.has(pubkey.toLowerCase());
}

/** The lane channel ids from the last set, deduplicated, reference-stable. */
export function perchLaneChannelIds(): readonly string[] {
  return laneIds;
}

/** The lane map from the last set: threat-class slug to channel id. */
export function perchLaneChannels(): Readonly<Record<string, string>> {
  return lanes;
}

/**
 * Count an unadmitted marker once per event id. A re-render is not a second
 * marker, and the counter is what the governance strip renders — rejected
 * frames are counted and dropped, never silently dropped.
 *
 * Silently does nothing until the admitted set is known, for the reason
 * `admittedIssuersKnown` gives.
 */
export function countUnadmittedMarker(eventId: string): void {
  if (!known) return;
  if (countedEvents.has(eventId)) return;
  countedEvents.add(eventId);
  unadmittedTotal += 1;
  emit();
}

/** Read one perch counter by its metric name. */
export function readPerchCounter(name: PerchCounterName): number {
  if (name === "perch_marker_unadmitted_total") return unadmittedTotal;
  return 0;
}

/**
 * Subscribe to any change here: a set update, a new unadmitted event id, or
 * a reset. Returns the unsubscribe function.
 */
export function subscribePerchCounters(listener: () => void): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

const getVersion = (): number => version;
const getServerVersion = (): number => 0;
const getServerKnown = (): boolean => false;

/** `admittedIssuersKnown` for React, re-rendering when the answer arrives. */
export function useAdmittedIssuersKnown(): boolean {
  return useSyncExternalStore(
    subscribePerchCounters,
    admittedIssuersKnown,
    getServerKnown,
  );
}
const getServerLanes = (): readonly string[] => EMPTY_LANES;

/**
 * The admitted-issuer predicate for React. The function identity never
 * changes; the version subscription re-renders the caller when the set
 * behind it does, so a memoised card re-parses after an admission change.
 */
export function useAdmittedIssuerPredicate(): (pubkey: string) => boolean {
  useSyncExternalStore(subscribePerchCounters, getVersion, getServerVersion);
  return isAdmittedIssuer;
}

/**
 * The version counter behind the predicate, for a memo that must recompute
 * when the admitted set changes even though `isAdmittedIssuer`'s identity
 * never does. The set loads asynchronously after the first timeline render,
 * so a parse memoised on the function alone would stay "unadmitted" forever.
 */
export function useAdmittedIssuersVersion(): number {
  return useSyncExternalStore(
    subscribePerchCounters,
    getVersion,
    getServerVersion,
  );
}

/** The lane channel ids for React, reference-stable until the set changes. */
export function usePerchLaneChannelIds(): readonly string[] {
  return useSyncExternalStore(
    subscribePerchCounters,
    perchLaneChannelIds,
    getServerLanes,
  );
}

/**
 * Load the set through `loader` at most once per reload window, applying the
 * result through `setAdmittedIssuers`. Concurrent callers share one load. A
 * failed load keeps the previous set, warns, and may be retried after the
 * shorter retry window.
 */
export function ensureAdmittedIssuersLoaded(
  loader: () => Promise<{ issuers: string[]; lanes: Record<string, string> }>,
): Promise<void> {
  if (loadedAt !== null && Date.now() - loadedAt < ADMITTED_ISSUERS_RELOAD_MS) {
    return Promise.resolve();
  }
  if (loading) return loading;
  loading = (async () => {
    try {
      const result = await loader();
      setAdmittedIssuers(result.issuers, result.lanes);
      loadedAt = Date.now();
    } catch (error) {
      console.warn(
        "[perch] admitted issuers: load failed; keeping the previous set",
        error,
      );
      loadedAt =
        Date.now() - ADMITTED_ISSUERS_RELOAD_MS + ADMITTED_ISSUERS_RETRY_MS;
    } finally {
      loading = null;
    }
  })();
  return loading;
}

/** Community-switch fence. Registered in the typed reset registry. */
export function resetPerchAdmittedIssuers(): void {
  known = false;
  admitted = new Set();
  lanes = NO_LANES;
  laneIds = EMPTY_LANES;
  countedEvents.clear();
  unadmittedTotal = 0;
  loadedAt = null;
  loading = null;
  emit();
}
