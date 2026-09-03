import { useSyncExternalStore } from "react";

import {
  type PerchSeqGap,
  perchGapsVersion,
  perchOpenGaps,
  subscribePerchGaps,
} from "./perchSubscriptions";

const EMPTY: readonly PerchSeqGap[] = Object.freeze([]);
let snapshotVersion = -1;
let snapshot: readonly PerchSeqGap[] = EMPTY;

function sameGaps(a: readonly PerchSeqGap[], b: readonly PerchSeqGap[]) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i += 1) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

/**
 * `getSnapshot` for `useSyncExternalStore`: rebuilt only when the gap set's
 * version moved, and even then the previous array is kept when its content
 * is the same, so a consumer that renders the gap row bails out of
 * re-render on every event that opened nothing.
 */
function getSnapshot(): readonly PerchSeqGap[] {
  const version = perchGapsVersion();
  if (version !== snapshotVersion) {
    snapshotVersion = version;
    const next = perchOpenGaps();
    if (next.length === 0) {
      snapshot = EMPTY;
    } else if (!sameGaps(snapshot, next)) {
      snapshot = Object.freeze(next);
    }
  }
  return snapshot;
}

const getServerSnapshot = (): readonly PerchSeqGap[] => EMPTY;

/**
 * The open sequence gaps, reference-stable between changes. A gap renders
 * as a row, never a toast, and closes only when the daemon serves the
 * missing range — the relay cannot heal it.
 */
export function usePerchOpenGaps(): readonly PerchSeqGap[] {
  return useSyncExternalStore(
    subscribePerchGaps,
    getSnapshot,
    getServerSnapshot,
  );
}
