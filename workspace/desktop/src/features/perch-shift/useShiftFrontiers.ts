import * as React from "react";

import { useAppShell } from "@/app/AppShellContext";

import type { ShiftCase } from "./lib/reviewSession";

/**
 * One case as the surfaces below know it, before the read frontiers are folded
 * in. Kept separate from {@link ShiftCase} so the caller cannot accidentally
 * supply a read position the shell never gave it.
 */
export type ShiftCaseSeed = Omit<
  ShiftCase,
  "readToMs" | "openThreadsUnread"
> & {
  /** Thread roots in this case, with the last reply time in unix SECONDS. */
  threadRoots: { rootId: string; lastReplyAtSeconds: number }[];
};

type ChannelReadAt = (channelId: string) => number | null;
type ThreadReadAt = (
  rootId: string,
  channelId?: string | null,
) => number | null;

/**
 * Fold the read frontiers onto each case.
 *
 * `getChannelReadAt` and `getThreadReadAt` answer in unix SECONDS; every
 * number in the handoff block is MILLISECONDS. The conversion happens here,
 * once, because a seconds value read as milliseconds dates a shift to 1970 and
 * a milliseconds value read as seconds dates it to the year 56000 — neither
 * looks like an error in a summary a human is skimming at 06:00.
 *
 * A thread the operator has never opened counts as unread. Treating an absent
 * frontier as "read" would let the handoff report a clean queue for exactly
 * the threads nobody has looked at.
 */
export function foldReadFrontiers(
  cases: ShiftCaseSeed[],
  getChannelReadAt: ChannelReadAt,
  getThreadReadAt: ThreadReadAt,
): ShiftCase[] {
  return cases.map((seed) => {
    const readAtSeconds = getChannelReadAt(seed.channelId);
    const openThreadsUnread = seed.threadRoots.filter((root) => {
      const frontier = getThreadReadAt(root.rootId, seed.channelId);
      return frontier === null || frontier < root.lastReplyAtSeconds;
    }).length;
    const { threadRoots: _threadRoots, ...rest } = seed;
    return {
      ...rest,
      readToMs: readAtSeconds === null ? null : readAtSeconds * 1000,
      openThreadsUnread,
    };
  });
}

/** {@link foldReadFrontiers} against the mounted shell's read-state manager. */
export function useShiftFrontiers(cases: ShiftCaseSeed[]): ShiftCase[] {
  const { getChannelReadAt, getThreadReadAt, readStateVersion } = useAppShell();

  // biome-ignore lint/correctness/useExhaustiveDependencies: readStateVersion invalidates the stable getChannelReadAt/getThreadReadAt callbacks
  return React.useMemo(
    () => foldReadFrontiers(cases, getChannelReadAt, getThreadReadAt),
    [cases, getChannelReadAt, getThreadReadAt, readStateVersion],
  );
}
