/**
 * The END WATCH block: what the next operator needs in order to resume.
 *
 * Composed as plain text because it is read in three places that share no
 * renderer — the console's own summary, a plain message posted into each case
 * channel, and the review session the daemon stores. One composition means
 * those three cannot disagree about what the shift did.
 *
 * Times render in UTC and the block says so. A handoff is read by whoever comes
 * on next, who may not be in the outgoing operator's timezone, and an unlabeled
 * "05:58" that the reader silently resolves to their own wall clock is the
 * quietest possible way to lose eight hours of a containment window.
 */

export type ShiftCase = {
  channelId: string;
  slug: string;
  threatClass: string;
  readToMs: number | null;
  canvasLines: number;
  openThreadsUnread: number;
  archivedAtMs: number | null;
  handoffNotes: string | null;
};

export type ShiftInput = {
  operator: string;
  shiftStartMs: number;
  nowMs: number;
  cases: ShiftCase[];
  findings: { reviewed: number; total: number };
  holds: { expiredUndecided: number };
  containments: {
    leaseId: string;
    host: string;
    remainingMs: number;
    expired: boolean;
  }[];
  snoozes: { returnsAtMs: number }[];
  verdicts: { confirm: number; dismiss: number; grant: number; refuse: number };
  promotion: { promoted: number; suppressed: number };
};

export type ReviewSessionDraft = {
  title: string;
  notes: string;
  artifactRefs: string[];
  blockers: { expiredUndecided: number };
};

const hhmm = (ms: number) => {
  const d = new Date(ms);
  return `${String(d.getUTCHours()).padStart(2, "0")}:${String(d.getUTCMinutes()).padStart(2, "0")}`;
};

const pad = (label: string, value: string) => `  ${label.padEnd(26)}${value}`;

/**
 * The unreviewed remainder. `reviewed` and `total` reach the console from two
 * different queries, so they can disagree; when they do this renders the
 * disagreement rather than a clamp, because a clamped `0 unreviewed` is exactly
 * the reassurance the block exists to avoid.
 */
function carryForward(reviewed: number, total: number): string {
  const unreviewed = total - reviewed;
  if (unreviewed < 0) {
    return "   (reviewed exceeds total; counts disagree)";
  }
  return `   (${unreviewed} unreviewed carry forward)`;
}

export function composeReviewSession(input: ShiftInput): ReviewSessionDraft {
  const title = `END WATCH — ${input.operator}, ${hhmm(input.shiftStartMs)} → ${hhmm(input.nowMs)}`;
  const lines: string[] = [title, "  times in UTC", ""];

  lines.push(pad("CASES TOUCHED", String(input.cases.length)));
  for (const c of input.cases) {
    if (c.archivedAtMs !== null) {
      lines.push(`    ${c.slug.padEnd(10)} archived ${hhmm(c.archivedAtMs)}`);
      continue;
    }
    const read =
      c.readToMs === null ? "nothing read" : `you read to ${hhmm(c.readToMs)}`;
    const threads = `${c.openThreadsUnread} open thread${c.openThreadsUnread === 1 ? "" : "s"} unread`;
    lines.push(
      `    ${c.slug.padEnd(10)} ${c.threatClass.padEnd(18)} ${read} · canvas ${c.canvasLines} lines · ${threads}`,
    );
  }

  lines.push(
    pad(
      "FINDINGS REVIEWED",
      `${input.findings.reviewed} / ${input.findings.total}${carryForward(input.findings.reviewed, input.findings.total)}`,
    ),
  );
  lines.push(
    pad(
      "HOLDS EXPIRED UNDECIDED",
      `${input.holds.expiredUndecided}${input.holds.expiredUndecided > 0 ? "   must be acknowledged before ending" : ""}`,
    ),
  );

  const expired = input.containments.filter((c) => c.expired).length;
  lines.push(
    pad(
      "OPEN CONTAINMENTS",
      `${input.containments.length}${expired > 0 ? `   (${expired} EXPIRED, host still contained → containment board)` : ""}`,
    ),
  );

  const next = input.snoozes.map((s) => s.returnsAtMs).sort((a, b) => a - b)[0];
  lines.push(
    pad(
      "SNOOZES RETURNING",
      `${input.snoozes.length}${next === undefined ? "" : `   next ${hhmm(next)}`}`,
    ),
  );

  const v = input.verdicts;
  lines.push(
    pad(
      "VERDICTS RECORDED",
      `${v.confirm + v.dismiss + v.grant + v.refuse}   ${v.confirm} confirm · ${v.dismiss} dismiss · ${v.grant} grant${v.refuse ? ` · ${v.refuse} refuse` : ""}`,
    ),
  );
  lines.push(
    pad(
      "PROMOTED / SUPPRESSED",
      `${input.promotion.promoted} / ${input.promotion.suppressed}`,
    ),
  );

  for (const c of input.cases) {
    if (c.handoffNotes) {
      lines.push("", `  HANDOFF NOTES · ${c.slug}`, `    ${c.handoffNotes}`);
    }
  }

  return {
    title,
    notes: lines.join("\n"),
    artifactRefs: [
      ...input.cases.map((c) => `case:${c.channelId}`),
      ...input.containments.map((c) => `containment-lease:${c.leaseId}`),
    ],
    blockers: { expiredUndecided: input.holds.expiredUndecided },
  };
}
