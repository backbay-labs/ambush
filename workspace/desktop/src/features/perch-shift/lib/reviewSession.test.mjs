import assert from "node:assert/strict";
import { test } from "node:test";

import { composeReviewSession } from "./reviewSession.ts";

const input = {
  operator: "connor",
  shiftStartMs: Date.UTC(2026, 2, 17, 22, 0, 0),
  nowMs: Date.UTC(2026, 2, 18, 6, 12, 0),
  cases: [
    {
      channelId: "27799e23-ab25-4659-b381-3de47ea7ca4d",
      slug: "case-0042",
      threatClass: "lateral_movement",
      readToMs: Date.UTC(2026, 2, 18, 5, 58, 0),
      canvasLines: 14,
      openThreadsUnread: 1,
      archivedAtMs: null,
      handoffNotes: "web-04 still isolated; ask ops about the rebuild",
    },
    {
      channelId: "0e1d2c3b-4a59-4687-9a0b-1c2d3e4f5061",
      slug: "case-0039",
      threatClass: "execution",
      readToMs: null,
      canvasLines: 0,
      openThreadsUnread: 0,
      archivedAtMs: Date.UTC(2026, 2, 18, 3, 11, 0),
      handoffNotes: null,
    },
  ],
  findings: { reviewed: 87, total: 214 },
  holds: { expiredUndecided: 1 },
  containments: [
    { leaseId: "cl_9b3645fc", host: "web-04", remainingMs: 0, expired: true },
    { leaseId: "cl_2", host: "db-01", remainingMs: 300_000, expired: false },
  ],
  snoozes: [
    { returnsAtMs: Date.UTC(2026, 2, 18, 9, 0, 0) },
    { returnsAtMs: Date.UTC(2026, 2, 18, 9, 30, 0) },
  ],
  verdicts: { confirm: 9, dismiss: 1, grant: 1, refuse: 0 },
  promotion: { promoted: 12, suppressed: 340 },
};

test("the END WATCH block carries every resumption fact, including reviewed/unreviewed counts", () => {
  const draft = composeReviewSession(input);
  assert.match(draft.title, /^END WATCH — connor, 22:00 → 06:12$/);
  assert.match(draft.notes, /CASES TOUCHED\s+2/);
  assert.match(
    draft.notes,
    /case-0042\s+lateral_movement\s+you read to 05:58 · canvas 14 lines · 1 open thread unread/,
  );
  assert.match(draft.notes, /case-0039\s+archived 03:11/);
  assert.match(
    draft.notes,
    /FINDINGS REVIEWED\s+87 \/ 214\s+\(127 unreviewed carry forward\)/,
  );
  assert.match(draft.notes, /HOLDS EXPIRED UNDECIDED\s+1/);
  assert.match(
    draft.notes,
    /OPEN CONTAINMENTS\s+2\s+\(1 EXPIRED, host still contained → containment board\)/,
  );
  assert.match(draft.notes, /SNOOZES RETURNING\s+2\s+next 09:00/);
  assert.match(
    draft.notes,
    /VERDICTS RECORDED\s+11\s+9 confirm · 1 dismiss · 1 grant/,
  );
  assert.match(draft.notes, /PROMOTED \/ SUPPRESSED\s+12 \/ 340/);
  assert.match(
    draft.notes,
    /HANDOFF NOTES · case-0042\n\s+web-04 still isolated/,
  );
  assert.deepEqual(draft.artifactRefs, [
    "case:27799e23-ab25-4659-b381-3de47ea7ca4d",
    "case:0e1d2c3b-4a59-4687-9a0b-1c2d3e4f5061",
    "containment-lease:cl_9b3645fc",
    "containment-lease:cl_2",
  ]);
  assert.equal(draft.blockers.expiredUndecided, 1);
});

test("no exclamation mark and no reassurance in the generated notes", () => {
  const draft = composeReviewSession({
    ...input,
    holds: { expiredUndecided: 0 },
  });
  assert.doesNotMatch(draft.notes, /!/);
  assert.doesNotMatch(
    draft.notes,
    /all clear|caught up|looks good|no data|nothing to see/i,
  );
});

test("the block declares its timezone, because the reader may not share it", () => {
  const draft = composeReviewSession(input);
  assert.match(draft.notes, /times in UTC/);
});

test("disagreeing review counts render as a disagreement, never as a clamped zero", () => {
  const draft = composeReviewSession({
    ...input,
    findings: { reviewed: 214, total: 87 },
  });
  assert.match(draft.notes, /reviewed exceeds total; counts disagree/);
  assert.doesNotMatch(draft.notes, /0 unreviewed carry forward/);
  assert.doesNotMatch(draft.notes, /-127/);
});

test("a shift that touched nothing still renders every heading", () => {
  const draft = composeReviewSession({
    ...input,
    cases: [],
    containments: [],
    snoozes: [],
    verdicts: { confirm: 0, dismiss: 0, grant: 0, refuse: 0 },
  });
  // An empty shift is a claim about coverage. The headings stay so the reader
  // sees WHICH things were zero rather than a block that omits them.
  for (const heading of [
    "CASES TOUCHED",
    "FINDINGS REVIEWED",
    "HOLDS EXPIRED UNDECIDED",
    "OPEN CONTAINMENTS",
    "SNOOZES RETURNING",
    "VERDICTS RECORDED",
    "PROMOTED / SUPPRESSED",
  ]) {
    assert.match(draft.notes, new RegExp(heading.replace("/", "\\/")));
  }
  assert.deepEqual(draft.artifactRefs, []);
});

test("composing does not reorder the caller's snooze list", () => {
  const snoozes = [{ returnsAtMs: 200 }, { returnsAtMs: 100 }];
  composeReviewSession({ ...input, snoozes });
  assert.deepEqual(snoozes, [{ returnsAtMs: 200 }, { returnsAtMs: 100 }]);
});
