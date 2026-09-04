import assert from "node:assert/strict";
import { test } from "node:test";

import { claimState, PERCH_WATCH_CLAIM_TTL_MS } from "./watchClaim.ts";

const claim = {
  holderPubkey: "ab".repeat(32),
  holderLabel: "connor",
  sinceMs: 1_000,
  ttlMs: PERCH_WATCH_CLAIM_TTL_MS,
};

test("twelve hours, then stale; none pages everyone", () => {
  assert.equal(PERCH_WATCH_CLAIM_TTL_MS, 43_200_000);
  assert.equal(claimState(null, 5_000), "none");
  assert.equal(claimState(claim, 1_000 + PERCH_WATCH_CLAIM_TTL_MS), "held");
  assert.equal(claimState(claim, 1_001 + PERCH_WATCH_CLAIM_TTL_MS), "stale");
});

test("both failure directions widen paging rather than narrow it", () => {
  // The two non-`held` states are the ones the strip renders as "classes 1-3
  // page everyone". A claim that could narrow delivery would let someone
  // silence a hold by forgetting to renew it.
  assert.notEqual(claimState(null, 0), "held");
  assert.notEqual(claimState(claim, Number.MAX_SAFE_INTEGER), "held");
});

test("a claim from the future is held, not stale", () => {
  assert.equal(
    claimState({ ...claim, sinceMs: 10_000 }, 5_000),
    "held",
    "clock skew must not expire a claim that was just made",
  );
});
