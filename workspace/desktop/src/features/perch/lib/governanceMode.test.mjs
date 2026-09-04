import assert from "node:assert/strict";
import { test } from "node:test";

import {
  derivePerchGovernanceMode,
  GOVERNANCE_STALE_AFTER_MS,
} from "./governanceMode.ts";

function input(overrides) {
  return {
    partitionState: "healthy",
    totalGovernors: 1,
    healthyGovernors: 1,
    receivedAtMs: 1_000,
    nowMs: 1_000,
    bridgeShedding: false,
    staleAfterMs: GOVERNANCE_STALE_AFTER_MS,
    ...overrides,
  };
}

test("no frame is bridge-down, never healthy", () => {
  assert.equal(
    derivePerchGovernanceMode(input({ receivedAtMs: null })),
    "bridge-down",
    "a strip saying healthy when it has heard nothing is the worst thing it can say",
  );
});

test("a stale frame outranks whatever it last said", () => {
  assert.equal(
    derivePerchGovernanceMode(
      input({ nowMs: 1_000 + GOVERNANCE_STALE_AFTER_MS + 1 }),
    ),
    "stale",
  );
  assert.equal(
    derivePerchGovernanceMode(
      input({
        partitionState: "partitioned",
        nowMs: 1_000 + GOVERNANCE_STALE_AFTER_MS + 1,
      }),
    ),
    "stale",
    "a stale partitioned frame is still a reading about the past",
  );
  assert.equal(
    derivePerchGovernanceMode(
      input({ nowMs: 1_000 + GOVERNANCE_STALE_AFTER_MS }),
    ),
    "healthy",
    "exactly at the boundary is not yet stale",
  );
});

test("more than one governor is worse, not better, and says so", () => {
  assert.equal(
    derivePerchGovernanceMode(
      input({ totalGovernors: 3, healthyGovernors: 3 }),
    ),
    "fail-closed-no-transport",
    "the solo transport refuses a larger committee, so every destructive action is vetoed",
  );
});

test("a live single-governor frame reports its own partition state", () => {
  for (const state of ["healthy", "degraded", "partitioned", "healing"]) {
    assert.equal(
      derivePerchGovernanceMode(input({ partitionState: state })),
      state,
    );
  }
});

test("fail-closed outranks a partitioned reading, because it is the larger fact", () => {
  assert.equal(
    derivePerchGovernanceMode(
      input({ partitionState: "partitioned", totalGovernors: 2 }),
    ),
    "fail-closed-no-transport",
  );
});
