import assert from "node:assert/strict";
import { test } from "node:test";

import {
  parseContainmentList,
  parseReleaseOutcome,
} from "./containmentList.ts";

test("a release the daemon did not describe reads null, never released", () => {
  const outcome = parseReleaseOutcome({});
  assert.equal(
    outcome.leaseClosed,
    null,
    "'the daemon did not say' is a third answer and must not render as released",
  );
  assert.equal(outcome.fullyReversed, null);
  assert.equal(outcome.attestationVerified, null);
  assert.equal(outcome.attestationError, null);
  assert.deepEqual(outcome.steps, []);
});

test("a 200 whose inverse failed is carried through as false, not smoothed", () => {
  const outcome = parseReleaseOutcome({
    lease_closed: false,
    fully_reversed: false,
    attestation_verified: false,
    attestation_error: "unattested: no governor available",
    steps: [
      {
        kind: "restore_host_connectivity",
        status: "failed",
        detail: "adapter refused",
      },
    ],
  });
  assert.equal(outcome.leaseClosed, false);
  assert.equal(outcome.attestationError, "unattested: no governor available");
  assert.deepEqual(outcome.steps, [
    {
      label: "restore_host_connectivity",
      status: "failed",
      reason: "adapter refused",
    },
  ]);
});

test("the list keeps the daemon's order and never invents one", () => {
  const list = parseContainmentList({
    observed_at_ms: 7,
    leases: [
      { lease_id: "cl_b", expires_at_ms: 200 },
      { lease_id: "cl_a", expires_at_ms: 100 },
    ],
  });
  assert.deepEqual(
    list.leases.map((lease) => lease.leaseId),
    ["cl_b", "cl_a"],
    "the daemon sorts by expiry then id; re-sorting would disagree with its paging",
  );
  assert.equal(list.observedAtMs, 7);
});

test("expired is only true when the daemon says so", () => {
  const list = parseContainmentList({
    leases: [{ lease_id: "cl_a" }, { lease_id: "cl_b", expired: true }],
  });
  assert.equal(list.leases[0].expired, false);
  assert.equal(list.leases[1].expired, true);
});

test("a malformed body yields an empty list rather than throwing at the board", () => {
  assert.deepEqual(parseContainmentList(null).leases, []);
  assert.deepEqual(parseContainmentList({ leases: "nope" }).leases, []);
  assert.equal(parseContainmentList({}).observedAtMs, null);
});
