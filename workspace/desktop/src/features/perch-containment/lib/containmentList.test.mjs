import assert from "node:assert/strict";
import { test } from "node:test";

import daemonFixture from "../../../testing/perch/daemonContainmentFixture.json" with {
  type: "json",
};
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

/** One entry of `open_leases`, in the shape `GET /v1/operator/containment/leases` serves. */
const served = (leaseId, extra = {}, wrapper = {}) => ({
  lease: {
    schema_version: 1,
    lease_id: leaseId,
    action: { type: "isolate_host", host_id: "web-04" },
    origin_receipt_id: `resp:${leaseId}`,
    governance_receipt_id: null,
    blast_radius: { scope_kind: "host", scope_value: "web-04" },
    rollback: { required: true, steps: [] },
    issued_at_ms: 1,
    expires_at_ms: 100,
    ...extra,
  },
  remaining_ms: 99,
  expired: false,
  ...wrapper,
});

test("the daemon's own answer parses: the captured GET /v1/operator/containment/leases body", () => {
  // Captured from a live daemon on 2026-09-06 after the window walk granted
  // an isolate_host hold. The board rendered "No open containments" against it
  // because the parser read `leases` and flat fields the mock had invented;
  // the daemon serves `open_leases` and nests the lease under `lease`.
  const list = parseContainmentList(daemonFixture);
  assert.equal(list.leases.length, 1);
  const lease = list.leases[0];
  assert.equal(
    lease.leaseId,
    "containment:walk-d82c41-2:isolate_host:resp:walk-d82c41-2:lease:walk-d82c41-2:isolate_host:1788741336782",
  );
  assert.equal(lease.actionKind, "isolate_host");
  assert.equal(lease.scopeValue, "host-ops-1");
  assert.equal(
    lease.originReceiptId,
    "resp:walk-d82c41-2:lease:walk-d82c41-2:isolate_host:1788741336782",
  );
  assert.equal(
    lease.governanceReceiptId,
    "bdeffa4aae44eb95e69104358ca3623223fe3baf4b54aa5eeaf5429fb4642eac",
  );
  assert.equal(lease.issuedAtMs, 1788741336782);
  assert.equal(lease.expiresAtMs, 1788742236782);
  assert.equal(lease.remainingMs, 614814);
  assert.equal(lease.expired, false);
  assert.equal(list.observedAtMs, 1788741621968);
});

test("the list keeps the daemon's order and never invents one", () => {
  const list = parseContainmentList({
    observed_at_ms: 7,
    open_leases: [
      served("cl_b", { expires_at_ms: 200 }),
      served("cl_a", { expires_at_ms: 100 }),
    ],
  });
  assert.deepEqual(
    list.leases.map((lease) => lease.leaseId),
    ["cl_b", "cl_a"],
    "the daemon sorts by expiry then id; re-sorting would disagree with its paging",
  );
  assert.equal(list.observedAtMs, 7);
});

test("expired and remaining_ms are read from the wrapper the daemon puts them on, never the lease", () => {
  const list = parseContainmentList({
    open_leases: [
      served("cl_a"),
      served(
        "cl_b",
        { expired: true, remaining_ms: 5 },
        { expired: true, remaining_ms: 0 },
      ),
    ],
  });
  assert.equal(list.leases[0].expired, false);
  assert.equal(list.leases[0].remainingMs, 99);
  assert.equal(list.leases[1].expired, true);
  assert.equal(list.leases[1].remainingMs, 0);
});

test("a malformed body yields an empty list rather than throwing at the board", () => {
  assert.deepEqual(parseContainmentList(null).leases, []);
  assert.deepEqual(parseContainmentList({ open_leases: "nope" }).leases, []);
  assert.deepEqual(
    parseContainmentList({ leases: [served("cl_a")] }).leases,
    [],
    "the flat shape the mock once invented is not the daemon's and must not parse",
  );
  assert.equal(parseContainmentList({}).observedAtMs, null);
});
