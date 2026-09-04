import assert from "node:assert/strict";
import test from "node:test";

import {
  isDaemonDependentQuery,
  isRelayDependentQuery,
  PERCH_FRESHNESS,
  PERCH_NO_RETRY,
  perchKeys,
} from "./perchKeys.ts";

test("every key names its source first and has a freshness row", () => {
  for (const [name, factory] of Object.entries(perchKeys)) {
    const k = factory("x", 0);
    assert.ok(["relay", "daemon", "local"].includes(k[0]), `${name}: ${k[0]}`);
    assert.ok(name in PERCH_FRESHNESS, `${name} has no freshness row`);
  }
  assert.equal(perchKeys.admittedIssuers()[0], "daemon");
  assert.ok(
    isDaemonDependentQuery({ queryKey: perchKeys.reviewedFindings(0) }),
  );
  assert.ok(
    !isRelayDependentQuery({ queryKey: perchKeys.reviewedFindings(0) }),
  );
});

test("the freshness table has no row without a key, and no policy left implicit", () => {
  for (const [name, row] of Object.entries(PERCH_FRESHNESS)) {
    assert.ok(name in perchKeys, `${name} has a freshness row but no key`);
    assert.equal(typeof row.staleTime, "number", name);
    assert.ok(row.poll === false || row.poll > 0, name);
    assert.ok(Array.isArray(row.invalidatesOnWrite), name);
    for (const dependent of row.invalidatesOnWrite) {
      assert.ok(
        dependent in perchKeys,
        `${name} invalidates unknown key ${dependent}`,
      );
    }
    assert.ok(row.why.length > 20, `${name} has no reason`);
  }
});

test("the relay and daemon predicates partition the sources, and local is neither", () => {
  assert.ok(isRelayDependentQuery({ queryKey: perchKeys.caseTimeline("c") }));
  assert.ok(!isDaemonDependentQuery({ queryKey: perchKeys.caseTimeline("c") }));
  assert.ok(!isRelayDependentQuery({ queryKey: perchKeys.spoolHealth() }));
  assert.ok(!isDaemonDependentQuery({ queryKey: perchKeys.spoolHealth() }));
  assert.deepEqual(PERCH_NO_RETRY, { retry: 0 });
});
