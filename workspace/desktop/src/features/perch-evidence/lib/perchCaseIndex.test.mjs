import assert from "node:assert/strict";
import test from "node:test";

import {
  caseFor,
  rememberCase,
  resetPerchCaseIndex,
  subscribePerchCaseIndex,
} from "./perchCaseIndex.ts";

test("a promoted finding remembers its case and incident until the community resets", () => {
  resetPerchCaseIndex();
  assert.equal(caseFor("f1"), null);
  const seen = [];
  const unsubscribe = subscribePerchCaseIndex(() => seen.push(caseFor("f1")));
  rememberCase("f1", { caseId: "c1", incidentId: "i1" });
  assert.deepEqual(caseFor("f1"), { caseId: "c1", incidentId: "i1" });
  assert.equal(caseFor("f1"), caseFor("f1"), "reference-stable per finding");
  rememberCase("f1", { caseId: "c1", incidentId: "i1" });
  assert.equal(seen.length, 1, "an identical re-remember is silent");
  rememberCase("f1", { caseId: "c2", incidentId: "i2" });
  assert.deepEqual(seen.at(-1), { caseId: "c2", incidentId: "i2" });
  resetPerchCaseIndex();
  assert.equal(caseFor("f1"), null);
  assert.equal(seen.at(-1), null);
  unsubscribe();
});
