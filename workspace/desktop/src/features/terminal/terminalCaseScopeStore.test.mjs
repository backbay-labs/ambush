import assert from "node:assert/strict";
import { test } from "node:test";

import {
  setTerminalCaseScope,
  terminalCaseScope,
} from "./useTerminalCaseScope.ts";

test("setting and clearing the pin", () => {
  setTerminalCaseScope(null);
  assert.deepEqual(terminalCaseScope(), {});
  setTerminalCaseScope({ caseId: "c1", caseSlug: "case-0001" });
  assert.deepEqual(terminalCaseScope(), {
    caseId: "c1",
    caseSlug: "case-0001",
  });
  setTerminalCaseScope(null);
  assert.deepEqual(terminalCaseScope(), {});
});

test("a scope with no case id clears rather than pinning to undefined", () => {
  setTerminalCaseScope({ caseId: "c1" });
  setTerminalCaseScope({ caseSlug: "orphan" });
  assert.deepEqual(terminalCaseScope(), {});
});

test("an unchanged pin keeps its identity, so subscribers do not re-render", () => {
  setTerminalCaseScope(null);
  setTerminalCaseScope({ caseId: "c1", caseSlug: "s" });
  const first = terminalCaseScope();
  setTerminalCaseScope({ caseId: "c1", caseSlug: "s" });
  assert.equal(terminalCaseScope(), first);
});

test("clearing an already-clear pin keeps its identity too", () => {
  setTerminalCaseScope(null);
  const first = terminalCaseScope();
  setTerminalCaseScope(null);
  assert.equal(terminalCaseScope(), first);
});

test("a changed slug on the same case publishes", () => {
  setTerminalCaseScope({ caseId: "c1", caseSlug: "a" });
  const first = terminalCaseScope();
  setTerminalCaseScope({ caseId: "c1", caseSlug: "b" });
  assert.notEqual(terminalCaseScope(), first);
  assert.equal(terminalCaseScope().caseSlug, "b");
  setTerminalCaseScope(null);
});
