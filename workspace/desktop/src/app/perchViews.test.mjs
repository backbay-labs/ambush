import assert from "node:assert/strict";
import test from "node:test";

import { derivePerchShellRoute } from "./perchViews.ts";

const full = (over) => ({
  selectedView: "other",
  selectedCaseId: null,
  selectedLaneId: null,
  chrome: "full",
  ...over,
});

test("a case path selects the case and carries its id", () => {
  assert.deepEqual(
    derivePerchShellRoute("/cases/9499a6e2-8872-453b-80d9-dafc6fc7fc69"),
    full({
      selectedView: "case",
      selectedCaseId: "9499a6e2-8872-453b-80d9-dafc6fc7fc69",
    }),
  );
  assert.deepEqual(derivePerchShellRoute("/channels/abc"), full({}));
  assert.deepEqual(
    derivePerchShellRoute("/cases/"),
    full({ selectedView: "case" }),
  );
});

test("a percent-encoded case segment is decoded, and a malformed one is kept verbatim", () => {
  assert.deepEqual(
    derivePerchShellRoute("/cases/a%20b"),
    full({ selectedView: "case", selectedCaseId: "a b" }),
  );
  assert.deepEqual(
    derivePerchShellRoute("/cases/%E0%A4%A"),
    full({ selectedView: "case", selectedCaseId: "%E0%A4%A" }),
  );
});

test("the root is the Watch", () => {
  assert.deepEqual(derivePerchShellRoute("/"), full({ selectedView: "watch" }));
});

test("a lane path carries its id", () => {
  assert.deepEqual(
    derivePerchShellRoute("/lanes/execution"),
    full({ selectedView: "lane", selectedLaneId: "execution" }),
  );
});

test("every routed surface has its own view", () => {
  for (const [path, view] of [
    ["/leases", "leases"],
    ["/policy", "policy"],
    ["/watch-floor", "watchfloor"],
    ["/ledger", "ledger"],
    ["/tuning", "tuning"],
    ["/handoff", "handoff"],
    ["/gaps", "gaps"],
  ]) {
    assert.equal(derivePerchShellRoute(path).selectedView, view, path);
  }
});

test("only the Watchfloor drops chrome", () => {
  assert.equal(derivePerchShellRoute("/watch-floor").chrome, "bare");
  for (const path of [
    "/",
    "/leases",
    "/policy",
    "/ledger",
    "/tuning",
    "/handoff",
    "/gaps",
  ]) {
    assert.equal(derivePerchShellRoute(path).chrome, "full", path);
  }
});

test("a prefix is not a match: /policyholders is not /policy", () => {
  // A `startsWith` alone would put the whole app into the policy view for any
  // future route sharing a stem, and the bare-chrome rule makes that visible
  // as a screen that loses its sidebar.
  assert.equal(derivePerchShellRoute("/policyholders").selectedView, "other");
  assert.equal(derivePerchShellRoute("/watch-floors").selectedView, "other");
  assert.equal(derivePerchShellRoute("/policy/rules").selectedView, "policy");
});
