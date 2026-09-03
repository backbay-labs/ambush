import assert from "node:assert/strict";
import test from "node:test";

import { derivePerchShellRoute } from "./perchViews.ts";

test("a case path selects the case and carries its id", () => {
  assert.deepEqual(
    derivePerchShellRoute("/cases/9499a6e2-8872-453b-80d9-dafc6fc7fc69"),
    {
      selectedView: "case",
      selectedCaseId: "9499a6e2-8872-453b-80d9-dafc6fc7fc69",
    },
  );
  assert.deepEqual(derivePerchShellRoute("/channels/abc"), {
    selectedView: "other",
    selectedCaseId: null,
  });
  assert.deepEqual(derivePerchShellRoute("/cases/"), {
    selectedView: "case",
    selectedCaseId: null,
  });
});

test("a percent-encoded case segment is decoded, and a malformed one is kept verbatim", () => {
  assert.deepEqual(derivePerchShellRoute("/cases/a%20b"), {
    selectedView: "case",
    selectedCaseId: "a b",
  });
  assert.deepEqual(derivePerchShellRoute("/cases/%E0%A4%A"), {
    selectedView: "case",
    selectedCaseId: "%E0%A4%A",
  });
  assert.deepEqual(derivePerchShellRoute("/"), {
    selectedView: "other",
    selectedCaseId: null,
  });
});
