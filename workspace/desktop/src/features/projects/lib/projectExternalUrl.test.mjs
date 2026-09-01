import assert from "node:assert/strict";
import { test } from "node:test";

import { projectExternalRefUrl } from "./projectExternalUrl.ts";

test("opens the selected GitHub branch", () => {
  assert.equal(
    projectExternalRefUrl(
      "https://github.com/backbay-labs/ambush",
      "fix/agent-profile-about-preserve",
    ),
    "https://github.com/backbay-labs/ambush/tree/fix%2Fagent-profile-about-preserve",
  );
});

test("normalizes clone URLs before adding the selected ref", () => {
  assert.equal(
    projectExternalRefUrl(
      "https://github.com/backbay-labs/ambush.git/",
      "main",
    ),
    "https://github.com/backbay-labs/ambush/tree/main",
  );
});

test("keeps unsupported and unscoped URLs unchanged", () => {
  assert.equal(
    projectExternalRefUrl("https://gitlab.com/block/ambush", "main"),
    "https://gitlab.com/block/ambush",
  );
  assert.equal(
    projectExternalRefUrl("https://github.com/backbay-labs/ambush", null),
    "https://github.com/backbay-labs/ambush",
  );
  assert.equal(projectExternalRefUrl("not a URL", "main"), "not a URL");
});
