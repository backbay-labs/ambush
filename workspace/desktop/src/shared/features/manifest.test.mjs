import assert from "node:assert/strict";
import test from "node:test";

import { desktopFeatures, getFeature } from "./manifest.ts";

test("the perch console is a desktop preview feature, off by default", () => {
  const feature = getFeature("perch");

  assert.ok(feature, "perch entry missing from preview-features.json");
  assert.deepEqual(feature.platforms, ["desktop"]);
  assert.notEqual(feature.defaultEnabled, true);
  assert.ok(
    desktopFeatures.some((f) => f.id === "perch"),
    "perch should be listed among desktop features",
  );
});

test("the perch entry never renders the banned word", () => {
  const feature = getFeature("perch");

  assert.ok(feature, "perch entry missing from preview-features.json");
  assert.doesNotMatch(feature.name, /perch/i);
  assert.doesNotMatch(feature.description, /perch/i);
});
