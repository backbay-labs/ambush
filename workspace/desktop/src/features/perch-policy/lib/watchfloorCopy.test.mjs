import assert from "node:assert/strict";
import { test } from "node:test";

import { fillWatchfloor, WATCHFLOOR } from "./watchfloorCopy.ts";

test("the colony band says where liveness comes from, and where it does not", () => {
  const line = fillWatchfloor(WATCHFLOOR.colony, { n: 8 });
  assert.match(line, /8 agents/);
  assert.match(line, /26002 health stream/);
  assert.match(line, /never Nostr presence/);
});

test("the decay band separates the interpolated curve from the served number", () => {
  assert.match(WATCHFLOOR.decay, /curve is an interpolation/);
  assert.match(WATCHFLOOR.decay, /header number is the runtime's/);
});

test("no frame is stated as not-told, never as zero", () => {
  assert.match(WATCHFLOOR.noFrame, /not a concentration of zero/);
});

test("the wall says it changes nothing", () => {
  assert.match(WATCHFLOOR.noClicks, /changes nothing/);
});

test("an unfilled placeholder stays visible rather than blanking", () => {
  assert.equal(
    fillWatchfloor(WATCHFLOOR.cooldown, { n: 300 }),
    "deescalation_cooldown_secs 300 · {remaining}s remaining",
  );
});
