import assert from "node:assert/strict";
import { test } from "node:test";

import { fillHandoff, HANDOFF } from "./handoffCopy.ts";

test("placeholders fill; an unknown key stays visible rather than blanking", () => {
  assert.equal(
    fillHandoff(HANDOFF.claimHeld, { holder: "connor", since: "22:00" }),
    "Watch held by connor since 22:00",
  );
  assert.equal(
    fillHandoff(HANDOFF.claimHeld, { holder: "connor" }),
    "Watch held by connor since {since}",
    "a missing value must not render as 'Watch held by connor since '",
  );
  assert.equal(
    fillHandoff(HANDOFF.blocked, { n: 2 }).startsWith("2 holds"),
    true,
  );
});

test("the claim's copy says what taking the watch does NOT do", () => {
  // The dangerous misreading is that claiming the watch removes other people
  // from the page. Both strings that mention the claim have to deny it.
  assert.match(HANDOFF.claimDoesNot, /does not change who is p-tagged/);
  assert.match(HANDOFF.claimStale, /fallen back to everyone/);
});

test("the publish copy promises only what actually happens", () => {
  // W3-36: no daemon-side shift record exists. A string naming a session id
  // would be a claim about a write the console never makes.
  assert.doesNotMatch(HANDOFF.published, /session/i);
  assert.match(HANDOFF.noDaemonRecord, /daemon keeps no shift record/);
  assert.equal(
    fillHandoff(HANDOFF.publishFailed, { published: 1, n: 3, failed: 2 }),
    "Handoff published to 1 of 3 case channels. 2 did not accept it; the block is below, unchanged, to post by hand.",
  );
});

test("acknowledging is described as changing nothing", () => {
  assert.match(HANDOFF.blocked, /Acknowledging changes nothing about the hold/);
  assert.match(HANDOFF.ackRow, /Nothing ran\. The finding is still open\./);
});
