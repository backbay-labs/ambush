import assert from "node:assert/strict";
import { test } from "node:test";

import { NOTIFICATION_BODIES, NOTIFICATION_FIELDS } from "./copy.ts";

test("exactly four wake classes, and every interpolation is a typed field", () => {
  assert.deepEqual(Object.keys(NOTIFICATION_BODIES).sort(), [
    "containmentFailedToRelease",
    "holdNamedYou",
    "incident",
    "snoozeDue",
  ]);
  for (const body of Object.values(NOTIFICATION_BODIES)) {
    for (const [, name] of body.matchAll(/\{([a-zA-Z]+)\}/g)) {
      assert.ok(
        NOTIFICATION_FIELDS.includes(name),
        `${name} is not a typed field`,
      );
    }
    assert.doesNotMatch(body, /!/);
  }
});

test("class 3 carries no TTL-backstop sentence, because the TTL has already failed", () => {
  assert.doesNotMatch(
    NOTIFICATION_BODIES.containmentFailedToRelease,
    /backstop|self-releases|TTL will/i,
  );
  assert.match(
    NOTIFICATION_BODIES.containmentFailedToRelease,
    /will not clear on its own/,
  );
});

test("no body carries free text from a detector", () => {
  // The fields that could carry adversary text are exactly the ones NOT on the
  // list: command_line, path, process, url, user_agent. Pinned so adding one
  // to NOTIFICATION_FIELDS is a visible decision rather than a quiet edit.
  for (const banned of ["commandLine", "path", "process", "url", "userAgent"]) {
    assert.equal(
      NOTIFICATION_FIELDS.includes(banned),
      false,
      `${banned} must never be interpolatable into an OS notification`,
    );
  }
});

test("findings do not page", () => {
  assert.equal(Object.keys(NOTIFICATION_BODIES).includes("finding"), false);
});
