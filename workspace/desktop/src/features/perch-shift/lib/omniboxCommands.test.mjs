import assert from "node:assert/strict";
import { test } from "node:test";

import {
  matchCommand,
  parseOmniboxInput,
  PERCH_COMMANDS,
} from "./omniboxCommands.ts";

test("the registry is exactly two commands and neither runs a write", () => {
  assert.equal(PERCH_COMMANDS.length, 2);
  assert.deepEqual(PERCH_COMMANDS.map((command) => command.verb).sort(), [
    "open",
    "release containment",
  ]);
  for (const command of PERCH_COMMANDS) {
    assert.ok(
      command.consequence.length > 0,
      "a command with no consequence line is a spec bug",
    );
    assert.ok(
      !("run" in command),
      "the omnibox emits an intent; the surface that owns the write performs it",
    );
  }
});

test("> as the FIRST character switches mode; anywhere else it is query text", () => {
  assert.deepEqual(parseOmniboxInput("> open gaps"), {
    mode: "command",
    body: "open gaps",
  });
  assert.deepEqual(parseOmniboxInput("strength > 2"), {
    mode: "query",
    body: "strength > 2",
  });
  assert.deepEqual(parseOmniboxInput(""), { mode: "query", body: "" });
});

test("release containment stages a write on Containments and never posts", () => {
  const matched = matchCommand(
    "release containment cl_9b3645fc",
    PERCH_COMMANDS,
  );
  assert.ok(matched);
  assert.deepEqual(matched.spec.effect, {
    kind: "request-write",
    write: "release-containment",
  });
  assert.deepEqual(matched.args, ["cl_9b3645fc"]);

  const nav = matchCommand("open gaps", PERCH_COMMANDS);
  assert.deepEqual(nav?.spec.effect, { kind: "navigate", view: "gaps" });

  assert.equal(
    matchCommand("release cap-77f3a2", PERCH_COMMANDS),
    null,
    "cap- names a capability lease, a different object with a different lifetime",
  );
  assert.equal(
    matchCommand("grant hold h_a07aeacf", PERCH_COMMANDS),
    null,
    "a destructive verb one keystroke from every surface is what the render laws forbid",
  );
});

test("open refuses a surface that is not openable rather than navigating nowhere", () => {
  assert.equal(matchCommand("open nowhere", PERCH_COMMANDS), null);
  assert.ok(matchCommand("open leases", PERCH_COMMANDS));
});

test("the wrong number of arguments does not match", () => {
  assert.equal(matchCommand("release containment", PERCH_COMMANDS), null);
  assert.equal(
    matchCommand("release containment cl_a1b2 extra", PERCH_COMMANDS),
    null,
  );
});
