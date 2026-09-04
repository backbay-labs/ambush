import assert from "node:assert/strict";
import { test } from "node:test";

import {
  caseTerminalScope,
  TERMINAL_BANNER_LINE,
} from "./terminalCaseScope.ts";

const CASE_ID = "27799e23-ab25-4659-b381-3de47ea7ca4d";

test("a case pin is a working directory plus three env vars, so swarmctl's relative data/ defaults land under the case", () => {
  const scope = caseTerminalScope(
    CASE_ID,
    "case-0042",
    "/var/lib/ambush/perch",
  );
  assert.equal(scope.cwd, `/var/lib/ambush/perch/cases/${CASE_ID}`);
  assert.deepEqual(scope.env, [
    ["AMBUSH_CASE_ID", CASE_ID],
    ["AMBUSH_CASE", "case-0042"],
    ["SWARM_RESULTS_ROOT", `/var/lib/ambush/perch/cases/${CASE_ID}`],
  ]);
});

test("a slug that is not shell-safe is replaced by the id, never interpolated", () => {
  const scope = caseTerminalScope(CASE_ID, "$(rm -rf /)", "/root");
  assert.equal(scope.env[1][1], CASE_ID);
});

test("the banner is the non-fiction line", () => {
  assert.equal(
    TERMINAL_BANNER_LINE,
    "124 of 126 swarmctl subcommands are not HTTP clients. This is a real shell on this host.",
  );
});

test("every rejected slug shape falls back to the id rather than being escaped", () => {
  for (const slug of [
    "",
    "-leading-dash",
    ".leading-dot",
    "has space",
    "has/slash",
    "back`tick`",
    "semi;colon",
    "new\nline",
    "a".repeat(65),
    "über",
  ]) {
    assert.equal(
      caseTerminalScope(CASE_ID, slug, "/root").env[1][1],
      CASE_ID,
      `slug ${JSON.stringify(slug)} must not reach the shell`,
    );
  }
});

test("a 64-character slug is the longest accepted", () => {
  assert.equal(
    caseTerminalScope(CASE_ID, "a".repeat(64), "/r").env[1][1],
    "a".repeat(64),
  );
});

test("SWARM_RESULTS_ROOT is the same string as the cwd, not a second computation", () => {
  const scope = caseTerminalScope(CASE_ID, "case-1", "/root");
  assert.equal(scope.env[2][1], scope.cwd);
});
