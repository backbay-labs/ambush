// The keymap's dispatch decision, as a table.
//
// The guards are the part worth testing: a held key, a chord, a rationale
// being typed. Every one of those is a sequence a keymap without guards would
// answer, and none of them is on a happy path.

import assert from "node:assert/strict";
import test from "node:test";

import { isDisabledOnRow, resolvePerchKey } from "./usePerchKeymap.ts";

const press = (key, extra = {}) => ({ key, ...extra });

test("a hold row answers R with refuse and G with grant", () => {
  assert.deepEqual(resolvePerchKey(press("r"), "hold"), {
    kind: "verb",
    verb: "refuse",
  });
  assert.deepEqual(resolvePerchKey(press("G"), "hold"), {
    kind: "verb",
    verb: "grant",
  });
});

test("no key on any row type resolves to a verdict bound to A", () => {
  // INV-31. The key survives a relabelled button, which is the failure the
  // ban exists to prevent, so this is asserted over every row type rather
  // than trusted from the registry alone.
  for (const rowType of ["finding", "hold", "case", "lane", "containment"]) {
    for (const key of ["a", "A"]) {
      const action = resolvePerchKey(press(key), rowType);
      assert.ok(
        action === null || action.kind !== "verb",
        `${key} on a ${rowType} row resolved to a verdict`,
      );
    }
  }
});

test("D is dismiss on a finding and resolves to nothing at all on a hold", () => {
  // The sharpest consequence of the ratified keymap: dismissal retroactively
  // removes pheromone deposits and refusal does not, and the two row types
  // interleave in one queue.
  assert.deepEqual(resolvePerchKey(press("d"), "finding"), {
    kind: "verb",
    verb: "dismiss",
  });
  assert.equal(resolvePerchKey(press("d"), "hold"), null);
});

// ---------------------------------------------------------------------------
// THE GUARDS. Each of these is a keypress a keymap without them would answer.
// ---------------------------------------------------------------------------

test("a held key is one intention, not forty", () => {
  assert.equal(resolvePerchKey(press("r", { repeat: true }), "hold"), null);
  assert.equal(resolvePerchKey(press("G", { repeat: true }), "hold"), null);
});

test("a keypress a nested control already answered is not answered twice", () => {
  assert.equal(
    resolvePerchKey(press("r", { defaultPrevented: true }), "hold"),
    null,
  );
});

test("a chord is a global shortcut, never a row verb", () => {
  assert.equal(
    resolvePerchKey(press("r", { primaryModifier: true }), "hold"),
    null,
  );
  assert.equal(resolvePerchKey(press("r", { altKey: true }), "hold"), null);
});

test("an operator typing a rationale is not refusing a hold", () => {
  assert.equal(
    resolvePerchKey(press("r", { editableTarget: true }), "hold"),
    null,
  );
  assert.equal(
    resolvePerchKey(press("Enter", { editableTarget: true }), "case"),
    null,
  );
});

test("with nothing selected no key resolves", () => {
  for (const key of ["r", "g", "j", "k", "e", "m", "u", "Enter"]) {
    assert.equal(resolvePerchKey(press(key), null), null, key);
  }
});

test("S is declared disabled on a hold rather than silently absent", () => {
  // INV-34. A key that quietly does nothing leaves the operator unable to tell
  // a rule from a broken build, so the registry states the disablement and the
  // UI states the reason.
  assert.deepEqual(resolvePerchKey(press("s"), "finding"), { kind: "snooze" });
  assert.equal(resolvePerchKey(press("s"), "hold"), null);
  assert.equal(isDisabledOnRow("s", "hold"), true);
  assert.equal(isDisabledOnRow("s", "finding"), false);
  assert.equal(isDisabledOnRow("r", "hold"), false);
});

test("navigation resolves on every row type and knows its direction", () => {
  for (const rowType of ["finding", "hold", "case", "lane", "containment"]) {
    assert.deepEqual(resolvePerchKey(press("j"), rowType), {
      kind: "move",
      delta: 1,
    });
    assert.deepEqual(resolvePerchKey(press("k"), rowType), {
      kind: "move",
      delta: -1,
    });
  }
});

test("Enter opens a case and does not open a hold", () => {
  // A hold's Enter is the grant's second stroke and belongs to the control
  // that owns the dwell. If this resolved `open` on a hold, the two would
  // fight for the same key.
  assert.deepEqual(resolvePerchKey(press("Enter"), "case"), { kind: "open" });
  assert.equal(resolvePerchKey(press("Enter"), "hold"), null);
});

test("Escape is never resolved here; the escape surface owns it", () => {
  for (const rowType of ["finding", "hold", "case", "lane", "containment"]) {
    assert.equal(resolvePerchKey(press("Escape"), rowType), null);
  }
});

test("an unbound key resolves to nothing rather than to the nearest match", () => {
  for (const key of ["x", "z", "1", "F5", "Tab", " "]) {
    assert.equal(resolvePerchKey(press(key), "hold"), null, key);
  }
});
