import assert from "node:assert/strict";
import test from "node:test";

import {
  ADVERSARY_CAP,
  escapeAdversaryText,
  escapedCodepointTitle,
} from "./adversaryText.ts";

// Every invisible character below is written as an escape so this file stays
// readable and free of the bytes it tests.

test("control, bidi and zero-width codepoints become named glyphs; a newline too", () => {
  const parts = escapeAdversaryText("isolate\u202Ehost\u200B\nsecond");
  const escaped = parts.filter((p) => p.kind === "escaped");
  assert.deepEqual(
    escaped.map((p) => p.codepoint),
    ["U+202E", "U+200B", "U+000A"],
  );
  assert.equal(
    parts
      .filter((p) => p.kind === "text")
      .map((p) => p.text)
      .join(""),
    "isolatehostsecond",
  );
});

test("adjacent text runs merge, plain text is one run, and an empty value is no parts", () => {
  assert.deepEqual(escapeAdversaryText("plain text"), [
    { kind: "text", text: "plain text" },
  ]);
  assert.deepEqual(escapeAdversaryText(""), []);
  const parts = escapeAdversaryText("a\u0000b");
  assert.equal(parts.length, 3);
  assert.equal(parts[1].kind, "escaped");
  assert.equal(parts[1].codepoint, "U+0000");
});

test("the glyph names the class: control pictures for C0, a visible space for zero-width, arrows for bidi", () => {
  const [lf] = escapeAdversaryText("\n").filter((p) => p.kind === "escaped");
  assert.equal(lf.glyph, "␊");
  const [zw] = escapeAdversaryText("\u200B").filter(
    (p) => p.kind === "escaped",
  );
  assert.equal(zw.glyph, "␣");
  const [rlo] = escapeAdversaryText("\u202E").filter(
    (p) => p.kind === "escaped",
  );
  assert.equal(rlo.glyph, "⇄");
  const [bom] = escapeAdversaryText("\uFEFF").filter(
    (p) => p.kind === "escaped",
  );
  assert.equal(bom.codepoint, "U+FEFF");
  const [c1] = escapeAdversaryText("\u0085").filter(
    (p) => p.kind === "escaped",
  );
  assert.equal(c1.codepoint, "U+0085");
  assert.equal(c1.glyph, "␀");
});

test("titles carry the Unicode name from the fixed table, and the bare codepoint otherwise", () => {
  assert.equal(
    escapedCodepointTitle("U+202E"),
    "U+202E RIGHT-TO-LEFT OVERRIDE",
  );
  assert.equal(escapedCodepointTitle("U+200B"), "U+200B ZERO WIDTH SPACE");
  assert.equal(escapedCodepointTitle("U+000A"), "U+000A LINE FEED");
  assert.equal(
    escapedCodepointTitle("U+FEFF"),
    "U+FEFF ZERO WIDTH NO-BREAK SPACE",
  );
  assert.equal(escapedCodepointTitle("U+0085"), "U+0085");
});

test("astral code points are one text unit each, never split", () => {
  const parts = escapeAdversaryText("\u{1F41D}\u202E\u{1F41D}");
  assert.equal(parts.length, 3);
  assert.equal(parts[0].text, "\u{1F41D}");
  assert.equal(parts[2].text, "\u{1F41D}");
  assert.equal(ADVERSARY_CAP, 512);
});
