import assert from "node:assert/strict";
import { test } from "node:test";

import {
  PERCH_CASE_TEMPLATE,
  sectionText,
  shouldSeed,
} from "./caseTemplate.ts";

test("five fixed headings, no prose, no placeholders", () => {
  assert.equal(
    PERCH_CASE_TEMPLATE,
    [
      "## Timeline",
      "",
      "## Hypothesis",
      "",
      "## Actions taken",
      "",
      "## Open questions",
      "",
      "## Handoff notes",
      "",
    ].join("\n"),
  );
  assert.doesNotMatch(PERCH_CASE_TEMPLATE, /TODO|example|e\.g\./i);
});

test("seed only a canvas that never had content, only with edit rights, only once per channel", () => {
  const seeded = new Set();
  assert.equal(
    shouldSeed({
      content: null,
      isSuccess: true,
      canEdit: true,
      channelId: "a",
      seeded,
    }),
    true,
  );
  seeded.add("a");
  assert.equal(
    shouldSeed({
      content: null,
      isSuccess: true,
      canEdit: true,
      channelId: "a",
      seeded,
    }),
    false,
  );
  assert.equal(
    shouldSeed({
      content: "",
      isSuccess: true,
      canEdit: true,
      channelId: "b",
      seeded,
    }),
    false,
    "an emptied canvas has had content",
  );
  assert.equal(
    shouldSeed({
      content: null,
      isSuccess: true,
      canEdit: false,
      channelId: "c",
      seeded,
    }),
    false,
  );
  assert.equal(
    shouldSeed({
      content: null,
      isSuccess: false,
      canEdit: true,
      channelId: "d",
      seeded,
    }),
    false,
  );
});

test("sectionText reads the text under one heading and null when the heading is absent", () => {
  const md =
    "## Timeline\n02:38 promoted\n\n## Handoff notes\nweb-04 still isolated\nask ops\n";
  assert.equal(
    sectionText(md, "Handoff notes"),
    "web-04 still isolated\nask ops",
  );
  assert.equal(sectionText(md, "Hypothesis"), null);
});

test("a present-but-empty heading reads as empty, not as absent", () => {
  // /handoff has to tell "nobody wrote a note" from "this case has no notes
  // section". Collapsing them onto null loses the first.
  assert.equal(sectionText(PERCH_CASE_TEMPLATE, "Handoff notes"), "");
  assert.equal(sectionText(PERCH_CASE_TEMPLATE, "Nonexistent"), null);
});

test("the seeded template round-trips through sectionText for every heading", () => {
  for (const heading of [
    "Timeline",
    "Hypothesis",
    "Actions taken",
    "Open questions",
    "Handoff notes",
  ]) {
    assert.equal(
      sectionText(PERCH_CASE_TEMPLATE, heading),
      "",
      `${heading} must be readable back`,
    );
  }
});

test("a heading inside a fenced block is still a heading to this reader, and that is stated", () => {
  // The reader is line-based on purpose: it must not need a markdown parser in
  // the handoff path. A ``` fence containing "## Timeline" ends the previous
  // section early. Pinned so the limit is visible rather than surprising.
  const md = "## Handoff notes\nsee below\n```\n## Timeline\n```\n";
  assert.equal(sectionText(md, "Handoff notes"), "see below\n```");
});
