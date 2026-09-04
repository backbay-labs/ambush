import assert from "node:assert/strict";
import { test } from "node:test";

import {
  buildExportManifest,
  planExportFiles,
  renderVerifyMd,
} from "./exportBundle.ts";

const BYTES = new Uint8Array([123, 125]);

const entries = [
  { kind: "receipt", id: "resp-1", bytes: BYTES, tier: 0, reconciled: true },
  {
    kind: "rollback",
    id: "rb_81c4a588",
    bytes: BYTES,
    tier: 1,
    reconciled: true,
  },
  {
    kind: "hold",
    id: "h_a07aeacf",
    bytes: BYTES,
    tier: 0,
    reconciled: true,
    verdictCardId: "cccc",
  },
  { kind: "hold", id: "h_ghost", bytes: BYTES, tier: 0, reconciled: false },
  { kind: "envelope", id: "seq-7", bytes: BYTES, tier: 2, reconciled: true },
];

test("every file carries a tier and the bundle says what it does not answer", async () => {
  const files = planExportFiles(entries);
  assert.ok(
    files.some(
      (f) => f.path === "receipts/resp-1.json" && f.verification_tier === 0,
    ),
  );
  assert.ok(
    files.some(
      (f) =>
        f.path === "receipts/rb_81c4a588.json" && f.verification_tier === 1,
    ),
  );
  assert.ok(
    files.some(
      (f) => f.path === "envelopes/seq-7.json" && f.verification_tier === 2,
    ),
  );
  assert.ok(
    !files.some((f) => f.path.includes("h_ghost")),
    "an unreconciled row is a claim the daemon does not corroborate; the bundle must not lend it authority",
  );

  const manifest = await buildExportManifest(files, {
    exportingOperator: `swarm:ed25519:${"a".repeat(64)}`,
    derived: [{ fn: "derivePerchGovernanceMode()", value: "healthy" }],
  });
  assert.equal(manifest.answers_who_approved, false);
  assert.equal(manifest.files.length, files.length);
  assert.ok(
    manifest.files.every(
      (f) => typeof f.sha256 === "string" && f.sha256.length === 64,
    ),
  );
  assert.deepEqual(
    Object.keys(manifest).sort(),
    [
      "answers_who_approved",
      "exporting_operator",
      "files",
      "generated_at",
      "manifest_signature",
      "verification_tiers_present",
    ].sort(),
  );
});

test("envelopes/ is present and empty, not omitted, when nothing is signed", () => {
  const files = planExportFiles(entries.filter((e) => e.kind !== "envelope"));
  assert.ok(
    files.some((f) => f.path === "envelopes/.keep"),
    "an absent directory reads as 'we did not look'",
  );
});

test("the digest is over the bytes as given, so a signed record stays verifiable", async () => {
  const files = planExportFiles([
    {
      kind: "receipt",
      id: "a",
      bytes: new Uint8Array([1, 2, 3]),
      tier: 0,
      reconciled: true,
    },
  ]);
  const manifest = await buildExportManifest(files, {
    exportingOperator: "op",
    derived: [],
  });
  // sha256 of the three bytes 01 02 03.
  assert.equal(
    manifest.files[0].sha256,
    "039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81",
  );
});

test("VERIFY.md names only tiers the bundle actually contains", async () => {
  const files = planExportFiles([
    { kind: "receipt", id: "a", bytes: BYTES, tier: 0, reconciled: true },
  ]);
  const md = renderVerifyMd(
    await buildExportManifest(files, { exportingOperator: "op", derived: [] }),
  );
  assert.match(md, /Tier 0 files/);
  assert.doesNotMatch(md, /Tier 1 files/);
  assert.doesNotMatch(md, /Tier 2 files/);
  assert.match(
    md,
    /answers_who_approved/,
    "the bundle states the question it does not answer",
  );
  assert.match(md, /swarmctl/, "verification must not require this console");
});
