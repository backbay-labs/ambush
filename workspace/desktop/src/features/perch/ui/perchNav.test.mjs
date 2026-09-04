import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

/**
 * The nav and the surface manifest are two lists of the same thing, kept in
 * two repositories of truth on purpose: the manifest is the gate's contract
 * and the nav is the operator's. This test is what stops them drifting.
 */
const MANIFEST = new URL(
  "../../../../../../tools/perch-surfaces.tsv",
  import.meta.url,
);

test("every routed surface except lanes and cases has a nav entry", () => {
  const rows = readFileSync(MANIFEST, "utf8")
    .split("\n")
    .filter((line) => line && !line.startsWith("#"))
    .map((line) => line.split("\t"))
    .filter((fields) => fields.length === 4 && fields[0] !== "id");

  const routed = rows
    .map((fields) => fields[2])
    .filter((route) => route !== "-")
    // Both take a parameter: there is no index for either, and a nav item
    // would be picking a case or a threat class for the operator.
    .filter((route) => !route.includes("$"));

  const nav = readFileSync(new URL("./PerchNav.tsx", import.meta.url), "utf8");
  for (const route of routed) {
    assert.ok(
      nav.includes(`to: "${route}"`),
      `${route} is a routed surface with no nav entry`,
    );
  }
});

test("the nav points at no route the manifest does not carry", () => {
  const rows = readFileSync(MANIFEST, "utf8")
    .split("\n")
    .filter((line) => line && !line.startsWith("#"))
    .map((line) => line.split("\t"))
    .filter((fields) => fields.length === 4 && fields[0] !== "id");
  const routed = new Set(rows.map((fields) => fields[2]));

  const nav = readFileSync(new URL("./PerchNav.tsx", import.meta.url), "utf8");
  for (const [, route] of nav.matchAll(/\{ to: "([^"]+)"/g)) {
    assert.ok(
      routed.has(route),
      `${route} is in the nav and not in the manifest`,
    );
  }
});
