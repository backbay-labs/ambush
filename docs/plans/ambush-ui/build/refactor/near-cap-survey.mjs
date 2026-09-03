#!/usr/bin/env node
// 15-FILE-SPLIT-PLAN.md §7 — "which files can Perch not add a line to?", made
// re-runnable. Read-only; touches nothing in BUZZ.
//
//   node near-cap-survey.mjs [--buzz /path/to/buzz] [--threshold 950] [--json]
//
// Prints every governed file at or above the threshold, with the cap the
// differential ratchet would actually apply to it. Three states:
//
//   FROZEN   base > 1000 — allowedLineCount pins the limit at the base size, so
//            the file may hold or shrink but not grow by one line.
//   AT-CAP   base == 1000 — same practical effect.
//   TIGHT    base in [threshold, 1000) — headroom = 1000 - base.
//
// Gate semantics are copied from BUZZ scripts/check-file-sizes-core.mjs:24-33.
// Rule roots are copied from the three per-project rule tables and verified
// against them at startup, so this script fails loudly rather than silently
// under-reporting when a project adds a governed root.

import { readFileSync, readdirSync, statSync } from "node:fs";
import path from "node:path";

const args = process.argv.slice(2);
const buzz = valueOf("--buzz") ?? "/Users/connor/Medica/backbay/buzz";
const threshold = Number(valueOf("--threshold") ?? 950);
const asJson = args.includes("--json");

function valueOf(flag) {
  const i = args.indexOf(flag);
  return i === -1 ? undefined : args[i + 1];
}

const MAX_LINES = 1000;

/** BUZZ scripts/check-file-sizes-core.mjs:24-29, verbatim. */
function countLines(content) {
  if (content.length === 0) return 0;
  return content.split(/\r?\n/).length;
}

/** BUZZ scripts/check-file-sizes-core.mjs:31-33, verbatim. */
function allowedLineCount(baseLines, maxLines) {
  return baseLines == null || baseLines <= maxLines ? maxLines : baseLines;
}

// Mirrors of the three rule tables. `checkScript` is the file each root is
// copied from; `assertRootsStillDeclared` re-reads it and fails if a root
// disappeared or a new one appeared that this survey does not know about.
const PROJECTS = [
  {
    project: "desktop",
    checkScript: "desktop/scripts/check-file-sizes.mjs",
    rules: [
      ["src-tauri/src", [".rs"]],
      ["src-tauri/crates", [".rs"]],
      ["src/app", [".ts", ".tsx"]],
      ["src/features", [".ts", ".tsx"]],
      ["src/shared/api", [".ts", ".tsx"]],
      ["src/shared/context", [".ts", ".tsx"]],
      ["src/shared/lib", [".ts", ".tsx"]],
      ["src/shared/ui", [".ts", ".tsx"]],
      ["src/shared/styles", [".css"]],
    ],
  },
  {
    project: "web",
    checkScript: "web/scripts/check-file-sizes.mjs",
    rules: null, // filled in from the script itself; see readRuleRoots
  },
  {
    project: "mobile",
    checkScript: "mobile/scripts/check-file-sizes.mjs",
    rules: null,
  },
];

/** Pull the `root:` string literals out of a project's rule table. */
function readRuleRoots(checkScript) {
  const source = readFileSync(path.join(buzz, checkScript), "utf8");
  return [...source.matchAll(/root:\s*"([^"]+)"/g)].map((m) => m[1]);
}

/** Pull the extension sets out of a project's rule table, in root order. */
function readRuleExtensions(checkScript) {
  const source = readFileSync(path.join(buzz, checkScript), "utf8");
  return [...source.matchAll(/extensions:\s*new Set\(\[([^\]]*)\]\)/g)].map(
    (m) => [...m[1].matchAll(/"([^"]+)"/g)].map((x) => x[1]),
  );
}

function assertRootsStillDeclared(entry) {
  const declared = readRuleRoots(entry.checkScript);
  const known = entry.rules.map(([root]) => root);
  const missing = declared.filter((r) => !known.includes(r));
  const stale = known.filter((r) => !declared.includes(r));
  if (missing.length || stale.length) {
    throw new Error(
      `${entry.checkScript} rule roots drifted from this survey.\n` +
        `  governed but not surveyed: ${missing.join(", ") || "(none)"}\n` +
        `  surveyed but not governed: ${stale.join(", ") || "(none)"}\n` +
        "Update PROJECTS in near-cap-survey.mjs and 15-FILE-SPLIT-PLAN.md §7.",
    );
  }
}

function* walk(dir) {
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) yield* walk(full);
    else if (entry.isFile()) yield full;
  }
}

const rows = [];
for (const entry of PROJECTS) {
  if (!entry.rules) {
    const roots = readRuleRoots(entry.checkScript);
    const exts = readRuleExtensions(entry.checkScript);
    entry.rules = roots.map((root, i) => [root, exts[i] ?? [".ts", ".tsx"]]);
  }
  assertRootsStillDeclared(entry);

  for (const [root, extensions] of entry.rules) {
    const base = path.join(buzz, entry.project, root);
    try {
      statSync(base);
    } catch {
      continue;
    }
    for (const file of walk(base)) {
      if (!extensions.includes(path.extname(file))) continue;
      const lines = countLines(readFileSync(file, "utf8"));
      if (lines < threshold) continue;
      const limit = allowedLineCount(lines, MAX_LINES);
      rows.push({
        path: path.relative(buzz, file),
        lines,
        limit,
        headroom: limit - lines,
        state:
          lines > MAX_LINES ? "FROZEN" : lines === MAX_LINES ? "AT-CAP" : "TIGHT",
      });
    }
  }
}

rows.sort((a, b) => b.lines - a.lines || a.path.localeCompare(b.path));

if (asJson) {
  console.log(JSON.stringify(rows, null, 2));
} else {
  const counts = { FROZEN: 0, "AT-CAP": 0, TIGHT: 0 };
  for (const row of rows) counts[row.state] += 1;
  console.log(
    `governed files at or above ${threshold} gate-lines: ${rows.length}` +
      `  (FROZEN ${counts.FROZEN} · AT-CAP ${counts["AT-CAP"]} · TIGHT ${counts.TIGHT})\n`,
  );
  for (const row of rows) {
    console.log(
      `${String(row.lines).padStart(5)}  ${row.state.padEnd(7)}` +
        `  headroom ${String(row.headroom).padStart(3)}  ${row.path}`,
    );
  }
}
