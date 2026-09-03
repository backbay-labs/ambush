#!/usr/bin/env node
// fixtures/demo/check-strings.mjs -- run the copy ban list over the demo's
// SPOKEN and ON-SCREEN strings.
//
// WHY IT IS SEPARATE FROM tools/check-copy-banned-terms.sh
//   That script is INSTALLED IN NEITHER REPOSITORY. Re-measured this session:
//   BUZZ has no tools/ directory at all, and AMBUSH's tools/ holds fourteen
//   check-*.sh scripts and one verify-*.sh, none of them this one. (An earlier
//   version of this comment said 23; that was wrong and 10-RELAY-FORK.md caught
//   it.) It DOES exist as a delivered skeleton at
//   docs/plans/ambush-ui/build/skeleton/tools/check-copy-banned-terms.sh, and
//   its Buzz-side half -- desktop/scripts/check-copy-banned-terms.mjs, which
//   16-INVARIANT-TESTS.md D2 requires to read the same TSV byte for byte -- is
//   not written at all, so the cross-repo parity test that decision rests on
//   cannot run yet.
//
//   This file reads the SAME data file,
//   docs/plans/ambush-ui/build/skeleton/tools/copy-ban-list.tsv, so when the
//   shell version ships the two read the same rows with the same semantics: one
//   row, one extracted string, ERE + flags + minlen + exempt. It is not a
//   substitute for either gate and covers only the strings named below.
//
// WHAT COUNTS AS A STRING HERE
//   A prose document is not a rendered string, so scanning the whole file would
//   fail on its own glossary. The extractor takes exactly two things out of
//   22-DEMO-FIXTURE.md and fixtures/demo/cue-card.txt:
//
//     lines beginning with "> "        -- what the presenter says out loud
//     lines inside a ```screen fence   -- what is on the display
//
//   plus, for any other file passed on the command line, every line.
//
//   A line may opt out with a trailing `[copy-ban-allow: id1,id2]`, and a whole
//   ```screen block may opt out by putting the same marker on its fence. Both use
//   the allowlist key the TSV documents. Use it only where the text IS the ban (a
//   glossary row naming the forbidden word) or where a WIRE IDENTIFIER embeds it
//   (`lease:hunt-evt-1:isolate_host:...` is a capability_id, not a noun).
//
// Usage:
//   node fixtures/demo/check-strings.mjs ../22-DEMO-FIXTURE.md cue-card.txt
//   exit 0 clean, exit 1 with one line per violation.

import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const TSV = resolve(HERE, "../../skeleton/tools/copy-ban-list.tsv");

const rows = readFileSync(TSV, "utf8")
  .split("\n")
  .filter((l) => l && !l.startsWith("#") && !l.startsWith("id\t"))
  .map((l) => {
    const [id, severity, flags, minlen, pattern, exempt, message] = l.split("\t");
    return {
      id,
      severity,
      re: new RegExp(pattern, flags === "i" ? "i" : ""),
      minlen: Number(minlen),
      exempt: exempt === "-" ? null : new RegExp(exempt, flags === "i" ? "i" : ""),
      message,
    };
  });

/** Pull the spoken lines and the on-screen blocks out of a markdown-ish file. */
function extract(text, everything) {
  const out = [];
  let inScreen = false;
  let blockAllow = "";
  text.split("\n").forEach((line, i) => {
    const n = i + 1;
    const fence = line.match(/^```screen\s*(\[copy-ban-allow:[^\]]*\])?\s*$/);
    if (fence) { inScreen = true; blockAllow = fence[1] ?? ""; return; }
    if (inScreen && /^```\s*$/.test(line)) { inScreen = false; blockAllow = ""; return; }
    // A block-level allow applies to every line of one ```screen fence. It
    // exists for a wire identifier that legitimately embeds a banned word --
    // `lease:hunt-evt-1:isolate_host:…` is a capability_id, not the noun
    // "lease" and not the noun "hunt" -- so the marker is not repeated on
    // every row of a mock the reader is supposed to read as a screen.
    if (inScreen) { out.push([n, line + blockAllow]); return; }
    if (line.startsWith("> ")) { out.push([n, line.slice(2)]); return; }
    if (everything) out.push([n, line]);
  });
  return out;
}

let violations = 0;
for (const file of process.argv.slice(2)) {
  const path = resolve(process.cwd(), file);
  const text = readFileSync(path, "utf8");
  const everything = !/\.md$/.test(path);
  for (const [lineNo, raw] of extract(text, everything)) {
    const allow = raw.match(/\[copy-ban-allow:\s*([a-z0-9,\- ]+)\]/);
    const allowed = new Set(allow ? allow[1].split(",").map((s) => s.trim()) : []);
    const s = raw.replace(/\[copy-ban-allow:[^\]]*\]/, "").trim();
    if (!s) continue;
    for (const row of rows) {
      if (allowed.has(row.id)) continue;
      if (s.length < row.minlen) continue;
      if (!row.re.test(s)) continue;
      if (row.exempt && row.exempt.test(s)) continue;
      violations += 1;
      console.log(`${file}:${lineNo}  [${row.severity} ${row.id}]  ${row.message}`);
      console.log(`    ${s}`);
    }
  }
}

if (violations > 0) {
  console.log(`\n${violations} violation(s)`);
  process.exit(1);
}
console.log("copy ban list: clean");
