// Target path in BUZZ: desktop/scripts/check-copy-banned-terms.mjs
// Wire into desktop/package.json's existing `check` script (see
// tools/ci-wiring.snippet.yml). Sibling of the shipped check-px-text.mjs and
// check-pubkey-truncation.mjs.
//
// WHY A SECOND IMPLEMENTATION EXISTS AT ALL
//   16-INVARIANT-TESTS.md decision D2 says the ban list is DATA, read by the
//   Ambush shell gate AND byte for byte by this file, with a parity test over a
//   shared corpus asserting identical verdicts. The review found that claim
//   unbacked: this file did not exist, so the parity test it describes could
//   not. Writing it is the fix, and it is not redundancy for its own sake:
//
//     - The Ambush gate runs in Ambush CI and needs a second actions/checkout of
//       block/buzz. It is the cross-repo backstop and it is what
//       check-gates-wired.sh can see.
//     - This file runs in `pnpm check`, which is what a Buzz developer and every
//       pre-push actually run. A ban enforced only in another repository's CI is
//       a ban a Buzz contributor discovers after opening a PR.
//
//   ONE list, two runners, one corpus, and a parity assertion. If the two ever
//   disagree on the corpus, the disagreement is the bug -- not the corpus.
//
// THE BAN LIST IS NOT VENDORED
//   It is read from tools/copy-ban-list.tsv in the Ambush checkout, located
//   through PERCH_BAN_LIST or PERCH_AMBUSH_ROOT. A vendored copy is a second
//   registry and would drift, which is the failure mode the whole wave-2 review
//   named. If neither is set the script SKIPS with an explicit reason and exit 0
//   -- a Buzz contributor without an Ambush checkout must not be blocked -- but
//   `pnpm check` in CI sets it, and CI is where a skip is a failure (see
//   --require, which turns the skip into an error).
//
// SCOPE PARITY WITH THE SHELL GATE
//   Same two modes (copy / markup), same skip rules, same extraction shapes,
//   same exemption semantics (matched against the SAME normalized string). The
//   extractor here is a regex port of the awk one; the corpus is what proves the
//   port. Anything the shell gate cannot see, this cannot see either -- in
//   particular NEITHER sees a string that arrives as data from the daemon. That
//   limit is stated in tools/copy-ban-list.tsv's header and in
//   16-INVARIANT-TESTS.md section 7.7; a clean run here is not coverage of
//   daemon-supplied text.

import { readFileSync, readdirSync, statSync } from "node:fs";
import path from "node:path";
import process from "node:process";

/** The six feature roots plus shared/ui/perch. 14-CLIENT-ARCHITECTURE section 2.1. */
const PERCH_ROOTS = [
  "src/features/perch",
  "src/features/perch-watch",
  "src/features/perch-evidence",
  "src/features/perch-containment",
  "src/features/perch-policy",
  "src/features/perch-shift",
  "src/shared/ui/perch",
];

const args = new Set(process.argv.slice(2));
const REQUIRE_LIST = args.has("--require");
const SELF_TEST = args.has("--self-test");

function resolveBanList() {
  if (process.env.PERCH_BAN_LIST) return process.env.PERCH_BAN_LIST;
  if (process.env.PERCH_AMBUSH_ROOT) {
    return path.join(process.env.PERCH_AMBUSH_ROOT, "tools", "copy-ban-list.tsv");
  }
  return null;
}

/**
 * Parse the TSV into rows. Mirrors the shell gate's BEGIN block exactly,
 * including "a row with an empty message column is not a row" and the
 * refuse-on-zero-rows rule.
 */
export function parseBanList(text) {
  const rows = [];
  for (const line of text.split(/\r?\n/)) {
    if (line.startsWith("#") || line === "") continue;
    const f = line.split("\t");
    if (f[0] === "id") continue;
    if (!f[6]) continue;
    rows.push({
      id: f[0],
      severity: f[1],
      insensitive: f[2] === "i",
      minlen: Number(f[3]) || 0,
      pattern: new RegExp(f[4]),
      exempt: f[5] === "-" ? null : new RegExp(f[5]),
      message: f[6],
    });
  }
  if (rows.length === 0) {
    throw new Error("ban list parsed to zero rows; refusing to pass silently");
  }
  return rows;
}

const SKIP_VALUE = [
  /^\//,
  /^#/,
  /^https?:/,
];

function skipValue(s) {
  if (SKIP_VALUE.some((re) => re.test(s))) return true;
  // A snake_case wire token is not product copy.
  return /^[a-z0-9_]+$/.test(s) && s.includes("_");
}

const LINE_SKIP = [
  /^\s*(\/\/|\*|\/\*|<!--)/,
  /^\s*(import|export type|export interface)\s/,
  /from\s*"/,
];

const ATTR_RE = /(?:aria-label|placeholder|alt|title)\s*=\s*"([^"]*)"/g;
const FIELD_RE = /(?:label|title|body|hint|detail|tip)\s*:\s*"([^"]*)"/g;
const TEXT_NODE_RE = />([^<>{}]+)</g;
const DQ_RE = /"([^"]*)"/g;
const BT_RE = /`([^`]*)`/g;

/** `path<TAB>line<TAB>string` triples, as the shell gate emits. */
export function extractStrings(mode, rel, content) {
  const out = [];
  const push = (line, s) => {
    const clean = s.replace(/\t/g, " ").replace(/\r/g, "");
    if (clean !== "") out.push({ file: rel, line, text: clean });
  };
  const lines = content.split(/\r?\n/);
  for (let i = 0; i < lines.length; i += 1) {
    const raw = lines[i];
    const lineNo = i + 1;
    if (LINE_SKIP.some((re) => re.test(raw))) continue;

    if (mode === "copy") {
      for (const re of [DQ_RE, BT_RE]) {
        re.lastIndex = 0;
        let m = re.exec(raw);
        while (m) {
          if (!skipValue(m[1])) push(lineNo, m[1]);
          m = re.exec(raw);
        }
      }
      continue;
    }

    // markup
    if (/href\s*=/.test(raw)) continue;
    if (/data-testid\s*=/.test(raw)) continue;
    if (/[^-a-zA-Z]to\s*=\s*"/.test(raw)) continue;

    for (const re of [ATTR_RE, FIELD_RE]) {
      re.lastIndex = 0;
      let m = re.exec(raw);
      while (m) {
        if (!skipValue(m[1])) push(lineNo, m[1]);
        m = re.exec(raw);
      }
    }
    TEXT_NODE_RE.lastIndex = 0;
    let t = TEXT_NODE_RE.exec(raw);
    while (t) {
      const text = t[1].trim();
      if (/[A-Za-z]/.test(text)) push(lineNo, text);
      t = TEXT_NODE_RE.exec(raw);
    }
    // A JSX text node alone on its line carries no angle brackets. Same three
    // conditions the awk rule uses: starts with a letter, holds a space between
    // letters, holds none of the punctuation that makes a line code.
    if (/^\s*[A-Za-z][^<>{}=;()"`]*$/.test(raw) && /[A-Za-z] [A-Za-z]/.test(raw)) {
      push(lineNo, raw.trim());
    }
  }
  return out;
}

export function scanExtracted(rows, extracted) {
  const hits = [];
  for (const item of extracted) {
    for (const row of rows) {
      if (item.text.length < row.minlen) continue;
      const normalized = row.insensitive ? item.text.toLowerCase() : item.text;
      if (!row.pattern.test(normalized)) continue;
      // The exemption is matched against the SAME normalized string, which is
      // why a case-insensitive row must write its exemption lowercase. The awk
      // side does exactly this; a mismatch here would show up on the corpus.
      if (row.exempt && row.exempt.test(normalized)) continue;
      hits.push({ ...item, id: row.id, severity: row.severity, message: row.message });
    }
  }
  return hits;
}

function walk(dir, out) {
  let entries;
  try {
    entries = readdirSync(dir);
  } catch {
    return out;
  }
  for (const name of entries) {
    const full = path.join(dir, name);
    const st = statSync(full);
    if (st.isDirectory()) {
      if (name === "tests" || name === "__fixtures__") continue;
      walk(full, out);
    } else if (/\.tsx?$/.test(name) && !/\.(test|spec)\./.test(name)) {
      out.push(full);
    }
  }
  return out;
}

/**
 * PRODUCTION mode rule, byte-identical to the shell gate's `case` patterns
 * (a trailing `copy.ts`, a `copy/` directory, or a `Copy.ts` suffix are copy;
 * everything else is markup).
 */
function modeFor(file) {
  return /(^|\/)copy\.ts$|(^|\/)copy\/[^/]+\.ts$|Copy\.ts$/.test(file) ? "copy" : "markup";
}

/**
 * CORPUS mode rule. The corpus files are not on production paths, so mode rides
 * the filename suffix instead -- see tools/fixtures/copy-corpus/README.md. A
 * corpus file matching neither suffix is REFUSED rather than silently scanned in
 * the wrong mode, which would make a parity pass meaningless.
 */
function modeForCorpus(name) {
  if (/\.copy\.tsx?$/.test(name)) return "copy";
  if (/\.markup\.tsx?$/.test(name)) return "markup";
  return null;
}

// ---------------------------------------------------------------------------
// THE PARITY CORPUS. Run with --self-test, and by the Ambush-side parity test.
// This is the half that makes "byte for byte" a claim rather than a hope.
// ---------------------------------------------------------------------------
function selfTest(rows, corpusDir) {
  const expectedPath = path.join(corpusDir, "expected.tsv");
  const expected = new Set();
  for (const line of readFileSync(expectedPath, "utf8").split(/\r?\n/)) {
    if (line.startsWith("#") || line === "") continue;
    const [file, id] = line.split("\t");
    if (file === "file") continue;
    expected.add(`${file}\t${id}`);
  }

  const got = new Set();
  const scanned = [];
  for (const name of readdirSync(corpusDir)) {
    if (!/\.tsx?$/.test(name)) continue;
    const mode = modeForCorpus(name);
    if (mode === null) {
      console.error(
        `copy-ban parity corpus: ${name} matches neither *.copy.ts* nor *.markup.ts*, ` +
          "so its mode is undecidable and it would be scanned wrong. Rename it or " +
          "remove it; a corpus file nobody scans makes a parity pass meaningless.",
      );
      return 1;
    }
    scanned.push(name);
    const content = readFileSync(path.join(corpusDir, name), "utf8");
    for (const hit of scanExtracted(rows, extractStrings(mode, name, content))) {
      got.add(`${hit.file}\t${hit.id}`);
    }
  }
  if (scanned.length === 0) {
    console.error("copy-ban parity corpus is empty; refusing to pass silently");
    return 1;
  }
  // Every corpus file must be NAMED in expected.tsv -- with rows if it violates,
  // and by the `clean.` prefix convention if it does not. A file that is neither
  // is a file nobody decided about.
  for (const name of scanned) {
    const named = [...expected].some((k) => k.startsWith(`${name}\t`));
    if (!named && !name.startsWith("clean.")) {
      console.error(
        `copy-ban parity corpus: ${name} has no row in expected.tsv and is not ` +
          "named clean.*, so nobody decided whether it should violate.",
      );
      return 1;
    }
  }

  const missing = [...expected].filter((k) => !got.has(k));
  const extra = [...got].filter((k) => !expected.has(k));
  if (missing.length === 0 && extra.length === 0) {
    console.log(`copy-ban parity corpus: ${expected.size} (file, row) pair(s), exact match`);
    return 0;
  }
  console.error("copy-ban parity corpus MISMATCH between this scanner and expected.tsv:");
  for (const k of missing) console.error(`  MISSING  ${k.replace("\t", " -> ")}`);
  for (const k of extra) console.error(`  EXTRA    ${k.replace("\t", " -> ")}`);
  console.error("");
  console.error("expected.tsv is the contract BOTH scanners meet. If a ban genuinely");
  console.error("changed, change tools/copy-ban-list.tsv and expected.tsv together, and");
  console.error("re-run the Ambush-side gate over the same corpus before landing.");
  return 1;
}

function main() {
  const banListPath = resolveBanList();
  if (!banListPath) {
    const msg =
      "check-copy-banned-terms: no ban list. Set PERCH_BAN_LIST, or PERCH_AMBUSH_ROOT " +
      "to a checkout of the Ambush repo. The list is NOT vendored here on purpose: " +
      "one file, two runners (16-INVARIANT-TESTS.md D2).";
    if (REQUIRE_LIST) {
      console.error(msg);
      console.error("--require was passed, so an unavailable ban list is an error.");
      return 1;
    }
    console.log(`${msg}\nSKIPPED (no --require).`);
    return 0;
  }

  let rows;
  try {
    rows = parseBanList(readFileSync(banListPath, "utf8"));
  } catch (error) {
    console.error(`check-copy-banned-terms: ${error.message} (${banListPath})`);
    return 1;
  }

  if (SELF_TEST) {
    const corpus =
      process.env.PERCH_BAN_CORPUS ??
      path.join(path.dirname(path.dirname(banListPath)), "tools", "fixtures", "copy-corpus");
    return selfTest(rows, corpus);
  }

  // The corpus runs on EVERY invocation, before the real scan -- the same rule
  // the four Ambush gates follow. A scanner nobody has proved can fail is not a
  // gate, and this one's whole job is to agree with another implementation.
  const corpus = path.join(path.dirname(path.dirname(banListPath)), "tools", "fixtures", "copy-corpus");
  if (selfTest(rows, corpus) !== 0) {
    console.error("The parity corpus failed, so this scanner's verdict over src/ means nothing.");
    return 1;
  }

  const desktopRoot = process.cwd();
  const files = [];
  let rootsPresent = 0;
  for (const root of PERCH_ROOTS) {
    const dir = path.join(desktopRoot, root);
    try {
      if (statSync(dir).isDirectory()) {
        rootsPresent += 1;
        walk(dir, files);
      }
    } catch {
      /* Phase 0: the root does not exist yet. */
    }
  }

  if (rootsPresent === 0) {
    // Symmetric with the Ambush gate's WARNING arm, and stated the same way:
    // a zero is never printed inside a success message.
    console.log("check-copy-banned-terms: the Perch tree does not exist yet.");
    console.error(
      "\nWARNING: no Perch source was scanned, so no vocabulary ban is enforced on\n" +
        "a rendered string. None of the seven roots in PERCH_ROOTS exists under\n" +
        `${desktopRoot}. The Ambush-side gate carries the manifest that makes this\n` +
        "arm expire automatically (tools/perch-source-roots.tsv).",
    );
    return 0;
  }

  if (files.length === 0) {
    console.error(
      `check-copy-banned-terms: ${rootsPresent} Perch root(s) exist under ${desktopRoot} ` +
        "but contain no .ts/.tsx file; refusing to pass silently.",
    );
    return 1;
  }

  const hits = [];
  for (const file of files) {
    const rel = path.relative(desktopRoot, file);
    hits.push(...scanExtracted(rows, extractStrings(modeFor(rel), rel, readFileSync(file, "utf8"))));
  }

  if (hits.length === 0) {
    console.log(`copy gate clean over ${files.length} Perch file(s)`);
    return 0;
  }

  console.error("\nBanned terms in rendered strings:\n");
  for (const hit of hits) {
    console.error(`  [${hit.severity} ${hit.id}] ${hit.file}:${hit.line}`);
    console.error(`      ${hit.text}`);
    console.error(`      -> ${hit.message}`);
  }
  console.error(
    "\nThe rule and its replacement come from tools/copy-ban-list.tsv in the Ambush\n" +
      "checkout. If a ban is wrong, change it there -- not here -- and say so in the\n" +
      "PR as a brief amendment under 00-BRIEF.md section 12.",
  );
  return 1;
}

process.exit(main());
