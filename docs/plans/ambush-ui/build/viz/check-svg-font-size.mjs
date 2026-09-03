#!/usr/bin/env node
/**
 * G1 — check-svg-font-size.mjs   [PROPOSED, lands at BUZZ desktop/scripts/]
 *
 * WHY THIS EXISTS
 *   The desktop app implements Cmd +/- zoom by scaling the root <html>
 *   font-size, so ONLY rem-based text scales. `desktop/scripts/check-px-text.mjs`
 *   is the guard for that, and it is run from `desktop/package.json`'s `check`
 *   script (verified at BUZZ eed74bde2: "check": "biome check . && pnpm
 *   check:px-text && pnpm check:pubkey-truncation"). Its two regexes live in
 *   `scripts/check-px-text-core.mjs`:
 *
 *     TEXT_ARBITRARY_RE = /\btext-\[\d+(?:\.\d+)?(?:px|rem|em)\]/g          (:29)
 *     FONT_SIZE_PX_RE   = /(?<!-)\bfont-size:\s*\d+(?:\.\d+)?px/g           (:32)
 *
 *   The first matches only a Tailwind arbitrary utility. The second REQUIRES A
 *   COLON. Neither can see:
 *
 *     <text font-size="11">          an SVG presentation attribute
 *     <text fontSize={11}>           the JSX prop form
 *     <text style={{fontSize: 11}}>  the numeric style form React turns into px
 *
 *   A hand-authored chart can therefore freeze every axis label against the
 *   zoom contract while CI stays green. Perch's chart layer is entirely
 *   hand-authored SVG (18-DATAVIZ.md section 1), so this hole sits directly under
 *   the work. This script closes it.
 *
 * WHAT IT COVERS
 *   Every file under the scan roots with an extension in the set: no
 *   `font-size=` attribute, no `fontSize=` JSX prop, no `fontSize:` numeric or
 *   px style value. The style-object form is the ONE rule with an allowance: a
 *   value carrying var(), calc() or rem passes, because those scale.
 *
 * WHAT IT CANNOT SEE, AND THEREFORE DOES NOT CLAIM
 *   1. A size computed at runtime and passed through a variable
 *      (`<text fontSize={n}>` where n is a number from elsewhere). The prop
 *      form IS caught; a spread (`<text {...attrs}>`) is not.
 *   2. A size set imperatively (`el.setAttribute("font-size", "11")`).
 *   3. A size arriving inside an imported .svg asset. Perch has none; a chart
 *      that imports one is a different review.
 *   4. Whether a rem value is on the token scale. That is check-px-text's job
 *      for classes. A rem literal in an ATTRIBUTE or a JSX PROP is flagged
 *      regardless, because an <svg> at width:100% rescales its own coordinate
 *      system and a rem inside it stops being the token it names. Only the
 *      style-object form has an allowance, and only for var()/calc()/rem.
 *
 * PROVING IT CAN FAIL
 *   The script runs a FIXTURE on every invocation, before it scans anything
 *   real: it plants seven forbidden shapes and fails if any is not caught, and
 *   it plants four clean controls (a className, a class, a calc(var())-bearing
 *   style fontSize, and a `--font-size:` custom property) that must pass.
 *   Without the controls the scanner could be "catching" everything by matching
 *   unconditionally. Two of the seven are rem-bearing, which is what pins the
 *   attribute/prop rules as unconditional rather than value-dependent.
 *
 * WIRING (two-part, must land together)
 *   desktop/package.json: add   "check:svg-font-size": "node ./scripts/check-svg-font-size.mjs"
 *                         and append it to the existing `check` chain.
 *   There is no tools/ directory in BUZZ, so this rides desktop's `check`
 *   script exactly the way check-px-text does. It is NOT an Ambush gate and
 *   therefore does not appear in tools/check-gates-wired.sh.
 *
 * Usage:  node check-svg-font-size.mjs [root ...]
 *         (default roots: ./src if it exists; otherwise the argument list)
 */

import { promises as fs } from "node:fs";
import path from "node:path";

const EXTENSIONS = new Set([".ts", ".tsx", ".jsx", ".js", ".css", ".html", ".svg"]);

/* One alternation, shared by the fixture and the real scan, so they cannot
 * drift apart. Group 1 is the offending literal, reported verbatim. */
const RULES = [
  {
    id: "svg-font-size-attr",
    // font-size="11" / font-size="0.6875rem" — an SVG presentation attribute.
    // Forbidden UNCONDITIONALLY, rem included: an <svg> at width:100% scales its
    // own coordinate system, so a rem inside it is multiplied by the viewBox
    // scale and stops being the token it names. SVG text takes a class.
    re: /(?<![-\w])font-size\s*=\s*["'][^"']*["']/g,
    allowScaled: false,
    hint: 'use className="text-2xs" (or another rem token); an SVG font-size attribute is never allowed',
  },
  {
    id: "jsx-fontsize-prop",
    // fontSize={11} / fontSize="11" — the JSX prop form. React writes a bare
    // number as px. Forbidden unconditionally, for the same reason as the
    // attribute: it lands on the element as a presentation attribute.
    re: /(?<![-\w])fontSize\s*=\s*[{"'][^}"']*[}"']/g,
    allowScaled: false,
    hint: "use className instead of a fontSize prop; React writes a bare number as px",
  },
  {
    id: "style-fontsize-number",
    // fontSize: 11 / fontSize: "11px" — the style-object form. This is the ONE
    // rule with an allowance: a style object is sometimes the only way to reach
    // a computed token, and a value carrying var()/calc()/rem does scale.
    re: /(?<![-\w])fontSize\s*:\s*(?:\d+(?:\.\d+)?|`[^`]*`|["'][^"']*["'])/g,
    allowScaled: true,
    hint: "a numeric or px fontSize in a style object freezes against zoom; use a class, or a var()/calc()/rem value",
  },
];

/** Only the style-object rule has an allowance, and only for a scaled value. */
function isAllowed(rule, literal) {
  if (!rule.allowScaled) return false;
  return /var\(\s*--/.test(literal) || /\brem\b/.test(literal) || /calc\(/.test(literal);
}

function scanText(text, label) {
  const hits = [];
  const lines = text.split(/\r?\n/);
  lines.forEach((line, i) => {
    for (const rule of RULES) {
      rule.re.lastIndex = 0;
      let m;
      while ((m = rule.re.exec(line)) !== null) {
        if (isAllowed(rule, m[0])) continue;
        hits.push({ file: label, line: i + 1, rule: rule.id, literal: m[0], hint: rule.hint });
      }
    }
  });
  return hits;
}

/* ------------------------------------------------------------------ fixture */
const FIXTURE_BAD = [
  ['<text x="0" y="0" font-size="11">2.00</text>', "svg-font-size-attr"],
  ["<text fontSize={11}>2.00</text>", "jsx-fontsize-prop"],
  ['<text fontSize="11px">2.00</text>', "jsx-fontsize-prop"],
  ["<text style={{ fontSize: 11 }}>2.00</text>", "style-fontsize-number"],
  ['<text style={{ fontSize: "11px" }}>2.00</text>', "style-fontsize-number"],
  // rem in an ATTRIBUTE is still a violation: the viewBox rescales it.
  ['<text font-size="0.6875rem">2.00</text>', "svg-font-size-attr"],
  // rem in a JSX PROP is still a violation, for the same reason.
  ['<text fontSize="0.6875rem">2.00</text>', "jsx-fontsize-prop"],
];
const FIXTURE_CLEAN = [
  '<text className="text-2xs">2.00</text>',
  '<text class="t-2xs">2.00</text>',
  "<text style={{ fontSize: `calc(var(--buzz-type-rem) * 0.6875)` }}>2.00</text>",
  ".widget { --font-size: 11px; }",
  // a CSS ATTRIBUTE SELECTOR, not an SVG presentation attribute. This control
  // exists because the first run of this script against the real BUZZ tree at
  // eed74bde2 flagged desktop/src/shared/styles/globals/typography.css:46 and
  // :50 -- `:root[data-font-size="smaller"]` -- which is the mechanism the zoom
  // contract is BUILT ON, not a violation of it.
  ':root[data-font-size="smaller"] { --buzz-type-scale: calc(13 / 14); }',
  ':root[data-font-size="larger"] { --buzz-type-scale: calc(15 / 14); }',
];

function selfTest() {
  const problems = [];
  for (const [line, expect] of FIXTURE_BAD) {
    const hits = scanText(line, "<fixture>");
    if (!hits.some((h) => h.rule === expect)) {
      problems.push(`fixture NOT CAUGHT by ${expect}: ${line}`);
    }
  }
  for (const line of FIXTURE_CLEAN) {
    const hits = scanText(line, "<fixture>");
    if (hits.length) problems.push(`clean control WRONGLY FLAGGED (${hits[0].rule}): ${line}`);
  }
  return problems;
}

/* ---------------------------------------------------------------- allowlist
 * `relativePath:matchedLiteral`, the same shape check-px-text.mjs uses for its
 * decorative-glyph overrides. Matching the LITERAL rather than the line keeps an
 * entry stable when an unrelated edit moves it. Every entry below was produced
 * by running this script against BUZZ at eed74bde2 and reading the site.
 *
 * PRODUCT COPY IS NEVER ALLOWLISTED. All four entries are emoji glyphs sized to
 * a fixed box, which is the same class check-px-text already exempts
 * (`text-[6rem]` avatar emoji at desktop/scripts/check-px-text.mjs:27-32).
 */
const OVERRIDES = new Set([
  // A 512x512 emoji-avatar SVG serialised to a data: URL and used as an <img>.
  // The glyph is sized to the avatar box, is never read as text, and the SVG is
  // rendered at a fixed size rather than width:100%.
  "src/features/profile/ui/ProfileAvatarEditor.utils.ts:font-size=\"${EMOJI_AVATAR_FONT_SIZE}\"",
  // Emoji particle sizes in the burst animation. Not text; Perch deletes this
  // subsystem (17-COMPONENT-SPECS section 8), so the entry is expected to be
  // removable rather than permanent.
  "src/shared/ui/EmojiBurstProvider.tsx:fontSize: 18",
  "src/shared/ui/EmojiBurstProvider.tsx:fontSize: 87",
  "src/shared/ui/EmojiBurstProvider.tsx:fontSize: 22",
]);

/* --------------------------------------------------------------------- walk */
async function walk(dir) {
  let out = [];
  let entries;
  try {
    entries = await fs.readdir(dir, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const e of entries) {
    if (e.name === "node_modules" || e.name === ".git" || e.name === "dist") continue;
    const p = path.join(dir, e.name);
    if (e.isDirectory()) out = out.concat(await walk(p));
    else if (EXTENSIONS.has(path.extname(e.name))) out.push(p);
  }
  return out;
}

/* --------------------------------------------------------------------- main */
const problems = selfTest();
if (problems.length) {
  console.error("check-svg-font-size: SELF-TEST FAILED. The scanner is broken; fix it before trusting it.");
  for (const p of problems) console.error("  " + p);
  process.exit(2);
}

const roots = process.argv.slice(2);
if (roots.length === 0) roots.push("src");

const files = [];
for (const r of roots) {
  const st = await fs.stat(r).catch(() => null);
  if (!st) continue;
  if (st.isDirectory()) files.push(...(await walk(r)));
  else files.push(r);
}
if (files.length === 0) {
  console.error("check-svg-font-size: no files under " + roots.join(", ") + "; refusing to pass silently");
  process.exit(2);
}

const hits = [];
const usedOverrides = new Set();
for (const f of files) {
  for (const h of scanText(await fs.readFile(f, "utf8"), f)) {
    // An override key is `relativePath:literal`. A repo path never contains a
    // colon, so splitting on the FIRST colon is exact even when the literal
    // does (`fontSize: 18`). The path is compared as a SUFFIX so the script
    // works from any working directory.
    const matched = [...OVERRIDES].some((o) => {
      const i = o.indexOf(":");
      return h.file.replace(/\\/g, "/").endsWith(o.slice(0, i)) && h.literal === o.slice(i + 1);
    });
    if (matched) { usedOverrides.add(h.literal); continue; }
    hits.push(h);
  }
}
if (hits.length) {
  console.error(`check-svg-font-size: ${hits.length} frozen text size(s) in ${files.length} file(s)`);
  for (const h of hits) console.error(`  ${h.file}:${h.line}  [${h.rule}]  ${h.literal}\n      ${h.hint}`);
  process.exit(1);
}
console.error(
  `check-svg-font-size: OK (${files.length} files, self-test ${FIXTURE_BAD.length} caught / ` +
  `${FIXTURE_CLEAN.length} controls clean, ${usedOverrides.size} allowlisted glyph literal(s))`,
);
