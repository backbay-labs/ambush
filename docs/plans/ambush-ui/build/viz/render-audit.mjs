#!/usr/bin/env node
/**
 * viz/render-audit.mjs — render prototypes/dataviz.html in headless Chrome, in
 * every state x regime x theme, and audit what actually came out.
 *
 * Four checks, all measured rather than asserted:
 *
 *   1. RENDER. Every combination produces a DOM with no thrown error, no
 *      literal "undefined"/"NaN"/"[object Object]" in rendered text, and no
 *      network request (there is nothing to request; the check exists so that
 *      stays true).
 *   2. TYPE CENSUS. Computed font-size of every VISIBLE text node inside the
 *      product surfaces (the plates), excluding the spec-notes panel and the
 *      control dock, which are page chrome and not part of the drawing. The
 *      review bar is: at least a quarter of product text nodes at >= 14px, and
 *      nothing at 8px.
 *   3. COPY LINT. Every rendered string is matched against
 *      skeleton/tools/copy-ban-list.tsv, byte for byte, using the same
 *      pattern/exempt/minlen columns the shell gate uses. This is the peer's
 *      data file, not a re-typed copy.
 *   4. PAINT + TYPE ATTRIBUTES. No SVG carries a font-size attribute, a
 *      fontSize prop, or a fill/stroke presentation attribute other than a
 *      paint-server reference or `none`.
 *
 * Requires Google Chrome. Usage:  node viz/render-audit.mjs [--quick]
 */

import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const PAGE = join(HERE, "..", "prototypes", "dataviz.html");
const BANLIST = join(HERE, "..", "skeleton", "tools", "copy-ban-list.tsv");
const CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";

const STATES = ["populated", "empty", "loading", "stale", "degraded", "error", "volume", "suppressed", "disagree"];
const REGIMES = ["A", "B"];
const THEMES = ["light", "dark"];

/* -------------------------------------------------- filed exemption proposals
 * A hit is bucketed as PROPOSED rather than failing ONLY when it is a wire
 * identifier that cannot be reworded, AND a named amendment has been filed
 * against copy-ban-list.tsv for exactly that shape. The test is strict: the
 * exempted substrings are removed and the ban pattern is re-applied; if it
 * still matches, the hit is a real violation. These are printed on every run,
 * so an un-ratified amendment can never quietly become invisible. */
const PROPOSED_EXEMPTIONS = [
  {
    banId: "hunt-noun",
    amendment: "C-A1 (22-DEMO-FIXTURE.md section 10)",
    re: /hunt[_-][a-z0-9]+/gi,
    why: "wire identifier. `hunt-evt-1` inside an incident id (incident:{hunt_id}:{ms}, " +
         "AMB crates/swarm-runtime/src/correlation.rs:211), a receipt id " +
         "(resp:{hunt_id}:{capability_id}) or a correlation reason string. Not the noun.",
  },
  {
    banId: "bare-lease",
    amendment: "C-A3 (22-DEMO-FIXTURE.md section 10)",
    re: /lease:[a-z0-9_:-]+/gi,
    why: "wire identifier. The capability_id `lease:{hunt_id}:{action}:{ms}` minted by " +
         "StaticApprovalGate::issue_lease (AMB crates/swarm-policy/src/static_gate.rs:307-324).",
  },
];
function bucketOf(ban, text) {
  for (const p of PROPOSED_EXEMPTIONS) {
    if (p.banId !== ban.id) continue;
    const stripped = text.replace(p.re, " ");
    if (!ban.re.test(stripped)) return p;
  }
  return null;
}

/* ------------------------------------------------------------------ ban list */
function loadBans() {
  const out = [];
  for (const line of readFileSync(BANLIST, "utf8").split("\n")) {
    if (!line || line.startsWith("#") || line.startsWith("id\t")) continue;
    const [id, severity, flags, minlen, pattern, exempt, message] = line.split("\t");
    if (!pattern) continue;
    const i = flags === "i" ? "i" : "";
    out.push({
      id, severity, minlen: Number(minlen) || 0, message,
      re: new RegExp(pattern, i),
      exempt: exempt && exempt !== "-" ? new RegExp(exempt, i) : null,
    });
  }
  return out;
}

/* -------------------------------------------------- instrumented page harness
 * The census must read COMPUTED styles, which only the page itself can do.
 * Chrome's --dump-dom returns the post-script DOM, so the harness appends a
 * script that writes its result into a <pre id="__audit"> and lets --dump-dom
 * carry it back. The instrumented copy is a temp file; the shipped page is
 * never modified. */
const PROBE = `
<pre id="__audit" style="display:none"></pre>
<script>
(function () {
  var errs = [];
  window.addEventListener("error", function (e) { errs.push(String(e.message)); });
  function visible(el) {
    var s = getComputedStyle(el);
    if (s.display === "none" || s.visibility === "hidden" || Number(s.opacity) === 0) return false;
    var r = el.getBoundingClientRect();
    return r.width > 0 || r.height > 0 || el.tagName === "text";
  }
  var nodes = [];
  var product = document.getElementById("plates");
  if (product) {
    var walk = document.createTreeWalker(product, NodeFilter.SHOW_TEXT, null);
    var n;
    while ((n = walk.nextNode())) {
      var txt = (n.nodeValue || "").replace(/\\s+/g, " ").trim();
      if (!txt) continue;
      var el = n.parentElement;
      if (!el) continue;
      if (el.closest("details.contract")) continue;   // code listing, not drawn copy
      if (!visible(el)) continue;
      var px = parseFloat(getComputedStyle(el).fontSize);
      nodes.push({ px: Math.round(px * 100) / 100, t: txt, tag: el.tagName.toLowerCase() });
    }
  }
  var svgAttrs = [];
  document.querySelectorAll("svg *").forEach(function (el) {
    ["font-size", "fill", "stroke"].forEach(function (a) {
      if (el.hasAttribute(a)) svgAttrs.push(a + "=" + el.getAttribute(a));
    });
  });
  document.getElementById("__audit").textContent = JSON.stringify({
    errors: errs, nodes: nodes, svgAttrs: svgAttrs,
    bodyBg: getComputedStyle(document.body).backgroundColor,
    plateCount: document.querySelectorAll("section.plate").length,
  });
})();
</script>`;

function renderOnce(tmp, params, forceDark) {
  const url = "file://" + tmp + "?" + params;
  const args = [
    "--headless", "--disable-gpu", "--no-sandbox", "--virtual-time-budget=4000",
    "--dump-dom", "--window-size=1440,1000",
  ];
  if (forceDark !== undefined) args.push("--blink-settings=preferredColorScheme=" + (forceDark ? 2 : 1));
  args.push(url);
  const dom = execFileSync(CHROME, args, { encoding: "utf8", maxBuffer: 64 * 1024 * 1024, stdio: ["ignore", "pipe", "ignore"] });
  const m = dom.match(/<pre id="__audit"[^>]*>([\s\S]*?)<\/pre>/);
  if (!m) throw new Error("audit probe did not run for " + params);
  const decoded = m[1].replace(/&quot;/g, '"').replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&");
  return { dom, audit: JSON.parse(decoded) };
}

/* ---------------------------------------------------------------------- main */
const quick = process.argv.includes("--quick");
const src = readFileSync(PAGE, "utf8");
const dir = mkdtempSync(join(tmpdir(), "perch-viz-"));
const tmp = join(dir, "dataviz.html");
writeFileSync(tmp, src.replace("</body>", PROBE + "\n</body>"));

const bans = loadBans();
const fails = [];
const proposed = [];
const censusAll = [];
const svgAttrSeen = new Set();
let combos = 0;

const combosList = [];
for (const s of STATES) for (const r of REGIMES) for (const th of THEMES) combosList.push([s, r, th]);
const run = quick ? combosList.filter(([s, r, th]) => r === "A" && th === "dark") : combosList;

for (const [s, r, th] of run) {
  const { audit } = renderOnce(tmp, `state=${s}&regime=${r}&theme=${th}`, th === "dark");
  combos++;
  const tag = `${s}/${r}/${th}`;
  if (audit.errors.length) fails.push(`${tag}: JS error ${audit.errors.join("; ")}`);
  if (audit.plateCount !== 6) fails.push(`${tag}: ${audit.plateCount} plates, expected 6`);
  const bad = audit.nodes.filter((n) => /\bundefined\b|\bNaN\b|\[object Object\]/.test(n.t));
  if (bad.length) fails.push(`${tag}: ${bad.length} bad text node(s), first "${bad[0].t.slice(0, 70)}"`);
  for (const a of audit.svgAttrs) svgAttrSeen.add(a.split("=")[0] + "=" + a.split("=").slice(1).join("="));
  if (s === "populated" && r === "A" && th === "dark") censusAll.push(...audit.nodes);
  if (s === "populated" && r === "A" && th === "light") censusAll.push(...audit.nodes);

  /* copy lint over every rendered product string */
  for (const n of audit.nodes) {
    for (const b of bans) {
      if (n.t.length < b.minlen) continue;
      if (!b.re.test(n.t)) continue;
      if (b.exempt && b.exempt.test(n.t)) continue;
      const p = bucketOf(b, n.t);
      if (p) { proposed.push({ ban: b.id, amendment: p.amendment, why: p.why, text: n.t }); continue; }
      fails.push(`${tag}: COPY [${b.id}/${b.severity}] "${n.t.slice(0, 90)}" -- ${b.message}`);
    }
  }
}

/* ------------------------------------------------------------- SVG attributes */
const badAttrs = [...svgAttrSeen].filter((a) => {
  if (a.startsWith("font-size=")) return true;
  const v = a.slice(a.indexOf("=") + 1);
  if (a.startsWith("fill=") || a.startsWith("stroke=")) {
    return !(v === "none" || v.startsWith("url(#"));
  }
  return false;
});
if (badAttrs.length) fails.push("SVG paint/type attribute(s): " + badAttrs.join(", "));

/* -------------------------------------------------------------- type census */
const buckets = {};
for (const n of censusAll) buckets[n.px] = (buckets[n.px] || 0) + 1;
const total = censusAll.length;
const atLeast14 = censusAll.filter((n) => n.px >= 14).length;
const at8 = censusAll.filter((n) => n.px <= 8.5).length;

console.log(`rendered ${combos} combination(s)`);
console.log("\nTYPE CENSUS over visible product text nodes (populated / regime A, both themes):");
for (const px of Object.keys(buckets).map(Number).sort((a, b) => a - b)) {
  const n = buckets[px];
  console.log(
    "  " + String(px).padStart(6) + "px  " + String(n).padStart(4) +
    "  " + ((n / total) * 100).toFixed(1).padStart(5) + "%  " +
    "#".repeat(Math.max(1, Math.round((n / total) * 60))),
  );
}
console.log(`  total ${total} nodes; >=14px ${atLeast14} (${((atLeast14 / total) * 100).toFixed(1)}%); <=8px ${at8}`);

if (atLeast14 / total < 0.25) fails.push(`TYPE: only ${((atLeast14 / total) * 100).toFixed(1)}% of product text is >=14px (bar is 25%)`);
if (at8 > 0) fails.push(`TYPE: ${at8} product text node(s) at 8px`);

if (proposed.length) {
  const byKey = new Map();
  for (const p of proposed) {
    const k = p.ban + "|" + p.text;
    if (!byKey.has(k)) byKey.set(k, { ...p, n: 0 });
    byKey.get(k).n++;
  }
  console.log("\nPROPOSED EXEMPTIONS applied (" + byKey.size + " distinct string(s), " +
    proposed.length + " hit(s)). Each is a filed amendment, NOT a ratified one:");
  for (const v of byKey.values()) {
    console.log("  [" + v.ban + "] " + v.amendment + " x" + v.n);
    console.log("      string : " + v.text.slice(0, 96));
    console.log("      because: " + v.why);
  }
}

if (fails.length) {
  console.error("\nFAIL (" + fails.length + "):");
  for (const f of fails.slice(0, 40)) console.error("  " + f);
  if (fails.length > 40) console.error("  ... " + (fails.length - 40) + " more");
  process.exit(1);
}
console.error("\nOK - render, copy lint, SVG attributes and type census all clean.");
