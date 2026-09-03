#!/usr/bin/env node
/**
 * contrast.mjs — WCAG 2.2 contrast, computed from `tokens/perch-tokens.css`.
 *
 * WHY THIS FILE EXISTS. `18-DATAVIZ.md` §15 reports 62 contrast ratios and
 * cites "viz/contrast.mjs in scratch". A ratio quoted from a script nobody
 * shipped cannot be re-run, and re-running it is the only way anyone checks it.
 * `19-TOKENS.md` §4 reports a further table the same way. This is that script,
 * delivered: it reads the SAME `tokens/perch-tokens.css` the app ships, parses
 * both palettes out of it, and recomputes every ink-on-surface pair.
 *
 * It reads one file and writes nothing. No network, no dependencies.
 *
 * WHAT IT MEASURES, and what it therefore cannot see:
 *   - It computes contrast for OPAQUE pairs only. A token drawn at an alpha
 *     (`hsl(var(--perch-danger-mark) / .35)`) composites against whatever is
 *     behind it and its effective ratio is lower than the number here. The
 *     `--perch-alpha-*` tokens are listed but never used as an ink.
 *   - It knows nothing about which pairs the product actually renders. A pair
 *     passing here is necessary, not sufficient; `19-TOKENS.md` §4 owns the
 *     question of which pairs are reachable.
 *   - It reads the CSS, not the DOM. A surface built by compositing two
 *     translucent layers is not modelled.
 *
 * Usage:
 *   node viz/contrast.mjs                 # the full table, both themes
 *   node viz/contrast.mjs --json          # machine-readable
 *   node viz/contrast.mjs --check         # exit 1 if a text ink fails its bar
 */

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const CSS = join(HERE, "..", "tokens", "perch-tokens.css");

/* ── colour ───────────────────────────────────────────────────────────────── */

/** `"150 10.5% 37.3%"` → `[r,g,b]` in 0-255. The CSS ships bare HSL triplets. */
export function hslTripletToRgb(triplet) {
  const m = triplet.trim().match(/^([\d.]+)\s+([\d.]+)%\s+([\d.]+)%$/);
  if (!m) return null;
  const h = Number(m[1]) / 360;
  const s = Number(m[2]) / 100;
  const l = Number(m[3]) / 100;
  if (s === 0) {
    const v = Math.round(l * 255);
    return [v, v, v];
  }
  const q = l < 0.5 ? l * (1 + s) : l + s - l * s;
  const p = 2 * l - q;
  const hue = (t) => {
    if (t < 0) t += 1;
    if (t > 1) t -= 1;
    if (t < 1 / 6) return p + (q - p) * 6 * t;
    if (t < 1 / 2) return q;
    if (t < 2 / 3) return p + (q - p) * (2 / 3 - t) * 6;
    return p;
  };
  return [hue(h + 1 / 3), hue(h), hue(h - 1 / 3)].map((v) => Math.round(v * 255));
}

export function rgbToHex([r, g, b]) {
  return "#" + [r, g, b].map((v) => v.toString(16).padStart(2, "0")).join("");
}

/** WCAG 2.2 relative luminance (sRGB), §Relative luminance. */
export function relativeLuminance([r, g, b]) {
  const lin = [r, g, b]
    .map((v) => v / 255)
    .map((v) => (v <= 0.04045 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4));
  return 0.2126 * lin[0] + 0.7152 * lin[1] + 0.0722 * lin[2];
}

/** WCAG 2.2 contrast ratio. Order-independent; always >= 1. */
export function contrast(a, b) {
  const la = relativeLuminance(a);
  const lb = relativeLuminance(b);
  return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05);
}

/* ── parse ────────────────────────────────────────────────────────────────── */

/**
 * Two palettes out of one file.
 *
 * `light` is everything declared on bare `:root {`. `dark` is `light` overlaid
 * with everything declared in the `:root.dark, :root[data-theme="dark"], .dark`
 * block — which is how the cascade resolves it, so a token the dark block does
 * not redeclare correctly keeps its light value here too.
 */
export function parsePalettes(cssText = readFileSync(CSS, "utf8")) {
  const light = {};
  const dark = {};
  let inLight = false;
  let inDark = false;
  let depth = 0;
  for (const raw of cssText.split("\n")) {
    const line = raw.split("/*")[0];
    if (/^:root\s*\{/.test(raw.trim())) {
      inLight = true;
      depth = 1;
      continue;
    }
    if (/^:root\.dark|^:root\[data-theme="dark"\]|^\.dark\s*[,{]/.test(raw.trim())) {
      inDark = true;
      continue;
    }
    if (inDark && raw.trim().endsWith("{")) {
      depth = 1;
      continue;
    }
    if ((inLight || inDark) && line.includes("}")) {
      depth -= 1;
      if (depth <= 0) {
        inLight = false;
        inDark = false;
      }
      continue;
    }
    const m = line.match(/^\s*(--perch-[a-z0-9-]+)\s*:\s*([^;]+);/);
    if (!m) continue;
    if (inLight) light[m[1]] = m[2].trim();
    else if (inDark) dark[m[1]] = m[2].trim();
  }
  return { light, dark: { ...light, ...dark } };
}

/* ── the pairs the product actually paints ────────────────────────────────── */

export const SURFACES = [
  "--perch-surface-chrome",
  "--perch-background",
  "--perch-card",
  "--perch-popover",
  "--perch-surface-raised",
];

/** `bar` is the ratio this ink must clear on EVERY surface above. */
export const INKS = [
  { name: "--perch-foreground", bar: 4.5, role: "body text" },
  { name: "--perch-foreground-secondary", bar: 4.5, role: "secondary text" },
  { name: "--perch-foreground-muted", bar: 4.5, role: "meta text — the most-rendered pair" },
  { name: "--perch-foreground-faint", bar: 0, role: "NEVER TEXT — disabled controls only" },
  { name: "--perch-pillar-substrate-ink", bar: 4.5, role: "pillar text" },
  { name: "--perch-pillar-authority-ink", bar: 4.5, role: "pillar text" },
  { name: "--perch-pillar-evidence-ink", bar: 4.5, role: "pillar text" },
  { name: "--perch-pillar-substrate-mark", bar: 3, role: "non-text mark" },
  { name: "--perch-pillar-authority-mark", bar: 3, role: "non-text mark" },
  { name: "--perch-pillar-evidence-mark", bar: 3, role: "non-text mark" },
  { name: "--perch-sev-low", bar: 4.5, role: "severity word" },
  { name: "--perch-sev-medium", bar: 4.5, role: "severity word" },
  { name: "--perch-sev-high", bar: 4.5, role: "severity word" },
  { name: "--perch-sev-critical", bar: 4.5, role: "severity word" },
  { name: "--perch-danger-mark", bar: 3, role: "non-text mark" },
  { name: "--perch-ring", bar: 3, role: "focus ring — WCAG 2.2 SC 1.4.11" },
  { name: "--perch-border-strong", bar: 0, role: "decoration" },
  { name: "--perch-border", bar: 0, role: "decoration" },
];

export function measure(palettes = parsePalettes()) {
  const rows = [];
  for (const theme of ["light", "dark"]) {
    const p = palettes[theme];
    for (const ink of INKS) {
      const inkRgb = hslTripletToRgb(p[ink.name] ?? "");
      if (!inkRgb) continue;
      for (const surface of SURFACES) {
        const surfRgb = hslTripletToRgb(p[surface] ?? "");
        if (!surfRgb) continue;
        rows.push({
          theme,
          ink: ink.name,
          inkHex: rgbToHex(inkRgb),
          surface,
          surfaceHex: rgbToHex(surfRgb),
          ratio: Math.round(contrast(inkRgb, surfRgb) * 100) / 100,
          bar: ink.bar,
          role: ink.role,
          pass: ink.bar === 0 || contrast(inkRgb, surfRgb) >= ink.bar,
        });
      }
    }
  }
  return rows;
}

/* ── cli ──────────────────────────────────────────────────────────────────── */

if (import.meta.url === `file://${process.argv[1]}`) {
  const rows = measure();
  if (process.argv.includes("--json")) {
    process.stdout.write(JSON.stringify(rows, null, 2) + "\n");
  } else {
    let theme = "";
    for (const r of rows) {
      if (r.theme !== theme) {
        theme = r.theme;
        process.stdout.write(`\n── ${theme.toUpperCase()} ──\n`);
      }
      const bar = r.bar === 0 ? "  —  " : r.bar.toFixed(1).padStart(5);
      process.stdout.write(
        `${r.pass ? " " : "✗"} ${r.ratio.toFixed(2).padStart(6)}  bar${bar}  ` +
          `${r.ink.replace("--perch-", "").padEnd(24)} on ` +
          `${r.surface.replace("--perch-", "").padEnd(16)} ${r.role}\n`,
      );
    }
    const fails = rows.filter((r) => !r.pass);
    process.stdout.write(
      `\n${rows.length} pair(s) measured from ${CSS}; ${fails.length} below bar\n`,
    );
  }
  if (process.argv.includes("--check")) {
    const fails = measure().filter((r) => !r.pass);
    if (fails.length > 0) {
      for (const f of fails) {
        process.stderr.write(
          `FAIL ${f.theme} ${f.ink} on ${f.surface}: ${f.ratio} < ${f.bar} (${f.role})\n`,
        );
      }
      process.exit(1);
    }
  }
}
