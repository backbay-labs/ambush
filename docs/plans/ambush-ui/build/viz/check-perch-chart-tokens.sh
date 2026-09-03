#!/usr/bin/env bash
#
# G2 — check-perch-chart-tokens.sh   [PROPOSED, lands at AMBUSH tools/]
#
# WHY THIS EXISTS
#   Four of 18-DATAVIZ.md's chart rules are enforceable only lexically, and each
#   one has already been violated once in this workspace by somebody who knew
#   the rule:
#
#   R1  CR-2. No hex colour literal in a chart component. A hex bypasses the
#       token layer entirely, so the chart does not re-theme and its measured
#       contrast ratio stops being the one anybody checked.
#
#   R2  CR-2. No `fill=` / `stroke=` PRESENTATION ATTRIBUTE carrying a colour.
#       Perch's colour tokens are bare HSL triplets (`141.9 69.2% 58%`), exactly
#       as BUZZ's own do at desktop/tailwind.config.js:83-136. A triplet does not
#       resolve inside an attribute, so `fill="var(--perch-viz-series-1)"`
#       renders BLACK and errors nowhere. Colour must reach an SVG node through
#       a CSS class. `none` and a paint-server reference `url(#...)` are values,
#       not colours, and are allowed.
#
#   R3  CR-5. No prop named `sources` typed `number`. Render law 2 forbids a
#       bare source count; the component takes ids (or a NAMED absence) and
#       derives both halves itself.
#
#   R4  TOKEN NAMESPACE (19-TOKENS.md). No Perch component may read a bare BUZZ
#       shadcn variable. `createThemeVars`
#       (BUZZ desktop/src/shared/theme/adaptive-theme.ts:191-240) returns exactly
#       38 of them and `applyTheme`
#       (desktop/src/shared/theme/ThemeProvider.tsx:427-446, in the renderer on
#       every theme change) writes each one with `root.style.setProperty`, an
#       INLINE declaration on the root element that no normal-priority stylesheet
#       rule can beat. A Perch surface authored against those names repaints with
#       whatever BUZZ syntax theme is active. This rule is the mechanical half of
#       that commitment; without it the commitment is a memo.
#
# WHAT THIS SCRIPT COVERS
#   Every file under the scan roots (default: the Perch chart layer and any
#   *Chart*/*Curve*/*Sparkline*/*Timeline* file under the Perch feature roots),
#   outside comment-only lines.
#
# WHAT IT CANNOT SEE, AND THEREFORE DOES NOT CLAIM
#   1. A hex assembled at runtime (`"#" + hue`).
#   2. A colour reaching a node through a spread (`<rect {...paint} />`).
#   3. A Buzz variable read indirectly (`const t = "--card"; var(t)`), or one
#      read from a CSS file this script's roots do not cover.
#   4. Whether a `--perch-*` name actually EXISTS in perch-tokens.css. That is
#      tokens/perch-tokens.test.mjs's parity assertion, not this one.
#   5. A `sources` prop typed through an interface alias.
#   Rules 1-3 are lexical blind spots and are why 18-DATAVIZ §3 states each rule
#   as a component-API constraint first and a grep second.
#
# PROVING IT CAN FAIL
#   The script runs a FIXTURE on every invocation, BEFORE it scans anything
#   real: it plants each forbidden shape and fails if any is not caught, and it
#   plants clean controls that must pass -- including the two allowed paint
#   values (`none`, `url(#id)`), a `--perch-*` var, a hex inside a comment, and
#   a `sourceIds: string[]` prop. Without the controls the scanner could be
#   "catching" everything by matching unconditionally.
#
# CROSS-REPO, exactly as 16-INVARIANT-TESTS.md decision D1 established for the
# copy gate: this gate lives in AMBUSH so tools/check-gates-wired.sh enumerates
# it, and it scans a block/buzz checkout supplied in PERCH_DESKTOP_ROOT. The
# `gates` job in .github/workflows/ci.yml needs a second actions/checkout, and
# the workflow `run:` step MUST land in the same commit or check-gates-wired.sh
# fails on the commit that adds this file.
#
# Usage:  PERCH_DESKTOP_ROOT=/path/to/buzz tools/check-perch-chart-tokens.sh
#         tools/check-perch-chart-tokens.sh <file-or-dir> ...   (explicit roots)
set -euo pipefail

# ---------------------------------------------------------------- the rules --
# One alternation per rule, shared by the fixture and the real scan so they
# cannot drift apart. awk EREs have no \b, so a word boundary is written
# (^|[^A-Za-z0-9_-]).
# A hex must not be preceded by a word character or a slash: `/#aabbcc` is a URL
# fragment, not a colour, and the fixture carries that control.
HEX_RE='(^|[^0-9A-Za-z/])#[0-9a-fA-F]{6}([^0-9a-fA-F]|$)|(^|[^0-9A-Za-z/])#[0-9a-fA-F]{3}([^0-9a-fA-F]|$)'
PAINT_RE='(fill|stroke)[[:space:]]*=[[:space:]]*"[^"]*"|(fill|stroke)[[:space:]]*=[[:space:]]*[{]'
PAINT_OK_RE='(fill|stroke)[[:space:]]*=[[:space:]]*"(none|url[(]#[A-Za-z0-9_-]+[)])"'
SOURCES_NUM_RE='(^|[^A-Za-z0-9_])sources[[:space:]]*[?]?:[[:space:]]*number'

# The 38 variables createThemeVars returns, verbatim, plus the six applyAccentColor
# writes. Any `var(--name)` naming one of these inside a Perch chart file is R4.
BUZZ_VARS='background|foreground|card|card-foreground|popover|popover-foreground|primary|primary-foreground|secondary|secondary-foreground|muted|muted-foreground|accent|accent-foreground|destructive|destructive-foreground|border|input|ring|status-added|status-deleted|status-modified|ui-warning|ui-warning-bg|sidebar-background|sidebar-foreground|sidebar-accent|sidebar-accent-foreground|sidebar-border|sidebar-ring|huddle-control-foreground|huddle-control-surface|huddle-control-hover-surface|huddle-control-chevron-surface|huddle-control-chevron-hover-surface|huddle-drawer-surface|huddle-popover-surface|huddle-popover-border|huddle-tooltip-surface|huddle-tooltip-foreground'
BUZZ_VAR_RE="var[(][[:space:]]*--(${BUZZ_VARS})[[:space:]]*[),]"

scan_stream() {
  # prints `label:line:rule:text` for every violation in one file.
  #
  # COMMENTS ARE STRIPPED FIRST, in all three forms, because a rule name inside
  # a comment declares nothing and every one of these rules has to be DOCUMENTED
  # somewhere -- including in the very files it governs. perch-tokens.css records
  # each token's measured hex equivalent in a trailing /* ... */; that is the
  # documentation of the measurement, not a colour a component reads.
  #
  # KNOWN LIMIT: a `//` inside a string is treated as a line comment unless it is
  # immediately preceded by `:` (the `https://` case). A violation placed AFTER a
  # bare `//` inside a string on the same line is therefore invisible. Recorded
  # rather than papered over.
  local label="$1"
  awk -v label="$label" \
      -v hex="$HEX_RE" -v paint="$PAINT_RE" -v paintok="$PAINT_OK_RE" \
      -v srcnum="$SOURCES_NUM_RE" -v buzzvar="$BUZZ_VAR_RE" '
    function strip_line_comment(s,   i, n) {
      i = 1
      while ((n = index(substr(s, i), "//")) > 0) {
        n = i + n - 1
        if (n > 1 && substr(s, n - 1, 1) == ":") { i = n + 2; continue }
        return substr(s, 1, n - 1)
      }
      return s
    }
    {
      line = $0
      # a /* ... */ opened on an earlier line
      if (in_block) {
        if (match(line, /\*\//)) { line = substr(line, RSTART + 2); in_block = 0 }
        else next
      }
      # every complete /* ... */ on this line
      while (match(line, /\/\*.*\*\//)) {
        line = substr(line, 1, RSTART - 1) substr(line, RSTART + RLENGTH)
      }
      # a /* that opens and does not close
      if (match(line, /\/\*/)) { line = substr(line, 1, RSTART - 1); in_block = 1 }
      line = strip_line_comment(line)
      # a shell/# comment line
      if (line ~ /^[[:space:]]*#[^0-9a-fA-F]/) next
      if (line ~ /^[[:space:]]*$/) next

      if (line ~ hex)     printf "%s:%d:R1-hex:%s\n",            label, FNR, $0
      if (line ~ paint && line !~ paintok)
                          printf "%s:%d:R2-paint-attr:%s\n",     label, FNR, $0
      if (line ~ srcnum)  printf "%s:%d:R3-sources-number:%s\n", label, FNR, $0
      if (line ~ buzzvar) printf "%s:%d:R4-buzz-var:%s\n",       label, FNR, $0
    }
  ' "$2"
}

# ------------------------------------------------------------------ fixture --
FIXTURE_DIR="$(mktemp -d)"
trap 'rm -rf "$FIXTURE_DIR"' EXIT

cat >"$FIXTURE_DIR/bad.tsx" <<'BAD'
const rule = "#b45309";
const short = "#fff";
<rect fill="var(--perch-viz-series-1)" />
<path stroke="hsl(var(--perch-chart-rule))" />
<circle fill={seriesColor} />
type Props = { sources: number };
type Opt = { sources?: number };
const bg = "hsl(var(--card))";
const ink = "var(--muted-foreground)";
const after = /* documented as #ffffff */ "#123456";
BAD

cat >"$FIXTURE_DIR/clean.tsx" <<'CLEAN'
// #b45309 in a comment declares nothing
<path className="k-s1" />
<rect fill="none" />
<rect fill="url(#perchHatch)" />
<path stroke="none" />
type Props = { sourceIds: string[] };
type Attr = { sourceIds: readonly string[]; distinctSources: number };
const bg = "hsl(var(--perch-card))";
const ink = "hsl(var(--perch-foreground-muted))";
const resources: number = 3;
/* --perch-sev-high: 26.1 91% 34.7%;  #a94e08  4.76-5.55 */
const doc = 1; /* measured #825b12 on --perch-card */
const url = "https://example.test/#aabbcc";
CLEAN

EXPECTED_RULES="R1-hex R2-paint-attr R3-sources-number R4-buzz-var"
BAD_HITS="$(scan_stream "<fixture-bad>" "$FIXTURE_DIR/bad.tsx" || true)"
for rule in $EXPECTED_RULES; do
  if ! printf '%s\n' "$BAD_HITS" | grep -q ":${rule}:"; then
    echo "check-perch-chart-tokens: SELF-TEST FAILED -- ${rule} caught nothing." >&2
    echo "The scanner is broken; fix it before trusting it." >&2
    exit 2
  fi
done
N_BAD="$(grep -c . "$FIXTURE_DIR/bad.tsx")"
N_CLEAN="$(grep -c . "$FIXTURE_DIR/clean.tsx")"
CLEAN_HITS="$(scan_stream "<fixture-clean>" "$FIXTURE_DIR/clean.tsx" || true)"
if [ -n "$CLEAN_HITS" ]; then
  echo "check-perch-chart-tokens: SELF-TEST FAILED -- clean control flagged:" >&2
  printf '%s\n' "$CLEAN_HITS" >&2
  exit 2
fi

# --------------------------------------------------------------------- scan --
ROOTS=()
if [ "$#" -gt 0 ]; then
  ROOTS=("$@")
elif [ -n "${PERCH_DESKTOP_ROOT:-}" ]; then
  ROOTS=(
    "${PERCH_DESKTOP_ROOT}/desktop/src/shared/viz"
    "${PERCH_DESKTOP_ROOT}/desktop/src/features/perch"
    "${PERCH_DESKTOP_ROOT}/desktop/src/features/perch-watch"
    "${PERCH_DESKTOP_ROOT}/desktop/src/features/perch-evidence"
    "${PERCH_DESKTOP_ROOT}/desktop/src/features/perch-containment"
    "${PERCH_DESKTOP_ROOT}/desktop/src/features/perch-policy"
    "${PERCH_DESKTOP_ROOT}/desktop/src/features/perch-shift"
    "${PERCH_DESKTOP_ROOT}/desktop/src/shared/ui/perch"
  )
else
  echo "check-perch-chart-tokens: set PERCH_DESKTOP_ROOT or pass roots explicitly" >&2
  exit 2
fi

FILES=()
for root in "${ROOTS[@]}"; do
  if [ -d "$root" ]; then
    while IFS= read -r f; do [ -n "$f" ] && FILES+=("$f"); done < <(
      find "$root" \( -name '*.ts' -o -name '*.tsx' -o -name '*.css' -o -name '*.html' \) -type f | LC_ALL=C sort
    )
  elif [ -f "$root" ]; then
    FILES+=("$root")
  fi
done

if [ "${#FILES[@]}" -eq 0 ]; then
  echo "check-perch-chart-tokens: no chart files under the scan roots." >&2
  echo "The Perch chart layer does not exist yet. This gate lands with the first" >&2
  echo "file under desktop/src/shared/viz/ and refuses to pass silently until then." >&2
  exit 2
fi

HITS=""
for f in "${FILES[@]}"; do
  out="$(scan_stream "$f" "$f" || true)"
  [ -n "$out" ] && HITS="${HITS}${out}
"
done

if [ -n "${HITS//[$'\n']/}" ]; then
  echo "check-perch-chart-tokens: violations in ${#FILES[@]} chart file(s)" >&2
  printf '%s' "$HITS" >&2
  echo "" >&2
  echo "R1 hex          -> use hsl(var(--perch-*)) through a CSS class" >&2
  echo "R2 paint attr   -> colour reaches SVG through a class; a bare HSL triplet does not resolve in an attribute" >&2
  echo "R3 sources:num  -> render law 2: take sourceIds, or a NAMED absence; never a bare count" >&2
  echo "R4 buzz var     -> ThemeProvider writes those 38 names INLINE on :root; read --perch-* only" >&2
  exit 1
fi

echo "check-perch-chart-tokens: OK (${#FILES[@]} file(s); self-test: 4 rules fired over ${N_BAD} planted shapes, ${N_CLEAN} clean controls passed)" >&2
