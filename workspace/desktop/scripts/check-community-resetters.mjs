import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

/**
 * "Every community-scoped singleton is torn down on a community switch" gate.
 *
 * Switching communities remounts the React tree but leaves module-level state
 * standing: a `Map`, a `let`, a cached promise, a class instance. Anything
 * community-scoped that survives leaks community A's data into community B.
 * `features/communities/communityScopedRegistry.ts` is the inventory that
 * prevents it — but its `Record<CommunityScopedSingleton, Resetter>` type only
 * keeps that file's two halves in agreement. A brand-new store that was never
 * added to it type-checks perfectly and leaks silently. That is exactly how
 * `timeoutStore` and `cardMintStore` were missed.
 *
 * So this scans `src/` for the shape those stores share — module-level mutable
 * state next to an exported `reset*`/`clear*` function — and fails on any whose
 * resetter the registry does not import. It is deliberately a shape heuristic,
 * not a semantic one: a false positive costs one allowlist line with a reason,
 * while a false negative costs a cross-community data leak.
 */

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const projectRoot = path.resolve(__dirname, "..");
const srcRoot = path.join(projectRoot, "src");
const REGISTRY = "src/features/communities/communityScopedRegistry.ts";
const SCRIPT_PATH = "desktop/scripts/check-community-resetters.mjs";

/**
 * Files that hold module-level state with a `reset*`/`clear*` export but are
 * genuinely **not** community-scoped. Every entry carries the reason it is
 * safe to leave standing across a switch. A stale entry (one whose file no
 * longer matches the heuristic) fails the check too, so this list cannot rot.
 */
const ALLOWLIST = new Map([
  [
    "src/features/communities/addCommunityPrefill.ts",
    "Holds a pending *add a community* deep link, consumed by the add dialog — it is about the community being added, not the one being left.",
  ],
  [
    "src/features/communities/communityNavigationStorage.ts",
    "`pendingCommunityRestoreId` is set before a switch and consumed after it; clearing it mid-teardown would break the destination restore it exists for.",
  ],
  [
    "src/features/terminal/terminalPanelStore.ts",
    "Panel open/closed chrome plus session channel ids that `TerminalBootstrap` re-derives from live sessions on mount; its only resetter is explicitly test-only.",
  ],
  [
    "src/shared/theme/communityThemePreference.ts",
    "The module-level `Set`s are frozen validation tables, never mutated; `clearCommunityThemeOutbox` is a keyed localStorage helper, not a store reset.",
  ],
]);

// Module-level mutable state, anchored at column 0 so anything nested inside a
// function or class is ignored. `let` is mutable by definition; a `const`
// counts when it is bound to a mutable container.
const MODULE_STATE_RE =
  /^(?:const\s+([A-Za-z_$][\w$]*)\s*(?::[^=]+)?=\s*(?:new\s+(?:Map|Set|WeakMap|WeakSet)\b|\{\s*\}|\[\s*\])|let\s+([A-Za-z_$][\w$]*)\b)/;
// An exported teardown entry point, again only at module scope.
const RESETTER_RE =
  /^export\s+(?:async\s+)?(?:function\s+|const\s+)((?:reset|clear)[A-Z][\w$]*)/;
// Named imports, including multi-line ones (the source is scanned whole).
const IMPORT_RE = /import\s*\{([^}]*)\}\s*from\s*["']([^"']+)["']/g;

async function walk(directory) {
  const entries = await fs.readdir(directory, { withFileTypes: true });
  const nested = await Promise.all(
    entries.map(async (entry) => {
      const full = path.join(directory, entry.name);
      return entry.isDirectory() ? walk(full) : [full];
    }),
  );
  return nested.flat();
}

/** Repo-relative, posix-separated, so it matches the allowlist keys on Windows. */
function toRelative(absolutePath) {
  return path.relative(projectRoot, absolutePath).split(path.sep).join("/");
}

/** Resolve one `@/…` or relative import specifier to a project-relative path. */
async function resolveSpecifier(specifier, importerAbsolutePath) {
  let base;
  if (specifier.startsWith("@/")) {
    base = path.join(srcRoot, specifier.slice(2));
  } else if (specifier.startsWith(".")) {
    base = path.resolve(path.dirname(importerAbsolutePath), specifier);
  } else {
    return null; // A package, not a source file.
  }
  for (const candidate of [
    base,
    `${base}.ts`,
    `${base}.tsx`,
    path.join(base, "index.ts"),
    path.join(base, "index.tsx"),
  ]) {
    try {
      const stat = await fs.stat(candidate);
      if (stat.isFile()) return toRelative(candidate);
    } catch {
      // Try the next candidate.
    }
  }
  return null;
}

/**
 * Every source file the registry imports a resetter *from*, keyed by
 * project-relative path. Only names that actually appear in the file's body
 * after the import block count, so a dangling import cannot fake coverage.
 */
async function registeredFiles() {
  const registryAbsolute = path.join(projectRoot, REGISTRY);
  const source = await fs.readFile(registryAbsolute, "utf8");
  const body = source.slice(source.lastIndexOf("import "));
  const registered = new Map();
  for (const match of source.matchAll(IMPORT_RE)) {
    const names = match[1]
      .split(",")
      .map((name) =>
        name
          .trim()
          .split(/\s+as\s+/)
          .pop()
          .trim(),
      )
      .filter(Boolean);
    const resolved = await resolveSpecifier(match[2], registryAbsolute);
    if (!resolved) continue;
    const used = names.filter((name) =>
      new RegExp(`\\b${name}\\b`).test(body.slice(body.indexOf("\n"))),
    );
    if (used.length === 0) continue;
    registered.set(resolved, [...(registered.get(resolved) ?? []), ...used]);
  }
  return registered;
}

const registered = await registeredFiles();
const files = (await walk(srcRoot)).filter(
  (file) =>
    /\.tsx?$/.test(file) && !file.endsWith(".d.ts") && !/\.test\./.test(file),
);

const violations = [];
const matched = new Set();

for (const file of files) {
  const relativePath = toRelative(file);
  if (relativePath === REGISTRY) continue;

  const lines = (await fs.readFile(file, "utf8")).split(/\r?\n/);
  const state = [];
  const resetters = [];
  lines.forEach((line, index) => {
    const stateMatch = line.match(MODULE_STATE_RE);
    if (stateMatch)
      state.push(`${stateMatch[1] ?? stateMatch[2]}:${index + 1}`);
    const resetterMatch = line.match(RESETTER_RE);
    if (resetterMatch) resetters.push(`${resetterMatch[1]}:${index + 1}`);
  });
  if (state.length === 0 || resetters.length === 0) continue;

  matched.add(relativePath);
  if (ALLOWLIST.has(relativePath)) continue;
  const wired = registered.get(relativePath) ?? [];
  if (wired.length > 0) continue;

  violations.push({ relativePath, state, resetters });
}

const stale = [...ALLOWLIST.keys()].filter((entry) => !matched.has(entry));

if (violations.length > 0 || stale.length > 0) {
  console.error("Desktop community-resetter check failed:");
  for (const violation of violations) {
    console.error(
      `- ${violation.relativePath}: module-level state (${violation.state.join(", ")}) ` +
        `with resetter(s) ${violation.resetters.join(", ")}, but ${REGISTRY} does not import one.`,
    );
  }
  for (const entry of stale) {
    console.error(
      `- ${entry}: allowlisted here but no longer holds module-level state with a reset*/clear* export. Drop the entry.`,
    );
  }
  if (violations.length > 0) {
    console.error(
      "\nA community switch remounts React but not module scope, so this state " +
        "would carry community A's data into community B. Add the store to " +
        `COMMUNITY_SCOPED_SINGLETONS and RESETTERS in ${REGISTRY}. If it is ` +
        "genuinely not community-scoped, add it to ALLOWLIST in " +
        `${SCRIPT_PATH} with the one-line reason it is safe to leave standing.`,
    );
  }
  process.exit(1);
}
