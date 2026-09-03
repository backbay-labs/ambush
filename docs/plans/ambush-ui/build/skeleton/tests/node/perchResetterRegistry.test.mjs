// Target path in BUZZ: desktop/src/features/communities/perchResetterRegistry.test.mjs
// Run by `pnpm test` in desktop/.
//
// INV-23 — `resetCommunityState` is exhaustive over the `ColonyScopedSingleton`
// union.
//
// TWO MECHANISMS, AND THIS IS THE WEAKER ONE. Say so up front.
//
//   MECHANISM 1 — THE TYPE (the real gate).
//     `resetCommunityState` today is 21 hand-written calls in one async function
//     (BUZZ desktop/src/features/communities/useCommunityInit.ts:47-84, body
//     :59-83; two behind the `resetAvatarState` flag and one behind
//     `isTauri() && isMacPlatform()`) `[V]`. Nothing connects that list to the
//     set of module-level singletons that exist. Perch replaces it with
//
//         export type ColonyScopedSingleton = "perchHoldCache" | "perchLaneWindows" | …;
//         export const RESETTERS: Record<ColonyScopedSingleton, () => void> = { … };
//
//     A `Record<Union, …>` is exhaustive: adding a union member without a
//     resetter fails `tsc --noEmit`, which already runs on every pre-push
//     (BUZZ CLAUDE.md), and an extra key fails too. That is the guarantee.
//     CATCHES: a declared singleton with no resetter, at compile time.
//     MISSES: a singleton nobody declared.
//
//   MECHANISM 2 — THIS TEST.
//     A filesystem sweep for the shape a colony-scoped singleton actually takes
//     in this codebase — a module-level `Map`, `Set`, `WeakMap`, class instance
//     or `let` cache in a `features/perch*` module — paired with the reset
//     function that module exports. Every such module must appear in RESETTERS.
//     CATCHES: a new cache whose author forgot the union member.
//     MISSES: a singleton held inside a hook's closure, a singleton in
//             `shared/`, and any cache built with a shape this sweep does not
//             recognise.
//
// WHY IT MATTERS MORE HERE THAN IN A CHAT APP
//   React key-remounting (`<AppReady key={communityKey} />`, BUZZ
//   desktop/src/app/App.tsx) clears React state only. Module-level values
//   survive. In Buzz a missed reset is a stale channel list. In Perch it is one
//   colony's holds, findings and host ids rendered under another colony's name —
//   a disclosure, not a cache bug. Buzz's own doc comment records that
//   hook-managed singletons are deliberately out of scope, so this test must not
//   claim to cover them; it says so in `SWEEP_LIMITS` below and the failure
//   message repeats it.

import assert from "node:assert/strict";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { RESETTERS } from "./perchResetterRegistry.ts";

/**
 * The tree to sweep. In BUZZ this file sits at
 * `desktop/src/features/communities/`, so `../..` is `src/` and the sweep root
 * is `src/features`. PERCH_FEATURES_ROOT overrides it, which is how this file is
 * runnable from the wave-2 skeleton, where no `features/` tree exists.
 *
 * A MISSING TREE IS A SKIP WITH A NAMED BLOCKER, NOT A PASS. The sweep's whole
 * value is that it refuses to report success over an empty set, and "the
 * directory is not there" is the emptiest set available -- so it must not reach
 * the same green line as "swept and found nothing".
 */
const featuresRoot =
  process.env.PERCH_FEATURES_ROOT ??
  path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "features");
const featuresRootExists = existsSync(featuresRoot);

/** Stated in the failure message, so nobody reads a pass as total coverage. */
const SWEEP_LIMITS =
  "This sweep sees module-level Map/Set/WeakMap/class/let caches in features/perch* " +
  "modules. It does not see singletons inside hook closures, singletons under " +
  "shared/, or a cache built with a shape it does not recognise. The Record<> type " +
  "is the guarantee; this is the backstop.";

const SINGLETON_SHAPES = [
  /^(?:const|let)\s+\w+\s*[:=][^=\n]*\bnew\s+(?:Map|Set|WeakMap|WeakSet)\b/,
  /^(?:const|let)\s+\w+\s*[:=][^=\n]*\bnew\s+[A-Z]\w+\(/,
  /^let\s+\w+\s*[:=]/,
];

function perchModules(dir) {
  const found = [];
  for (const entry of readdirSync(dir)) {
    const full = path.join(dir, entry);
    if (statSync(full).isDirectory()) {
      found.push(...perchModules(full));
      continue;
    }
    if (!/\.tsx?$/.test(entry)) continue;
    if (/\.(test|spec)\./.test(entry)) continue;
    found.push(full);
  }
  return found;
}

function holdsAModuleLevelSingleton(source) {
  return source
    .split("\n")
    // Module level means column 0. An indented `let` is inside a function and
    // dies with its call; that is the distinction the whole invariant turns on.
    .filter((line) => !line.startsWith(" ") && !line.startsWith("\t"))
    .some((line) => SINGLETON_SHAPES.some((shape) => shape.test(line.trim())));
}

test("the sweep can find a singleton, and can tell one from a local", () => {
  // A test whose detector is untested is a test that passes over an empty set.
  assert.ok(
    holdsAModuleLevelSingleton('const holdCache = new Map<string, Hold>();\n'),
    "the sweep failed to recognise a module-level Map",
  );
  assert.ok(
    holdsAModuleLevelSingleton("let lastReconciledAt = 0;\n"),
    "the sweep failed to recognise a module-level let cache",
  );
  assert.ok(
    !holdsAModuleLevelSingleton("function f() {\n  const local = new Map();\n}\n"),
    "the sweep mistook a function-local Map for a singleton",
  );
});

/**
 * The sweep, factored out so it can be driven over the real tree AND over a
 * fixture. A detector that is only ever run over a tree that happens to be clean
 * has never been shown to fire.
 */
function unregisteredSingletons(root, registered) {
  const modules = perchModules(root).filter((file) =>
    path.relative(root, file).startsWith("perch"),
  );
  const missing = [];
  for (const file of modules) {
    const source = readFileSync(file, "utf8");
    if (!holdsAModuleLevelSingleton(source)) continue;
    // The convention: a module holding colony-scoped state exports
    // `export function resetXxx()` and `Xxx` is its union member.
    const exported = source.match(/export function reset([A-Z]\w*)\s*\(/);
    if (!exported) {
      missing.push(
        `${path.relative(root, file)} holds a module-level singleton and exports no reset function`,
      );
      continue;
    }
    const member = exported[1][0].toLowerCase() + exported[1].slice(1);
    if (!registered.has(member)) {
      missing.push(
        `${path.relative(root, file)} exports reset${exported[1]}() but "${member}" is not a ColonyScopedSingleton`,
      );
    }
  }
  return { moduleCount: modules.length, missing };
}

test("the sweep fires on an unregistered singleton and on an un-resettable one", () => {
  // Two planted violations and two clean controls, over a throwaway tree. This
  // is the half that proves the assertion below can fail -- without it, a pass
  // over the real tree says only that the sweep ran.
  const dir = mkdtempSync(path.join(tmpdir(), "perch-resetter-sweep-"));
  try {
    const feature = path.join(dir, "perch-watch");
    mkdirSync(feature, { recursive: true });

    writeFileSync(
      path.join(feature, "unregistered.ts"),
      'const strayCache = new Map<string, number>();\nexport function resetStrayCache() { strayCache.clear(); }\n',
    );
    writeFileSync(
      path.join(feature, "noResetter.ts"),
      "let lastSeenAt = 0;\nexport const bump = () => { lastSeenAt += 1; };\n",
    );
    writeFileSync(
      path.join(feature, "registered.ts"),
      'const perchHoldCache = new Map<string, unknown>();\nexport function resetPerchHoldCache() { perchHoldCache.clear(); }\n',
    );
    writeFileSync(
      path.join(feature, "noSingleton.tsx"),
      "export function Row() {\n  const local = new Map();\n  return local.size;\n}\n",
    );

    const { moduleCount, missing } = unregisteredSingletons(dir, new Set(Object.keys(RESETTERS)));
    assert.equal(moduleCount, 4);
    assert.ok(
      missing.some((m) => m.startsWith("perch-watch/unregistered.ts") && m.includes("strayCache")),
      `an unregistered singleton was not caught: ${JSON.stringify(missing)}`,
    );
    assert.ok(
      missing.some(
        (m) => m.startsWith("perch-watch/noResetter.ts") && m.includes("exports no reset function"),
      ),
      `a singleton with no reset function was not caught: ${JSON.stringify(missing)}`,
    );
    // `startsWith`, not `includes`: "unregistered.ts" CONTAINS "registered.ts",
    // and an `includes` here passed while the sweep was flagging the clean
    // control. The fixture caught it, which is the argument for the fixture.
    assert.ok(
      !missing.some((m) => m.startsWith("perch-watch/registered.ts")),
      `a properly registered singleton was flagged: ${JSON.stringify(missing)}`,
    );
    assert.ok(
      !missing.some((m) => m.startsWith("perch-watch/noSingleton.tsx")),
      "a function-local Map was flagged",
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("INV-23 — every Perch module holding a singleton is in RESETTERS", (t) => {
  if (!featuresRootExists) {
    // Named blocker, not a silent pass. This is the wave-2 skeleton state: the
    // Perch feature tree does not exist in block/buzz yet, so there is nothing
    // to sweep. The detector test above still ran.
    t.skip(
      `no features tree at ${featuresRoot}. The Perch feature directories do not ` +
        "exist in block/buzz yet; set PERCH_FEATURES_ROOT to sweep another tree. " +
        "This is a SKIP and not a pass on purpose.",
    );
    return;
  }

  const { moduleCount, missing } = unregisteredSingletons(featuresRoot, new Set(Object.keys(RESETTERS)));
  assert.ok(
    moduleCount > 0,
    `${featuresRoot} exists but holds no perch* module; refusing to pass over an empty set`,
  );
  assert.deepEqual(
    missing,
    [],
    `Colony-scoped state that survives a community switch:\n  ${missing.join("\n  ")}\n\n${SWEEP_LIMITS}`,
  );
});

test("every RESETTERS entry is callable and idempotent", () => {
  // A resetter that throws on a second call turns a double switch into an error
  // state; a resetter that is not a function is a typo the Record<> type cannot
  // catch when the value is `undefined as never`.
  for (const [member, reset] of Object.entries(RESETTERS)) {
    assert.equal(typeof reset, "function", `RESETTERS["${member}"] is not a function`);
    reset();
    reset();
  }
});
