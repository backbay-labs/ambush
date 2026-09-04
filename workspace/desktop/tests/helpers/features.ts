// Single source of truth for E2E tests: derive preview-feature data from
// /preview-features.json so we don't have to hand-maintain a parallel array.
//
// Production reads the same JSON via the `@features-manifest` vite alias
// (see `desktop/src/shared/features/manifest.ts`). The localStorage key
// format matches `OVERRIDES_KEY` in `desktop/src/shared/features/store.ts`
// — bumping `version` in `preview-features.json` updates production AND
// every spec automatically.
import featuresManifest from "../../../preview-features.json" with {
  type: "json",
};

interface FeatureDefinition {
  id: string;
  name: string;
  description: string;
  platforms?: string[];
}

interface FeaturesManifest {
  version: number;
  features: FeatureDefinition[];
}

const manifest = featuresManifest as FeaturesManifest;

/** IDs of every preview feature on desktop, opt-in ones included. */
export const ALL_DESKTOP_FEATURE_IDS: string[] = manifest.features
  .filter((f) => !f.platforms || f.platforms.includes("desktop"))
  .map((f) => f.id);

/**
 * Preview features the blanket seeding below deliberately leaves OFF.
 *
 * `perch` reshapes what a timeline row renders: with it on, a `kind:9` whose
 * line 0 is a swarm marker becomes an evidence card instead of prose. The
 * whole existing smoke suite runs against the blanket seeding, so enabling
 * perch there would silently change Home and every message body in it. Perch
 * specs opt in through `installMockBridge(page, mock, { enableFeatures })`,
 * which is what `installPerchBridge` does.
 */
export const OPT_IN_FEATURE_IDS: readonly string[] = ["perch"];

// A rename in preview-features.json must not quietly turn the opt-in list
// into a no-op that switches perch on for 150 unrelated specs.
for (const id of OPT_IN_FEATURE_IDS) {
  if (!ALL_DESKTOP_FEATURE_IDS.includes(id)) {
    throw new Error(
      `OPT_IN_FEATURE_IDS names "${id}", which preview-features.json does not declare for desktop.`,
    );
  }
}

/** IDs of every preview feature the default seeding turns on. */
export const PREVIEW_FEATURE_IDS: string[] = ALL_DESKTOP_FEATURE_IDS.filter(
  (id) => !OPT_IN_FEATURE_IDS.includes(id),
);

/**
 * The localStorage key the production store uses for feature overrides.
 * Mirrors `OVERRIDES_KEY` in `src/shared/features/store.ts` so a manifest
 * version bump flows through to E2E seeding without manual updates.
 */
export const FEATURE_OVERRIDES_STORAGE_KEY = `ambush-feature-overrides-v${manifest.version}`;
