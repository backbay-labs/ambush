/**
 * The view derivation for the perch shell: one function, called from the
 * swarm card surface hook, that reads the router pathname and says which
 * perch surface the operator is on.
 *
 * This milestone (First card) needs two members: a case channel opened as a
 * case at `/cases/$caseId`, and everything else. The full eleven-view union
 * (`watch`, `lane`, `leases`, `policy`, `watchfloor`, `ledger`, `tuning`,
 * `handoff`, `gaps`, `settings`) is Operator-complete's, and it grows this
 * union rather than adding a second derivation beside it.
 */
export type PerchView =
  | "watch"
  | "case"
  | "lane"
  | "leases"
  | "policy"
  | "watchfloor"
  | "ledger"
  | "tuning"
  | "handoff"
  | "gaps"
  | "other";

/**
 * How much of the app's chrome a perch surface keeps.
 *
 * `bare` is the Watchfloor: no sidebar, no colony rail, because it is read
 * from across a room. The governance strip survives it — the state that strip
 * reports is the state in which every number on the wall becomes
 * untrustworthy, and a screen that hid it while showing the numbers would be
 * the worst possible combination.
 */
export type PerchChrome = "full" | "bare";

/** What the shell knows about the current route, derived from its pathname. */
export type PerchShellRoute = {
  readonly selectedView: PerchView;
  /** Case channel UUID when the route is a case, else null. */
  readonly selectedCaseId: string | null;
  /** Lane id when the route is a lane, else null. */
  readonly selectedLaneId: string | null;
  readonly chrome: PerchChrome;
};

/**
 * Path segment `index` of `pathname` (`/cases/<id>` puts the id at 2),
 * percent-decoded, or null when the segment is absent or empty. A malformed
 * percent sequence is returned verbatim rather than thrown: this runs inside
 * a render-path hook, and a bad bookmark must not blank the timeline.
 */
function segment(pathname: string, index: number): string | null {
  const raw = pathname.split("/")[index];
  if (!raw) return null;
  try {
    return decodeURIComponent(raw);
  } catch {
    return raw;
  }
}

/**
 * Derive the perch shell route from a router pathname. Pure; safe to call on
 * every render.
 */
const ROUTED_VIEWS: readonly (readonly [string, PerchView])[] = [
  ["/leases", "leases"],
  ["/policy", "policy"],
  ["/watch-floor", "watchfloor"],
  ["/ledger", "ledger"],
  ["/tuning", "tuning"],
  ["/handoff", "handoff"],
  ["/gaps", "gaps"],
];

export function derivePerchShellRoute(pathname: string): PerchShellRoute {
  if (pathname.startsWith("/cases/")) {
    return {
      selectedView: "case",
      selectedCaseId: segment(pathname, 2),
      selectedLaneId: null,
      chrome: "full",
    };
  }
  if (pathname.startsWith("/lanes/")) {
    return {
      selectedView: "lane",
      selectedCaseId: null,
      selectedLaneId: segment(pathname, 2),
      chrome: "full",
    };
  }
  for (const [prefix, view] of ROUTED_VIEWS) {
    // Exact or one-segment-deeper, never `startsWith` alone: `/policyholders`
    // is not `/policy`, and a prefix match would put the whole app into the
    // wrong view for any future route that shares a stem.
    if (pathname === prefix || pathname.startsWith(`${prefix}/`)) {
      return {
        selectedView: view,
        selectedCaseId: null,
        selectedLaneId: null,
        // Only the Watchfloor drops chrome.
        chrome: view === "watchfloor" ? "bare" : "full",
      };
    }
  }
  if (pathname === "/") {
    return {
      selectedView: "watch",
      selectedCaseId: null,
      selectedLaneId: null,
      chrome: "full",
    };
  }
  return {
    selectedView: "other",
    selectedCaseId: null,
    selectedLaneId: null,
    chrome: "full",
  };
}
