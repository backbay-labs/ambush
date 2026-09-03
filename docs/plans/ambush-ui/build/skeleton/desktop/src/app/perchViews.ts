// Target path in BUZZ: desktop/src/app/perchViews.ts  (NEW file)
//
// Replaces two hand-written, compiler-unlinked copies of the same union:
//   BUZZ desktop/src/app/AppShell.helpers.ts:5-12          `AppView`     (7 members)
//   BUZZ desktop/src/features/sidebar/ui/AppSidebarPinnedHeader.tsx:16-23
//                                                          `SidebarSelectedView` (7 members)
// Both were read this session; neither imports the other, so a new view
// silently mis-highlights the rail. Perch has one union and one derivation.
//
// `deriveShellRoute` is called from a useMemo at BUZZ AppShell.tsx:159-162 in
// the renderer; its `selectedView` drives sidebar highlighting and is the value
// useMarkAsReadShortcuts.ts:41 tests before marking a channel read. A route not
// added here falls through to the default and reads as the home view.
//
// Gate-line budget: 1000 (src/app is a governed root, BUZZ
// desktop/scripts/check-file-sizes.mjs:10-55). This file targets ~140.

/** The ten routed Perch surfaces plus settings. One member per route. */
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
  | "settings";

/**
 * How much of the shell a route wants around it.
 *
 * `full`  — colony rail, sidebar, top chrome, governance strip, outlet.
 * `bare`  — governance strip and outlet only. The Watchfloor is a wall screen
 *           that must not carry navigation chrome.
 *
 * This is the alternative to Buzz's settings takeover (AppShell.tsx:173 sets
 * `settingsOpen` from the pathname, and the branch at :784-823 renders
 * LazySettingsScreen INSTEAD of the outlet at :941, which is why
 * routes/settings.tsx:33-35 returns null). Perch keeps the outlet mounted on
 * every route and hides chrome instead of replacing the subtree, so a
 * full-screen surface costs one conditional in the existing JSX rather than a
 * second copy of the shell. See 14-CLIENT-ARCHITECTURE.md §3.4.
 */
export type PerchChromeMode = "full" | "bare";

export type PerchShellRoute = {
  /** Case channel UUID when the route is a case, else null. */
  selectedCaseId: string | null;
  /** Lane channel UUID when the route is a lane, else null. */
  selectedLaneId: string | null;
  selectedView: PerchView;
  chrome: PerchChromeMode;
};

const BARE_CHROME_VIEWS: ReadonlySet<PerchView> = new Set(["watchfloor"]);

function segment(pathname: string, index: number): string | null {
  const raw = pathname.split("/")[index];
  return raw ? decodeURIComponent(raw) : null;
}

function view(pathname: string): {
  selectedView: PerchView;
  selectedCaseId: string | null;
  selectedLaneId: string | null;
} {
  if (pathname.startsWith("/cases/")) {
    return {
      selectedView: "case",
      selectedCaseId: segment(pathname, 2),
      selectedLaneId: null,
    };
  }
  if (pathname.startsWith("/lanes/")) {
    return {
      selectedView: "lane",
      selectedCaseId: null,
      selectedLaneId: segment(pathname, 2),
    };
  }

  const flat: Record<string, PerchView> = {
    "/leases": "leases",
    "/policy": "policy",
    "/watch-floor": "watchfloor",
    "/ledger": "ledger",
    "/tuning": "tuning",
    "/handoff": "handoff",
    "/gaps": "gaps",
    "/settings": "settings",
  };

  return {
    selectedView: flat[pathname] ?? "watch",
    selectedCaseId: null,
    selectedLaneId: null,
  };
}

export function derivePerchShellRoute(pathname: string): PerchShellRoute {
  const resolved = view(pathname);
  return {
    ...resolved,
    chrome: BARE_CHROME_VIEWS.has(resolved.selectedView) ? "bare" : "full",
  };
}

/**
 * Exhaustive nav registry. The sidebar renders from this, so a route that
 * exists and is not listed cannot be reached from the rail, and a listed view
 * that is not a `PerchView` is a compile error.
 *
 * `label` values obey APPENDIX-NORMATIVE.md §7: /leases is labelled
 * "Containments" because bare "lease" is banned in a nav item — three
 * unrelated objects share the word (capability lease / containment lease /
 * contingency lease).
 *
 * Every label in this array was run through the ban list in
 * build/skeleton/tools/copy-ban-list.tsv: no `approve`, no capital-D `Deny`,
 * no trust claim, no bare `lane`, no bare `lease`, no bare source count, no
 * `hunt` as a noun, no exclamation mark.
 */
export const PERCH_NAV: ReadonlyArray<{
  view: PerchView;
  to: string;
  label: string;
  /**
   * The route table's own phase column, copied from APPENDIX-NORMATIVE.md §1
   * VERBATIM. `/settings` is phase 0 there. 14-CLIENT-ARCHITECTURE.md §13
   * proposes amendment A11 against the REASON that row gives ("must become a
   * real route before the first new surface" describes completed work), but a
   * proposed amendment is not a ratified one, so the DATA here stays the
   * registry's until it is. Baking an unratified amendment into a const is how
   * the wave-2 review found six correct prose corrections losing to one wrong
   * literal.
   */
  phase: 0 | 1 | 2 | 3;
}> = [
  { view: "watch", to: "/", label: "The Watch", phase: 1 },
  { view: "leases", to: "/leases", label: "Containments", phase: 2 },
  { view: "ledger", to: "/ledger", label: "Ledger", phase: 2 },
  { view: "tuning", to: "/tuning", label: "Tuning", phase: 2 },
  { view: "policy", to: "/policy", label: "Policy", phase: 2 },
  // "Handoff", not "End watch". APPENDIX-NORMATIVE.md §1 names the SURFACE
  // "Handoff — Take the watch / End watch": two verbs, one surface. A nav item
  // carrying one of the two verbs is wrong for half of every shift — an
  // operator arriving at 22:00 is taking the watch, and a rail that says
  // "End watch" is naming an action they must not take. The verbs belong on
  // the surface's own controls. prototypes/watch.html renders "End watch" in
  // the rail; that is a one-word divergence from this registry and 06 owns the
  // final string. Recorded in 14-CLIENT-ARCHITECTURE.md §14.
  { view: "handoff", to: "/handoff", label: "Handoff", phase: 2 },
  { view: "gaps", to: "/gaps", label: "Gaps", phase: 2 },
  { view: "watchfloor", to: "/watch-floor", label: "Watchfloor", phase: 3 },
  { view: "settings", to: "/settings", label: "Settings", phase: 0 },
] as const;

// `case` and `lane` are reachable only from a row, never from the rail, so
// they are deliberately absent from PERCH_NAV. This assertion is what stops a
// future edit from adding a nav entry for a view id that does not exist.
type Assert<T extends true> = T;
type NavView = (typeof PERCH_NAV)[number]["view"];
export type _NavViewsAreRealViews = Assert<
  NavView extends PerchView ? true : false
>;
