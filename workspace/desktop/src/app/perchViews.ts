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
export type PerchView = "case" | "other";

/** What the shell knows about the current route, derived from its pathname. */
export type PerchShellRoute = {
  readonly selectedView: PerchView;
  /** Case channel UUID when the route is a case, else null. */
  readonly selectedCaseId: string | null;
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
export function derivePerchShellRoute(pathname: string): PerchShellRoute {
  if (pathname.startsWith("/cases/")) {
    return { selectedView: "case", selectedCaseId: segment(pathname, 2) };
  }
  return { selectedView: "other", selectedCaseId: null };
}
