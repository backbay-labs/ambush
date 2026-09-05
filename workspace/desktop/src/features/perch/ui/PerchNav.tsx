import type * as React from "react";
import { Link } from "@tanstack/react-router";

import { useFeatureEnabled } from "@/shared/features/useFeatureEnabled";

/**
 * The routed perch surfaces, in the order an operator works through them.
 *
 * The Watch first because it is where a shift starts and where every decision
 * is recorded; Handoff last because it is where one ends. The middle is
 * ordered by how far from a live decision each surface sits — leases and lanes
 * are things happening now, policy and tuning are things you change between
 * incidents.
 *
 * `Lanes` has no entry: there is no lane index, only twelve lane channels, and
 * a nav item pointing at one of them would be picking a threat class for the
 * operator.
 */
const PERCH_ROUTES = [
  { to: "/", label: "Watch" },
  { to: "/leases", label: "Containments" },
  { to: "/watch-floor", label: "Watchfloor" },
  { to: "/ledger", label: "Ledger" },
  { to: "/gaps", label: "Gaps" },
  { to: "/policy", label: "Policy" },
  { to: "/tuning", label: "Tuning" },
  { to: "/handoff", label: "Handoff" },
] as const;

/**
 * Navigation for the perch surfaces.
 *
 * Rendered only when the feature is on. Without it the ten routes exist and
 * are reachable only by typing a URL, which is not reachable at all for the
 * person this console is for.
 */
export function PerchNav(): React.ReactElement | null {
  const enabled = useFeatureEnabled("perch");
  if (!enabled) return null;
  return (
    <nav
      data-testid="perch-nav"
      aria-label="Operator surfaces"
      className="px-2 py-1"
    >
      <ul className="flex flex-wrap gap-1">
        {PERCH_ROUTES.map((entry) => (
          <li key={entry.to}>
            <Link
              to={entry.to}
              data-testid={`perch-nav-${entry.label.toLowerCase()}`}
              className="rounded px-2 py-0.5 text-xs text-muted-foreground"
              activeProps={{ className: "rounded px-2 py-0.5 text-xs" }}
            >
              {entry.label}
            </Link>
          </li>
        ))}
      </ul>
    </nav>
  );
}

/** Exported for the surface-count contract: every routed surface but Lanes. */
export const PERCH_NAV_ROUTES = PERCH_ROUTES;
