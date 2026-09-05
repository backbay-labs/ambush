import * as React from "react";
import { useQuery } from "@tanstack/react-query";

import {
  groupGaps,
  type EvasionCoverageSnapshot,
} from "@/features/perch-policy/lib/gapsCatalog";
import { PERCH_NO_RETRY, perchKeys } from "@/shared/api/perchKeys";
import { perchEvasionCoverage } from "@/shared/api/tauriPerch";
import { AdversaryString } from "@/shared/ui/perch/AdversaryString";

/**
 * S12, `/gaps`. What the detectors deliberately do not see.
 *
 * The honest answer to a quiet queue. Every row is a gap the engine's own
 * evasion suite declares, rendered with the rationale its author wrote — a
 * paraphrase would be this console asserting a limit it did not measure.
 */
export function GapsScreen(): React.ReactElement {
  const query = useQuery<EvasionCoverageSnapshot>({
    queryKey: perchKeys.evasionCoverage(),
    queryFn: async () =>
      (await perchEvasionCoverage()) as EvasionCoverageSnapshot,
    // Five minutes, no poll: the catalog changes when the suite does, which is
    // a deploy, not a second.
    staleTime: 300_000,
    ...PERCH_NO_RETRY,
  });

  const snapshot = query.data;
  const grouped = React.useMemo(
    () =>
      snapshot
        ? groupGaps(snapshot)
        : { detectors: [], techniqueCount: 0, detectorCount: 0 },
    [snapshot],
  );

  return (
    <section data-testid="perch-gaps" className="flex flex-col gap-3 p-4">
      <h1 className="text-base font-medium text-[hsl(var(--perch-foreground))]">
        Gaps
      </h1>

      {query.isPending ? (
        <p
          data-testid="perch-gaps-loading"
          className="text-sm text-[hsl(var(--perch-foreground-muted))]"
        >
          Reading the detector coverage catalog…
        </p>
      ) : null}

      {query.isError ? (
        <p
          data-testid="perch-gaps-unavailable"
          role="alert"
          className="text-sm text-[hsl(var(--perch-foreground))]"
        >
          The daemon did not answer, so this console cannot say what the
          detectors miss. An empty catalog and an unanswered one are different
          facts, and this is the second.
        </p>
      ) : null}

      {snapshot ? (
        <p
          data-testid="perch-gaps-summary"
          className="text-sm text-[hsl(var(--perch-foreground-muted))]"
        >
          {`${grouped.techniqueCount} techniques across ${grouped.detectorCount} detectors · suite ${snapshot.suite_name} · corpus ${snapshot.corpus_version}`}
        </p>
      ) : null}

      {snapshot && grouped.detectors.length === 0 ? (
        <p
          data-testid="perch-gaps-none"
          className="text-sm text-[hsl(var(--perch-foreground-muted))]"
        >
          The suite declares no intentionally uncovered techniques. That is a
          statement about the suite, not a guarantee about the world.
        </p>
      ) : null}

      <ul className="flex flex-col gap-3">
        {grouped.detectors.map((detector) => (
          <li
            key={detector.detector}
            data-testid={`perch-gap-detector-${detector.detector}`}
            className="flex flex-col gap-2 border-l-4 border-[hsl(var(--perch-border-strong))] px-3 py-2"
          >
            <span className="font-mono text-xs text-[hsl(var(--perch-foreground))]">
              {detector.detector}
            </span>
            <ul className="flex flex-col gap-2">
              {detector.gaps.map((gap) => (
                <li
                  key={`${detector.detector}:${gap.technique}`}
                  data-testid={`perch-gap-${gap.technique}`}
                  className="flex flex-col gap-0.5"
                >
                  <span className="text-sm text-[hsl(var(--perch-foreground))]">
                    {`${gap.technique} · ${gap.threat_class}`}
                  </span>
                  {/* The catalog's own words, through the untrusted-text rail:
                      the rationale is authored upstream of this console. */}
                  <AdversaryString
                    field="rationale"
                    value={gap.rationale}
                    layout="block"
                    className="text-xs"
                  />
                </li>
              ))}
            </ul>
          </li>
        ))}
      </ul>
    </section>
  );
}
