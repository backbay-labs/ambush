import type * as React from "react";

import { DerivedMarker } from "@/shared/viz/markers";

import {
  deriveTuningProvenance,
  type TuningIncident,
  type TuningRecommendation,
} from "../lib/tuningProvenance";

export type TuningScreenProps = {
  recommendations: TuningRecommendation[];
  incidents: TuningIncident[];
  weekStartMs: number;
};

const ORIGIN_LABEL = {
  "analyst-promoted": "promoted by an analyst",
  "correlation-produced": "produced by correlation",
  unresolved: "provenance unresolved",
} as const;

/**
 * S10, `/tuning`. What the daemon suggests changing, and on whose evidence.
 *
 * Every row states its provenance, because "the machine tuned itself" and "we
 * cannot tell who tuned this" lead to different decisions and a screen that
 * showed neither would get the second treated as the first.
 *
 * A recommendation with no verdicts behind it says so in words rather than
 * rendering 0%. A fraction of zero over zero is not "none of it is recent" —
 * it is "there is nothing to be recent", and under a recommendation to weaken
 * a detector those read very differently.
 */
export function TuningScreen({
  recommendations,
  incidents,
  weekStartMs,
}: TuningScreenProps): React.ReactElement {
  return (
    <section data-testid="perch-tuning" className="p-4">
      <h2 className="text-base font-medium">Tuning bench</h2>
      <p className="mt-1 text-xs text-muted-foreground">
        Recommendations the daemon computed. Nothing here changes a detector;
        applying one is a change to the ruleset, made outside this console.
      </p>

      {recommendations.length === 0 ? (
        <p data-testid="perch-tuning-empty" className="mt-3 text-sm">
          The daemon has recommended no changes. That is a statement about its
          measurements, not about whether the detectors are well tuned.
        </p>
      ) : (
        <ul className="mt-3 space-y-3">
          {recommendations.map((recommendation) => {
            const provenance = deriveTuningProvenance(
              recommendation,
              incidents,
              weekStartMs,
            );
            return (
              <li
                key={`${recommendation.kind}-${recommendation.strategy_id}-${recommendation.host_id ?? "all-hosts"}`}
                data-testid={`perch-tuning-${recommendation.strategy_id}`}
                data-origin={provenance.origin}
                className="rounded-md border border-border p-3"
              >
                <p className="text-sm">
                  <span className="font-mono">
                    {recommendation.strategy_id}
                  </span>
                  {" · "}
                  {recommendation.kind}
                  {" · "}
                  {recommendation.host_id ?? "every host"}
                </p>
                <p className="mt-1 text-xs text-muted-foreground">
                  {ORIGIN_LABEL[provenance.origin]}
                  {" · "}
                  {provenance.totalVerdicts === 0
                    ? "no operator verdicts stand behind this recommendation"
                    : `${provenance.thisWeekVerdicts} of ${provenance.totalVerdicts} operator verdicts are from this week`}{" "}
                  <DerivedMarker />
                </p>
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}
