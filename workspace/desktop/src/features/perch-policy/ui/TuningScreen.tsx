import { Link } from "@tanstack/react-router";
import type * as React from "react";

import type { PerchOperatorStatus } from "@/shared/api/tauriPerch";

import { fillTuning, TUNING } from "../lib/tuningCopy";
import { TuningRecommendationCard } from "./TuningRecommendationCard";

export type TuningScreenProps = {
  /** The daemon's runtime status; null until it has answered. */
  status: PerchOperatorStatus | null;
};

/**
 * S10, `/tuning`. What the daemon suggests changing, and on whose evidence.
 *
 * Every card carries the daemon's own counts with their denominators. The
 * one thing this surface does not say is how many of those verdicts are from
 * this week: the status read carries counts, not verdict timestamps, and a
 * fraction computed from nothing would be a measurement that never happened.
 */
export function TuningScreen({
  status,
}: TuningScreenProps): React.ReactElement {
  const report = status?.alert_tuning ?? null;
  return (
    <section data-testid="perch-tuning-screen" className="p-4">
      <h2 className="text-base font-medium">{TUNING.title}</h2>
      <p className="mt-1 text-xs text-muted-foreground">{TUNING.subtitle}</p>
      {report === null ? (
        <p data-testid="perch-tuning-no-status" className="mt-3 text-sm">
          {TUNING.noStatus}
        </p>
      ) : report.recommendations.length === 0 ? (
        <div data-testid="perch-tuning-empty" className="mt-3 text-sm">
          <p className="font-medium">{TUNING.none.title}</p>
          <p className="mt-1 text-xs text-muted-foreground">
            {fillTuning(TUNING.none.body, {
              reviewed: report.reviewed_findings,
              fp: report.false_positive_findings,
            })}
          </p>
          <Link
            to={TUNING.none.action.href}
            data-testid="perch-tuning-open-watch"
            className="mt-2 inline-block text-xs underline"
          >
            {TUNING.none.action.label}
          </Link>
        </div>
      ) : (
        <>
          <p
            data-testid="perch-tuning-report"
            className="mt-3 font-mono text-xs text-muted-foreground"
          >
            {`${report.false_positive_findings} of ${report.reviewed_findings} reviewed findings were false positives · ${report.recommendation_count} recommendation${report.recommendation_count === 1 ? "" : "s"} · ${TUNING.cap}`}
          </p>
          <ul className="mt-3 space-y-3">
            {report.recommendations.map((recommendation, index) => (
              <TuningRecommendationCard
                key={`${recommendation.kind}-${recommendation.strategy_id ?? ""}-${recommendation.host_id ?? ""}`}
                index={index}
                recommendation={recommendation}
              />
            ))}
          </ul>
        </>
      )}
      <p className="mt-3 text-2xs text-muted-foreground">{TUNING.c9Restated}</p>
    </section>
  );
}
