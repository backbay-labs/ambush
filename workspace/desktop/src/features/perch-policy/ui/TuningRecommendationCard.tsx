import { Link } from "@tanstack/react-router";
import type * as React from "react";

import type { PerchAlertTuningRecommendation } from "@/shared/api/tauriPerch";
import { AdversaryString } from "@/shared/ui/perch/AdversaryString";
import { DerivedMarker } from "@/shared/viz/markers";

import { fillTuning, TUNING } from "../lib/tuningCopy";

type TuningRecommendationCardProps = {
  index: number;
  recommendation: PerchAlertTuningRecommendation;
};

/**
 * One recommendation, every field the daemon carries. The words in it —
 * summary, next step, host, signals — came off the wire from a detector's
 * evidence, so they render through the adversary rail; the numbers render
 * with their denominators, because `0.67` alone is not a measurement.
 *
 * No Apply, disabled or otherwise: the next step is a signed config diff.
 */
export function TuningRecommendationCard({
  index,
  recommendation,
}: TuningRecommendationCardProps): React.ReactElement {
  const kind = TUNING.kinds[recommendation.kind] ?? {
    label: recommendation.kind,
    minimum: "",
  };
  const strategyId = recommendation.strategy_id ?? null;
  const hostId = recommendation.host_id ?? null;
  const query = [
    strategyId ? `agent:${strategyId}` : null,
    recommendation.kind === "host_exclusion_review" && hostId
      ? `host:${hostId}`
      : null,
  ]
    .filter((part): part is string => part !== null)
    .join(" ");
  return (
    <li
      data-testid={`perch-tuning-card-${index}`}
      data-kind={recommendation.kind}
      data-priority={recommendation.priority}
      className="rounded-md border border-border p-3"
    >
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-sm font-medium">{kind.label}</span>
        <span
          data-testid={`perch-tuning-priority-${index}`}
          className="rounded border border-border px-1 text-2xs uppercase tracking-wide"
        >
          {recommendation.priority}
        </span>
        {strategyId ? (
          <span className="font-mono text-xs">{strategyId}</span>
        ) : null}
        {hostId ? (
          <AdversaryString value={hostId} field="host_id" className="text-xs" />
        ) : null}
      </div>
      <p className="mt-2 text-sm">
        <AdversaryString value={recommendation.summary} field="summary" />
      </p>
      <p className="mt-1 text-sm">
        <span className="text-muted-foreground">next step: </span>
        <AdversaryString value={recommendation.next_step} field="next_step" />
      </p>
      <p
        data-testid={`perch-tuning-basis-${index}`}
        className="mt-2 font-mono text-xs"
        title={TUNING.basisLabel}
      >
        {fillTuning(TUNING.basis, {
          fp: recommendation.false_positive_findings,
          reviewed: recommendation.reviewed_findings,
          rate: recommendation.false_positive_rate.toFixed(2),
        })}{" "}
        <DerivedMarker />
      </p>
      {recommendation.supporting_signals.length > 0 ? (
        <ul
          data-testid={`perch-tuning-signals-${index}`}
          className="mt-1 list-disc pl-5 text-xs"
        >
          {recommendation.supporting_signals.map((signal) => (
            <li key={signal}>
              <AdversaryString value={signal} field="supporting_signal" />
            </li>
          ))}
        </ul>
      ) : null}
      <p className="mt-2 text-2xs text-muted-foreground">
        {TUNING.timestampsNotServed}
      </p>
      {query ? (
        <Link
          to="/ledger"
          search={{ q: query }}
          data-testid={`perch-tuning-ledger-${index}`}
          className="mt-2 inline-block text-xs underline"
        >
          {TUNING.linkVerdicts}
        </Link>
      ) : null}
    </li>
  );
}
