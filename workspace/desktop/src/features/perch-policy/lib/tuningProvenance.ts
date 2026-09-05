/**
 * Where a tuning recommendation's evidence came from, and how much of it is
 * recent.
 *
 * Both questions exist because a recommendation an operator acts on is only as
 * good as the verdicts behind it: one produced by the correlation engine and
 * one promoted by an analyst carry different weight, and a fraction computed
 * from no denominator is a number with no meaning.
 */
export type IncidentOrigin =
  | "analyst-promoted"
  | "correlation-produced"
  | "unresolved";

/**
 * A promote-to-case incident is minted under an id scheme that CANNOT collide
 * with the correlation engine's `incident:{hunt_id}:{created_at_ms}`.
 *
 * Anything matching neither scheme is `unresolved` rather than guessed. Naming
 * an origin the id does not support would be the console inventing provenance
 * for evidence it is asking an operator to trust.
 */
export function incidentOrigin(incident: {
  incident_id: string;
}): IncidentOrigin {
  const id = incident.incident_id;
  // The daemon mints a promoted case as `incident:perch-case:<case>`; the
  // bare `perch-case:` form is the plan's spelling and is kept for it.
  if (id.startsWith("incident:perch-case:") || id.startsWith("perch-case:")) {
    return "analyst-promoted";
  }
  if (id.startsWith("incident:")) return "correlation-produced";
  return "unresolved";
}

export type FalsePositiveMeasurement = {
  finding_id: string;
  strategy_id: string;
  reviewed_at_ms: number;
  false_positive: boolean;
};

export type TuningIncident = {
  incident_id: string;
  false_positive_measurements: FalsePositiveMeasurement[];
};

export type TuningRecommendation = {
  kind: string;
  strategy_id: string;
  host_id: string | null;
};

export type TuningProvenance = {
  origin: IncidentOrigin;
  totalVerdicts: number;
  thisWeekVerdicts: number;
  /** `null` when there is no denominator. Never zero, which is a measurement. */
  fractionThisWeek: number | null;
};

/**
 * The provenance behind one recommendation.
 *
 * `fractionThisWeek` is `null` with no verdicts at all — a fraction of zero
 * over zero is not "none of it is recent", it is "there is nothing to be
 * recent", and those read very differently under a recommendation to change a
 * detector.
 */
export function deriveTuningProvenance(
  recommendation: TuningRecommendation,
  incidents: readonly TuningIncident[],
  weekStartMs: number,
): TuningProvenance {
  const measurements = incidents.flatMap((incident) =>
    incident.false_positive_measurements.filter(
      (measurement) => measurement.strategy_id === recommendation.strategy_id,
    ),
  );
  const total = measurements.length;
  const thisWeek = measurements.filter(
    (measurement) => measurement.reviewed_at_ms >= weekStartMs,
  ).length;
  const origin =
    incidents.length > 0 ? incidentOrigin(incidents[0]) : "unresolved";
  return {
    origin,
    totalVerdicts: total,
    thisWeekVerdicts: thisWeek,
    fractionThisWeek: total === 0 ? null : thisWeek / total,
  };
}

/**
 * The measurements the daemon persisted on an incident, as the provenance
 * reads them. Only Dismiss is a false positive; Confirm and Investigate count
 * toward the denominator and not the numerator.
 */
export function tuningIncidentFrom(read: {
  incident_id: string;
  false_positive_measurements: readonly Record<string, unknown>[];
}): TuningIncident {
  return {
    incident_id: read.incident_id,
    false_positive_measurements: read.false_positive_measurements.flatMap(
      (measurement) => {
        const findingId = measurement.finding_id;
        const strategyId = measurement.strategy_id;
        const reviewedAt = measurement.reviewed_at_ms;
        if (
          typeof findingId !== "string" ||
          typeof strategyId !== "string" ||
          typeof reviewedAt !== "number"
        ) {
          return [];
        }
        return [
          {
            finding_id: findingId,
            strategy_id: strategyId,
            reviewed_at_ms: reviewedAt,
            false_positive: measurement.action === "dismiss",
          },
        ];
      },
    ),
  };
}
