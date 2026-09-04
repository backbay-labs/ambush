/**
 * The types every Perch chart shares.
 *
 * `VizState` has four arms and none of them is a bool. "No data" and "the
 * source is unreachable" and "the source answered with nothing" are three
 * different facts, and a chart that renders all three as an empty plot tells
 * an operator the world is quiet when the console simply cannot see it.
 */
export type EmptyReason =
  /** The source answered, and its answer was empty. */
  | "served-empty"
  /** Nothing has been deposited in this window. */
  | "no-deposits"
  /** This case was promoted by hand, so correlation produced no graph. */
  | "hand-promoted";

export type DegradedDetail = {
  /** What the console could not read. Never a generic "error". */
  what: string;
  /** What is still true about the numbers shown. */
  stillShown: string;
};

export type VizState =
  | { kind: "loading" }
  | { kind: "ready" }
  | { kind: "empty"; reason: EmptyReason }
  | { kind: "degraded"; detail: DegradedDetail };

/** One threat class's thresholds, as the daemon serves them. */
export type ThreatClassPolicy = {
  half_life_secs: number;
  evaporation_threshold: number;
  min_sources_for_escalation: number;
  alert_threshold: number;
  incident_threshold: number;
};

/**
 * Where a count of sources came from.
 *
 * The `ids` arm carries the ids, so both a source count and an agent count can
 * be derived from one list. The `count` arm is what a frame that carries only
 * `distinct_sources` can honestly claim — and it must say the agent count is
 * not carried rather than reusing the source count for both.
 */
export type SourceAttribution =
  | { kind: "ids"; sourceIds: readonly string[] }
  | { kind: "count"; distinctSources: number };

/** One deposit, as B4 serves it: post-suppression, post-evaporation. */
export type DepositView = {
  agent_id: string;
  strategy_id: string;
  threat_class: string;
  severity: string;
  confidence: number;
  timestamp: number;
  decay_half_life: number;
  indicator: Readonly<Record<string, unknown>>;
  event_id: string;
};

/** A suppression, which subtracts RETROACTIVELY — the one non-monotone event. */
export type SuppressionMarker = {
  at: number;
  reason: string;
};

export type ConcentrationSample = {
  at: number;
  total_strength: number;
  distinct_sources: number;
  peak_confidence: number;
};
