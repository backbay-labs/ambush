import type {
  ConcentrationSample,
  DepositView,
  ThreatClassPolicy,
} from "./types";

/**
 * One deposit's strength at a moment.
 *
 * Mirrors `crates/swarm-core/src/pheromone.rs`. Before its own timestamp a
 * deposit is at full confidence rather than amplified: decay only subtracts,
 * and running the exponent backwards would invent strength the substrate never
 * had.
 */
export function strengthAt(
  deposit: Pick<DepositView, "confidence" | "timestamp" | "decay_half_life">,
  now: number,
): number {
  if (now <= deposit.timestamp) return deposit.confidence;
  return (
    deposit.confidence *
    0.5 ** ((now - deposit.timestamp) / deposit.decay_half_life)
  );
}

/**
 * The concentration a slice of deposits carries at `now`.
 *
 * The same reduction the substrate performs, in the same order, over a slice
 * B4 has already suppressed and evaporated. Deposits stamped after `now` are
 * excluded: a sample at t that included a deposit from t+1 would show the
 * console knowing something before it happened.
 */
export function concentrationAt(
  deposits: readonly DepositView[],
  now: number,
  policy: ThreatClassPolicy,
): {
  total_strength: number;
  distinct_sources: number;
  peak_confidence: number;
} {
  let total = 0;
  let peak = 0;
  const sources = new Set<string>();
  for (const deposit of deposits) {
    if (deposit.timestamp > now) continue;
    const strength = strengthAt(deposit, now);
    if (strength < policy.evaporation_threshold) continue;
    if (strength <= 0) continue;
    total += strength;
    peak = Math.max(peak, deposit.confidence);
    sources.add(deposit.agent_id);
  }
  return {
    total_strength: total,
    distinct_sources: sources.size,
    peak_confidence: peak,
  };
}

/**
 * The tolerance for "the served number and the derived number agree".
 *
 * One deposit's worth — the evaporation floor the daemon itself serves — never
 * a percentage of an unrelated dial. A percentage tolerance grows with the
 * number being checked, so it would hide exactly the disagreements that matter
 * most: the ones on a class with a lot of activity.
 */
export function snapshotEpsilon(
  policy: ThreatClassPolicy,
  served: number,
): number {
  return Math.max(policy.evaporation_threshold, 1e-9 * Math.abs(served));
}

/**
 * `>=`, not `>`: a deposit contributing exactly the evaporation floor is the
 * smallest real event the substrate admits, and a disagreement of exactly that
 * size is a whole missing deposit. It has to trip.
 */
export function snapshotDisagrees(
  derived: number,
  served: number,
  policy: ThreatClassPolicy,
): boolean {
  return Math.abs(served - derived) >= snapshotEpsilon(policy, served);
}

/**
 * Regime B: `S(t) = S(t0) · 2^(−(t − t0)/H)`.
 *
 * Exponential, never linear. A linear interpolation between two samples of a
 * decaying quantity always overstates the middle, and the middle is where an
 * operator reads a threshold crossing.
 */
export function interpolate(
  sample: ConcentrationSample,
  atSeconds: number,
  halfLifeSecs: number,
): number {
  return (
    sample.total_strength * 0.5 ** ((atSeconds - sample.at) / halfLifeSecs)
  );
}

/** The caption the forward segment must carry. It is an extrapolation. */
export function forwardSegmentNote(): string {
  return "forward segment is an extrapolation and a lower bound: decay only subtracts and a new deposit only adds — except after a suppression, which subtracts retroactively";
}
