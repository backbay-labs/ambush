/**
 * The detector coverage catalog: what the swarm deliberately does NOT see.
 *
 * Every gap here is declared by the engine's own evasion suite, with the
 * rationale its author wrote. Nothing is summarized or re-worded: the
 * catalog's prose says why a technique is out of reach, and a paraphrase would
 * be this console asserting a limit it did not measure.
 */

export type EvasionTechniqueGap = {
  technique: string;
  threat_class: string;
  rationale: string;
};

export type EvasionCoverageSnapshot = {
  generated_at_ms: number;
  suite_name: string;
  suite_path: string;
  corpus_version: string;
  detectors: {
    detector: string;
    intentionally_uncovered: EvasionTechniqueGap[];
  }[];
};

export type GapsGrouped = {
  detectors: { detector: string; gaps: EvasionTechniqueGap[] }[];
  /** DISTINCT techniques. Two detectors blind to one technique is one gap. */
  techniqueCount: number;
  /** Detectors that declare at least one gap. */
  detectorCount: number;
};

/**
 * Group the served snapshot by detector, optionally narrowed to one threat
 * class.
 *
 * A detector with nothing uncovered is not a row: an empty row would read as
 * "this detector has a gap we did not describe", which is the opposite of what
 * an empty list means.
 */
export function groupGaps(
  snapshot: EvasionCoverageSnapshot,
  threatClass?: string,
): GapsGrouped {
  const detectors = snapshot.detectors
    .map((detector) => ({
      detector: detector.detector,
      gaps: detector.intentionally_uncovered.filter((gap) =>
        threatClass ? gap.threat_class === threatClass : true,
      ),
    }))
    .filter((detector) => detector.gaps.length > 0);
  const techniques = new Set(
    detectors.flatMap((detector) => detector.gaps.map((gap) => gap.technique)),
  );
  return {
    detectors,
    techniqueCount: techniques.size,
    detectorCount: detectors.length,
  };
}
