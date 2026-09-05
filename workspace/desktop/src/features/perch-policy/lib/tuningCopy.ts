/**
 * Copy for `/tuning`. Every number carries its denominator, and nothing here
 * offers to apply a recommendation: the next step after one is a config diff
 * a human signs, made outside this console.
 */
export const TUNING = {
  title: "Tuning bench",
  subtitle:
    "What the verdicts changed. The next step after a recommendation is a config diff a human signs; this surface stops at the recommendation and what it came from.",
  kinds: {
    host_exclusion_review: {
      label: "Host exclusion review",
      minimum:
        "needs 2 reviewed findings and 2 false positives on one host (rate ≥ 0.75)",
    },
    detector_threshold_review: {
      label: "Detector threshold review",
      minimum:
        "needs 4 reviewed findings and 2 false positives on one detector (rate ≥ 0.50)",
    },
    detector_rule_review: {
      label: "Detector rule review",
      minimum:
        "needs 3 reviewed findings and 2 false positives on one detector (rate ≥ 0.34)",
    },
  },
  cap: "capped at 6 recommendations",
  basis: "{fp} of {reviewed} · {rate}",
  basisLabel: "false positives of reviewed findings · rate",
  timestampsNotServed:
    "The daemon's status read carries counts, not verdict timestamps; how many of these verdicts are from this week is not computed here.",
  linkVerdicts: "See the verdicts in the Ledger",
  none: {
    title: "No recommendations yet",
    body: "A detector-rule review needs 3 reviewed findings and 2 false positives on one detector; a threshold review needs 4 and 2; a host exclusion needs 2 and 2 on one host. You have recorded {reviewed} reviewed, {fp} false positive. Confirm, Dismiss and Investigate all count toward the denominator; only Dismiss counts as a false positive.",
    action: { label: "Open the watch", href: "/" },
  },
  c9Restated: "These three numbers are owned by The Watch and restated here.",
  noStatus: "The daemon has not answered its status read yet.",
} as const;

/** `{name}` placeholders, filled from a record; unknown names are left as-is. */
export function fillTuning(
  template: string,
  values: Record<string, string | number>,
): string {
  return template.replace(/\{(\w+)\}/g, (whole, name: string) =>
    name in values ? String(values[name]) : whole,
  );
}
