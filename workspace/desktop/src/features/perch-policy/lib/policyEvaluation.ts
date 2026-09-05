/**
 * A DISPLAY MIRROR of the daemon's rule evaluation.
 *
 * The daemon is authoritative. This exists so the evaluator stays responsive
 * while its answer is in flight, and the screen marks the mirror as derived
 * for exactly as long as it is showing. If the two ever disagree, the screen
 * says so rather than picking one: a policy view that silently preferred the
 * local answer would be telling an operator what this console thinks the rules
 * are, not what the runtime will do.
 */

/** Ascending. Comparison is by index, never by string. */
export const SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"] as const;

export type PolicySeverity = (typeof SEVERITY_ORDER)[number];

export type PolicyRule = {
  index: number;
  name: string;
  decision: string;
  threat_class: string;
  actions: string[];
  min_severity: PolicySeverity;
  max_severity: PolicySeverity;
};

export type PolicyTriple = {
  threat_class: string;
  severity: PolicySeverity;
  action: string;
};

export type PolicyRuleVerdict = "decides" | "not_matched" | "not_reached";

export type PolicyRuleEvaluation = {
  index: number;
  name: string;
  verdict: PolicyRuleVerdict;
};

function severityRank(severity: string): number {
  return SEVERITY_ORDER.indexOf(severity as PolicySeverity);
}

function matches(rule: PolicyRule, triple: PolicyTriple): boolean {
  if (rule.threat_class !== triple.threat_class) return false;
  const rank = severityRank(triple.severity);
  if (rank < 0) return false;
  if (rank < severityRank(rule.min_severity)) return false;
  if (rank > severityRank(rule.max_severity)) return false;
  // An empty action list is a wildcard, not an empty set: a rule that named no
  // action would otherwise match nothing and could never decide.
  return rule.actions.length === 0 || rule.actions.includes(triple.action);
}

/**
 * Which rule decides this triple, and what happened to the others.
 *
 * Shadowing is PER TRIPLE and never static. The same rule decides one triple
 * and is not matched by another, so a screen that marked a rule "shadowed" in
 * general would be asserting something that is not true of any particular
 * decision.
 */
export function evaluateTripleLocally(
  rules: readonly PolicyRule[],
  triple: PolicyTriple,
): PolicyRuleEvaluation[] {
  let decided = false;
  return rules.map((rule) => {
    if (decided) {
      return { index: rule.index, name: rule.name, verdict: "not_reached" };
    }
    if (matches(rule, triple)) {
      decided = true;
      return { index: rule.index, name: rule.name, verdict: "decides" };
    }
    return { index: rule.index, name: rule.name, verdict: "not_matched" };
  });
}
