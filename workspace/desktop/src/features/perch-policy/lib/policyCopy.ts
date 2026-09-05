/**
 * Copy for `/policy`. Every sentence says what the daemon did or will do; none
 * of them offers to change it, because the profile is pinned inside a signed
 * attestation and an edit here would produce a config the runtime refuses.
 */
export const POLICY = {
  title: "Policy",
  readOnly:
    "Read-only. {path} is sha256-pinned inside a signed attestation whose key is not in this repository; an edit here would produce a config the runtime refuses to start on.",
  unattested:
    "Read-only. {path} has no attestation sibling on this daemon; the runtime still decides with it, and this screen still does not edit it.",
  header:
    "policy.human_gate_severity = {humanGateSeverity} · policy.lease_ttl_ms = {leaseTtlMs} (the capability lease's authorization window, not the containment lease's TTL) · {scopeLimit} actions per scope per minute",
  evaluate: "EVALUATE AGAINST",
  verdicts: {
    decides: "DECIDES THIS TRIPLE",
    not_matched: "not matched",
    not_reached: "not reached",
  },
  decider: "Rule {index} ({name}) decides this triple.",
  outranks:
    "THIS RULE OUTRANKS THE HUMAN GATE. {action} is destructive and human_gate_severity is {humanGateSeverity}, but this rule matches first and allows it outright at {severity}.",
  fallthrough:
    "No rule matched → the static gate: {verdict} ({reason}). The static gate holds any of the twelve destructive actions at {humanGateSeverity} or above for a human and allows the rest.",
  unknownAction:
    "{action} is not an action kind the daemon knows; nothing was evaluated.",
  daemonPending: "Asking the daemon…",
  daemonUnavailable:
    "The daemon did not answer; the verdicts shown are this console's own reading of the rules it last served, not a decision.",
  requestCarried:
    "threat_class and severity are supplied by the requesting agent, not measured here: the evaluation reads what a request would say.",
  noRules: {
    title: "policy.rules is empty",
    body: "Every request falls through to the static gate, which holds any of the twelve destructive actions at {humanGateSeverity} or above for a human and allows the rest.",
  },
  noPolicy: "The daemon has not served its policy yet.",
} as const;

/** `{name}` placeholders, filled from a record; unknown names are left as-is. */
export function fill(
  template: string,
  values: Record<string, string | number>,
): string {
  return template.replace(/\{(\w+)\}/g, (whole, name: string) =>
    name in values ? String(values[name]) : whole,
  );
}
