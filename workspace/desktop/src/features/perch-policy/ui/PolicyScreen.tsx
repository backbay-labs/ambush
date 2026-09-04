import * as React from "react";

import { STANDARD_THREAT_CLASSES } from "@/features/perch/wire/types";

import {
  evaluateTripleLocally,
  SEVERITY_ORDER,
  type PolicyRule,
  type PolicySeverity,
} from "../lib/policyEvaluation";

export type PolicyScreenProps = {
  /** The rules the daemon serves, in the order it evaluates them. */
  rules: PolicyRule[];
};

const VERDICT_LABEL = {
  decides: "decides",
  not_matched: "not matched",
  not_reached: "not reached",
} as const;

/**
 * S7, `/policy`. Which rule decides a given triple, and what happened to the
 * rest.
 *
 * The screen asks for a triple before it says anything, because shadowing is a
 * property of a triple and not of a rule. A rule that decides
 * `execution/HIGH/isolate_host` may be the fourth rule not matched by
 * `impact/LOW/notify`, so a screen that labelled rules "shadowed" in general
 * would assert something true of no particular decision an operator will ever
 * make.
 *
 * `not matched` and `not reached` are kept apart for the same reason: the
 * first rule is a statement about this rule, the second is a statement about
 * an earlier one. Collapsing them into "inactive" loses which rule to edit.
 */
export function PolicyScreen({ rules }: PolicyScreenProps): React.ReactElement {
  const [threatClass, setThreatClass] = React.useState<string>(
    STANDARD_THREAT_CLASSES[0],
  );
  const [severity, setSeverity] = React.useState<PolicySeverity>("HIGH");
  const [action, setAction] = React.useState("isolate_host");

  const evaluation = React.useMemo(
    () =>
      evaluateTripleLocally(rules, {
        threat_class: threatClass,
        severity,
        action,
      }),
    [rules, threatClass, severity, action],
  );
  const decider = evaluation.find((row) => row.verdict === "decides") ?? null;

  return (
    <section data-testid="perch-policy" className="p-4">
      <h2 className="text-base font-medium">Policy</h2>
      <p className="mt-1 text-xs text-muted-foreground">
        Shadowing is a property of a triple, not of a rule. Name the triple and
        this shows which rule decides it.
      </p>

      <div className="mt-3 flex flex-wrap gap-2">
        <label className="text-xs">
          <span className="mr-1 text-muted-foreground">threat class</span>
          <select
            data-testid="perch-policy-threat-class"
            className="rounded border border-border px-1 py-0.5 text-xs"
            value={threatClass}
            onChange={(event) => setThreatClass(event.target.value)}
          >
            {STANDARD_THREAT_CLASSES.map((slug) => (
              <option key={slug} value={slug}>
                {slug}
              </option>
            ))}
          </select>
        </label>
        <label className="text-xs">
          <span className="mr-1 text-muted-foreground">severity</span>
          <select
            data-testid="perch-policy-severity"
            className="rounded border border-border px-1 py-0.5 text-xs"
            value={severity}
            onChange={(event) =>
              setSeverity(event.target.value as PolicySeverity)
            }
          >
            {SEVERITY_ORDER.map((value) => (
              <option key={value} value={value}>
                {value}
              </option>
            ))}
          </select>
        </label>
        <label className="text-xs">
          <span className="mr-1 text-muted-foreground">action</span>
          <input
            data-testid="perch-policy-action"
            className="rounded border border-border px-1 py-0.5 text-xs"
            value={action}
            onChange={(event) => setAction(event.target.value)}
          />
        </label>
      </div>

      <p data-testid="perch-policy-decider" className="mt-3 text-sm">
        {decider
          ? `Rule ${decider.index} (${decider.name}) decides this triple.`
          : "No rule matches this triple. The daemon's default applies, and this screen does not know what that is."}
      </p>

      <ol className="mt-2 space-y-1">
        {evaluation.map((row) => (
          <li
            key={row.index}
            data-testid={`perch-policy-rule-${row.index}`}
            data-verdict={row.verdict}
            className="text-xs"
          >
            <span className="font-mono">{`${row.index}. ${row.name}`}</span>
            {" · "}
            {VERDICT_LABEL[row.verdict]}
          </li>
        ))}
      </ol>

      <p className="mt-3 text-xs text-muted-foreground">
        This evaluation is the console's own, over the rules the daemon served.
        It is a reading of the policy, not the decision the daemon will make.
      </p>
    </section>
  );
}
