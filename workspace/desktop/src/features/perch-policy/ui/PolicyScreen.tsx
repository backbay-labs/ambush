import { useQuery } from "@tanstack/react-query";
import * as React from "react";

import { STANDARD_THREAT_CLASSES } from "@/features/perch/wire/types";
import { perchKeys } from "@/shared/api/perchKeys";
import {
  type PerchPolicyResponse,
  type PerchPolicyRuleVerdict,
  perchPolicy,
} from "@/shared/api/tauriPerch";

import { fill, POLICY } from "../lib/policyCopy";
import {
  evaluateTripleLocally,
  SEVERITY_ORDER,
  type PolicyRule,
  type PolicySeverity,
} from "../lib/policyEvaluation";

export type PolicyScreenProps = {
  /** The daemon's policy as `/v1/operator/policy` serves it; null until it has. */
  policy: PerchPolicyResponse | null;
};

/** The fifteen `ResponseAction` kinds, as the daemon spells them. */
const ACTION_KINDS = [
  "block_egress",
  "isolate_host",
  "revoke_credential",
  "sinkhole_dns",
  "terminate_user_session",
  "trigger_edr_scan",
  "inject_firewall_rule",
  "quarantine_file",
  "kill_process",
  "suspend_process",
  "disable_user_account",
  "force_password_reset",
  "remove_scheduled_task",
  "deploy_decoy",
  "escalate",
] as const;

/**
 * S7, `/policy`. Which rule decides a given triple, and what happened to the
 * rest — as the DAEMON evaluates it.
 *
 * The screen asks for a triple before it says anything, because shadowing is a
 * property of a triple and not of a rule. A rule that decides
 * `execution/HIGH/isolate_host` may be the fourth rule not matched by
 * `impact/LOW/notify`, so a screen that labelled rules "shadowed" in general
 * would assert something true of no particular decision an operator will ever
 * make.
 *
 * Two evaluations are on the screen. The console's own mirror renders at
 * once, over the rules the daemon served, so a triple change is never a blank
 * row; the daemon's evaluation replaces it when it arrives and is the one the
 * verdict words and the outranks sentence are taken from. When the daemon does
 * not answer, the mirror stays and says it is a reading, not a decision.
 */
export function PolicyScreen({
  policy,
}: PolicyScreenProps): React.ReactElement {
  const [threatClass, setThreatClass] = React.useState<string>(
    "command_and_control",
  );
  const [severity, setSeverity] = React.useState<PolicySeverity>("CRITICAL");
  const [action, setAction] = React.useState<string>("block_egress");
  const rules: PolicyRule[] = React.useMemo(
    () =>
      (policy?.rules ?? []).map((rule) => ({
        index: rule.index,
        name: rule.name,
        decision: rule.decision,
        threat_class: rule.threat_class,
        actions: [...rule.actions],
        min_severity: rule.min_severity as PolicySeverity,
        max_severity: rule.max_severity as PolicySeverity,
      })),
    [policy],
  );
  const tripleKey = `${threatClass}/${severity}/${action}`;
  const daemon = useQuery<PerchPolicyResponse>({
    queryKey: perchKeys.policy(tripleKey),
    queryFn: () => perchPolicy({ threatClass, severity, action }),
    enabled: policy !== null,
    staleTime: 60_000,
  });
  const local = React.useMemo(
    () =>
      evaluateTripleLocally(rules, {
        threat_class: threatClass,
        severity,
        action,
      }),
    [rules, threatClass, severity, action],
  );
  const evaluation = daemon.data?.evaluation ?? null;
  const verdictOf = (index: number): PerchPolicyRuleVerdict | null =>
    evaluation
      ? (evaluation.verdicts.find((v) => v.rule_index === index)?.verdict ??
        null)
      : (local.find((row) => row.index === index)?.verdict ?? null);
  const deciderIndex = rules.find(
    (rule) => verdictOf(rule.index) === "decides",
  )?.index;
  const decider =
    deciderIndex === undefined
      ? null
      : (rules.find((rule) => rule.index === deciderIndex) ?? null);
  const humanGateSeverity = policy?.human_gate_severity ?? "?";

  return (
    <section data-testid="perch-policy" className="p-4">
      <h2 className="text-base font-medium">{POLICY.title}</h2>
      {policy === null ? (
        <p data-testid="perch-policy-empty" className="mt-1 text-xs">
          {POLICY.noPolicy}
        </p>
      ) : (
        <>
          <p
            data-testid="perch-policy-source"
            className="mt-1 text-xs text-muted-foreground"
          >
            {fill(
              policy.source.attested ? POLICY.readOnly : POLICY.unattested,
              {
                path: policy.source.path,
              },
            )}
          </p>
          <p
            data-testid="perch-policy-header"
            className="mt-1 font-mono text-2xs text-muted-foreground"
          >
            {fill(POLICY.header, {
              humanGateSeverity: policy.human_gate_severity,
              leaseTtlMs: policy.lease_ttl_ms,
              scopeLimit: policy.max_actions_per_scope_per_minute,
            })}
          </p>
        </>
      )}
      <p className="mt-3 text-2xs tracking-wide text-muted-foreground">
        {POLICY.evaluate}
      </p>
      <div className="mt-1 flex flex-wrap gap-2">
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
          <select
            data-testid="perch-policy-action"
            className="rounded border border-border px-1 py-0.5 text-xs"
            value={action}
            onChange={(event) => setAction(event.target.value)}
          >
            {ACTION_KINDS.map((kind) => (
              <option key={kind} value={kind}>
                {kind}
              </option>
            ))}
          </select>
        </label>
      </div>
      {policy !== null && rules.length === 0 ? (
        <p data-testid="perch-policy-no-rules" className="mt-3 text-sm">
          <span className="font-medium">{POLICY.noRules.title}</span>{" "}
          {fill(POLICY.noRules.body, { humanGateSeverity })}
        </p>
      ) : null}
      <p
        data-testid="perch-policy-decider"
        data-source={evaluation ? "daemon" : "console"}
        className="mt-3 text-sm"
      >
        {decider
          ? fill(POLICY.decider, { index: decider.index, name: decider.name })
          : evaluation?.fallthrough
            ? fill(POLICY.fallthrough, {
                verdict: evaluation.fallthrough.verdict,
                reason: evaluation.fallthrough.reason,
                humanGateSeverity,
              })
            : evaluation && evaluation.verdicts.length === 0
              ? fill(POLICY.unknownAction, { action })
              : "No rule matches this triple; the daemon's own answer follows when it arrives."}
      </p>
      {evaluation?.outranks_human_gate ? (
        <p
          data-testid="perch-policy-outranks"
          className="mt-2 rounded border border-border p-2 text-sm"
        >
          {fill(POLICY.outranks, { action, humanGateSeverity, severity })}
        </p>
      ) : null}
      <ol className="mt-2 space-y-1">
        {rules.map((rule) => {
          const verdict = verdictOf(rule.index);
          return (
            <li
              key={rule.index}
              data-testid={`perch-policy-rule-${rule.index}`}
              data-verdict={verdict ?? "unknown"}
              className="text-xs"
            >
              <span className="font-mono">{`${rule.index}. ${rule.name}`}</span>
              {" · "}
              <code>{rule.decision}</code>
              {" · "}
              {verdict ? POLICY.verdicts[verdict] : "—"}
            </li>
          );
        })}
      </ol>
      <p
        data-testid="perch-policy-standing"
        className="mt-3 text-xs text-muted-foreground"
      >
        {daemon.isPending && policy !== null
          ? POLICY.daemonPending
          : daemon.isError
            ? POLICY.daemonUnavailable
            : POLICY.requestCarried}
      </p>
    </section>
  );
}
