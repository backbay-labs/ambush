// The Verdict Row's five slots, built from one hold.
//
// The slot SET never varies. Every hold gets all five, in the same order,
// whether or not the daemon had anything to put in one — because a pane that
// can omit a slot is a pane that can omit BLAST RADIUS on the request where it
// mattered, and nothing in the rendering would look wrong. An empty slot
// therefore carries ABSENCE COPY that says which absence it is: a runtime that
// derived no rehearsal and a runtime that could not are different facts.
//
// Provenance is carried per line, because the five slots mix three kinds of
// claim and an operator deciding under time pressure needs to know which is
// which:
//   request-carried  the REQUESTING AGENT said it. `severity` and
//                    `threat_class` are set by the caller and read back by the
//                    approval gate, so a compromised agent chooses its own
//                    review path. That is the single most useful thing on the
//                    pane and it must never look like the runtime's finding.
//   runtime          the daemon derived it from its own state.
//   derived          this console derived it from the daemon's answer.

import type {
  PerchHeldActionView,
  PerchThreatClass,
} from "@/shared/api/tauriPerch";

/** Fixed render order. `VerdictPane` maps this; there is no branch that skips one. */
export const VERDICT_SLOT_ORDER = [
  "action",
  "blast-radius",
  "if-you-undo",
  "why-we-are-asking",
  "what-granting-opens",
] as const;

/** One of the five slot ids. */
export type VerdictSlotId = (typeof VERDICT_SLOT_ORDER)[number];

/**
 * The eyebrow above each slot.
 *
 * "WHAT GRANTING OPENS" rather than "lease": the capability lease and the
 * containment lease are different objects with different lifetimes, and one
 * bare word for both is how a 60-second grant gets read as a 15-minute one.
 */
export const VERDICT_SLOT_LABELS: Record<VerdictSlotId, string> = {
  action: "ACTION",
  "blast-radius": "BLAST RADIUS",
  "if-you-undo": "IF YOU UNDO",
  "why-we-are-asking": "WHY WE ARE ASKING",
  "what-granting-opens": "WHAT GRANTING OPENS",
};

/** Where a line's claim came from. Rendered, not just recorded. */
export type VerdictLineProvenance = "request-carried" | "runtime" | "derived";

/** One line of a slot. `adversary` routes the value through `AdversaryString`. */
export type VerdictLine = {
  label: string | null;
  value: string;
  adversary: boolean;
  provenance?: VerdictLineProvenance;
};

/** A slot either has lines or states its absence. There is no third case. */
export type VerdictSlotContent =
  | { kind: "present"; lines: readonly VerdictLine[] }
  | { kind: "absent"; copy: string };

/** The two lease TTLs, passed in so the pane never guesses a duration. */
export type VerdictLeaseTtls = {
  capabilityLeaseTtlMs: number;
  containmentLeaseTtlMs: number;
};

/** Above this, a duration reads in minutes; at or below it, in seconds. */
const MINUTES_ABOVE_MS = 5 * 60_000;

/**
 * A duration in the unit that keeps the two leases visibly different.
 *
 * The capability lease is 60 s and the containment lease is 15 min. Rounding
 * the first to "1 min" would put them in the same unit and the same order of
 * magnitude on adjacent lines, which is precisely the confusion the two-lease
 * distinction exists to prevent — so anything at or below five minutes reads
 * in seconds.
 */
function formatMs(ms: number): string {
  return ms > MINUTES_ABOVE_MS
    ? `${Math.round(ms / 60_000)} min`
    : `${Math.round(ms / 1000)} s`;
}

/**
 * A threat class as one string.
 *
 * The Rust enum's custom arm serialises as `{ custom: "…" }`, so a consumer
 * that assumed `string` would render `[object Object]` on exactly the threat
 * class nobody has seen before — the one most worth reading.
 */
function threatClassLabel(value: PerchThreatClass): string {
  return typeof value === "string" ? value : value.custom;
}

function actionFieldValue(value: unknown): string {
  if (value === null || value === undefined) return "—";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

/**
 * Build the five slots for one hold.
 *
 * Pure, and takes the lease TTLs rather than reading config, so the fifteen
 * action kinds can be checked as a table.
 */
export function buildVerdictSlots(
  hold: PerchHeldActionView,
  leaseTtls: VerdictLeaseTtls,
): Record<VerdictSlotId, VerdictSlotContent> {
  const { type, ...fields } = hold.action_request.action;

  const action: VerdictSlotContent = {
    kind: "present",
    lines: [
      { label: null, value: type, adversary: false },
      ...Object.entries(fields).map(([label, value]) => ({
        label,
        value: actionFieldValue(value),
        // Every typed field came off the wire from a process this console does
        // not control. A host id that renders as a different host id is the
        // one lie this pane must not be able to tell.
        adversary: true,
      })),
    ],
  };

  const radius = hold.rehearsal?.blast_radius;
  const blastRadius: VerdictSlotContent = radius
    ? {
        kind: "present",
        lines: [
          {
            label: "impact",
            value: radius.impact,
            adversary: false,
            provenance: "runtime",
          },
          {
            label: "scope",
            value: `${radius.scope_kind}: ${radius.scope_value}`,
            adversary: true,
            provenance: "runtime",
          },
          {
            label: "max affected scopes",
            value: String(radius.max_affected_scopes),
            adversary: false,
            provenance: "runtime",
          },
          {
            label: "capabilities",
            value: radius.affected_capabilities.join(", ") || "—",
            adversary: false,
            provenance: "runtime",
          },
          {
            label: null,
            value: "served by the runtime's rehearsal preview",
            adversary: false,
            provenance: "runtime",
          },
        ],
      }
    : {
        kind: "absent",
        copy: "NO REHEARSAL — the runtime did not derive a blast radius for this request",
      };

  const ifYouUndo: VerdictSlotContent =
    hold.inverse_resolution.length > 0
      ? {
          kind: "present",
          lines: hold.inverse_resolution.map((step) => ({
            label: step.step_kind,
            value:
              step.verdict === "executable"
                ? "executable inverse"
                : step.verdict === "irreversible"
                  ? `irreversible — ${step.reason ?? "the forward action states the effect cannot be undone"}`
                  : "unmapped — no inverse is defined for this step",
            adversary: false,
            provenance: "derived",
          })),
        }
      : {
          kind: "absent",
          copy: hold.leases_a_containment
            ? "no rollback plan was derived for this containment"
            : "no executable inverse — this action is not a containment and has no inverse plan",
        };

  const whyWeAreAsking: VerdictSlotContent = {
    kind: "present",
    lines: [
      {
        label: "rule",
        value: hold.rationale.rule_name,
        adversary: false,
        provenance: "runtime",
      },
      {
        label: "reason",
        value: hold.rationale.reason,
        adversary: true,
        provenance: "runtime",
      },
      {
        label: "threat_class",
        value: threatClassLabel(hold.rationale.threat_class),
        adversary: false,
        provenance: "request-carried",
      },
      {
        label: "severity",
        value: hold.rationale.severity,
        adversary: false,
        provenance: "request-carried",
      },
      {
        label: null,
        value: hold.rationale.governance_receipt_present
          ? "a governance receipt was present at hold time; a decide re-runs the governance gate, and nothing checks that a receipt's signer is a governor"
          : "no governance receipt was present at hold time; a decide re-runs the governance gate from scratch",
        adversary: false,
        provenance: "runtime",
      },
    ],
  };

  const opens: VerdictLine[] = [
    {
      label: "capability lease",
      // W2-15: minted from the store's compare-and-set instant, never from
      // hold time and never from the body's `decided_at_ms`. Saying "not now"
      // is the difference between a usable window and a guess about one.
      value: `minted at your decision, not now · ${formatMs(leaseTtls.capabilityLeaseTtlMs)}`,
      adversary: false,
      provenance: "runtime",
    },
  ];
  if (hold.leases_a_containment) {
    opens.push({
      label: "containment lease",
      value: `then a containment lease on the lease board · ${formatMs(leaseTtls.containmentLeaseTtlMs)}`,
      adversary: false,
      provenance: "runtime",
    });
  }

  return {
    action,
    "blast-radius": blastRadius,
    "if-you-undo": ifYouUndo,
    "why-we-are-asking": whyWeAreAsking,
    "what-granting-opens": { kind: "present", lines: opens },
  };
}
