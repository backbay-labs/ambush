import * as React from "react";

import { acquireEscapeSurface } from "@/shared/hooks/escapeSurfaces";
import type { PerchHeldActionView } from "@/shared/api/tauriPerch";
import { AdversaryString } from "@/shared/ui/perch/AdversaryString";
import { EyebrowLabel } from "@/shared/ui/perch/EyebrowLabel";
import { HoldTtlClock } from "@/shared/ui/perch/HoldTtlClock";
import {
  DecisionStateRow,
  type DecisionWriteState,
} from "@/shared/ui/perch/DecisionStateRow";

import {
  buildVerdictSlots,
  VERDICT_SLOT_LABELS,
  VERDICT_SLOT_ORDER,
} from "../lib/verdictSlots";
import { VerdictSlot } from "./VerdictSlot";

/**
 * The Verdict Row: everything an operator needs to answer one held action.
 *
 * Five slots, always all five, always in the same order. The order is the
 * argument: what is being asked for, what it reaches, whether it can be
 * undone, why a human is in the loop at all, and what saying yes opens. A
 * pane that reordered itself per action kind would make the operator re-learn
 * where the blast radius is on every row.
 *
 * The pane never decides anything. It renders the daemon's record and hands
 * the decision to whatever `actionBar` the caller supplies; there is no code
 * path here that reaches a daemon.
 */
export type VerdictPaneProps = {
  hold: PerchHeldActionView;
  writeState: DecisionWriteState;
  /** `policy.lease_ttl_ms`, from config. Never guessed here. */
  capabilityLeaseTtlMs?: number;
  /** `runtime.containment.lease_ttl_ms`, from config. */
  containmentLeaseTtlMs?: number;
  /**
   * The grant and refuse controls. Receives the BLAST RADIUS sentinel so the
   * grant control can observe it — the dwell gate's mechanism lives with the
   * control it gates, not with the block it watches.
   */
  actionBar?: (blastRadiusEl: HTMLElement | null) => React.ReactNode;
};

/** `policy.lease_ttl_ms` default (W2-15). */
const DEFAULT_CAPABILITY_LEASE_TTL_MS = 60_000;
/** `runtime.containment.lease_ttl_ms` default. A DIFFERENT object. */
const DEFAULT_CONTAINMENT_LEASE_TTL_MS = 900_000;

export function VerdictPane({
  hold,
  writeState,
  capabilityLeaseTtlMs = DEFAULT_CAPABILITY_LEASE_TTL_MS,
  containmentLeaseTtlMs = DEFAULT_CONTAINMENT_LEASE_TTL_MS,
  actionBar,
}: VerdictPaneProps) {
  const paneRef = React.useRef<HTMLElement | null>(null);
  const [blastRadiusEl, setBlastRadiusEl] = React.useState<HTMLElement | null>(
    null,
  );
  const [legendOpen, setLegendOpen] = React.useState(false);

  // Escape closes THIS pane, not the channel behind it. Without the surface
  // lease, the app-level mark-as-read shortcut wins the key because it
  // registered first.
  React.useEffect(() => acquireEscapeSurface(), []);

  // A new hold is a new question. Focus moves so the keymap's next keypress
  // cannot land on the row the operator just left.
  // biome-ignore lint/correctness/useExhaustiveDependencies: hold_id is the identity that must move focus, not the object.
  React.useEffect(() => {
    paneRef.current?.focus();
    setLegendOpen(false);
  }, [hold.hold_id]);

  const slots = React.useMemo(
    () =>
      buildVerdictSlots(hold, {
        capabilityLeaseTtlMs,
        containmentLeaseTtlMs,
      }),
    [hold, capabilityLeaseTtlMs, containmentLeaseTtlMs],
  );

  const expired = hold.expired || hold.state === "expired";
  const irreversible = hold.inverse_resolution.find(
    (step) => step.verdict !== "executable",
  );
  const undoAvailable =
    hold.inverse_resolution.length > 0 && irreversible === undefined;

  return (
    <section
      ref={paneRef}
      tabIndex={-1}
      aria-labelledby="perch-verdict-action"
      data-testid="perch-verdict-pane"
      data-perch-hold-id={hold.hold_id}
      data-perch-hold-state={hold.state}
      className="flex flex-col gap-2 bg-[hsl(var(--perch-surface-raised))] p-3 text-[hsl(var(--perch-foreground))]"
    >
      <header className="flex flex-wrap items-baseline gap-2">
        <h2 id="perch-verdict-action" className="text-sm font-medium">
          {hold.action_kind}
        </h2>
        <span className="text-2xs uppercase tracking-wide text-[hsl(var(--perch-foreground-muted))]">
          {hold.severity}
        </span>
        <HoldTtlClock remainingMs={hold.remaining_ms} expired={expired} />
        {hold.leases_a_containment ? (
          <span
            data-testid="perch-pending-containment-lease"
            className="text-2xs text-[hsl(var(--perch-foreground-muted))]"
          >
            granting mints a containment lease
          </span>
        ) : null}
      </header>

      {VERDICT_SLOT_ORDER.map((id) => (
        <VerdictSlot
          key={id}
          id={id}
          label={VERDICT_SLOT_LABELS[id]}
          content={slots[id]}
          sentinelRef={id === "blast-radius" ? setBlastRadiusEl : undefined}
        />
      ))}

      <button
        type="button"
        data-testid="perch-undo-affordance"
        data-perch-undo-available={undoAvailable ? "true" : "false"}
        aria-disabled="true"
        className="self-start text-left text-xs text-[hsl(var(--perch-foreground-muted))] underline"
      >
        {undoAvailable
          ? "Every planned rollback step has an executable inverse. Releasing it is done from the containment board, not from here."
          : irreversible
            ? `No undo from here: ${irreversible.step_kind} is ${irreversible.verdict}${irreversible.reason ? ` — ${irreversible.reason}` : ""}`
            : "No rollback plan was derived, so nothing here can say this is undoable."}
      </button>

      {expired ? (
        <p
          data-testid="perch-verdict-pane-expired"
          className="text-xs text-[hsl(var(--perch-foreground))]"
        >
          this hold expired at{" "}
          {new Date(hold.expires_at_ms).toLocaleTimeString()} · no action was
          taken
        </p>
      ) : (
        actionBar?.(blastRadiusEl)
      )}

      <DecisionStateRow state={writeState} />

      <div>
        <button
          type="button"
          data-testid="perch-refusal-legend-open"
          aria-expanded={legendOpen}
          onClick={() => setLegendOpen((open) => !open)}
          className="text-2xs uppercase tracking-wide text-[hsl(var(--perch-foreground-muted))] underline"
        >
          What can still stop this after you decide
        </button>
        {legendOpen ? <RefusalLegend hold={hold} /> : null}
      </div>
    </section>
  );
}

/**
 * The ways a recorded decision can still fail to become an action.
 *
 * `data-perch-reachable` is per row and is a claim about THIS build: the
 * governance row reads `true` because the shared governance gate is landed and
 * a decide re-runs it. A legend that listed unreachable refusals as if they
 * could fire would be teaching a rule that does not exist yet.
 */
function RefusalLegend({ hold }: { hold: PerchHeldActionView }) {
  return (
    <ul
      data-testid="perch-refusal-legend"
      className="mt-1 flex flex-col gap-1 text-xs text-[hsl(var(--perch-foreground-muted))]"
    >
      <li data-perch-refusal="expiry" data-perch-reachable="true">
        The hold can expire between your decision and the daemon's
        compare-and-set. The action is never taken.
      </li>
      <li data-perch-refusal="governance" data-perch-reachable="true">
        Governance is re-evaluated at the decision instant, not at hold time. A
        veto, a stale receipt or a failed committee check refuses the grant.
        Nothing establishes that a receipt's signer is a governor.
      </li>
      <li data-perch-refusal="another-console" data-perch-reachable="true">
        Another operator's decision can win the compare-and-set. Yours is
        recorded on the case and does not run.
      </li>
      {hold.leases_a_containment ? (
        <li data-perch-refusal="containment-lease" data-perch-reachable="true">
          The containment lease store can refuse. The grant is recorded and the
          action is not taken.
        </li>
      ) : null}
      <li data-perch-refusal="reason" data-perch-reachable="true">
        <EyebrowLabel>rule that held it</EyebrowLabel>
        <AdversaryString
          layout="inline"
          field="reason"
          value={hold.policy_decision.reason}
          cap={200}
        />
      </li>
    </ul>
  );
}
