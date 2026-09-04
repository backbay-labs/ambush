import * as React from "react";

import {
  armGrant,
  disarmGrant,
  isGrantArmed,
  noteHoldSelected,
} from "@/features/perch/lib/keymapArmingState";
import { hasPrimaryShortcutModifier } from "@/shared/lib/platform";
import { Button } from "@/shared/ui/button";
import type { DecisionWriteState } from "@/shared/ui/perch/DecisionStateRow";

import {
  dwellComplete,
  dwellPercent,
  dwellReducer,
  type GRANT_DWELL_MS,
  initialDwell,
} from "../lib/grantDwell";

/**
 * The grant. Two strokes, and the second one is gated on having read the blast
 * radius.
 *
 * INV-11's three mechanisms all live in THIS file, and
 * `tools/check-perch-grant-affordance.sh` R3 reads this file for all three,
 * because a gate whose mechanism sits somewhere else is a gate that a second,
 * ungated grant affordance can be written without noticing:
 *
 *   `event.repeat`         a held `G` is one intention, not forty.
 *   `IntersectionObserver` at `threshold: 1.0` on the BLAST RADIUS block's last
 *                          element, so "seen" means the END of the block
 *                          reached the viewport rather than the heading.
 *   1500                   the dwell, below.
 *
 * The observer alone is not enough: a fast scroll can carry the sentinel past
 * the viewport between two frames without the callback firing at ratio 1, so a
 * 100 ms interval samples `getBoundingClientRect` as a second mechanism and
 * feeds the same reducer. Two mechanisms because a gate with one is a gate with
 * one way to miss.
 *
 * `refuse` has no gate at all and that asymmetry is deliberate: refusing
 * dispatches nothing, so nothing needs to be understood before it is safe.
 */
export type GrantControlProps = {
  holdId: string;
  /** The BLAST RADIUS slot's last element. `null` before the pane lays out. */
  blastRadiusEl: HTMLElement | null;
  /** How many rows the operator has selected. The control hides unless it is 1. */
  selectionCount: number;
  writeState: DecisionWriteState;
  onRecord: () => void;
  /** A reason the grant is unavailable for reasons other than the dwell. */
  disabledReason?: string | null;
};

/**
 * The dwell, restated here and checked against the reducer's by the type
 * system: `typeof GRANT_DWELL_MS` is the literal `1500`, so this line fails
 * `tsc --noEmit` the moment either side moves. The gate's scan of this file
 * therefore reads a value that is load-bearing rather than a comment.
 */
const DWELL_MS: typeof GRANT_DWELL_MS = 1500;

/** How often the second mechanism samples the sentinel's position. */
const DWELL_SAMPLE_MS = 100;

/** Whether `el` is fully inside the viewport right now. */
function isFullyVisible(el: HTMLElement): boolean {
  const rect = el.getBoundingClientRect();
  const height = window.innerHeight || document.documentElement.clientHeight;
  const width = window.innerWidth || document.documentElement.clientWidth;
  return (
    rect.height > 0 &&
    rect.top >= 0 &&
    rect.left >= 0 &&
    rect.bottom <= height &&
    rect.right <= width
  );
}

export function GrantControl({
  holdId,
  blastRadiusEl,
  selectionCount,
  writeState,
  onRecord,
  disabledReason,
}: GrantControlProps) {
  const [dwell, dispatch] = React.useReducer(
    dwellReducer,
    holdId,
    initialDwell,
  );
  const [armed, setArmed] = React.useState(() => isGrantArmed(holdId));

  // A new hold is a new question: the accrual and the arming both reset.
  React.useEffect(() => {
    noteHoldSelected(holdId);
    setArmed(isGrantArmed(holdId));
    dispatch({ type: "reset", holdId });
  }, [holdId]);

  // Mechanism 2 and 3: the observer reports the edges, the sampler covers the
  // frames the observer can miss. Both feed the one reducer, through one
  // transition function.
  //
  // `visible` is dispatched only on a CHANGE. The reducer re-bases
  // `lastTickMs` on every `visible`, so a sampler that re-announced the same
  // state each tick would reset the reference 10 times a second and the
  // accrual would sit at zero forever while looking perfectly correct.
  const visibleRef = React.useRef<boolean | null>(null);
  React.useEffect(() => {
    if (!blastRadiusEl) return;
    visibleRef.current = null;
    const report = (next: boolean) => {
      if (visibleRef.current === next) return;
      visibleRef.current = next;
      dispatch({ type: next ? "visible" : "hidden", atMs: Date.now() });
    };
    const observer = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) report(entry.intersectionRatio >= 1);
      },
      { threshold: 1.0 },
    );
    observer.observe(blastRadiusEl);
    const timer = window.setInterval(() => {
      report(isFullyVisible(blastRadiusEl));
      dispatch({ type: "tick", atMs: Date.now() });
    }, DWELL_SAMPLE_MS);
    return () => {
      observer.disconnect();
      window.clearInterval(timer);
    };
  }, [blastRadiusEl]);

  const complete = dwellComplete(dwell);
  const percent = dwellPercent(dwell);
  const idle = writeState.phase === "idle";
  const blocked = !complete
    ? percent === 0
      ? "read the blast radius first"
      : `keep the blast radius in view · ${percent}%`
    : (disabledReason ?? null);
  const disabled = blocked !== null || !idle;

  // Mechanism 1, and the two strokes. `G` arms; `Enter` records, and only when
  // the same hold is armed AND the gate is open. Neither stroke alone does
  // anything, which is the point.
  const recordRef = React.useRef(onRecord);
  recordRef.current = onRecord;

  // Hoisted out of the JSX so the opening tag stays short enough that
  // `data-perch-role="grant"` and render law 6's sentence sit within R7's
  // six-line window. An inline handler pushed them fourteen lines apart, and a
  // gate that cannot see the pair is a gate that admits an undeclared control.
  const record = React.useCallback(() => {
    if (disabled) return;
    disarmGrant();
    setArmed(false);
    recordRef.current();
  }, [disabled]);
  React.useEffect(() => {
    function onKeyDown(event: KeyboardEvent) {
      if (
        event.repeat ||
        event.defaultPrevented ||
        hasPrimaryShortcutModifier(event) ||
        event.altKey
      ) {
        return;
      }
      if (event.key === "g" || event.key === "G") {
        armGrant(holdId);
        setArmed(true);
        event.preventDefault();
        return;
      }
      if (event.key !== "Enter") return;
      if (!isGrantArmed(holdId) || !complete || !idle) return;
      event.preventDefault();
      disarmGrant();
      setArmed(false);
      recordRef.current();
    }
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [holdId, complete, idle]);

  // One selected row, or no control. A grant that could act on a multi-select
  // is a grant that can isolate a fleet from one keypress.
  if (selectionCount !== 1 || writeState.phase === "superseded") return null;

  return (
    <div className="flex flex-wrap items-center gap-3">
      {armed ? (
        <span
          data-testid="perch-grant-armed"
          className="text-2xs uppercase tracking-wide text-[hsl(var(--perch-foreground))]"
        >
          armed — press Enter to record
        </span>
      ) : null}
      {/* The role attribute sits on the BUTTON, beside render law 6's own
          sentence, not on the wrapper: R7 reads the two within six lines of
          each other precisely so a control that carries the sentence without
          the declaration cannot exist. */}
      <Button
        type="button"
        variant="verdict"
        aria-disabled={disabled}
        aria-describedby="perch-grant-reason"
        data-testid="perch-grant-record"
        data-perch-dwell-ms={DWELL_MS}
        data-perch-dwell-percent={percent}
        onClick={record}
        data-perch-role="grant"
      >
        Record my decision and send it to the daemon
      </Button>
      <span
        id="perch-grant-reason"
        data-testid="perch-grant-dwell"
        className="text-xs text-[hsl(var(--perch-foreground-muted))]"
      >
        {blocked ?? `${percent}%`}
      </span>
    </div>
  );
}
