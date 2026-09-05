import type * as React from "react";

import { CASE_TTL_CAVEAT, readCaseTtl } from "../lib/caseTtlClock";

type CaseTtlClockProps = {
  ttlDeadline: string | null;
  nowMs: number;
};

/**
 * When this case archives.
 *
 * A wall clock and a span, never a bar. `aria-live="off"` because the number
 * changes every minute and a screen reader announcing it every minute would
 * drown the surface it sits on; the value is readable on demand.
 */
export function CaseTtlClock({
  ttlDeadline,
  nowMs,
}: CaseTtlClockProps): React.ReactElement | null {
  const reading = readCaseTtl(ttlDeadline, nowMs);
  if (reading.kind === "none") return null;
  return (
    <span
      data-testid="perch-case-ttl"
      data-ttl-state={reading.kind}
      aria-live="off"
      title={CASE_TTL_CAVEAT}
      className="inline-flex items-baseline gap-1"
    >
      <span className="text-xs text-muted-foreground">
        {reading.kind === "archived" ? "archived at" : "archives at"}
      </span>
      <span className="text-sm">{reading.atLabel}</span>
      {reading.kind === "due" ? (
        <span className="text-xs text-muted-foreground">
          {`· in ${reading.inLabel}`}
        </span>
      ) : null}
    </span>
  );
}
