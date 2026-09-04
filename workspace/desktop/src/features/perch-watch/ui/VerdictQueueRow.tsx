import { AdversaryString } from "@/shared/ui/perch/AdversaryString";
import { HoldTtlClock } from "@/shared/ui/perch/HoldTtlClock";
import { cn } from "@/shared/lib/cn";

import type { PerchHoldRow } from "../lib/holdRows";

/**
 * One row of the HOLDS queue. Three lines (17-COMPONENT-SPECS.md §6.2):
 * what is held, why we are being asked, and how long there is to answer.
 *
 * Every value on the first two lines came off the wire from a process this
 * console does not control, so the host id and the rule's reason render
 * through `AdversaryString`. React escapes markup; it does nothing about a
 * bidi override, and a queue row that can be made to read as a different
 * host is the one lie this surface must not be able to tell.
 *
 * `data-perch-register` is the row's severity of PRESENTATION, not the
 * action's: `destructive` means the console is reporting a disagreement it
 * cannot resolve, which is a different alarm from a CRITICAL hold.
 */
export type VerdictQueueRowProps = {
  row: PerchHoldRow;
  selected: boolean;
  onSelect: () => void;
};

function rowId(row: PerchHoldRow): string {
  return row.kind === "unreconciled" ? row.holdId : row.hold.hold_id;
}

export function VerdictQueueRow({
  row,
  selected,
  onSelect,
}: VerdictQueueRowProps) {
  const id = rowId(row);
  const register = row.kind === "unreconciled" ? row.register : "ordinary";
  return (
    <button
      type="button"
      onClick={onSelect}
      data-testid={`perch-queue-row-${id}`}
      data-perch-row-kind={row.kind}
      data-perch-hold-state={
        row.kind === "unreconciled" ? "none" : row.hold.state
      }
      data-perch-register={register}
      data-perch-selected={selected ? "true" : "false"}
      aria-current={selected ? "true" : undefined}
      className={cn(
        "flex w-full flex-col gap-0.5 border-l-4 px-3 py-2 text-left",
        "bg-[hsl(var(--perch-card))] text-[hsl(var(--perch-foreground))]",
        register === "destructive"
          ? "border-[hsl(var(--perch-foreground))]"
          : "border-[hsl(var(--perch-border-strong))]",
        selected && "bg-[hsl(var(--perch-surface-raised))]",
      )}
    >
      {row.kind === "unreconciled" ? (
        <UnreconciledLines row={row} />
      ) : (
        <HoldLines row={row} />
      )}
    </button>
  );
}

function HoldLines({
  row,
}: {
  row: Extract<PerchHoldRow, { kind: "hold" | "expired" }>;
}) {
  const { hold } = row;
  return (
    <>
      <span className="flex items-baseline gap-2 text-sm">
        <span className="font-medium">{hold.action_kind}</span>
        <span
          data-testid="perch-row-severity"
          className="text-2xs uppercase tracking-wide text-[hsl(var(--perch-foreground-muted))]"
        >
          {hold.severity}
        </span>
        {hold.leases_a_containment ? (
          <span
            data-testid="perch-row-leases-containment"
            className="text-2xs text-[hsl(var(--perch-foreground-muted))]"
          >
            takes a containment lease
          </span>
        ) : null}
      </span>
      <AdversaryString
        layout="inline"
        field="reason"
        value={hold.rationale.reason}
        cap={160}
        className="text-xs"
      />
      <span className="flex items-baseline gap-2 text-xs">
        <HoldTtlClock
          remainingMs={hold.remaining_ms}
          expired={row.kind === "expired"}
        />
        {row.kind === "hold" && !row.noticed ? (
          <span
            data-testid="perch-row-undelivered"
            className="text-2xs text-[hsl(var(--perch-foreground-muted))]"
          >
            no notice reached the relay
          </span>
        ) : null}
      </span>
    </>
  );
}

/**
 * A hold the daemon has no record of.
 *
 * Renders the id, the event that claimed it and the daemon's own reason for
 * being unable to reconcile — and nothing else. The notice's content offers a
 * severity, an action kind and an expiry; none of them is a fact here, and
 * `reconcileHoldQueue` deliberately does not carry them onto the row so this
 * component could not render them if it tried.
 */
function UnreconciledLines({
  row,
}: {
  row: Extract<PerchHoldRow, { kind: "unreconciled" }>;
}) {
  return (
    <>
      <span className="flex items-baseline gap-2 text-sm">
        <span className="font-medium uppercase tracking-wide">
          UNRECONCILED
        </span>
        <AdversaryString
          layout="inline"
          field="hold id"
          value={row.holdId}
          cap={72}
          className="text-xs"
        />
      </span>
      <span className="text-xs text-[hsl(var(--perch-foreground-muted))]">
        {row.reason}
      </span>
      {/* The whole id, visually clipped by CSS rather than cut in the string:
          a truncated identifier is a forgeable one, and this is the pointer an
          operator uses to go and find the event that made the claim. */}
      <span
        data-testid="perch-row-notice-event"
        className="truncate font-mono text-2xs text-[hsl(var(--perch-foreground-muted))]"
      >
        claimed by relay event {row.noticeEventId}
      </span>
    </>
  );
}
