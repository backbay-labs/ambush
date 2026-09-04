import { cn } from "@/shared/lib/cn";

/**
 * A hold's remaining time and whether it has expired, as TWO elements.
 *
 * The daemon serves `remaining_ms` and `expired` as two fields for a reason
 * (`HeldActionView`'s doc says it): a clock reading and a decision about that
 * reading are different claims, and a single "2m left / expired" string makes
 * the console look like it is deciding. So this renders the reading and the
 * verdict separately, and the verdict is the daemon's.
 *
 * Three states, all on the element as `data-perch-ttl-state` so a test can
 * assert the transition rather than a colour: `live`, `under-5m`, `expired`.
 */
export type HoldTtlClockProps = {
  /** From the daemon. Saturates at zero. */
  remainingMs: number;
  /** From the daemon. Not derived here from `remainingMs`. */
  expired: boolean;
  className?: string;
};

/** Below this the row is close enough to expiry to say so. */
const UNDER_SOON_MS = 5 * 60_000;

/** `1h 04m` / `4m 20s` / `18s`. No "left", no "remaining" — the label says it. */
function formatRemaining(ms: number): string {
  const total = Math.max(0, Math.floor(ms / 1000));
  const hours = Math.floor(total / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  const seconds = total % 60;
  if (hours > 0) return `${hours}h ${String(minutes).padStart(2, "0")}m`;
  if (minutes > 0) return `${minutes}m ${String(seconds).padStart(2, "0")}s`;
  return `${seconds}s`;
}

export function HoldTtlClock({
  remainingMs,
  expired,
  className,
}: HoldTtlClockProps) {
  const state = expired
    ? "expired"
    : remainingMs <= UNDER_SOON_MS
      ? "under-5m"
      : "live";
  return (
    <span
      data-testid="perch-hold-ttl"
      data-perch-ttl-state={state}
      className={cn(
        "inline-flex items-baseline gap-1 text-2xs tabular-nums",
        "text-[hsl(var(--perch-foreground-muted))]",
        className,
      )}
    >
      <span data-testid="perch-hold-ttl-reading">
        {formatRemaining(remainingMs)}
      </span>
      {expired ? (
        <span
          data-testid="perch-hold-ttl-expired"
          className="uppercase tracking-wide text-[hsl(var(--perch-foreground))]"
        >
          expired — no action was taken
        </span>
      ) : (
        <span className="text-[hsl(var(--perch-foreground-muted))]">
          until it stops being decidable
        </span>
      )}
    </span>
  );
}
