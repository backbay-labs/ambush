import type * as React from "react";

import { deriveContainmentState } from "@/features/perch-containment/lib/containmentState";
import { cn } from "@/shared/lib/cn";

export type ContainmentTimerProps = {
  /** Saturates at zero by construction, in the daemon. */
  remainingMs: number;
  /**
   * A SEPARATE fact. True on a still-listed containment lease means the sweep
   * tried to release it and failed.
   */
  expired: boolean;
  /** For the "self-releases at" sentence. A wall clock, not a delta. */
  expiresAtMs: number;
  daemonReachable: boolean;
  className?: string;
};

function mmss(ms: number): string {
  const total = Math.floor(ms / 1000);
  const minutes = Math.floor(total / 60);
  const seconds = total % 60;
  return `${String(minutes).padStart(2, "0")}:${String(seconds).padStart(2, "0")}`;
}

/**
 * Two facts, two DOM elements, and never one bar.
 *
 * A single progress bar would collapse `remaining_ms` and `expired` into one
 * reading, and those are the two facts an operator most needs kept apart: a
 * bar at zero looks identical whether the containment is about to release
 * itself or has already failed to.
 */
export function ContainmentTimer({
  remainingMs,
  expired,
  expiresAtMs,
  daemonReachable,
  className,
}: ContainmentTimerProps): React.ReactElement {
  const state = deriveContainmentState({
    remainingMs,
    expired,
    daemonReachable,
  });
  const wall = new Date(expiresAtMs).toLocaleTimeString(undefined, {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
  const expiredWord =
    state === "expired-still-listed" || state === "daemon-down-expired"
      ? "EXPIRED, HOST STILL CONTAINED · the sweep tried and failed"
      : state === "expiring"
        ? "EXPIRING"
        : "OPEN";
  return (
    <div
      className={cn("flex flex-col gap-0.5", className)}
      data-perch-containment-state={state}
    >
      <span
        data-testid="perch-containment-remaining"
        // `status` so the label below is announced with the figure; the timer
        // updates every second and an assertive role would interrupt on each.
        role="status"
        aria-live="off"
        aria-label={`${mmss(remainingMs)} remaining, self-releases at ${wall}`}
        className="text-sm tabular-nums text-[hsl(var(--perch-foreground))]"
      >
        {mmss(remainingMs)}
      </span>
      {expired ? (
        <span
          data-testid="perch-containment-expired"
          role="alert"
          className="text-sm font-medium text-[hsl(var(--perch-foreground))]"
        >
          {/* The mark is decoration; the WORD carries the meaning, so a reader
              who cannot see the hue loses nothing. */}
          <span
            aria-hidden="true"
            className="mr-1 inline-block h-2 w-2 rounded-full bg-[hsl(var(--perch-foreground))]"
          />
          {expiredWord}
        </span>
      ) : (
        <span
          data-testid="perch-containment-expired"
          className="text-xs text-[hsl(var(--perch-foreground-muted))]"
        >
          {expiredWord} · self-releases at {wall}
        </span>
      )}
    </div>
  );
}
