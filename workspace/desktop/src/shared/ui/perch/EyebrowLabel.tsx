import type * as React from "react";

import { cn } from "@/shared/lib/cn";

/**
 * The small capitalised label above a block of governance content.
 *
 * A separate component rather than a class string repeated per slot, so the
 * Verdict Row's five eyebrows cannot drift apart pixel by pixel the way the
 * arbitrary text sizes did. `text-2xs` is a rem token, so it follows the
 * user's font-size preference and Cmd +/- zoom.
 */
export function EyebrowLabel({
  children,
  className,
  ...props
}: React.HTMLAttributes<HTMLSpanElement>) {
  return (
    <span
      className={cn(
        "block text-2xs font-medium uppercase tracking-wide",
        "text-[hsl(var(--perch-foreground-muted))]",
        className,
      )}
      {...props}
    >
      {children}
    </span>
  );
}
