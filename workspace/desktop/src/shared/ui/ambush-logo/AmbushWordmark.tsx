import type { CSSProperties } from "react";
import { cn } from "@/shared/lib/cn";
import "./ambush-logo-animation.css";

/** Tempo of one engrave cycle, before any rest window is added. */
export type AmbushWordmarkVariant = "steady" | "brisk";

const TEMPO_SECONDS: Record<AmbushWordmarkVariant, number> = {
  steady: 1.9,
  brisk: 1.2,
};

export type AmbushWordmarkProps = {
  /** When false, renders the crisp mark with no engrave cycle. */
  fuzz?: boolean;
  className?: string;
  ariaLabel?: string;
  loop?: boolean;
  /** When looping, hold the engraved mark for this many seconds between plays. */
  loopRestSeconds?: number;
  /** Set false when a parent drives its own opacity animation over the mark. */
  pulse?: boolean;
  reverse?: boolean;
  variant?: AmbushWordmarkVariant;
};

/**
 * The Ambush mark with the index engraving in: the live segment inks down from
 * the top, the spent segment follows, both hold for the rest of the cycle. Set
 * `fuzz={false}` to render the crisp geometry with a lightweight CSS pulse —
 * recommended for long-lived mounts.
 */
export function AmbushWordmark({
  fuzz = true,
  className,
  ariaLabel = "Ambush logo",
  loop = false,
  loopRestSeconds = 0,
  pulse = true,
  reverse = false,
  variant = "steady",
}: AmbushWordmarkProps) {
  // The rest-window loop already reads as "alive"; skip the pulse so the two
  // opacity animations don't fight.
  const restSeconds = loop ? Math.max(loopRestSeconds, 0) : 0;
  const hasRestWindow = restSeconds > 0;
  const cycleSeconds = TEMPO_SECONDS[variant] + restSeconds;

  return (
    <div
      aria-label={ariaLabel}
      className={cn(
        "ambush-logo ambush-logo--compact",
        fuzz && "ambush-logo--engrave",
        fuzz && !loop && "ambush-logo--once",
        fuzz && reverse && "ambush-logo--reverse",
        pulse && !fuzz && !hasRestWindow && "ambush-logo--pulse",
        className,
      )}
      role="img"
      style={{ "--ambush-logo-cycle": `${cycleSeconds}s` } as CSSProperties}
    >
      <svg
        aria-hidden="true"
        className="ambush-logo__mark"
        fill="currentColor"
        viewBox="0 0 256 256"
      >
        <path className="ambush-logo__live" d="M64 0h64v152H64z" />
        <path className="ambush-logo__spent" d="M128 136h64v120h-64z" />
      </svg>
    </div>
  );
}
