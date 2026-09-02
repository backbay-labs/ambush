import * as React from "react";

import {
  isWelcomeKickoffStageExiting,
  type WelcomeKickoffStagePhase,
} from "@/features/onboarding/useWelcomeKickoffStage";
import { cn } from "@/shared/lib/cn";

/** The same starter team the "Meet your starter team" onboarding step names. */
const STAGE_CHARACTERS: readonly string[] = ["Anvil", "Lantern", "Sextant"];

const STAGE_EXIT_ANIMATION = "motion-kickoff-stage-exit";

/**
 * The welcome team standing on top of the Welcome composer banner while the
 * team is being set up: one initial plate per member. Positioned relative to
 * the banner wrapper (`bottom-full` = feet on the banner's top edge) and purely
 * decorative — the banner's own copy carries the setup status for screen
 * readers.
 *
 * Staggered rise-from-below entrance per member (CSS
 * `motion-kickoff-character-enter`, delay via `--stagger-index`); the whole row
 * crossfades out on either resolution — the first agent message landing, or the
 * wait timing out. The row must not linger after a timeout: a stage that stays
 * up implies a team is still coming when none is.
 */
export function WelcomeKickoffStage({
  onExitComplete,
  phase,
}: {
  onExitComplete: () => void;
  phase: WelcomeKickoffStagePhase;
}) {
  const handleAnimationEnd = React.useCallback(
    (event: React.AnimationEvent<HTMLDivElement>) => {
      if (event.animationName === STAGE_EXIT_ANIMATION) {
        onExitComplete();
      }
    },
    [onExitComplete],
  );

  if (phase === "hidden" || phase === "done") return null;

  return (
    <div
      aria-hidden
      className={cn(
        "pointer-events-none absolute bottom-full left-10 z-10 flex items-end gap-4",
        isWelcomeKickoffStageExiting(phase) && "motion-kickoff-stage-exit",
      )}
      data-phase={phase}
      data-testid="welcome-kickoff-stage"
      onAnimationEnd={handleAnimationEnd}
    >
      {STAGE_CHARACTERS.map((name, index) => (
        <span
          className="motion-kickoff-character-enter flex h-16 w-16 items-center justify-center rounded border border-border bg-card font-mono text-xl uppercase text-card-foreground"
          data-testid={`welcome-kickoff-stage-${name.toLowerCase()}`}
          key={name}
          style={{ "--stagger-index": index } as React.CSSProperties}
        >
          {name.slice(0, 1)}
        </span>
      ))}
    </div>
  );
}
