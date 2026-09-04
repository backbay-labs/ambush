import * as React from "react";

import { usePerchKeymap } from "@/features/perch/usePerchKeymap";
import type { PerchHeldActionView } from "@/shared/api/tauriPerch";

import { useVerdictWrite } from "../useVerdictWrite";
import { GrantControl } from "./GrantControl";
import { RefuseControl } from "./RefuseControl";
import { VerdictPane } from "./VerdictPane";

/**
 * The Verdict Row with its two controls and the write behind them.
 *
 * Separated from `WatchScreen` because it is the only place in the console
 * where a keypress can change the world, and it should be possible to read that
 * whole path in one file.
 *
 * `usePerchKeymap` handles `R` and declares `grant` as another control's, so it
 * neither dispatches nor consumes `G`. The declaration is load-bearing: the
 * hook calls `preventDefault()` on every key it answers, and `GrantControl`
 * re-registers its own listener when the dwell completes — which moved it
 * behind the hook's and made `G` stop arming at the exact moment the gate
 * opened.
 */
export function HoldVerdictBar({ hold }: { hold: PerchHeldActionView }) {
  const write = useVerdictWrite(hold.hold_id);
  const armedAtRef = React.useRef<number | null>(null);

  const onGrant = React.useCallback(() => {
    void write.record("grant", null, armedAtRef.current);
  }, [write]);
  const onRefuse = React.useCallback(() => {
    // No dwell, no dialog: refusing dispatches nothing, so there is nothing to
    // have understood first.
    void write.record("refuse", null, null);
  }, [write]);

  usePerchKeymap({
    rowType: "hold",
    ignoreVerbs: ["grant"],
    onVerb: (verb) => {
      if (verb === "refuse") onRefuse();
    },
  });

  return (
    <VerdictPane
      hold={hold}
      writeState={write.state}
      actionBar={(blastRadiusEl) => (
        <div className="flex flex-wrap items-center gap-4">
          <GrantControl
            holdId={hold.hold_id}
            blastRadiusEl={blastRadiusEl}
            selectionCount={1}
            writeState={write.state}
            onRecord={onGrant}
          />
          <RefuseControl
            writeState={write.state}
            selectionCount={1}
            onRefuse={onRefuse}
          />
        </div>
      )}
    />
  );
}
