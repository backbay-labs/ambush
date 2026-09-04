import * as React from "react";

import {
  getPerchEphemeralServerSnapshot,
  getPerchEphemeralSnapshot,
  subscribePerchEphemeral,
} from "@/shared/api/perchEphemeralStore";

import { LANE } from "../lib/laneCopy";
import {
  laneLiveNumbers,
  laneTelemetryIsStale,
  type LanePolicy,
} from "../lib/laneLiveNumbers";

export type LaneScreenProps = {
  laneId: string;
  threatClass: string;
  policy: LanePolicy;
};

function fill(
  template: string,
  values: Record<string, string | number>,
): string {
  return template.replace(/\{(\w+)\}/g, (whole, key: string) =>
    key in values ? String(values[key]) : whole,
  );
}

/**
 * S5, `/lanes/$laneId`. One threat class's channel, with the live numbers on
 * its header.
 *
 * The header reads the 26001 frame, never the channel topic. The topic is
 * edge-written and durable; these numbers are ephemeral and per-second, so a
 * header built from the topic would show whatever was true at the last
 * threshold crossing and present it as now.
 *
 * A lane with no frame renders neither the numbers nor a zero. Its quiet state
 * says what decay means — deposits fade on a half-life, so a lane can go quiet
 * without anything having been resolved — and points at what the detectors
 * deliberately do not see.
 */
export function LaneScreen({
  laneId,
  threatClass,
  policy,
}: LaneScreenProps): React.ReactElement {
  const snapshot = React.useSyncExternalStore(
    subscribePerchEphemeral,
    getPerchEphemeralSnapshot,
    getPerchEphemeralServerSnapshot,
  );
  const [nowMs, setNowMs] = React.useState(() => Date.now());
  React.useEffect(() => {
    const id = window.setInterval(() => setNowMs(Date.now()), 1_000);
    return () => window.clearInterval(id);
  }, []);

  const numbers = laneLiveNumbers(
    snapshot.telemetry.get(26001),
    threatClass,
    policy,
    nowMs,
  );
  const stale = numbers !== null && laneTelemetryIsStale(numbers);

  return (
    <section data-testid="perch-lane" data-lane-id={laneId} className="p-4">
      <header>
        <h2 className="text-base font-medium">{threatClass}</h2>
        <p
          data-testid="perch-lane-liveness"
          className="text-xs text-muted-foreground"
        >
          {numbers === null
            ? "No concentration frame has arrived for this channel."
            : stale
              ? fill(LANE.headerStale, {
                  seconds: Math.floor(numbers.ageMs / 1000),
                })
              : LANE.headerLive}
        </p>
      </header>

      {numbers === null ? null : (
        <p data-testid="perch-lane-numbers" className="mt-2 text-sm">
          {`total_strength ${numbers.totalStrength.toFixed(2)} · alert_threshold ${numbers.alertThreshold.toFixed(2)} · ${numbers.distinctSources} sources / agent count not carried`}
        </p>
      )}

      <div data-testid="perch-lane-curve-slot" className="mt-3" />

      <p className="mt-3 text-xs text-muted-foreground">
        {LANE.annotationsOnly}
      </p>
      <p className="mt-1 text-xs text-muted-foreground">{LANE.mutedNote}</p>
    </section>
  );
}
