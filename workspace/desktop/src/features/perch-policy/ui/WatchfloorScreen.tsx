import * as React from "react";

import {
  getPerchEphemeralServerSnapshot,
  getPerchEphemeralSnapshot,
  subscribePerchEphemeral,
} from "@/shared/api/perchEphemeralStore";
import { STANDARD_THREAT_CLASSES } from "@/features/perch/wire/types";
import { ConcentrationCurve } from "@/shared/viz/ConcentrationCurve";
import { VizDefs } from "@/shared/viz/defs";
import type {
  ConcentrationSample,
  ThreatClassPolicy,
} from "@/shared/viz/types";

import {
  appendSample,
  colonyAgents,
  colonyMode,
  frameAgeSeconds,
  sampleForClass,
} from "../lib/watchfloorFrames";
import { fillWatchfloor, WATCHFLOOR } from "../lib/watchfloorCopy";

/** How many samples each class keeps. One frame a second, one hour. */
const HISTORY_CAP = 3_600;
/** Past this the wall says its curves are the last received, not current. */
const STALE_AFTER_SECONDS = 5;

/**
 * Thresholds until the daemon's per-class policy is cached.
 *
 * Marked as defaults in the caption rather than presented as the daemon's, so
 * a rule drawn from these is never read as the configured one.
 */
const FALLBACK_POLICY: ThreatClassPolicy = {
  half_life_secs: 3600,
  evaporation_threshold: 0.01,
  min_sources_for_escalation: 2,
  alert_threshold: 2,
  incident_threshold: 5,
};

function usePerchEphemeral() {
  return React.useSyncExternalStore(
    subscribePerchEphemeral,
    getPerchEphemeralSnapshot,
    getPerchEphemeralServerSnapshot,
  );
}

/**
 * S8, `/watch-floor`. The room's screen.
 *
 * Nothing here is clickable and the screen says so. It is read from across a
 * room by someone who did not open it, cannot ask where a number came from,
 * and will not notice a tooltip — so every band names its own source in
 * standing text, and every absence is rendered as an absence.
 *
 * The curves are regime B: interpolated between snapshots, with no deposits
 * behind them. Each carries that in its own caption, because a curve that
 * looks like the deposit-backed one on a case screen but is not would be the
 * most expensive possible confusion here.
 */
export function WatchfloorScreen(): React.ReactElement {
  const snapshot = usePerchEphemeral();
  const [nowMs, setNowMs] = React.useState(() => Date.now());
  const historiesRef = React.useRef(new Map<string, ConcentrationSample[]>());

  React.useEffect(() => {
    const id = window.setInterval(() => setNowMs(Date.now()), 1_000);
    return () => window.clearInterval(id);
  }, []);

  const concentration = snapshot.telemetry.get(26001);
  const health = snapshot.telemetry.get(26002);
  const modeFrame = snapshot.telemetry.get(26003);

  // Fold the newest frame into each class's ring. Done in a ref rather than
  // state because a thousand samples across twelve classes must not re-render
  // the whole wall; the one-second tick above is what repaints.
  for (const threatClass of STANDARD_THREAT_CLASSES) {
    const sample = sampleForClass(concentration, threatClass);
    if (!sample) continue;
    const history = historiesRef.current.get(threatClass) ?? [];
    historiesRef.current.set(
      threatClass,
      appendSample(history, sample, HISTORY_CAP),
    );
  }

  const ageSeconds = frameAgeSeconds(concentration, nowMs);
  const stale = ageSeconds !== null && ageSeconds > STALE_AFTER_SECONDS;
  const agents = colonyAgents(health);
  const mode = colonyMode(modeFrame);
  const nowSeconds = Math.floor(nowMs / 1000);

  return (
    <section data-testid="perch-watchfloor" className="p-4">
      <VizDefs />
      <header className="flex items-baseline justify-between gap-3">
        <h2 className="text-base font-medium">{WATCHFLOOR.title}</h2>
        <p className="text-xs text-muted-foreground">{WATCHFLOOR.noClicks}</p>
      </header>

      <section data-testid="perch-watchfloor-decay" className="mt-3">
        <h3 className="text-xs text-muted-foreground">{WATCHFLOOR.decay}</h3>
        {stale && ageSeconds !== null ? (
          <p data-testid="perch-watchfloor-stale" className="text-xs">
            {fillWatchfloor(WATCHFLOOR.stale, { seconds: ageSeconds })}
          </p>
        ) : null}
        {concentration === undefined ? (
          <p data-testid="perch-watchfloor-no-frame" className="text-sm">
            {WATCHFLOOR.noFrame}
          </p>
        ) : (
          <div className="grid gap-3">
            {STANDARD_THREAT_CLASSES.map((threatClass) => {
              const samples = historiesRef.current.get(threatClass) ?? [];
              return (
                <ConcentrationCurve
                  key={threatClass}
                  threatClass={threatClass}
                  policy={FALLBACK_POLICY}
                  samples={samples}
                  deposits={null}
                  suppressions={[]}
                  now={nowSeconds}
                  nowFromDaemon={
                    samples.length > 0
                      ? samples[samples.length - 1].at
                      : nowSeconds
                  }
                  attribution={{
                    kind: "count",
                    distinctSources:
                      samples.length > 0
                        ? samples[samples.length - 1].distinct_sources
                        : 0,
                  }}
                  state={
                    samples.length === 0
                      ? { kind: "empty", reason: "served-empty" }
                      : { kind: "ready" }
                  }
                />
              );
            })}
          </div>
        )}
      </section>

      <section data-testid="perch-watchfloor-colony" className="mt-4">
        <h3 className="text-xs text-muted-foreground">
          {fillWatchfloor(WATCHFLOOR.colony, { n: agents?.length ?? 0 })}
        </h3>
        {agents === null ? (
          <p className="text-sm">
            No health frame has arrived. This is not zero agents; the console
            has not been told anything.
          </p>
        ) : (
          <ul className="mt-1 flex flex-wrap gap-3">
            {agents.map((agent) => (
              <li
                key={agent.agentId}
                data-testid={`perch-colony-${agent.agentId}`}
                data-healthy={agent.healthy ? "1" : "0"}
                className="text-xs"
              >
                <span className="font-mono">{agent.role}</span>
                {" · "}
                {agent.healthy ? "healthy" : "not reporting healthy"}
              </li>
            ))}
          </ul>
        )}
      </section>

      <section data-testid="perch-watchfloor-mode" className="mt-4">
        <h3 className="text-xs text-muted-foreground">{WATCHFLOOR.mode}</h3>
        <p className="text-sm">
          {mode ??
            "No mode frame has arrived. The mode is unknown, not normal."}
        </p>
      </section>
    </section>
  );
}
