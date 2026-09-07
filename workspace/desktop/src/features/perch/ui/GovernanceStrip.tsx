import * as React from "react";

import {
  getPerchEphemeralServerSnapshot,
  getPerchEphemeralSnapshot,
  subscribePerchEphemeral,
} from "@/shared/api/perchEphemeralStore";
import { usePerchTelemetryConsumer } from "@/shared/api/perchTelemetryWanted";

import {
  fillGovernanceCopy,
  formatGovernanceAge,
  GOVERNANCE,
} from "../lib/governanceCopy";
import {
  derivePerchGovernanceMode,
  GOVERNANCE_STALE_AFTER_MS,
  type PerchGovernanceMode,
} from "../lib/governanceMode";

const COPY: Record<PerchGovernanceMode, string> = {
  healthy: GOVERNANCE.healthy,
  degraded: GOVERNANCE.degraded,
  partitioned: GOVERNANCE.partitioned,
  healing: GOVERNANCE.healing,
  "fail-closed-no-transport": GOVERNANCE.failClosed,
  stale: GOVERNANCE.stale,
  "bridge-down": GOVERNANCE.bridgeDown,
};

/**
 * S14. The one line that is on screen wherever Perch is.
 *
 * It survives the bare chrome of the Watchfloor on purpose: the state it
 * reports — whether the console can see governance at all — is the state in
 * which every other number on screen becomes untrustworthy, and a surface that
 * hid it while showing the numbers would be the worst possible combination.
 *
 * `bridge-down` is what an absent frame produces, never `healthy`. Governance
 * liveness is not restart-safe, so a strip reading healthy from a stale
 * snapshot would be worse than one saying nothing at all.
 */
export function GovernanceStrip(): React.ReactElement {
  // The 26004 frame this strip is made of rides the telemetry REQ, and that
  // REQ is opened only while a surface says it is reading one.
  usePerchTelemetryConsumer();
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

  const frame = snapshot.telemetry.get(26004);
  const body = (frame?.body ?? {}) as Record<string, unknown>;
  const partitionState =
    body.partition_state === "degraded" ||
    body.partition_state === "partitioned" ||
    body.partition_state === "healing"
      ? body.partition_state
      : "healthy";
  const totalGovernors =
    typeof body.total_governors === "number" ? body.total_governors : 1;
  const receivedAtMs = frame?.receivedAtMs ?? null;

  const mode = derivePerchGovernanceMode({
    partitionState,
    totalGovernors,
    healthyGovernors:
      typeof body.healthy_governors === "number" ? body.healthy_governors : 1,
    receivedAtMs,
    nowMs,
    bridgeShedding: body.shedding === true,
    staleAfterMs: GOVERNANCE_STALE_AFTER_MS,
  });

  // The strip fills its own line — a raw `{ago}`/`{lastSeen}` reaching the
  // window is found-1. Only a mode that has a frame renders `{ago}`, so the
  // no-frame fallback below is never shown; `{lastSeen}` carries the no-frame
  // case, and reads `never` until the first envelope lands.
  const ageMs =
    receivedAtMs === null ? null : Math.max(0, nowMs - receivedAtMs);
  const ago = ageMs === null ? "never" : formatGovernanceAge(ageMs);
  const line = fillGovernanceCopy(COPY[mode], {
    ago,
    lastSeen: ageMs === null ? "never" : `${ago} ago`,
    n: totalGovernors,
    unauthorized:
      typeof body.unauthorized_partition_actions === "number"
        ? body.unauthorized_partition_actions
        : 0,
  });

  return (
    <p
      data-testid="perch-governance-strip"
      data-governance-mode={mode}
      className="border-b border-border px-3 py-1 text-2xs text-muted-foreground"
    >
      {line}
      {body.shedding === true ? ` · ${GOVERNANCE.shedding}` : null}
    </p>
  );
}
