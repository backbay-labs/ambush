import * as React from "react";

import {
  perchSidecarStart,
  perchSidecarStatus,
  perchSidecarStop,
  type PerchSidecarStatus,
} from "@/shared/api/tauriPerch";

/** How often the panel re-reads the daemon's readiness. */
const POLL_MS = 5_000;

const HEALTH_LABEL = {
  starting: "starting",
  ready: "ready",
  unhealthy: "not answering /readyz",
  stopped: "stopped",
} as const;

/**
 * The laptop demo's daemon, supervised by this app.
 *
 * Three states the panel keeps apart, because the operator's next action
 * differs for each: never started (there is nothing to stop), starting (wait),
 * and unhealthy (read the log — it will not come up on its own). A panel that
 * showed "not ready" for the last two would make a daemon that has failed look
 * like one that is about to succeed.
 *
 * The seeds are reported as PRESENT or absent and never as values. They go
 * from the keyring straight into the child's environment inside the Tauri
 * process; nothing here has ever held one.
 */
export function PerchSidecarPanel(): React.ReactElement {
  const [status, setStatus] = React.useState<PerchSidecarStatus | null>(null);
  const [started, setStarted] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);
  const [configPath, setConfigPath] = React.useState("perch-dev.yaml");

  const refresh = React.useCallback(async () => {
    try {
      const next = await perchSidecarStatus();
      setStatus(next);
      if (next) setStarted(true);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    }
  }, []);

  React.useEffect(() => {
    void refresh();
    const id = window.setInterval(() => void refresh(), POLL_MS);
    return () => window.clearInterval(id);
  }, [refresh]);

  const onStart = React.useCallback(async () => {
    setError(null);
    try {
      setStatus(await perchSidecarStart(configPath));
      setStarted(true);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    }
  }, [configPath]);

  const onStop = React.useCallback(async () => {
    setError(null);
    try {
      await perchSidecarStop();
      await refresh();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    }
  }, [refresh]);

  const running =
    status !== null &&
    (status.healthz === "starting" ||
      status.healthz === "ready" ||
      status.healthz === "unhealthy");

  return (
    <section data-testid="perch-sidecar-panel" className="p-4">
      <h3 className="text-sm font-medium">Local detector</h3>
      <p className="mt-1 text-xs text-muted-foreground">
        Runs the bundled <code>swarm_detect</code> on this machine, bound to
        127.0.0.1:9090. It stops when this app quits.
      </p>

      <p
        data-testid="perch-sidecar-status"
        data-healthz={status?.healthz ?? "never-started"}
        className="mt-2 text-sm"
      >
        {status === null
          ? started
            ? "The daemon has stopped."
            : "The daemon has never been started from here."
          : `${HEALTH_LABEL[status.healthz]} · pid ${status.pid} · ${status.profile_path}`}
      </p>

      {status !== null ? (
        <p
          data-testid="perch-sidecar-seeds"
          className="mt-1 text-xs text-muted-foreground"
        >
          {`bridge seed ${status.seeds_present.nostr ? "configured" : "not configured"} · spine seed ${status.seeds_present.spine ? "configured" : "not configured"}`}
        </p>
      ) : null}

      <div className="mt-3 flex flex-wrap items-center gap-2">
        <label className="text-xs">
          <span className="mr-1 text-muted-foreground">config</span>
          <input
            data-testid="perch-sidecar-config"
            className="rounded border border-border px-1 py-0.5 text-xs"
            value={configPath}
            disabled={running}
            onChange={(event) => setConfigPath(event.target.value)}
          />
        </label>
        {running ? (
          <button
            type="button"
            data-testid="perch-sidecar-stop"
            className="rounded border border-border px-2 py-1 text-sm"
            onClick={() => void onStop()}
          >
            Stop
          </button>
        ) : (
          <button
            type="button"
            data-testid="perch-sidecar-start"
            className="rounded border border-border px-2 py-1 text-sm"
            onClick={() => void onStart()}
          >
            Start
          </button>
        )}
      </div>

      {error !== null ? (
        <p data-testid="perch-sidecar-error" className="mt-2 text-sm">
          {error}
        </p>
      ) : null}
    </section>
  );
}
