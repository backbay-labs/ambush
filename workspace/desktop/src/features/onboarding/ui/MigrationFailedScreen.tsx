import { relaunch } from "@tauri-apps/plugin-process";
import { useState } from "react";

import { retryStartupMigration } from "@/shared/api/tauriIdentity";
import { useSystemColorScheme } from "@/shared/theme/useSystemColorScheme";
import { Button } from "@/shared/ui/button";
import { StartupWindowDragRegion } from "@/shared/ui/StartupWindowDragRegion";

export function MigrationFailedScreen() {
  const systemColorScheme = useSystemColorScheme();
  const [isRetrying, setIsRetrying] = useState(false);
  const [retryFailed, setRetryFailed] = useState(false);

  const retry = async () => {
    setIsRetrying(true);
    setRetryFailed(false);
    try {
      await retryStartupMigration();
      await relaunch();
    } catch {
      setRetryFailed(true);
      setIsRetrying(false);
    }
  };

  return (
    <div
      className="ambush-onboarding-neutral-theme ambush-startup-shell flex items-center justify-center bg-background px-4 py-8 text-foreground"
      data-system-color-scheme={systemColorScheme}
      data-testid="migration-failed"
    >
      <StartupWindowDragRegion />
      <div className="relative flex w-full max-w-[500px] flex-col items-center text-center">
        <h1 className="text-3xl font-semibold tracking-tight">
          Your data needs repair
        </h1>
        <p className="mt-3 text-sm leading-6 text-muted-foreground">
          Ambush could not safely finish upgrading local data. Close any older
          Ambush, Buzz, or Sprout app, confirm this account can access its app
          data and keyring, then retry.
        </p>
        {retryFailed ? (
          <p className="mt-4 text-sm text-destructive" role="alert">
            Migration still could not complete. Your identity was not changed.
          </p>
        ) : null}
        <Button
          className="mt-8 h-10 w-full max-w-[300px]"
          data-testid="retry-startup-migration"
          disabled={isRetrying}
          onClick={() => void retry()}
          type="button"
        >
          {isRetrying ? "Retrying migration…" : "Retry migration"}
        </Button>
      </div>
    </div>
  );
}
