import * as React from "react";
import { openUrl } from "@tauri-apps/plugin-opener";
import { Check, Info } from "lucide-react";

import {
  useAcpAuthMethodsQuery,
  useAcpRuntimesQueryForced,
  useConnectAcpRuntimeMutation,
  useInstallAcpRuntimeMutation,
} from "@/features/agents/hooks";
import { useInstallOutputLine } from "@/features/agents/lib/useInstallOutputLine";
import { describeResolvedCommand } from "@/features/agents/ui/agentUi";
import type { AcpAuthMethod, AcpRuntimeCatalogEntry } from "@/shared/api/types";
import {
  getInstallErrorHeadline,
  getInstallErrorMessage,
} from "@/shared/lib/installError";
import { cn } from "@/shared/lib/cn";
import { Button } from "@/shared/ui/button";
import { Card } from "@/shared/ui/card";
import { AmbushLogoMotion } from "@/shared/ui/ambush-logo/AmbushLogoMotion";
import { Spinner } from "@/shared/ui/spinner";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/shared/ui/tooltip";
import {
  getReadyOnboardingRuntimes,
  getVisibleOnboardingRuntimes,
  runtimeIsReadyForOnboarding,
} from "./onboardingRuntimeSelection";
import { ONBOARDING_PRIMARY_CTA_CLASS } from "./OnboardingChrome";
import { RuntimeErrorTooltip } from "./RuntimeErrorTooltip";
import { OnboardingFooter } from "./OnboardingFooter";
import { getRuntimeDisplayLabel, RuntimeIcon } from "./RuntimeIcon";
import {
  type OnboardingTransitionDirection,
  OnboardingSlideTransition,
} from "./OnboardingSlideTransition";
import type { SetupStepActions, SetupStepState } from "./types";

type SetupStepProps = {
  actions: SetupStepActions;
  direction: OnboardingTransitionDirection;
  onReadyRuntimeIdsChange: (runtimeIds: readonly string[]) => void;
};

type SetupStepContentProps = SetupStepProps & {
  state: SetupStepState;
};

type InstallResultState = {
  error: string | null;
  /** The one line the card shows; the full `error` stays in the tooltip. */
  headline: string | null;
  success: boolean;
};

type InstallResultsState = Record<string, InstallResultState>;

/**
 * How long a card keeps claiming an install is running before it stops and says
 * so. The backend bounds each install command at 15 minutes
 * (`INSTALL_TIMEOUT`, install_exec.rs) and runs at most a few of them, so a
 * shorter bound would call a slow-but-working install dead; this sits past it
 * so only an install that genuinely never reported back is ever surfaced as
 * one. The point is that the spinner ends at all: a card that can spin forever
 * tells the user nothing and offers them nothing to do about it.
 */
const INSTALL_NO_RESPONSE_MS = 20 * 60_000;

const INSTALL_NO_RESPONSE_MESSAGE =
  "The installer stopped reporting back. It may still be running in the background — try again in a few minutes.";

/** Stands in for the live output line until the install prints its first one. */
const INSTALL_PREPARING_TEXT = "Preparing…";

function useSetupStepState(): SetupStepState {
  const runtimesQuery = useAcpRuntimesQueryForced();
  const items = runtimesQuery.data ?? [];
  const isChecking = runtimesQuery.isFetching;
  const errorMessage =
    runtimesQuery.error instanceof Error ? runtimesQuery.error.message : null;

  return {
    runtimeProviders: {
      errorMessage,
      isChecking,
      items,
    },
  };
}

function RuntimeReadinessIndicator({
  runtime,
  ready,
}: {
  runtime: AcpRuntimeCatalogEntry;
  ready: boolean;
}) {
  // Checkmark temporarily hidden; flip to true to restore it.
  const showReadinessCheckmark = false;
  if (!ready || !showReadinessCheckmark) return null;

  return (
    <span
      aria-hidden="true"
      className="pointer-events-none absolute right-8 top-8 flex h-8 w-8 items-center justify-center rounded-full border border-foreground bg-foreground"
      data-testid={`onboarding-runtime-check-${runtime.id}`}
    >
      <Check
        className="h-4 w-4 text-background"
        data-testid={`onboarding-runtime-checkmark-${runtime.id}`}
        strokeWidth={3}
      />
    </span>
  );
}

function RuntimeStatus({
  installError,
  isInstalling,
  onInstall,
  runtime,
}: {
  installError: string | null;
  isInstalling: boolean;
  onInstall: () => void;
  runtime: AcpRuntimeCatalogEntry;
}) {
  const methodsQuery = useAcpAuthMethodsQuery(runtime.id, {
    enabled:
      runtime.availability === "available" &&
      runtime.authStatus.status === "logged_out",
  });
  const connectMutation = useConnectAcpRuntimeMutation();
  // Child rows share the surface owner's forced query state + refresh callback
  // (`useSetupStepState` owns the single force-on-mount). Each row must not
  // mount its own force effect, or onboarding entry re-runs discovery once per
  // row instead of once for the surface.
  const runtimesQuery = useAcpRuntimesQueryForced({ forceOnMount: false });
  const [isWaitingForSignIn, setIsWaitingForSignIn] = React.useState(false);
  const [didSignInCheckTimeOut, setDidSignInCheckTimeOut] =
    React.useState(false);
  const isReady = runtimeIsReadyForOnboarding(runtime);

  React.useEffect(() => {
    if (!isWaitingForSignIn || !isReady) return;
    setIsWaitingForSignIn(false);
    setDidSignInCheckTimeOut(false);
  }, [isReady, isWaitingForSignIn]);

  React.useEffect(() => {
    if (!isWaitingForSignIn) return;

    const interval = window.setInterval(() => {
      void runtimesQuery.forceRefresh();
    }, 2_000);
    const timeout = window.setTimeout(() => {
      setIsWaitingForSignIn(false);
      setDidSignInCheckTimeOut(true);
    }, 120_000);

    return () => {
      window.clearInterval(interval);
      window.clearTimeout(timeout);
    };
  }, [isWaitingForSignIn, runtimesQuery.forceRefresh]);
  const authMethods = getOnboardingAuthMethods(
    runtime,
    methodsQuery.data?.methods ?? [],
  );
  const authMethod = authMethods[0] ?? null;
  const shouldSignIn =
    runtime.availability === "available" &&
    runtime.authStatus.status === "logged_out";

  if (shouldSignIn) {
    return (
      <div className="flex flex-col items-center gap-1.5">
        <Button
          aria-label={`Sign in to ${runtime.label}`}
          className="ambush-onboarding-runtime-setup h-5 rounded-full bg-foreground/10 px-2.5 font-mono !text-badge font-normal uppercase text-foreground hover:bg-foreground/15"
          data-testid={`onboarding-runtime-instructions-${runtime.id}`}
          onClick={() => {
            if (didSignInCheckTimeOut) {
              setDidSignInCheckTimeOut(false);
              setIsWaitingForSignIn(true);
              void runtimesQuery.forceRefresh();
              return;
            }
            if (!authMethod) {
              void methodsQuery.refetch();
              return;
            }
            connectMutation.mutate(
              {
                methodId: authMethod.id,
                runtimeId: runtime.id,
              },
              {
                onSuccess: () => setIsWaitingForSignIn(true),
              },
            );
          }}
          type="button"
          variant="ghost"
        >
          {isWaitingForSignIn
            ? "CHECKING…"
            : didSignInCheckTimeOut
              ? "CHECK AGAIN"
              : "SIGN IN"}
        </Button>
        {methodsQuery.error instanceof Error ? (
          <RuntimeErrorTooltip
            className="absolute inset-x-3 bottom-2 truncate text-xs leading-4 text-destructive"
            detail="Couldn’t load sign-in options."
            label="Sign-in unavailable"
          />
        ) : null}
        {connectMutation.error instanceof Error ? (
          <RuntimeErrorTooltip
            className="absolute inset-x-3 bottom-2 truncate text-xs leading-4 text-destructive"
            detail="Couldn’t start sign-in. Try again."
            label="Sign-in failed"
          />
        ) : null}
      </div>
    );
  }

  if (isInstalling) {
    return (
      <div
        aria-label={`Installing ${runtime.label}`}
        className="flex h-5 items-center gap-2 rounded-full bg-muted px-2.5 font-mono text-badge font-normal uppercase text-foreground"
        role="status"
      >
        <Spinner className="h-3 w-3 border-2 text-foreground" />
        INSTALLING
      </div>
    );
  }

  if (runtimeIsReadyForOnboarding(runtime)) {
    // Cached readiness must not read as freshly confirmed while a warm forced
    // probe is revalidating (or has rejected) over it. `runtimesQuery` shares
    // the surface owner's forced-query state, so its fetching/error flags track
    // the in-flight recheck. Pending → a visible CHECKING… state; a warm
    // rejection → a recheck affordance (never an unqualified READY). On success
    // both clear and READY returns. Next stays gated by isChecking/errorMessage
    // in SetupStepContent, so this only governs the per-card claim.
    if (runtimesQuery.isFetching) {
      return (
        <div
          aria-label={`Rechecking ${runtime.label}`}
          className="flex h-5 items-center gap-2 rounded-full bg-muted px-2.5 font-mono text-badge font-normal uppercase text-foreground"
          data-testid={`onboarding-runtime-rechecking-${runtime.id}`}
          role="status"
        >
          <Spinner className="h-3 w-3 border-2 text-foreground" />
          CHECKING…
        </div>
      );
    }
    if (runtimesQuery.isError) {
      return (
        <Button
          aria-label={`Check ${runtime.label} again`}
          className="ambush-onboarding-runtime-setup h-5 rounded-full bg-foreground/10 px-2.5 font-mono !text-badge font-normal uppercase text-foreground hover:bg-foreground/15"
          data-testid={`onboarding-runtime-recheck-${runtime.id}`}
          onClick={() => void runtimesQuery.forceRefresh()}
          type="button"
          variant="ghost"
        >
          CHECK AGAIN
        </Button>
      );
    }
    return (
      <Tooltip>
        <TooltipTrigger asChild>
          <span
            className="inline-flex h-5 cursor-default items-center rounded-full bg-muted px-2.5 font-mono text-badge font-normal uppercase text-foreground"
            data-testid={`onboarding-runtime-ready-${runtime.id}`}
          >
            READY
          </span>
        </TooltipTrigger>
        <TooltipContent
          className="max-w-80 bg-popover text-left text-xs text-popover-foreground"
          side="top"
        >
          <RuntimeDetails runtime={runtime} />
        </TooltipContent>
      </Tooltip>
    );
  }

  if (
    runtime.availability === "available" &&
    runtime.authStatus.status === "unknown"
  ) {
    return (
      <Button
        aria-label={`Check ${runtime.label} again`}
        className="ambush-onboarding-runtime-setup h-5 rounded-full bg-foreground/10 px-2.5 font-mono !text-badge font-normal uppercase text-foreground hover:bg-foreground/15"
        disabled={runtimesQuery.isFetching}
        onClick={() => void runtimesQuery.forceRefresh()}
        type="button"
        variant="ghost"
      >
        {runtimesQuery.isFetching ? "CHECKING…" : "CHECK AGAIN"}
      </Button>
    );
  }

  const installLabel = installError ? "RETRY INSTALL" : "INSTALL";
  if (runtime.canAutoInstall) {
    return (
      <Button
        aria-label={`${installError ? "Retry installing" : "Install"} ${runtime.label}`}
        className="ambush-onboarding-runtime-setup h-5 rounded-full bg-foreground/10 px-2.5 font-mono !text-badge font-normal uppercase text-foreground hover:bg-foreground/15"
        data-testid={`onboarding-runtime-install-${runtime.id}`}
        onClick={onInstall}
        type="button"
        variant="ghost"
      >
        {installLabel}
      </Button>
    );
  }

  return (
    <Button
      aria-label={`View ${runtime.label} install instructions`}
      className="ambush-onboarding-runtime-setup h-5 rounded-full bg-foreground/10 px-2.5 font-mono !text-badge font-normal uppercase text-foreground hover:bg-foreground/15"
      data-testid={`onboarding-runtime-instructions-${runtime.id}`}
      onClick={() => void openUrl(runtime.installInstructionsUrl)}
      type="button"
      variant="ghost"
    >
      INSTALL
    </Button>
  );
}

function RuntimeDetails({ runtime }: { runtime: AcpRuntimeCatalogEntry }) {
  if (
    runtime.availability === "available" &&
    runtime.command &&
    runtime.binaryPath
  ) {
    const description = describeResolvedCommand(
      runtime.command,
      runtime.binaryPath,
    );
    return (
      <>
        <p className="text-xs leading-4 text-popover-foreground">
          {description.charAt(0).toUpperCase() + description.slice(1)}
        </p>
        {runtime.defaultArgs.length > 0 ? (
          <p className="mt-1 text-xs leading-4 text-popover-foreground">
            Args:{" "}
            <code className="font-mono">{runtime.defaultArgs.join(", ")}</code>
          </p>
        ) : null}
      </>
    );
  }

  if (runtime.availability === "adapter_missing") {
    return (
      <>
        <p className="text-xs leading-4 text-popover-foreground">
          CLI detected; ACP adapter missing.
        </p>
        <p className="mt-1 text-xs leading-4 text-popover-foreground">
          {runtime.installHint}
        </p>
      </>
    );
  }

  if (runtime.availability === "adapter_outdated") {
    return (
      <>
        <p className="text-xs leading-4 text-popover-foreground">
          ACP adapter detected but outdated — reinstall required.
        </p>
        <p className="mt-1 text-xs leading-4 text-popover-foreground">
          This updates the machine-global{" "}
          <code className="rounded bg-foreground/10 px-0.5 font-mono text-xs text-popover-foreground">
            codex-acp
          </code>{" "}
          adapter. Older Ambush releases using the legacy adapter contract may
          lose community access until{" "}
          <code className="rounded bg-foreground/10 px-0.5 font-mono text-xs text-popover-foreground">
            @zed-industries/codex-acp@0.16.0
          </code>{" "}
          is restored.
        </p>
        <p className="mt-1 text-xs leading-4 text-popover-foreground">
          {runtime.installHint}
        </p>
      </>
    );
  }

  if (runtime.availability === "cli_missing") {
    return (
      <>
        <p className="text-xs leading-4 text-popover-foreground">
          ACP adapter detected; CLI missing.
        </p>
        <p className="mt-1 text-xs leading-4 text-popover-foreground">
          {runtime.installHint}
        </p>
      </>
    );
  }

  return (
    <>
      <p className="text-xs leading-4 text-popover-foreground">
        Not installed yet.
      </p>
      <p className="mt-1 text-xs leading-4 text-popover-foreground">
        {runtime.installHint}
      </p>
    </>
  );
}

function runtimeDetailText(runtime: AcpRuntimeCatalogEntry): string {
  if (
    runtime.availability === "available" &&
    runtime.command &&
    runtime.binaryPath
  ) {
    const description = describeResolvedCommand(
      runtime.command,
      runtime.binaryPath,
    );
    return description.charAt(0).toUpperCase() + description.slice(1);
  }
  if (runtime.availability === "adapter_missing") {
    return "CLI detected; ACP adapter missing.";
  }
  if (runtime.availability === "adapter_outdated") {
    return "ACP adapter detected but outdated — reinstall required.";
  }
  if (
    runtime.availability === "cli_missing" ||
    runtime.availability === "not_installed"
  ) {
    return "CLI not detected.";
  }
  return "";
}

function isSupportedOnboardingAuthMethod(
  runtime: AcpRuntimeCatalogEntry,
  method: AcpAuthMethod,
) {
  if (runtime.id !== "codex") return true;
  return !/api[-_ ]?key/i.test(`${method.id} ${method.name}`);
}

function isPreferredClaudeAuthMethod(method: AcpAuthMethod) {
  const haystack = [
    method.id,
    method.name,
    method.description ?? "",
    method.command.join(" "),
    method.args.join(" "),
  ]
    .join(" ")
    .toLowerCase();
  return (
    haystack.includes("claudeai") ||
    haystack.includes("claude ai") ||
    haystack.includes("claude.ai") ||
    haystack.includes("subscription")
  );
}

function getOnboardingAuthMethods(
  runtime: AcpRuntimeCatalogEntry,
  methods: AcpAuthMethod[],
) {
  const supported = methods.filter((method) =>
    isSupportedOnboardingAuthMethod(runtime, method),
  );

  if (runtime.id === "claude") {
    const preferred =
      supported.find(isPreferredClaudeAuthMethod) ?? supported[0];
    return preferred ? [preferred] : [];
  }

  if (runtime.id === "codex") {
    return supported.slice(0, 1);
  }

  return supported;
}

function RuntimeAuthError({ runtime }: { runtime: AcpRuntimeCatalogEntry }) {
  if (runtime.authStatus.status === "config_invalid") {
    return (
      <RuntimeErrorTooltip
        className="absolute inset-x-3 bottom-2 truncate text-xs leading-4 text-destructive"
        detail="Check this runtime’s configuration and try again."
        label="Configuration invalid"
      />
    );
  }
  if (
    runtime.availability === "available" &&
    runtime.authStatus.status === "unknown"
  ) {
    return (
      <RuntimeErrorTooltip
        className="absolute inset-x-3 bottom-2 truncate text-xs leading-4 text-destructive"
        detail="Couldn’t verify authentication."
        label="Status unavailable"
      />
    );
  }
  return null;
}

function RuntimeCard({
  installResults,
  onInstallResultsChange,
  runtime,
}: {
  installResults: InstallResultsState;
  onInstallResultsChange: React.Dispatch<
    React.SetStateAction<InstallResultsState>
  >;
  runtime: AcpRuntimeCatalogEntry;
}) {
  // Each card owns its own mutation instance so concurrent installs on
  // different cards each track their own isPending state and callbacks
  // independently (react-query v5 per-mutate callbacks only fire for the
  // latest mutate() call on a shared instance, silently dropping earlier ones).
  const installMutation = useInstallAcpRuntimeMutation();
  const installError = installResults[runtime.id]?.error ?? null;
  const installHeadline = installResults[runtime.id]?.headline ?? null;
  // The card's own claim, not the mutation's: an install whose answer never
  // arrives leaves `isPending` set for the life of the surface, and a spinner
  // with no end is the one state the card must not be able to reach. The
  // deadline is per click, so a retry is bounded on its own terms rather than
  // inheriting whatever was left of the first attempt's.
  const [installStopped, setInstallStopped] = React.useState(false);
  const [installDeadline, setInstallDeadline] = React.useState<number | null>(
    null,
  );
  const isInstalling = installMutation.isPending && !installStopped;
  const installOutputLine = useInstallOutputLine(runtime.id, isInstalling);
  const isAvailable = runtime.availability === "available";
  const isReady = runtimeIsReadyForOnboarding(runtime);
  const runtimeId = runtime.id;

  React.useEffect(() => {
    if (installDeadline === null) return;
    const timer = window.setTimeout(
      () => {
        setInstallStopped(true);
        onInstallResultsChange((current) => ({
          ...current,
          [runtimeId]: {
            error: INSTALL_NO_RESPONSE_MESSAGE,
            headline: INSTALL_NO_RESPONSE_MESSAGE,
            success: false,
          },
        }));
      },
      Math.max(0, installDeadline - Date.now()),
    );
    return () => window.clearTimeout(timer);
  }, [installDeadline, onInstallResultsChange, runtimeId]);

  function handleInstall() {
    setInstallStopped(false);
    setInstallDeadline(Date.now() + INSTALL_NO_RESPONSE_MS);
    onInstallResultsChange((current) => ({
      ...current,
      [runtime.id]: { error: null, headline: null, success: false },
    }));

    installMutation.mutate(runtime.id, {
      onSuccess: (result) => {
        setInstallDeadline(null);
        onInstallResultsChange((current) => ({
          ...current,
          [runtime.id]: result.success
            ? { error: null, headline: null, success: true }
            : {
                error: getInstallErrorMessage(result),
                headline: getInstallErrorHeadline(result),
                success: false,
              },
        }));
      },
      onError: (error) => {
        setInstallDeadline(null);
        const message =
          error instanceof Error ? error.message : "Install failed.";
        onInstallResultsChange((current) => ({
          ...current,
          [runtime.id]: {
            error: message,
            // A rejected invoke never produced a step, so the message is the
            // command's own error rather than an installer's output — the card
            // can show it as-is.
            headline: message,
            success: false,
          },
        }));
      },
    });
  }

  return (
    <Card
      className={cn(
        "group relative flex h-[224px] w-full max-w-[288px] select-none flex-col items-center justify-center px-3 py-1.5 text-center",
        installError && "border-destructive",
        // A ready runtime reads as a plate one step brighter than the rest.
        isReady && "bg-accent",
      )}
      data-ready={isReady ? "true" : "false"}
      data-testid={`onboarding-runtime-${runtime.id}`}
    >
      <RuntimeReadinessIndicator ready={isReady} runtime={runtime} />

      <div className="flex min-w-0 flex-col items-center gap-2.5">
        <div className="flex min-w-0 items-center justify-center gap-3">
          <RuntimeIcon className="h-7 w-7" runtime={runtime} />
          <h2 className="truncate text-sm font-normal leading-5 text-foreground">
            {getRuntimeDisplayLabel(runtime)}
          </h2>
        </div>
        <RuntimeStatus
          installError={installError}
          isInstalling={isInstalling}
          onInstall={handleInstall}
          runtime={runtime}
        />
        {isInstalling ? (
          // Takes the detail text's slot rather than adding a row: the card is
          // fixed-height, and during an install the live line is the more
          // useful of the two. It holds the slot even before the first line
          // arrives, because the alternative — the pre-install detail text —
          // still says the adapter is missing while Ambush is installing it.
          <p
            aria-live="polite"
            className="max-w-[13rem] truncate font-mono text-2xs leading-4 text-muted-foreground"
            data-testid={`onboarding-runtime-install-output-${runtime.id}`}
          >
            {installOutputLine ?? INSTALL_PREPARING_TEXT}
          </p>
        ) : !isAvailable && runtimeDetailText(runtime) ? (
          <p
            aria-hidden={installError ? "true" : undefined}
            className={cn(
              "max-w-[13rem] text-2xs leading-4 text-muted-foreground",
              installError && "invisible",
            )}
          >
            {runtimeDetailText(runtime)}
          </p>
        ) : null}
      </div>
      {installError ? (
        <RuntimeErrorTooltip
          className="absolute inset-x-3 bottom-2 flex min-w-0 items-center justify-center gap-1.5 overflow-hidden whitespace-nowrap text-xs leading-4 text-destructive"
          detail={installError}
          // A hint is Ambush's own sentence about what to do next, so it can be
          // read at a glance; a step's raw output cannot, and stays behind the
          // tooltip.
          label={installHeadline ?? "Installation failed"}
          showIcon
          testId={`onboarding-runtime-error-${runtime.id}`}
        />
      ) : (
        <RuntimeAuthError runtime={runtime} />
      )}
    </Card>
  );
}

function RuntimeProvidersLoadingState() {
  return (
    <div
      aria-live="polite"
      className="flex min-h-[260px] w-full items-center justify-center"
      data-testid="onboarding-runtime-loading"
      role="status"
    >
      <div className="flex flex-col items-center text-foreground opacity-35">
        <AmbushLogoMotion className="h-auto w-16" />
        <p className="mt-5 text-2xl font-normal leading-8">
          Finding your providers...
        </p>
      </div>
    </div>
  );
}

function RuntimeProvidersSection({
  installResults,
  navigateToAgentSettings,
  onInstallResultsChange,
  runtimeProviders,
}: {
  installResults: InstallResultsState;
  navigateToAgentSettings?: () => void;
  onInstallResultsChange: React.Dispatch<
    React.SetStateAction<InstallResultsState>
  >;
  runtimeProviders: SetupStepState["runtimeProviders"];
}) {
  const { errorMessage, isChecking, items } = runtimeProviders;
  const orderedItems = getVisibleOnboardingRuntimes(items);

  return (
    <section className="flex min-h-full w-full flex-col items-center">
      <div className="w-full max-w-[820px] text-center">
        <h1 className="text-title font-normal text-foreground">
          Set up your agent harnesses
        </h1>
        <p className="mx-auto mt-3 max-w-[760px] text-sm leading-6 text-foreground/90">
          Ambush checks for command-line harnesses on this machine. Install the
          CLI or sign in to at least one to continue.
        </p>
      </div>

      <div className="flex w-full flex-1 flex-col items-center justify-center gap-8 py-10">
        {orderedItems.length > 0 ? (
          <div className="grid min-w-0 w-full max-w-[1200px] grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-4">
            {orderedItems.map((runtime) => (
              <RuntimeCard
                installResults={installResults}
                key={runtime.id}
                onInstallResultsChange={onInstallResultsChange}
                runtime={runtime}
              />
            ))}
          </div>
        ) : isChecking ? (
          <RuntimeProvidersLoadingState />
        ) : errorMessage ? null : (
          <p
            className="max-w-[560px] rounded-2xl bg-muted px-6 py-6 text-sm text-muted-foreground"
            data-testid="onboarding-acp-empty"
          >
            No supported command-line harnesses were detected yet. Install a
            supported CLI, then check again.
          </p>
        )}

        {errorMessage ? (
          <p
            className="max-w-[560px] rounded-2xl bg-destructive/10 px-6 py-3 text-sm text-destructive"
            data-testid="onboarding-setup-error"
          >
            {errorMessage}
          </p>
        ) : null}

        <p className="mx-auto flex max-w-[440px] items-start justify-center gap-1.5 text-center text-xs leading-5 text-[var(--ambush-onboarding-backup-ink)]">
          <Info aria-hidden className="mt-0.5 h-3.5 w-3.5 shrink-0" />
          <span>
            More harnesses (Cursor, Grok, Amp&hellip;){" "}
            {navigateToAgentSettings ? (
              <button
                className="underline underline-offset-2 hover:text-foreground"
                data-testid="onboarding-setup-more-harnesses"
                onClick={navigateToAgentSettings}
                type="button"
              >
                Settings → Agents
              </button>
            ) : (
              <span>Settings → Agents</span>
            )}{" "}
            after setup.
          </span>
        </p>
      </div>
    </section>
  );
}

function SetupStepContent({
  actions,
  direction,
  onReadyRuntimeIdsChange,
  state,
}: SetupStepContentProps) {
  const { runtimeProviders } = state;
  const [installResults, setInstallResults] =
    React.useState<InstallResultsState>({});
  const readyRuntimeIds = React.useMemo(
    () =>
      getReadyOnboardingRuntimes(runtimeProviders.items).map(
        (runtime) => runtime.id,
      ),
    [runtimeProviders.items],
  );
  const readyRuntimeIdsKey = readyRuntimeIds.join("\0");
  // The key prevents catalog object refreshes from creating an effect loop
  // when the detected ready IDs have not changed.
  // biome-ignore lint/correctness/useExhaustiveDependencies: keyed by ID content
  React.useEffect(() => {
    onReadyRuntimeIdsChange(readyRuntimeIds);
  }, [onReadyRuntimeIdsChange, readyRuntimeIdsKey]);

  return (
    <OnboardingSlideTransition
      className="flex min-h-full w-full flex-col items-center"
      data-testid="onboarding-page-2"
      direction={direction}
      transitionKey={`setup-${direction}`}
    >
      <RuntimeProvidersSection
        installResults={installResults}
        navigateToAgentSettings={actions.navigateToAgentSettings}
        onInstallResultsChange={setInstallResults}
        runtimeProviders={runtimeProviders}
      />

      <OnboardingFooter>
        <Button
          className={`${ONBOARDING_PRIMARY_CTA_CLASS} text-sm`}
          data-testid="onboarding-setup-next"
          disabled={
            readyRuntimeIds.length === 0 ||
            runtimeProviders.isChecking ||
            !!runtimeProviders.errorMessage
          }
          onClick={() => actions.next(readyRuntimeIds)}
          type="button"
        >
          Next
        </Button>
        <Button
          className="h-9 whitespace-nowrap rounded-full px-6 text-sm hover:bg-foreground/10"
          data-testid="onboarding-setup-skip"
          onClick={() => actions.next([])}
          type="button"
          variant="ghost"
        >
          Skip for now
        </Button>
      </OnboardingFooter>
    </OnboardingSlideTransition>
  );
}

export function SetupStep({
  actions,
  direction,
  onReadyRuntimeIdsChange,
}: SetupStepProps) {
  const state = useSetupStepState();
  return (
    <SetupStepContent
      actions={actions}
      direction={direction}
      onReadyRuntimeIdsChange={onReadyRuntimeIdsChange}
      state={state}
    />
  );
}
