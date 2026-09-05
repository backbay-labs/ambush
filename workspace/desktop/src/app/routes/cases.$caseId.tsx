import * as React from "react";
import { createFileRoute, Navigate } from "@tanstack/react-router";

import { useChannelsQuery } from "@/features/channels/hooks";
import { CaseScreen } from "@/features/perch-evidence/ui/CaseScreen";
import { SwarmCardSurfaceProvider } from "@/features/perch-evidence/ui/SwarmCardSurface";
import { useTerminalContextOverride } from "@/app/TerminalContextOverrideContext";
import { useCaseTerminalPin } from "@/features/terminal/useTerminalCaseScope";
import {
  useFeatureEnabled,
  usePreviewFeatureWarning,
} from "@/shared/features/useFeatureEnabled";
import { useNow } from "@/shared/lib/useNow";
import { ViewLoadingFallback } from "@/shared/ui/ViewLoadingFallback";

const ChannelRouteScreen = React.lazy(async () => {
  const module = await import("./ChannelRouteScreen");
  return { default: module.ChannelRouteScreen };
});

/**
 * How long the route keeps asking the relay for the case channel before it
 * says the channel never arrived. The bridge creates the channel when the
 * daemon publishes `CasePromoted`; a minute is far past its steady-state
 * tick, so a timeout here is a real fault, not slowness.
 */
const CASE_OPEN_TIMEOUT_MS = 60_000;
const CASE_OPEN_POLL_MS = 1_000;

export const Route = createFileRoute("/cases/$caseId")({
  component: CaseRouteComponent,
});

function CaseRouteComponent() {
  const { caseId } = Route.useParams();
  const enabled = useFeatureEnabled("perch");
  usePreviewFeatureWarning("perch");
  // A shell spawned while this case is open runs under the case's own
  // directory, so swarmctl's relative `data/…` defaults land there and every
  // artifact is attributable to the case by path. Cleared on unmount: a banner
  // naming a case the screen no longer shows is worse than an unpinned shell.
  useCaseTerminalPin(enabled ? caseId : null, caseId.slice(0, 8));
  // A case is a channel, but the terminal's context comes from the channel
  // route; without this override ⌘J on a case is inert. The pin above scopes
  // the shell; this gives it somewhere to spawn.
  const terminalContext = React.useMemo(
    () =>
      enabled
        ? { channelId: caseId, channelName: `case-${caseId.slice(0, 8)}` }
        : null,
    [enabled, caseId],
  );
  useTerminalContextOverride(terminalContext);
  if (!enabled) {
    return (
      <Navigate to="/channels/$channelId" params={{ channelId: caseId }} />
    );
  }
  return (
    <SwarmCardSurfaceProvider surface="case" caseChannelId={caseId}>
      <CaseOpening caseId={caseId}>
        <CaseTabs caseId={caseId}>
          <div data-testid="perch-case-timeline" className="contents">
            <React.Suspense
              fallback={<ViewLoadingFallback includeHeader kind="channel" />}
            >
              <ChannelRouteScreen
                autoSendDraftKey={null}
                channelId={caseId}
                searchHighlight={null}
                selectedPostId={null}
                targetMessageId={null}
                targetReplyId={null}
                targetThreadRootId={null}
              />
            </React.Suspense>
          </div>
        </CaseTabs>
      </CaseOpening>
    </SwarmCardSurfaceProvider>
  );
}

/**
 * Holds the channel screen back until the case channel is in the channel
 * list. A case is opened from a finding card the moment the daemon mints it,
 * which can be before the bridge has created the channel; rendering the
 * channel screen against an unknown channel would show a "channel not
 * found" state for a channel that is about to exist.
 */
function CaseOpening({
  caseId,
  children,
}: {
  caseId: string;
  children: React.ReactNode;
}) {
  const channels = useChannelsQuery();
  // `refetch` is the stable member of the query result; the result object
  // itself is a new identity every render (CLAUDE.md gotcha 6).
  const { refetch } = channels;
  const known = (channels.data ?? []).some((c) => c.id === caseId);
  const [startedAt] = React.useState(() => Date.now());
  const [timedOut, setTimedOut] = React.useState(false);
  React.useEffect(() => {
    if (known) return;
    const id = window.setInterval(() => {
      void refetch();
      if (Date.now() - startedAt > CASE_OPEN_TIMEOUT_MS) setTimedOut(true);
    }, CASE_OPEN_POLL_MS);
    return () => window.clearInterval(id);
  }, [known, startedAt, refetch]);
  if (known) return children;
  if (timedOut) {
    return (
      <p
        data-testid="perch-case-not-found"
        className="p-4 text-sm text-[hsl(var(--perch-foreground-muted))]"
      >
        The daemon promoted this finding, but no case channel arrived in 60
        seconds. The bridge creates it; check the daemon log for "case channel
        created".
      </p>
    );
  }
  return (
    <p
      data-testid="perch-case-opening"
      role="status"
      className="p-4 text-sm text-[hsl(var(--perch-foreground-muted))]"
    >
      Opening the case. The bridge is creating its channel.
    </p>
  );
}

/**
 * The case's tabs around its channel timeline. `CaseScreen` existed and was
 * mounted nowhere, so the Canvas tab and the TTL clock could not be reached.
 *
 * The TTL deadline and the archive state come off the channel record the
 * relay serves; the operator can edit the canvas of a live case they were
 * addressed into (the relay refuses a write it does not allow, and the tab
 * shows that refusal rather than a saved-looking empty canvas).
 */
function CaseTabs({
  caseId,
  children,
}: {
  caseId: string;
  children: React.ReactNode;
}): React.ReactElement {
  const channels = useChannelsQuery();
  const channel = channels.data?.find((entry) => entry.id === caseId) ?? null;
  const isArchived = channel?.archivedAt != null;
  const nowMs = useNow(60_000);
  return (
    <CaseScreen
      caseChannelId={caseId}
      canEdit={channel !== null && !isArchived}
      isArchived={isArchived}
      ttlDeadline={channel?.ttlDeadline ?? null}
      nowMs={nowMs}
      timeline={children}
    />
  );
}
