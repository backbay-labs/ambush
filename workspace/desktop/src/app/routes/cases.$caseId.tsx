import * as React from "react";
import { createFileRoute, Navigate } from "@tanstack/react-router";

import { useChannelsQuery } from "@/features/channels/hooks";
import { SwarmCardSurfaceProvider } from "@/features/perch-evidence/ui/SwarmCardSurface";
import {
  useFeatureEnabled,
  usePreviewFeatureWarning,
} from "@/shared/features/useFeatureEnabled";
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
  if (!enabled) {
    return (
      <Navigate to="/channels/$channelId" params={{ channelId: caseId }} />
    );
  }
  return (
    <SwarmCardSurfaceProvider surface="case" caseChannelId={caseId}>
      <CaseOpening caseId={caseId}>
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
