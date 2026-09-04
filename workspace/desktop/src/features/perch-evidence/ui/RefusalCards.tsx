import type * as React from "react";

import type {
  SwarmCardSurfaceKind,
  SwarmMarkerCard,
  SwarmMarkerKind,
} from "../lib/markerTypes";

/**
 * The four refusal states (17-COMPONENT-SPECS.md §3.6). Each names the event
 * id and offers no verdict control. None carries `aria-live`: a timeline
 * replay would otherwise read every refusal aloud. The fifth outcome,
 * `unadmitted-issuer`, is not a card at all; `UnadmittedMarkerNotice` is the
 * one line it renders beside the prose.
 */

type RefusalShellProps = {
  testId: string;
  eventId: string;
  children: React.ReactNode;
};

function RefusalShell({ testId, eventId, children }: RefusalShellProps) {
  return (
    <p
      data-testid={testId}
      data-perch-role="evidence-card"
      role="status"
      className="my-1 rounded border-l-4 border-[hsl(var(--perch-border-strong))] bg-[hsl(var(--perch-card))] px-3 py-2 text-sm text-[hsl(var(--perch-foreground))]"
    >
      {children}{" "}
      <span className="text-2xs text-[hsl(var(--perch-foreground-muted))]">
        event {eventId.slice(0, 8)}
      </span>
    </p>
  );
}

/** The decoder returned `ok: false`. */
export function UndecodableCard({
  card,
  reason,
}: {
  card: SwarmMarkerCard;
  reason: string;
}) {
  return (
    <RefusalShell testId="perch-evidence-undecodable" eventId={card.eventId}>
      This {card.kind} card did not decode: {reason}. The daemon holds the
      record.
    </RefusalShell>
  );
}

/** Admitted issuer, unknown slug. The slug is regex-bounded to `[a-z][a-z-]*`. */
export function UnknownMarkerCard({
  slug,
  version,
  card,
}: {
  slug: string;
  version: number;
  card: Omit<SwarmMarkerCard, "kind" | "version">;
}) {
  return (
    <RefusalShell testId="perch-evidence-unknown-kind" eventId={card.eventId}>
      This console does not know how to render a swarm:{slug}:v{version} card.
      It was published by an admitted bridge; the daemon holds the record.
    </RefusalShell>
  );
}

/** Admitted issuer, known kind, `version !== 1`. */
export function UnsupportedVersionCard({
  kind,
  version,
  card,
}: {
  kind: SwarmMarkerKind;
  version: number;
  card: Omit<SwarmMarkerCard, "kind" | "version">;
}) {
  return (
    <RefusalShell
      testId="perch-evidence-unsupported-version"
      eventId={card.eventId}
    >
      This {kind} card is version {version}; this console reads version 1.
      Nothing is rendered rather than rendering it wrong.
    </RefusalShell>
  );
}

/** A `homeSurface` miss, or INV-13's channel mismatch on a case surface. */
export function MisplacedCard({
  card,
  surface,
  reason,
}: {
  card: SwarmMarkerCard;
  surface: SwarmCardSurfaceKind;
  reason?: "channel-mismatch";
}) {
  return (
    <RefusalShell testId="perch-evidence-misplaced" eventId={card.eventId}>
      A {card.kind} card arrived on a surface that does not hold them ({surface}
      ). It is not rendered here.
      {reason === "channel-mismatch" ? (
        <>
          {" "}
          <span data-testid="perch-channel-mismatch-notice">
            tagged for channel {card.channelTag ?? "none"}
          </span>
        </>
      ) : null}
    </RefusalShell>
  );
}
