import type { SwarmMarkerCard, SwarmMarkerKind } from "../lib/markerTypes";

/**
 * The presenter for the six kinds this milestone does not render, so the
 * registry stays exhaustive and honest: an admitted, well-formed card of a
 * kind the console cannot yet draw says so, rather than falling through to
 * markdown with a JSON payload in it.
 */
export function NotYetRenderedCard({
  kind,
  card,
}: {
  kind: SwarmMarkerKind;
  card: SwarmMarkerCard;
}) {
  return (
    <p
      data-testid="perch-evidence-not-yet-rendered"
      data-perch-role="evidence-card"
      role="status"
      className="my-1 rounded border-l-4 border-[hsl(var(--perch-border-strong))] bg-[hsl(var(--perch-card))] px-3 py-2 text-sm text-[hsl(var(--perch-foreground))]"
    >
      This console does not yet render {kind} cards. The daemon holds the
      record.{" "}
      <span className="text-2xs text-[hsl(var(--perch-foreground-muted))]">
        event {card.eventId.slice(0, 8)}
      </span>
    </p>
  );
}
