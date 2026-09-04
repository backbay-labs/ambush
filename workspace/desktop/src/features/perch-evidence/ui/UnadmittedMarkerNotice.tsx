import * as React from "react";

import { countUnadmittedMarker } from "../lib/admittedIssuers";

/**
 * One line beside the prose for a well-formed marker whose signer is not an
 * admitted bridge identity. Not a card: a refusal card is a signal an
 * adversary could plant at will. The message stays visible as text, because
 * dropping it silently would hide a live attempt from the person best placed
 * to notice it, and it is counted once per event id in
 * `perch_marker_unadmitted_total`.
 */
export function UnadmittedMarkerNotice({
  slug,
  eventId,
}: {
  slug: string;
  eventId: string;
}) {
  React.useEffect(() => {
    countUnadmittedMarker(eventId);
  }, [eventId]);
  return (
    <p
      data-testid="perch-unadmitted-marker-notice"
      className="text-2xs text-[hsl(var(--perch-foreground-muted))]"
    >
      This message carries a {slug} card marker from a signer this console does
      not admit. It is shown as text and counted.
    </p>
  );
}
