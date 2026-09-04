import type { GapBlock } from "@/features/perch/wire";

/**
 * Loss the bridge observed before a card, rendered beside it. The gap rides
 * inside the same signed envelope as the card so it cannot be lost on its
 * own; this is the one place it is said out loud, in words that name what
 * can and cannot be recovered.
 */
export function GapNotice({ gap }: { gap: GapBlock }) {
  return (
    <p
      data-testid="perch-gap-notice"
      role="status"
      className="text-2xs text-[hsl(var(--perch-foreground-muted))]"
    >
      {gapSentence(gap)}
    </p>
  );
}

function gapSentence(gap: GapBlock): string {
  if (gap.cause === "broadcast_lagged") {
    return `${gap.count ?? 0} events were lost before the bridge saw them (the runtime's broadcast lagged). Nothing between the previous card and this one can be recovered from the relay; the daemon holds its own record.`;
  }
  const verb =
    gap.cause === "spool_evicted"
      ? "evicted from"
      : gap.cause === "spool_torn_tail"
        ? "torn from"
        : "expired in";
  return `Cards ${gap.from_seq ?? "?"}–${gap.to_seq ?? "?"} from this issuer were ${verb} the bridge spool and cannot be delivered.`;
}
