import type * as React from "react";

import type { GapBlock } from "@/features/perch/wire";
import { truncatePubkey } from "@/shared/lib/pubkey";

import type { PerchPillar, SwarmMarkerKind } from "../lib/markerTypes";
import { GapNotice } from "./GapNotice";

/**
 * The only verification claim a tier-0 card may make, verbatim. It names the
 * chain that was checked (the relay's transport signature), says what was
 * not, and points at the record. Never "verified", never a check mark.
 */
export const TIER_0_BADGE =
  "secp256k1 · tier 0 · TRANSPORT-SIGNED ONLY · the daemon is the record";

/** The rendered heading per kind. `lease` never renders bare (appendix §7). */
function eyebrowFor(kind: SwarmMarkerKind): string {
  return kind === "lease" ? "CONTAINMENT LEASE" : kind.toUpperCase();
}

/**
 * The rail, eyebrow, tier badge, gap notice and provenance footer every
 * card presenter renders inside. The rail is the classifying channel; the
 * pillar rides `data-perch-pillar` so a stylesheet can colour it without a
 * presenter ever naming a hex.
 */
export function EvidenceCardFrame({
  kind,
  pillar,
  eventId,
  issuerPubkey,
  tier,
  gap,
  children,
}: {
  kind: SwarmMarkerKind;
  pillar: PerchPillar;
  eventId: string;
  issuerPubkey: string;
  tier: 0 | 1 | 2;
  gap?: GapBlock;
  children: React.ReactNode;
}) {
  return (
    <article
      data-testid="perch-evidence-frame"
      data-perch-role="evidence-card"
      data-perch-pillar={pillar}
      role="status"
      className="my-1 rounded border-l-4 border-[hsl(var(--perch-border-strong))] bg-[hsl(var(--perch-card))] px-3 py-2 text-[hsl(var(--perch-foreground))]"
    >
      <header className="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-1">
        <span className="text-2xs font-semibold uppercase tracking-wide">
          {eyebrowFor(kind)}
        </span>
        {tier === 0 ? (
          <span
            data-testid="perch-tier-badge"
            className="text-2xs uppercase tracking-wide text-[hsl(var(--perch-foreground-muted))]"
          >
            {TIER_0_BADGE}
          </span>
        ) : null}
      </header>
      {gap ? <GapNotice gap={gap} /> : null}
      {children}
      <footer className="mt-1 text-2xs text-[hsl(var(--perch-foreground-muted))]">
        event {eventId.slice(0, 8)} · signer {truncatePubkey(issuerPubkey)}
      </footer>
    </article>
  );
}
