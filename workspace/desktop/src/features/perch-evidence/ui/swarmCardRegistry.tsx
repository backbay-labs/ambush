import type {
  PerchPillar,
  SwarmCardContext,
  SwarmCardEntry,
  SwarmCardSurfaceKind,
  SwarmMarkerKind,
  SwarmMarkerParse,
} from "../lib/markerTypes";
import { findingCardEntry } from "./cards/FindingCard";
import { holdCardEntry } from "./cards/HoldCard";
import { verdictCardEntry } from "./cards/VerdictCard";
import { NotYetRenderedCard } from "./NotYetRenderedCard";
import {
  MisplacedCard,
  UnknownMarkerCard,
  UnsupportedVersionCard,
} from "./RefusalCards";

export { defineSwarmCard } from "./defineSwarmCard";

/**
 * The seven-entry registry (17-COMPONENT-SPECS.md §3.5). `satisfies
 * Record<SwarmMarkerKind, SwarmCardEntry>` is the exhaustiveness gate: a
 * union member without an entry fails `tsc --noEmit`. The four kinds The hold
 * does not produce render an honest "not yet" rather than an empty presenter.
 */

function notYetRendered(
  kind: SwarmMarkerKind,
  pillar: PerchPillar,
  homeSurface: readonly SwarmCardSurfaceKind[],
  maxTier: 0 | 1 | 2,
): SwarmCardEntry {
  return {
    pillar,
    homeSurface,
    maxTier,
    render: ({ card }) => <NotYetRenderedCard kind={kind} card={card} />,
  };
}

export const SWARM_CARD_REGISTRY = {
  finding: findingCardEntry,
  escalation: notYetRendered("escalation", "authority", ["case", "lane"], 2),
  hold: holdCardEntry,
  verdict: verdictCardEntry,
  receipt: notYetRendered("receipt", "evidence", ["case"], 2),
  lease: notYetRendered("lease", "evidence", ["case"], 2),
  rollback: notYetRendered("rollback", "evidence", ["case"], 1),
} satisfies Record<SwarmMarkerKind, SwarmCardEntry>;

/** Every parse outcome that renders a card or a refusal; never prose. */
export type SwarmCardParse = Exclude<
  SwarmMarkerParse,
  { status: "not-a-marker" } | { status: "unadmitted-issuer" }
>;

/**
 * The dispatcher. Refusals first (unknown kind, unsupported version), then
 * the surface check, then INV-13's channel check on a case surface, then the
 * entry's own decode-and-present.
 */
export function SwarmEvidenceCard({
  parsed,
  ctx,
}: {
  parsed: SwarmCardParse;
  ctx: SwarmCardContext;
}) {
  if (parsed.status === "unknown-kind") {
    return (
      <UnknownMarkerCard
        slug={parsed.slug}
        version={parsed.version}
        card={parsed.card}
      />
    );
  }
  if (parsed.status === "unsupported-version") {
    return (
      <UnsupportedVersionCard
        kind={parsed.kind}
        version={parsed.version}
        card={parsed.card}
      />
    );
  }
  const { card } = parsed;
  const entry = SWARM_CARD_REGISTRY[card.kind];
  if (!entry.homeSurface.includes(ctx.surface)) {
    return <MisplacedCard card={card} surface={ctx.surface} />;
  }
  if (ctx.surface === "case" && card.channelTag !== ctx.caseChannelId) {
    return (
      <MisplacedCard
        card={card}
        surface={ctx.surface}
        reason="channel-mismatch"
      />
    );
  }
  return entry.render({ card, ctx });
}
