import type * as React from "react";

import type {
  PerchPillar,
  SwarmCardDecoder,
  SwarmCardEntry,
  SwarmCardProps,
  SwarmCardSurfaceKind,
} from "../lib/markerTypes";
import { UndecodableCard } from "./RefusalCards";

/**
 * The one place a decoder's output and a presenter's input are checked
 * against each other. The payload type never escapes, which is what keeps
 * `SWARM_CARD_REGISTRY` a plain `Record`. Lives in its own module so a card
 * presenter can import it without a cycle through the registry that imports
 * the presenter.
 */
export function defineSwarmCard<T>(spec: {
  pillar: PerchPillar;
  homeSurface: readonly SwarmCardSurfaceKind[];
  decode: SwarmCardDecoder<T>;
  Presenter: React.ComponentType<SwarmCardProps<T>>;
}): SwarmCardEntry {
  const { decode, Presenter, pillar, homeSurface } = spec;
  return {
    pillar,
    homeSurface,
    render: ({ card, ctx }) => {
      const decoded = decode(card);
      if (!decoded.ok) {
        return <UndecodableCard card={card} reason={decoded.reason} />;
      }
      return <Presenter card={card} ctx={ctx} payload={decoded.value} />;
    },
  };
}
