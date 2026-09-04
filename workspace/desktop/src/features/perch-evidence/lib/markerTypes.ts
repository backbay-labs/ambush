import type * as React from "react";

/**
 * The closed marker vocabulary and the parse/registry types behind every
 * swarm card (17-COMPONENT-SPECS.md §3.3, with `ambush` → `swarm` per D1).
 *
 * Pure types plus one string builder. `defineSwarmCard` lives beside the
 * registry in `ui/swarmCardRegistry.tsx` so this module stays testable under
 * `node:test` without a JSX transform.
 */

/**
 * The seven marker slugs, closed. The registry is APPENDIX-NORMATIVE.md §3;
 * an eighth needs `03` §4.4's justification shape before this union grows.
 */
export type SwarmMarkerKind =
  | "finding"
  | "escalation"
  | "hold"
  | "verdict"
  | "receipt"
  | "lease"
  | "rollback";

export const SWARM_MARKER_KINDS = [
  "finding",
  "escalation",
  "hold",
  "verdict",
  "receipt",
  "lease",
  "rollback",
] as const satisfies readonly SwarmMarkerKind[];

/** The only admitted schema version. A `v2` card renders a refusal, never prose. */
export const SWARM_MARKER_VERSION = 1;

/**
 * `<!-- swarm:finding:v1 -->`. Built here so no call site concatenates the
 * string; the copy and adversary gates treat a hand-built marker literal
 * outside the wire mirror and this module as a failure.
 */
export function swarmMarkerComment(kind: SwarmMarkerKind): string {
  return `<!-- swarm:${kind}:v${SWARM_MARKER_VERSION} -->`;
}

/**
 * Which surface is rendering. Decides `homeSurface` admission. `case` and
 * `lane` are what `useSwarmCardSurface` derives today; `other` is every
 * non-perch route; `ledger` and `export-preview` are Operator-complete's.
 */
export type SwarmCardSurfaceKind =
  | "case"
  | "lane"
  | "other"
  | "ledger"
  | "export-preview";

/**
 * The three-hue taxonomy (brief A9). A component takes the pillar name and
 * picks the token pair; it never takes a hex.
 */
export type PerchPillar = "substrate" | "authority" | "evidence";

/** A marker that passed line-0 + admission. `rawBody` is never trimmed. */
export type SwarmMarkerCard = {
  kind: SwarmMarkerKind;
  version: typeof SWARM_MARKER_VERSION;
  /** Everything after the first newline, byte-for-byte. Interior whitespace is load-bearing. */
  rawBody: string;
  /** The signer whose admission was checked. Lowercased 64-hex, asserted by the parser. */
  issuerPubkey: string;
  /** The `h` tag on the carrying event, for INV-13's case-channel equality check. */
  channelTag: string | null;
  /** The carrying event id, so a refusal state can name it. */
  eventId: string;
};

/** Five outcomes. Only `ok` reaches a presenter; the rest are refusals or prose. */
export type SwarmMarkerParse =
  | { status: "not-a-marker" }
  | { status: "unadmitted-issuer"; slug: string; issuerPubkey: string | null }
  | {
      status: "unknown-kind";
      slug: string;
      version: number;
      card: Omit<SwarmMarkerCard, "kind" | "version">;
    }
  | {
      status: "unsupported-version";
      kind: SwarmMarkerKind;
      version: number;
      card: Omit<SwarmMarkerCard, "kind" | "version">;
    }
  | { status: "ok"; card: SwarmMarkerCard };

/** A decoder owns one marker's payload shape. The wire mirror owns the shapes. */
export type SwarmCardDecodeResult<T> =
  | { ok: true; value: T }
  | { ok: false; reason: string };

/**
 * Takes the whole card, not only `rawBody`: admission (`admitCard`) needs the
 * issuer pubkey. A deliberate one-argument widening of 17 §3.3.
 */
export type SwarmCardDecoder<T> = (
  card: SwarmMarkerCard,
) => SwarmCardDecodeResult<T>;

/**
 * Everything a presenter may read. Four reference-stable fields, supplied by
 * the `MessageBody` seam. Deliberately NOT `MessageRow`'s props.
 */
export type SwarmCardContext = {
  surface: SwarmCardSurfaceKind;
  /** The open case's channel UUID when `surface === "case"`, else null. INV-12/INV-13. */
  caseChannelId: string | null;
  /** Highlight terms, threaded through unchanged. */
  searchQuery: string;
  /** `comfortable | compact` — read once at the seam, never per card. */
  density: "comfortable" | "compact";
};

export type SwarmCardProps<T> = {
  card: SwarmMarkerCard;
  payload: T;
  ctx: SwarmCardContext;
};

export type SwarmCardRenderArgs = {
  card: SwarmMarkerCard;
  ctx: SwarmCardContext;
};

/**
 * Erased registry entry. The payload type never escapes `defineSwarmCard`,
 * which is the one place decoder output and presenter input are checked
 * against each other. That is what keeps the map a plain `Record`.
 */
export type SwarmCardEntry = {
  pillar: PerchPillar;
  /** Refuses to render outside these surfaces. A `hold` card in a lane is a bug, not a view. */
  homeSurface: readonly SwarmCardSurfaceKind[];
  render: (args: SwarmCardRenderArgs) => React.ReactElement;
};
