/**
 * SKELETON. Lands as BUZZ `desktop/src/features/perch/wire/index.ts`.
 *
 * The public surface of the Perch wire module. Everything a Perch feature needs
 * to read a card or a frame, and nothing that lets it construct one without
 * going through admission.
 *
 * # Placement
 *
 * `src/features/perch/wire/`, NOT `src/shared/api/`. Three files in that
 * governed root are at or over the 1000-line cap and are therefore FROZEN by the
 * file-size ratchet (`BUZZ scripts/check-file-sizes-core.mjs:31-33` sets
 * `limit = max(baseLines, 1000)`): `tauri.ts` at 1108 gate-lines,
 * `relayClientSession.ts` at 1084, and `types.ts` at exactly 1000. None can take
 * one added line.
 *
 * # What is deliberately NOT exported
 *
 * - Any way to build a `Card` object that has not been through `admitCard`.
 *   INV-15's two clauses are the only path in.
 * - A conversion between `UnixMillis` and `UnixSeconds`. Crossing the two clock
 *   domains must be named at the call site.
 * - A `signRelayEvent` wrapper. INV-29 requires the ONLY producer of an
 *   `swarm:verdict:v1` card to be a dedicated `perch_record_verdict` Tauri
 *   command that builds its body from daemon-fetched hold state — because
 *   `sign_event` (`BUZZ desktop/src-tauri/src/commands/identity.rs:108`, exposed
 *   to the webview as `signRelayEvent` at
 *   `BUZZ desktop/src/shared/api/tauri.ts:597`) signs an arbitrary kind, content
 *   and tag set with the operator's key, so any code in the React tree could
 *   otherwise forge a grant card for any hold.
 */

export {
  CARD_FACT_SCHEMA,
  CARD_FENCE,
  CARD_KINDS,
  CARD_MARKER,
  CARD_CONTENT_MAX_BYTES,
  buildCardContent,
  parseCardContent,
  parseCardParts,
  routeCard,
} from "./marker";
export type { CardContentParts, CardKind } from "./marker";

export {
  PUSHDOWN,
  channelOf,
  holdIdOf,
  pushdownClass,
  tagValue,
  tagValues,
  threatClassSlug,
  verdictCardTags,
} from "./tags";
export type { PushdownClass, Tag } from "./tags";

export { admitCard, admitFrame, envelopeTier, holdId } from "./zod";
export type { AdmissionFailure } from "./zod";

export type {
  AgentHealthState,
  AgentRole,
  Card,
  CardEnvelope,
  CardFact,
  Decision,
  DetachedSignature,
  EscalationFact,
  EscalationLevel,
  ExecutionMode,
  FactIssuer,
  FindingFact,
  FindingVerdictWord,
  Frame,
  FrameHeader,
  GapBlock,
  GapBlockCause,
  HoldFact,
  HoldId,
  HoldState,
  LeaseFact,
  Leg2Outcome,
  OperatorFactIssuer,
  PartitionState,
  PolicyDecision,
  PolicyVerdict,
  ReceiptFact,
  ResponseAction,
  ResponseActionKind,
  ResponseStatus,
  RollbackFact,
  RollbackStepStatus,
  RollbackTrigger,
  Severity,
  SourceIdsAbsentReason,
  SwarmMode,
  ThreatClass,
  ThreatConcentration,
  UnixMillis,
  UnixSeconds,
  VerdictFact,
} from "./types";

export {
  AGENT_ROLES,
  CONTAINMENT_ACTION_KINDS,
  RESPONSE_ACTION_KINDS,
  SEVERITIES,
  STANDARD_THREAT_CLASSES,
} from "./types";

/**
 * Kinds Perch subscribes to or publishes. Nothing else.
 *
 * `9` is already registered at all four client registration points, which is why
 * the seven markers cost none of them. `46010` is the one stored kind the relay
 * fork admits and, per `10-RELAY-FORK.md` decision RF-D3, it is a QUEUE RECORD
 * and not a timeline row: it is deliberately absent from
 * `CHANNEL_TIMELINE_CONTENT_KINDS`, so `buildChannelHistoryFilter` does not
 * fetch it and `buildChannelFilter`'s live REQ does not deliver it.
 */
export const PERCH_KINDS = Object.freeze({
  /** Every marker card. */
  CARD: 9,
  /** The hold notice — the needs-action queue record. */
  HOLD_NOTICE: 46010,
  /** The ephemeral block, contiguous. */
  FRAMES: Object.freeze([
    26000, 26001, 26002, 26003, 26004, 26005, 26006,
  ] as const),
} as const);
