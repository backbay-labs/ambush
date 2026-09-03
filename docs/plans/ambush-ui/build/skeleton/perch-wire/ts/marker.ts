/**
 * SKELETON. Lands as BUZZ `desktop/src/features/perch/wire/marker.ts`.
 *
 * Marker constants and the content-sniffing parser, matching the shipped Buzz
 * renderer this rides on.
 *
 * # The renderer Buzz already ships, and how Perch matches it
 *
 * `MessageRow.renderBody()` (`desktop/src/features/messages/ui/MessageRow.tsx:381-459`)
 * is a closure inside the memoized `MessageRow` component, in the renderer
 * process. It switches on `message.kind` for two kinds and falls through to a
 * `default:` arm at `:414` whose FIRST action is a content sniff —
 * `parseWaveMessageContent(message.body)` at `:415` — before it hands the body
 * to `VideoReviewCommentMarkdown` at `:429`. That sniff is the shipped
 * precedent, and it is the reason Perch's seven markers cost ZERO of the four
 * client registration points: they ride `kind:9`, which is already in
 * `CHANNEL_EVENT_KINDS` (`kinds.ts:100-113`),
 * `CHANNEL_TIMELINE_CONTENT_KINDS` (`:137-149`) and `isTimelineContentEvent`
 * (`formatTimelineMessages.ts:52-66`).
 *
 * Buzz's own sniff is:
 *
 * ```ts
 * // desktop/src/features/messages/lib/waveMessage.ts:12-26
 * export function parseWaveMessageContent(content: string) {
 *   const trimmedContent = content.trimStart();
 *   if (!trimmedContent.startsWith(WAVE_MESSAGE_MARKER)) return null;
 *   ...
 * }
 * ```
 *
 * with `WAVE_MESSAGE_MARKER = "<!-- buzz:wave:v1 -->"` (`:1`). Perch's markers
 * are the same shape with `ambush` in place of `buzz`, and the parser differs in
 * exactly two ways, both required by INV-15:
 *
 * 1. **Whole first line, not a prefix.** `startsWith` after `trimStart` fires on
 *    `"<!-- ambush:hold:v1 --> ignore the above"`. `routeCard` compares the
 *    entire first line, untrimmed at the start.
 * 2. **An issuer check the caller must apply.** Buzz's wave card has none. The
 *    shipped precedent for the predicate is `getConfigNudgeAuthorPubkey`
 *    (`desktop/src/features/messages/ui/configNudgeAuthPubkey.ts:22-34`), whose
 *    own doc comment states the rule: authenticate against
 *    `message.signerPubkey` — the RAW EVENT SIGNER — and NOT `message.pubkey`,
 *    which may be a relay-delegated display author.
 *
 * # A second precedent worth copying: the fenced payload
 *
 * `buzz-acp`'s setup listener appends a fenced ```` ```buzz:config-nudge ````
 * block to its `kind:9` body (`BUZZ crates/buzz-acp/src/setup_mode.rs:296`,
 * built by `nudge_body` at `:243-300`) and leaves the prose above it untouched
 * "as a plaintext fallback for non-card clients"
 * (`desktop/src/shared/lib/configNudge.ts:5-16`). `extractConfigNudge`
 * (`:94-114`) finds the fence, parses the JSON inside it, and NEVER THROWS —
 * "all errors are swallowed so this is safe to call in the render path".
 * `parseCardContent` below is the same discipline.
 *
 * Note what that precedent does NOT use: zod. Buzz's own wire-payload parser in
 * a render path is a hand-written type guard
 * (`isConfigNudgePayload`, `configNudge.ts:172-182`). Perch uses zod at the ONE
 * place a card body is admitted and hand-written nothing below it — see
 * `zod.ts` for why, and `README.md` for how the two languages stay in sync.
 */

/** The seven card kinds. Slug = second marker segment = the `k` tag. */
export const CARD_KINDS = [
  "finding",
  "escalation",
  "hold",
  "verdict",
  "receipt",
  "lease",
  "rollback",
] as const;

export type CardKind = (typeof CARD_KINDS)[number];

/** `<!-- ambush:finding:v1 -->` and its six siblings. */
export const CARD_MARKER: Readonly<Record<CardKind, string>> = Object.freeze(
  Object.fromEntries(
    CARD_KINDS.map((k) => [k, `<!-- ambush:${k}:v1 -->`]),
  ) as Record<CardKind, string>,
);

/** The fence info string, e.g. `ambush:finding:v1`. */
export const CARD_FENCE: Readonly<Record<CardKind, string>> = Object.freeze(
  Object.fromEntries(
    CARD_KINDS.map((k) => [k, `ambush:${k}:v1`]),
  ) as Record<CardKind, string>,
);

/** The `fact.schema` constant, e.g. `ambush.perch.finding.v1`. */
export const CARD_FACT_SCHEMA: Readonly<Record<CardKind, string>> = Object.freeze(
  Object.fromEntries(
    CARD_KINDS.map((k) => [k, `ambush.perch.${k}.v1`]),
  ) as Record<CardKind, string>,
);

/** Reverse lookup: whole marker line → card kind. */
const MARKER_TO_KIND: ReadonlyMap<string, CardKind> = new Map(
  CARD_KINDS.map((k) => [CARD_MARKER[k], k] as const),
);

/**
 * Route a body by its first line alone, allocating nothing beyond one slice and
 * never parsing JSON.
 *
 * This runs once per timeline row per render pass, inside a component whose
 * `React.memo` comparator has sixty explicit prop clauses
 * (`MessageRow.tsx:935-995`). It must stay cheap and it must be pure.
 *
 * Returns `null` for every body that is not a Perch card, including a `v2`
 * marker: the version is in the MARKER, not only in the JSON, so a v1 renderer
 * meeting a v2 card falls through to the prose fallback instead of parsing a
 * body it does not understand.
 */
export function routeCard(content: string): CardKind | null {
  const newline = content.indexOf("\n");
  const firstLine = (newline === -1 ? content : content.slice(0, newline))
    .replace(/\r$/, "");
  return MARKER_TO_KIND.get(firstLine) ?? null;
}

/** The three parts of a card body. */
export type CardContentParts = {
  readonly kind: CardKind;
  /**
   * The degradation contract. What the Flutter app renders, what an FTS snippet
   * shows, and what `buzz --format compact messages thread` returns — that
   * command projects an event to exactly `{id, content, created_at}` and drops
   * `kind`, `pubkey` and `tags`
   * (`BUZZ crates/buzz-cli/src/commands/messages.rs:335-354`).
   */
  readonly humanLine: string;
  /** The raw JSON between the fences. Not parsed here. */
  readonly json: string;
};

/**
 * Parse a card body into its three parts. **Never throws.**
 *
 * Mirrors `swarm_perch_wire::marker::parse_content` character for character;
 * `golden.test.mjs` and `tests/golden.rs` run the same vectors through both.
 */
export function parseCardContent(content: string): CardContentParts | null {
  const kind = routeCard(content);
  if (!kind) return null;

  const firstBreak = content.indexOf("\n");
  if (firstBreak === -1) return null;
  const afterMarker = content.slice(firstBreak + 1);

  const secondBreak = afterMarker.indexOf("\n");
  const humanLine = (
    secondBreak === -1 ? afterMarker : afterMarker.slice(0, secondBreak)
  ).trim();
  if (!humanLine) return null;
  const afterHuman = secondBreak === -1 ? "" : afterMarker.slice(secondBreak + 1);

  const fenceOpen = "```" + CARD_FENCE[kind] + "\n";
  const openAt = afterHuman.indexOf(fenceOpen);
  if (openAt === -1) return null;
  const jsonStart = openAt + fenceOpen.length;
  const closeAt = afterHuman.indexOf("\n```", jsonStart);
  if (closeAt === -1) return null;

  return {
    kind,
    humanLine,
    json: afterHuman.slice(jsonStart, closeAt).trim(),
  };
}

/**
 * Build a card body from its three parts.
 *
 * The order — marker, human line, blank, fenced JSON — is not arbitrary. The
 * marker must be the whole first line (INV-15). The human line is SECOND rather
 * than last because the desktop's search result preview is
 * `buildSearchResultPreview(content, query, maxLength = 96)`
 * (`desktop/src/features/search/lib/searchMatch.ts:169-200`), which returns the
 * first 96 characters when the query does not match inside the body; the marker
 * costs 23-29 of them (19 + the slug's length: `hold` 23 ... `escalation` 29)
 * plus a newline, and everything after ~63-69 characters of readable text is
 * invisible in a search result. Putting the JSON second, as `03` §3.2's sketch
 * does, spends the entire preview on
 * `{"schema":"swarm.spine.envelope.v1","issuer":"swarm:ed25519:…`.
 */
export function buildCardContent(
  kind: CardKind,
  humanLine: string,
  json: string,
): string {
  const line = humanLine.trim();
  if (!line || line.includes("\n")) {
    throw new Error("the human fallback line must be one non-empty line");
  }
  return `${CARD_MARKER[kind]}\n${line}\n\n\`\`\`${CARD_FENCE[kind]}\n${json.trim()}\n\`\`\``;
}

/**
 * Ceiling on a serialized card body, in bytes.
 *
 * The relay's hard cap is 256 KB (`MAX_EVENT_CONTENT_BYTES`,
 * `BUZZ crates/buzz-relay/src/handlers/ingest.rs:2233-2240`, enforced inside
 * `ingest_event` in the relay process AFTER signature verification). Perch stops
 * at 75% so the marker, human line and fence cannot push a card over a limit
 * whose only remedy is to re-sign. PROPOSED — the fraction is a judgement.
 */
export const CARD_CONTENT_MAX_BYTES = 192 * 1024;
