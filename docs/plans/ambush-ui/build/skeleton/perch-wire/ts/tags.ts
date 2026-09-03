/**
 * SKELETON. Lands as BUZZ `desktop/src/features/perch/wire/tags.ts`.
 *
 * Tag reading, on the client side.
 *
 * The client BUILDS tags in exactly one place — the `ambush:verdict:v1` card,
 * which is the only event the operator's own key publishes. Everything else on
 * this wire is built by the bridge in Rust (`tags.rs`). This module is
 * predominantly a reader, and its most important export is `pushdownClass`,
 * because the difference between an indexed selection and a post-filter decides
 * how deep a query has to page.
 *
 * # Pushdown, measured against the relay's own predicate
 *
 * `filter_fully_pushable` (`BUZZ crates/buzz-relay/src/handlers/req.rs:851-895`)
 * runs in the relay process and decides whether a filter can use the fast COUNT
 * path. Read arm by arm:
 *
 * | tag | pushed? | source |
 * |---|---|---|
 * | `h` | yes — the caller has already put the complete authorized set through `EventQuery::channel_id`/`channel_ids` | `req.rs:863-866` |
 * | `p` | a SINGLE value only; two or more return `false` | `req.rs:867-873` |
 * | `e` | yes, any count, via JSONB containment | `req.rs:882-884` |
 * | `d` | only when EVERY kind in the filter is NIP-33 | `req.rs:874-881` |
 * | anything else (`t`, `l`, `k`, `broadcast`, `hold`, `card`) | **no** — the default arm returns `false`, naming `#t` and `#a` | `req.rs:885-890` |
 * | a NIP-50 `search` filter | **no** | `req.rs:892-895` |
 *
 * `EventQuery` has no generic tag field beyond `custom_tag: Option<(String, String)>`
 * — ONE pair (`BUZZ crates/buzz-db/src/store/event.rs:81-83`).
 *
 * ## The two consequences, stated so nobody re-derives them wrong
 *
 * 1. **Paging depth must be sized for dilution.** A REQ of
 *    `{kinds:[9], "#h":[case], "#k":["receipt"]}` fetches a page of ALL `kind:9`
 *    in the case and drops non-matching rows afterwards. On a busy case a
 *    `limit:200` can return a handful of receipts. **Where per-card-type
 *    selection matters, fetch one page of `{kinds:[9], "#h":[case]}` and
 *    partition client-side on the parsed marker.**
 * 2. **Such a filter disqualifies the fast COUNT path.** So the Ledger's result
 *    count is an estimate over a page, and the copy says so rather than printing
 *    a number the query cannot produce.
 *
 * ## The permanent cost, named
 *
 * `strategy_id`, `host_id`, `receipt_id`, `lease_id` and `hunt_id` are reachable
 * through NIP-50 FTS only, never as a `#filter`. The events are signed and
 * cannot be re-tagged. FTS reaches them because `search_tsv` is
 * `to_tsvector('simple', content)` and the privacy `CASE` at
 * `BUZZ schema/schema.sql:223-227` nulls it only for kinds
 * `{1059, 30179, 30300, 30350, 30622, 44100, 44101, 44200}` — neither `9` nor
 * `46010` is among them. That is also why the fenced JSON is worth its bytes:
 * every join key in a card body is FTS-searchable.
 */

import type { CardKind } from "./marker";
import type { Severity } from "./types";

/** A raw Nostr tag row. */
export type Tag = readonly string[];

/** Whether a tag name reaches SQL as an indexed selection. */
export type PushdownClass = "sql" | "sql-single-only" | "post-filter";

/** How the relay treats each tag name Perch uses. */
export const PUSHDOWN: Readonly<Record<string, PushdownClass>> = Object.freeze({
  h: "sql",
  e: "sql",
  p: "sql-single-only",
  d: "sql",
  t: "post-filter",
  l: "post-filter",
  k: "post-filter",
  broadcast: "post-filter",
  hold: "post-filter",
  card: "post-filter",
});

/** Classify a tag name. Unknown names are post-filters, per `req.rs:885-890`. */
export function pushdownClass(name: string): PushdownClass {
  return PUSHDOWN[name] ?? "post-filter";
}

/** First value of the named tag, or undefined. */
export function tagValue(tags: readonly Tag[], name: string): string | undefined {
  return tags.find((tag) => tag[0] === name)?.[1];
}

/** Every value of the named tag. */
export function tagValues(tags: readonly Tag[], name: string): string[] {
  return tags.filter((tag) => tag[0] === name).map((tag) => tag[1] ?? "");
}

/**
 * The `h` tag, i.e. the case or lane channel.
 *
 * `extract_channel_id` reads the FIRST `h` tag and ignores the rest
 * (`BUZZ crates/buzz-relay/src/handlers/ingest.rs:549-561`), so a second `h`
 * tag is silently dead weight and this helper matches that behaviour rather
 * than being cleverer than the relay.
 */
export function channelOf(tags: readonly Tag[]): string | undefined {
  return tagValue(tags, "h");
}

/**
 * The `hold` tag on a `kind:46010` notice: the reconciliation key.
 *
 * Layer 3 of the hold path matches each relay row against
 * `GET /v1/response/holds`, and INV-35 requires a `46010` present on the relay
 * and absent from the daemon to render FORGED. Both need this value off the
 * event. It survives the Tauri boundary because `FeedItemInfo` carries `tags`
 * and `pubkey` (`BUZZ desktop/src-tauri/src/models.rs:198-210`) — but NOT `sig`,
 * so the client cannot re-verify the Nostr signature and relies on the relay's
 * ingest check.
 */
export function holdIdOf(tags: readonly Tag[]): string | undefined {
  return tagValue(tags, "hold");
}

/** Tags for the one event the operator's own key publishes. */
export function verdictCardTags(args: {
  readonly caseChannel: string;
  readonly holdCardId: string;
  readonly threatClassSlug: string;
  readonly severity: Severity;
}): Tag[] {
  return [
    ["h", args.caseChannel],
    ["e", args.holdCardId],
    ["t", args.threatClassSlug],
    ["l", args.severity],
    ["k", "verdict" satisfies CardKind],
  ];
}

/**
 * The threat-class slug for the `t` tag.
 *
 * A `ThreatClass::Custom(name)` becomes the literal `custom`, with the class
 * name carried in the body instead — APPENDIX-NORMATIVE §3's ruling, and the
 * only one of the three in-tree conventions that keeps an operator-supplied
 * string out of an indexed tag. The other two: `threat_class_name`
 * (`AMB crates/swarm-runtime/src/escalation.rs:389-405`) returns the raw name,
 * and the NATS subject builder (`AMB crates/swarm-pheromone/src/jetstream.rs:1190`)
 * returns `custom_{sanitized}`. `AMB crates/swarm-runtime/src/sphinx_agent.rs:1799`
 * returns the literal `"custom"`, which is the one this matches.
 */
export function threatClassSlug(
  threatClass: string | { readonly custom: string },
): string {
  return typeof threatClass === "string" ? threatClass : "custom";
}
