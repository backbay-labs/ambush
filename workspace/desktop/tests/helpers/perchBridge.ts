import type { Page } from "@playwright/test";

import goldenFinding from "../../src/features/perch/wire/golden/card-swarm-finding-v1.json" with {
  type: "json",
};
import {
  buildCardContent,
  CARD_FENCE,
  CARD_MARKER,
} from "../../src/features/perch/wire/marker";
import {
  buildWaveMessageContent,
  WAVE_MESSAGE_MARKER,
} from "../../src/features/messages/lib/waveMessage";
import type { PerchMockFixture } from "../../src/testing/perch/e2ePerchBridge";
import { installMockBridge } from "./bridge";

/**
 * The Playwright side of the perch fixture: one installer, one emitter, and
 * the card bodies the two perch specs render.
 *
 * # Ordering is the whole contract here
 *
 * `page.addInitScript` seeds `window.__AMBUSH_E2E_PERCH__` BEFORE
 * `installMockBridge` runs, because React reads localStorage and the mock
 * bridge answers commands on mount — a fixture seeded after the bridge is a
 * fixture the first render never saw. Perch specs call `installPerchBridge`
 * once and never call `installMockBridge` again.
 *
 * The emitter never reaches into React. It waits for the mock live
 * subscription on the target channel and then goes through
 * `__AMBUSH_E2E_EMIT_MOCK_MESSAGE__`, because a message emitted before the
 * subscription exists is silently dropped.
 */

export {
  PERCH_ADMITTED_ISSUER,
  PERCH_CASE_CHANNEL,
  PERCH_COLONY_ID,
  PERCH_FINDING_CARD_EVENT_ID,
  PERCH_FINDING_ID,
  PERCH_INCIDENT_ID,
  PERCH_LANE_CHANNEL,
  PERCH_LANE_CHANNEL_NAME,
  PERCH_NOW_MS,
  PERCH_OPERATOR_ID,
  PERCH_SECOND_LANE_CHANNEL,
  PERCH_UNADMITTED_ISSUER,
  mintedCaseId,
  mintedIncidentId,
} from "../../src/testing/perch/e2ePerchBridge";
export type { PerchMockFixture } from "../../src/testing/perch/e2ePerchBridge";

/**
 * The finding card's human fallback line, pinned to the Rust golden
 * (`crates/swarm-perch-wire/tests/human_lines.rs`). Line 1 of every card body
 * this helper builds, so the degradation contract is exercised rather than
 * assumed.
 */
export const PERCH_FINDING_HUMAN_LINE =
  "whisker-7a3f · data_exfiltration · HIGH · confidence 0.82 · host web-04 · finding f2c9a1b4";

type JsonObject = Record<string, unknown>;

function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

/**
 * The golden finding envelope, optionally with `fact.locator` fields
 * replaced. Used to plant adversary-controlled text in the host without
 * hand-writing a second envelope that could drift from the vector.
 */
export function findingEnvelope(locator?: JsonObject): JsonObject {
  const envelope = clone(goldenFinding) as JsonObject;
  if (locator) {
    const fact = envelope.fact as JsonObject;
    fact.locator = { ...(fact.locator as JsonObject), ...locator };
  }
  return envelope;
}

/**
 * A complete `swarm:finding:v1` body: the marker on line 0, the human line on
 * line 1, a blank line, then the fenced envelope (W3-21's order).
 */
export function findingCardBody(locator?: JsonObject): string {
  return buildCardContent(
    "finding",
    PERCH_FINDING_HUMAN_LINE,
    JSON.stringify(findingEnvelope(locator), null, 2),
  );
}

/**
 * A body whose marker and human line are well formed but whose fenced block
 * is not a `swarm.perch.finding.v1` envelope. The card must refuse it and
 * offer no action controls, rather than rendering a half-decoded card.
 */
export function malformedFindingCardBody(): string {
  return `${CARD_MARKER.finding}\n${PERCH_FINDING_HUMAN_LINE}\n\n\`\`\`${CARD_FENCE.finding}\n{"schema":"swarm.spine.envelope.v1","fact":{"schema":"swarm.perch.rollback.v1"}}\n\`\`\``;
}

/**
 * The chat app's own wave body, built by the chat app's own builder. The two
 * marker namespaces must not collide, and a hand-written copy of the wave
 * marker here would stop testing that the moment the chat app changed it.
 */
export function waveMessageBody(): string {
  return buildWaveMessageContent("alice");
}

export { WAVE_MESSAGE_MARKER };

/**
 * Seed the perch fixture and install the mock bridge with only the `perch`
 * preview feature added to the default set.
 *
 * @param fixture merged over the mock's defaults before the app loads.
 * @param options forwarded to `installMockBridge`.
 */
export async function installPerchBridge(
  page: Page,
  fixture?: PerchMockFixture,
  options?: {
    relayWsUrl?: string;
    autoConnectDefaultRelay?: boolean;
    skipOnboardingSeed?: boolean;
    skipCommunitySeed?: boolean;
  },
): Promise<void> {
  if (fixture) {
    await page.addInitScript((seed) => {
      window.__AMBUSH_E2E_PERCH__ = seed;
    }, fixture);
  }
  await installMockBridge(page, undefined, {
    ...options,
    enableFeatures: ["perch"],
  });
}

/** Merge `fixture` into the running page's mock state. */
export async function seedPerchFixtureAt(
  page: Page,
  fixture: PerchMockFixture,
): Promise<void> {
  await page.evaluate((seed) => {
    window.__AMBUSH_E2E_PERCH_SEED__?.(seed);
  }, fixture);
}

/** One perch renderer counter, read out of the running page. */
export async function readPerchCounterAt(
  page: Page,
  name: "perch_marker_unadmitted_total",
): Promise<number> {
  return page.evaluate(
    (counter) => window.__AMBUSH_E2E_PERCH_COUNTER__?.(counter) ?? -1,
    name,
  );
}

/** Every perch Tauri command the page has answered, in order. */
export async function readPerchMockLog(page: Page): Promise<string[]> {
  return page.evaluate(() => window.__AMBUSH_E2E_PERCH_LOG__?.() ?? []);
}

/** How many times the page answered `command`. */
export async function countPerchCommand(
  page: Page,
  command: string,
): Promise<number> {
  const log = await readPerchMockLog(page);
  return log.filter((entry) => entry === command).length;
}

/**
 * Wait until the app has an open live subscription on `channelName`. An
 * emitted message before this resolves is dropped on the floor.
 */
export async function waitForMockLiveSubscription(
  page: Page,
  channelName: string,
): Promise<void> {
  await page.waitForFunction(
    (name) =>
      window.__AMBUSH_E2E_HAS_MOCK_LIVE_SUBSCRIPTION__?.({
        channelName: name,
      }) === true,
    channelName,
  );
}

export type PerchEmitInput = {
  channelName: string;
  content: string;
  /** The RAW SIGNER. INV-15 admits on this and never on a delegated author. */
  pubkey: string;
  /** 64-hex, so the mock event id is the one the fixture already knows. */
  id?: string;
  /** Extra tags, e.g. a delegated authorship claim that must be ignored. */
  extraTags?: string[][];
  createdAt?: number;
  /**
   * The event kind. Defaults to the chat message kind. A card rides ANY kind
   * that reaches the `MessageBody` seam, so a spec can prove the seam is not
   * keyed to kind 9 by emitting the same bytes on another card-bearing kind.
   */
  kind?: number;
};

/**
 * Emit one mock message into a channel, after its live subscription exists.
 * Returns the event id the timeline row will carry.
 */
export async function emitPerchMessage(
  page: Page,
  input: PerchEmitInput,
): Promise<string> {
  await waitForMockLiveSubscription(page, input.channelName);
  return page.evaluate((emitted) => {
    const event = window.__AMBUSH_E2E_EMIT_MOCK_MESSAGE__?.({
      channelName: emitted.channelName,
      content: emitted.content,
      pubkey: emitted.pubkey,
      id: emitted.id,
      extraTags: emitted.extraTags,
      createdAt: emitted.createdAt,
      kind: emitted.kind,
    });
    if (!event) throw new Error("the mock bridge has no message emitter");
    return event.id;
  }, input);
}
