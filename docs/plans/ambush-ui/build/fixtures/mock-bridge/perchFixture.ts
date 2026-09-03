// perchFixture.ts -- seed the Perch demo fixture into Buzz's E2E mock bridge.
//
// LANDING PLACE: BUZZ desktop/tests/helpers/perchFixture.ts, beside bridge.ts.
// Call it AFTER installMockBridge(page) (desktop/tests/helpers/bridge.ts:961)
// and after the app has mounted, because every seam it uses is installed by
// installE2eBridge inside the page.
//
// ── WHERE THIS SITS IN THE ONE HARNESS DESIGN ─────────────────────────────
// Three wave-2 artifacts specified three ways to wire Perch into the mock
// bridge. 14-CLIENT-ARCHITECTURE.md section 7.4.1 arbitrated, and this file
// binds to that ruling rather than restating a fourth. The design has three
// layers and they are not alternatives:
//
//   RELAY STATE (this file).  Channels, kind:9 marker cards, kind:46010 feed
//     rows. Seeded through five window seams e2eBridge.ts ALREADY installs.
//     Zero upstream edits. Unchanged by the arbitration.
//   DAEMON READS (not this file).  `perch_*` Tauri commands, answered by
//     desktop/src/testing/perch/e2ePerchBridge.ts, which e2eBridge.ts reaches
//     through a three-line `if (command.startsWith("perch_"))` guard placed
//     immediately before its `default:` throw at :14594. That module reads the
//     SAME corpus this file reads -- build/fixtures/perch-demo-fixture.json,
//     vendored to desktop/src/testing/perch/perchDemoFixture.json -- under the
//     key `mock_bridge.perch_read_commands`.
//   DAEMON WRITES (deliberately nobody's).  See perchDaemonRoutes() below.
//
// WHY A DELEGATED MODULE AND NOT AN e2eBridge.ts EDIT
//   desktop/src/testing/e2eBridge.ts is 14,620 lines in one switch(command) and
//   162 Playwright specs depend on it. 00-BRIEF.md section 5 and 09 both say do
//   not split it. Everything below therefore runs through seams the file already
//   exports on `window`:
//
//     __BUZZ_E2E_INVOKE_MOCK_COMMAND__     e2eBridge.ts:14597 -- calls
//         handleMockCommand directly, in the page, so `create_channel` takes the
//         real handler at :6970-7018 and pushes a real MockChannel (with
//         ttl_seconds / ttl_deadline honoured at :6981-6984, :7007-7008).
//     __BUZZ_E2E_EMIT_MOCK_MESSAGE__       declared :1210-1223, installed with the
//         other seams; appends a RelayEvent to mockMessages for the named channel
//         and, when a live subscription exists, delivers it to the renderer.
//     __BUZZ_E2E_PUSH_MOCK_FEED_ITEM__     :11238-11243 -- unshifts a RawFeedItem
//         into mockFeedOverrides, which handleGetFeed merges ahead of the default
//         feed at :8004-8009, then fires `buzz:e2e-home-feed-updated`.
//     __BUZZ_E2E_HAS_MOCK_LIVE_SUBSCRIPTION__  :1202-1209 -- the poll that stops a
//         message being dropped because no REQ is open for the channel yet.
//     __BUZZ_E2E_INVALIDATE_CHANNELS__     declared :1438; flushes the channel
//         cache after a mutation so the sidebar re-reads.
//
// WHAT IT DOES NOT DO
//   It does not mock POST /decide or any other daemon WRITE. Those are HTTP to
//   :9090 and belong to a page.route() interception the spec installs
//   deliberately -- perchDaemonRoutes() below is that helper, and it is a
//   separate exported function on purpose, so a spec cannot acquire a decide
//   endpoint by accident. Keeping the halves apart in the harness is the same
//   process boundary the product is built on: this file can seed a queue, and
//   nothing in it can authorize anything.

import type { Page } from "@playwright/test";
import { PERCH_DEMO_CARDS, PERCH_DEMO_FIXTURE, PERCH_DEMO_NOTICES } from "./perchFixtureData";

/** Channel ids the mock actually assigned. See `deterministicIds` below. */
export type PerchFixtureHandles = {
  laneChannelId: string;
  laneChannelName: string;
  caseChannelId: string;
  caseChannelName: string;
  /** Nostr event ids of the seeded marker cards, keyed by fixture card name. */
  cardEventIds: Record<string, string>;
};

export type SeedPerchDemoOptions = {
  /**
   * Force the mock's channel ids to the fixture's canonical UUIDs.
   *
   * handleCreateChannel mints `crypto.randomUUID()` (e2eBridge.ts:6993 and
   * :7020) and takes no id override, so a spec that asserts on a URL like
   * `#/cases/27799e23-...` needs this. It patches `crypto.randomUUID` inside the
   * page for the duration of the two create calls and restores it immediately;
   * it is test-local and changes no product code.
   *
   * Default false: prefer reading the ids back out of PerchFixtureHandles.
   */
  deterministicIds?: boolean;
  /**
   * Stop before the grant. Seeds telemetry, findings, escalation and both holds,
   * leaving hold A undecided so a spec can drive the two-stroke grant itself.
   * Default false, which seeds the whole arc through the rollback receipt.
   */
  upTo?: "holds" | "grant" | "rollback";
  /**
   * Also seed the `contested` variant: hold B decided by a SECOND Approve-scoped
   * principal while this console's leg 1 was in flight, plus this console's
   * `superseded` update card.
   *
   * Off by default and named rather than implied, because it is the one place
   * the fixture admits a second operator. The shipped default synthesises
   * exactly one principal (AMB crates/swarm-core/src/config/operator.rs:153-168),
   * so a spec that turns this on is asserting a two-principal deployment and
   * should say so in its name.
   */
  contested?: boolean;
};

const MARKERS = {
  finding: "<!-- ambush:finding:v1 -->",
  escalation: "<!-- ambush:escalation:v1 -->",
  hold: "<!-- ambush:hold:v1 -->",
  verdict: "<!-- ambush:verdict:v1 -->",
  receipt: "<!-- ambush:receipt:v1 -->",
  lease: "<!-- ambush:lease:v1 -->",
  rollback: "<!-- ambush:rollback:v1 -->",
} as const;

type CardKind = keyof typeof MARKERS;

/**
 * The rendered body of a marker card.
 *
 * The marker is the WHOLE FIRST LINE, followed by a fenced json block. Buzz's
 * own precedent (features/messages/lib/waveMessage.ts:12-19) is
 * `content.trimStart().startsWith(MARKER)` over arbitrary content; Perch's sniff
 * is deliberately stricter (INV-15) because ProcessStartEvent.command_line is
 * adversary-authored and reaches the same renderer. Building the body here the
 * strict way means a fixture can never accidentally pass a loose sniff that the
 * product will later tighten.
 */
export function markerCardBody(kind: CardKind, envelope: unknown): string {
  return `${MARKERS[kind]}\n\n\`\`\`json\n${JSON.stringify(envelope, null, 2)}\n\`\`\`\n`;
}

async function waitForLiveSubscription(page: Page, channelName: string) {
  await page.waitForFunction(
    (name) =>
      window.__BUZZ_E2E_HAS_MOCK_LIVE_SUBSCRIPTION__?.({ channelName: name }) ?? false,
    channelName,
    { timeout: 10_000 },
  );
}

async function createChannel(
  page: Page,
  args: {
    name: string;
    channelType: "stream" | "forum";
    visibility: "open" | "private";
    description: string;
    ttlSeconds?: number;
    forceId?: string;
  },
): Promise<string> {
  return page.evaluate(async (input) => {
    const patched = typeof input.forceId === "string";
    const original = crypto.randomUUID;
    if (patched) {
      // Test-local, two calls wide, restored in the finally below.
      (crypto as { randomUUID: () => string }).randomUUID = () => input.forceId as string;
    }
    try {
      const raw = (await window.__BUZZ_E2E_INVOKE_MOCK_COMMAND__?.("create_channel", {
        name: input.name,
        channelType: input.channelType,
        visibility: input.visibility,
        description: input.description,
        ttlSeconds: input.ttlSeconds,
      })) as { id: string };
      return raw.id;
    } finally {
      if (patched) (crypto as { randomUUID: () => string }).randomUUID = original;
    }
  }, args);
}

async function emitCard(
  page: Page,
  args: {
    channelName: string;
    content: string;
    pubkey: string;
    createdAtMs: number;
    id: string;
    extraTags: string[][];
    parentEventId?: string;
  },
): Promise<void> {
  await page.evaluate((input) => {
    window.__BUZZ_E2E_EMIT_MOCK_MESSAGE__?.({
      channelName: input.channelName,
      content: input.content,
      pubkey: input.pubkey,
      kind: 9,
      // created_at is a TRANSPORT timestamp in unix SECONDS. It is not the
      // domain instant: the relay rejects anything more than
      // MAX_TIMESTAMP_DRIFT_SECS = 900 from now
      // (BUZZ crates/buzz-relay/src/handlers/ingest.rs:2224-2231) and created_at
      // is inside the Nostr signature, so a spooled card cannot carry its true
      // emit time. Every Perch surface sorts on fact.emitted_at_ms instead.
      createdAt: Math.floor(input.createdAtMs / 1000),
      id: input.id,
      extraTags: input.extraTags,
      parentEventId: input.parentEventId ?? null,
    });
  }, args);
}

/**
 * Seed the whole canonical demo. Returns the ids the mock actually assigned.
 *
 * Ordering matters and is not cosmetic:
 *   1. channels first -- __BUZZ_E2E_EMIT_MOCK_MESSAGE__ looks a channel up BY
 *      NAME and throws on a miss.
 *   2. navigate to each channel and wait for its live subscription before
 *      emitting into it, or the message is dropped with no error.
 *   3. feed items last, so the queue row's created_at is newer than the case
 *      timeline it points at and the selection lands where the demo expects.
 */
export async function seedPerchDemo(
  page: Page,
  options: SeedPerchDemoOptions = {},
): Promise<PerchFixtureHandles> {
  const f = PERCH_DEMO_FIXTURE;
  const upTo = options.upTo ?? "rollback";
  const det = options.deterministicIds === true;

  const laneChannelId = await createChannel(page, {
    name: f.channels.lane_execution.name,
    channelType: "stream",
    visibility: "open",
    description: "Execution — one of the twelve threat-class channels",
    forceId: det ? f.channels.lane_execution.id : undefined,
  });
  const caseChannelId = await createChannel(page, {
    name: f.channels.case.name,
    channelType: "stream",
    visibility: "private",
    description: "host-ops-1 · two Office-spawned PowerShell chains",
    // channels.ttl_seconds / ttl_deadline are real columns
    // (BUZZ schema/schema.sql:102-103) with a partial index on expiry (:116-117)
    // and a constraint trigger that pushes the deadline forward on every durable
    // insert (:960-998). Six hours: activity renews, silence archives.
    ttlSeconds: f.channels.case.ttl_seconds,
    forceId: det ? f.channels.case.id : undefined,
  });
  await page.evaluate(() => window.__BUZZ_E2E_INVALIDATE_CHANNELS__?.());

  const ids = f.nostr_event_ids;
  const cardEventIds: Record<string, string> = {};

  // ── lane: the three findings and the escalation ──────────────────────────
  await page.goto(`/#/channels/${laneChannelId}`);
  await waitForLiveSubscription(page, f.channels.lane_execution.name);

  const laneCards: Array<[string, CardKind, string, number, string[][]]> = [
    ["card-01-finding-suspicious-process-tree-evt1", "finding", ids.finding_spt_1,
      f.clock.timestamps.finding_spt1_ms, [["t", "execution"], ["l", "CRITICAL"], ["k", "finding"]]],
    ["card-02-finding-suspicious-scripting-evt1", "finding", ids.finding_scr_1,
      f.clock.timestamps.finding_scr1_ms, [["t", "execution"], ["l", "CRITICAL"], ["k", "finding"]]],
    ["card-03-finding-suspicious-process-tree-evt2", "finding", ids.finding_spt_2,
      f.clock.timestamps.finding_spt2_ms, [["t", "execution"], ["l", "CRITICAL"], ["k", "finding"]]],
    ["card-04-escalation-execution-alert", "escalation", ids.escalation,
      f.clock.timestamps.cross_ms, [["t", "execution"], ["l", "CRITICAL"], ["k", "escalation"]]],
  ];
  for (const [name, kind, eventId, createdAtMs, tags] of laneCards) {
    await emitCard(page, {
      channelName: f.channels.lane_execution.name,
      content: markerCardBody(kind, PERCH_DEMO_CARDS[name as keyof typeof PERCH_DEMO_CARDS]),
      pubkey: f.cast.bridge.nostr_pubkey,
      createdAtMs,
      id: eventId,
      extraTags: tags,
    });
    cardEventIds[name] = eventId;
  }

  // ── case: holds, then the decision arc ───────────────────────────────────
  await page.goto(`/#/channels/${caseChannelId}`);
  await waitForLiveSubscription(page, f.channels.case.name);

  const caseCards: Array<[string, CardKind, string, number, string[][], string?]> = [
    ["card-05-hold-a-isolate-host-open", "hold", ids.hold_a_open,
      f.clock.timestamps.hold_a_ms, [["t", "execution"], ["l", "CRITICAL"], ["k", "hold"]]],
    ["card-06-hold-b-block-egress-open", "hold", ids.hold_b_open,
      f.clock.timestamps.hold_b_ms, [["t", "execution"], ["l", "CRITICAL"], ["k", "hold"]]],
  ];
  if (upTo !== "holds") {
    caseCards.push(
      ["card-07-verdict-grant-hold-a", "verdict", ids.verdict_grant,
        f.clock.timestamps.leg1_ms, [["k", "verdict"]], ids.hold_a_open],
      ["card-08-hold-a-terminal-executed", "hold", ids.hold_a_terminal,
        f.clock.timestamps.hold_a_terminal_ms, [["t", "execution"], ["l", "CRITICAL"], ["k", "hold"]], ids.hold_a_open],
      ["card-09-receipt-hunt-evt-1", "receipt", ids.receipt,
        f.clock.timestamps.receipt_ms, [["k", "receipt"]]],
      ["card-10-lease-host-ops-1", "lease", ids.lease,
        f.clock.timestamps.lease_ms, [["k", "lease"]]],
    );
  }
  if (upTo === "rollback") {
    caseCards.push(
      ["card-11-rollback-host-ops-1", "rollback", ids.rollback,
        f.clock.timestamps.rollback_ms, [["k", "rollback"]], ids.lease],
    );
  }
  for (const [name, kind, eventId, createdAtMs, tags, parent] of caseCards) {
    await emitCard(page, {
      channelName: f.channels.case.name,
      content: markerCardBody(kind, PERCH_DEMO_CARDS[name as keyof typeof PERCH_DEMO_CARDS]),
      pubkey: kind === "verdict" ? f.cast.operator.nostr_pubkey : f.cast.bridge.nostr_pubkey,
      createdAtMs,
      id: eventId,
      extraTags: tags,
      parentEventId: parent,
    });
    cardEventIds[name] = eventId;
  }

  // ── the queue rows ───────────────────────────────────────────────────────
  // Two kind:46010 notices, one per hold. Category `needs_action` is what
  // isActionRequired reads (features/home/lib/inbox.ts:615) and what puts the
  // row in queue 1. Hold A's notice is seeded only when the demo has NOT yet
  // been advanced past the grant, because a decided hold leaves the queue by
  // reconciliation against GET /v1/response/holds, not by a relay delete.
  const notices: Array<[keyof typeof PERCH_DEMO_NOTICES, string, number]> = [
    ["event-46010-hold-b", ids.notice_46010_b, f.clock.timestamps.hold_b_ms],
  ];
  if (upTo === "holds") {
    notices.unshift(["event-46010-hold-a", ids.notice_46010_a, f.clock.timestamps.hold_a_ms]);
  }
  for (const [noticeName, eventId, createdAtMs] of notices) {
    const notice = PERCH_DEMO_NOTICES[noticeName];
    await page.evaluate(
      (input) => {
        window.__BUZZ_E2E_PUSH_MOCK_FEED_ITEM__?.({
          id: input.id,
          kind: 46010,
          pubkey: input.pubkey,
          content: input.content,
          created_at: Math.floor(input.createdAtMs / 1000),
          channel_id: input.channelId,
          channel_name: input.channelName,
          channel_type: "stream",
          tags: input.tags,
          category: "needs_action",
        });
      },
      {
        id: eventId,
        pubkey: f.cast.bridge.nostr_pubkey,
        content: notice.content,
        createdAtMs,
        channelId: caseChannelId,
        channelName: f.channels.case.name,
        // The `h` tag is rewritten to the id the mock actually assigned. In
        // production it is the case channel UUID and the relay resolves it with
        // `val.parse::<Uuid>()` (BUZZ ingest.rs:549-561); a non-UUID value makes
        // the event channel-less, which after the 46010 fork is a rejection at
        // ingest.rs:2460-2464 rather than a global event.
        tags: notice.tags.map((t) => (t[0] === "h" ? ["h", caseChannelId] : t)),
      },
    );
  }

  // ── the contested variant, only when a spec asks for it by name ─────────
  if (options.contested === true) {
    const v = f.variants.contested;
    const contested: Array<[string, string, number]> = [
      ["variant-contested-01-verdict-op2-wins", v.nostr_event_ids.verdict_grant_op2, v.decided_at_ms],
      ["variant-contested-02-verdict-op1-sending", v.nostr_event_ids.verdict_grant_op1, v.decided_at_ms + 400],
      ["variant-contested-03-verdict-op1-superseded", v.nostr_event_ids.verdict_superseded_op1, v.decided_at_ms + 700],
    ];
    for (const [name, eventId, createdAtMs] of contested) {
      const card = PERCH_DEMO_CARDS[name as keyof typeof PERCH_DEMO_CARDS];
      await emitCard(page, {
        channelName: f.channels.case.name,
        content: markerCardBody("verdict", card),
        // Each card is signed by the operator who published it. The winner's
        // card and the loser's card are BOTH real, BOTH signed, and both stay
        // in the channel forever; only the third card says which was which.
        pubkey: (card as { fact: { issuer: { nostr_pubkey: string } } }).fact.issuer.nostr_pubkey,
        createdAtMs,
        id: eventId,
        extraTags: [["k", "verdict"]],
        parentEventId: ids.hold_b_open,
      });
      cardEventIds[name] = eventId;
    }
  }

  await page.goto("/#/");
  return {
    laneChannelId,
    laneChannelName: f.channels.lane_execution.name,
    caseChannelId,
    caseChannelName: f.channels.case.name,
    cardEventIds,
  };
}

/**
 * Install page.route() interceptions for the daemon's HTTP surface.
 *
 * SEPARATE FROM seedPerchDemo ON PURPOSE. Leg 2 of a Perch write crosses a
 * process boundary — the console POSTs to the daemon on :9090, a different
 * process that re-derives authority from scratch and can refuse — and that
 * boundary is the product's central claim. A harness that answered
 * `POST /decide` from inside the same module that seeds the queue would have
 * quietly deleted the thing under test. So a spec that needs leg 2 asks for it,
 * by name, in its own line.
 *
 * `outcome` picks which decide body hold B gets:
 *   "granted"    the ordinary path, 200 with a receipt.
 *   "contested"  409 hold_already_decided, naming the winning intent event id —
 *                the input a console needs to publish its `superseded` card.
 *
 * Bodies come from build/fixtures/http/, which fixtures/validate.mjs and the
 * OpenAPI document both cover, so a route mock cannot drift from the contract.
 */
export async function perchDaemonRoutes(
  page: Page,
  bodies: {
    listHolds: unknown;
    decideHoldA: unknown;
    decideHoldB?: unknown;
    findingFeedback?: unknown;
    mintIncident?: unknown;
  },
  options: { daemonOrigin?: string; outcome?: "granted" | "contested" } = {},
): Promise<void> {
  const origin = options.daemonOrigin ?? "http://127.0.0.1:9090";
  const json = (body: unknown, status = 200) => ({
    status,
    contentType: "application/json",
    body: JSON.stringify(body),
  });

  await page.route(`${origin}/v1/response/holds`, (route) => route.fulfill(json(bodies.listHolds)));
  await page.route(`${origin}/v1/response/holds/*/decide`, (route) => {
    const url = route.request().url();
    const holdId = url.split("/holds/")[1]?.split("/")[0] ?? "";
    if (holdId === PERCH_DEMO_FIXTURE.holds.b.hold_id) {
      // 409 is a NORMAL OUTCOME, not a transport error: the daemon's
      // compare-and-set admitted another operator's decision first. INV-28.
      return route.fulfill(json(bodies.decideHoldB, options.outcome === "contested" ? 409 : 200));
    }
    return route.fulfill(json(bodies.decideHoldA));
  });
  if (bodies.findingFeedback !== undefined) {
    await page.route(`${origin}/v1/operator/findings/*/feedback`, (route) =>
      route.fulfill(json(bodies.findingFeedback)));
  }
  if (bodies.mintIncident !== undefined) {
    await page.route(`${origin}/v1/operator/incidents`, (route) =>
      route.fulfill(json(bodies.mintIncident)));
  }
}
