// Target path in BUZZ: desktop/tests/helpers/perchBridge.ts  (NEW file)
//
// ── THE SEAM, RECONCILED ───────────────────────────────────────────────────
//
// Three artifacts specified three different, non-interoperable ways to wire
// Perch into Buzz's E2E mock bridge, and the review was right that a team cannot
// build from three. They are now one, and the tiebreak is ownership, not
// preference:
//
//   14-CLIENT-ARCHITECTURE.md OWNS the client seam and commits
//     * ONE delegating guard, `if (command.startsWith("perch_"))`, placed before
//       e2eBridge.ts's `default:` throw at :14594 `[V]` (the arm reads
//       `throw new Error(\`Unsupported mocked Tauri command: ${command}\`)`);
//     * fixtures in a NEW `desktop/src/testing/perchBridgeFixtures.ts`.
//   22-DEMO-FIXTURE.md OWNS the scenario and commits
//     * `fixtures/perch-demo-fixture.json` as the canonical data, every id
//       regenerable with `node fixtures/derive-ids.mjs`;
//     * "THE MOCK-BRIDGE SEED EDITS NOTHING" -- seeding rides existing seams.
//   This file OWNS neither, so it BINDS to both. The earlier draft's
//   `src/testing/perch/e2ePerchBridge.ts` module path is withdrawn in favour of
//   14's, and the earlier draft's own fixture corpus is withdrawn in favour of
//   22's.
//
// WHAT THAT COSTS, EXACTLY
//   ONE line changes in `e2eBridge.ts` (14's prefix guard), and it is the same
//   line 22's seed does not need and does not conflict with. Everything else is
//   new files Perch owns. `e2eBridge.ts` is 14,620 lines behind one
//   `switch (command)` and 162 specs depend on it; it is never split.
//
// ── THE TWO WINDOW SEAMS, DOWN FROM FIVE ───────────────────────────────────
//
// The earlier draft required five new `window.__BUZZ_E2E_PERCH*__` globals. Four
// of them were doing work the DOM or an existing seam already does, and each new
// global is a thing that must exist in the product build before any spec runs.
// Two remain, both installed by `perchBridgeFixtures.ts` (14's module) rather
// than by `e2eBridge.ts`:
//
//   1. `window.__BUZZ_E2E_PERCH__` -- the fixture, seeded by `addInitScript`
//      BEFORE `installMockBridge`. When absent, `perchBridgeFixtures.ts` falls
//      back to the canonical demo scenario, so a spec that wants the demo state
//      seeds nothing at all.
//   2. `window.__BUZZ_E2E_PERCH_CONTROL__` -- ONE object with two methods,
//      `emitEphemeral(frame)` and `advanceClock(ms)`. A 26xxx frame is not a
//      Tauri command and not a channel message, so no existing seam carries it;
//      a frozen clock is what lets INV-18 assert a 60-minute TTL without
//      sleeping for one.
//
// Withdrawn, and what replaced each:
//   `__BUZZ_E2E_PERCH_QUEUE_RECONCILED__` -> `[data-perch-queue-reconciled]` on
//       the queue element. Better as well as cheaper: it is an assertion about
//       what rendered, and INV-35's divergence rendering needs the attribute
//       anyway.
//   `__BUZZ_E2E_EMIT_PERCH_EPHEMERAL__` -> `__BUZZ_E2E_PERCH_CONTROL__.emitEphemeral`.
//   `__BUZZ_E2E_PERCH_ADVANCE__`        -> `__BUZZ_E2E_PERCH_CONTROL__.advanceClock`.
//   `__BUZZ_E2E_PERCH_COUNTER__`        -> `[data-perch-counter="<name>"]` text.
//       A counter nobody renders is a counter nobody reads; asserting the
//       rendered value is the invariant, and a window global would have let the
//       counter be right and invisible.
//   `__BUZZ_E2E_PERCH_EXPORT_MANIFEST__` -> `[data-perch-export-manifest]`'s
//       `textContent`, parsed as JSON. Same argument.
//
// ── THE ORDERING RULE THAT BREAKS SPECS WHEN IGNORED ───────────────────────
//   `page.addInitScript` seeding must run BEFORE `installMockBridge(page)` --
//   React reads state on mount and the bridge triggers mount (BUZZ CLAUDE.md).
//   `installPerchBridge` therefore MUST be awaited before `installMockBridge`,
//   and every spec in this directory does it in that order.
//
// ── BUILD TRAP, restated because it costs a day every time ─────────────────
//   Build with `pnpm build:e2e`, never `pnpm run build`: a plain build strips
//   `installE2eBridgeIfConfigured` (src/main.tsx) and every mock-mode spec fails
//   with "Cannot read properties of undefined (reading 'invoke')", rendering
//   "Community connection failed" -- which looks exactly like a product bug.
//   `pnpm test:e2e:smoke` does the right build. Kill port 4173 first;
//   `reuseExistingServer: true` will otherwise serve the previous build.

import { expect, type Page } from "@playwright/test";

// ── CANONICAL IDS ───────────────────────────────────────────────────────────
//
// Every value below is copied from `fixtures/perch-demo-fixture.json`
// (22-DEMO-FIXTURE.md's canonical scenario `hellcat-office`) and nothing here is
// invented. Regenerate with `node fixtures/derive-ids.mjs`; every opaque id is
// `sha256("perch-demo-fixture/v1/" + label)` truncated, so the derivation is
// public and reproducible.
//
// The wave-2 review found FIVE different channel UUIDs for one case across five
// artifacts. There is one, and it is this one.

/** The bridge identity the admitted-issuer rule (INV-15) resolves. */
export const PERCH_ADMITTED_ISSUER =
  "207176338a897b2379564322033e86ed7197600499ba348e6c6c898b8139b586";
/**
 * A well-formed signer that is NOT admitted. Used to prove the negative. It is
 * the OPERATOR's own pubkey, deliberately: the sharpest unadmitted case is not a
 * stranger, it is a real participant in the channel whose key is not a bridge
 * identity, because that is the one a naive "is this pubkey known?" check waves
 * through.
 */
export const PERCH_UNADMITTED_ISSUER =
  "684949a3287973d209a80c63057ff9e099ede5996b18288936db5e318fafbde5";

export const PERCH_CASE_CHANNEL = "27799e23-ab25-4659-b381-3de47ea7ca4d";
export const PERCH_LANE_CHANNEL = "b8240a37-88b1-4a9f-8b77-5cc005891115";
export const PERCH_WATCH_CHANNEL = "426cef7e-808f-4988-af82-42d911a0d480";
/** A second case, for INV-13's wrong-`h`-tag assertion. Not in the scenario. */
export const PERCH_OTHER_CASE_CHANNEL = "0e1d2c3b-4a59-4687-9a0b-1c2d3e4f5061";

/** APPENDIX-NORMATIVE.md section 6: PERCH_HOLD_TTL_MS, 60 minutes. */
export const PERCH_HOLD_TTL_MS = 3_600_000;
/** The scenario's frozen `now`: 2026-03-17T09:20:00Z. */
export const PERCH_NOW_MS = 1_773_739_200_000;

/**
 * The two holds the scenario mints. Hold A is a containment action (leased,
 * reversible); hold B is destructive and NOT leased -- the 12 -> 4 -> 3 ladder
 * on one screen, with B rendering an explicit absence rather than an empty
 * containment slot.
 */
export const PERCH_HOLD_A = "h_a07aeacf";
export const PERCH_HOLD_B = "h_1c28ae79";
export const PERCH_CONTAINMENT_LEASE = "cl_9b3645fc";

/**
 * Every hold id must satisfy `common.schema.json#/$defs/HoldId`:
 * `^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$` -- no colon, URL-safe, 8..64 chars. The
 * `hold:{hunt_id}:{held_at_ms}` derived form is unrepresentable by construction,
 * which is the point: `hunt_id` is a join key into detection data and the
 * hold_id rides a global `kind:26006` frame.
 *
 * Called by `perchHold` on every fixture it builds, so a spec cannot invent a
 * seventh id format the way five wave-2 artifacts did.
 */
const HOLD_ID_RE = /^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$/;
export function assertHoldId(holdId: string): string {
  if (!HOLD_ID_RE.test(holdId)) {
    throw new Error(
      `hold_id ${JSON.stringify(holdId)} violates common.schema.json#/$defs/HoldId ` +
        `(${HOLD_ID_RE.source}). A colon means somebody derived it from hunt_id.`,
    );
  }
  return holdId;
}

export type PerchMockHold = {
  hold_id: string;
  action_kind: string;
  /** SCREAMING_SNAKE -- the serialization, per voice law L2's register rule. */
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  case_channel: string;
  held_at_ms: number;
  expires_at_ms: number;
  state:
    | "created"
    | "notified"
    | "armed"
    | "deciding"
    | "granted"
    | "executed"
    | "refused"
    | "expired"
    | "failed";
  /**
   * Only the four containment actions mint one
   * (AMB crates/swarm-runtime/src/containment.rs:54-63). The other eight
   * destructive actions have no containment lease, no countdown and no rollback
   * receipt -- the hold card must not render a pending-lease slot for them.
   */
  containment_lease_id: string | null;
  /**
   * `resolve_inverse` returned Ok for EVERY step of the plan
   * (AMB crates/swarm-response/src/rollback.rs:145-192). INV-03 gates the Undo
   * affordance on this and nothing else.
   */
  every_step_reversible: boolean;
  /**
   * The daemon's own rule name and reason, rendered VERBATIM in render law 1's
   * fourth slot. Every hold today carries exactly these
   * (AMB crates/swarm-policy/src/static_gate.rs:297, set by
   * `StaticApprovalGate::evaluate` inside `swarm_detect --serve` and carried onto
   * every `PolicyDecision`) `[V]`. The reason contains the word "approval",
   * which the copy gate's `approve` row exempts for exactly this string -- see
   * `tools/copy-ban-list.tsv`.
   */
  rationale: { rule_name: string; reason: string };
  /**
   * PROPOSED FIELD -- does not exist on any Ambush type today. INV-08's
   * `UNATTESTED - BY DESIGN` arm needs the partition state AT EXECUTION, and
   * `ResponseGovernanceAudit` carries only {governing_agent_id, reason, receipt}
   * (AMB crates/swarm-response/src/lib.rs:137-142). See 16-INVARIANT-TESTS.md
   * section 7.2 for the one-field bill addendum this depends on.
   */
  partition_state_at_hold: "healthy" | "degraded" | "partitioned" | "healing" | null;
};

export type PerchMockContainment = {
  lease_id: string;
  action_kind: string;
  /** Saturates at zero (AMB crates/swarm-response/src/containment.rs:276). */
  remaining_ms: number;
  /** True on a still-listed row means the sweep TRIED AND FAILED. */
  expired: boolean;
};

export type PerchMockDecideOutcome = {
  outcome:
    | "dispatched"
    | "refused_late"
    | "refused_late_governance"
    | "expired"
    | "unknown_hold"
    /**
     * 409 hold_already_deciding / hold_already_decided with a decision id that
     * is not this console's leg-1 event id. INV-36's outcome.
     */
    | "superseded";
  /** The daemon's own rule name. Rendered verbatim; never summarised. */
  rule: string | null;
  reason: string | null;
  receipt_id: string | null;
  /** The WINNING leg-1 card's Nostr event id, non-null iff outcome is superseded. */
  superseded_by?: string | null;
  /** Latency the mock waits before answering, so INV-33's `sending` state is observable. */
  delay_ms?: number;
};

export type PerchFixture = {
  holds: PerchMockHold[];
  containments: PerchMockContainment[];
  /** Keyed by hold_id. A hold with no entry answers `dispatched`. */
  decide: Record<string, PerchMockDecideOutcome>;
  /** INV-35: hold ids the RELAY carries that `GET /v1/response/holds` does not. */
  relayOnlyHoldIds: string[];
  /**
   * INV-35's split. `false` means the daemon's hold store is in memory (the
   * SHIPPED DEFAULT: `hold_store_path` is `None`, so a restart forgets every
   * open hold). A relay-known hold missing from a non-durable store is an
   * ordinary restart, and 12-BACKEND-BILL-API.md section 4.3 calls that state
   * *unreconcilable* -- not forged.
   */
  storeDurable: boolean;
  admittedIssuers: string[];
  /** Frozen clock for the mock's `now_ms`, so a TTL test does not sleep an hour. */
  nowMs: number;
};

export function perchFixture(overrides: Partial<PerchFixture> = {}): PerchFixture {
  const fixture: PerchFixture = {
    holds: [],
    containments: [],
    decide: {},
    relayOnlyHoldIds: [],
    storeDurable: false,
    admittedIssuers: [PERCH_ADMITTED_ISSUER],
    nowMs: PERCH_NOW_MS,
    ...overrides,
  };
  for (const hold of fixture.holds) assertHoldId(hold.hold_id);
  for (const holdId of fixture.relayOnlyHoldIds) assertHoldId(holdId);
  return fixture;
}

export function perchHold(overrides: Partial<PerchMockHold> = {}): PerchMockHold {
  const heldAt = 1_773_738_882_600;
  const hold: PerchMockHold = {
    hold_id: PERCH_HOLD_A,
    action_kind: "isolate_host",
    severity: "CRITICAL",
    case_channel: PERCH_CASE_CHANNEL,
    held_at_ms: heldAt,
    expires_at_ms: heldAt + PERCH_HOLD_TTL_MS,
    state: "notified",
    containment_lease_id: null,
    every_step_reversible: true,
    rationale: {
      rule_name: "static.human_gate",
      reason: "authorized but held for human approval",
    },
    partition_state_at_hold: "healthy",
    ...overrides,
  };
  assertHoldId(hold.hold_id);
  return hold;
}

// ── SEEDING ─────────────────────────────────────────────────────────────────

/**
 * MUST be awaited BEFORE installMockBridge(page).
 *
 * Omit `fixture` entirely to run against the canonical `hellcat-office`
 * scenario: `perchBridgeFixtures.ts` falls back to it when the seam is unset,
 * which is what keeps one scenario canonical rather than five.
 */
export async function installPerchBridge(page: Page, fixture?: PerchFixture) {
  if (!fixture) return;
  await page.addInitScript((seed) => {
    (window as unknown as { __BUZZ_E2E_PERCH__?: unknown }).__BUZZ_E2E_PERCH__ = seed;
  }, fixture);
}

/**
 * The queue reconciles `query_needs_action` against `GET /v1/response/holds`
 * (APPENDIX-NORMATIVE.md section 4 layer 3) before it renders a decidable row.
 *
 * Waiting on the RENDERED attribute rather than a window flag means a spec
 * asserting "zero rows" cannot pass by racing the first fetch, AND the thing
 * being waited on is the thing INV-35 asserts about.
 */
export async function waitForPerchQueue(page: Page) {
  await expect(page.locator("[data-perch-queue-reconciled='true']")).toBeVisible();
}

type PerchControl = {
  emitEphemeral: (frame: { kind: number; pubkey: string; payload: unknown }) => void;
  advanceClock: (deltaMs: number) => void;
};

/**
 * Emit a 26006 hold alarm -- the only live path, because the two-arm fork makes
 * 46010 channel-scoped and global subscriptions never receive channel-scoped
 * events (BUZZ crates/buzz-relay/src/subscription.rs:486-491).
 *
 * `issuer` defaults to the admitted bridge identity; pass
 * PERCH_UNADMITTED_ISSUER to drive the counted-and-dropped arm.
 */
export async function emitPerchHoldAlarm(
  page: Page,
  alarm: {
    holdId: string;
    actionKind: string;
    severity: string;
    caseChannel: string;
    expiresAtMs: number;
    issuer?: string;
  },
) {
  assertHoldId(alarm.holdId);
  await page.evaluate((input) => {
    const control = (window as unknown as { __BUZZ_E2E_PERCH_CONTROL__?: PerchControl })
      .__BUZZ_E2E_PERCH_CONTROL__;
    if (!control) throw new Error("__BUZZ_E2E_PERCH_CONTROL__ is not installed");
    control.emitEphemeral({
      kind: 26006,
      pubkey: input.issuer,
      payload: {
        hold_id: input.holdId,
        action_kind: input.actionKind,
        severity: input.severity,
        case_channel: input.caseChannel,
        expires_at_ms: input.expiresAtMs,
      },
    });
  }, { ...alarm, issuer: alarm.issuer ?? PERCH_ADMITTED_ISSUER });
}

/**
 * Emit a kind:9 card carrying an `ambush:*:v1` marker into a case channel.
 * `signerPubkey` is the RAW event signer, not a delegated display author --
 * admission is a signature question (17-COMPONENT-SPECS.md section 3.4).
 *
 * Uses the EXISTING `__BUZZ_E2E_EMIT_MOCK_MESSAGE__` seam (22-DEMO-FIXTURE.md's
 * commitment: the seed edits nothing). The card body grammar is
 * 13-WIRE-SCHEMAS.md's: marker alone on line 0, blank line, fenced JSON.
 */
export async function emitAmbushCard(
  page: Page,
  card: { channelName: string; marker: string; body: unknown; signerPubkey: string; hTag?: string },
) {
  await page.evaluate((input) => {
    (
      window as unknown as {
        __BUZZ_E2E_EMIT_MOCK_MESSAGE__?: (message: {
          channelName: string;
          content: string;
          pubkey: string;
          extraTags?: string[][];
        }) => unknown;
      }
    ).__BUZZ_E2E_EMIT_MOCK_MESSAGE__?.({
      channelName: input.channelName,
      content:
        `<!-- ${input.marker} -->\n` +
        `${input.humanLine}\n\n` +
        "```" +
        `${input.marker}\n${JSON.stringify(input.body)}\n` +
        "```",
      pubkey: input.signerPubkey,
      extraTags: input.hTag ? [["h", input.hTag]] : undefined,
    });
  }, { ...card, humanLine: `${card.marker} card` });
}

/** Advance the mock daemon's frozen clock. INV-18 uses this instead of sleeping. */
export async function advancePerchClock(page: Page, deltaMs: number) {
  await page.evaluate((delta) => {
    const control = (window as unknown as { __BUZZ_E2E_PERCH_CONTROL__?: PerchControl })
      .__BUZZ_E2E_PERCH_CONTROL__;
    if (!control) throw new Error("__BUZZ_E2E_PERCH_CONTROL__ is not installed");
    control.advanceClock(delta);
  }, deltaMs);
}

/** Read a rendered counter. A counter nobody renders is a counter nobody reads. */
export async function readPerchCounter(page: Page, name: string): Promise<number> {
  const text = await page.locator(`[data-perch-counter="${name}"]`).innerText();
  const value = Number.parseInt(text.replace(/[^0-9-]/g, ""), 10);
  if (Number.isNaN(value)) throw new Error(`counter ${name} rendered ${JSON.stringify(text)}`);
  return value;
}

/** Read the export manifest the Ledger renders, as JSON. */
export async function readPerchExportManifest(page: Page): Promise<Record<string, unknown>> {
  const text = await page.locator("[data-perch-export-manifest]").innerText();
  return JSON.parse(text) as Record<string, unknown>;
}
