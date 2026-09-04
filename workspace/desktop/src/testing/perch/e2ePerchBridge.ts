import {
  readPerchCounter,
  type PerchCounterName,
} from "@/features/perch-evidence/lib/admittedIssuers";
import {
  PERCH_TAURI_COMMANDS,
  type PerchAdmittedIssuers,
  type PerchFindingAction,
  type PerchFindingFeedbackResponse,
  type PerchMintIncidentResponse,
  type PerchReviewedFinding,
  type PerchReviewedFindingsResponse,
} from "@/shared/api/tauriPerch";

/**
 * The mock answers for every `perch_*` Tauri command, and the fixture seam the
 * Playwright specs drive them through.
 *
 * A delegated module rather than five more arms in `e2eBridge.ts`: the perch
 * command set is closed and named in one place (`PERCH_TAURI_COMMANDS`), so
 * the bridge's own dispatch keeps one prefix guard and this file answers all
 * of them. A perch command the console calls and this file does not answer
 * fails the module's import-time assertion, which is what turns a missing mock
 * into a legible failure rather than "Unsupported mocked Tauri command".
 *
 * # Two legs, two mocks, no shortcut between them
 *
 * `perch_record_verdict` is a RELAY write and `perch_finding_feedback` is a
 * DAEMON write. They fail independently here — `daemonReachable: false` takes
 * leg 2 offline and leaves leg 1 working — precisely so a spec can prove the
 * console never renders one leg's success as the other's. Every answered
 * command is appended to an ordered log, so "leg 1 then leg 2" and "a retry
 * calls leg 2 only" are assertions about observed calls rather than about
 * rendered copy.
 *
 * These values are fixtures, not fetched: the E2E build has no daemon.
 */

// ===========================================================================
// The fixture's fixed points. Specs import these rather than repeating a
// literal, so a change here moves every assertion with it.
// ===========================================================================

/**
 * The bridge identity every admitted mock card is signed by. Specs that
 * exercise the unadmitted path sign with `PERCH_UNADMITTED_ISSUER`.
 */
export const PERCH_ADMITTED_ISSUER =
  "207176338a897b2379564322033e86ed7197600499ba348e6c6c898b8139b586";

/**
 * A well-formed key that is NOT in the admitted set. The marker-admission
 * spec signs its forgery with this, so the only difference between the two
 * messages is the raw signer.
 */
export const PERCH_UNADMITTED_ISSUER =
  "9b4a1d77c0f2e5389a6c4b10de23f7a85c19b046ff7128e3ad50c96b2e814f30";

/** The colony the mock daemon speaks for. */
export const PERCH_COLONY_ID = "colony-e2e";

/**
 * The lane the specs render cards in. It is a real mock channel id
 * (`random`), because a lane the mock bridge cannot navigate to is a lane no
 * spec can open.
 */
export const PERCH_LANE_CHANNEL = "9dae0116-799b-5071-a0a8-fdd30a91a35d";

/** The mock channel name behind `PERCH_LANE_CHANNEL`. */
export const PERCH_LANE_CHANNEL_NAME = "random";

/**
 * A second lane, so the subscription manager is fed a map rather than one
 * value and a hardcoded single lane in the renderer would be visible.
 */
export const PERCH_SECOND_LANE_CHANNEL = "1c7e1c02-87bb-5e88-b2da-5a7a9432d0c9";

/** The threat-class slug to lane-channel map the daemon serves (D-FC-2). */
export const PERCH_LANES: Readonly<Record<string, string>> = Object.freeze({
  data_exfiltration: PERCH_LANE_CHANNEL,
  persistence: PERCH_SECOND_LANE_CHANNEL,
});

/**
 * The event id the admitted finding card is emitted under. Fixed rather than
 * generated so the mock can answer `perch_record_verdict` for it the way the
 * real command answers: by reading the finding id off the named card.
 */
export const PERCH_FINDING_CARD_EVENT_ID =
  "5f1c3b9a204e7d68c1a4b0937e25fd8146ac9b3e70d25f81cc4a6b93e017d2af";

/** `locator.finding_id` in `golden/card-swarm-finding-v1.json`. */
export const PERCH_FINDING_ID = "f2c9a1b4";

/**
 * The case the mock daemon mints for `PERCH_FINDING_ID`, and its incident.
 * Both are derived, so a spec that promotes a second finding gets a second
 * case without a second constant.
 */
export const PERCH_CASE_CHANNEL = mintedCaseId(PERCH_FINDING_ID);
export const PERCH_INCIDENT_ID = mintedIncidentId(PERCH_FINDING_ID);

/**
 * The mock daemon's clock, in milliseconds. Equal to the golden finding's
 * `emitted_at_ms`, so a rendered timestamp and a fixture timestamp agree.
 */
export const PERCH_NOW_MS = 1_787_754_972_123;

/** The operator id `rulesets-dev/perch-dev.yaml`'s principal carries (D-FC-4). */
export const PERCH_OPERATOR_ID = "local-operator";

/** The operator's Ed25519 verifying key, as the real command would return it. */
const PERCH_OPERATOR_PUBLIC_KEY =
  "3c8ab41e5d90672fbc1e04a7d3859bf620c7a1e48db35f0296e17ca4b8032d15";

// ===========================================================================
// The fixture
// ===========================================================================

/**
 * Everything a spec may vary. Seeded through `window.__AMBUSH_E2E_PERCH__`
 * before the app loads, or through `window.__AMBUSH_E2E_PERCH_SEED__` at any
 * point after it. Every field is optional; the defaults are an honest daemon
 * with one admitted bridge and an empty review window.
 */
export type PerchMockFixture = {
  /** The admitted bridge identities (INV-15). `[]` admits nobody. */
  issuers?: readonly string[];
  /** Threat-class slug to lane channel id. */
  lanes?: Readonly<Record<string, string>>;
  colonyId?: string;
  /** Rows B3r reports before any verdict is recorded in this session. */
  reviewed?: readonly PerchReviewedFinding[];
  /** B3r's honest window flags. */
  windowIsTruncated?: boolean;
  storeDurable?: boolean;
  /** The mock daemon's clock. */
  nowMs?: number;
  /** Finding card event id to the `locator.finding_id` it carries. */
  findings?: Readonly<Record<string, string>>;
  /**
   * When false every DAEMON-bound command throws as an unreachable host.
   * Leg 1 is a relay write and is deliberately unaffected.
   */
  daemonReachable?: boolean;
  /**
   * When true B3 answers its 404: the daemon has not joined this finding to
   * an incident yet. Surfaced by the Rust command as `not-yet-correlated:`.
   */
  feedbackNotCorrelated?: boolean;
  /**
   * Hold leg 1 open for this long. A spec that must see `sending` needs the
   * relay write to take measurable time; the real one takes a round trip.
   */
  verdictDelayMs?: number;
  /**
   * Hold leg 2 open for this long. This is what makes the in-flight window
   * observable, and that window is where the two-leg contract is provable:
   * leg 1 reads "recorded on Ambush" while leg 2 still reads "sending".
   */
  feedbackDelayMs?: number;
};

type MockState = {
  issuers: string[];
  lanes: Record<string, string>;
  colonyId: string;
  reviewed: PerchReviewedFinding[];
  windowIsTruncated: boolean;
  storeDurable: boolean;
  nowMs: number;
  findings: Record<string, string>;
  daemonReachable: boolean;
  feedbackNotCorrelated: boolean;
  verdictDelayMs: number;
  feedbackDelayMs: number;
  /** `finding_id` to the ids the daemon minted for it. */
  minted: Map<string, { incident_id: string; case_id: string }>;
  /** `(finding_id, verdict_event_id)` to the one row B3 recorded. */
  feedback: Map<string, PerchFindingFeedbackResponse>;
  /** Every answered command, in order. */
  log: string[];
  /** How many relay verdict cards this session published. */
  verdicts: number;
};

function defaults(): MockState {
  return {
    issuers: [PERCH_ADMITTED_ISSUER],
    lanes: { ...PERCH_LANES },
    colonyId: PERCH_COLONY_ID,
    reviewed: [],
    windowIsTruncated: false,
    storeDurable: false,
    nowMs: PERCH_NOW_MS,
    findings: { [PERCH_FINDING_CARD_EVENT_ID]: PERCH_FINDING_ID },
    daemonReachable: true,
    feedbackNotCorrelated: false,
    verdictDelayMs: 0,
    feedbackDelayMs: 0,
    minted: new Map(),
    feedback: new Map(),
    log: [],
    verdicts: 0,
  };
}

let state: MockState | null = null;

/**
 * The fixture seam. `page.addInitScript` writes it before the app bundle
 * evaluates, so the first command already sees the spec's fixture.
 */
declare global {
  interface Window {
    __AMBUSH_E2E_PERCH__?: PerchMockFixture;
    __AMBUSH_E2E_PERCH_SEED__?: (fixture: PerchMockFixture) => void;
    __AMBUSH_E2E_PERCH_LOG__?: () => string[];
    __AMBUSH_E2E_PERCH_RESET__?: () => void;
    __AMBUSH_E2E_PERCH_COUNTER__?: (name: PerchCounterName) => number;
  }
}

function current(): MockState {
  if (!state) {
    state = defaults();
    if (typeof window !== "undefined" && window.__AMBUSH_E2E_PERCH__) {
      applyFixture(state, window.__AMBUSH_E2E_PERCH__);
    }
  }
  return state;
}

function applyFixture(target: MockState, fixture: PerchMockFixture): void {
  if (fixture.issuers) target.issuers = [...fixture.issuers];
  if (fixture.lanes) target.lanes = { ...fixture.lanes };
  if (fixture.colonyId !== undefined) target.colonyId = fixture.colonyId;
  if (fixture.reviewed) target.reviewed = [...fixture.reviewed];
  if (fixture.windowIsTruncated !== undefined) {
    target.windowIsTruncated = fixture.windowIsTruncated;
  }
  if (fixture.storeDurable !== undefined) {
    target.storeDurable = fixture.storeDurable;
  }
  if (fixture.nowMs !== undefined) target.nowMs = fixture.nowMs;
  if (fixture.findings) {
    target.findings = { ...target.findings, ...fixture.findings };
  }
  if (fixture.daemonReachable !== undefined) {
    target.daemonReachable = fixture.daemonReachable;
  }
  if (fixture.feedbackNotCorrelated !== undefined) {
    target.feedbackNotCorrelated = fixture.feedbackNotCorrelated;
  }
  if (fixture.verdictDelayMs !== undefined) {
    target.verdictDelayMs = fixture.verdictDelayMs;
  }
  if (fixture.feedbackDelayMs !== undefined) {
    target.feedbackDelayMs = fixture.feedbackDelayMs;
  }
}

/**
 * Answer after `ms`, or right now when it is zero. A zero delay stays
 * synchronous so the node tests can read the answer without awaiting.
 */
function after<T>(ms: number, value: () => T): T | Promise<T> {
  if (ms <= 0) return value();
  return new Promise<T>((resolve, reject) => {
    setTimeout(() => {
      try {
        resolve(value());
      } catch (error) {
        reject(error);
      }
    }, ms);
  });
}

/**
 * Merge `fixture` into the mock's state, keeping everything it does not
 * name. Recorded rows and the command log survive, so a spec can take the
 * daemon offline mid-workflow and bring it back without losing leg 1.
 */
export function seedPerchFixture(fixture: PerchMockFixture): void {
  applyFixture(current(), fixture);
}

/** Drop every mocked perch answer and every recorded row. */
export function resetPerchMock(): void {
  state = defaults();
}

/** Every perch command answered since the last reset, in order. */
export function perchMockLog(): string[] {
  return [...current().log];
}

// ===========================================================================
// Deterministic ids
// ===========================================================================

/**
 * A stable v4-shaped UUID for `seed`. Deterministic so a spec can name the
 * case the daemon will mint before it presses the key that mints it, and so
 * a replay across a page navigation answers the same id.
 */
function deterministicUuid(seed: string): string {
  const bytes: number[] = [];
  for (let round = 0; bytes.length < 16; round += 1) {
    let hash = 0x811c9dc5;
    for (const character of `${round}:${seed}`) {
      hash ^= character.codePointAt(0) ?? 0;
      hash = Math.imul(hash, 0x01000193) >>> 0;
    }
    bytes.push(
      (hash >>> 24) & 0xff,
      (hash >>> 16) & 0xff,
      (hash >>> 8) & 0xff,
      hash & 0xff,
    );
  }
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.map((b) => b.toString(16).padStart(2, "0")).join("");
  return [
    hex.slice(0, 8),
    hex.slice(8, 12),
    hex.slice(12, 16),
    hex.slice(16, 20),
    hex.slice(20, 32),
  ].join("-");
}

/** The case channel the mock daemon mints for one finding. */
export function mintedCaseId(findingId: string): string {
  return deterministicUuid(`case:${findingId}`);
}

/**
 * The incident id the mock daemon mints. The `incident:perch-case:` prefix
 * is the one `perch_record_verdict` validates, so a fixture that dropped it
 * would pass here and fail in Rust.
 */
export function mintedIncidentId(findingId: string): string {
  return `incident:perch-case:${mintedCaseId(findingId)}`;
}

/** 64 lowercase hex, deterministic in `seed`. */
function deterministicHex64(seed: string): string {
  return `${deterministicUuid(`a:${seed}`)}${deterministicUuid(`b:${seed}`)}`
    .replace(/-/g, "")
    .padEnd(64, "0")
    .slice(0, 64);
}

// ===========================================================================
// The closed command set
// ===========================================================================

/**
 * Every command this module answers. Compared against `PERCH_TAURI_COMMANDS`
 * at import, so a command added to the console without a mock fails the whole
 * smoke project at load rather than one spec at its first click.
 */
export const PERCH_HANDLED_COMMANDS: readonly string[] = Object.freeze([
  "perch_admitted_issuers",
  "perch_reviewed_findings",
  "perch_record_verdict",
  "perch_finding_feedback",
  "perch_mint_incident",
]);

/**
 * Refuse a console command set this module cannot answer. Exported so the
 * refusal itself has a test; called at module scope with the real set.
 *
 * @throws when `commands` contains a member `PERCH_HANDLED_COMMANDS` omits.
 */
export function assertEveryPerchCommandHandled(
  commands: readonly string[],
): void {
  const handled = new Set(PERCH_HANDLED_COMMANDS);
  const missing = commands.filter((command) => !handled.has(command));
  if (missing.length > 0) {
    throw new Error(
      `e2ePerchBridge has no mock for: ${missing.join(", ")}. Add an arm to handlePerchMockCommand and a name to PERCH_HANDLED_COMMANDS.`,
    );
  }
}

assertEveryPerchCommandHandled(PERCH_TAURI_COMMANDS);

/** True when `command` is one this module answers. */
export function isPerchMockCommand(command: string): boolean {
  return command.startsWith("perch_");
}

// ===========================================================================
// The answers
// ===========================================================================

/**
 * The Rust side's own prefix for a daemon it could not reach
 * (`daemon unreachable: {e}` in `perch/daemon_client.rs`). The console
 * classifies leg-2 outcomes by this prefix, so a mock that spelled it
 * differently would exercise the wrong branch and prove nothing.
 */
export const PERCH_DAEMON_UNREACHABLE_PREFIX = "daemon unreachable:";

function unreachable(): never {
  throw new Error(
    `${PERCH_DAEMON_UNREACHABLE_PREFIX} error sending request for url (http://127.0.0.1:9090)`,
  );
}

function admittedIssuers(): PerchAdmittedIssuers {
  const s = current();
  return {
    issuers: [...s.issuers],
    lanes: { ...s.lanes },
    colony_id: s.colonyId,
  };
}

function reviewedFindings(): PerchReviewedFindingsResponse {
  const s = current();
  const recorded: PerchReviewedFinding[] = [...s.feedback.values()].map(
    (row) => ({
      finding_id: row.finding_id,
      reviewed_at_ms: s.nowMs,
      action: row.action,
      analyst_id: row.analyst_id,
      false_positive: row.false_positive,
      incident_id: row.incident_id,
      strategy_id: "dns_exfil_beaconing",
      host_id: "web-04",
    }),
  );
  const reviewed = [...s.reviewed, ...recorded];
  return {
    schema_version: 1,
    observed_at_ms: s.nowMs,
    reviewed,
    window_incident_count: reviewed.length,
    window_is_truncated: s.windowIsTruncated,
    window_oldest_incident_at_ms: reviewed.length > 0 ? s.nowMs : null,
    store_durable: s.storeDurable,
  };
}

function mintIncident(payload: unknown): PerchMintIncidentResponse {
  const s = current();
  if (!s.daemonReachable) unreachable();
  const input = (payload as { input?: { findingId?: string } } | null)?.input;
  const findingId = input?.findingId;
  if (!findingId) {
    throw new Error("daemon answered 400: findingId is required");
  }
  const existing = s.minted.get(findingId);
  const ids = existing ?? {
    incident_id: mintedIncidentId(findingId),
    case_id: mintedCaseId(findingId),
  };
  s.minted.set(findingId, ids);
  return {
    schema_version: 1,
    incident_id: ids.incident_id,
    case_id: ids.case_id,
    created: existing === undefined,
    degraded: [],
    record: { finding_id: findingId },
  };
}

type FeedbackPayload = {
  findingId?: string;
  incidentId?: string;
  action?: PerchFindingAction;
  verdictEventId?: string;
  reason?: string | null;
};

function findingFeedback(payload: unknown): PerchFindingFeedbackResponse {
  const s = current();
  if (!s.daemonReachable) unreachable();
  const input = (payload ?? {}) as FeedbackPayload;
  const findingId = input.findingId ?? "";
  const verdictEventId = input.verdictEventId ?? "";
  const action = input.action ?? "dismiss";
  if (!findingId || !verdictEventId) {
    throw new Error(
      "daemon answered 400: findingId and verdictEventId are required",
    );
  }
  if (s.feedbackNotCorrelated) {
    // The Rust command maps B3's 404 onto this exact prefix, and the console
    // treats it as a state rather than as a failure.
    throw new Error("not-yet-correlated: no incident carries this finding yet");
  }
  const key = `${findingId} ${verdictEventId}`;
  const existing = s.feedback.get(key);
  if (existing) return { ...existing, replayed: true };
  const row: PerchFindingFeedbackResponse = {
    schema_version: 1,
    feedback_id: deterministicHex64(`feedback:${key}`).slice(0, 32),
    action,
    incident_id: input.incidentId ?? mintedIncidentId(findingId),
    finding_id: findingId,
    analyst_id: PERCH_OPERATOR_ID,
    false_positive: action === "dismiss",
    replayed: false,
    outcome: { suppression_recalculated: true },
  };
  s.feedback.set(key, row);
  return row;
}

type RecordVerdictPayload = {
  input?: {
    findingCardId?: string;
    caseChannel?: string;
    incidentId?: string;
    decision?: PerchFindingAction;
    rationale?: string | null;
  };
};

function recordVerdict(payload: unknown) {
  const s = current();
  const input = (payload as RecordVerdictPayload | null)?.input ?? {};
  const cardId = input.findingCardId ?? "";
  const findingId = s.findings[cardId];
  if (!findingId) {
    // The real command queries the relay for the card and refuses when it is
    // absent or unadmitted. The renderer never supplies the finding id.
    throw new Error("finding card not found on the relay");
  }
  s.verdicts += 1;
  const nonce = `${cardId}:${s.verdicts}`;
  return {
    nostr_intent_event_id: deterministicHex64(`intent:${nonce}`),
    decided_at_ms: s.nowMs,
    signature: {
      algorithm: "ed25519",
      key_id: PERCH_OPERATOR_ID,
      public_key_hex: PERCH_OPERATOR_PUBLIC_KEY,
      signature_hex: `${deterministicHex64(`sig-a:${nonce}`)}${deterministicHex64(`sig-b:${nonce}`)}`,
    },
    finding_id: findingId,
  };
}

/**
 * Answer one `perch_*` command. Throws for a perch command with no fixture,
 * so a new command lands with its mock or fails loudly in the smoke project.
 */
export function handlePerchMockCommand(
  command: string,
  payload: unknown,
): unknown {
  const s = current();
  switch (command) {
    case "perch_admitted_issuers":
      s.log.push(command);
      return admittedIssuers();
    case "perch_reviewed_findings":
      s.log.push(command);
      return reviewedFindings();
    case "perch_mint_incident":
      s.log.push(command);
      return mintIncident(payload);
    case "perch_record_verdict":
      s.log.push(command);
      return after(s.verdictDelayMs, () => recordVerdict(payload));
    case "perch_finding_feedback":
      s.log.push(command);
      return after(s.feedbackDelayMs, () => findingFeedback(payload));
    default:
      throw new Error(`Unmocked perch Tauri command: ${command}`);
  }
}

/**
 * Install the runtime control seams a spec drives the fixture through. Called
 * at import so `e2eBridge.ts` needs no second edit; guarded for the node
 * tests, which import this module with no `window`.
 */
export function installPerchControlSeams(target: Window): void {
  target.__AMBUSH_E2E_PERCH_SEED__ = seedPerchFixture;
  target.__AMBUSH_E2E_PERCH_LOG__ = perchMockLog;
  target.__AMBUSH_E2E_PERCH_RESET__ = resetPerchMock;
  // The unadmitted-marker counter is renderer state, not mock state: it is
  // the number INV-15 requires a refused marker to be counted in, and a spec
  // that asserted only "the notice rendered" would not be asserting it.
  target.__AMBUSH_E2E_PERCH_COUNTER__ = readPerchCounter;
}

if (typeof window !== "undefined") {
  installPerchControlSeams(window);
}
