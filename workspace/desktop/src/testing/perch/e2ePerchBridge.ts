/**
 * The mock answers for every `perch_*` Tauri command.
 *
 * A delegated module rather than seven more arms in `e2eBridge.ts`: the perch
 * command set is closed and named in one place (`PERCH_TAURI_COMMANDS`), so the
 * bridge's own dispatch keeps one prefix guard and this file answers all of
 * them. A perch command the console calls and this file does not answer throws
 * with the command's name, which is what turns a missing mock into a legible
 * failure rather than "Unsupported mocked Tauri command".
 *
 * These values are fixtures, not fetched: the E2E build has no daemon.
 */

/**
 * The bridge identity every mock finding card is signed by. Tests that assert
 * the unadmitted path sign with a different key.
 */
export const MOCK_PERCH_BRIDGE_PUBKEY =
  "207176338a897b2379564322033e86ed7197600499ba348e6c6c898b8139b586";

/** The colony the mock daemon speaks for. */
export const MOCK_PERCH_COLONY_ID = "colony-e2e";

/**
 * The lane channels the console subscribes to. Two of the twelve, which is
 * enough to prove the lane-movement REQ is built from this answer and not from
 * a hardcoded list in the renderer.
 */
export const MOCK_PERCH_LANES: Readonly<Record<string, string>> = Object.freeze(
  {
    execution: "a30249d7-446b-4135-8e9f-8704a5a052b1",
    persistence: "b4c1f0e2-8f31-4a67-9d2c-1e5b7a90c334",
  },
);

type MockPerchState = {
  issuers: string[];
  lanes: Record<string, string>;
  colonyId: string;
};

let state: MockPerchState = freshState();

function freshState(): MockPerchState {
  return {
    issuers: [MOCK_PERCH_BRIDGE_PUBKEY],
    lanes: { ...MOCK_PERCH_LANES },
    colonyId: MOCK_PERCH_COLONY_ID,
  };
}

/** Reset every mocked perch answer to its fixture default. */
export function resetMockPerchState(): void {
  state = freshState();
}

/**
 * Override the admitted-issuer answer for one spec — the seam the
 * unadmitted-marker spec uses to admit nobody.
 */
export function setMockPerchIssuers(issuers: readonly string[]): void {
  state.issuers = [...issuers];
}

/** True when `command` is one this module answers. */
export function isMockPerchCommand(command: string): boolean {
  return command.startsWith("perch_");
}

/**
 * Answer one `perch_*` command. Throws for a perch command with no fixture, so
 * a new command lands with its mock or fails loudly in the smoke project.
 */
export function handleMockPerchCommand(
  command: string,
  _payload: unknown,
): unknown {
  switch (command) {
    case "perch_admitted_issuers":
      return {
        issuers: [...state.issuers],
        lanes: { ...state.lanes },
        colony_id: state.colonyId,
      };
    case "perch_reviewed_findings":
      // An honest empty window: the daemon has ruled on nothing in this
      // fixture, and says so rather than pretending its record is complete.
      return {
        schema_version: 1,
        observed_at_ms: Date.now(),
        reviewed: [],
        window_incident_count: 0,
        window_is_truncated: false,
        window_oldest_incident_at_ms: null,
        store_durable: false,
      };
    default:
      throw new Error(`Unmocked perch Tauri command: ${command}`);
  }
}
