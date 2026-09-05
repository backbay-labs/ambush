// The console's hold types against the daemon's real bytes.
//
// `src/testing/perch/daemonHoldFixture.json` was produced by serialising
// `HoldListResponse` and `HeldActionView` from
// `crates/swarm-runtime-http/src/http/perch/holds.rs` at d6b0c6eb3, through
// the mounted axum route for the list and through `HeldActionView::from_hold`
// for the decided view. It is not a hand-written sample: a field that appears
// on one side and not the other fails here rather than at 3am on a hold
// nobody can read.

import { readdirSync, readFileSync } from "node:fs";

import assert from "node:assert/strict";
import test from "node:test";

/**
 * Every Rust file that could register a perch Tauri command.
 *
 * The whole commands directory, not a hand-written list: a hand-written list
 * silently loses coverage when a file is split or renamed, which is exactly
 * what happened when the hold commands moved to `perch_verdict_hold.rs` — the
 * list still named three files and the guard reported nine commands where it
 * had seen ten.
 */
const PERCH_RUST_COMMAND_DIR = new URL(
  "../../../src-tauri/src/commands/",
  import.meta.url,
);
const PERCH_RUST_COMMAND_FILES = readdirSync(PERCH_RUST_COMMAND_DIR)
  .filter((name) => name.endsWith(".rs"))
  .map((name) => `../../../src-tauri/src/commands/${name}`);

import fixture from "../../testing/perch/daemonHoldFixture.json" with {
  type: "json",
};
import {
  PERCH_HOLD_DTO_KEYS,
  PERCH_READ_COMMANDS,
  PERCH_TAURI_COMMANDS,
} from "./tauriPerch.ts";

const listResponse = fixture.list;
const openHold = fixture.list.holds[0];
const decidedHold = fixture.decided_hold;

function assertSameKeys(actual, expected, label) {
  assert.deepEqual(
    [...actual].sort(),
    [...expected].sort(),
    `${label}: the console's type and the daemon's body disagree`,
  );
}

test("HoldListResponse carries exactly the fields the console types", () => {
  assertSameKeys(
    Object.keys(listResponse),
    PERCH_HOLD_DTO_KEYS.HoldListResponse,
    "HoldListResponse",
  );
  // The two the wave-2 drafts omitted, named so a later edit cannot quietly
  // drop them: `truncated` says the page is short of the store, and
  // `store_durable` is the difference between "no holds" and "no memory".
  assert.equal(typeof listResponse.truncated, "boolean");
  assert.equal(typeof listResponse.store_durable, "boolean");
  assert.equal(typeof listResponse.open_count, "number");
});

test("HeldActionView carries exactly the fields the console types", () => {
  assertSameKeys(
    Object.keys(openHold),
    PERCH_HOLD_DTO_KEYS.HeldActionView,
    "HeldActionView (open)",
  );
  assertSameKeys(
    Object.keys(decidedHold),
    PERCH_HOLD_DTO_KEYS.HeldActionView,
    "HeldActionView (decided)",
  );
  // W3-26: leg 1 is built from daemon state, so all three relay pointers must
  // be on the view or the console would have to guess one of them.
  for (const field of ["case_channel", "notice_event_id", "card_event_id"]) {
    assert.ok(field in decidedHold, `HeldActionView lost ${field}`);
  }
});

test("remaining_ms and expired are two separate facts", () => {
  assert.equal(typeof openHold.remaining_ms, "number");
  assert.equal(typeof openHold.expired, "boolean");
  assert.notEqual(
    openHold.state,
    openHold.expired,
    "state and expired are different questions and must stay different fields",
  );
});

test("HoldDecisionRecord and HoldRationale carry exactly what the console types", () => {
  assertSameKeys(
    Object.keys(decidedHold.decision),
    PERCH_HOLD_DTO_KEYS.HoldDecisionRecord,
    "HoldDecisionRecord",
  );
  assertSameKeys(
    Object.keys(decidedHold.rationale),
    PERCH_HOLD_DTO_KEYS.HoldRationale,
    "HoldRationale",
  );
  assert.equal(decidedHold.decision.decision, "grant");
  assert.equal(
    decidedHold.decision.governance_clearance,
    "not_required",
    "no clearance variant is named `verified`; nothing here establishes one",
  );
});

test("severity is SCREAMING_SNAKE and state is snake_case on the wire", () => {
  assert.equal(openHold.severity, "CRITICAL");
  assert.equal(openHold.state, "notified");
  assert.equal(decidedHold.state, "executed");
});

test("inverse_resolution names its producing function and omits an absent reason", () => {
  const steps = decidedHold.inverse_resolution;
  assert.ok(steps.length >= 2);
  for (const step of steps) {
    assert.equal(step.derived_by, "swarm_response::rollback::resolve_inverse");
    assert.ok(
      ["executable", "irreversible", "unmapped"].includes(step.verdict),
    );
  }
  assert.ok(
    !("reason" in steps[0]),
    "an absent reason is ABSENT, not null: the type marks it optional",
  );
});

test("inverse_resolution step_kind is the Debug name, not the rollback slug", () => {
  // The daemon builds `step_kind` with `format!("{:?}")` while the same enum
  // serialises as snake_case inside `rehearsal.rollback.steps[].kind`. Joining
  // the two lists on the raw string is the obvious bug; this locks the fact
  // that they are spelled differently so nothing derives one from the other.
  assert.equal(
    decidedHold.inverse_resolution[0].step_kind,
    "RestoreHostConnectivity",
  );
  assert.equal(
    decidedHold.rehearsal.rollback.steps[0].kind,
    "restore_host_connectivity",
  );
});

test("the action carries its discriminator and the request carries its origin", () => {
  assert.equal(openHold.action_request.action.type, "isolate_host");
  assert.equal(openHold.action_kind, "isolate_host");
  assert.equal(typeof openHold.action_request.hunt_id, "string");
  assert.equal(typeof openHold.action_request.requested_by, "string");
});

test("policy_decision carries the verdict the wave-2 draft omitted", () => {
  assert.deepEqual(Object.keys(openHold.policy_decision).sort(), [
    "reason",
    "rule_name",
    "verdict",
  ]);
  assert.equal(openHold.policy_decision.verdict, "require_human");
});

test("the two hold reads are registered read commands, not writes", () => {
  for (const command of ["perch_list_holds", "perch_get_hold"]) {
    assert.ok(
      PERCH_READ_COMMANDS.includes(command),
      `${command} is missing from PERCH_READ_COMMANDS`,
    );
    assert.ok(PERCH_TAURI_COMMANDS.includes(command));
  }
  assert.equal(
    new Set(PERCH_TAURI_COMMANDS).size,
    PERCH_TAURI_COMMANDS.length,
    "a command listed twice would let the E2E bridge answer one and miss one",
  );
});

// Every command name this client sends must be a command the Rust side
// actually registers.
//
// This exists because it caught a live one during integration: the hold's
// leg-1 wrapper `perchRecordHoldVerdict` invoked `perch_record_verdict`, the
// FINDING command, whose input requires `finding_card_id`, `case_channel` and
// `incident_id`. Serde would have refused the hold payload at runtime. It went
// unnoticed because the E2E mock answered whatever name it was handed, so the
// mock proved the console talked to the mock and nothing about the product.
// A name is not a contract until something compares the two sides.
test("every perch command the client sends is registered in Rust", () => {
  const client = readFileSync(
    new URL("./tauriPerch.ts", import.meta.url),
    "utf8",
  );
  const registered = new Set();
  for (const file of PERCH_RUST_COMMAND_FILES) {
    const source = readFileSync(new URL(file, import.meta.url), "utf8");
    for (const m of source.matchAll(
      /#\[tauri::command\][\s\S]{0,120}?(?:pub )?(?:async )?fn (perch_\w+)/g,
    )) {
      registered.add(m[1]);
    }
  }
  assert.ok(registered.size >= 10, `found only ${registered.size} commands`);

  const invoked = [
    ...client.matchAll(/invokeTauri<[\s\S]*?>\(\s*"(perch_\w+)"/g),
    ...client.matchAll(/invokeTauri\(\s*"(perch_\w+)"/g),
  ].map((m) => m[1]);
  assert.ok(invoked.length >= 10, `found only ${invoked.length} invocations`);
  for (const name of new Set(invoked)) {
    assert.ok(
      registered.has(name),
      `the client invokes ${name}, which no #[tauri::command] registers`,
    );
  }
});

// The declared list drives the E2E mock's closed set, so a command that is
// invoked but not declared would ship with no mock and no failure until a spec
// happened to reach it. Both directions are asserted.
test("the declared command list is exactly what the client invokes", async () => {
  const client = readFileSync(
    new URL("./tauriPerch.ts", import.meta.url),
    "utf8",
  );
  const invoked = new Set(
    [...client.matchAll(/invokeTauri(?:<[\s\S]*?>)?\(\s*"(perch_\w+)"/g)].map(
      (m) => m[1],
    ),
  );
  const { PERCH_TAURI_COMMANDS } = await import("./tauriPerch.ts");
  assert.deepEqual(
    [...invoked].sort(),
    [...PERCH_TAURI_COMMANDS].sort(),
    "PERCH_TAURI_COMMANDS and the invocations in this file disagree",
  );
});

// The inverse for the two record commands specifically: they take different
// inputs, so sending one where the other is meant fails at deserialisation.
// Pinning the wrapper-to-command mapping keeps them from being swapped again.
test("each record wrapper invokes its own command", () => {
  const client = readFileSync(
    new URL("./tauriPerch.ts", import.meta.url),
    "utf8",
  );
  for (const [fn, command] of [
    ["perchRecordVerdict", "perch_record_verdict"],
    ["perchRecordHoldVerdict", "perch_record_hold_verdict"],
  ]) {
    const body = client.split(
      new RegExp(`export (?:async )?function ${fn}\\b`),
    )[1];
    assert.ok(body, `${fn} is not exported from tauriPerch.ts`);
    const sent = body.match(/"(perch_\w+)"/)?.[1];
    assert.equal(sent, command, `${fn} invokes ${sent}`);
  }
});

// Two defects found by reading the Rust signatures against this client while
// preparing the live walking skeleton, pinned from both sides. Every
// `perch_*` command binding one parameter named `input` must be invoked with
// `{ input }` — sent flat, Tauri answers "missing required key input". And
// every struct a `perch_*` command returns must serialize snake_case: the
// renderer reads `decided_at_ms`, and a `rename_all = "camelCase"` on the Rust
// side leaves it reading `undefined` in a real build while a snake_case mock
// keeps every E2E spec green.
test("input-shaped commands are invoked as { input } and outputs stay snake_case", () => {
  const client = readFileSync(
    new URL("./tauriPerch.ts", import.meta.url),
    "utf8",
  );
  const injected = /\b(State|AppHandle|Window|WebviewWindow|Webview)\b/;
  let inputShaped = 0;
  let outputsChecked = 0;
  for (const file of PERCH_RUST_COMMAND_FILES) {
    const source = readFileSync(new URL(file, import.meta.url), "utf8");
    for (const m of source.matchAll(
      /#\[tauri::command\][\s\S]{0,160}?fn (perch_\w+)\(([\s\S]*?)\)\s*->\s*([^{]+)\{/g,
    )) {
      const [, name, params, ret] = m;
      const named = params
        .split(/,(?![^<]*>)/)
        .map((p) => p.trim())
        .filter((p) => p && !injected.test(p))
        .map((p) => p.split(":")[0].trim());
      // The name also appears in the command-list constants, so take the
      // occurrence that is an `invokeTauri(` call: the one whose preceding
      // text, back to the last top-level `}`, contains `invokeTauri`.
      let invocation = null;
      for (const m of client.matchAll(
        new RegExp(`"${name}"\\s*(?:,\\s*([\\s\\S]*?))?\\)\\s*;`, "g"),
      )) {
        const before = client.slice(0, m.index);
        const call = before.slice(before.lastIndexOf("\n}\n"));
        if (/invokeTauri(?:<[\s\S]*?>)?\(\s*$/.test(call)) {
          invocation = m;
          break;
        }
      }
      // Commands invoked from other client files (identity, sidecar) are not
      // this file's contract; the registered-in-Rust guard covers direction.
      if (!invocation) continue;
      const args = (invocation[1] ?? "").trim();
      if (named.length === 1 && named[0] === "input") {
        inputShaped += 1;
        assert.ok(
          /^\{\s*input\b/.test(args),
          `${name} binds \`input\` but the client sends: ${args || "(nothing)"}`,
        );
      } else {
        assert.ok(
          !/^\{\s*input\b/.test(args),
          `${name} does not bind \`input\` but the client wraps one`,
        );
      }
      const returned = ret.match(/Result<\s*(\w+)\s*[,>]/)?.[1];
      if (!returned || !/^[A-Z]/.test(returned)) continue;
      const decl = source.indexOf(`pub struct ${returned}`);
      if (decl < 0) continue;
      outputsChecked += 1;
      const above = source.slice(Math.max(0, decl - 400), decl);
      // Attributes only: a comment explaining why there is NO rename must
      // not trip a lexical read of the word.
      const attrs = above
        .slice(above.lastIndexOf("\n}\n") + 1)
        .split("\n")
        .filter((line) => !line.trim().startsWith("//"))
        .join("\n");
      assert.ok(
        !/rename_all/.test(attrs),
        `${returned} (returned by ${name}) renames its fields; the renderer reads snake_case`,
      );
    }
  }
  assert.ok(
    inputShaped >= 4,
    `found only ${inputShaped} input-shaped commands`,
  );
  assert.ok(
    outputsChecked >= 3,
    `checked only ${outputsChecked} output structs`,
  );
});
