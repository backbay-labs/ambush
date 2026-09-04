// The Verdict Row's five slots, across every action kind the engine can hold.
//
// Built on the daemon's real `HeldActionView` bytes
// (`src/testing/perch/daemonHoldFixture.json`), overridden per action, so a
// builder that only works on a hand-simplified view fails here.
//
// The property under test is that the slot SET never varies. A pane that can
// omit a slot is a pane that can omit BLAST RADIUS on the one request where it
// mattered, and nothing in the rendering would look wrong.

import assert from "node:assert/strict";
import test from "node:test";

import fixture from "../../../testing/perch/daemonHoldFixture.json" with {
  type: "json",
};
import {
  buildVerdictSlots,
  VERDICT_SLOT_LABELS,
  VERDICT_SLOT_ORDER,
} from "./verdictSlots.ts";

const TTLS = { capabilityLeaseTtlMs: 60_000, containmentLeaseTtlMs: 900_000 };

/** The fifteen `ResponseAction` variants, with whether each takes a lease. */
const ACTIONS = [
  ["block_egress", { target: "203.0.113.10" }, false],
  ["isolate_host", { host_id: "h" }, true],
  ["revoke_credential", { credential_id: "c" }, false],
  ["sinkhole_dns", { domain: "d" }, false],
  ["terminate_user_session", { host_id: "h", session_id: "s" }, true],
  ["trigger_edr_scan", { host_id: "h", scan_profile: "quick" }, false],
  [
    "inject_firewall_rule",
    {
      host_id: "h",
      rule_name: "r",
      direction: "in",
      cidr: "10.0.0.0/8",
      port: null,
    },
    false,
  ],
  ["quarantine_file", { host_id: "h", file_path: "/tmp/x" }, true],
  ["kill_process", { host_id: "h", process_name: "p" }, false],
  ["suspend_process", { host_id: "h", process_name: "p" }, true],
  ["disable_user_account", { user_id: "u" }, false],
  ["force_password_reset", { user_id: "u" }, false],
  ["remove_scheduled_task", { host_id: "h", task_name: "t" }, false],
  ["deploy_decoy", { decoy_type: "honeytoken", target_zone: "z" }, false],
  ["escalate", { summary: "s", urgency: "HIGH" }, false],
];

const hold = (kind, fields, leased, extra = {}) => ({
  ...structuredClone(fixture.list.holds[0]),
  action_kind: kind,
  action_request: {
    ...structuredClone(fixture.list.holds[0].action_request),
    action: { type: kind, ...fields },
  },
  leases_a_containment: leased,
  ...extra,
});

for (const [kind, fields, leased] of ACTIONS) {
  test(`${kind}: five slots, fixed order, none empty`, () => {
    const slots = buildVerdictSlots(hold(kind, fields, leased), TTLS);
    assert.deepEqual(Object.keys(slots), [...VERDICT_SLOT_ORDER]);
    for (const id of VERDICT_SLOT_ORDER) {
      const slot = slots[id];
      if (slot.kind === "present") {
        assert.ok(slot.lines.length > 0, `${kind} ${id} has no lines`);
      } else {
        assert.ok(slot.copy.length > 0, `${kind} ${id} has no absence copy`);
      }
    }

    // The ACTION slot names every typed field through the adversary path: each
    // one came off the wire from a process this console does not control.
    const action = slots.action;
    assert.equal(action.kind, "present");
    for (const field of Object.keys(fields)) {
      assert.ok(
        action.lines.some((line) => line.label === field && line.adversary),
        `${kind} lacks ${field}`,
      );
    }

    // No rehearsal in the fixture, so BLAST RADIUS is an explicit absence.
    // Never collapsed: a missing blast radius is the loudest fact on the pane.
    assert.equal(slots["blast-radius"].kind, "absent");
    assert.match(slots["blast-radius"].copy, /NO REHEARSAL/);

    // WHY WE ARE ASKING marks which fields the REQUESTING AGENT supplied.
    const why = slots["why-we-are-asking"];
    assert.equal(why.kind, "present");
    assert.ok(
      why.lines.some(
        (line) =>
          line.provenance === "request-carried" &&
          line.label === "threat_class",
      ),
    );

    // WHAT GRANTING OPENS names the capability lease always, and the
    // containment lease only when granting would mint one.
    const opens = slots["what-granting-opens"];
    assert.equal(opens.kind, "present");
    assert.ok(opens.lines.some((line) => line.value.includes("60 s")));
    assert.equal(
      opens.lines.some((line) => line.value.includes("15 min")),
      leased,
    );
  });
}

test("every slot has a label and no label uses a banned word", () => {
  assert.deepEqual(Object.keys(VERDICT_SLOT_LABELS), [...VERDICT_SLOT_ORDER]);
  for (const label of Object.values(VERDICT_SLOT_LABELS)) {
    assert.ok(label.trim().length > 0);
    assert.doesNotMatch(label, /perch|approv|\bdeny\b/i);
  }
  // "lease" never appears bare: the capability lease and the containment lease
  // are different objects with different lifetimes, and one word for both is
  // how an operator reads a 60-second grant as a 15-minute one.
  const opens = buildVerdictSlots(
    hold("isolate_host", { host_id: "h" }, true),
    TTLS,
  )["what-granting-opens"];
  for (const line of opens.lines) {
    if (line.label === null) continue;
    assert.match(line.label, /capability lease|containment lease/);
  }
});

test("a rehearsal turns BLAST RADIUS present and names the producing layer", () => {
  const slots = buildVerdictSlots(
    { ...structuredClone(fixture.decided_hold), decision: null },
    TTLS,
  );
  const radius = slots["blast-radius"];
  assert.equal(radius.kind, "present");
  assert.ok(radius.lines.some((line) => line.label === "impact"));
  assert.ok(
    radius.lines.some((line) => line.provenance === "runtime"),
    "every blast-radius line is the runtime's claim, not the console's",
  );
  assert.ok(
    radius.lines.some((line) => line.label === "scope" && line.adversary),
    "the scope VALUE is adversary-influenced and must render escaped",
  );
});

test("IF YOU UNDO names each step's verdict and quotes an irreversible reason", () => {
  const slots = buildVerdictSlots(
    { ...structuredClone(fixture.decided_hold), decision: null },
    TTLS,
  );
  const undo = slots["if-you-undo"];
  assert.equal(undo.kind, "present");
  assert.equal(undo.lines.length, 2);
  assert.match(undo.lines[0].value, /executable/);
  assert.match(undo.lines[1].value, /unmapped/);
  for (const line of undo.lines) {
    assert.equal(line.provenance, "derived");
  }
});

test("an absent inverse plan says which absence it is", () => {
  const leased = buildVerdictSlots(
    hold("isolate_host", { host_id: "h" }, true),
    TTLS,
  )["if-you-undo"];
  assert.equal(leased.kind, "absent");
  assert.match(leased.copy, /containment/);

  const unleased = buildVerdictSlots(
    hold("block_egress", { target: "t" }, false),
    TTLS,
  )["if-you-undo"];
  assert.equal(unleased.kind, "absent");
  assert.match(unleased.copy, /not a containment/);
});

test("a custom threat class renders its slug, not [object Object]", () => {
  const custom = hold("block_egress", { target: "t" }, false);
  custom.rationale = {
    ...custom.rationale,
    threat_class: { custom: "beaconing" },
  };
  const why = buildVerdictSlots(custom, TTLS)["why-we-are-asking"];
  const line = why.lines.find((entry) => entry.label === "threat_class");
  assert.equal(line.value, "beaconing");
  assert.doesNotMatch(line.value, /object Object/);
});

test("a null-valued action field renders an em dash rather than the word null", () => {
  const slots = buildVerdictSlots(
    hold(
      "inject_firewall_rule",
      {
        host_id: "h",
        rule_name: "r",
        direction: "in",
        cidr: "10.0.0.0/8",
        port: null,
      },
      false,
    ),
    TTLS,
  );
  const port = slots.action.lines.find((line) => line.label === "port");
  assert.equal(port.value, "—");
});

test("the capability lease line says the lease is minted at the decision, not now", () => {
  // W2-15: the capability lease is minted from the store's compare-and-set
  // instant. A pane that implied the clock starts when the operator reads it
  // would overstate how long a grant stays usable.
  const opens = buildVerdictSlots(
    hold("isolate_host", { host_id: "h" }, true),
    TTLS,
  )["what-granting-opens"];
  const capability = opens.lines.find(
    (line) => line.label === "capability lease",
  );
  assert.match(capability.value, /minted at your decision, not now/);
});
