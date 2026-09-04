import type { Page } from "@playwright/test";
import { expect, test } from "@playwright/test";

import { installMockBridge } from "../helpers/bridge";
import {
  enablePerchFeature,
  PERCH_HOLD_A,
  perchHold,
  seedPerchDaemon,
  waitForPerchQueue,
} from "../helpers/perchBridge";

/** The five slots, in the order the pane must always render them. */
const SLOTS = [
  "action",
  "blast-radius",
  "if-you-undo",
  "why-we-are-asking",
  "what-granting-opens",
];

/** The fifteen `ResponseAction` variants and whether each takes a lease. */
const ACTIONS: ReadonlyArray<[string, Record<string, unknown>, boolean]> = [
  ["block_egress", { target: "203.0.113.10" }, false],
  ["isolate_host", { host_id: "host-ops-1" }, true],
  ["revoke_credential", { credential_id: "c-1" }, false],
  ["sinkhole_dns", { domain: "evil.example" }, false],
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

async function openPane(
  page: Page,
  hold: Record<string, unknown>,
): Promise<void> {
  await installMockBridge(page);
  await enablePerchFeature(page);
  await seedPerchDaemon(page, { holds: [hold] });
  await page.goto("/");
  await waitForPerchQueue(page);
  await page.getByTestId(`perch-queue-row-${PERCH_HOLD_A}`).click();
  await expect(page.getByTestId("perch-verdict-pane")).toBeVisible();
}

function actionHold(
  kind: string,
  fields: Record<string, unknown>,
  leased: boolean,
) {
  const base = perchHold({ hold_id: PERCH_HOLD_A });
  return {
    ...base,
    action_kind: kind,
    leases_a_containment: leased,
    action_request: {
      ...(base.action_request as Record<string, unknown>),
      action: { type: kind, ...fields },
    },
  };
}

test("all five slots render in a fixed order for every action kind", async ({
  page,
}) => {
  // One page, fifteen holds: the property is that the slot SET never varies
  // with the action, so varying the action is the test.
  await installMockBridge(page);
  await enablePerchFeature(page);
  await seedPerchDaemon(page, {
    holds: [actionHold(...ACTIONS[0])],
  });
  await page.goto("/");
  await waitForPerchQueue(page);

  for (const [kind, fields, leased] of ACTIONS) {
    // Re-seed through the init script, not the live control: a reload rebuilds
    // the mock module from the seed, so a `setHolds` mutation would be gone by
    // the time the console makes its first read.
    await seedPerchDaemon(page, { holds: [actionHold(kind, fields, leased)] });
    await page.reload();
    await waitForPerchQueue(page);
    await page.getByTestId(`perch-queue-row-${PERCH_HOLD_A}`).click();

    const rendered = await page
      .locator('[data-perch-role="verdict-slot"]')
      .evaluateAll((nodes) =>
        nodes.map((node) => node.getAttribute("data-perch-slot")),
      );
    expect(rendered, `${kind} did not render the five slots in order`).toEqual(
      SLOTS,
    );

    // The containment-lease note is ABSENT, not empty, on an unleased action.
    await expect(
      page.getByTestId("perch-pending-containment-lease"),
    ).toHaveCount(leased ? 1 : 0);
  }
});

test("a missing rehearsal renders as a stated absence, never as an empty slot", async ({
  page,
}) => {
  await openPane(page, perchHold({ hold_id: PERCH_HOLD_A, rehearsal: null }));
  const slot = page.getByTestId("perch-verdict-slot-blast-radius");
  await expect(slot).toBeVisible();
  await expect(slot).toContainText("NO REHEARSAL");
  await expect(slot.locator("[data-perch-absence]")).toHaveCount(1);
});

test("WHY WE ARE ASKING marks which fields the requesting agent supplied", async ({
  page,
}) => {
  // The single most useful thing on the pane: `severity` and `threat_class`
  // are set by the agent asking for the action and read back by the approval
  // gate, so a compromised agent picks its own review path. It must never
  // read as the runtime's own finding.
  await openPane(page, perchHold({ hold_id: PERCH_HOLD_A }));
  const slot = page.getByTestId("perch-verdict-slot-why-we-are-asking");
  await expect(
    slot.locator('[data-perch-provenance="request-carried"]'),
  ).toHaveCount(2);
  await expect(
    slot.locator('[data-perch-provenance="runtime"]').first(),
  ).toBeVisible();
});

test("an expired hold replaces the action bar and says no action was taken", async ({
  page,
}) => {
  await openPane(
    page,
    perchHold({
      hold_id: PERCH_HOLD_A,
      state: "expired",
      expired: true,
      remaining_ms: 0,
    }),
  );
  await expect(page.getByTestId("perch-verdict-pane-expired")).toContainText(
    "no action was taken",
  );
  await expect(page.getByTestId("perch-grant-record")).toHaveCount(0);
});

test("the refusal legend lists what can still stop a recorded decision", async ({
  page,
}) => {
  await openPane(page, perchHold({ hold_id: PERCH_HOLD_A }));
  await page.getByTestId("perch-refusal-legend-open").click();
  const legend = page.getByTestId("perch-refusal-legend");
  await expect(legend).toBeVisible();
  // Governance is REACHABLE now that a decide re-runs the shared gate. A
  // legend that listed it as hypothetical would teach a rule that is real.
  await expect(
    legend.locator('[data-perch-refusal="governance"]'),
  ).toHaveAttribute("data-perch-reachable", "true");
  await expect(legend).toContainText("re-evaluated at the decision instant");
  await expect(
    legend.locator('[data-perch-refusal="another-console"]'),
  ).toBeVisible();
});

test("the pane offers no undo for the decision and states why the action cannot be undone", async ({
  page,
}) => {
  await openPane(page, perchHold({ hold_id: PERCH_HOLD_A }));
  // A recorded decision is a signed event and, once granted, a minted lease.
  // Nothing this console renders takes either back.
  await expect(page.getByTestId("perch-decision-undo")).toHaveCount(0);
  const undo = page.getByTestId("perch-undo-affordance");
  await expect(undo).toHaveAttribute("aria-disabled", "true");
  await expect(undo).toHaveAttribute("data-perch-undo-available", "false");
});

test("an UNRECONCILED selection gets no Verdict Row at all", async ({
  page,
}) => {
  // The pane is built from the daemon's record. With no record there is
  // nothing to build it from, and building it from the relay's notice is the
  // exact lie the queue refuses to tell.
  await installMockBridge(page);
  await enablePerchFeature(page);
  await seedPerchDaemon(page, { holds: [], storeDurable: true });
  await page.goto("/");
  await waitForPerchQueue(page);
  await expect(page.getByTestId("perch-verdict-pane")).toHaveCount(0);
});
