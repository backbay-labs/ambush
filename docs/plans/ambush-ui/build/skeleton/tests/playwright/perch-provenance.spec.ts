// Target path in BUZZ: desktop/tests/e2e/perch-provenance.spec.ts
// Register under the `smoke` project: "**/perch-provenance.spec.ts".
//
// Covers INV-08, INV-16, INV-17, INV-25, and the card-scoped half of the
// `signed`/`verified` ban that tools/copy-ban-list.tsv deliberately does not try
// to express lexically.

import { expect, test } from "@playwright/test";

import { installMockBridge } from "../helpers/bridge";
import { waitForAnimations } from "../helpers/animations";
import {
  emitAmbushCard,
  installPerchBridge,
  PERCH_ADMITTED_ISSUER,
  PERCH_CASE_CHANNEL,
  perchFixture,
  perchHold,
  readPerchExportManifest,
} from "../helpers/perchBridge";

/**
 * The four marker card types that carry NO Ed25519 signature under any condition
 * today (brief amendment A8): finding, escalation, hold, and the containment
 * lease. `receipt` and `rollback` carry one conditionally; `verdict` only after
 * B2o. A card in this list may never render the word `signed` or `verified`.
 *
 * The array values below are MARKER SLUGS (`swarm:lease:v1`), not labels. The
 * appendix's ban on a bare `lease` governs a rendered label, heading, nav item
 * or badge; a wire slug is a wire value and stays in lower_snake register.
 */
const UNSIGNED_CARD_KINDS = ["finding", "escalation", "hold", "lease"] as const;

async function openCase(page: import("@playwright/test").Page) {
  await installPerchBridge(page, perchFixture({ holds: [perchHold()] }));
  await installMockBridge(page);
  await page.goto(`/#/cases/${PERCH_CASE_CHANNEL}`);
  await expect(page.getByTestId("perch-case-timeline")).toBeVisible();
}

test.describe("Perch provenance and honest badges", () => {
  // INV-25. Two rows, ALWAYS. Never one badge, never a shield.
  test("01 — every verification result names its chain and its tier", async ({ page }) => {
    await openCase(page);
    await emitAmbushCard(page, {
      channelName: "case",
      marker: "swarm:rollback:v1",
      signerPubkey: PERCH_ADMITTED_ISSUER,
      hTag: PERCH_CASE_CHANNEL,
      body: {
        receipt_id: "rollback-1",
        governance_attestation: { signature_hex: "00".repeat(64), public_key_hex: "11".repeat(32) },
        attestation_verified: true,
      },
    });

    const rows = page.locator('[data-perch-role="provenance-row"]');
    await expect(rows).toHaveCount(2);
    await expect(rows.nth(0)).toContainText("Ed25519");
    await expect(rows.nth(1)).toContainText(/tier [012]/i);

    // verify_release_attestation's own doc comment
    // (AMB swarm-runtime/src/containment.rs:227-230) says do not read
    // attestation_verified:true as "a governor we trust authorized this". The
    // limit renders beside the badge, in body copy, at the same size -- voice
    // law L1, never a tooltip.
    await expect(page.getByTestId("perch-attestation-limit")).toBeVisible();
    await expect(page.getByTestId("perch-attestation-limit")).toContainText(
      "attestation matches this body",
    );
    await expect(page.getByTestId("perch-attestation-limit")).not.toContainText(/verified by|trusted/i);
    await expect(page.locator("svg.lucide-shield, svg.lucide-shield-check, svg.lucide-lock")).toHaveCount(0);
  });

  // INV-08, arm 1. `governance_attestation: None` is the literal token
  // UNATTESTED, in no success register.
  test("02 — a missing attestation renders UNATTESTED and never a success register", async ({ page }) => {
    await openCase(page);
    await emitAmbushCard(page, {
      channelName: "case",
      marker: "swarm:receipt:v1",
      signerPubkey: PERCH_ADMITTED_ISSUER,
      hTag: PERCH_CASE_CHANNEL,
      body: { receipt_id: "receipt-2", governance_attestation: null, partition_state_at_execution: "healthy" },
    });

    const badge = page.getByTestId("perch-attestation-badge");
    await expect(badge).toHaveText("UNATTESTED");
    await expect(badge).toHaveAttribute("data-perch-register", "absence");
    await expect(badge).not.toHaveAttribute("data-perch-register", "success");
  });

  // INV-08, arm 2 -- and the field it needs DOES NOT EXIST TODAY.
  //
  // `ResponseGovernanceAudit` is {governing_agent_id, reason, receipt}
  // (AMB crates/swarm-response/src/lib.rs:137-142) and `partition_state` appears
  // on no receipt anywhere in `crates/` -- only on GovernanceStatusReport
  // (AMB crates/swarm-policy/src/governance.rs:62-71), which is the CURRENT
  // state, not the state at execution. The "iff" in INV-08 is therefore
  // unassertable until the one-field bill addendum in 16-INVARIANT-TESTS.md
  // section 5.8 lands.
  //
  // The test is written now and skipped with the reason, because a skipped test
  // naming its blocker is an artifact and a missing test is not.
  test("03 — UNATTESTED — BY DESIGN renders iff the partition state at execution was partitioned or healing", async ({ page }) => {
    test.skip(
      true,
      "Blocked: no Ambush type records partition state at execution. ResponseGovernanceAudit " +
        "carries {governing_agent_id, reason, receipt} (swarm-response/src/lib.rs:137-142). " +
        "Un-skip when B1/B2 stamp partition_state_at_hold and partition_state_at_execution.",
    );
    await openCase(page);
    for (const [state, expected] of [
      ["healthy", "UNATTESTED"],
      ["degraded", "UNATTESTED"],
      ["partitioned", "UNATTESTED — BY DESIGN"],
      ["healing", "UNATTESTED — BY DESIGN"],
    ] as const) {
      await emitAmbushCard(page, {
        channelName: "case",
        marker: "swarm:receipt:v1",
        signerPubkey: PERCH_ADMITTED_ISSUER,
        hTag: PERCH_CASE_CHANNEL,
        body: { receipt_id: `receipt-${state}`, governance_attestation: null, partition_state_at_execution: state },
      });
      await expect(page.getByTestId(`perch-attestation-badge-receipt-${state}`)).toHaveText(expected);
    }
  });

  // The card-scoped ban the flat copy gate cannot express.
  test("04 — no unsigned card type renders the words signed or verified", async ({ page }) => {
    await openCase(page);
    for (const kind of UNSIGNED_CARD_KINDS) {
      await emitAmbushCard(page, {
        channelName: "case",
        marker: `ambush:${kind}:v1`,
        signerPubkey: PERCH_ADMITTED_ISSUER,
        hTag: PERCH_CASE_CHANNEL,
        body: { id: `${kind}-1`, summary: "a summary" },
      });
      const card = page.getByTestId(`perch-evidence-${kind}`);
      await expect(card).toBeVisible();
      const text = await card.innerText();
      expect(text).not.toMatch(/\bsigned\b/i);
      expect(text).not.toMatch(/\bverified\b/i);
      // It says the true thing instead.
      expect(text).toMatch(/no signature of its own/i);
    }
  });

  // INV-16. Render law 2. The mechanism, restated because the plan set had it
  // backwards: concentration_for counts `deposit.agent_id.0`
  // (AMB swarm-pheromone/src/substrate.rs:1295) and WhiskerAgent::tick derives
  // ONE id per agent (AMB swarm-agents/src/whisker_agent.rs:148-149), so one
  // Whisker running four detectors reports distinct_sources == 1 and FAILS
  // min_sources_for_escalation: 2. The two numbers are therefore both needed and
  // frequently equal, which is exactly when a lazy renderer drops one.
  test("05 — no source count renders alone", async ({ page }) => {
    await openCase(page);
    await emitAmbushCard(page, {
      channelName: "case",
      marker: "swarm:escalation:v1",
      signerPubkey: PERCH_ADMITTED_ISSUER,
      hTag: PERCH_CASE_CHANNEL,
      body: { threat_class: "lateral_movement", distinct_sources: 1, source_ids: ["whisker-7a3f:port_scan"] },
    });

    const counts = page.locator('[data-perch-role="source-count"]');
    await expect(counts).toHaveCount(1);
    await expect(counts.first()).toHaveText(/\d+ sources? \/ \d+ agents?/);
    // The chart layer takes only sourceIds and derives both numbers, so a caller
    // cannot pass a bare count in the first place.
    await expect(counts.first()).toContainText("1 source / 1 agent");
  });

  // INV-17. Derived-vs-served marking, plus the export's DERIVED.json iff-clause.
  test("06 — every console-computed value carries a marker naming its function", async ({ page }) => {
    await openCase(page);
    await emitAmbushCard(page, {
      channelName: "case",
      marker: "swarm:escalation:v1",
      signerPubkey: PERCH_ADMITTED_ISSUER,
      hTag: PERCH_CASE_CHANNEL,
      body: { threat_class: "lateral_movement", distinct_sources: 2, source_ids: ["a:x", "b:y"], total_strength: 2.4 },
    });

    const derived = page.locator('[data-perch-role="derived"]');
    await expect(derived.first()).toBeVisible();
    const count = await derived.count();
    for (let index = 0; index < count; index += 1) {
      // Naming the producing function is the whole requirement; a bare
      // "computed" chip would say nothing an operator can check.
      await expect(derived.nth(index)).toHaveAttribute("data-perch-derived-fn", /.+/);
    }

    // Read the RENDERED manifest, not a window global. A manifest that is
    // correct and invisible fails the operator the same way a wrong one does.
    const manifest = await readPerchExportManifest(page);
    expect((manifest.derived as unknown[]).length).toBeGreaterThan(0);
  });

  // The other half of the iff: no derived value rendered => DERIVED.json empty.
  test("07 — DERIVED.json is empty when nothing derived is on screen", async ({ page }) => {
    await openCase(page);
    await waitForAnimations(page);
    await expect(page.locator('[data-perch-role="derived"]')).toHaveCount(0);
    const manifest = await readPerchExportManifest(page);
    expect((manifest.derived as unknown[]).length).toBe(0);
  });
});
