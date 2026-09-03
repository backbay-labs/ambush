// Target path in BUZZ: desktop/tests/e2e/perch-marker-admission.spec.ts
// Register under the `smoke` project: "**/perch-marker-admission.spec.ts".
//
// Covers INV-13, INV-15 (the UI half), INV-14 (the runtime half the type system
// cannot reach), and the live-document half of INV-30.
//
// This is the prompt-injection surface. ProcessStartEvent.command_line and
// DetectionFinding.evidence reach this renderer, and Buzz's own sniff is
// `content.trimStart().startsWith(WAVE_MESSAGE_MARKER)` over arbitrary body text
// (BUZZ desktop/src/features/messages/lib/waveMessage.ts:15-19), called from
// MessageRow.renderBody's default arm (MessageRow.tsx:414-426). Safe for a wave;
// unsafe here.

import { expect, test } from "@playwright/test";

import { installMockBridge } from "../helpers/bridge";
import {
  emitAmbushCard,
  installPerchBridge,
  PERCH_ADMITTED_ISSUER,
  PERCH_CASE_CHANNEL,
  PERCH_OTHER_CASE_CHANNEL,
  PERCH_UNADMITTED_ISSUER,
  perchFixture,
  readPerchCounter,
} from "../helpers/perchBridge";

/**
 * The three codepoint classes an attacker reaches for, written as escapes so the
 * spec file itself stays free of invisible characters: U+202E RIGHT-TO-LEFT
 * OVERRIDE reverses the rendered order of everything after it, U+200B ZERO WIDTH
 * SPACE hides a token boundary, and a bare newline lets a payload masquerade as
 * a second field.
 */
const RTL_OVERRIDE = "‮";
const ZERO_WIDTH_SPACE = "​";

async function openCase(page: import("@playwright/test").Page) {
  await installPerchBridge(page, perchFixture());
  await installMockBridge(page);
  await page.goto(`/#/cases/${PERCH_CASE_CHANNEL}`);
  await expect(page.getByTestId("perch-case-timeline")).toBeVisible();
}

test.describe("Perch marker admission", () => {
  // INV-15, arm 1: the marker must be the ENTIRE first line. `line0.trimEnd()`,
  // never `trimStart()` -- a leading space is a producer bug worth seeing.
  test("01 — a marker fires only when it is the whole of line 0", async ({ page }) => {
    await openCase(page);

    const cases = [
      { name: "exact", content: "<!-- swarm:finding:v1 -->\n{}", renders: true },
      { name: "leading-space", content: " <!-- swarm:finding:v1 -->\n{}", renders: false },
      { name: "trailing-text", content: "<!-- swarm:finding:v1 --> hello\n{}", renders: false },
      { name: "second-line", content: "hello\n<!-- swarm:finding:v1 -->\n{}", renders: false },
      // \r\n: line 0 is trimEnd()-ed, so a CRLF producer still works.
      { name: "crlf", content: "<!-- swarm:finding:v1 -->\r\n{}", renders: true },
    ] as const;

    let expectedCards = 0;
    for (const testCase of cases) {
      await page.evaluate(
        (input) => {
          (
            window as unknown as {
              __BUZZ_E2E_EMIT_MOCK_MESSAGE__?: (m: {
                channelName: string;
                content: string;
                pubkey: string;
                extraTags?: string[][];
              }) => unknown;
            }
          ).__BUZZ_E2E_EMIT_MOCK_MESSAGE__?.({
            channelName: "case",
            content: input.content,
            pubkey: input.pubkey,
            extraTags: [["h", input.h]],
          });
        },
        { content: testCase.content, pubkey: PERCH_ADMITTED_ISSUER, h: PERCH_CASE_CHANNEL },
      );
      if (testCase.renders) expectedCards += 1;
      await expect(
        page.getByTestId("perch-evidence-finding"),
        `after emitting the ${testCase.name} case`,
      ).toHaveCount(expectedCards);
    }
  });

  // INV-15, arm 2: an unadmitted signer renders as untrusted prose. It must not
  // become an evidence card, must not enter the needs-action queue, and must not
  // reach a wake class -- three separate claims, three separate assertions,
  // because a renderer can get one right and the other two wrong.
  test("02 — a well-formed marker from an unadmitted signer renders as prose only", async ({ page }) => {
    await openCase(page);
    await emitAmbushCard(page, {
      channelName: "case",
      marker: "swarm:hold:v1",
      signerPubkey: PERCH_UNADMITTED_ISSUER,
      hTag: PERCH_CASE_CHANNEL,
      body: { hold_id: "h_unreconciled01", action_kind: "isolate_host", severity: "CRITICAL" },
    });

    await expect(page.getByTestId("perch-evidence-hold")).toHaveCount(0);
    await expect(page.getByTestId("perch-queue-row-forged-1")).toHaveCount(0);

    const notifications = await page.evaluate(
      () =>
        (window as unknown as { __BUZZ_E2E_NOTIFICATIONS__?: unknown[] })
          .__BUZZ_E2E_NOTIFICATIONS__ ?? [],
    );
    expect(notifications).toHaveLength(0);

    // And it IS still visible -- as prose. Dropping it silently would hide a
    // live attempt from the person best placed to notice it.
    await expect(page.getByTestId("perch-unadmitted-marker-notice")).toBeVisible();
    expect(await readPerchCounter(page, "perch_marker_unadmitted_total")).toBe(1);
  });

  // INV-13. A verdict card whose `h` tag is not this case's channel UUID must
  // not render here. The relay guarantees an h tag EXISTS on kind:9; it
  // guarantees nothing about WHICH channel a client renders it under.
  test("03 — the case timeline refuses a verdict card tagged for another case", async ({ page }) => {
    await openCase(page);
    await emitAmbushCard(page, {
      channelName: "case",
      marker: "swarm:verdict:v1",
      signerPubkey: PERCH_ADMITTED_ISSUER,
      hTag: PERCH_OTHER_CASE_CHANNEL,
      body: { hold_id: "h_elsewhere01", decision: "grant" },
    });

    await expect(page.getByTestId("perch-evidence-verdict")).toHaveCount(0);
    await expect(page.getByTestId("perch-channel-mismatch-notice")).toBeVisible();
    await expect(page.getByTestId("perch-channel-mismatch-notice")).toContainText(
      PERCH_OTHER_CASE_CHANNEL,
    );
  });

  // The two refusal states an unknown slug and an unsupported version produce.
  // Falling through to markdown would push a JSON payload containing host_id,
  // file_path and command_line into shared/ui/markdown.tsx's remark pipeline.
  test("04 — an unknown kind and an unsupported version render refusals, never markdown", async ({ page }) => {
    await openCase(page);
    await emitAmbushCard(page, {
      channelName: "case",
      marker: "ambush:teapot:v1",
      signerPubkey: PERCH_ADMITTED_ISSUER,
      hTag: PERCH_CASE_CHANNEL,
      body: { anything: "[a link](javascript:alert(1))" },
    });
    await emitAmbushCard(page, {
      channelName: "case",
      marker: "swarm:hold:v2",
      signerPubkey: PERCH_ADMITTED_ISSUER,
      hTag: PERCH_CASE_CHANNEL,
      body: { hold_id: "h_futureversion" },
    });

    await expect(page.getByTestId("perch-evidence-unknown-kind")).toBeVisible();
    await expect(page.getByTestId("perch-evidence-unsupported-version")).toBeVisible();
    await expect(page.getByTestId("perch-evidence-unsupported-version")).toContainText(
      "this console reads version 1",
    );
    // No markdown pass ran over either body.
    await expect(
      page.locator("[data-testid='perch-case-timeline'] a[href^='javascript:']"),
    ).toHaveCount(0);
  });

  // INV-14's runtime half. The AdversaryText brand stops a raw wire string
  // reaching JSX at compile time; this proves the component the brand forces you
  // through actually neutralises the bytes.
  test("05 — AdversaryString renders control and bidi characters visibly, as text", async ({ page }) => {
    await openCase(page);
    const hostile = `isolate${RTL_OVERRIDE}host${ZERO_WIDTH_SPACE}\nsecond line`;
    await emitAmbushCard(page, {
      channelName: "case",
      marker: "swarm:finding:v1",
      signerPubkey: PERCH_ADMITTED_ISSUER,
      hTag: PERCH_CASE_CHANNEL,
      body: { finding_id: "f-1", summary: hostile, strategy_id: "port_scan" },
    });

    const value = page.locator('[data-perch-role="adversary-string"]').first();
    await expect(value).toBeVisible();
    // The wrapper labels itself. The LABEL is trusted; the VALUE is not read
    // into any aria attribute, because a screen reader announcing a
    // bidi-overridden string defeats the visual escaping.
    await expect(value).toHaveAttribute("aria-label", /adversary-controlled value/);
    const ariaLabel = (await value.getAttribute("aria-label")) ?? "";
    expect(ariaLabel).not.toContain(RTL_OVERRIDE);

    const rendered = await value.innerText();
    expect(rendered).not.toContain(RTL_OVERRIDE);
    expect(rendered).not.toContain(ZERO_WIDTH_SPACE);
    // Three replaced codepoints: the override, the zero-width space, the newline.
    await expect(value.getByTestId("perch-escaped-codepoint")).toHaveCount(3);
    // Each replacement names the codepoint it stands for, so an operator can
    // tell U+202E from U+200B rather than seeing three identical boxes.
    await expect(value.getByTestId("perch-escaped-codepoint").first()).toHaveAttribute(
      "title",
      /U\+202E/,
    );
    // Plain text node: no element the payload could have introduced.
    await expect(value.locator("script, iframe, a, img")).toHaveCount(0);
  });

  // INV-30's live half. The pinned header is a build-time gate
  // (scripts/check-csp-pin.mjs); this asserts nothing injected a second policy
  // into the document at runtime.
  test("06 — the document carries no meta CSP beside the pinned header", async ({ page }) => {
    await openCase(page);
    const metas = await page
      .locator('meta[http-equiv="Content-Security-Policy" i]')
      .count();
    expect(metas).toBe(0);
  });
});
