import { expect, test, type Page } from "@playwright/test";
import {
  emitPerchMessage,
  findingCardBody,
  installPerchBridge,
  PERCH_ADMITTED_ISSUER,
  PERCH_CASE_CHANNEL,
  PERCH_FINDING_CARD_EVENT_ID,
  PERCH_LANE_CHANNEL_NAME,
} from "../helpers/perchBridge";

/**
 * The swarmctl terminal pinned to a case: the banner names the pin, and the
 * attach request carries the case so the Tauri side can scope the shell.
 */

const TERM = 'section[aria-label="Ambush Term"]';

type AttachRecord = { request?: Record<string, unknown> };

/**
 * A terminal backend that answers `terminal_attach` and records what each
 * attach asked for. Modelled on `terminal-wheel.spec.ts`; the recording is
 * what this spec adds.
 */
async function installRecordingTerminalBackend(page: Page): Promise<void> {
  await page.addInitScript(() => {
    const w = window as typeof window & {
      isTauri?: boolean;
      __TAURI_INTERNALS__?: Record<string, unknown>;
      __SAMI_TERM_ATTACHES__?: AttachRecord[];
    };
    w.isTauri = true;
    const attaches: AttachRecord[] = [];
    w.__SAMI_TERM_ATTACHES__ = attaches;
    let sequence = 0;
    const internals: Record<string, unknown> = {};
    let inner: ((cmd: string, args: unknown, opts: unknown) => unknown) | null =
      null;
    Object.defineProperty(internals, "invoke", {
      configurable: true,
      get:
        () => (cmd: string, args: Record<string, unknown>, opts: unknown) => {
          switch (cmd) {
            case "terminal_attach": {
              sequence += 1;
              attaches.push({
                request: args.request as Record<string, unknown>,
              });
              return Promise.resolve({
                sessionId: `sami-session-${sequence}`,
                subscriptionId: "sami-sub-1",
                columns: 80,
                screenLines: 24,
              });
            }
            case "terminal_input":
            case "terminal_resize":
            case "terminal_scroll":
            case "terminal_detach":
              return Promise.resolve(null);
            default:
              return inner ? inner(cmd, args, opts) : Promise.resolve(null);
          }
        },
      set: (value: (cmd: string, args: unknown, opts: unknown) => unknown) => {
        inner = value;
      },
    });
    w.__TAURI_INTERNALS__ = internals;
  });
}

async function attaches(page: Page): Promise<AttachRecord[]> {
  return page.evaluate(
    () =>
      (window as typeof window & { __SAMI_TERM_ATTACHES__?: AttachRecord[] })
        .__SAMI_TERM_ATTACHES__ ?? [],
  );
}

async function openCase(page: Page): Promise<void> {
  await page.setViewportSize({ width: 1280, height: 800 });
  await installRecordingTerminalBackend(page);
  await installPerchBridge(page);
  await page.goto("/");
  await page.getByTestId(`channel-${PERCH_LANE_CHANNEL_NAME}`).click();
  await expect(page.getByTestId("chat-title")).toHaveText(
    PERCH_LANE_CHANNEL_NAME,
  );
  const eventId = await emitPerchMessage(page, {
    channelName: PERCH_LANE_CHANNEL_NAME,
    content: findingCardBody(),
    pubkey: PERCH_ADMITTED_ISSUER,
    id: PERCH_FINDING_CARD_EVENT_ID,
  });
  const card = page
    .locator(`[data-message-id="${eventId}"]`)
    .getByTestId("perch-evidence-finding");
  await expect(card).toBeVisible();
  await card
    .getByTestId("perch-finding-actions")
    .getByTestId("perch-finding-action-promote")
    .focus();
  await page.keyboard.press("e");
  await expect(page).toHaveURL(new RegExp(`/cases/${PERCH_CASE_CHANNEL}$`));
  await expect(page.getByTestId("perch-case")).toBeVisible();
}

test("⌘J on a case opens the terminal pinned to it, and says so", async ({
  page,
}) => {
  await openCase(page);
  await page.keyboard.press("Meta+j");
  await expect(page.locator(TERM)).toHaveAttribute(
    "data-terminal-owner",
    "terminal",
  );
  const banner = page.getByTestId("perch-terminal-banner");
  await expect(banner).toContainText("pinned to");
  await expect(banner).toContainText("real shell on this host");
});

test("the attach request carries the case, so the Tauri side can scope the shell", async ({
  page,
}) => {
  await openCase(page);
  await page.keyboard.press("Meta+j");
  await expect(page.locator(TERM)).toHaveAttribute(
    "data-terminal-owner",
    "terminal",
  );
  await expect
    .poll(async () => (await attaches(page)).length)
    .toBeGreaterThan(0);
  const last = (await attaches(page)).at(-1);
  expect(last?.request?.caseId).toBe(PERCH_CASE_CHANNEL);
  expect(
    typeof last?.request?.caseSlug === "string" ||
      last?.request?.caseSlug === undefined,
  ).toBe(true);
});
