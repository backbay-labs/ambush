import assert from "node:assert/strict";
import test from "node:test";

import {
  getCardGalleryOpen,
  getCardMintJobs,
  runCardMintJob,
  setCardGalleryOpen,
} from "@/features/agents/cardMintStore";
import {
  getTimeoutSnapshot,
  recordTimeoutFromRejection,
} from "@/features/moderation/lib/timeoutStore";

import {
  COMMUNITY_SCOPED_SINGLETONS,
  RESETTERS,
  runResetters,
} from "./communityScopedRegistry.ts";

const AVATAR_ONLY = ["avatarProfileSync", "avatarPresentations"];
const MAC_TAURI_ONLY = ["trayAgentActivity"];

function fakeResetters(order, { async = false } = {}) {
  return Object.fromEntries(
    COMMUNITY_SCOPED_SINGLETONS.map((key) => [
      key,
      async
        ? async () => {
            order.push(key);
          }
        : () => {
            order.push(key);
          },
    ]),
  );
}

test("every named singleton has a resetter and nothing else does", () => {
  assert.deepEqual(
    Object.keys(RESETTERS).sort(),
    [...COMMUNITY_SCOPED_SINGLETONS].sort(),
  );
});

test("the perch singletons are registered", () => {
  assert.ok(
    [
      "perchSubscriptions",
      "perchSeqTracking",
      "perchAdmittedIssuers",
      "perchWriteStates",
      "perchCaseIndex",
    ].every((k) => COMMUNITY_SCOPED_SINGLETONS.includes(k)),
  );
});

test("the singleton list has no duplicate names", () => {
  assert.equal(
    new Set(COMMUNITY_SCOPED_SINGLETONS).size,
    COMMUNITY_SCOPED_SINGLETONS.length,
  );
});

test("resetters run in declaration order, sequentially", async () => {
  const order = [];
  const fakes = fakeResetters(order, { async: true });

  await runResetters({ resetAvatarState: true, isMacTauri: true }, fakes);

  assert.deepEqual(order, [...COMMUNITY_SCOPED_SINGLETONS]);
});

test("an async resetter finishes before the next one starts", async () => {
  const events = [];
  const fakes = fakeResetters(events);
  fakes.navigationDeepLinkDrain = async () => {
    events.push("navigationDeepLinkDrain:start");
    await new Promise((resolve) => setTimeout(resolve, 5));
    events.push("navigationDeepLinkDrain:end");
  };

  await runResetters({ resetAvatarState: true, isMacTauri: true }, fakes);

  const start = events.indexOf("navigationDeepLinkDrain:start");
  const end = events.indexOf("navigationDeepLinkDrain:end");
  assert.ok(start >= 0 && end === start + 1, events.join(","));
  assert.equal(events[end + 1], "rateLimitGate");
});

test("avatar resetters are skipped when resetAvatarState is false", async () => {
  const order = [];
  const fakes = fakeResetters(order);

  await runResetters({ resetAvatarState: false, isMacTauri: true }, fakes);

  for (const key of AVATAR_ONLY) {
    assert.ok(!order.includes(key), `${key} should have been skipped`);
  }
  assert.deepEqual(
    order,
    COMMUNITY_SCOPED_SINGLETONS.filter((key) => !AVATAR_ONLY.includes(key)),
  );
});

test("the tray resetter is skipped off macOS Tauri", async () => {
  const order = [];
  const fakes = fakeResetters(order);

  await runResetters({ resetAvatarState: true, isMacTauri: false }, fakes);

  for (const key of MAC_TAURI_ONLY) {
    assert.ok(!order.includes(key), `${key} should have been skipped`);
  }
  assert.deepEqual(
    order,
    COMMUNITY_SCOPED_SINGLETONS.filter((key) => !MAC_TAURI_ONLY.includes(key)),
  );
});

test("a throwing resetter stops the run and surfaces the error", async () => {
  const order = [];
  const fakes = fakeResetters(order);
  fakes.rateLimitGate = () => {
    throw new Error("boom");
  };

  await assert.rejects(
    runResetters({ resetAvatarState: true, isMacTauri: true }, fakes),
    /boom/,
  );
  assert.deepEqual(order, ["relayClient", "navigationDeepLinkDrain"]);
});

test("every real resetter receives the reset context", async () => {
  const seen = [];
  const fakes = Object.fromEntries(
    COMMUNITY_SCOPED_SINGLETONS.map((key) => [
      key,
      (ctx) => {
        seen.push([key, ctx]);
      },
    ]),
  );
  const ctx = { resetAvatarState: true, isMacTauri: true };

  await runResetters(ctx, fakes);

  assert.equal(seen.length, COMMUNITY_SCOPED_SINGLETONS.length);
  for (const [, received] of seen) {
    assert.equal(received, ctx);
  }
});

// The real resetter for `key`, with every other singleton faked out. Exercises
// the actual teardown loop (so removing `key` from the inventory fails the
// test) without disconnecting the relay client or touching the tray.
function realResetterFor(...keys) {
  const fakes = fakeResetters([]);
  for (const key of keys) {
    fakes[key] = RESETTERS[key];
  }
  return fakes;
}

test("a community timeout does not survive a community switch", async () => {
  // Learned reactively from a relay send rejection in community A.
  recordTimeoutFromRejection(
    `restricted: you are timed out until ${Math.floor(Date.now() / 1000) + 3600}`,
  );
  assert.equal(getTimeoutSnapshot().active, true);

  await runResetters(
    { resetAvatarState: false, isMacTauri: false },
    realResetterFor("moderationTimeout"),
  );

  // Community B must start writable: the only other thing that clears this is
  // an accepted send, which the disabled composer cannot make.
  assert.deepEqual(getTimeoutSnapshot(), { active: false, expiresAtMs: null });
});

test("card mints do not survive a community switch", async () => {
  await runCardMintJob({ agentId: "agent-1", agentName: "Eva" }, () =>
    Promise.resolve({
      cardPngBase64: "aGVsbG8=",
      fileName: "eva.agent.png",
      designerNotes: "notes",
      locked: false,
      memoryLevel: "none",
    }),
  );
  setCardGalleryOpen(true);
  assert.equal(getCardMintJobs().length, 1);

  await runResetters(
    { resetAvatarState: false, isMacTauri: false },
    realResetterFor("cardMintStore"),
  );

  assert.deepEqual(getCardMintJobs(), []);
  assert.equal(getCardGalleryOpen(), false);
});

test("synchronous resetters run without yielding to the microtask queue", async () => {
  const order = [];
  const run = runResetters(
    { resetAvatarState: true, isMacTauri: true },
    fakeResetters(order),
  );
  // Queued after runResetters has run as far as it can synchronously. If the
  // loop awaited every (synchronous) resetter, this microtask would interleave
  // between resetters instead of landing after all of them.
  void Promise.resolve().then(() => {
    order.push("microtask");
  });

  await run;

  assert.deepEqual(order, [...COMMUNITY_SCOPED_SINGLETONS, "microtask"]);
});
