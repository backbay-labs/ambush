import assert from "node:assert/strict";
import test from "node:test";

import {
  recoverLocalStorageQuotaOnStartup,
  setLocalStorageItemWithRecovery,
} from "./localStorageQuota.ts";

function makeQuotaLocalStorage({ maxEntries }) {
  const store = new Map();
  return {
    store,
    get length() {
      return store.size;
    },
    key: (i) => [...store.keys()][i] ?? null,
    getItem: (key) => store.get(key) ?? null,
    setItem(key, value) {
      if (!store.has(key) && store.size >= maxEntries) {
        throw new Error("QuotaExceededError");
      }
      store.set(key, value);
    },
    removeItem: (key) => store.delete(key),
  };
}

function install(ls) {
  if (typeof globalThis.window === "undefined") {
    globalThis.window = {};
  }
  globalThis.window.localStorage = ls;
  globalThis.localStorage = ls;
}

test("startup recovery removes disposable caches but preserves user state", () => {
  const ls = makeQuotaLocalStorage({ maxEntries: 7 });
  install(ls);
  ls.store.set("ambush-channel-messages.v1:relay:chan", "big");
  ls.store.set("ambush-channels.v1:relay", "big");
  ls.store.set("ambush-projects.v1:relay:owner", "big");
  ls.store.set("ambush-timeline-skeleton-shape.v1:chan", "small");
  ls.store.set("ambush-sidebar-skeleton-shape.v1:community:user", "small");
  ls.store.set("ambush-user-labels.v1:relay", "small");
  ls.store.set("ambush-communities", "keep");

  recoverLocalStorageQuotaOnStartup();

  assert.equal(ls.getItem("ambush-channel-messages.v1:relay:chan"), null);
  assert.equal(ls.getItem("ambush-channels.v1:relay"), null);
  assert.equal(ls.getItem("ambush-projects.v1:relay:owner"), null);
  assert.equal(ls.getItem("ambush-timeline-skeleton-shape.v1:chan"), null);
  assert.equal(
    ls.getItem("ambush-sidebar-skeleton-shape.v1:community:user"),
    null,
  );
  assert.equal(ls.getItem("ambush-user-labels.v1:relay"), null);
  assert.equal(ls.getItem("ambush-communities"), "keep");
  assert.equal(ls.getItem("ambush-local-storage-quota-recovery.v1"), "1");
});

test("healthy startup preserves disposable caches", () => {
  const ls = makeQuotaLocalStorage({ maxEntries: 10 });
  install(ls);
  ls.store.set("ambush-channel-messages.v1:relay:new", "snapshot");

  recoverLocalStorageQuotaOnStartup();

  assert.equal(ls.getItem("ambush-channel-messages.v1:relay:new"), "snapshot");
  assert.equal(ls.getItem("ambush-local-storage-quota-recovery.v1"), "1");
});

test("startup recovery does not remove namespace near misses", () => {
  const ls = makeQuotaLocalStorage({ maxEntries: 2 });
  install(ls);
  ls.store.set("ambush-channels.v10:durable", "keep");
  ls.store.set("ambush-channel-messages.v1-durable", "keep");

  recoverLocalStorageQuotaOnStartup();

  assert.equal(ls.getItem("ambush-channels.v10:durable"), "keep");
  assert.equal(ls.getItem("ambush-channel-messages.v1-durable"), "keep");
  assert.equal(ls.getItem("ambush-local-storage-quota-recovery.v1"), null);
});

test("startup recovery runs only once", () => {
  const ls = makeQuotaLocalStorage({ maxEntries: 10 });
  install(ls);

  recoverLocalStorageQuotaOnStartup();
  ls.store.set("ambush-channel-messages.v1:relay:new", "new snapshot");
  recoverLocalStorageQuotaOnStartup();

  assert.equal(
    ls.getItem("ambush-channel-messages.v1:relay:new"),
    "new snapshot",
  );
});

test("startup recovery retries after marker write fails", () => {
  const ls = makeQuotaLocalStorage({ maxEntries: 1 });
  install(ls);
  ls.store.set("ambush-communities", "keep");

  recoverLocalStorageQuotaOnStartup();
  assert.equal(ls.getItem("ambush-local-storage-quota-recovery.v1"), null);

  ls.store.delete("ambush-communities");
  ls.store.set("ambush-channel-messages.v1:relay:chan", "big");
  recoverLocalStorageQuotaOnStartup();

  assert.equal(ls.getItem("ambush-channel-messages.v1:relay:chan"), null);
  assert.equal(ls.getItem("ambush-local-storage-quota-recovery.v1"), "1");
});

test("global cache byte budget evicts only oldest entries needed", () => {
  const ls = makeQuotaLocalStorage({ maxEntries: 20 });
  install(ls);
  ls.store.set("ambush-communities", "keep");
  const snapshot = (updatedAt) =>
    JSON.stringify({ updatedAt, payload: "x".repeat(400_000) });
  const oldestKey = "ambush-channel-messages.v1:relay:oldest";
  const newerKey = "ambush-channels.v1:relay-newer";
  const newestKey = "ambush-channel-messages.v1:relay:newest";

  assert.equal(setLocalStorageItemWithRecovery(oldestKey, snapshot(1)), true);
  assert.equal(setLocalStorageItemWithRecovery(newerKey, snapshot(2)), true);
  assert.equal(setLocalStorageItemWithRecovery(newestKey, snapshot(3)), true);

  assert.equal(ls.getItem(oldestKey), null);
  assert.notEqual(ls.getItem(newerKey), null);
  assert.notEqual(ls.getItem(newestKey), null);
  assert.equal(ls.getItem("ambush-communities"), "keep");
});

test("global cache byte budget spans relays and preserves durable state", () => {
  const ls = makeQuotaLocalStorage({ maxEntries: 20 });
  install(ls);
  ls.store.set("ambush-communities", "keep");
  const largeSnapshot = "x".repeat(600_000);

  assert.equal(
    setLocalStorageItemWithRecovery(
      "ambush-channel-messages.v1:relay-one:chan",
      largeSnapshot,
    ),
    true,
  );
  assert.equal(
    setLocalStorageItemWithRecovery(
      "ambush-channel-messages.v1:relay-two:chan",
      largeSnapshot,
    ),
    true,
  );

  assert.equal(ls.getItem("ambush-channel-messages.v1:relay-one:chan"), null);
  assert.equal(
    ls.getItem("ambush-channel-messages.v1:relay-two:chan"),
    largeSnapshot,
  );
  assert.equal(ls.getItem("ambush-communities"), "keep");
});

test("rejects a single cache entry larger than the global byte budget", () => {
  const ls = makeQuotaLocalStorage({ maxEntries: 10 });
  install(ls);
  const key = "ambush-projects.v1:relay:oversized";
  ls.store.set(key, "previous snapshot");

  assert.equal(
    setLocalStorageItemWithRecovery(key, "x".repeat(1_100_000)),
    false,
  );
  assert.equal(ls.getItem(key), null);
});

test("writes normally when under quota", () => {
  const ls = makeQuotaLocalStorage({ maxEntries: 10 });
  install(ls);
  assert.equal(setLocalStorageItemWithRecovery("k", "v"), true);
  assert.equal(ls.getItem("k"), "v");
});

test("evicts pure caches and retries on quota failure", () => {
  const ls = makeQuotaLocalStorage({ maxEntries: 2 });
  install(ls);
  ls.store.set("ambush-projects.v1:relay:owner", "big");
  ls.store.set("ambush-channels.v1:relay", "big");

  assert.equal(setLocalStorageItemWithRecovery("k", "v"), true);
  assert.equal(ls.getItem("k"), "v");
  assert.equal(ls.getItem("ambush-projects.v1:relay:owner"), null);
  assert.equal(ls.getItem("ambush-channels.v1:relay"), null);
});

test("project snapshots participate in global LRU budgeting", () => {
  const ls = makeQuotaLocalStorage({ maxEntries: 20 });
  install(ls);
  ls.store.set("ambush-communities", "keep");
  const snapshot = (updatedAt) =>
    JSON.stringify({ updatedAt, payload: "x".repeat(400_000) });
  const projectKey = "ambush-projects.v1:relay:owner";
  const newerKey = "ambush-channels.v1:relay:newer";
  const newestKey = "ambush-channel-messages.v1:relay:newest";

  assert.equal(setLocalStorageItemWithRecovery(projectKey, snapshot(1)), true);
  assert.equal(setLocalStorageItemWithRecovery(newerKey, snapshot(2)), true);
  assert.equal(setLocalStorageItemWithRecovery(newestKey, snapshot(3)), true);

  assert.equal(ls.getItem(projectKey), null);
  assert.notEqual(ls.getItem(newerKey), null);
  assert.notEqual(ls.getItem(newestKey), null);
  assert.equal(ls.getItem("ambush-communities"), "keep");
});

test("returns false when eviction frees nothing", () => {
  const ls = makeQuotaLocalStorage({ maxEntries: 2 });
  install(ls);
  ls.store.set("ambush-workspaces", "keep");
  ls.store.set("ambush-active-workspace-id", "keep");

  assert.equal(setLocalStorageItemWithRecovery("k", "v"), false);
  assert.equal(ls.getItem("k"), null);
  assert.equal(ls.getItem("ambush-workspaces"), "keep");
});

test("ambush-observed-unread.v1: prefix participates in LRU eviction and durable state survives", () => {
  // Sentinel: fails if ambush-observed-unread.v1: is removed from PURE_CACHE_KEY_PREFIXES —
  // the bucket becomes invisible to LRU and the wrong entry is evicted instead.
  const ls = makeQuotaLocalStorage({ maxEntries: 20 });
  install(ls);
  ls.store.set("ambush-communities", "keep");

  const snapshot = (updatedAt) =>
    JSON.stringify({ updatedAt, payload: "x".repeat(400_000) });
  const observedKey = "ambush-observed-unread.v1:wss://relay.example.com:pk1";
  const olderKey = "ambush-channel-messages.v1:relay:older";
  const newestKey = "ambush-channel-messages.v1:relay:newest";

  // Seed observed-unread (oldest updatedAt=1) and a sibling channel-messages entry (updatedAt=2).
  assert.equal(setLocalStorageItemWithRecovery(observedKey, snapshot(1)), true);
  assert.equal(setLocalStorageItemWithRecovery(olderKey, snapshot(2)), true);

  // Writing a third pure-cache entry (updatedAt=3) pushes the total above the 2 MiB budget.
  // The observed-unread entry must be evicted first (oldest LRU); the sibling survives.
  assert.equal(setLocalStorageItemWithRecovery(newestKey, snapshot(3)), true);
  assert.equal(
    ls.getItem(observedKey),
    null,
    "observed-unread bucket must be evicted as the oldest LRU pure-cache entry",
  );
  assert.notEqual(
    ls.getItem(olderKey),
    null,
    "channel-messages bucket with newer updatedAt must survive",
  );
  assert.equal(
    ls.getItem("ambush-communities"),
    "keep",
    "durable state must survive",
  );
});
