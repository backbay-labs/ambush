import assert from "node:assert/strict";
import test from "node:test";

import {
  clearCommunityStorage,
  initFirstCommunity,
  loadCommunities,
  loadCommunityDiscoveryAfterLeave,
  markCommunityDiscoveryAfterLeave,
  migrateLegacyCommunityStorage,
  saveCommunities,
  shouldAutoConnectDefaultRelay,
} from "./communityStorage.ts";

function createMemoryStorage(initial = {}) {
  const values = new Map(Object.entries(initial));
  return {
    values,
    getItem: (key) => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, String(value)),
    removeItem: (key) => values.delete(key),
    clear: () => values.clear(),
    key: (index) => Array.from(values.keys())[index] ?? null,
    get length() {
      return values.size;
    },
  };
}

test("migrateLegacyCommunityStorage promotes current Ambush workspace state", () => {
  const storage = createMemoryStorage({
    "ambush-workspaces": '[{"id":"current"}]',
    "ambush-active-workspace-id": "current",
  });

  migrateLegacyCommunityStorage(storage);

  assert.equal(storage.getItem("ambush-communities"), '[{"id":"current"}]');
  assert.equal(storage.getItem("ambush-active-community-id"), "current");
});

test("migrateLegacyCommunityStorage does not overwrite new community state", () => {
  const storage = createMemoryStorage({
    "ambush-communities": '[{"id":"new"}]',
    "ambush-active-community-id": "new",
    "ambush-workspaces": '[{"id":"old"}]',
    "ambush-active-workspace-id": "old",
  });

  migrateLegacyCommunityStorage(storage);

  assert.equal(storage.getItem("ambush-communities"), '[{"id":"new"}]');
  assert.equal(storage.getItem("ambush-active-community-id"), "new");
});

test("signed-build relay defaults auto-connect during first-run onboarding", () => {
  assert.equal(shouldAutoConnectDefaultRelay("wss://ambush.example.com"), true);
  assert.equal(shouldAutoConnectDefaultRelay("ws://localhost:3000"), false);
  assert.equal(shouldAutoConnectDefaultRelay("ws://127.0.0.1:3000"), false);
  assert.equal(shouldAutoConnectDefaultRelay("ws://[::1]:3000"), false);
  assert.equal(shouldAutoConnectDefaultRelay("ws://0.0.0.0:3000"), false);
  assert.equal(shouldAutoConnectDefaultRelay("http://localhost:3000"), false);
  assert.equal(
    shouldAutoConnectDefaultRelay("https://relay.example.com"),
    false,
  );
  assert.equal(shouldAutoConnectDefaultRelay("relay.example.com"), false);
  assert.equal(shouldAutoConnectDefaultRelay("not a valid relay"), false);
});

test("failed first-community write preserves existing community data", () => {
  const storage = createMemoryStorage({
    "ambush-communities": '[{"id":"existing"}]',
    "ambush-workspaces": '[{"id":"legacy"}]',
    "ambush-active-workspace-id": "legacy",
  });
  storage.setItem = (key, value) => {
    if (key === "ambush-communities") {
      throw new Error("QuotaExceededError");
    }
    storage.values.set(key, String(value));
  };
  globalThis.localStorage = storage;
  globalThis.window = { localStorage: storage };

  assert.equal(initFirstCommunity("wss://relay.example.com", "pubkey"), null);
  assert.equal(storage.getItem("ambush-communities"), '[{"id":"existing"}]');
  assert.equal(storage.getItem("ambush-active-community-id"), null);
  assert.equal(storage.getItem("ambush-workspaces"), '[{"id":"legacy"}]');
  assert.equal(storage.getItem("ambush-active-workspace-id"), "legacy");
});

test("loading an existing community clears stale final-leave discovery", () => {
  const storage = createMemoryStorage({
    "ambush-communities": '[{"id":"joined"}]',
    "ambush-community-discovery-after-leave": "1",
  });
  globalThis.localStorage = storage;
  globalThis.window = { localStorage: storage };

  assert.deepEqual(loadCommunities(), [{ id: "joined" }]);
  assert.equal(loadCommunityDiscoveryAfterLeave(storage), false);
});

test("completed final leave persists discovery until a community is saved", () => {
  const storage = createMemoryStorage();
  globalThis.localStorage = storage;
  globalThis.window = { localStorage: storage };

  assert.equal(markCommunityDiscoveryAfterLeave(storage), true);
  assert.equal(loadCommunityDiscoveryAfterLeave(storage), true);

  assert.equal(saveCommunities([{ id: "joined" }]), true);
  assert.equal(loadCommunityDiscoveryAfterLeave(storage), false);
});

test("clearCommunityStorage preserves completed final-leave discovery", () => {
  const storage = createMemoryStorage({
    "ambush-communities": "new",
    "ambush-active-community-id": "new",
    "ambush-workspaces": "old",
    "ambush-active-workspace-id": "old",
    "ambush-community-discovery-after-leave": "1",
  });

  clearCommunityStorage(storage);
  migrateLegacyCommunityStorage(storage);

  assert.equal(storage.length, 1);
  assert.equal(loadCommunityDiscoveryAfterLeave(storage), true);
});
