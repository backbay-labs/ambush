import assert from "node:assert/strict";
import test from "node:test";

import {
  configuredCommunityName,
  resolveConfiguredCommunity,
} from "./configuredCommunity.ts";

const RELAY_URL = "ws://localhost:3000";

/**
 * Serve the two documents the resolver reads: the NIP-11 relay information
 * document at the relay root, and the join policy at `/api/join-policy`.
 */
function installFetch({ relayInfo, joinPolicy = { status: 404 } }) {
  const requested = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (input) => {
    const url = String(input);
    requested.push(url);
    const served = url.endsWith("/api/join-policy") ? joinPolicy : relayInfo;
    if (served instanceof Error) return Promise.reject(served);
    return Promise.resolve({
      ok: (served.status ?? 200) < 400,
      status: served.status ?? 200,
      json: () => Promise.resolve(served.body ?? {}),
    });
  };
  return {
    requested,
    restore: () => {
      globalThis.fetch = originalFetch;
    },
  };
}

test("configuredCommunityName prefers the advertised relay name", () => {
  assert.equal(
    configuredCommunityName("  Ambush Relay  ", RELAY_URL),
    "Ambush Relay",
  );
});

test("configuredCommunityName falls back to the host-derived name", () => {
  assert.equal(configuredCommunityName(undefined, RELAY_URL), "Local Dev");
  assert.equal(configuredCommunityName("   ", RELAY_URL), "Local Dev");
  assert.equal(configuredCommunityName(42, RELAY_URL), "Local Dev");
});

test("resolveConfiguredCommunity names a reachable relay with no join policy", async () => {
  const fetchStub = installFetch({
    relayInfo: { body: { name: "Ambush Relay" } },
  });
  try {
    assert.deepEqual(await resolveConfiguredCommunity(RELAY_URL), {
      name: "Ambush Relay",
      relayUrl: RELAY_URL,
    });
    assert.deepEqual(fetchStub.requested, [
      "http://localhost:3000",
      "http://localhost:3000/api/join-policy",
    ]);
  } finally {
    fetchStub.restore();
  }
});

test("resolveConfiguredCommunity withholds an unreachable relay", async () => {
  const fetchStub = installFetch({
    relayInfo: new Error("connection refused"),
  });
  try {
    assert.equal(await resolveConfiguredCommunity(RELAY_URL), null);
  } finally {
    fetchStub.restore();
  }
});

test("resolveConfiguredCommunity withholds a relay that answers with an error", async () => {
  const fetchStub = installFetch({ relayInfo: { status: 502 } });
  try {
    assert.equal(await resolveConfiguredCommunity(RELAY_URL), null);
  } finally {
    fetchStub.restore();
  }
});

test("resolveConfiguredCommunity withholds a relay carrying a join policy", async () => {
  const fetchStub = installFetch({
    relayInfo: { body: { name: "Ambush Relay" } },
    joinPolicy: {
      body: {
        policy: {
          age_attestation_required: true,
          version: "1",
        },
      },
    },
  });
  try {
    assert.equal(await resolveConfiguredCommunity(RELAY_URL), null);
  } finally {
    fetchStub.restore();
  }
});

test("resolveConfiguredCommunity withholds a non-relay URL", async () => {
  const fetchStub = installFetch({ relayInfo: { body: {} } });
  try {
    assert.equal(
      await resolveConfiguredCommunity("http://localhost:3000"),
      null,
    );
    assert.deepEqual(fetchStub.requested, []);
  } finally {
    fetchStub.restore();
  }
});
