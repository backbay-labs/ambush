import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const queryEvents = vi.hoisted(() => vi.fn());

vi.mock("@/shared/lib/nostr-client", () => ({ queryEvents }));
vi.mock("@/shared/lib/relay-url", () => ({
  relayHttpBaseUrl: () => "http://relay.test",
  relayWsUrl: () => "ws://relay.test",
}));

import { fetchRepoRefs } from "./use-repo-refs";

describe("fetchRepoRefs", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    queryEvents.mockResolvedValue([]);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("accepts repository state only from the NIP-11 relay signing key", async () => {
    const relayPubkey = "ab".repeat(32);
    const fetch = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ self: relayPubkey }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetch);

    await fetchRepoRefs("repo-id");

    expect(fetch).toHaveBeenCalledWith(
      "http://relay.test",
      expect.objectContaining({
        headers: { Accept: "application/nostr+json" },
      }),
    );
    expect(queryEvents).toHaveBeenCalledWith("ws://relay.test", {
      authors: [relayPubkey],
      kinds: [30618],
      "#d": ["repo-id"],
    });
  });

  it("discards a mismatched author even if the relay violates its filter", async () => {
    const relayPubkey = "ab".repeat(32);
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(
          new Response(JSON.stringify({ self: relayPubkey }), { status: 200 }),
        ),
    );
    queryEvents.mockResolvedValue([
      {
        id: "1".repeat(64),
        pubkey: "cd".repeat(32),
        kind: 30618,
        content: "",
        created_at: 1,
        tags: [
          ["d", "repo-id"],
          ["HEAD", "ref: refs/heads/forged"],
          ["refs/heads/forged", "e".repeat(40)],
        ],
        sig: "f".repeat(128),
      },
    ]);

    await expect(fetchRepoRefs("repo-id")).resolves.toEqual({
      branches: [],
      tags: [],
      head: null,
    });
  });

  it("fails closed when NIP-11 does not advertise a valid signing key", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify({ self: "not-a-pubkey" }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      ),
    );

    await expect(fetchRepoRefs("repo-id")).rejects.toThrow(
      "relay signing pubkey",
    );
    expect(queryEvents).not.toHaveBeenCalled();
  });
});
