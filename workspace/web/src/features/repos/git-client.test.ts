import { beforeEach, describe, expect, it, vi } from "vitest";

const git = vi.hoisted(() => ({
  clone: vi.fn(),
  fetch: vi.fn(),
  log: vi.fn(),
  readBlob: vi.fn(),
  readTree: vi.fn(),
  resolveRef: vi.fn(),
  writeRef: vi.fn(),
}));
const stat = vi.hoisted(() => vi.fn());

vi.mock("isomorphic-git", () => git);
vi.mock("@isomorphic-git/lightning-fs", () => ({
  default: class FakeLightningFs {
    promises = { stat };
  },
}));
vi.mock("isomorphic-git/http/web", () => ({ default: {} }));
vi.mock("@/shared/lib/nip98", () => ({
  makeNip98AuthHeader: vi.fn().mockResolvedValue("Nostr test"),
}));
vi.mock("@/shared/lib/relay-url", () => ({
  relayHttpBaseUrl: () => "http://relay.test",
}));

import { ensureClone } from "./git-client";

describe("ensureClone", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    stat.mockResolvedValue({});
    git.fetch.mockResolvedValue({ fetchHead: "b".repeat(40) });
    git.resolveRef.mockResolvedValue("b".repeat(40));
    git.writeRef.mockResolvedValue(undefined);
  });

  it("advances the local branch to FETCH_HEAD after an existing clone is fetched", async () => {
    const result = await ensureClone("alice", "demo", "main");

    expect(git.resolveRef).toHaveBeenCalledWith(
      expect.objectContaining({ ref: "FETCH_HEAD" }),
    );
    expect(git.writeRef).toHaveBeenCalledWith(
      expect.objectContaining({
        ref: "refs/heads/main",
        value: "b".repeat(40),
        force: true,
      }),
    );
    expect(result.oid).toBe("b".repeat(40));
  });

  it("returns the checked-out oid after creating a new clone", async () => {
    stat.mockRejectedValue(new Error("not cloned"));
    git.clone.mockResolvedValue(undefined);
    git.resolveRef.mockResolvedValue("c".repeat(40));

    const result = await ensureClone("alice", "demo", "main");

    expect(git.resolveRef).toHaveBeenCalledWith(
      expect.objectContaining({ ref: "main" }),
    );
    expect(result.oid).toBe("c".repeat(40));
  });

  it("does not hide a failed refresh behind stale repository data", async () => {
    git.fetch.mockRejectedValue(new Error("network unavailable"));

    await expect(ensureClone("alice", "demo", "main")).rejects.toThrow(
      "network unavailable",
    );
    expect(git.writeRef).not.toHaveBeenCalled();
  });
});
