import { beforeEach, describe, expect, it, vi } from "vitest";

const useRepo = vi.hoisted(() => vi.fn());
const useRepoRefs = vi.hoisted(() => vi.fn());

vi.mock("./use-repos", () => ({ useRepo }));
vi.mock("./use-repo-refs", () => ({ useRepoRefs }));

import { useRepoContext } from "./use-repo-context";

describe("useRepoContext", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    useRepo.mockReturnValue({
      data: { owner: "alice", id: "demo" },
      isLoading: false,
      error: null,
    });
    useRepoRefs.mockReturnValue({
      data: { branches: ["dev"], tags: [], head: { ref: "dev", sha: "" } },
      isLoading: false,
      error: null,
    });
  });

  it("resolves the announcement and the trusted HEAD ref", () => {
    expect(useRepoContext("repo-id")).toEqual({
      owner: "alice",
      repoName: "demo",
      defaultRef: "dev",
      isLoading: false,
      error: null,
    });
  });

  it("surfaces a refs lookup failure instead of silently browsing main", () => {
    const refsError = new Error(
      "NIP-11 did not advertise a valid relay signing pubkey",
    );
    useRepoRefs.mockReturnValue({
      data: undefined,
      isLoading: false,
      error: refsError,
    });

    const context = useRepoContext("repo-id");

    expect(context.error).toBe(refsError);
    expect(context.isLoading).toBe(false);
  });

  it("reports the announcement failure ahead of a refs failure", () => {
    const repoError = new Error("relay unreachable");
    useRepo.mockReturnValue({
      data: undefined,
      isLoading: false,
      error: repoError,
    });
    useRepoRefs.mockReturnValue({
      data: undefined,
      isLoading: false,
      error: new Error("refs failed"),
    });

    expect(useRepoContext("repo-id").error).toBe(repoError);
  });
});
