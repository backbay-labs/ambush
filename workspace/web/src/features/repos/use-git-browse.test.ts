import { beforeEach, describe, expect, it, vi } from "vitest";

const useQuery = vi.hoisted(() => vi.fn());
const gitClient = vi.hoisted(() => ({
  ensureClone: vi.fn(),
  findReadme: vi.fn().mockResolvedValue(null),
  getCommitLog: vi.fn().mockResolvedValue([]),
  readBlobView: vi
    .fn()
    .mockResolvedValue({ kind: "html", content: "<p>snapshot</p>" }),
  readTreeEntries: vi.fn().mockResolvedValue([]),
  resolveHtmlAssets: vi.fn().mockResolvedValue(""),
}));

vi.mock("@tanstack/react-query", () => ({ useQuery }));
vi.mock("./git-client", () => gitClient);

import {
  useGitBlob,
  useGitHtmlDoc,
  useGitLog,
  useGitReadme,
  useGitTree,
} from "./use-git-browse";

describe("git browse snapshot cache", () => {
  const fs = {};
  const dir = "/repos/alice/demo";
  const oid = "d".repeat(40);

  beforeEach(() => {
    vi.clearAllMocks();
    useQuery.mockImplementation((options) =>
      options.queryKey[0] === "git-clone"
        ? { data: { fs, dir, oid } }
        : options,
    );
  });

  it("keys and reads every derived view from the clone's immutable oid", async () => {
    useGitTree("alice", "demo", "main", "src");
    useGitLog("alice", "demo", "main");
    useGitReadme("alice", "demo", "main");
    useGitBlob("alice", "demo", "main", "src/lib.ts");
    useGitHtmlDoc("alice", "demo", "main", "docs/index.html", true);

    const queries = useQuery.mock.calls
      .map(
        ([options]) =>
          options as {
            queryKey: unknown[];
            queryFn: () => Promise<unknown>;
          },
      )
      .filter((query) => query.queryKey[0] !== "git-clone");
    expect(queries).toHaveLength(5);

    for (const query of queries) {
      expect(query.queryKey).toContain(oid);
      await query.queryFn();
    }

    expect(gitClient.readTreeEntries).toHaveBeenCalledWith(fs, dir, oid, "src");
    expect(gitClient.getCommitLog).toHaveBeenCalledWith(fs, dir, oid);
    expect(gitClient.findReadme).toHaveBeenCalledWith(fs, dir, oid);
    expect(gitClient.readBlobView).toHaveBeenCalledWith(
      fs,
      dir,
      oid,
      "src/lib.ts",
    );
    expect(gitClient.resolveHtmlAssets).toHaveBeenCalledWith(
      fs,
      dir,
      oid,
      "docs/index.html",
      "<p>snapshot</p>",
    );
  });
});
