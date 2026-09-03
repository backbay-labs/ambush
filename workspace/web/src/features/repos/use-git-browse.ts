/**
 * React Query hooks for browsing git repos via isomorphic-git.
 *
 * All hooks depend on `useGitClone` which ensures the repo is shallow-cloned
 * into IndexedDB before any reads happen.
 */

import { useQuery } from "@tanstack/react-query";
import {
  ensureClone,
  findReadme,
  getCommitLog,
  readBlobView,
  readTreeEntries,
  resolveHtmlAssets,
} from "./git-client";

/**
 * Ensure the repo is cloned (or fetched) into IndexedDB.
 * Other hooks depend on this to get `fs` and `dir`.
 */
export function useGitClone(owner: string, repoName: string, ref: string) {
  return useQuery({
    queryKey: ["git-clone", owner, repoName, ref],
    queryFn: () => ensureClone(owner, repoName, ref),
    staleTime: 5 * 60_000,
    enabled: !!owner && !!repoName && !!ref,
    retry: false,
  });
}

/** Read tree entries at a path (or root). Directories first, then files, alphabetical. */
export function useGitTree(
  owner: string,
  repoName: string,
  ref: string,
  path?: string,
) {
  const cloneQuery = useGitClone(owner, repoName, ref);

  return useQuery({
    queryKey: [
      "git-tree",
      owner,
      repoName,
      ref,
      cloneQuery.data?.oid,
      path ?? "",
    ],
    queryFn: async () => {
      if (!cloneQuery.data) throw new Error("unreachable: enabled guards data");
      const { fs, dir, oid } = cloneQuery.data;
      const entries = await readTreeEntries(fs, dir, oid, path || undefined);

      // Sort: directories first, then files, alphabetical within each group
      return entries.sort((a, b) => {
        if (a.type === "tree" && b.type !== "tree") return -1;
        if (a.type !== "tree" && b.type === "tree") return 1;
        return a.name.localeCompare(b.name);
      });
    },
    enabled: !!cloneQuery.data,
    staleTime: 5 * 60_000,
  });
}

/** Get recent commits for the given ref. */
export function useGitLog(owner: string, repoName: string, ref: string) {
  const cloneQuery = useGitClone(owner, repoName, ref);

  return useQuery({
    queryKey: ["git-log", owner, repoName, ref, cloneQuery.data?.oid],
    queryFn: async () => {
      if (!cloneQuery.data) throw new Error("unreachable: enabled guards data");
      const { fs, dir, oid } = cloneQuery.data;
      return getCommitLog(fs, dir, oid);
    },
    enabled: !!cloneQuery.data,
    staleTime: 5 * 60_000,
  });
}

/** Find and read the README from the repo root. */
export function useGitReadme(owner: string, repoName: string, ref: string) {
  const cloneQuery = useGitClone(owner, repoName, ref);

  return useQuery({
    queryKey: ["git-readme", owner, repoName, ref, cloneQuery.data?.oid],
    queryFn: async () => {
      if (!cloneQuery.data) throw new Error("unreachable: enabled guards data");
      const { fs, dir, oid } = cloneQuery.data;
      return findReadme(fs, dir, oid);
    },
    enabled: !!cloneQuery.data,
    staleTime: 5 * 60_000,
  });
}

/** Read a single file's content as a classified `BlobView`. */
export function useGitBlob(
  owner: string,
  repoName: string,
  ref: string,
  filepath: string,
) {
  const cloneQuery = useGitClone(owner, repoName, ref);

  return useQuery({
    queryKey: [
      "git-blob",
      owner,
      repoName,
      ref,
      cloneQuery.data?.oid,
      filepath,
    ],
    queryFn: async () => {
      if (!cloneQuery.data) throw new Error("unreachable: enabled guards data");
      const { fs, dir, oid } = cloneQuery.data;
      return readBlobView(fs, dir, oid, filepath);
    },
    enabled: !!cloneQuery.data && !!filepath,
    staleTime: 5 * 60_000,
  });
}

/**
 * Resolve an HTML file into a self-contained doc (relative assets inlined),
 * ready to drop into a sandboxed iframe. Lazy: `enabled` is caller-gated so
 * we only do the inlining work when the user clicks "Run". The decoded HTML
 * is passed in (the blob view already has it) to avoid a second read.
 */
export function useGitHtmlDoc(
  owner: string,
  repoName: string,
  ref: string,
  filepath: string,
  enabled: boolean,
) {
  const cloneQuery = useGitClone(owner, repoName, ref);

  return useQuery({
    queryKey: [
      "git-html-doc",
      owner,
      repoName,
      ref,
      cloneQuery.data?.oid,
      filepath,
    ],
    queryFn: async () => {
      if (!cloneQuery.data) throw new Error("unreachable: enabled guards data");
      const { fs, dir, oid } = cloneQuery.data;
      const view = await readBlobView(fs, dir, oid, filepath);
      if (view.kind !== "html") {
        throw new Error("HTML preview source is no longer an HTML document");
      }
      return resolveHtmlAssets(fs, dir, oid, filepath, view.content);
    },
    enabled: enabled && !!cloneQuery.data && !!filepath,
    staleTime: 5 * 60_000,
  });
}
