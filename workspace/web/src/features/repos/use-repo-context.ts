/**
 * Shared resolver for the `(owner, repoName, defaultRef)` triple every
 * repo-scoped page needs. Combines the NIP-34 announcement (`useRepo`) with
 * the refs query (`useRepoRefs`) so callers don't duplicate that wiring.
 *
 * `defaultRef` falls back to `"main"` until refs load, matching the
 * pre-existing behaviour in `RepoDetailPage`.
 */
import { useRepo } from "./use-repos";
import { useRepoRefs } from "./use-repo-refs";

export interface RepoContext {
  owner: string;
  repoName: string;
  defaultRef: string;
  isLoading: boolean;
  error: Error | null;
}

export function useRepoContext(
  repoId: string,
  { preview = false } = {},
): RepoContext {
  const {
    data: repo,
    isLoading: repoLoading,
    error: repoError,
  } = useRepo(repoId, { preview });
  const {
    data: refs,
    isLoading: refsLoading,
    error: refsError,
  } = useRepoRefs(repoId, { preview });

  // A failed refs lookup (NIP-11 unreachable, no stable relay signing key,
  // relay query failure) is an error, not a repository on `main`: report it
  // so pages stop before browsing a guessed ref.
  return {
    owner: repo?.owner ?? "",
    repoName: repo?.id ?? "",
    defaultRef: refs?.head?.ref ?? "main",
    isLoading: repoLoading || refsLoading,
    error: (repoError as Error | null) ?? (refsError as Error | null) ?? null,
  };
}
