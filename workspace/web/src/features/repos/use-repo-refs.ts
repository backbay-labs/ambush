import { useQuery } from "@tanstack/react-query";
import { queryEvents, type NostrEvent } from "@/shared/lib/nostr-client";
import { relayHttpBaseUrl, relayWsUrl } from "@/shared/lib/relay-url";
import { dedup } from "./use-repos";

export interface RepoRefs {
  branches: string[];
  tags: string[];
  head: { ref: string; sha: string } | null;
}

function parseRefs(events: NostrEvent[]): RepoRefs {
  const latest = dedup(events);
  const branches: string[] = [];
  const tags: string[] = [];
  let head: RepoRefs["head"] = null;

  for (const event of latest) {
    for (const tag of event.tags) {
      const [name, value] = tag;
      if (!name || !value) continue;

      if (name === "HEAD" && value.startsWith("ref: refs/heads/")) {
        // HEAD points to a branch ref — find its SHA from a matching branch tag
        const branchName = value.replace("ref: refs/heads/", "");
        head = { ref: branchName, sha: "" };
      } else if (name.startsWith("refs/heads/")) {
        branches.push(name.replace("refs/heads/", ""));
      } else if (name.startsWith("refs/tags/")) {
        tags.push(name.replace("refs/tags/", ""));
      }
    }
  }

  // Resolve HEAD SHA from the matching branch
  if (head) {
    for (const event of latest) {
      for (const tag of event.tags) {
        if (tag[0] === `refs/heads/${head.ref}` && tag[1]) {
          head = { ref: head.ref, sha: tag[1] };
          break;
        }
      }
      if (head.sha) break;
    }
  }

  return { branches, tags, head };
}

async function fetchRelaySigningPubkey(): Promise<string> {
  const response = await fetch(relayHttpBaseUrl(), {
    headers: { Accept: "application/nostr+json" },
    signal: AbortSignal.timeout(10_000),
  });
  if (!response.ok) {
    throw new Error(`Failed to load relay signing pubkey (${response.status})`);
  }

  const document = (await response.json()) as { self?: unknown };
  if (
    typeof document.self !== "string" ||
    !/^[0-9a-f]{64}$/i.test(document.self)
  ) {
    throw new Error("NIP-11 did not advertise a valid relay signing pubkey");
  }
  return document.self.toLowerCase();
}

export async function fetchRepoRefs(repoId: string): Promise<RepoRefs> {
  const relayPubkey = await fetchRelaySigningPubkey();
  const events = await queryEvents(relayWsUrl(), {
    authors: [relayPubkey],
    kinds: [30618],
    "#d": [repoId],
  });
  return parseRefs(events.filter((event) => event.pubkey === relayPubkey));
}

export function useRepoRefs(repoId: string, { preview = false } = {}) {
  const mockRefs: RepoRefs = {
    branches: ["main"],
    tags: ["v0.1.0"],
    head: { ref: "main", sha: "a".repeat(40) },
  };

  return useQuery({
    queryKey: preview ? ["repo-refs", "mock", repoId] : ["repo-refs", repoId],
    queryFn: preview ? async () => mockRefs : () => fetchRepoRefs(repoId),
    initialData: preview ? mockRefs : undefined,
    staleTime: 60_000,
  });
}
