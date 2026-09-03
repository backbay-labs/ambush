import { File, Folder } from "lucide-react";
import { Link } from "@tanstack/react-router";
import type { TreeEntry } from "../git-client";

function TreeRow({
  entry,
  repoId,
  preview,
}: {
  entry: TreeEntry;
  repoId: string;
  preview: boolean;
}) {
  if (entry.type === "tree") {
    // Sub-tree navigation is deferred — show folders as visibly non-clickable
    // so the affordance matches the behaviour.
    return (
      <div
        className="flex items-center gap-2 border-b border-border px-3 py-2 text-sm text-muted-foreground last:border-b-0"
        aria-disabled="true"
      >
        <Folder className="h-4 w-4 shrink-0 text-muted-foreground" />
        <span className="font-medium">{entry.name}</span>
      </div>
    );
  }

  return (
    <Link
      to="/repos/$repoId/blob/$"
      params={{ repoId, _splat: entry.name }}
      search={preview ? { preview: "repositories" } : undefined}
      className="flex items-center gap-2 border-b border-border px-3 py-2 text-sm text-foreground last:border-b-0 hover:bg-accent"
    >
      <File className="h-4 w-4 shrink-0 text-muted-foreground" />
      <span>{entry.name}</span>
    </Link>
  );
}

export function RepoTreeSection({
  entries,
  isLoading,
  repoId,
  preview = false,
}: {
  entries: TreeEntry[] | undefined;
  isLoading: boolean;
  repoId: string;
  preview?: boolean;
}) {
  if (isLoading) {
    return (
      <div className="mt-8">
        <div className="rounded-lg border border-border">
          {["sk-1", "sk-2", "sk-3", "sk-4", "sk-5"].map((key) => (
            <div
              key={key}
              className="flex items-center gap-2 border-b border-border px-3 py-2 last:border-b-0"
            >
              <div className="h-4 w-4 animate-pulse rounded bg-muted" />
              <div className="h-4 w-32 animate-pulse rounded bg-muted" />
            </div>
          ))}
        </div>
      </div>
    );
  }

  if (!entries || entries.length === 0) return null;

  return (
    <div className="mt-8">
      <div className="overflow-hidden rounded-lg border border-border bg-secondary">
        {entries.map((entry) => (
          <TreeRow
            key={entry.name}
            entry={entry}
            repoId={repoId}
            preview={preview}
          />
        ))}
      </div>
    </div>
  );
}
