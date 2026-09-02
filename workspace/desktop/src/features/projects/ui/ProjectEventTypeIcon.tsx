import {
  Check,
  CircleDot,
  FolderGit2,
  GitCommitHorizontal,
  GitPullRequest,
  MessageSquare,
  TriangleAlert,
  UserPlus,
} from "lucide-react";
import type { ComponentType } from "react";

import { cn } from "@/shared/lib/cn";

export type ProjectEventKind =
  | "repository"
  | "commit"
  | "pull-request"
  | "issue"
  | "comment"
  | "approval"
  | "changes-requested"
  | "review-request";

export const PROJECT_EVENT_VISUALS: Record<
  ProjectEventKind,
  {
    icon: ComponentType<{ className?: string }>;
    iconClassName: string;
    badgeClassName: string;
    detailClassName: string;
  }
> = {
  repository: {
    icon: FolderGit2,
    iconClassName: "text-primary",
    badgeClassName: "bg-primary/10 text-primary",
    detailClassName: "border-primary/30 text-primary",
  },
  commit: {
    icon: GitCommitHorizontal,
    iconClassName: "text-primary",
    badgeClassName: "bg-primary/10 text-primary",
    detailClassName: "border-primary/30 text-primary",
  },
  "pull-request": {
    icon: GitPullRequest,
    iconClassName: "text-foreground",
    badgeClassName: "bg-accent text-foreground",
    detailClassName: "border-border text-foreground",
  },
  issue: {
    icon: CircleDot,
    iconClassName: "text-foreground",
    badgeClassName: "bg-accent text-foreground",
    detailClassName: "border-border text-foreground",
  },
  comment: {
    icon: MessageSquare,
    iconClassName: "text-muted-foreground",
    badgeClassName: "bg-muted text-muted-foreground",
    detailClassName: "border-border/60 text-muted-foreground",
  },
  approval: {
    icon: Check,
    iconClassName: "text-foreground",
    badgeClassName: "bg-accent text-foreground",
    detailClassName: "border-border text-foreground",
  },
  "changes-requested": {
    icon: TriangleAlert,
    iconClassName: "text-warning",
    badgeClassName: "bg-warning-bg text-warning",
    detailClassName: "border-border text-warning",
  },
  "review-request": {
    icon: UserPlus,
    iconClassName: "text-foreground",
    badgeClassName: "bg-accent text-foreground",
    detailClassName: "border-border text-foreground",
  },
};

export function ProjectEventTypeIcon({
  className,
  kind,
}: {
  className?: string;
  kind: ProjectEventKind;
}) {
  const visual = PROJECT_EVENT_VISUALS[kind];
  const Icon = visual.icon;

  return (
    <span
      aria-hidden="true"
      className={cn(
        "inline-flex h-6 w-6 shrink-0 items-center justify-center rounded-full ring-1 ring-border/60",
        visual.badgeClassName,
        className,
      )}
    >
      <Icon className={cn("h-3 w-3", visual.iconClassName)} />
    </span>
  );
}
