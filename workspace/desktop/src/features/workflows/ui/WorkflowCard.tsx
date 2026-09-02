import {
  ArrowRight,
  CalendarClock,
  CircleCheckBig,
  GitPullRequest,
  Hash,
  MessageCircle,
  MessageSquare,
  SmilePlus,
  Timer,
  Webhook,
  Zap,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { motion, useReducedMotion } from "motion/react";
import * as React from "react";

import type { Workflow } from "@/shared/api/types";
import { cn } from "@/shared/lib/cn";
import { Switch } from "@/shared/ui/switch";
import { WorkflowActionsMenu } from "./WorkflowActionsMenu";
import {
  getWorkflowEnabled,
  getWorkflowActionTiles,
  getWorkflowCardLabel,
  getWorkflowTriggerEmoji,
  getWorkflowTriggerConfig,
  getWorkflowTriggerType,
} from "./workflowDefinition";
import { StatusEmoji } from "@/features/user-status/ui/StatusEmoji";
import type { WorkflowCardAuthorPresentation } from "./useWorkflowListAuthorPresentations";
import type { WorkflowMessagePresentation } from "./useWorkflowListMessagePresentations";
import { workflowTriggerDescription } from "./workflowTriggerDescription";

type WorkflowCardProps = {
  workflow: Workflow;
  authorPresentation?: WorkflowCardAuthorPresentation;
  channelName?: string;
  isTogglingEnabled?: boolean;
  messagePresentation?: WorkflowMessagePresentation;
  onView: (workflow: Workflow) => void;
  onTrigger: (workflowId: string) => void;
  onToggleEnabled: (workflow: Workflow) => void;
  onEdit: (workflow: Workflow) => void;
  onDuplicate: (workflow: Workflow) => void;
  onDelete: (workflow: Workflow) => void;
};

const TRIGGER_ICONS: Record<string, LucideIcon> = {
  diff_posted: GitPullRequest,
  message_posted: MessageSquare,
  reaction_added: SmilePlus,
  schedule: CalendarClock,
  webhook: Webhook,
};

const ACTION_ICONS: Record<string, LucideIcon> = {
  add_reaction: SmilePlus,
  call_webhook: Webhook,
  delay: Timer,
  request_approval: CircleCheckBig,
  send_dm: MessageCircle,
  send_message: MessageSquare,
  set_channel_topic: Hash,
};

const TRIGGER_ACCENTS: Record<string, string> = {
  diff_posted: "border-border bg-secondary text-secondary-foreground",
  message_posted: "border-border bg-secondary text-secondary-foreground",
  reaction_added: "border-border bg-secondary text-secondary-foreground",
  schedule: "border-border bg-secondary text-secondary-foreground",
  webhook: "border-border bg-secondary text-secondary-foreground",
};

const ACTION_ACCENTS: Record<string, string> = {
  add_reaction: "border-border bg-secondary text-secondary-foreground",
  call_webhook: "border-border bg-secondary text-secondary-foreground",
  delay: "border-border bg-secondary text-secondary-foreground",
  request_approval: "border-border bg-secondary text-secondary-foreground",
  send_dm: "border-border bg-secondary text-secondary-foreground",
  send_message: "border-border bg-secondary text-secondary-foreground",
  set_channel_topic: "border-border bg-secondary text-secondary-foreground",
};

function StatusToggle({
  disabled,
  enabled,
  onToggle,
}: {
  disabled: boolean;
  enabled: boolean;
  onToggle: () => void;
}) {
  return (
    <Switch
      aria-label={enabled ? "Disable workflow" : "Enable workflow"}
      checked={enabled}
      disabled={disabled}
      onCheckedChange={(checked) => {
        if (checked !== enabled) onToggle();
      }}
    />
  );
}

function ActionTile({
  action,
  animationSequence,
  className,
  emoji,
  index,
}: {
  action: string;
  animationSequence: number;
  className?: string;
  emoji: string | null;
  index: number;
}) {
  const ActionIcon = ACTION_ICONS[action];
  const accent = ACTION_ACCENTS[action];
  const reduceMotion = useReducedMotion();

  return (
    <span
      aria-hidden="true"
      className={cn(
        "absolute inset-y-0 flex w-9 items-center justify-center rounded-xl border",
        accent ?? "border-border/65 bg-background/80 text-muted-foreground",
        className,
      )}
    >
      <motion.span
        animate={
          animationSequence > 0 && !reduceMotion
            ? { scale: [1, 1.18, 0.94, 1], y: [0, -5, 1, 0] }
            : undefined
        }
        className="flex items-center justify-center"
        transition={{
          delay: index * 0.11,
          duration: 0.48,
          ease: "easeOut",
        }}
      >
        {emoji ? (
          <StatusEmoji className="h-6 w-6 text-xl" value={emoji} />
        ) : ActionIcon ? (
          <ActionIcon className="h-5 w-5" />
        ) : (
          <Zap className="h-5 w-5" />
        )}
      </motion.span>
    </span>
  );
}

function ActionTileStack({
  actions,
  animationSequence = 0,
}: {
  actions: Array<{ action: string; emoji: string | null; key: string }>;
  animationSequence?: number;
}) {
  const visibleActions = actions.slice(0, 3);

  return (
    <span
      className={cn(
        "relative h-9",
        visibleActions.length === 1 && "w-9",
        visibleActions.length === 2 && "w-[2.625rem]",
        visibleActions.length > 2 && "w-12",
      )}
      data-testid="workflow-card-action-stack"
    >
      {visibleActions
        .map((action, index) => (
          <ActionTile
            action={action.action}
            animationSequence={animationSequence}
            className={cn(
              index === 0 && "left-0 z-10",
              index === 1 && "left-1.5 z-[5] scale-90 opacity-60",
              index === 2 && "left-3 scale-75 opacity-35",
            )}
            emoji={action.emoji}
            index={index}
            key={`${action.key}-${animationSequence}`}
          />
        ))
        .reverse()}
    </span>
  );
}

export function WorkflowCard({
  workflow,
  authorPresentation,
  channelName,
  isTogglingEnabled = false,
  messagePresentation,
  onView,
  onTrigger,
  onToggleEnabled,
  onEdit,
  onDuplicate,
  onDelete,
}: WorkflowCardProps) {
  const [triggerAnimationSequence, setTriggerAnimationSequence] =
    React.useState(0);
  const isEnabled = getWorkflowEnabled(workflow.definition);
  const configuredTrigger = getWorkflowTriggerConfig(workflow.definition);
  const cardLabel = getWorkflowCardLabel(workflow.definition, {
    triggerDescription: configuredTrigger
      ? workflowTriggerDescription(configuredTrigger, {
          authorLabel: authorPresentation?.label ?? undefined,
          authorLoading: authorPresentation?.loading,
          messageLabel: messagePresentation?.messageLabel ?? undefined,
          messageLoading: messagePresentation?.messageLoading,
        })
      : undefined,
  });
  const triggerType = getWorkflowTriggerType(workflow.definition);
  const actionTiles = getWorkflowActionTiles(workflow.definition);
  const triggerEmoji = getWorkflowTriggerEmoji(workflow.definition);
  const TriggerIcon = triggerType ? TRIGGER_ICONS[triggerType] : undefined;
  const triggerAccent = triggerType ? TRIGGER_ACCENTS[triggerType] : undefined;

  return (
    <div
      className={cn(
        "group relative flex min-h-60 w-full flex-col overflow-hidden rounded-2xl border border-border/60 bg-muted/50 p-5 text-left text-foreground transition-colors hover:bg-muted/65",
      )}
      data-testid={`workflow-card-${workflow.id}`}
    >
      <button
        className="absolute inset-0 z-0 rounded-2xl focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-ring"
        onClick={() => onView(workflow)}
        type="button"
      >
        <span className="sr-only">View {workflow.name}</span>
      </button>

      <div className="pointer-events-none relative z-10 flex min-h-48 flex-1 flex-col">
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-center gap-2" aria-hidden="true">
            <span
              className={cn(
                "flex h-9 w-9 items-center justify-center rounded-xl border",
                triggerAccent ??
                  "border-border/65 bg-background/80 text-muted-foreground",
              )}
            >
              {triggerEmoji ? (
                <StatusEmoji className="h-6 w-6 text-xl" value={triggerEmoji} />
              ) : TriggerIcon ? (
                <TriggerIcon className="h-5 w-5" />
              ) : (
                <Zap className="h-5 w-5" />
              )}
            </span>
            {actionTiles.length > 0 ? (
              <>
                <ArrowRight className="h-4 w-4 text-muted-foreground" />
                <ActionTileStack
                  actions={actionTiles}
                  animationSequence={triggerAnimationSequence}
                />
              </>
            ) : null}
          </div>

          <div className="pointer-events-auto flex items-center gap-1.5">
            <StatusToggle
              disabled={isTogglingEnabled}
              enabled={isEnabled}
              onToggle={() => onToggleEnabled(workflow)}
            />
            <WorkflowActionsMenu
              isEnabled={isEnabled}
              isTogglingEnabled={isTogglingEnabled}
              onDelete={() => onDelete(workflow)}
              onDuplicate={() => onDuplicate(workflow)}
              onEdit={() => onEdit(workflow)}
              onToggleEnabled={() => onToggleEnabled(workflow)}
              onTrigger={() => {
                setTriggerAnimationSequence((sequence) => sequence + 1);
                onTrigger(workflow.id);
              }}
              showEnabledToggle={false}
            />
          </div>
        </div>

        <h3
          className="mt-4 line-clamp-4 text-xl font-bold leading-tight tracking-tight"
          data-testid="workflow-card-semantic-label"
        >
          {cardLabel}
        </h3>

        <div className="mt-auto flex min-w-0 items-end justify-between gap-3 pt-5 text-muted-foreground">
          <div className="min-w-0">
            {channelName ? (
              <p
                className="truncate text-xs font-semibold text-foreground"
                data-testid="workflow-card-channel"
              >
                #{channelName}
              </p>
            ) : null}
            <p
              className={cn(
                "truncate text-2xs text-muted-foreground",
                channelName && "mt-0.5",
              )}
              data-testid="workflow-card-name"
            >
              {workflow.name}
            </p>
          </div>
          <span className="shrink-0 text-2xs">
            {new Date(workflow.updatedAt * 1000).toLocaleDateString()}
          </span>
        </div>
      </div>
    </div>
  );
}
