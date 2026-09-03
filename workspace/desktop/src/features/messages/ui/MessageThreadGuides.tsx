import * as React from "react";
import {
  getThreadReplyAvatarCenterRem,
  getThreadReplyAvatarCenterYRem,
  getThreadReplyConnectorLayout,
  getThreadReplyDescendantRailStartYRem,
  threadReplyLength,
  THREAD_REPLY_LINE_WIDTH_REM,
} from "@/features/messages/lib/threadTreeLayout";
import type { TimelineMessage } from "@/features/messages/types";
import { cn } from "@/shared/lib/cn";

/** A collapse affordance offered on one ancestor depth guide. */
export type ThreadDepthGuideAction = {
  active?: boolean;
  depth: number;
  label: string;
  message: TimelineMessage;
};

export function MessageThreadGuides({
  collapseDepthGuideActions,
  collapseDescendantsLabel,
  connectDescendants = false,
  depthGuideDepths,
  highlightDescendantRail = false,
  highlightReplyConnector = false,
  highlightThreadLineDepths,
  isThreadReplyLayout,
  message,
  onCollapseDepthGuide,
  onCollapseDepthGuideHoverChange,
  onCollapseDescendants,
  onCollapseDescendantsHoverChange,
  showDepthGuides = true,
}: {
  collapseDepthGuideActions?: ReadonlyArray<ThreadDepthGuideAction>;
  collapseDescendantsLabel?: string;
  connectDescendants?: boolean;
  depthGuideDepths?: ReadonlyArray<number>;
  highlightDescendantRail?: boolean;
  highlightReplyConnector?: boolean;
  highlightThreadLineDepths?: ReadonlyArray<number>;
  isThreadReplyLayout: boolean;
  message: TimelineMessage;
  onCollapseDepthGuide?: (message: TimelineMessage) => void;
  onCollapseDepthGuideHoverChange?: (
    message: TimelineMessage,
    hovered: boolean,
  ) => void;
  onCollapseDescendants?: (message: TimelineMessage) => void;
  onCollapseDescendantsHoverChange?: (
    message: TimelineMessage,
    hovered: boolean,
  ) => void;
  showDepthGuides?: boolean;
}) {
  const descendantGuideOffsetRem = connectDescendants
    ? getThreadReplyAvatarCenterRem(message.depth)
    : null;
  const replyConnector = React.useMemo(() => {
    return getThreadReplyConnectorLayout(message.depth);
  }, [message.depth]);
  const depthGuideItems = React.useMemo(() => {
    const depths =
      depthGuideDepths ??
      Array.from(
        { length: Math.max(0, message.depth - 1) },
        (_, index) => index + 1,
      );

    return depths.map((depth) => ({
      depth,
      offset: getThreadReplyAvatarCenterRem(depth),
    }));
  }, [depthGuideDepths, message.depth]);
  const handleCollapseDescendants = React.useCallback(
    (event: React.MouseEvent<HTMLButtonElement>) => {
      event.preventDefault();
      event.stopPropagation();
      onCollapseDescendants?.(message);
    },
    [message, onCollapseDescendants],
  );
  const handleCollapseDescendantsHoverChange = React.useCallback(
    (hovered: boolean) => {
      onCollapseDescendantsHoverChange?.(message, hovered);
    },
    [message, onCollapseDescendantsHoverChange],
  );
  const handleCollapseDepthGuide = React.useCallback(
    (
      event: React.MouseEvent<HTMLButtonElement>,
      targetMessage: TimelineMessage,
    ) => {
      event.preventDefault();
      event.stopPropagation();
      onCollapseDepthGuide?.(targetMessage);
    },
    [onCollapseDepthGuide],
  );
  const handleCollapseDepthGuideHoverChange = React.useCallback(
    (targetMessage: TimelineMessage, hovered: boolean) => {
      onCollapseDepthGuideHoverChange?.(targetMessage, hovered);
    },
    [onCollapseDepthGuideHoverChange],
  );
  const collapseDepthGuideActionsByDepth = React.useMemo(() => {
    if (!collapseDepthGuideActions?.length) {
      return new Map<number, ThreadDepthGuideAction>();
    }

    return new Map(
      collapseDepthGuideActions.map((action) => [action.depth, action]),
    );
  }, [collapseDepthGuideActions]);
  const guideBleedRem = isThreadReplyLayout ? 0.25 : 0;

  return (
    <>
      {showDepthGuides && depthGuideItems.length > 0 ? (
        <div
          aria-hidden={
            collapseDepthGuideActionsByDepth.size > 0 ? undefined : true
          }
          className={cn(
            "absolute left-0",
            collapseDepthGuideActionsByDepth.size === 0 &&
              "pointer-events-none",
          )}
          style={{
            bottom: threadReplyLength(-guideBleedRem),
            top: threadReplyLength(-guideBleedRem),
          }}
        >
          {depthGuideItems.map(({ depth, offset }) => {
            const collapseAction = collapseDepthGuideActionsByDepth.get(depth);
            const isHighlighted =
              Boolean(collapseAction?.active) ||
              Boolean(highlightThreadLineDepths?.includes(depth));
            if (collapseAction) {
              return (
                <React.Fragment key={`${message.id}-depth-guide-${offset}`}>
                  <div
                    aria-hidden
                    className={cn(
                      "pointer-events-none absolute bottom-0 top-0 border-l transition-[border-color]",
                      isHighlighted ? "border-primary" : "border-border/45",
                    )}
                    style={{
                      borderLeftWidth: threadReplyLength(
                        THREAD_REPLY_LINE_WIDTH_REM,
                      ),
                      left: threadReplyLength(offset),
                    }}
                  />
                  <button
                    aria-label={collapseAction.label}
                    className="absolute bottom-0 top-0 z-20 w-5 -translate-x-1/2 cursor-pointer rounded-full focus-visible:outline-hidden"
                    data-thread-head-id={collapseAction.message.id}
                    data-testid="thread-collapse-guide"
                    onBlur={() =>
                      handleCollapseDepthGuideHoverChange(
                        collapseAction.message,
                        false,
                      )
                    }
                    onClick={(event) =>
                      handleCollapseDepthGuide(event, collapseAction.message)
                    }
                    onFocus={() =>
                      handleCollapseDepthGuideHoverChange(
                        collapseAction.message,
                        true,
                      )
                    }
                    onMouseEnter={() =>
                      handleCollapseDepthGuideHoverChange(
                        collapseAction.message,
                        true,
                      )
                    }
                    onMouseLeave={() =>
                      handleCollapseDepthGuideHoverChange(
                        collapseAction.message,
                        false,
                      )
                    }
                    style={{ left: threadReplyLength(offset) }}
                    type="button"
                  />
                </React.Fragment>
              );
            }

            return (
              <div
                aria-hidden
                className={cn(
                  "pointer-events-none absolute bottom-0 top-0 border-l transition-[border-color]",
                  isHighlighted ? "border-primary" : "border-border/45",
                )}
                key={`${message.id}-depth-guide-${offset}`}
                style={{
                  borderLeftWidth: threadReplyLength(
                    THREAD_REPLY_LINE_WIDTH_REM,
                  ),
                  left: threadReplyLength(offset),
                }}
              />
            );
          })}
        </div>
      ) : null}
      {showDepthGuides && descendantGuideOffsetRem !== null ? (
        <>
          <div
            aria-hidden
            className={cn(
              "pointer-events-none absolute bottom-0 z-0 border-l transition-[border-color]",
              highlightDescendantRail ? "border-primary" : "border-border/45",
            )}
            style={{
              bottom: threadReplyLength(-guideBleedRem),
              borderLeftWidth: threadReplyLength(THREAD_REPLY_LINE_WIDTH_REM),
              left: threadReplyLength(descendantGuideOffsetRem),
              top: threadReplyLength(getThreadReplyDescendantRailStartYRem()),
            }}
          />
          {onCollapseDescendants ? (
            <button
              aria-label={
                collapseDescendantsLabel ?? "Collapse replies to this message"
              }
              className="absolute bottom-0 z-20 w-5 -translate-x-1/2 cursor-pointer rounded-full p-0 focus-visible:outline-hidden"
              data-thread-head-id={message.id}
              data-testid="thread-collapse-rail"
              onBlur={() => handleCollapseDescendantsHoverChange(false)}
              onClick={handleCollapseDescendants}
              onFocus={() => handleCollapseDescendantsHoverChange(true)}
              onMouseEnter={() => handleCollapseDescendantsHoverChange(true)}
              onMouseLeave={() => handleCollapseDescendantsHoverChange(false)}
              style={{
                left: threadReplyLength(descendantGuideOffsetRem),
                top: threadReplyLength(getThreadReplyAvatarCenterYRem()),
              }}
              type="button"
            />
          ) : null}
        </>
      ) : null}
      {showDepthGuides && replyConnector ? (
        <div
          aria-hidden
          className={cn(
            "pointer-events-none absolute left-0 top-0 rounded-bl-2xl border-b border-l transition-[border-color]",
            highlightReplyConnector ? "border-primary" : "border-border/45",
          )}
          style={{
            borderBottomWidth: threadReplyLength(THREAD_REPLY_LINE_WIDTH_REM),
            borderLeftWidth: threadReplyLength(THREAD_REPLY_LINE_WIDTH_REM),
            height: threadReplyLength(replyConnector.heightRem + guideBleedRem),
            left: threadReplyLength(replyConnector.parentOffsetRem),
            top: threadReplyLength(-guideBleedRem),
            width: threadReplyLength(replyConnector.widthRem),
          }}
        />
      ) : null}
    </>
  );
}
