import * as React from "react";

import {
  type InboxContextMessage,
  type InboxItem,
  type InboxReply,
  formatInboxFullTimestamp,
} from "@/features/home/lib/inbox";
import { getHomeMessageCapabilities } from "@/features/home/lib/homeMessageCapabilities";
import { useInboxEditMessage } from "@/features/home/useInboxEditMessage";
import { formatTime } from "@/features/messages/lib/dateFormatters";
import { splitOutgoingTags } from "@/features/messages/lib/imetaMediaMarkdown";
import { getThreadReference } from "@/features/messages/lib/threading";
import { useToggleReactionMutation } from "@/features/messages/hooks";
import { resolveUserLabel } from "@/features/profile/lib/identity";
import { sendChannelMessage } from "@/shared/api/tauri";
import type { Channel, FeedItem, UserProfileSummary } from "@/shared/api/types";
import { InboxDetailPane } from "@/features/home/ui/InboxDetailPane";

type UnreadBoundary = {
  conversationId: string;
  eventId: string;
} | null;

type LocalReplies = Record<string, InboxReply[]>;

type HomeMessagesDetailProps = {
  activeLatchedItem: FeedItem | null;
  agentPubkeys: ReadonlySet<string>;
  availableChannelIds: ReadonlySet<string>;
  canOpenSelected: boolean;
  channel: Channel | null;
  channelMessagesRefetch: () => Promise<unknown>;
  currentPubkey: string | undefined;
  deleteInboxMessage: (eventId: string) => void;
  editTargetId: string | null;
  effectiveDoneSet: ReadonlySet<string>;
  handleCloseProfilePanel: () => void;
  handleOpenSelectedContext: (
    channelId: string,
    messageId: string,
    threadRootId?: string | null,
  ) => void;
  hasThreadContextLoadError: boolean;
  isDeletingMessage: boolean;
  isReopenErrored: (channelId: string | null | undefined) => boolean;
  isReopenPending: (channelId: string | null | undefined) => boolean;
  isSendingReply: boolean;
  isSinglePanelView: boolean;
  isThreadContextLoading: boolean;
  localRepliesByItemId: LocalReplies;
  messages: InboxContextMessage[];
  onRefresh: () => void;
  onSelectNone: () => void;
  profiles: Record<string, UserProfileSummary> | undefined;
  recordThreadInteraction: (rootId: string) => void;
  refreshReactions: () => Promise<void>;
  refreshStructuralEvents: () => Promise<void>;
  selectedEventId: string | null;
  selectedItem: InboxItem | null;
  setEditTargetId: React.Dispatch<React.SetStateAction<string | null>>;
  setEmptyDeleteId: React.Dispatch<React.SetStateAction<string | null>>;
  setIsSendingReply: React.Dispatch<React.SetStateAction<boolean>>;
  setLocalRepliesByItemId: React.Dispatch<React.SetStateAction<LocalReplies>>;
  setManagedChannelId: React.Dispatch<React.SetStateAction<string | null>>;
  show: boolean;
  unreadBoundary: UnreadBoundary;
};

/** Renders and owns the message-specific detail behavior for the Home inbox. */
export function HomeMessagesDetail({
  activeLatchedItem,
  agentPubkeys,
  availableChannelIds,
  canOpenSelected,
  channel,
  channelMessagesRefetch,
  currentPubkey,
  deleteInboxMessage,
  editTargetId,
  effectiveDoneSet,
  handleCloseProfilePanel,
  handleOpenSelectedContext,
  hasThreadContextLoadError,
  isDeletingMessage,
  isReopenErrored,
  isReopenPending,
  isSendingReply,
  isSinglePanelView,
  isThreadContextLoading,
  localRepliesByItemId,
  messages,
  onRefresh,
  onSelectNone,
  profiles,
  recordThreadInteraction,
  refreshReactions,
  refreshStructuralEvents,
  selectedEventId,
  selectedItem,
  setEditTargetId,
  setEmptyDeleteId,
  setIsSendingReply,
  setLocalRepliesByItemId,
  setManagedChannelId,
  show,
  unreadBoundary,
}: HomeMessagesDetailProps) {
  const latchedDefaultParentId =
    activeLatchedItem !== null
      ? (getThreadReference(activeLatchedItem.tags).parentId ??
        activeLatchedItem.id)
      : null;
  const toggleReactionMutation = useToggleReactionMutation();
  const { editMessage, isEditingMessage } = useInboxEditMessage(
    channel,
    refreshStructuralEvents,
  );
  const unreadBoundaryEventId = React.useMemo(() => {
    if (!selectedItem) return null;
    if (unreadBoundary?.conversationId === selectedItem.conversationId) {
      return unreadBoundary.eventId;
    }
    return effectiveDoneSet.has(selectedItem.id) ? null : selectedItem.id;
  }, [effectiveDoneSet, selectedItem, unreadBoundary]);
  const selectedItemReplies = React.useMemo<InboxReply[]>(() => {
    if (!selectedItem) return [];
    const localReplies =
      localRepliesByItemId[selectedItem.conversationId] ?? [];
    const contextIds = new Set(messages.map((message) => message.id));
    return localReplies.filter((reply) => !contextIds.has(reply.id));
  }, [localRepliesByItemId, messages, selectedItem]);
  const { canDelete, canReact, canReply, disabledReplyReason } =
    getHomeMessageCapabilities(
      selectedItem,
      currentPubkey,
      availableChannelIds,
    );

  if (!show) return null;

  return (
    <InboxDetailPane
      agentPubkeys={agentPubkeys}
      canDelete={canDelete}
      canOpenChannel={canOpenSelected}
      canReply={canReply}
      channel={channel}
      contextChannelName={channel?.name ?? null}
      currentPubkey={currentPubkey}
      disabledReplyReason={disabledReplyReason}
      isDeletingMessage={isDeletingMessage}
      isEditingMessage={isEditingMessage}
      isSendingReply={isSendingReply}
      isSinglePanelView={isSinglePanelView}
      hasThreadContextLoadError={hasThreadContextLoadError}
      isThreadContextLoading={isThreadContextLoading}
      item={selectedItem}
      latchedDefaultParentId={latchedDefaultParentId}
      messages={messages}
      profiles={profiles}
      selectedEventId={selectedEventId}
      unreadBoundaryEventId={unreadBoundaryEventId}
      editTargetId={editTargetId}
      onEditTargetChange={setEditTargetId}
      onBack={isSinglePanelView ? onSelectNone : undefined}
      onDelete={() => {
        if (!selectedItem || !canDelete) return;
        void deleteInboxMessage(selectedItem.id);
      }}
      onDeleteMessage={deleteInboxMessage}
      onManageChannel={(channelId) => {
        handleCloseProfilePanel();
        setManagedChannelId(channelId);
      }}
      onEditSave={editMessage}
      onRequestEmptyEditDelete={setEmptyDeleteId}
      onOpenContext={handleOpenSelectedContext}
      reopenPending={isReopenPending(selectedItem?.item.channelId)}
      reopenErrored={isReopenErrored(selectedItem?.item.channelId)}
      onSendReply={async ({
        content,
        mediaTags,
        mentionPubkeys,
        parentEventId,
      }) => {
        const channelId = selectedItem?.item.channelId;
        if (!selectedItem || !channelId || !canReply) {
          throw new Error("Replies are not available for this item.");
        }

        const itemToReply = selectedItem;
        setIsSendingReply(true);
        try {
          const {
            mediaTags: imetaTags,
            emojiTags,
            mentionTags,
          } = splitOutgoingTags(mediaTags);
          const result = await sendChannelMessage(
            channelId,
            content,
            parentEventId,
            imetaTags,
            mentionPubkeys,
            undefined,
            emojiTags,
            mentionTags,
          );
          const authorPubkey = currentPubkey ?? itemToReply.item.pubkey;
          const reply: InboxReply = {
            authorLabel: currentPubkey
              ? resolveUserLabel({
                  currentPubkey,
                  profiles,
                  pubkey: authorPubkey,
                })
              : "You",
            authorPubkey,
            avatarUrl:
              currentPubkey && profiles
                ? (profiles[currentPubkey.trim().toLowerCase()]?.avatarUrl ??
                  null)
                : null,
            content,
            createdAt: result.createdAt,
            depth: result.depth,
            fullTimestampLabel: formatInboxFullTimestamp(result.createdAt),
            id: result.eventId,
            parentId: result.parentEventId,
            rootId: result.rootEventId,
            tags: [...imetaTags, ...emojiTags, ...mentionTags],
            timeLabel: formatTime(result.createdAt),
          };
          setLocalRepliesByItemId((current) => ({
            ...current,
            [itemToReply.conversationId]: [
              ...(current[itemToReply.conversationId] ?? []),
              reply,
            ],
          }));
          onRefresh();
        } finally {
          setIsSendingReply(false);
        }
      }}
      onToggleReaction={
        canReact
          ? async (message, emoji, remove) => {
              await toggleReactionMutation.mutateAsync({
                emoji,
                eventId: message.id,
                remove,
              });
              if (!remove) {
                recordThreadInteraction(
                  selectedItem?.conversationId ?? message.rootId ?? message.id,
                );
              }
              await refreshReactions();
              await channelMessagesRefetch();
              onRefresh();
            }
          : undefined
      }
      replies={selectedItemReplies}
    />
  );
}
