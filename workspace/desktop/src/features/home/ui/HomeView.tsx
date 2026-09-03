import * as React from "react";
import { RefreshCcw } from "lucide-react";

import { useAppShell } from "@/app/AppShellContext";
import { useKnownAgentPubkeys } from "@/features/agents/useKnownAgentPubkeys";
import { useChannelsQuery } from "@/features/channels/hooks";
import {
  type InboxFilter,
  type InboxReply,
  buildInboxItems,
  findInboxItemByEventId,
  getInboxItemConversationId,
} from "@/features/home/lib/inbox";
import { useInboxSelectionAnchor } from "@/features/home/useInboxSelectionAnchor";
import { useOwnedAgentPubkeys } from "@/features/home/useOwnedAgentPubkeys";
import {
  filterInboxItems,
  matchesInboxFilter,
} from "@/features/home/lib/inboxViewHelpers";
import { resolveInboxFilterSelection } from "@/features/home/lib/inboxSelection";
import { useHomeInboxReadState } from "@/features/home/useHomeInboxReadState";
import { useHomeInboxAutoSelection } from "@/features/home/useHomeInboxAutoSelection";
import { useHomeInboxContextMessages } from "@/features/home/useHomeInboxContextMessages";
import { useHomePersonalInbox } from "@/features/home/useHomePersonalInbox";
import { useInboxThreadContext } from "@/features/home/useInboxThreadContext";
import { useHiddenDmInboxNavigation } from "@/features/home/useHiddenDmInboxNavigation";
import {
  INBOX_SINGLE_COLUMN_BREAKPOINT_PX,
  useResizableInboxListWidth,
} from "@/features/home/useResizableInboxListWidth";
import { getHomePaneLayout } from "@/features/home/lib/homePaneLayout";
import { HomeLoadingState } from "@/features/home/ui/HomeLoadingState";
import { HomeInboxAuxiliaryPane } from "@/features/home/ui/HomeInboxAuxiliaryPane";
import { HomeMessagesDetail } from "@/features/home/ui/HomeMessagesDetail";
import { InboxListPane } from "@/features/home/ui/InboxListPane";
import { HomePersonalInboxDetail } from "@/features/home/ui/HomePersonalInboxDetail";
import { useChannelMessagesQuery } from "@/features/messages/hooks";
import { collectMessageMentionPubkeys } from "@/features/messages/lib/formatTimelineMessages";
import { DeleteMessageConfirmDialog } from "@/features/messages/ui/DeleteMessageConfirmDialog";
import { useUsersBatchQuery } from "@/features/profile/hooks";
import { useRelaySelfQuery } from "@/features/moderation/hooks";
import { useRemindLater } from "@/features/reminders/ui/RemindMeLaterProvider";
import { deleteMessage } from "@/shared/api/tauri";
import type { Channel, HomeFeedResponse } from "@/shared/api/types";
import { KIND_REACTION } from "@/shared/constants/kinds";
import { topChromeInset } from "@/shared/layout/chromeLayout";
import { cn } from "@/shared/lib/cn";
import { normalizePubkey } from "@/shared/lib/pubkey";
import { useElementWidth } from "@/shared/hooks/use-mobile";
import { useThreadPanelWidth } from "@/shared/hooks/useThreadPanelWidth";
import { AUXILIARY_PANEL_SINGLE_COLUMN_BREAKPOINT_PX } from "@/shared/layout/AuxiliaryPanel";
import { useHistorySearchState } from "@/shared/hooks/useHistorySearchState";
import { ProfilePanelProvider } from "@/shared/context/ProfilePanelContext";
import { Button } from "@/shared/ui/button";
import { HomeMembersSidebarOverlay } from "./HomeMembersSidebarOverlay";

const INBOX_SEARCH_KEYS = [
  "item",
  "profile",
  "profileTab",
  "profileView",
] as const;

type HomeViewProps = {
  feed?: HomeFeedResponse;
  isLoading?: boolean;
  errorMessage?: string;
  currentPubkey?: string;
  availableChannelIds: ReadonlySet<string>;
  onOpenContext: (
    channelId: string,
    messageId: string,
    threadRootId?: string | null,
  ) => void;
  onRefresh: () => void;
};

export function HomeView({
  feed,
  isLoading = false,
  errorMessage,
  currentPubkey,
  availableChannelIds,
  onOpenContext,
  onRefresh,
}: HomeViewProps) {
  const relaySelfPubkey = useRelaySelfQuery().data;
  const [homeInboxRef, homeInboxWidthPx] = useElementWidth<HTMLDivElement>();
  const isNarrowHomeViewport =
    homeInboxWidthPx > 0 &&
    homeInboxWidthPx < INBOX_SINGLE_COLUMN_BREAKPOINT_PX;
  const [filter, setFilter] = React.useState<InboxFilter>("all");
  const [unreadOnly, setUnreadOnly] = React.useState(false);
  // Explicit selections are mirrored to the URL (`?item=`), so back/forward
  // restores the detail pane each history entry was showing and reloads
  // restore it from the URL. Default/automatic selection stays local-only —
  // background data loads must never trigger navigations.
  const { applyPatch: applyInboxSearchPatch, values: inboxSearchValues } =
    useHistorySearchState(INBOX_SEARCH_KEYS);
  const isReminders = filter === "reminders";
  const isDrafts = filter === "drafts";
  const isMessagesMode = !isReminders && !isDrafts;
  const allowMixedPersonalSelection = filter === "all";
  const {
    drafts: {
      activeCount: activeDraftCount,
      deleteDraft: handleDeleteDraft,
      items: draftItems,
      selectedItem: selectedDraftItem,
      selectedKey: selectedDraftKey,
      selectDraft: setSelectedDraftKey,
    },
    dueReminderCount,
    pendingReminders,
    reminders: {
      selectedId: selectedReminderId,
      selectedItem: selectedReminder,
      select: setSelectedReminderId,
    },
  } = useHomePersonalInbox({
    allowMixedSelection: allowMixedPersonalSelection,
    currentPubkey,
    isDrafts,
    isNarrowHomeViewport,
    isReminders,
    viewportWidthPx: homeInboxWidthPx,
  });
  // `?item=` is Messages-mode-only machinery: a reminder never enters the
  // FeedItem selection model, so reload while in Reminders mode keeps a stale
  // `?item=` unconsumed and does not snap back to a feed-item detail view.
  const urlSelectedItemId = isMessagesMode ? inboxSearchValues.item : null;
  const profilePanelPubkey = inboxSearchValues.profile;
  // Explicit selection is URL-owned; automatic desktop selection stays local.
  const [autoSelectedEventId, setAutoSelectedEventId] = React.useState<
    string | null
  >(null);
  const [unreadBoundary, setUnreadBoundary] = React.useState<{
    conversationId: string;
    eventId: string;
  } | null>(null);
  const selectedEventId = urlSelectedItemId ?? autoSelectedEventId;
  const [managedChannelId, setManagedChannelId] = React.useState<string | null>(
    null,
  );
  const [membersChannel, setMembersChannel] = React.useState<Channel | null>(
    null,
  );
  const handleUserSelectItem = React.useCallback(
    (itemId: string | null) => {
      setAutoSelectedEventId(null);
      applyInboxSearchPatch({ item: itemId });
    },
    [applyInboxSearchPatch],
  );
  const handleOpenProfilePanel = React.useCallback(
    (pubkey: string) => {
      setManagedChannelId(null);
      applyInboxSearchPatch({
        profile: pubkey,
        profileTab: null,
        profileView: null,
      });
    },
    [applyInboxSearchPatch],
  );
  const handleCloseProfilePanel = React.useCallback(() => {
    applyInboxSearchPatch({
      profile: null,
      profileTab: null,
      profileView: null,
    });
  }, [applyInboxSearchPatch]);
  const [isDeletingMessage, setIsDeletingMessage] = React.useState(false);
  const [emptyDeleteId, setEmptyDeleteId] = React.useState<string | null>(null);
  const [editTargetId, setEditTargetId] = React.useState<string | null>(null);
  const [isSendingReply, setIsSendingReply] = React.useState(false);
  const { activeReminderEventIds, openReminder } = useRemindLater();
  const [localRepliesByItemId, setLocalRepliesByItemId] = React.useState<
    Record<string, InboxReply[]>
  >({});
  const {
    canReset: canResetThreadPanelWidth,
    onResetWidth: handleThreadPanelWidthReset,
    onResizeStart: handleThreadPanelResizeStart,
    widthPx: threadPanelWidthPx,
  } = useThreadPanelWidth();
  const {
    canResetInboxListWidth,
    handleInboxListResizeStart,
    handleInboxListWidthReset,
    inboxListWidthPx,
  } = useResizableInboxListWidth();
  const {
    clearChannelUnreadSource,
    getChannelReadAt,
    getThreadReadAt,
    getMessageReadAt,
    feedItemState,
    markChannelRead,
    markChannelUnread,
    markMessageRead,
    markThreadRead,
    recordThreadInteraction,
    readStateVersion,
  } = useAppShell();
  const { doneSet, markDone, markUnread, undoDone, undoUnread, unreadSet } =
    feedItemState;
  const { feedItems, activeLatchedItem, coldResolutionPending } =
    useInboxSelectionAnchor({
      feed,
      selectedEventId,
      availableChannelIds,
    });

  const threadContextFeedItem = activeLatchedItem;
  const channelsQuery = useChannelsQuery();
  const channels = channelsQuery.data;
  const selectedChannelIdCandidate = React.useMemo(() => {
    return threadContextFeedItem?.channelId ?? null;
  }, [threadContextFeedItem]);
  const selectedChannel = React.useMemo(() => {
    if (!selectedChannelIdCandidate || !channels) return null;
    return (
      channels.find((channel) => channel.id === selectedChannelIdCandidate) ??
      null
    );
  }, [channels, selectedChannelIdCandidate]);
  const managedChannel = React.useMemo(() => {
    if (!managedChannelId || !channels) return null;
    return channels.find((channel) => channel.id === managedChannelId) ?? null;
  }, [channels, managedChannelId]);
  const isChannelManagementOpen = managedChannel !== null;
  const hasAuxiliaryPane =
    isChannelManagementOpen || profilePanelPubkey !== null;
  const isSinglePanelAuxiliaryView =
    hasAuxiliaryPane &&
    homeInboxWidthPx > 0 &&
    homeInboxWidthPx < AUXILIARY_PANEL_SINGLE_COLUMN_BREAKPOINT_PX;

  const channelMessagesQuery = useChannelMessagesQuery(selectedChannel);
  const channelMessages = channelMessagesQuery.data;
  const threadContext = useInboxThreadContext(
    threadContextFeedItem,
    channelMessages,
    {
      fullChannel:
        selectedChannel?.channelType === "dm" ||
        threadContextFeedItem?.channelType === "dm",
      hasChannelLoadError: channelMessagesQuery.isError,
      isChannelLoading: channelMessagesQuery.isPending,
    },
  );
  const feedProfilePubkeys = React.useMemo(
    () => [
      ...new Set([
        ...feedItems.map((item) => item.pubkey),
        ...collectMessageMentionPubkeys(feedItems),
        ...threadContext.events.map((event) => event.pubkey),
        ...collectMessageMentionPubkeys(threadContext.events),
        ...(channelMessages ?? [])
          .filter((event) => event.kind === KIND_REACTION)
          .map((event) => event.pubkey),
        ...(currentPubkey ? [currentPubkey] : []),
      ]),
    ],
    [channelMessages, currentPubkey, feedItems, threadContext.events],
  );
  const feedProfilesQuery = useUsersBatchQuery(feedProfilePubkeys, {
    enabled: feedProfilePubkeys.length > 0,
  });
  const feedProfiles = feedProfilesQuery.data?.profiles;
  const ownedAgentPubkeys = useOwnedAgentPubkeys(
    true,
    feedProfiles,
    currentPubkey,
  );
  const feedOwnerPubkeys = React.useMemo(
    () => [
      ...new Set(
        Object.values(feedProfiles ?? {})
          .map((profile) => profile.ownerPubkey)
          .filter((pubkey): pubkey is string => Boolean(pubkey)),
      ),
    ],
    [feedProfiles],
  );
  const feedOwnerProfilesQuery = useUsersBatchQuery(feedOwnerPubkeys, {
    enabled: feedOwnerPubkeys.length > 0,
  });
  const feedOwnerProfiles = feedOwnerProfilesQuery.data?.profiles;
  const communityAgentPubkeys = useKnownAgentPubkeys();
  const inboxAgentPubkeys = React.useMemo(() => {
    const pubkeys = new Set(communityAgentPubkeys);

    for (const [pubkey, profile] of Object.entries(feedProfiles ?? {})) {
      if (profile.isAgent) {
        pubkeys.add(normalizePubkey(pubkey));
      }
    }

    return pubkeys;
  }, [feedProfiles, communityAgentPubkeys]);
  // biome-ignore lint/correctness/useExhaustiveDependencies: readStateVersion invalidates the stable getChannelReadAt callback
  const inboxItems = React.useMemo(() => {
    const items = buildInboxItems({
      channels,
      currentPubkey,
      feed,
      getChannelReadAt,
      getMessageReadAt,
      getThreadReadAt,
      profiles: feedProfiles,
    });
    return filterInboxItems(items);
  }, [
    channels,
    currentPubkey,
    feed,
    feedProfiles,
    getChannelReadAt,
    getMessageReadAt,
    getThreadReadAt,
    readStateVersion,
  ]);
  const { effectiveDoneSet, markItemRead, markItemUnread } =
    useHomeInboxReadState({
      items: inboxItems,
      getChannelReadAt,
      getThreadReadAt,
      getMessageReadAt,
      readStateVersion,
      localDoneSet: doneSet,
      localUnreadSet: unreadSet,
      clearChannelUnreadSource,
      markChannelRead,
      markChannelUnread,
      markMessageRead,
      markThreadRead,
      markDoneLocal: markDone,
      markUnreadLocal: markUnread,
      undoDoneLocal: undoDone,
      undoUnreadLocal: undoUnread,
    });
  // Resolve selection before filtering so unread-only can retain its active row.
  const selectedItemFromAll = React.useMemo(
    () =>
      selectedEventId
        ? findInboxItemByEventId(inboxItems, selectedEventId)
        : null,
    [inboxItems, selectedEventId],
  );
  // selectedConversationId: prefer the InboxItem-derived conversationId (stable
  // group key). Fall back to deriving it from the latched FeedItem when the
  // anchored event is no longer present in any group's items — this keeps the
  // correct row selected (by conversationId) even after the anchor event has
  // been displaced from groupItems by a newer representative.
  const latchedConversationId = activeLatchedItem
    ? getInboxItemConversationId(activeLatchedItem)
    : null;
  const selectedConversationId =
    selectedItemFromAll?.conversationId ?? latchedConversationId;

  const filteredItems = React.useMemo(() => {
    return inboxItems.filter(
      (item) =>
        matchesInboxFilter(item, filter, ownedAgentPubkeys) &&
        (!unreadOnly ||
          !effectiveDoneSet.has(item.id) ||
          item.conversationId === selectedConversationId),
    );
  }, [
    effectiveDoneSet,
    filter,
    inboxItems,
    ownedAgentPubkeys,
    selectedConversationId,
    unreadOnly,
  ]);
  // A filter change may only retain detail for a conversation that remains
  // visible. The filter handler selects the next valid row in the same update,
  // so the detail pane never renders a stale conversation between states.
  const selectedItem = React.useMemo(() => {
    if (!selectedEventId) return null;
    const fromFiltered = findInboxItemByEventId(filteredItems, selectedEventId);
    if (fromFiltered) return fromFiltered;
    if (selectedConversationId) {
      return (
        filteredItems.find(
          (item) => item.conversationId === selectedConversationId,
        ) ?? null
      );
    }
    return null;
  }, [filteredItems, selectedConversationId, selectedEventId]);
  const {
    canOpenSelected,
    handleOpenDirect,
    handleOpenDm,
    handleOpenSelectedContext,
    isReopenPending,
    isReopenErrored,
  } = useHiddenDmInboxNavigation({
    availableChannelIds,
    currentPubkey,
    onOpenContext,
    selectedItem,
  });
  const deleteInboxMessage = React.useCallback(
    async (eventId: string) => {
      const channelId = selectedItem?.item.channelId;
      if (!channelId) return;
      setIsDeletingMessage(true);
      try {
        await deleteMessage(channelId, eventId);
        await threadContext.refreshStructuralEvents();
        onRefresh();
      } finally {
        setIsDeletingMessage(false);
      }
    },
    [
      onRefresh,
      selectedItem?.item.channelId,
      threadContext.refreshStructuralEvents,
    ],
  );
  const contextMessages = useHomeInboxContextMessages({
    channelMessages,
    currentPubkey,
    events: threadContext.events,
    ownerProfiles: feedOwnerProfiles,
    profiles: feedProfiles,
    reactionEvents: threadContext.reactionEvents,
    relaySelfPubkey,
    selectedChannel,
    selectedEventId,
    selectedItem,
    structuralEvents: threadContext.structuralEvents,
  });
  useHomeInboxAutoSelection({
    coldResolutionPending,
    filteredItems,
    hasFeed: Boolean(feed),
    hasPersonalSelection:
      selectedDraftItem !== null || selectedReminder !== null,
    homeInboxWidthPx,
    isLoading,
    isMessagesMode,
    isNarrowHomeViewport,
    selectedConversationId,
    setAutoSelectedEventId,
    urlSelectedItemId,
  });

  React.useEffect(() => {
    void selectedConversationId;
    setEmptyDeleteId(null);
    setEditTargetId(null);
    setIsDeletingMessage(false);
    setIsSendingReply(false);
  }, [selectedConversationId]);

  const handleFilterChange = React.useCallback(
    (nextFilter: InboxFilter) => {
      const nextItems = inboxItems.filter(
        (item) =>
          matchesInboxFilter(item, nextFilter, ownedAgentPubkeys) &&
          (!unreadOnly ||
            !effectiveDoneSet.has(item.id) ||
            item.conversationId === selectedConversationId),
      );
      const selection = resolveInboxFilterSelection({
        isNarrow: isNarrowHomeViewport,
        items: nextItems,
        selectedConversationId,
      });

      setUnreadBoundary(null);
      setSelectedDraftKey(null);
      setSelectedReminderId(null);
      setFilter(nextFilter);

      if (
        nextFilter === "reminders" ||
        nextFilter === "drafts" ||
        selection.preserveSelection
      ) {
        if (nextFilter === "reminders" || nextFilter === "drafts") {
          setAutoSelectedEventId(null);
          applyInboxSearchPatch({ item: null });
        }
        return;
      }

      applyInboxSearchPatch({ item: null });
      setAutoSelectedEventId(selection.autoSelectedEventId);
    },
    [
      applyInboxSearchPatch,
      effectiveDoneSet,
      inboxItems,
      isNarrowHomeViewport,
      ownedAgentPubkeys,
      selectedConversationId,
      setSelectedDraftKey,
      setSelectedReminderId,
      unreadOnly,
    ],
  );

  if (isLoading && !feed) {
    return <HomeLoadingState />;
  }

  if (!feed) {
    return (
      <div className="flex-1 overflow-hidden px-4 pb-3 pt-4 sm:px-6">
        <div className="flex w-full max-w-3xl flex-col gap-4">
          <div className="rounded-md border border-destructive/30 bg-destructive/5 px-4 py-5">
            <p className="text-base font-semibold tracking-tight">
              Home feed unavailable
            </p>
            <p className="mt-2 text-sm text-muted-foreground">
              {errorMessage ?? "The relay did not return a feed response."}
            </p>
            <Button className="mt-5" onClick={onRefresh} type="button">
              <RefreshCcw className="h-4 w-4" />
              Try again
            </Button>
          </div>
        </div>
      </div>
    );
  }

  const detailMode = isDrafts
    ? "drafts"
    : isReminders
      ? "reminders"
      : selectedDraftItem
        ? "drafts"
        : selectedReminder
          ? "reminders"
          : "messages";
  const {
    auxiliaryPaneWidthPx,
    effectiveInboxListWidthPx,
    isSinglePanelDetailView,
    isSinglePanelDraftDetailView,
    isSinglePanelReminderDetailView,
    showDetailPane,
    showListPane,
  } = getHomePaneLayout({
    hasAuxiliaryPane,
    homeWidthPx: homeInboxWidthPx,
    inboxListWidthPx,
    isDrafts: detailMode === "drafts",
    isMessagesMode: detailMode === "messages",
    isNarrow: isNarrowHomeViewport,
    isReminders: detailMode === "reminders",
    isSinglePanelAuxiliaryView,
    selectedDraft: selectedDraftItem !== null,
    selectedEvent: selectedEventId !== null,
    selectedReminder: selectedReminder !== null,
    threadPanelWidthPx,
  });

  return (
    <ProfilePanelProvider onOpenProfilePanel={handleOpenProfilePanel}>
      <DeleteMessageConfirmDialog
        onConfirm={() => {
          if (emptyDeleteId) {
            setEditTargetId(null);
            void deleteInboxMessage(emptyDeleteId);
          }
          setEmptyDeleteId(null);
        }}
        onOpenChange={(open) => {
          if (!open) setEmptyDeleteId(null);
        }}
        open={emptyDeleteId !== null}
      />
      <div className="flex min-h-0 flex-1 flex-col overflow-hidden">
        <div
          className={cn(
            "relative grid min-h-0 w-full flex-1",
            isSinglePanelAuxiliaryView
              ? "grid-cols-1"
              : showListPane && showDetailPane && hasAuxiliaryPane
                ? "grid-cols-[var(--home-inbox-list-width)_minmax(0,1fr)_var(--home-channel-management-width)]"
                : showListPane && showDetailPane
                  ? "grid-cols-[var(--home-inbox-list-width)_minmax(0,1fr)]"
                  : hasAuxiliaryPane
                    ? "grid-cols-[minmax(0,1fr)_var(--home-channel-management-width)]"
                    : "grid-cols-1",
          )}
          data-testid="home-inbox"
          ref={homeInboxRef}
          style={
            {
              "--home-channel-management-width": `${auxiliaryPaneWidthPx}px`,
              "--home-inbox-list-width": `${effectiveInboxListWidthPx}px`,
            } as React.CSSProperties
          }
        >
          {showListPane || showDetailPane ? (
            <div
              aria-hidden="true"
              className="pointer-events-none absolute inset-x-0 top-0 z-30 h-13 bg-background/80 backdrop-blur-md supports-backdrop-filter:bg-background/70 dark:bg-background/70 dark:backdrop-blur-xl dark:supports-backdrop-filter:bg-background/55"
              data-testid="home-inbox-shared-header-backdrop"
            />
          ) : null}

          {showListPane ? (
            <InboxListPane
              activeReminderEventIds={activeReminderEventIds}
              agentPubkeys={inboxAgentPubkeys}
              activeDraftCount={activeDraftCount}
              draftItems={draftItems}
              doneSet={effectiveDoneSet}
              dueReminderCount={dueReminderCount}
              filter={filter}
              items={filteredItems}
              onDeleteDraft={handleDeleteDraft}
              onFilterChange={handleFilterChange}
              onMarkRead={markItemRead}
              onMarkUnread={markItemUnread}
              onOpenDirect={handleOpenDirect}
              isReopenPending={isReopenPending}
              isReopenErrored={isReopenErrored}
              onRemindLater={(item) => {
                const channelId = item.item.channelId;
                if (!channelId) {
                  return;
                }
                openReminder({
                  authorPubkey: item.item.pubkey,
                  channelId,
                  eventId: item.id,
                  preview: item.preview.slice(0, 100),
                });
              }}
              onSelect={(itemId) => {
                const item = findInboxItemByEventId(inboxItems, itemId);
                setUnreadBoundary(
                  item && !effectiveDoneSet.has(item.id)
                    ? {
                        conversationId: item.conversationId,
                        eventId: item.id,
                      }
                    : null,
                );
                setSelectedDraftKey(null);
                setSelectedReminderId(null);
                handleUserSelectItem(itemId);
                markItemRead(itemId);
              }}
              onSelectDraft={(draftKey) => {
                setUnreadBoundary(null);
                setSelectedReminderId(null);
                handleUserSelectItem(null);
                setSelectedDraftKey(draftKey);
              }}
              onSelectReminder={(reminderId) => {
                setUnreadBoundary(null);
                setSelectedDraftKey(null);
                handleUserSelectItem(null);
                setSelectedReminderId(reminderId);
              }}
              onUnreadOnlyChange={setUnreadOnly}
              reminderPubkey={currentPubkey}
              reminders={pendingReminders}
              selectedConversationId={selectedConversationId}
              selectedDraftKey={selectedDraftKey}
              selectedReminderId={selectedReminderId}
              showRightDivider={showListPane && showDetailPane}
              unreadOnly={unreadOnly}
            />
          ) : null}

          <button
            aria-label="Resize inbox list"
            className={cn(
              "group absolute bottom-0 z-40 w-3 -translate-x-1/2 cursor-col-resize",
              topChromeInset.top,
              showListPane && showDetailPane ? "block" : "hidden",
            )}
            data-testid="home-inbox-list-resize-handle"
            onDoubleClick={
              canResetInboxListWidth ? handleInboxListWidthReset : undefined
            }
            onPointerDown={handleInboxListResizeStart}
            style={{ left: `${effectiveInboxListWidthPx}px` }}
            title={
              canResetInboxListWidth
                ? "Drag to resize. Double-click to reset width."
                : "Drag to resize."
            }
            type="button"
          >
            <span className="absolute bottom-0 left-1/2 top-0 w-px -translate-x-1/2 bg-transparent transition-colors group-hover:bg-border/80 group-focus-visible:bg-border/80" />
          </button>

          <HomeMessagesDetail
            activeLatchedItem={activeLatchedItem}
            agentPubkeys={inboxAgentPubkeys}
            availableChannelIds={availableChannelIds}
            canOpenSelected={canOpenSelected}
            channel={selectedChannel}
            channelMessagesRefetch={channelMessagesQuery.refetch}
            currentPubkey={currentPubkey}
            deleteInboxMessage={deleteInboxMessage}
            editTargetId={editTargetId}
            effectiveDoneSet={effectiveDoneSet}
            handleCloseProfilePanel={handleCloseProfilePanel}
            handleOpenSelectedContext={handleOpenSelectedContext}
            hasThreadContextLoadError={threadContext.hasLoadError}
            isDeletingMessage={isDeletingMessage}
            isReopenErrored={isReopenErrored}
            isReopenPending={isReopenPending}
            isSendingReply={isSendingReply}
            isSinglePanelView={isSinglePanelDetailView}
            isThreadContextLoading={threadContext.isLoading}
            localRepliesByItemId={localRepliesByItemId}
            messages={contextMessages}
            onRefresh={onRefresh}
            onSelectNone={() => handleUserSelectItem(null)}
            profiles={feedProfiles}
            recordThreadInteraction={recordThreadInteraction}
            refreshReactions={threadContext.refreshReactions}
            refreshStructuralEvents={threadContext.refreshStructuralEvents}
            selectedEventId={selectedEventId}
            selectedItem={selectedItem}
            setEditTargetId={setEditTargetId}
            setEmptyDeleteId={setEmptyDeleteId}
            setIsSendingReply={setIsSendingReply}
            setLocalRepliesByItemId={setLocalRepliesByItemId}
            setManagedChannelId={setManagedChannelId}
            show={showDetailPane && detailMode === "messages"}
            unreadBoundary={unreadBoundary}
          />
          {showDetailPane && detailMode !== "messages" ? (
            <HomePersonalInboxDetail
              currentPubkey={currentPubkey}
              draftItem={selectedDraftItem}
              mode={detailMode}
              onBack={
                isSinglePanelDraftDetailView
                  ? () => setSelectedDraftKey(null)
                  : isSinglePanelReminderDetailView
                    ? () => setSelectedReminderId(null)
                    : undefined
              }
              onDeleteDraft={handleDeleteDraft}
              reminder={selectedReminder}
            />
          ) : null}
          <HomeInboxAuxiliaryPane
            applyInboxSearchPatch={applyInboxSearchPatch}
            canResetWidth={canResetThreadPanelWidth}
            currentPubkey={currentPubkey}
            isChannelManagementOpen={isChannelManagementOpen}
            isSinglePanelView={isSinglePanelAuxiliaryView}
            managedChannel={managedChannel}
            onCloseProfilePanel={handleCloseProfilePanel}
            onOpenDm={handleOpenDm}
            onOpenProfilePanel={handleOpenProfilePanel}
            onResetWidth={handleThreadPanelWidthReset}
            onResizeStart={handleThreadPanelResizeStart}
            profilePanelPubkey={profilePanelPubkey}
            profilePanelTabSearch={inboxSearchValues.profileTab}
            profilePanelViewSearch={inboxSearchValues.profileView}
            setManagedChannelId={setManagedChannelId}
            setMembersChannel={setMembersChannel}
            widthPx={auxiliaryPaneWidthPx}
          />
        </div>
      </div>
      <HomeMembersSidebarOverlay
        channel={membersChannel}
        currentPubkey={currentPubkey}
        onClose={() => setMembersChannel(null)}
      />
    </ProfilePanelProvider>
  );
}
