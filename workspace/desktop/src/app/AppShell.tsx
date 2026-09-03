import * as React from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Outlet, useLocation } from "@tanstack/react-router";
import { deriveShellRoute, markAllReadSources } from "@/app/AppShell.helpers";
import { useTerminalContext } from "@/app/useTerminalContext";
import { AppShellProvider } from "@/app/AppShellContext";
import { AppShellOverlays, TerminalBootstrap } from "@/app/AppShellOverlays";
import { AppShellChannelSurface } from "@/app/AppShellChannelSurface";
import { AppHuddleShell } from "@/app/AppHuddleShell";
import { AppTopChrome } from "@/app/AppTopChrome";
import {
  type TerminalContextOverride,
  TerminalContextOverrideProvider,
} from "@/app/TerminalContextOverrideContext";
import { useAppNavigation } from "@/app/navigation/useAppNavigation";
import { useBackForwardControls } from "@/app/navigation/useBackForwardControls";
import { useCommunityNavigationTransitions } from "@/app/useCommunityNavigationTransitions";
import { useCommunityDestinationRestore } from "@/app/useCommunityDestinationRestore";
import { useChannelCreationHandlers } from "@/app/useChannelCreationHandlers";
import { useLiveHomeFeedActions } from "@/app/useLiveHomeFeedActions";
import { useChannelBrowserDialog } from "@/app/useChannelBrowserDialog";
import { useMarkAsReadShortcuts } from "@/app/useMarkAsReadShortcuts";
import { useSettingsShortcuts } from "@/app/useSettingsShortcuts";
import { useAppShellKeyboardShortcuts } from "@/app/useAppShellKeyboardShortcuts";
import { useAppShellDesktopNotifications } from "@/app/useAppShellDesktopNotifications";
import { useAppShellBackgroundSync } from "@/app/useAppShellBackgroundSync";
import { useAppShellLifecycleEffects } from "@/app/useAppShellLifecycleEffects";
import { useChannelActivityProjection } from "@/app/useChannelActivityProjection";
import { useTauriWindowDrag } from "@/app/useTauriWindowDrag";
import { useWebviewZoomShortcuts } from "@/app/useWebviewZoomShortcuts";
import { useHuddlePresentation } from "@/app/useHuddlePresentation";
import { shouldShowSidebarChannel } from "@/app/huddleChannelVisibility";
import {
  channelsQueryKey,
  useChannelsQuery,
  useHideDmMutation,
  useOpenDmMutation,
} from "@/features/channels/hooks";
import { useDmResurfaceFromMessages } from "@/features/channels/useDmResurfaceFromMessages";
import { useUnreadChannels } from "@/features/channels/useUnreadChannels";
import { useFeedItemState } from "@/features/home/useFeedItemState";
import { useThreadFollows } from "@/features/messages/lib/useThreadFollows";
import {
  useHomeFeedNotifications,
  useHomeFeedNotificationState,
} from "@/features/notifications/hooks";
import { PreventSleepProvider } from "@/features/agents/usePreventSleep";
import { requestOpenCreateAgent } from "@/features/agents/openCreateAgentEvent";
import { AgentManagementDialogs } from "@/features/agents/ui/AgentManagementDialogs";
import { RequestedAgentCreateDialogs } from "@/features/agents/ui/RequestedAgentCreateDialogs";
import { usePresenceSession } from "@/features/presence/hooks";
import {
  useSetUserStatusMutation,
  useUserStatusQuery,
} from "@/features/user-status/hooks";
import { useProfileQuery } from "@/features/profile/hooks";
import { SendFeedbackController } from "@/features/settings/ui/SendFeedbackController";
import {
  DEFAULT_SETTINGS_SECTION,
  type SettingsSection,
  isSettingsSection,
} from "@/features/settings/ui/SettingsPanels";
import { useDueReminderBadgeCount } from "@/features/reminders/hooks";
import { useReminderNotifications } from "@/features/reminders/useReminderNotifications";
import { AppSidebar } from "@/features/sidebar/ui/AppSidebar";
import { requestFocusedThreadClose } from "@/features/channels/focusedThreadCloseRequest";
import { CommunityRail } from "@/features/sidebar/ui/CommunityRail";
import { useChannelMutes } from "@/features/sidebar/lib/useChannelMutes";
import { useChannelStars } from "@/features/sidebar/lib/useChannelStars";
import { useCommunities } from "@/features/communities/useCommunities";
import { useAddCommunityDialogState } from "@/features/communities/addCommunityPrefill";
import { relayClient } from "@/shared/api/relayClient";
import { useIdentityQuery } from "@/shared/api/hooks";
import { useWebviewScrollBoundaryLock } from "@/shared/hooks/useWebviewScrollBoundaryLock";
import { joinChannel } from "@/shared/api/tauri";
import type { Channel, SearchHit } from "@/shared/api/types";
import { ChannelNavigationProvider } from "@/shared/context/ChannelNavigationContext";
import { useAppDeepLinks } from "@/shared/useAppDeepLinks";
import { SidebarProvider } from "@/shared/ui/sidebar";
import { RelayConnectionOverlay } from "@/app/RelayConnectionOverlay";
import { useSidebarRelayConnectionCard } from "@/features/sidebar/ui/useSidebarRelayConnectionCard";
import { AppShellTrayMenu } from "@/app/useAppShellTrayMenu";
import { AppProfilePanelProvider } from "@/app/AppProfilePanelProvider";
import { AppWorkflowEditorOverlayProvider } from "@/app/AppWorkflowEditorOverlayProvider";
import { LazySettingsScreen } from "@/app/LazySettingsScreen";
const EMPTY_CHANNELS: Channel[] = [];
export function AppShell() {
  useWebviewZoomShortcuts();
  useTauriWindowDrag();
  useWebviewScrollBoundaryLock();
  const communitiesHook = useCommunities();
  const {
    handleHuddleCompanionOpen,
    handleHuddleEnded,
    handleHuddleStartPendingChange,
    handleHuddleStarted,
    handleHuddleVisibilityChange,
    handleSidebarChannelSelect,
    huddleBackingChannelIds,
    revealedHuddleChannelIds,
    isHuddleCompanionOpen,
    isHuddleDrawerOpen,
    isHuddleRoom,
    isHuddleRoomStarting,
    showHuddleInMainApp,
    viewHuddleChannel,
  } = useHuddlePresentation();
  const hasCommunityRail = communitiesHook.communities.length > 1;
  const addCommunityDialog = useAddCommunityDialogState();
  const [isChannelManagementOpen, setIsChannelManagementOpen] =
    React.useState(false);
  const [managedChannelId, setManagedChannelId] = React.useState<string | null>(
    null,
  );
  const [searchFocusRequest, setSearchFocusRequest] = React.useState(0);
  const [scopeSearchFocusRequest, setScopeSearchFocusRequest] =
    React.useState(0);
  const [isCreateChannelOpen, setIsCreateChannelOpen] = React.useState(false);
  const [isSendFeedbackOpen, setIsSendFeedbackOpen] = React.useState(false);
  const mainInsetRef = React.useRef<HTMLElement>(null);
  const location = useLocation();
  const queryClient = useQueryClient();
  const {
    goAgents,
    goChannel,
    goHome,
    goNewMessage,
    goProjects,
    goPulse,
    goSettings,
    goWorkflows,
    closeSettings,
    openSearchHit,
  } = useAppNavigation();
  const { canGoBack, canGoForward, goBack, goForward } =
    useBackForwardControls();
  const { selectedChannelId, selectedView } = React.useMemo(
    () => deriveShellRoute(location.pathname),
    [location.pathname],
  );
  const {
    removeCommunity: handleRemoveCommunity,
    switchCommunity: handleSwitchCommunity,
  } = useCommunityNavigationTransitions({
    communities: communitiesHook,
    goHome,
    selectedChannelId,
    selectedView,
  });
  // Settings lives in history so back returns to the previous app entry.
  const settingsOpen = location.pathname === "/settings";
  const locationSearchSection = (location.search as { section?: unknown })
    .section;
  const settingsSection: SettingsSection = isSettingsSection(
    locationSearchSection,
  )
    ? locationSearchSection
    : DEFAULT_SETTINGS_SECTION;
  const identityQuery = useIdentityQuery();
  const { mutedChannelIds, muteChannel, unmuteChannel } = useChannelMutes(
    identityQuery.data?.pubkey,
    communitiesHook.activeCommunity?.relayUrl,
  );
  const { starredChannelIds, starChannel, unstarChannel } = useChannelStars(
    identityQuery.data?.pubkey,
    communitiesHook.activeCommunity?.relayUrl,
  );
  const { deferredPubkey } = useAppShellBackgroundSync({
    communities: communitiesHook.communities,
    pubkey: identityQuery.data?.pubkey,
    relayUrl: communitiesHook.activeCommunity?.relayUrl,
  });
  const profileQuery = useProfileQuery();
  const presenceSession = usePresenceSession(deferredPubkey);
  const selfStatusQuery = useUserStatusQuery(
    deferredPubkey ? [deferredPubkey] : [],
  );
  const setUserStatusMutation = useSetUserStatusMutation(deferredPubkey);
  const { feedProfilesQuery, homeFeedQuery, notificationSettings } =
    useHomeFeedNotifications(identityQuery.data?.pubkey);
  const feedItemState = useFeedItemState(identityQuery.data?.pubkey);
  const channelsQuery = useChannelsQuery();
  const channels = channelsQuery.data ?? [];
  useReminderNotifications(
    identityQuery.data?.pubkey,
    notificationSettings.settings,
    channels,
  );
  const refetchHomeFeedFromLiveSignal = React.useEffectEvent(() => {
    void homeFeedQuery.refetch();
  });
  useLiveHomeFeedActions(
    identityQuery.data?.pubkey,
    refetchHomeFeedFromLiveSignal,
  );
  const { refetch: refetchChannels } = channelsQuery;
  const channelsErrorMessage =
    channelsQuery.error instanceof Error
      ? channelsQuery.error.message
      : undefined;
  const relayConnectionCard = useSidebarRelayConnectionCard(
    channelsErrorMessage,
    communitiesHook.activeCommunity?.relayUrl,
    `${communitiesHook.activeCommunity?.id ?? "none"}-${communitiesHook.reinitKey}`,
  );
  const memberChannels = React.useMemo(
    () => channels.filter((channel) => channel.isMember),
    [channels],
  );
  const sidebarChannels = React.useMemo(
    () =>
      memberChannels.filter(
        (channel) =>
          channel.archivedAt === null &&
          shouldShowSidebarChannel(
            channel,
            huddleBackingChannelIds,
            revealedHuddleChannelIds,
          ),
      ),
    [huddleBackingChannelIds, memberChannels, revealedHuddleChannelIds],
  );
  useCommunityDestinationRestore({
    activeCommunityId: communitiesHook.activeCommunity?.id,
    channelsQuery,
    goChannel,
    goHome,
    selectedView,
    sidebarChannels,
  });
  const [terminalContextOverride, setTerminalContextOverride] =
    React.useState<TerminalContextOverride | null>(null);
  const { activeChannel, terminalContext } = useTerminalContext({
    channelId: selectedChannelId,
    channels,
    locationSearch: location.search,
    pubkey: identityQuery.data?.pubkey,
    relayUrl: communitiesHook.activeCommunity?.relayUrl,
  });
  const effectiveTerminalContext = terminalContextOverride
    ? {
        ...terminalContext,
        channelId: terminalContextOverride.channelId,
        channelName: terminalContextOverride.channelName,
        threadId: null,
      }
    : terminalContext;
  const managedChannel = React.useMemo(() => {
    const targetChannelId = managedChannelId ?? selectedChannelId;
    return targetChannelId
      ? (channels.find((channel) => channel.id === targetChannelId) ?? null)
      : null;
  }, [channels, managedChannelId, selectedChannelId]);
  const {
    handleChannelNotification,
    handleDmNotification,
    handleThreadReplyDesktopNotification,
  } = useAppShellDesktopNotifications({
    channels,
    enabled: !isHuddleRoom,
    goChannel,
    goHome,
    notificationSettings: notificationSettings.settings,
    openSearchHit,
    pubkey: identityQuery.data?.pubkey,
    silentChannelIds: huddleBackingChannelIds,
  });
  const {
    followedRootIds,
    isFollowing: isFollowingThread,
    followThread,
    unfollowThread,
  } = useThreadFollows(identityQuery.data?.pubkey);
  const {
    markAllChannelsRead: markAllChannelReadMarkers,
    markChannelRead,
    markChannelUnread,
    clearChannelUnreadSource,
    unreadChannelIds,
    topLevelUnreadChannelIds,
    unreadChannelCounts,
    highPriorityUnreadChannelIds,
    unreadChannelNotificationCount,
    getEffectiveTimestamp: getChannelReadAt,
    getOwnTimestamp: getOwnReadAt,
    readStateVersion,
    setContextParentResolver,
    participatedRootIds,
    authoredRootIds,
    mentionedRootIds,
    recordThreadInteraction,
    threadActivityItems,
    mutedRootIds,
    muteThread,
    unmuteThread,
  } = useUnreadChannels(
    isHuddleRoom ? EMPTY_CHANNELS : sidebarChannels,
    isHuddleRoom ? null : activeChannel,
    {
      pubkey: identityQuery.data?.pubkey,
      relayClient,
      relayUrl: communitiesHook.activeCommunity?.relayUrl,
      currentPubkey: identityQuery.data?.pubkey,
      mutedChannelIds,
      notifyForActiveChannel: notificationSettings.settings.notifyWhileViewing,
      onChannelMessage: handleChannelNotification,
      onDmMessage: handleDmNotification,
      onLiveMention: refetchHomeFeedFromLiveSignal,
      onThreadReplyDesktopNotification: handleThreadReplyDesktopNotification,
      followedRootIds,
    },
  );

  const {
    getThreadReadAt,
    markThreadRead,
    getMessageReadAt,
    getChannelActivityItemReadAt,
    markMessageRead,
    threadActivityFeedItems,
    locallyUnreadFeedItems,
    unreadThreadFeedItems,
    unreadThreadChannelIds,
  } = useChannelActivityProjection({
    channels,
    feed: homeFeedQuery.data?.feed,
    unreadFeedItemIds: feedItemState.unreadSet,
    getChannelReadAt,
    getOwnReadAt,
    markChannelRead,
    readStateVersion,
    threadActivityItems,
    mutedRootIds,
  });
  const markAllChannelsRead = React.useCallback(() => {
    markAllReadSources({
      activeChannelId: activeChannel?.id ?? null,
      channelActivityItems: unreadThreadFeedItems,
      markAllChannelReadMarkers,
      markActiveChannelRead: (channelId, createdAt) =>
        markChannelRead(channelId, new Date(createdAt * 1_000).toISOString()),
      undoUnreadFeedItem: feedItemState.undoUnread,
      unreadFeedItemIds: feedItemState.unreadSet,
    });
  }, [
    activeChannel?.id,
    feedItemState.undoUnread,
    feedItemState.unreadSet,
    markAllChannelReadMarkers,
    markChannelRead,
    unreadThreadFeedItems,
  ]);

  const { homeBadgeCount, homeBadgeCountExcludingHighPriority } =
    useHomeFeedNotificationState(
      homeFeedQuery.data,
      identityQuery.data?.pubkey,
      notificationSettings.settings,
      notificationSettings.setDesktopEnabled,
      !isHuddleRoom,
      selectedView === "home" && !settingsOpen,
      getChannelReadAt,
      readStateVersion,
      highPriorityUnreadChannelIds,
      feedProfilesQuery.data?.profiles,
      mutedChannelIds,
      feedItemState.unreadSet,
      threadActivityFeedItems,
      getThreadReadAt,
      getMessageReadAt,
      channels,
      huddleBackingChannelIds,
    );
  const dueReminderBadge = useDueReminderBadgeCount(
    identityQuery.data?.pubkey,
    notificationSettings.settings.homeBadgeEnabled,
  );
  const isNotifiedForThread = React.useCallback(
    (rootId: string) =>
      !mutedRootIds.has(rootId) &&
      (followedRootIds.has(rootId) ||
        participatedRootIds.has(rootId) ||
        authoredRootIds.has(rootId) ||
        mentionedRootIds.has(rootId)),
    [
      followedRootIds,
      mutedRootIds,
      participatedRootIds,
      authoredRootIds,
      mentionedRootIds,
    ],
  );

  const handleFollowThread = React.useCallback(
    (rootId: string) => {
      followThread(rootId);
      unmuteThread(rootId);
    },
    [followThread, unmuteThread],
  );

  const handleUnfollowThread = React.useCallback(
    (rootId: string) => {
      unfollowThread(rootId);
      muteThread(rootId);
    },
    [unfollowThread, muteThread],
  );

  const openDmMutation = useOpenDmMutation();
  const hideDmMutation = useHideDmMutation();
  useDmResurfaceFromMessages({
    pubkey: identityQuery.data?.pubkey,
    relayUrl: communitiesHook.activeCommunity?.relayUrl,
    reopen: openDmMutation.mutateAsync,
  });
  const {
    browseDialogType,
    openBrowseChannels: handleOpenBrowseChannels,
    onBrowseDialogOpenChange: handleBrowseDialogOpenChange,
    getCreateSuccess,
  } = useChannelBrowserDialog(() => void refetchChannels());
  const handleOpenSearch = React.useCallback(() => {
    setSearchFocusRequest((request) => request + 1);
    void refetchChannels();
  }, [refetchChannels]);
  const handleOpenChannelSearch = React.useCallback(() => {
    setScopeSearchFocusRequest((request) => request + 1);
    void refetchChannels();
  }, [refetchChannels]);

  const handleBrowseChannelJoin = React.useCallback(
    async (channelId: string) => {
      await joinChannel(channelId);
      await queryClient.invalidateQueries({ queryKey: channelsQueryKey });
    },
    [queryClient],
  );

  const {
    handleBrowseChannelCreate,
    handleCreateChannel,
    handleCreateForum,
    isCreatingChannel,
    isCreatingForum,
  } = useChannelCreationHandlers({
    browseDialogType,
    getCreateSuccess,
    goChannel,
  });

  const handleHideDm = React.useCallback(
    async (channelId: string) => {
      try {
        await hideDmMutation.mutateAsync(channelId);
      } catch {
        return;
      }

      if (selectedChannelId === channelId) {
        void goHome();
      }
    },
    [goHome, hideDmMutation, selectedChannelId],
  );
  const handleOpenSettings = React.useCallback(
    (section: SettingsSection = DEFAULT_SETTINGS_SECTION) => {
      setIsChannelManagementOpen(false);
      void goSettings(section);
    },
    [goSettings],
  );
  const handleCloseSettings = React.useCallback(
    () => closeSettings(),
    [closeSettings],
  );
  // Section switches rewrite the settings entry rather than stacking one
  // history entry per section, so back always exits settings in one step.
  const handleSettingsSectionChange = React.useCallback(
    (section: SettingsSection) => {
      void goSettings(section, { replace: true });
    },
    [goSettings],
  );

  const handleOpenSearchResult = React.useCallback(
    (hit: SearchHit, query: string) => {
      void openSearchHit(hit, { query });
    },
    [openSearchHit],
  );
  useAppShellLifecycleEffects({
    desktopBadgeEnabled: !isHuddleRoom,
    homeBadgeCountExcludingHighPriority,
    topLevelUnreadChannelIds,
    unreadChannelNotificationCount,
  });
  // Dispatch `ambush://` deep links only from the main window; the companion is dedicated to its active Huddle route.
  useAppDeepLinks(!isHuddleRoom);
  const handleOpenCreateChannel = React.useCallback(
    () => setIsCreateChannelOpen(true),
    [],
  );
  useAppShellKeyboardShortcuts({
    activeChannelId: selectedView === "channel" ? selectedChannelId : null,
    canSearchCurrentChannel:
      selectedView === "channel" && Boolean(activeChannel),
    disabled: settingsOpen || isHuddleRoom,
    onBrowseChannels: handleOpenBrowseChannels,
    onCreateChannel: handleOpenCreateChannel,
    onGoHome: goHome,
    onNewMessage: goNewMessage,
    onSearchCurrentChannel: handleOpenChannelSearch,
    onSearchEverything: handleOpenSearch,
  });
  useSettingsShortcuts({
    onClose: handleCloseSettings,
    onOpenSettings: handleOpenSettings,
    open: isHuddleRoom ? undefined : settingsOpen,
  });
  useMarkAsReadShortcuts({
    activeChannelId: activeChannel?.id ?? null,
    activeChannelLastMessageAt: activeChannel?.lastMessageAt,
    markAllChannelsRead,
    markChannelRead,
    selectedView,
  });
  return (
    <PreventSleepProvider>
      {!isHuddleRoom ? (
        <AppShellTrayMenu
          channels={channels}
          goChannel={goChannel}
          openCreateChannel={handleOpenCreateChannel}
        />
      ) : null}
      <ChannelNavigationProvider channels={channels}>
        <AppShellProvider
          value={{
            markAllChannelsRead,
            markChannelRead,
            markChannelUnread,
            clearChannelUnreadSource,
            openBrowseChannels: handleOpenBrowseChannels,
            openCreateChannel: handleOpenCreateChannel,
            openChannelManagement: (channelId?: string) => {
              setManagedChannelId(
                typeof channelId === "string" ? channelId : null,
              );
              setIsChannelManagementOpen(true);
            },
            getChannelReadAt,
            getThreadReadAt,
            markThreadRead,
            getMessageReadAt,
            getChannelActivityItemReadAt,
            markMessageRead,
            readStateVersion,
            setContextParentResolver,
            followThread: handleFollowThread,
            unfollowThread: handleUnfollowThread,
            isFollowingThread,
            isNotifiedForThread,
            recordThreadInteraction,
            isThreadMuted: (rootId) => mutedRootIds.has(rootId),
            threadActivityItems,
            threadActivityFeedItems,
            locallyUnreadFeedItems,
            unreadThreadFeedItems,
            unreadThreadChannelIds,
            topLevelUnreadChannelIds,
            hasSidebarUnreadProjections: true,
            feedItemState,
            onOpenSettings: handleOpenSettings,
          }}
        >
          <AppHuddleShell
            currentPubkey={identityQuery.data?.pubkey}
            isCompanionOpen={isHuddleCompanionOpen}
            isDrawerOpen={isHuddleDrawerOpen}
            isRoom={isHuddleRoom}
            onCompanionOpen={handleHuddleCompanionOpen}
            onHuddleStartPendingChange={handleHuddleStartPendingChange}
            onHuddleStarted={handleHuddleStarted}
            onShowHuddleInMainApp={showHuddleInMainApp}
            onViewHuddleChannel={viewHuddleChannel}
            onVisibilityChange={handleHuddleVisibilityChange}
          >
            {hasCommunityRail && !isHuddleRoom ? (
              <CommunityRail
                activeCommunityId={communitiesHook.activeCommunity?.id ?? null}
                onAddCommunity={addCommunityDialog.openDialog}
                onReorderCommunities={communitiesHook.reorderCommunities}
                onSwitchCommunity={handleSwitchCommunity}
                onUpdateCommunity={communitiesHook.updateCommunity}
                communities={communitiesHook.communities}
              />
            ) : null}
            <SidebarProvider
              className="relative z-10 min-h-0 min-w-0 flex-1 flex-col overflow-visible"
              data-testid="app-sidebar-layer"
            >
              <AppProfilePanelProvider>
                <AppWorkflowEditorOverlayProvider>
                  {!settingsOpen && !isHuddleRoom ? (
                    <AppTopChrome
                      canGoBack={canGoBack}
                      canGoForward={canGoForward}
                      hasCommunityRail={hasCommunityRail}
                      onGoBack={goBack}
                      onGoForward={goForward}
                    />
                  ) : null}
                  {settingsOpen ? (
                    <div className="flex min-h-0 flex-1 overflow-hidden">
                      <React.Suspense fallback={null}>
                        <LazySettingsScreen
                          currentPubkey={identityQuery.data?.pubkey}
                          fallbackDisplayName={identityQuery.data?.displayName}
                          isUpdatingDesktopNotifications={
                            notificationSettings.isUpdatingDesktopEnabled
                          }
                          notificationErrorMessage={
                            notificationSettings.errorMessage
                          }
                          notificationPermission={
                            notificationSettings.permission
                          }
                          notificationSettings={notificationSettings.settings}
                          onClose={handleCloseSettings}
                          onSectionChange={handleSettingsSectionChange}
                          onSetDesktopNotificationsEnabled={
                            notificationSettings.setDesktopEnabled
                          }
                          onSetHomeBadgeEnabled={
                            notificationSettings.setHomeBadgeEnabled
                          }
                          onSetSlotAlertsEnabled={
                            notificationSettings.setSlotAlertsEnabled
                          }
                          onSetNotifyWhileViewing={
                            notificationSettings.setNotifyWhileViewing
                          }
                          onSetAllSlotAlertsEnabled={
                            notificationSettings.setAllSlotAlertsEnabled
                          }
                          onSetSoundForSlot={
                            notificationSettings.setSoundForSlot
                          }
                          section={settingsSection}
                        />
                      </React.Suspense>
                    </div>
                  ) : (
                    <div className="relative flex min-h-0 flex-1 overflow-visible">
                      {!isHuddleRoom ? (
                        <AppSidebar
                          activeCommunity={communitiesHook.activeCommunity}
                          channels={sidebarChannels}
                          currentPubkey={identityQuery.data?.pubkey}
                          errorMessage={channelsErrorMessage}
                          fallbackDisplayName={identityQuery.data?.displayName}
                          homeBadgeCount={homeBadgeCount + dueReminderBadge}
                          addCommunityPrefill={addCommunityDialog.prefill}
                          isAddCommunityOpen={addCommunityDialog.open}
                          relayConnectionCard={relayConnectionCard}
                          isCreatingChannel={isCreatingChannel}
                          isCreatingForum={isCreatingForum}
                          isLoading={channelsQuery.isLoading}
                          isCreateChannelOpen={isCreateChannelOpen}
                          isHuddleCompanionOpen={isHuddleCompanionOpen}
                          isPresencePending={presenceSession.isPending}
                          onAddCommunity={(community) => {
                            const id = communitiesHook.addCommunity({
                              ...community,
                              pubkey:
                                community.pubkey ?? identityQuery.data?.pubkey,
                            });
                            handleSwitchCommunity(id);
                          }}
                          onAddCommunityOpenChange={
                            addCommunityDialog.onOpenChange
                          }
                          onNewMessage={goNewMessage}
                          onBackgroundClick={requestFocusedThreadClose}
                          onCreateChannelOpenChange={setIsCreateChannelOpen}
                          onOpenAddCommunity={addCommunityDialog.openDialog}
                          onSendFeedback={() => setIsSendFeedbackOpen(true)}
                          onUpdateCommunity={communitiesHook.updateCommunity}
                          onRemoveCommunity={handleRemoveCommunity}
                          onSwitchCommunity={handleSwitchCommunity}
                          onCreateAgent={() => requestOpenCreateAgent()}
                          selfPresenceStatus={presenceSession.currentStatus}
                          communities={communitiesHook.communities}
                          onCreateChannel={handleCreateChannel}
                          onCreateForum={handleCreateForum}
                          onHideDm={handleHideDm}
                          onHuddleEnded={handleHuddleEnded}
                          onMarkAllChannelsRead={markAllChannelsRead}
                          onMarkChannelRead={markChannelRead}
                          onMarkChannelUnread={markChannelUnread}
                          onBrowseChannels={handleOpenBrowseChannels}
                          onOpenDm={async ({ pubkeys }) => {
                            const directMessage =
                              await openDmMutation.mutateAsync({
                                pubkeys,
                              });
                            await goChannel(directMessage.id);
                          }}
                          onSelectAgents={() => void goAgents()}
                          onSelectChannel={handleSidebarChannelSelect}
                          onOpenSearchResult={handleOpenSearchResult}
                          searchChannels={channels}
                          searchFocusRequests={[
                            searchFocusRequest,
                            scopeSearchFocusRequest,
                          ]}
                          onSelectHome={() => void goHome()}
                          onSelectProjects={() => void goProjects()}
                          onSelectPulse={() => void goPulse()}
                          onSelectSettings={handleOpenSettings}
                          onSelectWorkflows={() => void goWorkflows()}
                          onSetPresenceStatus={(status) =>
                            presenceSession.setStatus(status)
                          }
                          onSetUserStatus={(text, emoji) =>
                            setUserStatusMutation.mutate({ text, emoji })
                          }
                          onClearUserStatus={() =>
                            setUserStatusMutation.mutate({
                              text: "",
                              emoji: "",
                            })
                          }
                          profile={profileQuery.data}
                          projectsOverviewActive={
                            location.pathname === "/projects"
                          }
                          selfUserStatus={
                            deferredPubkey
                              ? (selfStatusQuery.data?.[
                                  deferredPubkey.toLowerCase()
                                ] ?? undefined)
                              : undefined
                          }
                          selectedChannelId={selectedChannelId}
                          selectedView={selectedView}
                          unreadChannelIds={unreadChannelIds}
                          previewActivityChannelIds={unreadThreadChannelIds}
                          unreadChannelCounts={unreadChannelCounts}
                          mutedChannelIds={mutedChannelIds}
                          onMuteChannel={muteChannel}
                          onUnmuteChannel={unmuteChannel}
                          starredChannelIds={starredChannelIds}
                          onStarChannel={starChannel}
                          onUnstarChannel={unstarChannel}
                        />
                      ) : null}
                      <TerminalContextOverrideProvider
                        onChange={setTerminalContextOverride}
                      >
                        <AppShellChannelSurface
                          hasCommunityRail={hasCommunityRail}
                          isHuddleRoom={isHuddleRoom}
                          isHuddleRoomStarting={isHuddleRoomStarting}
                          mainInsetRef={mainInsetRef}
                          terminal={
                            <TerminalBootstrap {...effectiveTerminalContext} />
                          }
                        >
                          <Outlet />
                        </AppShellChannelSurface>
                      </TerminalContextOverrideProvider>
                      {!isHuddleRoom ? (
                        <RelayConnectionOverlay
                          card={relayConnectionCard}
                          errorMessage={channelsErrorMessage}
                          hasCommunityRail={hasCommunityRail}
                          isHuddleDrawerOpen={isHuddleDrawerOpen}
                        />
                      ) : null}
                    </div>
                  )}
                  <RequestedAgentCreateDialogs />
                  <AgentManagementDialogs />
                  <AppShellOverlays
                    activeChannel={managedChannel}
                    browseDialogType={browseDialogType}
                    channels={channels}
                    currentPubkey={identityQuery.data?.pubkey}
                    isChannelManagementOpen={isChannelManagementOpen}
                    isCreatingBrowseChannel={
                      isCreatingChannel || isCreatingForum
                    }
                    onBrowseChannelJoin={handleBrowseChannelJoin}
                    onBrowseChannelCreate={handleBrowseChannelCreate}
                    onBrowseDialogOpenChange={handleBrowseDialogOpenChange}
                    onChannelManagementOpenChange={(open) => {
                      setIsChannelManagementOpen(open);
                      if (!open) {
                        setManagedChannelId(null);
                      }
                    }}
                    onDeleteActiveChannel={() => {
                      setIsChannelManagementOpen(false);
                      setManagedChannelId(null);
                      void goHome({ replace: true });
                    }}
                    onSelectChannel={(channelId) => {
                      void goChannel(channelId);
                    }}
                    relayUrl={communitiesHook.activeCommunity?.relayUrl}
                  />
                  <SendFeedbackController
                    onOpenChange={setIsSendFeedbackOpen}
                    open={isSendFeedbackOpen}
                  />
                </AppWorkflowEditorOverlayProvider>
              </AppProfilePanelProvider>
            </SidebarProvider>
          </AppHuddleShell>
        </AppShellProvider>
      </ChannelNavigationProvider>
    </PreventSleepProvider>
  );
}
