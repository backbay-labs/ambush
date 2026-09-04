import * as React from "react";

import { ChannelManagementSheet } from "@/features/channels/ui/ChannelManagementSheet";
import { RightAuxiliaryPane } from "@/features/channels/ui/RightAuxiliaryPane";
import {
  type ProfilePanelTab,
  type ProfilePanelView,
  UserProfilePanel,
} from "@/features/profile/ui/UserProfilePanel";
import {
  profilePanelTabFromSearch,
  profilePanelViewFromSearch,
} from "@/features/profile/ui/UserProfilePanelUtils";
import type { HistorySearchSetterOptions } from "@/shared/hooks/useHistorySearchState";
import type { Channel } from "@/shared/api/types";

type ApplyProfileSearchPatch = (
  patch: Partial<
    Record<"profile" | "profileTab" | "profileView", string | null>
  >,
  options?: HistorySearchSetterOptions,
) => void;

type HomeInboxAuxiliaryPaneProps = {
  applyInboxSearchPatch: ApplyProfileSearchPatch;
  canResetWidth: boolean;
  currentPubkey: string | undefined;
  isChannelManagementOpen: boolean;
  isSinglePanelView: boolean;
  managedChannel: Channel | null;
  onCloseProfilePanel: () => void;
  onOpenDm: (pubkeys: string[]) => Promise<void>;
  onOpenProfilePanel: (pubkey: string) => void;
  profilePanelPubkey: string | null;
  profilePanelTabSearch: string | null;
  profilePanelViewSearch: string | null;
  setManagedChannelId: React.Dispatch<React.SetStateAction<string | null>>;
  setMembersChannel: React.Dispatch<React.SetStateAction<Channel | null>>;
  widthPx: number;
  onResetWidth: () => void;
  onResizeStart: (event: React.PointerEvent<HTMLButtonElement>) => void;
};

/** Renders the profile or channel-management pane beside the Home inbox. */
export function HomeInboxAuxiliaryPane({
  applyInboxSearchPatch,
  canResetWidth,
  currentPubkey,
  isChannelManagementOpen,
  isSinglePanelView,
  managedChannel,
  onCloseProfilePanel,
  onOpenDm,
  onOpenProfilePanel,
  onResetWidth,
  onResizeStart,
  profilePanelPubkey,
  profilePanelTabSearch,
  profilePanelViewSearch,
  setManagedChannelId,
  setMembersChannel,
  widthPx,
}: HomeInboxAuxiliaryPaneProps) {
  const profilePanelTab = profilePanelTabFromSearch(profilePanelTabSearch);
  const profilePanelView = profilePanelViewFromSearch(profilePanelViewSearch);
  const handleProfilePanelViewChange = React.useCallback(
    (view: ProfilePanelView, options?: { replace?: boolean }) =>
      applyInboxSearchPatch(
        { profileView: view === "summary" ? null : view },
        options,
      ),
    [applyInboxSearchPatch],
  );
  const handleProfilePanelTabChange = React.useCallback(
    (tab: ProfilePanelTab, options?: { replace?: boolean }) =>
      applyInboxSearchPatch(
        { profileTab: tab === "info" ? null : tab },
        options,
      ),
    [applyInboxSearchPatch],
  );

  if (profilePanelPubkey) {
    return (
      <RightAuxiliaryPane
        canResetWidth={canResetWidth}
        constrainToAvailableSpace={false}
        onResetWidth={onResetWidth}
        onResizeStart={onResizeStart}
        testId="home-user-profile-panel"
        widthPx={widthPx}
      >
        <UserProfilePanel
          currentPubkey={currentPubkey}
          isSinglePanelView={isSinglePanelView}
          layout="split"
          onClose={onCloseProfilePanel}
          onOpenDm={onOpenDm}
          onOpenProfile={onOpenProfilePanel}
          onTabChange={handleProfilePanelTabChange}
          onViewChange={handleProfilePanelViewChange}
          pubkey={profilePanelPubkey}
          splitPaneClamp
          tab={profilePanelTab}
          transparentChrome
          view={profilePanelView}
          widthPx={widthPx}
        />
      </RightAuxiliaryPane>
    );
  }

  if (!isChannelManagementOpen || !managedChannel) return null;

  return (
    <RightAuxiliaryPane
      canResetWidth={canResetWidth}
      constrainToAvailableSpace={false}
      onResetWidth={onResetWidth}
      onResizeStart={onResizeStart}
      testId="home-channel-management-auxiliary-pane"
      widthPx={widthPx}
    >
      <ChannelManagementSheet
        channel={managedChannel}
        currentPubkey={currentPubkey}
        layout="split"
        onOpenMembers={() => setMembersChannel(managedChannel)}
        onOpenChange={(nextOpen) => {
          if (!nextOpen) {
            setManagedChannelId(null);
          }
        }}
        open={true}
      />
    </RightAuxiliaryPane>
  );
}
