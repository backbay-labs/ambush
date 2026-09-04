import * as React from "react";
import { LazySettingsScreen } from "@/app/LazySettingsScreen";
import { useAppNavigation } from "@/app/navigation/useAppNavigation";
import type { useHomeFeedNotifications } from "@/features/notifications/hooks";
import {
  DEFAULT_SETTINGS_SECTION,
  type SettingsSection,
  isSettingsSection,
} from "@/features/settings/ui/SettingsPanels";

type NotificationSettings = ReturnType<
  typeof useHomeFeedNotifications
>["notificationSettings"];

/** The full-window Settings surface the shell swaps in for `/settings`. */
export function AppShellSettingsSurface({
  currentPubkey,
  fallbackDisplayName,
  locationSearch,
  notificationSettings,
  onClose,
}: {
  currentPubkey: string | undefined;
  fallbackDisplayName: string | undefined;
  locationSearch: unknown;
  notificationSettings: NotificationSettings;
  onClose: () => void;
}) {
  const { goSettings } = useAppNavigation();
  const locationSearchSection = (locationSearch as { section?: unknown })
    .section;
  const settingsSection: SettingsSection = isSettingsSection(
    locationSearchSection,
  )
    ? locationSearchSection
    : DEFAULT_SETTINGS_SECTION;
  // Section switches rewrite the settings entry rather than stacking one
  // history entry per section, so back always exits settings in one step.
  const handleSectionChange = React.useCallback(
    (section: SettingsSection) => {
      void goSettings(section, { replace: true });
    },
    [goSettings],
  );

  return (
    <div className="flex min-h-0 flex-1 overflow-hidden">
      <React.Suspense fallback={null}>
        <LazySettingsScreen
          currentPubkey={currentPubkey}
          fallbackDisplayName={fallbackDisplayName}
          isUpdatingDesktopNotifications={
            notificationSettings.isUpdatingDesktopEnabled
          }
          notificationErrorMessage={notificationSettings.errorMessage}
          notificationPermission={notificationSettings.permission}
          notificationSettings={notificationSettings.settings}
          onClose={onClose}
          onSectionChange={handleSectionChange}
          onSetDesktopNotificationsEnabled={
            notificationSettings.setDesktopEnabled
          }
          onSetHomeBadgeEnabled={notificationSettings.setHomeBadgeEnabled}
          onSetSlotAlertsEnabled={notificationSettings.setSlotAlertsEnabled}
          onSetNotifyWhileViewing={notificationSettings.setNotifyWhileViewing}
          onSetAllSlotAlertsEnabled={
            notificationSettings.setAllSlotAlertsEnabled
          }
          onSetSoundForSlot={notificationSettings.setSoundForSlot}
          section={settingsSection}
        />
      </React.Suspense>
    </div>
  );
}
