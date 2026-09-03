// PROPOSED — lands at BUZZ desktop/src/app/AppShellSettingsSurface.tsx
//
// Commit AS-4 of 15-FILE-SPLIT-PLAN.md. Pure extraction: AppShell.tsx:174-180
// (the section derivation), :647-654 (the section-change callback and its
// comment) and :785-823 (the JSX) at eed74bde2, verbatim.
//
// This is also the file Perch Phase 0 edits when Settings stops being a
// shell-level takeover and starts rendering through the router outlet
// (APPENDIX-NORMATIVE.md §1 route table, `/settings`, Phase 0). Today
// AppShell.tsx:173 and :784-823 unmount the outlet for `/settings`, which is
// why routes/settings.tsx:33-35 returns null. Moving that surface into the
// outlet after this commit is one file, not a shell rewrite. The extraction
// itself changes nothing about where it renders.

import * as React from "react";
import { useAppNavigation } from "@/app/navigation/useAppNavigation";
import { LazySettingsScreen } from "@/app/LazySettingsScreen";
import {
  DEFAULT_SETTINGS_SECTION,
  type SettingsSection,
  isSettingsSection,
} from "@/features/settings/ui/SettingsPanels";
import type { useHomeFeedNotifications } from "@/features/notifications/hooks";

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
                          notificationErrorMessage={
                            notificationSettings.errorMessage
                          }
                          notificationPermission={
                            notificationSettings.permission
                          }
                          notificationSettings={notificationSettings.settings}
                          onClose={onClose}
                          onSectionChange={handleSectionChange}
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
  );
}
