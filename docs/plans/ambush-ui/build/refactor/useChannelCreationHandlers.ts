// PROPOSED — lands at BUZZ desktop/src/app/useChannelCreationHandlers.ts
//
// Commit AS-3 of 15-FILE-SPLIT-PLAN.md. Pure extraction: AppShell.tsx:504-506
// and :537-620 at eed74bde2, verbatim, comments included. The two `isPending`
// booleans the shell's JSX read (AppShell.tsx:837,:838,:963,:964) are returned
// by name rather than as the mutation objects, so no React Query result object
// crosses the boundary — `CLAUDE.md` gotcha 6.

import * as React from "react";
import { useCreateChannelMutation } from "@/features/channels/hooks";
import { useApplyTemplate } from "@/features/channel-templates/useApplyTemplate";
import type { BrowseDialogType } from "@/app/AppShellOverlays";
import type { ChannelVisibility } from "@/shared/api/types";

/** Stream/forum creation, template application and the browse-dialog fan-out. */
export function useChannelCreationHandlers({
  browseDialogType,
  getCreateSuccess,
  goChannel,
}: {
  browseDialogType: BrowseDialogType;
  getCreateSuccess: () => ((channelId: string) => void) | null;
  goChannel: (channelId: string) => Promise<unknown>;
}) {
  const createChannelMutation = useCreateChannelMutation(),
    createForumMutation = useCreateChannelMutation();
  const { applyCanvas, applyAgents } = useApplyTemplate();
  const handleCreateChannel = React.useCallback(
    async (
      {
        description,
        name,
        visibility,
        ttlSeconds,
        templateId,
      }: {
        name: string;
        description?: string;
        visibility: ChannelVisibility;
        ttlSeconds?: number;
        templateId?: string;
      },
      onCreated?: (channelId: string) => void,
    ) => {
      const createdChannel = await createChannelMutation.mutateAsync({
        name,
        description,
        channelType: "stream",
        visibility,
        ttlSeconds,
      });

      await applyCanvas(templateId, createdChannel.id, name);
      await goChannel(createdChannel.id);
      onCreated?.(createdChannel.id);
      void applyAgents(templateId, createdChannel.id);
    },
    [applyAgents, applyCanvas, createChannelMutation, goChannel],
  );
  const handleCreateForum = React.useCallback(
    async ({
      description,
      name,
      visibility,
      ttlSeconds,
      templateId,
    }: {
      name: string;
      description?: string;
      visibility: ChannelVisibility;
      ttlSeconds?: number;
      templateId?: string;
    }) => {
      const createdForum = await createForumMutation.mutateAsync({
        name,
        description,
        channelType: "forum",
        visibility,
        ttlSeconds,
      });

      await applyCanvas(templateId, createdForum.id, name);
      await goChannel(createdForum.id);
      void applyAgents(templateId, createdForum.id);
    },
    [applyAgents, applyCanvas, createForumMutation, goChannel],
  );

  // The channel browser can create either a stream or a forum depending on
  // which section opened it. Route to the matching handler.
  const handleBrowseChannelCreate = React.useCallback(
    async (input: {
      name: string;
      description?: string;
      visibility: ChannelVisibility;
      ttlSeconds?: number;
      templateId?: string;
    }) => {
      if (browseDialogType === "forum") {
        await handleCreateForum(input);
      } else {
        await handleCreateChannel(input, getCreateSuccess() ?? undefined);
      }
    },
    [
      browseDialogType,
      handleCreateChannel,
      handleCreateForum,
      getCreateSuccess,
    ],
  );

  return {
    handleBrowseChannelCreate,
    handleCreateChannel,
    handleCreateForum,
    isCreatingChannel: createChannelMutation.isPending,
    isCreatingForum: createForumMutation.isPending,
  };
}
