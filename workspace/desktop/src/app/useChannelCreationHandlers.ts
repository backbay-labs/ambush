import * as React from "react";
import type { BrowseDialogType } from "@/app/AppShellOverlays";
import { useApplyTemplate } from "@/features/channel-templates/useApplyTemplate";
import { useCreateChannelMutation } from "@/features/channels/hooks";
import type { ChannelVisibility } from "@/shared/api/types";

type ChannelCreationInput = {
  name: string;
  description?: string;
  visibility: ChannelVisibility;
  ttlSeconds?: number;
  templateId?: string;
};

type CreateChannelHandler = (
  input: ChannelCreationInput,
  onCreated?: (channelId: string) => void,
) => Promise<unknown>;

type CreateForumHandler = (input: ChannelCreationInput) => Promise<unknown>;

/** Routes a browser create request to its stream or forum handler. */
export async function routeBrowseChannelCreate({
  browseDialogType,
  getCreateSuccess,
  handleCreateChannel,
  handleCreateForum,
  input,
}: {
  browseDialogType: BrowseDialogType;
  getCreateSuccess: () => ((channelId: string) => void) | null;
  handleCreateChannel: CreateChannelHandler;
  handleCreateForum: CreateForumHandler;
  input: ChannelCreationInput;
}): Promise<void> {
  if (browseDialogType === "forum") {
    await handleCreateForum(input);
  } else {
    await handleCreateChannel(input, getCreateSuccess() ?? undefined);
  }
}

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
      }: ChannelCreationInput,
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
    }: ChannelCreationInput) => {
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
    async (input: ChannelCreationInput) => {
      await routeBrowseChannelCreate({
        browseDialogType,
        getCreateSuccess,
        handleCreateChannel,
        handleCreateForum,
        input,
      });
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
