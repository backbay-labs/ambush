import * as React from "react";
import { toast } from "sonner";
import { hasLinkPreviewSuppression } from "@/features/messages/lib/formatTimelineMessages";
import { resolveSnapshotSharedBy } from "@/features/messages/lib/snapshotSharedBy";
import { getChannelIdFromTags } from "@/features/messages/lib/threading";
import { parseWaveMessageContent } from "@/features/messages/lib/waveMessage";
import type { TimelineMessage } from "@/features/messages/types";
import { getConfigNudgeAuthorPubkey } from "@/features/messages/ui/configNudgeAuthPubkey";
import {
  useAdmittedIssuerPredicate,
  useAdmittedIssuersVersion,
} from "@/features/perch-evidence/lib/admittedIssuers";
import type {
  SwarmCardContext,
  SwarmMarkerParse,
} from "@/features/perch-evidence/lib/markerTypes";
import { parseSwarmMarker } from "@/features/perch-evidence/lib/parseSwarmMarker";
import { useSwarmCardSurface } from "@/features/perch-evidence/ui/SwarmCardSurface";
import { SwarmEvidenceCard } from "@/features/perch-evidence/ui/swarmCardRegistry";
import { UnadmittedMarkerNotice } from "@/features/perch-evidence/ui/UnadmittedMarkerNotice";
import type { UserProfileLookup } from "@/features/profile/lib/identity";
import { editMessage } from "@/shared/api/tauri";
import { useChannelNavigation } from "@/shared/context/ChannelNavigationContext";
import { cn } from "@/shared/lib/cn";
import type { CustomEmoji } from "@/shared/lib/remarkCustomEmoji";
import { parseImetaTags } from "@/shared/ui/markdown/parseImeta";
import type { VideoReviewContext } from "@/shared/ui/VideoPlayer";
import { VideoReviewCommentMarkdown } from "@/shared/ui/VideoReviewCommentMarkdown";
import { WaveMessageAttachment } from "./WaveMessageAttachment";

export type MessageBodyProps = {
  agentAddressPrefix?: React.ReactNode;
  channelId: string | null;
  customEmoji: CustomEmoji[] | undefined;
  emojiOnly: boolean;
  huddleMemberPubkeys?: readonly string[];
  huddleMemberPubkeysPending?: boolean;
  isKnownAgentPubkey: (pubkey: string) => boolean;
  mentionNames?: string[];
  mentionPubkeysByName?: Record<string, string>;
  message: TimelineMessage;
  onEdit?: (message: TimelineMessage) => void;
  profiles: UserProfileLookup | undefined;
  searchQuery?: string;
  videoReviewCommentRootId?: string;
  videoReviewContext?: VideoReviewContext;
};

/** The common case: a body that is not a swarm card. One frozen identity. */
const NOT_A_SWARM_MARKER: SwarmMarkerParse = Object.freeze({
  status: "not-a-marker",
} as const);

/** Renders the fallback body for message kinds without a dedicated row case. */
export function MessageBody({
  agentAddressPrefix,
  channelId,
  customEmoji,
  emojiOnly,
  huddleMemberPubkeys,
  huddleMemberPubkeysPending,
  isKnownAgentPubkey,
  mentionNames,
  mentionPubkeysByName,
  message,
  onEdit,
  profiles,
  searchQuery,
  videoReviewCommentRootId,
  videoReviewContext,
}: MessageBodyProps) {
  // The perch seam (12-PLAN-FIRST-CARD.md Task 17): route the body by its
  // line 0 and its raw signer before any other sniff. The parse is memoised
  // per message and per admitted-set version; the predicate's identity never
  // changes, so the version is what re-parses a row after the set loads.
  const swarmSurface = useSwarmCardSurface();
  const isAdmittedIssuer = useAdmittedIssuerPredicate();
  const admittedVersion = useAdmittedIssuersVersion();
  // biome-ignore lint/correctness/useExhaustiveDependencies: `admittedVersion` is the memo's invalidation key — `isAdmittedIssuer`'s identity never changes, so the version is what re-parses a row once the admitted set loads
  const swarmParse = React.useMemo(
    () =>
      swarmSurface.enabled
        ? parseSwarmMarker({
            content: message.body,
            signerPubkey: message.signerPubkey,
            channelTag: getChannelIdFromTags(message.tags ?? []),
            eventId: message.id,
            isAdmittedIssuer,
          })
        : NOT_A_SWARM_MARKER,
    [
      swarmSurface.enabled,
      message.body,
      message.signerPubkey,
      message.tags,
      message.id,
      isAdmittedIssuer,
      admittedVersion,
    ],
  );
  const swarmCtx = React.useMemo<SwarmCardContext>(
    () => ({
      surface: swarmSurface.surface,
      caseChannelId: swarmSurface.caseChannelId,
      searchQuery: searchQuery ?? "",
      density: "comfortable",
    }),
    [swarmSurface.surface, swarmSurface.caseChannelId, searchQuery],
  );

  const linkPreviewsSuppressed = hasLinkPreviewSuppression(message.tags);
  const removeLinkPreviewsForEveryone =
    channelId && onEdit && !message.pending && !linkPreviewsSuppressed
      ? async () => {
          const tags = message.tags ?? [];
          try {
            await editMessage(
              channelId,
              message.id,
              message.body,
              tags.filter((tag) => tag[0] === "imeta"),
              tags.filter((tag) => tag[0] === "emoji"),
              undefined,
              true,
              tags.filter((tag) => tag[0] === "mention"),
            );
          } catch (error) {
            toast.error(
              `Failed to remove previews: ${error instanceof Error ? error.message : String(error)}`,
            );
            throw error;
          }
        }
      : undefined;

  const agentMentionPubkeysByName = React.useMemo(() => {
    if (!mentionPubkeysByName) {
      return undefined;
    }

    const values: Record<string, string> = {};
    for (const [name, pubkey] of Object.entries(mentionPubkeysByName)) {
      if (isKnownAgentPubkey(pubkey)) {
        values[name] = pubkey;
      }
    }

    return Object.keys(values).length > 0 ? values : undefined;
  }, [isKnownAgentPubkey, mentionPubkeysByName]);

  const imetaByUrl = React.useMemo(
    () => (message.tags ? parseImetaTags(message.tags) : undefined),
    [message.tags],
  );
  const snapshotSharedBy = React.useMemo(
    () =>
      resolveSnapshotSharedBy({ signerPubkey: message.signerPubkey }, profiles),
    [message.signerPubkey, profiles],
  );

  const { nonDmChannelNames: channelNames } = useChannelNavigation();

  if (
    swarmParse.status === "ok" ||
    swarmParse.status === "unknown-kind" ||
    swarmParse.status === "unsupported-version"
  ) {
    return <SwarmEvidenceCard parsed={swarmParse} ctx={swarmCtx} />;
  }
  const unadmittedNotice =
    swarmParse.status === "unadmitted-issuer" ? (
      <UnadmittedMarkerNotice slug={swarmParse.slug} eventId={message.id} />
    ) : null;

  const waveMessage = parseWaveMessageContent(message.body);
  if (waveMessage) {
    return (
      <WaveMessageAttachment
        channelId={channelId}
        fallbackText={waveMessage.fallbackText}
        huddleMemberPubkeys={huddleMemberPubkeys}
        huddleMemberPubkeysPending={huddleMemberPubkeysPending}
        searchQuery={searchQuery}
      />
    );
  }

  return (
    <>
      {unadmittedNotice}
      <VideoReviewCommentMarkdown
        channelNames={channelNames}
        className={cn(
          "max-w-full text-message",
          emojiOnly &&
            "text-4xl leading-tight [&_p]:leading-tight [&_img[data-custom-emoji]]:h-[1.45em] [&_img[data-custom-emoji]]:align-middle [&_button:has(img[data-custom-emoji])]:align-middle",
        )}
        configNudgeAuthorPubkey={getConfigNudgeAuthorPubkey(
          message,
          isKnownAgentPubkey,
        )}
        content={message.body}
        messageId={message.id}
        linkPreviewsSuppressed={linkPreviewsSuppressed}
        linkPreviewTags={message.tags}
        leadingInlineContent={agentAddressPrefix}
        onRemoveLinkPreviewsForEveryone={removeLinkPreviewsForEveryone}
        customEmoji={customEmoji}
        imetaByUrl={imetaByUrl}
        agentMentionPubkeysByName={agentMentionPubkeysByName}
        mentionNames={mentionNames}
        mentionPubkeysByName={mentionPubkeysByName}
        searchQuery={searchQuery}
        snapshotSharedBy={snapshotSharedBy}
        videoReviewCommentRootId={videoReviewCommentRootId}
        videoReviewContext={videoReviewContext}
      />
    </>
  );
}
