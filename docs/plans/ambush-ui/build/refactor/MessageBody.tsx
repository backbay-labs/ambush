// PROPOSED — lands at BUZZ desktop/src/features/messages/ui/MessageBody.tsx
//
// Commit MR-2 of 15-FILE-SPLIT-PLAN.md, and the seam 17-COMPONENT-SPECS.md §3
// binds to. UPSTREAM-SAFE VERSION: this file contains no Perch code. Every
// expression is moved verbatim from MessageRow.tsx at eed74bde2 —
// :174-197 (link-preview suppression + the remove-for-everyone callback),
// :268-281 (agentMentionPubkeysByName), :297-308 (imetaByUrl, snapshotSharedBy),
// :316 (channelNames) and the `default:` arm at :414-461. Nothing is rewritten.
//
// Why those five ranges and no others: each one's readers, measured with
// `grep -n '\<name\>' MessageRow.tsx`, are all inside the `default:` arm. See
// 15-FILE-SPLIT-PLAN.md §4.3 for the table.
//
// PERCH ADDS ONE CALL HERE LATER (commit P-1, not part of the upstream PR):
// between the wave sniff and the markdown fallthrough,
//
//     const parsed = parseAmbushMarker({ body: message.body, signerPubkey: … });
//     if (parsed.status !== "not-a-marker") {
//       return <AmbushEvidenceCard card={parsed.card} ctx={ambushCtx} />;
//     }
//
// with `ambushCtx` read from `AmbushCardProvider` via `useContext` — never from
// a prop, so MessageRow's memo comparator (MessageRow.tsx:935-995) never grows.
// 17-COMPONENT-SPECS.md §3.3/§3.7 own that contract; this file owns the slot.

import * as React from "react";
import { toast } from "sonner";
import { getConfigNudgeAuthorPubkey } from "@/features/messages/ui/configNudgeAuthPubkey";
import { hasLinkPreviewSuppression } from "@/features/messages/lib/formatTimelineMessages";
import type { TimelineMessage } from "@/features/messages/types";
import type { UserProfileLookup } from "@/features/profile/lib/identity";
import { parseWaveMessageContent } from "@/features/messages/lib/waveMessage";
import { resolveSnapshotSharedBy } from "@/features/messages/lib/snapshotSharedBy";
import { editMessage } from "@/shared/api/tauri";
import { useChannelNavigation } from "@/shared/context/ChannelNavigationContext";
import { cn } from "@/shared/lib/cn";
import type { CustomEmoji } from "@/shared/lib/remarkCustomEmoji";
import { parseImetaTags } from "@/shared/ui/markdown/parseImeta";
import type { VideoReviewContext } from "@/shared/ui/VideoPlayer";
import { VideoReviewCommentMarkdown } from "@/shared/ui/VideoReviewCommentMarkdown";
import { WaveMessageAttachment } from "./WaveMessageAttachment";

/**
 * The body of one conversation row for every kind `MessageRow.renderBody` has
 * no explicit `case` for.
 *
 * Extracted so that adding a body renderer is an edit to this file rather than
 * to `MessageRow.tsx`, which sat one gate-line under the 1000-line CI cap
 * (`BUZZ scripts/check-file-sizes-core.mjs:24-33`) and could not take one.
 *
 * Not memoized on purpose: it renders inside `MessageRow`'s own `React.memo`
 * boundary (`MessageRow.tsx:74`), so a second comparator here would run on
 * every parent render for no benefit — and would be a second place a new prop
 * has to be declared reference-stable.
 */
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
}: {
  agentAddressPrefix?: React.ReactNode;
  channelId: string | null;
  customEmoji: CustomEmoji[] | undefined;
  emojiOnly: boolean;
  huddleMemberPubkeys?: readonly string[];
  huddleMemberPubkeysPending?: boolean;
  isKnownAgentPubkey: (pubkey: string) => boolean;
  mentionNames?: Record<string, string>;
  mentionPubkeysByName?: Record<string, string>;
  message: TimelineMessage;
  onEdit?: (message: TimelineMessage) => void;
  profiles?: UserProfileLookup;
  searchQuery?: string;
  videoReviewCommentRootId?: string;
  videoReviewContext?: VideoReviewContext;
}) {
  // ── moved verbatim from MessageRow.tsx:174-197 ──────────────────────────
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

  // ── moved verbatim from MessageRow.tsx:268-281 ──────────────────────────
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

  // ── moved verbatim from MessageRow.tsx:297-308 ──────────────────────────
  const imetaByUrl = React.useMemo(
    () => (message.tags ? parseImetaTags(message.tags) : undefined),
    [message.tags],
  );
  const snapshotSharedBy = React.useMemo(
    () =>
      resolveSnapshotSharedBy({ signerPubkey: message.signerPubkey }, profiles),
    [message.signerPubkey, profiles],
  );

  // ── moved verbatim from MessageRow.tsx:316 ──────────────────────────────
  const { nonDmChannelNames: channelNames } = useChannelNavigation();

  // ── moved verbatim from MessageRow.tsx:415-460 ──────────────────────────
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
    <VideoReviewCommentMarkdown
      channelNames={channelNames}
      className={cn(
        "max-w-full text-message",
        emojiOnly &&
          "text-4xl leading-tight [&_p]:leading-tight [&_img[data-custom-emoji]]:h-[1.45em] [&_img[data-custom-emoji]]:align-middle [&_button:has(img[data-custom-emoji])]:align-middle",
      )}
      // Only pass the author pubkey for agent-authored messages so
      // config-nudge cards can authenticate the sender. Uses the
      // raw event signer (signerPubkey), not a relay-delegated display
      // author, because the agent itself must have signed the card.
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
  );
}
