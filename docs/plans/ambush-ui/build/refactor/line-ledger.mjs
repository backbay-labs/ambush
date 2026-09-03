#!/usr/bin/env node
// 15-FILE-SPLIT-PLAN.md — the arithmetic, made re-runnable.
//
// This script does not modify BUZZ. It reads the three capped files, applies
// each planned commit's line edits to an in-memory copy, and reports the
// gate-line count the CI ratchet would compute afterwards. Run it before and
// after the real refactor lands; if the "projected" column and the real file
// disagree by more than the stated tolerance, the plan drifted and this file is
// the thing to fix first.
//
//   node line-ledger.mjs [--buzz /path/to/buzz] [--write-after <dir>]
//
// REFUSES TO PASS SILENTLY. Every edit carries an `anchor`: the text that must
// be present on its `from` line in the tree being measured. If BUZZ moves under
// the plan, the anchor check fails with the expected and actual line rather
// than quietly producing a number computed against the wrong ranges. This is
// the guard the wave-2 red team asked for by name — a figure quoted from this
// script is only meaningful if the script was run against the tree the figure
// claims to describe. Exit 2 means "the plan's line numbers are stale"; exit 1
// means "a planned split does not clear the cap".
//
// Gate-line semantics are copied from BUZZ scripts/check-file-sizes-core.mjs:24-29
// (countLines splits on /\r?\n/, so a newline-terminated file counts wc -l + 1)
// and :31-33 (allowedLineCount pins an over-cap file at its own size).

import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import path from "node:path";

const args = process.argv.slice(2);
const buzz = valueOf("--buzz") ?? "/Users/connor/Medica/backbay/buzz";
const writeAfter = valueOf("--write-after");

function valueOf(flag) {
  const i = args.indexOf(flag);
  return i === -1 ? undefined : args[i + 1];
}

/** BUZZ scripts/check-file-sizes-core.mjs:24-29, verbatim. */
function countLines(content) {
  if (content.length === 0) return 0;
  return content.split(/\r?\n/).length;
}

/** BUZZ scripts/check-file-sizes-core.mjs:31-33, verbatim. */
function allowedLineCount(baseLines, maxLines) {
  return baseLines == null || baseLines <= maxLines ? maxLines : baseLines;
}

/**
 * Apply one commit's edits. Each edit is {from, to, text} over 1-indexed lines
 * of the ORIGINAL file for that commit; `text` of null deletes. Edits are
 * applied bottom-up so earlier line numbers stay valid.
 */
function applyEdits(source, edits) {
  const lines = source.split("\n");
  const sorted = [...edits].sort((a, b) => b.from - a.from);
  for (const edit of sorted) {
    const replacement = edit.text == null ? [] : edit.text.split("\n");
    lines.splice(edit.from - 1, edit.to - edit.from + 1, ...replacement);
  }
  return lines.join("\n");
}

/** Lines an edit list removes from the host file, net of what it inserts. */
function movedLineCount(edits) {
  let removed = 0;
  for (const edit of edits) removed += edit.to - edit.from + 1;
  return removed;
}

/**
 * The stale-plan guard. `anchor` is matched against the ORIGINAL file's `from`
 * line, trimmed. An empty anchor asserts the line is blank (two ranges in
 * MessageRow deliberately start on the blank line above the block they move,
 * so the extraction does not leave a double blank behind).
 *
 * `anchorTo` is REQUIRED whenever `anchor` is not discriminating — a bare
 * `import {` matches dozens of lines, so a one-line shift would land on
 * another one and the guard would stay silent. `--self-test` inserts one line
 * at the top of each file and requires EVERY anchored edit to report; it
 * caught exactly this on its first run (58 of 62 edits fired, and the four
 * silent ones were all `import {`). Two MessageRow edits whose only anchor is
 * "this line is blank" cannot report against that perturbation; the self-test
 * names them as EXCLUDED rather than counting them as passes.
 */
function verifyAnchors(original, entryFile, step) {
  const lines = original.split("\n");
  const problems = [];
  const check = (edit, lineNo, expected, which) => {
    const actual = (lines[lineNo - 1] ?? "").trim();
    const ok = expected === "" ? actual === "" : actual.startsWith(expected);
    if (ok) return;
    problems.push(
      `${step.id} ${entryFile}:${lineNo} (${which})\n` +
        `      expected line to start with: ${JSON.stringify(expected)}\n` +
        `      found:                       ${JSON.stringify(actual.slice(0, 78))}`,
    );
  };
  for (const edit of step.edits) {
    if (edit.anchor === undefined) {
      problems.push(`${step.id} ${entryFile}:${edit.from} has no anchor`);
      continue;
    }
    if (edit.anchor === "import {" && edit.anchorTo === undefined) {
      problems.push(
        `${step.id} ${entryFile}:${edit.from} anchor "import {" is not ` +
          `discriminating and carries no anchorTo`,
      );
      continue;
    }
    check(edit, edit.from, edit.anchor, "anchor");
    if (edit.anchorTo !== undefined) {
      check(edit, edit.to, edit.anchorTo, "anchorTo");
    }
  }
  return problems;
}

// ───────────────────────────────────────────────────────────────────────────
// MessageRow.tsx — MR-1 (thread guides) then MR-2 (message body / marker seam)
// ───────────────────────────────────────────────────────────────────────────

const MR_1 = [
  // Trim the threadTreeLayout import to the two symbols the row still uses
  // (getThreadReplyIndentRem at :318, threadReplyLength at :730) and add the
  // new child's import in the same block.
  {
    from: 21,
    to: 29,
    anchor: "import {",
    anchorTo: '} from "@/features/messages/lib/threadTreeLayout";',
    text: `import {
  getThreadReplyIndentRem,
  threadReplyLength,
} from "@/features/messages/lib/threadTreeLayout";
import { MessageThreadGuides } from "./MessageThreadGuides";`,
  },
  // ThreadDepthGuideAction becomes the guides module's type; MessageRow
  // re-exports it so MessageThreadPanel.tsx:42 and MessageThreadSummaryRow.tsx:8
  // do not change.
  {
    from: 67,
    to: 72,
    anchor: "export type ThreadDepthGuideAction",
    text: `export type { ThreadDepthGuideAction } from "./MessageThreadGuides";`,
  },
  // descendantGuideOffsetRem, replyConnector, depthGuideItems, the four
  // collapse handlers and collapseDepthGuideActionsByDepth are used only by
  // the guide JSX.
  {
    from: 319,
    to: 377,
    anchor: "const descendantGuideOffsetRem",
    text: null,
  },
  // guideBleedRem — used only at :745,:746,:838,:877,:880, all inside the
  // guide JSX.
  { from: 466, to: 466, anchor: "const guideBleedRem", text: null },
  // The guide JSX itself.
  {
    from: 734,
    to: 884,
    anchor: "{showDepthGuides && depthGuideItems.length > 0 ? (",
    text: `        <MessageThreadGuides
          collapseDepthGuideActions={collapseDepthGuideActions}
          collapseDescendantsLabel={collapseDescendantsLabel}
          connectDescendants={connectDescendants}
          depthGuideDepths={depthGuideDepths}
          highlightDescendantRail={highlightDescendantRail}
          highlightReplyConnector={highlightReplyConnector}
          highlightThreadLineDepths={highlightThreadLineDepths}
          isThreadReplyLayout={isThreadReplyLayout}
          message={message}
          onCollapseDepthGuide={onCollapseDepthGuide}
          onCollapseDepthGuideHoverChange={onCollapseDepthGuideHoverChange}
          onCollapseDescendants={onCollapseDescendants}
          onCollapseDescendantsHoverChange={onCollapseDescendantsHoverChange}
          showDepthGuides={showDepthGuides}
        />`,
  },
];

const MR_2 = [
  {
    from: 34,
    to: 34,
    anchor: "import { getConfigNudgeAuthorPubkey }",
    text: null,
  },
  {
    from: 38,
    to: 39,
    anchor: "import { useChannelNavigation }",
    text: null,
  },
  {
    from: 41,
    to: 42,
    anchor: "import { parseWaveMessageContent }",
    text: null,
  },
  {
    from: 45,
    to: 45,
    anchor: "import { VideoReviewCommentMarkdown }",
    text: null,
  },
  { from: 47, to: 49, anchor: "import { editMessage }", text: null },
  {
    from: 58,
    to: 58,
    anchor: "import { WaveMessageAttachment }",
    text: `import { MessageBody } from "./MessageBody";`,
  },
  // linkPreviewsSuppressed + removeLinkPreviewsForEveryone
  {
    from: 174,
    to: 197,
    anchor: "const linkPreviewsSuppressed",
    text: null,
  },
  {
    from: 268,
    to: 281,
    anchor: "const agentMentionPubkeysByName",
    text: null,
  },
  // imetaByUrl + snapshotSharedBy, taking the blank line above with them
  { from: 296, to: 308, anchor: "", text: null },
  // channelNames, taking the blank line above with it
  { from: 315, to: 316, anchor: "", text: null },
  {
    from: 414,
    to: 461,
    anchor: "default: {",
    text: `        default:
          return (
            <MessageBody
              agentAddressPrefix={agentAddressPrefix}
              channelId={channelId}
              customEmoji={customEmoji}
              emojiOnly={emojiOnly}
              huddleMemberPubkeys={huddleMemberPubkeys}
              huddleMemberPubkeysPending={huddleMemberPubkeysPending}
              isKnownAgentPubkey={isKnownAgentPubkey}
              mentionNames={mentionNames}
              mentionPubkeysByName={mentionPubkeysByName}
              message={message}
              onEdit={onEdit}
              profiles={profiles}
              searchQuery={searchQuery}
              videoReviewCommentRootId={videoReviewCommentRootId}
              videoReviewContext={videoReviewContext}
            />
          );`,
  },
];

// ───────────────────────────────────────────────────────────────────────────
// AppShell.tsx — AS-1 … AS-4
// ───────────────────────────────────────────────────────────────────────────

const AS_1 = [
  {
    from: 39,
    to: 39,
    anchor: "import { useMembershipNotifications }",
    text: null,
  },
  // agents data refresh / reconciliation / restart / persona / observer
  { from: 48, to: 52, anchor: "import { useAgentsDataRefresh }", text: null },
  {
    from: 55,
    to: 58,
    anchor: "import {",
    anchorTo: '} from "@/features/presence/hooks";',
    text: `import { usePresenceSession } from "@/features/presence/hooks";`,
  },
  {
    from: 59,
    to: 63,
    anchor: "import {",
    anchorTo: '} from "@/features/user-status/hooks";',
    text: `import {
  useSetUserStatusMutation,
  useUserStatusQuery,
} from "@/features/user-status/hooks";`,
  },
  // emoji live updates + four archive hooks
  {
    from: 64,
    to: 68,
    anchor: "import { useCommunityEmojiLiveUpdates }",
    text: null,
  },
  {
    from: 93,
    to: 94,
    anchor: "import { useRelayAutoHeal }",
    text: `import { useAppShellBackgroundSync } from "@/app/useAppShellBackgroundSync";`,
  },
  {
    from: 144,
    to: 144,
    anchor: "useManagedAgentRuntimeReconciliation(",
    text: null,
  },
  { from: 181, to: 181, anchor: "const startupReady = useDeferredStartup", text: null },
  {
    from: 191,
    to: 221,
    anchor: "usePersonaSync(",
    text: `  const { deferredPubkey } = useAppShellBackgroundSync({
    communities: communitiesHook.communities,
    pubkey: identityQuery.data?.pubkey,
    relayUrl: communitiesHook.activeCommunity?.relayUrl,
  });`,
  },
  // autoHeal, presence sub, status sub, emoji, membership
  { from: 223, to: 227, anchor: "useRelayAutoHeal();", text: null },
];

const AS_2 = [
  {
    from: 84,
    to: 88,
    anchor: "import {",
    anchorTo: '} from "@/features/communities/communityNavigationStorage";',
    text: `import { useCommunityDestinationRestore } from "@/app/useCommunityDestinationRestore";`,
  },
  {
    from: 277,
    to: 324,
    anchor: "const hasRestoredCommunityDestinationRef",
    text: `  useCommunityDestinationRestore({
    activeCommunityId: communitiesHook.activeCommunity?.id,
    channelsQuery,
    goChannel,
    goHome,
    selectedView,
    sidebarChannels,
  });`,
  },
];

const AS_3 = [
  { from: 33, to: 33, anchor: "useCreateChannelMutation,", text: null },
  {
    from: 90,
    to: 90,
    anchor: "import { useApplyTemplate }",
    text: `import { useChannelCreationHandlers } from "@/app/useChannelCreationHandlers";`,
  },
  // two mutations + useApplyTemplate
  { from: 504, to: 506, anchor: "const createChannelMutation", text: null },
  {
    from: 537,
    to: 620,
    anchor: "const handleCreateChannel = React.useCallback(",
    text: `  const {
    handleBrowseChannelCreate,
    handleCreateChannel,
    handleCreateForum,
    isCreatingChannel,
    isCreatingForum,
  } = useChannelCreationHandlers({
    browseDialogType,
    getCreateSuccess,
    goChannel,
  });`,
  },
];

const AS_4 = [
  { from: 74, to: 74, anchor: "isSettingsSection,", text: null },
  {
    from: 106,
    to: 106,
    anchor: "import { LazySettingsScreen }",
    text: `import { AppShellSettingsSurface } from "@/app/AppShellSettingsSurface";`,
  },
  { from: 174, to: 180, anchor: "const locationSearchSection", text: null },
  // handleSettingsSectionChange, with the comment that explains it
  { from: 647, to: 654, anchor: "// Section switches rewrite", text: null },
  {
    from: 785,
    to: 823,
    anchor: '<div className="flex min-h-0 flex-1 overflow-hidden">',
    text: `                    <AppShellSettingsSurface
                      currentPubkey={identityQuery.data?.pubkey}
                      fallbackDisplayName={identityQuery.data?.displayName}
                      locationSearch={location.search}
                      notificationSettings={notificationSettings}
                      onClose={handleCloseSettings}
                    />`,
  },
];

// ───────────────────────────────────────────────────────────────────────────
// HomeView.tsx — HV-1 … HV-4
//
// The third capped file. 20-TASK-BREAKDOWN.md's task P0-13 is right that it
// must be split before F1 rewrites it (00-BRIEF.md §3 surface 1 and
// 04-SURFACES-AND-UX.md §2.1 both make The Watch a re-skin of this file, not a
// new one). The four steps are ordered by what F1 does to each block:
//   HV-1 removes the block F1 DELETES   (the messages detail pane)
//   HV-2 removes the block F1 KEEPS     (the auxiliary pane)
//   HV-3 removes the logic F1 REWRITES  (filter → queue selection)
//   HV-4 removes the copy F1 REWRITES   (the feed-unavailable pane)
// ───────────────────────────────────────────────────────────────────────────

const HV_1 = [
  // formatInboxFullTimestamp is read only at :874, inside the detail JSX.
  {
    from: 9,
    to: 16,
    anchor: "import {",
    anchorTo: '} from "@/features/home/lib/inbox";',
    text: `import {
  type InboxFilter,
  type InboxReply,
  buildInboxItems,
  findInboxItemByEventId,
  getInboxItemConversationId,
} from "@/features/home/lib/inbox";`,
  },
  { from: 18, to: 18, anchor: "import { useInboxEditMessage }", text: null },
  {
    from: 45,
    to: 45,
    anchor: "import { getHomeMessageCapabilities }",
    text: null,
  },
  {
    from: 47,
    to: 47,
    anchor: "import { InboxDetailPane }",
    text: `import { HomeMessagesDetail } from "@/features/home/ui/HomeMessagesDetail";`,
  },
  {
    from: 50,
    to: 53,
    anchor: "import {",
    anchorTo: '} from "@/features/messages/hooks";',
    text: `import { useChannelMessagesQuery } from "@/features/messages/hooks";`,
  },
  { from: 55, to: 55, anchor: "import { formatTime }", text: null },
  // splitOutgoingTags (:845) and getThreadReference (:265, which also moves)
  { from: 57, to: 58, anchor: "import { splitOutgoingTags }", text: null },
  { from: 61, to: 61, anchor: "import { resolveUserLabel }", text: null },
  {
    from: 63,
    to: 63,
    anchor: "import { deleteMessage, sendChannelMessage }",
    text: `import { deleteMessage } from "@/shared/api/tauri";`,
  },
  // latchedDefaultParentId — read only at :799
  { from: 263, to: 267, anchor: "const latchedDefaultParentId", text: null },
  { from: 293, to: 293, anchor: "const toggleReactionMutation", text: null },
  {
    from: 306,
    to: 309,
    anchor: "const { editMessage, isEditingMessage }",
    text: null,
  },
  // unreadBoundaryEventId — read only at :803
  { from: 485, to: 491, anchor: "const unreadBoundaryEventId", text: null },
  // selectedItemReplies — read only at :916
  { from: 505, to: 511, anchor: "const selectedItemReplies", text: null },
  // getHomeMessageCapabilities destructure — all four values read only inside
  // the detail JSX (:785,:787,:791,:814,:834,:896)
  {
    from: 608,
    to: 613,
    anchor: "const { canDelete, canReact, canReply, disabledReplyReason }",
    text: null,
  },
  {
    from: 782,
    to: 918,
    anchor: '{showDetailPane && detailMode === "messages" ? (',
    text: `          {showDetailPane && detailMode === "messages" ? (
            <HomeMessagesDetail
              availableChannelIds={availableChannelIds}
              channelMessages={channelMessages}
              channelMessagesQuery={channelMessagesQuery}
              contextMessages={contextMessages}
              currentPubkey={currentPubkey}
              editTargetId={editTargetId}
              feedProfiles={feedProfiles}
              inboxAgentPubkeys={inboxAgentPubkeys}
              isDeletingMessage={isDeletingMessage}
              isSendingReply={isSendingReply}
              isSinglePanelView={isSinglePanelDetailView}
              localRepliesByItemId={localRepliesByItemId}
              onCloseProfilePanel={handleCloseProfilePanel}
              onDeleteMessage={deleteInboxMessage}
              onDeletingChange={setIsDeletingMessage}
              onEditTargetChange={setEditTargetId}
              onLocalRepliesChange={setLocalRepliesByItemId}
              onManageChannel={setManagedChannelId}
              onOpenContext={onOpenContext}
              onRefresh={onRefresh}
              onRequestEmptyEditDelete={setEmptyDeleteId}
              onSelectItem={handleUserSelectItem}
              onSendingChange={setIsSendingReply}
              recordThreadInteraction={recordThreadInteraction}
              selectedChannel={selectedChannel}
              selectedEventId={selectedEventId}
              selectedItem={selectedItem}
              threadContext={threadContext}
            />
          ) : null}`,
  },
];

const HV_2 = [
  { from: 7, to: 7, anchor: "import { RightAuxiliaryPane }", text: null },
  {
    from: 8,
    to: 8,
    anchor: "import { ChannelManagementSheet }",
    text: `import { HomeInboxAuxiliaryPane } from "@/features/home/ui/HomeInboxAuxiliaryPane";`,
  },
  // The UserProfilePanel import block and the UserProfilePanelUtils block are
  // contiguous; ProfilePanelTab / ProfilePanelView are read only by the two
  // handlers at :199-214, which move.
  {
    from: 31,
    to: 39,
    anchor: "import {",
    anchorTo: '} from "@/features/profile/ui/UserProfilePanelUtils";',
    text: null,
  },
  { from: 153, to: 158, anchor: "const profilePanelTab", text: null },
  {
    from: 199,
    to: 214,
    anchor: "const handleProfilePanelViewChange",
    text: null,
  },
  {
    from: 935,
    to: 983,
    anchor: "{profilePanelPubkey ? (",
    text: `          <HomeInboxAuxiliaryPane
            currentPubkey={currentPubkey}
            canResetWidth={canResetThreadPanelWidth}
            isSinglePanelView={isSinglePanelAuxiliaryView}
            managedChannel={isChannelManagementOpen ? managedChannel : null}
            onApplySearchPatch={applyInboxSearchPatch}
            onCloseChannelManagement={() => setManagedChannelId(null)}
            onCloseProfilePanel={handleCloseProfilePanel}
            onOpenDm={handleOpenDm}
            onOpenMembers={setMembersChannel}
            onOpenProfile={handleOpenProfilePanel}
            onResetWidth={handleThreadPanelWidthReset}
            onResizeStart={handleThreadPanelResizeStart}
            profilePanelPubkey={profilePanelPubkey}
            searchValues={inboxSearchValues}
            widthPx={auxiliaryPaneWidthPx}
          />`,
  },
];

const HV_3 = [
  {
    from: 24,
    to: 24,
    anchor: "import { resolveInboxFilterSelection }",
    text: `import { useHomeInboxFilterChange } from "@/features/home/useHomeInboxFilterChange";`,
  },
  {
    from: 535,
    to: 581,
    anchor: "const handleFilterChange = React.useCallback(",
    text: `  const handleFilterChange = useHomeInboxFilterChange({
    applyInboxSearchPatch,
    effectiveDoneSet,
    inboxItems,
    isNarrowHomeViewport,
    ownedAgentPubkeys,
    selectedConversationId,
    setAutoSelectedEventId,
    setFilter,
    setSelectedDraftKey,
    setSelectedReminderId,
    setUnreadBoundary,
    unreadOnly,
  });`,
  },
];

const HV_4 = [
  {
    from: 2,
    to: 2,
    anchor: "import { RefreshCcw }",
    text: `import { HomeFeedUnavailable } from "@/features/home/ui/HomeFeedUnavailable";`,
  },
  {
    from: 74,
    to: 74,
    anchor: "import { Button }",
    text: null,
  },
  {
    from: 587,
    to: 606,
    anchor: "if (!feed) {",
    text: `  if (!feed) {
    return (
      <HomeFeedUnavailable errorMessage={errorMessage} onRefresh={onRefresh} />
    );
  }`,
  },
];

const PLAN = [
  {
    file: "desktop/src/features/messages/ui/MessageRow.tsx",
    steps: [
      { id: "MR-1", label: "extract MessageThreadGuides", edits: MR_1 },
      { id: "MR-2", label: "extract MessageBody (marker seam)", edits: MR_2 },
    ],
  },
  {
    file: "desktop/src/app/AppShell.tsx",
    steps: [
      { id: "AS-1", label: "extract useAppShellBackgroundSync", edits: AS_1 },
      {
        id: "AS-2",
        label: "extract useCommunityDestinationRestore",
        edits: AS_2,
      },
      { id: "AS-3", label: "extract useChannelCreationHandlers", edits: AS_3 },
      { id: "AS-4", label: "extract AppShellSettingsSurface", edits: AS_4 },
    ],
  },
  {
    file: "desktop/src/features/home/ui/HomeView.tsx",
    steps: [
      { id: "HV-1", label: "extract HomeMessagesDetail", edits: HV_1 },
      { id: "HV-2", label: "extract HomeInboxAuxiliaryPane", edits: HV_2 },
      { id: "HV-3", label: "extract useHomeInboxFilterChange", edits: HV_3 },
      { id: "HV-4", label: "extract HomeFeedUnavailable", edits: HV_4 },
    ],
  },
];

const MAX_LINES = 1000;
let failed = false;
const staleness = [];

// Self-test the stale-plan guard before trusting it. A guard nobody has seen
// fail is not a guard. Inserting one line at the top of each file shifts every
// anchor by one; every edit whose anchor is a non-blank line must then report.
if (args.includes("--self-test")) {
  let fired = 0;
  let checked = 0;
  for (const entry of PLAN) {
    const shifted =
      "// self-test: one inserted line\n" +
      readFileSync(path.join(buzz, entry.file), "utf8");
    for (const step of entry.steps) {
      for (const edit of step.edits) {
        // An edit whose only anchor is "this line is blank" cannot report
        // against a shift that lands on another blank line; it is excluded and
        // named, not counted as a pass.
        if (edit.anchor === "" && edit.anchorTo === undefined) {
          console.log(
            `  EXCLUDED (blank-line anchor)  ${step.id} ` +
              `${entry.file}:${edit.from}-${edit.to}`,
          );
          continue;
        }
        checked += 1;
        const reported = verifyAnchors(shifted, entry.file, {
          id: step.id,
          edits: [edit],
        }).length;
        if (reported > 0) {
          fired += 1;
        } else {
          console.error(
            `  SILENT  ${step.id} ${entry.file}:${edit.from}-${edit.to} ` +
              `anchor ${JSON.stringify(edit.anchor)}` +
              (edit.anchorTo
                ? ` / anchorTo ${JSON.stringify(edit.anchorTo)}`
                : ""),
          );
        }
      }
    }
  }
  console.log(
    `self-test: ${fired} of ${checked} anchored edits reported against a ` +
      `one-line-shifted tree`,
  );
  if (fired < checked) {
    console.error("self-test FAILED: the stale-plan guard does not fire");
    process.exit(3);
  }
  console.log("self-test passed: the guard fires on a shifted tree");
  process.exit(0);
}

for (const entry of PLAN) {
  const absolute = path.join(buzz, entry.file);
  const originalSource = readFileSync(absolute, "utf8");
  let content = originalSource;
  const original = countLines(content);
  console.log(`\n${entry.file}`);
  console.log(
    `  base                                    ${String(original).padStart(5)} gate-lines  ` +
      `(cap in force ${allowedLineCount(original, MAX_LINES)})`,
  );

  for (const step of entry.steps) {
    staleness.push(...verifyAnchors(originalSource, entry.file, step));
    // Each step's line numbers are stated against the ORIGINAL file, so the
    // step is reviewable against `git show HEAD:<file>`. Re-slice from the
    // original and accumulate the deltas.
    const before = countLines(content);
    content =
      step === entry.steps[0]
        ? applyEdits(originalSource, step.edits)
        : applyEdits(content, remap(step.edits, entry, step));
    const after = countLines(content);
    console.log(
      `  ${step.id} ${step.label.padEnd(36)} ${String(after).padStart(5)} gate-lines  ` +
        `(${after - before >= 0 ? "+" : ""}${after - before}; ` +
        `${movedLineCount(step.edits)} lines out of the host file)`,
    );
  }

  const finalCount = countLines(content);
  console.log(
    `  headroom after the split                ${String(MAX_LINES - finalCount).padStart(5)} gate-lines`,
  );
  if (finalCount > MAX_LINES) {
    failed = true;
    console.error(`  FAIL: ${entry.file} still over the cap`);
  }
  if (writeAfter) {
    const out = path.join(writeAfter, path.basename(entry.file));
    mkdirSync(writeAfter, { recursive: true });
    writeFileSync(out, content, "utf8");
    console.log(`  wrote ${out}`);
  }
}

/**
 * Steps after the first address the ORIGINAL file's line numbers. Re-express
 * them against the already-edited buffer by shifting each range by the net
 * line delta every earlier edit introduced above it.
 */
function remap(edits, entry, step) {
  const earlier = entry.steps
    .slice(0, entry.steps.indexOf(step))
    .flatMap((s) => s.edits);
  return edits.map((edit) => {
    let shift = 0;
    for (const prior of earlier) {
      if (prior.to < edit.from) {
        const inserted = prior.text == null ? 0 : prior.text.split("\n").length;
        shift += inserted - (prior.to - prior.from + 1);
      }
    }
    return { ...edit, from: edit.from + shift, to: edit.to + shift };
  });
}

if (staleness.length > 0) {
  console.error(
    `\nSTALE PLAN — ${staleness.length} anchor(s) no longer match BUZZ.\n` +
      `Every number printed above was computed against ranges that have moved.\n`,
  );
  for (const problem of staleness) console.error(`  ${problem}`);
  process.exit(2);
}

console.log("\nall anchors matched; the ranges above are the ranges in BUZZ.");
process.exit(failed ? 1 : 0);
