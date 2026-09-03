import * as React from "react";

import type { InboxFilter, InboxItem } from "@/features/home/lib/inbox";
import { resolveInboxFilterSelection } from "@/features/home/lib/inboxSelection";
import { matchesInboxFilter } from "@/features/home/lib/inboxViewHelpers";

type PreviousSelection = {
  effectiveDoneSet: ReadonlySet<string>;
  isNarrow: boolean;
  ownedAgentPubkeys: ReadonlySet<string>;
  selectedConversationId: string | null;
  unreadOnly: boolean;
};

/** Selects the retained or first visible conversation after a filter change. */
export function selectAfterFilterChange(
  items: readonly InboxItem[],
  filter: InboxFilter,
  previousSelection: PreviousSelection,
) {
  const nextItems = items.filter(
    (item) =>
      matchesInboxFilter(item, filter, previousSelection.ownedAgentPubkeys) &&
      (!previousSelection.unreadOnly ||
        !previousSelection.effectiveDoneSet.has(item.id) ||
        item.conversationId === previousSelection.selectedConversationId),
  );
  return resolveInboxFilterSelection({
    isNarrow: previousSelection.isNarrow,
    items: nextItems,
    selectedConversationId: previousSelection.selectedConversationId,
  });
}

type UseHomeInboxFilterChangeOptions = PreviousSelection & {
  applyInboxSearchPatch: (patch: { item: string | null }) => void;
  inboxItems: readonly InboxItem[];
  setAutoSelectedEventId: React.Dispatch<React.SetStateAction<string | null>>;
  setFilter: React.Dispatch<React.SetStateAction<InboxFilter>>;
  setSelectedDraftKey: (draftKey: string | null) => void;
  setSelectedReminderId: (reminderId: string | null) => void;
  setUnreadBoundary: React.Dispatch<
    React.SetStateAction<{
      conversationId: string;
      eventId: string;
    } | null>
  >;
};

/** Owns the coordinated Home inbox state transition when its filter changes. */
export function useHomeInboxFilterChange({
  applyInboxSearchPatch,
  effectiveDoneSet,
  inboxItems,
  isNarrow,
  ownedAgentPubkeys,
  selectedConversationId,
  setAutoSelectedEventId,
  setFilter,
  setSelectedDraftKey,
  setSelectedReminderId,
  setUnreadBoundary,
  unreadOnly,
}: UseHomeInboxFilterChangeOptions) {
  return React.useCallback(
    (nextFilter: InboxFilter) => {
      const selection = selectAfterFilterChange(inboxItems, nextFilter, {
        effectiveDoneSet,
        isNarrow,
        ownedAgentPubkeys,
        selectedConversationId,
        unreadOnly,
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
      isNarrow,
      ownedAgentPubkeys,
      selectedConversationId,
      setAutoSelectedEventId,
      setFilter,
      setSelectedDraftKey,
      setSelectedReminderId,
      setUnreadBoundary,
      unreadOnly,
    ],
  );
}
