import * as React from "react";

import { CaseCanvasTab } from "./CaseCanvasTab";

export type CaseScreenTab = "timeline" | "members" | "evidence" | "canvas";

export type CaseScreenProps = {
  caseChannelId: string;
  canEdit: boolean;
  isArchived: boolean;
  ttlDeadline: string | null;
  nowMs: number;
  /** The channel surface, rendered under the Timeline tab. */
  timeline: React.ReactNode;
  /**
   * Members and evidence tabs exist only when their content does. A tab
   * whose body says "not built" is a placeholder, and the case surface
   * carries none; the tab appears the day the content does.
   */
  members?: React.ReactNode;
  evidence?: React.ReactNode;
};

const TABS: { id: CaseScreenTab; label: string }[] = [
  { id: "timeline", label: "Timeline" },
  { id: "members", label: "Members" },
  { id: "evidence", label: "Evidence" },
  { id: "canvas", label: "Canvas" },
];

/**
 * S3, `/cases/$caseId`. One investigation.
 *
 * The tabs are siblings rather than a stack: the canvas is working notes and
 * the timeline is the record, and an operator moves between them constantly
 * while a case is live. Only the selected tab is mounted, so the canvas's
 * seeding effect cannot run for a case nobody opened.
 */
export function CaseScreen({
  caseChannelId,
  canEdit,
  isArchived,
  ttlDeadline,
  nowMs,
  timeline,
  members,
  evidence,
}: CaseScreenProps): React.ReactElement {
  const [tab, setTab] = React.useState<CaseScreenTab>("timeline");
  const tabs = TABS.filter(
    (entry) =>
      (entry.id !== "members" || members !== undefined) &&
      (entry.id !== "evidence" || evidence !== undefined),
  );

  return (
    <section
      data-testid="perch-case"
      data-case-tab={tab}
      className="flex h-full flex-col"
    >
      <div role="tablist" className="flex gap-1 border-b border-border px-3">
        {tabs.map((entry) => (
          <button
            key={entry.id}
            type="button"
            role="tab"
            aria-selected={tab === entry.id}
            data-testid={`perch-case-tab-${entry.id}`}
            className="px-2 py-1 text-sm"
            onClick={() => setTab(entry.id)}
          >
            {entry.label}
          </button>
        ))}
      </div>
      <div className="min-h-0 flex-1 overflow-auto p-3">
        {tab === "timeline" ? timeline : null}
        {tab === "members" ? members : null}
        {tab === "evidence" ? evidence : null}
        {tab === "canvas" ? (
          <CaseCanvasTab
            caseChannelId={caseChannelId}
            canEdit={canEdit}
            isArchived={isArchived}
            ttlDeadline={ttlDeadline}
            nowMs={nowMs}
          />
        ) : null}
      </div>
    </section>
  );
}
