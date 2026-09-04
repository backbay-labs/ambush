import * as React from "react";

import {
  useCanvasQuery,
  useSetCanvasMutation,
} from "@/features/channels/hooks";
import { ChannelCanvas } from "@/features/channels/ui/ChannelCanvas";

import { PERCH_CASE_TEMPLATE, shouldSeed } from "../lib/caseTemplate";
import {
  caseCanvasSeeded,
  markCaseCanvasSeeded,
} from "../lib/caseCanvasSeeded";

import { CaseTtlClock } from "./CaseTtlClock";

type CaseCanvasTabProps = {
  caseChannelId: string;
  canEdit: boolean;
  isArchived: boolean;
  ttlDeadline: string | null;
  nowMs: number;
};

/**
 * The case's working notes.
 *
 * Seeding writes the five headings once, into a canvas the relay has never
 * held. Three states that look alike are kept apart: a canvas still loading, a
 * canvas that has never had content, and a canvas an operator emptied. Only
 * the second is seeded — re-seeding the third would restore headings someone
 * deliberately deleted, every time they opened the tab.
 *
 * A failed seed leaves the headings rendered as UNCOMMITTED text with a retry.
 * An empty canvas shown as saved is the one outcome worth avoiding: the
 * operator would type into a document the relay never took.
 */
export function CaseCanvasTab({
  caseChannelId,
  canEdit,
  isArchived,
  ttlDeadline,
  nowMs,
}: CaseCanvasTabProps): React.ReactElement {
  const canvas = useCanvasQuery(caseChannelId);
  const setCanvas = useSetCanvasMutation(caseChannelId);
  const [seedFailed, setSeedFailed] = React.useState(false);
  // `mutateAsync` is the reference-stable member; the mutation result object
  // is a new identity every render (CLAUDE.md gotcha 6).
  const { mutateAsync } = setCanvas;

  const content = canvas.data?.content ?? null;
  const isSuccess = canvas.isSuccess;

  React.useEffect(() => {
    if (
      !shouldSeed({
        content,
        isSuccess,
        canEdit,
        channelId: caseChannelId,
        seeded: caseCanvasSeeded(),
      })
    ) {
      return;
    }
    markCaseCanvasSeeded(caseChannelId);
    setSeedFailed(false);
    void mutateAsync(PERCH_CASE_TEMPLATE).catch(() => setSeedFailed(true));
  }, [content, isSuccess, canEdit, caseChannelId, mutateAsync]);

  const retrySeed = React.useCallback(() => {
    setSeedFailed(false);
    void mutateAsync(PERCH_CASE_TEMPLATE).catch(() => setSeedFailed(true));
  }, [mutateAsync]);

  return (
    <section data-testid="perch-case-canvas" className="flex flex-col gap-2">
      <header className="flex items-center justify-between gap-3">
        <h3 className="text-sm font-medium">Canvas</h3>
        <CaseTtlClock ttlDeadline={ttlDeadline} nowMs={nowMs} />
      </header>
      {seedFailed ? (
        <div data-testid="perch-case-canvas-seed-failed" className="text-sm">
          <pre className="overflow-x-auto rounded-md border border-dashed border-border p-2 text-xs font-mono">
            {PERCH_CASE_TEMPLATE}
          </pre>
          <p className="mt-1 text-xs text-muted-foreground">
            These headings are not saved. The relay did not accept them.
          </p>
          <button
            type="button"
            data-testid="perch-case-canvas-seed-retry"
            className="mt-1 rounded border border-border px-2 py-1 text-xs"
            onClick={retrySeed}
          >
            Try again
          </button>
        </div>
      ) : null}
      <ChannelCanvas
        channelId={caseChannelId}
        canEdit={canEdit}
        isArchived={isArchived}
      />
    </section>
  );
}
