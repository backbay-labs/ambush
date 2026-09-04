import type * as React from "react";

import { cn } from "@/shared/lib/cn";
import { AdversaryString } from "@/shared/ui/perch/AdversaryString";
import { EyebrowLabel } from "@/shared/ui/perch/EyebrowLabel";

import type { VerdictSlotContent, VerdictSlotId } from "../lib/verdictSlots";

/**
 * One slot of the Verdict Row.
 *
 * Renders whatever `buildVerdictSlots` produced, including an absence. There
 * is no branch here that can decide a slot is not worth showing — that
 * decision was already made, once, in the builder, and it always came out
 * "show it".
 *
 * `sentinelRef` is attached to the slot's LAST element. The grant control
 * observes it at `threshold: 1.0`, so "the operator saw the blast radius"
 * means the end of the block reached the viewport, not that the heading did.
 */
export type VerdictSlotProps = {
  id: VerdictSlotId;
  label: string;
  content: VerdictSlotContent;
  sentinelRef?: React.Ref<HTMLDivElement>;
};

export function VerdictSlot({
  id,
  label,
  content,
  sentinelRef,
}: VerdictSlotProps) {
  return (
    <section
      data-testid={`perch-verdict-slot-${id}`}
      data-perch-role="verdict-slot"
      data-perch-slot={id}
      className="border-l-[2.5px] border-[hsl(var(--perch-border-strong))] py-2 pl-3"
    >
      <EyebrowLabel>{label}</EyebrowLabel>
      {content.kind === "absent" ? (
        <div ref={sentinelRef}>
          <p
            data-perch-absence=""
            className="text-sm text-[hsl(var(--perch-foreground-muted))]"
          >
            {content.copy}
          </p>
        </div>
      ) : (
        content.lines.map((line, index) => (
          // Keyed on content, not position: a slot's lines are rebuilt whole
          // from one hold, so the label-and-value pair is stable and unique
          // within a slot while the index is neither.
          <div
            key={`${line.label ?? "note"}=${line.value}`}
            ref={index === content.lines.length - 1 ? sentinelRef : undefined}
            data-perch-provenance={line.provenance ?? undefined}
            className={cn(
              "grid grid-cols-[minmax(6rem,auto)_1fr] gap-x-3 text-sm",
              "text-[hsl(var(--perch-foreground))]",
            )}
          >
            <span className="font-mono text-xs text-[hsl(var(--perch-foreground-muted))]">
              {line.label ?? ""}
            </span>
            {line.adversary ? (
              <AdversaryString
                layout="inline"
                field={line.label ?? label.toLowerCase()}
                value={line.value}
                cap={320}
              />
            ) : (
              // `<code>` fed from DATA, never a literal: the copy gate's
              // extractor reads rendered string literals, and a policy reason
              // that happens to contain a banned word is the daemon's words,
              // not this console's.
              <code className="font-mono">{line.value}</code>
            )}
          </div>
        ))
      )}
    </section>
  );
}
