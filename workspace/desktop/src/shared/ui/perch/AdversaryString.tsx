import * as React from "react";

import {
  ADVERSARY_CAP,
  escapeAdversaryText,
  escapedCodepointTitle,
} from "@/features/perch-evidence/lib/adversaryText";
import { cn } from "@/shared/lib/cn";

/**
 * The one way an adversary-shaped wire string reaches the screen (INV-14,
 * 17-COMPONENT-SPECS.md §4.1).
 *
 * Renders a plain text node per part: no markdown pass, no autolink, no
 * `dangerouslySetInnerHTML`, no `children`. Control, bidi and zero-width
 * code points become visible glyphs whose `title` names the codepoint, the
 * value is capped at `cap` graphemes behind a real button, and the wrapper's
 * `aria-label` carries the trusted FIELD name only: the value is never read
 * into an aria attribute, because a screen reader announcing a
 * bidi-overridden string defeats the visual escaping.
 */
export type AdversaryStringProps = {
  /** The untrusted value, verbatim. Never pre-formatted by the caller. */
  value: string;
  /** What field this is, rendered as the rail label. A trusted constant. */
  field: string;
  /** Rendered graphemes before the expand control. Default 512. */
  cap?: number;
  /** `inline` for a value inside a sentence; `block` for a field row. */
  layout?: "inline" | "block";
  className?: string;
};

const segmenter =
  typeof Intl !== "undefined" && "Segmenter" in Intl
    ? new Intl.Segmenter(undefined, { granularity: "grapheme" })
    : null;

/** Grapheme clusters, so a cap can never split a surrogate pair or a flag. */
function graphemesOf(value: string): string[] {
  if (segmenter) {
    return Array.from(segmenter.segment(value), (s) => s.segment);
  }
  return Array.from(value);
}

export function AdversaryString({
  value,
  field,
  cap,
  layout = "inline",
  className,
}: AdversaryStringProps) {
  const [expanded, setExpanded] = React.useState(false);
  const limit = cap ?? ADVERSARY_CAP;
  const graphemes = React.useMemo(() => graphemesOf(value), [value]);
  const capped = !expanded && graphemes.length > limit;
  const visible = capped ? graphemes.slice(0, limit).join("") : value;
  const parts = React.useMemo(() => escapeAdversaryText(visible), [visible]);
  const containsEscapes = React.useMemo(
    () => escapeAdversaryText(value).some((part) => part.kind === "escaped"),
    [value],
  );
  const Wrapper = layout === "block" ? "div" : "span";

  return (
    <Wrapper
      data-testid="perch-adversary-string"
      data-perch-role="adversary-string"
      aria-label={`${field}, adversary-controlled value`}
      className={cn(
        "border-l border-[hsl(var(--perch-border-strong))] bg-[hsl(var(--perch-surface-raised))] pl-2",
        layout === "block"
          ? "flex flex-col gap-0.5 py-1 pr-2"
          : "inline-flex flex-wrap items-baseline gap-x-1.5 align-baseline",
        className,
      )}
    >
      <span className="text-2xs uppercase tracking-wide text-[hsl(var(--perch-foreground-muted))]">
        {containsEscapes
          ? "ADVERSARY-CONTROLLED · CONTAINS ESCAPED CHARACTERS"
          : "ADVERSARY-CONTROLLED"}
      </span>
      {value === "" ? (
        <span className="font-mono text-sm text-[hsl(var(--perch-foreground-muted))]">
          EMPTY
        </span>
      ) : (
        <span className="font-mono text-sm whitespace-pre-wrap break-all text-[hsl(var(--perch-foreground))]">
          {"“"}
          {parts.map((part, index) =>
            part.kind === "text" ? (
              // A part's position is its identity: the array is rebuilt only
              // when the value changes, and no part is ever reordered.
              // biome-ignore lint/suspicious/noArrayIndexKey: positional, immutable
              <React.Fragment key={index}>{part.text}</React.Fragment>
            ) : (
              <span
                // biome-ignore lint/suspicious/noArrayIndexKey: positional, immutable
                key={index}
                data-testid="perch-escaped-codepoint"
                title={escapedCodepointTitle(part.codepoint)}
                className="rounded bg-[hsl(var(--perch-card))] px-0.5 text-[hsl(var(--perch-foreground-muted))]"
              >
                {part.glyph}
              </span>
            ),
          )}
          {capped ? "…" : null}
          {"”"}
        </span>
      )}
      {capped ? (
        <button
          type="button"
          data-testid="perch-adversary-string-expand"
          onClick={() => setExpanded(true)}
          className="self-start text-2xs underline text-[hsl(var(--perch-foreground-muted))]"
        >
          show all {graphemes.length} characters
        </button>
      ) : null}
    </Wrapper>
  );
}
