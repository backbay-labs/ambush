import * as React from "react";
import { type AnyRouter, useRouter } from "@tanstack/react-router";
import { useQueryClient } from "@tanstack/react-query";

import type { PerchFindingAction } from "@/shared/api/tauriPerch";
import { AdversaryString } from "@/shared/ui/perch/AdversaryString";
import {
  PERCH_REASON_CAP,
  WriteStateRow,
} from "@/shared/ui/perch/WriteStateRow";

import {
  type FindingCardSubject,
  promoteFinding,
  recordFindingVerdict,
  retryFindingFeedback,
  useFindingVerdictIntent,
} from "../../lib/findingVerdictFlow";
import { useCaseFor } from "../../lib/perchCaseIndex";
import { useVerdictWriteState } from "../../lib/verdictWriteState";

/**
 * The four verbs on a finding card, and the two-legged write behind three of
 * them.
 *
 * # The keys, and what they may not be
 *
 * `E` promotes and means nothing else, ever. `C`, `D` and `I` are the three
 * verdicts B3 admits. There is deliberately no `A`: an "Approve" key on a
 * detection is the affordance that turns a review queue into a clicking
 * exercise, and this console does not have one.
 *
 * A verdict is never one keystroke. The first press arms the verb and opens a
 * rationale row; the second press, or the explicit record control, commits.
 * The rule matters most for `D`, which suppresses future findings like this
 * one, but it costs nothing to hold `C` and `I` to it as well and it means
 * the group has one interaction to learn instead of two.
 *
 * The keys only fire while this group holds focus, only bare (no modifier),
 * only on a first press (never a key repeat), and never while a text field or
 * a dialog has the keyboard.
 */

const VERDICTS = ["confirm", "dismiss", "investigate"] as const;

const KEY_TO_VERB: Readonly<Record<string, "promote" | PerchFindingAction>> =
  Object.freeze({
    e: "promote",
    c: "confirm",
    d: "dismiss",
    i: "investigate",
  });

/** Why C/D/I cannot be used yet. Rendered as the disabled reason. */
const PROMOTE_FIRST = "Promote this finding to a case first";

function verbLabel(verb: PerchFindingAction): string {
  return verb === "confirm"
    ? "Confirm"
    : verb === "dismiss"
      ? "Dismiss"
      : "Investigate";
}

function verbKey(verb: PerchFindingAction): string {
  return verb === "confirm" ? "C" : verb === "dismiss" ? "D" : "I";
}

/**
 * True when the keyboard belongs to something else on the page: a text field,
 * or a dialog that is actually on screen.
 *
 * Visibility, not mere presence: a component library that keeps a closed
 * dialog mounted would otherwise disable these keys permanently, and a
 * shortcut that silently stops working is worse than one that never existed.
 */
function keyboardIsElsewhere(target: EventTarget | null): boolean {
  if (typeof document !== "undefined") {
    const dialogs = document.querySelectorAll<HTMLElement>(
      '[role="dialog"], [role="alertdialog"], [aria-modal="true"]',
    );
    for (const dialog of dialogs) {
      if (dialog.getClientRects().length > 0) return true;
    }
  }
  if (!(target instanceof HTMLElement)) return false;
  const tag = target.tagName;
  return (
    tag === "INPUT" ||
    tag === "TEXTAREA" ||
    tag === "SELECT" ||
    target.isContentEditable
  );
}

export function FindingCardActions({ card }: { card: FindingCardSubject }) {
  const findingId = card.fact.locator.finding_id;
  const caseRef = useCaseFor(findingId);
  const writeState = useVerdictWriteState(findingId);
  const intent = useFindingVerdictIntent(findingId);
  const [armed, setArmed] = React.useState<PerchFindingAction | null>(null);
  const [rationale, setRationale] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const [promoteError, setPromoteError] = React.useState<string | null>(null);

  const router = useRouter({ warn: false }) as AnyRouter | undefined;
  const queryClient = useQueryClient();
  // `invalidateQueries` is the stable member; the client object is not a new
  // identity per render, but reading the method keeps the dependency honest.
  const invalidate = React.useCallback(
    (keys: readonly (readonly unknown[])[]) => {
      for (const queryKey of keys) {
        void queryClient.invalidateQueries({ queryKey: [...queryKey] });
      }
    },
    [queryClient],
  );
  const navigate = React.useCallback(
    (caseId: string) => {
      void router?.navigate({ to: "/cases/$caseId", params: { caseId } });
    },
    [router],
  );
  const deps = React.useMemo(
    () => ({ invalidate, navigate }),
    [invalidate, navigate],
  );

  const promote = React.useCallback(async () => {
    if (busy || caseRef) return;
    setBusy(true);
    setPromoteError(null);
    try {
      await promoteFinding(card, deps);
    } catch (error) {
      // A refused promotion is rendered, not thrown into the void: the daemon
      // minted no case, so the operator needs to know their next keystroke
      // has nowhere to publish to.
      setPromoteError(error instanceof Error ? error.message : String(error));
    } finally {
      setBusy(false);
    }
  }, [busy, caseRef, card, deps]);

  const commit = React.useCallback(
    async (verb: PerchFindingAction) => {
      setArmed(null);
      setBusy(true);
      try {
        await recordFindingVerdict(card, verb, rationale.trim() || null, deps);
      } finally {
        setBusy(false);
        setRationale("");
      }
    },
    [card, deps, rationale],
  );

  const pressVerdict = React.useCallback(
    (verb: PerchFindingAction) => {
      if (!caseRef || busy) return;
      if (armed === verb) {
        void commit(verb);
        return;
      }
      setArmed(verb);
    },
    [armed, busy, caseRef, commit],
  );

  const onKeyDown = React.useCallback(
    (event: React.KeyboardEvent<HTMLFieldSetElement>) => {
      if (event.repeat) return;
      if (event.metaKey || event.ctrlKey || event.altKey || event.shiftKey) {
        return;
      }
      if (keyboardIsElsewhere(event.target)) return;
      const verb = KEY_TO_VERB[event.key.toLowerCase()];
      if (!verb) return;
      event.preventDefault();
      event.stopPropagation();
      if (verb === "promote") {
        void promote();
        return;
      }
      pressVerdict(verb);
    },
    [pressVerdict, promote],
  );

  const retry = React.useCallback(() => {
    void retryFindingFeedback(findingId, deps);
  }, [deps, findingId]);

  return (
    // A `fieldset` rather than a focusable `div`: the group is a grouping, not
    // a widget, and the keyboard already lives on the controls inside it. The
    // bare-key handler sits here and receives what bubbles from whichever
    // control holds focus, which is exactly "while the group has focus" — with
    // no extra tab stop and no non-interactive element pretending to be one.
    <fieldset
      data-testid="perch-finding-actions"
      aria-label="Finding verdict"
      onKeyDown={onKeyDown}
      className="mt-2 flex min-w-0 flex-col gap-1"
    >
      <div className="flex flex-wrap items-center gap-1.5">
        <button
          type="button"
          data-testid="perch-finding-action-promote"
          disabled={busy || caseRef !== null}
          title={
            caseRef ? `Already promoted to case ${caseRef.caseId}` : undefined
          }
          onClick={() => void promote()}
          className="rounded border border-[hsl(var(--perch-border-strong))] px-2 py-0.5 text-2xs uppercase tracking-wide disabled:opacity-50"
        >
          <span aria-hidden="true">E</span> Promote
        </button>
        {VERDICTS.map((verb) => (
          <button
            key={verb}
            type="button"
            data-testid={`perch-finding-action-${verb}`}
            disabled={!caseRef || busy}
            title={caseRef ? undefined : PROMOTE_FIRST}
            aria-describedby={caseRef ? undefined : "perch-promote-first"}
            onClick={() => pressVerdict(verb)}
            className="rounded border border-[hsl(var(--perch-border-strong))] px-2 py-0.5 text-2xs uppercase tracking-wide disabled:opacity-50"
          >
            <span aria-hidden="true">{verbKey(verb)}</span> {verbLabel(verb)}
          </button>
        ))}
      </div>
      {promoteError === null ? null : (
        // The sentence is ours; the message inside it is the daemon's and
        // quotes wire identifiers, so it is railed like every other untrusted
        // string on this card rather than trusted because React escapes HTML.
        <p
          data-testid="perch-finding-promote-error"
          role="status"
          className="flex flex-wrap items-baseline gap-1 text-2xs text-[hsl(var(--perch-foreground))]"
        >
          The daemon did not open a case:{" "}
          <AdversaryString
            field="daemon message"
            value={promoteError}
            cap={PERCH_REASON_CAP}
            layout="inline"
          />
        </p>
      )}
      {caseRef ? null : (
        <p
          id="perch-promote-first"
          data-testid="perch-finding-promote-first"
          className="text-2xs text-[hsl(var(--perch-foreground-muted))]"
        >
          {PROMOTE_FIRST}
        </p>
      )}
      {armed ? (
        <div
          data-testid="perch-finding-rationale-row"
          className="flex flex-col gap-1"
        >
          <label
            htmlFor={`perch-rationale-${findingId}`}
            className="text-2xs uppercase tracking-wide text-[hsl(var(--perch-foreground-muted))]"
          >
            Why {verbLabel(armed).toLowerCase()}? Press {verbKey(armed)} again
            to record.
          </label>
          <textarea
            id={`perch-rationale-${findingId}`}
            data-testid="perch-finding-rationale"
            value={rationale}
            onChange={(event) => setRationale(event.target.value)}
            rows={2}
            className="w-full rounded border border-[hsl(var(--perch-border-strong))] bg-[hsl(var(--perch-surface-raised))] p-1 text-sm"
          />
          <div className="flex gap-1.5">
            <button
              type="button"
              data-testid="perch-finding-record"
              onClick={() => void commit(armed)}
              className="rounded border border-[hsl(var(--perch-border-strong))] px-2 py-0.5 text-2xs uppercase tracking-wide"
            >
              Record {verbLabel(armed).toLowerCase()}
            </button>
            <button
              type="button"
              data-testid="perch-finding-rationale-cancel"
              onClick={() => setArmed(null)}
              className="rounded px-2 py-0.5 text-2xs uppercase tracking-wide text-[hsl(var(--perch-foreground-muted))]"
            >
              Cancel
            </button>
          </div>
        </div>
      ) : null}
      <WriteStateRow
        findingId={findingId}
        state={writeState}
        intentEventId={intent?.verdictEventId ?? null}
        onRetry={retry}
      />
    </fieldset>
  );
}
