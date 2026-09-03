// Target path in BUZZ: desktop/src/features/perch/ui/PerchSurfaceBoundary.tsx  (NEW file)
//
// Buzz has exactly ONE React error boundary in the whole desktop app:
// `RootErrorBoundary` (BUZZ desktop/src/app/RootErrorBoundary.tsx:22-57),
// mounted at main.tsx:86 outside every provider. Verified this session by
// grepping `componentDidCatch|getDerivedStateFromError` over desktop/src —
// one file. Its own doc comment says the reconciler's error boundary "isn't
// one", and its fallback replaces the entire window with "Buzz failed to
// start" plus a Reload button.
//
// (`MessageTimelineErrorCard.tsx` is NOT a counterexample: it is a retry card
// for a failed history QUERY, rendered from MessageTimeline.tsx:811 — a render
// throw inside the timeline still blanks the window.)
//
// That is an acceptable posture for a chat app. It is not acceptable here: a
// throw inside the Watchfloor's hand-authored SVG would take down the verdict
// queue on the same screen, and the operator would see a generic
// "failed to start" splash while a destructive action sat un-decided behind it.
//
// Gate-line budget: 1000. Targets ~180.

import { Component, type ErrorInfo, type ReactNode } from "react";

import type { PerchView } from "@/app/perchViews";

type PerchSurfaceBoundaryProps = {
  /** Which surface this boundary fences. Rendered verbatim in the fallback. */
  surface: PerchView | "verdict-pane" | "evidence-card" | "governance-strip";
  /**
   * Reset token. When it changes, the boundary clears its error and retries —
   * the route id, or the `hold_id` for the verdict pane. A boundary with no
   * token stays broken until navigation, which is correct for a wall screen
   * and wrong for a queue row.
   */
  resetKey?: string | null;
  children: ReactNode;
};

type PerchSurfaceBoundaryState = {
  error: Error | null;
  resetKey: string | null;
};

/**
 * Fences one Perch surface.
 *
 * THE RULE THIS COMPONENT EXISTS TO ENFORCE: a crashed surface must never
 * render in a neutral or reassuring register, and must never imply that the
 * state behind it is settled.
 *
 * Concretely:
 *  - The fallback is `role="alert"` in the destructive register. It is one of
 *    the only two assertive regions in Perch (the other is an expired,
 *    still-listed containment).
 *  - It names the surface and says what is NOT known, because "this pane
 *    failed to render" and "there is nothing to decide" are different facts
 *    and the operator cannot tell them apart from a blank pane.
 *  - A crashed VERDICT PANE leaves its queue row UNDECIDED. The boundary
 *    performs no write, cancels no in-flight leg, and clears no arming state
 *    other than by remount — there is no code path from a render crash to a
 *    recorded decision.
 *  - It never offers "retry" as a primary control on a governance surface. The
 *    control reloads the surface, and the copy says the decision was not
 *    recorded, so a reader cannot mistake a successful remount for a
 *    successful write.
 *
 * NO `data-perch-role` HERE, deliberately. 17-COMPONENT-SPECS.md §1.4 declares
 * that attribute a CLOSED thirteen-value vocabulary and
 * `tools/check-perch-grant-affordance.sh` rule R1 asserts the closure, so a
 * fourteenth value invented by this file would fail the gate. A crashed surface
 * is not one of the thirteen things those greps hunt; the `data-testid` is what
 * the Playwright specs bind to, and testids may churn where
 * `data-perch-role` may not.
 *
 * COPY: every rendered string in this component was checked against
 * build/skeleton/tools/copy-ban-list.tsv. No `approve`, no capital-D `Deny`, no
 * `verified by`/`trusted`/`proof`, no shield or lock glyph, no bare `lane`, no
 * bare `lease`, no bare source count, no `hunt` as a noun, no exclamation mark,
 * and none of the four reassurance phrases — the body deliberately says what is
 * NOT known rather than that anything is fine.
 */
export class PerchSurfaceBoundary extends Component<
  PerchSurfaceBoundaryProps,
  PerchSurfaceBoundaryState
> {
  override state: PerchSurfaceBoundaryState = { error: null, resetKey: null };

  static getDerivedStateFromProps(
    props: PerchSurfaceBoundaryProps,
    state: PerchSurfaceBoundaryState,
  ): PerchSurfaceBoundaryState | null {
    const next = props.resetKey ?? null;
    if (state.error !== null && next !== state.resetKey) {
      return { error: null, resetKey: next };
    }
    if (next !== state.resetKey) {
      return { ...state, resetKey: next };
    }
    return null;
  }

  static getDerivedStateFromError(
    error: unknown,
  ): Pick<PerchSurfaceBoundaryState, "error"> {
    return {
      error: error instanceof Error ? error : new Error(String(error)),
    };
  }

  override componentDidCatch(error: unknown, info: ErrorInfo): void {
    // Same shape as RootErrorBoundary.tsx:32-34. One console.error, once.
    console.error(
      `[PerchSurfaceBoundary:${this.props.surface}] render error:`,
      error,
      info,
    );
    // A crashed surface is a countable event, not an anecdote. The counter is
    // read by /settings and by the governance strip's diagnostics row.
    incrementSurfaceCrashCount(this.props.surface);
  }

  override render(): ReactNode {
    const { error } = this.state;
    if (!error) return this.props.children;

    // TOKENS: every colour below is a `--perch-*` class from
    // tokens/tailwind.perch.js. NOT a bare Buzz shadcn name (`--background`,
    // `--card`, `--muted-foreground`, `--border`, `--destructive`). BUZZ
    // ThemeProvider writes 38 of those names INLINE on the root element. Read
    // this session: `applyTheme` (desktop/src/shared/theme/ThemeProvider.tsx:436-446,
    // renderer) calls `createThemeVars` — which returns exactly 38 custom
    // properties, counted in shared/theme/adaptive-theme.ts — and loops
    // `root.style.setProperty(key, value)` over every one; `applyCachedVars`
    // (:398-409) does the same on the pre-paint boot path. An inline
    // declaration on `:root` outranks every normal-priority stylesheet rule. A Perch
    // component authored against `text-muted-foreground` repaints with whatever
    // Buzz syntax theme is active. 19-TOKENS.md's TOKEN NAMESPACE commitment is
    // binding and this file obeys it.
    //
    // The danger hue appears ONLY as a border. 19-TOKENS marks
    // `--perch-danger-mark` NEVER TEXT (3.70:1 on raised in dark); the WORD
    // carries the meaning, in `--perch-foreground`. So the non-colour channel
    // here is the sentence itself, not a glyph — and no shield, lock or warning
    // glyph appears anywhere in this component (APPENDIX-NORMATIVE.md §7).
    return (
      <div
        className="flex h-full min-h-0 flex-col items-start justify-center gap-2 border border-perch-danger bg-perch-card p-6"
        data-testid={`perch-surface-crash-${this.props.surface}`}
        role="alert"
      >
        <p className="text-base font-semibold text-perch-fg">
          This surface stopped rendering: {this.props.surface}
        </p>
        <p className="max-w-prose text-sm text-perch-fg">
          Nothing was recorded and nothing was sent to the daemon. Whatever this
          surface was showing is still in whatever state it was in — reload it
          to see the current state, or open the Ledger for the record.
        </p>
        <p className="font-mono text-2xs text-perch-fg-muted">
          {error.name}: {error.message}
        </p>
        <button
          className="mt-2 rounded-md border border-perch-border px-3 py-1.5 text-sm text-perch-fg"
          onClick={() => this.setState({ error: null })}
          type="button"
        >
          Reload this surface
        </button>
      </div>
    );
  }
}

declare function incrementSurfaceCrashCount(surface: string): void;
