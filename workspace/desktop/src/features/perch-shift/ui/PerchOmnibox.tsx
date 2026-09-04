import * as React from "react";
import { useNavigate } from "@tanstack/react-router";

import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/shared/ui/dialog";

import {
  matchCommand,
  parseOmniboxInput,
  PERCH_COMMANDS,
  type OpenableSurface,
} from "../lib/omniboxCommands";

/** Where each openable surface lives. `watch` is the root. */
const SURFACE_ROUTES: Record<OpenableSurface, string> = {
  watch: "/",
  leases: "/leases",
  policy: "/policy",
  watchfloor: "/watch-floor",
  ledger: "/ledger",
  tuning: "/tuning",
  handoff: "/handoff",
  gaps: "/gaps",
  settings: "/settings",
};

export type PerchOmniboxProps = {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** Run a query. The omnibox itself never searches. */
  onQuery: (text: string) => void;
};

/**
 * The ⌘K omnibox.
 *
 * It emits an INTENT and never performs a write. `release containment` does
 * not release anything: it navigates to Containments with the row focused, and
 * the daemon is asked from that surface, behind that surface's confirmation.
 * A destructive verb one keystroke from every screen is exactly what the
 * render laws forbid, and the registry has no `run` field so a command
 * physically cannot become an un-audited write path beside the allowlisted
 * five.
 *
 * Every match shows its CONSEQUENCE before the operator commits. A command
 * palette whose entries do not say what they do is a palette people learn by
 * pressing things.
 */
export function PerchOmnibox({
  open,
  onOpenChange,
  onQuery,
}: PerchOmniboxProps): React.ReactElement {
  const navigate = useNavigate();
  const [raw, setRaw] = React.useState("");

  const parsed = parseOmniboxInput(raw);
  const match =
    parsed.mode === "command"
      ? matchCommand(parsed.body, PERCH_COMMANDS)
      : null;

  const reset = React.useCallback(() => {
    setRaw("");
    onOpenChange(false);
  }, [onOpenChange]);

  const submit = React.useCallback(() => {
    if (parsed.mode === "query") {
      if (parsed.body.trim().length === 0) return;
      onQuery(parsed.body);
      reset();
      return;
    }
    if (!match) return;
    if (match.spec.effect.kind === "navigate") {
      void navigate({ to: SURFACE_ROUTES[match.spec.effect.view] });
      reset();
      return;
    }
    // The write is REQUESTED, never performed: Containments opens with the
    // lease in focus and its own confirmation still in front of the daemon.
    void navigate({
      to: SURFACE_ROUTES.leases,
      search: { lease: match.args[0] },
    });
    reset();
  }, [match, navigate, onQuery, parsed, reset]);

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent data-testid="perch-omnibox">
        <DialogHeader>
          <DialogTitle>Search or command</DialogTitle>
          <DialogDescription>
            Type to search the record. Start with <code>&gt;</code> for a
            command.
          </DialogDescription>
        </DialogHeader>

        <input
          data-testid="perch-omnibox-input"
          aria-label="Search or command"
          className="w-full rounded border border-border px-2 py-1 text-sm"
          value={raw}
          onChange={(event) => setRaw(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === "Enter") {
              event.preventDefault();
              submit();
            }
          }}
        />

        <p
          data-testid="perch-omnibox-mode"
          data-mode={parsed.mode}
          className="text-xs text-muted-foreground"
        >
          {parsed.mode === "command"
            ? "command"
            : "search — `>` is a command only as the first character, so `strength > 2` stays a search"}
        </p>

        {parsed.mode === "command" ? (
          match ? (
            <p data-testid="perch-omnibox-consequence" className="text-sm">
              {match.spec.consequence}
            </p>
          ) : (
            <p data-testid="perch-omnibox-no-match" className="text-sm">
              No command matches. Two exist:{" "}
              {PERCH_COMMANDS.map((spec) => spec.verb).join(", ")}.
            </p>
          )
        ) : null}
      </DialogContent>
    </Dialog>
  );
}
