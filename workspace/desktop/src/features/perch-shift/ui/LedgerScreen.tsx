import * as React from "react";

import { buildLedgerQuery, type LedgerQuery } from "../lib/ledgerQuery";

export type LedgerRow = {
  eventId: string;
  atMs: number;
  summary: string;
};

export type LedgerScreenProps = {
  /** Seeded from `?q=`, which the omnibox sets. */
  initialQuery?: string;
  /** Rows the relay returned for the last executed query, or null before one. */
  rows: LedgerRow[] | null;
  onSearch: (query: LedgerQuery) => void;
};

/**
 * S9, `/ledger`. Everything the record holds, searchable.
 *
 * The query box parses `class:`, `action:`, `host:` and `agent:` at token
 * START only. A word boundary fires after `-` and `/`, so `built-in:react`
 * would parse as an operator and silently drop the operator's literal text —
 * the worst failure a search box can have, because the results look fine.
 *
 * Before a search runs the screen shows nothing rather than a default result
 * set: "these are all the events" and "these are the events matching an empty
 * query" are different claims, and only one of them is one this screen can
 * make.
 */
export function LedgerScreen({
  initialQuery = "",
  rows,
  onSearch,
}: LedgerScreenProps): React.ReactElement {
  const [raw, setRaw] = React.useState(initialQuery);
  const parsed = React.useMemo(() => buildLedgerQuery(raw), [raw]);
  const operators = Object.entries(parsed.ftsTerms);

  return (
    <section data-testid="perch-ledger" className="p-4">
      <h2 className="text-base font-medium">Ledger</h2>
      <form
        className="mt-2 flex gap-2"
        onSubmit={(event) => {
          event.preventDefault();
          onSearch(parsed);
        }}
      >
        <input
          data-testid="perch-ledger-query"
          className="flex-1 rounded border border-border px-2 py-1 text-sm"
          value={raw}
          placeholder="class:execution host:web-04 isolate"
          onChange={(event) => setRaw(event.target.value)}
        />
        <button
          type="submit"
          className="rounded border border-border px-2 py-1 text-sm"
        >
          Search
        </button>
      </form>

      {operators.length > 0 ? (
        <p
          data-testid="perch-ledger-operators"
          className="mt-1 text-xs text-muted-foreground"
        >
          {operators.map(([key, value]) => `${key}:${value}`).join(" · ")}
          {parsed.text.trim().length > 0
            ? ` · text "${parsed.text.trim()}"`
            : null}
        </p>
      ) : null}

      {rows === null ? (
        <p data-testid="perch-ledger-idle" className="mt-3 text-sm">
          No search has run. This is not an empty record.
        </p>
      ) : rows.length === 0 ? (
        <p data-testid="perch-ledger-empty" className="mt-3 text-sm">
          Nothing in the record matches this query. The record may still hold
          events this query does not reach.
        </p>
      ) : (
        <ul className="mt-3 space-y-1">
          {rows.map((row) => (
            <li key={row.eventId} className="text-xs">
              <span className="font-mono">{row.eventId.slice(0, 8)}</span>
              {" · "}
              {new Date(row.atMs).toISOString()}
              {" · "}
              {row.summary}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
