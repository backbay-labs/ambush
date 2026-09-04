import { parseSearchOperators } from "@/features/search/lib/parseSearchOperators";

/**
 * The Ledger's query: four inherited operators plus four of Perch's own.
 *
 * Perch's four are FTS TERMS, not filters. NIP-01 indexes single-letter tags
 * only and these events are signed, so `strategy_id`, `host_id`, `receipt_id`
 * and `lease_id` live inside the card body and are reachable through text
 * search alone. The value therefore stays in the text so it participates in
 * the search; only the operator prefix is stripped.
 */
export type LedgerQuery = {
  text: string;
  from: string | null;
  in: string | null;
  since: number | null;
  until: number | null;
  ftsTerms: { class?: string; action?: string; host?: string; agent?: string };
};

/**
 * Token-START only, never `\b`.
 *
 * A word boundary fires after `-` and `/`, so `built-in:react` would parse as
 * an `in:` operator and silently drop the user's literal text. The inherited
 * parser insists on the same rule for the same reason.
 */
const PERCH_OPERATOR_RE = /(?:^|\s)(class|action|host|agent):(\S+)/gi;

export function buildLedgerQuery(raw: string): LedgerQuery {
  const ftsTerms: LedgerQuery["ftsTerms"] = {};
  let stripped = "";
  let last = 0;
  for (const match of raw.matchAll(PERCH_OPERATOR_RE)) {
    const index = match.index ?? 0;
    stripped += raw.slice(last, index);
    const key = match[1].toLowerCase() as keyof LedgerQuery["ftsTerms"];
    // Trailing punctuation belongs to the sentence, not the identifier.
    const value = match[2].replace(/[.,;:!?]+$/g, "");
    ftsTerms[key] = value;
    stripped += ` ${value}`;
    last = index + match[0].length;
  }
  stripped += raw.slice(last);
  const inherited = parseSearchOperators(stripped);
  return {
    text: inherited.text.replace(/\s+/g, " ").trim(),
    from: inherited.from,
    in: inherited.in,
    since: inherited.since,
    until: inherited.until,
    ftsTerms,
  };
}
