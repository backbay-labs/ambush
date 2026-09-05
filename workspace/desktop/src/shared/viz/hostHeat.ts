import { strengthAt } from "./concentration";
import type { DepositView } from "./types";

/**
 * Per-host concentration, summed by this console.
 *
 * THE RUNTIME HAS NO PER-HOST CONCENTRATION. The substrate concentrates by
 * threat class, and this sum is the console's own reduction over the deposits
 * it was served. Every rendering of it carries a derived marker, because an
 * operator reading a number the daemon would not agree with must know which
 * one they are reading.
 */

export type HostHeatRow = {
  host: string;
  strength: number;
  depositCount: number;
  sourceIds: string[];
  dominantThreatClass: string;
  /** True for the one row that gathers deposits carrying no host. */
  unattributed: boolean;
};

const UNATTRIBUTED = "host unattributed";

function hostOf(deposit: DepositView): string | null {
  const indicator = deposit.indicator as { host_id?: unknown };
  return typeof indicator.host_id === "string" && indicator.host_id.length > 0
    ? indicator.host_id
    : null;
}

/**
 * Rows sorted by strength, with the unattributed row ALWAYS last.
 *
 * The unattributed row is not sorted into place because it is not a host: it
 * is a statement about the console's own visibility, and letting it sit at the
 * top of a sorted list would read as "this host is the hottest".
 */
export function hostHeatRows(
  deposits: readonly DepositView[],
  now: number,
): HostHeatRow[] {
  const byHost = new Map<string, DepositView[]>();
  for (const deposit of deposits) {
    const host = hostOf(deposit) ?? UNATTRIBUTED;
    const bucket = byHost.get(host);
    if (bucket) bucket.push(deposit);
    else byHost.set(host, [deposit]);
  }

  const rows: HostHeatRow[] = [];
  for (const [host, hostDeposits] of byHost) {
    const classCounts = new Map<string, number>();
    let strength = 0;
    for (const deposit of hostDeposits) {
      strength += strengthAt(deposit, now);
      classCounts.set(
        deposit.threat_class,
        (classCounts.get(deposit.threat_class) ?? 0) + 1,
      );
    }
    // Ties break on the class name so the label is stable between renders; a
    // dominant class that flickers between two equals reads as movement.
    const dominantThreatClass = [...classCounts.entries()].sort(
      (a, b) => b[1] - a[1] || a[0].localeCompare(b[0]),
    )[0][0];
    rows.push({
      host,
      strength,
      depositCount: hostDeposits.length,
      sourceIds: hostDeposits.map((d) => d.agent_id),
      dominantThreatClass,
      unattributed: host === UNATTRIBUTED,
    });
  }

  rows.sort((a, b) => {
    if (a.unattributed !== b.unattributed) return a.unattributed ? 1 : -1;
    return b.strength - a.strength || a.host.localeCompare(b.host);
  });
  return rows;
}

/** The unattributed row's own label, which names how many deposits it covers. */
export function unattributedLabel(row: HostHeatRow): string {
  return `${UNATTRIBUTED} · no host_id on ${row.depositCount} deposit${row.depositCount === 1 ? "" : "s"}`;
}
