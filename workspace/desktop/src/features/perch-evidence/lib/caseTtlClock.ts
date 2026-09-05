/**
 * A case's archive deadline as a wall clock, never a bar.
 *
 * A progress bar implies the number behind it is a proportion of something
 * known and steady. This one is neither: the relay's TTL refresh can fail and
 * is downgraded to a warning, so a case can archive under an active
 * investigation and the deadline can move without warning. A clock reading
 * plus the caveat is the honest rendering; a bar draining smoothly toward zero
 * asserts a schedule nothing guarantees.
 */

export const CASE_TTL_CAVEAT =
  "a failed TTL refresh is downgraded to a warning, so a case can archive under an active investigation; open cases are read from the daemon";

export type CaseTtlReading =
  | { kind: "none" }
  | { kind: "archived"; atLabel: string }
  | { kind: "due"; atLabel: string; inLabel: string };

function hhmm(ms: number): string {
  const d = new Date(ms);
  return `${String(d.getUTCHours()).padStart(2, "0")}:${String(d.getUTCMinutes()).padStart(2, "0")}`;
}

/** `5h 12m`, `12m`, and `0m` — never a negative duration. */
export function remainingLabel(ms: number): string {
  const total = Math.max(0, Math.floor(ms / 60_000));
  const hours = Math.floor(total / 60);
  const minutes = total % 60;
  return hours > 0 ? `${hours}h ${minutes}m` : `${minutes}m`;
}

/**
 * Read the deadline.
 *
 * `null` is `none`, not "no deadline soon": a channel with no TTL is not
 * scheduled to archive at all, and rendering it as a very distant deadline
 * would invent one. A deadline already past reads `archived`, because the
 * clock cannot tell whether the sweep has run and must not imply it has not.
 */
export function readCaseTtl(
  ttlDeadline: string | null,
  nowMs: number,
): CaseTtlReading {
  if (ttlDeadline === null) return { kind: "none" };
  const deadlineMs = Date.parse(ttlDeadline);
  if (Number.isNaN(deadlineMs)) return { kind: "none" };
  if (deadlineMs <= nowMs) {
    return { kind: "archived", atLabel: hhmm(deadlineMs) };
  }
  return {
    kind: "due",
    atLabel: hhmm(deadlineMs),
    inLabel: remainingLabel(deadlineMs - nowMs),
  };
}
