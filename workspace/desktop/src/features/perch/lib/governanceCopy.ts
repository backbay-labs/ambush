/**
 * Every rendered string on the governance strip.
 *
 * "committee of 1 (solo transport)" and never a fraction: `1/1` reads as
 * redundancy that is not there, and the transport is the fact that matters.
 */
export const GOVERNANCE = {
  healthy:
    "GOVERNANCE healthy · committee of 1 (solo transport) · recv {ago} ago",
  degraded:
    "GOVERNANCE degraded · committee of 1 (solo transport) · recv {ago} ago",
  partitioned:
    "GOVERNANCE PARTITIONED · destructive response runs only under contingency leases · recv {ago} ago",
  healing:
    "GOVERNANCE HEALING · reconciling partition-era activity · {unauthorized} unauthorized partition actions · recv {ago} ago",
  failClosed:
    "GOVERNANCE committee of {n} · no networked transport · destructive response FAILS CLOSED — every destructive action will be vetoed until a transport is installed",
  stale:
    "GOVERNANCE last frame {ago} ago · the strip is showing a stale snapshot, not the current state",
  bridgeDown:
    "bridge: down (last envelope {lastSeen}) · holds may not be reaching the console",
  shedding:
    "bridge is shedding the evidence stream to protect the alarm stream",
  mode: {
    normal: "mode normal",
    alert: "mode ALERT",
    incident: "mode INCIDENT",
  },
  modeDown: "de-escalated to {mode} · the daemon named no threat class",
  cooldown: "cooldown {seconds}s",
  watchHeld: "watch held by {holder} since {since}",
  watchStale:
    "watch claim by {holder} is stale ({ago} old) — classes 1–3 page everyone",
  watchNone: "no watch claimed — classes 1–3 page everyone",
  derived: "derived · derivePerchGovernanceMode()",
} as const;

/**
 * Substitute every `{name}`, and THROW on one the values do not cover.
 *
 * The sibling copy modules leave an unfilled placeholder visible; this one
 * refuses to. A raw `{lastSeen}` on the strip was found-1 — the one line on
 * screen wherever the console is, reading as an un-rendered template — so a
 * value the strip forgot to supply is a defect a unit test catches, not a
 * string that ships.
 */
export function fillGovernanceCopy(
  template: string,
  values: Record<string, string | number>,
): string {
  return template.replace(/\{(\w+)\}/g, (_whole, name: string) => {
    if (!(name in values)) {
      throw new Error(
        `governance copy has no value for {${name}}: a rendered placeholder is a defect`,
      );
    }
    return String(values[name]);
  });
}

/**
 * How long ago the newest frame arrived, in the strip's register.
 *
 * The strip is read at a glance and from across a room, so age is coarse and
 * self-labelling: whole seconds under a minute, minutes-and-seconds under an
 * hour, hours-and-minutes beyond. `ageMs` is a non-negative age — the strip
 * clamps a future-dated frame to zero before it calls.
 */
export function formatGovernanceAge(ageMs: number): string {
  const totalSeconds = Math.floor(ageMs / 1000);
  if (totalSeconds < 60) return `${totalSeconds}s`;
  const minutes = Math.floor(totalSeconds / 60);
  if (minutes < 60) return `${minutes}m ${totalSeconds % 60}s`;
  return `${Math.floor(minutes / 60)}h ${minutes % 60}m`;
}
