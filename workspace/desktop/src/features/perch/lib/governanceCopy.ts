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
