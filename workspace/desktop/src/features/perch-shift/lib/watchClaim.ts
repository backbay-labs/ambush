/**
 * The watch claim: who is on shift, as the console understands it.
 *
 * A CLIENT-SIDE PAGING FILTER only. It never changes who is `p`-tagged on a
 * hold — every Approve principal is, always — so a stale or absent claim can
 * only make the console page MORE people, never fewer. That direction is the
 * whole safety argument: a claim that could narrow delivery would be a way to
 * silence a hold by forgetting to renew it.
 *
 * Where the claim is RECORDED is still an open decision; this is the read
 * model, and it is the same under either cheap option.
 */

/** Twelve hours. */
export const PERCH_WATCH_CLAIM_TTL_MS = 43_200_000;

export type WatchClaim = {
  holderPubkey: string;
  holderLabel: string;
  sinceMs: number;
  ttlMs: number;
};

export type WatchClaimState = "none" | "held" | "stale";

export function claimState(
  claim: WatchClaim | null,
  nowMs: number,
): WatchClaimState {
  if (!claim) return "none";
  return nowMs - claim.sinceMs <= claim.ttlMs ? "held" : "stale";
}
