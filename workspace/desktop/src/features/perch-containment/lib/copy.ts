/**
 * Every rendered string on the Containments board.
 *
 * In a module so the copy gate scans them: a literal inlined in a component is
 * one the ban list cannot reach. "containment lease" is always spelled out —
 * a bare "lease" reads as a rental agreement to anyone who has not read the
 * design.
 */
export const CONTAINMENT = {
  open: "Open · {remaining} remaining",
  expiringSoon: "Open · {remaining} remaining · releases automatically",
  expired: "EXPIRED — {host} may still be contained",
  expiredBody:
    "This containment lease passed its expiry {ago} ago and is still listed as open. remaining_ms saturates at zero, so “0s” and “expired” are two separate facts and this is the second one. The sweep tried and failed. Nothing will release {host} without you.",
  attemptsUnknown:
    "last attempt: — (the runtime does not report attempt counts)",
  releaseConfirmTitle: "Release containment on {host}?",
  releaseConfirmBody:
    "The daemon runs {inverseKind} against {target} and co-signs the release on the governance chain. If the inverse fails, the containment lease stays open and the response reports lease_closed: false.",
  releaseConfirmCta: "Ask the daemon to release",
  releasedClosed:
    "Released. lease_closed: true · fully_reversed: {fullyReversed}",
  releasedNotClosed:
    "NOT RELEASED. The daemon returned 200 but lease_closed: false — the inverse failed and the containment is still in effect. The next sweep will retry.",
  releasedUnattested:
    "Released, UNATTESTED. No governor was available to co-sign. The release proceeded because refusing to undo a containment over a bookkeeping failure inverts the safety argument. The receipt says so plainly.",
  daemonDownOpen:
    "Early release needs the running daemon. The TTL is the only backstop; this containment lease self-releases at {expiresAt}.",
  daemonDownExpired:
    "Early release needs the running daemon. The TTL has already passed and the sweep already failed. This will not clear on its own.",
  extendDisabled:
    "A containment lease cannot be extended. Request the action again to open a new containment lease with its own receipt.",
  noStore: {
    title: "No containment lease store is configured",
    body: "runtime.containment.lease_store_path is unset. A granted quarantine_file, suspend_process, isolate_host or terminate_user_session is refused at the decide route; the other eight destructive actions are unaffected.",
  },
  none: {
    title: "No open containments",
    body: "Nothing is currently isolated, quarantined or suspended. {n} destructive actions ran in this window without a hold. Expired containment leases are released by the sweep and appear in the Ledger.",
    action: {
      label: "Search released containments",
      href: "/ledger?q=swarm:lease",
    },
  },
} as const;

/**
 * One entry per `RollbackStepStatus`. Each says what happened to the WORLD,
 * because four of the five are ways a step can finish without restoring
 * anything, and a list that rendered them all as "done" would be lying by
 * omission.
 */
export const ROLLBACK_STATUS = {
  reversed: {
    label: "Reversed",
    body: "The inverse ran against the real target and succeeded.",
  },
  simulated: {
    label: "Simulated",
    body: "The inverse was rehearsed. No real target was touched, so nothing was restored.",
  },
  irreversible: {
    label: "Irreversible",
    body: "No inverse exists for this step. The world was not restored and no adapter can restore it.",
  },
  unsupported: {
    label: "Unsupported",
    body: "The configured adapter cannot execute this inverse.",
  },
  failed: {
    label: "Failed",
    body: "The inverse was attempted against a real target and failed.",
  },
} as const;

export const ROLLBACK_SUMMARY = {
  fullyReversed: "Fully reversed — every step reported Reversed.",
  /**
   * The daemon did not report `fully_reversed`. Not "partially reversed":
   * that is a finding, and a finding must come from the daemon or not at all.
   */
  reversalNotReported:
    "The daemon did not report whether the reversal completed. The steps above are what it did say.",
  notFullyReversed:
    "Not fully reversed. {n} of {total} steps: {breakdown}. fully_reversed() requires every step to be Reversed; Simulated and Irreversible do not count.",
} as const;
