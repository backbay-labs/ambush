/**
 * Handoff copy.
 *
 * Two substitutions against the drafted wording, both forced by the copy gate
 * and both improvements: the engine's `OperatorScope::Approve` is a typed wire
 * value, not a word this product says to a person, so the rendered phrase is
 * "every operator who can decide a hold" — which is also what the reader
 * actually needs to know. And the containment pointer names the board rather
 * than embedding a route in a sentence.
 *
 * The publish strings changed shape for a third reason (W3-36): there is no
 * daemon-side shift record to promise. `POST /v1/operator/review/sessions`
 * refuses a session with no artifact refs and resolves every ref it is given
 * against the review workbench's own evidence stores, and a case channel is not
 * one of those. So the handoff goes to the case channels, and the copy says so
 * rather than naming a session id that was never minted.
 */
export const HANDOFF = {
  title: "Handoff",
  takeCta: "Take the watch",
  endCta: "End watch and publish handoff",
  noClaim: {
    title: "No watch is claimed",
    body: "Classes 1–3 page every operator who can decide a hold until someone takes the watch.",
    actionLabel: "Take the watch",
  },
  claimHeld: "Watch held by {holder} since {since}",
  claimStale:
    "Watch claim by {holder} is {ago} old and stale. Paging has fallen back to everyone.",
  claimDoesNot:
    "Taking the watch does not change who is p-tagged on a hold — every operator who can decide one gets the row in their queue. It only decides whose workstation pages for classes 1–3.",
  claimUndecided:
    "Where the claim is recorded is not yet decided. Until it is, this panel renders the read model and offers no take control.",
  takeover:
    "Taking a held watch overwrites the claim and records both times. Nothing gates it; it is logged.",
  blocked:
    "{n} holds expired undecided this shift. End watch is disabled until each is acknowledged below. Acknowledging changes nothing about the hold.",
  ackRow:
    "Expired undecided after {minutes}m. Nothing ran. The finding is still open.",
  ackCta: "Acknowledge",
  published: "Handoff published to {n} case channels.",
  publishFailed:
    "Handoff published to {published} of {n} case channels. {failed} did not accept it; the block is below, unchanged, to post by hand.",
  noDaemonRecord:
    "This block is published to the case channels and nowhere else. The daemon keeps no shift record.",
} as const;

/** Substitute `{name}` placeholders. An unknown key is left visible, not blanked. */
export function fillHandoff(
  template: string,
  values: Record<string, string | number>,
): string {
  return template.replace(/\{(\w+)\}/g, (whole, key: string) =>
    key in values ? String(values[key]) : whole,
  );
}
