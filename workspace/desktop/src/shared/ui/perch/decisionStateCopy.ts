// The sentences the two-legged write renders, kept out of the component so the
// state machine can own one sentence per phase and a unit test can assert the
// exact words without a DOM.
//
// found-14: a failed leg 1 used to borrow `daemon-unreachable`'s copy, which
// asserts the decision was recorded and that the daemon did not answer. Both
// are false when the intent card never published, so the failure gets its own
// register: nothing was written, and the daemon was never asked.

/**
 * The single honest sentence for a leg-1 failure. `reason` is the raw failure
 * the relay or bridge reported, rendered verbatim — never wrapped in a second
 * "the daemon…" clause, which is the register this sentence exists to refuse.
 */
export function failedToRecordSentence(reason: string): string {
  return `Nothing was recorded: ${reason}. The daemon was not asked.`;
}
