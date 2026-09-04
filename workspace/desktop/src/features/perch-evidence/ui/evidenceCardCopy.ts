/**
 * Rendered copy for the evidence card frame.
 *
 * This is a copy module on purpose, not a stylistic choice. The copy gate
 * (`tools/check-copy-banned-terms.sh`) reads a `*Copy.ts` file in `copy` mode,
 * which extracts every string literal; it reads a `.tsx` component in `markup`
 * mode, which extracts only four attribute values, six object field names and
 * JSX text nodes. A bare `export const X = "..."` is none of those, so while
 * these strings lived in `EvidenceCardFrame.tsx` no ban row could judge them --
 * including the tier badge, the one literal the plan mandates verbatim.
 *
 * Put a rendered literal here, and the vocabulary bans apply to it.
 */

/**
 * The only verification claim a tier-0 card may make, verbatim. It names the
 * chain that was checked (the relay's transport signature), says what was not,
 * and points at the record. Never "verified", never a check mark.
 *
 * If anyone ever adds a flat `signed` or `verified` row to
 * `tools/copy-ban-list.tsv`, its exemption has to be written in the SAME
 * change: this string contains the substring `SIGNED`, and a naive
 * word-bounded row fires on it. Measured, not assumed. The exemption must be
 * anchored to the whole string so it exempts this badge and never a sentence
 * that merely contains it.
 */
export const TIER_0_BADGE =
  "secp256k1 · tier 0 · TRANSPORT-SIGNED ONLY · the daemon is the record";
