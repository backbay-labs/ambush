// THE ROW KEYMAP, AS DATA.
//
// THE KEYMAP IS DATA. That is 17-COMPONENT-SPECS.md section 6.1's commitment and
// it is what makes INV-31 and INV-32 table tests over a registry rather than UI
// crawls over whichever list a spec happened to open. Two consumers read this
// file:
//
//   - `perchKeymapRegistry.test.mjs` (its sibling), which asserts the appendix
//     section 2 keymap is bound as ratified;
//   - `tools/check-copy-banned-terms.sh`'s keymap pass, which parses the
//     `PERCH_BINDINGS` array LEXICALLY from the Ambush side, because
//     APPENDIX-NORMATIVE.md section 2 names that script as INV-31's enforcer.
//     Its parser is `sed -n '/PERCH_BINDINGS/,/^];/p' | tr '{' '\n'` over a flat
//     array of flat objects, so KEEP THE SHAPE FLAT: one object per binding, no
//     nesting, `key:` and `verb:` as double-quoted literals on the object. A
//     nested object parses to an entry with no `key:` and is ignored, which the
//     gate's own fixture proves -- but a `verb` behind a helper call would be
//     invisible to it, and INV-31 would go quiet.
//
// WHY THIS FILE SHIPS WITH ITS TEST
//   The review found `perchKeymapRegistry.test.mjs` importing `./perchKeymapRegistry.ts`
//   from an artifact set that did not contain it: `node --test` exited
//   ERR_MODULE_NOT_FOUND, and the "8/8 green" figure had been measured against a
//   local file nobody shipped. A test whose subject is missing is not a weaker
//   test, it is no test. The registry is the ratified keymap from
//   APPENDIX-NORMATIVE.md section 2 -- data, not an implementation choice -- so
//   shipping it here costs nothing and makes the assertion runnable.
//   17-COMPONENT-SPECS.md owns the TYPE declaration and the `usePerchKeymap`
//   hook; this file is the VALUE, and if 17 revises the field names this file is
//   the one to reconcile.
//
// LANDED in The hold Task 26, transcribed unchanged from the ratified skeleton.
// Every value below comes from APPENDIX-NORMATIVE.md section 2, which is
// normative; nothing here is invented. `usePerchKeymap` in the sibling
// directory is the one consumer that acts on it.

/** The five row types a Perch list can carry. */
export type PerchRowType = "finding" | "hold" | "case" | "lane" | "containment";

/**
 * The five verdict verbs. APPENDIX-NORMATIVE.md section 2 names exactly these,
 * and INV-32 is "no key is bound to two of them".
 *
 * `refuse` (operator) / `deny` (policy) / `veto` (governance) are three actors
 * and three typed words (appendix section 7); only the operator's appears here,
 * because only the operator presses a key.
 */
export type PerchVerdictVerb =
  | "confirm"
  | "dismiss"
  | "investigate"
  | "grant"
  | "refuse";

export type PerchBinding = {
  /** A single character, or the literal `Enter` / `Escape`. */
  readonly key: string;
  /** Row types on which the binding is OFFERED and enabled. */
  readonly rowTypes: readonly PerchRowType[];
  /**
   * Row types on which the binding is rendered DISABLED with a stated reason.
   * INV-34: a control that is absent teaches nothing; a control that is present,
   * disabled and states why teaches the rule once.
   */
  readonly disabledOn?: readonly PerchRowType[];
  /** Present iff the binding records a verdict. INV-31 and INV-32 read this. */
  readonly verb?: PerchVerdictVerb;
  /** The rendered key hint. Never empty. */
  readonly meaning: string;
};

/**
 * APPENDIX-NORMATIVE.md section 2, transcribed. The appendix is where the value
 * lives; this is the machine-readable copy, and the sibling test pins the five
 * verdict pairs so a silent re-map cannot happen without reading as a brief
 * amendment in the diff.
 *
 * `A` IS ABSENT ON PURPOSE and its absence is asserted, not assumed: `A` is
 * banned as a verdict key because the key survives a relabelled button, which is
 * the failure render law 6 exists to prevent.
 *
 * `Cmd-K` and the terminal chord are global bindings, not row bindings, and are
 * deliberately not in this array -- it is the ROW keymap. A global chord in here
 * would give INV-32 a key with no row type to reason about.
 */
export const PERCH_BINDINGS: readonly PerchBinding[] = [
  { key: "C", rowTypes: ["finding"], verb: "confirm", meaning: "Confirm" },
  {
    key: "D",
    rowTypes: ["finding"],
    verb: "dismiss",
    meaning: "Dismiss — two-stage",
  },
  {
    key: "I",
    rowTypes: ["finding"],
    verb: "investigate",
    meaning: "Investigate",
  },
  {
    key: "G",
    rowTypes: ["hold"],
    verb: "grant",
    meaning: "Arms the grant; Enter records it",
  },
  {
    key: "R",
    rowTypes: ["hold"],
    verb: "refuse",
    meaning: "Refuse — one keypress, no dialog, no undo",
  },
  {
    key: "S",
    rowTypes: ["finding", "case"],
    disabledOn: ["hold"],
    meaning: "Snooze",
  },
  {
    key: "E",
    rowTypes: ["finding", "hold", "lane"],
    meaning: "Promote to a case",
  },
  {
    key: "J",
    rowTypes: ["finding", "hold", "case", "lane", "containment"],
    meaning: "Move selection down",
  },
  {
    key: "K",
    rowTypes: ["finding", "hold", "case", "lane", "containment"],
    meaning: "Move selection up",
  },
  {
    key: "M",
    rowTypes: ["finding", "hold", "case", "lane", "containment"],
    meaning: "Mark done — local only, never a decision record",
  },
  {
    key: "U",
    rowTypes: ["finding", "hold", "case", "lane", "containment"],
    meaning: "Mark unread — local only, never a decision record",
  },
  { key: "Enter", rowTypes: ["case", "lane", "containment"], meaning: "Open" },
];
