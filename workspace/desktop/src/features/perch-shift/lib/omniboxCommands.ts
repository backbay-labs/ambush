/**
 * The omnibox's command registry.
 *
 * `run` is deliberately NOT part of a command. The omnibox emits an INTENT and
 * the surface that owns the write performs it, so a command can never become
 * an un-audited write path beside the allowlisted five. A destructive verb one
 * keystroke from every surface is exactly what the render laws forbid.
 */

/** The surfaces `open` will navigate to. Not the same set as card views. */
export const OPENABLE_SURFACES = [
  "watch",
  "leases",
  "policy",
  "watchfloor",
  "ledger",
  "tuning",
  "handoff",
  "gaps",
  "settings",
] as const;

export type OpenableSurface = (typeof OPENABLE_SURFACES)[number];

export type PerchOmniboxMode = "query" | "command";

export type PerchCommandSpec = {
  verb: string;
  args: readonly string[];
  effect:
    | { kind: "navigate"; view: OpenableSurface }
    | { kind: "request-write"; write: "release-containment" };
  /** What happens if the operator presses enter. Never empty. */
  consequence: string;
};

/** Exactly two. A third is a written argument, not a convenience. */
export const PERCH_COMMANDS: readonly PerchCommandSpec[] = [
  {
    verb: "release containment",
    args: ["lease_id"],
    effect: { kind: "request-write", write: "release-containment" },
    consequence:
      "opens Containments with the row focused and its release control armed — the daemon is asked only from that surface",
  },
  {
    verb: "open",
    args: ["surface"],
    effect: { kind: "navigate", view: "watch" },
    consequence: "navigates; changes nothing",
  },
];

/**
 * `>` switches to command mode only as the FIRST character.
 *
 * Anywhere else it is query text: `strength > 2` is a search an operator will
 * type, and treating it as a command would swallow the query.
 */
export function parseOmniboxInput(raw: string): {
  mode: PerchOmniboxMode;
  body: string;
} {
  if (raw.startsWith(">"))
    return { mode: "command", body: raw.slice(1).trim() };
  return { mode: "query", body: raw };
}

function isOpenable(value: string): value is OpenableSurface {
  return (OPENABLE_SURFACES as readonly string[]).includes(value);
}

export function matchCommand(
  body: string,
  commands: readonly PerchCommandSpec[],
): { spec: PerchCommandSpec; args: readonly string[] } | null {
  const trimmed = body.trim();
  for (const spec of commands) {
    if (!trimmed.startsWith(spec.verb)) continue;
    const rest = trimmed.slice(spec.verb.length).trim();
    const args = rest.length === 0 ? [] : rest.split(/\s+/);
    if (args.length !== spec.args.length) continue;
    if (spec.effect.kind === "navigate") {
      const view = args[0] ?? "";
      if (!isOpenable(view)) continue;
      return { spec: { ...spec, effect: { kind: "navigate", view } }, args };
    }
    // `cl_` is a containment lease. `cap-` names a capability lease, which is a
    // different object with a different lifetime, and releasing one because it
    // looked like the other is not a mistake an operator can undo.
    if (!/^cl_[A-Za-z0-9_-]{4,}$/.test(args[0] ?? "")) continue;
    return { spec, args };
  }
  return null;
}
