/**
 * Pinning a terminal to a case.
 *
 * The PTY is the operator's tool, not an agent's. Pinning is a working
 * directory plus three environment variables — never injected flags — because
 * swarmctl's twelve `--*-results-dir` options default to RELATIVE `data/…`
 * paths. Changing the shell's cwd therefore scopes every default at once, and
 * every artifact a command writes is attributable to the case by its path.
 */
export const TERMINAL_BANNER_LINE =
  "124 of 126 swarmctl subcommands are not HTTP clients. This is a real shell on this host.";

const SAFE_SLUG = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

export type CaseTerminalScope = {
  cwd: string;
  env: [string, string][];
};

/**
 * The cwd and env for a case-pinned shell.
 *
 * The slug reaches a shell's environment, so a slug that is not shell-safe is
 * REPLACED by the case id rather than escaped. Escaping is a claim about every
 * consumer downstream; substitution is a claim about one value here.
 */
export function caseTerminalScope(
  caseId: string,
  caseSlug: string,
  stateRoot: string,
): CaseTerminalScope {
  const slug = SAFE_SLUG.test(caseSlug) ? caseSlug : caseId;
  const cwd = `${stateRoot}/cases/${caseId}`;
  return {
    cwd,
    env: [
      ["AMBUSH_CASE_ID", caseId],
      ["AMBUSH_CASE", slug],
      ["SWARM_RESULTS_ROOT", cwd],
    ],
  };
}
