import type { InstallRuntimeResult } from "@/shared/api/types";

/**
 * Build the user-visible error message for a failed install.
 * When the last step carries an actionable hint, it is shown first,
 * followed by the raw step failure detail.
 *
 * The step detail is truncated for display, so the message ends with a pointer
 * to the install log — which holds every attempt of every step, each record
 * bounded far above the display truncation — when one was written.
 */
export function getInstallErrorMessage(result: InstallRuntimeResult): string {
  const { steps, logPath } = result;
  const lastStep = steps[steps.length - 1];
  if (!lastStep) {
    return withLog("Install failed with no output.", logPath);
  }
  const base = `Step "${lastStep.step}" failed: ${lastStep.stderr || lastStep.stdout || "unknown error"}`;
  const detail = lastStep.hint ? `${lastStep.hint}\n\n${base}` : base;
  return withLog(detail, logPath);
}

/**
 * The one line of a failed install a fixed-height card can show, or `null` when
 * the failure has nothing better than a generic label to offer.
 *
 * Only the failing step's `hint` qualifies. A hint is Ambush's own sentence
 * about what to do next; the rest of the message is the vendor's raw stdout and
 * stderr, which belongs behind the tooltip — a card is the wrong place to
 * publish whatever an installer happened to print.
 */
export function getInstallErrorHeadline(
  result: InstallRuntimeResult,
): string | null {
  const hint = result.steps[result.steps.length - 1]?.hint?.trim();
  return hint || null;
}

function withLog(message: string, logPath: string | null): string {
  return logPath ? `${message}\n\nFull log: ${logPath}` : message;
}
