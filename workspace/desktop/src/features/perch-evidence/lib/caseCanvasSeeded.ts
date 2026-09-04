/**
 * Which case canvases this session has already seeded.
 *
 * Community-scoped: switching communities must not re-seed a case whose canvas
 * an operator deliberately emptied, and the relay's answer for one community
 * says nothing about the same channel id in another.
 */
let seeded = new Set<string>();

export function caseCanvasSeeded(): Set<string> {
  return seeded;
}

export function markCaseCanvasSeeded(channelId: string): void {
  seeded.add(channelId);
}

/** Replaces the set rather than clearing it, so a stale reader sees nothing new. */
export function resetCaseCanvasSeeded(): void {
  seeded = new Set();
}
