/**
 * The case canvas template.
 *
 * Five fixed markdown headings and nothing else. No prose, no placeholders, no
 * examples: an operator must not have to delete a machine's guesses at 03:00,
 * and a template carrying sample text becomes a template nobody edits.
 *
 * `Handoff notes` is the fifth because `/handoff` reads it back out.
 */
export const PERCH_CASE_TEMPLATE = [
  "## Timeline",
  "",
  "## Hypothesis",
  "",
  "## Actions taken",
  "",
  "## Open questions",
  "",
  "## Handoff notes",
  "",
].join("\n");

/**
 * Whether to write the template into this case's canvas.
 *
 * Four conditions, and the interesting one is `content === null`. A canvas an
 * operator emptied has HAD content; re-seeding it would restore headings they
 * deliberately removed, every time they opened the tab. Only a canvas the
 * relay has never held is seeded, and only once per channel per community.
 */
export function shouldSeed(input: {
  content: string | null;
  isSuccess: boolean;
  canEdit: boolean;
  channelId: string;
  seeded: Set<string>;
}): boolean {
  return (
    input.isSuccess &&
    input.content === null &&
    input.canEdit &&
    !input.seeded.has(input.channelId)
  );
}

/**
 * The text under `## {heading}`, up to the next `## `, trimmed.
 *
 * `null` means the heading is absent. An empty string means the heading is
 * there and holds nothing — a different fact, and the one `/handoff` needs in
 * order to distinguish "no note was written" from "this case has no notes
 * section at all".
 */
export function sectionText(markdown: string, heading: string): string | null {
  const lines = markdown.split(/\r?\n/);
  const start = lines.findIndex((line) => line.trim() === `## ${heading}`);
  if (start === -1) return null;
  const rest = lines.slice(start + 1);
  const end = rest.findIndex((line) => line.startsWith("## "));
  return rest
    .slice(0, end === -1 ? rest.length : end)
    .join("\n")
    .trim();
}
