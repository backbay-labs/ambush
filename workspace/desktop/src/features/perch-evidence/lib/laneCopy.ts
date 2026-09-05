/**
 * Every rendered string on a lane screen, in a module so the copy gate reaches
 * them.
 */
export const LANE = {
  headerLive: "live · 1 Hz · ephemeral",
  headerStale: "telemetry stale · last frame {seconds}s ago",
  customLanded: "classified Custom({name}) → shown in {slug}",
  quiet: {
    title: "No live deposits in {threatClass}",
    body: "Concentration is {strength} against an alert threshold of {alertThreshold}, from {sources} sources / {agents} agents. Deposits decay on a {halfLife}s half-life, so this can go quiet without anything being resolved.",
    action: {
      label: "See what this channel cannot see",
      href: "/gaps?threat_class={slug}",
    },
  },
  mutedNote:
    "Muted on first run: every top-level post in an unmuted channel notifies, and unmuted this would page on every escalation card.",
  annotationsOnly:
    "Human messages here are annotations on the record. Decisions are recorded on a case.",
} as const;
