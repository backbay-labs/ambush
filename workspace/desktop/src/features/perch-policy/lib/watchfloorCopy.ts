/**
 * Watchfloor copy.
 *
 * Every band names the source of its own numbers, because this screen is read
 * from across a room by someone who did not open it and cannot ask where a
 * figure came from.
 */
export const WATCHFLOOR = {
  title: "Watchfloor",
  decay:
    "DECAY FIELD · 12 classes · curve is an interpolation; the header number is the runtime's",
  colony:
    "COLONY · {n} agents · liveness from the 26002 health stream (never Nostr presence: a dead agent reads online for up to 180s there)",
  mode: "MODE",
  cooldown: "deescalation_cooldown_secs {n} · {remaining}s remaining",
  stale:
    "No concentration snapshot for {seconds}s. Curves below are the last received values, not current ones.",
  noClicks: "This screen changes nothing. Decisions are recorded on /.",
  regimeB:
    "regime B · snapshot-only · assumes every live deposit carries half_life_secs {h}",
  noFrame:
    "No concentration frame has arrived. This is not a concentration of zero; the console has not been told anything.",
} as const;

/** Substitute `{name}` placeholders. An unknown key stays visible. */
export function fillWatchfloor(
  template: string,
  values: Record<string, string | number>,
): string {
  return template.replace(/\{(\w+)\}/g, (whole, key: string) =>
    key in values ? String(values[key]) : whole,
  );
}
