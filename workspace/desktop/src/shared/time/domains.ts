/**
 * Two time domains, kept apart by the type system.
 *
 * The engine's pheromone substrate works in unix SECONDS; the relay, the read
 * frontiers and every browser API work in MILLISECONDS. Mixing them silently
 * produces a number that is wrong by a factor of a thousand and still looks
 * like a plausible timestamp, which is the hardest kind of bug to see in a
 * chart.
 *
 * No conversion helper is exported on purpose. Crossing domains has to be
 * named at the call site, where a reader can check it.
 */
declare const SECONDS_BRAND: unique symbol;
declare const MILLIS_BRAND: unique symbol;

export type UnixSeconds = number & { readonly [SECONDS_BRAND]: true };
export type UnixMillis = number & { readonly [MILLIS_BRAND]: true };

export const nowSeconds = (): UnixSeconds =>
  Math.floor(Date.now() / 1000) as UnixSeconds;

export const nowMillis = (): UnixMillis => Date.now() as UnixMillis;
