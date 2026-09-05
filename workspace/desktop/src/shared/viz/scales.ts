/**
 * The two scales every Perch chart uses.
 *
 * Both are pure and both refuse to invent a range. A degenerate domain (every
 * value identical) maps to the middle of the range rather than to zero or to
 * NaN: a flat series is a real observation, and drawing it along the bottom
 * axis would read as "nothing happened".
 */

export type Scale = (value: number) => number;

export function linearScale(
  domain: readonly [number, number],
  range: readonly [number, number],
): Scale {
  const [d0, d1] = domain;
  const [r0, r1] = range;
  const span = d1 - d0;
  if (span === 0) {
    const mid = (r0 + r1) / 2;
    return () => mid;
  }
  return (value) => r0 + ((value - d0) / span) * (r1 - r0);
}

/**
 * A sparkline's vertical scale: the WINDOW's min and max, never zero-based.
 *
 * A zero-based sparkline of a rate that varies between 900 and 1000 draws a
 * flat line, hiding the only thing the chart is for. The cost is that the
 * baseline is not zero, which is why the sparkline never carries a y-axis
 * label — it shows shape, and the number beside it carries magnitude.
 */
export function sparkScale(values: readonly number[], height: number): Scale {
  if (values.length === 0) return () => height / 2;
  const min = Math.min(...values);
  const max = Math.max(...values);
  // SVG y grows downward: the maximum maps to 0 and the minimum to `height`.
  return linearScale([min, max], [height, 0]);
}
