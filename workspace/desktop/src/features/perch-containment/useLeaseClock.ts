import * as React from "react";

/**
 * One board-level clock, ticking once a second.
 *
 * Rows derive their remaining time from this scalar; nobody runs a per-row
 * interval. Twenty rows with twenty timers drift apart from each other within
 * a minute, and a board where two containments expiring at the same instant
 * count down differently is one an operator stops trusting.
 */
export function useLeaseClock(): number {
  const [nowMs, setNowMs] = React.useState(() => Date.now());
  React.useEffect(() => {
    const id = window.setInterval(() => setNowMs(Date.now()), 1_000);
    return () => window.clearInterval(id);
  }, []);
  return nowMs;
}
