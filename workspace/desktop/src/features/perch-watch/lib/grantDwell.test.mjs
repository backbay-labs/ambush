// The dwell gate.
//
// Every test below that the happy path would also pass is worthless, so most
// of these are the OTHER cases: time that passes while nobody is looking, a
// gate that is asked to complete without ever going visible, a selection that
// changes underneath an armed control. A gate proven only by the sequence that
// opens it is not proven at all.

import assert from "node:assert/strict";
import test from "node:test";

import {
  dwellComplete,
  dwellPercent,
  dwellReducer,
  GRANT_DWELL_MS,
  initialDwell,
} from "./grantDwell.ts";

const start = initialDwell("h_a07aeacf");

test("time accrues only while the blast radius is fully visible and freezes when it is not", () => {
  let state = dwellReducer(start, { type: "visible", atMs: 0 });
  state = dwellReducer(state, { type: "tick", atMs: 800 });
  assert.equal(state.accruedMs, 800);

  state = dwellReducer(state, { type: "hidden", atMs: 800 });
  state = dwellReducer(state, { type: "tick", atMs: 2_800 });
  assert.equal(
    state.accruedMs,
    800,
    "frozen, not reset, and nothing accrued while hidden",
  );
  assert.equal(dwellComplete(state), false);

  state = dwellReducer(state, { type: "visible", atMs: 2_800 });
  state = dwellReducer(state, { type: "tick", atMs: 3_500 });
  assert.equal(state.accruedMs, GRANT_DWELL_MS);
  assert.equal(dwellComplete(state), true);
});

// ---------------------------------------------------------------------------
// THE NEGATIVE CONTROLS. Each of these is a sequence a gate-less control would
// pass.
// ---------------------------------------------------------------------------

test("two seconds spent not looking never completes the gate", () => {
  const state = dwellReducer(start, { type: "tick", atMs: 2_000 });
  assert.equal(state.accruedMs, 0);
  assert.equal(dwellComplete(state), false);
});

test("an hour of ticks with no visibility event completes nothing", () => {
  let state = start;
  for (let atMs = 100; atMs <= 3_600_000; atMs += 100) {
    state = dwellReducer(state, { type: "tick", atMs });
  }
  assert.equal(state.accruedMs, 0, "wall-clock time is not dwell");
  assert.equal(dwellComplete(state), false);
});

test("visibility with no ticks accrues nothing: the clock is the tick, not the event", () => {
  // A control that treated `visible` as "start counting from now" and read the
  // wall clock at press time would pass the happy path and would also pass
  // this. It must not.
  const state = dwellReducer(start, { type: "visible", atMs: 0 });
  assert.equal(state.accruedMs, 0);
  assert.equal(dwellComplete(state), false);
});

test("flicking the blast radius in and out of view cannot outrun the gate", () => {
  // 30 visible/hidden cycles of 40 ms each: 1200 ms of real visibility, which
  // is under the gate. A reducer that reset `lastTickMs` on every `visible`
  // and then credited the whole interval would sail past 1500.
  let state = start;
  let clock = 0;
  for (let i = 0; i < 30; i += 1) {
    state = dwellReducer(state, { type: "visible", atMs: clock });
    clock += 40;
    state = dwellReducer(state, { type: "tick", atMs: clock });
    state = dwellReducer(state, { type: "hidden", atMs: clock });
    clock += 1_000;
    state = dwellReducer(state, { type: "tick", atMs: clock });
  }
  assert.equal(state.accruedMs, 1_200);
  assert.equal(dwellComplete(state), false);
});

test("a hold_id change resets the accrual even when the gate had completed", () => {
  let state = dwellReducer(dwellReducer(start, { type: "visible", atMs: 0 }), {
    type: "tick",
    atMs: GRANT_DWELL_MS,
  });
  assert.equal(dwellComplete(state), true);
  state = dwellReducer(state, { type: "reset", holdId: "h_b18bfbd0" });
  assert.equal(state.accruedMs, 0);
  assert.equal(state.holdId, "h_b18bfbd0");
  assert.equal(state.visible, false, "the new hold has not been looked at");
  assert.equal(dwellComplete(state), false);
});

test("a clock that runs backwards cannot credit negative or bonus time", () => {
  let state = dwellReducer(start, { type: "visible", atMs: 10_000 });
  state = dwellReducer(state, { type: "tick", atMs: 9_000 });
  assert.equal(state.accruedMs, 0, "a backwards tick credits nothing");
  state = dwellReducer(state, { type: "tick", atMs: 10_500 });
  assert.ok(state.accruedMs <= 1_500);
});

test("accrual is capped, so a long read cannot bank dwell for the next hold", () => {
  let state = dwellReducer(start, { type: "visible", atMs: 0 });
  state = dwellReducer(state, { type: "tick", atMs: 60_000 });
  assert.equal(state.accruedMs, GRANT_DWELL_MS);
  assert.equal(dwellPercent(state), 100);
});

test("the percentage is a reading of the accrual, not of the wall clock", () => {
  let state = dwellReducer(start, { type: "visible", atMs: 0 });
  state = dwellReducer(state, { type: "tick", atMs: 750 });
  assert.equal(dwellPercent(state), 50);
  state = dwellReducer(state, { type: "hidden", atMs: 750 });
  state = dwellReducer(state, { type: "tick", atMs: 100_000 });
  assert.equal(dwellPercent(state), 50);
});

test("the dwell is 1500 ms and the reducer is the only place that says so", () => {
  assert.equal(GRANT_DWELL_MS, 1500);
});
