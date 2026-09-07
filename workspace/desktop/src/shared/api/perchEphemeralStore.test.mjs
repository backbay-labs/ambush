import assert from "node:assert/strict";
import test from "node:test";

import {
  applyPerchEphemeralFrame,
  drainPerchAlarms,
  getPerchEphemeralSnapshot,
  PERCH_PREADMISSION_BUFFER_CAP,
  perchDroppedFrameCount,
  perchLatestTelemetry,
  perchUnadmittedFrameCount,
  resetPerchEphemeralStore,
  setPerchAdmittedIssuers,
} from "./perchEphemeralStore.ts";

const ADMITTED = "20".repeat(32);
const STRANGER = "68".repeat(32);

function frame(overrides = {}) {
  return {
    kind: 26004,
    pubkey: ADMITTED,
    receivedAtMs: 1,
    body: { partition_state: "healthy" },
    ...overrides,
  };
}

test("a frame that arrives before the admitted set is known is held, not refused", () => {
  // The daemon's identities read is asynchronous and the bridge publishes at
  // 1 Hz, so the first frames of a session routinely land first. Counting them
  // as unadmitted would put every launch into a counter that is read as
  // "somebody tried to plant a frame"; dropping them would blank the strip
  // for as long as the read takes.
  resetPerchEphemeralStore();
  assert.equal(applyPerchEphemeralFrame(frame()), false, "not stored yet");
  assert.equal(perchUnadmittedFrameCount(), 0, "and not refused either");
  assert.equal(perchDroppedFrameCount(), 0);
  assert.equal(perchLatestTelemetry(26004), undefined);

  setPerchAdmittedIssuers([ADMITTED]);
  assert.deepEqual(perchLatestTelemetry(26004)?.body, {
    partition_state: "healthy",
  });
  assert.equal(perchLatestTelemetry(26004)?.receivedAtMs, 1);
});

test("a held alarm is queued for its drainer once the answer arrives", () => {
  resetPerchEphemeralStore();
  applyPerchEphemeralFrame(
    frame({ kind: 26006, body: { hold_id: "hold_1c28ae79" } }),
  );
  assert.equal(getPerchEphemeralSnapshot().alarms.length, 0);
  setPerchAdmittedIssuers([ADMITTED]);
  assert.deepEqual(drainPerchAlarms(), [{ hold_id: "hold_1c28ae79" }]);
});

test("a held frame the answer does not admit is counted as unadmitted at that moment", () => {
  resetPerchEphemeralStore();
  applyPerchEphemeralFrame(frame({ pubkey: STRANGER }));
  assert.equal(perchUnadmittedFrameCount(), 0, "no answer, no refusal");
  setPerchAdmittedIssuers([ADMITTED]);
  assert.equal(perchUnadmittedFrameCount(), 1);
  assert.equal(perchLatestTelemetry(26004), undefined);
});

test("the hold buffer is bounded and drops the oldest", () => {
  resetPerchEphemeralStore();
  assert.equal(PERCH_PREADMISSION_BUFFER_CAP, 32);
  for (let index = 0; index <= PERCH_PREADMISSION_BUFFER_CAP; index += 1) {
    applyPerchEphemeralFrame(
      frame({ kind: 26006, body: { hold_id: `hold_${index}` } }),
    );
  }
  setPerchAdmittedIssuers([ADMITTED]);
  const drained = drainPerchAlarms();
  assert.equal(drained.length, PERCH_PREADMISSION_BUFFER_CAP);
  assert.deepEqual(drained[0], { hold_id: "hold_1" }, "the oldest went");
  assert.deepEqual(drained[drained.length - 1], { hold_id: "hold_32" });
});

test("a frame whose content did not decode to an object is undecodable, never a body of {}", () => {
  // A 26004 stored with an empty body would make the governance strip read
  // `healthy` off a frame nobody could decode, which is the one thing the
  // strip must never do.
  resetPerchEphemeralStore();
  setPerchAdmittedIssuers([ADMITTED]);
  for (const body of [undefined, null, "healthy", 7, true, [1, 2]]) {
    assert.equal(applyPerchEphemeralFrame(frame({ body })), false);
  }
  assert.equal(perchDroppedFrameCount(), 6);
  assert.equal(perchUnadmittedFrameCount(), 0, "a different number");
  assert.equal(perchLatestTelemetry(26004), undefined);
  assert.equal(getPerchEphemeralSnapshot().droppedFrames, 6);
});

test("undecodable is decided before admission is known, so the hold buffer never fills with garbage", () => {
  resetPerchEphemeralStore();
  assert.equal(applyPerchEphemeralFrame(frame({ body: undefined })), false);
  assert.equal(perchDroppedFrameCount(), 1);
  setPerchAdmittedIssuers([ADMITTED]);
  assert.equal(perchLatestTelemetry(26004), undefined, "nothing was held");
});

test("a kind outside the block is refused without touching either counter", () => {
  resetPerchEphemeralStore();
  setPerchAdmittedIssuers([ADMITTED]);
  assert.equal(applyPerchEphemeralFrame(frame({ kind: 9 })), false);
  assert.equal(perchDroppedFrameCount(), 0);
  assert.equal(perchUnadmittedFrameCount(), 0);
});

test("the community fence empties the hold buffer and un-knows the answer", () => {
  resetPerchEphemeralStore();
  setPerchAdmittedIssuers([ADMITTED]);
  applyPerchEphemeralFrame(frame({ body: undefined }));
  assert.equal(perchDroppedFrameCount(), 1);

  resetPerchEphemeralStore();
  assert.equal(perchDroppedFrameCount(), 0);
  applyPerchEphemeralFrame(frame());
  assert.equal(
    perchLatestTelemetry(26004),
    undefined,
    "the reset un-knew the admitted set, so this one is held",
  );

  resetPerchEphemeralStore();
  setPerchAdmittedIssuers([ADMITTED]);
  assert.equal(
    perchLatestTelemetry(26004),
    undefined,
    "and the reset emptied the buffer, so there was nothing to replay",
  );
});

test("the snapshot changes identity on a held frame's arrival only once it lands", () => {
  resetPerchEphemeralStore();
  const empty = getPerchEphemeralSnapshot();
  applyPerchEphemeralFrame(frame());
  assert.equal(getPerchEphemeralSnapshot(), empty, "held is not a change");
  setPerchAdmittedIssuers([ADMITTED]);
  assert.notEqual(getPerchEphemeralSnapshot(), empty);
});
