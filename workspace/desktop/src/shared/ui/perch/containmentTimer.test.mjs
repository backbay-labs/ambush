import assert from "node:assert/strict";
import { test } from "node:test";

import React from "react";
import { renderToStaticMarkup } from "react-dom/server";

import { ContainmentTimer } from "./ContainmentTimer.tsx";

const AT = 1_773_739_879_900;

test("two facts render as two elements, and zero/expired differs from zero/open", () => {
  const open = renderToStaticMarkup(
    React.createElement(ContainmentTimer, {
      remainingMs: 0,
      expired: false,
      expiresAtMs: AT,
      daemonReachable: true,
    }),
  );
  const expired = renderToStaticMarkup(
    React.createElement(ContainmentTimer, {
      remainingMs: 0,
      expired: true,
      expiresAtMs: AT,
      daemonReachable: true,
    }),
  );
  assert.notEqual(
    open,
    expired,
    "a bar at zero would render these identically; that is the failure this avoids",
  );
  for (const html of [open, expired]) {
    assert.match(html, /data-testid="perch-containment-remaining"/);
    assert.match(html, /data-testid="perch-containment-expired"/);
    assert.doesNotMatch(html, /<progress/, "two facts are never one bar");
  }
  assert.match(expired, /role="alert"/);
  assert.doesNotMatch(open, /role="alert"/);
});

test("the remaining figure is small tabular text and never a bar", () => {
  const html = renderToStaticMarkup(
    React.createElement(ContainmentTimer, {
      remainingMs: 41_000,
      expired: false,
      expiresAtMs: AT,
      daemonReachable: true,
    }),
  );
  assert.match(html, /text-sm[^"]*tabular-nums|tabular-nums[^"]*text-sm/);
  assert.match(html, /00:41/);
});

test("the expired word carries the meaning, so the hue is decoration", () => {
  const html = renderToStaticMarkup(
    React.createElement(ContainmentTimer, {
      remainingMs: 0,
      expired: true,
      expiresAtMs: AT,
      daemonReachable: true,
    }),
  );
  assert.match(html, /EXPIRED, HOST STILL CONTAINED/);
  assert.match(html, /aria-hidden="true"/, "the mark is hidden from a reader");
});

test("an unreachable daemon still reports expiry, and the state attribute says which", () => {
  const html = renderToStaticMarkup(
    React.createElement(ContainmentTimer, {
      remainingMs: 0,
      expired: true,
      expiresAtMs: AT,
      daemonReachable: false,
    }),
  );
  assert.match(html, /data-perch-containment-state="daemon-down-expired"/);
  assert.match(html, /EXPIRED, HOST STILL CONTAINED/);
});
