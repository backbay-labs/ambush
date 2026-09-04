import assert from "node:assert/strict";
import { test } from "node:test";

import React from "react";
import { renderToStaticMarkup } from "react-dom/server";

import { RollbackStepList } from "./RollbackStepList.tsx";

test("every step says what happened to the world, not merely that it finished", () => {
  const html = renderToStaticMarkup(
    React.createElement(RollbackStepList, {
      steps: [
        { label: "restore_host_connectivity", status: "reversed" },
        { label: "rejoin_domain", status: "simulated" },
        { label: "unshred_file", status: "irreversible" },
      ],
      fullyReversed: false,
    }),
  );
  assert.match(html, /Reversed/);
  assert.match(html, /Simulated/);
  assert.match(html, /Irreversible/);
  assert.match(html, /data-perch-rollback-status="simulated"/);
});

test("not fully reversed names the count and the breakdown", () => {
  const html = renderToStaticMarkup(
    React.createElement(RollbackStepList, {
      steps: [
        { label: "a", status: "reversed" },
        { label: "b", status: "simulated" },
      ],
      fullyReversed: false,
    }),
  );
  assert.match(html, /1 of 2 steps/);
  assert.match(html, /1 Reversed, 1 Simulated/);
  assert.match(html, /data-perch-fully-reversed="false"/);
});

test("fully reversed says so plainly and drops the breakdown", () => {
  const html = renderToStaticMarkup(
    React.createElement(RollbackStepList, {
      steps: [{ label: "a", status: "reversed" }],
      fullyReversed: true,
    }),
  );
  assert.match(html, /Fully reversed/);
  assert.doesNotMatch(html, /of 1 steps/);
  assert.match(html, /data-perch-fully-reversed="true"/);
});

test("a step reason goes through the adversary rail, not raw into the row", () => {
  const html = renderToStaticMarkup(
    React.createElement(RollbackStepList, {
      steps: [
        {
          label: "a",
          status: "failed",
          reason: "adapter refused‮gnirts desrever",
        },
      ],
      fullyReversed: false,
    }),
  );
  // The rail labels the field, which a raw interpolation would not do.
  assert.match(html, /reason/);
});
