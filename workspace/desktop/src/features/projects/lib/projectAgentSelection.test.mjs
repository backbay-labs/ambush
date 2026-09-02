import assert from "node:assert/strict";
import test from "node:test";

import { pickDefaultProjectsAgent } from "./projectAgentSelection.ts";

test("prefers Anvil over the first running agent", () => {
  const implementationPartner = {
    name: "Implementation Partner",
    personaId: "custom:implementation",
  };
  const anvil = { name: "Anvil", personaId: "builtin:fizz" };
  assert.equal(pickDefaultProjectsAgent([implementationPartner, anvil]), anvil);
});

test("ignores an unmanaged agent using the Anvil display name", () => {
  const managed = { name: "Builder", personaId: "custom:builder" };
  const spoofedAnvil = { name: "Anvil" };
  assert.equal(pickDefaultProjectsAgent([managed, spoofedAnvil]), managed);
  assert.equal(pickDefaultProjectsAgent([managed]), managed);
  assert.equal(pickDefaultProjectsAgent([]), null);
});
