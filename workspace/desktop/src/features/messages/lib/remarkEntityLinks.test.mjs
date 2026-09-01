import assert from "node:assert/strict";
import test from "node:test";

import remarkEntityLinks from "./remarkEntityLinks.ts";

function run(value) {
  const tree = {
    type: "root",
    children: [{ type: "paragraph", children: [{ type: "text", value }] }],
  };
  remarkEntityLinks()(tree);
  return tree.children[0].children;
}

test("turns every bare Ambush entity permalink family into a chip node", () => {
  const owner = "ab".repeat(32);
  const id = "cd".repeat(32);
  const links = [
    `ambush://repo?owner=${owner}&d=ambush`,
    `ambush://project?owner=${owner}&d=onboarding`,
    `ambush://pr?id=${id}&owner=${owner}&d=ambush`,
    `ambush://issue?id=${id}&owner=${owner}&d=ambush`,
  ];
  for (const link of links) {
    const children = run(link);
    assert.equal(children[0].type, "entity-link");
    assert.equal(children[0].value, link);
  }
});

test("keeps sentence punctuation outside entity chip nodes", () => {
  const link = `ambush://repo?owner=${"ab".repeat(32)}&d=ambush`;
  const children = run(`${link}.`);
  assert.equal(children[0].value, link);
  assert.equal(children[1].value, ".");
});
