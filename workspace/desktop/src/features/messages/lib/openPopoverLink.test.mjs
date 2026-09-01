import assert from "node:assert/strict";
import test from "node:test";

import { openPopoverLink } from "./openPopoverLink.ts";

const CHANNEL = "f570339f-8f8a-4e08-a779-8d954aa44109";
const MESSAGE =
  "b04819ffc1f7c8ffb49c6d30b5899f470198264680d02e78894a658e30a9059f";

function makeSpies() {
  const external = [];
  const inApp = [];
  return {
    handlers: {
      openExternal: (url) => external.push(url),
      openMessageLink: (link) => inApp.push(link),
    },
    external,
    inApp,
  };
}

test("ambush://message deep-link routes in-app, not the OS opener", () => {
  const { handlers, external, inApp } = makeSpies();
  openPopoverLink(
    `ambush://message?channel=${CHANNEL}&id=${MESSAGE}`,
    handlers,
  );
  assert.equal(external.length, 0);
  assert.deepEqual(inApp, [
    { channelId: CHANNEL, messageId: MESSAGE, threadRootId: null },
  ]);
});

test("http(s) URLs go to the OS opener", () => {
  const { handlers, external, inApp } = makeSpies();
  openPopoverLink("https://example.com/path", handlers);
  assert.deepEqual(external, ["https://example.com/path"]);
  assert.equal(inApp.length, 0);
});

test("non-message ambush:// URLs fall through to the OS opener", () => {
  const { handlers, external, inApp } = makeSpies();
  openPopoverLink("ambush://channel?foo=bar", handlers);
  assert.deepEqual(external, ["ambush://channel?foo=bar"]);
  assert.equal(inApp.length, 0);
});

test("malformed ambush://message URL falls back to the OS opener", () => {
  const { handlers, external, inApp } = makeSpies();
  // Matches isMessageLink (starts with ambush://message?) but is missing the
  // required channel/id params, so parse fails and we don't navigate in-app.
  openPopoverLink("ambush://message?nope=1", handlers);
  assert.deepEqual(external, ["ambush://message?nope=1"]);
  assert.equal(inApp.length, 0);
});
