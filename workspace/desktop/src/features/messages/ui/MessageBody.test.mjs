import assert from "node:assert/strict";
import test from "node:test";

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";

import { HuddleProvider } from "@/features/huddle";
import { MessageBody } from "./MessageBody.tsx";

test("the Ambush wave marker still renders its fallback text", () => {
  const client = new QueryClient();
  const html = renderToStaticMarkup(
    React.createElement(
      QueryClientProvider,
      { client },
      React.createElement(
        HuddleProvider,
        null,
        React.createElement(MessageBody, {
          channelId: null,
          customEmoji: undefined,
          emojiOnly: false,
          isKnownAgentPubkey: () => false,
          message: {
            body: "<!-- ambush:wave:v1 -->\nTaylor waved at you.",
            id: "wave-event",
            pending: false,
            signerPubkey: "a".repeat(64),
            tags: [],
          },
          profiles: {},
        }),
      ),
    ),
  );

  assert.match(html, /Taylor waved at you\./);
  assert.match(html, /data-testid="message-wave-attachment"/);
  client.clear();
});
