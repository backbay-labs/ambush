import assert from "node:assert/strict";
import test from "node:test";

import {
  classifyTool,
  parseAmbushCliCommand,
  tokenizeShellCommand,
} from "./agentSessionToolClassifier.ts";

test("tokenizeShellCommand preserves quoted strings and command separators", () => {
  assert.deepEqual(
    tokenizeShellCommand(
      'echo "hello world" | ambush messages send --content - --channel agents; ambush feed get',
    ),
    [
      "echo",
      "hello world",
      "|",
      "ambush",
      "messages",
      "send",
      "--content",
      "-",
      "--channel",
      "agents",
      ";",
      "ambush",
      "feed",
      "get",
    ],
  );
});

test("parseAmbushCliCommand returns null preview for echo-piped stdin sends", () => {
  const descriptor = parseAmbushCliCommand(
    'echo "Permission wired" | ambush messages send --channel agents --content -',
  );

  assert.equal(descriptor?.renderClass, "message");
  assert.equal(descriptor?.label, "Send Message");
  assert.equal(descriptor?.preview, null);
  assert.equal(descriptor?.operation, "messages.send");
});

test("parseAmbushCliCommand returns null preview for printf-piped stdin sends", () => {
  const descriptor = parseAmbushCliCommand(
    "printf 'hello\\n\\nworld\\n' | ambush messages send --channel a6e0737c-4205-4bcc-9741-2aad800e613f --content -",
  );

  assert.equal(descriptor?.renderClass, "message");
  assert.equal(descriptor?.preview, null);
});

test("parseAmbushCliCommand returns null preview for heredoc/cat stdin sends", () => {
  const descriptor = parseAmbushCliCommand(
    'ambush messages send --channel some-uuid --content "$(cat /tmp/file)"',
  );

  assert.equal(descriptor?.renderClass, "message");
  assert.equal(descriptor?.preview, null);
});

test("parseAmbushCliCommand returns null preview for --content with embedded command substitution", () => {
  const descriptor = parseAmbushCliCommand(
    'ambush messages send --channel some-uuid --content "prefix $(cat /tmp/f)"',
  );

  assert.equal(descriptor?.renderClass, "message");
  assert.equal(descriptor?.preview, null);
});

test("parseAmbushCliCommand returns null preview for --content with a bare variable", () => {
  const descriptor = parseAmbushCliCommand(
    'ambush messages send --channel some-uuid --content "$MESSAGE"',
  );

  assert.equal(descriptor?.renderClass, "message");
  assert.equal(descriptor?.preview, null);
});

test("parseAmbushCliCommand returns null preview for --content with a prefixed variable", () => {
  const descriptor = parseAmbushCliCommand(
    'ambush messages send --channel some-uuid --content "prefix $MESSAGE"',
  );

  assert.equal(descriptor?.renderClass, "message");
  assert.equal(descriptor?.preview, null);
});

test("parseAmbushCliCommand preserves inline --content for sends", () => {
  const descriptor = parseAmbushCliCommand(
    'ambush messages send --channel agents --content "Hello from inline"',
  );

  assert.equal(descriptor?.renderClass, "message");
  assert.equal(descriptor?.preview, "Hello from inline");
});

test("parseAmbushCliCommand preserves --content=inline for sends", () => {
  const descriptor = parseAmbushCliCommand(
    "ambush messages send --channel agents --content=Acknowledged",
  );

  assert.equal(descriptor?.renderClass, "message");
  assert.equal(descriptor?.preview, "Acknowledged");
});

test("parseAmbushCliCommand never surfaces --channel as preview for sends", () => {
  const commands = [
    "printf 'msg' | ambush messages send --channel my-uuid --content -",
    'ambush messages send --channel my-uuid --content "$(cat /tmp/f)"',
    "ambush messages send --channel my-uuid --content -",
  ];

  for (const cmd of commands) {
    const descriptor = parseAmbushCliCommand(cmd);
    assert.equal(descriptor?.renderClass, "message");
    assert.notEqual(
      descriptor?.preview,
      "my-uuid",
      `send preview leaked --channel for: ${cmd}`,
    );
  }
});

test("classifyTool promotes load_skill to skill-read descriptors", () => {
  const descriptor = classifyTool({
    title: "load_skill",
    toolName: "load_skill",
    ambushToolName: null,
    args: { name: "block-safe-github" },
    result: "# Safe GitHub usage at Block\n",
    isError: false,
  });

  assert.equal(descriptor.renderClass, "skill-read");
  assert.equal(descriptor.label, "Read skill");
  assert.equal(descriptor.preview, "block-safe-github");
  assert.deepEqual(descriptor.action, {
    verb: "Read",
    object: "block-safe-github",
  });
  assert.equal(descriptor.groupKey, "skill:load");
});

test("classifyTool promotes supporting-file load_skill to skill-read file descriptors", () => {
  const descriptor = classifyTool({
    title: "load_skill",
    toolName: "load_skill",
    ambushToolName: null,
    args: { name: "block-safe-github/references/foo.md" },
    result: "# Reference\n",
    isError: false,
  });

  assert.equal(descriptor.renderClass, "skill-read");
  assert.equal(descriptor.label, "Read skill file");
  assert.equal(descriptor.groupKey, "skill:load-file");
});

test("classifyTool promotes ambush CLI shell commands to relay operations", () => {
  const descriptor = classifyTool({
    title: "Shell",
    toolName: "dev__shell",
    ambushToolName: null,
    args: {
      command: "ambush channels get --channel ambush-agent-observability",
    },
    result: "{}",
    isError: false,
  });

  assert.equal(descriptor.renderClass, "relay-op");
  assert.equal(descriptor.label, "Channels Get");
  assert.equal(descriptor.preview, "ambush-agent-observability");
  assert.equal(descriptor.groupKey, "ambush-cli:channels.get");
});

test("classifyTool falls back once to a generic descriptor", () => {
  const descriptor = classifyTool({
    title: "Mystery",
    toolName: "mcp__mystery",
    ambushToolName: null,
    args: { path: "notes.md" },
    result: "",
    isError: false,
  });

  assert.equal(descriptor.renderClass, "generic");
  assert.equal(descriptor.label, "Ran tool");
  assert.equal(descriptor.preview, "notes.md");
  assert.equal(descriptor.source, "fallback");
});
