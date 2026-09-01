import assert from "node:assert/strict";
import test from "node:test";

import {
  extractSupportedLinkPreviews,
  isSupportedLinkAutolinkLabel,
  parseSupportedLinkPreview,
} from "./linkPreview.ts";

test("parseSupportedLinkPreview parses GitHub pull request URLs", () => {
  assert.deepEqual(
    parseSupportedLinkPreview(
      "https://github.com/backbay-labs/ambush/pull/1234",
    ),
    {
      kind: "github-pull-request",
      href: "https://github.com/backbay-labs/ambush/pull/1234",
      provider: "GitHub",
      title: "backbay-labs/ambush #1234",
      typeLabel: "PR",
    },
  );
});

test("parseSupportedLinkPreview strips the fragment from the preview href", () => {
  // A `#fragment` is a client-only anchor; the preview and its signed snapshot
  // canonical URL are of the page. Keeping it would fail the fragmentless
  // snapshot-URL guard and drop the preview entirely.
  assert.equal(
    parseSupportedLinkPreview(
      "https://github.com/backbay-labs/ambush/pull/1234#pullrequestreview-99",
    )?.href,
    "https://github.com/backbay-labs/ambush/pull/1234",
  );
});

test("extractSupportedLinkPreviews collapses fragment variants of one page", () => {
  const previews = extractSupportedLinkPreviews(
    [
      "https://github.com/backbay-labs/ambush/pull/1234#pullrequestreview-99",
      "https://github.com/backbay-labs/ambush/pull/1234#issuecomment-1",
      "https://github.com/backbay-labs/ambush/pull/5678",
    ].join("\n"),
  );
  // Two anchors into the same page dedupe to one card at first occurrence; the
  // distinct second page keeps its own card.
  assert.deepEqual(
    previews.map((preview) => preview.href),
    [
      "https://github.com/backbay-labs/ambush/pull/1234",
      "https://github.com/backbay-labs/ambush/pull/5678",
    ],
  );
});

test("parseSupportedLinkPreview parses GitHub repository URLs", () => {
  assert.deepEqual(
    parseSupportedLinkPreview("https://github.com/backbay-labs/ambush"),
    {
      kind: "github-repository",
      href: "https://github.com/backbay-labs/ambush",
      provider: "GitHub",
      title: "backbay-labs/ambush",
      typeLabel: "repo",
    },
  );
});

test("parseSupportedLinkPreview trims markdown punctuation around GitHub URLs", () => {
  assert.deepEqual(
    parseSupportedLinkPreview(
      "https://github.com/backbay-labs/ambush/pull/1234).",
    ),
    {
      kind: "github-pull-request",
      href: "https://github.com/backbay-labs/ambush/pull/1234",
      provider: "GitHub",
      title: "backbay-labs/ambush #1234",
      typeLabel: "PR",
    },
  );
});

test("parseSupportedLinkPreview ignores unsupported GitHub URLs", () => {
  assert.equal(
    parseSupportedLinkPreview(
      "https://github.com/backbay-labs/ambush/tree/main",
    ),
    null,
  );
});

const AMBUSH_OWNER =
  "71d67180ba17e749ee825fc8819c9c6ee7003617e1c126504f9b658070ab9224";

test("parseSupportedLinkPreview parses Ambush relay git clone URLs", () => {
  // Must pass the active relay origin for host validation.
  assert.deepEqual(
    parseSupportedLinkPreview(
      `https://ambush.example.com/git/${AMBUSH_OWNER}/ambush-world-galaxy`,
      "https://ambush.example.com",
    ),
    {
      kind: "ambush-repository",
      href: `ambush://repo?owner=${AMBUSH_OWNER}&d=ambush-world-galaxy`,
      provider: "Ambush",
      title: "ambush-world-galaxy",
      typeLabel: "repo",
    },
  );
  // Same URL without a matching origin stays an ordinary external preview.
  assert.equal(
    parseSupportedLinkPreview(
      `https://ambush.example.com/git/${AMBUSH_OWNER}/ambush-world-galaxy`,
    )?.kind,
    "generic-link",
  );
});

test("parseSupportedLinkPreview strips .git suffix from clone URLs", () => {
  assert.deepEqual(
    parseSupportedLinkPreview(
      `http://localhost:3000/git/${AMBUSH_OWNER}/ambush-world.git`,
      "http://localhost:3000",
    ),
    {
      kind: "ambush-repository",
      href: `ambush://repo?owner=${AMBUSH_OWNER}&d=ambush-world`,
      provider: "Ambush",
      title: "ambush-world",
      typeLabel: "repo",
    },
  );
});

test("parseSupportedLinkPreview rejects malformed Ambush git URLs", () => {
  for (const href of [
    // Owner segment must be a 64-char lowercase hex pubkey.
    "https://relay.example/git/not-a-pubkey/repo",
    `https://relay.example/git/${AMBUSH_OWNER.toUpperCase()}/repo`,
    `https://relay.example/git/${AMBUSH_OWNER.slice(0, 32)}/repo`,
    // Missing or invalid repo segment.
    `https://relay.example/git/${AMBUSH_OWNER}`,
    `https://relay.example/git/${AMBUSH_OWNER}/.hidden`,
    // Deeper transport paths are not repo links.
    `https://relay.example/git/${AMBUSH_OWNER}/repo/info/refs`,
  ]) {
    // Structural non-matches remain ordinary external previews.
    assert.equal(
      parseSupportedLinkPreview(href, "https://relay.example")?.kind,
      "generic-link",
      href,
    );
  }
});

test("parseSupportedLinkPreview rejects clone URLs from non-relay hosts", () => {
  // Correct path shape but origin does not match the active relay.
  assert.equal(
    parseSupportedLinkPreview(
      `https://evil.example/git/${AMBUSH_OWNER}/my-repo`,
      "https://ambush.example.com",
    )?.kind,
    "generic-link",
  );
  // github.com sharing the path shape must never become an Ambush repo card.
  assert.equal(
    parseSupportedLinkPreview(
      `https://github.com/git/${AMBUSH_OWNER}/my-repo`,
      "https://ambush.example.com",
    ),
    null,
  );
  // No relay origin provided — stays external.
  assert.equal(
    parseSupportedLinkPreview(
      `https://ambush.example.com/git/${AMBUSH_OWNER}/ambush-world`,
      null,
    )?.kind,
    "generic-link",
  );
});

const AMBUSH_EVENT_ID =
  "c3b589fa5713ba25bad6dc095e2de00a4ac8f50050fdea00fc6444e603be1dd1";

test("parseSupportedLinkPreview parses ambush:// PR and issue deep links", () => {
  assert.deepEqual(
    parseSupportedLinkPreview(
      `ambush://pr?id=${AMBUSH_EVENT_ID}&owner=${AMBUSH_OWNER}&d=ambush-world`,
    ),
    {
      kind: "ambush-pull-request",
      href: `ambush://pr?id=${AMBUSH_EVENT_ID}&owner=${AMBUSH_OWNER}&d=ambush-world`,
      provider: "Ambush",
      title: "ambush-world #c3b589fa",
      typeLabel: "Review",
    },
  );
  assert.deepEqual(
    parseSupportedLinkPreview(
      `ambush://issue?id=${AMBUSH_EVENT_ID}&owner=${AMBUSH_OWNER}&d=ambush-world`,
    )?.typeLabel,
    "Task",
  );
  assert.deepEqual(
    parseSupportedLinkPreview(
      `ambush://repo?owner=${AMBUSH_OWNER}&d=ambush-world`,
    ),
    {
      kind: "ambush-repository",
      href: `ambush://repo?owner=${AMBUSH_OWNER}&d=ambush-world`,
      provider: "Ambush",
      title: "ambush-world",
      typeLabel: "repo",
    },
  );
});

test("parseSupportedLinkPreview parses ambush:// project deep links", () => {
  assert.deepEqual(
    parseSupportedLinkPreview(
      `ambush://project?owner=${AMBUSH_OWNER}&d=ambush-world`,
    ),
    {
      kind: "ambush-project",
      href: `ambush://project?owner=${AMBUSH_OWNER}&d=ambush-world`,
      provider: "Ambush",
      title: "ambush-world",
      typeLabel: "project",
    },
  );
});

test("parseSupportedLinkPreview rejects malformed ambush:// entity links", () => {
  for (const href of [
    `ambush://pr?owner=${AMBUSH_OWNER}&d=ambush-world`,
    `ambush://pr?id=short&owner=${AMBUSH_OWNER}&d=ambush-world`,
    `ambush://issue?id=${AMBUSH_EVENT_ID}&owner=nope&d=ambush-world`,
    `ambush://repo?owner=${AMBUSH_OWNER}&d=.hidden`,
    `ambush://project?owner=${AMBUSH_OWNER}&d=.hidden`,
  ]) {
    assert.equal(parseSupportedLinkPreview(href), null, href);
  }
});

test("extractSupportedLinkPreviews excludes Ambush entity links while keeping external links", () => {
  const entityLinks = [
    `ambush://project?owner=${AMBUSH_OWNER}&d=ambush-world`,
    `ambush://repo?owner=${AMBUSH_OWNER}&d=ambush-world`,
    `ambush://issue?id=${AMBUSH_EVENT_ID}&owner=${AMBUSH_OWNER}&d=ambush-world`,
    `ambush://pr?id=${AMBUSH_EVENT_ID}&owner=${AMBUSH_OWNER}&d=ambush-world`,
  ];

  assert.deepEqual(
    extractSupportedLinkPreviews(
      `${entityLinks.join(" ")} https://example.com/story`,
    ).map((preview) => preview.href),
    ["https://example.com/story"],
  );
});

test("extractSupportedLinkPreviews excludes markdown-labeled Ambush entity links", () => {
  assert.deepEqual(
    extractSupportedLinkPreviews(
      `[Project](ambush://project?owner=${AMBUSH_OWNER}&d=ambush-world)`,
    ),
    [],
  );
});

test("parseSupportedLinkPreview parses Linear issue URLs", () => {
  assert.deepEqual(
    parseSupportedLinkPreview(
      "https://linear.app/ambush/issue/BUG-321/fix-link-previews",
    ),
    {
      kind: "linear-issue",
      href: "https://linear.app/ambush/issue/BUG-321/fix-link-previews",
      provider: "Linear",
      title: "BUG-321",
      typeLabel: "issue",
    },
  );
});

test("parseSupportedLinkPreview normalizes Linear issue URL variants", () => {
  assert.deepEqual(
    parseSupportedLinkPreview("linear.app/ambush/issue/a-7/fix-link-previews"),
    {
      kind: "linear-issue",
      href: "https://linear.app/ambush/issue/a-7/fix-link-previews",
      provider: "Linear",
      title: "A-7",
      typeLabel: "issue",
    },
  );
});

test("parseSupportedLinkPreview parses Google app URLs", () => {
  assert.deepEqual(
    [
      "https://drive.google.com/file/d/abc123/view",
      "https://drive.google.com/drive/folders/folder123",
      "https://docs.google.com/document/d/doc123/edit",
      "https://docs.google.com/spreadsheets/d/sheet123/edit",
      "https://docs.google.com/presentation/d/slides123/edit",
    ].map((href) => parseSupportedLinkPreview(href)?.kind),
    [
      "google-drive-file",
      "google-drive-folder",
      "google-docs-document",
      "google-sheets-spreadsheet",
      "google-slides-presentation",
    ],
  );
});

test("extractSupportedLinkPreviews returns unique supported links in order", () => {
  assert.deepEqual(
    extractSupportedLinkPreviews(
      [
        "See github.com/backbay-labs/ambush/pull/1",
        "and https://linear.app/ambush/issue/BUG-2/fix-preview",
        "then https://github.com/backbay-labs/ambush/pull/1 again.",
        "plus https://docs.google.com/document/d/doc123/edit",
      ].join(" "),
    ).map((preview) => preview.title),
    ["backbay-labs/ambush #1", "BUG-2", "Document"],
  );
});

test("extractSupportedLinkPreviews excludes same-relay Ambush clone URLs", () => {
  assert.deepEqual(
    extractSupportedLinkPreviews(
      `master pushed; clone: https://ambush.example.com/git/${AMBUSH_OWNER}/ambush-world-galaxy and review please.`,
      "https://ambush.example.com",
    ),
    [],
  );
  // Without a relay origin the URL is treated as an ordinary external link.
  assert.deepEqual(
    extractSupportedLinkPreviews(
      `clone: https://ambush.example.com/git/${AMBUSH_OWNER}/ambush-world-galaxy`,
    ).map((preview) => preview.kind),
    ["generic-link"],
  );
});

test("extractSupportedLinkPreviews excludes markdown-labeled Ambush clone URLs", () => {
  assert.deepEqual(
    extractSupportedLinkPreviews(
      `[Ambush World](https://relay.example/git/${AMBUSH_OWNER}/ambush-world-galaxy)`,
      "https://relay.example",
    ),
    [],
  );
});

test("extractSupportedLinkPreviews handles markdown link serialization", () => {
  assert.deepEqual(
    extractSupportedLinkPreviews(
      "[https://github.com/backbay-labs/ambush/pull/44](https://github.com/backbay-labs/ambush/pull/44)",
    ).map((preview) => preview.title),
    ["backbay-labs/ambush #44"],
  );
});

test("extractSupportedLinkPreviews uses useful markdown labels as titles", () => {
  assert.deepEqual(
    extractSupportedLinkPreviews(
      "[Composer attachment polish](https://docs.google.com/document/d/doc123/edit)",
    ),
    [
      {
        kind: "google-docs-document",
        href: "https://docs.google.com/document/d/doc123/edit",
        provider: "Google Docs",
        title: "Composer attachment polish",
        typeLabel: "document",
      },
    ],
  );
});

test("extractSupportedLinkPreviews includes multiple supported Google links", () => {
  assert.deepEqual(
    extractSupportedLinkPreviews(
      [
        "https://docs.google.com/document/d/doc123/edit",
        "https://docs.google.com/spreadsheets/d/sheet123/edit",
        "https://docs.google.com/presentation/d/slides123/edit",
      ].join(" "),
    ).map((preview) => preview.kind),
    [
      "google-docs-document",
      "google-sheets-spreadsheet",
      "google-slides-presentation",
    ],
  );
});

test("extractSupportedLinkPreviews skips URLs inside inline and fenced code", () => {
  assert.deepEqual(
    extractSupportedLinkPreviews(
      [
        "`https://github.com/backbay-labs/ambush/pull/1`",
        "```",
        "https://linear.app/ambush/issue/BUG-2/fix-preview",
        "```",
        "https://github.com/backbay-labs/ambush/pull/3",
      ].join("\n"),
    ).map((preview) => preview.title),
    ["backbay-labs/ambush #3"],
  );
});

test("extractSupportedLinkPreviews skips URLs inside indented code", () => {
  assert.deepEqual(
    extractSupportedLinkPreviews(
      [
        "    https://docs.google.com/document/d/hidden/edit",
        "\tgithub.com/backbay-labs/ambush/pull/4",
        "https://github.com/backbay-labs/ambush/pull/5",
      ].join("\n"),
    ).map((preview) => preview.title),
    ["backbay-labs/ambush #5"],
  );
});

test("extractSupportedLinkPreviews skips markdown image link URLs", () => {
  assert.deepEqual(
    extractSupportedLinkPreviews(
      [
        "![alt](https://docs.google.com/document/d/doc123/edit)",
        "![alt](https://github.com/backbay-labs/ambush)",
        "[Composer attachment polish](https://docs.google.com/document/d/doc456/edit)",
      ].join("\n"),
    ).map((preview) => preview.title),
    ["Composer attachment polish"],
  );
});

test("extractSupportedLinkPreviews treats other absolute HTTPS URLs as generic", () => {
  assert.deepEqual(
    extractSupportedLinkPreviews(
      [
        "https://evil-github.com/backbay-labs/ambush/pull/1",
        "https://example.com/go/https://docs.google.com/document/d/doc123/edit",
        "(https://github.com/backbay-labs/ambush/pull/2)",
      ].join(" "),
    ).map((preview) => preview.title),
    ["evil-github.com", "example.com", "backbay-labs/ambush #2"],
  );
});

test("extractSupportedLinkPreviews skips links inside inline spoilers", () => {
  assert.deepEqual(
    extractSupportedLinkPreviews(
      [
        "Keep",
        "||[roadmap](https://docs.google.com/document/d/hidden/edit)||",
        "hidden, but show https://github.com/backbay-labs/ambush/pull/7",
      ].join(" "),
    ).map((preview) => preview.title),
    ["backbay-labs/ambush #7"],
  );
});

test("extractSupportedLinkPreviews skips links inside block spoilers", () => {
  assert.deepEqual(
    extractSupportedLinkPreviews(
      [
        "||",
        "",
        "https://linear.app/ambush/issue/BUG-99/hidden-spoiler-link",
        "",
        "||",
        "https://github.com/backbay-labs/ambush/pull/8",
      ].join("\n"),
    ).map((preview) => preview.title),
    ["backbay-labs/ambush #8"],
  );
});

test("isSupportedLinkAutolinkLabel matches normalized bare URL labels", () => {
  const preview = parseSupportedLinkPreview(
    "github.com/backbay-labs/ambush/pull/5",
  );
  assert.ok(preview);
  assert.equal(
    isSupportedLinkAutolinkLabel(
      "https://github.com/backbay-labs/ambush/pull/5",
      preview,
    ),
    true,
  );
  assert.equal(isSupportedLinkAutolinkLabel("review this", preview), false);
});

test("parseSupportedLinkPreview parses generic HTTPS URLs", () => {
  assert.deepEqual(
    parseSupportedLinkPreview("https://example.com/articles/rich-previews"),
    {
      kind: "generic-link",
      href: "https://example.com/articles/rich-previews",
      provider: "example.com",
      title: "example.com",
      typeLabel: "link",
    },
  );
});

test("parseSupportedLinkPreview rejects generic HTTP URLs", () => {
  assert.equal(
    parseSupportedLinkPreview("http://example.com/articles/rich-previews"),
    null,
  );
});

test("extractSupportedLinkPreviews finds generic links and preserves exclusions", () => {
  assert.deepEqual(
    extractSupportedLinkPreviews(
      [
        "Read https://example.com/article first.",
        "`https://hidden.example.com/secret`",
        "then [the details](https://docs.example.org/details)",
      ].join(" "),
    ).map(({ kind, title }) => ({ kind, title })),
    [
      { kind: "generic-link", title: "example.com" },
      { kind: "generic-link", title: "the details" },
    ],
  );
});
