/**
 * SKELETON. Lands as BUZZ
 * `desktop/src/features/perch/wire/golden.test.mjs`.
 *
 * THIS FILE IS HALF THE SYNC MECHANISM. The other half is
 * `AMB crates/swarm-perch-wire/tests/golden.rs`, which runs the SAME vectors
 * through the Rust types. There is no codegen step in either repository and this
 * design does not add one; instead one directory of golden vectors is the
 * contract and both bindings are asserted against it, so neither can pass while
 * the other's parse of the same bytes differs.
 *
 * It runs under `pnpm test`
 * (`node --import ./test-loader.mjs --experimental-strip-types --test
 * "src/**\/*.test.mjs"`, `BUZZ desktop/package.json`), which is
 * `just desktop-test` and one of lefthook's pre-push groups. The loader
 * (`desktop/test-loader-hooks.mjs`) transpiles `.ts` on import, which is why a
 * `.mjs` test can import `./zod.ts` directly.
 *
 * The precedent for this shape is
 * `desktop/src/features/messages/lib/formatTimelineMessages.test.mjs:663-676`,
 * which asserts `CHANNEL_TIMELINE_CONTENT_KINDS` and `isTimelineContentEvent`
 * agree in BOTH directions. That test is why those two registration points can
 * only be paid together, and it is the house pattern for pinning a registry.
 */

import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

import {
  CARD_FACT_SCHEMA,
  CARD_KINDS,
  CARD_MARKER,
  buildCardContent,
  parseCardContent,
  routeCard,
} from "./marker.ts";
import { admitCard, admitFrame, cardEnvelope, frame } from "./zod.ts";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const GOLDEN = path.join(HERE, "golden");

function vectors(prefix) {
  return readdirSync(GOLDEN)
    .filter((f) => f.startsWith(prefix) && f.endsWith(".json") && f !== "manifest.json")
    .sort()
    .map((f) => ({ name: f, raw: readFileSync(path.join(GOLDEN, f), "utf8") }));
}

/**
 * ONE vector by exact stem.
 *
 * `vectors()` is a PREFIX match, and prefix matching bit once already:
 * `vector("card-swarm-verdict-v1")` returns the SUPERSEDED vector, because
 * `-` (0x2D) sorts before `.` (0x2E) so `card-swarm-verdict-v1-superseded.json`
 * comes first. Every single-vector assertion goes through this instead.
 */
function vector(stem) {
  const name = `${stem}.json`;
  return { name, raw: readFileSync(path.join(GOLDEN, name), "utf8") };
}

// ─────────────────────────────────────────────────────── the vectors exist

test("the registry is seven cards, one stored kind and seven frames", () => {
  // Eight card VECTORS, seven card TYPES: `swarm:verdict:v1` has two, the
  // second being the losing console's `superseded` update card. Counting
  // distinct `fact.schema` values is what keeps this honest.
  const schemas = new Set(
    vectors("card-").map(({ raw }) => JSON.parse(raw).fact.schema),
  );
  assert.equal(schemas.size, 7);
  assert.equal(vectors("event-").length, 1);
  assert.equal(vectors("frame-").length, 7);
});

// ────────────────────────────────────────────────────────────────── the pin

/**
 * THE PIN, and an honest note about it.
 *
 * `13-WIRE-SCHEMAS.md` §0 quoted a golden hash as a verification result before
 * this assertion existed in any committed file: the number had been computed by
 * hand at a shell prompt, not by anything a reviewer could re-run. That is the
 * "measured against a file that is not the one in the tree" pattern, and the fix
 * is the same as everywhere else it appeared — put the check in the artifact.
 *
 * Re-pin with `scripts/sync-perch-golden.sh`, never by hand. The vectors are
 * EXTRACTED from the schemas' own `examples`, so editing a vector to match a
 * hash inverts the entire mechanism.
 */
const GOLDEN_SHA256 =
  "10233c15d1945bad14124022dbb359ed5e00de2f9b4300b6ea55e0b3124a285f";

test("the golden corpus matches its pinned hash", () => {
  const hash = createHash("sha256");
  for (const name of readdirSync(GOLDEN).filter(
    (f) => f.endsWith(".json") && f !== "manifest.json",
  ).sort()) {
    hash.update(readFileSync(path.join(GOLDEN, name)));
  }
  assert.equal(
    hash.digest("hex"),
    GOLDEN_SHA256,
    "golden corpus drifted; re-run scripts/sync-perch-golden.sh",
  );
});

test("the Rust suite pins the same hash", () => {
  // Half the point of two suites is that they cannot silently disagree. This
  // reads the constant out of the sibling repository's test file when it is
  // reachable and skips when it is not -- a skip is visible, a false pass is not.
  const rust = path.join(
    HERE,
    "..",
    "..",
    "..",
    "swarm-perch-wire",
    "tests",
    "golden.rs",
  );
  let text;
  try {
    text = readFileSync(rust, "utf8");
  } catch {
    console.log(
      "  (skipped: the Ambush checkout is not a sibling here; " +
        "tools/check-perch-wire-parity.sh is the cross-repo gate)",
    );
    return;
  }
  const m = text.match(/GOLDEN_SHA256: &str =\s*\n?\s*"([0-9a-f]{64})"/);
  assert.ok(m, "could not find GOLDEN_SHA256 in the Rust suite");
  assert.equal(m[1], GOLDEN_SHA256, "the two suites pin different corpora");
});

// ─────────────────────────────────────── the two identity chains stay apart

test("no card stamps an agent role on a human", () => {
  // AgentRole.Tom is "Governance -- enforces policy, manages lifecycle"
  // (AMB crates/swarm-core/src/agent.rs:26-27): the VETO actor.
  // APPENDIX-NORMATIVE section 7 rules that governance's veto and the operator's
  // refuse are never conflated, and adr/0016 spends a document keeping the two
  // identity chains apart. A verdict vector previously carried role: "tom" on an
  // operator's own decision, and the pinned hash held it there.
  for (const { name, raw } of vectors("card-")) {
    const fact = JSON.parse(raw).fact;
    if (fact.schema === "swarm.perch.verdict.v1") {
      assert.equal(
        fact.issuer.role,
        null,
        `${name}: a human decision may not carry an AgentRole`,
      );
    }
    assert.notEqual(
      fact.issuer.role,
      "tom",
      `${name}: \`tom\` is the governance/veto actor and never a fact issuer`,
    );
  }
});

test("role is required and nullable, never absent", () => {
  // A MISSING key must be a decode error while a genuine absence is an explicit
  // null. Collapsing the two would let a truncated body pass as an unattributed
  // fact -- which is the one thing an evidence card must never do quietly.
  for (const { name, raw } of vectors("card-")) {
    const issuer = JSON.parse(raw).fact.issuer;
    assert.ok(
      "role" in issuer,
      `${name}: role is required even when its value is null`,
    );
  }
});

// ──────────────────────────────────────── render law 2's two halves, on the wire

test("the escalation vector names the true counting unit", () => {
  // resolve_deposits writes agent_id: strategy_scoped_agent_id(...) onto every
  // deposit (AMB crates/swarm-runtime/src/detection/pipeline.rs:573) and
  // concentration_for counts those strings
  // (AMB crates/swarm-pheromone/src/substrate.rs:1295), over a base that is
  // already instance-scoped (whisker_agent.rs:148-149). The wrong literal
  // "agent_instance_id" would have REJECTED a truthful bridge inside admitCard.
  const { raw } = vector("card-swarm-escalation-v1");
  const esc = JSON.parse(raw).fact.escalation;
  assert.equal(esc.distinct_sources_counts, "strategy_scoped_agent_id");
  assert.equal(esc.source_ids, null);
  assert.equal(esc.source_ids_absent_reason, "not_carried_by_runtime_event");
});

test("an unnamed source_ids absence does not decode", () => {
  // The M half of render law 2 has NO data source on any Phase-1 card. Leaving
  // that as a bare null is how a component ends up fabricating an agent count or
  // spinning forever; the decoder insists the absence carries its reason.
  const { raw } = vector("card-swarm-escalation-v1");
  const card = JSON.parse(raw);
  card.fact.escalation.source_ids_absent_reason = null;
  assert.throws(() => cardEnvelope.parse(card));
  const both = JSON.parse(raw);
  both.fact.escalation.source_ids = ["w:1:spt", "w:1:scr"];
  assert.throws(() => cardEnvelope.parse(both));
});

// ───────────────────────────────────────────── two operators, one hold

test("a superseded verdict names the card that won", () => {
  const { raw } = vector("card-swarm-verdict-v1-superseded");
  const leg2 = JSON.parse(raw).fact.leg2;
  assert.equal(leg2.state, "superseded");
  assert.equal(
    leg2.superseded_by.length,
    64,
    "a superseded card with no winner is a dead end for the reconciler",
  );
  assert.equal(typeof leg2.superseded_at_ms, "number");
});

test("only a superseded verdict may carry a winner", () => {
  const { raw } = vector("card-swarm-verdict-v1");
  const card = JSON.parse(raw);
  card.fact.leg2 = { state: "recorded", superseded_by: "d".repeat(64) };
  assert.throws(
    () => cardEnvelope.parse(card),
    "a `recorded` card claiming a winner asserts something the console never observed",
  );
});

// ────────────────────────────────────────── hold ids are opaque, everywhere

test("every hold id in the corpus is an opaque token", () => {
  // Six formats were in circulation across the wave-2 artifact set; two used the
  // `hold:` colon prefix, which is the forbidden hunt-id-derived shape.
  const OPAQUE = /^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$/;
  const found = [];
  const walk = (value) => {
    if (Array.isArray(value)) return value.forEach(walk);
    if (value && typeof value === "object") {
      for (const [k, v] of Object.entries(value)) {
        if (k === "hold_id" && typeof v === "string") found.push(v);
        walk(v);
      }
    }
  };
  for (const { name, raw } of [...vectors("card-"), ...vectors("frame-")]) {
    const before = found.length;
    walk(JSON.parse(raw));
    for (const id of found.slice(before)) {
      assert.match(id, OPAQUE, `${name}: hold id \`${id}\` is not opaque`);
    }
  }
  assert.ok(found.length >= 4, "expected the hold path's vectors to carry hold ids");
});

test("the 46010 vector carries exactly the four closed tag names", () => {
  // The Rust producer (TagSet::assert_publishable) has refused t/l/k since the
  // first draft; the SCHEMA did not, because its `items` was an open
  // `array of string` while its description claimed the set was closed. Both
  // sides refuse now, and this is the TypeScript half.
  const { raw } = vector("event-46010-hold-notice");
  const names = JSON.parse(raw).tags.map((t) => t[0]);
  assert.deepEqual(new Set(names), new Set(["h", "p", "hold", "card"]));
  assert.equal(names.filter((n) => n === "h").length, 1);
  assert.equal(names.filter((n) => n === "hold").length, 1);
  assert.ok(names.includes("p"), "a p-less notice reaches nobody");
});

test("the 26006 vector is global: no h tag anywhere in the frame block", () => {
  // adr/0017 clause C3. An h tag would route the frame through the channel index,
  // where p_gated_filters_authorized is never consulted -- it is wrapped in
  // `if channel_id.is_none()` at BUZZ crates/buzz-relay/src/handlers/req.rs:218
  // -- narrowing the disclosure ring rather than closing it, and delivering zero
  // frames to the shipped client's global filter. Withdrawn amendment W-1.
  for (const { name, raw } of vectors("frame-")) {
    const body = JSON.parse(raw);
    assert.equal(
      body.h ?? body.case_channel_scope ?? undefined,
      undefined,
      `${name}: the ephemeral block is global`,
    );
  }
});

test("the golden directory matches its pinned hash", () => {
  // `scripts/sync-perch-golden.sh` copies this directory from
  // AMB crates/swarm-perch-wire/golden/. Both sides pin the same hash, so a
  // one-sided edit turns BOTH suites red in the same commit instead of one of
  // them silently.
  const files = readdirSync(GOLDEN)
    .filter((f) => f.endsWith(".json") && f !== "manifest.json")
    .sort();
  const hash = createHash("sha256");
  for (const file of files) {
    hash.update(readFileSync(path.join(GOLDEN, file)));
  }
  const pinned = readFileSync(path.join(GOLDEN, "GOLDEN.sha256"), "utf8")
    .trim()
    .split(/\s+/)[0];
  assert.equal(hash.digest("hex"), pinned);
});

// ────────────────────────────────────────────────────────────── admission

const ADMITTED = "b".repeat(64);
const isAdmitted = (pubkey) => pubkey === ADMITTED;

test("every card vector is admitted by the zod envelope", () => {
  for (const { name, raw } of vectors("card-")) {
    const result = admitCard(raw, ADMITTED, isAdmitted);
    assert.ok(result.ok, `${name}: ${result.ok ? "" : result.reason}`);
  }
});

test("every frame vector is admitted by the zod frame union", () => {
  for (const { name, raw } of vectors("frame-")) {
    const result = admitFrame(raw, ADMITTED, isAdmitted);
    assert.ok(result.ok, `${name}: ${result.ok ? "" : result.reason}`);
  }
});

test("an unadmitted signer is refused before the body is parsed", () => {
  // INV-15's second clause. The ephemeral ingest gate is a single scope test
  // with no per-kind allowlist
  // (BUZZ crates/buzz-relay/src/handlers/event.rs:699-707), so every
  // chat-capable member of the community can publish a 26xxx.
  const { raw } = vector("frame-26006-hold-alarm");
  const result = admitFrame(raw, "a".repeat(64), isAdmitted);
  assert.equal(result.ok, false);
  assert.equal(result.reason, "unadmitted-issuer");
});

test("a missing signer is refused, not treated as anonymous", () => {
  const { raw } = vector("card-swarm-hold-v1");
  const result = admitCard(raw, undefined, isAdmitted);
  assert.equal(result.ok, false);
  assert.equal(result.reason, "unadmitted-issuer");
});

test("admission never throws on malformed JSON", () => {
  const result = admitCard("{not json", ADMITTED, isAdmitted);
  assert.equal(result.ok, false);
  assert.equal(result.reason, "malformed-json");
});

// ───────────────────────────────────────────────────── serde shape traps
//
// Three shapes on this wire are internally or externally tagged in ways a
// hand-written TypeScript type gets wrong on the first try. These are the tests
// that catch a wrong guess.

test("ThreatClass is a bare string for the twelve and an object for Custom", () => {
  // AMB crates/swarm-core/src/pheromone.rs:13-30 — externally tagged, so serde
  // emits "lateral_movement" for a unit variant and {"custom":"..."} for the
  // newtype variant. Two production agents mint Custom classes.
  const base = JSON.parse(vector("frame-26001-concentration").raw);
  assert.equal(typeof base.concentrations[0].threat_class, "string");

  const withCustom = structuredClone(base);
  withCustom.concentrations[0].threat_class = { custom: "sphinx_memory" };
  assert.ok(frame.safeParse(withCustom).success, "Custom must parse");

  const bare = structuredClone(base);
  bare.concentrations[0].threat_class = "custom";
  assert.equal(
    frame.safeParse(bare).success,
    false,
    "a bare 'custom' string is not a ThreatClass",
  );
});

test("ResponseAction is internally tagged on `type`", () => {
  // AMB crates/swarm-core/src/types.rs:416-467 —
  // {"type":"isolate_host","host_id":"web-04"}, NOT {"isolate_host":{...}}.
  const card = JSON.parse(vector("card-swarm-hold-v1").raw);
  assert.equal(card.fact.hold.action_request.action.type, "isolate_host");
  assert.equal(card.fact.hold.action_request.action.host_id, "web-04");

  const wrong = structuredClone(card);
  wrong.fact.hold.action_request.action = { isolate_host: { host_id: "web-04" } };
  assert.equal(cardEnvelope.safeParse(wrong).success, false);
});

test("AuditResponseRecord flattens a newtype variant beside its `kind` tag", () => {
  // AMB crates/swarm-spine/src/lib.rs:102-110 — #[serde(tag = "kind")] over
  // four variants, two of them newtype. A success arm carries ResponseReceipt's
  // seven fields at the SAME level as `kind`.
  const card = JSON.parse(vector("card-swarm-receipt-v1").raw);
  const response = card.fact.audit_trail.response;
  assert.equal(response.kind, "success");
  assert.equal(typeof response.receipt_id, "string");
  assert.equal(response.status, "executed");
  assert.equal(
    response.success,
    undefined,
    "an externally tagged {success:{...}} would be the wrong shape",
  );
});

test("Severity is SCREAMING_SNAKE and nothing else is", () => {
  // AMB crates/swarm-core/src/types.rs:406-414 is the only enum in the
  // workspace with rename_all = "SCREAMING_SNAKE_CASE"; ~40 siblings are
  // snake_case. Any codegen that lowercases uniformly breaks exactly this field.
  const card = JSON.parse(vector("card-swarm-hold-v1").raw);
  assert.equal(card.fact.hold.severity, "HIGH");
  assert.equal(card.fact.hold.action_kind, "isolate_host");
  assert.equal(card.fact.hold.policy_decision.verdict, "require_human");

  const lowered = structuredClone(card);
  lowered.fact.hold.severity = "high";
  assert.equal(cardEnvelope.safeParse(lowered).success, false);
});

// ────────────────────────────────────────────────────── the content grammar

test("the marker must be the entire first line", () => {
  // INV-15's first clause. Buzz's own parseWaveMessageContent
  // (desktop/src/features/messages/lib/waveMessage.ts:12-26) does
  // content.trimStart().startsWith(MARKER) and WOULD accept these.
  assert.equal(routeCard(`${CARD_MARKER.hold}\nx`), "hold");
  assert.equal(routeCard(`${CARD_MARKER.hold} and more`), null);
  assert.equal(routeCard(`  ${CARD_MARKER.hold}`), null);
  assert.equal(routeCard("<!-- swarm:hold:v2 -->\nx"), null);
  assert.equal(routeCard("<!-- buzz:wave:v1 -->\nx"), null);
});

test("the content grammar round-trips for every card vector", () => {
  for (const kind of CARD_KINDS) {
    const { raw } = vectors(`card-swarm-${kind}-v1`)[0];
    const compact = JSON.stringify(JSON.parse(raw));
    const human = `${kind} · fixture`;
    const body = buildCardContent(kind, human, compact);

    const lines = body.split("\n");
    assert.equal(lines[0], CARD_MARKER[kind], "marker is the whole first line");
    assert.equal(lines[1], human, "the human line is second, not last");

    const parts = parseCardContent(body);
    assert.ok(parts);
    assert.equal(parts.kind, kind);
    assert.equal(parts.humanLine, human);
    assert.deepEqual(JSON.parse(parts.json), JSON.parse(raw));
    assert.equal(JSON.parse(parts.json).fact.schema, CARD_FACT_SCHEMA[kind]);
  }
});

test("the human line survives the desktop's 96-character search preview", () => {
  // buildSearchResultPreview(content, query, maxLength = 96)
  // (desktop/src/features/search/lib/searchMatch.ts:169-200) returns the first
  // 96 characters when the query does not match inside the body. The marker
  // costs 26 of them plus a newline. This test is why the human line is second
  // and the JSON is last.
  const human =
    "hold h_7f3a2c91 · isolate_host · HIGH · host web-04 · expires 03:41:14Z";
  const body = buildCardContent("hold", human, "{}");
  const preview = body.slice(0, 96);
  assert.ok(
    preview.includes("h_7f3a2c91"),
    "the hold id must be inside the first 96 characters",
  );
  assert.ok(preview.includes("isolate_host"));
  assert.ok(
    !preview.includes("```"),
    "the fence must not reach the preview window",
  );
});

test("parseCardContent never throws", () => {
  for (const hostile of [
    "",
    "\n",
    CARD_MARKER.hold,
    `${CARD_MARKER.hold}\n`,
    `${CARD_MARKER.hold}\n\n`,
    `${CARD_MARKER.hold}\nhuman\n\n\`\`\`swarm:hold:v1\nunterminated`,
    `${CARD_MARKER.hold}\nhuman\n\n\`\`\`swarm:finding:v1\n{}\n\`\`\``,
    " ".repeat(64),
  ]) {
    assert.doesNotThrow(() => parseCardContent(hostile));
  }
});

// ────────────────────────────────────────────────── the 46010 tag contract

test("the hold notice carries exactly h, p, hold and card", () => {
  // RF-D1 (10-RELAY-FORK.md §4.2) fixes the single-letter set at {h, p}; `hold`
  // and `card` are multi-letter and outside its scope by its own wording.
  const notice = JSON.parse(vector("event-46010-hold-notice").raw);
  assert.equal(notice.kind, 46010);
  assert.deepEqual(
    notice.tags.map((t) => t[0]),
    ["h", "p", "hold", "card"],
  );
  for (const banned of ["e", "t", "l", "k"]) {
    assert.ok(
      !notice.tags.some((t) => t[0] === banned),
      `46010 may not carry \`${banned}\``,
    );
  }
});

test("every p tag is 64 lowercase hex", () => {
  // insert_mentions drops anything else with a debug! and the publish still
  // returns OK (BUZZ crates/buzz-db/src/runtime/mod.rs:65-81, :943-948), so a
  // stored-but-unmentioned hold is invisible to query_needs_action forever and
  // a republish is deduplicated by event id.
  const notice = JSON.parse(vector("event-46010-hold-notice").raw);
  for (const tag of notice.tags.filter((t) => t[0] === "p")) {
    assert.match(tag[1], /^[0-9a-f]{64}$/);
  }
});

test("the hold notice content is one line and starts with the hold id", () => {
  // Nothing parses this string, but three things RENDER it: the desktop inbox
  // (features/home/lib/inbox.ts:165, :186), the mobile activity feed
  // (mobile/lib/features/activity/feed_item.dart:83-88, whose displayContent is
  // content.trim()), and Postgres FTS, because schema.sql:223-227's privacy
  // CASE does not null search_tsv for 46010.
  const notice = JSON.parse(vector("event-46010-hold-notice").raw);
  assert.ok(!notice.content.includes("\n"));
  assert.match(notice.content, /^hold [A-Za-z0-9_]+ · /);
  assert.ok(!notice.content.includes("<!--"), "no marker on the queue record");
  assert.ok(!notice.content.includes("{"), "no JSON on the queue record");
});

// ───────────────────────────────────────────── the aggregates-only rule

test("no global frame carries a host id, a path or a telemetry join key", () => {
  // filter_fanout_by_access returns EVERY match at
  // BUZZ crates/buzz-relay/src/handlers/event.rs:177-179 for a channel-less
  // event, so anything on a global frame reaches every member of the community.
  const BANNED = [
    "host_id",
    "unexpected_library_loads",
    "details",
    "evidence",
    "finding_id",
    "event_id",
    "hunt_id",
    "correlation_id",
    "indicator",
  ];
  const walk = (value, at, hits) => {
    if (Array.isArray(value)) {
      value.forEach((item, i) => walk(item, `${at}[${i}]`, hits));
    } else if (value && typeof value === "object") {
      for (const [key, sub] of Object.entries(value)) {
        if (BANNED.includes(key)) hits.push(`${at}.${key}`);
        walk(sub, `${at}.${key}`, hits);
      }
    }
  };
  for (const { name, raw } of vectors("frame-")) {
    const hits = [];
    walk(JSON.parse(raw), name, hits);
    assert.deepEqual(hits, [], `aggregates-only violated in ${name}`);
  }
});

// ────────────────────────────────────────────────────── the tier contract

test("an envelope hash without a signature is still tier 0", () => {
  // 08 §6.2 defines tier 1 as a detached Ed25519 signature over the body. The
  // envelope hash is keyless (compute_envelope_hash_hex takes no keypair,
  // AMB crates/swarm-spine/src/envelope.rs:47-51), so it is a continuity fact
  // and not an authorship fact. A surface reading it as verification would be
  // exactly the green check that document exists to prevent.
  for (const { name, raw } of vectors("card-")) {
    const card = JSON.parse(raw);
    assert.ok(card.envelope_hash, `${name}: hash present from day one`);
    assert.equal(card.signature, undefined, `${name}: absent until B6`);
  }
});
