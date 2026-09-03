#!/usr/bin/env node
// fixtures/validate.mjs -- prove every generated fixture against the wire
// schemas in ../schemas, and prove every envelope hash against its own bytes.
//
//   node fixtures/validate.mjs        # requires ajv 8 on the resolution path
//
// THERE IS NO DEPARTURE ALLOWLIST, AND THAT IS THE POINT.
//
// An earlier version of this script carried one: six `match` predicates keyed on
// ajv instancePath+keyword, each pointing at a proposed schema amendment, and it
// printed "0 unexplained failure(s); 13 recorded departure(s)" and exited 0. The
// red-team read that line correctly — those were not annotations, they were
// twelve failing files with the failures suppressed by the validator's own
// configuration. A fixture is the thing every other artifact is built on; a
// validator for it that can be taught to pass is worse than none.
//
// The amendments the allowlist was waiting for have since landed in the peer
// schemas (FactIssuer.role nullable-and-required; SourceCountMechanism const
// `strategy_scoped_agent_id`; the closed four-name 46010 tag set), and this
// fixture was corrected to match the third. So the allowlist has nothing left to
// suppress and it is gone. If a future amendment is genuinely pending, the right
// shape is a SECOND, named pass over an explicit overlay -- never a predicate
// that turns a red line green in the default run.
//
// Exit 0 only when every file validates and every envelope hash recomputes.

import Ajv2020 from "ajv/dist/2020.js";
import { createHash } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const SCHEMAS = join(HERE, "..", "schemas");

const ajv = new Ajv2020({ strict: false, allErrors: true, validateFormats: false });

// Load every schema by its FILENAME: the card schemas $ref each other by bare
// filename ("common.schema.json#/$defs/Severity").
for (const f of readdirSync(SCHEMAS).filter((n) => n.endsWith(".schema.json"))) {
  ajv.addSchema(JSON.parse(readFileSync(join(SCHEMAS, f), "utf8")), f);
}

const index = JSON.parse(readFileSync(join(SCHEMAS, "_index.json"), "utf8"));
const kTagToSchema = new Map(index.cards.map((c) => [c.k_tag, c.schema]));
const kindToSchema = new Map([
  ...index.stored_events.map((e) => [String(e.kind), e.schema]),
  ...index.frames.map((e) => [String(e.kind), e.schema]),
]);

/**
 * Map a fixture body to the schema that must validate it.
 *
 * Keyed on the CONTENT, never the filename. The earlier version keyed on a
 * `card-` filename prefix, so the three `variant-contested-*` verdict cards were
 * silently reported SKIP -- a file that is neither ok nor FAIL, which is how an
 * unvalidated fixture hides in a green run. A body this function cannot place is
 * now a hard failure.
 */
function schemaFor(body) {
  const factSchema = body?.fact?.schema;
  if (typeof factSchema === "string") {
    // "ambush.perch.hold.v1" -> "hold"
    return kTagToSchema.get(factSchema.split(".").at(-2));
  }
  if (typeof body?.kind === "number") return kindToSchema.get(String(body.kind));
  return null;
}

// ── the JCS port, identical to build.mjs's, so this is an INDEPENDENT check ──
// It re-derives each envelope_hash from the committed file's own bytes rather
// than trusting the value written beside them. crates/swarm-spine/src/envelope.rs:47-51.
function jcs(value) {
  if (value === null) return "null";
  const t = typeof value;
  if (t === "boolean") return value ? "true" : "false";
  if (t === "number") {
    if (!Number.isFinite(value)) throw new Error("non-finite number");
    if (value === 0) return "0";
    const a = Math.abs(value);
    if (!(a >= 1e-6 && a < 1e21)) throw new Error(`number ${value} needs the exponential JCS form`);
    return String(value);
  }
  if (t === "string") {
    for (const ch of value) {
      const c = ch.codePointAt(0);
      if (c >= 0x7f && c <= 0x9f) throw new Error(`U+${c.toString(16)} escapes differently in Rust and JS`);
    }
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return "[" + value.map(jcs).join(",") + "]";
  if (t === "object") {
    return "{" + Object.keys(value).sort().map((k) => jcs(k) + ":" + jcs(value[k])).join(",") + "}";
  }
  throw new Error(`unserializable ${t}`);
}

/** Self-test the port against RFC 8785's own key-ordering and number vectors. */
function selfTestJcs() {
  const cases = [
    [{ b: 1, a: 2 }, '{"a":2,"b":1}'],
    [{ "ä": 1, a: 2 }, '{"a":2,"ä":1}'],   // UTF-16 code-unit order
    [{ a: 1.0 }, '{"a":1}'],                     // integral f64 -> integer form
    [{ a: 0.9 }, '{"a":0.9}'],
    [{ a: 2.696884 }, '{"a":2.696884}'],
    [{ a: -0 }, '{"a":0}'],                      // canonical.rs:82-84
    [{ a: [1, null, true, "x"] }, '{"a":[1,null,true,"x"]}'],
    [{ a: "q\"\\\n" }, '{"a":"q\\"\\\\\\n"}'],
  ];
  for (const [input, want] of cases) {
    const got = jcs(input);
    if (got !== want) throw new Error(`JCS self-test failed: ${JSON.stringify(input)} -> ${got}, want ${want}`);
  }
}
selfTestJcs();

let hard = 0;
let hashChecked = 0;
const wire = join(HERE, "wire");

for (const name of readdirSync(wire).sort()) {
  const body = JSON.parse(readFileSync(join(wire, name), "utf8"));
  const schemaFile = schemaFor(body);
  if (!schemaFile) {
    hard += 1;
    console.log(`FAIL  ${name}  -- no schema maps to this body (fact.schema / kind unrecognised)`);
    continue;
  }
  const validate = ajv.getSchema(schemaFile);
  if (!validate) {
    hard += 1;
    console.log(`FAIL  ${name}  -- schema ${schemaFile} did not compile`);
    continue;
  }
  let line = validate(body) ? `ok    ${name}` : null;
  if (line === null) {
    hard += 1;
    console.log(`FAIL  ${name}  (${schemaFile})`);
    for (const e of (validate.errors ?? []).slice(0, 8)) {
      console.log(`        ${e.instancePath || "/"} ${e.keyword} ${JSON.stringify(e.params)}`);
    }
    continue;
  }
  // Envelopes carry a hash over their own canonical bytes. Recompute it.
  if (typeof body.envelope_hash === "string") {
    const { envelope_hash, signature, ...unsigned } = body;
    if (signature !== undefined) {
      hard += 1;
      console.log(`FAIL  ${name}  -- carries a signature field; nothing in this fixture is signed (section 9)`);
      continue;
    }
    const recomputed = "0x" + createHash("sha256").update(jcs(unsigned), "utf8").digest("hex");
    if (recomputed !== envelope_hash) {
      hard += 1;
      console.log(`FAIL  ${name}  -- envelope_hash does not match its own bytes`);
      console.log(`        written    ${envelope_hash}`);
      console.log(`        recomputed ${recomputed}`);
      continue;
    }
    hashChecked += 1;
    line += "  · envelope_hash verified";
  }
  console.log(line);
}

// ── the per-(issuer, stream) envelope chain ────────────────────────────────
// 13-WIRE-SCHEMAS.md: `seq` is per-issuer, per-stream, monotonic, and
// prev_envelope_hash links each envelope to the previous one from the SAME
// issuer. A consumer that merges issuers reports a phantom gap at every verdict
// card, so this asserts the chains are separate and each one is intact.
const chains = new Map();
for (const name of readdirSync(wire).sort()) {
  const body = JSON.parse(readFileSync(join(wire, name), "utf8"));
  if (typeof body.envelope_hash !== "string") continue;
  const key = body.issuer;
  if (!chains.has(key)) chains.set(key, []);
  chains.get(key).push({ name, seq: body.seq, prev: body.prev_envelope_hash, hash: body.envelope_hash });
}
for (const [issuer, links] of chains) {
  links.sort((a, b) => a.seq - b.seq);
  let expected = null;
  for (const [i, link] of links.entries()) {
    if (link.seq !== i + 1) {
      hard += 1;
      console.log(`FAIL  chain ${issuer}: expected seq ${i + 1}, got ${link.seq} (${link.name})`);
    }
    if (link.prev !== expected) {
      hard += 1;
      console.log(`FAIL  chain ${issuer}: ${link.name} prev_envelope_hash ${link.prev} != ${expected}`);
    }
    expected = link.hash;
  }
  console.log(`chain ${issuer.slice(0, 26)}…  ${links.length} link(s), intact`);
}

console.log(`\n${hard} failure(s); ${hashChecked} envelope hash(es) recomputed and matched`);
process.exit(hard > 0 ? 1 : 0);
