#!/usr/bin/env node
// fixtures/derive-ids.mjs -- regenerate every opaque id in the Perch demo fixture.
//
// WHY THIS EXISTS. Every hex id in this fixture is derived, not typed, so that a
// reviewer can prove no id was chosen to make a screenshot look good and so that
// a regenerated fixture is byte-identical. The derivation is deliberately public:
//
//     id = sha256("perch-demo-fixture/v1/" + label)
//
// NOTHING HERE IS A KEY OR A SIGNATURE. The 64-hex "pubkey" values are shaped
// like secp256k1 x-only keys and Ed25519 public keys and are neither: no private
// key exists for any of them and no signature in this fixture verifies. That is
// the same honesty the workspace already owes about its one real call to
// build_signed_envelope, whose keypair is Keypair::from_seed(sha256(
// "approval-ledger-envelope:{ledger_id}")) -- derived from a public identifier --
// at crates/swarm-runtime/src/approval.rs:1807-1809.
//
// Usage:  node fixtures/derive-ids.mjs            # print the table
//         node fixtures/derive-ids.mjs --json     # emit ids.json

import { createHash } from "node:crypto";

const DOMAIN = "perch-demo-fixture/v1/";

const h = (label, bytes = 32) =>
  createHash("sha256").update(DOMAIN + label).digest("hex").slice(0, bytes * 2);

// A 128-hex value shaped like a Schnorr signature. Not a signature.
const sig = (label) =>
  (createHash("sha256").update(DOMAIN + label + "/a").digest("hex") +
   createHash("sha256").update(DOMAIN + label + "/b").digest("hex"));

// A UUID v4-shaped value derived from the same hash, so channel ids parse with
// `val.parse::<Uuid>()` at BUZZ crates/buzz-relay/src/handlers/ingest.rs:549-561,
// which is what makes an `h` tag resolvable at all.
const uuid = (label) => {
  const x = h(label);
  const v = (x.slice(0, 8) + "-" + x.slice(8, 12) + "-4" + x.slice(13, 16) +
    "-" + ((parseInt(x.slice(16, 17), 16) & 0x3 | 0x8).toString(16)) +
    x.slice(17, 20) + "-" + x.slice(20, 32));
  return v;
};

// Short opaque tokens. `hold_id` MUST be opaque: it travels in a kind 26006
// frame and BUZZ crates/buzz-relay/src/handlers/event.rs:115-222's
// filter_fanout_by_access returns every match at :177-179 for a channel-less
// event without consulting p tags, so every community member sees it.
const token = (prefix, label, n = 8) => `${prefix}${h(label).slice(0, n)}`;

export const IDS = {
  // --- Nostr identities (secp256k1 x-only shape, 32 bytes) ---------------
  operator_nostr_pubkey: h("nostr/operator-1"),
  // The SECOND Approve-scoped principal. Used ONLY by the `contested` variant
  // (22-DEMO-FIXTURE.md section 12.1). The base scenario has one operator,
  // because OperatorAuthConfig::effective_principals synthesises exactly one on
  // the shipped default (AMB crates/swarm-core/src/config/operator.rs:153-168).
  operator2_nostr_pubkey: h("nostr/operator-2"),
  bridge_nostr_pubkey: h("nostr/bridge"),

  // --- Ed25519 identities (swarm:ed25519: shape) -------------------------
  operator_ed25519_pubkey: h("ed25519/operator-1"),
  operator2_ed25519_pubkey: h("ed25519/operator-2"),
  bridge_spine_pubkey: h("ed25519/bridge-spine"),
  daemon_ingest_pubkey: h("ed25519/daemon-ingest"),

  // --- The three agent identities a shipped daemon actually registers -----
  // Each is the public half of a PersistedAgentIdentity, whose `id` is
  // AgentId::from_verifying_key -> `swarm:ed25519:{hex}`
  // (AMB crates/swarm-runtime/src/agent_identity.rs:100-105). The role and the
  // slot live beside it in ActiveAgentIdentityRecord; they are NOT part of the
  // id, which is why no shipped agent is ever called `whisker-7a3f`.
  agent_whisker: h("ed25519/agent/whisker/primary"),
  agent_tom: h("ed25519/agent/tom/primary"),
  agent_pouncer: h("ed25519/agent/pouncer/primary"),

  // --- Buzz channels ------------------------------------------------------
  lane_execution_channel: uuid("channel/lane/execution"),
  case_channel: uuid("channel/case/2026-03-17-host-ops-1"),
  watch_channel: uuid("channel/watch"),

  // --- Ambush opaque ids --------------------------------------------------
  hold_a: token("h_", "hold/isolate-host/host-ops-1"),
  hold_b: token("h_", "hold/block-egress/198.51.100.20"),
  containment_lease: token("cl_", "containment-lease/host-ops-1"),
  rollback: token("rb_", "rollback/host-ops-1"),
  trail_a: token("trail-", "audit-trail/hunt-evt-1", 6),
  feedback_id_dismiss: "perch-feedback:suspicious_scripting:hunt-evt-1:" +
    h("nostr-event/verdict-dismiss-scripting"),

  // --- Nostr event ids (32-byte, lowercase hex) --------------------------
  ev_finding_spt_1: h("nostr-event/finding/suspicious_process_tree/hunt-evt-1"),
  ev_finding_scr_1: h("nostr-event/finding/suspicious_scripting/hunt-evt-1"),
  ev_finding_spt_2: h("nostr-event/finding/suspicious_process_tree/hunt-evt-2"),
  ev_escalation: h("nostr-event/escalation/execution/alert"),
  ev_hold_a_open: h("nostr-event/hold/a/open"),
  ev_hold_b_open: h("nostr-event/hold/b/open"),
  ev_verdict_grant: h("nostr-event/verdict-grant-hold-a"),
  ev_verdict_dismiss: h("nostr-event/verdict-dismiss-scripting"),
  ev_hold_a_terminal: h("nostr-event/hold/a/terminal"),
  ev_receipt: h("nostr-event/receipt/hunt-evt-1"),
  ev_lease: h("nostr-event/lease/host-ops-1"),
  ev_rollback: h("nostr-event/rollback/host-ops-1"),
  ev_46010_a: h("nostr-event/46010/hold-a"),
  ev_46010_b: h("nostr-event/46010/hold-b"),

  // --- the `contested` variant: two consoles, one hold -------------------
  ev_verdict_grant_op2: h("nostr-event/contested/verdict-grant-hold-b/operator-2"),
  ev_verdict_grant_op1_contested: h("nostr-event/contested/verdict-grant-hold-b/operator-1"),
  ev_verdict_superseded_op1: h("nostr-event/contested/verdict-superseded-hold-b/operator-1"),

  // --- Non-signatures (128-hex, shaped like a Schnorr sig) ---------------
  sig_placeholder: sig("not-a-signature"),
  operator_ed25519_sig_grant: sig("ed25519/operator-1/grant/hold-a"),
  operator_ed25519_sig_grant_b: sig("ed25519/operator-1/grant/hold-b"),
  operator2_ed25519_sig_grant_b: sig("ed25519/operator-2/grant/hold-b"),

};

// NOTE ON ENVELOPE HASHES. They are NOT derived here and they are not
// placeholders. `build.mjs` computes each one for real — sha256 over the RFC
// 8785 canonical form of the envelope with `envelope_hash` and `signature`
// absent, `0x`-prefixed — using a JCS port of
// AMB crates/swarm-crypto/src/canonical.rs::canonicalize, which is what
// `envelope_signing_bytes` feeds `compute_envelope_hash_hex`
// (AMB crates/swarm-spine/src/envelope.rs:38-51). Any reader can recompute one
// from the committed file, which is what makes the demo's "check against the
// daemon" affordance a real byte diff instead of a picture of one. A hash still
// proves NOTHING about provenance: it is keyless, every card lacks `signature`,
// and every card in this fixture is verification tier 0.

if (process.argv.includes("--json")) {
  const out = { ...IDS };
  process.stdout.write(JSON.stringify(out, null, 2) + "\n");
} else if (import.meta.url === `file://${process.argv[1]}`) {
  for (const [k, v] of Object.entries(IDS)) {
    if (typeof v === "string") console.log(k.padEnd(32), v);
  }
}
