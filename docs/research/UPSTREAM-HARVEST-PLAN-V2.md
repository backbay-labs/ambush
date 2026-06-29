# Ambush Upstream Harvest Plan v2 — The Next Wave

*Lead review, read-only. Both upstreams Apache-2.0. Verified in-repo: Ambush ships 20 `swarm-*` crates, but `swarm-guard/src/` contains only 5 guards (`egress_allowlist`, `forbidden_path`, `path_normalization`, `secret_leak`, `shell_command`). The kernel — receipts, attestation, governor, mcp-gate, authority — exists. What it governs is thin.*

---

## 1. The single highest-value next harvest

**Grow `swarm-guard` with ClawdStrike's missing trust-boundary guards, gated behind a one-time `GuardAction` enum extension.** Source: `/Users/connor/Medica/backbay/standalone/clawdstrike/crates/libs/clawdstrike/src/guards/`.

This is the highest-value move because the entire kernel we already built is a *delivery system with almost nothing to deliver*. `swarm-governor::evaluate()` runs `default_pipeline()` and signs a `SignedReceipt`; `swarm-mcp-gate` wraps `tools/call`; the receipt/attestation/authority plumbing all consumes a `GuardResult`. But that pipeline currently enforces only 5 coarse checks. Every dollar already spent on governor + gate + receipts + ambush-verify is amortized over a 5-guard surface. Adding 6 self-contained guards multiplies the value of all prior work at S effort each, with **zero new architecture**.

Two of these guards fix a *known correctness defect*: `swarm-mcp-gate/src/mapping.rs` today lossily coerces MCP `tools/call` into `FileAccess`/`ShellCommand` (e.g. a `delete` becomes a synthetic `rm -rf {path}`). Porting `mcp_tool.rs` plus a native `GuardAction::McpTool` makes the gate *honest* — it governs the actual tool call instead of a fabricated shell string. `patch_integrity.rs` is the real guard for the code-agent's diffs (we already adopted `code-agent.yaml`); `path_allowlist.rs` is the positive-allowlist complement to the existing negative `forbidden_path`.

Critically, this harvest is the **prerequisite that unlocks the monetization wedge** (Section 3): the HIPAA/SOC2/PCI compliance packs (`clawdstrike/packs/`) are written in the exact HushSpec YAML schema we already adopted, and they reference guard keys (`mcp_tool`, `patch_integrity`, `prompt_injection`, `jailbreak`) that don't yet exist in `swarm-guard`. The packs are worthless data until these guards land. So this one harvest is both the deepest extension of the governance kernel and the gate to the GTM story.

The shared prerequisite — extend `swarm-guard::GuardAction` with `McpTool(&str,&Value)`, `Patch(&str,&str)`, `Custom(&str,&Value)` — is done once and also unblocks the async-guard runtime later. Each guard is an async→sync conversion following the *exact recipe already proven* on the 4 originally-harvested guards: drop `async_trait`, reduce ClawdStrike's heavy `GuardContext` to Ambush's `{agent_id, metadata}`, map the (identically-shaped) `Severity`. Add `regex` + `glob` to the workspace.

---

## 2. Ranked harvest table

Lead group = "harvest now." Effort: S ≈ ½–1 day, M ≈ 2–4 days, L ≈ week+.

| # | WHAT | FROM (exact path) | INTO Ambush | Extends the kernel by | Effort | Mode | Lic |
|---|------|-------------------|-------------|----------------------|--------|------|-----|
| **1** | **6 trust-boundary guards** (`mcp_tool`, `patch_integrity`, `path_allowlist`, `computer_use`, `input_injection_capability`, `remote_desktop_side_channel`) + `GuardAction` extension | `clawdstrike/crates/libs/clawdstrike/src/guards/*.rs` | new files in `engine/crates/swarm-guard/src/`; register in `default_pipeline()` | Turns the 5-guard pipeline that governor/gate/receipts already consume into a real enforcement surface; makes `swarm-mcp-gate` honest via native `McpTool` | M (S/guard) | ADAPT | Apache-2.0 |
| **2** | **Compliance policy packs** HIPAA / SOC2 / PCI-DSS | `clawdstrike/packs/{hipaa,soc2,pci-dss}/policies/*.yaml` + manifests | `engine/rulesets/packs/{hipaa,soc2,pci-dss}/` | Same HushSpec schema as adopted `code-agent.yaml`; reframes "governed swarm" as "run in HIPAA mode" — regulated-buyer surface for a data copy | S | COPY (data) | Apache-2.0 |
| **3** | **Packaged-app binary resolver** + **atomic private write** | `clawdstrike/apps/agent/src-tauri/src/daemon/binary_discovery.rs`; `.../security/fs.rs` | `src/main/util/binary-resolver.ts`, `src/main/util/atomic-write.ts` | **Ship-blocker fix**: today `chio-governor.ts`/`terminal-governor.ts`/`openknowledge-engine.ts` resolve bins only via PATH+`cwd/engine/target` → fail-closed governance silently dies in a packaged `.app`. Atomic write protects `governor.secret` + `current.json` | S–M | ADAPT (TS port) | Apache-2.0 |
| 4 | **Process supervisor** (state machine + readiness gate + capped-backoff crash-restart + attach-to-external) | `clawdstrike/apps/agent/src-tauri/src/daemon/{manager,spawn,ready_probe,state}.rs` | `src/main/engine/process-supervisor.ts`; refit `openknowledge-engine.ts` | Makes the engine subprocess supervised; the second consumer it unlocks is promoting one-shot `swarm-governor` into a long-lived governor-oracle daemon | M (1–1.5d) | ADAPT (TS) | Apache-2.0 |
| 5 | **Fuzz harness** for harvested primitives (merkle, sha256, canonical_json, policy_parse, attest_verify, secret_leak) | `clawdstrike/fuzz/` + `arc/fuzz/` (incl. structure-aware `mutators/canonical_json.rs`) | new `engine/fuzz/` workspace | Makes the "tamper-evident / fail-closed" claim *defensible*; regression-guards `swarm-crypto`/`swarm-attest`/`swarm-guard` as the other items land | S–M | ADAPT (re-point deps) | Apache-2.0 |
| 6 | **Multi-hop witness chain** + attenuation-proof primitive | `arc/crates/kernel/chio-swarm-authority/src/verifier/witness.rs`; `arc/crates/core/chio-core-types/src/capability/{attenuation,scope}.rs`; threat tests `arc/crates/tooling/chio-conformance/tests/threats/{delegation_chain_abuse,capability_token_theft}.rs` | extend `engine/crates/swarm-authority` | Lifts authority from single-hop to verifiable Vector→sub-Vector delegation; the kernel literally cannot express sub-delegation today | M–L (3–5d) | ADAPT (Ambush-native `VectorScope`, copy witness envelope) | Apache-2.0 |
| 7 | **Inbound eval-receipt SDK** (`swarm-eval-receipt` + `ambush-eval-receipt` CLI) | `arc/crates/sdk/chio-eval-receipt/{export,verify,bin/cli}.rs` (+ Python binding) | new `engine/crates/swarm-eval-receipt/` | Symmetric inbound mirror of outbound `swarm-attest`: other fleets emit receipt bundles, Ambush verifies offline/fail-closed. "Bring your fleet's receipts, we verify them" | M (2–3d) | COPY+adapt onto `swarm-crypto` | Apache-2.0 |
| 8 | **`chio-egress-contract`** SSRF-hardened egress | `arc/crates/protocol/chio-egress-contract/` | fold into `swarm-guard/src/egress_allowlist.rs` | Drop-in hardening: literal loopback/link-local/IPv6-ULA denial, redirect-chain + response-byte caps over today's string allowlist; backs future route-plan receipts | S–M | COPY+adapt | Apache-2.0 |
| 9 | **SandboxAttestation** types | `clawdstrike/crates/libs/clawdstrike/src/sandbox/attestation.rs` | `engine/crates/swarm-crypto/src/sandbox.rs` | Fills the pre-stubbed `receipt.metadata["sandbox"]` slot that `SignedReceipt::is_kernel_enforced()` already reads; "the OS enforced it" credibility tier | M (types only) | COPY types, drop `nono::` constructors | Apache-2.0 |
| 10 | **NDA redaction + re-sign + safe-archive export**, **receipt-coverage crypto**, **hardened archive reader** | `arc/crates/products/chio-cli/src/{cli/dispatch/proof/export.rs,archive.rs}`; `arc/crates/products/chio-proof-room/src/receipt_coverage.rs` | extend `engine/crates/swarm-attest` + `ambush-verify` | Redacted-but-offline-verifiable single-file deliverable; upgrades coverage from "artifact exists" to "trusted kernel signed this verdict" (ties to `swarm-governor` keys) | M–L | ADAPT (stub Chio re-sign chain) | Apache-2.0 |

Items 11–14 (NormalizedDecision normalizer, constant-time token compare, metering, SIEM/lineage) feed Section 3 or are cheap consistency wins folded into the roadmap.

---

## 3. The Org/Audit-tier bundle — the monetization story

The local-first kernel is a great free/pro product. The **paid Org/Audit SKU** is built from four upstream pieces that have *no kernel equivalent today* and that only make sense once you have signed receipts to feed them — which we do. The pitch: *"Every governed action your swarm takes is signed, metered, streamed to your SIEM in OCSF, traceable through a chain-of-custody DAG, and exportable as a redacted, offline-verifiable evidence bundle for your auditor."*

**(a) SIEM export — the enterprise connector.** Source `arc/crates/observability/chio-siem/` (verified present). Crown jewel is `ocsf.rs` + `exporters/ocsf_exporter.rs` (the compliance lingua franca), with Splunk-HEC / Elastic / Datadog / CEF / webhook formatters, a bounded DLQ, and rate-limiting as reusable shells. This is the heaviest adapt in the wave: `event.rs::SiemEvent` is welded to `ChioReceipt` semantics and `manager.rs` assumes a rusqlite source — both must be rewritten around `SignedReceipt`/`Verdict`/`Provenance` sourced from `swarm-spine` file stores (avoid adding `rusqlite`). New crate `engine/crates/swarm-siem/`. **This is the single feature most likely to close an enterprise deal** — "does it export to Splunk?" is table stakes for regulated buyers.

**(b) Metering — per-lane budget governance (the cost doom-loop lever).** Source `arc/crates/economy/chio-metering/` (`budget.rs`, `budget_hierarchy.rs`, `cost.rs`, `export.rs` — verified present). `BudgetEnforcer.check()/record()` is a clean pre-allow gate wired into `swarm-governor::evaluate()` (deny → still emit a signed deny receipt, matching the existing fail-closed pattern). `AggregateSpend` already meters tokens/requests/bytes, not just money — the direct LLM cost-runaway control. `BudgetTree` (org→dept→team→agent) governs the multi-Vector swarm. Only external dep is a 2-field `MonetaryAmount` → localize as a `swarm-core` type. Pure logic, no async/network/DB. `budget.rs` alone delivers ~80% at S effort; `budget_hierarchy.rs` is the org-tier upsell. `CostMetadata` rides in the already-open `receipt.metadata["cost"]` slot.

**(c) Lineage — chain-of-custody DAG.** Source `arc/crates/observability/chio-lineage/src/schema.rs` (verified present). The gem is the `LineageGraph`/`LineageNode`/`LineageEdge` model with an `EvidenceClass { Asserted, Observed, Verified }` taxonomy and bounded-traversal `TruncationMarker`. Copy `schema.rs` into `swarm-spine/src/lineage.rs` (it belongs beside the existing hash-chained envelopes), add `petgraph`, and adopt `EvidenceClass` widely. Rebuild the ingest/query layer as a projection over `swarm-spine` envelopes rather than the Chio NDJSON+sqlite path. This is what turns "we have receipts" into "here is the provenance graph of how this decision was reached."

**(d) Redacted evidence export — the auditor deliverable (item 10).** The redaction profile in `chio-cli/src/.../proof/export.rs` drops non-public artifacts but **fails closed** if redaction would remove an artifact participating in the primary verdict, force-redacts privacy-forbidden paths, then re-signs the new manifest and packs a deterministic hardened `.tgz`. Paired with the hardened `archive.rs` reader so `ambush-verify` accepts the single file directly. This is the literal artifact you hand a regulator: redacted, signed, offline-verifiable. Add `sensitivity_class` to `ArtifactRef` in both `swarm-attest/src/lib.rs` and the TS producer `attestation.ts`.

**Bundle narrative:** governor signs → metering caps + stamps cost → spine builds lineage with EvidenceClass → SIEM streams OCSF → redacted export hands the auditor one verifiable file. Each layer reuses `swarm-crypto` primitives; none requires re-architecting the kernel. This is the natural paid tier and the strongest reason to do the wave at all.

---

## 4. What to SKIP (and why)

- **Full `SwarmAuthorityBundle` verifier** (`chio-swarm-authority/verifier.rs`, ~3155 LOC). Adopting it forces Ambush's runtime to *produce* signed task-graph DAGs, budget pools, and route plans — a major rewrite. Cherry-pick the witness hop (item 6) only. **Do NOT re-import Chio's revocation epoch** — Ambush's monotonic `epoch_number` + lineage-anchored, rollback-guarded epoch is *strictly better* than Chio's flat list-root.
- **Protocol bridges** — `chio-mcp-edge`, `chio-a2a-adapter`, `chio-acp-proxy`, `chio-ag-ui-proxy`, the 10 provider tool-adapters, `chio-tower`, `chio-envoy-ext-authz`. Each is large and pinned to an external protocol/provider; we already govern MCP via `swarm-mcp-gate`. Multi-week-each product expansion, not a v1 move.
- **`chio-guard-sdk` (WASM guest SDK)** — requires standing up a wasmtime host to run untrusted third-party guards. Premature unless third-party guard authoring becomes a goal.
- **`source_verifier.rs` orchestrator + all PR-937 domain verifier crates** (`chio-transaction-passport`, `chio-commerce-order`, `chio-web3` settlement proofs, `chio-enterprise-export`, …). These encode Chio's agent-economy/commerce/web3 domain and contradict Ambush's local-first security posture. Keep stubbed exactly as `swarm-attest` already does.
- **`async_guards/threat_intel/` providers** (snyk, virustotal, safe_browsing, spider_sense — 2783 LOC alone). External API keys + network egress, against local-first posture. Harvest the async *runtime* later if/when a network-enrichment tier is decided; defer the providers.
- **Proof-room HTTP server, Chio dashboard (`ProofRoomView.tsx` 2772 LOC), brokerd, local control HTTP API.** brokerd and the control API are real future value but are *subsumed by item 4's supervisor* and gated on there being a non-IPC consumer (Ambush's renderer↔main is already trusted in-process IPC). Defer to dedicated design docs.
- **Editor integrations** (`vscode-chio`, `zed-chio`) and **HITRUST narrative prose** — weak fit / GTM collateral, not governance code. The HIPAA/SOC2/PCI *policy packs* (item 2) are the harvestable slice of the compliance story.

---

## 5. Sequenced next-wave roadmap

**Wave A — "more to govern + ship it" (week 1–2, do together):**
1. `GuardAction` extension + the 6 self-contained guards (item 1). *Skip jailbreak/prompt_injection this wave — they each drag a heavy detector module.*
2. Compliance packs (item 2) — lands the instant the guards expose the keys; immediate GTM artifact.
3. Packaged-app binary resolver + atomic-write (item 3) — ship-blocker; do in parallel (TS, independent of Rust work).
4. Fuzz harness (item 5) — regression-guards everything Wave A touches.

**Wave B — control-plane + authority depth (week 3–4):**
5. Process supervisor (item 4); refit `openknowledge-engine.ts`, then promote `swarm-governor` to a supervised oracle daemon.
6. egress-contract hardening (item 8) — cheap, independent security win.
7. Multi-hop witness chain into `swarm-authority` (item 6) + the two threat-test suites — the headline swarm narrative.

**Wave C — the Org/Audit SKU (week 5+, the monetization wave):**
8. Metering (item 11/§3b) wired into the governor.
9. SandboxAttestation types (item 9) — lock the on-wire schema `is_kernel_enforced()` already assumes.
10. Redacted export + receipt-coverage crypto + archive reader (item 10/§3d).
11. SIEM/OCSF (§3a) + lineage `EvidenceClass` DAG (§3c).
12. Inbound `swarm-eval-receipt` SDK (item 7) — partner/audit surface.

**Deferred (design docs, not harvests):** join/terminal fan-in receipts (needs runtime that spawns ≥2 sub-Vectors first), brokerd credential sidecar, local control HTTP API, async-guard network runtime, TrustBundle quorum signing.

Every item adapts onto `swarm-crypto` using the bridge pattern already proven in `swarm-authority/token.rs` and `swarm-crypto/src/receipt.rs`; carry the Apache-2.0 attribution header on each copied file (no NOTICE obligation for clean-room TS ports). Net effect: the wave widens what the kernel *enforces* (guards), proves it *can't be tampered with* (fuzz), lets it *ship* (resolver/supervisor), deepens *who can delegate to whom* (witness chains), and assembles the four pieces — SIEM + metering + lineage + redacted export — into a sellable Org/Audit tier, without importing any of Chio's weaker revocation, premature full-bundle, or domain-specific surface.