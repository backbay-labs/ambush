# Upstream Harvest — License & ROI Vetting

Verification confirms the load-bearing facts (and surfaces one worse-than-stated reality), so I can vet with confidence. Findings below.

---

# Vetting: Harvesting ClawdStrike + Chio into AMBUSH

**Ground-truth checks I ran first** (so the recommendations aren't taking the maps on faith):

- The shim is **157 lines and fails OPEN, while its own comment claims fail-closed** — worse than the brief states. `src/main/governance/chio-governor.ts:8` says *"Chio is fail-closed"*, but `configure()` on a missing binary sets `detail: 'Agents run ungoverned'` and `wrapMcp()` (L83-84) **returns the inner command unchanged** when unavailable. `listReceipts()` returns `[]` on any failure. And `DEFAULT_POLICY` (L13-29) **allows `exec`, `write`, `edit`, `move`** and denies only `delete`. This is the vapor, confirmed.
- `engine/crates/swarm-guard/src/` has exactly **5 guards** (forbidden_path, shell_command, secret_leak, egress_allowlist, path_normalization) — the "9 missing guards" claim holds.
- `swarm-crypto/src/signing.rs` already exposes `trait Signer`, `Keypair`, `verify` (+ canonical/merkle/hashing). **No `SignedReceipt` exists in engine source** (only docs). `swarm-spine` has chain/checkpoint/envelope but **no `trust.rs`**. Gaps confirmed.
- `chio-swarm-authority/Cargo.toml` deps = `chio-core-types`, `serde`, `thiserror` only (clean crate) — but `chio-core-types` is the iceberg. `chio-proof-room/Cargo.toml` pulls **17 `chio-*` crates**. Coupling claims hold.

## 1. License & coupling reality — what must stay subprocess-only

Both upstreams are Apache-2.0, and the engine is already Apache-2.0, so **every Rust→engine lift is a clean reunification needing only NOTICE attribution** — no contamination question. The one genuine license nuance is on the TypeScript side: `chio-ts` is Apache-2.0 *source*. Vendoring it into the MIT control-plane npm package makes that package mixed-license (the vendored files stay Apache-2.0 with patent grant + NOTICE; you cannot relicense them MIT). That's legally fine but it means "the MIT control plane" stops being purely MIT. **Cleaner: `npm`-depend on `@chio-protocol/sdk` as an external Apache-2.0 dependency** rather than vendoring `src/invariants/*`, keeping Ambush's own code MIT. If you must vendor, isolate it in a clearly-labeled Apache-2.0 directory.

**Must stay subprocess/sidecar-only** (importing the source would drag heavy transitive deps or tight upstream-infra coupling):
- `hushd` (42k-LOC axum service: control_db, OIDC, RBAC) — the brief *wants* a daemon; run/fork it, don't vendor.
- `chio-cli` (default-run pulls ~50 crates incl. web3/federation/market) — subprocess a **trimmed** binary, or back the shim with the engine's own `swarmctl serve`.
- `chio-proof-room` (17 chio-crate deps), `chio-siem`, `chio-store-sqlite`, `server.rs` (axum) — sidecars, not libraries.
- Lean4 `formal/` — separate CI lane, never in the product build.

**Carve-out, not import** (low-coupling core trapped inside a high-coupling crate): `chio-swarm-authority`'s verifier is clean, but pulls `chio-core-types` → `attenuation.rs` (~1,099 lines) and the whole Chio type universe. `bundle_a.rs`'s DSSE verify is ~120 lines but its orchestrator routes into the 14-crate domain stack. Extract the leaf logic; stub the routing.

## 2. Dedup & overlap — who's the better source, and what Ambush already has

The two upstreams overlap on three things; pick deliberately or you'll fork yourself into byte-drift hell:

- **Crypto (Ed25519 + RFC 8785).** Both have it; `swarm-crypto` is *already* a fork of ClawdStrike `hush-core`. **Do NOT pull `chio-core-types` crypto.** Re-point Chio's verifiers at `swarm-crypto`. The real risk is two canonical-JSON implementations disagreeing on bytes → every cross-language signature fails. Adopt `hush-core`'s `jcs_vectors.json` + Chio `chio-conformance` as shared corpora; that's the cheap insurance.
- **Signed receipts / attestation.** ClawdStrike `hush-core/receipt.rs` is the *primitive* (same lineage as swarm-crypto, near-mechanical drop-in). Chio proof-room is the *product surface*: DSSE detached-sig, manifest schema, receipt-coverage, NDA redaction, negative-case self-test. **Source the primitive from ClawdStrike; source the bundle/export/verify surface from Chio.** They compose — but only if Ambush picks **one canonical receipt field schema** (see the trap).
- **Policy.** ClawdStrike `HushSpec` (validate/merge/resolve/sign) + `clawdstrike-logos` verifier is the richer *authoring + VALIDATED* layer with no Chio analog. Chio `code_agent.yaml` is ready *content*. Take the schema/validator from ClawdStrike, the content pack from Chio.

**What duplicates what Ambush already has — leave alone:** `swarm-crypto` (canonical/merkle/hashing/signing) → don't re-import, reference vectors only. `swarm-policy` (capability leases + human gate + rate limit) is genuinely fit-for-purpose with no upstream equivalent — **don't replace it.** `swarm-guard`'s sync `GuardPipeline` works; don't drag in the 55k-LOC `HushEngine`. `swarm-whisker` (host-behavior EDR) is net-new vs ClawdStrike's tool-boundary guards — complementary, not duplicate; `hunt-correlate` bolts an IOC store *onto* it.

## 3. ROI ranking

**Single highest-ROI harvest: `hush-core/src/receipt.rs` → `swarm-crypto` (SMALL effort).** Verified: swarm-crypto already ships every dependency it needs (`Signer`, `Keypair`, `verify`, canonical, merkle, hashing), so this is a near-mechanical drop-in. It is the *one* missing primitive — without `SignedReceipt`/`VerificationResult`/`VFY_*` there is no Export Attestation, no `ambush verify`, no MOAT. Its fail-closed `validate_receipt_version` (rejecting schema drift *before* signature check) is the brief's philosophy in code, and its co-signer field is where the human-gate's approval signature attaches. Everything else in the attestation thesis stacks on top of this struct.

**Tier — Harvest now** (high value, low effort, unblocks the brief):
1. `hush-core/receipt.rs` → swarm-crypto **(the pick)** + free conformance corpora (`version_cases.json`, `jcs_vectors.json`).
2. ClawdStrike `apps/agent/src/policy/evaluate.rs` fail-closed contract — the literal antidote to the fail-open shim I confirmed.
3. ClawdStrike `approval/{queue,types}.rs` human-gate (chrono/serde/tokio/uuid only — "easiest lift in the assignment"), incl. the trusted-vs-untrusted resolution split.
4. Chio `code_agent.yaml` — strictly better than the current allow-`exec` default policy.
5. `chio-ts/src/invariants/*` TS client verifier — fixes "no client-side verification" (npm-dep, don't vendor).
6. ClawdStrike `secret_leak.rs` full version (44 patterns/Luhn/masking) — upgrade the 390-LOC stub.
7. ClawdStrike `security/fs.rs` `write_private_atomic` (zero coupling).
8. Chio `receipt_coverage.rs` (allow/deny matrix = the demo painkiller) + `bundle.schema.json` + the 12-line DSSE PAE (the export envelope).

**Harvest later** (high value, larger effort): ClawdStrike `cmd_verify` fused with Chio's `proof verify` exit-code taxonomy → `ambush verify`; `clawdstrike-logos` verifier (pure-Rust path, the VALIDATED engine); `chio-swarm-authority` verifier + v1 schemas + `admission_hook` (the governed-swarm spine); the 9 missing guards; `daemon/manager.rs` supervisor; `audit_queue.rs` + Chio `export.rs` redaction (the NDA deliverable); `spine/trust.rs` TrustBundle → swarm-spine.

**Reference only:** `hushd`, `chio-cli` binary, proof-room `server.rs`, IRM, hunt-correlate, chio-siem, chio-store-sqlite, chio-lineage, chio-conformance, threat-intel async guards, THREAT_MODEL.md, HITRUST mapping, supply-chain cargo-vet skeleton.

**Skip:** Lean4 as a build dep (marketing-only, and ~8 `sorry` + axiomatized ed25519 — claim "spec-level proofs," not "verified implementation"); `spine/attestation.rs` (SPIFFE/k8s/Tetragon); `eas-anchor` (Ethereum contradicts local-first); protocol bridge crates (MCP/A2A/ACP); Chio economy/marketplace/web3; `chio-guard-sdk` WASM (competes with engine guards); the compiled control-console bundle; `enterprise-export` (proof-room-adjacent, conceptual only).

## 4. The trap

The dominant trap is **over-vendoring the Chio proof surface**: `chio-proof-room`/`chio-cli` look like turnkey "ambush verify," but importing them drags 17+ crates and web3/federation/commerce. Take the ~120-line DSSE verify, `receipt_coverage.rs`, and the manifest schema; leave the orchestration.

Second: **two crypto stacks / three receipt formats.** Vendoring `chio-core-types` crypto next to `swarm-crypto`, or adopting `hush-core` `SignedReceipt` *and* `ChioReceipt` *and* the verification-bundle without choosing one canonical field schema, guarantees canonical-JSON byte drift and cross-language verification failures. Decide once: ClawdStrike `receipt.rs` as the internal model, Chio DSSE bundle as the export envelope, and re-point `chio-ts` to verify that chosen schema.

Third: **heavyweight niche deps on the critical path** — Logos's Z3, the sandbox's `nono`, the TPM signer, full multi-hop attenuation (`attenuation.rs`, ~1,099 lines, for Vectors that share a fixed scope). Feature-gate all of them, ship software-first, stub single-hop. And resist the prestige pull of vendoring Lean — it's reputational, not runtime.