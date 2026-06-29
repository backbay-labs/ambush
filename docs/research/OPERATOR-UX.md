I've read all existing components, the store, shared types/IPC, the governor, agents, and orchestrator. Here is the concrete design.

---

# Ambush War Room — Operator-Surface UX / Information Architecture

## 0. Grounding: what exists today vs. what the brief demands

Today the app is **tab-routed**: `App.tsx` shows exactly one of `SwarmView | IntelPane | ReceiptsPane` based on `store.tab` (`'swarm'|'intel'|'receipts'`), switched from `TopBar`. Swarm/intel/governance are mutually exclusive full-screen views. Receipts are **polled** (`refreshReceipts`), there is no streaming receipt event, no Finding type, no consensus/quarantine, no attestation, no scope/lease concept. `ReceiptSummary` carries no command arguments, so an argument-level DENY ("out-of-scope curl") can't even be rendered today.

The brief demands a **persistent three-pane war room** where the swarm tree, the focused lane, and the signed audit stream are visible *simultaneously*, with a scope/authorization banner and kill-switch always on top. So the core IA move is: **collapse the three tabs into one always-on layout**, and demote intel/runbook to center-pane *modes* rather than peer tabs.

Color tokens already exist in `globals.css` and I reuse them throughout: `accent #36f1a3` (live/allow), `danger #ff5d6c` (deny/fail), `warn #ffb454` (quarantine/incomplete), `vector #5ad7ff` (corroboration), `panel/panel-2/edge` (chrome).

---

## 1. Information Architecture — the three-pane war room

```
┌──────────────────────────────────────────────────────────────────────────────────────┐
│ TopBar (keep): ◎ Ambush · Operation Nightfall                          [● governed]    │  h-11
├──────────────────────────────────────────────────────────────────────────────────────┤
│ ScopeBanner (NEW):  ⌖ DIFF REVIEW   scope: ./payments-sdk @ a1b2c3   net: DENY-all     │  h-9
│                     fs: ro+sandbox   authz: signed by you 14:02   ████ [ ⛔ KILL ALL ] │
├───────────────┬──────────────────────────────────────────────┬─────────────────────────┤
│ OperationTree │  CenterStage  ( ▣ Lane | ⚑ Findings | ▤ Run ) │  AuditStream (NEW)      │
│ (NEW, from    │  ───────────────────────────────────────────  │  signed receipt feed    │
│  SwarmView    │                                                │  ┌────────────────────┐ │
│  aside)       │   selected mode renders here:                  │  │●ALLOW search vec03 │ │
│               │    • Lane  = TerminalPane + IntelGraph         │  │●ALLOW write  vec07 │ │
│  ▸ 24 vectors │    • Findings = FindingsReview                 │  │⛔DENY curl  vec11 ⚠│ │
│    grouped by │    • Runbook  = RunbookView                    │  │●ALLOW edit   vec02 │ │
│    lease/role │                                                │  │ … live, newest top │ │
│  + Deploy     │                                                │  └────────────────────┘ │
│   Controls    │                                                │  [✔ chain verified 312] │
│  (keep)       │                                                │  filter: All ▾  ⛔only  │
├───────────────┴──────────────────────────────────────────────┴─────────────────────────┤
│ StatusBar (extend): 18 live · 4 done · 2 failed │ intel live │ trust-kernel ● │ chain ⛓312 │  h-7
└──────────────────────────────────────────────────────────────────────────────────────┘
```

Widths: left `OperationTree` `w-80` (reuse the existing `w-80 aside`), right `AuditStream` `w-96` (collapsible to `w-10` rail), center fluid. Persisted in store as `panes: { tree: boolean; audit: boolean }`.

### 1a. The Operation tree (left) — extend `SwarmView` aside + `VectorCard`

Vectors are grouped by **role/lease**, each row shows status dot, codename, **lease chip**, and **ALLOW/DENY tallies**. This replaces the flat list in `SwarmView.tsx` lines 17-29.

```
┌ OperationTree ───────────────────────────┐
│ DeployControls (keep as-is)               │
│ ─────────────────────────────────────────│
│ ⌖ READ-ONLY REVIEW            12 vectors  │   ← group header (collapsible)
│  ● vec-03-authz   [ro]      ✓214  ⛔0      │   ← VectorCard (extended)
│  ● vec-07-crypto  [ro]      ✓180  ⛔0  ⚑3 │   ← ⚑3 = 3 findings emitted
│  ◐ vec-11-deps    [net⊘]    ✓ 96  ⛔1 ⚠  │   ← ⚠ = this lane has a DENY
│ ⌖ SANDBOXED WRITE            8 vectors    │
│  ● vec-19-fuzz    [rw▣ net⊘] ✓ 41 ⛔0     │   ← rw inside microVM, net denied
│ ⌖ FAILED / KILLED            2            │
│  ✕ vec-23-sqli    [rw▣]      ✓ 12 ⛔3      │
└───────────────────────────────────────────┘
```

Lease chip legend (one glyph set, color-coded): `ro` read-only worktree · `rw▣` sandboxed write (container/microVM) · `net⊘` egress denied · `net⊕scope` scoped egress allowlist · `exec▣` exec only inside sandbox. The chip is the visible promise that **worktrees aren't the boundary** — `rw▣` means a real microVM.

### 1b. Focused lane (center, **Lane** mode) — keep `TerminalPane`, add `IntelGraph`

```
┌ CenterStage · ▣ Lane ─────────────────────────────────────────────┐
│ vec-07-crypto · branch ambush/vec-07 · agent: Claude Code  [▣][↻]  │  ← TerminalPane header (keep)
│ ┌───────────────────────────────────┬───────────────────────────┐ │
│ │  live PTY (xterm)                 │  IntelGraph (NEW, collaps.)│ │
│ │  $ rg -n "jwt.verify" .           │   this lane's findings:    │ │
│ │  src/auth/token.ts:42  ...        │   ⚑ JWT alg=none accepted  │ │
│ │                                   │   ⚑ HMAC key in repo       │ │
│ │                                   │   ─ corroborated-by ───    │ │
│ │                                   │   vec-03 ·●  vec-19 ·●     │ │
│ └───────────────────────────────────┴───────────────────────────┘ │
└───────────────────────────────────────────────────────────────────┘
```

`TerminalPane.tsx` is reused verbatim (it already keys on `terminalId` and replays scrollback). `IntelGraph` is a right-side rail in Lane mode: the **per-lane slice** of the findings graph (this vector's findings + edges to lanes that corroborate them). The full OpenKnowledge webview (`IntelPane`) is retained but moves to a Runbook sub-tab / "Open full wiki" button — it's the browse surface, not the war-room surface.

### 1c. Unified Audit Stream (right) — refactor `ReceiptsPane` → `AuditStream`

The current `ReceiptsPane` table becomes a **live, append-newest-on-top stream** that's always visible. It subscribes to a new `evt:receipt` event (see §5) instead of only polling. DENY rows are full-red and pinned-sticky for ~6s. Footer carries the **verify badge** for the whole chain.

```
┌ AuditStream ───────────────────────────────┐
│ ⛓ signed receipts · trust-kernel            │
│ filter: [All ▾]  [⛔ DENY only]  [🔍 vec-11] │
│ ───────────────────────────────────────────│
│ ⛔ DENY  net.connect  vec-11        14:07:22 │  ← red, sticky, click→detail
│    curl https://pastebin.com/raw/x          │     args shown (NEW field)
│    ✗ host not in scope allowlist             │     policy reason
│ ● ALLOW  fs.read   src/db.ts  vec-03 14:07:21│
│ ● ALLOW  ok.write  findings/3  vec-03 14:07:19│
│ ● ALLOW  fs.read   go.sum    vec-11  14:07:18│
│ …                                            │
│ ───────────────────────────────────────────│
│ [✔ chain verified · 312 receipts · ed25519] │  ← VerifyBadge, click→re-verify
└─────────────────────────────────────────────┘
```

---

## 2. Signature moments as UX

### 2a. Real-time DENY toast + receipt — NEW `DenyToast` + `ToastHost`

When an `evt:receipt` with `verdict==='DENY'` arrives, the store pushes it to `toasts[]` and the row is flagged in `AuditStream`. A `ToastHost` (fixed, bottom-right, `z-50`) renders:

```
                       ┌──────────────────────────────────────┐
                       │ ⛔  DENIED in real time      vec-11   │
                       │ net.connect → pastebin.com:443       │
                       │ policy: scope.egress (host not in    │
                       │ allowlist)   ·  receipt #312         │
                       │ [ View receipt ]      nothing left   │
                       │                        the box ✓     │
                       └──────────────────────────────────────┘
```

Auto-dismiss 6s (DENY toasts persist until clicked). "View receipt" deep-links the `AuditStream` to that row + opens the receipt drawer (signed JSON, policy hash, chain prev-hash). This is the literal demo beat: *"a lane's out-of-scope curl is DENIED in real time."* The toast is driven by the same event that writes the row, so they're guaranteed consistent.

### 2b. Slop quarantine — inside `FindingsReview` (NEW), the painkiller centerpiece

Findings are clustered by the synthesis step into **the same underlying issue**. Two columns: **Corroborated** (≥2 *independent* lanes agree) and **Quarantine** (lone / unconfirmed). The killer subtlety from the brief — *N agreeing lanes can be one model hallucinating N times* — is made explicit by a **model-diversity meter**, not just a lane count.

```
┌ CenterStage · ⚑ Findings ─────────────────────────────────────────────────────────────┐
│  CORROBORATED (3)                          │  QUARANTINE — unverified slop (5)          │
│ ┌────────────────────────────────────────┐ │ ┌────────────────────────────────────────┐ │
│ │ ▣ HIGH  JWT alg=none accepted          │ │ │ ◐ MED  "Possible SSRF in fetchAvatar"  │ │
│ │ src/auth/token.ts:42 · CWE-347         │ │ │ src/img.ts:88 · CWE-918                 │ │
│ │ corroboration: 3 lanes / 2 models      │ │ │ corroboration: 1 lane / 1 model        │ │
│ │ [Claude ▰▰] [Codex ▰] diversity ●●○    │ │ │ diversity ●○○   ⚠ single source        │ │
│ │ evidence: PTY✓ poc.http✓ receipt#218✓  │ │ │ evidence: PTY✓  poc ✗  receipt ✗       │ │
│ │ [ Confirm → deliverable ] [ Dismiss ]  │ │ │ [ Promote ] [ Dismiss as slop ]        │ │
│ └────────────────────────────────────────┘ │ └────────────────────────────────────────┘ │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

A cluster lands in **Quarantine** if `distinctModels < 2` OR no lane carries a reproducible evidence artifact (PoC/exec receipt) — i.e., it's unconfirmed *or* mono-model. The diversity dots (`●●○`) read distinct frontier models, so "3 lanes / 1 model" still shows `●○○` and stays quarantined — that's the correlated-error guard rendered as UI.

### 2c. Export Attestation + Verify — NEW `AttestationDialog` + `VerifyBadge`

**Export** is launched from `RunbookView`. A two-step dialog:

```
┌ Export Attestation ─────────────────────────────────┐   ┌ Verify ───────────────────────────┐
│ Step 1 — Contents                                   │   │ drop a .ambush-attest bundle…      │
│  ☑ 3 confirmed findings                             │   │ ┌────────────────────────────────┐ │
│  ☑ 312 receipts (hash-chained, head 9f3a…)          │   │ │ verifying on this machine…     │ │
│  ☑ in-toto statement + Sigstore bundle              │   │ │ ✔ chain intact (312 links)     │ │
│  ☑ policy packs (diff-review v1, sha 4c1…)          │   │ │ ✔ ed25519 sig valid            │ │
│  signer: you · ed25519 fp 7C:2A:… (local key)       │   │ │ ✔ 3 findings ↔ receipts match  │ │
│ ─────────────────────────────────────────────────── │   │ │ key fp 7C:2A:…  (this operator)│ │
│ Step 2 — [ Export bundle ]  → operation.attest.tgz   │   │ └────────────────────────────────┘ │
│ "Nothing left the box. This verifies on a clean PC." │   │ [ ✔ VERIFIED ]   ambush verify ✓   │
└──────────────────────────────────────────────────────┘   └────────────────────────────────────┘
```

`VerifyBadge` is reused in three places: AuditStream footer (whole-chain), the Verify dialog, and on the exported Runbook header. States: `verified` (green check), `unverified`/`stale` (warn), `broken` (danger, chain mismatch). Verify calls the same `ambush verify` logic the CLI ships, surfaced over IPC.

### 2d. Consolidated Runbook — NEW `RunbookView` (subsumes `IntelPane` consolidate)

`consolidate()` already exists in the store and writes `RUNBOOK.md`. `RunbookView` renders that synthesized deliverable as the **final review surface**, not raw markdown in a webview:

```
┌ CenterStage · ▤ Runbook ──────────────────────────────────────────┐
│ Diff Review — payments-sdk @ a1b2c3        [✔ chain verified 312]  │
│ Deliverable: 3 confirmed · 5 quarantined (excluded) · 0 open       │
│ ───────────────────────────────────────────────────────────────── │
│ 1 ▣ HIGH JWT alg=none — token.ts:42 — CWE-347 — 3 lanes/2 models   │
│ 2 ▣ HIGH HMAC key committed — config.ts:9 — CWE-798 — 2 lanes/2 m  │
│ 3 ◐ MED  Timing-unsafe compare — auth.ts:71 — CWE-208 — 2/2        │
│ ───────────────────────────────────────────────────────────────── │
│ [ Re-consolidate ]  [ Open full wiki ]  [ ⤓ Export Attestation ]   │
└────────────────────────────────────────────────────────────────────┘
```

Quarantined items are listed but visibly **excluded** from the signed deliverable — the buyer sees exactly what was filtered and why.

---

## 3. Validated-findings review surface (the painkiller made visible)

This is `FindingsReview` + `FindingCard`, the heart of the product. Each card carries everything a staff AppSec engineer needs to confirm/dismiss in seconds, and the confirm action is what flows into the signed deliverable.

`FindingCard` anatomy (props-level spec in §4):
- **Severity** badge (`critical/high/med/low/info`) using `danger/warn/accent` tokens.
- **Identity**: title, `file:line`, `cwe`, owning vector(s).
- **Corroboration**: `lanes N / models M` + diversity dots; mono-model gets a `⚠ single source` tag.
- **Evidence row** (the non-repudiation made tangible): three checkable artifacts — `PTY` (link to the exact terminal scrollback offset in `TerminalPane`), `PoC` (e.g. `poc.http`, opens artifact), `receipt#` (deep-link into `AuditStream`; proves the tool call that produced the finding actually happened and was allowed). A finding with no allowed-receipt evidence cannot be confirmed.
- **Actions**: `Confirm → deliverable` / `Dismiss as slop` / (quarantine) `Promote`. Confirm sets `finding.status='confirmed'` and adds it to the attestation manifest; the count in `RunbookView` and `ScopeBanner` updates live.

**What makes the final signed deliverable:** only `status==='confirmed'` findings, each with ≥1 ALLOW receipt as evidence + ≥2 distinct models OR an exec/PoC receipt. The bundle = confirmed findings ∪ their evidence receipts ∪ full hash-chained receipt log ∪ in-toto statement ∪ policy pack hashes, Ed25519-signed by the local operator key.

---

## 4. Component map — keep / extend / replace + NEW

### Keep (reuse unchanged or near-unchanged)
| Component | Action |
|---|---|
| `TerminalPane.tsx` | **Keep.** Embeds in CenterStage Lane mode. |
| `lib/terminalHub.ts`, `lib/cn.ts` | Keep. |
| `DeployControls.tsx` | Keep; mount inside `OperationTree` (it already is the aside header). Add template-aware default count. |
| `TopBar.tsx` | Keep; **remove the swarm/intel/receipts tab switcher** (lines 32-47) — those become CenterStage modes / persistent panes. Leave logo + op name + governed pill. |

### Extend
| Component | Change |
|---|---|
| `VectorCard.tsx` | Add **lease chip**, **ALLOW/DENY tallies**, findings count `⚑N`, per-lane DENY `⚠`. New props read from extended `Vector` (§5). |
| `StatusBar.tsx` | Add **trust-kernel daemon** indicator (rename "governed/ungoverned" → trust-kernel `●/○`) and **chain head** `⛓ 312`. Reuse existing counts reducer. |
| `OperationSetup.tsx` | Add **one-click templates** (Security review / Dependency vet / Diff review) as a 3-button row that pre-fills objective + scope + lease defaults; add **scope** (target path/host allowlist) and **egress allowlist** fields feeding the new `scope` on `Operation`. |
| `IntelPane.tsx` | Keep webview; relocate as "Open full wiki" target + the Lane-mode `IntelGraph` data source. Drop the standalone tab. |

### Replace / restructure
| Component | Change |
|---|---|
| `App.tsx` | Replace tab routing (lines 33-39) with `<WarRoom/>` (still gated by `booting`/`!operation`). |
| `SwarmView.tsx` | Split: aside → `OperationTree`; main → `CenterStage`. SwarmView itself retired. |
| `ReceiptsPane.tsx` | Refactor table into `AuditStream` (streaming, always-on, verify badge, args column, DENY emphasis, filter). Reuse `VERDICT_STYLE` map. |

### NEW components (12)
`WarRoom.tsx` (3-pane shell) · `ScopeBanner.tsx` (scope/authz/template + KILL) · `OperationTree.tsx` (grouped vectors + DeployControls) · `CenterStage.tsx` (segmented Lane/Findings/Runbook) · `IntelGraph.tsx` (per-lane findings rail) · `AuditStream.tsx` · `FindingsReview.tsx` · `FindingCard.tsx` · `DenyToast.tsx` + `ToastHost.tsx` · `AttestationDialog.tsx` (Export + Verify) · `VerifyBadge.tsx` · `RunbookView.tsx`.

---

## 5. Data + IPC the React dev needs (new types & channels)

Add to `src/shared/types.ts`:

```ts
export type LeaseFs = 'ro' | 'rw-sandboxed'
export type LeaseNet = 'none' | 'scoped'
export type LeaseExec = 'denied' | 'sandboxed'
export interface VectorLease { fs: LeaseFs; net: LeaseNet; exec: LeaseExec; scopeId: string }

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'
export type FindingStatus = 'unconfirmed' | 'quarantined' | 'corroborated' | 'confirmed' | 'dismissed'
export interface EvidenceRef { kind: 'pty' | 'poc' | 'receipt' | 'file'; label: string; ref: string }
export interface Finding {
  id: string; clusterId: string; vectorId: string; title: string
  severity: Severity; file: string | null; line: number | null; cwe: string | null
  status: FindingStatus; evidence: EvidenceRef[]
}
export interface FindingCluster {     // the synthesis output: one real issue
  id: string; title: string; severity: Severity; file: string | null; cwe: string | null
  findingIds: string[]; vectorIds: string[]
  models: string[]; distinctModels: number     // <-- correlated-error guard
  status: FindingStatus
}
export interface ScopeAuth {
  templateId: 'security-review' | 'dependency-vet' | 'diff-review'
  targetRef: string; fsScope: string[]; egressAllow: string[]
  signedAt: number; signerFp: string
}
export interface Attestation {
  verified: boolean; receiptCount: number; chainHead: string; signerFp: string
  checks: { chain: boolean; signature: boolean; findingsMatch: boolean }
}
```

Extend `Vector` with `lease: VectorLease; allowCount: number; denyCount: number; findingCount: number; model: string`. Extend `Operation` with `scope: ScopeAuth`. Extend `ReceiptSummary` with `args: string | null; reason: string | null; vectorId: string | null; prevHash: string | null`.

Add IPC channels (mirror existing `IPC` map + `AmbushApi` in `src/shared/ipc.ts`):
```
findingsList → Finding[]        clustersList → FindingCluster[]
findingConfirm(id) / findingDismiss(id) / findingPromote(id)
attestationExport(findingIds) → { path }     attestationVerify(path) → Attestation
chainVerify() → Attestation                  scopeAuthorize(scope) → Operation
// streaming events (the demo depends on these):
evtReceipt   (ReceiptSummary)   // drives AuditStream + DenyToast in real time
evtFinding   (Finding)          evtCluster (FindingCluster)
```

Store additions (`useStore.ts`): `findings: Finding[]`, `clusters: FindingCluster[]`, `toasts: ToastItem[]`, `attestation: Attestation | null`, `centerMode: 'lane'|'findings'|'runbook'`, `panes`, plus `onReceipt`/`onFinding`/`onCluster` subscriptions registered in `bootstrap()` alongside the existing `onVectorUpdate` etc. The existing poll-based `refreshReceipts` stays as a fallback/initial load.

---

## 6. Minimal changes to ship the killer demo

The demo has exactly four beats; here's the smallest build that lands each:

1. **24 heterogeneous lanes on untrusted code** — already works (`DeployControls` count slider goes to 50, `AGENT_PROFILES` are heterogeneous). Only add the **lease chip** to `VectorCard` so the `rw▣ net⊘` posture is visible. (extend 1 file)
2. **Out-of-scope curl DENIED in real time** — needs the streaming `evtReceipt` event in the governor/bus + `ReceiptSummary.args/reason`, `AuditStream` (DENY-emphasized list), and `DenyToast`/`ToastHost`. This is the highest-leverage net-new: ~3 small components + 1 event. Back it with the trust-kernel's argument-level network policy (host allowlist).
3. **3 lanes corroborate / 1 lone quarantined** — needs `FindingCluster` synthesis + `FindingsReview`/`FindingCard` with the **model-diversity meter**. The synthesis can run inside the existing `consolidate()` path (it already reads every `findings/*.md`); it just additionally emits clusters with `distinctModels`. (~2 components + extend consolidate)
4. **Export Attestation that verifies on a clean machine** — `AttestationDialog` + `VerifyBadge` + `attestationExport`/`attestationVerify` IPC bound to the engine's existing Ed25519/hash-chain crypto, plus the `ambush verify` CLI reusing the same verifier. (~2 components + 2 IPC handlers)

Everything else (ScopeBanner template buttons, IntelGraph, RunbookView polish, pane collapsing) is fast follow on top of components 1-4. The persistent three-pane `WarRoom` shell + `CenterStage` mode switch is a one-file layout refactor of `App.tsx`/`SwarmView.tsx` and should land first so the four beats have a home.

**Relevant files:**
- Existing to edit: `/Users/connor/orca/workspaces/ambush/ruffe/src/renderer/src/App.tsx`, `.../components/{SwarmView,VectorCard,StatusBar,TopBar,OperationSetup,ReceiptsPane,IntelPane}.tsx`, `.../store/useStore.ts`, `/Users/connor/orca/workspaces/ambush/ruffe/src/shared/{types,ipc}.ts`, `/Users/connor/orca/workspaces/ambush/ruffe/src/main/governance/chio-governor.ts` (emit streaming receipts + args/reason), `/Users/connor/orca/workspaces/ambush/ruffe/src/main/swarm/swarm-orchestrator.ts` (cluster synthesis in `consolidate`).
- Keep as-is: `.../components/TerminalPane.tsx`, `.../lib/{terminalHub,cn}.ts`.
- New files under `/Users/connor/orca/workspaces/ambush/ruffe/src/renderer/src/components/`: `WarRoom.tsx`, `ScopeBanner.tsx`, `OperationTree.tsx`, `CenterStage.tsx`, `IntelGraph.tsx`, `AuditStream.tsx`, `FindingsReview.tsx`, `FindingCard.tsx`, `DenyToast.tsx`, `ToastHost.tsx`, `AttestationDialog.tsx`, `VerifyBadge.tsx`, `RunbookView.tsx`.