# Ambush GTM / Pricing / Packaging — the Burp Playbook, Numeric Edition

Grounded in the locked brief (governed, validated swarm code-review; NDA/burst slice; staff/principal AppSec, boutique principal, or M&A-DD lead as buyer; local-first single-tenant; painkiller = validated signal-to-noise, vitamin = signed attestation). License facts confirmed in-repo: control plane MIT (`/Users/connor/orca/workspaces/ambush/ruffe/LICENSE`, "Backbay Labs"), engine Apache-2.0 (`engine/Cargo.toml`), OpenKnowledge GPL-3.0 invoked subprocess-only (`docs/GOVERNANCE-SECURITY.md:336-341`).

---

## 1. Feature split: OSS-core vs Pro vs Org-Audit

The line is drawn on one principle: **free = the swarm and the safety floor and the verifier (commodity + trust + funnel); Pro = making the swarm's output trustworthy and exportable (the painkiller); Org = making that trust shared, identity-bound, and retained (the program).**

### OSS Core — MIT — free forever (commodity + funnel + trust floor)

| Capability | Why it MUST be free |
|---|---|
| **Fan-out** (`deploySwarm`, up to 100 lanes, concurrent launch) | Replicable with tmux+scripts; it's the demo hook and the CTF funnel, not the moat. |
| **Worktree-per-Vector isolation + PTY terminals + "any CLI agent" profiles** | Commodity (Orca-lineage); table stakes for adoption. |
| **Intel vault** (OpenKnowledge subprocess), wiki-link graph, **basic Consolidate** (concatenation → `RUNBOOK.md`) | The free "calm surface." Basic merge only. |
| **Basic governance: the local trust-kernel daemon** — fail-closed shell/exec/network/fs policy at argument level | A security tool that **paywalls the safety floor doesn't get trusted**. Governance must be on by default and free so people will point it at untrusted code at all. This is also the CTF/offense proving ground. |
| **Local receipts** (append-only, single machine) + **`ambush verify` CLI** | **The verifier must be free and open** — an attestation is worth nothing if checking it costs money. Mirrors Sigstore `cosign verify` (free) / in-toto. You pay to *produce* trust, never to *check* it. |

**Boundary defense:** everything free is either commodity (cloneable in a weekend), the trust floor (un-paywallable on principle), or the funnel (CTF → leaderboard → Pro pipeline). Nothing free, on its own, produces a *trustworthy, exportable* result.

### Pro — ~$300-500/seat/yr — the differentiator (painkiller + sandbox + vitamin)

| Capability | What it is | Why it's the paid line |
|---|---|---|
| **Validated slop-filter** (consensus crate, load-bearing) | Cross-lane corroboration; quarantine of lone unconfirmed findings; **cross-model-family decorrelation** (defends the #1 risk: BYO agents are the same few frontier models → correlated hallucinations; N agreeing lanes can be one model wrong N times). | THE painkiller. Validated signal-to-noise is the reason to buy. |
| **Container/microVM sandbox** for any write/exploit lane | Real isolation (worktrees are *not* a security boundary). | Enables "point 24 BYO vectors at untrusted code on your laptop" safely → "nothing left the box." |
| **Consolidate *synthesis*** | LLM-grade dedup, severity normalization, graph-aware cross-lane merge — beyond free concatenation. | The deliverable-grade report. |
| **Signed Attestation export** | Ed25519 hash-chained, in-toto/Sigstore-aligned bundle + export UX; policy hash stamped per receipt. | The non-repudiation vitamin. `ambush verify` is free; **producing** the signed bundle is Pro. |
| **Policy packs** | Curated argument-level scopes for M&A-DD / dependency-vetting / pre-release-diff. | Productized governance for the wedge. |

**Boundary defense — the sign/verify split is the cleanest line:** you pay to *generate* a validated, synthesized, signed artifact; anyone, anywhere, on a clean machine, verifies it for free. That's exactly what makes the attestation credible (an external party never needs an Ambush license to trust it) *and* what makes Pro worth buying (the buyer is paying for produced trust, not checked trust).

### Org / Audit — ~$15-40k/yr — the program (team + compliance)

| Capability | Why Org, not Pro |
|---|---|
| **Shared audit server** — multi-seat receipt aggregation, org-wide tamper-evident chain | Single-tenant local-first stays the Pro default; a *team* sharing provenance is a different product. |
| **SSO/SAML + RBAC** | Identity-binding attestations to people is an org/compliance need. |
| **Retention & legal-hold** — configurable retention, auditor export | DD/deal-file and compliance retention. |
| **Receipt SDK** — programmatic ingest/verify, CI/CD + deal-room embedding | Lets the org wire attestations into their own pipelines/data-room. |
| **Org policy-pack distribution & governance** | Central policy management across operators. |

**Boundary defense:** classic Burp → Burp Enterprise jump (individual power tool → org program). The trigger is structural, not feature-greed: the moment provenance must be **shared, identity-bound, and retained across a team and handed to external parties**, you're an Org. See §5 for the exact conversion event.

---

## 2. Pricing with real comparables

| Product | What they charge | Model | Read-across to Ambush |
|---|---|---|---|
| **Burp Suite Pro** | **$475/seat/yr** (2025); $380-420 at 5-10 seats, $320-380 at 20+ | Per *person*, expensed on a team card, no procurement | **The anchor.** Ambush Pro at **$400** sits just under Burp in the "expense-it, no-approval" zone. Position literally as *"Burp for the agent swarm."* |
| **Semgrep** | Free ≤10 contributors/repos; **Team $35/contributor/mo (~$420/yr)**; Enterprise custom | Per active contributor | Brackets the $300-500 AppSec-seat band; validates per-seat AppSec pricing. |
| **Snyk** | Free; **Team $25/dev/mo (~$300/yr)**, capped at 10 devs; Enterprise custom ($697-948/dev/yr at 50+) | Per contributing dev | Lower bound of the band. Note: these scale by *dev count*; Ambush scales by **operator** (the staff/principal engineer) — 1-5 seats/org, low friction, high margin. |
| **ZeroPath** (AI-native SAST) | **$1,000/mo base + $60/dev/mo**; Core $200/mo (1-25 repos) | Platform + per-dev | Proves the AI-native premium exists; Ambush Pro undercuts on a per-operator basis. |
| **Corgea** | Free forever + Pro (custom) | — | Free-core + paid-Pro precedent. |
| **XBOW Pentest-on-Demand** | **$4,000-6,000 per test** (depth of a 2-4 wk manual pentest; report in 5 business days) | Per engagement/outcome | The **outcome anchor** for the DD value story. Traditional pentest = $10-35k. |
| **Horizon3 NodeZero** | Quote-based, annual/multi-year, by asset count (Pro/Elite) | Enterprise SOC subscription | The enterprise ceiling Ambush deliberately is *not* (yet) — the IR/DFIR later-expansion comparator. |

**Where Ambush lands:**
- **Pro $400/seat/yr** — $75 under Burp, inside the Semgrep/Snyk seat band, well under ZeroPath per-operator. Round number, instant expense, "the validated slop-filter + sandbox + signed export for the price of a Burp seat."
- **Org $15-40k/yr** — *below a single traditional DD engagement ($25-50k) and below ~3-7 XBOW tests*, but recurring and unlimited bursts. For a PE firm doing 10-30 deals/yr that's ~$1-4k/deal — a rounding error on the deal.

**ROI / value narrative:**

- **M&A technical-DD lead.** A target's codebase DD today = a $25-50k boutique engagement or a time-boxed in-house scramble under NDA. Ambush: run a validated swarm review on your own laptop (NDA-safe — *nothing left the box*), days not weeks, output a **board-grade signed attestation** of exactly what was reviewed and what was denied. All-in cost ≈ $400 seat + a few hundred dollars of tokens per target. **Replaces/de-risks a $25-50k line item at <2% of its cost** and produces an artifact the deal lawyers actually want. Org at $15-40k/yr is sub-rounding-error across a deal flow.

- **Boutique pentest/AppSec principal.** Sells reviews/DD at $15-40k/engagement, ~15-30/yr (~$300k-1M revenue). Tooling = $400 seat + ~$4-6k tokens/yr = **<2% of revenue.** Two compounding wins: (1) the slop-filter protects *reputation* — one AI-slop-laden deliverable loses a $50k client; (2) the signed-attestation bundle is a **deliverable upgrade** (verifiable artifact, not a PDF) that justifies a higher engagement price. The seat pays for itself on the first engagement.

---

## 3. Unit economics: why the slop-filter must cut *lanes spent*

### Per-lane cost (agentic, multi-turn review lane)

Cumulative per lane: ~1.5M input tokens (file reads, re-reads, growing tool-result context), ~150k output (reasoning + findings).

| Model (API, 2026) | Rate in/out per M | No-cache | With prompt caching (~75% cached) |
|---|---|---|---|
| Claude Opus 4.5 | $5 / $25 | $11.25 | ~$6.2 |
| Claude Sonnet 4.6 | $3 / $15 | $6.75 | ~$3.7 |
| GPT-5.5 | $5 / $30 | $12.0 | ~$6.5 |
| GPT-5 | $0.63 / $5 | $1.7 | ~$1.2 |

**Heterogeneous blended ≈ $6/lane.**

### The two burst regimes

- **Naive (correlated, over-provisioned):** because correlated noise makes any *single* lane untrustworthy, the operator drags the slider to 100 to "feel safe" — and gets the same 2-3 frontier models hallucinating in parallel. **100 × $6 = ~$600/burst.**
- **Governed (slop-filter feeds the scheduler):** decorrelate (cap lanes per model-family), **stop spawning at corroboration saturation**, kill quarantined slop lanes early → **~18 diverse lanes × $6 = $108**, + per-*finding* cross-family adjudication (~40 candidates × $0.20 = $8) → **~$116/burst. ~80% fewer lanes spent.**

### Why it must be LANES SPENT, not findings emitted

If you spawn 100 and filter the *output*, you already paid the $600 — filtering only cleans the report. **Cost (buyer TCO and any Ambush-side validation COGS) is committed at spawn time.** So the slop-filter has to close the loop *into scheduling*: don't spin up 4 lanes of the same model, stop once corroboration saturates, kill divergent slop lanes. Fewer, decorrelated, slightly-more-expensive lanes beat many cheap correlated ones — **better signal AND lower spend at once.**

### The numbers that matter

**Buyer TCO (Pro is BYO-keys → Ambush COGS ≈ $0, ~95%+ gross margin like Burp).** Boutique running 25 engagements/yr × 2 bursts:
- Naive: 50 × $600 = **$30k/yr** token burn.
- Governed: 50 × $116 = **$5.8k/yr.** → **~$24k/yr saved per operator.** A $400 seat that saves $24k = **~60× return on the license**, before analyst triage hours. This is why the $400 Pro price is trivially justified.

**Ambush COGS (managed-validation SKU / Org shared-audit, where Ambush runs the cross-family adjudicator on its own keys):**
- Adjudicate **per finding, never per lane:** ~$0.20 × ~40 = **~$8/burst** COGS.
- Against an effective $50-150/burst Org/validation price → **~85-95% gross margin.**
- **Break-even guardrail:** adjudication COGS must stay **< ~15-20%** of the validation SKU price. Per-finding adjudication ($8) clears it. **Per-lane re-validation would re-run ~18 lanes (+$108/burst), pushing COGS to ~$116 and destroying margin.** Hence the architectural law: **adjudicate findings, never re-run lanes; and cap lanes at spawn.** This is the same discipline that protects the buyer's TCO — the slop-filter is margin-protective on both sides of the BYO/managed line.

---

## 4. The OSS license boundary and how the free/paid line respects it

Three components, three licenses, no copyleft contamination:

- **Control plane (`src/`) — MIT.** All the Pro/Org value (slop-filter, sandbox orchestration, synthesis, attestation export, policy packs, audit server, SDK) is built here and can be **commercially closed** — MIT permits a proprietary Pro build atop the MIT core.
- **Engine (`engine/`) — Apache-2.0.** The real crypto/policy/consensus crates (the slop-filter's spine, Ed25519 hash-chaining). Apache-2.0 is permissive → can be linked into the closed Pro build; patent grant is a plus for an attestation product.
- **OpenKnowledge — GPL-3.0 — subprocess only.** Invoked exclusively via `ok` CLI / MCP / local web server; **never imported or vendored** (`docs/GOVERNANCE-SECURITY.md:336-341`). The subprocess boundary keeps GPL copyleft from reaching the MIT/closed control plane. *Implication for packaging:* the intel-vault UI must stay an embedded `<webview>` of the running `ok` server + native panels talking over MCP/CLI — never a vendored fork. This is a hard line for v1.0 distribution.

**How the free/paid line respects it:** the free OSS core is MIT (and stays genuinely open — fan-out, worktrees, the governance floor, and crucially **`ambush verify`**). Pro/Org features are *additive proprietary modules* over the MIT core and Apache engine — permissive licenses make this clean. The GPL component is never a build dependency of either the free core or the paid modules; it's a runtime subprocess the user installs, so it constrains neither tier. **The verifier being free is not just GTM — it's also the cleanest license posture:** an open, MIT `ambush verify` means the trust artifact is checkable by anyone independent of any proprietary code.

---

## 5. First-revenue motion + design-partner plan, and the Pro→Org proof point

### Channels (Burp playbook: seed the community, sell the painkiller)

1. **CTF leaderboard — the funnel.** Free MIT core + a public leaderboard. CTF/offense is the proving ground per the brief; top players become Pro evangelists and the credibility engine. Offense funnels, it isn't first revenue.
2. **AppSec / red-team communities.** r/netsec, PortSwigger/Burp community, OWASP chapters, offensive Discords, DEF CON local groups. Message: *"governed swarm review that filters AI slop and signs what it found — Burp-priced."*
3. **Boutique consultancies — the first dollars.** Direct outreach to small AppSec/pentest shops and M&A-DD technical advisors. They feel both pains most acutely: slop is reputation-ending in a client deliverable, and a signed/verifiable bundle is an upsell.

### Design-partner program (90 days to revenue)

- Recruit **5-10 boutique AppSec/pentest shops + 1-2 M&A-DD leads** (PE/corp-dev technical advisors).
- Give **Pro free for 90 days** in exchange for: running ≥2 real engagements, validating the killer demo on their own untrusted code, and a named case study.
- **The killer demo is the conversion event** (straight from the brief): ~24 heterogeneous BYO Vectors on untrusted code on the user's laptop → an out-of-scope `curl` **DENIED in real time** → 3 lanes corroborate one finding while a lone unconfirmed one is **quarantined as slop** → **Export Attestation** produces an Ed25519 hash-chained bundle that **verifies on a clean machine**. *"Nothing left the box."* That single run demonstrates painkiller (slop-filter), safety ("nothing left the box"), and vitamin (signed attestation) at once → close Pro.

### The single proof point that converts Pro → Org

**The first time a Pro user's signed attestation is independently `ambush verify`'d by an *external counterparty* on a clean machine** — the acquirer's board / deal counsel / the consultancy's client / an auditor — and that party says *"we trust this, and we want all of them this way."*

That externally-verified attestation is the structural trigger: the instant trust crosses an org boundary and a *team* needs every operator's bundles **identity-bound (SSO), centrally retained, and reproducible org-wide**, single-seat Pro can't carry it — that's the shared audit server + SSO + retention + receipt SDK = **Org**. Concretely: **the first externally-verified attestation inside a live deal or client engagement is the Pro→Org conversion moment.** Instrument for it; it's the metric that predicts every Org upsell.

---

### Sources
- [PortSwigger / Burp Suite Pro pricing $475/seat (2025)](https://appsecsanta.com/burp-suite) · [Vendr PortSwigger](https://www.vendr.com/buyer-guides/portswigger) · [2025 price increase notice](https://www.e-spincorp.com/burp-suite-pro-price-increase-2025/)
- [Semgrep pricing — Team $35/contributor/mo, free ≤10](https://semgrep.dev/pricing/)
- [Snyk pricing — Team $25/dev/mo, Enterprise custom](https://snyk.io/plans/) · [Snyk cliff analysis](https://opensourcebeat.com/article/the-snyk-pricing-cliff-why-small-teams-love-it-why-growing-companies-dont/)
- [ZeroPath pricing — $1k/mo + $60/dev](https://zeropath.com/pricing) · [Corgea (free + Pro custom)](https://corgea.com/learn/best-sast-tools)
- [XBOW Pentest-on-Demand $4-6k/test](https://xbow.com/pricing) · [XBOW On-Demand announcement](https://www.businesswire.com/news/home/20251112470912/en/Announcing-XBOW-Pentest-On-Demand-for-Security-at-Machine-Speed)
- [Horizon3 NodeZero pricing (quote-based)](https://www.spotsaas.com/product/horizon3-ai-nodezero/pricing)
- [Claude API pricing — Opus 4.5 $5/$25, Sonnet 4.6 $3/$15](https://platform.claude.com/docs/en/about-claude/pricing) · [Opus 4.5 details](https://claudefa.st/blog/models/claude-opus-4-5)
- [OpenAI API pricing — GPT-5.5 $5/$30, GPT-5 $0.63/$5](https://developers.openai.com/api/docs/pricing) · [Morph OpenAI pricing table](https://www.morphllm.com/openai-api-pricing)

Repo files backing the license/feature claims: `/Users/connor/orca/workspaces/ambush/ruffe/LICENSE` (MIT), `/Users/connor/orca/workspaces/ambush/ruffe/engine/Cargo.toml` (Apache-2.0), `/Users/connor/orca/workspaces/ambush/ruffe/docs/GOVERNANCE-SECURITY.md:336-341` (GPL subprocess boundary), `/Users/connor/orca/workspaces/ambush/ruffe/docs/PRODUCT.md` and `docs/ROADMAP.md` (current feature state).