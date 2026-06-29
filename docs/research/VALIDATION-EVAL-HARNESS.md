I have everything I need: the repo facts (findings are freeform `findings/<id>.md` today with no structured schema or consensus layer — the eval must define both), the real engine crypto/consensus primitives, and verified current benchmarks. Here is the runnable plan.

---

# AMBUSH Validation Eval Harness — "Does filtered fan-out beat one strong agent?"

**Owner:** AppSec eng (1–2 people) · **Duration:** 3 weeks (1 pilot + 2 full) · **Gate:** this runs and answers GO/KILL **before** any product engineering. **Decision artifact:** a single scorecard CSV + this plan's thresholds.

The whole company hinges on one falsifiable claim:

> **H1 (signal):** N filtered, consensus-gated heterogeneous lanes beat (a) one strong agent and (b) one strong agent + Semgrep on **finding-level precision** without losing more than 10% of the recall that raw fan-out generates.
> **H2 (independence):** Cross-family lanes add real signal over same-family lanes — i.e. BYO-agent error correlation is low enough that corroboration means something.
> **Kill condition:** if **either** fails, the "validated swarm" wedge is unfounded as specified.

This is deliberately adversarial toward our own thesis. The #1 risk (from the brief) is **correlated errors** — 3 Claude lanes hallucinating the same finding and consensus *promoting* it as corroborated slop. The eval is built to catch exactly that.

---

## 0. Repo wiring (what the eval reads/writes, with real paths)

Today there is **no structured finding output and no consensus/evidence layer** — lanes write freeform markdown:

- `src/main/swarm/swarm-orchestrator.ts:112` → `findingsPath: findings/${id}.md`
- `src/main/swarm/mission.ts` → instructs the agent to "write findings as markdown"
- `swarm-orchestrator.consolidate()` (`:286`) just **concatenates** all `findings/*.md` into `RUNBOOK.md`. There is no dedup, no corroboration, no gate.

So this eval must **define** the structured Finding schema, the consensus key, and the evidence gate. That spec (Sections 3–4) is the deliverable that becomes the product's `Consolidate` pipeline. The attestation reuses real engine crypto:

- `engine/crates/swarm-crypto/src/lib.rs` → `Ed25519Signer`, `canonical_json_bytes`, `sha256_hex`, `verify_detached_signature`
- `engine/crates/swarm-crypto/src/merkle.rs` → `MerkleTree::from_leaves`, `inclusion_proof`, `verify` (the hash-chained bundle)
- `engine/crates/swarm-consensus/` is BFT *committee voting* — **not** finding corroboration. Do **not** reuse it for finding consensus; corroboration is a clustering problem (Section 4). Reuse only the crypto crate for the attestation bundle.

Eval lives in a new sibling, not touching product code yet:

```
eval/
  corpora/            # cloned benchmarks + frozen snapshots + ground_truth.jsonl per task
  runner/             # lane_runner.py  (spawns a lane on a task → findings.jsonl)
  pipeline/           # consensus.py, evidence_gate.py, semgrep_arm.py
  score/              # matcher.py, metrics.py, adjudicate.py, stats.py
  panels/             # panel definitions (homo/hetero composition)
  results/            # per-arm findings, scorecard.csv, adjudication.sqlite
  attest/             # ambush-verify prototype (calls engine swarm-crypto)
```

---

## 1. Corpora (named, real, with ground-truth mechanism)

We need four tiers. **Tier D (negative controls) is non-negotiable** — without code whose correct answer is "no finding," you cannot measure precision or the slop-filter, only recall.

| Tier | Corpus | What / size | Ground truth = oracle | How to get | Lang |
|---|---|---|---|---|---|
| **A. Execution-oracle, real CVEs** | **CyberGym** (UC Berkeley, [arXiv 2506.02548](https://arxiv.org/abs/2506.02548)) | 1,507 real CVE repro tasks, 188 OSS projects; ships Docker harness | **Strongest possible:** fixing commit's patched file+hunks+CWE = location label; PoC crashes pre-patch under sanitizer, clean post-patch = "is real" oracle | clone repo + pull task images; sample ~80 tasks | C/C++/Py/Go |
| **A** | **CVE-Bench** (UIUC, [arXiv 2503.17332](https://arxiv.org/abs/2503.17332), `github.com/uiuc-kang-lab/cve-bench`) | 40 critical web-app CVEs; sandbox exploit verifier | Exploit-success oracle + advisory's affected file/CWE | clone; v2.1.0 (RCE oracle). Use ~20 | PHP/JS/Py web |
| **B. Commit-level, real OSS** | **PrimeVul** ([arXiv 2403.18624](https://arxiv.org/abs/2403.18624), HF `starsofchance/PrimeVul`) | 6,968 vuln / 228,800 safe **functions**, **cleaned labels**, **paired safe/vuln versions** | CVE+CWE+fixing-commit; *paired safe function is a built-in negative control* | HF dataset (JSONL) | C/C++ |
| **B** | **CVEfixes** / **DiverseVul** | vuln-fixing commits w/ diffs | CVE+CWE+commit. **Label noise (~60% on DiverseVul)** → treat as weak labels, adjudicate | HF / scripts | multi |
| **C. Planted-vuln whole apps** | **OWASP Juice Shop** ([owasp.org](https://owasp.org/www-project-juice-shop/)) | full Node/Angular app, ~100 challenges | **Machine-readable** `data/static/challenges.yml` (vuln class, hints, code location) | clone repo | TS/JS |
| **C** | **OWASP NodeGoat** | OWASP-Top-10 Node app | documented tutorial mapping each Top-10 item → code location | clone repo | JS |
| **C / SAST calibration** | **OWASP Benchmark (Java)** + **BenchmarkUtils** | ~2,740 test cases, **deliberate TP *and* FP** | `expectedresults-1.2.csv` (per-case TP/FP + CWE); Youden's-J scorer | clone both repos | Java |
| **D. Negative controls / slop bait** | (1) PrimeVul *safe* halves; (2) OWASP-Benchmark FP cases; (3) a **frozen, hardened release** of a well-audited lib (e.g. a tagged `libsodium`/`ring`/`zod` release) with **no open advisories** | "correct answer = no finding" | any reported finding here = **false positive** | derive from above | mixed |

**Contamination control (these benchmarks are likely in model training data):**
1. Prefer CyberGym instances and OSS commits **after each model's training cutoff** (CyberGym tags dates; filter commits to 2025+).
2. Build a **20–30 finding "private planted set"**: take 6–8 recent clean OSS files and inject known CWE patterns (CWE-89/79/22/78/502) by hand, plus keep matched clean originals as negatives. This set is leak-proof and is the tie-breaker if public corpora look memorized.
3. Report public-vs-private deltas; if public precision >> private, suspect leakage and weight the private set.

**Scope to the wedge.** The buyer reviews *code under NDA / pre-release diffs / dependency vetting*, so the **diff-review framing** is primary: give a lane the repo at the **vulnerable commit** (and for CVEfixes, the diff) and ask "what's exploitable here?" Ground truth = the fixing commit. CTF/CVE-Bench exploit tasks are the **proving-ground funnel**, run as a secondary slice, not the headline number.

**Pilot vs full sizing.** Pilot (week 1): 15 tasks across tiers to debug the harness. Full: target **≥120 ground-truth positives** and **≥150 negative-control opportunities** so precision CIs are ≤ ±0.07. Concretely ≈ 80 CyberGym + 20 CVE-Bench + 60 PrimeVul pairs + Juice Shop/NodeGoat (≈60 planted) + OWASP-Bench slice + 30 private.

---

## 2. The structured Finding schema (this IS the product spec)

Every lane emits, alongside its human-readable `findings/<id>.md`, a `findings/<id>.jsonl` (one object per finding). The lane runner enforces this via the mission prompt (extend `src/main/swarm/mission.ts` reporting protocol). Schema:

```jsonc
{
  "finding_id": "uuid",
  "lane_id": "vec-03-injection",
  "model": "claude-opus-4-8 | gpt-x | gemini-x | qwen-coder-x",   // family-tagged
  "task_id": "cybergym/CVE-2024-XXXX",
  "title": "SQL injection in order lookup",
  "cwe": "CWE-89",                         // REQUIRED, drives the consensus key
  "severity": "critical|high|medium|low",
  "location": { "file": "src/routes/orders.js", "start_line": 42, "end_line": 47,
                "symbol": "getOrderById", "sink": "db.query" },
  "data_flow": { "source": "req.params.id", "sink": "db.query", "sanitizer": null },
  "evidence": [                            // typed, machine-checkable — drives the gate
    { "type": "poc",        "value": "curl '...id=1 OR 1=1--'", "verifier": "exploit_oracle" },
    { "type": "taint_path", "value": "req.params.id -> ... -> db.query", "verifier": "none" },
    { "type": "test",       "value": "tests/poc_test.js",       "verifier": "pytest/jest" },
    { "type": "sast_corro", "value": "semgrep:javascript.lang.security.sqli", "verifier": "semgrep" },
    { "type": "citation",   "value": "OWASP A03",               "verifier": "none" }
  ],
  "lane_confidence": 0.0,                  // self-reported; we measure if it's calibrated
  "raw_md_ref": "findings/vec-03.md#L10"
}
```

**Consensus key** (the dedup/corroboration identity): `K = (normalized_file_path, CWE_class, sink_or_symbol)`, with line ranges considered overlapping if within ±N lines (N=10, tuned on pilot). Two findings corroborate iff same `K` (after a normalization pass). This is the load-bearing definition; Section 4 measures whether it's the right one (dedup-correctness).

---

## 3. The pipeline machinery = the arms' internals

**`consensus.py`** — clusters all lane findings on `K`, outputs clusters with `support = #distinct lanes` and `family_support = #distinct model families`. (Distinct *families*, not lanes, is the anti-correlation lever.)

**`evidence_gate.py`** — a cluster passes iff it meets a configurable rule, e.g.:
`PASS = support ≥ k`  **AND**  `(has machine-verifiable evidence that actually verifies)`,
where "verifies" = the PoC reproduces / the test passes / Semgrep independently flags the same sink. We sweep `k ∈ {1,2,3}` and gate-on/off as the ablation. Unverifiable lone findings are **quarantined as slop** (the demo behavior), not dropped — counted separately.

**`semgrep_arm.py`** — `semgrep --config "p/default" --config "p/owasp-top-ten" --sarif`, map SARIF results → the same Finding schema (`evidence.type=sast_corro`). Match languages to corpus (Semgrep is strong on JS/TS/Py for Juice Shop/NodeGoat/CVE-Bench, weak on C — note this; for OWASP-Bench-Java use `p/java`).

---

## 4. The arms (each maps to a product stage)

| Arm | Definition | Product meaning |
|---|---|---|
| **A0** | Single best agent, 1 lane, no filter | the "one strong agent" baseline |
| **A1** | A0 ∪ Semgrep (union, deduped) | "one strong agent + static analyzer" baseline |
| **A2** | N-lane raw **union** (no consensus) | naive fan-out (max recall, the slop generator) |
| **A3** | A2 → consensus, support ≥ k | the corroboration layer alone |
| **A4** | A3 → **evidence/oracle gate** | **the actual product pipeline** (Consolidate) |
| **A5** | Semgrep alone | pure SAST baseline |
| **A6** | A4 ∪ Semgrep | full Pro pipeline (governed swarm + static) |

N = 6 lanes default (sweep 1,2,4,6,8). Everything runs on the **same task set** so comparisons are paired (enables McNemar).

---

## 5. The correlation experiment (H2 — the existential test)

For each task, build two **panels** of equal size N=6 and run A2→A4 on each:

- **HOMO-6:** 6× the *same* model family (e.g. 6 Claude lanes), varied only by seed/temperature + 3 distinct persona prompts (recon/injection/authz framing). Mirrors "BYO agents are the same few frontier models."
- **HETERO-6:** spread across ≥3 families — Claude, GPT, Gemini, + one OSS (Qwen-Coder or DeepSeek or Llama). Equal lanes/family where possible.
- (Optional **HETERO-3 vs HOMO-3** to isolate count from diversity.)

**Measure independence directly, per panel:**
1. Build each lane's per-ground-truth **error vector** (1 = lane missed/false-positived item i). Compute pairwise **Cohen's κ / φ** between lanes' error vectors.
2. **Effective independent voters** `N_eff` via the standard correlated-voter formula `N_eff = N / (1 + (N−1)ρ̄)` (ρ̄ = mean pairwise error correlation). The literature finds family-correlated panels collapse to **~2.5–3.6 effective voters** ([Nine Judges, Two Effective Votes, arXiv 2605.29800](https://arxiv.org/html/2605.29800); [Hidden Clones, arXiv 2603.17111](https://arxiv.org/abs/2603.17111)).
3. **Correlated-FP promotion rate:** fraction of *false* clusters that reach support ≥ k. This is the kill-shot: if HOMO panels promote hallucinated findings (3 Claude lanes inventing the same non-bug), consensus is actively harmful.
4. **Misleading-majority rate:** items where the consensus answer is wrong but ≥1 lane was right (consensus *destroyed* available signal).

**H2 is supported iff** HETERO shows materially higher `N_eff`, **lower** correlated-FP promotion, and higher precision-at-iso-recall than HOMO. If HETERO ≈ HOMO, BYO independence is a myth and corroboration is theater → contributes to KILL.

---

## 6. Metrics, matching, adjudication, statistics

**Matcher (`matcher.py`)** — a reported finding is a True Positive iff:
- `file` matches a ground-truth patched file **AND** line range overlaps a patched hunk (±10 lines) **AND** `CWE` is in the same class (use a CWE-equivalence map; e.g. CWE-89⊆injection). For whole-app corpora, match on `(vuln_class, endpoint/file)` from `challenges.yml`. For PrimeVul, match on `(function, CWE)`.
- Near-misses (right file, wrong CWE; right vuln, off-by-region) → **human adjudication** (don't auto-decide).
- Any finding on a Tier-D negative-control file = **False Positive**, no exceptions.

**Core metrics (finding level):**
- **Precision, Recall, F1** per arm × corpus.
- **Dedup-correctness:** cluster the reported findings, compare to adjudicated "same underlying vuln" gold clusters via **V-measure + Adjusted Rand Index**. A split (1 vuln → many findings) inflates counts; a bad merge (2 vulns → 1) hides a bug. Both penalized.
- **Cost-per-validated-finding** = total $ (API) + wall-clock / (# adjudicated-true findings that passed the arm's gate).
- **Lanes-spent-per-validated-finding.**
- **Calibration:** reliability curve of `support` (and `lane_confidence`) vs P(correct). The gate threshold `k` is only justifiable if support is calibrated.

**Adjudication protocol:** 2 annotators label every TP/FP/near-miss into `adjudication.sqlite`; report **Cohen's κ** for inter-annotator agreement (target κ ≥ 0.7); a third breaks ties. Adjudicate **blind to arm** to avoid bias. This adjudicated set is the labeled corpus the product's gate is later tuned on (deliverable reuse).

**Statistics (`stats.py`):**
- Paired **McNemar test** per item for A4-vs-A0 and A4-vs-A1 (same tasks → paired). Report p and effect size.
- **Bootstrap 95% CIs** (resample tasks, 10k iters) on precision/recall/F1 for every arm.
- Decisions made on **CIs**, not point estimates — overlapping CIs = "no win."

---

## 7. GREENLIGHT / KILL thresholds (decide on these, no relitigating)

Let `P_x`, `R_x` = precision/recall of arm x; `R_union = R_{A2}`.

**GREENLIGHT (all four must hold):**
1. **Signal:** `P_{A4} − max(P_{A0}, P_{A1}) ≥ +0.15` absolute, with non-overlapping bootstrap CIs **and** McNemar p < 0.05.
2. **Recall retention:** `R_{A4} ≥ 0.90 × R_union` — the filter keeps ≥90% of fan-out's recall (it must not become a strong agent with extra steps).
3. **Independence pays:** HETERO `N_eff ≥ 1.5 × HOMO N_eff` **and** HETERO precision-at-iso-recall > HOMO (CIs separated).
4. **Slop is contained & cheap:** correlated-FP promotion rate (HETERO, A4) < 0.10, **and** cost-per-validated-finding(A4) ≤ 3 × cost(A1).

**KILL / PIVOT (any one):**
- **K1:** `P_{A4}` CI overlaps `P_{A1}` at iso-recall → governed swarm doesn't beat "strong agent + Semgrep." The cheaper baseline wins.
- **K2:** HETERO ≈ HOMO (N_eff within 10%, no precision gain) → BYO independence is fictional; corroboration is theater.
- **K3:** HOMO consensus **promotes** correlated FPs such that `P_{A4} < P_{A0}` → consensus is *actively harmful* (the brief's nightmare confirmed).
- **K4:** Recall retention < 0.75 → the filter is just an expensive single agent.

A **YELLOW** (signal real but small, or only HETERO works) means: ship, but the product **must force family-diversity** and the slop-filter is the whole pitch — sandboxing/attestation become secondary. That outcome itself reshapes the roadmap.

---

## 8. Attestation tie-in (validates the vitamin, cheaply)

For one full run, emit the **Export Attestation** end-to-end so we prove "nothing left the box" works on real data:
- Wrap each adjudicated cluster as an **in-toto Statement** (predicate type `Test Result` / `Vulnerability`; SARIF embedded for Semgrep corroboration — [in-toto/attestation spec](https://github.com/in-toto/attestation)).
- Hash-chain the bundle with `MerkleTree::from_leaves` and sign the root with `Ed25519Signer` (real crates, Section 0).
- Prototype **`ambush verify`** (`eval/attest/`) that re-derives the Merkle root and checks the Ed25519 signature on a clean machine. Success = the headline-demo's verifier is real, not vapor. (This is a side-quest; not part of GO/KILL, but de-risks the Pro feature in the same 3 weeks.)

---

## 9. Schedule, commands, budget

**Week 1 — pilot + harness.**
```bash
# clone corpora
git clone https://github.com/uiuc-kang-lab/cve-bench eval/corpora/cve-bench
git clone https://github.com/OWASP-Benchmark/BenchmarkJava eval/corpora/owasp-bench
git clone https://github.com/OWASP-Benchmark/BenchmarkUtils eval/corpora/owasp-bench-utils
git clone https://github.com/juice-shop/juice-shop eval/corpora/juice-shop
git clone https://github.com/OWASP/NodeGoat eval/corpora/nodegoat
# CyberGym per its README (Docker task images); PrimeVul via HF datasets
python -c "from datasets import load_dataset; load_dataset('starsofchance/PrimeVul')"
# build ground_truth.jsonl per task; write the matcher; run 15-task pilot through A0,A2,A4
```
Validate: schema emission, matcher against `expectedresults-1.2.csv` (should reproduce OWASP-Bench TP/FP exactly), κ on a 30-finding adjudication slice.

**Week 2 — full run, all arms.** Run A0–A6 across all tiers; run HOMO-6 vs HETERO-6 panels. ~ (80+20+60+60+30) tasks × 6 lanes × 7 arms is the heavy compute; parallelize lane_runner, cache per-lane findings so arms A2–A6 are pure post-processing (no re-querying models).

**Week 3 — score, adjudicate, decide.** Two-annotator adjudication, bootstrap CIs, McNemar, fill `scorecard.csv`, run the GO/KILL table, ship the one-page verdict + the finding-schema/consensus/gate spec (which becomes the product `Consolidate` ticket).

**Budget:** dominated by hetero API calls. Estimate ≈ 250 tasks × 6 lanes × ~$0.30–1.50/lane ≈ **$1.5–4k** API + CyberGym Docker compute. Cache aggressively; pilot first to catch cost blowups. (CyberGym's own paper spent $40k across 1,507 tasks at full scale — our sampled ~80 is ~5% of that.)

---

## 10. Risks & mitigations

- **Training-data leakage** → private planted set + post-cutoff commits + report public/private delta (Section 1).
- **Matcher is the experiment's soul** → calibrate it to reproduce OWASP-Benchmark's published scores exactly before trusting it elsewhere; adjudicate all near-misses by hand.
- **Semgrep language coverage** → match corpus language to Semgrep strength; don't let a weak C ruleset flatter the swarm.
- **Lane prompt is a confound** → freeze identical mission prompts across families (extend `mission.ts`); persona variation is *within* HOMO only.
- **Self-reported `lane_confidence` is unreliable** → gate on machine-verifiable evidence + cross-family support, never on self-confidence; we *measure* confidence calibration but don't trust it.
- **Consensus key wrong granularity** → dedup-correctness (V-measure/ARI) is an explicit metric, and N (line tolerance) is tuned on the pilot.

---

### One-line summary for the calling script
Build `eval/` with four corpus tiers (CyberGym + CVE-Bench execution oracles, PrimeVul commit labels, Juice Shop/NodeGoat/OWASP-Benchmark planted apps, plus a private planted set and PrimeVul-safe negative controls); emit a structured Finding JSONL per lane; compare 7 arms (single / single+Semgrep / raw-union / consensus / consensus+gate / Semgrep / full) on finding-level precision/recall/F1/dedup/cost; run HOMO-vs-HETERO panels measuring effective-independent-voters and correlated-FP promotion; **GREENLIGHT** only if consensus+gate beats both baselines by ≥+15pts precision at ≥90% recall retention *and* heterogeneity demonstrably adds independence, else **KILL**.

**Sources:** [CVE-Bench (arXiv 2503.17332)](https://arxiv.org/abs/2503.17332) · [Cybench (arXiv 2408.08926)](https://arxiv.org/abs/2408.08926) · [CyberGym (arXiv 2506.02548)](https://arxiv.org/abs/2506.02548) · [PrimeVul (arXiv 2403.18624)](https://arxiv.org/abs/2403.18624) · [DiverseVul (arXiv 2304.00409)](https://arxiv.org/abs/2304.00409) · [OWASP Benchmark](https://owasp.org/www-project-benchmark/) / [BenchmarkUtils](https://github.com/OWASP-Benchmark/BenchmarkUtils) · [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) · [Nine Judges, Two Effective Votes (arXiv 2605.29800)](https://arxiv.org/html/2605.29800) · [Hidden Clones (arXiv 2603.17111)](https://arxiv.org/abs/2603.17111) · [in-toto Attestation Framework](https://github.com/in-toto/attestation)