# Ambush Validation Eval — "Does filtered fan-out beat one strong agent?"

This harness answers the one falsifiable question the whole company hinges on, **before any
product engineering**:

> **H1 (signal):** N filtered, consensus-gated *heterogeneous* lanes beat (a) one strong agent
> and (b) one strong agent + Semgrep on **finding-level precision** without losing >10% of the
> recall raw fan-out generates.
> **H2 (independence):** cross-family lanes add real signal over same-family lanes — i.e. BYO
> error correlation is low enough that corroboration means something.
>
> If **either** fails, the "validated swarm" wedge is unfounded as specified → **KILL**.

The #1 risk is **correlated errors**: 3 Claude lanes hallucinating the same finding and consensus
*promoting* it as corroborated slop. The eval is built to catch exactly that (see the demo).

Full design: [`../docs/research/VALIDATION-EVAL-HARNESS.md`](../docs/research/VALIDATION-EVAL-HARNESS.md).

## Run it now (no API keys)

```bash
cd eval
python -m pip install -e ".[dev]"   # numpy + pytest
pytest                              # the deterministic core is fully tested
python run_eval.py --demo           # end-to-end on synthetic data -> scorecard + verdict
```

The `--demo` run uses `FakeLaneRunner` so the **entire scoring/decision path** (consensus →
gate → matcher → metrics → GO/KILL) runs without models. It demonstrates the headline behavior:
the all-Claude (HOMO) panel promotes a correlated false positive that the cross-family (HETERO)
panel does not.

## What's implemented vs. stubbed

| Implemented (deterministic core, tested) | Stubbed (needs models / corpora / engine) |
|---|---|
| `schema.py` — the structured Finding (the product spec) + consensus key + CWE classes | `runner/lane_runner.py::LiveLaneRunner` — call model providers / drive the orchestrator |
| `pipeline/consensus.py` — corroboration clustering (support + **family_support**) | `corpora/fetch.sh` — clone benchmarks; build `ground_truth.jsonl` |
| `pipeline/evidence_gate.py` — the slop-filter (support≥k AND verified evidence) | `attest/verify.py` — `ambush verify` via real engine `swarm-crypto` |
| `pipeline/arms.py` — A0…A6 | live McNemar/CIs wired into `run_eval` (logic exists in `score/stats.py`) |
| `pipeline/semgrep_arm.py` — SARIF → Finding | |
| `score/matcher.py` — TP/FP/near-miss + recall | |
| `score/metrics.py` — P/R/F1, **N_eff**, **correlated-FP promotion**, ARI | |
| `score/stats.py` — McNemar, bootstrap CI | |
| `score/gate_decision.py` — the GO/KILL/YELLOW evaluator | |

## The GO / KILL thresholds (in `config.py`, decided once)

**GREENLIGHT** (all four): (1) `P(A4) − max(P(A0),P(A1)) ≥ +0.15` with separated CIs + McNemar
p<0.05; (2) `R(A4) ≥ 0.90 × R(union)`; (3) HETERO `N_eff ≥ 1.5 × HOMO N_eff` and HETERO
precision-at-iso-recall > HOMO; (4) correlated-FP promotion (HETERO,A4) < 0.10 and
cost-per-validated ≤ 3× the A1 baseline.

**KILL** (any): A4 doesn't beat "strong agent + Semgrep"; HETERO ≈ HOMO (independence is
fiction); HOMO consensus makes precision *worse* than a single agent (consensus actively
harmful); or recall retention < 0.75.

A **YELLOW** (signal real but only with forced diversity) ships — but family-diversity and the
slop-filter become the entire pitch, and sandboxing/attestation demote to secondary.

## Layout
```
config.py schema.py demo_fixture.py run_eval.py
pipeline/  consensus · evidence_gate · arms · semgrep_arm
score/     matcher · metrics · stats · gate_decision · adjudicate
runner/    lane_runner (Fake + Live stub)
panels/    HOMO/HETERO composition
attest/    ambush-verify prototype (stub)
corpora/   fetch.sh + ground-truth spec
tests/     the deterministic core
```
