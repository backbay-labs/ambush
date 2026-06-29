# Corpora

Four tiers. **Tier D (negative controls) is non-negotiable** — without code whose correct
answer is "no finding," you can only measure recall, never precision or the slop-filter.

| Tier | Corpus | Ground truth = oracle | Lang |
|---|---|---|---|
| **A** execution-oracle CVEs | **CyberGym** (1,507 CVE repro tasks; sample ~80), **CVE-Bench** (40 web CVEs; ~20) | PoC crashes pre-patch / clean post-patch; advisory file+CWE | C/C++/Py/web |
| **B** commit-level labels | **PrimeVul** (cleaned labels, *paired safe/vuln* functions), CVEfixes/DiverseVul (weak labels) | CVE+CWE+fixing commit; paired safe fn is a built-in negative | C/C++/multi |
| **C** planted whole apps | **Juice Shop** (`data/static/challenges.yml`), **NodeGoat**, **OWASP Benchmark Java** (`expectedresults-1.2.csv`, deliberate TP *and* FP) | machine-readable vuln class + location | TS/JS/Java |
| **D** negative controls | PrimeVul *safe* halves; OWASP-Benchmark FP cases; a frozen hardened lib release (no open advisories) | any reported finding = FP | mixed |

## Ground-truth format
Each task gets a `ground_truth.jsonl` of `GroundTruth` records (see `eval/schema.py`):
```jsonc
{"task_id":"cve-bench/CVE-2024-XXXX","file":"app/orders.js","cwe":"CWE-89",
 "patched_hunks":[[40,46]],"vuln_class":"injection","is_negative":false}
```
Negative-control tasks carry `"is_negative": true` and an empty CWE.

## Contamination control (these benchmarks are likely in training data)
1. Prefer CyberGym instances / OSS commits **after each model's cutoff** (filter to 2025+).
2. Build a **20–30 finding private planted set** (inject CWE-89/79/22/78/502 into recent clean
   OSS files; keep matched clean originals as negatives). Leak-proof tie-breaker.
3. Report **public-vs-private precision delta**; if public ≫ private, suspect leakage.

## Calibrate the matcher first
`score/matcher.py` is the experiment's soul. Before trusting it, confirm it **reproduces
OWASP-Benchmark's published TP/FP exactly** against `expectedresults-1.2.csv`.

Run `./fetch.sh` to clone the public corpora.
