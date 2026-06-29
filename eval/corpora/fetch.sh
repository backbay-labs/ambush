#!/usr/bin/env bash
# Fetch the eval corpora (design Section 1 / 9). Run from eval/.
# Tier A/B/C/D -- see corpora/README.md for the ground-truth mechanism per corpus.
set -euo pipefail
cd "$(dirname "$0")"

echo "== Tier C: planted-vuln whole apps =="
git clone --depth 1 https://github.com/juice-shop/juice-shop juice-shop || true
git clone --depth 1 https://github.com/OWASP/NodeGoat nodegoat || true

echo "== Tier C / SAST calibration: OWASP Benchmark (Java) -- the matcher must reproduce its expectedresults =="
git clone --depth 1 https://github.com/OWASP-Benchmark/BenchmarkJava owasp-bench || true
git clone --depth 1 https://github.com/OWASP-Benchmark/BenchmarkUtils owasp-bench-utils || true

echo "== Tier A: execution-oracle web CVEs =="
git clone --depth 1 https://github.com/uiuc-kang-lab/cve-bench cve-bench || true

echo "== Tier A: CyberGym -- follow its README to pull the per-task Docker images (large) =="
echo "   https://github.com/sunblaze-ucb/cybergym  (arXiv 2506.02548)"

echo "== Tier B: PrimeVul (HuggingFace; needs 'datasets') =="
python -c "from datasets import load_dataset; load_dataset('starsofchance/PrimeVul')" || \
  echo "   (install ambush-eval[full] for HuggingFace datasets)"

echo "Done. Next: build ground_truth.jsonl per task (see corpora/README.md)."
