"""Finding-level metrics, plus the two independence metrics that make or break H2:
effective-independent-voters (N_eff) and correlated-FP promotion rate.

numpy is required. scipy/scikit-learn are optional (pure-python fallbacks provided).
"""

from __future__ import annotations

import math
from typing import Sequence

import numpy as np


# --- precision / recall / F1 -----------------------------------------------------
def prf(tp: int, fp: int, n_positives_hit: int, n_positives_total: int) -> dict:
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = n_positives_hit / n_positives_total if n_positives_total else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return {"precision": precision, "recall": recall, "f1": f1,
            "tp": tp, "fp": fp, "hit": n_positives_hit, "pos": n_positives_total}


def aggregate_prf(task_scores: Sequence[dict]) -> dict:
    tp = sum(s["tp"] for s in task_scores)
    fp = sum(s["fp"] for s in task_scores)
    hit = sum(s["matched_positives"] for s in task_scores)
    pos = sum(s["n_positives"] for s in task_scores)
    return prf(tp, fp, hit, pos)


# --- independence (H2) -----------------------------------------------------------
def effective_voters(error_vectors: np.ndarray) -> float:
    """N_eff = N / (1 + (N-1) * rho_bar), the standard correlated-voter formula.

    error_vectors: shape (n_lanes, n_items), 1 = lane WRONG on item i.
    rho_bar = mean pairwise Pearson correlation of error vectors, clamped to >=0
    (negative correlation only helps; the voter formula assumes positive dependence).
    Constant lanes (all-right / all-wrong) contribute no defined correlation and are
    treated as rho=0 against others.
    """
    ev = np.asarray(error_vectors, dtype=float)
    n = ev.shape[0]
    if n <= 1:
        return float(n)
    corrs = []
    for i in range(n):
        for j in range(i + 1, n):
            a, b = ev[i], ev[j]
            if a.std() == 0 or b.std() == 0:
                corrs.append(0.0)
            else:
                corrs.append(float(np.corrcoef(a, b)[0, 1]))
    rho_bar = max(0.0, float(np.mean(corrs))) if corrs else 0.0
    return n / (1.0 + (n - 1) * rho_bar)


def mean_pairwise_correlation(error_vectors: np.ndarray) -> float:
    ev = np.asarray(error_vectors, dtype=float)
    n = ev.shape[0]
    corrs = []
    for i in range(n):
        for j in range(i + 1, n):
            a, b = ev[i], ev[j]
            if a.std() == 0 or b.std() == 0:
                corrs.append(0.0)
            else:
                corrs.append(float(np.corrcoef(a, b)[0, 1]))
    return float(np.mean(corrs)) if corrs else 0.0


def correlated_fp_promotion_rate(clusters, k: int) -> float:
    """Fraction of FALSE clusters that nonetheless reach support >= k -- the kill-shot.

    If homogeneous panels promote hallucinated findings (N lanes inventing the same
    non-bug), consensus is actively harmful. Requires clusters already labeled TP/FP.
    """
    false_clusters = [c for c in clusters if c.label == "FP"]
    if not false_clusters:
        return 0.0
    promoted = sum(1 for c in false_clusters if c.support >= k)
    return promoted / len(false_clusters)


# --- dedup correctness (Adjusted Rand Index, pure python) ------------------------
def adjusted_rand_index(pred_labels: Sequence[int], gold_labels: Sequence[int]) -> float:
    """ARI between predicted clustering and gold 'same underlying vuln' clustering.
    Penalizes both splitting one vuln into many and merging two vulns into one."""
    from collections import Counter
    assert len(pred_labels) == len(gold_labels)
    n = len(pred_labels)
    if n == 0:
        return 1.0
    contingency: dict[tuple[int, int], int] = Counter(zip(pred_labels, gold_labels))
    a = Counter(pred_labels)
    b = Counter(gold_labels)
    comb2 = lambda x: x * (x - 1) // 2
    sum_comb_c = sum(comb2(v) for v in contingency.values())
    sum_comb_a = sum(comb2(v) for v in a.values())
    sum_comb_b = sum(comb2(v) for v in b.values())
    total = comb2(n)
    expected = (sum_comb_a * sum_comb_b) / total if total else 0.0
    max_index = (sum_comb_a + sum_comb_b) / 2.0
    denom = max_index - expected
    if denom == 0:
        return 1.0
    return (sum_comb_c - expected) / denom


# --- cost ------------------------------------------------------------------------
def cost_per_validated_finding(total_cost_usd: float, wall_clock_s: float,
                               n_validated_true: int) -> float:
    if n_validated_true <= 0:
        return float("inf")
    return total_cost_usd / n_validated_true
