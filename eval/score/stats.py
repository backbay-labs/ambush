"""Statistics: paired McNemar test and bootstrap confidence intervals.

Decisions are made on CIs and paired tests, never point estimates. scipy is used if
available; otherwise an exact-binomial McNemar fallback is implemented here.
"""

from __future__ import annotations

import math
from typing import Callable, Sequence

import numpy as np


def mcnemar(correct_a: Sequence[bool], correct_b: Sequence[bool]) -> dict:
    """Paired McNemar test on per-item correctness of two arms on the SAME items.

    b = items A right & B wrong; c = items A wrong & B right.
    Uses the exact binomial test (robust for small/discordant counts).
    """
    a = np.asarray(correct_a, dtype=bool)
    b = np.asarray(correct_b, dtype=bool)
    assert a.shape == b.shape
    n_b = int(np.sum(a & ~b))   # A right, B wrong
    n_c = int(np.sum(~a & b))   # A wrong, B right
    n = n_b + n_c
    if n == 0:
        return {"b": n_b, "c": n_c, "p_value": 1.0, "test": "exact-binomial"}
    # two-sided exact binomial with p=0.5
    k = min(n_b, n_c)
    cdf = sum(math.comb(n, i) for i in range(0, k + 1)) / (2 ** n)
    p = min(1.0, 2 * cdf)
    return {"b": n_b, "c": n_c, "p_value": p, "test": "exact-binomial"}


def bootstrap_ci(items: Sequence, stat_fn: Callable, n_iter: int = 10000,
                 alpha: float = 0.05, seed: int = 1234) -> tuple[float, float, float]:
    """Percentile bootstrap CI by resampling tasks (items). stat_fn maps a resampled
    list of items -> a scalar. Returns (point_estimate, lo, hi)."""
    items = list(items)
    rng = np.random.default_rng(seed)
    n = len(items)
    if n == 0:
        return (0.0, 0.0, 0.0)
    point = float(stat_fn(items))
    stats = np.empty(n_iter, dtype=float)
    idx = np.arange(n)
    for t in range(n_iter):
        sample = [items[i] for i in rng.choice(idx, size=n, replace=True)]
        stats[t] = stat_fn(sample)
    lo = float(np.percentile(stats, 100 * (alpha / 2)))
    hi = float(np.percentile(stats, 100 * (1 - alpha / 2)))
    return (point, lo, hi)


def cis_separated(ci_a: tuple[float, float], ci_b: tuple[float, float]) -> bool:
    """True if two CIs (lo,hi) do not overlap."""
    (a_lo, a_hi), (b_lo, b_hi) = ci_a, ci_b
    return a_lo > b_hi or b_lo > a_hi
