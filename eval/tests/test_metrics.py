import numpy as np

from schema import Finding, Location, Cluster
from score.metrics import (effective_voters, correlated_fp_promotion_rate,
                           adjusted_rand_index, prf)


def test_neff_identical_lanes_collapses_to_one():
    # two lanes that make the SAME errors are one effective voter
    ev = np.array([[0, 1, 0, 1], [0, 1, 0, 1]])
    assert abs(effective_voters(ev) - 1.0) < 1e-6


def test_neff_independent_lanes_near_n():
    # anti-correlated/independent error vectors -> ~N effective voters
    ev = np.array([[1, 1, 0, 0], [0, 0, 1, 1]])
    assert effective_voters(ev) >= 1.9  # clamps negative corr to 0 -> N_eff == N == 2


def test_correlated_fp_promotion_rate():
    def fp_cluster(n_lanes):
        fs = [Finding(task_id="t", lane_id=f"l{i}", model="claude", title="x",
                      cwe="CWE-89", location=Location("safe.js", 1, 2)) for i in range(n_lanes)]
        c = Cluster(key=("safe.js", "injection", ""), findings=fs)
        c.label = "FP"
        return c
    clusters = [fp_cluster(3), fp_cluster(1)]  # one promoted (support 3>=2), one not
    assert correlated_fp_promotion_rate(clusters, k=2) == 0.5


def test_ari_perfect_and_split():
    # identical clusterings -> ARI 1.0
    assert abs(adjusted_rand_index([0, 0, 1, 1], [0, 0, 1, 1]) - 1.0) < 1e-9
    # a split (one gold cluster predicted as two singletons) is penalized below 1
    assert adjusted_rand_index([0, 1, 2, 3], [0, 0, 0, 0]) < 1.0


def test_prf_basic():
    m = prf(tp=8, fp=2, n_positives_hit=8, n_positives_total=10)
    assert abs(m["precision"] - 0.8) < 1e-9
    assert abs(m["recall"] - 0.8) < 1e-9
