"""The matcher -- 'the experiment's soul' (design Section 6 / Section 10).

Labels each emitted cluster TP / FP / near_miss against the task's ground truth,
and computes recall over the ground-truth positives. Any cluster reported on a
Tier-D negative-control task is a False Positive, no exceptions.

Calibrate this against OWASP-Benchmark's published expectedresults before trusting
it elsewhere (see corpora/README.md).
"""

from __future__ import annotations

from config import LINE_TOLERANCE
from schema import Cluster, GroundTruth, cwe_class, normalize_path


def _loc_matches_gt(cluster: Cluster, gt: GroundTruth, tol: int) -> bool:
    rep = cluster.representative.location
    if normalize_path(rep.file) != normalize_path(gt.file):
        return False
    if not gt.patched_hunks:
        return True  # file-level ground truth (whole-app corpora)
    a0, a1 = min(rep.start_line, rep.end_line), max(rep.start_line, rep.end_line)
    for (h0, h1) in gt.patched_hunks:
        if (a0 - tol) <= h1 and (h0 - tol) <= a1:
            return True
    return False


def label_cluster(cluster: Cluster, ground_truth: list[GroundTruth],
                  tol: int = LINE_TOLERANCE) -> str:
    """Return TP / FP / near_miss for a single emitted cluster.

    - On a task with only negative-control ground truth, any cluster is FP.
    - TP: matches a positive GT on file+line(+/-tol)+cwe-class.
    - near_miss: right file & region but wrong CWE class -> human adjudication.
    - FP: otherwise.
    """
    positives = [g for g in ground_truth if not g.is_negative]
    negatives_only = len(positives) == 0 and len(ground_truth) > 0

    if negatives_only:
        cluster.label = "FP"
        return "FP"

    rep_class = cluster.representative.cwe_klass
    near = False
    for gt in positives:
        if _loc_matches_gt(cluster, gt, tol):
            if rep_class == gt.cwe_klass:
                cluster.label = "TP"
                return "TP"
            near = True
    cluster.label = "near_miss" if near else "FP"
    return cluster.label


def score_task(emitted: list[Cluster], ground_truth: list[GroundTruth],
               tol: int = LINE_TOLERANCE) -> dict:
    """Label all clusters for one task and compute per-task TP/FP and matched GT.

    Returns counts plus the set of ground-truth positives that were hit (for recall).
    near_miss is reported separately (counts toward neither P nor R until adjudicated).
    """
    positives = [g for g in ground_truth if not g.is_negative]
    tp = fp = near = 0
    matched_gt: set[int] = set()
    for c in emitted:
        lbl = label_cluster(c, ground_truth, tol)
        if lbl == "TP":
            tp += 1
            for i, gt in enumerate(positives):
                if _loc_matches_gt(c, gt, tol) and c.representative.cwe_klass == gt.cwe_klass:
                    matched_gt.add(i)
        elif lbl == "FP":
            fp += 1
        else:
            near += 1
    return {
        "tp": tp,
        "fp": fp,
        "near_miss": near,
        "n_positives": len(positives),
        "matched_positives": len(matched_gt),
        "is_negative_task": len(positives) == 0 and len(ground_truth) > 0,
    }
