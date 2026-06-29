from schema import Finding, Location, Cluster, GroundTruth
from score.matcher import label_cluster, score_task


def cl(file, s, e, cwe):
    f = Finding(task_id="t", lane_id="l1", model="claude", title="x", cwe=cwe,
                location=Location(file, s, e))
    return Cluster(key=f.bucket_key(), findings=[f])


def test_true_positive_on_file_line_cwe_match():
    gt = [GroundTruth("t", "app/orders.js", "CWE-89", [(40, 46)])]
    assert label_cluster(cl("app/orders.js", 42, 44, "CWE-89"), gt) == "TP"


def test_false_positive_on_negative_control():
    gt = [GroundTruth("t", "lib/safe.js", "", [], is_negative=True)]
    assert label_cluster(cl("lib/safe.js", 20, 22, "CWE-89"), gt) == "FP"


def test_near_miss_right_region_wrong_cwe():
    gt = [GroundTruth("t", "app/orders.js", "CWE-89", [(40, 46)])]
    # CWE-79 (xss) is the wrong class at the right place -> adjudicate, not auto-TP
    assert label_cluster(cl("app/orders.js", 42, 44, "CWE-79"), gt) == "near_miss"


def test_false_positive_wrong_file():
    gt = [GroundTruth("t", "app/orders.js", "CWE-89", [(40, 46)])]
    assert label_cluster(cl("app/other.js", 42, 44, "CWE-89"), gt) == "FP"


def test_score_task_counts_and_recall():
    gt = [GroundTruth("t", "app/orders.js", "CWE-89", [(40, 46)])]
    emitted = [cl("app/orders.js", 42, 44, "CWE-89"), cl("app/x.js", 1, 2, "CWE-89")]
    s = score_task(emitted, gt)
    assert s["tp"] == 1 and s["fp"] == 1
    assert s["matched_positives"] == 1 and s["n_positives"] == 1
