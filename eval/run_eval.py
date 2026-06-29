"""Eval orchestrator: tasks x panels x arms -> scorecard -> GO/KILL verdict.

Runnable end-to-end TODAY against the FakeLaneRunner (synthetic findings) so the whole
scoring/decision path is exercised without API keys:

    python run_eval.py --demo

The real run swaps in LiveLaneRunner + real corpora (see corpora/fetch.sh). The pure
scoring/decision logic (consensus, gate, matcher, metrics, gate_decision) is identical
either way -- that is the point of the FakeLaneRunner.
"""

from __future__ import annotations

import argparse
import csv
import json

import numpy as np

from config import DEFAULT_K, DEFAULT_N
from panels.panels import panel, lane_id
from pipeline.arms import run_arm, ARM_FUNCS
from pipeline.semgrep_arm import run_semgrep
from runner.lane_runner import Task, FakeLaneRunner
from score.matcher import score_task, label_cluster
from score.metrics import (aggregate_prf, effective_voters, correlated_fp_promotion_rate)
from score.gate_decision import evaluate
from demo_fixture import demo_tasks_and_runner  # synthetic GO-ish dataset for --demo


def run_panel_over_tasks(runner, tasks, ground_truth, panel_name, k=DEFAULT_K, use_semgrep=False):
    """Run one panel across all tasks, all arms. Returns per-arm aggregate PRF +
    the labeled clusters for A4 (for correlated-FP promotion) + per-lane error vectors."""
    specs = panel(panel_name)
    per_arm_taskscores: dict[str, list[dict]] = {a: [] for a in ARM_FUNCS}
    # correlated-FP promotion is a CONSENSUS-stage threat metric: measure it over the
    # raw-union (A2) clusters -- before the evidence gate defends against it.
    a2_clusters_all = []
    # error vectors: rows=lanes, cols=ground-truth positives across tasks (1 = lane wrong)
    lane_models = [s["model"] for s in specs]
    error_rows = [[] for _ in specs]

    for task in tasks:
        gts = ground_truth.get(task.task_id, [])
        lane_findings: dict[str, list] = {}
        per_lane_hit: list[set] = []
        positives = [g for g in gts if not g.is_negative]
        for li, spec in enumerate(specs):
            lid = lane_id(panel_name, li, spec)
            findings = runner.run_lane(task, spec)
            for f in findings:
                f.lane_id = lid
            lane_findings[lid] = findings
            # which positives did this lane individually hit? (for the error vector)
            hit = set()
            from pipeline.consensus import cluster as _cl
            for c in _cl(findings):
                label_cluster(c, gts)
                if c.label == "TP":
                    for pi, gt in enumerate(positives):
                        rep = c.representative.location
                        from schema import normalize_path
                        if normalize_path(rep.file) == normalize_path(gt.file) and \
                           c.representative.cwe_klass == gt.cwe_klass:
                            hit.add(pi)
            per_lane_hit.append(hit)

        semgrep = run_semgrep(task.repo_path, task_id=task.task_id) if use_semgrep else []

        for arm in ARM_FUNCS:
            emitted = run_arm(arm, lane_findings, semgrep, k=k) if arm in ("A3", "A4", "A6") \
                else run_arm(arm, lane_findings, semgrep)
            s = score_task(emitted, gts)
            per_arm_taskscores[arm].append(s)
            if arm == "A2":
                for c in emitted:
                    label_cluster(c, gts)
                a2_clusters_all.extend(emitted)

        # append this task's positives to each lane's error vector
        for li in range(len(specs)):
            for pi in range(len(positives)):
                error_rows[li].append(0 if pi in per_lane_hit[li] else 1)

    arm_prf = {a: aggregate_prf(s) for a, s in per_arm_taskscores.items()}
    error_vectors = np.array(error_rows) if error_rows and error_rows[0] else np.zeros((len(specs), 1))
    neff = effective_voters(error_vectors)
    corr_fp = correlated_fp_promotion_rate(a2_clusters_all, k)
    return {"arm_prf": arm_prf, "neff": neff, "corr_fp_A4": corr_fp}


def build_scorecard(homo: dict, hetero: dict) -> dict:
    """Assemble the gate_decision scorecard from HOMO/HETERO panel results.
    CIs are stubbed to point estimates here; the full run fills them via stats.bootstrap_ci."""
    h = hetero["arm_prf"]
    def trip(arm, key):
        v = h[arm][key]; return (v, v, v)
    return {
        "precision": {a: trip(a, "precision") for a in ("A0", "A1", "A4")},
        "recall": {"A2": trip("A2", "recall"), "A4": trip("A4", "recall")},
        "mcnemar_p": {"A4_vs_A0": 0.0, "A4_vs_A1": 0.0},  # TODO: real McNemar on paired items
        "neff": {"HOMO": homo["neff"], "HETERO": hetero["neff"]},
        "hetero_precision_at_iso_recall": trip("A4", "precision"),
        "homo_precision_at_iso_recall": (homo["arm_prf"]["A4"]["precision"],) * 3,
        "corr_fp_promotion_hetero_A4": hetero["corr_fp_A4"],
        "cost_per_validated": {"A1": 1.0, "A4": 2.0},  # TODO: wire real $ from lane cache
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--demo", action="store_true", help="run on synthetic data (no API keys)")
    ap.add_argument("--k", type=int, default=DEFAULT_K)
    ap.add_argument("--out", default="results/scorecard.csv")
    args = ap.parse_args()

    if not args.demo:
        raise SystemExit("Only --demo is wired today. Implement LiveLaneRunner + corpora for a real run.")

    tasks, ground_truth, runner = demo_tasks_and_runner()
    homo = run_panel_over_tasks(runner, tasks, ground_truth, "HOMO_6", k=args.k)
    hetero = run_panel_over_tasks(runner, tasks, ground_truth, "HETERO_6", k=args.k)
    scorecard = build_scorecard(homo, hetero)
    verdict = evaluate(scorecard)

    print(json.dumps({"verdict": verdict["verdict"],
                      "detail": verdict["detail"],
                      "checks": verdict["checks"],
                      "fired_kills": verdict["fired_kills"]}, indent=2))
    print("\nPer-arm precision/recall (HETERO panel):")
    for a in ("A0", "A1", "A2", "A3", "A4", "A5", "A6"):
        p = hetero["arm_prf"][a]
        print(f"  {a}: P={p['precision']:.2f} R={p['recall']:.2f} F1={p['f1']:.2f} (tp={p['tp']} fp={p['fp']})")
    print(f"\nN_eff: HOMO={homo['neff']:.2f}  HETERO={hetero['neff']:.2f}")
    print(f"Correlated-FP promotion (A4): HOMO={homo['corr_fp_A4']:.2f}  HETERO={hetero['corr_fp_A4']:.2f}")


if __name__ == "__main__":
    main()
