"""End-to-end smoke test on the synthetic dataset: the whole tasks x panels x arms ->
scorecard path runs, and the harness exhibits its headline behavior -- a homogeneous
panel PROMOTES a correlated false positive that the heterogeneous panel does not.
"""

from run_eval import run_panel_over_tasks, build_scorecard
from score.gate_decision import evaluate
from demo_fixture import demo_tasks_and_runner


def test_demo_runs_and_homo_promotes_correlated_fp():
    tasks, gt, runner = demo_tasks_and_runner()
    homo = run_panel_over_tasks(runner, tasks, gt, "HOMO_6", k=2)
    hetero = run_panel_over_tasks(runner, tasks, gt, "HETERO_6", k=2)

    # The nightmare the eval exists to catch: all-Claude lanes corroborate a false
    # finding on the negative-control file; the cross-family panel does not.
    assert homo["corr_fp_A4"] > hetero["corr_fp_A4"]
    assert hetero["corr_fp_A4"] == 0.0

    # Both panels still detect the two true vulns via the gated product arm (A4).
    assert hetero["arm_prf"]["A4"]["tp"] == 2
    assert homo["arm_prf"]["A4"]["tp"] == 2

    # The full decision path produces a verdict object without error.
    verdict = evaluate(build_scorecard(homo, hetero))
    assert verdict["verdict"] in {"GREENLIGHT", "YELLOW", "KILL"}
