"""The GO / KILL / YELLOW decision -- the single decision artifact.

Consumes a Scorecard (the numbers each run produces) and applies the thresholds from
config.THRESHOLDS exactly. No relitigating: change config, not this logic.

Scorecard shape (all fields point estimates + CIs as (lo, hi)):
{
  "precision": {"A0": (p, lo, hi), "A1": ..., "A4": ...},
  "recall":    {"A2": (p, lo, hi), "A4": (p, lo, hi)},          # A2 == raw union
  "mcnemar_p": {"A4_vs_A0": p, "A4_vs_A1": p},
  "neff":      {"HOMO": x, "HETERO": y},
  "hetero_precision_at_iso_recall": (p, lo, hi),
  "homo_precision_at_iso_recall":   (p, lo, hi),
  "corr_fp_promotion_hetero_A4": r,
  "cost_per_validated": {"A1": c, "A4": c},
}
"""

from __future__ import annotations

from config import THRESHOLDS as T
from score.stats import cis_separated


def _pt(triple):
    return triple[0] if isinstance(triple, (list, tuple)) else triple


def _ci(triple):
    if isinstance(triple, (list, tuple)) and len(triple) == 3:
        return (triple[1], triple[2])
    p = _pt(triple)
    return (p, p)


def evaluate(scorecard: dict) -> dict:
    """Return {verdict: GREENLIGHT|YELLOW|KILL, greenlight:[...], kills:[...], detail:{}}."""
    P = scorecard["precision"]
    R = scorecard["recall"]
    mc = scorecard.get("mcnemar_p", {})
    neff = scorecard.get("neff", {})
    corr_fp = scorecard.get("corr_fp_promotion_hetero_A4", 1.0)
    cost = scorecard.get("cost_per_validated", {})

    p_a4 = _pt(P["A4"]); p_a0 = _pt(P["A0"]); p_a1 = _pt(P["A1"])
    r_a4 = _pt(R["A4"]); r_union = _pt(R["A2"])
    base_p = max(p_a0, p_a1)

    checks = {}

    # GREENLIGHT 1 -- signal: precision delta + separated CIs + McNemar
    baseline_arm = "A0" if p_a0 >= p_a1 else "A1"
    delta = p_a4 - base_p
    ci_sep = cis_separated(_ci(P["A4"]), _ci(P[baseline_arm]))
    mcnemar_ok = (mc.get("A4_vs_A0", 1.0) < T.MCNEMAR_ALPHA and
                  mc.get("A4_vs_A1", 1.0) < T.MCNEMAR_ALPHA)
    checks["G1_signal"] = bool(delta >= T.SIGNAL_PRECISION_DELTA and ci_sep and mcnemar_ok)

    # GREENLIGHT 2 -- recall retention
    retention = (r_a4 / r_union) if r_union else 0.0
    checks["G2_recall_retention"] = bool(retention >= T.RECALL_RETENTION)

    # GREENLIGHT 3 -- independence pays
    homo, hetero = neff.get("HOMO", 0.0), neff.get("HETERO", 0.0)
    neff_ok = hetero >= T.NEFF_RATIO * homo if homo > 0 else hetero > 0
    prec_ok = cis_separated(_ci(scorecard.get("hetero_precision_at_iso_recall", 0)),
                            _ci(scorecard.get("homo_precision_at_iso_recall", 0))) and \
        _pt(scorecard.get("hetero_precision_at_iso_recall", 0)) > \
        _pt(scorecard.get("homo_precision_at_iso_recall", 0))
    checks["G3_independence"] = bool(neff_ok and prec_ok)

    # GREENLIGHT 4 -- slop contained & cheap
    cost_ratio = (cost.get("A4", float("inf")) / cost["A1"]) if cost.get("A1") else float("inf")
    checks["G4_slop_contained"] = bool(corr_fp < T.CORR_FP_PROMOTION_MAX and
                                       cost_ratio <= T.COST_RATIO_MAX)

    # KILL conditions
    kills = {}
    kills["K1_no_beat_baseline"] = not cis_separated(_ci(P["A4"]), _ci(P["A1"])) and p_a4 <= p_a1
    # K2: heterogeneity buys nothing -- N_eff within 10% AND no precision gain (design Section 7)
    hetero_prec = _pt(scorecard.get("hetero_precision_at_iso_recall", 0))
    homo_prec = _pt(scorecard.get("homo_precision_at_iso_recall", 0))
    neff_close = (abs(hetero - homo) / homo < 0.10) if homo > 0 else False
    kills["K2_independence_fiction"] = bool(neff_close and hetero_prec <= homo_prec)
    kills["K3_consensus_harmful"] = p_a4 < p_a0
    kills["K4_recall_collapse"] = retention < T.KILL_RECALL_RETENTION

    greenlight = [k for k, v in checks.items() if v]
    failed_greenlight = [k for k, v in checks.items() if not v]
    fired_kills = [k for k, v in kills.items() if v]

    if fired_kills:
        verdict = "KILL"
    elif all(checks.values()):
        verdict = "GREENLIGHT"
    else:
        # signal real but partial -> YELLOW (ship, but family-diversity becomes the pitch)
        verdict = "YELLOW" if checks["G1_signal"] else "KILL"

    return {
        "verdict": verdict,
        "checks": checks,
        "kills": kills,
        "greenlight_passed": greenlight,
        "greenlight_failed": failed_greenlight,
        "fired_kills": fired_kills,
        "detail": {
            "precision_delta": delta,
            "baseline_arm": baseline_arm,
            "recall_retention": retention,
            "neff_homo": homo,
            "neff_hetero": hetero,
            "corr_fp_promotion": corr_fp,
            "cost_ratio_A4_over_A1": cost_ratio,
        },
    }
