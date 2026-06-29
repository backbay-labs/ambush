from score.gate_decision import evaluate


def greenlight_scorecard():
    return {
        "precision": {"A0": (0.55, 0.50, 0.60), "A1": (0.60, 0.55, 0.65), "A4": (0.85, 0.80, 0.90)},
        "recall": {"A2": (0.70, 0.65, 0.75), "A4": (0.66, 0.61, 0.71)},  # 0.66/0.70 = 0.94 retention
        "mcnemar_p": {"A4_vs_A0": 0.001, "A4_vs_A1": 0.01},
        "neff": {"HOMO": 2.0, "HETERO": 3.4},
        "hetero_precision_at_iso_recall": (0.84, 0.80, 0.88),
        "homo_precision_at_iso_recall": (0.62, 0.58, 0.66),
        "corr_fp_promotion_hetero_A4": 0.04,
        "cost_per_validated": {"A1": 1.0, "A4": 2.4},
    }


def test_greenlight_when_all_pass():
    v = evaluate(greenlight_scorecard())
    assert v["verdict"] == "GREENLIGHT", v


def test_kill_when_consensus_actively_harmful():
    sc = greenlight_scorecard()
    sc["precision"]["A4"] = (0.50, 0.45, 0.55)   # below A0=0.55 -> K3
    v = evaluate(sc)
    assert v["verdict"] == "KILL"
    assert "K3_consensus_harmful" in v["fired_kills"]


def test_kill_on_recall_collapse():
    sc = greenlight_scorecard()
    sc["recall"]["A4"] = (0.40, 0.35, 0.45)      # 0.40/0.70 = 0.57 < 0.75 -> K4
    v = evaluate(sc)
    assert v["verdict"] == "KILL"
    assert "K4_recall_collapse" in v["fired_kills"]


def test_yellow_when_signal_real_but_independence_fails():
    sc = greenlight_scorecard()
    # N_eff ratio still fine (no K2), but the precision-at-iso-recall CIs overlap so the
    # "independence pays" greenlight (G3) fails -> signal real, nothing fatal -> YELLOW.
    sc["hetero_precision_at_iso_recall"] = (0.63, 0.58, 0.68)
    sc["homo_precision_at_iso_recall"] = (0.62, 0.57, 0.67)
    v = evaluate(sc)
    assert v["verdict"] == "YELLOW", v
    assert not v["checks"]["G3_independence"]
