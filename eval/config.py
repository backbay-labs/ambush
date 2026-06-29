"""Central configuration for the Ambush validation eval.

Everything the GO/KILL decision depends on is a named constant here so it can be
audited and is never relitigated mid-run. See eval/README.md for the rationale and
docs/research/VALIDATION-EVAL-HARNESS.md for the full design.
"""

from __future__ import annotations

# --- Model families (the anti-correlation lever) ---------------------------------
# Map a concrete model id to its family. Corroboration counts distinct *families*,
# not lanes, because BYO agents that share a family share their errors.
MODEL_FAMILY = {
    "claude": "anthropic",
    "claude-opus-4-8": "anthropic",
    "claude-sonnet-4-6": "anthropic",
    "gpt": "openai",
    "gpt-5": "openai",
    "o4": "openai",
    "gemini": "google",
    "gemini-2.5-pro": "google",
    "qwen-coder": "qwen",
    "deepseek": "deepseek",
    "llama": "meta",
}


def family_of(model: str) -> str:
    """Best-effort family lookup; falls back to the longest matching prefix."""
    if model in MODEL_FAMILY:
        return MODEL_FAMILY[model]
    best = ""
    for key in MODEL_FAMILY:
        if model.startswith(key) and len(key) > len(best):
            best = key
    return MODEL_FAMILY.get(best, "unknown")


# --- Consensus / clustering ------------------------------------------------------
# Two findings corroborate iff same (normalized_file, cwe_class, sink_or_symbol)
# and their line ranges overlap within +/- LINE_TOLERANCE. Tuned on the pilot.
LINE_TOLERANCE = 10

# Default consensus support threshold k (distinct lanes). Swept over K_SWEEP.
DEFAULT_K = 2
K_SWEEP = (1, 2, 3)

# Lane-count sweep for the fan-out arms.
N_SWEEP = (1, 2, 4, 6, 8)
DEFAULT_N = 6

# Evidence verifiers that count as "machine-verifiable" for the gate. A piece of
# evidence only helps if its verifier actually confirmed it (Evidence.verified is True).
VERIFYING_VERIFIERS = {"exploit_oracle", "pytest", "jest", "pytest/jest", "semgrep"}


# --- Arms (each maps to a product stage) -----------------------------------------
ARMS = {
    "A0": "Single best agent, 1 lane, no filter",
    "A1": "A0 union Semgrep (deduped) -- strong agent + static analyzer",
    "A2": "N-lane raw union, no consensus (the slop generator)",
    "A3": "A2 -> consensus, support >= k",
    "A4": "A3 -> evidence/oracle gate  ==  THE PRODUCT PIPELINE",
    "A5": "Semgrep alone",
    "A6": "A4 union Semgrep -- full Pro pipeline",
}


# --- Panels (the H2 / independence experiment) -----------------------------------
# HOMO mirrors "BYO agents are the same few frontier models". HETERO spreads families.
PANELS = {
    "HOMO_6": {
        "family": "anthropic",
        "lanes": [
            {"model": "claude-opus-4-8", "persona": "recon", "seed": 1},
            {"model": "claude-opus-4-8", "persona": "injection", "seed": 2},
            {"model": "claude-opus-4-8", "persona": "authz", "seed": 3},
            {"model": "claude-opus-4-8", "persona": "recon", "seed": 4},
            {"model": "claude-opus-4-8", "persona": "injection", "seed": 5},
            {"model": "claude-opus-4-8", "persona": "authz", "seed": 6},
        ],
    },
    "HETERO_6": {
        "family": "mixed",
        "lanes": [
            {"model": "claude-opus-4-8", "persona": "injection", "seed": 1},
            {"model": "claude-opus-4-8", "persona": "authz", "seed": 2},
            {"model": "gpt-5", "persona": "injection", "seed": 3},
            {"model": "gpt-5", "persona": "recon", "seed": 4},
            {"model": "gemini-2.5-pro", "persona": "authz", "seed": 5},
            {"model": "qwen-coder", "persona": "recon", "seed": 6},
        ],
    },
}


# --- GO / KILL thresholds (decide once; do not relitigate) ------------------------
class Thresholds:
    # GREENLIGHT (all four must hold)
    SIGNAL_PRECISION_DELTA = 0.15   # P(A4) - max(P(A0), P(A1)) >= this, CIs separated, McNemar p<0.05
    RECALL_RETENTION = 0.90         # R(A4) >= this * R(union/A2)
    NEFF_RATIO = 1.50               # HETERO N_eff >= this * HOMO N_eff
    CORR_FP_PROMOTION_MAX = 0.10    # correlated-FP promotion (HETERO, A4) < this
    COST_RATIO_MAX = 3.0            # cost-per-validated-finding(A4) <= this * cost(A1)
    MCNEMAR_ALPHA = 0.05

    # KILL / PIVOT (any one triggers)
    KILL_RECALL_RETENTION = 0.75    # R(A4) < this * R(union) -> filter is just an expensive single agent


THRESHOLDS = Thresholds()
