"""Panel composition for the H2 independence experiment.

HOMO-N mirrors 'BYO agents are the same few frontier models' (one family, varied only
by seed/persona). HETERO-N spreads across >=3 families. Identical mission prompts are
used across families so the lane prompt is not a confound; persona variation lives only
*within* HOMO. See config.PANELS.
"""

from __future__ import annotations

from config import PANELS, family_of


def panel(name: str) -> list[dict]:
    if name not in PANELS:
        raise KeyError(f"unknown panel {name!r}; known: {list(PANELS)}")
    return list(PANELS[name]["lanes"])


def families_in(name: str) -> set[str]:
    return {family_of(l["model"]) for l in panel(name)}


def lane_id(panel_name: str, i: int, spec: dict) -> str:
    return f"{panel_name.lower()}-{i:02d}-{spec['model']}-{spec.get('persona', 'gen')}"
