"""Main kernel execution loop.

Coordinates scheduling, dispatch, verification, and state updates.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hellcat.core.runner.runner import KernelRunner, SpeculateDispatchPlan

__all__ = [
    "KernelRunner",
    "SpeculateDispatchPlan",
]


def __getattr__(name: str):
    if name in ("KernelRunner", "SpeculateDispatchPlan"):
        from hellcat.core.runner.runner import (
            KernelRunner,
            SpeculateDispatchPlan,
        )
        return {"KernelRunner": KernelRunner, "SpeculateDispatchPlan": SpeculateDispatchPlan}[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
