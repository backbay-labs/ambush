"""
Kernel Inspector - Reality verification for integration work.

Inspects the current state of Cyntra modules, skills, gates, and subsystems.
Used to verify as-is architecture before integration changes.
"""

from __future__ import annotations

import ast
import importlib.util
import inspect
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class ModuleInfo:
    """Information about a kernel module."""

    name: str
    path: str
    class_name: str | None = None
    line_number: int | None = None
    status: str = "found"  # found, stub, missing


@dataclass
class SkillCategory:
    """Information about a skill category."""

    name: str
    count: int
    skills: list[str] = field(default_factory=list)


@dataclass
class SubsystemInfo:
    """Information about a subsystem."""

    name: str
    status: str  # operational, stub, missing, not_configured
    location: str | None = None
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class InspectionResult:
    """Complete inspection result."""

    # Core kernel modules
    scheduler: ModuleInfo | None = None
    dispatcher: ModuleInfo | None = None
    verifier: ModuleInfo | None = None

    # Gates
    gates: list[str] = field(default_factory=list)

    # Skills
    skill_categories: list[SkillCategory] = field(default_factory=list)
    total_skills: int = 0

    # Subsystems
    playtest: SubsystemInfo | None = None
    game_world: SubsystemInfo | None = None
    memory: SubsystemInfo | None = None
    dynamics: SubsystemInfo | None = None
    evolution: SubsystemInfo | None = None

    # Planners (Rust crates)
    planners: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON output."""
        return {
            "modules": {
                "scheduler": self._module_to_dict(self.scheduler),
                "dispatcher": self._module_to_dict(self.dispatcher),
                "verifier": self._module_to_dict(self.verifier),
            },
            "gates": self.gates,
            "skills": {
                "total": self.total_skills,
                "categories": [
                    {"name": c.name, "count": c.count, "skills": c.skills}
                    for c in self.skill_categories
                ],
            },
            "subsystems": {
                "playtest": self._subsystem_to_dict(self.playtest),
                "game_world": self._subsystem_to_dict(self.game_world),
                "memory": self._subsystem_to_dict(self.memory),
                "dynamics": self._subsystem_to_dict(self.dynamics),
                "evolution": self._subsystem_to_dict(self.evolution),
            },
            "planners": self.planners,
        }

    def _module_to_dict(self, mod: ModuleInfo | None) -> dict[str, Any] | None:
        if mod is None:
            return None
        return {
            "name": mod.name,
            "path": mod.path,
            "class_name": mod.class_name,
            "line_number": mod.line_number,
            "status": mod.status,
        }

    def _subsystem_to_dict(self, sub: SubsystemInfo | None) -> dict[str, Any] | None:
        if sub is None:
            return None
        return {
            "name": sub.name,
            "status": sub.status,
            "location": sub.location,
            "details": sub.details,
        }


class KernelInspector:
    """Inspects Cyntra kernel state for integration verification."""

    def __init__(self, repo_root: Path):
        self.repo_root = repo_root
        self.kernel_src = repo_root / "kernel" / "src" / "cyntra"
        self.crates_root = repo_root / "crates"

    def inspect(self) -> InspectionResult:
        """Run full inspection and return results."""
        result = InspectionResult()

        # Inspect core modules
        result.scheduler = self._inspect_module(
            "scheduler",
            self.kernel_src / "kernel" / "scheduler.py",
            "Scheduler",
        )
        result.dispatcher = self._inspect_module(
            "dispatcher",
            self.kernel_src / "kernel" / "dispatcher.py",
            "Dispatcher",
        )
        result.verifier = self._inspect_module(
            "verifier",
            self.kernel_src / "kernel" / "verifier.py",
            "Verifier",
        )

        # Inspect gates
        result.gates = self._inspect_gates()

        # Inspect skills
        result.skill_categories, result.total_skills = self._inspect_skills()

        # Inspect subsystems
        result.playtest = self._inspect_playtest()
        result.game_world = self._inspect_game_world()
        result.memory = self._inspect_memory()
        result.dynamics = self._inspect_dynamics()
        result.evolution = self._inspect_evolution()

        # Inspect Rust planners
        result.planners = self._inspect_planners()

        return result

    def _inspect_module(
        self,
        name: str,
        path: Path,
        class_name: str,
    ) -> ModuleInfo:
        """Inspect a kernel module."""
        if not path.exists():
            return ModuleInfo(
                name=name,
                path=str(path.relative_to(self.repo_root)),
                status="missing",
            )

        # Find class definition line
        line_number = self._find_class_line(path, class_name)

        return ModuleInfo(
            name=name,
            path=str(path.relative_to(self.repo_root)),
            class_name=class_name,
            line_number=line_number,
            status="found",
        )

    def _find_class_line(self, path: Path, class_name: str) -> int | None:
        """Find the line number of a class definition."""
        try:
            source = path.read_text()
            tree = ast.parse(source)
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef) and node.name == class_name:
                    return node.lineno
        except Exception:
            pass
        return None

    def _inspect_gates(self) -> list[str]:
        """Inspect available gates from config and code."""
        gates = []

        # Default code gates
        gates.extend(["test", "typecheck", "lint"])

        # Fab gates from dispatcher
        dispatcher_path = self.kernel_src / "kernel" / "dispatcher.py"
        if dispatcher_path.exists():
            content = dispatcher_path.read_text()
            if "fab-realism" in content:
                gates.append("fab-realism")
            if "fab-godot" in content:
                gates.append("fab-godot")
            if "fab-playability" in content:
                gates.append("fab-playability")

        # Check for gate configs in fab/gates/
        gates_dir = self.repo_root / "fab" / "gates"
        if gates_dir.exists():
            for gate_file in gates_dir.glob("*.yaml"):
                gate_name = gate_file.stem
                if gate_name not in gates:
                    gates.append(f"config:{gate_name}")

        return sorted(set(gates))

    def _inspect_skills(self) -> tuple[list[SkillCategory], int]:
        """Inspect skill categories and counts."""
        skills_dir = self.kernel_src / "skills"
        if not skills_dir.exists():
            return [], 0

        categories = []
        total = 0

        for category_dir in sorted(skills_dir.iterdir()):
            if not category_dir.is_dir():
                continue
            if category_dir.name.startswith("_") or category_dir.name == "tests":
                continue

            skill_files = list(category_dir.glob("*.yaml"))
            skill_names = [f.stem for f in skill_files]

            if skill_names:
                categories.append(
                    SkillCategory(
                        name=category_dir.name,
                        count=len(skill_names),
                        skills=sorted(skill_names),
                    )
                )
                total += len(skill_names)

        return categories, total

    def _inspect_playtest(self) -> SubsystemInfo:
        """Inspect playtest subsystem."""
        playability_gate = self.kernel_src / "fab" / "playability_gate.py"
        gamevla_bridge = self.kernel_src / "fab" / "gamevla_bridge.py"

        if not playability_gate.exists():
            return SubsystemInfo(
                name="playtest",
                status="missing",
            )

        details = {
            "playability_gate": str(playability_gate.relative_to(self.repo_root)),
            "gamevla_bridge_exists": gamevla_bridge.exists(),
        }

        # Check for NitroGen client
        nitrogen_client = self.kernel_src / "fab" / "nitrogen_client.py"
        if nitrogen_client.exists():
            details["nitrogen_client"] = str(nitrogen_client.relative_to(self.repo_root))

        return SubsystemInfo(
            name="playtest",
            status="operational",
            location=str(playability_gate.relative_to(self.repo_root)),
            details=details,
        )

    def _inspect_game_world(self) -> SubsystemInfo:
        """Inspect GameWorld model."""
        model_path = self.kernel_src / "playtest" / "world_model" / "model.py"

        if not model_path.exists():
            return SubsystemInfo(
                name="game_world",
                status="missing",
            )

        # Parse model to extract config
        details: dict[str, Any] = {}
        try:
            content = model_path.read_text()
            tree = ast.parse(content)

            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef) and node.name == "GameWorldConfig":
                    for item in node.body:
                        if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
                            if isinstance(item.value, ast.Constant):
                                details[item.target.id] = item.value.value

            # Find transformer layer count
            if "num_layers: int = " in content:
                import re

                match = re.search(r"num_layers:\s*int\s*=\s*(\d+)", content)
                if match:
                    details["num_layers"] = int(match.group(1))
            if "num_heads: int = " in content:
                match = re.search(r"num_heads:\s*int\s*=\s*(\d+)", content)
                if match:
                    details["num_heads"] = int(match.group(1))
            if "hidden_dim: int = " in content:
                match = re.search(r"hidden_dim:\s*int\s*=\s*(\d+)", content)
                if match:
                    details["hidden_dim"] = int(match.group(1))

        except Exception:
            pass

        # Check for KV cache (VGGT integration point)
        cache_path = self.kernel_src / "playtest" / "world_model" / "cache.py"
        details["kv_cache_exists"] = cache_path.exists()

        return SubsystemInfo(
            name="game_world",
            status="operational",
            location=str(model_path.relative_to(self.repo_root)),
            details=details,
        )

    def _inspect_memory(self) -> SubsystemInfo:
        """Inspect memory subsystem."""
        db_path = self.kernel_src / "memory" / "database.py"

        if not db_path.exists():
            return SubsystemInfo(
                name="memory",
                status="missing",
            )

        details: dict[str, Any] = {}

        # Check for FTS5
        try:
            content = db_path.read_text()
            details["uses_fts5"] = "fts5" in content.lower()
            details["uses_vector"] = "pgvector" in content.lower() or "qdrant" in content.lower()
        except Exception:
            pass

        # Check for membox
        membox_path = self.kernel_src / "memory" / "membox"
        details["membox_exists"] = membox_path.exists()

        # Check for actual DB file
        db_file = self.repo_root / ".cyntra" / "memory" / "cyntra-mem.db"
        details["db_file_exists"] = db_file.exists()
        if db_file.exists():
            details["db_file_size_kb"] = round(db_file.stat().st_size / 1024, 2)

        return SubsystemInfo(
            name="memory",
            status="operational",
            location=str(db_path.relative_to(self.repo_root)),
            details=details,
        )

    def _inspect_dynamics(self) -> SubsystemInfo:
        """Inspect dynamics subsystem."""
        state_t1 = self.kernel_src / "dynamics" / "state_t1.py"
        transition_db = self.kernel_src / "dynamics" / "transition_db.py"

        if not state_t1.exists():
            return SubsystemInfo(
                name="dynamics",
                status="missing",
            )

        details = {
            "state_t1": str(state_t1.relative_to(self.repo_root)),
            "transition_db_exists": transition_db.exists(),
        }

        # Check for actual DB file
        db_file = self.repo_root / ".cyntra" / "dynamics" / "cyntra.db"
        details["db_file_exists"] = db_file.exists()
        if db_file.exists():
            details["db_file_size_kb"] = round(db_file.stat().st_size / 1024, 2)

        return SubsystemInfo(
            name="dynamics",
            status="operational",
            location=str(state_t1.relative_to(self.repo_root)),
            details=details,
        )

    def _inspect_evolution(self) -> SubsystemInfo:
        """Inspect evolution subsystem."""
        genome_path = self.kernel_src / "evolve" / "genome.py"
        reflect_path = self.kernel_src / "evolve" / "reflect.py"
        pareto_path = self.kernel_src / "evolve" / "pareto.py"

        if not genome_path.exists():
            return SubsystemInfo(
                name="evolution",
                status="missing",
            )

        details: dict[str, Any] = {
            "genome": str(genome_path.relative_to(self.repo_root)),
            "genome_status": "implemented",
        }

        # Check if reflect.py is a stub
        if reflect_path.exists():
            try:
                content = reflect_path.read_text()
                is_stub = (
                    "not implemented" in content.lower()
                    or "placeholder" in content.lower()
                    or "stub" in content.lower()
                )
                details["reflect"] = str(reflect_path.relative_to(self.repo_root))
                details["reflect_status"] = "stub" if is_stub else "implemented"
            except Exception:
                details["reflect_status"] = "error"
        else:
            details["reflect_status"] = "missing"

        # Check pareto
        details["pareto_exists"] = pareto_path.exists()

        # Determine overall status
        overall_status = "operational"
        if details.get("reflect_status") == "stub":
            overall_status = "partial"

        return SubsystemInfo(
            name="evolution",
            status=overall_status,
            location=str(genome_path.relative_to(self.repo_root)),
            details=details,
        )

    def _inspect_planners(self) -> list[str]:
        """Inspect Rust AI crates (planners)."""
        planners = []

        if not self.crates_root.exists():
            return planners

        planner_crates = [
            "ai-goap",
            "ai-htn",
            "ai-bt",
            "ai-utility",
            "ai-nav",
            "ai-bevy",
        ]

        for crate_name in planner_crates:
            crate_path = self.crates_root / crate_name
            if crate_path.exists():
                cargo_toml = crate_path / "Cargo.toml"
                if cargo_toml.exists():
                    planners.append(crate_name)

        return planners


def run_inspection(repo_root: Path, json_output: bool = False) -> None:
    """Run inspection and display results."""
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table

    console = Console()
    inspector = KernelInspector(repo_root)
    result = inspector.inspect()

    if json_output:
        console.print(json.dumps(result.to_dict(), indent=2))
        return

    # Display modules
    console.print("\n[bold cyan]Kernel Modules[/bold cyan]")
    table = Table(show_header=True)
    table.add_column("Module")
    table.add_column("Class")
    table.add_column("Location")
    table.add_column("Status")

    for mod in [result.scheduler, result.dispatcher, result.verifier]:
        if mod:
            loc = f"{mod.path}:{mod.line_number}" if mod.line_number else mod.path
            status_style = "green" if mod.status == "found" else "red"
            table.add_row(
                mod.name.capitalize(),
                mod.class_name or "-",
                loc,
                f"[{status_style}]{mod.status}[/{status_style}]",
            )

    console.print(table)

    # Display gates
    console.print("\n[bold cyan]Quality Gates[/bold cyan]")
    console.print(f"  {', '.join(result.gates)}")

    # Display skills
    console.print(f"\n[bold cyan]Skills[/bold cyan] ({result.total_skills} total)")
    for cat in result.skill_categories:
        console.print(f"  [dim]{cat.name}:[/dim] {cat.count}")

    # Display subsystems
    console.print("\n[bold cyan]Subsystems[/bold cyan]")
    subsystems_table = Table(show_header=True)
    subsystems_table.add_column("Subsystem")
    subsystems_table.add_column("Status")
    subsystems_table.add_column("Location")
    subsystems_table.add_column("Details")

    for sub in [
        result.playtest,
        result.game_world,
        result.memory,
        result.dynamics,
        result.evolution,
    ]:
        if sub:
            status_style = {
                "operational": "green",
                "partial": "yellow",
                "stub": "yellow",
                "missing": "red",
            }.get(sub.status, "white")

            # Format key details
            detail_parts = []
            for k, v in sub.details.items():
                if isinstance(v, bool):
                    if v:
                        detail_parts.append(k.replace("_", " "))
                elif k in ("num_layers", "num_heads", "hidden_dim"):
                    detail_parts.append(f"{k}={v}")
                elif k.endswith("_status"):
                    if v == "stub":
                        detail_parts.append(f"{k.replace('_status', '')}=STUB")

            subsystems_table.add_row(
                sub.name,
                f"[{status_style}]{sub.status}[/{status_style}]",
                sub.location or "-",
                ", ".join(detail_parts[:3]) if detail_parts else "-",
            )

    console.print(subsystems_table)

    # Display planners
    if result.planners:
        console.print("\n[bold cyan]Rust Planners[/bold cyan]")
        console.print(f"  {', '.join(result.planners)}")

    # Summary panel
    issues = []
    if result.evolution and result.evolution.details.get("reflect_status") == "stub":
        issues.append("evolve/reflect.py is STUB")
    if result.game_world and not result.game_world.details.get("kv_cache_exists"):
        issues.append("GameWorld KV cache not implemented")

    if issues:
        console.print(
            Panel(
                "\n".join(f"[yellow]![/yellow] {i}" for i in issues),
                title="[yellow]Integration Gaps[/yellow]",
            )
        )
    else:
        console.print(
            Panel("[green]All inspected modules found[/green]", title="Status")
        )
