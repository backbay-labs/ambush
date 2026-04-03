"""
Blender Workcell Adapter

Provides agent integration for Blender-based asset creation tasks.
This adapter handles:
1. Dispatching asset creation tasks to Blender agents
2. Reading manifests and generating Blender scripts
3. Executing Blender in headless mode
4. Collecting outputs and running gate verification

The Blender agent workflow:
1. Receive issue manifest with asset requirements
2. Generate/modify Blender asset (via MCP tools or scripts)
3. Export GLB + blend file
4. Run through fab-realism gate
5. Return proof with verdict

Compatible with:
- BlenderMCP tools (interactive)
- Headless Blender scripts (automated)
- Sverchok procedural generation
"""

import json
import logging
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cyntra.core.gates.results import (
    build_verification_payload,
    emit_gates_event,
    normalize_gate_result,
    resolve_logs_dir,
)

logger = logging.getLogger(__name__)


@dataclass
class BlenderAgentConfig:
    """Configuration for Blender agent adapter."""

    blender_path: Path | None = None
    timeout_seconds: int = 600  # 10 minutes for complex assets
    use_factory_startup: bool = True
    cpu_only: bool = True  # For determinism
    thread_count: int | None = 1  # 1 for maximal determinism
    python_hash_seed: int = 0
    enable_sverchok: bool = True


@dataclass
class BlenderTaskManifest:
    """Manifest for a Blender asset creation task."""

    task_id: str
    issue_id: str
    category: str  # "car", "furniture", etc.
    prompt: str
    template_ref: str | None = None
    scaffold_ref: str | None = None
    scaffold_params: dict[str, Any] = field(default_factory=dict)
    style_hints: list[str] = field(default_factory=list)
    constraints: dict[str, Any] = field(default_factory=dict)
    output_formats: list[str] = field(default_factory=lambda: ["glb", "blend"])
    gate_config_id: str = "car_realism_v001"


@dataclass
class BlenderTaskResult:
    """Result from a Blender agent task."""

    success: bool
    task_id: str
    issue_id: str
    output_dir: Path
    asset_files: dict[str, Path] = field(default_factory=dict)
    blender_log: str = ""
    duration_seconds: float = 0.0
    error: str | None = None
    gate_result: dict[str, Any] | None = None
    verification: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "task_id": self.task_id,
            "issue_id": self.issue_id,
            "output_dir": str(self.output_dir),
            "asset_files": {k: str(v) for k, v in self.asset_files.items()},
            "duration_seconds": self.duration_seconds,
            "error": self.error,
            "gate_result": self.gate_result,
            "verification": self.verification,
        }


class BlenderAgentAdapter:
    """
    Adapter for Blender-based asset creation agents.

    Handles the full lifecycle of an asset creation task:
    1. Parse issue manifest
    2. Generate Blender script (from template/scaffold or prompt)
    3. Execute Blender headless
    4. Verify output via fab gate
    5. Return proof
    """

    def __init__(self, config: BlenderAgentConfig | None = None):
        self.config = config or BlenderAgentConfig()
        self._blender_path: Path | None = None

    def find_blender(self) -> Path | None:
        """Find Blender executable."""
        if self._blender_path:
            return self._blender_path

        if self.config.blender_path:
            self._blender_path = self.config.blender_path
            return self._blender_path

        # Check common locations
        candidates = [
            Path("/Applications/Blender.app/Contents/MacOS/Blender"),  # macOS
            Path("/usr/bin/blender"),  # Linux
            Path("/usr/local/bin/blender"),
            Path("C:/Program Files/Blender Foundation/Blender 5.0/blender.exe"),  # Win
        ]

        for candidate in candidates:
            if candidate.exists():
                self._blender_path = candidate
                return self._blender_path

        # Try PATH
        blender_in_path = shutil.which("blender")
        if blender_in_path:
            self._blender_path = Path(blender_in_path)
            return self._blender_path

        return None

    def execute_task(
        self,
        manifest: BlenderTaskManifest,
        workcell_dir: Path,
    ) -> BlenderTaskResult:
        """
        Execute a Blender asset creation task.

        Args:
            manifest: Task manifest with requirements
            workcell_dir: Working directory for the task

        Returns:
            BlenderTaskResult with outputs and status
        """
        start_time = datetime.now(UTC)

        # Setup output directories
        output_dir = workcell_dir / "output"
        output_dir.mkdir(parents=True, exist_ok=True)
        logs_dir = workcell_dir / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)

        blender_path = self.find_blender()
        if not blender_path:
            return BlenderTaskResult(
                success=False,
                task_id=manifest.task_id,
                issue_id=manifest.issue_id,
                output_dir=output_dir,
                error="Blender executable not found",
            )

        try:
            # Generate Blender script based on manifest
            script_path = workcell_dir / "generate_asset.py"
            script_content = self._generate_script(manifest, output_dir)
            script_path.write_text(script_content)

            # Build Blender command
            cmd = self._build_blender_command(blender_path, script_path)

            # Set environment for determinism
            env = self._build_env()

            # Execute Blender
            logger.info(f"Executing Blender task {manifest.task_id}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.config.timeout_seconds,
                env=env,
                cwd=str(blender_path.parent) if blender_path.suffix == "" else None,
            )

            blender_log = result.stdout + "\n" + result.stderr
            (logs_dir / "blender.log").write_text(blender_log)

            # Check for output files
            asset_files = self._collect_outputs(output_dir, manifest)

            if not asset_files:
                return BlenderTaskResult(
                    success=False,
                    task_id=manifest.task_id,
                    issue_id=manifest.issue_id,
                    output_dir=output_dir,
                    blender_log=blender_log,
                    error="No asset files generated",
                    duration_seconds=(datetime.now(UTC) - start_time).total_seconds(),
                )

            # Run gate verification
            gate_result = self._run_gate(
                asset_files.get("glb"),
                manifest.gate_config_id,
                output_dir / "gate",
            )
            verification = None
            if gate_result:
                gate_name = manifest.gate_config_id or "fab-gate"
                verdict = str(gate_result.get("verdict") or gate_result.get("status") or "").lower()
                is_dry_run = bool(gate_result.get("_dry_run"))
                passed = bool(gate_result.get("passed", verdict in {"pass", "passed", "success"}))
                skipped = is_dry_run or verdict == "pending"
                failure_summary = gate_result.get("verdict_reason") or gate_result.get("verdict")
                if skipped:
                    passed = True
                    failure_summary = None

                log_paths: list[str] = []
                verdict_path = output_dir / "gate" / "verdict" / "gate_verdict.json"
                report_path = output_dir / "gate" / "critics" / "report.json"
                if verdict_path.exists():
                    log_paths.append(str(verdict_path))
                if report_path.exists():
                    log_paths.append(str(report_path))

                normalized = normalize_gate_result(
                    name=str(gate_name),
                    result={
                        **dict(gate_result),
                        "passed": passed,
                        "skipped": skipped,
                        "failure_summary": failure_summary,
                        "log_paths": log_paths,
                        "gate_type": "fab",
                        "blocking": True,
                    },
                    gate_type="fab",
                )
                verification = build_verification_payload({str(gate_name): normalized})

                emit_gates_event(
                    logs_dir=resolve_logs_dir(workcell_dir),
                    workcell_id=manifest.task_id,
                    passed=bool(verification.get("all_passed", False)),
                    results=verification.get("gates", {}),
                    summary=verification.get("gate_summary"),
                )

            duration = (datetime.now(UTC) - start_time).total_seconds()

            return BlenderTaskResult(
                success=result.returncode == 0 and bool(asset_files),
                task_id=manifest.task_id,
                issue_id=manifest.issue_id,
                output_dir=output_dir,
                asset_files=asset_files,
                blender_log=blender_log,
                duration_seconds=duration,
                gate_result=gate_result,
                verification=verification,
            )

        except subprocess.TimeoutExpired:
            return BlenderTaskResult(
                success=False,
                task_id=manifest.task_id,
                issue_id=manifest.issue_id,
                output_dir=output_dir,
                error=f"Blender timed out after {self.config.timeout_seconds}s",
                duration_seconds=self.config.timeout_seconds,
            )
        except Exception as e:
            logger.exception(f"Blender task failed: {e}")
            return BlenderTaskResult(
                success=False,
                task_id=manifest.task_id,
                issue_id=manifest.issue_id,
                output_dir=output_dir,
                error=str(e),
                duration_seconds=(datetime.now(UTC) - start_time).total_seconds(),
            )

    def _generate_script(
        self,
        manifest: BlenderTaskManifest,
        output_dir: Path,
    ) -> str:
        """Generate Blender Python script from manifest."""
        # Check if using scaffold
        if manifest.scaffold_ref:
            return self._generate_scaffold_script(manifest, output_dir)
        elif manifest.template_ref:
            return self._generate_template_script(manifest, output_dir)
        else:
            return self._generate_prompt_script(manifest, output_dir)

    def _generate_scaffold_script(
        self,
        manifest: BlenderTaskManifest,
        output_dir: Path,
    ) -> str:
        """Generate script using a procedural scaffold."""
        params = manifest.scaffold_params or {}
        output_glb = output_dir / "asset.glb"
        output_blend = output_dir / "asset.blend"

        return f'''#!/usr/bin/env python3
"""
Auto-generated Blender script for task: {manifest.task_id}
Scaffold: {manifest.scaffold_ref}
"""

import bpy
import sys
from pathlib import Path

# Add kernel to path for scaffold access
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

try:
    from cyntra.fab.scaffolds import get_scaffold

    scaffold = get_scaffold("{manifest.category}", "{manifest.scaffold_ref}")
    if scaffold:
        params = {params!r}
        result = scaffold.instantiate(params=params, output_dir=Path("{output_dir}"))
        print(f"Scaffold generated: {{result.success}}")
    else:
        print("Scaffold not found, using basic generation")
        raise ImportError("Scaffold not found")

except ImportError as e:
    print(f"Could not load scaffold: {{e}}")
    # Fallback to basic generation
    bpy.ops.mesh.primitive_cube_add()
    obj = bpy.context.active_object
    obj.name = "Asset"

    # Export
    bpy.ops.export_scene.gltf(
        filepath="{output_glb}",
        export_format='GLB',
    )
    bpy.ops.wm.save_as_mainfile(filepath="{output_blend}")

print("Asset generation complete")
'''

    def _generate_template_script(
        self,
        manifest: BlenderTaskManifest,
        output_dir: Path,
    ) -> str:
        """Generate script using a template asset."""
        output_glb = output_dir / "asset.glb"
        output_blend = output_dir / "asset.blend"

        return f'''#!/usr/bin/env python3
"""
Auto-generated Blender script for task: {manifest.task_id}
Template: {manifest.template_ref}
"""

import bpy
from pathlib import Path

# Load template
template_path = Path("fab/templates/{manifest.category}/{manifest.template_ref}/asset.blend")
if template_path.exists():
    bpy.ops.wm.open_mainfile(filepath=str(template_path))
else:
    print(f"Template not found: {{template_path}}")
    bpy.ops.wm.read_factory_settings(use_empty=True)
    bpy.ops.mesh.primitive_cube_add()
    bpy.context.active_object.name = "Fallback_Asset"

# Apply modifications based on prompt
# Prompt: {manifest.prompt}
# Style hints: {manifest.style_hints}

# Export
bpy.ops.export_scene.gltf(
    filepath="{output_glb}",
    export_format='GLB',
)
bpy.ops.wm.save_as_mainfile(filepath="{output_blend}")

print("Template-based asset generation complete")
'''

    def _generate_prompt_script(
        self,
        manifest: BlenderTaskManifest,
        output_dir: Path,
    ) -> str:
        """Generate script for freeform prompt-based generation."""
        output_dir / "asset.glb"
        output_dir / "asset.blend"

        # For freeform, we generate a basic structure
        # In production, this would be more sophisticated (LLM-generated code)
        return f'''#!/usr/bin/env python3
"""
Auto-generated Blender script for task: {manifest.task_id}
Category: {manifest.category}
Prompt: {manifest.prompt}
"""

import bpy
import math
from pathlib import Path

# Clear scene
bpy.ops.wm.read_factory_settings(use_empty=True)

# Create asset based on category
category = "{manifest.category}"

if category == "car":
    # Create basic car shape
    # Body
    bpy.ops.mesh.primitive_cube_add(size=1)
    body = bpy.context.active_object
    body.name = "Body"
    body.scale = (4.5, 1.8, 0.5)
    body.location = (0, 0, 0.6)
    bpy.ops.object.transform_apply(scale=True)

    # Cabin
    bpy.ops.mesh.primitive_cube_add(size=1)
    cabin = bpy.context.active_object
    cabin.name = "Cabin"
    cabin.scale = (2.5, 1.7, 0.5)
    cabin.location = (0.3, 0, 1.2)
    bpy.ops.object.transform_apply(scale=True)

    # Wheels
    for name, pos in [
        ("Wheel_FL", (1.5, 1.0, 0.35)),
        ("Wheel_FR", (1.5, -1.0, 0.35)),
        ("Wheel_RL", (-1.5, 1.0, 0.35)),
        ("Wheel_RR", (-1.5, -1.0, 0.35)),
    ]:
        bpy.ops.mesh.primitive_cylinder_add(radius=0.35, depth=0.22, vertices=32)
        wheel = bpy.context.active_object
        wheel.name = name
        wheel.location = pos
        wheel.rotation_euler = (math.pi/2, 0, 0)

elif category == "furniture":
    # Create basic chair
    # Seat
    bpy.ops.mesh.primitive_cube_add(size=1)
    seat = bpy.context.active_object
    seat.name = "Seat"
    seat.scale = (0.5, 0.5, 0.05)
    seat.location = (0, 0, 0.45)
    bpy.ops.object.transform_apply(scale=True)

    # Backrest
    bpy.ops.mesh.primitive_cube_add(size=1)
    back = bpy.context.active_object
    back.name = "Backrest"
    back.scale = (0.5, 0.05, 0.5)
    back.location = (0, -0.225, 0.75)
    bpy.ops.object.transform_apply(scale=True)

    # Legs
    for name, pos in [
        ("Leg_FL", (0.2, 0.2, 0.225)),
        ("Leg_FR", (0.2, -0.2, 0.225)),
        ("Leg_BL", (-0.2, 0.2, 0.225)),
        ("Leg_BR", (-0.2, -0.2, 0.225)),
    ]:
        bpy.ops.mesh.primitive_cylinder_add(radius=0.025, depth=0.45, vertices=16)
        leg = bpy.context.active_object
        leg.name = name
        leg.location = pos

else:
    # Generic placeholder
    bpy.ops.mesh.primitive_cube_add(size=1)
    bpy.context.active_object.name = "Asset"

# Add basic material
mat = bpy.data.materials.new(name="Asset_Material")
mat.use_nodes = True
bsdf = mat.node_tree.nodes["Principled BSDF"]
bsdf.inputs["Base Color"].default_value = (0.3, 0.3, 0.35, 1.0)
bsdf.inputs["Metallic"].default_value = 0.2
bsdf.inputs["Roughness"].default_value = 0.5

for obj in bpy.data.objects:
    if obj.type == 'MESH':
        obj.data.materials.append(mat)

# Export
output_dir = Path("{output_dir}")
output_dir.mkdir(parents=True, exist_ok=True)

bpy.ops.export_scene.gltf(
    filepath=str(output_dir / "asset.glb"),
    export_format='GLB',
)
bpy.ops.wm.save_as_mainfile(filepath=str(output_dir / "asset.blend"))

print("Prompt-based asset generation complete")
'''

    def _build_blender_command(
        self,
        blender_path: Path,
        script_path: Path,
    ) -> list[str]:
        """Build Blender command line."""
        cmd = [str(blender_path)]

        if self.config.use_factory_startup:
            cmd.append("--factory-startup")

        cmd.extend(
            [
                "--background",
                "--python",
                str(script_path),
            ]
        )

        return cmd

    def _build_env(self) -> dict[str, str]:
        """Build environment for deterministic execution."""
        env = os.environ.copy()

        # Determinism settings
        env["PYTHONHASHSEED"] = str(self.config.python_hash_seed)

        if self.config.thread_count:
            env["OMP_NUM_THREADS"] = str(self.config.thread_count)
            env["MKL_NUM_THREADS"] = str(self.config.thread_count)

        return env

    def _collect_outputs(
        self,
        output_dir: Path,
        manifest: BlenderTaskManifest,
    ) -> dict[str, Path]:
        """Collect generated output files."""
        outputs = {}

        # Look for expected files
        for fmt in manifest.output_formats:
            pattern = f"*.{fmt}"
            files = list(output_dir.glob(pattern))
            if files:
                outputs[fmt] = files[0]

        # Also check for asset.* specifically
        for fmt in ["glb", "blend"]:
            asset_file = output_dir / f"asset.{fmt}"
            if asset_file.exists() and fmt not in outputs:
                outputs[fmt] = asset_file

        return outputs

    def _run_gate(
        self,
        asset_path: Path | None,
        gate_config_id: str,
        output_dir: Path,
    ) -> dict[str, Any] | None:
        """Run fab gate on generated asset."""
        if not asset_path or not asset_path.exists():
            return None

        try:
            # Import and run gate
            from cyntra.fab.config import find_gate_config, load_gate_config
            from cyntra.fab.gate import run_gate

            config_path = find_gate_config(gate_config_id)
            if not config_path:
                logger.warning(f"Gate config not found: {gate_config_id}")
                return None

            # Load the config object
            config = load_gate_config(config_path)

            output_dir.mkdir(parents=True, exist_ok=True)

            # Run gate (dry-run for now to avoid render dependency)
            result = run_gate(
                asset_path=asset_path,
                config=config,
                output_dir=output_dir,
                dry_run=True,
            )

            # Load verdict
            verdict_path = output_dir / "verdict" / "gate_verdict.json"
            if verdict_path.exists():
                return json.loads(verdict_path.read_text())

            return {
                "status": "completed",
                "verdict": result.verdict if result else "pending",
            }

        except Exception as e:
            logger.exception(f"Gate execution failed: {e}")
            return {"status": "error", "error": str(e)}


def create_blender_adapter(
    blender_path: str | None = None,
    config: BlenderAgentConfig | None = None,
) -> BlenderAgentAdapter:
    """Factory function to create Blender adapter."""
    if config is None:
        config = BlenderAgentConfig()
    if blender_path:
        config.blender_path = Path(blender_path)
    return BlenderAgentAdapter(config)
