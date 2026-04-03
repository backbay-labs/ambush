"""
Outora Library Adapter - Agent integration for library population.

This adapter extends the base BlenderAgentAdapter with Outora-specific:
1. Study pod generation and placement
2. Library scene validation
3. Sverchok layout integration
4. Hand-tuned pod customization

Usage:
    from cyntra.core.adapters.outora import OutoraLibraryAdapter

    adapter = OutoraLibraryAdapter(
        library_blend_path="/path/to/outora_library_v0.1.1.blend"
    )

    result = adapter.create_study_pod(
        student_name="maria",
        position=(12.0, 6.0, 0.0),
        desk_style="concrete",
        personal_items=["lamp", "telescope", "globe"],
    )
"""

import json
import logging
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class PodPlacement:
    """Configuration for a study pod placement."""

    student_name: str
    position: tuple[float, float, float]
    rotation_z: float = 0.0
    desk_style: str = "concrete"
    chair_type: str = "wooden"
    book_density: float = 0.5
    personal_items: list[str] = field(default_factory=lambda: ["lamp"])
    random_seed: int = 42

    def to_dict(self) -> dict[str, Any]:
        return {
            "student_name": self.student_name,
            "position": list(self.position),
            "rotation_z": self.rotation_z,
            "desk_style": self.desk_style,
            "chair_type": self.chair_type,
            "book_density": self.book_density,
            "book_style": "stacks",
            "personal_items": self.personal_items,
            "random_seed": self.random_seed,
        }


@dataclass
class LibraryValidationResult:
    """Result of validating the library scene."""

    success: bool
    pod_count: int = 0
    floor_coverage: float = 0.0
    furniture_count: int = 0
    material_issues: list[str] = field(default_factory=list)
    geometry_issues: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    gate_verdict: str | None = None
    gate_score: float = 0.0


class OutoraLibraryAdapter:
    """
    Adapter for Outora Library asset generation and validation.

    Handles:
    1. Study pod placement via scaffold
    2. Library scene validation
    3. Batch pod generation
    4. Integration with fab-realism gate
    """

    # Default paths relative to project root
    DEFAULT_LIBRARY_PATH = "fab/assets/blender/outora_library_v0.1.1.blend"
    DEFAULT_GATE_CONFIG = "interior_library_v001"

    # Outora asset naming conventions
    POD_COLLECTION_PREFIX = "StudyPod_"
    LAYOUT_COLLECTION = "OL_GOTHIC_LAYOUT"
    PROPS_COLLECTION = "OL_PodProps"

    def __init__(
        self,
        library_blend_path: Path | None = None,
        blender_path: Path | None = None,
        gate_config_id: str = DEFAULT_GATE_CONFIG,
        project_root: Path | None = None,
    ):
        """
        Initialize the Outora adapter.

        Args:
            library_blend_path: Path to the main library .blend file
            blender_path: Path to Blender executable
            gate_config_id: Gate config for validation
            project_root: Root of the glia-fab project
        """
        self.project_root = project_root or Path(__file__).parents[4]
        self.library_blend_path = library_blend_path or (
            self.project_root / self.DEFAULT_LIBRARY_PATH
        )
        self.blender_path = blender_path or self._find_blender()
        self.gate_config_id = gate_config_id

    def _find_blender(self) -> Path:
        """Find Blender executable."""
        import platform

        if platform.system() == "Darwin":
            app_path = Path("/Applications/Blender.app/Contents/MacOS/Blender")
            if app_path.exists():
                return app_path

        # Try PATH
        import shutil

        blender = shutil.which("blender")
        if blender:
            return Path(blender)

        raise RuntimeError("Blender not found")

    def create_study_pod(
        self,
        student_name: str,
        position: tuple[float, float, float],
        rotation_z: float = 0.0,
        desk_style: str = "concrete",
        chair_type: str = "wooden",
        book_density: float = 0.5,
        personal_items: list[str] | None = None,
        output_dir: Path | None = None,
        random_seed: int = 42,
    ) -> dict[str, Any]:
        """
        Create a study pod and optionally place it in the library.

        Args:
            student_name: Name identifier for the pod
            position: World position (x, y, z) in meters
            rotation_z: Rotation around Z axis in radians
            desk_style: Style of desk (concrete, wood, glass, metal)
            chair_type: Type of chair (wooden, modern, stool, armchair)
            book_density: Density of books (0-1)
            personal_items: List of personal items to include
            output_dir: Directory for generated files
            random_seed: Seed for randomization

        Returns:
            Dict with generated file paths and status
        """
        from cyntra.fab.scaffolds.study_pod import StudyPodScaffold

        # Setup output
        output_dir = output_dir or Path(tempfile.mkdtemp(prefix="outora_pod_"))
        output_dir.mkdir(parents=True, exist_ok=True)

        # Generate scaffold
        scaffold = StudyPodScaffold()
        params = {
            "student_name": student_name,
            "position": position,
            "rotation_z": rotation_z,
            "desk_style": desk_style,
            "chair_type": chair_type,
            "book_density": book_density,
            "book_style": "stacks",
            "personal_items": personal_items or ["lamp"],
            "random_seed": random_seed,
        }

        script_path = scaffold.generate_script(params, output_dir)

        # Run in Blender with the library scene
        result = self._run_blender_script(
            script_path,
            blend_file=self.library_blend_path,
            save_to=output_dir / f"library_with_{student_name}.blend",
        )

        return {
            "success": result["returncode"] == 0,
            "student_name": student_name,
            "position": position,
            "script_path": str(script_path),
            "output_dir": str(output_dir),
            "blend_file": str(output_dir / f"library_with_{student_name}.blend"),
            "glb_file": str(output_dir / f"study_pod_{student_name}.glb"),
            "blender_stdout": result.get("stdout", ""),
            "blender_stderr": result.get("stderr", ""),
        }

    def create_multiple_pods(
        self,
        placements: list[PodPlacement],
        output_dir: Path | None = None,
    ) -> dict[str, Any]:
        """
        Create multiple study pods in batch.

        Args:
            placements: List of PodPlacement configurations
            output_dir: Directory for generated files

        Returns:
            Dict with results for each pod
        """
        output_dir = output_dir or Path(tempfile.mkdtemp(prefix="outora_pods_"))
        output_dir.mkdir(parents=True, exist_ok=True)

        # Generate batch script
        script_path = output_dir / "batch_pods.py"
        script_content = self._generate_batch_script(placements, output_dir)

        with open(script_path, "w") as f:
            f.write(script_content)

        # Run batch
        result = self._run_blender_script(
            script_path,
            blend_file=self.library_blend_path,
            save_to=output_dir / "library_populated.blend",
        )

        return {
            "success": result["returncode"] == 0,
            "pod_count": len(placements),
            "placements": [p.to_dict() for p in placements],
            "output_dir": str(output_dir),
            "blend_file": str(output_dir / "library_populated.blend"),
            "blender_stdout": result.get("stdout", ""),
            "blender_stderr": result.get("stderr", ""),
        }

    def _generate_batch_script(
        self,
        placements: list[PodPlacement],
        output_dir: Path,
    ) -> str:
        """Generate a batch script for multiple pod creation."""
        placements_json = json.dumps([p.to_dict() for p in placements], indent=2)

        return f'''#!/usr/bin/env python3
"""Batch study pod generation for Outora Library."""

import bpy
import math
import random
from pathlib import Path

PLACEMENTS = {placements_json}
OUTPUT_DIR = r"{output_dir}"

# Import the study pod creation logic
# (Simplified inline version for batch execution)

def find_source_object(name):
    obj = bpy.data.objects.get(name)
    if obj:
        return obj
    for col_name in ["OL_Assets", "OL_PodSources", "OL_Furniture"]:
        col = bpy.data.collections.get(col_name)
        if col:
            for obj in col.objects:
                if obj.name == name or obj.name.startswith(name):
                    return obj
    return None


def create_simple_desk(name):
    bpy.ops.mesh.primitive_cube_add(size=1.0, location=(0, 0, 0.375))
    desk = bpy.context.object
    desk.name = name
    desk.scale = (1.2, 0.6, 0.75)
    bpy.ops.object.transform_apply(scale=True)
    mat = bpy.data.materials.new(name=f"{{name}}_mat")
    mat.use_nodes = True
    bsdf = mat.node_tree.nodes["Principled BSDF"]
    bsdf.inputs["Base Color"].default_value = (0.3, 0.2, 0.1, 1)
    desk.data.materials.append(mat)
    return desk


def create_simple_chair(name):
    bpy.ops.mesh.primitive_cube_add(size=0.4, location=(0, 0, 0.45))
    seat = bpy.context.object
    seat.scale = (1.0, 1.0, 0.1)
    bpy.ops.object.transform_apply(scale=True)
    bpy.ops.mesh.primitive_cube_add(size=0.4, location=(0, -0.18, 0.7))
    back = bpy.context.object
    back.scale = (1.0, 0.1, 0.6)
    bpy.ops.object.transform_apply(scale=True)
    seat.select_set(True)
    back.select_set(True)
    bpy.context.view_layer.objects.active = seat
    bpy.ops.object.join()
    chair = bpy.context.object
    chair.name = name
    mat = bpy.data.materials.new(name=f"{{name}}_mat")
    mat.use_nodes = True
    bsdf = mat.node_tree.nodes["Principled BSDF"]
    bsdf.inputs["Base Color"].default_value = (0.4, 0.25, 0.1, 1)
    chair.data.materials.append(mat)
    return chair


def instance_object(src, name, location, rotation_z=0.0, scale=(1,1,1)):
    if not src:
        return None
    inst = src.copy()
    if src.data:
        inst.data = src.data.copy()
    inst.name = name
    inst.location = location
    inst.rotation_euler = (0, 0, rotation_z)
    inst.scale = scale
    return inst


def create_pod(params):
    random.seed(params.get("random_seed", 42))
    pod_name = f"StudyPod_{{params.get('student_name', 'anon')}}"

    pod_col = bpy.data.collections.get(pod_name)
    if not pod_col:
        pod_col = bpy.data.collections.new(pod_name)
        bpy.context.scene.collection.children.link(pod_col)

    pos = tuple(params.get("position", (0, 0, 0)))
    rot_z = params.get("rotation_z", 0.0)

    created = []

    # Desk
    desk_src = find_source_object("ol_desk_concrete")
    if desk_src:
        desk = instance_object(desk_src, f"{{pod_name}}_desk", pos, rot_z, (1.35, 1.35, 1.35))
    else:
        desk = create_simple_desk(f"{{pod_name}}_desk")
        desk.location = pos
        desk.rotation_euler.z = rot_z

    if desk:
        pod_col.objects.link(desk)
        if desk.name in bpy.context.scene.collection.objects:
            bpy.context.scene.collection.objects.unlink(desk)
        created.append(desk)

    # Chair
    chair_offset = (0, 1.2, 0)
    chair_pos = (
        pos[0] + chair_offset[0] * math.cos(rot_z) - chair_offset[1] * math.sin(rot_z),
        pos[1] + chair_offset[0] * math.sin(rot_z) + chair_offset[1] * math.cos(rot_z),
        pos[2]
    )

    chair_src = find_source_object("WoodenChair_01")
    if chair_src:
        chair = instance_object(chair_src, f"{{pod_name}}_chair", chair_pos, rot_z + math.pi, (0.85, 0.85, 0.85))
    else:
        chair = create_simple_chair(f"{{pod_name}}_chair")
        chair.location = chair_pos
        chair.rotation_euler.z = rot_z + math.pi

    if chair:
        pod_col.objects.link(chair)
        if chair.name in bpy.context.scene.collection.objects:
            bpy.context.scene.collection.objects.unlink(chair)
        created.append(chair)

    print(f"Created pod {{pod_name}} with {{len(created)}} objects")
    return created


def main():
    for placement in PLACEMENTS:
        create_pod(placement)

    print(f"\\nCreated {{len(PLACEMENTS)}} study pods")


if __name__ == "__main__":
    main()
'''

    def _run_blender_script(
        self,
        script_path: Path,
        blend_file: Path | None = None,
        save_to: Path | None = None,
    ) -> dict[str, Any]:
        """Run a Python script in Blender."""
        import platform

        cmd = [str(self.blender_path)]

        if blend_file and blend_file.exists():
            cmd.append(str(blend_file))

        cmd.extend(
            [
                "--background",
                "--python",
                str(script_path),
            ]
        )

        if save_to:
            # Add save command via python
            cmd.extend(
                ["--python-expr", f"import bpy; bpy.ops.wm.save_as_mainfile(filepath=r'{save_to}')"]
            )

        # On macOS, run from Blender app directory
        cwd = None
        if platform.system() == "Darwin" and "/Blender.app/" in str(self.blender_path):
            cwd = str(Path(self.blender_path).parent)

        logger.info(f"Running Blender: {' '.join(cmd)}")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
                cwd=cwd,
            )

            return {
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
            }
        except subprocess.TimeoutExpired:
            return {
                "returncode": -1,
                "stdout": "",
                "stderr": "Timeout expired",
            }
        except Exception as e:
            return {
                "returncode": -1,
                "stdout": "",
                "stderr": str(e),
            }

    def validate_library(
        self,
        output_dir: Path | None = None,
    ) -> LibraryValidationResult:
        """
        Validate the library scene through the fab-realism gate.

        Returns validation results including any issues found.
        """
        output_dir = output_dir or Path(tempfile.mkdtemp(prefix="outora_validate_"))
        output_dir.mkdir(parents=True, exist_ok=True)

        # Generate inspection script
        script_path = output_dir / "inspect_library.py"
        script_content = self._generate_inspection_script(output_dir)

        with open(script_path, "w") as f:
            f.write(script_content)

        # Run inspection
        self._run_blender_script(
            script_path,
            blend_file=self.library_blend_path,
        )

        # Parse results
        inspection_json = output_dir / "inspection_result.json"
        if inspection_json.exists():
            with open(inspection_json) as f:
                data = json.load(f)
                return LibraryValidationResult(
                    success=data.get("success", False),
                    pod_count=data.get("pod_count", 0),
                    floor_coverage=data.get("floor_coverage", 0.0),
                    furniture_count=data.get("furniture_count", 0),
                    material_issues=data.get("material_issues", []),
                    geometry_issues=data.get("geometry_issues", []),
                    warnings=data.get("warnings", []),
                )

        return LibraryValidationResult(
            success=False,
            warnings=["Inspection script did not produce results"],
        )

    def _generate_inspection_script(self, output_dir: Path) -> str:
        """Generate script to inspect the library scene."""
        return f'''#!/usr/bin/env python3
"""Inspect Outora Library scene for validation."""

import bpy
import json
from pathlib import Path

OUTPUT_PATH = r"{output_dir / "inspection_result.json"}"


def inspect():
    result = {{
        "success": True,
        "pod_count": 0,
        "floor_coverage": 0.0,
        "furniture_count": 0,
        "material_issues": [],
        "geometry_issues": [],
        "warnings": [],
    }}

    # Count study pods
    for col in bpy.data.collections:
        if col.name.startswith("StudyPod_"):
            result["pod_count"] += 1

    # Count furniture
    furniture_keywords = ["desk", "chair", "shelf", "table", "lamp"]
    for obj in bpy.data.objects:
        name_lower = obj.name.lower()
        if any(kw in name_lower for kw in furniture_keywords):
            result["furniture_count"] += 1

    # Check for missing materials
    for obj in bpy.data.objects:
        if obj.type == "MESH":
            if not obj.data.materials:
                result["material_issues"].append(f"{{obj.name}}: no materials")
            else:
                for mat in obj.data.materials:
                    if mat is None:
                        result["material_issues"].append(f"{{obj.name}}: empty material slot")

    # Check geometry bounds
    all_objects = [o for o in bpy.data.objects if o.type == "MESH"]
    if all_objects:
        min_z = min(o.location.z for o in all_objects)
        max_z = max(o.location.z + o.dimensions.z for o in all_objects)

        if min_z < -1.0:
            result["geometry_issues"].append(f"Objects below ground (min_z={{min_z:.2f}})")

        if max_z > 50.0:
            result["warnings"].append(f"Very tall scene (max_z={{max_z:.2f}}m)")

    # Check collections
    expected_collections = ["OL_GOTHIC_LAYOUT", "OL_Floors", "OL_Columns"]
    for col_name in expected_collections:
        if col_name not in bpy.data.collections:
            result["warnings"].append(f"Missing collection: {{col_name}}")

    # Write results
    with open(OUTPUT_PATH, "w") as f:
        json.dump(result, f, indent=2)

    print(f"Inspection complete: {{result['pod_count']}} pods, {{result['furniture_count']}} furniture items")


if __name__ == "__main__":
    inspect()
'''

    def get_available_positions(self) -> list[tuple[float, float, float]]:
        """
        Get available study pod positions from the Sverchok layout.

        Returns grid positions where pods can be placed.
        """
        # These are based on the 6m bay grid from sverchok_layout.py
        # Desks are placed at wing side positions (abs_i == 2 or abs_j == 2)
        bay_size = 6.0
        wing_bays = 3
        cross_r = 2
        limit = cross_r + wing_bays

        positions = []

        # Generate positions matching sverchok_bake.py desk placements
        for i in range(-limit, limit + 1):
            for j in range(-limit, limit + 1):
                abs_i = abs(i)
                abs_j = abs(j)

                # Check if in shape
                in_crossing = abs_i <= cross_r and abs_j <= cross_r
                in_wing_x = abs_j <= 2 and abs_i <= limit
                in_wing_y = abs_i <= 2 and abs_j <= limit

                if not (in_crossing or in_wing_x or in_wing_y):
                    continue

                # Desk positions are at wing sides
                if abs_j == 2 and not in_crossing:
                    # Wing sides X-axis
                    x = i * bay_size
                    y = j * bay_size - (0.5 * bay_size if j == 2 else -0.5 * bay_size)
                    positions.append((x, y, 0.0))

                if abs_i == 2 and not in_crossing:
                    # Wing sides Y-axis
                    x = i * bay_size - (0.5 * bay_size if i == 2 else -0.5 * bay_size)
                    y = j * bay_size
                    positions.append((x, y, 0.0))

        return positions


def create_outora_adapter(
    library_path: str | None = None,
    project_root: str | None = None,
) -> OutoraLibraryAdapter:
    """
    Factory function to create an Outora adapter.

    Args:
        library_path: Path to library .blend file
        project_root: Path to glia-fab project root

    Returns:
        Configured OutoraLibraryAdapter instance
    """
    return OutoraLibraryAdapter(
        library_blend_path=Path(library_path) if library_path else None,
        project_root=Path(project_root) if project_root else None,
    )
