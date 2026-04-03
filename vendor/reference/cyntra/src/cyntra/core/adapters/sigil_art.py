"""
Sigil Art Adapter - Generate techno-gothic sigil art via FLUX + Hunyuan3D.

This adapter implements a hybrid pipeline:
1. Seed → Sigil spec (deterministic)
2. Spec → FLUX prompt (composer)
3. FLUX → 2D concept art
4. Hunyuan3D → 3D mesh + textures

The adapter orchestrates calls to RunPod-hosted GPU pods.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
import aiohttp

import structlog

from cyntra.core.adapters.base import CostEstimate, PatchProof, ToolchainAdapter

logger = structlog.get_logger()


def _utc_now() -> datetime:
    return datetime.now(UTC)


# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════


@dataclass
class SigilArtConfig:
    """Configuration for sigil art generation."""

    # FLUX pod configuration
    flux_host: str = "localhost"
    flux_port: int = 8888

    # Hunyuan3D pod configuration
    hunyuan_host: str = "localhost"
    hunyuan_port: int = 8080

    # Generation defaults
    default_width: int = 1024
    default_height: int = 1024
    default_steps: int = 4
    generate_3d: bool = True
    generate_textures: bool = True

    # Timeouts
    flux_timeout_seconds: float = 60.0
    hunyuan_timeout_seconds: float = 300.0

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "SigilArtConfig":
        """Create config from dictionary."""
        return cls(
            flux_host=str(d.get("flux_host", "localhost")),
            flux_port=int(d.get("flux_port", 8888)),
            hunyuan_host=str(d.get("hunyuan_host", "localhost")),
            hunyuan_port=int(d.get("hunyuan_port", 8080)),
            default_width=int(d.get("default_width", 1024)),
            default_height=int(d.get("default_height", 1024)),
            default_steps=int(d.get("default_steps", 4)),
            generate_3d=bool(d.get("generate_3d", True)),
            generate_textures=bool(d.get("generate_textures", True)),
            flux_timeout_seconds=float(d.get("flux_timeout_seconds", 60.0)),
            hunyuan_timeout_seconds=float(d.get("hunyuan_timeout_seconds", 300.0)),
        )


@dataclass
class SigilTaskConfig:
    """Configuration for a single sigil generation task."""

    seed: str
    intention: str = ""
    style: str | None = None
    palette: str | None = None
    complexity: int | None = None
    width: int = 1024
    height: int = 1024
    steps: int = 4
    generate_3d: bool = True
    generate_textures: bool = True


# ═══════════════════════════════════════════════════════════════════════════════
# HTTP CLIENTS
# ═══════════════════════════════════════════════════════════════════════════════


class FluxClient:
    """HTTP client for FLUX inference server."""

    def __init__(self, host: str, port: int, timeout: float = 60.0):
        self.base_url = f"http://{host}:{port}"
        self.timeout = aiohttp.ClientTimeout(total=timeout)

    async def health_check(self) -> bool:
        """Check if FLUX server is healthy."""
        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.get(f"{self.base_url}/health") as resp:
                    return resp.status == 200
        except Exception:
            return False

    async def generate(
        self,
        prompt: str,
        seed: int,
        width: int = 1024,
        height: int = 1024,
        steps: int = 4,
        negative_prompt: str = "",
    ) -> dict[str, Any]:
        """
        Generate an image with FLUX.

        Returns:
            Dict with 'path', 'filename', 'seed', 'generation_time_ms'
        """
        payload = {
            "prompt": prompt,
            "seed": seed,
            "width": width,
            "height": height,
            "steps": steps,
        }
        if negative_prompt:
            payload["negative_prompt"] = negative_prompt

        async with aiohttp.ClientSession(timeout=self.timeout) as session:
            async with session.post(
                f"{self.base_url}/generate",
                json=payload,
            ) as resp:
                if resp.status != 200:
                    error_text = await resp.text()
                    raise RuntimeError(f"FLUX generation failed: {error_text}")
                return await resp.json()

    async def download_output(
        self,
        filename: str,
        output_path: Path,
    ) -> Path:
        """Download a generated image to local path."""
        async with aiohttp.ClientSession(timeout=self.timeout) as session:
            async with session.get(f"{self.base_url}/outputs/{filename}") as resp:
                if resp.status != 200:
                    raise RuntimeError(f"Failed to download {filename}")
                content = await resp.read()
                output_path.write_bytes(content)
                return output_path


class Hunyuan3DClient:
    """HTTP client for Hunyuan3D inference server."""

    def __init__(self, host: str, port: int, timeout: float = 300.0):
        self.base_url = f"http://{host}:{port}"
        self.timeout = aiohttp.ClientTimeout(total=timeout)

    async def health_check(self) -> bool:
        """Check if Hunyuan3D server is healthy."""
        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.get(f"{self.base_url}/health") as resp:
                    return resp.status == 200
        except Exception:
            return False

    async def generate(
        self,
        image_path: Path,
        seed: int = 42,
        texture: bool = True,
    ) -> dict[str, Any]:
        """
        Generate 3D mesh from image.

        Returns:
            Dict with 'mesh_path', 'textured_mesh_path', 'generation_time_ms'
        """
        data = aiohttp.FormData()
        data.add_field(
            "image",
            open(image_path, "rb"),
            filename=image_path.name,
            content_type="image/png",
        )
        data.add_field("seed", str(seed))
        data.add_field("texture", str(texture).lower())

        async with aiohttp.ClientSession(timeout=self.timeout) as session:
            async with session.post(
                f"{self.base_url}/generate",
                data=data,
            ) as resp:
                if resp.status != 200:
                    error_text = await resp.text()
                    raise RuntimeError(f"Hunyuan3D generation failed: {error_text}")
                return await resp.json()

    async def download_output(
        self,
        filename: str,
        output_path: Path,
    ) -> Path:
        """Download a generated mesh to local path."""
        async with aiohttp.ClientSession(timeout=self.timeout) as session:
            async with session.get(f"{self.base_url}/outputs/{filename}") as resp:
                if resp.status != 200:
                    raise RuntimeError(f"Failed to download {filename}")
                content = await resp.read()
                output_path.write_bytes(content)
                return output_path


# ═══════════════════════════════════════════════════════════════════════════════
# ADAPTER
# ═══════════════════════════════════════════════════════════════════════════════


class SigilArtAdapter(ToolchainAdapter):
    """
    Adapter for sigil art generation via FLUX + Hunyuan3D.

    This adapter orchestrates a hybrid 2D→3D pipeline for generating
    techno-gothic sigil art from seeds.

    Expected manifest shape:
        manifest["sigil_config"] = {
            "seed": "0x2a7f8c3e",
            "intention": "protection ward",
            "style": "gothic",        # optional: gothic, circuit, runic, organic
            "palette": "gold",        # optional: gold, steel, mono, ember, void
            "complexity": 7,          # optional: 1-10
            "generate_3d": true,      # optional: whether to run Hunyuan3D
        }

    The adapter:
    1. Parses sigil config from manifest
    2. Generates a deterministic sigil spec from seed
    3. Composes a FLUX-optimized prompt
    4. Calls FLUX to generate 2D concept art
    5. Optionally calls Hunyuan3D to generate 3D mesh
    6. Returns PatchProof with all artifacts

    Example usage:
        adapter = SigilArtAdapter({
            "flux_host": "pod-ip",
            "flux_port": 8888,
            "hunyuan_host": "pod-ip",
            "hunyuan_port": 8080,
        })
        if await adapter.health_check():
            proof = await adapter.execute(manifest, workcell_path, timeout)
    """

    name = "sigil-art"
    supports_mcp = False
    supports_streaming = False

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        """
        Initialize SigilArt adapter.

        Args:
            config: Configuration dict with pod connection details
        """
        self.raw_config = config or {}
        self.config = SigilArtConfig.from_dict(self.raw_config)
        self._available: bool | None = None
        self._flux_client: FluxClient | None = None
        self._hunyuan_client: Hunyuan3DClient | None = None

    @property
    def available(self) -> bool:
        """Check if adapter is available (sync check)."""
        if self._available is None:
            self._available = True  # Assume available, verify in health_check
        return self._available

    def _get_flux_client(self) -> FluxClient:
        """Get or create FLUX client."""
        if self._flux_client is None:
            self._flux_client = FluxClient(
                host=self.config.flux_host,
                port=self.config.flux_port,
                timeout=self.config.flux_timeout_seconds,
            )
        return self._flux_client

    def _get_hunyuan_client(self) -> Hunyuan3DClient:
        """Get or create Hunyuan3D client."""
        if self._hunyuan_client is None:
            self._hunyuan_client = Hunyuan3DClient(
                host=self.config.hunyuan_host,
                port=self.config.hunyuan_port,
                timeout=self.config.hunyuan_timeout_seconds,
            )
        return self._hunyuan_client

    async def health_check(self) -> bool:
        """
        Check if both pods are healthy.

        Returns:
            True if at least FLUX is available
        """
        try:
            flux_ok = await self._get_flux_client().health_check()
            self._available = flux_ok
            return flux_ok
        except Exception as e:
            logger.debug("SigilArt health check failed", error=str(e))
            self._available = False
            return False

    def estimate_cost(self, manifest: dict) -> CostEstimate:
        """
        Estimate cost for sigil generation.

        RunPod A40: ~$0.35/hr = ~$0.006/min
        FLUX generation: ~30s = ~$0.003
        Hunyuan3D generation: ~60s = ~$0.006

        Args:
            manifest: Task manifest

        Returns:
            CostEstimate (GPU cost, not tokens)
        """
        sigil_config = manifest.get("sigil_config") or {}
        generate_3d = sigil_config.get("generate_3d", self.config.generate_3d)

        # Rough cost estimate
        flux_cost = 0.003  # ~30s on A40
        hunyuan_cost = 0.006 if generate_3d else 0.0  # ~60s on A5000

        return CostEstimate(
            estimated_tokens=0,
            estimated_cost_usd=flux_cost + hunyuan_cost,
            model="flux-klein-9b+hunyuan3d-2",
        )

    def execute_sync(
        self,
        manifest: dict,
        workcell_path: Path,
        timeout_seconds: int = 600,
    ) -> PatchProof:
        """Synchronous execution wrapper."""
        return asyncio.run(
            self.execute(
                manifest=manifest,
                workcell_path=workcell_path,
                timeout=timedelta(seconds=timeout_seconds),
            )
        )

    async def execute(
        self,
        manifest: dict,
        workcell_path: Path,
        timeout: timedelta,
    ) -> PatchProof:
        """
        Execute sigil art generation.

        Args:
            manifest: Task manifest with sigil_config
            workcell_path: Path to workcell directory
            timeout: Maximum execution time

        Returns:
            PatchProof with status, artifacts, and metadata
        """
        started_at = _utc_now()
        workcell_id = str(manifest.get("workcell_id", "unknown"))
        issue = manifest.get("issue") or {}
        issue_id = str(issue.get("id", "unknown"))

        # Setup output directory
        output_dir = workcell_path / "sigil_outputs"
        output_dir.mkdir(parents=True, exist_ok=True)

        # Parse sigil config
        sigil_config = manifest.get("sigil_config") or {}
        task_config = self._parse_task_config(sigil_config)

        logger.info(
            "SigilArt execution starting",
            workcell_id=workcell_id,
            issue_id=issue_id,
            seed=task_config.seed,
            style=task_config.style,
            palette=task_config.palette,
        )

        try:
            # Import sigil composer
            try:
                from cyntra.fab.sigil.spec import SigilSpec, SigilStyle, SigilPalette
                from cyntra.fab.sigil.composer import SigilPromptComposer
            except ImportError:
                # Fallback for direct execution
                import sys
                sigil_path = Path(__file__).parent.parent.parent / "fab" / "sigil"
                sys.path.insert(0, str(sigil_path))
                from spec import SigilSpec, SigilStyle, SigilPalette
                from composer import SigilPromptComposer

            # Build sigil spec from seed
            style = SigilStyle(task_config.style) if task_config.style else None
            palette = SigilPalette(task_config.palette) if task_config.palette else None

            spec = SigilSpec.from_seed(
                seed=task_config.seed,
                intention=task_config.intention,
                style=style,
                complexity=task_config.complexity,
                palette=palette,
            )

            # Compose FLUX prompt
            composer = SigilPromptComposer()
            composed = composer.compose(spec)

            logger.info(
                "Sigil spec generated",
                seed=task_config.seed,
                style=spec.style.value,
                palette=spec.palette.value,
                complexity=spec.complexity,
                rarity=spec.rarity.value,
                flux_seed=composed.seed,
            )

            # Save spec and prompt
            spec_path = output_dir / f"sigil_{task_config.seed}_spec.json"
            spec_data = {
                "seed": task_config.seed,
                "intention": task_config.intention,
                "style": spec.style.value,
                "palette": spec.palette.value,
                "complexity": spec.complexity,
                "rarity": spec.rarity.value,
                "traits": {
                    "symmetry": spec.traits.symmetry.value,
                    "glyph_count": spec.traits.glyph_count,
                    "node_count": spec.traits.node_count,
                    "has_inner_circle": spec.traits.has_inner_circle,
                    "has_outer_ring": spec.traits.has_outer_ring,
                    "has_runic_marks": spec.traits.has_runic_marks,
                    "has_concentric": spec.traits.has_concentric,
                    "special_element": spec.traits.special_element.value if spec.traits.special_element else None,
                },
                "flux_seed": composed.seed,
                "prompt": composed.prompt,
                "negative_prompt": composed.negative_prompt,
                "components": composed.components,
            }
            spec_path.write_text(json.dumps(spec_data, indent=2))

            # Check FLUX availability
            flux_client = self._get_flux_client()
            if not await flux_client.health_check():
                return self._create_error_proof(
                    workcell_id=workcell_id,
                    issue_id=issue_id,
                    error="FLUX server not available",
                    started_at=started_at,
                )

            # Generate 2D concept with FLUX
            logger.info("Generating 2D concept with FLUX", seed=composed.seed)
            flux_result = await flux_client.generate(
                prompt=composed.prompt,
                seed=composed.seed,
                width=task_config.width,
                height=task_config.height,
                steps=task_config.steps,
            )

            # Download concept image
            concept_filename = flux_result.get("filename", f"sigil_{composed.seed}.png")
            concept_path = output_dir / f"concept_{concept_filename}"
            await flux_client.download_output(concept_filename, concept_path)

            logger.info(
                "2D concept generated",
                path=str(concept_path),
                generation_time_ms=flux_result.get("generation_time_ms"),
            )

            # Optionally generate 3D mesh
            mesh_path: Path | None = None
            textured_mesh_path: Path | None = None
            hunyuan_result: dict[str, Any] | None = None

            if task_config.generate_3d:
                hunyuan_client = self._get_hunyuan_client()
                if await hunyuan_client.health_check():
                    logger.info("Generating 3D mesh with Hunyuan3D")
                    hunyuan_result = await hunyuan_client.generate(
                        image_path=concept_path,
                        seed=composed.seed,
                        texture=task_config.generate_textures,
                    )

                    # Download mesh files
                    if hunyuan_result.get("mesh_path"):
                        mesh_filename = Path(hunyuan_result["mesh_path"]).name
                        mesh_path = output_dir / f"mesh_{mesh_filename}"
                        await hunyuan_client.download_output(mesh_filename, mesh_path)

                    if hunyuan_result.get("textured_mesh_path"):
                        tex_filename = Path(hunyuan_result["textured_mesh_path"]).name
                        textured_mesh_path = output_dir / f"textured_{tex_filename}"
                        await hunyuan_client.download_output(tex_filename, textured_mesh_path)

                    logger.info(
                        "3D mesh generated",
                        mesh_path=str(mesh_path) if mesh_path else None,
                        textured_path=str(textured_mesh_path) if textured_mesh_path else None,
                        generation_time_ms=hunyuan_result.get("generation_time_ms"),
                    )
                else:
                    logger.warning("Hunyuan3D server not available, skipping 3D generation")

            # Build proof
            completed_at = _utc_now()
            duration_ms = int((completed_at - started_at).total_seconds() * 1000)

            return self._build_proof(
                workcell_id=workcell_id,
                issue_id=issue_id,
                spec=spec_data,
                concept_path=concept_path,
                mesh_path=mesh_path,
                textured_mesh_path=textured_mesh_path,
                flux_result=flux_result,
                hunyuan_result=hunyuan_result,
                started_at=started_at,
                completed_at=completed_at,
                duration_ms=duration_ms,
            )

        except Exception as e:
            logger.exception("SigilArt execution error", error=str(e))
            return self._create_error_proof(
                workcell_id=workcell_id,
                issue_id=issue_id,
                error=f"Execution failed: {e}",
                started_at=started_at,
            )

    def _parse_task_config(self, config: dict[str, Any]) -> SigilTaskConfig:
        """Parse task configuration from manifest."""
        return SigilTaskConfig(
            seed=str(config.get("seed", "0")),
            intention=str(config.get("intention", "")),
            style=config.get("style"),
            palette=config.get("palette"),
            complexity=config.get("complexity"),
            width=int(config.get("width", self.config.default_width)),
            height=int(config.get("height", self.config.default_height)),
            steps=int(config.get("steps", self.config.default_steps)),
            generate_3d=bool(config.get("generate_3d", self.config.generate_3d)),
            generate_textures=bool(config.get("generate_textures", self.config.generate_textures)),
        )

    def _build_proof(
        self,
        *,
        workcell_id: str,
        issue_id: str,
        spec: dict[str, Any],
        concept_path: Path,
        mesh_path: Path | None,
        textured_mesh_path: Path | None,
        flux_result: dict[str, Any],
        hunyuan_result: dict[str, Any] | None,
        started_at: datetime,
        completed_at: datetime,
        duration_ms: int,
    ) -> PatchProof:
        """Build PatchProof from execution results."""
        # Collect all output files
        output_files = [str(concept_path)]
        if mesh_path:
            output_files.append(str(mesh_path))
        if textured_mesh_path:
            output_files.append(str(textured_mesh_path))

        artifacts: dict[str, Any] = {
            "sigil_spec": spec,
            "concept_image": str(concept_path),
            "flux_result": flux_result,
            "output_files": output_files,
        }

        if mesh_path:
            artifacts["mesh"] = str(mesh_path)
        if textured_mesh_path:
            artifacts["textured_mesh"] = str(textured_mesh_path)
        if hunyuan_result:
            artifacts["hunyuan_result"] = hunyuan_result

        return PatchProof(
            schema_version="1.0.0",
            workcell_id=workcell_id,
            issue_id=issue_id,
            status="success",
            patch={
                "files_modified": [],
                "diff_stats": {"files_changed": 0, "insertions": 0, "deletions": 0},
                "forbidden_path_violations": [],
            },
            verification={
                "gates": {},
                "all_passed": True,
                "blocking_failures": [],
            },
            metadata={
                "toolchain": self.name,
                "model": "flux-klein-9b+hunyuan3d-2",
                "seed": spec["seed"],
                "style": spec["style"],
                "palette": spec["palette"],
                "rarity": spec["rarity"],
                "started_at": started_at.isoformat().replace("+00:00", "Z"),
                "completed_at": completed_at.isoformat().replace("+00:00", "Z"),
                "duration_ms": duration_ms,
                "flux_generation_ms": flux_result.get("generation_time_ms"),
                "hunyuan_generation_ms": hunyuan_result.get("generation_time_ms") if hunyuan_result else None,
            },
            commands_executed=[
                {
                    "command": f"flux generate --seed {spec['flux_seed']}",
                    "exit_code": 0,
                    "duration_ms": flux_result.get("generation_time_ms", 0),
                },
            ],
            artifacts=artifacts,
            confidence=0.95,
            risk_classification="low",
        )

    def _create_error_proof(
        self,
        *,
        workcell_id: str,
        issue_id: str,
        error: str,
        started_at: datetime,
    ) -> PatchProof:
        """Create PatchProof for execution error."""
        completed_at = _utc_now()
        duration_ms = int((completed_at - started_at).total_seconds() * 1000)

        return PatchProof(
            schema_version="1.0.0",
            workcell_id=workcell_id,
            issue_id=issue_id,
            status="error",
            patch={
                "files_modified": [],
                "diff_stats": {"files_changed": 0, "insertions": 0, "deletions": 0},
                "forbidden_path_violations": [],
            },
            verification={
                "gates": {},
                "all_passed": False,
                "blocking_failures": ["sigil_art_error"],
            },
            metadata={
                "toolchain": self.name,
                "model": "flux-klein-9b+hunyuan3d-2",
                "started_at": started_at.isoformat().replace("+00:00", "Z"),
                "completed_at": completed_at.isoformat().replace("+00:00", "Z"),
                "duration_ms": duration_ms,
                "error": error,
            },
            artifacts={"error": error},
            confidence=0.0,
            risk_classification="low",
        )
