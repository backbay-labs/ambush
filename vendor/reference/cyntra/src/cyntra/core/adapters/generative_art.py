"""
Generative Art Adapter - Kernel adapter for fab/art pipeline.

Thin wrapper that delegates to:
- cyntra.fab.art for spec generation and prompt composition
- cyntra.fab.art.backends for FLUX/Hunyuan3D generation

Supports all artifact types: sigils, portraits, icons, textures, etc.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import structlog

from cyntra.core.adapters.base import CostEstimate, PatchProof, ToolchainAdapter

logger = structlog.get_logger()


def _utc_now() -> datetime:
    return datetime.now(UTC)


# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════


@dataclass
class GenerativeArtConfig:
    """Configuration for generative art adapter."""

    # FLUX backend
    flux_endpoint: str = "http://localhost:8089"
    flux_timeout: int = 120

    # Hunyuan3D backend
    hunyuan_endpoint: str = "http://localhost:8088"
    hunyuan_timeout: int = 300

    # Generation defaults
    default_width: int = 1024
    default_height: int = 1024
    default_steps: int = 4
    generate_3d: bool = True

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "GenerativeArtConfig":
        """Create config from dictionary."""
        return cls(
            flux_endpoint=str(d.get("flux_endpoint", "http://localhost:8089")),
            flux_timeout=int(d.get("flux_timeout", 120)),
            hunyuan_endpoint=str(d.get("hunyuan_endpoint", "http://localhost:8088")),
            hunyuan_timeout=int(d.get("hunyuan_timeout", 300)),
            default_width=int(d.get("default_width", 1024)),
            default_height=int(d.get("default_height", 1024)),
            default_steps=int(d.get("default_steps", 4)),
            generate_3d=bool(d.get("generate_3d", True)),
        )


# ═══════════════════════════════════════════════════════════════════════════════
# ADAPTER
# ═══════════════════════════════════════════════════════════════════════════════


class GenerativeArtAdapter(ToolchainAdapter):
    """
    Kernel adapter for generative art via fab/art pipeline.

    This adapter orchestrates artifact generation for any supported type:
    - Sigils, portraits, icons, textures, banners, cards, environments

    Expected manifest shape:
        manifest["art_config"] = {
            "artifact_type": "sigil",      # sigil, portrait, icon, texture, etc.
            "seed": "0x2a7f8c3e",
            "intention": "protection ward",
            # Type-specific options (for sigil):
            "style": "gothic",
            "palette": "gold",
            "complexity": 7,
            # Generation options:
            "generate_3d": true,
            "width": 1024,
            "height": 1024,
        }

    The adapter:
    1. Creates spec via fab.art.create_spec()
    2. Composes prompt via fab.art.compose_prompt()
    3. Generates 2D image via FluxBackend
    4. Optionally generates 3D mesh via Hunyuan3DBackend
    5. Returns PatchProof with all artifacts
    """

    name = "generative-art"
    supports_mcp = False
    supports_streaming = False

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self.raw_config = config or {}
        self.config = GenerativeArtConfig.from_dict(self.raw_config)
        self._available: bool | None = None

    @property
    def available(self) -> bool:
        if self._available is None:
            self._available = True
        return self._available

    async def health_check(self) -> bool:
        """Check if FLUX backend is available."""
        try:
            from cyntra.fab.art.backends import FluxBackend
            from cyntra.fab.art.backends.flux import FluxConfig

            backend = FluxBackend(FluxConfig(endpoint=self.config.flux_endpoint))
            self._available = await backend.health_check()
            await backend.close()
            return self._available
        except Exception as e:
            logger.debug("GenerativeArt health check failed", error=str(e))
            self._available = False
            return False

    def estimate_cost(self, manifest: dict) -> CostEstimate:
        """Estimate generation cost."""
        art_config = manifest.get("art_config") or {}
        generate_3d = art_config.get("generate_3d", self.config.generate_3d)

        # RunPod A40: ~$0.35/hr
        flux_cost = 0.003  # ~30s
        hunyuan_cost = 0.006 if generate_3d else 0.0  # ~60s

        return CostEstimate(
            estimated_tokens=0,
            estimated_cost_usd=flux_cost + hunyuan_cost,
            model="flux+hunyuan3d",
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
        """Execute generative art pipeline."""
        started_at = _utc_now()
        workcell_id = str(manifest.get("workcell_id", "unknown"))
        issue = manifest.get("issue") or {}
        issue_id = str(issue.get("id", "unknown"))

        # Setup output directory
        output_dir = workcell_path / "art_outputs"
        output_dir.mkdir(parents=True, exist_ok=True)

        # Parse art config
        art_config = manifest.get("art_config") or manifest.get("sigil_config") or {}

        try:
            # Import fab.art
            from cyntra.fab.art import (
                ArtifactType,
                create_spec,
                create_composer,
                GenerationInput,
                OutputFormat,
            )
            from cyntra.fab.art.backends import FluxBackend, Hunyuan3DBackend
            from cyntra.fab.art.backends.flux import FluxConfig
            from cyntra.fab.art.backends.hunyuan3d import Hunyuan3DConfig

            # Determine artifact type
            type_str = art_config.get("artifact_type", "sigil")
            try:
                artifact_type = ArtifactType(type_str)
            except ValueError:
                artifact_type = ArtifactType.SIGIL

            # Extract common params
            seed = str(art_config.get("seed", "0"))
            intention = str(art_config.get("intention", ""))
            width = int(art_config.get("width", self.config.default_width))
            height = int(art_config.get("height", self.config.default_height))
            steps = int(art_config.get("steps", self.config.default_steps))
            generate_3d = bool(art_config.get("generate_3d", self.config.generate_3d))

            # Build type-specific overrides
            overrides = {}
            if "style" in art_config:
                overrides["style"] = art_config["style"]
            if "palette" in art_config:
                overrides["palette"] = art_config["palette"]
            if "complexity" in art_config:
                overrides["complexity"] = art_config["complexity"]

            logger.info(
                "GenerativeArt execution starting",
                artifact_type=artifact_type.value,
                seed=seed,
                workcell_id=workcell_id,
            )

            # Create spec and compose prompt
            spec = create_spec(artifact_type, seed=seed, intention=intention, **overrides)
            composer = create_composer(artifact_type)
            prompt = composer.compose(spec)

            logger.info(
                "Spec and prompt generated",
                artifact_type=artifact_type.value,
                seed=seed,
                rarity=spec.rarity.value,
                model_seed=prompt.seed,
            )

            # Save spec
            spec_path = output_dir / f"{artifact_type.value}_{seed}_spec.json"
            spec_data = spec.to_dict()
            spec_data["prompt"] = prompt.prompt
            spec_data["negative_prompt"] = prompt.negative_prompt
            spec_data["model_seed"] = prompt.seed
            spec_data["components"] = prompt.components
            spec_path.write_text(json.dumps(spec_data, indent=2))

            # Initialize FLUX backend
            flux_backend = FluxBackend(FluxConfig(
                endpoint=self.config.flux_endpoint,
                timeout_seconds=self.config.flux_timeout,
            ))

            # Generate 2D image
            flux_input = GenerationInput(
                prompt=prompt,
                spec=spec,
                output_dir=output_dir,
                output_format=OutputFormat.PNG,
                width=width,
                height=height,
                steps=steps,
            )

            logger.info("Generating 2D image with FLUX")
            flux_result = await flux_backend.generate(flux_input)
            await flux_backend.close()

            if not flux_result.success:
                return self._create_error_proof(
                    workcell_id=workcell_id,
                    issue_id=issue_id,
                    error=f"FLUX generation failed: {flux_result.errors}",
                    started_at=started_at,
                )

            logger.info(
                "2D image generated",
                path=str(flux_result.image_path),
                time_ms=flux_result.generation_time_ms,
            )

            # Optionally generate 3D mesh
            mesh_path = None
            hunyuan_result = None

            if generate_3d and flux_result.image_path:
                hunyuan_backend = Hunyuan3DBackend(Hunyuan3DConfig(
                    endpoint=self.config.hunyuan_endpoint,
                    timeout_seconds=self.config.hunyuan_timeout,
                ))

                if await hunyuan_backend.health_check():
                    hunyuan_input = GenerationInput(
                        prompt=prompt,
                        spec=spec,
                        output_dir=output_dir,
                        mesh_format=OutputFormat.GLB,
                        generate_3d=True,
                        params={"image_path": str(flux_result.image_path)},
                    )

                    logger.info("Generating 3D mesh with Hunyuan3D")
                    hunyuan_result = await hunyuan_backend.generate(hunyuan_input)

                    if hunyuan_result.success:
                        mesh_path = hunyuan_result.mesh_path
                        logger.info(
                            "3D mesh generated",
                            path=str(mesh_path),
                            time_ms=hunyuan_result.generation_time_ms,
                        )
                    else:
                        logger.warning(
                            "Hunyuan3D generation failed",
                            errors=hunyuan_result.errors,
                        )

                await hunyuan_backend.close()

            # Build proof
            completed_at = _utc_now()
            duration_ms = int((completed_at - started_at).total_seconds() * 1000)

            return self._build_proof(
                workcell_id=workcell_id,
                issue_id=issue_id,
                spec_data=spec_data,
                image_path=flux_result.image_path,
                mesh_path=mesh_path,
                flux_time_ms=flux_result.generation_time_ms,
                hunyuan_time_ms=hunyuan_result.generation_time_ms if hunyuan_result else None,
                started_at=started_at,
                completed_at=completed_at,
                duration_ms=duration_ms,
            )

        except Exception as e:
            logger.exception("GenerativeArt execution error", error=str(e))
            return self._create_error_proof(
                workcell_id=workcell_id,
                issue_id=issue_id,
                error=f"Execution failed: {e}",
                started_at=started_at,
            )

    def _build_proof(
        self,
        *,
        workcell_id: str,
        issue_id: str,
        spec_data: dict[str, Any],
        image_path: Path | None,
        mesh_path: Path | None,
        flux_time_ms: int,
        hunyuan_time_ms: int | None,
        started_at: datetime,
        completed_at: datetime,
        duration_ms: int,
    ) -> PatchProof:
        """Build PatchProof from execution results."""
        output_files = []
        if image_path:
            output_files.append(str(image_path))
        if mesh_path:
            output_files.append(str(mesh_path))

        artifacts: dict[str, Any] = {
            "spec": spec_data,
            "output_files": output_files,
        }
        if image_path:
            artifacts["image"] = str(image_path)
        if mesh_path:
            artifacts["mesh"] = str(mesh_path)

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
                "model": "flux+hunyuan3d",
                "artifact_type": spec_data.get("artifact_type"),
                "seed": spec_data.get("seed"),
                "rarity": spec_data.get("rarity"),
                "started_at": started_at.isoformat().replace("+00:00", "Z"),
                "completed_at": completed_at.isoformat().replace("+00:00", "Z"),
                "duration_ms": duration_ms,
                "flux_generation_ms": flux_time_ms,
                "hunyuan_generation_ms": hunyuan_time_ms,
            },
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
                "blocking_failures": ["generative_art_error"],
            },
            metadata={
                "toolchain": self.name,
                "started_at": started_at.isoformat().replace("+00:00", "Z"),
                "completed_at": completed_at.isoformat().replace("+00:00", "Z"),
                "duration_ms": duration_ms,
                "error": error,
            },
            artifacts={"error": error},
            confidence=0.0,
            risk_classification="low",
        )


# Backwards compatibility alias
SigilArtAdapter = GenerativeArtAdapter
