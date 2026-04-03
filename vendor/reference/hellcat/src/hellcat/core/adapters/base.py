"""
Base adapter interface for toolchain integrations.

All toolchain adapters must implement this protocol.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import logging
import os
import re
import subprocess
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

logger = logging.getLogger(__name__)
_aegis_client = None
_aegis_executor = ThreadPoolExecutor(max_workers=2)


def _get_aegis_client() -> Any | None:
    """Get or create the Aegis client."""
    global _aegis_client
    if _aegis_client is None:
        try:
            from hellcat.trust.aegis.client import AegisClient

            _aegis_client = AegisClient(fallback_to_local=True)
        except ImportError:
            _aegis_client = False
    return _aegis_client if _aegis_client else None


@dataclass
class CostEstimate:
    """Estimated cost for executing a task."""

    estimated_tokens: int
    estimated_cost_usd: float
    model: str


@dataclass
class PatchProof:
    """Standardized output from a workcell execution."""

    schema_version: str
    workcell_id: str
    issue_id: str
    status: str  # success, partial, failed, timeout, error
    patch: dict[str, Any]
    verification: dict[str, Any]
    metadata: dict[str, Any]
    commands_executed: list[dict[str, Any]] | None = None
    artifacts: dict[str, Any] | None = None
    confidence: float = 0.5
    risk_classification: str = "medium"
    risk_factors: list[str] | None = None
    beads_mutations: list[dict[str, Any]] | None = None
    follow_ups: list[dict[str, Any]] | None = None
    review: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "workcell_id": self.workcell_id,
            "issue_id": self.issue_id,
            "status": self.status,
            "patch": self.patch,
            "verification": self.verification,
            "metadata": self.metadata,
            "commands_executed": self.commands_executed,
            "artifacts": self.artifacts,
            "confidence": self.confidence,
            "risk_classification": self.risk_classification,
            "risk_factors": self.risk_factors,
            "beads_mutations": self.hellcat_mutations,
            "follow_ups": self.follow_ups,
            "review": self.review,
        }


@dataclass
class AegisRunState:
    """Tracks Aegis run state for adapter executions."""

    run_id: str
    run_dir: Path
    workcell_path: Path | None
    client: Any | None = None
    handle: Any | None = None


class ToolchainAdapter(ABC):
    """
    Base class for toolchain adapters.

    All adapters must implement:
    - execute: Run the task and return Patch+Proof
    - health_check: Verify adapter is operational
    - estimate_cost: Estimate tokens/cost for a task
    """

    name: str
    supports_mcp: bool = False
    supports_streaming: bool = False

    @abstractmethod
    async def execute(
        self,
        manifest: dict,
        workcell_path: Path,
        timeout: timedelta,
    ) -> PatchProof:
        """
        Execute a task in the workcell.

        Args:
            manifest: Task manifest with issue details and configuration
            workcell_path: Path to the workcell directory
            timeout: Maximum execution time

        Returns:
            PatchProof with execution results
        """
        ...

    @abstractmethod
    async def health_check(self) -> bool:
        """
        Verify the adapter is operational.

        Returns:
            True if the toolchain is available and working
        """
        ...

    @abstractmethod
    def estimate_cost(self, manifest: dict) -> CostEstimate:
        """
        Estimate the cost of executing a task.

        Args:
            manifest: Task manifest

        Returns:
            Cost estimate including tokens and USD
        """
        ...

    def _build_prompt(self, manifest: dict, workcell_path: Path | None = None) -> str:
        """
        Build a prompt from the task manifest.

        Override in subclasses for toolchain-specific formatting.
        """
        issue = manifest.get("issue", {})
        description = issue.get("description")
        if not isinstance(description, str) or not description.strip():
            description = "No description provided."

        workcell_id = manifest.get("workcell_id", "unknown")
        issue_id = issue.get("id", "unknown")
        branch_name = manifest.get("branch_name")
        toolchain = manifest.get("toolchain")
        model = (manifest.get("toolchain_config") or {}).get("model")

        parts = [f"# Task: {issue.get('title', 'Unknown')}", ""]

        # High-signal context for the agent
        context_lines: list[str] = []
        if issue_id:
            context_lines.append(f"- Issue: {issue_id}")
        if workcell_id:
            context_lines.append(f"- Workcell: {workcell_id}")
        if branch_name:
            context_lines.append(f"- Branch: {branch_name}")
        if toolchain:
            context_lines.append(f"- Toolchain: {toolchain}")
        if model:
            context_lines.append(f"- Model: {model}")
        tags = issue.get("tags", [])
        if tags:
            context_lines.append(f"- Tags: {', '.join(str(t) for t in tags)}")

        if context_lines:
            parts.extend(["## Context", *context_lines, ""])

        policy_summary = self._format_policy_summary(manifest)
        if policy_summary:
            parts.extend(["## Security Policy", *policy_summary, ""])

        parts.extend(
            [
                "## Execution Guidelines",
                "- Start by stating a short plan (3–6 bullets) before making edits.",
                "- Satisfy the acceptance criteria and keep changes minimal.",
                "- Prefer root-cause fixes; avoid unrelated refactors and drive-by formatting.",
                "- Respect forbidden paths exactly (do not modify them).",
                "- Prefer ripgrep (`rg`) for search; keep commands deterministic and repo-local.",
                "- Run the listed quality gates before finishing; if a gate can't be run, explain why and give the exact command(s) to run.",
                "- Finish with a concise summary of changes, key files touched, and any follow-up steps.",
                "",
            ]
        )

        # Optional: pre-run strategy directive (compact, no verbose chain-of-thought required).
        strategy_cfg = manifest.get("strategy")
        if isinstance(strategy_cfg, dict) and strategy_cfg.get("enabled") is True:
            directive_cfg = strategy_cfg.get("directive")
            patterns = directive_cfg.get("patterns") if isinstance(directive_cfg, dict) else None
            if isinstance(patterns, dict) and patterns:
                parts.append("## Strategy Directive")
                source = directive_cfg.get("source") if isinstance(directive_cfg, dict) else None
                directive_hash = (
                    directive_cfg.get("directive_hash") if isinstance(directive_cfg, dict) else None
                )
                header_bits: list[str] = []
                if isinstance(source, str) and source.strip():
                    header_bits.append(f"source={source.strip()}")
                if isinstance(directive_hash, str) and directive_hash.strip():
                    header_bits.append(f"id={directive_hash.strip()}")
                if header_bits:
                    parts.append(f"[{', '.join(header_bits)}]")
                parts.append(
                    "Follow these high-level strategy patterns throughout this task:"
                )

                try:
                    from hellcat.eval.strategy.rubric import HELLCAT_V1_RUBRIC

                    for dim in HELLCAT_V1_RUBRIC:
                        value = patterns.get(dim.id)
                        if isinstance(value, str) and value.strip():
                            parts.append(f"- {dim.name} (`{dim.id}`): `{value.strip()}`")
                except Exception:
                    for dim_id, value in sorted(patterns.items()):
                        parts.append(f"- {dim_id}: {value}")

                parts.append("")

        # Inject learned context from memory (claude-mem pattern)
        memory_context = manifest.get("memory_context", {})
        if not isinstance(memory_context, dict):
            memory_context = {}

        learned_patterns = memory_context.get("learned_patterns")
        if isinstance(learned_patterns, dict) and learned_patterns:
            # Learned patterns are markdown blocks written by sleeptime.
            # Render compact bullet excerpts for prompt injection.
            parts.append("## Learned Context (Sleeptime)")
            parts.append("*From `.hellcat/learned_context/` consolidation blocks:*")
            parts.append("")

            def _humanize_block_name(name: str) -> str:
                return " ".join(bit.capitalize() for bit in name.replace("-", "_").split("_") if bit)

            total_bullets = 0
            max_total_bullets = 24
            for block_name in sorted(learned_patterns.keys()):
                if total_bullets >= max_total_bullets:
                    break
                content = learned_patterns.get(block_name)
                if not isinstance(content, str) or not content.strip():
                    continue

                # Prefer top-level entries written by MemoryBlockWriter ("- **...**").
                lines = [line.rstrip() for line in content.splitlines()]
                excerpt: list[str] = []
                i = 0
                while i < len(lines) and len(excerpt) < 8 and total_bullets < max_total_bullets:
                    line = lines[i].strip()
                    if line.startswith("- **"):
                        excerpt.append(f"- {line[2:].strip()}")
                        total_bullets += 1
                        # Include up to 1 sub-bullet if present (e.g., mitigation/reason).
                        if i + 1 < len(lines):
                            next_line = lines[i + 1]
                            if next_line.startswith("  -") or next_line.startswith("\t-"):
                                i += 1
                                excerpt.append(next_line.rstrip())
                    i += 1

                if not excerpt:
                    continue

                parts.append(f"### {_humanize_block_name(str(block_name))}")
                parts.extend(excerpt)
                parts.append("")

        if memory_context and memory_context.get("memory_available"):
            warnings = memory_context.get("warnings", [])
            patterns = memory_context.get("patterns", [])
            membox = memory_context.get("membox", {}) if isinstance(memory_context, dict) else {}
            recent_topics = (
                membox.get("recent_topics", []) if isinstance(membox, dict) else []
            )
            membox_section_lines: list[str] = []
            try:
                from hellcat.cognition.memory.membox.retrieval import render_membox_context_section

                if isinstance(membox, dict):
                    membox_section_lines = render_membox_context_section(membox)
            except Exception:
                membox_section_lines = []

            if warnings or patterns:
                parts.append("## Learned Context")
                parts.append("*From previous executions in this codebase:*")
                parts.append("")

            if warnings:
                parts.append("### Avoid These Patterns")
                for w in warnings[:5]:
                    parts.append(f"- {w}")
                parts.append("")

            if patterns:
                parts.append("### Successful Approaches")
                for p in patterns[:5]:
                    parts.append(f"- {p}")
                parts.append("")

            if membox_section_lines:
                parts.extend(membox_section_lines)
            elif recent_topics:
                parts.append("## Membox Context")
                parts.append("*Topic-continuous memory (recent topics):*")
                parts.append("")
                for item in recent_topics[:5]:
                    if isinstance(item, str):
                        parts.append(f"- {item}")
                        continue
                    if not isinstance(item, dict):
                        continue
                    topic = str(item.get("topic") or "").strip()
                    keywords = item.get("keywords") if isinstance(item.get("keywords"), list) else []
                    kw = ", ".join([str(x) for x in keywords[:6] if x is not None])
                    if topic and kw:
                        parts.append(f"- {topic} (keywords: {kw})")
                    elif topic:
                        parts.append(f"- {topic}")
                parts.append("")

            blender_docs = memory_context.get("blender_docs")
            if isinstance(blender_docs, str) and blender_docs.strip():
                parts.append(blender_docs.strip())
                parts.append("")

        parts.extend(
            [
                "## Description",
                description,
                "",
            ]
        )

        # Acceptance criteria
        criteria = issue.get("acceptance_criteria", [])
        if criteria:
            parts.append("## Acceptance Criteria")
            for criterion in criteria:
                parts.append(f"- {criterion}")
            parts.append("")

        # Forbidden paths
        forbidden = issue.get("forbidden_paths", [])
        if forbidden:
            parts.append("## ⚠️ Forbidden Paths (DO NOT MODIFY)")
            for path in forbidden:
                parts.append(f"- {path}")
            parts.append("")

        # Context files
        context = issue.get("context_files", [])
        if context:
            parts.append("## Relevant Files")
            for path in context:
                parts.append(f"- {path}")
            parts.append("")

        # Quality gates
        gates = manifest.get("quality_gates", {})
        if gates:
            parts.append("## Quality Gates (must all pass)")
            for name, gate in gates.items():
                if isinstance(gate, str):
                    parts.append(f"- {name}: `{gate}`")
                    continue
                if isinstance(gate, dict):
                    gate_type = gate.get("type")
                    gate_config_id = gate.get("gate_config_id")
                    gate_cmd = gate.get("command")
                    details: list[str] = []
                    if gate_type:
                        details.append(f"type={gate_type}")
                    if gate_config_id:
                        details.append(f"config={gate_config_id}")
                    if gate_cmd:
                        details.append(f"cmd={gate_cmd}")
                    rendered = " ".join(details) if details else str(gate)
                    parts.append(f"- {name}: {rendered}")
                    continue
                parts.append(f"- {name}: {gate!r}")
            parts.append("")

        parts.extend(
            [
                "## Completion Checklist",
                "- [ ] Acceptance criteria satisfied",
                "- [ ] Forbidden paths respected",
                "- [ ] Quality gates run (or commands provided)",
                "- [ ] Clear summary + next steps",
                "",
            ]
        )

        # Optional: compact strategy telemetry (CoT Encyclopedia-style rubric, no verbose CoT).
        strategy_cfg = manifest.get("strategy")
        if (
            isinstance(strategy_cfg, dict)
            and strategy_cfg.get("enabled") is True
            and strategy_cfg.get("self_report", True)
        ):
            prompt_style = str(strategy_cfg.get("prompt_style") or "compact").strip().lower()
            try:
                from hellcat.eval.strategy.profiler import (
                    get_strategy_prompt_section,
                    get_strategy_prompt_section_compact,
                )

                parts.append(
                    get_strategy_prompt_section()
                    if prompt_style == "full"
                    else get_strategy_prompt_section_compact()
                )
                parts.append("")
            except Exception:
                # Strategy telemetry is best-effort; never block prompt construction.
                pass

        prompt_body = "\n".join(parts)

        toolchain_config = manifest.get("toolchain_config") or {}
        genome_id = None
        if isinstance(toolchain_config, dict):
            genome_id = toolchain_config.get("prompt_genome_id")
        if genome_id is None:
            genome_id = manifest.get("prompt_genome_id")

        if isinstance(genome_id, str) and genome_id.strip() and isinstance(workcell_path, Path):
            try:
                from hellcat.infra.prompts.runtime import (
                    detect_domain,
                    load_prompt_genome,
                    render_prompt_genome_preamble,
                )

                job_type = str(manifest.get("job_type") or "code")
                domain = detect_domain(job_type)
                toolchain = str(manifest.get("toolchain") or "").strip() or "unknown"
                prompts_root = workcell_path / "prompts"
                genome = load_prompt_genome(
                    prompts_root=prompts_root,
                    domain=domain,
                    toolchain=toolchain,
                    genome_id=genome_id.strip(),
                )
                if isinstance(genome, dict):
                    sampling = None
                    if isinstance(toolchain_config, dict):
                        sampling_raw = toolchain_config.get("sampling")
                        if isinstance(sampling_raw, dict):
                            sampling = sampling_raw
                    preamble = render_prompt_genome_preamble(
                        genome=genome,
                        genome_id=genome_id.strip(),
                        sampling=sampling,
                    )
                    return f"{preamble}\n\n{prompt_body}"
            except Exception:
                # Prompt genomes are optional; fall back to base prompt on any load/parse issue.
                pass

        return prompt_body

    def _format_policy_summary(self, manifest: dict) -> list[str]:
        policy = manifest.get("security_policy") or manifest.get("security")
        if not isinstance(policy, dict):
            return []

        lines: list[str] = []
        egress_mode = policy.get("egress_mode")
        if egress_mode:
            lines.append(f"- Egress: {egress_mode}")

        allowed_domains = policy.get("allowed_domains")
        if isinstance(allowed_domains, list) and allowed_domains:
            lines.append(f"- Allowed domains: {', '.join(allowed_domains[:5])}")

        allowed_write_roots = policy.get("allowed_write_roots")
        if isinstance(allowed_write_roots, list) and allowed_write_roots:
            lines.append(f"- Write roots: {', '.join(allowed_write_roots)}")

        forbidden_paths = policy.get("forbidden_paths")
        if isinstance(forbidden_paths, list) and forbidden_paths:
            lines.append(f"- Forbidden paths: {', '.join(forbidden_paths[:5])}")

        allow_tools = policy.get("allow_tools")
        if isinstance(allow_tools, list) and allow_tools:
            lines.append(f"- Allowed tools: {', '.join(allow_tools[:6])}")

        on_violation = policy.get("on_violation")
        if on_violation:
            lines.append(f"- On violation: {on_violation}")

        return lines

    def _run_coroutine_sync(self, coro: Any, timeout: float | None = 10.0) -> Any | None:
        """Run an async coroutine from sync context safely."""
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(coro)
        future = _aegis_executor.submit(lambda: asyncio.run(coro))
        try:
            return future.result(timeout=timeout)
        except FutureTimeoutError:
            logger.debug("Async helper timed out")
            return None

    def _resolve_run_id(self, manifest: dict) -> str:
        run_id = manifest.get("run_id")
        if isinstance(run_id, str) and run_id.strip():
            return run_id.strip()
        workcell_id = manifest.get("workcell_id")
        if isinstance(workcell_id, str) and workcell_id.strip():
            return workcell_id.strip()
        return f"run_{uuid4().hex[:12]}"

    def _resolve_run_dir(self, manifest: dict, workcell_path: Path | None, run_id: str) -> Path:
        run_dir_value = manifest.get("run_dir")
        if isinstance(run_dir_value, str) and run_dir_value.strip():
            run_dir = Path(run_dir_value).expanduser()
            run_dir.mkdir(parents=True, exist_ok=True)
            return run_dir

        repo_root = None
        cursor = workcell_path
        while cursor is not None:
            if (cursor / ".hellcat").exists():
                repo_root = cursor
                break
            if cursor.parent == cursor:
                break
            cursor = cursor.parent
        if repo_root is None:
            repo_root = workcell_path.parent.parent if workcell_path else Path.cwd()

        run_dir = repo_root / ".hellcat" / "runs" / run_id
        run_dir.mkdir(parents=True, exist_ok=True)
        return run_dir

    def _build_env(self, manifest: dict, workcell_path: Path | None) -> dict[str, str]:
        env = os.environ.copy()
        extra_env = getattr(self, "env", None)
        if isinstance(extra_env, dict):
            env.update(extra_env)

        run_id = self._resolve_run_id(manifest)
        run_dir = self._resolve_run_dir(manifest, workcell_path, run_id)
        env.setdefault("HELLCAT_RUN_ID", run_id)
        env.setdefault("HELLCAT_RUN_DIR", str(run_dir))
        return env

    def _extract_policy_snapshot(self, manifest: dict) -> dict[str, Any] | None:
        policy = manifest.get("security_policy") or manifest.get("security")
        return policy if isinstance(policy, dict) else None

    def _write_security_policy_snapshot(self, run_dir: Path, policy: dict[str, Any]) -> None:
        path = run_dir / "security_policy.json"
        try:
            path.write_text(
                json.dumps(policy, indent=2, sort_keys=True, ensure_ascii=True)
            )
        except Exception:
            logger.debug("Failed to write security policy snapshot", exc_info=True)

    def _write_ledger_root_snapshot(self, run_dir: Path, payload: dict[str, Any]) -> None:
        path = run_dir / "ledger_root.json"
        try:
            path.write_text(
                json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True)
            )
        except Exception:
            logger.debug("Failed to write ledger root snapshot", exc_info=True)

    def _hash_file(self, path: Path) -> str | None:
        if not path.exists():
            return None
        hasher = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(8192), b""):
                hasher.update(chunk)
        return "0x" + hasher.hexdigest()

    def _resolve_telemetry_path(self, run_dir: Path, workcell_path: Path | None) -> Path | None:
        candidates = [run_dir / "telemetry.jsonl"]
        if workcell_path:
            candidates.append(workcell_path / "telemetry.jsonl")
        for candidate in candidates:
            if candidate.exists():
                return candidate
        return None

    async def _start_aegis_run(
        self,
        manifest: dict,
        workcell_path: Path | None,
    ) -> AegisRunState:
        run_id = self._resolve_run_id(manifest)
        run_dir = self._resolve_run_dir(manifest, workcell_path, run_id)
        policy = self._extract_policy_snapshot(manifest)
        if policy:
            self._write_security_policy_snapshot(run_dir, policy)

        client = _get_aegis_client()
        handle = None
        if client and client.is_daemon_available():
            try:
                from hellcat.trust.aegis.client import ExecutionMode
                from hellcat.trust.aegis.client import SecurityPolicy as AegisPolicy

                policy_obj = AegisPolicy.from_dict(policy) if policy else None
                try:
                    handle = await client.create_run(
                        run_id=run_id,
                        policy=policy_obj,
                        mode=ExecutionMode.EXTERNAL,
                        workdir=str(workcell_path or run_dir),
                    )
                except Exception:
                    await client.start_run(run_id)
                    if policy_obj:
                        await client.set_run_policy(run_id, policy_obj)
            except Exception:
                logger.debug("Failed to initialize Aegis run", exc_info=True)
                client = None
        else:
            client = None

        return AegisRunState(
            run_id=run_id,
            run_dir=run_dir,
            workcell_path=workcell_path,
            client=client,
            handle=handle,
        )

    def _start_aegis_run_sync(
        self,
        manifest: dict,
        workcell_path: Path | None,
    ) -> AegisRunState:
        result = self._run_coroutine_sync(self._start_aegis_run(manifest, workcell_path))
        if isinstance(result, AegisRunState):
            return result
        run_id = self._resolve_run_id(manifest)
        run_dir = self._resolve_run_dir(manifest, workcell_path, run_id)
        policy = self._extract_policy_snapshot(manifest)
        if policy:
            self._write_security_policy_snapshot(run_dir, policy)
        return AegisRunState(
            run_id=run_id,
            run_dir=run_dir,
            workcell_path=workcell_path,
            client=None,
            handle=None,
        )

    async def _finalize_aegis_run(
        self,
        state: AegisRunState | None,
        status: str | None,
    ) -> dict[str, Any]:
        if not state:
            return {}
        metadata: dict[str, Any] = {}
        if state.client and state.client.is_daemon_available():
            try:
                ledger_root = await state.client.complete_run(state.run_id, status or "completed")
                self._write_ledger_root_snapshot(
                    state.run_dir,
                    {
                        "ledger_root": ledger_root.root_hash,
                        "anchored_events": ledger_root.event_count,
                        "violation_count": ledger_root.violation_count,
                        "source": "aegis",
                    },
                )
                metadata = {
                    "aegis_ledger_root": ledger_root.root_hash,
                    "aegis_violation_count": ledger_root.violation_count,
                }
            except Exception:
                logger.debug("Failed to complete Aegis run", exc_info=True)
            finally:
                with contextlib.suppress(Exception):
                    await state.client.close_run(state.run_id)

        ledger_root_path = state.run_dir / "ledger_root.json"
        if not ledger_root_path.exists():
            telemetry_path = self._resolve_telemetry_path(state.run_dir, state.workcell_path)
            if telemetry_path:
                telemetry_hash = self._hash_file(telemetry_path)
                if telemetry_hash:
                    self._write_ledger_root_snapshot(
                        state.run_dir,
                        {
                            "ledger_root": telemetry_hash,
                            "anchored_events": 0,
                            "violation_count": 0,
                            "source": "telemetry_hash",
                        },
                    )

        return metadata

    def _finalize_aegis_run_sync(
        self,
        state: AegisRunState | None,
        status: str | None,
    ) -> dict[str, Any]:
        result = self._run_coroutine_sync(self._finalize_aegis_run(state, status))
        return result if isinstance(result, dict) else {}

    def _refresh_proof_metadata(
        self,
        proof: PatchProof,
        manifest: dict,
        workcell_path: Path | None,
        extra: dict[str, Any] | None = None,
    ) -> None:
        metadata = dict(proof.metadata or {})
        if extra:
            metadata.update(extra)
        run_id = self._resolve_run_id(manifest)
        run_dir = self._resolve_run_dir(manifest, workcell_path, run_id)
        metadata["run_id"] = run_id
        metadata["run_dir"] = str(run_dir)
        proof.metadata = self._augment_metadata(metadata, manifest, workcell_path)

    def _augment_metadata(
        self,
        metadata: dict[str, Any],
        manifest: dict,
        workcell_path: Path | None,
    ) -> dict[str, Any]:
        run_id = self._resolve_run_id(manifest)
        run_dir = self._resolve_run_dir(manifest, workcell_path, run_id)
        metadata.setdefault("run_id", run_id)
        metadata.setdefault("run_dir", str(run_dir))

        policy = manifest.get("security_policy") or manifest.get("security")
        if isinstance(policy, dict):
            metadata.setdefault("security_policy", policy)

        ledger_root_path = run_dir / "ledger_root.json"
        if ledger_root_path.exists():
            try:
                payload = json.loads(ledger_root_path.read_text())
                ledger_root = payload.get("ledger_root")
                if ledger_root:
                    metadata.setdefault("ledger_root", ledger_root)
                source = payload.get("source")
                if source:
                    metadata.setdefault("ledger_root_source", source)
                anchored = payload.get("anchored_events")
                if anchored is not None:
                    metadata.setdefault("ledger_root_event_count", anchored)
                violations = payload.get("violation_count")
                if violations is not None:
                    metadata.setdefault("ledger_root_violation_count", violations)
            except Exception:
                pass

        return metadata

    def _get_patch_info(self, workcell_path: Path, manifest: dict) -> dict:
        """Get git patch information from a workcell."""
        # Auto-commit any uncommitted changes left by the CLI tool
        # so that diff stats reflect the actual work done
        self._auto_commit_workcell(workcell_path, manifest)

        base_result = subprocess.run(
            ["git", "merge-base", "main", "HEAD"],
            cwd=workcell_path,
            capture_output=True,
            text=True,
        )
        base_commit = base_result.stdout.strip() if base_result.returncode == 0 else ""

        head_result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=workcell_path,
            capture_output=True,
            text=True,
        )
        head_commit = head_result.stdout.strip() if head_result.returncode == 0 else ""

        stat_result = subprocess.run(
            ["git", "diff", "--stat", "main...HEAD"],
            cwd=workcell_path,
            capture_output=True,
            text=True,
        )

        files_changed, insertions, deletions = self._parse_diff_stats(stat_result.stdout)

        files_result = subprocess.run(
            ["git", "diff", "--name-only", "main...HEAD"],
            cwd=workcell_path,
            capture_output=True,
            text=True,
        )
        files_modified = (
            [f for f in files_result.stdout.strip().split("\n") if f]
            if files_result.returncode == 0 and files_result.stdout.strip()
            else []
        )

        forbidden = manifest.get("issue", {}).get("forbidden_paths", [])
        violations = self._check_forbidden_paths(files_modified, forbidden)

        return {
            "branch": manifest.get("branch_name", ""),
            "base_commit": base_commit,
            "head_commit": head_commit,
            "diff_stats": {
                "files_changed": files_changed,
                "insertions": insertions,
                "deletions": deletions,
            },
            "files_modified": files_modified,
            "forbidden_path_violations": violations,
        }

    def _auto_commit_workcell(self, workcell_path: Path, manifest: dict) -> None:
        """Auto-commit any uncommitted changes in the workcell.

        CLI tools (codex, claude --print) may edit files without committing.
        We need committed changes for git diff main...HEAD to work.
        """
        # Check for uncommitted changes (staged or unstaged)
        status = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=workcell_path,
            capture_output=True,
            text=True,
        )
        if status.returncode != 0 or not status.stdout.strip():
            return  # Clean or git error

        # Filter out infrastructure files that the kernel deletes during setup
        infra_prefixes = (".hellcat/", ".hellcat/", ".mise.toml", ".workcell", "telemetry.jsonl")
        has_real_changes = False
        for line in status.stdout.strip().split("\n"):
            # git status --porcelain: first 2 chars are status, then space, then path
            path = line[3:].strip()
            if not any(path.startswith(p) for p in infra_prefixes):
                has_real_changes = True
                break

        if not has_real_changes:
            return

        issue_id = manifest.get("issue", {}).get("id", "unknown")
        subprocess.run(
            ["git", "add", "-A"],
            cwd=workcell_path,
            capture_output=True,
            text=True,
        )
        subprocess.run(
            ["git", "commit", "-m", f"hellcat: auto-commit changes for {issue_id}",
             "--no-verify"],
            cwd=workcell_path,
            capture_output=True,
            text=True,
        )

    def _parse_diff_stats(self, stat_output: str) -> tuple[int, int, int]:
        """Parse git diff --stat output."""
        if not stat_output:
            return 0, 0, 0

        lines = stat_output.strip().split("\n")
        if not lines:
            return 0, 0, 0

        summary = lines[-1]
        files_match = re.search(r"(\d+) files? changed", summary)
        ins_match = re.search(r"(\d+) insertions?", summary)
        del_match = re.search(r"(\d+) deletions?", summary)

        return (
            int(files_match.group(1)) if files_match else 0,
            int(ins_match.group(1)) if ins_match else 0,
            int(del_match.group(1)) if del_match else 0,
        )

    def _check_forbidden_paths(self, files_modified: list[str], forbidden: list[str]) -> list[str]:
        """Check for forbidden path violations."""
        violations = []
        for file in files_modified:
            for pattern in forbidden:
                if pattern.endswith("/"):
                    if file.startswith(pattern):
                        violations.append(file)
                elif pattern.endswith("*"):
                    if file.startswith(pattern[:-1]):
                        violations.append(file)
                else:
                    if file == pattern or file.startswith(pattern + "/"):
                        violations.append(file)
        return violations

    def _classify_risk(self, patch_info: dict, manifest: dict | None = None) -> str:
        """Classify risk based on changes."""
        if patch_info.get("forbidden_path_violations"):
            return "critical"

        files = patch_info.get("files_modified", [])
        high_risk_patterns = [
            "auth",
            "security",
            "password",
            "secret",
            "key",
            "migration",
            "schema",
            "database",
            "payment",
            "billing",
            "stripe",
        ]

        for file in files:
            file_lower = file.lower()
            if any(pattern in file_lower for pattern in high_risk_patterns):
                return "high"

        stats = patch_info.get("diff_stats", {})
        total_changes = stats.get("insertions", 0) + stats.get("deletions", 0)

        if total_changes > 500:
            return "high"
        elif total_changes > 100:
            return "medium"

        return "low"

    def _create_timeout_proof(self, manifest: dict, started_at: datetime) -> PatchProof:
        """Create a proof for timeout case."""
        completed_at = datetime.now(UTC)
        metadata = {
            "toolchain": self.name,
            "started_at": started_at.isoformat().replace("+00:00", "Z"),
            "completed_at": completed_at.isoformat().replace("+00:00", "Z"),
            "error": "Execution timed out",
        }
        metadata = self._augment_metadata(metadata, manifest, None)

        return PatchProof(
            schema_version="1.0.0",
            workcell_id=manifest.get("workcell_id", "unknown"),
            issue_id=manifest.get("issue", {}).get("id", "unknown"),
            status="timeout",
            patch={
                "branch": manifest.get("branch_name", ""),
                "base_commit": "",
                "head_commit": "",
                "diff_stats": {"files_changed": 0, "insertions": 0, "deletions": 0},
                "files_modified": [],
                "forbidden_path_violations": [],
            },
            verification={
                "gates": {},
                "all_passed": False,
                "blocking_failures": ["timeout"],
            },
            metadata=metadata,
            confidence=0,
            risk_classification="high",
        )

    def _create_error_proof(self, manifest: dict, started_at: datetime, error: str) -> PatchProof:
        """Create a proof for error case."""
        completed_at = datetime.now(UTC)
        metadata = {
            "toolchain": self.name,
            "started_at": started_at.isoformat().replace("+00:00", "Z"),
            "completed_at": completed_at.isoformat().replace("+00:00", "Z"),
            "error": error,
        }
        metadata = self._augment_metadata(metadata, manifest, None)

        return PatchProof(
            schema_version="1.0.0",
            workcell_id=manifest.get("workcell_id", "unknown"),
            issue_id=manifest.get("issue", {}).get("id", "unknown"),
            status="error",
            patch={
                "branch": manifest.get("branch_name", ""),
                "base_commit": "",
                "head_commit": "",
                "diff_stats": {"files_changed": 0, "insertions": 0, "deletions": 0},
                "files_modified": [],
                "forbidden_path_violations": [],
            },
            verification={
                "gates": {},
                "all_passed": False,
                "blocking_failures": ["error"],
            },
            metadata=metadata,
            confidence=0,
            risk_classification="high",
        )
