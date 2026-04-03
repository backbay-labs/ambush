"""
Memory Integration Layer

Bridges MemoryHooks with the kernel lifecycle:
- Instantiates memory hooks per workcell
- Parses telemetry for tool_use observations
- Extracts gate results from verification
- Manages session lifecycle
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

import structlog

from cyntra.core.adapters.telemetry import read_telemetry_events
from cyntra.cognition.memory import MemoryHooks

if TYPE_CHECKING:
    from cyntra.core.adapters.base import PatchProof
    from cyntra.core.state.models import Issue

logger = structlog.get_logger()

# Default memory database path
DEFAULT_MEMORY_DB_PATH = Path(".cyntra/memory/cyntra-mem.db")


class KernelMemoryBridge:
    """
    Integrates memory hooks with kernel lifecycle.

    Usage:
        bridge = KernelMemoryBridge(db_path=".cyntra/memory/cyntra-mem.db")

        # Before dispatch
        context = bridge.on_workcell_start(workcell_id, issue, manifest)
        manifest["memory_context"] = context

        # After dispatch
        bridge.on_dispatch_complete(workcell_id, workcell_path, proof)

        # After verification
        for gate, result in verification["gates"].items():
            bridge.on_gate_result(gate, result["passed"], ...)

        # At end
        bridge.on_workcell_end(workcell_id, status)
    """

    def __init__(
        self,
        db_path: Path | str | None = None,
        *,
        maturity_path: Path | str | None = None,
    ):
        self.db_path = Path(db_path) if db_path else DEFAULT_MEMORY_DB_PATH
        self.hooks = MemoryHooks(db_path=self.db_path)
        self._active_sessions: dict[str, str] = {}  # workcell_id -> session_id
        self._active_workcell_paths: dict[str, Path] = {}  # workcell_id -> workcell_path
        self._maturity_path = Path(maturity_path) if maturity_path else None

    def on_workcell_start(
        self,
        workcell_id: str,
        issue: Issue,
        manifest: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Called before dispatch. Creates memory session and returns context.

        Args:
            workcell_id: Unique workcell identifier
            issue: Issue being worked on
            manifest: Task manifest

        Returns:
            Memory context dict for injection into agent prompt
        """
        domain = self._infer_domain(manifest)
        job_type = manifest.get("job_type", "code")
        toolchain = manifest.get("toolchain")

        context = self.hooks.workcell_start(
            workcell_id=workcell_id,
            issue_id=str(issue.id),
            domain=domain,
            job_type=job_type,
            toolchain=toolchain,
        )

        # Membox (Phase 1 scaffolding): attach recent topic-continuous memory
        try:
            from cyntra.cognition.memory.membox.membox_store import MemboxStore, MemboxStoreConfig
            from cyntra.cognition.memory.membox.retrieval import (
                MemboxRetrieval,
                RetrievalConfig,
                build_membox_query_text,
            )

            store = MemboxStore(config=MemboxStoreConfig(db_path=self.db_path))
            try:
                query = build_membox_query_text(issue=issue, manifest=manifest)
                retriever = MemboxRetrieval(
                    store,
                    config=RetrievalConfig(
                        max_results=6,
                        max_candidates=250,
                        min_score=0.1,
                        max_events_per_item=3,
                        max_tokens=200,
                        primary_weight=0.7,
                        secondary_weight=0.2,
                        coverage_weight=0.1,
                    ),
                )
                membox_context = retriever.build_context(query=query)
                stats = membox_context.get("stats") if isinstance(membox_context, dict) else None
                if isinstance(stats, dict):
                    stats["db_totals"] = {
                        "memboxes": store.count_memboxes(),
                        "traces": store.count_traces(),
                    }
                context["membox"] = membox_context
            finally:
                store.close()
        except Exception:
            # Membox is optional; never block workcell dispatch on memory add-ons.
            pass

        # Blender docs (local index): for fab domains, attach a small docs excerpt block
        # to reduce "research" overhead in the workcell.
        try:
            if domain.startswith("fab"):
                docs_db_path = self.db_path.parent.parent / "indexes" / "blender_docs.db"
                if docs_db_path.exists():
                    from cyntra.infra.indexing.blender_docs_index import (
                        BlenderDocsIndex,
                        BlenderDocsIndexConfig,
                    )
                    from cyntra.cognition.memory.membox.retrieval import build_membox_query_text

                    docs_idx = BlenderDocsIndex(config=BlenderDocsIndexConfig(db_path=docs_db_path))
                    try:
                        query = build_membox_query_text(issue=issue, manifest=manifest)
                        hits = docs_idx.search(query, top_k=3, use_embeddings=False)
                        md = docs_idx.format_hits_markdown(hits, max_chars=1500)
                        if md:
                            context["blender_docs"] = md
                    finally:
                        docs_idx.close()
        except Exception:
            # Optional: never block workcell dispatch on docs retrieval.
            pass

        # Track session
        if self.hooks._session_id:
            self._active_sessions[workcell_id] = self.hooks._session_id

        logger.info(
            "Memory session started",
            workcell_id=workcell_id,
            issue_id=issue.id,
            domain=domain,
            patterns_available=len(context.get("patterns", [])),
            warnings_available=len(context.get("warnings", [])),
        )

        return context

    def on_dispatch_complete(
        self,
        workcell_id: str,
        workcell_path: Path,
        proof: PatchProof | None,
    ) -> None:
        """
        Called after adapter execution. Parses telemetry for observations.

        Args:
            workcell_id: Workcell identifier
            workcell_path: Path to workcell directory
            proof: Execution proof (may be None on failure)
        """
        if workcell_id not in self._active_sessions:
            logger.warning(
                "on_dispatch_complete called without active session",
                workcell_id=workcell_id,
            )
            return

        self._active_workcell_paths[workcell_id] = workcell_path

        # Parse telemetry.jsonl for tool observations
        telemetry_path = workcell_path / "telemetry.jsonl"
        if telemetry_path.exists():
            self._ingest_telemetry(telemetry_path)

        logger.debug(
            "Dispatch telemetry processed",
            workcell_id=workcell_id,
            telemetry_exists=telemetry_path.exists(),
        )

    def on_gate_result(
        self,
        gate_name: str,
        passed: bool,
        score: float | None = None,
        fail_codes: list[str] | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        """
        Called for each gate result from verifier.

        Args:
            gate_name: Name of the quality gate
            passed: Whether gate passed
            score: Optional numeric score
            fail_codes: List of failure codes
            details: Additional gate details
        """
        self.hooks.gate_result(
            gate_name=gate_name,
            passed=passed,
            score=score,
            fail_codes=fail_codes,
            details=details,
        )

    def on_workcell_end(
        self,
        workcell_id: str,
        status: str,
    ) -> dict[str, Any]:
        """
        Called at end of workcell lifecycle.

        Args:
            workcell_id: Workcell identifier
            status: Final status ("success", "failed", etc.)

        Returns:
            Session summary with patterns and observations
        """
        if workcell_id not in self._active_sessions:
            logger.warning(
                "on_workcell_end called without active session",
                workcell_id=workcell_id,
            )
            self._active_workcell_paths.pop(workcell_id, None)
            return {"success": False, "error": "No active session"}

        # Ingest any late-bound artifacts before the memory session closes
        # (e.g. post-execution hooks, PSN traces).
        workcell_path = self._active_workcell_paths.get(workcell_id)
        if workcell_path is not None:
            self._ingest_invocation_traces(workcell_id=workcell_id, workcell_path=workcell_path)

        result = self.hooks.workcell_end(status=status)
        workcell_path = self._active_workcell_paths.pop(workcell_id, None)
        self._active_sessions.pop(workcell_id, None)

        # Membox (Phase 1): ingest workcell telemetry + summary to reduce swarm amnesia.
        try:
            from cyntra.cognition.memory.membox.integration import MemboxKernelBridge
            from cyntra.cognition.memory.membox.membox_store import MemboxStore, MemboxStoreConfig
            from cyntra.cognition.memory.membox.models import MemboxMessage

            source = f"workcell:{workcell_id}"
            messages: list[MemboxMessage] = []

            summary = result.get("summary") if isinstance(result, dict) else None
            if isinstance(summary, dict):
                content = summary.get("content")
                if isinstance(content, str) and content.strip():
                    messages.append(
                        MemboxMessage(
                            role="workcell_summary",
                            content=f"[{status}] {content}",
                            source=source,
                        )
                    )

                for decision in summary.get("key_decisions") or []:
                    if isinstance(decision, str) and decision.strip():
                        messages.append(MemboxMessage(role="decision", content=decision, source=source))
                for pattern in summary.get("patterns") or []:
                    if isinstance(pattern, str) and pattern.strip():
                        messages.append(MemboxMessage(role="pattern", content=pattern, source=source))
                for anti in summary.get("anti_patterns") or []:
                    if isinstance(anti, str) and anti.strip():
                        messages.append(MemboxMessage(role="anti_pattern", content=anti, source=source))

            session_id = result.get("session_id") if isinstance(result, dict) else None
            if isinstance(session_id, str) and session_id:
                try:
                    obs_rows = self.hooks.db.get_observations(session_id=session_id, limit=200)
                except Exception:
                    obs_rows = []
                for row in reversed(obs_rows):
                    obs_type = str(row.get("type") or "")
                    content = str(row.get("content") or "").strip()
                    if not content:
                        continue

                    tool_name = str(row.get("tool_name") or "")
                    tool_args_raw = row.get("tool_args")
                    file_refs_raw = row.get("file_refs")
                    try:
                        tool_args = json.loads(tool_args_raw) if isinstance(tool_args_raw, str) else {}
                    except Exception:
                        tool_args = {}
                    try:
                        file_refs = json.loads(file_refs_raw) if isinstance(file_refs_raw, str) else []
                    except Exception:
                        file_refs = []

                    if obs_type == "gate_result":
                        messages.append(MemboxMessage(role="gate_result", content=content, source=source))
                        continue

                    if obs_type == "decision":
                        messages.append(MemboxMessage(role="decision", content=content, source=source))
                        continue

                    if obs_type == "change" and tool_name in {"Write", "Edit", "Bash"}:
                        suffix = ""
                        if file_refs:
                            suffix = f" (files: {', '.join([str(x) for x in file_refs[:4]])})"
                        elif tool_args:
                            suffix = f" (args: {json.dumps(tool_args)[:200]})"
                        messages.append(
                            MemboxMessage(
                                role="tool_use",
                                content=f"{content}{suffix}",
                                source=source,
                            )
                        )

            if workcell_path is not None:
                logs_dir = workcell_path / "logs"
                if logs_dir.exists():
                    for log_name in (
                        "codex-stderr.log",
                        "claude-stderr.log",
                        "codex-stdout.log",
                        "claude-stdout.log",
                    ):
                        log_path = logs_dir / log_name
                        if not log_path.exists():
                            continue
                        try:
                            raw = log_path.read_text(errors="ignore")
                        except Exception:
                            continue
                        tail = raw[-4000:] if len(raw) > 4000 else raw
                        tail = tail.strip()
                        if tail:
                            messages.append(
                                MemboxMessage(
                                    role="workcell_log_tail",
                                    content=f"{log_name} tail:\n{tail}",
                                    source=source,
                                )
                            )

            if messages:
                store = MemboxStore(config=MemboxStoreConfig(db_path=self.db_path))
                try:
                    bridge = MemboxKernelBridge(store=store)
                    bridge.ingest_messages_sync(messages, timeout_s=30.0)
                finally:
                    store.close()
        except Exception:
            # Best-effort; never block kernel lifecycle on Membox ingestion.
            pass

        logger.info(
            "Memory session ended",
            workcell_id=workcell_id,
            status=status,
            observation_count=result.get("observation_count", 0),
        )

        return result

    def _ingest_invocation_traces(self, *, workcell_id: str, workcell_path: Path) -> None:
        """
        Ingest PSN InvocationTrace artifacts into the MemoryDB (best-effort).

        The canonical file is `logs/psn/invocation_traces.jsonl` under the workcell.
        """
        session_id = self._active_sessions.get(workcell_id)
        if not session_id:
            return

        candidates = [
            workcell_path / "logs" / "psn" / "invocation_traces.jsonl",
            workcell_path / "invocation_traces.jsonl",
            workcell_path / "logs" / "invocation_traces.jsonl",
        ]

        trace_path = next((p for p in candidates if p.exists()), None)
        if trace_path is None:
            return

        try:
            from cyntra.domain.skills.trace import ingest_invocation_traces_jsonl
        except Exception as exc:
            logger.debug(
                "Failed to import InvocationTrace helpers; skipping PSN ingestion",
                error=str(exc),
            )
            return

        try:
            counts = ingest_invocation_traces_jsonl(
                trace_path,
                db=self.hooks.db,
                session_id=session_id,
            )
            ingested = int(counts.get("ingested", 0))
            skipped = int(counts.get("skipped", 0))
        except OSError as exc:
            logger.debug(
                "Failed to read invocation trace file",
                path=str(trace_path),
                error=str(exc),
            )
            return

        if ingested or skipped:
            logger.debug(
                "PSN invocation traces ingested",
                workcell_id=workcell_id,
                ingested=ingested,
                skipped=skipped,
                path=str(trace_path),
            )

    def _ingest_telemetry(self, telemetry_path: Path) -> None:
        """Parse telemetry.jsonl and create tool_use observations."""
        events = read_telemetry_events(telemetry_path)

        for event in events:
            event_type = event.get("type")

            try:
                if event_type == "file_write":
                    self.hooks.tool_use(
                        tool_name="Write",
                        tool_args={"path": event.get("path")},
                        result="File written",
                        file_refs=[event.get("path")] if event.get("path") else None,
                    )

                elif event_type == "file_read":
                    # Skip reads - too noisy, low value
                    pass

                elif event_type == "bash_command":
                    self.hooks.tool_use(
                        tool_name="Bash",
                        tool_args={"command": event.get("command", "")[:200]},
                        result=(event.get("output", "")[:500] if "output" in event else ""),
                    )

                elif event_type == "tool_call":
                    tool = event.get("tool", "unknown")
                    args = event.get("args", {})

                    # Extract file refs from common args
                    file_refs = []
                    if "path" in args:
                        file_refs.append(args["path"])
                    elif "file_path" in args:
                        file_refs.append(args["file_path"])

                    self.hooks.tool_use(
                        tool_name=tool,
                        tool_args=args,
                        result="",  # Result comes in tool_result event
                        file_refs=file_refs if file_refs else None,
                    )

                elif event_type == "tool_result":
                    # Tool results are paired with tool_call, skip separate handling
                    pass

                elif event_type == "error":
                    # Record errors as discoveries
                    error_msg = event.get("error", "Unknown error")
                    self.hooks.add_discovery(
                        discovery=f"Error encountered: {error_msg[:200]}",
                        context=event.get("context"),
                    )

            except Exception as e:
                logger.warning(
                    "Failed to process telemetry event",
                    event_type=event_type,
                    error=str(e),
                )

    def _infer_domain(self, manifest: dict[str, Any]) -> str:
        """Infer domain from manifest job_type."""
        job_type = manifest.get("job_type", "code")

        if "fab" in job_type.lower():
            if "asset" in job_type.lower():
                return "fab_asset"
            elif "world" in job_type.lower():
                return "fab_world"
            return "fab_asset"  # default fab domain

        return "code"

    def get_context_for_prompt_injection(
        self,
        domain: str | None = None,
        max_patterns: int = 5,
        max_warnings: int = 5,
    ) -> str:
        """
        Generate markdown context block for prompt injection.

        Args:
            domain: Optional domain filter
            max_patterns: Max successful patterns to include
            max_warnings: Max warnings/anti-patterns to include

        Returns:
            Markdown string for injection into system prompt
        """
        context = self.hooks.db.get_context_for_injection(
            domain=domain,
            max_observations=50,
            max_tokens=2000,
        )

        lines = []

        # Extract patterns from summaries
        patterns = []
        warnings = []

        for summary in context.get("summaries", []):
            if summary.get("patterns"):
                try:
                    p = (
                        json.loads(summary["patterns"])
                        if isinstance(summary["patterns"], str)
                        else summary["patterns"]
                    )
                    patterns.extend(p[:3])
                except (json.JSONDecodeError, TypeError):
                    pass

            if summary.get("anti_patterns"):
                try:
                    ap = (
                        json.loads(summary["anti_patterns"])
                        if isinstance(summary["anti_patterns"], str)
                        else summary["anti_patterns"]
                    )
                    warnings.extend(ap[:3])
                except (json.JSONDecodeError, TypeError):
                    pass

        # Format as markdown
        if warnings:
            lines.append("### Avoid These Patterns")
            for w in warnings[:max_warnings]:
                lines.append(f"- {w}")
            lines.append("")

        if patterns:
            lines.append("### Successful Approaches")
            for p in patterns[:max_patterns]:
                lines.append(f"- {p}")
            lines.append("")

        if not lines:
            return ""

        return "## Learned Context\n\n" + "\n".join(lines)

    def get_session_id(self, workcell_id: str) -> str | None:
        """
        Get the active memory session ID for a workcell.

        Args:
            workcell_id: The workcell identifier

        Returns:
            Session ID if active, None otherwise
        """
        return self._active_sessions.get(workcell_id)

    def close(self) -> None:
        """Close database connection."""
        self.hooks.close()
