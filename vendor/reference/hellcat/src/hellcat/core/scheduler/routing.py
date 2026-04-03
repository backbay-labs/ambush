"""
Kernel Configuration - All settings for the Hellcat Kernel orchestrator.

Loaded from YAML config file with environment variable override support.
"""

from __future__ import annotations

import contextlib
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


def _deep_merge_dicts(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """
    Deterministically merge two dictionaries.

    - Dicts are merged recursively
    - Non-dicts (including lists) are replaced by `override`
    """
    result: dict[str, Any] = dict(base)
    for key, value in override.items():
        existing = result.get(key)
        if isinstance(existing, dict) and isinstance(value, dict):
            result[key] = _deep_merge_dicts(existing, value)
        else:
            result[key] = value
    return result


def _load_yaml(path: Path) -> dict[str, Any]:
    with open(path) as f:
        data = yaml.safe_load(f) or {}
    return dict(data) if isinstance(data, dict) else {}


@dataclass
class ToolchainConfig:
    """Configuration for a specific toolchain adapter."""

    name: str
    enabled: bool = True
    path: str = ""  # CLI executable (defaults to toolchain name)
    model: str | None = None  # Default model for this toolchain
    timeout_seconds: int = 1800  # 30 minutes
    max_tokens: int = 100_000
    env: dict[str, str] = field(default_factory=dict)
    config: dict[str, Any] = field(default_factory=dict)  # adapter-specific passthrough


@dataclass
class GatesConfig:
    """Configuration for quality gates."""

    test_command: str = "pytest"
    typecheck_command: str = "mypy ."
    lint_command: str = "ruff check ."
    build_command: str | None = None
    timeout_seconds: int = 300
    retry_flaky: int = 2
    parallel: bool = True  # Run gates concurrently for ~3x speedup
    total_budget_ms: int | None = None
    max_cpu_seconds: int | None = None
    max_memory_mb: int | None = None
    max_diff_lines: int | None = 2000
    max_diff_files: int | None = 100
    secret_detection: bool = True
    secret_detection_scan_diff: bool = True
    secret_detection_max_bytes: int = 200_000


@dataclass
class SpeculationConfig:
    """Configuration for speculate+vote mode."""

    enabled: bool = True
    default_parallelism: int = 2
    max_parallelism: int = 3
    vote_threshold: float = 0.7
    auto_trigger_on_critical_path: bool = True
    auto_trigger_risk_levels: list[str] = field(default_factory=lambda: ["high", "critical"])
    early_terminate: bool = True  # Stop as soon as first candidate passes verification
    # Multiplex next-steps: on gate failure, attach merged "next steps" back onto the issue.
    # 0 disables (default).
    next_step_candidates: int = 0
    next_step_max_steps: int = 12


@dataclass
class ControlConfig:
    """Closed-loop exploration control configuration."""

    enabled: bool = True
    action_low: float = 0.1
    action_high: float = 0.5
    temperature_base: float = 0.2
    temperature_min: float = 0.1
    temperature_max: float = 0.6
    temperature_step: float = 0.1
    parallelism_step: int = 1


@dataclass
class CodeReviewerHookConfig:
    """Configuration for code-reviewer hook."""

    enabled: bool = True
    model: str = "haiku"  # Fast/cheap model for reviews
    trigger_on: list[str] = field(default_factory=lambda: ["success", "partial"])
    review_depth: str = "standard"  # quick, standard, deep
    max_diff_lines: int = 500


@dataclass
class DebugSpecialistHookConfig:
    """Configuration for debug-specialist hook."""

    enabled: bool = True
    trigger_on_gate_failure: bool = True
    trigger_on_status_failed: bool = True
    max_error_context_lines: int = 100
    auto_fix_attempt: bool = False


@dataclass
class PostExecutionHooksConfig:
    """Configuration for post-execution hooks."""

    enabled: bool = True
    timeout_seconds: int = 120
    code_reviewer: CodeReviewerHookConfig = field(default_factory=CodeReviewerHookConfig)
    debug_specialist: DebugSpecialistHookConfig = field(default_factory=DebugSpecialistHookConfig)


@dataclass
class PlannerConfig:
    """Swarm planner integration configuration."""

    # Feature flag / integration mode:
    # - off: do not run model inference (baseline heuristic only)
    # - log: run inference, record predicted action, but always execute baseline behavior
    # - enforce: run inference, execute predicted action when safe
    mode: str = "off"
    bundle_dir: Path | None = None
    confidence_threshold: float = 0.2


@dataclass
class SentinelScheduleConfig:
    """Schedule configuration for a sentinel (from YAML)."""

    interval_seconds: int = 3600
    run_on_startup: bool = False
    only_during_idle: bool = True
    min_idle_seconds: int = 60
    jitter_seconds: int = 30


@dataclass
class SentinelsConfig:
    """Configuration for the sentinel system."""

    enabled: bool = True

    # Per-sentinel overrides (keys are sentinel names)
    # Each value can have: enabled, schedule, config
    bead_gardener: dict[str, Any] = field(default_factory=dict)
    doc_sync: dict[str, Any] = field(default_factory=dict)
    security: dict[str, Any] = field(default_factory=dict)
    memory_gardener: dict[str, Any] = field(default_factory=dict)
    shield_ingest: dict[str, Any] = field(default_factory=dict)
    range_raids: dict[str, Any] = field(default_factory=dict)

    # Global sentinel settings
    dry_run: bool = False  # All sentinels run in dry-run mode
    max_runtime_seconds: int = 300
    max_changes_per_run: int = 10


@dataclass
class OracleConfig:
    """Oracle safety configuration for price-based decisions."""

    enabled: bool = False
    sources: list[str] = field(default_factory=list)
    max_age_seconds: int = 600
    max_deviation_bps: int = 500
    min_price: float | None = None
    max_price: float | None = None


@dataclass
class SettlementConfig:
    """Settlement and verifier economy configuration (Solana)."""

    enabled: bool = False
    rpc_url: str | None = None
    registry_program_id: str | None = None
    staking_program_id: str | None = None
    fee_market_program_id: str | None = None
    sas_enabled: bool = False
    sas_endpoint: str | None = None
    allowlist: list[str] = field(default_factory=list)
    oracle: OracleConfig = field(default_factory=OracleConfig)
    orca: OrcaConfig = field(default_factory=lambda: OrcaConfig())
    treasury: TreasuryConfig = field(default_factory=lambda: TreasuryConfig())


@dataclass
class OrcaConfig:
    """Orca liquidity configuration."""

    enabled: bool = False
    pool_id: str | None = None
    slippage_bps: int = 50
    max_trade_usdc: float | None = None


@dataclass
class TreasuryConfig:
    """Treasury buyback/distribution configuration."""

    enabled: bool = False
    buyback_enabled: bool = True
    interval_seconds: int = 3600
    treasury_wallet: str | None = None
    source_mint: str = "USDC"
    target_mint: str = "AEGIS"


@dataclass
class E2BConfig:
    """E2B cloud sandbox provider configuration."""

    template: str = "base"
    timeout: int = 1800  # 30 minutes


@dataclass
class CCIPConfig:
    """Chainlink CCIP configuration."""

    enabled: bool = False
    router_address: str | None = None
    source_chain: str | None = None
    target_chains: list[str] = field(default_factory=list)
    anchor_interval_seconds: int = 300


@dataclass
class FederationConfig:
    """Cross-chain federation configuration."""

    enabled: bool = False
    ccip: CCIPConfig = field(default_factory=CCIPConfig)


@dataclass
class StrategyRoutingConfig:
    """Configuration for pre-run strategy directive routing."""

    enabled: bool = False

    # Only supported mode for now (matches paper's dataset-wide optimal patterns).
    mode: str = "dataset_optimal"  # dataset_optimal | off

    # Deterministic A/B routing: only apply directives to treatment bucket.
    ab_test_enabled: bool = False
    ab_test_ratio: float = 0.5  # 0.0-1.0
    ab_test_salt: str = "hellcat.strategy.ab.v1"

    # Query parameters for dataset-wide optimal patterns.
    outcome: str = "passed"
    min_confidence: float = 0.5
    per_toolchain: bool = True


@dataclass
class StrategyConfig:
    """Configuration for strategy telemetry + (optional) directive routing."""

    enabled: bool = False
    prompt_style: str = "compact"  # compact | full
    self_report: bool = True
    routing: StrategyRoutingConfig = field(default_factory=StrategyRoutingConfig)


@dataclass
class RoutingRule:
    """A single routing rule (evaluated in order)."""

    match: dict[str, Any] = field(default_factory=dict)
    use: list[str] = field(default_factory=list)
    speculate: bool = False
    parallelism: int | None = None
    execution_mode: str | None = None  # "interactive" | "print" | None (adapter decides)


@dataclass
class RoutingConfig:
    """Toolchain routing configuration."""

    rules: list[RoutingRule] = field(default_factory=list)
    fallbacks: dict[str, list[str]] = field(default_factory=dict)


@dataclass
class GpuPoolBackendConfig:
    """Backend configuration for the GPU pool."""

    backend_id: str
    enabled: bool = True
    priority: int = 0
    config: dict[str, Any] = field(default_factory=dict)


@dataclass
class GpuPoolPoolConfig:
    """Named pool configuration for GPU backends."""

    id: str
    backends: list[str] = field(default_factory=list)
    min_idle: int | None = None
    max_size: int | None = None


@dataclass
class GpuPoolConfig:
    """Top-level GPU pool configuration."""

    manager_url: str | None = None
    backends: dict[str, GpuPoolBackendConfig] = field(default_factory=dict)
    pools: list[GpuPoolPoolConfig] = field(default_factory=list)


@dataclass
class KernelConfig:
    """Main kernel configuration."""

    # Execution limits
    max_concurrent_workcells: int = 3
    max_concurrent_tokens: int = 200_000
    starvation_threshold_hours: float = 4.0

    # Workcell provider: "local" (git worktrees) or "e2b" (cloud sandboxes)
    workcell_provider: str = "local"
    e2b: E2BConfig = field(default_factory=E2BConfig)

    # Paths
    repo_root: Path = field(default_factory=Path.cwd)
    beads_path: Path = field(default_factory=lambda: Path(".hellcat"))
    workcells_dir: Path = field(default_factory=lambda: Path(".workcells"))

    kernel_dir: Path = field(default_factory=lambda: Path(".hellcat"))
    logs_dir: Path = field(default_factory=lambda: Path(".hellcat/logs"))
    archives_dir: Path = field(default_factory=lambda: Path(".hellcat/archives"))
    state_dir: Path = field(default_factory=lambda: Path(".hellcat/state"))

    config_path: Path = field(default_factory=lambda: Path(".hellcat/config.yaml"))

    # Toolchain priority order
    toolchain_priority: list[str] = field(default_factory=lambda: ["codex", "claude", "crush"])

    # Sub-configs
    toolchains: dict[str, ToolchainConfig] = field(default_factory=dict)
    gates: GatesConfig = field(default_factory=GatesConfig)
    speculation: SpeculationConfig = field(default_factory=SpeculationConfig)
    routing: RoutingConfig = field(default_factory=RoutingConfig)
    gpu_pool: GpuPoolConfig = field(default_factory=GpuPoolConfig)
    control: ControlConfig = field(default_factory=ControlConfig)
    post_execution_hooks: PostExecutionHooksConfig = field(default_factory=PostExecutionHooksConfig)
    planner: PlannerConfig = field(default_factory=PlannerConfig)
    strategy: StrategyConfig = field(default_factory=StrategyConfig)
    sentinels: SentinelsConfig = field(default_factory=SentinelsConfig)
    settlement: SettlementConfig = field(default_factory=SettlementConfig)
    federation: FederationConfig = field(default_factory=FederationConfig)
    # Raw sleeptime config dict (parsed by SleeptimeConfig.from_dict in runner).
    sleeptime: dict[str, Any] | None = None

    # Ralph config dict (parsed by RalphConfig.from_dict in runner).
    # Enables Ralph-style autonomous loop features:
    # - circuit_breaker: stagnation detection
    # - rate_limiter: API quota management
    # - session: context continuity across retries
    # - completion detection and auto-exit
    ralph: dict[str, Any] | None = None

    # Model override (from cockpit resources, affects default toolchain selection)
    model_provider: str | None = None
    model_name: str | None = None
    model_endpoint: str | None = None

    # Knowledge base source (from cockpit resources, for context injection)
    kb_source: str | None = None

    # Skill network source (from cockpit resources, for PSN)
    skills_source: str | None = None

    # Runtime overrides
    force_speculate: bool = False
    dry_run: bool = False
    watch_mode: bool = False

    def __post_init__(self) -> None:
        self._normalize_paths()

    @classmethod
    def load(cls, config_path: Path) -> KernelConfig:
        """Load configuration from YAML file.

        Also loads .hellcat/config.local.yaml if it exists, merging it on top
        of the main config. This allows local overrides (e.g., enabling
        additional toolchains) without modifying tracked files.
        """
        config_path = Path(config_path)
        if not config_path.exists():
            config = cls()
            config._apply_config_path(config_path)
            return config

        data = _load_yaml(config_path)

        merged = cls._load_with_includes(data, config_path, seen=set())

        # Load local config overlay if it exists (gitignored, for local overrides)
        local_config_path = config_path.parent / "config.local.yaml"
        if local_config_path.exists():
            local_data = _load_yaml(local_config_path)
            merged = _deep_merge_dicts(merged, local_data)

        return cls.from_dict(merged, config_path)

    @classmethod
    def from_dict(cls, data: dict[str, Any], config_path: Path | None = None) -> KernelConfig:
        """Create config from dictionary."""
        data = dict(data or {})

        # Support both "flat" config keys and the documented nested "version: 1.0" format.
        scheduling_data = data.get("scheduling") or {}
        toolchains_data = data.get("toolchains") or {}
        routing_data = data.get("routing") or {}
        # Support both:
        # - `gates:` (canonical)
        # - `quality_gates:` (back-compat; used in repo-level .hellcat/config.yaml docs)
        gates_data = data.get("gates") or data.get("quality_gates") or {}
        speculation_data = data.get("speculation") or {}
        control_data = data.get("control") or {}
        planner_data = data.get("planner") or {}
        strategy_data = data.get("strategy") or {}
        sentinels_data = data.get("sentinels") or {}
        gpu_pool_data = data.get("gpu_pool") or {}
        sleeptime_data = data.get("sleeptime")
        ralph_data = data.get("ralph")

        # Back-compat: allow flat keys at top-level (tests + older configs).
        max_concurrent_workcells = scheduling_data.get(
            "max_concurrent_workcells", data.get("max_concurrent_workcells", 3)
        )
        max_concurrent_tokens = scheduling_data.get(
            "max_concurrent_tokens", data.get("max_concurrent_tokens", 200_000)
        )
        starvation_threshold_hours = scheduling_data.get(
            "starvation_threshold_hours", data.get("starvation_threshold_hours", 4.0)
        )

        # Build toolchain configs
        toolchains = {}
        for name, tc_data in toolchains_data.items():
            if isinstance(tc_data, dict):
                import shlex

                # Support both:
                # - {model: "...", timeout_seconds: ...}
                # - {path: "...", default_model: "...", timeout_minutes: ... , config: {...}}
                timeout_seconds = int(tc_data.get("timeout_seconds", 0) or 0)
                if not timeout_seconds and tc_data.get("timeout_minutes"):
                    timeout_seconds = int(tc_data["timeout_minutes"]) * 60

                raw_config = tc_data.get("config")
                adapter_config: dict[str, Any] = (
                    dict(raw_config) if isinstance(raw_config, dict) else {}
                )

                # Back-compat: allow "command" to include an executable + flags.
                path_value = tc_data.get("path")
                command_value = tc_data.get("command")
                parsed_args: list[str] = []
                if not path_value and isinstance(command_value, str) and command_value.strip():
                    try:
                        parsed_args = shlex.split(command_value)
                    except ValueError:
                        parsed_args = command_value.split()
                    if parsed_args:
                        path_value = parsed_args[0]

                # Promote a few common adapter keys when provided at the top-level.
                for key in (
                    "approval_mode",
                    "skip_permissions",
                    "provider",
                    "auto_approve",
                    "agent",
                    "interactive",
                    "teams",
                    "effort_level_map",
                    "default_effort_level",
                    "default_reasoning_effort",
                    "reasoning_effort_map",
                ):
                    if key in tc_data and key not in adapter_config:
                        adapter_config[key] = tc_data[key]

                # Best-effort parsing of common flags from legacy "command".
                if parsed_args:
                    if "--model" in parsed_args and "model" not in adapter_config:
                        with contextlib.suppress(Exception):
                            adapter_config["model"] = parsed_args[parsed_args.index("--model") + 1]
                    if "--approval-mode" in parsed_args and "approval_mode" not in adapter_config:
                        with contextlib.suppress(Exception):
                            adapter_config["approval_mode"] = parsed_args[
                                parsed_args.index("--approval-mode") + 1
                            ]
                    if (
                        "--dangerously-skip-permissions" in parsed_args
                        and "skip_permissions" not in adapter_config
                    ):
                        adapter_config["skip_permissions"] = True
                    if "-y" in parsed_args and "auto_approve" not in adapter_config:
                        adapter_config["auto_approve"] = True

                toolchains[name] = ToolchainConfig(
                    name=name,
                    enabled=bool(tc_data.get("enabled", True)),
                    path=str(path_value or ""),
                    model=tc_data.get("model")
                    or adapter_config.get("model")
                    or tc_data.get("default_model"),
                    timeout_seconds=timeout_seconds or 1800,
                    max_tokens=int(tc_data.get("max_tokens", 100_000)),
                    env=dict(tc_data.get("env") or {}),
                    config=adapter_config,
                )

        # Build routing config (optional)
        routing_rules: list[RoutingRule] = []
        rules_data = routing_data.get("rules") if isinstance(routing_data, dict) else None
        if isinstance(rules_data, list):
            for rule in rules_data:
                if not isinstance(rule, dict):
                    continue
                match = rule.get("match") if isinstance(rule.get("match"), dict) else {}
                use = rule.get("use")
                if isinstance(use, str):
                    use_list = [use]
                elif isinstance(use, list):
                    use_list = [str(x) for x in use]
                else:
                    use_list = []

                parallelism_value = rule.get("parallelism")
                parallelism_int: int | None = None
                if parallelism_value is not None:
                    try:
                        parallelism_int = int(parallelism_value)
                    except (TypeError, ValueError):
                        parallelism_int = None

                execution_mode_value = rule.get("execution_mode")
                execution_mode: str | None = None
                if isinstance(execution_mode_value, str) and execution_mode_value.strip():
                    execution_mode = execution_mode_value.strip()

                routing_rules.append(
                    RoutingRule(
                        match=dict(match),
                        use=use_list,
                        speculate=bool(rule.get("speculate", False)),
                        parallelism=parallelism_int,
                        execution_mode=execution_mode,
                    )
                )

        fallbacks = {}
        fallbacks_data = routing_data.get("fallbacks") if isinstance(routing_data, dict) else None
        if isinstance(fallbacks_data, dict):
            for k, v in fallbacks_data.items():
                if isinstance(v, list):
                    fallbacks[str(k)] = [str(x) for x in v]

        # Normalize speculation config: support docs-style "auto_trigger" nesting and ignore unknown keys.
        speculation_data = dict(speculation_data) if isinstance(speculation_data, dict) else {}
        auto_trigger = speculation_data.pop("auto_trigger", None)
        if isinstance(auto_trigger, dict):
            if (
                "on_critical_path" in auto_trigger
                and "auto_trigger_on_critical_path" not in speculation_data
            ):
                speculation_data["auto_trigger_on_critical_path"] = auto_trigger.get(
                    "on_critical_path"
                )
            if "risk_levels" in auto_trigger and "auto_trigger_risk_levels" not in speculation_data:
                speculation_data["auto_trigger_risk_levels"] = auto_trigger.get("risk_levels")

        def _filter_keys(src: dict[str, Any], allowed: set[str]) -> dict[str, Any]:
            return {k: v for k, v in src.items() if k in allowed}

        gates_kwargs = _filter_keys(
            dict(gates_data) if isinstance(gates_data, dict) else {},
            {
                "test_command",
                "typecheck_command",
                "lint_command",
                "build_command",
                "timeout_seconds",
                "retry_flaky",
                "parallel",
                "total_budget_ms",
                "max_cpu_seconds",
                "max_memory_mb",
                "max_diff_lines",
                "max_diff_files",
                "secret_detection",
                "secret_detection_scan_diff",
                "secret_detection_max_bytes",
            },
        )
        speculation_kwargs = _filter_keys(
            speculation_data,
            {
                "enabled",
                "default_parallelism",
                "max_parallelism",
                "vote_threshold",
                "auto_trigger_on_critical_path",
                "auto_trigger_risk_levels",
                "next_step_candidates",
                "next_step_max_steps",
            },
        )
        control_kwargs = _filter_keys(
            dict(control_data) if isinstance(control_data, dict) else {},
            {
                "enabled",
                "action_low",
                "action_high",
                "temperature_base",
                "temperature_min",
                "temperature_max",
                "temperature_step",
                "parallelism_step",
            },
        )
        planner_kwargs = _filter_keys(
            dict(planner_data) if isinstance(planner_data, dict) else {},
            {"mode", "bundle_dir", "confidence_threshold", "enabled"},
        )

        strategy_kwargs = _filter_keys(
            dict(strategy_data) if isinstance(strategy_data, dict) else {},
            {"enabled", "prompt_style", "self_report"},
        )
        strategy_routing_kwargs = {}
        strategy_routing_data = (
            strategy_data.get("routing") if isinstance(strategy_data, dict) else None
        )
        if isinstance(strategy_routing_data, dict):
            strategy_routing_kwargs = _filter_keys(
                dict(strategy_routing_data),
                {
                    "enabled",
                    "mode",
                    "ab_test_enabled",
                    "ab_test_ratio",
                    "ab_test_salt",
                    "outcome",
                    "min_confidence",
                    "per_toolchain",
                },
            )

        # Back-compat: allow boolean `planner.enabled`.
        if "enabled" in planner_kwargs and "mode" not in planner_kwargs:
            planner_kwargs["mode"] = "enforce" if bool(planner_kwargs.get("enabled")) else "off"
        planner_kwargs.pop("enabled", None)

        if "bundle_dir" in planner_kwargs:
            bundle_dir = planner_kwargs.get("bundle_dir")
            if bundle_dir is None:
                planner_kwargs["bundle_dir"] = None
            elif isinstance(bundle_dir, Path):
                planner_kwargs["bundle_dir"] = bundle_dir
            else:
                planner_kwargs["bundle_dir"] = Path(str(bundle_dir))

        sleeptime_cfg: dict[str, Any] | None = None
        if isinstance(sleeptime_data, dict):
            sleeptime_cfg = dict(sleeptime_data)

        ralph_cfg: dict[str, Any] | None = None
        if isinstance(ralph_data, dict):
            ralph_cfg = dict(ralph_data)

        settlement_cfg: dict[str, Any] | None = None
        if isinstance(data.get("settlement"), dict):
            settlement_cfg = dict(data.get("settlement") or {})

        federation_cfg: dict[str, Any] | None = None
        if isinstance(data.get("federation"), dict):
            federation_cfg = dict(data.get("federation") or {})

        # E2B cloud sandbox provider config
        workcell_provider = str(data.get("workcell_provider", "local"))
        e2b_data = data.get("e2b")
        e2b_cfg = E2BConfig()
        if isinstance(e2b_data, dict):
            e2b_cfg = E2BConfig(
                template=str(e2b_data.get("template", "base")),
                timeout=int(e2b_data.get("timeout", 1800)),
            )

        gpu_pool_cfg = GpuPoolConfig()
        if isinstance(gpu_pool_data, dict):
            manager_url = gpu_pool_data.get("manager_url")
            backends_data = gpu_pool_data.get("backends")
            pools_data = gpu_pool_data.get("pools")
            backend_configs: dict[str, GpuPoolBackendConfig] = {}
            if isinstance(backends_data, dict):
                for backend_id, backend_data in backends_data.items():
                    if isinstance(backend_data, dict):
                        enabled = bool(backend_data.get("enabled", True))
                        priority_raw = backend_data.get("priority", 0)
                        try:
                            priority = int(priority_raw)
                        except (TypeError, ValueError):
                            priority = 0
                        adapter_config = {
                            k: v
                            for k, v in backend_data.items()
                            if k not in {"enabled", "priority"}
                        }
                        backend_configs[backend_id] = GpuPoolBackendConfig(
                            backend_id=backend_id,
                            enabled=enabled,
                            priority=priority,
                            config=adapter_config,
                        )
                    else:
                        backend_configs[backend_id] = GpuPoolBackendConfig(
                            backend_id=backend_id,
                            enabled=bool(backend_data),
                        )

            pool_configs: list[GpuPoolPoolConfig] = []
            if isinstance(pools_data, list):
                for pool_data in pools_data:
                    if not isinstance(pool_data, dict):
                        continue
                    pool_id = pool_data.get("id")
                    if not pool_id:
                        continue
                    backends = pool_data.get("backends")
                    backend_list = [str(b) for b in backends] if isinstance(backends, list) else []
                    min_idle = pool_data.get("min_idle")
                    max_size = pool_data.get("max_size")
                    try:
                        min_idle_value = int(min_idle) if min_idle is not None else None
                    except (TypeError, ValueError):
                        min_idle_value = None
                    try:
                        max_size_value = int(max_size) if max_size is not None else None
                    except (TypeError, ValueError):
                        max_size_value = None
                    pool_configs.append(
                        GpuPoolPoolConfig(
                            id=str(pool_id),
                            backends=backend_list,
                            min_idle=min_idle_value,
                            max_size=max_size_value,
                        )
                    )

            gpu_pool_cfg = GpuPoolConfig(
                manager_url=manager_url,
                backends=backend_configs,
                pools=pool_configs,
            )

        # Build sentinels config
        sentinels_kwargs = _filter_keys(
            dict(sentinels_data) if isinstance(sentinels_data, dict) else {},
            {"enabled", "dry_run", "max_runtime_seconds", "max_changes_per_run"},
        )
        # Extract per-sentinel configs
        for sentinel_name in (
            "bead_gardener",
            "doc_sync",
            "security",
            "memory_gardener",
            "shield_ingest",
            "range_raids",
        ):
            sentinel_cfg = sentinels_data.get(sentinel_name)
            if isinstance(sentinel_cfg, dict):
                sentinels_kwargs[sentinel_name] = dict(sentinel_cfg)

        # Build main config
        config = cls(
            max_concurrent_workcells=int(max_concurrent_workcells),
            max_concurrent_tokens=int(max_concurrent_tokens),
            starvation_threshold_hours=float(starvation_threshold_hours),
            workcell_provider=workcell_provider,
            e2b=e2b_cfg,
            toolchain_priority=data.get("toolchain_priority", ["codex", "claude", "crush"]),
            toolchains=toolchains,
            gates=GatesConfig(**gates_kwargs) if gates_kwargs else GatesConfig(),
            speculation=SpeculationConfig(**speculation_kwargs)
            if speculation_kwargs
            else SpeculationConfig(),
            routing=RoutingConfig(rules=routing_rules, fallbacks=fallbacks),
            gpu_pool=gpu_pool_cfg,
            control=ControlConfig(**control_kwargs) if control_kwargs else ControlConfig(),
            planner=PlannerConfig(**planner_kwargs) if planner_kwargs else PlannerConfig(),
            strategy=StrategyConfig(
                **{
                    **strategy_kwargs,
                    "routing": StrategyRoutingConfig(**strategy_routing_kwargs)
                    if strategy_routing_kwargs
                    else StrategyRoutingConfig(),
                }
            )
            if strategy_kwargs or strategy_routing_kwargs
            else StrategyConfig(),
            sentinels=SentinelsConfig(**sentinels_kwargs)
            if sentinels_kwargs
            else SentinelsConfig(),
            settlement=SettlementConfig(
                **{
                    **_filter_keys(
                        settlement_cfg or {},
                        {
                            "enabled",
                            "rpc_url",
                            "registry_program_id",
                            "staking_program_id",
                            "fee_market_program_id",
                            "sas_enabled",
                            "sas_endpoint",
                            "allowlist",
                        },
                    ),
                    "oracle": OracleConfig(
                        **(settlement_cfg.get("oracle") or {})
                    )
                    if settlement_cfg
                    else OracleConfig(),
                    "orca": OrcaConfig(**(settlement_cfg.get("orca") or {}))
                    if settlement_cfg
                    else OrcaConfig(),
                    "treasury": TreasuryConfig(**(settlement_cfg.get("treasury") or {}))
                    if settlement_cfg
                    else TreasuryConfig(),
                }
            )
            if settlement_cfg
            else SettlementConfig(),
            federation=FederationConfig(
                **{
                    **_filter_keys(
                        federation_cfg or {},
                        {"enabled"},
                    ),
                    "ccip": CCIPConfig(**(federation_cfg.get("ccip") or {}))
                    if federation_cfg
                    else CCIPConfig(),
                }
            )
            if federation_cfg
            else FederationConfig(),
            sleeptime=sleeptime_cfg,
            ralph=ralph_cfg,
        )

        if config_path:
            config._apply_config_path(config_path)

        # Optional path overrides from config (flat or nested under `paths:`)
        paths_data = data.get("paths") if isinstance(data.get("paths"), dict) else {}

        def _path_value(key: str) -> str | None:
            value = paths_data.get(key) or data.get(key)
            if isinstance(value, Path):
                return str(value)
            if isinstance(value, str) and value.strip():
                return value.strip()
            return None

        beads_path_value = _path_value("beads_path")
        if beads_path_value:
            config.hellcat_path = Path(beads_path_value)

        workcells_dir_value = _path_value("workcells_dir")
        if workcells_dir_value:
            config.workcells_dir = Path(workcells_dir_value)

        archives_dir_value = _path_value("archives_dir")
        if archives_dir_value:
            config.archives_dir = Path(archives_dir_value)

        # Environment overrides (per-job, set by the desktop cockpit bindings)
        beads_env = os.environ.get("HELLCAT_BEADS_PATH")
        if beads_env and beads_env.strip():
            config.hellcat_path = Path(beads_env.strip())

        workcells_env = os.environ.get("HELLCAT_WORKCELLS_DIR")
        if workcells_env and workcells_env.strip():
            config.workcells_dir = Path(workcells_env.strip())

        archives_env = os.environ.get("HELLCAT_ARCHIVES_DIR")
        if archives_env and archives_env.strip():
            config.archives_dir = Path(archives_env.strip())

        max_wc_env = os.environ.get("HELLCAT_MAX_CONCURRENT_WORKCELLS")
        if max_wc_env and max_wc_env.strip():
            with contextlib.suppress(Exception):
                config.max_concurrent_workcells = int(max_wc_env.strip())

        # Model override from cockpit resources
        model_provider_env = os.environ.get("HELLCAT_MODEL_PROVIDER")
        if model_provider_env and model_provider_env.strip():
            config.model_provider = model_provider_env.strip()

        model_name_env = os.environ.get("HELLCAT_MODEL_NAME")
        if model_name_env and model_name_env.strip():
            config.model_name = model_name_env.strip()

        model_endpoint_env = os.environ.get("HELLCAT_MODEL_ENDPOINT")
        if model_endpoint_env and model_endpoint_env.strip():
            config.model_endpoint = model_endpoint_env.strip()

        # Knowledge base source from cockpit resources
        kb_source_env = os.environ.get("HELLCAT_KB_SOURCE")
        if kb_source_env and kb_source_env.strip():
            config.kb_source = kb_source_env.strip()

        # Skill network source from cockpit resources
        skills_source_env = os.environ.get("HELLCAT_SKILLS_SOURCE")
        if skills_source_env and skills_source_env.strip():
            config.skills_source = skills_source_env.strip()

        config._normalize_paths()
        return config

    @classmethod
    def _load_with_includes(
        cls, data: dict[str, Any], config_path: Path, *, seen: set[Path]
    ) -> dict[str, Any]:
        """
        Load a config file that may include one or more base configs.

        Supports:
          include: relative/or/absolute/path.yaml
          include: [path1.yaml, path2.yaml]
        """
        resolved = config_path.resolve()
        if resolved in seen:
            raise ValueError(f"Config include cycle detected at {resolved}")
        seen.add(resolved)

        include_value = data.get("include")
        includes: list[str] = []
        if isinstance(include_value, str) and include_value.strip():
            includes = [include_value]
        elif isinstance(include_value, list):
            includes = [str(x) for x in include_value if str(x).strip()]

        base: dict[str, Any] = {}
        for include in includes:
            include_path = Path(include)
            if not include_path.is_absolute():
                include_path = (config_path.parent / include_path).resolve()

            include_data = _load_yaml(include_path)
            include_merged = cls._load_with_includes(include_data, include_path, seen=seen)
            base = _deep_merge_dicts(base, include_merged)

        # Child overrides base; keep include key out of final merged dict.
        child = dict(data)
        child.pop("include", None)
        return _deep_merge_dicts(base, child)

    def _apply_config_path(self, config_path: Path) -> None:
        config_path = Path(config_path).resolve()
        self.config_path = config_path
        self.repo_root = config_path.parent.parent

        self.kernel_dir = config_path.parent
        self.logs_dir = self.kernel_dir / "logs"
        self.archives_dir = self.kernel_dir / "archives"
        self.state_dir = self.kernel_dir / "state"

        self.hellcat_path = self.repo_root / ".hellcat"
        self.workcells_dir = self.repo_root / ".workcells"

    def _normalize_paths(self) -> None:
        self.repo_root = self.repo_root.resolve()

        def _resolve(path: Path) -> Path:
            return path if path.is_absolute() else (self.repo_root / path).resolve()

        self.hellcat_path = _resolve(self.hellcat_path)
        self.workcells_dir = _resolve(self.workcells_dir)
        self.kernel_dir = _resolve(self.kernel_dir)
        self.logs_dir = _resolve(self.logs_dir)
        self.archives_dir = _resolve(self.archives_dir)
        self.state_dir = _resolve(self.state_dir)
        self.config_path = _resolve(self.config_path)
        if self.planner.bundle_dir is not None:
            self.planner.bundle_dir = _resolve(self.planner.bundle_dir)

    def to_dict(self) -> dict[str, Any]:
        """Serialize config to dictionary."""
        return {
            "max_concurrent_workcells": self.max_concurrent_workcells,
            "max_concurrent_tokens": self.max_concurrent_tokens,
            "starvation_threshold_hours": self.starvation_threshold_hours,
            "workcell_provider": self.workcell_provider,
            "e2b": {
                "template": self.e2b.template,
                "timeout": self.e2b.timeout,
            },
            "toolchain_priority": self.toolchain_priority,
            "toolchains": {
                name: {
                    "enabled": tc.enabled,
                    "path": tc.path,
                    "model": tc.model,
                    "timeout_seconds": tc.timeout_seconds,
                    "max_tokens": tc.max_tokens,
                    "env": tc.env,
                    "config": tc.config,
                }
                for name, tc in self.toolchains.items()
            },
            "gates": {
                "test_command": self.gates.test_command,
                "typecheck_command": self.gates.typecheck_command,
                "lint_command": self.gates.lint_command,
                "build_command": self.gates.build_command,
                "timeout_seconds": self.gates.timeout_seconds,
                "max_diff_lines": self.gates.max_diff_lines,
                "max_diff_files": self.gates.max_diff_files,
                "secret_detection": self.gates.secret_detection,
                "secret_detection_scan_diff": self.gates.secret_detection_scan_diff,
                "secret_detection_max_bytes": self.gates.secret_detection_max_bytes,
            },
            "speculation": {
                "enabled": self.speculation.enabled,
                "default_parallelism": self.speculation.default_parallelism,
                "vote_threshold": self.speculation.vote_threshold,
            },
            "control": {
                "enabled": self.control.enabled,
                "action_low": self.control.action_low,
                "action_high": self.control.action_high,
                "temperature_base": self.control.temperature_base,
                "temperature_min": self.control.temperature_min,
                "temperature_max": self.control.temperature_max,
                "temperature_step": self.control.temperature_step,
                "parallelism_step": self.control.parallelism_step,
            },
            "routing": {
                "rules": [
                    {
                        "match": r.match,
                        "use": r.use,
                        "speculate": r.speculate,
                        "parallelism": r.parallelism,
                        "execution_mode": r.execution_mode,
                    }
                    for r in self.routing.rules
                ],
                "fallbacks": self.routing.fallbacks,
            },
            "gpu_pool": {
                "manager_url": self.gpu_pool.manager_url,
                "backends": {
                    backend_id: {
                        "enabled": backend_cfg.enabled,
                        "priority": backend_cfg.priority,
                        **backend_cfg.config,
                    }
                    for backend_id, backend_cfg in self.gpu_pool.backends.items()
                },
                "pools": [
                    {
                        "id": pool.id,
                        "backends": pool.backends,
                        "min_idle": pool.min_idle,
                        "max_size": pool.max_size,
                    }
                    for pool in self.gpu_pool.pools
                ],
            },
            "planner": {
                "mode": self.planner.mode,
                "bundle_dir": str(self.planner.bundle_dir)
                if self.planner.bundle_dir is not None
                else None,
                "confidence_threshold": self.planner.confidence_threshold,
            },
            "settlement": {
                "enabled": self.settlement.enabled,
                "rpc_url": self.settlement.rpc_url,
                "registry_program_id": self.settlement.registry_program_id,
                "staking_program_id": self.settlement.staking_program_id,
                "fee_market_program_id": self.settlement.fee_market_program_id,
                "sas_enabled": self.settlement.sas_enabled,
                "sas_endpoint": self.settlement.sas_endpoint,
                "allowlist": self.settlement.allowlist,
                "oracle": {
                    "enabled": self.settlement.oracle.enabled,
                    "sources": self.settlement.oracle.sources,
                    "max_age_seconds": self.settlement.oracle.max_age_seconds,
                    "max_deviation_bps": self.settlement.oracle.max_deviation_bps,
                    "min_price": self.settlement.oracle.min_price,
                    "max_price": self.settlement.oracle.max_price,
                },
                "orca": {
                    "enabled": self.settlement.orca.enabled,
                    "pool_id": self.settlement.orca.pool_id,
                    "slippage_bps": self.settlement.orca.slippage_bps,
                    "max_trade_usdc": self.settlement.orca.max_trade_usdc,
                },
                "treasury": {
                    "enabled": self.settlement.treasury.enabled,
                    "buyback_enabled": self.settlement.treasury.buyback_enabled,
                    "interval_seconds": self.settlement.treasury.interval_seconds,
                    "treasury_wallet": self.settlement.treasury.treasury_wallet,
                    "source_mint": self.settlement.treasury.source_mint,
                    "target_mint": self.settlement.treasury.target_mint,
                },
            },
            "federation": {
                "enabled": self.federation.enabled,
                "ccip": {
                    "enabled": self.federation.ccip.enabled,
                    "router_address": self.federation.ccip.router_address,
                    "source_chain": self.federation.ccip.source_chain,
                    "target_chains": self.federation.ccip.target_chains,
                    "anchor_interval_seconds": self.federation.ccip.anchor_interval_seconds,
                },
            },
            "sleeptime": self.sleeptime,
            "ralph": self.ralph,
        }
