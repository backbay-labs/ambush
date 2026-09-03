"""Harbor custom-agent entry point for Ambush orchestration."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from harbor.agents.base import BaseAgent
from harbor.environments.base import BaseEnvironment
from harbor.models.agent.context import AgentContext

from .container_runtime import AmbushContainerRuntime, EndpointLaunchConfig
from .manifest import ExperimentManifest
from .provisioning import TrialProvisioner
from .runtime import OrchestraRuntime


class AmbushOrchestraAgent(BaseAgent):
    """Coordinate an arbitrary manifest-defined team through a Ambush trial."""

    # Set True only once the runtime writes a validated agent/trajectory.json.
    SUPPORTS_ATIF = False

    def __init__(
        self,
        logs_dir: Path,
        model_name: str | None = None,
        *,
        manifest: str | Path | dict[str, Any],
        provisioner: TrialProvisioner | None = None,
        runtime: OrchestraRuntime | None = None,
        provisioner_factory: str | None = None,
        provisioner_config: str | Path | dict[str, Any] | None = None,
        artifact_root: str | Path | None = None,
        endpoint_config: str | Path | dict[str, Any] | None = None,
        ambush_acp_binary: str = "ambush-acp",
        ambush_agent_binary: str = "ambush-agent",
        ambush_dev_mcp_binary: str = "ambush-dev-mcp",
        ambush_cli_binary: str = "ambush",
        relay_gateway: str = "",
        forwarder_binary: str = "relay-forwarder",
        run_id: str | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(logs_dir=logs_dir, model_name=model_name, **kwargs)
        self.manifest = ExperimentManifest.load(manifest)
        self.provisioner = provisioner or self._build_provisioner(
            provisioner_factory, provisioner_config
        )
        self.runtime = runtime or self._build_runtime(
            logs_dir,
            artifact_root,
            endpoint_config,
            ambush_acp_binary,
            ambush_agent_binary,
            ambush_dev_mcp_binary,
            ambush_cli_binary,
            relay_gateway,
            forwarder_binary,
        )
        self.run_id = run_id

    @staticmethod
    def name() -> str:
        return "ambush-orchestra"

    def version(self) -> str:
        return "0.1.0"

    @staticmethod
    def _load_mapping(
        source: str | Path | dict[str, Any] | None,
    ) -> dict[str, Any] | None:
        if source is None:
            return None
        if isinstance(source, dict):
            return source
        import json

        path = Path(source).expanduser()
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise ValueError(f"cannot load JSON config {path}: {error}") from error
        if not isinstance(value, dict):
            raise TypeError(f"JSON config {path} must contain an object")
        return value

    @classmethod
    def _build_provisioner(
        cls,
        factory_path: str | None,
        config_source: str | Path | dict[str, Any] | None,
    ) -> TrialProvisioner | None:
        config = cls._load_mapping(config_source)
        if factory_path is None and config is None:
            return None
        if factory_path is None or config is None:
            raise ValueError(
                "provisioner_factory and provisioner_config must be provided together"
            )
        from harbor.utils.import_path import import_symbol

        factory = import_symbol(factory_path)
        return factory(config)

    @classmethod
    def _build_runtime(
        cls,
        logs_dir: Path,
        artifact_root: str | Path | None,
        endpoint_source: str | Path | dict[str, Any] | None,
        ambush_acp_binary: str,
        ambush_agent_binary: str,
        ambush_dev_mcp_binary: str,
        ambush_cli_binary: str,
        relay_gateway: str,
        forwarder_binary: str,
    ) -> OrchestraRuntime | None:
        endpoint_data = cls._load_mapping(endpoint_source)
        if endpoint_data is None and artifact_root is None:
            return None
        if endpoint_data is None or artifact_root is None:
            raise ValueError(
                "artifact_root and endpoint_config must be provided together"
            )
        endpoints = {
            name: EndpointLaunchConfig(
                provider=value["provider"],
                api_key_env=value["api_key_env"],
                env=value.get("env", {}),
            )
            for name, value in endpoint_data.items()
        }
        return AmbushContainerRuntime(
            logs_dir=logs_dir,
            artifact_root=Path(artifact_root),
            endpoints=endpoints,
            ambush_acp_binary=ambush_acp_binary,
            ambush_agent_binary=ambush_agent_binary,
            ambush_dev_mcp_binary=ambush_dev_mcp_binary,
            ambush_cli_binary=ambush_cli_binary,
            relay_gateway=relay_gateway,
            forwarder_binary=forwarder_binary,
        )

    async def setup(self, environment: BaseEnvironment) -> None:
        """Fail fast when the provisioner is configured but its stack is unhealthy."""
        if self.provisioner is not None:
            self.provisioner.healthcheck()

    async def run(
        self,
        instruction: str,
        environment: BaseEnvironment,
        context: AgentContext,
    ) -> None:
        if self.provisioner is None or self.runtime is None:
            raise RuntimeError(
                "AmbushOrchestraAgent requires provisioner and runtime integrations; "
                "the adapter contract is installed but M1 wiring is incomplete"
            )

        context_id = self.context_id or environment.context_id
        if context_id is None:
            raise RuntimeError("Harbor context_id is required as the trial join key")
        trial_id = str(context_id)
        run_id = self.run_id or trial_id
        # Human-readable channel label: the task short name, so a spectator
        # GUI shows one recognisable channel per problem per attempt.
        channel_label = getattr(environment, "environment_name", None)
        handle = self.provisioner.create_trial(
            run_id,
            trial_id,
            self.manifest,
            channel_label=channel_label,
            task_name=channel_label,
        )
        if handle.trial_id != trial_id:
            raise RuntimeError("provisioner returned a handle for a different trial_id")
        if handle.manifest_hash != self.manifest.sha256:
            raise RuntimeError("provisioner returned a handle for a different manifest")
        try:
            result = await self.runtime.run(
                instruction=instruction,
                environment=environment,
                manifest=self.manifest,
                trial=handle,
            )
        finally:
            self.provisioner.teardown(handle)

        context.n_input_tokens = result.input_tokens
        context.n_cache_tokens = result.cached_input_tokens
        context.n_output_tokens = result.output_tokens
        context.cost_usd = result.cost_usd
        context.metadata = {
            **result.metadata,
            "manifest_sha256": self.manifest.sha256,
            "condition": self.manifest.condition,
            "ambush_channel_id": handle.channel_id,
            "run_id": run_id,
            "trial_id": trial_id,
        }
