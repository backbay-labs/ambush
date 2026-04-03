"""Runner for Youtu-Agent SimpleAgent (invoked by the adapter)."""

from __future__ import annotations

import argparse
import asyncio
import inspect
import json
import os
import sys
import traceback
from pathlib import Path
from typing import Any


def _load_config(config_name: str | None, config_path: str | None) -> Any:
    errors: list[str] = []

    if config_name:
        try:
            from utu.config import ConfigLoader

            loader = ConfigLoader()
            for method_name in ("load_agent", "load", "load_config"):
                if hasattr(loader, method_name):
                    config = getattr(loader, method_name)(config_name)
                    if config is not None:
                        return config
        except Exception as exc:
            errors.append(f"ConfigLoader failed: {exc}")

    if config_path:
        try:
            from utu.config import AgentConfig

            if hasattr(AgentConfig, "load"):
                return AgentConfig.load(config_path)
            if hasattr(AgentConfig, "from_yaml"):
                return AgentConfig.from_yaml(config_path)

            try:
                import yaml
            except Exception as exc:
                raise RuntimeError("PyYAML is required to load config from path") from exc

            data = yaml.safe_load(Path(config_path).read_text())
            if hasattr(AgentConfig, "parse_obj"):
                return AgentConfig.parse_obj(data)
            return AgentConfig(**data)
        except Exception as exc:
            errors.append(f"AgentConfig failed: {exc}")

    if errors:
        raise RuntimeError("; ".join(errors))

    raise RuntimeError("No config_name or config_path provided")


def _set_attr_if_present(obj: Any, attr: str, value: Any) -> bool:
    if hasattr(obj, attr):
        try:
            setattr(obj, attr, value)
            return True
        except Exception:
            return False
    return False


def _apply_model_override(config: Any, model: str | None) -> None:
    if not model:
        return
    if _set_attr_if_present(config, "model", model):
        return
    llm = getattr(config, "llm", None)
    if llm is not None:
        _set_attr_if_present(llm, "model", model)


def _apply_mcp_servers(config: Any, mcp_servers: Any) -> None:
    if not mcp_servers:
        return
    toolkits = getattr(config, "toolkits", None)
    if isinstance(toolkits, dict):
        mcp_cfg = toolkits.get("mcp")
        if mcp_cfg is None:
            toolkits["mcp"] = {"servers": mcp_servers}
            return
        if isinstance(mcp_cfg, dict):
            mcp_cfg.setdefault("servers", mcp_servers)
            return
    if isinstance(toolkits, list):
        toolkits.append({"type": "mcp", "servers": mcp_servers})


def _extract_metrics(result: Any) -> dict[str, Any]:
    metrics: dict[str, Any] = {}
    if isinstance(result, dict):
        for key in (
            "tokens_used",
            "total_tokens",
            "prompt_tokens",
            "completion_tokens",
            "cost_usd",
        ):
            if key in result:
                metrics[key] = result[key]
        return metrics

    for key in (
        "tokens_used",
        "total_tokens",
        "prompt_tokens",
        "completion_tokens",
        "cost_usd",
    ):
        value = getattr(result, key, None)
        if value is not None:
            metrics[key] = value
    return metrics


def _extract_output(result: Any) -> str:
    if isinstance(result, dict):
        for key in ("final_output", "output", "response"):
            value = result.get(key)
            if isinstance(value, str):
                return value
        return json.dumps(result, ensure_ascii=True)

    for attr in ("final_output", "output", "response"):
        value = getattr(result, attr, None)
        if isinstance(value, str):
            return value
    return str(result)


def _parse_mcp_servers(raw: str | None) -> Any:
    if not raw:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run Youtu-Agent SimpleAgent")
    parser.add_argument("--prompt", required=True, help="Path to prompt file")
    parser.add_argument("--output", required=True, help="Path to output JSON")
    parser.add_argument("--config-name", help="Config name to load")
    parser.add_argument("--config-path", help="Path to YAML config")
    parser.add_argument("--model", help="Model override")
    parser.add_argument("--mcp-servers", help="JSON list of MCP servers")
    parser.add_argument("--workdir", help="Working directory override")
    return parser


async def _run(args: argparse.Namespace) -> dict[str, Any]:
    if args.workdir:
        os.chdir(args.workdir)

    config = _load_config(args.config_name, args.config_path)
    _apply_model_override(config, args.model)
    mcp_servers = _parse_mcp_servers(args.mcp_servers)
    if mcp_servers is not None:
        _apply_mcp_servers(config, mcp_servers)

    from utu.agents import SimpleAgent

    prompt_text = Path(args.prompt).read_text()
    agent = SimpleAgent(config)

    result = agent.run(prompt_text)
    if inspect.isawaitable(result):
        result = await result

    output_text = _extract_output(result)
    metrics = _extract_metrics(result)

    return {
        "status": "success",
        "final_output": output_text,
        "metrics": metrics,
    }


def main() -> int:
    parser = _build_arg_parser()
    args = parser.parse_args()

    payload: dict[str, Any]
    try:
        payload = asyncio.run(_run(args))
    except Exception as exc:
        payload = {
            "status": "error",
            "error": str(exc),
            "traceback": traceback.format_exc(),
        }

    output_path = Path(args.output)
    output_path.write_text(json.dumps(payload, ensure_ascii=True))
    print(json.dumps(payload, ensure_ascii=True))
    return 0 if payload.get("status") == "success" else 2


if __name__ == "__main__":
    raise SystemExit(main())
