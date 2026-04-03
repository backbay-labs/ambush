"""Claude agent loop executor.

Implements the standard tool_use loop: send messages → process tool calls →
append results → repeat until the agent is done or limits are hit.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

import structlog

from hellcat.operators.tools import ToolContext, dispatch_tool

logger = structlog.get_logger()

# Sonnet pricing per 1M tokens (default; overridden per-model below)
_MODEL_PRICING: dict[str, tuple[float, float]] = {
    # (input_per_1m, output_per_1m)
    "claude-sonnet-4-5-20250929": (3.0, 15.0),
    "claude-sonnet-4-20250514": (3.0, 15.0),
    "claude-opus-4-6": (15.0, 75.0),
    "claude-opus-4-20250514": (15.0, 75.0),
    "claude-haiku-4-5-20251001": (0.80, 4.0),
}

_DEFAULT_PRICING = (3.0, 15.0)  # Sonnet fallback

_MODEL_ALIASES: dict[str, str] = {
    "sonnet": "claude-sonnet-4-5-20250929",
    "opus": "claude-opus-4-6",
    "haiku": "claude-haiku-4-5-20251001",
}


def resolve_model(model: str) -> str:
    """Resolve a short alias to a full model ID."""
    return _MODEL_ALIASES.get(model, model)


def _compute_cost(model: str, input_tokens: int, output_tokens: int) -> float:
    inp_rate, out_rate = _MODEL_PRICING.get(model, _DEFAULT_PRICING)
    return (input_tokens * inp_rate + output_tokens * out_rate) / 1_000_000


# ---------------------------------------------------------------------------
# Configuration and result types
# ---------------------------------------------------------------------------


@dataclass
class ExecutionConfig:
    """Configuration for an agent execution run."""

    model: str = "claude-sonnet-4-5-20250929"
    max_turns: int = 100
    timeout_seconds: int = 600
    system_prompt: str = ""
    tools: list[dict[str, Any]] = field(default_factory=list)
    provider: str = "anthropic"


@dataclass
class ToolCall:
    """Record of a single tool invocation."""

    tool_name: str
    tool_input: dict[str, Any]
    result: str
    turn: int


@dataclass
class ExecutionResult:
    """Result from a completed agent execution."""

    final_text: str = ""
    turns: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0
    stop_reason: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Retry helpers
# ---------------------------------------------------------------------------

_RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 529}
_MAX_RETRIES = 5
_BASE_BACKOFF = 2.0  # seconds
_RATE_LIMIT_BASE_BACKOFF = 15.0  # longer wait for 429s (per-minute limits)


def _should_retry(exc: Exception) -> bool:
    """Return True if the exception looks transient and retryable."""
    exc_str = str(exc)
    # Anthropic SDK raises APIStatusError with a status_code attribute
    status_code = getattr(exc, "status_code", None)
    if status_code and status_code in _RETRYABLE_STATUS_CODES:
        return True
    return bool("overloaded" in exc_str.lower() or "rate" in exc_str.lower())


# ---------------------------------------------------------------------------
# Agent executor
# ---------------------------------------------------------------------------


class AgentExecutor:
    """Run a Claude agent loop with tool dispatch.

    Usage::

        executor = AgentExecutor(tool_context)
        result = executor.run(config, initial_user_message)
    """

    def __init__(self, tool_context: ToolContext) -> None:
        self.ctx = tool_context

    def run(
        self,
        config: ExecutionConfig,
        initial_message: str,
    ) -> ExecutionResult:
        """Execute the agent loop synchronously.

        Args:
            config: Model, tools, limits, system prompt.
            initial_message: The first user message (typically the prompt).

        Returns:
            :class:`ExecutionResult` with final text, token usage, and tool call log.
        """
        # Validate provider before creating the client
        if config.provider and config.provider != "anthropic":
            raise NotImplementedError(
                f"Provider '{config.provider}' is not supported. "
                f"Only 'anthropic' is currently implemented."
            )

        import anthropic

        client = anthropic.Anthropic()
        model = resolve_model(config.model)

        logger.info(
            "executor.model_selected",
            model=model,
            provider=config.provider or "anthropic",
        )

        messages: list[dict[str, Any]] = [
            {"role": "user", "content": initial_message},
        ]

        result = ExecutionResult()
        start = time.monotonic()

        for turn in range(1, config.max_turns + 1):
            elapsed = time.monotonic() - start
            if elapsed >= config.timeout_seconds:
                result.stop_reason = "timeout"
                result.errors.append(
                    f"Timed out after {elapsed:.0f}s ({turn - 1} turns)"
                )
                break

            # Call the API with retries
            response = self._call_api(
                client, model, config, messages, result
            )
            if response is None:
                break

            # Track tokens
            result.input_tokens += response.usage.input_tokens
            result.output_tokens += response.usage.output_tokens
            result.cost_usd = _compute_cost(
                model, result.input_tokens, result.output_tokens
            )
            result.turns = turn

            # Log progress periodically
            if turn % 10 == 0:
                logger.info(
                    "executor.progress",
                    turn=turn,
                    input_tokens=result.input_tokens,
                    output_tokens=result.output_tokens,
                    cost_usd=f"${result.cost_usd:.4f}",
                    elapsed=f"{elapsed:.0f}s",
                )

            # Process response content blocks
            tool_use_blocks: list[Any] = []
            text_parts: list[str] = []

            for block in response.content:
                if block.type == "text":
                    text_parts.append(block.text)
                elif block.type == "tool_use":
                    tool_use_blocks.append(block)

            if text_parts:
                result.final_text = "\n".join(text_parts)

            # If no tool_use blocks, the agent is done
            if not tool_use_blocks:
                result.stop_reason = response.stop_reason or "end_turn"
                break

            # Dispatch each tool call and build tool_result messages
            assistant_content: list[dict[str, Any]] = []
            for block in response.content:
                if block.type == "text":
                    assistant_content.append({"type": "text", "text": block.text})
                elif block.type == "tool_use":
                    assistant_content.append({
                        "type": "tool_use",
                        "id": block.id,
                        "name": block.name,
                        "input": block.input,
                    })

            messages.append({"role": "assistant", "content": assistant_content})

            tool_results: list[dict[str, Any]] = []
            for block in tool_use_blocks:
                # Update remaining time budget for tool handlers
                self.ctx.remaining_budget_seconds = (
                    config.timeout_seconds - (time.monotonic() - start)
                )
                tool_result_str = dispatch_tool(
                    self.ctx, block.name, block.input
                )
                result.tool_calls.append(
                    ToolCall(
                        tool_name=block.name,
                        tool_input=block.input,
                        result=tool_result_str,
                        turn=turn,
                    )
                )
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": tool_result_str,
                })

            messages.append({"role": "user", "content": tool_results})

        else:
            # max_turns exhausted
            result.stop_reason = "max_turns"
            result.errors.append(
                f"Reached max turns ({config.max_turns})"
            )

        # Final cost tally
        result.cost_usd = _compute_cost(
            model, result.input_tokens, result.output_tokens
        )

        logger.info(
            "executor.finished",
            turns=result.turns,
            input_tokens=result.input_tokens,
            output_tokens=result.output_tokens,
            cost_usd=f"${result.cost_usd:.4f}",
            stop_reason=result.stop_reason,
            tool_calls=len(result.tool_calls),
        )
        return result

    def _call_api(
        self,
        client: Any,
        model: str,
        config: ExecutionConfig,
        messages: list[dict[str, Any]],
        result: ExecutionResult,
    ) -> Any | None:
        """Call the Anthropic messages API with retry on transient errors."""
        kwargs: dict[str, Any] = {
            "model": model,
            "max_tokens": 16384,
            "messages": messages,
        }
        if config.system_prompt:
            kwargs["system"] = config.system_prompt
        if config.tools:
            kwargs["tools"] = config.tools

        for attempt in range(_MAX_RETRIES + 1):
            try:
                return client.messages.create(**kwargs)
            except Exception as exc:
                if attempt < _MAX_RETRIES and _should_retry(exc):
                    status_code = getattr(exc, "status_code", None)
                    if status_code == 429:
                        # Use longer backoff for rate limits (per-minute quotas)
                        retry_after = getattr(
                            getattr(exc, "response", None), "headers", {}
                        ).get("retry-after")
                        if retry_after:
                            try:
                                wait = float(retry_after) + 1.0
                            except ValueError:
                                wait = _RATE_LIMIT_BASE_BACKOFF * (1.5**attempt)
                        else:
                            wait = _RATE_LIMIT_BASE_BACKOFF * (1.5**attempt)
                    else:
                        wait = _BASE_BACKOFF * (2**attempt)
                    logger.warning(
                        "executor.api_retry",
                        attempt=attempt + 1,
                        wait_s=f"{wait:.0f}",
                        error=str(exc)[:200],
                    )
                    time.sleep(wait)
                    continue

                result.stop_reason = "api_error"
                result.errors.append(f"API error: {exc}")
                logger.error("executor.api_error", error=str(exc)[:500])
                return None
        return None
