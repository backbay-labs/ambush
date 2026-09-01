#!/usr/bin/env bash
# Sourced by the goose and goose-bg just recipes to build shared agent env_args.
# Usage: source scripts/_goose-env.sh <relay> <key> <agents> <heartbeat> <prompt>
# Sets: env_args (bash array), ready for: exec env "${env_args[@]}" <binary>
set -euo pipefail

_relay="$1"
_key="$2"
_agents="$3"
_heartbeat="$4"
_prompt="${5:-}"

cargo build --release -p ambush-acp -p ambush-cli

env_args=(
    AMBUSH_RELAY_URL="$_relay"
    AMBUSH_PRIVATE_KEY="$_key"
    AMBUSH_ACP_AGENT_COMMAND=goose
    AMBUSH_ACP_AGENT_ARGS=acp
    AMBUSH_ACP_AGENTS="$_agents"
    GOOSE_MODE=auto
)
[[ -n "$_prompt" ]] && env_args+=(AMBUSH_ACP_SYSTEM_PROMPT="$_prompt")
if [[ "$_heartbeat" != "0" ]]; then
    env_args+=(AMBUSH_ACP_HEARTBEAT_INTERVAL="$_heartbeat")
fi
