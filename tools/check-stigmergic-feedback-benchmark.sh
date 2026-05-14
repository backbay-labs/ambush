#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

cargo test -p swarm-runtime \
  recruitment_kill_chain_replay_reaches_alert_at_least_twenty_percent_faster \
  --test recruitment_integration -- --nocapture

cargo test -p swarm-whisker \
  behavioral_anomaly_quantifies_distinct_poisoning_observations_required_for_sigma_shifts \
  --lib -- --nocapture
