#!/bin/sh
set -eu

python3 /tests/verify.py \
  --evidence /logs/artifacts/ambush-evidence.json \
  --skill-file /home/ambush/.claude/skills/context-health-check/SKILL.md \
  --reward /logs/verifier/reward.json \
  --details /logs/verifier/details.json
