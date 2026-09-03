#!/bin/sh
set -eu

mkdir -p /logs/verifier
python3 /tests/verify.py \
  --evidence /logs/artifacts/ambush-evidence.json \
  --reward /logs/verifier/reward.json \
  --details /logs/verifier/details.json
