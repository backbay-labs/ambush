"""Live smoke test: ReconOperator against OWASP Juice Shop.

Usage:
    cd /Users/connor/Medica/backbay/standalone/hellcat
    uv run python -m hellcat.operators.live_test

Requires:
    - ANTHROPIC_API_KEY env var (or .env file in repo root)
    - Juice Shop running at http://localhost:3001
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Ensure API key is available
# ---------------------------------------------------------------------------

def _ensure_api_key() -> None:
    if os.environ.get("ANTHROPIC_API_KEY"):
        return
    # Try to load from .env file in the hellcat repo root
    repo_root = Path(__file__).resolve().parents[4]
    dot_env = repo_root / ".env"
    if dot_env.exists():
        for line in dot_env.read_text().splitlines():
            line = line.strip()
            if line.startswith("ANTHROPIC_API_KEY=") and not line.startswith("#"):
                key = line.split("=", 1)[1].strip()
                os.environ["ANTHROPIC_API_KEY"] = key
                print(f"[setup] Loaded API key from {dot_env}")
                return
    print("[ERROR] No ANTHROPIC_API_KEY found. Set it in env or in .env at the hellcat repo root.")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Main test
# ---------------------------------------------------------------------------

async def main() -> None:
    _ensure_api_key()

    # Set up workspace
    base = Path("/tmp/hellcat-live-test")
    if base.exists():
        shutil.rmtree(base)

    workspace = base / "workspace"
    artifacts = base / "artifacts"
    workspace.mkdir(parents=True)
    artifacts.mkdir(parents=True)

    os.environ["STRIKECELL_WORKSPACE"] = str(workspace)
    os.environ["STRIKECELL_ARTIFACTS"] = str(artifacts)

    print("=" * 60)
    print("Hellcat ReconOperator - Live Smoke Test")
    print("=" * 60)
    print("Target:     http://localhost:3001")
    print(f"Workspace:  {workspace}")
    print(f"Artifacts:  {artifacts}")
    print("Model:      sonnet")
    print("Max turns:  30")
    print("Timeout:    300s")
    print("=" * 60)

    from hellcat.offensive.operator_base import AttackManifest
    from hellcat.offensive.operators.recon_operator import ReconOperator

    manifest = AttackManifest(
        strike_cell_id="smoke-test-001",
        target_id="juice-shop-local",
        target_url="http://localhost:3001",
        scope_includes=["localhost:3001"],
        model="sonnet",
        timeout_seconds=300,
        toolchain_config={"max_turns": 30},
    )

    operator = ReconOperator()
    print("\n[*] Starting ReconOperator.execute()...\n")

    try:
        proof = await operator.execute(manifest)
    except Exception as exc:
        print(f"\n[FATAL] Operator execution crashed: {exc}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

    # Print results
    print("\n" + "=" * 60)
    print("RESULTS")
    print("=" * 60)
    print(f"Status:       {proof.status}")
    print(f"Confidence:   {proof.confidence}")
    print(f"Operator:     {proof.operator_name}")
    print(f"Turns:        {proof.metadata.get('turns', '?')}")
    print(f"Input tokens: {proof.metadata.get('input_tokens', '?')}")
    print(f"Output tokens:{proof.metadata.get('output_tokens', '?')}")
    print(f"Cost:         ${proof.metadata.get('cost_usd', 0):.4f}")
    print(f"Stop reason:  {proof.metadata.get('stop_reason', '?')}")
    print(f"Errors:       {proof.metadata.get('errors', [])}")
    print(f"Vulns found:  {len(proof.vulnerabilities_found)}")
    print(f"Exploits:     {len(proof.exploitation_results)}")
    print(f"Defenses:     {len(proof.defense_observations)}")
    print(f"Tool calls:   {proof.evidence.get('tool_calls_count', '?')}")

    # Check for deliverables
    deliverables = list(artifacts.glob("*.md"))
    print(f"\nDeliverables: {len(deliverables)}")
    for d in deliverables:
        size = d.stat().st_size
        print(f"  - {d.name} ({size:,} bytes)")

    # Show first 500 chars of final text
    final_text = proof.evidence.get("final_text", "")
    if final_text:
        print("\nFinal text (first 500 chars):")
        print("-" * 40)
        print(final_text[:500])
        print("-" * 40)

    # Save proof as JSON
    proof_path = base / "proof.json"
    proof_path.write_text(json.dumps(proof.to_dict(), indent=2, default=str))
    print(f"\nFull proof saved to: {proof_path}")

    print("\n[DONE]")


if __name__ == "__main__":
    asyncio.run(main())
