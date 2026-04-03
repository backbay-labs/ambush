"""
CLI commands for Aegis Net Phase 2: Verification Market.

Provides commands for:
- Task management (claim, submit, finalize)
- Challenges (submit, resolve)
- Settlement (settle, slash)
- DA obligations (check-da)
- QC (run QC batch)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

import click

if TYPE_CHECKING:
    from rich.console import Console


def get_console() -> Console:
    """Get rich console for output."""
    from rich.console import Console
    return Console()


# ============================================================================
# Task Commands
# ============================================================================


@click.group(name="task")
def task_group() -> None:
    """Verification task management."""
    pass


@task_group.command(name="create")
@click.argument("bundle_hash", type=str)
@click.option("--tier", type=int, default=0, help="Verification tier (0=spot, 1=full, 2=multi)")
@click.option("--reward", "reward_wei", type=int, default=0, help="Reward in wei")
@click.option("--stake", "stake_wei", type=int, default=0, help="Required stake in wei")
@click.option("--deadline", type=int, default=24, help="Liveness deadline in hours")
@click.option("--job-family", type=str, default="", help="Job family for routing")
@click.option("--json", "as_json", is_flag=True, help="JSON output")
def task_create(
    bundle_hash: str,
    tier: int,
    reward_wei: int,
    stake_wei: int,
    deadline: int,
    job_family: str,
    as_json: bool,
) -> None:
    """Create a new verification task for a bundle."""
    from cyntra.trust.protocol.task_protocol import TaskRegistry

    console = get_console()
    registry = TaskRegistry()

    task = registry.create_task(
        bundle_hash=bundle_hash,
        tier=tier,
        reward_wei=reward_wei,
        stake_wei=stake_wei,
        liveness_deadline_hours=deadline,
        job_family=job_family,
    )

    if as_json:
        console.print(json.dumps(task.to_dict(), indent=2))
    else:
        console.print(f"[green]✓[/green] Created task {task.task_id}")
        console.print(f"  Bundle: {bundle_hash}")
        console.print(f"  Tier: {tier}")
        console.print(f"  Reward: {reward_wei} wei")
        console.print(f"  Deadline: {deadline} hours")


@task_group.command(name="claim")
@click.argument("task_id", type=str)
@click.option("--verifier", type=str, required=True, help="Verifier public key")
@click.option("--json", "as_json", is_flag=True, help="JSON output")
def task_claim(task_id: str, verifier: str, as_json: bool) -> None:
    """Claim a verification task."""
    from cyntra.trust.protocol.task_protocol import TaskRegistry, TaskStateError

    console = get_console()

    # In production, this would load from persistent storage
    # For now, we demonstrate the API
    registry = TaskRegistry()

    try:
        # Note: In real usage, task would be loaded from storage
        console.print("[yellow]Note: This is a demonstration. In production, tasks are loaded from storage.[/yellow]")

        # Create a mock task for demonstration
        task = registry.create_task(bundle_hash="demo", tier=0)
        task.claim(verifier)

        if as_json:
            console.print(json.dumps(task.to_dict(), indent=2))
        else:
            console.print("[green]✓[/green] Task claimed")
            console.print(f"  Task: {task.task_id}")
            console.print(f"  Verifier: {verifier}")
            console.print(f"  Deadline: {task.deadline.isoformat() if task.deadline else 'N/A'}")

    except (TaskStateError, ValueError) as e:
        raise click.ClickException(str(e)) from None


@task_group.command(name="submit")
@click.argument("task_id", type=str)
@click.option("--verdict", type=Path, required=True, help="Path to verdict JSON file")
@click.option("--json", "as_json", is_flag=True, help="JSON output")
def task_submit(task_id: str, verdict: Path, as_json: bool) -> None:
    """Submit a verification verdict for a task."""
    from cyntra.trust.protocol.task_protocol import TaskRegistry, TaskStateError, Verdict

    console = get_console()

    if not verdict.exists():
        raise click.ClickException(f"Verdict file not found: {verdict}")

    try:
        verdict_data = json.loads(verdict.read_text())
        verdict_obj = Verdict.from_dict(verdict_data)
    except (json.JSONDecodeError, KeyError) as e:
        raise click.ClickException(f"Invalid verdict file: {e}") from None

    console.print("[yellow]Note: This is a demonstration. In production, tasks are loaded from storage.[/yellow]")

    # Demonstrate the API
    registry = TaskRegistry()
    task = registry.create_task(bundle_hash="demo", tier=0)
    task.claim("demo_verifier")

    try:
        task.submit(verdict_obj)

        if as_json:
            console.print(json.dumps(task.to_dict(), indent=2))
        else:
            console.print("[green]✓[/green] Verdict submitted")
            console.print(f"  Task: {task.task_id}")
            console.print(f"  Outcome: {verdict_obj.outcome.value}")
            console.print(f"  Gates: {verdict_obj.gates_passed}/{verdict_obj.gates_checked} passed")

    except TaskStateError as e:
        raise click.ClickException(str(e)) from None


@task_group.command(name="list")
@click.option("--state", type=str, help="Filter by state (open, claimed, submitted, finalized, disputed, slashed)")
@click.option("--verifier", type=str, help="Filter by verifier")
@click.option("--json", "as_json", is_flag=True, help="JSON output")
def task_list(state: str | None, verifier: str | None, as_json: bool) -> None:
    """List verification tasks."""
    from cyntra.trust.protocol.task_protocol import TaskRegistry, TaskState

    console = get_console()
    registry = TaskRegistry()

    # In production, this would load from persistent storage
    tasks = list(registry._tasks.values())

    if state:
        try:
            filter_state = TaskState(state)
            tasks = [t for t in tasks if t.state == filter_state]
        except ValueError:
            raise click.ClickException(f"Invalid state: {state}") from None

    if verifier:
        tasks = [t for t in tasks if t.verifier == verifier]

    if as_json:
        console.print(json.dumps([t.to_dict() for t in tasks], indent=2))
    else:
        if not tasks:
            console.print("No tasks found.")
            return

        from rich.table import Table
        table = Table(title="Verification Tasks")
        table.add_column("Task ID", style="cyan")
        table.add_column("Bundle", max_width=20)
        table.add_column("Tier")
        table.add_column("State")
        table.add_column("Verifier", max_width=20)

        for task in tasks:
            state_color = {
                TaskState.OPEN: "green",
                TaskState.CLAIMED: "yellow",
                TaskState.SUBMITTED: "blue",
                TaskState.FINALIZED: "green",
                TaskState.DISPUTED: "red",
                TaskState.SLASHED: "red",
            }.get(task.state, "white")

            table.add_row(
                task.task_id[:16] + "...",
                task.bundle_hash[:16] + "...",
                str(task.tier),
                f"[{state_color}]{task.state.value}[/{state_color}]",
                (task.verifier[:16] + "...") if task.verifier else "-",
            )

        console.print(table)


# ============================================================================
# Challenge Commands
# ============================================================================


@click.group(name="challenge")
def challenge_group() -> None:
    """Challenge management."""
    pass


@challenge_group.command(name="submit")
@click.argument("task_id", type=str)
@click.option("--challenger", type=str, required=True, help="Challenger public key")
@click.option("--evidence", type=Path, required=True, help="Path to evidence bundle")
@click.option("--description", type=str, default="", help="Challenge description")
@click.option("--json", "as_json", is_flag=True, help="JSON output")
def challenge_submit(
    task_id: str,
    challenger: str,
    evidence: Path,
    description: str,
    as_json: bool,
) -> None:
    """Submit a challenge against a verification verdict."""
    import hashlib

    from cyntra.trust.protocol.challenges import ChallengeEvidence, ChallengeRegistry

    console = get_console()

    if not evidence.exists():
        raise click.ClickException(f"Evidence file not found: {evidence}")

    # Compute evidence hash
    evidence_content = evidence.read_bytes()
    evidence_hash = "0x" + hashlib.sha256(evidence_content).hexdigest()

    evidence_obj = ChallengeEvidence(
        evidence_hash=evidence_hash,
        evidence_uri=f"file://{evidence.absolute()}",
        description=description,
    )

    registry = ChallengeRegistry()

    try:
        challenge = registry.submit_challenge(
            task_id=task_id,
            challenger=challenger,
            evidence=evidence_obj,
        )

        if as_json:
            console.print(json.dumps(challenge.to_dict(), indent=2))
        else:
            console.print("[green]✓[/green] Challenge submitted")
            console.print(f"  Challenge ID: {challenge.challenge_id}")
            console.print(f"  Task: {task_id}")
            console.print(f"  Bond: {challenge.challenge_bond_wei} wei")
            console.print(f"  Evidence hash: {evidence_hash[:20]}...")

    except ValueError as e:
        raise click.ClickException(str(e)) from None


@challenge_group.command(name="resolve")
@click.argument("challenge_id", type=str)
@click.option("--upheld/--rejected", required=True, help="Whether to uphold the challenge")
@click.option("--reason", type=str, required=True, help="Reason for resolution")
@click.option("--arbiter", type=str, help="Arbiter public key")
@click.option("--json", "as_json", is_flag=True, help="JSON output")
def challenge_resolve(
    challenge_id: str,
    upheld: bool,
    reason: str,
    arbiter: str | None,
    as_json: bool,
) -> None:
    """Resolve a pending challenge."""
    from cyntra.trust.protocol.challenges import ChallengeRegistry

    console = get_console()
    registry = ChallengeRegistry()

    console.print("[yellow]Note: This is a demonstration. In production, challenges are loaded from storage.[/yellow]")

    try:
        # In production, challenge would be loaded from storage
        challenge = registry.resolve_challenge(
            challenge_id=challenge_id,
            upheld=upheld,
            reason=reason,
            arbiter=arbiter,
        )

        if as_json:
            console.print(json.dumps(challenge.to_dict(), indent=2))
        else:
            status = "[green]UPHELD[/green]" if upheld else "[red]REJECTED[/red]"
            console.print(f"Challenge {status}")
            console.print(f"  Challenge ID: {challenge_id}")
            console.print(f"  Reason: {reason}")
            if challenge.payout_wei > 0:
                console.print(f"  Payout: {challenge.payout_wei} wei")

    except ValueError as e:
        raise click.ClickException(str(e)) from None


@challenge_group.command(name="list")
@click.option("--task", "task_id", type=str, help="Filter by task ID")
@click.option("--challenger", type=str, help="Filter by challenger")
@click.option("--pending", is_flag=True, help="Show only pending challenges")
@click.option("--json", "as_json", is_flag=True, help="JSON output")
def challenge_list(
    task_id: str | None,
    challenger: str | None,
    pending: bool,
    as_json: bool,
) -> None:
    """List challenges."""
    from cyntra.trust.protocol.challenges import ChallengeRegistry, ChallengeStatus

    console = get_console()
    registry = ChallengeRegistry()

    challenges = list(registry._challenges.values())

    if task_id:
        challenges = [c for c in challenges if c.task_id == task_id]
    if challenger:
        challenges = [c for c in challenges if c.challenger == challenger]
    if pending:
        challenges = [c for c in challenges if c.status == ChallengeStatus.PENDING]

    if as_json:
        console.print(json.dumps([c.to_dict() for c in challenges], indent=2))
    else:
        if not challenges:
            console.print("No challenges found.")
            return

        from rich.table import Table
        table = Table(title="Challenges")
        table.add_column("Challenge ID", style="cyan")
        table.add_column("Task", max_width=16)
        table.add_column("Challenger", max_width=16)
        table.add_column("Status")
        table.add_column("Bond (wei)")

        for c in challenges:
            status_color = {
                ChallengeStatus.PENDING: "yellow",
                ChallengeStatus.UPHELD: "green",
                ChallengeStatus.REJECTED: "red",
                ChallengeStatus.EXPIRED: "dim",
                ChallengeStatus.WITHDRAWN: "dim",
            }.get(c.status, "white")

            table.add_row(
                c.challenge_id[:16] + "...",
                c.task_id[:12] + "...",
                c.challenger[:12] + "...",
                f"[{status_color}]{c.status.value}[/{status_color}]",
                str(c.challenge_bond_wei),
            )

        console.print(table)


# ============================================================================
# DA Obligation Commands
# ============================================================================


@click.command(name="check-da")
@click.argument("bundle_hash", type=str)
@click.option("--uris", type=str, multiple=True, help="Storage URIs to check")
@click.option("--min-fetchers", type=int, default=3, help="Minimum successful fetchers")
@click.option("--json", "as_json", is_flag=True, help="JSON output")
def check_da(
    bundle_hash: str,
    uris: tuple[str, ...],
    min_fetchers: int,
    as_json: bool,
) -> None:
    """Check data availability for a bundle.

    Verifies that a bundle is retrievable from the specified storage URIs
    using multiple independent fetchers.
    """
    import asyncio

    from cyntra.trust.availability.checker import MultiFetcherChecker
    from cyntra.trust.availability.obligation import AvailabilityObligation

    console = get_console()

    if not uris:
        raise click.ClickException("At least one --uris is required")

    obligation = AvailabilityObligation(
        bundle_hash=bundle_hash,
        availability_window_hours=72,
        min_fetchers=min_fetchers,
        storage_uris=list(uris),
        da_bond_wei=0,
    )

    checker = MultiFetcherChecker.default()

    async def run_check():
        return await checker.check_obligation(obligation, slash_on_failure=False)

    result = asyncio.run(run_check())

    if as_json:
        console.print(json.dumps(result.to_dict(), indent=2))
    else:
        status = "[green]AVAILABLE[/green]" if result.available else "[red]UNAVAILABLE[/red]"
        console.print(f"Bundle: {bundle_hash[:20]}...")
        console.print(f"Status: {status}")
        console.print(f"Fetchers: {result.successful_fetchers}/{result.required_fetchers} required")
        console.print(f"Hash verified: {'Yes' if result.hash_verified else 'No'}")
        console.print(f"Mean latency: {result.mean_latency_ms:.1f} ms")

        if result.fetchers:
            console.print("\n[bold]Fetcher results:[/bold]")
            for f in result.fetchers:
                icon = "[green]✓[/green]" if f.success else "[red]✗[/red]"
                console.print(f"  {icon} {f.fetcher_id}: {f.latency_ms:.1f} ms")
                if f.error:
                    console.print(f"      Error: {f.error}")

    if not result.available:
        raise SystemExit(1)


# ============================================================================
# Settlement Commands
# ============================================================================


@click.group(name="settle")
def settle_group() -> None:
    """Settlement operations."""
    pass


@settle_group.command(name="finalize")
@click.argument("task_id", type=str)
@click.option("--json", "as_json", is_flag=True, help="JSON output")
def settle_finalize(task_id: str, as_json: bool) -> None:
    """Finalize a verification task and trigger payout."""
    from cyntra.trust.settlement.court import SettlementCourt

    console = get_console()
    _ = SettlementCourt()  # Initialize to verify import works

    console.print("[yellow]Note: This is a demonstration. In production, tasks are loaded from storage.[/yellow]")

    # In production, task would be loaded and validated
    console.print(f"Would finalize task: {task_id}")
    console.print("Call court.finalize_verdict(task) in production code.")


@settle_group.command(name="slash")
@click.argument("task_id", type=str)
@click.option("--reason", type=str, required=True, help="Reason for slashing")
@click.option("--json", "as_json", is_flag=True, help="JSON output")
def settle_slash(task_id: str, reason: str, as_json: bool) -> None:
    """Slash a verifier for failure."""
    from cyntra.trust.settlement.court import SettlementCourt

    console = get_console()
    _ = SettlementCourt()  # Initialize to verify import works

    console.print("[yellow]Note: This is a demonstration. In production, tasks are loaded from storage.[/yellow]")
    console.print(f"Would slash task: {task_id}")
    console.print(f"Reason: {reason}")


@settle_group.command(name="receipts")
@click.option("--task", "task_id", type=str, help="Filter by task ID")
@click.option("--verifier", type=str, help="Filter by verifier")
@click.option("--limit", type=int, default=20, help="Maximum receipts to show")
@click.option("--json", "as_json", is_flag=True, help="JSON output")
def settle_receipts(
    task_id: str | None,
    verifier: str | None,
    limit: int,
    as_json: bool,
) -> None:
    """List settlement receipts."""
    from cyntra.trust.settlement.court import SettlementCourt

    console = get_console()
    court = SettlementCourt()

    receipts = court.get_receipts(task_id=task_id, verifier=verifier, limit=limit)

    if as_json:
        console.print(json.dumps([r.to_dict() for r in receipts], indent=2))
    else:
        if not receipts:
            console.print("No receipts found.")
            return

        from rich.table import Table
        table = Table(title="Settlement Receipts")
        table.add_column("Receipt ID", style="cyan")
        table.add_column("Task", max_width=16)
        table.add_column("Type")
        table.add_column("Verifier", max_width=16)
        table.add_column("Payout (wei)")
        table.add_column("Settled At")

        for r in receipts:
            table.add_row(
                r.receipt_id[:16] + "...",
                r.task_id[:12] + "...",
                r.settlement_type,
                r.verifier[:12] + "..." if r.verifier else "-",
                str(r.payout_wei),
                r.settled_at.strftime("%Y-%m-%d %H:%M"),
            )

        console.print(table)


# ============================================================================
# QC Commands
# ============================================================================


@click.command(name="qc")
@click.option("--sample-rate", type=float, default=0.05, help="Sample rate for re-verification (0.0-1.0)")
@click.option("--seed", type=int, help="Random seed for reproducible selection")
@click.option("--json", "as_json", is_flag=True, help="JSON output")
def qc_run(sample_rate: float, seed: int | None, as_json: bool) -> None:
    """Run QC random re-verification selection.

    Selects a random sample of finalized PASS verdicts for re-verification.
    """
    from cyntra.trust.protocol.qc import QualityController, ReVerificationConfig

    console = get_console()

    config = ReVerificationConfig(sample_rate=sample_rate)
    qc = QualityController(config=config)

    selection = qc.select_for_reverification(seed=seed)

    if as_json:
        console.print(json.dumps(selection.to_dict(), indent=2))
    else:
        console.print("[bold]QC Selection[/bold]")
        console.print(f"  Sample rate: {selection.sample_rate:.1%}")
        console.print(f"  Total eligible: {selection.total_eligible}")
        console.print(f"  Selected: {len(selection.selected_tasks)}")
        console.print(f"  Seed: {selection.selection_seed}")

        if selection.selected_tasks:
            console.print("\n[bold]Selected tasks:[/bold]")
            for task in selection.selected_tasks:
                console.print(f"  - {task.task_id}")


# ============================================================================
# Registration function
# ============================================================================


def register_phase2_commands(trust_group: click.Group) -> None:
    """Register Phase 2 commands under the trust group."""
    trust_group.add_command(task_group)
    trust_group.add_command(challenge_group)
    trust_group.add_command(check_da)
    trust_group.add_command(settle_group)
    trust_group.add_command(qc_run)


# Export for CLI integration
__all__ = [
    "task_group",
    "challenge_group",
    "check_da",
    "settle_group",
    "qc_run",
    "register_phase2_commands",
]
