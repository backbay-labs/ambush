#!/usr/bin/env bash
#
# Decision-core dependency boundary gate (DCORE-03, DCORE-04).
#
# WHY THIS EXISTS
#   Phase 292 carved `swarm-policy`'s rate-limit and governance predicates into
#   a pure, clock-injected core (`crates/swarm-policy/src/formal_core.rs`) so
#   phases 293 (Kani) and 294 (named safety properties) have a machine-checkable
#   proof surface: no transport, no telemetry client, no CLI parser, no IO. A
#   proof engine reasons about the code it is given; a transport or telemetry
#   dependency arriving in that surface -- even transitively, even only in a
#   dev-dependency's normal graph -- drags network IO and non-determinism into
#   exactly the region 293/294 need to be pure. `swarm-policy` is measured clean
#   of all seven today (see the verification block below); this gate is
#   enforce-only -- there is nothing to remove, only something to keep true.
#
#   ADR 0009 ships the same idea one layer up (the TCB as a whole must never
#   reach a transport) and `tools/check-workspace-layering.sh` is its executable
#   form. This gate is narrower on purpose: DCORE-03 names `swarm-policy`
#   specifically and a longer forbidden list (`opentelemetry*`, `x509-parser` on
#   top of the four TCBOUND-03 names), because the decision core is where the
#   proof obligation actually lives, not merely where trust concentrates.
#
# WHERE THIS LIVES, AND WHY NOT WHERE THE PLAN SAYS
#   The phase-292 plan names `docs/adr/0012-...` and
#   `scripts/check-decision-core-boundary.sh`. There is no `docs/adr/` and no
#   `scripts/` directory in this repository and never has been -- ADRs live in
#   `docs/decisions/` (0001-0011 exist; this is 0012) and every gate lives in
#   `tools/`, which `tools/check-gates-wired.sh` enumerates by globbing
#   `tools/check-*.sh`. Landing this gate at the plan's path would have made it
#   invisible to the wiring gate -- an unrun gate, which is the exact failure
#   `check-gates-wired.sh` exists to prevent. Same deviation ADR 0009 already
#   recorded for TCBOUND-01/03; recorded again here in ADR 0012.
#
# MECHANISM: THE RESOLVED GRAPH, NOT THE MANIFEST
#   `crates/swarm-policy/Cargo.toml` names five normal dependencies today, none
#   of them forbidden -- a `grep` of that one file would say "clean" and mean
#   almost nothing. ADR 0008/0009's lesson is that a transport can arrive
#   through a crate `swarm-policy` DOES depend on (`swarm-core` today, or
#   anything added to it later) without a single line of `swarm-policy`'s own
#   manifest changing. So this gate reads `cargo metadata`'s RESOLVED graph --
#   `resolve.nodes[...].deps[...].dep_kinds` -- which is the feature- and
#   version-resolved truth, and walks every NORMAL edge (dev/build deps are out
#   of scope: a proof engine over `formal_core.rs` never compiles
#   `swarm-policy`'s dev or build profile) reachable from `swarm-policy` itself.
#   `cargo metadata` resolves without compiling, so this is one fast call, not a
#   build. python3 does the walk (no `jq`; ubuntu-latest guarantees python3 and
#   four gates already rely on plain python3, per `check-workspace-layering.sh`
#   and `check-gates-wired.sh`).
#
# THE SELF-TEST IS THE POINT
#   A gate never observed to fail is not a gate -- `.planning/STATE.md`
#   catalogues that shape of defect repeatedly, and `check-workspace-layering.sh`
#   answers it with a real generated cargo fixture. This gate answers the same
#   requirement more cheaply: the forbidden-name walk is one function,
#   `scan_forbidden(graph, name_of, root)`, that takes a generic
#   node -> [children] mapping and a display-name lookup. The REAL check builds
#   that mapping from `cargo metadata`'s resolved NORMAL edges and calls it
#   once; the SELF-TEST builds a small synthetic mapping in memory -- a clean
#   control shaped like `swarm-policy`'s real tree, then the same shape with a
#   forbidden crate planted directly, planted two hops away behind a stand-in
#   for `swarm-core` (the ADR 0008 smuggling shape), and planted as an
#   `opentelemetry*` family member to prove the ban is a prefix rule, not one
#   exact name -- and calls the IDENTICAL function on each. Nothing here writes
#   to any real `Cargo.toml`/`Cargo.lock`, spawns `cargo`, or touches the
#   filesystem outside the one scratch metadata JSON this script's own `cargo
#   metadata` call produces (cleaned up by the trap below); the self-test is
#   pure Python data, so there is no fixture to build or tear down. Every
#   invocation runs the self-test AND the real check; either one failing fails
#   the gate.
#
# REFUSING TO PASS SILENTLY
#   Three states are treated as vacuity (exit 2), because each is a state in
#   which a broken gate would otherwise report a clean boundary over a region it
#   never inspected:
#     - `swarm-policy` does not resolve to exactly one package id (a rename, or
#       an ambiguous workspace)
#     - the resolved graph is empty
#     - none of the seven forbidden names appear anywhere in the ENTIRE
#       resolved graph, so the rule that bans them from `swarm-policy` could
#       never fire regardless of what `swarm-policy` reaches (all seven are
#       real dependencies of other crates in this workspace today -- see the
#       ADR -- so this should never trip while that stays true)
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

WORK_DIR="$(mktemp -d)"
cleanup() { rm -rf "$WORK_DIR"; }
trap cleanup EXIT

ENGINE="$WORK_DIR/decision_core_engine.py"

cat >"$ENGINE" <<'PY'
"""Decision-core dependency boundary engine (DCORE-03/04).

Usage: decision_core_engine.py <cargo-metadata.json>

Every invocation does two things, in order, and either failing fails the run:
  1. a self-test of scan_forbidden() against synthetic, in-memory dependency
     graphs (direct hit, transitive/"smuggled" hit, opentelemetry* prefix hit,
     and a clean control);
  2. the real check, over the resolved NORMAL dependency graph the given
     cargo-metadata.json describes.

Exit codes:
  0  self-test passed AND no forbidden crate is reachable from swarm-policy
  1  self-test failed, or a forbidden crate IS reachable (DCORE-VIOLATION[...]
     / DCORE-SELFTEST-FAILED[...] on stderr)
  2  vacuity -- the check could not establish that it inspected anything
     (DCORE-VACUITY[...] on stderr)
"""

import json
import sys
from collections import deque

CRATE = "swarm-policy"

# DCORE-03, verbatim. "opentelemetry*" is a family (opentelemetry,
# opentelemetry_sdk, opentelemetry-otlp, ...), matched below by prefix; the
# other six are matched by exact package name.
FORBIDDEN_EXACT = (
    "axum",
    "hyper",
    "tokio-rustls",
    "reqwest",
    "clap",
    "x509-parser",
)
FORBIDDEN_PREFIX = "opentelemetry"
FORBIDDEN_DISPLAY = FORBIDDEN_EXACT + (FORBIDDEN_PREFIX + "*",)


class Vacuity(Exception):
    pass


def is_forbidden(name):
    return name in FORBIDDEN_EXACT or name.startswith(FORBIDDEN_PREFIX)


def scan_forbidden(graph, name_of, root):
    """Breadth-first search of `graph` (node -> iterable of child nodes) from
    `root`, using `name_of(node)` to name each node, for the shortest path to
    every reachable node whose name is forbidden.

    This is the ONE piece of logic both callers below share: `check_real`
    builds `graph`/`name_of` from cargo metadata's resolved NORMAL edges and
    calls this; `self_test` builds a synthetic `graph`/`name_of` in memory and
    calls the SAME function, unmodified. Neither caller reimplements the walk,
    so a self-test pass is evidence about the function the real check runs,
    not about a second, unrelated one.

    Returns [(forbidden_name, [names of root..hit]), ...], one entry per
    distinct forbidden name reachable, in BFS (shortest-path) order.
    """
    visited = {root}
    parent = {root: None}
    queue = deque([root])
    found = []
    seen_names = set()
    while queue:
        current = queue.popleft()
        for child in graph.get(current, ()):
            if child in visited:
                continue
            visited.add(child)
            parent[child] = current
            queue.append(child)
            child_name = name_of(child)
            if is_forbidden(child_name) and child_name not in seen_names:
                seen_names.add(child_name)
                path = []
                node = child
                while node is not None:
                    path.append(name_of(node))
                    node = parent[node]
                path.reverse()
                found.append((child_name, path))
    return found


def self_test():
    """Run scan_forbidden() over synthetic graphs; return the failure count.

    Every case is plain Python data -- no cargo invocation, no temp fixture
    workspace, no file outside this process. That is deliberate: the unit
    under test is a graph walk, and a synthetic graph exercises it exactly as
    directly as a generated cargo project would, without a second `cargo
    metadata` call's latency or its own chance of drifting from what it means
    to test.
    """
    # A shape matching swarm-policy's real one: crate -> swarm-core -> a few
    # leaf libraries, nothing forbidden anywhere.
    clean = {
        "swarm-policy": ["swarm-core", "serde", "serde_json", "thiserror", "tracing"],
        "swarm-core": ["anyhow", "ed25519-dalek", "hex", "tracing"],
        "serde": [],
        "serde_json": [],
        "thiserror": [],
        "tracing": [],
        "anyhow": [],
        "ed25519-dalek": [],
        "hex": [],
    }

    direct = {k: list(v) for k, v in clean.items()}
    direct["swarm-policy"] = direct["swarm-policy"] + ["reqwest"]
    direct["reqwest"] = []

    # THE ADR 0008/0009 LESSON: a forbidden crate smuggled in two hops behind
    # swarm-core. swarm-policy's own manifest never changes in this scenario --
    # a Cargo.toml grep of swarm-policy would call this clean. Only reading the
    # resolved graph catches it.
    smuggled = {k: list(v) for k, v in clean.items()}
    smuggled["swarm-core"] = smuggled["swarm-core"] + ["telemetry-shim"]
    smuggled["telemetry-shim"] = ["hyper"]
    smuggled["hyper"] = []

    # opentelemetry* is a family ban, not one exact name.
    otel = {k: list(v) for k, v in clean.items()}
    otel["swarm-policy"] = otel["swarm-policy"] + ["opentelemetry-otlp"]
    otel["opentelemetry-otlp"] = []

    cases = [
        ("clean synthetic graph reports nothing", clean, []),
        ("a direct forbidden dependency is caught", direct, ["reqwest"]),
        (
            "a forbidden dependency smuggled two hops behind swarm-core is caught",
            smuggled,
            ["hyper"],
        ),
        (
            "an opentelemetry* family member is caught by the prefix rule",
            otel,
            ["opentelemetry-otlp"],
        ),
    ]

    failures = 0
    for label, graph, expected_names in cases:
        found = scan_forbidden(graph, lambda node: node, "swarm-policy")
        found_names = sorted(name for name, _ in found)
        if found_names != sorted(expected_names):
            failures += 1
            print(
                f"::error::DCORE-SELFTEST-FAILED[{label}] expected forbidden "
                f"name(s) {sorted(expected_names)!r}, got {found_names!r}",
                file=sys.stderr,
            )
            continue
        detail = ", ".join(f"{n} via {' -> '.join(p)}" for n, p in found) or "none"
        print(f"  ok  {label}  (found: {detail})")

    return failures, len(cases)


def check_real(metadata_path):
    with open(metadata_path, "r", encoding="utf-8") as handle:
        meta = json.load(handle)

    packages = {p["id"]: p for p in meta["packages"]}
    resolve = meta.get("resolve") or {}
    nodes = resolve.get("nodes") or []
    if not nodes:
        raise Vacuity("cargo metadata reported an empty resolved dependency graph")

    def name_of(pkg_id):
        return packages[pkg_id]["name"]

    root_ids = [pid for pid in packages if name_of(pid) == CRATE]
    if len(root_ids) != 1:
        raise Vacuity(
            f"'{CRATE}' resolved to {len(root_ids)} package id(s) in cargo "
            "metadata (expected exactly 1); a rename or an ambiguous workspace "
            "would silently point this gate at nothing"
        )
    root = root_ids[0]

    all_names = {p["name"] for p in meta["packages"]}
    if not any(is_forbidden(n) for n in all_names):
        raise Vacuity(
            "none of the forbidden crate names appear anywhere in the resolved "
            "dependency graph, so the rule banning them from "
            f"'{CRATE}' could never fire: " + ", ".join(FORBIDDEN_DISPLAY)
        )

    graph = {}
    for node in nodes:
        graph[node["id"]] = [
            dep["pkg"]
            for dep in node["deps"]
            # `kind: null` is cargo metadata's spelling of "normal". Dev- and
            # build-dependency edges are deliberately excluded: a Kani proof
            # over formal_core.rs never compiles swarm-policy's dev or build
            # profile, so those graphs are out of scope for this boundary
            # (mirrors how check-workspace-layering.sh's RULE 3 reasons about
            # the resolved NORMAL graph specifically).
            if any(k["kind"] is None for k in dep["dep_kinds"])
        ]

    return scan_forbidden(graph, name_of, root)


def main(argv):
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2

    print("self-test: proving the scan can both pass and catch a plant before trusting it")
    failures, total = self_test()
    if failures:
        print(
            f"\n{failures} of {total} self-test case(s) failed; the scan is not "
            "behaving as documented, so its verdict on the real graph below "
            "would mean nothing. Fix the engine first.",
            file=sys.stderr,
        )
        return 1
    print(f"self-test: {total} case(s) passed (1 control, {total - 1} deliberately planted)\n")

    metadata_path = argv[1]
    violations = check_real(metadata_path)
    if violations:
        for name, path in violations:
            print(
                f"::error::DCORE-VIOLATION[{CRATE}] forbidden crate '{name}' is "
                "reachable on the resolved NORMAL dependency graph via "
                f"{' -> '.join(path)} (DCORE-03; see ADR 0012)",
                file=sys.stderr,
            )
        return 1

    print(
        f"decision-core boundary holds: none of {len(FORBIDDEN_DISPLAY)} "
        f"forbidden crate name(s) ({', '.join(FORBIDDEN_DISPLAY)}) are "
        f"reachable from '{CRATE}' on the resolved NORMAL dependency graph"
    )
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except Vacuity as exc:
        print(f"::error::DCORE-VACUITY[guard] {exc}", file=sys.stderr)
        sys.exit(2)
PY

# `--all-features` for the same reason check-workspace-layering.sh gives: a
# feature-gated dependency is still a dependency somebody can switch on, and
# swarm-policy carries no [features] today only by choice, not by cargo's
# guarantee. `--locked` so this gate can never rewrite Cargo.lock as a side
# effect of running. No `--offline`: this is the real workspace, which has
# registry dependencies, and failing on a cold cargo cache would be a false
# red rather than a real one.
METADATA="$WORK_DIR/metadata.json"
cargo metadata --format-version 1 --all-features --locked >"$METADATA"

python3 "$ENGINE" "$METADATA"
