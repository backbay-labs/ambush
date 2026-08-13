#!/usr/bin/env bash
#
# Trusted-computing-base layering gate (TCBOUND-03, TCBOUND-04).
#
# WHY THIS EXISTS
#   ADR 0009 names `swarm-policy`, `swarm-crypto` and `swarm-spine` as the
#   trusted computing base and states in negative-space form what they must never
#   depend on. Prose in an ADR is not a boundary. This script is that ADR made
#   executable, and it is the only thing standing between the TCB and the six
#   milestones of capability queued on top of it.
#
#   `.planning/STATE.md` catalogues ten shipped defects of one shape: a check
#   reporting success over a region it never inspected. A layering script that
#   has never been observed to fail would be the eleventh, so this one carries a
#   FIXTURE that runs on every invocation: it builds a miniature workspace with
#   the same crate names and the same shape as the real one, runs the SAME rule
#   engine over it unmodified, proves the clean fixture passes, then breaks it
#   seven different ways and proves each break is caught with the right
#   diagnostic. See "THE FIXTURE" below.
#
# WHERE THIS LIVES, AND WHY NOT WHERE THE REQUIREMENT SAYS
#   TCBOUND-03 names `scripts/check-workspace-layering.sh`. There is no
#   `scripts/` directory in this repository and never has been; every gate lives
#   in `tools/` and `tools/check-gates-wired.sh` enumerates `tools/check-*.sh`.
#   Landing it at the requirement's path would have made it invisible to the
#   wiring gate -- an unrun gate, which is the exact failure `tools/check-gates-
#   wired.sh` exists to prevent. Deviation recorded in ADR 0009 and in
#   `.planning/REQUIREMENTS.md`.
#
# DECLARED EDGES vs THE RESOLVED GRAPH
#   Phase 282 shipped a wrong claim by conflating these, so this gate states
#   which rule reads which, and why, for every rule it enforces.
#
#   A DECLARED edge is a line in a crate's own `Cargo.toml`, read here from
#   `cargo metadata`'s `packages[].dependencies` -- which carries `kind`
#   (normal / dev / build) and reports the real PACKAGE name, so
#   `wire = { package = "reqwest" }` is still matched as `reqwest`.
#
#   A RESOLVED edge is a path through `resolve.nodes`, the feature- and
#   version-resolved graph. `swarm-runtime` declares `axum` only under
#   `[dev-dependencies]` and yet still reaches `axum` on its NORMAL resolved
#   profile, through `swarm-ingest-tetragon -> tonic -> axum` (ADR 0008). The two
#   readings genuinely disagree, and picking one silently is what made the
#   earlier claim wrong.
#
#   RULE 1 and RULE 2 read DECLARED edges, in all three kinds. A crate's manifest
#   is what its author controls and what a reviewer of that crate can be held to,
#   and TCBOUND-03's own wording is "a DIRECT clap/axum/reqwest/hyper
#   dependency". Dev and build kinds are included deliberately: ADR 0008's whole
#   subject is an `axum` edge that is "only" a dev-dependency and still compiles
#   a transport stack into five of that crate's targets. A TCB crate acquiring a
#   HTTP parser for its tests has widened the TCB's attack surface just the same.
#
#   RULE 3 reads the RESOLVED NORMAL graph, and it is the rule that would have
#   caught a transport smuggled in through `swarm-core`. It cannot be enforced
#   at zero, because the shipped tree already violates it:
#
#     $ cargo tree -p swarm-spine -i reqwest -e normal
#     reqwest v0.12.28
#     └── swarm-response v0.1.0
#         └── swarm-spine v0.1.0
#
#   `swarm-spine` declares `swarm-response` (it embeds `ResponseReceipt` and
#   `ResponseFailure` in its envelopes) and `swarm-response` declares `reqwest`
#   for the HTTP EDR adapter, so the TCB reaches `reqwest` and `hyper` today.
#   Closing that is a dependency inversion inside `swarm-spine`, not a gate.
#   Rather than narrow the rule until it passes -- "satisfying a grep without
#   changing what gets built", the alternative SPLIT-01 explicitly rejected --
#   the two edges are recorded below as a BASELINE, exactly as
#   `tools/check-visibility-baseline.sh` records its three accepted widenings. A
#   THIRD resolved transport edge fails the build, and so does a baseline entry
#   that no longer holds, so the exemption cannot quietly outlive its reason.
#
#   RULE 4 (advisory lane, TCBOUND-04) reads BOTH, for the same reasons.
#
# WHAT "PRODUCT CRATE" MEANS HERE
#   TCBOUND-03 names three product crates: `swarm-cli`, `swarm-runtime`,
#   `swarm-runtime-http`. That list was written before phase 282 split
#   `swarm-runtime` into seven crates, so taken literally it would let the same
#   inversion in through `swarm-agents` or `swarm-ingest-runtime`. The set is
#   therefore DERIVED, not typed:
#
#     closure    = the TCB crates plus everything they reach on the resolved
#                  normal graph  (measured: swarm-core, swarm-crypto,
#                  swarm-policy, swarm-response, swarm-spine, swarm-whisker)
#     downstream = workspace crates outside that closure which reach a TCB crate
#
#   `downstream` is "strictly above the TCB", which is what a TCB crate must
#   never depend on. It is self-maintaining: a crate added tomorrow is
#   classified by its edges, not by remembering to add it here. The gate asserts
#   TCBOUND-03's three named crates are IN the derived set, so the requirement's
#   own list is checked rather than replaced.
#
#   The derivation excludes the closure deliberately: `swarm-spine` depending on
#   `swarm-response` is not an inversion, it is the TCB's own internal layering,
#   and a rule that flagged it would fail on day one for the wrong reason.
#
# WHAT THIS GATE DOES NOT CATCH, BY CONSTRUCTION
#   A TCB crate taking a NORMAL dependency on a downstream crate is a cycle --
#   `swarm-runtime` already depends on `swarm-policy` -- and `cargo metadata`
#   refuses to resolve it. That failure is real (this script runs under `set -e`
#   and dies with cargo's message) but it is cargo speaking, not this gate. What
#   cargo permits, and what this gate is therefore actually for, is:
#     - dev- and build-dependency cycles, which cargo allows outright
#     - transitive transport edges, which cargo has no opinion about
#     - the advisory-lane rule, whose crates are not in a cycle at all
#   All seven fixture variants below exercise cases cargo itself accepts.
#
# THE FIXTURE
#   `tools/check-visibility-baseline.sh` pins its parser with a table of inputs
#   and expected outputs. That works there because the unit under test is a
#   regex. Here the unit under test is a rule engine reading `cargo metadata`,
#   so a table of hand-written JSON would prove only that the engine agrees with
#   a mock -- the "pinned against a string the real solver never emits" defect
#   STATE.md records.
#
#   So the fixture is a REAL cargo workspace, generated into a temp directory,
#   with the real crate names and stub crates literally named `axum`, `clap`,
#   `hyper` and `reqwest` (path dependencies, so no registry and no network).
#   `cargo metadata` really runs on it and the real engine really reads the
#   result. The fixture is shape-preserving: it reproduces the same TCB closure,
#   the same downstream set membership for the three named product crates, and
#   the same two baseline resolved transport edges, so the engine runs with its
#   policy and baseline UNMODIFIED. Nothing about the fixture is configured
#   differently from the real check.
#
#   Variant 0 is the unbroken fixture and must EXIT 0. Without that control the
#   other seven prove nothing: a fixture that fails for an unrelated reason
#   would "catch" every violation while catching none.
#
# REFUSING TO PASS SILENTLY
#   Every one of these is a hard failure with exit code 2, because each is a
#   state in which a broken gate would otherwise report a clean boundary over a
#   region it never inspected:
#     - zero workspace members parsed
#     - a policy-named crate that is not a workspace member (a rename)
#     - an empty derived downstream set
#     - one of TCBOUND-03's three named product crates missing from it
#     - a transport package name that appears nowhere in the graph, so the rule
#       that bans it could never fire
#     - a registered advisory-lane module path that no longer exists, so the
#       lane moved and the rule is aimed at the wrong crate
#     - an advisory-lane host crate that is not a workspace member
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

WORK_DIR="$(mktemp -d)"
cleanup() { rm -rf "$WORK_DIR"; }
trap cleanup EXIT

ENGINE="$WORK_DIR/layering_engine.py"

cat >"$ENGINE" <<'PY'
"""Rule engine for the TCB layering boundary.

Usage: layering_engine.py <workspace-root> <cargo-metadata.json>

Exit codes:
  0  boundary holds
  1  boundary violated (LAYERING-VIOLATION[...] on stderr)
  2  the engine could not establish that it inspected anything
     (LAYERING-VACUITY[...] on stderr)

Every rule below states which reading of the dependency graph it uses. See the
shell header for why each one reads what it reads.
"""

import json
import os
import sys

# ---------------------------------------------------------------------------
# POLICY. This is the executable form of ADR 0009. Every name here is checked
# against the workspace before it is used, so a rename fails the gate rather
# than silently disabling a rule.
# ---------------------------------------------------------------------------

# ADR 0009 / TCBOUND-01.
TCB = ("swarm-crypto", "swarm-policy", "swarm-spine")

# TCBOUND-02. Order is the requirement's; sorted only for output.
TRUST_SENSITIVE = (
    "swarm-policy",
    "swarm-pheromone",
    "swarm-response",
    "swarm-guard",
    "swarm-crypto",
    "swarm-spine",
)

# TCBOUND-03's four named transport/CLI crates.
TRANSPORTS = ("axum", "clap", "hyper", "reqwest")

# TCBOUND-03's three named product crates. Asserted to be a SUBSET of the
# derived downstream set rather than used as the set itself; see shell header.
NAMED_PRODUCT_CRATES = ("swarm-cli", "swarm-runtime", "swarm-runtime-http")

# TCBOUND-04. The two crates that must stay out of the advisory lane.
ADVISORY_CONSUMERS = ("swarm-policy", "swarm-response")

# TCBOUND-04's "memory or correlation modules", located by measurement. The
# rule is stated over crates because cargo's boundary is the crate; naming the
# MODULE files here is what keeps the crate-level rule aimed correctly. If a
# module moves to a crate of its own, its path stops existing, this gate fails
# loudly, and whoever moved it must re-point the registry -- instead of the rule
# silently continuing to guard the crate the module left.
#
# A crate-level ban is strictly stronger than a module-level one: with
# `swarm-runtime` out of `swarm-policy`'s manifest, `use
# swarm_runtime::correlation::CorrelationEngine` is a compile error, not a
# review catch.
ADVISORY_MODULES = {
    "memory": "crates/swarm-runtime/src/sphinx_agent.rs",
    "correlation": "crates/swarm-runtime/src/correlation.rs",
}

# RULE 3's baseline: the resolved-normal transport edges that exist TODAY and
# are accepted, each with the declared edge that causes it. Adding a line is a
# reviewable act; a line that stops holding is a gate failure, so the list
# cannot outlive its reason.
#
#   swarm-spine -> reqwest   via swarm-spine -> swarm-response -> reqwest
#   swarm-spine -> hyper     via the same edge, reqwest -> hyper
#
# Both are deleted by one change: inverting `swarm-spine`'s dependency on
# `swarm-response` behind a trait, so the receipt types stop pulling the EDR
# HTTP client into the TCB. ADR 0009, "The one accepted deviation".
RESOLVED_TRANSPORT_BASELINE = {
    ("swarm-spine", "hyper"),
    ("swarm-spine", "reqwest"),
}

# TCBOUND-02's two required headings, matched as whole lines of the crate-level
# doc comment.
OWNS_HEADING = "//! ## Owns"
NOT_OWNS_HEADING = "//! ## Does not own"


class Vacuity(Exception):
    pass


class Report:
    def __init__(self):
        self.violations = []

    def violation(self, rule, message):
        self.violations.append(f"LAYERING-VIOLATION[{rule}] {message}")


def load(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def main(argv):
    if len(argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    root = os.path.abspath(argv[1])
    meta = load(argv[2])

    packages = {p["id"]: p for p in meta["packages"]}
    nodes = {n["id"]: n for n in meta["resolve"]["nodes"]}
    members = set(meta["workspace_members"])

    def name(pkg_id):
        return packages[pkg_id]["name"]

    # ---- vacuity guard: the workspace parsed at all -----------------------
    if not members:
        raise Vacuity("cargo metadata reported zero workspace members")
    if not nodes:
        raise Vacuity("cargo metadata reported an empty resolve graph")

    member_ids = {}
    for pkg_id in members:
        member_ids.setdefault(name(pkg_id), pkg_id)

    # ---- vacuity guard: every policy name is a real workspace crate --------
    policy_names = sorted(
        set(TCB)
        | set(TRUST_SENSITIVE)
        | set(NAMED_PRODUCT_CRATES)
        | set(ADVISORY_CONSUMERS)
    )
    missing = [n for n in policy_names if n not in member_ids]
    if missing:
        raise Vacuity(
            "policy names crates that are not workspace members, so the rules "
            "about them could never fire: " + ", ".join(missing)
        )

    # ---- vacuity guard: the transport names exist in the graph -------------
    all_package_names = {p["name"] for p in meta["packages"]}
    absent_transports = [t for t in TRANSPORTS if t not in all_package_names]
    if absent_transports:
        raise Vacuity(
            "transport package name(s) appear nowhere in the dependency graph, "
            "so the rule banning them could never fire: "
            + ", ".join(absent_transports)
        )

    # ---- graph readings ----------------------------------------------------
    def normal_children(pkg_id):
        out = []
        for dep in nodes[pkg_id]["deps"]:
            # `kind: null` is a normal dependency. Target-specific edges are
            # NOT filtered out: this gate wants the superset over every target
            # so its answer does not depend on the host it runs on.
            if any(k["kind"] is None for k in dep["dep_kinds"]):
                out.append(dep["pkg"])
        return out

    def reach_normal(pkg_id):
        seen, stack = set(), [pkg_id]
        while stack:
            for child in normal_children(stack.pop()):
                if child not in seen:
                    seen.add(child)
                    stack.append(child)
        return seen

    def declared(pkg_id):
        """[(dep package name, kind), ...] straight from the manifest.

        `dep["name"]` is the PACKAGE name, so `wire = { package = "reqwest" }`
        is reported as `reqwest`; a rename cannot walk past these rules.
        """
        out = []
        for dep in packages[pkg_id]["dependencies"]:
            out.append((dep["name"], dep["kind"] or "normal"))
        return out

    reach_cache = {n: reach_normal(i) for n, i in member_ids.items()}

    # ---- derived: the TCB closure and everything strictly above it ---------
    tcb_ids = {member_ids[n] for n in TCB}
    closure = set(tcb_ids)
    for pkg_id in tcb_ids:
        closure |= reach_normal(pkg_id)

    downstream = set()
    for crate, pkg_id in member_ids.items():
        if pkg_id in closure:
            continue
        if reach_cache[crate] & tcb_ids:
            downstream.add(crate)

    if not downstream:
        raise Vacuity(
            "no workspace crate was derived as downstream of the TCB, so RULE 2 "
            "has nothing to ban and would pass over any inversion"
        )
    not_derived = [c for c in NAMED_PRODUCT_CRATES if c not in downstream]
    if not_derived:
        raise Vacuity(
            "TCBOUND-03 names these as product crates but they were not derived "
            "as downstream of the TCB, so the derivation no longer covers the "
            "requirement's own list: " + ", ".join(not_derived)
        )

    # ---- derived: which crates host the advisory-lane modules --------------
    member_dirs = {}
    for crate, pkg_id in member_ids.items():
        manifest = packages[pkg_id]["manifest_path"]
        member_dirs[crate] = os.path.dirname(os.path.abspath(manifest))

    advisory_hosts = {}
    for lane, rel_path in sorted(ADVISORY_MODULES.items()):
        abs_path = os.path.join(root, rel_path)
        if not os.path.isfile(abs_path):
            raise Vacuity(
                f"advisory-lane module '{lane}' is registered at {rel_path} and "
                "that file does not exist; the lane moved and RULE 4 is now "
                "aimed at the wrong crate. Re-point ADVISORY_MODULES."
            )
        owner = None
        owner_dir_len = -1
        for crate, crate_dir in member_dirs.items():
            prefix = crate_dir + os.sep
            if abs_path.startswith(prefix) and len(crate_dir) > owner_dir_len:
                owner, owner_dir_len = crate, len(crate_dir)
        if owner is None:
            raise Vacuity(
                f"advisory-lane module '{lane}' at {rel_path} is not inside any "
                "workspace crate, so RULE 4 has no crate to ban"
            )
        advisory_hosts.setdefault(owner, []).append(lane)

    if not advisory_hosts:
        raise Vacuity("no advisory-lane host crate was derived")
    for host in advisory_hosts:
        if host in ADVISORY_CONSUMERS:
            raise Vacuity(
                f"advisory-lane module(s) live in '{host}', which is itself one "
                "of the crates RULE 4 forbids from reaching them; the rule is "
                "unsatisfiable as stated and must be restated, not relaxed"
            )

    report = Report()

    # ---- RULE 1: DECLARED. No TCB crate may name a transport, any kind. ----
    for crate in sorted(TCB):
        for dep_name, kind in sorted(declared(member_ids[crate])):
            if dep_name in TRANSPORTS:
                report.violation(
                    "tcb-declared-transport",
                    f"{crate} declares transport '{dep_name}' as a {kind} "
                    "dependency; the TCB must never name a transport or CLI "
                    "crate in any dependency section (ADR 0009, TCBOUND-03)",
                )

    # ---- RULE 2: DECLARED. No TCB crate may name a downstream crate. -------
    for crate in sorted(TCB):
        for dep_name, kind in sorted(declared(member_ids[crate])):
            if dep_name in downstream:
                report.violation(
                    "tcb-declared-downstream",
                    f"{crate} declares '{dep_name}' as a {kind} dependency, and "
                    f"'{dep_name}' is downstream of the TCB; this inverts the "
                    "layering (ADR 0009, TCBOUND-03)",
                )

    # ---- RULE 3: RESOLVED NORMAL, against the recorded baseline ------------
    observed_resolved = set()
    for crate in sorted(TCB):
        reached = {name(i) for i in reach_cache[crate]}
        for transport in sorted(TRANSPORTS):
            if transport in reached:
                observed_resolved.add((crate, transport))

    for crate, transport in sorted(observed_resolved - RESOLVED_TRANSPORT_BASELINE):
        report.violation(
            "tcb-resolved-transport-new",
            f"{crate} reaches transport '{transport}' on the resolved NORMAL "
            "graph and that edge is not on the accepted baseline; run "
            f"`cargo tree -p {crate} -i {transport} -e normal` to see the path. "
            "Invert the dependency, or add the edge to "
            "RESOLVED_TRANSPORT_BASELINE with the reason and what deletes it, "
            "and record it in ADR 0009",
        )
    for crate, transport in sorted(RESOLVED_TRANSPORT_BASELINE - observed_resolved):
        report.violation(
            "tcb-resolved-transport-stale",
            f"the baseline records {crate} -> '{transport}' on the resolved "
            "NORMAL graph and that edge no longer exists; delete the line from "
            "RESOLVED_TRANSPORT_BASELINE so the exemption cannot outlive its "
            "reason",
        )

    # ---- RULE 4: the advisory lane (TCBOUND-04), DECLARED and RESOLVED -----
    for crate in sorted(ADVISORY_CONSUMERS):
        declared_names = {d for d, _ in declared(member_ids[crate])}
        reached = {name(i) for i in reach_cache[crate]}
        for host, lanes in sorted(advisory_hosts.items()):
            lane_list = "/".join(sorted(lanes))
            if host in declared_names:
                kinds = sorted(
                    {k for d, k in declared(member_ids[crate]) if d == host}
                )
                report.violation(
                    "advisory-declared",
                    f"{crate} declares '{host}' as a {'/'.join(kinds)} "
                    f"dependency, and '{host}' hosts the {lane_list} module(s); "
                    "the advisory lane must never gate the critical path "
                    "(ADR 0009, TCBOUND-04)",
                )
            if host in reached:
                report.violation(
                    "advisory-resolved",
                    f"{crate} reaches '{host}' on the resolved NORMAL graph, and "
                    f"'{host}' hosts the {lane_list} module(s); the advisory "
                    "lane must never gate the critical path (ADR 0009, "
                    "TCBOUND-04)",
                )

    # ---- RULE 5: TCBOUND-02's Owns / Does not own sections -----------------
    documented = 0
    for crate in sorted(TRUST_SENSITIVE):
        lib_rs = os.path.join(member_dirs[crate], "src", "lib.rs")
        if not os.path.isfile(lib_rs):
            raise Vacuity(
                f"{crate} has no src/lib.rs at {lib_rs}; the crate-level doc "
                "comment rule cannot be evaluated"
            )
        with open(lib_rs, "r", encoding="utf-8") as handle:
            lines = [line.rstrip("\n").rstrip() for line in handle]
        absent = [h for h in (OWNS_HEADING, NOT_OWNS_HEADING) if h not in lines]
        if absent:
            report.violation(
                "missing-owns-section",
                f"{crate}/src/lib.rs crate-level doc comment is missing "
                + " and ".join(f"'{h}'" for h in absent)
                + " (TCBOUND-02)",
            )
        else:
            documented += 1

    if report.violations:
        for line in report.violations:
            print("::error::" + line, file=sys.stderr)
        return 1

    # Every number below is DERIVED from the sets computed above. A success line
    # carrying hand-typed counts is a claim the gate cannot check, and this repo
    # has shipped exactly that defect.
    print(
        "workspace layering holds: "
        f"{len(TCB)} TCB crates ({', '.join(sorted(TCB))}); "
        f"{len(closure & members)} crates in the TCB closure; "
        f"{len(downstream)} crates derived as downstream of it, including all "
        f"{len(NAMED_PRODUCT_CRATES)} named by TCBOUND-03; "
        f"{len(TRANSPORTS)} transport names checked against declared edges of "
        "all three kinds; "
        f"{len(observed_resolved)} resolved-normal transport edge(s), all on the "
        "accepted baseline; "
        f"{len(advisory_hosts)} advisory-lane host crate(s) "
        f"({', '.join(sorted(advisory_hosts))}) held out of "
        f"{len(ADVISORY_CONSUMERS)} critical-path crate(s); "
        f"{documented} crate(s) carrying Owns / Does not own"
    )
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except Vacuity as exc:
        print(f"::error::LAYERING-VACUITY[guard] {exc}", file=sys.stderr)
        sys.exit(2)
PY

# ---------------------------------------------------------------------------
# THE FIXTURE
#
# A real cargo workspace, generated fresh into a temp directory on every run.
# `crate|deps...` -- deps are path dependencies on siblings, so nothing is
# fetched and `--offline` always succeeds.
#
# The shape is chosen so the engine's policy and baseline apply UNMODIFIED:
#   - the TCB closure is {core, crypto, policy, response, spine, whisker}
#   - swarm-cli / swarm-runtime / swarm-runtime-http are all downstream
#   - swarm-spine reaches reqwest and hyper, and only those, exactly matching
#     RESOLVED_TRANSPORT_BASELINE
#   - crates/swarm-runtime/src/{sphinx_agent,correlation}.rs exist, so the
#     advisory-lane registry resolves to swarm-runtime
# ---------------------------------------------------------------------------
FIXTURE_CRATES='swarm-core|swarm-crypto
swarm-crypto|
swarm-whisker|swarm-core
swarm-guard|swarm-core
swarm-pheromone|swarm-core swarm-crypto
swarm-policy|swarm-core
swarm-response|swarm-core swarm-crypto swarm-policy swarm-whisker reqwest
swarm-spine|swarm-core swarm-crypto swarm-policy swarm-response swarm-whisker
swarm-agents|swarm-pheromone swarm-spine
swarm-runtime|swarm-spine swarm-policy swarm-response swarm-pheromone swarm-guard swarm-agents clap
swarm-runtime-http|swarm-runtime axum
swarm-cli|swarm-policy clap
reqwest|hyper
hyper|
axum|
clap|'

# The six TCBOUND-02 crates get the two headings in the fixture too, so RULE 5
# is exercised by the fixture rather than skipped in it.
FIXTURE_DOCUMENTED='swarm-policy swarm-pheromone swarm-response swarm-guard swarm-crypto swarm-spine'

build_fixture() { # <dir>
  local dir="$1" line crate deps dep members=""
  rm -rf "$dir"
  mkdir -p "$dir/crates"

  while IFS='|' read -r crate deps; do
    [ -n "$crate" ] || continue
    mkdir -p "$dir/crates/$crate/src"
    {
      echo '[package]'
      echo "name = \"$crate\""
      echo 'version = "0.1.0"'
      echo 'edition = "2021"'
      echo
      echo '[dependencies]'
      for dep in $deps; do
        echo "$dep = { path = \"../$dep\" }"
      done
    } >"$dir/crates/$crate/Cargo.toml"

    {
      echo "//! Fixture stub for $crate."
      case " $FIXTURE_DOCUMENTED " in
        *" $crate "*)
          echo '//!'
          echo '//! ## Owns'
          echo '//! Fixture text.'
          echo '//!'
          echo '//! ## Does not own'
          echo '//! Fixture text.'
          ;;
      esac
    } >"$dir/crates/$crate/src/lib.rs"

    members="$members    \"crates/$crate\",
"
  done <<EOF
$FIXTURE_CRATES
EOF

  # The advisory-lane modules, at the paths ADVISORY_MODULES registers.
  echo '//! Fixture stub: the memory lane.' >"$dir/crates/swarm-runtime/src/sphinx_agent.rs"
  echo '//! Fixture stub: the correlation lane.' >"$dir/crates/swarm-runtime/src/correlation.rs"

  {
    echo '[workspace]'
    echo 'resolver = "2"'
    echo 'members = ['
    printf '%s' "$members"
    echo ']'
  } >"$dir/Cargo.toml"
}

fixture_metadata() { # <dir> <out.json>
  # cwd stays at the repo root so rust-toolchain.toml still selects the pinned
  # toolchain; `--manifest-path` points cargo at the fixture. `--offline`
  # because the fixture has no registry dependencies at all -- if this ever
  # needs the network, the fixture has stopped being self-contained.
  cargo metadata --format-version 1 --all-features --offline \
    --manifest-path "$1/Cargo.toml" >"$2"
}

# Append a dependency line to a fixture crate's `[dependencies]` (normal kind)
# or under a fresh section (dev/build kind).
break_fixture_dep() { # <dir> <crate> <dep> <kind>
  local manifest="$1/crates/$2/Cargo.toml"
  case "$4" in
    normal) printf '%s = { path = "../%s" }\n' "$3" "$3" >>"$manifest" ;;
    dev)
      printf '\n[dev-dependencies]\n%s = { path = "../%s" }\n' "$3" "$3" \
        >>"$manifest"
      ;;
    build)
      printf '\n[build-dependencies]\n%s = { path = "../%s" }\n' "$3" "$3" \
        >>"$manifest"
      ;;
  esac
}

FIXTURE_DIR="$WORK_DIR/fixture"
FIXTURE_META="$WORK_DIR/fixture-metadata.json"
FIXTURE_LOG="$WORK_DIR/fixture.log"
fixture_failures=0
fixture_cases=0

# Runs one fixture case: rebuild the fixture, apply a mutation, run the ENGINE,
# and assert the exit code and the diagnostic. `expect_text` empty means the
# case must pass cleanly.
fixture_case() { # <label> <expect-code> <expect-text> <mutator...>
  local label="$1" expect_code="$2" expect_text="$3"
  shift 3
  fixture_cases=$((fixture_cases + 1))

  build_fixture "$FIXTURE_DIR"
  if [ "$#" -gt 0 ]; then
    "$@"
  fi
  fixture_metadata "$FIXTURE_DIR" "$FIXTURE_META"

  set +e
  python3 "$ENGINE" "$FIXTURE_DIR" "$FIXTURE_META" >"$FIXTURE_LOG" 2>&1
  local code=$?
  set -e

  if [ "$code" -ne "$expect_code" ]; then
    fixture_failures=$((fixture_failures + 1))
    echo "  FIXTURE CASE FAILED: $label" >&2
    echo "    expected exit $expect_code, got $code" >&2
    sed 's/^/      /' "$FIXTURE_LOG" >&2
    return 0
  fi
  # `-F`, not a regex: every expected string contains `LAYERING-VIOLATION[...]`,
  # and as a basic regex the brackets are a character class -- `[tcb-declared-
  # transport]` is an "invalid character range" on some greps and a silently
  # different match on others. A fixture whose assertion is a broken regex is
  # the same defect this fixture exists to rule out.
  if [ -n "$expect_text" ] && ! grep -qF -- "$expect_text" "$FIXTURE_LOG"; then
    fixture_failures=$((fixture_failures + 1))
    echo "  FIXTURE CASE FAILED: $label" >&2
    echo "    exit $code was right but the diagnostic did not contain:" >&2
    echo "      $expect_text" >&2
    sed 's/^/      /' "$FIXTURE_LOG" >&2
    return 0
  fi
  echo "  ok  $label  (exit $code)"
  printf '        %s\n' "$(head -1 "$FIXTURE_LOG")"
}

# Mutators used by the cases below. Each is a shell function so the case table
# reads as a list of violations rather than a list of sed invocations.
fx_policy_declares_clap() { break_fixture_dep "$FIXTURE_DIR" swarm-policy clap normal; }
fx_crypto_dev_axum() { break_fixture_dep "$FIXTURE_DIR" swarm-crypto axum dev; }
fx_policy_dev_runtime() { break_fixture_dep "$FIXTURE_DIR" swarm-policy swarm-runtime dev; }
fx_spine_build_pheromone() { break_fixture_dep "$FIXTURE_DIR" swarm-spine swarm-pheromone build; }
fx_core_gains_axum() { break_fixture_dep "$FIXTURE_DIR" swarm-core axum normal; }
fx_response_dev_runtime() { break_fixture_dep "$FIXTURE_DIR" swarm-response swarm-runtime dev; }
fx_response_drops_reqwest() {
  # Removes the edge that both baseline entries depend on.
  local manifest="$FIXTURE_DIR/crates/swarm-response/Cargo.toml"
  grep -v '^reqwest = ' "$manifest" >"$manifest.new"
  mv "$manifest.new" "$manifest"
}
fx_spine_loses_owns_section() {
  local lib="$FIXTURE_DIR/crates/swarm-spine/src/lib.rs"
  grep -v '^//! ## Does not own$' "$lib" >"$lib.new"
  mv "$lib.new" "$lib"
}
fx_correlation_module_moves() {
  rm -f "$FIXTURE_DIR/crates/swarm-runtime/src/correlation.rs"
}

echo "fixture: proving this gate can fail before trusting it to pass"

# CASE 0 -- the control. Without a clean baseline every case below is worthless.
fixture_case "clean fixture passes" 0 "workspace layering holds"

# RULE 1, normal kind.
fixture_case "swarm-policy declaring clap is caught" 1 \
  "LAYERING-VIOLATION[tcb-declared-transport] swarm-policy declares transport 'clap' as a normal dependency" \
  fx_policy_declares_clap

# RULE 1, dev kind -- the ADR 0008 lesson. cargo accepts this outright.
fixture_case "swarm-crypto taking axum as a DEV dependency is caught" 1 \
  "LAYERING-VIOLATION[tcb-declared-transport] swarm-crypto declares transport 'axum' as a dev dependency" \
  fx_crypto_dev_axum

# RULE 2, dev kind -- a dev cycle back into the composition root, which cargo
# permits and which a normal-edge-only check would miss entirely.
fixture_case "swarm-policy taking swarm-runtime as a DEV dependency is caught" 1 \
  "LAYERING-VIOLATION[tcb-declared-downstream] swarm-policy declares 'swarm-runtime' as a dev dependency" \
  fx_policy_dev_runtime

# RULE 2, build kind.
fixture_case "swarm-spine taking swarm-pheromone as a BUILD dependency is caught" 1 \
  "LAYERING-VIOLATION[tcb-declared-downstream] swarm-spine declares 'swarm-pheromone' as a build dependency" \
  fx_spine_build_pheromone

# RULE 3, growth -- the transport arrives through a crate the TCB depends on,
# so no TCB manifest changes and RULES 1 and 2 see nothing.
fixture_case "a transport smuggled in through swarm-core is caught" 1 \
  "LAYERING-VIOLATION[tcb-resolved-transport-new] swarm-policy reaches transport 'axum' on the resolved NORMAL graph" \
  fx_core_gains_axum

# RULE 3, staleness -- the exemption must not outlive its reason.
fixture_case "a baseline edge that no longer holds is caught" 1 \
  "LAYERING-VIOLATION[tcb-resolved-transport-stale] the baseline records swarm-spine -> 'reqwest'" \
  fx_response_drops_reqwest

# RULE 4 -- TCBOUND-04. swarm-response is not in the TCB, so RULES 1-3 do not
# cover it; this is the advisory-lane boundary specifically.
fixture_case "swarm-response reaching the advisory lane is caught" 1 \
  "LAYERING-VIOLATION[advisory-declared] swarm-response declares 'swarm-runtime' as a dev dependency" \
  fx_response_dev_runtime

# RULE 5 -- TCBOUND-02.
fixture_case "a trust-sensitive crate losing its Owns section is caught" 1 \
  "LAYERING-VIOLATION[missing-owns-section] swarm-spine/src/lib.rs" \
  fx_spine_loses_owns_section

# VACUITY GUARD -- the advisory lane moving out from under the rule must fail
# loudly rather than leave RULE 4 pointed at a crate the modules have left.
fixture_case "the correlation module moving fails the gate loudly" 2 \
  "LAYERING-VACUITY[guard] advisory-lane module 'correlation'" \
  fx_correlation_module_moves

if [ "$fixture_failures" -ne 0 ]; then
  echo >&2
  echo "$fixture_failures of $fixture_cases fixture case(s) failed." >&2
  echo "The gate's own rules are not behaving as documented, so its verdict on" >&2
  echo "the real workspace below would mean nothing. Fix the engine first." >&2
  exit 1
fi
echo "fixture: $fixture_cases case(s) passed (1 control, $((fixture_cases - 1)) deliberately broken)"
echo

# ---------------------------------------------------------------------------
# THE REAL WORKSPACE
#
# `--all-features` because a feature-gated transport is still a transport
# somebody can switch on; the gate wants the union over every feature
# combination, not the default one. `--locked` because a gate must not rewrite
# Cargo.lock as a side effect of running. No `--offline`: unlike the fixture,
# this workspace has registry dependencies, and failing on a cold cargo home
# would be a false red.
# ---------------------------------------------------------------------------
REAL_META="$WORK_DIR/workspace-metadata.json"
cargo metadata --format-version 1 --all-features --locked >"$REAL_META"

python3 "$ENGINE" "$ROOT_DIR" "$REAL_META"
