# Contributing to Ambush

Thanks for your interest. This document covers the workflow, the gate your change has to pass,
and the conventions that keep the critical lane safe.

## Before you start

Read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for lane boundaries and
[docs/REFERENCE-STATUS.md](docs/REFERENCE-STATUS.md) for which documents are the active contract.
`vendor/reference/` and `.planning/` are historical material. Do not treat either as a spec.

For anything larger than a bug fix, open an issue first and describe the change against the
lane it touches. Changes to the critical lane, the policy gate, or the governance path get more
scrutiny than changes to an optional lane, and it is cheaper to align on scope before the code
exists.

## Setup

```bash
git clone https://github.com/backbay-labs/ambush
cd ambush
cargo build --workspace
```

Rust edition 2024, stable toolchain. The JetStream substrate suite needs a local NATS server;
`tools/with-nats-jetstream.sh` starts one for the duration of a command.

## The gate

Everything in this section runs in CI. An earlier version of this list named five commands and
called itself "the gate", omitting six scripts CI was already running — so if you change what CI
runs, change this list too. `tools/check-gates-wired.sh` enforces the other direction: a
`tools/check-*.sh` or `tools/verify-*.sh` that no workflow invokes fails the build. Three of them
had drifted out of CI entirely before that gate existed.

### The fast loop

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo build --workspace --all-targets
cargo test --workspace --exclude swarm-runtime --exclude swarm-ingest-runtime
cargo test -p swarm-runtime -p swarm-ingest-runtime -- --test-threads=1
```

The two test lanes are split deliberately: `ingest::tests` mutates shared `SWARM_*_TEST_TOKEN`
environment variables and the race is cargo-test-thread-scoped, so those two crates run serially.
`cargo test --workspace` in one lane is fine locally and is what CI splits.

### Static gates (no toolchain beyond `python3`)

```bash
bash tools/check-runtime-panic-contract.sh
bash tools/check-no-committed-keys.sh
bash tools/check-no-include-files.sh
bash tools/check-visibility-baseline.sh   # needs full history; a shallow clone fails it loudly
bash tools/check-gates-wired.sh
```

### Build- and test-backed gates

```bash
bash tools/check-fixture-freshness.sh
bash tools/check-platform-openapi.sh      # needs `uv` on PATH and outbound network (PyPI)
bash tools/check-stigmergic-feedback-benchmark.sh
bash tools/check-adversary-emulation-coverage.sh
bash tools/check-supply-chain.sh          # needs cargo-deny 0.19.4 and cargo-audit 0.22.0
bash tools/check-hot-path-regression.sh   # Criterion; the slowest of these by a wide margin
```

### Residue

```bash
bash tools/check-worktree-clean.sh
```

Run this **last**, and **not** in the same working tree as
`tools/check-hot-path-regression.sh` without cleaning up first: that gate writes
`artifacts/benchmarks/hot-path-regression.log`, `.gitignore`'s `*.log` rule makes it an
ignored-but-present file, and the residue assertion reports it. In CI the two live in different
jobs, so they never meet. `rm -rf artifacts` between them locally.

Do not paper over this with `for gate in tools/check-*.sh; do bash "$gate"; done`. That loop
fails for the reason above, and a loop over a glob is also how a gate that no longer exists stops
being noticed.

### Separate lanes

The JetStream and multi-instance suites are ignored by default and run separately:

```bash
bash tools/with-nats-jetstream.sh cargo test -p swarm-pheromone \
  --test jetstream --test multi_instance -- --ignored
```

`tools/verify-release-hardening.sh` runs on the release workflow only. It does a full `--release`
build and proves `-C panic=abort` and `-C overflow-checks=on` reach the two binaries the
container ships, before that image is signed and attested.

Supply chain is enforced with `cargo deny` and `cargo audit` through
`tools/check-supply-chain.sh`. A new dependency needs a reason in the pull request description.

Waiving a supply-chain finding -- a RustSec advisory or a duplicate dependency -- means adding an
entry to `deny.toml` with the metadata that gate parses out of its `reason`: `last-checked
<YYYY-MM-DD>` and a `clears-when:` clause on either kind of entry, plus `expires <YYYY-MM-DD>` and a
`blast-radius:` note on an `[advisories] ignore`. Duplicate skips must use the exact
`<crate>@<SemVer 2.0>` form. The gate splits at the final `@`, requires a non-empty name and valid
exact SemVer, and uses exact `Cargo.lock` matching as the authority for Cargo package names; this
includes leading-underscore and Unicode-XID names. The complete version text must occur in the
lock, including build metadata. Every selector is rejected when multiple locked rows share its
exact name and build-stripped core-plus-prerelease identity; diagnostics list registry/git sources
and truthfully identify source-less rows as path/local while noting that Cargo.lock omits the
filesystem path. Cargo-deny separately checks duplicate applicability in its scanned graph. Do not
add `--ignore` to `cargo audit`: that list is derived from `deny.toml`, and a RustSec id in a
workflow or `tools/*.sh` fails as a second list that would drift. The gate refuses stale resolution
before parsing the lock with `cargo metadata --locked`, runs cargo-deny with `--locked`, and
byte-compares Cargo.lock after cargo-audit because cargo-audit has no locked mode. Its executable
fixture changes a path dependency's manifest version without updating its locked dependency row
and proves the first locked metadata call fails without changing the lock bytes.

## Conventions

- **No panics on the runtime path.** `unwrap_used` and `expect_used` are denied workspace-wide,
  and `tools/check-runtime-panic-contract.sh` enforces the contract beyond what clippy catches.
  Return a typed error. If a panic is genuinely unreachable, prove it with types rather than a
  comment.
- **Fail closed on action, not on observation.** Detection and health reporting may be permissive.
  Anything that authorizes or executes a response denies by default when it is uncertain.
- **Configuration is repo-owned.** New runtime behavior arrives as a config surface under
  `rulesets/` with `deny_unknown_fields`, validated at load, and documented in
  [docs/CONFIGURATION.md](docs/CONFIGURATION.md). Do not hardcode what an operator will need to
  tune.
- **New behavior gets a scenario.** A detector change ships with a recorded scenario under
  `scenarios/`, and a coverage decision goes in
  `rulesets/evasion/attack-technique-catalog.yaml` with the reason it is out of scope. Declared
  gaps are fine. Silent ones are not.
- **Conventional Commits** where practical: `feat:`, `fix:`, `docs:`, `test:`, `chore:`,
  `refactor:`.

## Pull requests

Keep the change scoped to one lane where you can. In the description, say what lane it touches,
what the failure mode is if it is wrong, and which gate command demonstrates it works. If you
changed detection behavior, include the before and after from the relevant suite:

```bash
swarmctl replay-evaluate --suite scenario-suites/evasion-breadth-v1.yaml
```

Benchmark claims need a rerun on your host, not a repeated number from
[docs/benchmarks/](docs/benchmarks/). If your change moves the hot path, say so with the output.

## Security issues

Do not open a public issue for a vulnerability. Follow [SECURITY.md](SECURITY.md).

## License

Contributions are accepted under the Apache License 2.0. See [LICENSE](LICENSE).
