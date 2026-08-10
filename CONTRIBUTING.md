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

CI runs this. Run it locally before opening a pull request.

```bash
cargo fmt --all -- --check
bash tools/check-runtime-panic-contract.sh
cargo clippy --workspace --all-targets -- -D warnings
cargo build --workspace --all-targets
cargo test --workspace
```

The JetStream and multi-instance suites are ignored by default and run separately:

```bash
bash tools/with-nats-jetstream.sh cargo test -p swarm-pheromone \
  --test jetstream --test multi_instance -- --ignored
```

Supply chain is enforced with `cargo deny` and `cargo audit` through
`tools/check-supply-chain.sh`. A new dependency needs a reason in the pull request description.

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
