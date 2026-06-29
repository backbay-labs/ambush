# engine/fuzz

`cargo-fuzz` (libFuzzer) harnesses for the security-critical Ambush
primitives. These back the "tamper-evident / fail-closed" claims: each target
asserts that a trust-boundary surface either produces a stable, verifiable
result or returns an error -- and **never panics or aborts** on adversarial
input.

This is a **standalone Cargo workspace** (note the empty `[workspace]` stanza
in `Cargo.toml`) so the nightly/libFuzzer toolchain does not leak into the
stable engine workspace at `../Cargo.toml`. Its path dependencies point back
at the real engine crates, so the fuzzer drives production code.

## Layout

- `fuzz_targets/` — one libFuzzer entrypoint per `[[bin]]`.
- `mutators/canonical_json.rs` — structure-aware RFC 8785 canonical-JSON
  mutator, re-exported via `src/lib.rs` as
  `swarm_fuzz::canonical_json::canonical_json_mutate` and wired into the
  JSON-decoding targets with `fuzz_mutator!`.
- `corpus/<target>/` — seed corpora (created on first run; git-ignored).

## Targets

| Target | Surface under test | Fail-closed contract |
| --- | --- | --- |
| `canonical_json` | `swarm_crypto::canonicalize_json` | `canon(parse(canon(x))) == canon(x)` (idempotent fixpoint), output re-parses |
| `sha256` | `swarm_crypto::{sha256, hmac_sha256}` | never panics; deterministic; hex round-trips |
| `merkle` | `swarm_crypto::MerkleTree` (RFC 6962) | build never panics; valid proof verifies; tampered root rejected |
| `policy_parse` | `swarm_core::config::{SwarmConfig, PolicyConfig}` + `swarm_policy` gate | ruleset parse + compile + evaluate never panic |
| `secret_leak` | `swarm_guard::SecretLeakGuard::scan` | never panics; match ranges in bounds |
| `attest_verify` | `swarm_spine::envelope::verify_envelope` + chain/issuer parse | `Err`/`Ok(false)` only; never a crash |

## Running

cargo-fuzz needs a nightly toolchain (libFuzzer's runtime is nightly-only).

```bash
cargo install cargo-fuzz --locked      # once
cd engine/fuzz

# Run a single target (Ctrl-C to stop):
cargo +nightly fuzz run canonical_json
cargo +nightly fuzz run sha256
cargo +nightly fuzz run merkle
cargo +nightly fuzz run policy_parse
cargo +nightly fuzz run secret_leak
cargo +nightly fuzz run attest_verify
```

### PR smoke (bounded, CI-friendly)

```bash
cd engine/fuzz
for t in canonical_json sha256 merkle policy_parse secret_leak attest_verify; do
  cargo +nightly fuzz run "$t" -- -max_total_time=30
done
```

### Build-only / non-nightly environments

If nightly is unavailable, the harness still type-checks on stable (it does
not link the libFuzzer runtime, so `check` succeeds):

```bash
cd engine/fuzz
cargo +stable check --all-targets        # compiles every target + the mutator lib
cargo +stable test                        # runs the mutator unit tests
```

The full instrumented build is:

```bash
cd engine/fuzz && cargo +nightly fuzz build
```
