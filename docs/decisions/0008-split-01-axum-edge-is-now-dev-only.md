# ADR 0008: SPLIT-01's `axum` Edge Is Now Dev-Only, And What That Does Not Close

## Status

Accepted on 2026-08-13. Supersedes
`0002-split-01-open-until-split-05.md`, whose verification step is now
misleading (see "Consequences").

## Context

ADR 0002 held SPLIT-01 open on one line. SPLIT-01 names six transport
dependencies to take out of `swarm-runtime`'s manifest; five left with the moved
code, and `axum` stayed because `ingest/` (six files) and `http/rate_limit.rs`
named it in NON-TEST code. ADR 0002 recorded that no work inside SPLIT-01's own
file boundary could remove it, and that SPLIT-05 was where it would go.

SPLIT-05 has since landed. The rate limiter went down to
`swarm_core::http_rate_limit` and `ingest/` went out to `swarm-ingest-runtime`.
Re-running ADR 0002's own measurement on a tree with nothing else moving:

```
$ sed -i '' '/^axum.workspace = true$/d' crates/swarm-runtime/Cargo.toml
$ cargo check -p swarm-runtime --lib 2>&1 | grep -c '^error'
0
```

Zero, where ADR 0002 measured 52. No lib or bin target in this crate names
`axum`. Six dev targets still do, which is why the line moved to
`[dev-dependencies]` rather than being deleted:

```
$ cargo check -p swarm-runtime --all-targets --message-format=short 2>&1 \
    | grep 'unresolved import `axum`' | sort -u
crates/swarm-runtime/examples/end_to_end_ingest_bench.rs:3:5
crates/swarm-runtime/src/providence.rs:1318:9          # inside #[cfg(test)] mod tests
crates/swarm-runtime/src/service/tests_support.rs:16:9 # include!d only under #[cfg(test)]
crates/swarm-runtime/src/threat_intel_runtime.rs:281:9 # inside #[cfg(test)] mod tests
crates/swarm-runtime/tests/bridge_registry_integration.rs:3:5
crates/swarm-runtime/tests/dispatch_integration.rs:5:5
```

## Decision

The `axum` line moves from `[dependencies]` to `[dev-dependencies]`. That is the
whole change; it is a manifest edit with no accompanying code motion, which is
the condition under which the measurement above is worth anything.

**What this establishes:** `swarm-runtime` may no longer NAME `axum` outside dev
targets. A transport type reappearing in its lib or bin code is now a compile
error rather than a review catch. That is the durable property.

**What this does NOT establish, and the reason this ADR exists:** `axum` is
still compiled for `swarm-runtime`'s normal profile. One normal-edge path
survives and is not removable from this manifest:

```
$ cargo tree -p swarm-runtime -i axum -e normal
axum v0.8.9
└── tonic v0.13.1
    └── swarm-ingest-tetragon v0.1.0
        └── swarm-runtime v0.1.0
```

`tonic` uses `axum` for its own server routing, so every crate linking the
composition root still pays for `axum` in build time and binary size. ADR 0002's
"Negative" consequence — "every crate that links the composition root still pays
for `axum`" — is therefore NOT retired by this change. Retiring it means
addressing `tonic`, which is the gRPC transport for Tetragon ingest and is
nobody's idea of a SPLIT-01 line item.

This is precisely the failure mode SPLIT-01 warns about in its own rejected
alternative: satisfying a grep without changing what gets built. The difference
here is that the naming boundary is real and enforced by the compiler; the claim
being declined is the graph-level one.

## Whether SPLIT-01 Is Satisfied Is Not This ADR's Call

SPLIT-01's text says "taking the `axum` ... dependencies **out of
`swarm-runtime`'s manifest**". A `[dev-dependencies]` entry is still in the
manifest. ADR 0002 restated that literally: SPLIT-01 "is **not satisfied** while
`axum` is in `swarm-runtime`'s manifest, whatever the state of the other five".

Read that way, this change does not close SPLIT-01 and the checkbox stays
unchecked. Read as intent — get the transport closure out of the composition
root's production surface — it closes the part a manifest edit can close.

Deciding between those readings reassigns requirement scope and edits
`.planning/REQUIREMENTS.md`. Neither is an implementer's to do, and this ADR does
not do it. It is the same scope question ADR 0002 left open, now with the code
side finished and only the wording in dispute. **SPLIT-01's checkbox is left
unchecked for the phase owner.**

## Consequences

### Positive

- No lib or bin target in `swarm-runtime` can name a transport type; the
  compiler enforces it.
- All six of SPLIT-01's named dependencies are now out of `[dependencies]`.
  `rustls-pemfile` and `x509-parser` are not in the crate's graph at all.
- Dev edges do not propagate, so `swarm-runtime`'s consumers do not inherit this
  edge — only its own test, example and bench targets do.

### Negative

- `axum` is still built for the normal profile through `tonic`. Anyone reading
  "SPLIT-01 removed axum" as "axum is no longer compiled" is misreading it.
- ADR 0002's verification snippet, `grep -nE '^axum'
  crates/swarm-runtime/Cargo.toml`, still prints a line and by its own legend
  would report SPLIT-01 open. The grep cannot see manifest sections; use the
  check below instead.

## Verification

```sh
# The property this ADR actually establishes: no NORMAL edge from this manifest.
# Prints the tonic path and nothing rooted directly at swarm-runtime.
cargo tree -p swarm-runtime -i axum -e normal

# The dev edge is expected, and is the line that moved.
cargo tree -p swarm-runtime -i axum -e dev

# Section-aware replacement for ADR 0002's grep: must print dev-dependencies.
awk '/^\[/{s=$0} /^axum/{print s}' crates/swarm-runtime/Cargo.toml
```
