# ADR 0008: SPLIT-01's `axum` Edge Is Now Dev-Only, And What That Does Not Close

## Status

Accepted on 2026-08-13. Supersedes
`0002-split-01-open-until-split-05.md`, whose verification step is now
misleading (see "Consequences").

Amended on 2026-08-13 after review, on the measurement in the Context section
and its two downstream restatements. As first written this ADR said "six dev
targets" and listed six files. Both numbers were wrong and the command that
produced them is not reproducible: it is **five** dev targets across **seven**
files, and `crates/swarm-runtime/tests/ingest_integration.rs` was missing from
the list. See "Counting the dev targets" below for why the original command
under-reports, and "ADR 0002 predicted a deletion that was never reachable" for
what the corrected count does to ADR 0002's forecast. The decision itself --
the line moves to `[dev-dependencies]`, the checkbox is the phase owner's -- is
unchanged.

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
`axum`. Dev targets still do, which is why the line moved to
`[dev-dependencies]` rather than being deleted.

### Counting the dev targets

Two independent defects make the naive count wrong, and the first version of
this ADR hit both. They fail in different ways, which is the part worth
recording: the **grep pattern** sets a ceiling on how many files can ever be
reported, and **`--keep-going`** decides whether a run reliably reaches that
ceiling.

#### The grep pattern sets the ceiling, and alone explains the missing file

The grep must not be for `unresolved import`. Deleting the `axum` line and
compiling every target raises two different resolution errors, and which one a
file gets depends on the shape of its `use`:

- `use axum::{Json, Router};` or `use axum::serve;` names an item at the crate
  root, so it is the import that is unresolved: **E0432**.
- `use axum::extract::{Path, State};` names a module *path* through the absent
  crate, so resolution fails at the path before any import is formed: **E0433**.

Six of the seven files contain at least one `use` of the first shape and so
raise E0432; five of those six raise E0433 as well, which is why a naive grep
sees them perfectly well. Exactly **one** file --
`crates/swarm-runtime/tests/ingest_integration.rs` -- contains only the second
shape (`use axum::body::{Body, to_bytes};` and
`use axum::http::{Request, StatusCode};`) and so raises E0433 alone. Comparing
the two file sets from the `--keep-going` run below:

```
$ comm -13 e432.files e433.files      # E0433 but NOT E0432 -- invisible to the naive grep
crates/swarm-runtime/tests/ingest_integration.rs

$ comm -12 e432.files e433.files      # both codes
crates/swarm-runtime/src/providence.rs
crates/swarm-runtime/src/service/tests_support.rs
crates/swarm-runtime/src/threat_intel_runtime.rs
crates/swarm-runtime/tests/bridge_registry_integration.rs
crates/swarm-runtime/tests/dispatch_integration.rs

$ comm -23 e432.files e433.files      # E0432 only
crates/swarm-runtime/examples/end_to_end_ingest_bench.rs
```

So a grep for `unresolved import` can report at most **six** files however the
build is scheduled, and the single file it can never see is exactly the one the
first version of this ADR was missing. The pattern alone fully accounts for that
omission; no appeal to scheduling is needed to explain it.

Note that the error-code census below (6 E0432, 17 E0433) counts *errors*, not
files. Seventeen E0433 errors arise across six files, so the census cannot be
read as a file count -- an earlier revision of this section inferred "three
files" from it and was wrong on both the number and the direction. Both messages
carry the same tail, so match on that instead:

```
$ sed -i '' '/^axum.workspace = true$/d' crates/swarm-runtime/Cargo.toml
$ cargo check -p swarm-runtime --all-targets --keep-going --message-format=short \
    2>&1 | grep 'unresolved module or unlinked crate `axum`' | cut -d: -f1 | sort -u
crates/swarm-runtime/examples/end_to_end_ingest_bench.rs
crates/swarm-runtime/src/providence.rs                    # inside #[cfg(test)] mod tests
crates/swarm-runtime/src/service/tests_support.rs         # include!d only under #[cfg(test)]
crates/swarm-runtime/src/threat_intel_runtime.rs          # inside #[cfg(test)] mod tests
crates/swarm-runtime/tests/bridge_registry_integration.rs
crates/swarm-runtime/tests/dispatch_integration.rs
crates/swarm-runtime/tests/ingest_integration.rs
```

Seven files, but not seven targets: the three under `src/` are all `#[cfg(test)]`
code compiled into the single `lib test` target. Cargo's own tally is the
target-level answer:

```
$ cargo check -p swarm-runtime --all-targets --keep-going 2>&1 \
    | grep '^error: could not compile' | sort -u
error: could not compile `swarm-runtime` (example "end_to_end_ingest_bench") due to 1 previous error
error: could not compile `swarm-runtime` (lib test) due to 14 previous errors
error: could not compile `swarm-runtime` (test "bridge_registry_integration") due to 3 previous errors
error: could not compile `swarm-runtime` (test "dispatch_integration") due to 3 previous errors
error: could not compile `swarm-runtime` (test "ingest_integration") due to 26 previous errors
```

**Five dev targets, across seven files.** Every error in that run is
axum-rooted -- 6 E0432, 17 E0433, and 18 E0277 cascading off the unresolved
`axum::body::to_bytes` -- and no fourth error code appears, so those five
targets are exactly the ones this line holds up and nothing else is hiding
behind them.

#### `--keep-going` decides whether a run reaches the ceiling

`--keep-going` appears in every command above, and it is load-bearing. Without
it cargo stops scheduling new units once a target fails, so what gets reported
depends on which units happened to be in flight. The result is **not stable and
must not be recorded as a single number.** Measured on this tree with
`cargo clean -p swarm-runtime` before every run, counting distinct files. Each
column is its own independent series of three cold trials -- the rows are not
paired runs, so read down a column, not across:

| cold trial | naive grep, no `--keep-going` | tail grep, no `--keep-going` | tail grep, `--keep-going` |
| ---------- | --- | --- | --- |
| 1 | 6 | 3 | 7 |
| 2 | 2 | 2 | 7 |
| 3 | 2 | 5 | 7 |

On a warm tree the naive command returned 6, and the six files it named were
exactly the six this amendment was raised to correct. Only the `--keep-going`
column is stable: across all three cold trials it returned the identical
seven-file set, byte for byte.

An earlier revision of this section reported the naive command as returning "three
of the seven files" and printed a fixed three-line listing. That is one draw from
the distribution above, not a property of the tree. Recording it as a constant
repeats the defect this amendment exists to correct, so the honest statement is
the one this table makes: **without `--keep-going` the count is nondeterministic
(2-6 observed); with it, seven files, every time.**

### ADR 0002 predicted a deletion that was never reachable

ADR 0002's Decision says "SPLIT-05 is where the `axum` line is expected to be
**deleted**". That outcome was not available, and the reason is visible in ADR
0002's own method: its 52-error measurement was `cargo check -p swarm-runtime
--lib`, which compiles neither `tests/`, nor `examples/`, nor `#[cfg(test)]`
modules. It could not see any of the seven files above -- and all seven already
named `axum` at ADR 0002's own commit:

```
$ git grep -nE '^[[:space:]]*use axum' 8a7beeb -- crates/swarm-runtime/examples \
    crates/swarm-runtime/tests crates/swarm-runtime/src/providence.rs \
    crates/swarm-runtime/src/threat_intel_runtime.rs \
    crates/swarm-runtime/src/service/tests_support.rs
crates/swarm-runtime/examples/end_to_end_ingest_bench.rs:3:use axum::serve;
crates/swarm-runtime/src/providence.rs:1316:    use axum::extract::{Path, State};
crates/swarm-runtime/src/providence.rs:1317:    use axum::http::StatusCode;
crates/swarm-runtime/src/providence.rs:1318:    use axum::routing::{get, put};
crates/swarm-runtime/src/providence.rs:1319:    use axum::{Json, Router};
crates/swarm-runtime/src/service/tests_support.rs:12:    use axum::body::to_bytes;
crates/swarm-runtime/src/service/tests_support.rs:13:    use axum::extract::{Request, State};
crates/swarm-runtime/src/service/tests_support.rs:14:    use axum::http::{HeaderMap, StatusCode, header};
crates/swarm-runtime/src/service/tests_support.rs:15:    use axum::routing::post;
crates/swarm-runtime/src/service/tests_support.rs:16:    use axum::{Json, Router};
crates/swarm-runtime/src/threat_intel_runtime.rs:281:    use axum::{Json, Router, routing::get};
crates/swarm-runtime/tests/bridge_registry_integration.rs:3:use axum::{Router, routing::get};
crates/swarm-runtime/tests/dispatch_integration.rs:5:use axum::{Json, Router, routing::post};
crates/swarm-runtime/tests/ingest_integration.rs:1:use axum::body::{Body, to_bytes};
crates/swarm-runtime/tests/ingest_integration.rs:2:use axum::http::{Request, StatusCode};
```

(`8a7beeb` is the commit that added ADR 0002.)

So "delete the line" and "keep the tests" were in conflict on the day ADR 0002
was written, and SPLIT-05 could not have resolved it, because the blocker was
never in `ingest/`. What SPLIT-05 changed is which manifest SECTION the line
belongs in. That is the whole of what this ADR claims, and it is why the
forecast it inherited cannot be met by any amount of further code motion in
`ingest/`.

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

The literal reading now has a price attached, which it did not when ADR 0002
posed the question. Taking `axum` out of the manifest ENTIRELY means relocating
five dev targets across seven files. Three of those files are `#[cfg(test)]`
code living inside production `src/` files — `providence.rs`,
`threat_intel_runtime.rs`, and the `service/tests_support.rs` that one of them
`include!`s — so it is not a manifest edit at all: it is code motion in the
remainder crate, over files that SPLIT-01's own file set (`http/`, `serve.rs`,
`operator_http.rs`) does not contain. Whatever the ruling is, it should be
priced against that rather than against a one-line deletion.

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

Enumerating the five dev targets that hold the line in `[dev-dependencies]` is
deliberately not in this block: it deletes the manifest line first, so it is
destructive and belongs in a scratch checkout. The exact command, and the two
reasons the naive form under-reports -- a ceiling set by the grep pattern and a
scheduling race closed by `--keep-going` -- are in "Counting the dev targets"
above.
