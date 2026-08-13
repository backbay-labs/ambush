# ADR 0002: SPLIT-01 Stays Open Until SPLIT-05 Removes The `axum` Edge

## Status

**Superseded on 2026-08-13 by
[`0008-split-01-axum-edge-is-now-dev-only.md`](0008-split-01-axum-edge-is-now-dev-only.md).**
Accepted on 2026-08-12. The Context below is kept as the record of what was
measured that day; the forecast in the Decision -- that SPLIT-05 would DELETE the
`axum` line -- was never reachable, and ADR 0008 shows why with the measurement
this ADR's `--lib` probe could not see.

The Verification block at the foot of this file was amended the same day. Leaving
it in place was the more dangerous option: run unchanged at a tree where SPLIT-01
is closed, it reports SPLIT-01 open. Read that block before running anything from
this ADR.

## Context

SPLIT-01 (phase 282) undertook to extract `swarm-runtime-http` from
`crates/swarm-runtime/src/http/`, `serve.rs` and `operator_http.rs`, "taking the
`axum`, `hyper`, `hyper-util`, `tokio-rustls`, `rustls-pemfile`, and
`x509-parser` dependencies out of `swarm-runtime`'s manifest".

Five of the six left with the moved code. `axum` did not:

```
$ grep -nE '^(axum|hyper|hyper-util|tokio-rustls|rustls-pemfile|x509-parser)' crates/swarm-runtime/Cargo.toml
25:axum.workspace = true
$ cargo tree -p swarm-runtime -e normal -i axum
axum v0.8.9
├── swarm-runtime v0.1.0 (crates/swarm-runtime)          <- direct edge
└── tonic v0.13.1 └── swarm-ingest-tetragon └── swarm-runtime
$ cargo tree -p swarm-runtime -e normal -i rustls-pemfile
error: package ID specification `rustls-pemfile` did not match any packages
```

Which code owns the survivor is reproducible rather than a judgement call.
Deleting line 25 and running `cargo check -p swarm-runtime --lib` fails with 52
errors: 19 in `ingest/platform_api.rs`, 8 in `ingest/providence_handlers.rs`, 7
each in `ingest/mod.rs` and `ingest/demo.rs`, 6 in
`ingest/soar_verdict_handlers.rs`, 4 in `ingest/health.rs`, and 1 in
`http/rate_limit.rs`.

All 52 fall inside SPLIT-05's file set — `ingest/`, plus the rate limiter that
SPLIT-05's own text names as an import it has to resolve. None fall inside
SPLIT-01's — `http/` less `rate_limit` and `tls_identity`, `serve.rs`,
`operator_http.rs` — because that set is fully extracted. No further work within
SPLIT-01's boundary can remove the edge.

Nor can SPLIT-05 ride along inside SPLIT-01's diff. The coupling is
bidirectional: `ingest/` and `bridge_runtime.rs` import 28 distinct `crate::`
modules of the remainder, while four remainder files import back into them from
non-test code (`anti_tamper.rs:1`, `control.rs:8`, `providence.rs:1`,
`service/mod.rs:39`). Like SPLIT-03 before it, SPLIT-05 needs a trait inversion
first; it is a separate extraction, not a rider.

That leaves a scope question that code cannot answer: is SPLIT-01 done on five
of six dependencies, or does it stay open until the sixth goes?

## Decision

SPLIT-01 stays open.

- It is **not satisfied** while `axum` is in `swarm-runtime`'s manifest, whatever
  the state of the other five dependencies. Its checkbox stays unchecked.
- The requirement text is **not amended**; the six-dependency clause stands as
  written.
- SPLIT-05 is where the `axum` line is expected to be deleted. That deletion is
  the event that closes both requirements' claim on this edge.

## Alternative Considered

**Amend SPLIT-01 so the `axum` clause moves to SPLIT-05**, closing SPLIT-01 on
the five delivered dependencies. This is a legitimate resolution and remains
open to the phase owner: it reassigns requirement scope, and it edits
`.planning/REQUIREMENTS.md`, neither of which is an implementer's to do. If the
phase owner records that amendment it supersedes this ADR. The one state ruled
out is leaving the question unrecorded while calling SPLIT-01 delivered.

**Rejected outright:** having `swarm-runtime` reach `axum` through a
`swarm-runtime-http` re-export so the manifest line can be deleted. It would
satisfy the grep and nothing else — the runtime would still build routers and
handlers — and it would invert the crate direction the split exists to
establish, since nothing in `swarm-runtime` may depend on `swarm-runtime-http`.

## Consequences

### Positive

- The five heavier transport crates are out of the composition root's tree;
  `rustls-pemfile` and `x509-parser` are no longer reachable from it at all.
- "Done" for SPLIT-01 is now one grep, not a narrative.

### Negative

- `swarm-runtime` keeps a web-framework dependency until SPLIT-05 lands, so
  every crate that links the composition root still pays for `axum`.
- Phase 282 cannot report SPLIT-01 as delivered, though its code motion is
  complete and green.

## Verification

**Amended 2026-08-13: do not run the original command.** It was

```sh
# Requirement still open while this prints a line; if it prints nothing,
# SPLIT-05 has landed the deletion and this ADR is spent.
grep -nE '^axum' crates/swarm-runtime/Cargo.toml
```

and it fails in the unsafe direction. `grep` cannot see which manifest section a
line falls in, so the surviving DEV-dependency reads exactly like the
normal-dependency edge that ADR 0002 was written about. Measured at cc5b169:

```
$ grep -nE '^axum' crates/swarm-runtime/Cargo.toml
75:axum.workspace = true
$ grep -n '^\[' crates/swarm-runtime/Cargo.toml
1:[package]
8:[features]
12:[dependencies]
49:[dev-dependencies]
100:[[bench]]
104:[lints]
```

Line 75 is inside `[dev-dependencies]`. Following the instruction above, a reader
concludes SPLIT-01 is still open on a tree where the normal edge is gone -- the
misreading ADR 0008 exists to disarm. Use ADR 0008's Verification block, whose
section-aware replacement for this command is:

```sh
# Prints `[dev-dependencies]`. Anything else -- `[dependencies]` above all --
# means the normal edge is back and ADR 0008 no longer holds.
awk '/^\[/{s=$0} /^axum/{print s}' crates/swarm-runtime/Cargo.toml
```
