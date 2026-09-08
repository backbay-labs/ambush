# Phase 286 checkpoint evidence

This evidence does not establish phase acceptance. The production mutation base
is `92df4f4c8f3bdeaf55539bd2964b417d7d313a6f`. Each mutation was applied
independently to the disposable recovery clone, tested with the ordinary DST
selected-seed command, then restored byte-for-byte before the next mutation.
The original main and rejected candidate checkouts were unchanged. Each result
JSON binds the command, source digest, patch digest, expected named oracle and
terminal Cargo exit status. The outer runner exited zero only after all three
Cargo invocations exited 101 with their expected named oracle; 101 here is the
required negative-control result, not a positive test pass.

`dst-baseline.log` records the 64-seed baseline plus matrix/replay/oracle tests:
4 passed / 1 nightly ignored; both new invariant negative tests also passed.
That command began at `eb4923cca8974ff58eee5de25b98643e193408e4`; the subsequent
`92df4f4c8` changes only a development YAML profile and its signature. No Rust
source differs between the baseline and mutation base. `runtime-restored.log` records the completed positive restoration control:
DST 4 passed / 1 nightly ignored and both negative invariant tests passed. The
same combined Cargo command exited 101 because the runtime library and dispatch
integration targets had seven denied-listener setup failures (578/6 and 20/1).

`response-sandbox.log` records current compiled response library results at
`5df3c228b`: 43 passed / 28 failed, all failures at denied local TCP listener
creation. `ingest-sandbox.log` records 171 passed / 5 denied-listener failures,
including all eleven new composition tests passing. The ingest run predates the
first-run replay correction and does not validate that later behavior.

No 5,000-seed nightly, final Clippy, complete network-enabled regression suite,
or full Phase 286 acceptance is represented by these artifacts.


`ingest-final.log` records the post-fix library run: 172 passed / the same five
TCP listener permission failures. It includes the first-run publication/reopen
regression and all eleven journal-composition tests.
