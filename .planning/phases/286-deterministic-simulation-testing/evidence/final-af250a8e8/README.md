# Final local validation evidence

All five commands exited zero at source checkpoint
`af250a8e883695f92cdbf9f21f3175ff1f1e5d19`.

| Run | Terminal result |
|---|---|
| Ordinary suite | 4 passed / 1 nightly ignored; 64 seeds, 16 verdict/fault pairs, 53 executed traces |
| Seed57 first replay | 1 passed |
| Seed57 repeated replay | 1 passed; entire printed plan/trace matched first run exactly |
| Seed11 denied-case replay | 1 passed |
| Ignored nightly suite | 1 passed; 5,000 seeds, all 18 verdict/fault pairs, 897 executed traces |

Nightly command elapsed 693.741 seconds; the Rust test reported 693.20 seconds.
JSON records preserve exact commands, source commit and exit statuses. The latest
harness source change is only the diagnostic that prints corpus metrics after
its existing assertions pass. Production mutation results remain explicitly
bound to their original `92df4f4c8` source; see the sibling evidence directory.

These results do not make the network-denied regression targets pass, establish
OS-process-kill or distributed recovery, or constitute full Phase 286 acceptance.

All 17 registered invariant test functions executed and passed; grouped logs and
JSON records preserve commands and names. Full workspace/all-targets Clippy
initially failed for an unnecessary first-run closure; after the sole Rust delta
`ok_or_else` to `ok_or`, its corrected rerun exited zero. Both logs are retained.
The HTTP approval target compiled but failed at TCP listener setup with
`Operation not permitted`; it is not a regression pass.

Trace diversity includes polling variation and sequential requests with one
shared verdict per seed; it is not a count of distinct crash/effect orderings.

After the Clippy correction, all four selected first-run regressions passed,
including replay lookup through the original configuration beside a live daemon.
