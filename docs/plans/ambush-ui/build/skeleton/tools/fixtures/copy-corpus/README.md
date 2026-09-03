# tools/fixtures/copy-corpus

The shared corpus for the ban-list PARITY test.

`tools/check-copy-banned-terms.sh` (this repo) and
`BUZZ desktop/scripts/check-copy-banned-terms.mjs` read the same
`tools/copy-ban-list.tsv`. Two implementations of one rule set drift; the parity
test is what stops them. It runs both scanners over every file here and asserts
the two produce **identical** `(file, id)` sets against `expected.tsv`.

Each scanner also carries its OWN inline fixture (planted violations, clean
controls) which runs on every invocation. That fixture proves the scanner can
fail. This corpus proves the two scanners fail the same way.

`expected.tsv` columns: `file <TAB> id`. Sorted, one line per expected hit. A
scanner producing a hit not listed, or missing one that is, fails the parity
test — in either direction, because a Buzz-side scanner that is quietly
*stricter* than the Ambush-side one is how a build goes red for a reason nobody
can find in the ban list.

## Mode is carried by the filename, and that is deliberate

The two scan modes are not interchangeable and a corpus that only exercised one
would leave the other unproved. In production, mode is derived from the file's
**path** (`*/copy.ts`, `*/copy/*.ts`, `*Copy.ts` are `copy`; everything else is
`markup`), and both scanners implement that rule identically. Inside this
directory the files are not on those paths, so mode is derived from the
**filename suffix** instead:

| Suffix | Mode | What it exercises |
|---|---|---|
| `*.copy.ts` | `copy` | every string literal, single- and back-quoted |
| `*.markup.tsx` | `markup` | four attributes, six field names, JSX text nodes (inline and alone on a line) |

Both scanners hard-code that suffix rule for this directory only. If you add a
corpus file, its name must end in one of the two suffixes or it is silently
unscanned — which is exactly the class of hole this whole gate exists to close,
so `expected.tsv` carries at least one row for every corpus file and a file with
zero expected rows must be named `clean.*` so the omission is legible.

## The four cases that are here because they were nearly wrong

1. **Word-boundary near-misses.** `release`, `control-plane`, `resources`,
   `hunting` — all four were live false positives on this repository's own
   assets before the `(^|[^a-z])word([^a-z]|$)` idiom went in.
2. **The ratified `Lanes` nav label.** `APPENDIX-NORMATIVE.md` §1 carries the
   routes `/lanes` and `/lanes/$laneId`; their sidebar item and page heading are
   the bare word. The `bare-lane` row exempts the whole-string form only, so
   `Lanes` passes and `open the async lane` still fails. Both are in the corpus,
   in that order, so a future "simplification" of the exemption breaks parity.
3. **The daemon's verbatim hold reason.** `authorized but held for human
   approval` (`AMB crates/swarm-policy/src/static_gate.rs:297`) is the one reason
   every hold carries today and render law 1's fourth slot requires it be
   rendered. It must pass; `Approve this action` must still fail.
4. **A capability_id token.** `lease:hunt-evt-1:isolate_host:…` is an identifier,
   not prose, and trips neither `bare-lease` nor `hunt-noun`.
