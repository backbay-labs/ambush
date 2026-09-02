# Phase 285 witness dependency-closure fixtures

`tools/check-witness-dependency-closure.sh` creates a confined scratch
projection from the actual metadata workspace-member inventory. It copies each
complete workspace package root, the root manifests and lockfile, and the
actual Cargo configuration, excluding only generated or VCS directories. An
independent copied-file inventory is compared byte-for-byte with the source
inventory before mutation. Each named self-test first accepts the actual tree
and copied tree, then applies one mutation and runs the same package-ID-based
closure evaluator again. Scratch directories are outside both the subject and
Git directories, are explicitly cleaned, and must be observed absent before a
self-test can pass.

The Stage One mutation inventory is: missing library target; forbidden declared
normal, dev, and build edges; forbidden resolved normal, dev, and build edges;
the reverse `swarm-governance -> swarm-governance-witness` edge; a wrong library
name; a premature binary target; and a same-name foreign internal-package
substitution. Two future-target controls add the exact three Plan 04 binaries,
compile each target, then prove syntax-invalid and type-invalid binaries fail.
The fourteenth control removes only the witness package's direct dev edge while
`swarm-crypto` remains normally reachable elsewhere; the explicit dev-root
closure must still emit `resolved-dev-root`. Normal, build, and per-direct-dev
normal `cargo tree` rows are mapped to unique metadata package IDs and compared
to independently resolved package-scoped metadata closures, including optional
feature activation, exact ID sets and counts, and a non-root requirement. The
fifteenth control feeds the same parser the real root plus a strict nontrivial
subset of the normal tree and requires exact-parity rejection.
The sixteenth control places `TMPDIR` inside the copied subject and proves the
package-scoped metadata harness refuses that boundary before writing any
harness file, removes the temporary child, and leaves no boundary-test path.
