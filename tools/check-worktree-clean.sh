#!/usr/bin/env bash
#
# Phase-284 clean-tree contract.
#
# Lifted VERBATIM out of the inline `Assert the suite left the working tree
# clean` step in .github/workflows/ci.yml so a second job can run the identical
# four assertions instead of a paraphrase of them. The comments below are the
# original ones and are load-bearing: they record two separate near-misses that
# each made a previous version of this block inert. Do not compress them.
#
# Usage: bash tools/check-worktree-clean.sh [label]
#   `label` names what is being blamed in the ::error:: lines and defaults to
#   "the test run", which is the wording the test job has always emitted.
#
# The caller is responsible for `if: always()`. Without it a red preceding step
# skips this one, and the gate would be inert on exactly the runs most likely to
# leave the tree dirty.
#
# --- moved verbatim from .github/workflows/ci.yml, phase 284 ---------------
#
# FIXTURE-04. Test call sites, not the production config shape, keep the
# suite out of the working tree, so a NEW test can silently reintroduce
# drift. This step closes that mechanically.
#
# This step used to compute `ignored_count`, echo it, and then assert ONLY
# on `git status --porcelain`. That made it inert for the regression it
# exists to catch, for two independent reasons:
#
#   1. the leaked store roots had been `git rm --cached`-ed AND added to
#      .gitignore, so a recurrence is ignored and `--porcelain` stays
#      empty;
#   2. `git status` NEVER reports an empty directory, ignored or not, and
#      the two leaks that survived phase 284 created only empty
#      directories -- `crates/swarm-runtime/data/evolution-population/`
#      and `.../evolution-assurance-cases/{reports,scenarios}/`.
#
# So the assertions below are on things that actually change when the
# suite dirties the tree. `find` is used for the store roots precisely
# because it is immune to .gitignore and does see empty directories.
#
# --------------------------------------------------------------------------
# `-e` matches the inline step's semantics: GitHub runs `run:` bodies under
# `bash -e`. `pipefail` is added on top so a `find` or `git status` that dies
# mid-pipeline aborts loudly instead of yielding an empty result that reads as
# "clean" -- an assertion whose input silently went missing is the failure mode
# this whole block exists to catch.
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

LABEL="${1:-the test run}"

status=0

echo "== tracked files =="
if [ -n "$(git status --porcelain)" ]; then
  echo "::error::${LABEL} mutated tracked files"
  git status --porcelain
  status=1
else
  echo "clean"
fi

echo "== crate-local store roots (ignore-proof, sees empty dirs) =="
crate_residue="$(
  find crates -maxdepth 2 \
    \( -name data -type d -o -name dead-letter.jsonl -type f \) \
    -print | sort
)"
if [ -n "$crate_residue" ]; then
  echo "::error::${LABEL} created store roots inside crates/"
  printf '%s\n' "$crate_residue" | while IFS= read -r path; do
    find "$path" -print | sort
  done
  status=1
else
  echo "clean"
fi

echo "== untracked and ignored residue outside target/ =="
# `--ignored=matching -uall` is required: the default `--ignored`
# collapses to the ignored DIRECTORY and omits empty ones entirely.
# Restricted to `??`/`!!` so it reports residue only; modified tracked
# files are the first check's business.
tree_residue="$(
  git status --porcelain --ignored=matching -uall \
    | grep -E '^(\?\?|!!) ' \
    | grep -v '^!! target/' || true
)"
if [ -n "$tree_residue" ]; then
  echo "::error::${LABEL} left files in the working tree"
  echo "$tree_residue"
  status=1
else
  echo "clean"
fi

echo "== stray empty directories anywhere in the tree =="
# git cannot track an empty directory, so a fresh checkout has exactly
# zero of them (verified on 4fdcd22). Any empty directory is therefore
# residue by construction. This is the only check of the four that is
# not scoped to a path list: `rulesets/data/deception-lifecycle` slipped
# past the other three because they look under `crates/` (and because
# `git status` never reports an empty directory, ignored or not).
# Do NOT replace this with `find crates rulesets -name data`: `rulesets/data`
# is a tracked directory and would fail the gate permanently.
empty_dirs="$(
  find . -type d -empty \
    -not -path './.git/*' -not -path './target/*' \
    -print | sort
)"
if [ -n "$empty_dirs" ]; then
  echo "::error::${LABEL} created empty directories in the checkout"
  printf '%s\n' "$empty_dirs"
  status=1
else
  echo "clean"
fi

exit "$status"
