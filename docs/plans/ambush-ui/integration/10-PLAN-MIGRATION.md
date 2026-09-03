# Repository Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Merge the Ambush workspace (the former block/buzz fork on branch `rebrand/ambush`) into this repository under `workspace/` with its full history, as a second Cargo workspace whose own gates, hooks and CI keep working, so every later milestone is built once in its final home.

**Architecture:** The chat repository's branch is rewritten with `git filter-repo --to-subdirectory-filter workspace` in a throwaway full clone and merged with `--allow-unrelated-histories`. The engine keeps the root; the workspace keeps its toolchain pin, Hermit, justfile, hooks and CI under `workspace/`. Engine gates that enumerate the whole repository are scoped by exact-path allowlists, never blanket exclusions of tracked files.

**Tech Stack:** git 2.x, git-filter-repo (installed under pyenv Python 3.8.16), cargo, just, lefthook 2.1.3, GitHub Actions.

**Spec:** `docs/plans/ambush-ui/integration/01-DESIGN.md` §2, and `00-DECISIONS.md` D2.

## Global Constraints

- The engine's root `Cargo.toml` lists its twenty members explicitly and now carries `exclude = ["workspace"]`; the workspace's `Cargo.toml` excludes `desktop/src-tauri`. Neither workspace may glob into the other.
- Root `rust-toolchain.toml` pins 1.97.1 (edition 2024); `workspace/rust-toolchain.toml` pins 1.95.0 (edition 2021). Both stay.
- No engine gate may be weakened to pass: a repo-wide scan gets an exact-path allowlist or a subtree exclusion whose rationale is written into the script, never a pattern that hides a whole class of files.
- Commits: `git commit -s` with Conventional Commits subjects; every commit created by an agent ends with the attribution trailers in use on this branch.
- Nothing is pushed by this plan. Pushing is Task 9 and needs the project owner's explicit go-ahead.

---

## Status on 2026-09-02

Tasks 1–8 were executed and verified on branch `integrate/workspace`; their steps are ticked and the commit that landed each is named. Tasks 9–11 remain.

```
f649bd87e fix(hooks): globs are repository-relative under root:, so prefix them
128cf2174 docs(plans): wave 3 design of record, and the CI/hooks paragraph as built
b3a5ace01 chore(ci): re-root the workspace's CI and hooks under workspace/
ec9fb5689 docs(plans): wave 3 — the 2026-09-02 decision record and index
3ab7d7142 chore(repo): wire workspace/ in as a second Cargo workspace
81b97ecea merge: bring the Ambush workspace (former block/buzz fork) in under workspace/
c94cbd093 docs(plans): commit the Perch plan set as authored
```

Measured facts that changed the plan while executing it:

| Assumed | Measured | Consequence |
|---|---|---|
| the merge adds the chat repo's 585 MiB pack | the single-branch clone repacked to **96.8 MiB** after `filter-repo`; the rest belonged to other upstream branches | the weight objection to full history is moot |
| `git filter-repo` runs on a local clone | it refuses a hardlinked local clone ("expected freshly packed repo"); `--no-local` is required, and the tool is only on the pyenv 3.8.16 interpreter | Task 2 step 2 |
| the engine's `build/` ignore pattern is harmless | it silently swallowed the plan set's entire `build/` subdirectory (238 of 251 files) | Task 1 step 2 |
| lefthook's `root:` strips the prefix from `{files}` so globs stay unchanged | `root:` only changes the working directory; globs match repository-relative paths | Task 7 step 4 |
| the workspace file-size ratchet works from a subdirectory | `git diff` printed root-relative paths and `git ls-files` printed cwd-relative ones, so the diff half matched no rule and the gate passed vacuously | Task 6 |
| the disk had room | the volume was at 100 percent; two stale `target/` subdirectories (21 GB) had to go first | Task 0 |

---

## File Structure

| Path | Responsibility |
|---|---|
| `Cargo.toml` | engine workspace; `exclude = ["workspace"]` documents the boundary |
| `.gitignore` | re-includes the plan set's `build/` and the three shadowed workspace paths |
| `NOTICE` | attribution line for the workspace's origin |
| `CLAUDE.md` | the two-product layout and the pointer to `workspace/CLAUDE.md` |
| `tools/check-no-committed-keys.sh` | exact-path allowlist for six push-gateway PEM test fixtures |
| `tools/check-worktree-clean.sh` | `workspace/` excluded from residue and empty-directory sweeps only |
| `.github/workflows/workspace-ci.yml` | the workspace CI, re-rooted; the engine `ci.yml` is untouched |
| `workspace/**` | the former chat repository, history preserved |
| `workspace/lefthook.yml`, `workspace/bin/.lefthookrc`, `workspace/Justfile` | hooks installed from the subdirectory with `LEFTHOOK_CONFIG`, lanes run from `workspace/`, globs prefixed |
| `workspace/scripts/check-file-sizes-core.mjs` | `git diff --relative` and `<rev>:./<path>` so both path sources agree from a subdirectory |
| `docs/plans/ambush-ui/**` | waves 1–2 committed byte-for-byte; wave 3 in `integration/` |

---

### Task 0: Free the disk

**Files:** none in the repository.

- [x] **Step 1: Measure.** `df -h /Users/connor` showed 132 MiB free; `du -sh target/*` showed `target/pr5-restack-focused` 19 GB and `target/pr2-relay-timeout-observation` 2.4 GB, both stale custom target dirs.
- [x] **Step 2: Delete only what the owner approved.** `rm -rf target/pr5-restack-focused target/pr2-relay-timeout-observation` (run by the owner; the harness could not open its own output file at 100 percent). Result: 68 GiB free.

### Task 1: Commit the plan set as authored

**Files:**
- Modify: `.gitignore` (append a negation)
- Create: `docs/plans/ambush-ui/**` (250 files, untracked before)

- [x] **Step 1: Preflight.** `grep -rlE "nsec1[a-z0-9]{20,}|-----BEGIN [A-Z ]*PRIVATE KEY" docs/plans/ambush-ui` → nothing; `find docs/plans/ambush-ui -name '*.inc'` → nothing; `find docs/plans/ambush-ui -type f | git check-ignore --stdin` → **every file under `build/`**, because the Python-era `build/` pattern matches it.
- [x] **Step 2: Re-include.** Append to `.gitignore`:
  ```
  # The Perch plan set (docs/plans/ambush-ui/build/) was silently excluded by the
  # Python `build/` pattern above; re-include it explicitly.
  !docs/plans/ambush-ui/build/
  ```
- [x] **Step 3: Verify the count.** `git add .gitignore docs/plans/ambush-ui && git diff --cached --name-only | wc -l` → 251; `… | grep -c ambush-ui/build/` → 238.
- [x] **Step 4: Commit.** `git checkout -b integrate/workspace && git commit -s -F msg` → `c94cbd093`.

### Task 2: Rewrite the chat repository's history under `workspace/`

**Files:** a throwaway clone under the session scratch directory; nothing in this repository.

- [x] **Step 1: Full clone of exactly one branch.** `git clone --no-local --no-tags --single-branch --branch rebrand/ambush /Users/connor/Medica/backbay/buzz buzz-filtered`. `--single-branch --no-tags` is what dropped the pack from 585 MiB to 97 MiB; `--no-local` is what filter-repo demands.
- [x] **Step 2: Rewrite.** `cd buzz-filtered && PYENV_VERSION=3.8.16 git filter-repo --to-subdirectory-filter workspace`. Expected tail: `Completely finished after N seconds.`
- [x] **Step 3: Assert the prefix.** `test "$(git ls-files | grep -c '^workspace/')" = "$(git ls-files | wc -l)"` → 4864 = 4864. `git count-objects -vH | grep size-pack` → 96.76 MiB.

### Task 3: Merge with unrelated histories

**Files:** the whole `workspace/` subtree.

- [x] **Step 1: Fetch and merge without committing.** `git remote add workspace-import <clone> && git fetch workspace-import rebrand/ambush && git merge --no-commit --allow-unrelated-histories workspace-import/rebrand/ambush`. Expected: `Automatic merge went well; stopped before committing as requested`, zero conflicts (`git diff --name-only --diff-filter=U` empty), 4864 staged paths, all under `workspace/`.
- [x] **Step 2: Commit the pure merge.** `git commit -s -F msg` → `81b97ecea`. Remove the temporary remote.
- [x] **Step 3: Assert Cargo isolation.** `cargo metadata --no-deps --format-version 1 | python3 -c "import json,sys; print(len(json.load(sys.stdin)['packages']))"` at the root → 20.

### Task 4: Wire the second workspace and scope the engine's repo-wide gates

**Files:**
- Modify: `Cargo.toml` (after `members`), `.gitignore`, `NOTICE`, `CLAUDE.md`
- Modify: `tools/check-no-committed-keys.sh` (Python body), `tools/check-worktree-clean.sh` (two sweeps)

- [x] **Step 1: Find shadowed tracked files.** `git ls-files workspace | git check-ignore --no-index --verbose --stdin` → 9: six `workspace/crates/ambush-push-gateway/tests/fixtures/*.pem` (pattern `*.pem`), `workspace/.claude/skills/**` (`.claude/`), `workspace/.vscode/settings.json` (`.vscode/`).
- [x] **Step 2: Re-include them.** Append to `.gitignore`: `!workspace/.claude/`, `!workspace/.vscode/`, `!workspace/crates/ambush-push-gateway/tests/fixtures/*.pem` with the rationale comment. Re-run step 1 → 0.
- [x] **Step 3: Run the key gate and scope it.** `bash tools/check-no-committed-keys.sh` failed on exactly the six PEM fixtures. Add `ALLOWED_TEST_FIXTURES = {…six exact paths…}` and `if rel in ALLOWED_TEST_FIXTURES: continue` before the extension check. Re-run → `no committed key material: scanned 8339 tracked file(s)`.
- [x] **Step 4: Scope the worktree-clean gate.** Add `| grep -v '^!! workspace/'` to the residue filter and `-not -path './workspace/*'` to the empty-directory `find`, each with a comment saying the workspace's build output is its own gates' business and a modified tracked file under it still fails the first check.
- [x] **Step 5: Cargo boundary, attribution, layout note.** `exclude = ["workspace"]` in `Cargo.toml`; the NOTICE paragraph; the "Repository Layout Since 2026-09-02" section in `CLAUDE.md`.
- [x] **Step 6: Verify and commit.** `cargo build --workspace` at the root → `Finished` (4 s, incremental). `bash tools/check-worktree-clean.sh post-merge` → clean once the edits are committed. Commit → `3ab7d7142`.

### Task 5: Run the workspace's own gate from its subdirectory

- [x] **Step 1:** `cd workspace && . ./bin/activate-hermit && just check` → exit 0 in 8 min 02 s (fmt-check, clippy, desktop-check, tauri fmt and clippy, web-check, mobile-check, security-review-check, file-size-check). Hermit resolved `cargo`, `just`, `dart` and `flutter` from `workspace/bin`.

### Task 6: Make the file-size ratchet correct from a subdirectory

**Files:**
- Modify: `workspace/scripts/check-file-sizes-core.mjs` (`changedProjectFiles`, `readBaseFile`)

- [x] **Step 1: Reproduce the vacuous pass.** From `workspace/`: `git diff --name-status HEAD~3 -- desktop | head -1` → `A workspace/desktop/.gitignore` (root-relative); `git ls-files --others -- desktop` → `desktop/…` (cwd-relative). `path.relative("desktop", "workspace/desktop/src/x")` matches no rule.
- [x] **Step 2: Fix.** Add `"--relative"` to the `git diff` argument list and use `` `${baseRef}:./${filePath}` `` in `readBaseFile`, each with a comment naming the 2026-09-02 layout change.
- [x] **Step 3: Prove it bites.** Write a 1001-line `desktop/src/features/zz-probe/probe.ts`; `CHECK_FILE_SIZES_BASE=HEAD node desktop/scripts/check-file-sizes.mjs` → `src/features/zz-probe/probe.ts: new -> 1002 lines (allowed 1000)`, exit 1. Remove it → exit 0. (A first probe placed directly under `src/` was rightly ignored: `src/` itself is not a governed root.)
- [x] **Step 4: Note the first-push consequence.** Against the engine's `origin/main` every workspace file is "new", so the ratchet lists the workspace's own frozen over-cap files (`src-tauri/src/app_state.rs` 1055, …). See Task 9.

### Task 7: Re-root hooks

**Files:**
- Modify: `workspace/lefthook.yml` (rc path, `root:` per lane, prefixed globs), `workspace/bin/.lefthookrc`, `workspace/Justfile` (`hooks` recipe)

- [x] **Step 1: Confirm the override exists.** `./bin/lefthook dump` from `workspace/` fails ("No config files … found in <root>"); `LEFTHOOK_CONFIG=$PWD/lefthook.yml ./bin/lefthook dump` prints the merged config.
- [x] **Step 2: Point the dispatcher at the subdirectory.** `rc: workspace/bin/.lefthookrc`; the rc file prepends `<root>/workspace/bin` to `PATH`, pins `LEFTHOOK_BIN`, and exports `LEFTHOOK_CONFIG=<root>/workspace/lefthook.yml`; the `hooks` recipe exports `LEFTHOOK_CONFIG="{{justfile_directory()}}/lefthook.yml"` before `lefthook install --force`.
- [x] **Step 3: Give every pre-commit and pre-push lane `root: workspace/`** (15 lanes; not `commit-msg`, whose `{1}` is a root-relative message path).
- [x] **Step 4: Measure the glob semantics, then prefix.** With `root:` set, a staged mangled `workspace/crates/ambush-core/src/lib.rs` matched nothing against `crates/**` ("no files for inspection") and matched `workspace/crates/**`, after which `just fmt` ran from `workspace/` and reflowed it. Prefix all 36 glob/exclude entries with `workspace/`.
- [x] **Step 5: Install and prove.** `just hooks` → `sync hooks: ✔️ (commit-msg, pre-push, pre-commit)`; the generated `.git/hooks/pre-commit` contains `[ -f workspace/bin/.lefthookrc ] && . workspace/bin/.lefthookrc`; a real commit ran the sign-off lane. Commits → `b3a5ace01`, `f649bd87e`.

### Task 8: Re-root the workspace CI

**Files:**
- Create: `.github/workflows/workspace-ci.yml` (from `workspace/.github/workflows/ci.yml`)

- [x] **Step 1: Transform mechanically.** `name: Workspace CI`; a workflow-level `defaults.run.working-directory: workspace`; `with: working-directory: workspace` on every `cashapp/activate-hermit` step (its only path input); `working-directory: desktop` → `workspace/desktop`; every dorny `paths-filter` glob, single-line and block `path:` entry, and `hashFiles(...)` argument prefixed; `.github/workflows/ci.yml` self-references → `workspace-ci.yml`; every `Swatinem/rust-cache` step given `workspaces: workspace` (or its existing value prefixed).
- [x] **Step 2: Review every changed line and parse.** `diff` of old vs new reviewed by hand; `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/workspace-ci.yml'))"` → ok.
- [x] **Step 3: Do not add a top-level `paths:` filter.** A workflow skipped by path filtering leaves required checks pending forever; the existing `changes` job with `if:` conditions is the mechanism that skips safely. Leave the engine `ci.yml` untouched for the same reason (its own `changes` job is a Ground task).
- [ ] **Step 4: Verify on GitHub.** Unverifiable locally. On the first push, open the Actions tab: `Workspace CI` must reach the `changes` job and its lanes must run from `workspace/`. Fix forward in a follow-up commit.

### Task 9: First push — decide the landing strategy

**Files:** none; a decision and a push.

The ratchet compares against `origin/main`'s merge-base, and on GitHub Actions against `HEAD^1`. On the integration branch's first run, every workspace file is "new", so the workspace's frozen over-cap files fail the gate. Two ways to land, the owner chooses:

- [ ] **Option A (recommended): fast-forward `main` locally and push `main` directly.** `git checkout main && git merge --ff-only integrate/workspace && git push origin main`. From then on `origin/main` contains the workspace and the ratchet baseline is right. Requires that no branch protection on `backbay-labs/ambush` forbids direct pushes.
- [ ] **Option B: open a PR and set the base explicitly for its first run.** Add `CHECK_FILE_SIZES_BASE=${{ github.event.pull_request.head.sha }}` as a one-run override in `workspace-ci.yml`'s file-size lane, merge, then remove the override in the next PR.
- [ ] **Step 2: Watch the first run** (Task 8 step 4) and the engine `ci.yml` run on the same commit (its gates must stay green; `check-worktree-clean.sh` and `check-no-committed-keys.sh` were exercised locally).
- [ ] **Step 3: Delete the temporary clone** under the scratch directory once the push is confirmed.

### Task 10: Repository policy after the merge

- [ ] **Step 1: Commit policy.** Decide DCO repo-wide (`git commit -s`, the workspace's habit and what this branch used) versus none; if DCO, enable the DCO app on `backbay-labs/ambush` and note it in the root `CLAUDE.md`.
- [ ] **Step 2: CODEOWNERS and templates.** `workspace/.github/CODEOWNERS`, `ISSUE_TEMPLATE/`, `PULL_REQUEST_TEMPLATE.md` are inert under the subdirectory. Move or merge them into root `.github/` if wanted.
- [ ] **Step 3: The nineteen remaining workspace workflows** stay inert under `workspace/.github/workflows/` until each is needed (release, canaries, Helm, sprig images, staging relay image). Re-root each with the same transform when it is.
- [ ] **Step 4: Local directory name.** `standalone/swarm-team-six` → `standalone/ambush` is the owner's call; nothing in either tree depends on the directory name, but the agent memory files and any shell aliases do.

### Task 11: Retire the standalone chat checkout

- [ ] **Step 1:** Once `main` carries the workspace, `/Users/connor/Medica/backbay/buzz` is an archive. Keep it until the first release from the merged repository ships, then delete or move it; its `target/` alone is 7.6 GB.

---

## Self-Review

- **Spec coverage.** `01-DESIGN.md` §2 (layout): Tasks 2–4. `00-DECISIONS.md` D2 (toolchains, gates, CI, hooks, attribution): Tasks 4–8. The one thing the design assumes and this plan cannot deliver locally is a green CI run: Task 8 step 4 and Task 9.
- **Placeholder scan.** None; every step names its command and its measured result.
- **Consistency.** The commit hashes in the status block match the branch as of 2026-09-02.

## Exit criteria

1. `git log --oneline -7` on `integrate/workspace` shows the seven commits above, and `git status` is clean.
2. At the root: `cargo build --workspace` exits 0; `bash tools/check-no-committed-keys.sh` and `bash tools/check-worktree-clean.sh x` exit 0 on a clean tree.
3. In `workspace/`: `just check` exits 0; a 1001-line file under a governed root fails `just file-size-check` against `CHECK_FILE_SIZES_BASE=HEAD`.
4. A commit from the repository root runs the workspace's pre-commit lanes on staged `workspace/` files and the sign-off lane on every commit.
5. After Task 9: `Workspace CI` and `CI` are both green on the landed commit.

## Sizing

Executed in one working session on 2026-09-02, about six hours wall-clock including the disk incident and the two measured surprises. Remaining: Task 9 half a day including the CI watch; Task 10 an hour; Task 11 five minutes when its time comes.
