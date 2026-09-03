#!/usr/bin/env bash
#
# Shared presence gate for the four Perch scanners. Sourced, never executed.
#
# NOT NAMED check-*.sh ON PURPOSE: tools/check-gates-wired.sh enumerates
# `tools/check-*.sh` and `tools/verify-*.sh` (git ls-files pathspec, tracked or
# untracked) and demands each be named by a real workflow `run:` step. A sourced
# library is not a gate and must not be enumerated, so it lives under tools/lib/
# with a name matching neither pattern.
#
# CONTRACT
#   perch_roots_gate <gate-id> <PERCH_DESKTOP_ROOT>
#
#   Sets PERCH_ROOT_DIRS (bash array, absolute) to the directories this gate
#   should scan, and PERCH_TREE_STATE to `present` or `absent`.
#
#   Returns 0 with PERCH_TREE_STATE=absent when no row for this gate is
#   `required` AND no `absent` row's directory exists. The CALLER must then print
#   its own "nothing asserted" line and exit 0 -- after running its fixture, so
#   a broken scanner is still caught in Phase 0.
#
#   THREE STATUSES, not two:
#     absent    the directory must NOT exist yet. Phase 0.
#     probe     the directory MUST exist and is NOT Perch source. Its only job is
#               to prove PERCH_DESKTOP_ROOT resolves to a real block/buzz
#               desktop/ tree, so that "nothing found" in Phase 0 can never be
#               confused with "wrong checkout path". A probe row does not make
#               PERCH_TREE_STATE `present`.
#     required  the directory MUST exist and IS Perch source. Scan it.
#
#   Exits 1 -- from inside this function, deliberately, so no caller can forget
#   -- on either drift direction:
#     * a row says `absent` and the directory EXISTS (the tree landed; flip it);
#     * a row says `required` and the directory is MISSING (renamed root, wrong
#       checkout, or desktop/ vs repo-root mix-up).
#
# WHY THE EXIT IS IN HERE AND NOT IN THE CALLER
#   Four callers, one rule. A `return 1` that a caller forgot to check is the
#   same class of defect as the silent green this file exists to prevent.

perch_roots_manifest_path() {
  printf '%s\n' "${PERCH_ROOTS_MANIFEST:-$ROOT_DIR/tools/perch-source-roots.tsv}"
}

# perch_root_status <root> -> prints `absent`, `probe`, `required`, or nothing
# when the manifest carries no such row. Callers that need per-root state (the
# writes gate distinguishes its probe row from its scan root) use this rather
# than re-parsing the manifest.
perch_root_status() {
  awk -F'\t' -v want="$1" '
    $1 == want { print $2; found = 1; exit }
    END { if (!found) exit 0 }
  ' "$(perch_roots_manifest_path)"
}

# perch_roots_gate <gate-id> <desktop-root>
perch_roots_gate() {
  local gate_id="$1" desktop_root="$2"
  local manifest
  manifest="$(perch_roots_manifest_path)"

  if [ ! -f "$manifest" ]; then
    echo "missing $manifest; refusing to pass silently" >&2
    exit 1
  fi

  local rows=0 required=0 present=0
  local drift=""
  PERCH_ROOT_DIRS=()

  local root status gates reason
  while IFS=$'\t' read -r root status gates reason; do
    case "$root" in ''|'#'*) continue ;; esac
    [ "$root" = "root" ] && continue
    case ",$gates," in *",$gate_id,"*) ;; *) continue ;; esac
    if [ -z "$reason" ]; then
      echo "perch-source-roots.tsv row '$root' has no reason column; every row is reviewed, not appended" >&2
      exit 1
    fi
    rows=$((rows + 1))

    local dir="$desktop_root/$root"
    local exists=0
    [ -d "$dir" ] && exists=1

    case "$status" in
      required)
        required=$((required + 1))
        if [ "$exists" -eq 0 ]; then
          drift="${drift}  MISSING  $root  (status=required)"$'\n'
        else
          present=$((present + 1))
          PERCH_ROOT_DIRS+=("$dir")
        fi
        ;;
      probe)
        if [ "$exists" -eq 0 ]; then
          drift="${drift}  MISSING  $root  (status=probe -- this directory exists in block/buzz today, so PERCH_DESKTOP_ROOT is almost certainly wrong)"$'\n'
        fi
        ;;
      absent)
        if [ "$exists" -eq 1 ]; then
          drift="${drift}  LANDED   $root  (status=absent, but the directory exists)"$'\n'
        fi
        ;;
      *)
        echo "perch-source-roots.tsv row '$root' has status '$status'; expected absent, probe or required" >&2
        exit 1
        ;;
    esac
  done < "$manifest"

  if [ "$rows" -eq 0 ]; then
    echo "perch-source-roots.tsv names no root for gate '$gate_id'; refusing to pass silently" >&2
    exit 1
  fi

  if [ -n "$drift" ]; then
    echo "" >&2
    echo "Perch source-root drift (tools/perch-source-roots.tsv vs $desktop_root):" >&2
    printf '%s' "$drift" >&2
    echo "" >&2
    echo "  LANDED   the Perch tree exists and its row still says absent. Flip that row" >&2
    echo "           to 'required' in the SAME commit that creates the directory; that is" >&2
    echo "           what turns this gate from advisory into enforcing, and it is the" >&2
    echo "           only thing that does." >&2
    echo "  MISSING  a root marked required is not there. Check PERCH_DESKTOP_ROOT points" >&2
    echo "           at block/buzz's desktop/ (not the repo root), and that nobody renamed" >&2
    echo "           a feature directory without updating this manifest." >&2
    exit 1
  fi

  if [ "$required" -eq 0 ]; then
    PERCH_TREE_STATE="absent"
  else
    PERCH_TREE_STATE="present"
  fi
}

# Self-test, run by every caller before its own fixture. Proves both drift arms
# fire and the Phase-0 arm does not, against a throwaway manifest and tree --
# because a presence gate that cannot fail is worse than no presence gate.
perch_roots_selftest() {
  local d
  d="$(mktemp -d "${TMPDIR:-/tmp}/perch-roots-selftest.XXXXXX")"
  mkdir -p "$d/tree/src/features/perch-watch" "$d/tree-empty"

  printf 'root\tstatus\tgates\treason\n' > "$d/absent.tsv"
  printf 'src/features/perch-watch\tabsent\tselftest\tfixture row\n' >> "$d/absent.tsv"
  printf 'root\tstatus\tgates\treason\n' > "$d/required.tsv"
  printf 'src/features/perch-watch\trequired\tselftest\tfixture row\n' >> "$d/required.tsv"

  local rc out
  # absent + present -> must fail
  out="$(PERCH_ROOTS_MANIFEST="$d/absent.tsv" bash -c '
    ROOT_DIR="'"$ROOT_DIR"'"; source "'"${BASH_SOURCE[0]}"'"
    perch_roots_gate selftest "'"$d"'/tree"' 2>&1)" && rc=0 || rc=$?
  if [ "${rc:-0}" -eq 0 ]; then
    echo "FIXTURE FAILURE: an absent row over an existing directory did not fail" >&2
    rm -rf "$d"; return 1
  fi

  # required + missing -> must fail
  out="$(PERCH_ROOTS_MANIFEST="$d/required.tsv" bash -c '
    ROOT_DIR="'"$ROOT_DIR"'"; source "'"${BASH_SOURCE[0]}"'"
    perch_roots_gate selftest "'"$d"'/tree-empty"' 2>&1)" && rc=0 || rc=$?
  if [ "${rc:-0}" -eq 0 ]; then
    echo "FIXTURE FAILURE: a required row over a missing directory did not fail" >&2
    rm -rf "$d"; return 1
  fi

  # absent + missing -> Phase 0, must pass and report `absent`
  out="$(PERCH_ROOTS_MANIFEST="$d/absent.tsv" bash -c '
    ROOT_DIR="'"$ROOT_DIR"'"; source "'"${BASH_SOURCE[0]}"'"
    perch_roots_gate selftest "'"$d"'/tree-empty"; printf "%s" "$PERCH_TREE_STATE"' 2>&1)" && rc=0 || rc=$?
  if [ "${rc:-0}" -ne 0 ] || [ "$out" != "absent" ]; then
    echo "FIXTURE FAILURE: the Phase-0 arm did not pass with PERCH_TREE_STATE=absent (rc=${rc:-0}, out=$out)" >&2
    rm -rf "$d"; return 1
  fi

  # probe + missing -> must fail, naming the checkout
  printf 'root\tstatus\tgates\treason\n' > "$d/probe.tsv"
  printf 'src-tauri/src/commands\tprobe\tselftest\tfixture row\n' >> "$d/probe.tsv"
  out="$(PERCH_ROOTS_MANIFEST="$d/probe.tsv" bash -c '
    ROOT_DIR="'"$ROOT_DIR"'"; source "'"${BASH_SOURCE[0]}"'"
    perch_roots_gate selftest "'"$d"'/tree-empty"' 2>&1)" && rc=0 || rc=$?
  if [ "${rc:-0}" -eq 0 ]; then
    echo "FIXTURE FAILURE: a probe row over a missing directory did not fail" >&2
    rm -rf "$d"; return 1
  fi
  case "$out" in
    *PERCH_DESKTOP_ROOT*) ;;
    *) echo "FIXTURE FAILURE: a missing probe row did not name PERCH_DESKTOP_ROOT as the likely cause" >&2
       rm -rf "$d"; return 1 ;;
  esac

  # probe + present -> must pass AND must not count as Perch source
  mkdir -p "$d/tree/src-tauri/src/commands"
  out="$(PERCH_ROOTS_MANIFEST="$d/probe.tsv" bash -c '
    ROOT_DIR="'"$ROOT_DIR"'"; source "'"${BASH_SOURCE[0]}"'"
    perch_roots_gate selftest "'"$d"'/tree"; printf "%s:%d" "$PERCH_TREE_STATE" "${#PERCH_ROOT_DIRS[@]}"' 2>&1)" && rc=0 || rc=$?
  if [ "${rc:-0}" -ne 0 ] || [ "$out" != "absent:0" ]; then
    echo "FIXTURE FAILURE: a present probe row was counted as Perch source (rc=${rc:-0}, out=$out)" >&2
    rm -rf "$d"; return 1
  fi

  rm -rf "$d"
  return 0
}
