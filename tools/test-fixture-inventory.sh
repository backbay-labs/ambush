#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# shellcheck source=tools/fixture-inventory.sh
source "$ROOT_DIR/tools/fixture-inventory.sh"

TEST_ROOT="$(mktemp -d)"
trap 'rm -rf "$TEST_ROOT"' EXIT

git -C "$TEST_ROOT" init -q
mkdir -p "$TEST_ROOT/experiments"

backslash='experiments/back\slash.yaml'
newline=$'experiments/hidden\n::error::forged.yaml'
normal='experiments/normal.yaml'
quote='experiments/quote"name.yaml'
tab=$'experiments/tab\tname.yml'

for path in "$backslash" "$newline" "$normal" "$quote" "$tab"; do
  : >"$TEST_ROOT/$path"
done
printf '%s\n' 'phase285_unknown_schema_field: true' >"$TEST_ROOT/$newline"
git -C "$TEST_ROOT" add experiments

inventory="$TEST_ROOT/inventory.nul"
fixture_inventory_write "$TEST_ROOT" "$inventory"

actual=()
while IFS= read -r -d '' path; do
  fixture_require_direct_path "$path"
  actual+=("$path")
done <"$inventory"
expected=("$backslash" "$newline" "$normal" "$quote" "$tab")

if [ "${#actual[@]}" -ne "${#expected[@]}" ]; then
  echo "fixture inventory self-test lost a special-character path" >&2
  exit 1
fi
index=0
while [ "$index" -lt "${#expected[@]}" ]; do
  if [ "${actual[$index]}" != "${expected[$index]}" ]; then
    echo "fixture inventory self-test order/path mismatch at index $index" >&2
    exit 1
  fi
  index=$((index + 1))
done

rendered=""
for path in "${actual[@]}"; do
  rendered="${rendered}$(fixture_display "$path")"$'\n'
done
case "$rendered" in
  *$'\n::error::'*)
    echo "fixture path renderer emitted a raw workflow command" >&2
    exit 1
    ;;
esac
case "$rendered" in
  *'hidden\n::error::forged.yaml'*) ;;
  *)
    echo "fixture path renderer did not preserve the escaped hostile filename" >&2
    exit 1
    ;;
esac
invalid_rendered="$(printf '\377' | fixture_display_stream)"
if [ "$invalid_rendered" != '"\u00ff"' ]; then
  echo "fixture path renderer did not escape an invalid UTF-8 byte stream" >&2
  exit 1
fi
if ! printf '%s' "$rendered$invalid_rendered" | LC_ALL=C /usr/bin/perl -e '
  local $/;
  my $value = <STDIN> // "";
  exit($value =~ /[\x80-\xff]/ ? 1 : 0);
'; then
  echo "fixture path renderer emitted non-ASCII diagnostic bytes" >&2
  exit 1
fi

nested=$'experiments/nested/hidden\n::error::nested.yaml'
mkdir -p "$TEST_ROOT/experiments/nested"
: >"$TEST_ROOT/$nested"
git -C "$TEST_ROOT" add experiments
fixture_inventory_write "$TEST_ROOT" "$inventory"
nested_diagnostic="$TEST_ROOT/nested-diagnostic"
nested_rejected=0
while IFS= read -r -d '' path; do
  if ! fixture_require_direct_path "$path" 2>>"$nested_diagnostic"; then
    nested_rejected=1
  fi
done <"$inventory"
if [ "$nested_rejected" -ne 1 ]; then
  echo "fixture inventory self-test accepted a nested YAML fixture" >&2
  exit 1
fi
nested_output="$(<"$nested_diagnostic")"
case "$nested_output" in
  *$'\n::error::'*)
    echo "nested-path diagnostic emitted a raw workflow command" >&2
    exit 1
    ;;
esac
case "$nested_output" in
  *'hidden\n::error::nested.yaml'*) ;;
  *)
    echo "nested-path diagnostic did not retain the escaped rejected path" >&2
    exit 1
    ;;
esac

if ! git -C "$TEST_ROOT" rm -q -f -- "$nested" >/dev/null 2>&1; then
  echo "fixture inventory self-test could not remove its nested mutation" >&2
  exit 1
fi

mkdir -p "$TEST_ROOT/tools" "$TEST_ROOT/fake-bin"
cp "$ROOT_DIR/tools/fixture-inventory.sh" "$TEST_ROOT/tools/fixture-inventory.sh"
cp "$ROOT_DIR/tools/regen-kitten-fixtures.sh" "$TEST_ROOT/tools/regen-kitten-fixtures.sh"
cp "$ROOT_DIR/tools/check-fixture-freshness.sh" "$TEST_ROOT/tools/check-fixture-freshness.sh"
printf '#!/usr/bin/env bash\nexit 0\n' >"$TEST_ROOT/tools/test-fixture-inventory.sh"
chmod +x "$TEST_ROOT/tools/"*.sh

cat >"$TEST_ROOT/fake-bin/cargo" <<'FAKE_CARGO'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\0' "$@" >"$FIXTURE_ARGUMENT_LOG"
after_separator=0
output=""
fixtures=()
for argument in "$@"; do
  if [ "$after_separator" -eq 0 ]; then
    if [ "$argument" = "--" ]; then
      after_separator=1
    fi
    continue
  fi
  if [ -z "$output" ]; then
    output="$argument"
  else
    fixtures+=("$argument")
  fi
done
mkdir -p "$output"
for fixture in "${fixtures[@]}"; do
  if [ "${FAKE_SCHEMA_REJECT_NEWLINE:-0}" -eq 1 ]; then
    case "$fixture" in
      *$'\n'*)
        printf 'schema rejected %s\n' "$fixture" >&2
        exit 42
        ;;
    esac
  fi
  cp "$fixture" "$output/${fixture#experiments/}"
done
case "${FAKE_OUTPUT_MUTATION:-}" in
  hidden-extra)
    : >"$output/.unexpected-extra.yaml"
    ;;
  nested-output)
    mkdir -p "$output/nested"
    : >"$output/nested/unexpected.yaml"
    ;;
  symlink-output)
    ln -s normal.yaml "$output/unexpected-link.yaml"
    ;;
esac
FAKE_CARGO
chmod +x "$TEST_ROOT/fake-bin/cargo"

argument_log="$TEST_ROOT/generator-arguments.nul"
test_path="$TEST_ROOT/fake-bin:/usr/bin:/bin:/usr/sbin:/sbin"
clean_output="$TEST_ROOT/clean-output"
FIXTURE_ARGUMENT_LOG="$argument_log" PATH="$test_path" \
  bash "$TEST_ROOT/tools/check-fixture-freshness.sh" >"$clean_output" 2>&1
clean_text="$(<"$clean_output")"
case "$clean_text" in
  *$'\n::error::'*)
    echo "clean freshness listing emitted a forged workflow-command line" >&2
    exit 1
    ;;
esac
case "$clean_text" in
  *'hidden\n::error::forged.yaml'*) ;;
  *)
    echo "clean freshness listing omitted the escaped hostile path" >&2
    exit 1
    ;;
esac

newline_forwarded=0
while IFS= read -r -d '' argument; do
  if [ "$argument" = "$newline" ]; then
    newline_forwarded=1
  fi
done <"$argument_log"
if [ "$newline_forwarded" -ne 1 ]; then
  echo "generator differential omitted the newline fixture argument" >&2
  exit 1
fi

set +e
red_output="$({
  FIXTURE_ARGUMENT_LOG="$argument_log" FAKE_SCHEMA_REJECT_NEWLINE=1 PATH="$test_path" \
    bash "$TEST_ROOT/tools/check-fixture-freshness.sh"
} 2>&1)"
red_status=$?
set -e
if [ "$red_status" -eq 0 ]; then
  echo "freshness differential passed after the generator rejected the newline fixture" >&2
  exit 1
fi
case "$red_output" in
  *$'\n::error::'*)
    echo "freshness differential emitted a forged workflow-command line" >&2
    exit 1
    ;;
esac
case "$red_output" in
  *'hidden\n::error::forged.yaml'*) ;;
  *)
    echo "freshness differential did not retain the escaped rejected path" >&2
    exit 1
    ;;
esac

assert_output_mutation_rejected() {
  local mutation="$1"
  local expected_fragment="$2"
  local output
  local status

  set +e
  output="$({
    FIXTURE_ARGUMENT_LOG="$argument_log" FAKE_OUTPUT_MUTATION="$mutation" PATH="$test_path" \
      bash "$TEST_ROOT/tools/check-fixture-freshness.sh"
  } 2>&1)"
  status=$?
  set -e
  if [ "$status" -eq 0 ]; then
    echo "freshness differential accepted generated output mutation: $mutation" >&2
    exit 1
  fi
  case "$output" in
    *$'\n::error::'*)
      echo "generated-output diagnostic emitted a forged workflow-command line" >&2
      exit 1
      ;;
  esac
  case "$output" in
    *"$expected_fragment"*) ;;
    *)
      echo "freshness differential omitted the generated-output diagnostic for $mutation" >&2
      exit 1
      ;;
  esac
}

assert_output_mutation_rejected hidden-extra 'experiments/.unexpected-extra.yaml'
assert_output_mutation_rejected nested-output '"nested"'
assert_output_mutation_rejected symlink-output '"unexpected-link.yaml"'

assert_source_type_rejected() {
  local expected_fragment="$1"
  local output
  local status

  set +e
  output="$({
    FIXTURE_ARGUMENT_LOG="$argument_log" PATH="$test_path" \
      bash "$TEST_ROOT/tools/check-fixture-freshness.sh"
  } 2>&1)"
  status=$?
  set -e
  if [ "$status" -eq 0 ]; then
    echo "freshness differential accepted a non-regular source fixture" >&2
    exit 1
  fi
  case "$output" in
    *$'\n::error::'*)
      echo "source-type diagnostic emitted a forged workflow-command line" >&2
      exit 1
      ;;
  esac
  case "$output" in
    *"$expected_fragment"*) ;;
    *)
      echo "freshness differential omitted the non-regular source diagnostic" >&2
      exit 1
      ;;
  esac
}

source_symlink=$'experiments/linked\n::error::source.yaml'
ln -s normal.yaml "$TEST_ROOT/$source_symlink"
git -C "$TEST_ROOT" add -- "$source_symlink"
assert_source_type_rejected 'linked\n::error::source.yaml'
git -C "$TEST_ROOT" rm -q -f -- "$source_symlink"

source_fifo=$'experiments/pipe\n::error::source.yml'
: >"$TEST_ROOT/$source_fifo"
git -C "$TEST_ROOT" add -- "$source_fifo"
rm -f -- "$TEST_ROOT/$source_fifo"
mkfifo "$TEST_ROOT/$source_fifo"
assert_source_type_rejected 'pipe\n::error::source.yml'
rm -f -- "$TEST_ROOT/$source_fifo"
git -C "$TEST_ROOT" rm -q -f --cached -- "$source_fifo"

echo "fixture inventory self-test: 14 cases passed (NUL inventory, ordering, direct regular source scope, ASCII-only diagnostics, generator/freshness differential, exact regenerated set)"
