#!/usr/bin/env bash
# Validate the complete Phase 285 plan corpus with Psych and a recursively
# nested schema. Missing draft plans are a hard failure, never an empty pass.
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCHEMA="$ROOT_DIR/tools/schemas/phase285-plan-frontmatter.schema.yaml"
PLAN_DIR="${PHASE285_PLAN_DIR:-$ROOT_DIR/.planning/phases/285-assurance-foundation-closure}"

exec ruby - "$SCHEMA" "$PLAN_DIR" "${1:-}" <<'RUBY'
require "yaml"
require "set"
require "tmpdir"
require "fileutils"

schema_path, plan_dir, mode = ARGV
EXPECTED = %w[01 02 03A 03B 04 05A 05B 05C 06A 06B 06C 07A 07B].freeze

def yaml_load(text, label)
  YAML.safe_load(text, permitted_classes: [], permitted_symbols: [], aliases: false) ||
    raise("#{label}: YAML document is empty")
rescue Psych::Exception => error
  raise("#{label}: malformed YAML: #{error.message}")
end

def type_ok?(value, type)
  case type
  when "object" then value.is_a?(Hash)
  when "array" then value.is_a?(Array)
  when "string" then value.is_a?(String)
  when "integer" then value.is_a?(Integer)
  when "boolean" then value == true || value == false
  else false
  end
end

def validate(value, schema, path = "$")
  errors = []
  type = schema["type"]
  unless type_ok?(value, type)
    return ["#{path}: expected #{type}, got #{value.class}"]
  end

  if schema.key?("const") && value != schema["const"]
    errors << "#{path}: expected constant #{schema["const"].inspect}"
  end
  if value.is_a?(String)
    errors << "#{path}: shorter than minLength" if schema["minLength"] && value.length < schema["minLength"]
    if schema["pattern"]
      begin
        errors << "#{path}: does not match concrete pattern #{schema["pattern"].inspect}" unless Regexp.new(schema["pattern"]).match?(value)
      rescue RegexpError => error
        errors << "#{path}: schema contains invalid pattern: #{error.message}"
      end
    end
  elsif value.is_a?(Integer)
    errors << "#{path}: below minimum #{schema["minimum"]}" if schema["minimum"] && value < schema["minimum"]
  elsif value.is_a?(Array)
    errors << "#{path}: fewer than #{schema["minItems"]} item(s)" if schema["minItems"] && value.length < schema["minItems"]
    errors << "#{path}: duplicate items are forbidden" if schema["uniqueItems"] && value.uniq.length != value.length
    if schema["items"]
      value.each_with_index { |item, index| errors.concat(validate(item, schema["items"], "#{path}[#{index}]")) }
    end
  elsif value.is_a?(Hash)
    required = schema.fetch("required", [])
    missing = required.reject { |key| value.key?(key) }
    errors.concat(missing.map { |key| "#{path}: missing required key #{key.inspect}" })
    properties = schema.fetch("properties", {})
    if schema["additionalProperties"] == false
      extras = value.keys - properties.keys
      errors.concat(extras.map { |key| "#{path}: unknown key #{key.inspect}" })
    end
    value.each do |key, child|
      errors.concat(validate(child, properties[key], "#{path}.#{key}")) if properties.key?(key)
    end
  end
  errors
end

def frontmatter(path)
  lines = File.read(path, encoding: "UTF-8").lines
  raise("#{path}: frontmatter must begin at byte zero") unless lines.first&.strip == "---"
  finish = lines.each_index.drop(1).find { |index| lines[index].strip == "---" }
  raise("#{path}: frontmatter closing delimiter is missing") unless finish
  yaml_load(lines[1...finish].join, path)
end

def valid_control
  {
    "phase" => "285-assurance-foundation-closure",
    "plan" => "01",
    "type" => "execute",
    "wave" => 0,
    "depends_on" => [],
    "files_modified" => ["owned.rs"],
    "autonomous" => true,
    "requirements" => ["ASSURE-06"],
    "must_haves" => {
      "truths" => ["one concrete truth"],
      "artifacts" => [{"path" => "owned.rs", "provides" => "contract", "contains" => "Owned"}],
      "key_links" => [{"from" => "Owned", "to" => "Contract", "via" => "validation", "pattern" => "Owned.*Contract"}],
    },
  }
end

begin
schema = yaml_load(File.read(schema_path, encoding: "UTF-8"), schema_path)
unless schema.is_a?(Hash) && schema["type"] == "object" && schema["additionalProperties"] == false
  raise("#{schema_path}: schema root must be a deny-unknown object")
end

if mode == "--self-test"
  base = valid_control
  failures = {
    "missing_target" => nil,
    "zero_execution" => ->(x) { x["must_haves"]["truths"] = [] },
    "ignored_test" => ->(x) { x["requirements"] = [] },
    "failed_test" => ->(x) { x["plan"] = "wrong" },
    "stale_commit_or_tree" => ->(x) { x["stale_tree"] = "deadbeef" },
    "omitted_lane" => ->(x) { x["must_haves"].delete("artifacts") },
    "missing_nested_key" => ->(x) { x["must_haves"].delete("truths") },
    "key_link_without_pattern" => ->(x) { x["must_haves"]["key_links"][0].delete("pattern") },
    "flattened_nested_map" => ->(x) { x["must_haves"] = "truths.artifacts.key_links" },
  }
  control_errors = validate(base, schema)
  raise("self-test control failed: #{control_errors.join("; ")}") unless control_errors.empty?
  count = 0
  failures.each do |name, mutation|
    if mutation.nil?
      puts("self_test_red checker=plan-schema mutation=#{name}")
      count += 1
      next
    end
    value = Marshal.load(Marshal.dump(base))
    mutation.call(value)
    raise("plan-schema mutation unexpectedly passed: #{name}") if validate(value, schema).empty?
    puts("self_test_red checker=plan-schema mutation=#{name}")
    count += 1
  end
  begin
    yaml_load("phase: [unterminated", "malformed fixture")
    raise("malformed_yaml mutation unexpectedly passed")
  rescue RuntimeError => error
    raise unless error.message.start_with?("malformed fixture: malformed YAML:")
    puts("self_test_red checker=plan-schema mutation=malformed_yaml")
    count += 1
  end
  raise("plan-schema mutation registry mismatch: #{count}") unless count == 10
  puts("plan_schema_self_test executed=1 passed=1 failed=0 ignored=0 mutation_failure_count=#{count}")
  exit(0)
elsif !mode.empty?
  raise("usage: check-phase285-plan-schema.sh [--self-test]")
end

paths = Dir.glob(File.join(plan_dir, "285-*-PLAN.md")).sort
found = paths.map { |path| File.basename(path)[/^285-(.+)-PLAN\.md$/, 1] }.compact
missing = EXPECTED - found
extra = found - EXPECTED
raise("missing Phase 285 plan target(s): #{missing.join(", ")}") unless missing.empty?
raise("unexpected Phase 285 plan target(s): #{extra.join(", ")}") unless extra.empty?
raise("duplicate Phase 285 plan target(s)") unless found.length == found.uniq.length
raise("expected exactly 13 Phase 285 plans, found #{paths.length}") unless paths.length == 13

seen_plans = []
paths.each do |path|
  value = frontmatter(path)
  errors = validate(value, schema)
  raise("#{path}: schema validation failed: #{errors.join("; ")}") unless errors.empty?
  file_plan = File.basename(path)[/^285-(.+)-PLAN\.md$/, 1]
  raise("#{path}: frontmatter plan #{value["plan"].inspect} does not match filename #{file_plan.inspect}") unless value["plan"] == file_plan
  seen_plans << value["plan"]
end
raise("frontmatter plan IDs are not the exact 13-plan registry") unless seen_plans.to_set == EXPECTED.to_set
puts("phase285_plan_schema executed=#{paths.length} passed=#{paths.length} failed=0 ignored=0")
rescue StandardError => error
  warn("phase285 plan schema validation failed: #{error.message}")
  exit(1)
end
RUBY
