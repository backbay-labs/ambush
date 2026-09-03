import assert from "node:assert/strict";
import test from "node:test";

import {
  AMBUSH_AGENT_MAX_CONTEXT_TOKENS,
  AMBUSH_AGENT_MAX_OUTPUT_TOKENS,
  AMBUSH_AGENT_MAX_ROUNDS,
  AMBUSH_AGENT_THINKING_EFFORT,
  AMBUSH_AGENT_THINKING_EFFORT_VALUES,
  getProviderEffortConfig,
  isAmbushAgentRuntime,
} from "./ambushAgentConfig.ts";

// ---------------------------------------------------------------------------
// Thinking effort values
// ---------------------------------------------------------------------------

test("AMBUSH_AGENT_THINKING_EFFORT_VALUES contains exactly the 7 accepted values", () => {
  assert.deepEqual(
    [...AMBUSH_AGENT_THINKING_EFFORT_VALUES],
    ["none", "minimal", "low", "medium", "high", "xhigh", "max"],
  );
});

test("AMBUSH_AGENT_THINKING_EFFORT_VALUES has no duplicates", () => {
  const set = new Set(AMBUSH_AGENT_THINKING_EFFORT_VALUES);
  assert.equal(set.size, AMBUSH_AGENT_THINKING_EFFORT_VALUES.length);
});

// ---------------------------------------------------------------------------
// Env var key constants
// ---------------------------------------------------------------------------

test("env var key constants match expected AMBUSH_AGENT_* names", () => {
  assert.equal(AMBUSH_AGENT_THINKING_EFFORT, "AMBUSH_AGENT_THINKING_EFFORT");
  assert.equal(
    AMBUSH_AGENT_MAX_OUTPUT_TOKENS,
    "AMBUSH_AGENT_MAX_OUTPUT_TOKENS",
  );
  assert.equal(
    AMBUSH_AGENT_MAX_CONTEXT_TOKENS,
    "AMBUSH_AGENT_MAX_CONTEXT_TOKENS",
  );
  assert.equal(AMBUSH_AGENT_MAX_ROUNDS, "AMBUSH_AGENT_MAX_ROUNDS");
});

// ---------------------------------------------------------------------------
// isAmbushAgentRuntime
// ---------------------------------------------------------------------------

test("isAmbushAgentRuntime returns true only for ambush-agent id", () => {
  assert.equal(isAmbushAgentRuntime("ambush-agent"), true);
});

test("isAmbushAgentRuntime returns false for other runtimes", () => {
  assert.equal(isAmbushAgentRuntime("goose"), false);
  assert.equal(isAmbushAgentRuntime("custom"), false);
  assert.equal(isAmbushAgentRuntime(""), false);
  assert.equal(isAmbushAgentRuntime("ambush-agent-v2"), false);
});

// ---------------------------------------------------------------------------
// handleEnvVarChange logic (the field→envVars mapping)
// ---------------------------------------------------------------------------

/**
 * Mirrors the handleEnvVarChange helper in CreateAgentRuntimeFields.
 * Tests this directly without rendering React.
 */
function applyEnvVarChange(envVars, key, value) {
  const next = { ...envVars };
  if (value === "") {
    delete next[key];
  } else {
    next[key] = value;
  }
  return next;
}

test("setting a thinking effort value writes the key into envVars", () => {
  const initial = {};
  const result = applyEnvVarChange(
    initial,
    AMBUSH_AGENT_THINKING_EFFORT,
    "high",
  );
  assert.equal(result[AMBUSH_AGENT_THINKING_EFFORT], "high");
});

test("clearing thinking effort removes the key so the agent inherits", () => {
  const initial = { [AMBUSH_AGENT_THINKING_EFFORT]: "high" };
  const result = applyEnvVarChange(initial, AMBUSH_AGENT_THINKING_EFFORT, "");
  assert.equal(Object.hasOwn(result, AMBUSH_AGENT_THINKING_EFFORT), false);
});

test("setting max output tokens writes the exact AMBUSH_AGENT_MAX_OUTPUT_TOKENS key", () => {
  const initial = {};
  const result = applyEnvVarChange(
    initial,
    AMBUSH_AGENT_MAX_OUTPUT_TOKENS,
    "4096",
  );
  assert.equal(result[AMBUSH_AGENT_MAX_OUTPUT_TOKENS], "4096");
  // Must not affect other keys
  assert.equal(Object.keys(result).length, 1);
});

test("clearing max output tokens removes the key", () => {
  const initial = { [AMBUSH_AGENT_MAX_OUTPUT_TOKENS]: "4096" };
  const result = applyEnvVarChange(initial, AMBUSH_AGENT_MAX_OUTPUT_TOKENS, "");
  assert.equal(Object.hasOwn(result, AMBUSH_AGENT_MAX_OUTPUT_TOKENS), false);
});

test("setting context limit writes the exact AMBUSH_AGENT_MAX_CONTEXT_TOKENS key", () => {
  const initial = {};
  const result = applyEnvVarChange(
    initial,
    AMBUSH_AGENT_MAX_CONTEXT_TOKENS,
    "100000",
  );
  assert.equal(result[AMBUSH_AGENT_MAX_CONTEXT_TOKENS], "100000");
});

test("clearing context limit removes the key", () => {
  const initial = { [AMBUSH_AGENT_MAX_CONTEXT_TOKENS]: "100000" };
  const result = applyEnvVarChange(
    initial,
    AMBUSH_AGENT_MAX_CONTEXT_TOKENS,
    "",
  );
  assert.equal(Object.hasOwn(result, AMBUSH_AGENT_MAX_CONTEXT_TOKENS), false);
});

test("setting max rounds writes the exact AMBUSH_AGENT_MAX_ROUNDS key", () => {
  const initial = {};
  const result = applyEnvVarChange(initial, AMBUSH_AGENT_MAX_ROUNDS, "50");
  assert.equal(result[AMBUSH_AGENT_MAX_ROUNDS], "50");
});

test("clearing max rounds removes the key", () => {
  const initial = { [AMBUSH_AGENT_MAX_ROUNDS]: "50" };
  const result = applyEnvVarChange(initial, AMBUSH_AGENT_MAX_ROUNDS, "");
  assert.equal(Object.hasOwn(result, AMBUSH_AGENT_MAX_ROUNDS), false);
});

test("changing one field does not disturb other env vars", () => {
  const initial = {
    SOME_OTHER_KEY: "value",
    [AMBUSH_AGENT_MAX_OUTPUT_TOKENS]: "2048",
  };
  const result = applyEnvVarChange(initial, AMBUSH_AGENT_MAX_ROUNDS, "20");
  assert.equal(result.SOME_OTHER_KEY, "value");
  assert.equal(result[AMBUSH_AGENT_MAX_OUTPUT_TOKENS], "2048");
  assert.equal(result[AMBUSH_AGENT_MAX_ROUNDS], "20");
});

test("clearing one field does not disturb other env vars", () => {
  const initial = {
    SOME_OTHER_KEY: "value",
    [AMBUSH_AGENT_MAX_OUTPUT_TOKENS]: "2048",
    [AMBUSH_AGENT_MAX_ROUNDS]: "20",
  };
  const result = applyEnvVarChange(initial, AMBUSH_AGENT_MAX_ROUNDS, "");
  assert.equal(Object.hasOwn(result, AMBUSH_AGENT_MAX_ROUNDS), false);
  assert.equal(result.SOME_OTHER_KEY, "value");
  assert.equal(result[AMBUSH_AGENT_MAX_OUTPUT_TOKENS], "2048");
});

test("thinking effort select is bounded: all 7 accepted values are present in the constant", () => {
  const expected = ["none", "minimal", "low", "medium", "high", "xhigh", "max"];
  for (const v of expected) {
    assert.ok(
      AMBUSH_AGENT_THINKING_EFFORT_VALUES.includes(v),
      `missing value: ${v}`,
    );
  }
  assert.equal(AMBUSH_AGENT_THINKING_EFFORT_VALUES.length, expected.length);
});

test("non-numeric string is stored as-is (validation is at the backend)", () => {
  // HTML type=number inputs enforce numeric in the browser; we verify the
  // mapping function itself is not a validator — that's intentional.
  const result = applyEnvVarChange(
    {},
    AMBUSH_AGENT_MAX_OUTPUT_TOKENS,
    "not-a-number",
  );
  assert.equal(result[AMBUSH_AGENT_MAX_OUTPUT_TOKENS], "not-a-number");
});

// ---------------------------------------------------------------------------
// modelTuningRuntimeId → visibility mapping (regression for Edit dialog path)
// ---------------------------------------------------------------------------

// Mirrors the `isAmbushAgent` derivation in CreateAgentRuntimeFields.
// The point of modelTuningRuntimeId is that the Edit dialog can pass
// prospectiveRuntimeId (the real resolved runtime) while selectedRuntimeId
// carries the "inherit"/"custom" sentinel — the two must not be conflated.

test("isAmbushAgentRuntime(prospectiveRuntimeId) shows fields when Edit resolves ambush-agent even though selectedRuntimeId sentinel is 'inherit'", () => {
  // Simulates Edit dialog state: inheritHarness=true, persona is ambush-agent.
  // selectedRuntimeId would be "inherit" (sentinel for custom-command hiding),
  // but prospectiveRuntimeId correctly resolves to "ambush-agent".
  const selectedRuntimeIdSentinel = "inherit"; // what Edit passes to selectedRuntimeId
  const prospectiveRuntimeId = "ambush-agent"; // what Edit passes to modelTuningRuntimeId

  assert.equal(
    isAmbushAgentRuntime(selectedRuntimeIdSentinel),
    false,
    "sentinel 'inherit' must NOT trigger model-tuning fields",
  );
  assert.equal(
    isAmbushAgentRuntime(prospectiveRuntimeId),
    true,
    "prospectiveRuntimeId 'ambush-agent' MUST trigger model-tuning fields",
  );
});

test("isAmbushAgentRuntime(prospectiveRuntimeId) shows fields when Edit has a pinned ambush-agent (selectedRuntimeId sentinel is also 'inherit')", () => {
  // Simulates Edit dialog with a pinned non-custom runtime:
  // selectedRuntimeId sentinel = "inherit" (non-custom known runtime),
  // prospectiveRuntimeId = "ambush-agent" (selectedRuntime?.id).
  const selectedRuntimeIdSentinel = "inherit";
  const prospectiveRuntimeId = "ambush-agent";

  assert.equal(isAmbushAgentRuntime(prospectiveRuntimeId), true);
  assert.equal(isAmbushAgentRuntime(selectedRuntimeIdSentinel), false);
});

test("isAmbushAgentRuntime(prospectiveRuntimeId) hides fields when Edit resolves to non-ambush-agent", () => {
  // E.g. user switches from ambush-agent to goose in Edit — prospectiveRuntimeId = "goose"
  const prospectiveRuntimeId = "goose";
  assert.equal(isAmbushAgentRuntime(prospectiveRuntimeId), false);
});

test("isAmbushAgentRuntime(prospectiveRuntimeId) hides fields when Edit has no resolved runtime (empty string)", () => {
  // prospectiveRuntimeId falls back to "" when catalog hasn't loaded yet
  assert.equal(isAmbushAgentRuntime(""), false);
});

// ---------------------------------------------------------------------------
// getProviderEffortConfig — Anthropic model families
// ---------------------------------------------------------------------------

test("anthropic unknown model returns adaptive full set with high default", () => {
  const { validValues, defaultValue } = getProviderEffortConfig(
    "anthropic",
    "",
  );
  assert.deepEqual([...validValues], ["low", "medium", "high", "xhigh", "max"]);
  assert.equal(defaultValue, "high");
});

test("anthropic claude-3 model returns manual-budget set with null default", () => {
  const { validValues, defaultValue } = getProviderEffortConfig(
    "anthropic",
    "claude-3-7-sonnet-20250219",
  );
  assert.deepEqual([...validValues], ["low", "medium", "high"]);
  assert.equal(defaultValue, null);
});

test("anthropic claude-opus-4-5 returns manual-budget set with null default", () => {
  const { validValues, defaultValue } = getProviderEffortConfig(
    "anthropic",
    "claude-opus-4-5",
  );
  assert.deepEqual([...validValues], ["low", "medium", "high"]);
  assert.equal(defaultValue, null);
});

test("anthropic claude-opus-4-7 returns xhigh-supporting set with high default", () => {
  const { validValues, defaultValue } = getProviderEffortConfig(
    "anthropic",
    "claude-opus-4-7",
  );
  assert.deepEqual([...validValues], ["low", "medium", "high", "xhigh", "max"]);
  assert.equal(defaultValue, "high");
});

test("anthropic claude-opus-4-6 returns non-xhigh adaptive set (no xhigh)", () => {
  const { validValues, defaultValue } = getProviderEffortConfig(
    "anthropic",
    "claude-opus-4-6",
  );
  assert.deepEqual([...validValues], ["low", "medium", "high", "max"]);
  assert.equal(defaultValue, "high");
});

test("anthropic claude-sonnet-5 returns xhigh-supporting set", () => {
  const { validValues, defaultValue } = getProviderEffortConfig(
    "anthropic",
    "claude-sonnet-5-20260101",
  );
  assert.deepEqual([...validValues], ["low", "medium", "high", "xhigh", "max"]);
  assert.equal(defaultValue, "high");
});

test("anthropic claude-sonnet-4-6 returns non-xhigh adaptive set", () => {
  const { validValues, defaultValue } = getProviderEffortConfig(
    "anthropic",
    "claude-sonnet-4-6",
  );
  assert.deepEqual([...validValues], ["low", "medium", "high", "max"]);
  assert.equal(defaultValue, "high");
});

test("anthropic claude-mythos-preview returns non-xhigh adaptive set", () => {
  const { validValues, defaultValue } = getProviderEffortConfig(
    "anthropic",
    "claude-mythos-preview",
  );
  assert.deepEqual([...validValues], ["low", "medium", "high", "max"]);
  assert.equal(defaultValue, "high");
});

test("anthropic claude-mythos-5 returns xhigh-supporting set", () => {
  const { validValues, defaultValue } = getProviderEffortConfig(
    "anthropic",
    "claude-mythos-5",
  );
  assert.deepEqual([...validValues], ["low", "medium", "high", "xhigh", "max"]);
  assert.equal(defaultValue, "high");
});

// ---------------------------------------------------------------------------
// getProviderEffortConfig — OpenAI model families
// ---------------------------------------------------------------------------

test("openai gpt-5-pro returns only high with high default", () => {
  const { validValues, defaultValue } = getProviderEffortConfig(
    "openai",
    "gpt-5-pro",
  );
  assert.deepEqual([...validValues], ["high"]);
  assert.equal(defaultValue, "high");
});

test("openai gpt-5.5 returns none/low/medium/high/xhigh with medium default", () => {
  const { validValues, defaultValue } = getProviderEffortConfig(
    "openai",
    "gpt-5.5",
  );
  assert.deepEqual(
    [...validValues],
    ["none", "low", "medium", "high", "xhigh"],
  );
  assert.equal(defaultValue, "medium");
});

test("openai gpt-5.4 returns same table as gpt-5.5", () => {
  const { validValues, defaultValue } = getProviderEffortConfig(
    "openai",
    "gpt-5.4",
  );
  assert.deepEqual(
    [...validValues],
    ["none", "low", "medium", "high", "xhigh"],
  );
  assert.equal(defaultValue, "medium");
});

test("openai gpt-5.1 returns none/low/medium/high with none default", () => {
  const { validValues, defaultValue } = getProviderEffortConfig(
    "openai",
    "gpt-5.1",
  );
  assert.deepEqual([...validValues], ["none", "low", "medium", "high"]);
  assert.equal(defaultValue, "none");
});

test("openai gpt-5 base returns minimal/low/medium/high with medium default", () => {
  const { validValues, defaultValue } = getProviderEffortConfig(
    "openai",
    "gpt-5",
  );
  assert.deepEqual([...validValues], ["minimal", "low", "medium", "high"]);
  assert.equal(defaultValue, "medium");
});

test("openai unknown model returns all-except-max with medium default", () => {
  const { validValues, defaultValue } = getProviderEffortConfig(
    "openai",
    "gpt-4o",
  );
  assert.deepEqual(
    [...validValues],
    ["none", "minimal", "low", "medium", "high", "xhigh"],
  );
  assert.equal(defaultValue, "medium");
});

test("openai empty model returns all-except-max with medium default", () => {
  const { validValues, defaultValue } = getProviderEffortConfig("openai", "");
  assert.deepEqual(
    [...validValues],
    ["none", "minimal", "low", "medium", "high", "xhigh"],
  );
  assert.equal(defaultValue, "medium");
});

// gpt-5-pro must not match the gpt-5 base bucket
test("openai gpt-5-pro is not matched by gpt-5 base bucket", () => {
  const { validValues } = getProviderEffortConfig("openai", "gpt-5-pro");
  assert.deepEqual(
    [...validValues],
    ["high"],
    "gpt-5-pro must use its own table",
  );
});

// gpt-5.10 must NOT match gpt-5.1 (digit boundary), but DOES match the gpt-5
// base rule at the dot boundary → base table, not the unknown fallback.
test("openai gpt-5.10 rejects gpt-5.1 at the digit boundary and matches the gpt-5 base rule", () => {
  const { validValues, defaultValue } = getProviderEffortConfig(
    "openai",
    "gpt-5.10",
  );
  assert.deepEqual([...validValues], ["minimal", "low", "medium", "high"]);
  assert.equal(defaultValue, "medium");
});

// ---------------------------------------------------------------------------
// getProviderEffortConfig — DatabricksV2 routing
// ---------------------------------------------------------------------------

test("databricks_v2 with claude-opus-4-7 routes to anthropic xhigh table", () => {
  const { validValues, defaultValue } = getProviderEffortConfig(
    "databricks_v2",
    "claude-opus-4-7",
  );
  assert.deepEqual([...validValues], ["low", "medium", "high", "xhigh", "max"]);
  assert.equal(defaultValue, "high");
});

test("databricks_v2 with databricks-prefixed claude model strips prefix and routes correctly", () => {
  const { validValues, defaultValue } = getProviderEffortConfig(
    "databricks_v2",
    "databricks-claude-opus-4-7",
  );
  assert.deepEqual([...validValues], ["low", "medium", "high", "xhigh", "max"]);
  assert.equal(defaultValue, "high");
});

test("databricks_v2 with gpt-5.4 routes to openai gpt-5.5/5.4 table", () => {
  const { validValues, defaultValue } = getProviderEffortConfig(
    "databricks_v2",
    "gpt-5.4",
  );
  assert.deepEqual(
    [...validValues],
    ["none", "low", "medium", "high", "xhigh"],
  );
  assert.equal(defaultValue, "medium");
});

test("databricks_v2 with databricks-gpt-5.1 strips prefix and routes to OpenAI gpt-5.1", () => {
  const { validValues, defaultValue } = getProviderEffortConfig(
    "databricks_v2",
    "databricks-gpt-5.1",
  );
  assert.deepEqual([...validValues], ["none", "low", "medium", "high"]);
  assert.equal(defaultValue, "none");
});

test("databricks_v2 with concrete non-claude non-gpt model excludes max (MLflow clamps it)", () => {
  // llama-3 falls to the databricks_v2 concrete-unknown fallback, whose
  // OpenaiClampMaxToXhigh normalization policy clamps max→xhigh
  // (normalize_effort_for_databricks_v2). Show all-except-max so the UI is honest.
  const { validValues, defaultValue } = getProviderEffortConfig(
    "databricks_v2",
    "llama-3",
  );
  assert.deepEqual(
    [...validValues],
    ["none", "minimal", "low", "medium", "high", "xhigh"],
  );
  assert.equal(defaultValue, "medium");
});

test("databricks_v2 with databricks-prefixed llama model strips prefix and excludes max", () => {
  const { validValues } = getProviderEffortConfig(
    "databricks_v2",
    "databricks-llama-3",
  );
  assert.ok(!validValues.includes("max"));
});

test("databricks_v2 goose-claude-fable-5 strips goose- prefix and routes to anthropic adaptive+xhigh", () => {
  // "goose-claude-fable-5": first claude- occurrence at index 6 → strips "goose-"
  const { validValues, defaultValue } = getProviderEffortConfig(
    "databricks_v2",
    "goose-claude-fable-5",
  );
  assert.ok(
    validValues.includes("max"),
    "max must be valid for goose-claude-fable-5 (adaptive xhigh model)",
  );
  assert.ok(
    validValues.includes("xhigh"),
    "xhigh must be valid for goose-claude-fable-5",
  );
  assert.equal(defaultValue, "high");
});

test("databricks_v2 goose-gpt-5.5 strips goose- prefix and routes to openai gpt-5.5 table", () => {
  // "goose-gpt-5.5": first gpt- occurrence at index 6 → strips "goose-"
  const { validValues } = getProviderEffortConfig(
    "databricks_v2",
    "goose-gpt-5.5",
  );
  assert.ok(!validValues.includes("max"), "max must be excluded for gpt-5.5");
  assert.ok(validValues.includes("xhigh"), "xhigh must be valid for gpt-5.5");
  assert.ok(
    !validValues.includes("minimal"),
    "minimal is not in gpt-5.5 table",
  );
});

test("databricks_v2 arbitrary prefix team-x-claude-opus-4-7 strips to claude-opus-4-7 and routes to anthropic xhigh", () => {
  // "team-x-claude-opus-4-7": first claude- occurrence at index 7 → strips "team-x-"
  // Same routing result as bare "claude-opus-4-7" — verifies prefix allowlist is not required.
  const { validValues, defaultValue } = getProviderEffortConfig(
    "databricks_v2",
    "team-x-claude-opus-4-7",
  );
  assert.ok(
    validValues.includes("max"),
    "max must be valid: claude-opus-4-7 is adaptive xhigh",
  );
  assert.ok(validValues.includes("xhigh"), "xhigh must be valid");
  assert.equal(defaultValue, "high");
});

test("databricks_v2 with empty model returns all-7 (blank = route unknown)", () => {
  const { validValues, defaultValue } = getProviderEffortConfig(
    "databricks_v2",
    "",
  );
  assert.equal(validValues.length, 7);
  assert.equal(defaultValue, "medium");
});

// ---------------------------------------------------------------------------
// getProviderEffortConfig — databricks v1 and other providers
// ---------------------------------------------------------------------------

test("databricks v1 routes like openai unknown (no gpt-5 model)", () => {
  const { validValues, defaultValue } = getProviderEffortConfig(
    "databricks",
    "",
  );
  assert.deepEqual(
    [...validValues],
    ["none", "minimal", "low", "medium", "high", "xhigh"],
  );
  assert.equal(defaultValue, "medium");
});

test("openai-compat returns all-except-max with medium default", () => {
  // openai-compat canonicalizes to openai, whose blank/unknown fallback omits
  // max (the OpenAI wire route clamps max → xhigh, so the UI stays honest).
  const { validValues, defaultValue } = getProviderEffortConfig(
    "openai-compat",
    "",
  );
  assert.deepEqual(
    [...validValues],
    ["none", "minimal", "low", "medium", "high", "xhigh"],
  );
  assert.equal(defaultValue, "medium");
});

test("empty provider returns all-7 with medium default", () => {
  const { validValues, defaultValue } = getProviderEffortConfig("", "");
  assert.equal(validValues.length, 7);
  assert.equal(defaultValue, "medium");
});

test("unknown provider returns all-7 with medium default", () => {
  const { validValues, defaultValue } = getProviderEffortConfig("goose", "");
  assert.equal(validValues.length, 7);
  assert.equal(defaultValue, "medium");
});

// ---------------------------------------------------------------------------
// getProviderEffortConfig — provider case-insensitivity
// ---------------------------------------------------------------------------

test("provider id matching is case-insensitive", () => {
  const lower = getProviderEffortConfig("anthropic", "claude-opus-4-7");
  const upper = getProviderEffortConfig("Anthropic", "claude-opus-4-7");
  assert.deepEqual([...lower.validValues], [...upper.validValues]);
  assert.equal(lower.defaultValue, upper.defaultValue);
});

// ---------------------------------------------------------------------------
// getProviderEffortConfig — auto-clear logic (valid-values membership)
// ---------------------------------------------------------------------------

// Tests below verify the validValues membership check that the auto-clear
// useEffect in AmbushAgentModelTuningFields and AgentDefaultsSettingsCard
// use to decide whether to reset the current effort to Inherit.

test("effort max is invalid for OpenAI (should trigger auto-clear)", () => {
  const { validValues } = getProviderEffortConfig("openai", "gpt-5.1");
  assert.ok(!validValues.includes("max"), "max must not be in gpt-5.1 set");
});

test("effort none is invalid for Anthropic adaptive (should trigger auto-clear)", () => {
  const { validValues } = getProviderEffortConfig(
    "anthropic",
    "claude-opus-4-7",
  );
  assert.ok(!validValues.includes("none"), "none must not be in anthropic set");
});

test("effort high is valid for all providers (must not trigger auto-clear)", () => {
  for (const provider of [
    "anthropic",
    "openai",
    "databricks_v2",
    "databricks",
    "openai-compat",
    "",
  ]) {
    const { validValues } = getProviderEffortConfig(provider, "");
    assert.ok(
      validValues.includes("high"),
      `high must be valid for provider "${provider}"`,
    );
  }
});

test("effort none is invalid for anthropic manual-budget (should trigger auto-clear)", () => {
  const { validValues } = getProviderEffortConfig(
    "anthropic",
    "claude-3-7-sonnet-20250219",
  );
  assert.ok(
    !validValues.includes("none"),
    "none must not be in manual-budget set",
  );
});
