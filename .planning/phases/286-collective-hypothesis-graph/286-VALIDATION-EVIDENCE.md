# Phase 286 Validation Evidence

Only rows with current nonzero execution evidence are listed. The strict
matrix checker requires an exact `task_id` and complete normalized `command`
entry before a row may be marked green.

## 286-00-01

task_id: 286-00-01
command: cargo test -p swarm-runtime --test collective_hypothesis_oracle benchmark_manifest_is_strict --locked --offline -- --exact
result_status: pass
passed_count: 1
failed_count: 0

## 286-00-02

task_id: 286-00-02
command: cargo test -p swarm-runtime --test negative_graph_response_boundary boundary_checker_rejects_broken_fixture --locked --offline -- --exact
result_status: pass
passed_count: 1
failed_count: 0

## 286-00-03

task_id: 286-00-03
command: bash -n tools/check-collective-hypothesis-graph.sh && bash tools/check-collective-hypothesis-graph.sh --self-test && cargo test -p swarm-runtime --test collective_hypothesis_oracle benchmark_manifest_is_strict --locked --offline -- --exact && cargo test -p swarm-runtime --test negative_graph_response_boundary boundary_checker_rejects_broken_fixture --locked --offline -- --exact && git diff --check
result_status: pass
passed_count: 5
failed_count: 0

## 286-00B-01

task_id: 286-00B-01
command: python3 tools/check-phase286-validation-matrix.py --strict --self-test --cwd . && git diff --check
result_status: pass
passed_count: 2
failed_count: 0

## 286-01B-01

task_id: 286-01B-01
command: cargo test -p swarm-runtime --lib --locked --offline canary::tests::canary_support_config_preserves_disabled_graph_and_legacy_runtime_bytes -- --exact --nocapture && cargo test -p swarm-runtime --lib --locked --offline promotion::tests::promotion_support_config_preserves_disabled_graph_and_legacy_runtime_bytes -- --exact --nocapture && cargo test -p swarm-runtime --lib --locked --offline service::tests::service_support_config_preserves_disabled_graph_and_legacy_runtime_bytes -- --exact --nocapture && cargo fmt --all -- --check && git diff --check
result_status: pass
passed_count: 5
failed_count: 0
