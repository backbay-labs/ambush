#[test]
fn dispatcher_admission_is_linear_and_not_publicly_forgeable() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail(
        "tests/ui/one_dispatcher_admission_can_be_reused_for_two_enforced_executions.rs",
    );
    cases.compile_fail("tests/ui/routed_action_request_cannot_be_forged.rs");
    cases.compile_fail("tests/ui/resume_clock_cannot_be_selected.rs");
    cases.compile_fail("tests/ui/fake_governance_authority_cannot_be_implemented.rs");
    cases.compile_fail("tests/ui/legacy_policy_governance_traits_do_not_exist.rs");
    cases.compile_fail("tests/ui/governance_authority_cannot_be_constructed.rs");
    cases.compile_fail("tests/ui/fake_governance_authority_cannot_be_installed.rs");
    cases.pass("tests/ui/legacy_first_run_api_compiles.rs");
}
