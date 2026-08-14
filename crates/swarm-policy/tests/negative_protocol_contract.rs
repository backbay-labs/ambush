//! Executable contract for the shared Phase-285 typed negative protocol.

#![allow(clippy::expect_used)]

#[path = "../../../tests/negative_protocol.rs"]
mod negative_protocol;

use negative_protocol::{
    MutationRole, RegisteredNegativeCase, assert_registered_negative_case,
    execute_registered_negative_case_sync,
};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ContractMutation {
    None,
    Broken,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ContractOutcome {
    Denied,
    Permitted,
}

#[derive(Debug, Default, PartialEq, Eq)]
struct Calls {
    real: usize,
    control: usize,
    broken: usize,
    roles: Vec<ContractMutation>,
}

#[derive(Clone)]
struct ContractState {
    calls: Arc<Mutex<Calls>>,
    real: ContractOutcome,
    control: ContractOutcome,
    broken: ContractOutcome,
}

impl ContractState {
    fn new(real: ContractOutcome, control: ContractOutcome, broken: ContractOutcome) -> Self {
        Self {
            calls: Arc::new(Mutex::new(Calls::default())),
            real,
            control,
            broken,
        }
    }

    fn real(&self, _probe: &u8) -> ContractOutcome {
        self.calls.lock().expect("calls lock").real += 1;
        self.real
    }

    fn mirror(&self, _probe: &u8, mutation: ContractMutation) -> ContractOutcome {
        let mut calls = self.calls.lock().expect("calls lock");
        calls.roles.push(mutation);
        match mutation {
            ContractMutation::None => {
                calls.control += 1;
                self.control
            }
            ContractMutation::Broken => {
                calls.broken += 1;
                self.broken
            }
        }
    }
}

macro_rules! run_contract_case {
    ($case:ident, $state:expr) => {{
        assert_registered_negative_case! {
            case: $case,
            mutation: ContractMutation,
            control: ContractMutation::None,
            broken: ContractMutation::Broken,
            state: { state: ContractState = $state },
            probe: u8 = 7,
            outcome: ContractOutcome,
            real: |state, probe| state.real(probe),
            mirror: |state, probe, mutation| state.mirror(probe, mutation),
            denied: |outcome| outcome == &ContractOutcome::Denied,
            permitted: |outcome| outcome == &ContractOutcome::Permitted,
        }
    }};
}

#[test]
fn protocol_executes_each_typed_role_exactly_once() {
    let state = ContractState::new(
        ContractOutcome::Denied,
        ContractOutcome::Denied,
        ContractOutcome::Permitted,
    );
    let calls = state.calls.clone();
    run_contract_case!(PROTOCOL_SUCCESS, state);
    assert_eq!(
        *calls.lock().expect("calls lock"),
        Calls {
            real: 1,
            control: 1,
            broken: 1,
            roles: vec![ContractMutation::None, ContractMutation::Broken],
        }
    );
}

#[test]
#[should_panic(expected = "unmutated mirror drifted")]
fn protocol_rejects_real_control_mismatch() {
    run_contract_case!(
        PROTOCOL_MISMATCH,
        ContractState::new(
            ContractOutcome::Denied,
            ContractOutcome::Permitted,
            ContractOutcome::Permitted,
        )
    );
}

#[test]
#[should_panic(expected = "real operation did not deny")]
fn protocol_rejects_permitting_real() {
    run_contract_case!(
        PROTOCOL_PERMITTING_REAL,
        ContractState::new(
            ContractOutcome::Permitted,
            ContractOutcome::Permitted,
            ContractOutcome::Permitted,
        )
    );
}

#[test]
#[should_panic(expected = "named guard did not permit")]
fn protocol_rejects_denying_broken() {
    run_contract_case!(
        PROTOCOL_DENYING_BROKEN,
        ContractState::new(
            ContractOutcome::Denied,
            ContractOutcome::Denied,
            ContractOutcome::Denied,
        )
    );
}

struct SwappedRoleCase;

impl RegisteredNegativeCase for SwappedRoleCase {
    type Probe = ();
    type Outcome = ContractOutcome;
    type Mutation = ContractMutation;

    const INVARIANT: &'static str = "PROTOCOL_SWAPPED_ROLES";
    const CONTROL: Self::Mutation = ContractMutation::Broken;
    const BROKEN: Self::Mutation = ContractMutation::None;

    fn mutation_role(mutation: Self::Mutation) -> MutationRole {
        match mutation {
            ContractMutation::None => MutationRole::Control,
            ContractMutation::Broken => MutationRole::Broken,
        }
    }

    async fn real(&mut self, _probe: &Self::Probe) -> Self::Outcome {
        ContractOutcome::Denied
    }

    async fn mirror(&mut self, _probe: &Self::Probe, mutation: Self::Mutation) -> Self::Outcome {
        match mutation {
            ContractMutation::None => ContractOutcome::Denied,
            ContractMutation::Broken => ContractOutcome::Permitted,
        }
    }

    fn denied(outcome: &Self::Outcome) -> bool {
        outcome == &ContractOutcome::Denied
    }

    fn permitted(outcome: &Self::Outcome) -> bool {
        outcome == &ContractOutcome::Permitted
    }
}

#[test]
#[should_panic(expected = "control mutation role is not None")]
fn protocol_rejects_swapped_none_and_broken_roles() {
    let _ = execute_registered_negative_case_sync(SwappedRoleCase, ());
}
