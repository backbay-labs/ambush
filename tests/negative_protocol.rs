//! Shared typed protocol for Phase-285 fail-closed differential tests.
//!
//! Each registered case is a named [`RegisteredNegativeCase`] adapter. The
//! shared executor owns the only operation sequence: one real call, one
//! mirror(None) call, and one mirror(BrokenVariant) call over the same typed
//! probe. It checks the mutation roles before executing and then checks the
//! real/control denial and broken permission differential.
//!
//! The assertion macros own the production call itself. Call sites provide an
//! exact function path and argument expressions, followed by a narrow inline
//! projection of that call's result. The registry gate parses and locally
//! digests the complete protocol and registered test AST, including the
//! production path, setup, mirror roles, and denial/permission predicates.
//! Those co-located digests expose uncoordinated drift; they are not external
//! provenance and do not resist a coherent edit of the checker and its inputs.

use core::fmt::Debug;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MutationRole {
    Control,
    Broken,
    Other,
}

#[allow(async_fn_in_trait)]
pub(crate) trait RegisteredNegativeCase {
    type Probe;
    type Outcome: Debug + PartialEq;
    type Mutation: Copy + Debug + PartialEq;

    const INVARIANT: &'static str;
    const CONTROL: Self::Mutation;
    const BROKEN: Self::Mutation;

    fn mutation_role(mutation: Self::Mutation) -> MutationRole;
    async fn real(&mut self, probe: &Self::Probe) -> Self::Outcome;
    async fn mirror(&mut self, probe: &Self::Probe, mutation: Self::Mutation) -> Self::Outcome;
    fn denied(outcome: &Self::Outcome) -> bool;
    fn permitted(outcome: &Self::Outcome) -> bool;
}

pub(crate) async fn execute_registered_negative_case<C>(mut case: C, probe: C::Probe) -> C
where
    C: RegisteredNegativeCase,
{
    assert!(!C::INVARIANT.is_empty(), "case invariant identity is empty");
    assert_eq!(
        C::mutation_role(C::CONTROL),
        MutationRole::Control,
        "control mutation role is not None"
    );
    assert_eq!(
        C::mutation_role(C::BROKEN),
        MutationRole::Broken,
        "broken mutation role is not BrokenVariant"
    );

    let real = case.real(&probe).await;
    let control = case.mirror(&probe, C::CONTROL).await;
    let broken = case.mirror(&probe, C::BROKEN).await;

    assert_eq!(
        real, control,
        "the unmutated mirror drifted from the real denial"
    );
    assert!(C::denied(&real), "the real operation did not deny");
    assert!(
        C::permitted(&broken),
        "removing the named guard did not permit"
    );
    case
}

fn block_on_ready<F: Future>(future: F) -> F::Output {
    // Synchronous registered cases must complete on the first poll; a pending
    // future is a protocol misuse and panics below.
    let mut context = Context::from_waker(Waker::noop());
    let mut future = Box::pin(future);
    match Pin::as_mut(&mut future).poll(&mut context) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("synchronous negative case returned Pending"),
    }
}

pub(crate) fn execute_registered_negative_case_sync<C>(case: C, probe: C::Probe) -> C
where
    C: RegisteredNegativeCase,
{
    block_on_ready(execute_registered_negative_case(case, probe))
}

#[allow(unused_macros)]
macro_rules! define_registered_negative_case {
    (
        case: $case:ident,
        mutation: $mutation_ty:ty,
        control: $control:path,
        broken: $broken:path,
        state: { $($state_name:ident : $state_ty:ty = $state:expr),* $(,)? },
        probe: $probe_ty:ty = $probe:expr,
        outcome: $outcome_ty:ty,
        real_probe: $real_probe:ident,
        production: $production:path,
        arguments: ($($production_arg:expr),* $(,)?),
        call: $call:ident,
        normalize: |$production_result:ident| $normalize:expr,
        mirror: |$mirror_state:ident, $mirror_probe:ident, $mirror_mutation:ident| $mirror:expr,
        denied: |$denied_outcome:ident| $denied:expr,
        permitted: |$permitted_outcome:ident| $permitted:expr $(,)?
    ) => {{
        #[allow(non_camel_case_types)]
        struct $case {
            $($state_name: $state_ty),*
        }

        impl $crate::negative_protocol::RegisteredNegativeCase for $case {
            type Probe = $probe_ty;
            type Outcome = $outcome_ty;
            type Mutation = $mutation_ty;

            const INVARIANT: &'static str = stringify!($case);
            const CONTROL: Self::Mutation = $control;
            const BROKEN: Self::Mutation = $broken;

            fn mutation_role(mutation: Self::Mutation) -> $crate::negative_protocol::MutationRole {
                if mutation == $control {
                    $crate::negative_protocol::MutationRole::Control
                } else if mutation == $broken {
                    $crate::negative_protocol::MutationRole::Broken
                } else {
                    $crate::negative_protocol::MutationRole::Other
                }
            }

            #[allow(unused_variables)]
            async fn real(&mut self, probe: &Self::Probe) -> Self::Outcome {
                $(let $state_name = &mut self.$state_name;)*
                let $real_probe = probe;
                let $production_result = $crate::negative_protocol::invoke_registered_production!(
                    $call,
                    $production,
                    ($($production_arg),*)
                );
                $normalize
            }

            #[allow(unused_variables)]
            async fn mirror(
                &mut self,
                probe: &Self::Probe,
                mutation: Self::Mutation,
            ) -> Self::Outcome {
                let $mirror_state = self;
                $(let $state_name = &mut $mirror_state.$state_name;)*
                let $mirror_probe = probe;
                let $mirror_mutation = mutation;
                $mirror
            }

            fn denied(outcome: &Self::Outcome) -> bool {
                let $denied_outcome = outcome;
                $denied
            }

            fn permitted(outcome: &Self::Outcome) -> bool {
                let $permitted_outcome = outcome;
                $permitted
            }
        }

        ($case { $($state_name: $state),* }, $probe)
    }};
    (
        case: $case:ident,
        mutation: $mutation_ty:ty,
        control: $control:path,
        broken: $broken:path,
        state: { $($state_name:ident : $state_ty:ty = $state:expr),* $(,)? },
        probe: $probe_ty:ty = $probe:expr,
        outcome: $outcome_ty:ty,
        real_probe: $real_probe:ident,
        production_each: $production:path,
        arguments_each: ($($production_arg:expr),* $(,)?),
        items: $item:ident in $iter:expr,
        normalize_each: |$production_result:ident, $normalize_item:ident| $normalize:expr,
        mirror: |$mirror_state:ident, $mirror_probe:ident, $mirror_mutation:ident| $mirror:expr,
        denied: |$denied_outcome:ident| $denied:expr,
        permitted: |$permitted_outcome:ident| $permitted:expr $(,)?
    ) => {{
        #[allow(non_camel_case_types)]
        struct $case {
            $($state_name: $state_ty),*
        }

        impl $crate::negative_protocol::RegisteredNegativeCase for $case {
            type Probe = $probe_ty;
            type Outcome = $outcome_ty;
            type Mutation = $mutation_ty;

            const INVARIANT: &'static str = stringify!($case);
            const CONTROL: Self::Mutation = $control;
            const BROKEN: Self::Mutation = $broken;

            fn mutation_role(mutation: Self::Mutation) -> $crate::negative_protocol::MutationRole {
                if mutation == $control {
                    $crate::negative_protocol::MutationRole::Control
                } else if mutation == $broken {
                    $crate::negative_protocol::MutationRole::Broken
                } else {
                    $crate::negative_protocol::MutationRole::Other
                }
            }

            #[allow(unused_variables)]
            async fn real(&mut self, probe: &Self::Probe) -> Self::Outcome {
                $(let $state_name = &mut self.$state_name;)*
                let $real_probe = probe;
                let mut outcomes = Vec::new();
                for $item in $iter {
                    let $production_result = $production($($production_arg),*);
                    let $normalize_item = $item;
                    outcomes.push($normalize);
                }
                outcomes
            }

            #[allow(unused_variables)]
            async fn mirror(
                &mut self,
                probe: &Self::Probe,
                mutation: Self::Mutation,
            ) -> Self::Outcome {
                let $mirror_state = self;
                $(let $state_name = &mut $mirror_state.$state_name;)*
                let $mirror_probe = probe;
                let $mirror_mutation = mutation;
                $mirror
            }

            fn denied(outcome: &Self::Outcome) -> bool {
                let $denied_outcome = outcome;
                $denied
            }

            fn permitted(outcome: &Self::Outcome) -> bool {
                let $permitted_outcome = outcome;
                $permitted
            }
        }

        ($case { $($state_name: $state),* }, $probe)
    }};
}

macro_rules! invoke_registered_production {
    (sync, $production:path, ($($argument:expr),* $(,)?)) => {
        $production($($argument),*)
    };
    (awaited, $production:path, ($($argument:expr),* $(,)?)) => {
        $production($($argument),*).await
    };
}

macro_rules! assert_registered_negative_case {
    ($($tokens:tt)*) => {{
        let (case, probe) = $crate::negative_protocol::define_registered_negative_case! { $($tokens)* };
        let _completed_case =
            $crate::negative_protocol::execute_registered_negative_case_sync(case, probe);
    }};
}

#[allow(unused_macros)]
macro_rules! assert_registered_async_negative_case {
    ($($tokens:tt)*) => {{
        let (case, probe) = $crate::negative_protocol::define_registered_negative_case! { $($tokens)* };
        let _completed_case =
            $crate::negative_protocol::execute_registered_negative_case(case, probe).await;
    }};
}

#[allow(unused_imports)]
pub(crate) use assert_registered_async_negative_case;
pub(crate) use assert_registered_negative_case;
pub(crate) use define_registered_negative_case;
pub(crate) use invoke_registered_production;
