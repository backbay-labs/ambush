//! Shared typed protocol for Phase-285 fail-closed differential tests.
//!
//! The macro owns the three protocol operations. A case supplies one typed
//! probe, the real operation, and one mirror operation selected by a typed
//! mutation. The protocol compares the real result with `None`, proves that
//! result is a denial, and proves the named broken mutation permits it.
//!
//! This does not mechanically prove that a handwritten mirror is a faithful
//! copy of production for inputs other than the registered probe. The typed
//! protocol proves only that the registered real and mirror operations are
//! executed over that same probe and satisfy the stated differential.

macro_rules! assert_registered_negative_case {
    (
        case: $case:ident,
        mutation: $mutation_ty:ty,
        control: $control:path,
        broken: $broken:path,
        probe: $probe_ty:ty = $probe:expr,
        outcome: $outcome_ty:ty,
        real: |$real_probe:ident| $real:expr,
        mirror: |$mirror_probe:ident, $mirror_mutation:ident| $mirror:expr,
        denied: |$denied_outcome:ident| $denied:expr,
        permitted: |$permitted_outcome:ident| $permitted:expr $(,)?
    ) => {{
        #[allow(non_camel_case_types)]
        struct $case;
        let _typed_case_identity = core::marker::PhantomData::<$case>;
        let probe: $probe_ty = $probe;

        let real: $outcome_ty = {
            let $real_probe = &probe;
            $real
        };
        let control: $outcome_ty = {
            let $mirror_probe = &probe;
            let $mirror_mutation: $mutation_ty = $control;
            $mirror
        };
        let broken: $outcome_ty = {
            let $mirror_probe = &probe;
            let $mirror_mutation: $mutation_ty = $broken;
            $mirror
        };

        assert_eq!(
            real, control,
            concat!(
                stringify!($case),
                ": the unmutated mirror drifted from the real denial"
            )
        );
        assert!(
            {
                let $denied_outcome = &real;
                $denied
            },
            concat!(stringify!($case), ": the real operation did not deny")
        );
        assert!(
            {
                let $permitted_outcome = &broken;
                $permitted
            },
            concat!(
                stringify!($case),
                ": removing the named guard did not permit"
            )
        );
    }};
}

pub(crate) use assert_registered_negative_case;
