------------------------ MODULE PartitionContingency ------------------------
(***************************************************************************)
(* SAFEP-04: a bounded model of the partition-contingency-lease protocol,  *)
(* the highest-risk concurrent logic in Ambush.                            *)
(*                                                                         *)
(* It models the four partition states, contingency-lease issuance (only   *)
(* in a partition, only via an approved governance receipt, with a         *)
(* blast-radius cap), redemption (cap-bounded and expiry-denied), and      *)
(* reconciliation on heal (the lease is settled and pruned). The named     *)
(* invariants are the TLA+ statements of properties P3/P4/P5 in            *)
(* formal/PROPERTIES.md; formal/tla/negative/ breaks them one at a time    *)
(* (SAFEP-05).                                                             *)
(*                                                                         *)
(* Apalache (typed) checks it: apalache-mc check --inv=<Inv> --length=N.   *)
(***************************************************************************)
EXTENDS Integers

CONSTANTS
    \* @type: Int;
    BlastRadiusCap,
    \* @type: Int;
    LeaseDuration,
    \* @type: Int;
    MaxClock

VARIABLES
    \* @type: Str;   "Healthy" | "Degraded" | "Partitioned" | "Healing"
    partitionState,
    \* @type: Bool;  a contingency lease is currently active
    leaseActive,
    \* @type: Bool;  the active lease was issued against an approved receipt
    leaseHasReceipt,
    \* @type: Int;   scopes redeemed under the active lease
    redeemedCount,
    \* @type: Int;   logical clock
    clock,
    \* @type: Int;   the active lease's expiry time
    leaseExpiry,
    \* @type: Bool;  a redemption ever occurred at or after expiry (must stay FALSE)
    redeemedWhileExpired

vars == << partitionState, leaseActive, leaseHasReceipt, redeemedCount,
           clock, leaseExpiry, redeemedWhileExpired >>

States == { "Healthy", "Degraded", "Partitioned", "Healing" }

Init ==
    /\ partitionState = "Healthy"
    /\ leaseActive = FALSE
    /\ leaseHasReceipt = FALSE
    /\ redeemedCount = 0
    /\ clock = 0
    /\ leaseExpiry = 0
    /\ redeemedWhileExpired = FALSE

Degrade ==
    /\ partitionState = "Healthy"
    /\ partitionState' = "Degraded"
    /\ UNCHANGED << leaseActive, leaseHasReceipt, redeemedCount, clock,
                    leaseExpiry, redeemedWhileExpired >>

Partition ==
    /\ partitionState = "Degraded"
    /\ partitionState' = "Partitioned"
    /\ UNCHANGED << leaseActive, leaseHasReceipt, redeemedCount, clock,
                    leaseExpiry, redeemedWhileExpired >>

\* A contingency lease is issued only in a partition and only via an approved
\* receipt (OverrideRequiresReceipt), with a fresh blast-radius budget.
IssueLease ==
    /\ partitionState = "Partitioned"
    /\ ~leaseActive
    /\ leaseActive' = TRUE
    /\ leaseHasReceipt' = TRUE
    /\ redeemedCount' = 0
    /\ leaseExpiry' = clock + LeaseDuration
    /\ UNCHANGED << partitionState, clock, redeemedWhileExpired >>

\* Redemption fails closed: only an active, receipt-backed, unexpired lease with
\* remaining blast-radius budget may redeem one more scope.
Redeem ==
    /\ leaseActive
    /\ leaseHasReceipt
    /\ clock < leaseExpiry
    /\ redeemedCount < BlastRadiusCap
    /\ redeemedCount' = redeemedCount + 1
    /\ redeemedWhileExpired' = (redeemedWhileExpired \/ (clock >= leaseExpiry))
    /\ UNCHANGED << partitionState, leaseActive, leaseHasReceipt, clock,
                    leaseExpiry >>

Tick ==
    /\ clock < MaxClock
    /\ clock' = clock + 1
    /\ UNCHANGED << partitionState, leaseActive, leaseHasReceipt, redeemedCount,
                    leaseExpiry, redeemedWhileExpired >>

Heal ==
    /\ partitionState \in { "Degraded", "Partitioned" }
    /\ partitionState' = "Healing"
    /\ UNCHANGED << leaseActive, leaseHasReceipt, redeemedCount, clock,
                    leaseExpiry, redeemedWhileExpired >>

\* Reconciliation on heal settles and prunes the lease.
Reconcile ==
    /\ partitionState = "Healing"
    /\ partitionState' = "Healthy"
    /\ leaseActive' = FALSE
    /\ leaseHasReceipt' = FALSE
    /\ redeemedCount' = 0
    /\ leaseExpiry' = 0
    /\ UNCHANGED << clock, redeemedWhileExpired >>

Next ==
    \/ Degrade \/ Partition \/ IssueLease \/ Redeem \/ Tick \/ Heal \/ Reconcile

Spec == Init /\ [][Next]_vars

------------------------------------------------------------------------------
\* Bounded constant assignment for Apalache (--cinit=CInit).
CInit ==
    /\ BlastRadiusCap = 2
    /\ LeaseDuration = 3
    /\ MaxClock = 6

------------------------------------------------------------------------------
\* Named safety invariants (P3/P4/P5 in formal/PROPERTIES.md).

\* P4 blast-radius conservation: redemption never exceeds the cap.
BlastRadiusNeverExceeded == redeemedCount <= BlastRadiusCap

\* P3 partition-override receipt integrity: a lease exists only via a receipt.
OverrideRequiresReceipt == leaseActive => leaseHasReceipt

\* P4/expiry: no redemption ever occurs at or after the lease's expiry.
NoRedemptionAfterExpiry == ~redeemedWhileExpired

\* Reconciliation-on-heal: a healthy system holds no contingency lease.
NoLeaseWhenHealthy == (partitionState = "Healthy") => ~leaseActive

\* Type/state sanity used as a cheap all-invariant conjunction.
TypeOK ==
    /\ partitionState \in States
    /\ redeemedCount >= 0
    /\ clock >= 0

AllInvariants ==
    /\ BlastRadiusNeverExceeded
    /\ OverrideRequiresReceipt
    /\ NoRedemptionAfterExpiry
    /\ NoLeaseWhenHealthy
    /\ TypeOK
==============================================================================
