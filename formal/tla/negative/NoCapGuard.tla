--------------------------- MODULE NoCapGuard -------------------------------
(* SAFEP-05 negative variant N1: the blast-radius cap guard is REMOVED from   *)
(* Redeem, so redemption runs past the cap. Apalache must report a VIOLATION  *)
(* of BlastRadiusNeverExceeded. Runtime regression test pinning the same      *)
(* defect: swarm-policy formal_core `lease_redeem_fails_closed_on_mismatch_expiry_and_cap`. *)
(* Identical to PartitionContingency EXCEPT the one marked line.              *)
EXTENDS Integers
CONSTANTS
    \* @type: Int;
    BlastRadiusCap,
    \* @type: Int;
    LeaseDuration,
    \* @type: Int;
    MaxClock
VARIABLES
    \* @type: Str;
    partitionState,
    \* @type: Bool;
    leaseActive,
    \* @type: Bool;
    leaseHasReceipt,
    \* @type: Int;
    redeemedCount,
    \* @type: Int;
    clock,
    \* @type: Int;
    leaseExpiry,
    \* @type: Bool;
    redeemedWhileExpired
vars == << partitionState, leaseActive, leaseHasReceipt, redeemedCount,
           clock, leaseExpiry, redeemedWhileExpired >>
Init ==
    /\ partitionState = "Healthy" /\ leaseActive = FALSE /\ leaseHasReceipt = FALSE
    /\ redeemedCount = 0 /\ clock = 0 /\ leaseExpiry = 0 /\ redeemedWhileExpired = FALSE
Degrade == partitionState = "Healthy" /\ partitionState' = "Degraded"
    /\ UNCHANGED << leaseActive, leaseHasReceipt, redeemedCount, clock, leaseExpiry, redeemedWhileExpired >>
Partition == partitionState = "Degraded" /\ partitionState' = "Partitioned"
    /\ UNCHANGED << leaseActive, leaseHasReceipt, redeemedCount, clock, leaseExpiry, redeemedWhileExpired >>
IssueLease ==
    /\ partitionState = "Partitioned" /\ ~leaseActive
    /\ leaseActive' = TRUE /\ leaseHasReceipt' = TRUE /\ redeemedCount' = 0
    /\ leaseExpiry' = clock + LeaseDuration
    /\ UNCHANGED << partitionState, clock, redeemedWhileExpired >>
Redeem ==
    /\ leaseActive /\ leaseHasReceipt /\ clock < leaseExpiry
    \* DEFECT (N1): the `redeemedCount < BlastRadiusCap` guard is REMOVED here.
    /\ redeemedCount' = redeemedCount + 1
    /\ redeemedWhileExpired' = (redeemedWhileExpired \/ (clock >= leaseExpiry))
    /\ UNCHANGED << partitionState, leaseActive, leaseHasReceipt, clock, leaseExpiry >>
Tick == clock < MaxClock /\ clock' = clock + 1
    /\ UNCHANGED << partitionState, leaseActive, leaseHasReceipt, redeemedCount, leaseExpiry, redeemedWhileExpired >>
Heal == partitionState \in { "Degraded", "Partitioned" } /\ partitionState' = "Healing"
    /\ UNCHANGED << leaseActive, leaseHasReceipt, redeemedCount, clock, leaseExpiry, redeemedWhileExpired >>
Reconcile == partitionState = "Healing" /\ partitionState' = "Healthy"
    /\ leaseActive' = FALSE /\ leaseHasReceipt' = FALSE /\ redeemedCount' = 0 /\ leaseExpiry' = 0
    /\ UNCHANGED << clock, redeemedWhileExpired >>
Next == Degrade \/ Partition \/ IssueLease \/ Redeem \/ Tick \/ Heal \/ Reconcile
CInit == BlastRadiusCap = 2 /\ LeaseDuration = 3 /\ MaxClock = 6
BlastRadiusNeverExceeded == redeemedCount <= BlastRadiusCap
=============================================================================
