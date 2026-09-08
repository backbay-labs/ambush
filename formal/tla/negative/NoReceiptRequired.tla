----------------------- MODULE NoReceiptRequired ----------------------------
(* SAFEP-05 negative variant N3: IssueLease drops the receipt requirement     *)
(* (leaseHasReceipt := FALSE), so a contingency lease exists without an       *)
(* approved governance receipt. Apalache must report a VIOLATION of           *)
(* OverrideRequiresReceipt. Runtime regression test pinning the same defect:  *)
(* swarm-agents `keyless_policy_reloaded_into_a_partition_refuses_persisted_leases`. *)
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
    \* DEFECT (N3): leaseHasReceipt is set FALSE — no receipt required.
    /\ leaseActive' = TRUE /\ leaseHasReceipt' = FALSE /\ redeemedCount' = 0
    /\ leaseExpiry' = clock + LeaseDuration
    /\ UNCHANGED << partitionState, clock, redeemedWhileExpired >>
Redeem ==
    /\ leaseActive /\ leaseHasReceipt /\ clock < leaseExpiry /\ redeemedCount < BlastRadiusCap
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
OverrideRequiresReceipt == leaseActive => leaseHasReceipt
=============================================================================
