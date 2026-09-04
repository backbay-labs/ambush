// Whether the grant is armed, and for which hold.
//
// Module-level on purpose: arming must survive a row re-render, or a queue that
// refetched between the two strokes would silently disarm and the operator's
// Enter would land on nothing. It must NOT survive a selection change or a
// community switch, and both of those are the whole reason this is a module
// with a fence rather than a `useState` in the control.
//
// The arming is keyed by hold id and never by "the selected row", so an armed
// grant cannot follow the cursor onto a different hold — the failure this
// two-stroke exists to prevent is granting the wrong thing, and a stroke that
// arms one row and fires on another is that failure with extra steps.

let armedHoldId: string | null = null;
let selectedHoldId: string | null = null;

/** Arm the grant for one hold. The second stroke is what records. */
export function armGrant(holdId: string): void {
  armedHoldId = holdId;
}

/** Disarm without recording. */
export function disarmGrant(): void {
  armedHoldId = null;
}

/** Whether `holdId` is the armed hold. Never "is something armed". */
export function isGrantArmed(holdId: string): boolean {
  return armedHoldId === holdId;
}

/**
 * Tell the arming state which hold is selected now.
 *
 * A change disarms. Called on every selection change, including to `null`.
 */
export function noteHoldSelected(holdId: string | null): void {
  if (holdId !== selectedHoldId) armedHoldId = null;
  selectedHoldId = holdId;
}

/**
 * Community-switch fence, registered in the typed reset registry
 * (`features/communities/communityScopedRegistry.ts`). An armed grant is armed
 * against one colony's hold; carrying it across would leave a live second
 * stroke pointing at an id the new daemon has never heard of.
 */
export function resetKeymapArmingState(): void {
  armedHoldId = null;
  selectedHoldId = null;
}
