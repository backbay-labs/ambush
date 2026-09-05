/**
 * OS notification bodies.
 *
 * An OS notification is rendered by the operating system, outside this app's
 * markup and outside its escaping. So no adversary-controlled string may reach
 * one: every interpolation is a TYPED FIELD from the list below, and
 * `tools/check-perch-notification-fields.sh` fails the build on any other name.
 * A detector's `command_line` in a notification body is a remote-controlled
 * string on the operator's lock screen.
 */
export const NOTIFICATION_FIELDS = [
  "actionKind",
  "severity",
  "threatClass",
  "inverseKind",
  "rollbackStatus",
  "cardKind",
  "perchLabel",
  "holdIdShort",
  "leaseIdShort",
  "relative",
  "n",
  "m",
  "strength",
  "incidentThreshold",
] as const;

/**
 * The four wake classes, and only four.
 *
 * Findings never page. A fifth key here fails the gate, because the set of
 * things allowed to interrupt a person is a decision, not a default — and
 * every surface that can add one would otherwise add one.
 */
export const NOTIFICATION_BODIES = {
  incident:
    "Mode INCIDENT · {threatClass} · strength {strength} crossed incident_threshold {incidentThreshold}",
  holdNamedYou:
    "A held {actionKind} at {severity} names you · hold {holdIdShort} · decide within {relative}",
  // Class 3 deliberately carries no TTL-backstop sentence. The backstop is
  // exactly what failed; repeating "it self-releases" here would tell the
  // operator to wait for a mechanism that has already not worked.
  containmentFailedToRelease:
    "Containment lease {leaseIdShort} expired and the sweep failed. The host is still contained. This will not clear on its own.",
  snoozeDue: "Snooze returned · {cardKind} {perchLabel}",
} as const;

export type NotificationClass = keyof typeof NOTIFICATION_BODIES;
