/**
 * The daemon's containment answers, narrowed at the boundary.
 *
 * Every field is read defensively and nothing is defaulted into a reassuring
 * value: an absent `expired` reads FALSE only because the daemon always sends
 * it, and an absent `lease_closed` reads `null` — "the daemon did not say" is
 * a third answer, and rendering it as "released" is the one mistake this
 * surface cannot make.
 */

export type ContainmentLeaseView = {
  leaseId: string;
  actionKind: string;
  scopeValue: string;
  originReceiptId: string;
  governanceReceiptId: string | null;
  issuedAtMs: number;
  expiresAtMs: number;
  remainingMs: number;
  expired: boolean;
};

export type ContainmentList = {
  leases: ContainmentLeaseView[];
  observedAtMs: number | null;
};

export type ReleaseOutcome = {
  /** `null` when the daemon did not say. Never defaulted to `true`. */
  leaseClosed: boolean | null;
  fullyReversed: boolean | null;
  attestationVerified: boolean | null;
  attestationError: string | null;
  steps: { label: string; status: string; reason?: string }[];
};

function asRecord(value: unknown): Record<string, unknown> {
  return typeof value === "object" && value !== null
    ? (value as Record<string, unknown>)
    : {};
}

function asString(value: unknown): string {
  return typeof value === "string" ? value : "";
}

function asNumber(value: unknown): number {
  return typeof value === "number" && Number.isFinite(value) ? value : 0;
}

function asOptionalBoolean(value: unknown): boolean | null {
  return typeof value === "boolean" ? value : null;
}

/** One lease row from the daemon's list. */
export function parseContainmentLease(value: unknown): ContainmentLeaseView {
  const lease = asRecord(value);
  return {
    leaseId: asString(lease.lease_id),
    actionKind: asString(lease.action_kind),
    scopeValue: asString(lease.scope_value),
    originReceiptId: asString(lease.origin_receipt_id),
    governanceReceiptId:
      typeof lease.governance_receipt_id === "string"
        ? lease.governance_receipt_id
        : null,
    issuedAtMs: asNumber(lease.issued_at_ms),
    expiresAtMs: asNumber(lease.expires_at_ms),
    remainingMs: asNumber(lease.remaining_ms),
    expired: lease.expired === true,
  };
}

/** The list route's body. */
export function parseContainmentList(value: unknown): ContainmentList {
  const body = asRecord(value);
  const raw = Array.isArray(body.leases) ? body.leases : [];
  return {
    // Served order is kept. The daemon sorts by expiry then id, and a board
    // that re-sorted would put a row somewhere the daemon's own paging did not.
    leases: raw.map(parseContainmentLease),
    observedAtMs:
      typeof body.observed_at_ms === "number" ? body.observed_at_ms : null,
  };
}

/** The release route's body. */
export function parseReleaseOutcome(value: unknown): ReleaseOutcome {
  const body = asRecord(value);
  const steps = Array.isArray(body.steps) ? body.steps : [];
  return {
    leaseClosed: asOptionalBoolean(body.lease_closed),
    fullyReversed: asOptionalBoolean(body.fully_reversed),
    attestationVerified: asOptionalBoolean(body.attestation_verified),
    attestationError:
      typeof body.attestation_error === "string"
        ? body.attestation_error
        : null,
    steps: steps.map((step) => {
      const record = asRecord(step);
      const reason = asString(record.detail);
      return {
        label: asString(record.kind),
        status: asString(record.status),
        ...(reason ? { reason } : {}),
      };
    }),
  };
}
