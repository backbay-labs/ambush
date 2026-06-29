import { randomUUID } from 'node:crypto'
import type { ApprovalRequest, ApprovalResolution } from '@shared/types'
import { bus } from '../util/bus'

const DEFAULT_TTL_MS = 60_000
const MAX_TTL_MS = 3_600_000
const MAX_QUEUE = 500
const RESOLVED_RETENTION_MS = 10 * 60_000

export interface ApprovalRequestInput {
  tool: string
  resource: string
  guard: string
  reason: string
  severity: string
  ttlMs?: number
}

/**
 * In-memory human-gate approval queue. Ported from the upstream ClawdStrike approval
 * queue (apps/agent, Apache-2.0): per-request TTL, dedup of identical pending requests,
 * capacity eviction, and a trusted-vs-local resolution split. Lifecycle changes are
 * emitted on the bus so the renderer's Approvals pane stays live. Lives in the control
 * plane today; moves to the engine trust-kernel once the convergence is wired.
 */
export class ApprovalQueue {
  /** Resource key for the "launch ungoverned?" gate (ties into the fail-closed governor). */
  static readonly UNGOVERNED_RESOURCE = 'swarm:ungoverned-launch'

  private requests = new Map<string, ApprovalRequest>()
  private sessionGrants = new Set<string>()
  private timer: NodeJS.Timeout | null = null

  /** Start the background sweep that expires stale and GCs old resolved requests. */
  start(): void {
    if (this.timer) return
    this.timer = setInterval(() => this.gc(), 10_000)
    this.timer.unref?.()
  }

  stop(): void {
    if (this.timer) {
      clearInterval(this.timer)
      this.timer = null
    }
  }

  /** Current requests (pending + recently resolved), newest first. */
  list(): ApprovalRequest[] {
    this.expireStale()
    return [...this.requests.values()].sort((a, b) => b.createdAt - a.createdAt)
  }

  request(input: ApprovalRequestInput): ApprovalRequest {
    this.expireStale()
    // Dedup: an identical pending request is reused rather than duplicated.
    for (const r of this.requests.values()) {
      if (
        r.status === 'pending' &&
        r.tool === input.tool &&
        r.resource === input.resource &&
        r.guard === input.guard &&
        r.reason === input.reason
      ) {
        return r
      }
    }
    this.evictIfFull()
    const now = Date.now()
    const ttl = Math.min(input.ttlMs ?? DEFAULT_TTL_MS, MAX_TTL_MS)
    const req: ApprovalRequest = {
      id: randomUUID(),
      tool: input.tool,
      resource: input.resource,
      guard: input.guard,
      reason: input.reason,
      severity: input.severity,
      status: 'pending',
      resolution: null,
      resolvedByTrustedAuthority: false,
      createdAt: now,
      expiresAt: now + ttl,
      resolvedAt: null,
    }
    this.requests.set(req.id, req)
    bus.approvalNew(req)
    return req
  }

  /** Resolve from the trusted operator UI. */
  resolve(id: string, resolution: ApprovalResolution): ApprovalRequest | null {
    return this.resolveWithTrust(id, resolution, true)
  }

  /** Resolve from a low-trust/local path (gates may reject these). */
  resolveLocal(id: string, resolution: ApprovalResolution): ApprovalRequest | null {
    return this.resolveWithTrust(id, resolution, false)
  }

  private resolveWithTrust(
    id: string,
    resolution: ApprovalResolution,
    trusted: boolean,
  ): ApprovalRequest | null {
    const req = this.requests.get(id)
    if (!req || req.status !== 'pending') return null
    req.status = 'resolved'
    req.resolution = resolution
    req.resolvedByTrustedAuthority = trusted
    req.resolvedAt = Date.now()
    // Only a TRUSTED operator resolution grants standing authority — a local/untrusted resolution
    // resolves the request but never adds a session grant (otherwise the trust flag is decorative).
    if (trusted && (resolution === 'allow-session' || resolution === 'allow-always')) {
      this.sessionGrants.add(req.resource)
    }
    bus.approvalResolved(req)
    return req
  }

  /** Per-operation key for the ungoverned-launch grant so it never leaks across operations. */
  private static ungovernedKey(operationId: string): string {
    return `${ApprovalQueue.UNGOVERNED_RESOURCE}:${operationId}`
  }

  /** Whether a session/always grant exists for a resource key. */
  isGranted(resource: string): boolean {
    return this.sessionGrants.has(resource)
  }

  /** Producer: enqueue (deduped) the "launch ungoverned?" human-gate request, scoped to this op. */
  requestUngovernedLaunch(operationName: string, operationId: string): ApprovalRequest {
    return this.request({
      tool: 'swarm.deploy',
      resource: ApprovalQueue.ungovernedKey(operationId),
      guard: 'governance.fail_closed',
      reason: `Operation "${operationName}" has no active governor — launching agents UNGOVERNED (no signed receipts). Approve to proceed for this operation.`,
      severity: 'high',
      ttlMs: MAX_TTL_MS,
    })
  }

  isUngovernedAllowed(operationId: string): boolean {
    return this.isGranted(ApprovalQueue.ungovernedKey(operationId))
  }

  private expireStale(): void {
    const now = Date.now()
    for (const r of this.requests.values()) {
      if (r.status === 'pending' && r.expiresAt <= now) {
        r.status = 'expired'
        bus.approvalExpired(r.id)
      }
    }
  }

  private gc(): void {
    this.expireStale()
    const cutoff = Date.now() - RESOLVED_RETENTION_MS
    for (const [id, r] of this.requests) {
      if (r.status !== 'pending' && (r.resolvedAt ?? r.expiresAt) < cutoff) {
        this.requests.delete(id)
      }
    }
  }

  private evictIfFull(): void {
    if (this.requests.size < MAX_QUEUE) return
    // First evict resolved/expired entries.
    for (const [id, r] of this.requests) {
      if (r.status !== 'pending') {
        this.requests.delete(id)
        if (this.requests.size < MAX_QUEUE) return
      }
    }
    // Still full of pending requests: evict the OLDEST pending (Map is insertion-ordered) so the
    // cap is a hard bound — a flood of distinct pending tuples cannot grow the map without limit.
    // Dropping a pending request grants nothing, so fail-closed semantics hold.
    for (const [id] of this.requests) {
      this.requests.delete(id)
      bus.approvalExpired(id)
      if (this.requests.size < MAX_QUEUE) return
    }
  }
}
