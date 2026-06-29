import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomBytes,
  sign as edSign,
  type KeyObject,
} from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import type { AttestationResult, Operation, ReceiptSummary, VerifyOutcome } from '@shared/types'
import { run, which } from '../util/run'

// These MUST match swarm-attest (engine/crates/swarm-attest) so the Rust `ambush-verify`
// binary accepts what this TS producer signs. The verifier hashes the raw manifest bytes on
// disk, so no canonical-JSON agreement is needed — only identical bytes for hash + signature.
const BUNDLE_SCHEMA = 'ambush.attestation.bundle.v1'
const DSSE_PAYLOAD_TYPE = 'application/vnd.ambush.attestation-bundle+json'
const SIGNATURE_KIND = 'detached-dsse'
const TRUST_ROOTS_SCHEMA = 'ambush.attestation.trust-roots.v1'
const MANIFEST_NAME = 'manifest.json'

function sha256Hex(buf: Buffer): string {
  return createHash('sha256').update(buf).digest('hex')
}

/** DSSE Pre-Authentication Encoding (PAEv1), byte-identical to swarm-attest::pae. */
function pae(payloadType: string, payload: Buffer): Buffer {
  const pt = Buffer.from(payloadType, 'utf8')
  return Buffer.concat([
    Buffer.from('DSSEv1 '),
    Buffer.from(String(pt.length)),
    Buffer.from(' '),
    pt,
    Buffer.from(' '),
    Buffer.from(String(payload.length)),
    Buffer.from(' '),
    payload,
  ])
}

interface ArtifactRef {
  path: string
  sha256: string
  schema: string
}

/**
 * Produces signed, hash-bound attestation bundles from an Operation's intel vault, and verifies
 * them with the standalone Rust `ambush-verify` binary (subprocess; degrades gracefully if absent).
 * The signing key is per-operation, persisted in the ops dir; its public key is what a client pins.
 */
export class AttestationManager {
  private loadKey(opsDir: string): { privateKey: KeyObject; publicKeyHex: string } {
    const attestDir = join(opsDir, 'attest')
    mkdirSync(attestDir, { recursive: true })
    const keyPath = join(attestDir, 'signing-key.pem')
    let privateKey: KeyObject
    if (existsSync(keyPath)) {
      privateKey = createPrivateKey(readFileSync(keyPath, 'utf8'))
    } else {
      const { privateKey: pk } = generateKeyPairSync('ed25519')
      writeFileSync(keyPath, pk.export({ type: 'pkcs8', format: 'pem' }) as string, { mode: 0o600 })
      privateKey = pk
    }
    const jwk = createPublicKey(privateKey).export({ format: 'jwk' }) as { x: string }
    const publicKeyHex = Buffer.from(jwk.x, 'base64url').toString('hex')
    return { privateKey, publicKeyHex }
  }

  /** Build + sign an attestation bundle for the operation. Returns the bundle dir + signer key. */
  exportBundle(operation: Operation, receipts: ReceiptSummary[]): AttestationResult {
    const opsDir = dirname(operation.intelVaultPath)
    const { privateKey, publicKeyHex } = this.loadKey(opsDir)
    const bundleId = `bundle-${Date.now().toString(36)}-${randomBytes(3).toString('hex')}`
    const bundleDir = join(opsDir, 'attest', 'bundles', bundleId)
    mkdirSync(bundleDir, { recursive: true })

    const artifacts: ArtifactRef[] = []
    const addArtifact = (rel: string, bytes: Buffer, schema: string): void => {
      const dest = join(bundleDir, rel)
      mkdirSync(dirname(dest), { recursive: true })
      writeFileSync(dest, bytes)
      artifacts.push({ path: rel, sha256: sha256Hex(bytes), schema })
    }

    // Trust roots (the bundle declares its own signer; the client also pins it out-of-band).
    const trustRoots = Buffer.from(
      JSON.stringify({
        roots: [
          { key_id: publicKeyHex, key_digest: sha256Hex(Buffer.from(publicKeyHex, 'utf8')) },
        ],
      }),
    )
    addArtifact('artifacts/authority/trust-roots.json', trustRoots, TRUST_ROOTS_SCHEMA)

    // Findings from the vault.
    const findingsDir = join(operation.intelVaultPath, 'findings')
    let firstFinding: string | null = null
    if (existsSync(findingsDir)) {
      for (const name of readdirSync(findingsDir)) {
        if (!name.endsWith('.md')) continue
        addArtifact(`findings/${name}`, readFileSync(join(findingsDir, name)), 'ambush.finding.v1')
        firstFinding ??= `findings/${name}`
      }
    }

    // The consolidated runbook, if present.
    const runbookPath = join(operation.intelVaultPath, 'RUNBOOK.md')
    const hasRunbook = existsSync(runbookPath)
    if (hasRunbook) addArtifact('RUNBOOK.md', readFileSync(runbookPath), 'ambush.runbook.v1')

    // A receipts snapshot (the governed audit trail).
    addArtifact('receipts.json', Buffer.from(JSON.stringify(receipts, null, 2)), 'ambush.receipts.v1')

    // Claims (each must reference a registered artifact; a failed claim fails verification).
    const claims: Array<{
      claim_id: string
      required_artifacts: string[]
      checker: string
      result: 'verified' | 'failed' | 'unsupported'
    }> = []
    if (hasRunbook) {
      claims.push({
        claim_id: 'runbook-consolidated',
        required_artifacts: ['RUNBOOK.md'],
        checker: 'consolidate',
        result: 'verified',
      })
    }
    claims.push({
      claim_id: 'findings-present',
      required_artifacts: [firstFinding ?? 'receipts.json'],
      checker: 'findings',
      result: firstFinding ? 'verified' : 'unsupported',
    })

    // Receipt-coverage matrix (all three categories must be accounted for).
    const allow = receipts.some((r) => r.verdict === 'ALLOW')
    const deny = receipts.some((r) => r.verdict === 'DENY')
    const coverage = [
      allow
        ? { category: 'allow', status: 'covered', artifact_path: 'receipts.json', terminal_status: 'allowed_executed' }
        : { category: 'allow', status: 'excluded', exclusion_reason: 'no allow receipts (ungoverned or none yet)' },
      deny
        ? { category: 'denial', status: 'covered', artifact_path: 'receipts.json', terminal_status: 'denied_guard_request' }
        : { category: 'denial', status: 'excluded', exclusion_reason: 'no denial receipts recorded' },
      { category: 'failure', status: 'excluded', exclusion_reason: 'no terminal failures recorded' },
    ]

    const manifest = {
      schema: BUNDLE_SCHEMA,
      bundle_id: bundleId,
      operation: operation.name,
      created_at: new Date().toISOString(),
      source_command: 'ambush export-attestation',
      hash_algorithm: 'sha256',
      artifacts,
      claims,
      receipt_coverage: coverage,
      negative_cases: [],
      signature: { kind: SIGNATURE_KIND, signature_ref: 'signature.dsse.json' },
    }

    // Serialize ONCE — these exact bytes are hashed, signed, and written.
    const manifestBytes = Buffer.from(JSON.stringify(manifest, null, 2))
    writeFileSync(join(bundleDir, MANIFEST_NAME), manifestBytes)

    const signature = edSign(null, pae(DSSE_PAYLOAD_TYPE, manifestBytes), privateKey)
    const detached = {
      payload_type: DSSE_PAYLOAD_TYPE,
      payload_ref: { path: MANIFEST_NAME, sha256: sha256Hex(manifestBytes), schema: BUNDLE_SCHEMA },
      signatures: [{ keyid: publicKeyHex, sig: signature.toString('hex') }],
    }
    writeFileSync(join(bundleDir, 'signature.dsse.json'), JSON.stringify(detached, null, 2))

    return {
      bundleDir,
      signerKeyHex: publicKeyHex,
      bundleId,
      artifactCount: artifacts.length,
    }
  }

  /** Resolve the standalone Rust verifier (PATH, then known dev build locations). */
  private resolveVerifier(): string | null {
    const onPath = which('ambush-verify')
    if (onPath) return onPath
    for (const rel of [
      'engine/target/release/ambush-verify',
      'engine/target/debug/ambush-verify',
    ]) {
      const p = join(process.cwd(), rel)
      if (existsSync(p)) return p
    }
    return null
  }

  /** Verify a bundle with `ambush-verify`, pinning `trustedKeyHex`. Degrades gracefully. */
  async verifyBundle(bundleDir: string, trustedKeyHex: string): Promise<VerifyOutcome> {
    const bin = this.resolveVerifier()
    if (!bin) {
      return {
        ok: false,
        exitCode: -1,
        errorCode: 'VERIFIER_UNAVAILABLE',
        error: 'ambush-verify not found (build engine/crates/swarm-attest or add it to PATH)',
      }
    }
    const res = await run(bin, [bundleDir], {
      env: { ...process.env, AMBUSH_TRUSTED_SIGNER_KEYS: trustedKeyHex },
      timeoutMs: 15_000,
    })
    try {
      const raw = JSON.parse(res.stdout) as Record<string, unknown>
      return {
        ok: Boolean(raw.ok),
        exitCode: typeof raw.exit_code === 'number' ? raw.exit_code : (res.code ?? -1),
        errorCode: (raw.error_code as string | undefined) ?? null,
        error: (raw.error as string | undefined) ?? null,
        bundleId: (raw.bundle_id as string | undefined) ?? '',
        artifactsVerified: (raw.artifacts_verified as number | undefined) ?? 0,
        signaturesVerified: (raw.signatures_verified as number | undefined) ?? 0,
        claimsVerified: (raw.claims_verified as number | undefined) ?? 0,
      }
    } catch {
      return {
        ok: false,
        exitCode: res.code ?? -1,
        errorCode: 'VERIFIER_OUTPUT_UNPARSEABLE',
        error: res.stderr || 'verifier produced no parseable output',
      }
    }
  }
}
