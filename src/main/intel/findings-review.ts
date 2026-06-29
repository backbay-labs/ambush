import { existsSync, readFileSync, readdirSync } from 'node:fs'
import { join } from 'node:path'
import type { FindingCluster, FindingEvidence, FindingsReview } from '@shared/types'

// The validated slop-filter. Founder decision #3: trust comes from cross-model corroboration,
// not BFT. This reads every finding in the vault, clusters claim-lines by token similarity, and
// labels each cluster CORROBORATED (>=2 distinct model families independently reported it) or
// QUARANTINE (single-source — treat as possible slop until a second model agrees). Pure +
// deterministic so it is unit-testable headlessly (smoke/findings-review-smoke.ts).

const STOP = new Set([
  'the', 'and', 'for', 'that', 'with', 'this', 'from', 'have', 'was', 'are', 'were', 'will',
  'should', 'their', 'open', 'http', 'target', 'lane', 'candidate', 'them', 'observed', 'enumerated',
])

const SIMILARITY_THRESHOLD = 0.4

// Untagged findings get a constant 'unknown' family — NOT the per-vector name — so two
// same-model (or untagged) lanes are not mistaken for two distinct model families (which would
// fake corroboration). Corroboration counts only KNOWN families.
const UNKNOWN_FAMILY = 'unknown'

function familyOf(text: string): string {
  const m = text.match(/model-family:\s*([\w-]+)/i)
  return m ? m[1] : UNKNOWN_FAMILY
}

function signalLines(text: string): string[] {
  return text
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l.length > 0 && !l.startsWith('#') && !l.startsWith('<!--'))
}

function tokenize(line: string): Set<string> {
  return new Set(
    line
      .toLowerCase()
      .replace(/[^a-z0-9\s]/g, ' ')
      .split(/\s+/)
      .filter((w) => w.length >= 4 && !STOP.has(w)),
  )
}

function jaccard(a: Set<string>, b: Set<string>): number {
  if (a.size === 0 || b.size === 0) return 0
  let inter = 0
  for (const x of a) if (b.has(x)) inter++
  return inter / (a.size + b.size - inter)
}

interface Claim {
  vector: string
  family: string
  line: string
  tokens: Set<string>
}

/** Cluster the findings in `vaultPath/findings` and label each by cross-model corroboration. */
export function reviewFindings(vaultPath: string): FindingsReview {
  const dir = join(vaultPath, 'findings')
  const claims: Claim[] = []
  if (existsSync(dir)) {
    for (const name of readdirSync(dir).sort()) {
      if (!name.endsWith('.md')) continue
      const text = readFileSync(join(dir, name), 'utf8')
      const vector = name.replace(/\.md$/, '')
      const family = familyOf(text)
      for (const line of signalLines(text)) {
        const tokens = tokenize(line)
        if (tokens.size > 0) claims.push({ vector, family, line, tokens })
      }
    }
  }

  // Greedy single-link clustering by token Jaccard.
  const buckets: Claim[][] = []
  for (const claim of claims) {
    let best = -1
    let bestSim = 0
    buckets.forEach((bucket, i) => {
      const sim = Math.max(...bucket.map((c) => jaccard(c.tokens, claim.tokens)))
      if (sim > bestSim) {
        bestSim = sim
        best = i
      }
    })
    if (best >= 0 && bestSim >= SIMILARITY_THRESHOLD) buckets[best].push(claim)
    else buckets.push([claim])
  }

  const clusters: FindingCluster[] = buckets.map((bucket, i) => {
    const modelFamilies = [...new Set(bucket.map((c) => c.family))].sort()
    // Corroboration requires >=2 distinct KNOWN model families — untagged ('unknown') lanes can
    // never corroborate each other, so they fail-safe to QUARANTINE.
    const knownFamilies = modelFamilies.filter((f) => f !== UNKNOWN_FAMILY)
    const evidence: FindingEvidence[] = bucket.map((c) => ({
      vector: c.vector,
      modelFamily: c.family,
      snippet: c.line.slice(0, 160),
    }))
    return {
      id: `cluster-${i}`,
      summary: bucket[0].line.slice(0, 120),
      modelFamilies,
      label: knownFamilies.length >= 2 ? 'corroborated' : 'quarantine',
      evidence,
    }
  })

  const corroborated = clusters.filter((c) => c.label === 'corroborated').length
  return {
    clusters,
    corroborated,
    quarantined: clusters.length - corroborated,
    modelFamilies: [...new Set(claims.map((c) => c.family))].sort(),
  }
}
