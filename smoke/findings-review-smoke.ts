#!/usr/bin/env tsx
// Slop-filter smoke: three lanes from THREE distinct model families independently report the
// same claim ("open port 8080") plus their own unique lines. Asserts the shared claim is
// CORROBORATED (>=2 families) while the unique lines stay QUARANTINE — the validated
// cross-model trust signal (founder decision #3). Pure + deterministic; no gate needed.

import assert from 'node:assert/strict'
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { reviewFindings } from '../src/main/intel/findings-review'

const vault = mkdtempSync(join(tmpdir(), 'ambush-review-'))
const dir = join(vault, 'findings')
mkdirSync(dir, { recursive: true })

const shared = 'Observed: open port 8080 (http) on the target.'
writeFileSync(join(dir, 'recon-01.md'), `# recon-01\n\n${shared}\nUnique: SQL injection on /login.\n\n<!-- model-family: claude -->\n`)
writeFileSync(join(dir, 'recon-02.md'), `# recon-02\n\n${shared}\nUnique: weak TLS ciphers negotiated.\n\n<!-- model-family: gpt -->\n`)
writeFileSync(join(dir, 'recon-03.md'), `# recon-03\n\n${shared}\n\n<!-- model-family: gemini -->\n`)

const review = reviewFindings(vault)

const problems: string[] = []
const corroboratedCluster = review.clusters.find((c) => c.label === 'corroborated')
if (!corroboratedCluster) problems.push('no corroborated cluster found for the shared port-8080 claim')
else {
  if (corroboratedCluster.modelFamilies.length < 2) problems.push('corroborated cluster has <2 model families')
  if (!corroboratedCluster.summary.toLowerCase().includes('8080')) problems.push('corroborated cluster is not the 8080 claim')
}
if (review.corroborated < 1) problems.push('corroborated count < 1')
if (review.quarantined < 2) problems.push('the two unique single-source lines should be quarantined')
if (review.modelFamilies.length !== 3) problems.push(`expected 3 model families, got ${review.modelFamilies.length}`)

if (problems.length) {
  console.error('\x1b[31mREVIEW SMOKE FAIL:\x1b[0m', problems.join('; '))
  process.exit(1)
}

console.log('\x1b[32mREVIEW SMOKE PASS\x1b[0m — cross-model corroboration clustered findings correctly')
console.log(`  corroborated: ${review.corroborated}  quarantined: ${review.quarantined}  families: ${review.modelFamilies.join(', ')}`)
