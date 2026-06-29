// Adapted from ClawdStrike/Arc (Apache-2.0)
//
// Resolves governance/engine binaries across the three environments Ambush runs
// in. The original code only ever looked on PATH (and implicitly cwd), so a
// packaged Electron .app — where binaries are bundled under `resources/` — could
// not find them and fail-closed governance silently degraded. This adds the
// missing packaged-app lookup (process.resourcesPath + app.getAppPath()-relative)
// while keeping PATH and dev build outputs resolving first so dev behavior is
// unchanged.

import { app } from 'electron'
import { existsSync } from 'node:fs'
import { join } from 'node:path'
import { which } from './run'

/** On Windows also probe the `.exe` variant of a bare binary name. */
function binaryNames(name: string): string[] {
  if (process.platform === 'win32' && !name.toLowerCase().endsWith('.exe')) {
    return [name, `${name}.exe`]
  }
  return [name]
}

/** Packaged-app roots under which bundled binaries may live. */
function packagedRoots(): string[] {
  const roots: string[] = []
  // In a packaged build this points at `…/Contents/Resources` (macOS),
  // `resources/` (Windows/Linux). Available for both packaged and dev runs.
  if (process.resourcesPath) roots.push(process.resourcesPath)
  try {
    // app.getAppPath() resolves to the app.asar (or the unpacked app dir).
    const appPath = app?.getAppPath?.()
    if (appPath) roots.push(appPath)
  } catch {
    // Not running inside a live Electron app (e.g. unit context) — skip.
  }
  return roots
}

/**
 * Resolve an executable named `name`.
 *
 * Lookup order (dev-first, so dev behavior is preserved):
 *   1. PATH — the existing `which` lookup.
 *   2. Dev build outputs — `cwd/engine/target/{release,debug}`.
 *   3. Packaged resources — `process.resourcesPath` and `app.getAppPath()`,
 *      each joined with `relCandidates` plus common bundle subdirs
 *      (e.g. `engine/bin`). This is the case that was missing.
 *
 * `relCandidates` lets a caller supply bundle-relative subdirectories to probe
 * first (e.g. `['engine/bin', 'bin']`). Returns the absolute path, or null.
 */
export function resolveBin(name: string, relCandidates: string[] = []): string | null {
  // 1) PATH — preserves existing dev behavior when the tool is installed.
  const onPath = which(name)
  if (onPath) return onPath

  const names = binaryNames(name)

  // 2) Dev build outputs.
  const devDirs = [
    join(process.cwd(), 'engine', 'target', 'release'),
    join(process.cwd(), 'engine', 'target', 'debug'),
  ]
  for (const dir of devDirs) {
    for (const n of names) {
      const candidate = join(dir, n)
      if (existsSync(candidate)) return candidate
    }
  }

  // 3) Packaged app resources — the previously-missing case.
  const rels = [
    ...relCandidates,
    join('engine', 'bin'),
    'bin',
    join('engine', 'target', 'release'),
    join('engine', 'target', 'debug'),
    '.',
  ]
  for (const root of packagedRoots()) {
    for (const rel of rels) {
      for (const n of names) {
        const candidate = join(root, rel, n)
        if (existsSync(candidate)) return candidate
      }
    }
  }

  return null
}
