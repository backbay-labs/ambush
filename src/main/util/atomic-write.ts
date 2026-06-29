// Adapted from ClawdStrike/Arc (Apache-2.0)
//
// Port of security/fs.rs `write_private_atomic`: write to a temp file in the
// same directory, fsync it, then atomically rename over the destination with
// owner-only (0o600) permissions. Used for governance-sensitive files (policy,
// secrets) and persisted operation state so a crash mid-write can never leave a
// truncated or world-readable file behind.

import { randomBytes } from 'node:crypto'
import {
  closeSync,
  fsyncSync,
  mkdirSync,
  openSync,
  renameSync,
  unlinkSync,
  writeSync,
} from 'node:fs'
import { basename, dirname, join } from 'node:path'

/**
 * Atomically write `data` to `path` with private (0o600) permissions.
 *
 * The temp file is created in the same directory as the destination so the
 * final `rename` is atomic (same filesystem). The destination inherits the
 * temp file's 0o600 mode. On Windows the mode argument is ignored by Node but
 * the atomic-rename + fsync semantics still hold.
 */
export function writePrivateAtomic(path: string, data: string | Uint8Array): void {
  const dir = dirname(path)
  mkdirSync(dir, { recursive: true })

  const tmp = join(dir, `.${basename(path)}.${randomBytes(8).toString('hex')}.tmp`)
  const buf = typeof data === 'string' ? Buffer.from(data, 'utf8') : Buffer.from(data)

  // mode 0o600 applies on creation (Unix). Truncate/create with 'w'.
  const fd = openSync(tmp, 'w', 0o600)
  try {
    writeSync(fd, buf)
    fsyncSync(fd)
  } finally {
    closeSync(fd)
  }

  try {
    // Atomic replace: destination ends up as the 0o600 temp inode.
    renameSync(tmp, path)
  } catch (err) {
    try {
      unlinkSync(tmp)
    } catch {
      // best-effort cleanup
    }
    throw err
  }
}
