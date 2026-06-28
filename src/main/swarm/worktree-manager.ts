import { mkdirSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { bus } from '../util/bus'
import { run } from '../util/run'

export interface WorktreeHandle {
  path: string
  branch: string | null
  isGit: boolean
}

/**
 * Creates isolated working directories for swarm agents. When the target is a
 * git repo, each vector gets its own `git worktree` + branch (Orca-style
 * isolation). When the target is not a repo (CTF endpoint, host, empty dir),
 * we fall back to plain per-vector scratch directories so the mechanism still
 * works everywhere.
 */
export class WorktreeManager {
  private async isGitRepo(dir: string): Promise<boolean> {
    if (!dir) return false
    const res = await run('git', ['-C', dir, 'rev-parse', '--is-inside-work-tree'])
    return res.code === 0 && res.stdout.trim() === 'true'
  }

  private worktreeRoot(targetPath: string): string {
    // Keep ambush worktrees out of the target's tree where possible.
    const base = targetPath && targetPath.length > 0 ? targetPath : process.cwd()
    return join(base, '.ambush', 'worktrees')
  }

  async create(targetPath: string, vectorId: string, branch: string): Promise<WorktreeHandle> {
    const root = this.worktreeRoot(targetPath)
    mkdirSync(root, { recursive: true })
    const dest = join(root, vectorId)

    const isGit = await this.isGitRepo(targetPath)
    if (!isGit) {
      mkdirSync(dest, { recursive: true })
      bus.log('info', 'worktree', `Created scratch dir for ${vectorId} (target is not a git repo)`)
      return { path: dest, branch: null, isGit: false }
    }

    // Resolve a base commit to branch from.
    const head = await run('git', ['-C', targetPath, 'rev-parse', 'HEAD'])
    const baseRef = head.code === 0 ? head.stdout.trim() : 'HEAD'

    const res = await run('git', [
      '-C',
      targetPath,
      'worktree',
      'add',
      '-b',
      branch,
      dest,
      baseRef,
    ])
    if (res.code !== 0) {
      // Branch may already exist (redeploy). Try without -b.
      const retry = await run('git', ['-C', targetPath, 'worktree', 'add', dest, branch])
      if (retry.code !== 0) {
        bus.log('warn', 'worktree', `git worktree failed for ${vectorId}: ${res.stderr.trim()}`)
        mkdirSync(dest, { recursive: true })
        return { path: dest, branch: null, isGit: false }
      }
    }
    bus.log('info', 'worktree', `Worktree ${branch} ready at ${dest}`)
    return { path: dest, branch, isGit: true }
  }

  async remove(targetPath: string, handle: WorktreeHandle): Promise<void> {
    try {
      if (handle.isGit) {
        await run('git', ['-C', targetPath, 'worktree', 'remove', '--force', handle.path])
        if (handle.branch) {
          await run('git', ['-C', targetPath, 'branch', '-D', handle.branch])
        }
      } else {
        rmSync(handle.path, { recursive: true, force: true })
      }
    } catch (err) {
      bus.log('warn', 'worktree', `Failed to remove ${handle.path}: ${String(err)}`)
    }
  }
}
