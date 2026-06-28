import type * as React from 'react'
import { useState } from 'react'
import { Crosshair, FolderOpen } from 'lucide-react'
import { useStore } from '../store/useStore'

export function OperationSetup(): React.JSX.Element {
  const createOperation = useStore((s) => s.createOperation)
  const [name, setName] = useState('Operation Nightfall')
  const [objective, setObjective] = useState(
    'Assess the target for exploitable weaknesses and produce an evidence-backed report.',
  )
  const [target, setTarget] = useState('')
  const [targetPath, setTargetPath] = useState('')
  const [busy, setBusy] = useState(false)

  const pick = async (): Promise<void> => {
    const dir = await window.ambush.pickDirectory()
    if (dir) setTargetPath(dir)
  }

  const submit = async (): Promise<void> => {
    setBusy(true)
    try {
      await createOperation({ name, objective, target, targetPath })
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="flex flex-1 items-center justify-center p-8">
      <div className="w-full max-w-xl rounded-2xl border border-edge bg-panel p-7 shadow-2xl">
        <div className="mb-5 flex items-center gap-2">
          <Crosshair size={20} className="text-accent" />
          <h1 className="text-lg font-semibold">New Operation</h1>
        </div>
        <p className="mb-6 text-zinc-400">
          Define the mission. Then deploy a swarm of agents — each runs an attack vector in an
          isolated worktree and reports into a governed intel vault.
        </p>

        <Field label="Operation name">
          <input
            className="input"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="Operation Nightfall"
          />
        </Field>

        <Field label="Objective">
          <textarea
            className="input min-h-20 resize-y"
            value={objective}
            onChange={(e) => setObjective(e.target.value)}
          />
        </Field>

        <Field label="Target (host, URL, or CTF endpoint)">
          <input
            className="input"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="https://target.example / 10.0.0.5 / ctf.example:1337"
          />
        </Field>

        <Field label="Target repo / working dir (optional — enables git worktrees)">
          <div className="flex gap-2">
            <input
              className="input flex-1"
              value={targetPath}
              onChange={(e) => setTargetPath(e.target.value)}
              placeholder="/path/to/target-repo"
            />
            <button type="button" className="btn-ghost" onClick={() => void pick()}>
              <FolderOpen size={15} />
            </button>
          </div>
        </Field>

        <button
          type="button"
          className="btn-primary mt-3 w-full justify-center"
          disabled={busy || !name.trim()}
          onClick={() => void submit()}
        >
          {busy ? 'Standing up operation…' : 'Create Operation'}
        </button>
      </div>

      <style>{styles}</style>
    </div>
  )
}

function Field({ label, children }: { label: string; children: React.ReactNode }): React.JSX.Element {
  return (
    <label className="mb-4 block">
      <span className="mb-1.5 block text-xs font-medium text-zinc-400">{label}</span>
      {children}
    </label>
  )
}

const styles = `
.input{ width:100%; background:#0e1015; border:1px solid #232733; border-radius:10px; padding:9px 12px; color:#e6e8ee; outline:none; font-size:13px; }
.input:focus{ border-color:#36f1a3; box-shadow:0 0 0 3px rgba(54,241,163,.12); }
.btn-primary{ display:inline-flex; align-items:center; gap:8px; background:#36f1a3; color:#04130c; font-weight:600; border:none; border-radius:10px; padding:10px 16px; cursor:pointer; }
.btn-primary:disabled{ opacity:.5; cursor:not-allowed; }
.btn-ghost{ display:inline-flex; align-items:center; gap:6px; background:#161922; border:1px solid #232733; color:#cbd1dc; border-radius:10px; padding:9px 12px; cursor:pointer; }
.btn-ghost:hover{ border-color:#36f1a3; }
`
