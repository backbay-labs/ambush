import type * as React from 'react'
import { useEffect } from 'react'
import { startTerminalHub } from './lib/terminalHub'
import { useStore } from './store/useStore'
import { IntelPane } from './components/IntelPane'
import { OperationSetup } from './components/OperationSetup'
import { ReceiptsPane } from './components/ReceiptsPane'
import { StatusBar } from './components/StatusBar'
import { SwarmView } from './components/SwarmView'
import { TopBar } from './components/TopBar'

export default function App(): React.JSX.Element {
  const booting = useStore((s) => s.booting)
  const operation = useStore((s) => s.operation)
  const tab = useStore((s) => s.tab)
  const bootstrap = useStore((s) => s.bootstrap)

  useEffect(() => {
    startTerminalHub()
    void bootstrap()
  }, [bootstrap])

  return (
    <div className="flex h-screen flex-col bg-surface text-[13px]">
      <TopBar />
      <div className="relative flex min-h-0 flex-1">
        {booting ? (
          <div className="flex flex-1 items-center justify-center text-zinc-500">
            initializing swarm…
          </div>
        ) : !operation ? (
          <OperationSetup />
        ) : tab === 'swarm' ? (
          <SwarmView />
        ) : tab === 'intel' ? (
          <IntelPane />
        ) : (
          <ReceiptsPane />
        )}
      </div>
      <StatusBar />
    </div>
  )
}
