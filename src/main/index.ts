import { join } from 'node:path'
import { electronApp, optimizer } from '@electron-toolkit/utils'
import { app, BrowserWindow, shell } from 'electron'
import { OpenKnowledgeEngine } from './engine/openknowledge-engine'
import { ApprovalQueue } from './governance/approval-queue'
import { AttestationManager } from './governance/attestation'
import { ChioGovernor } from './governance/chio-governor'
import { registerIpc } from './ipc/register-ipc'
import { SwarmOrchestrator } from './swarm/swarm-orchestrator'
import { WorktreeManager } from './swarm/worktree-manager'
import { PtyManager } from './terminal/pty-manager'
import { TerminalGovernor } from './terminal/terminal-governor'
import { bus } from './util/bus'

let mainWindow: BrowserWindow | null = null

const engine = new OpenKnowledgeEngine()
const governor = new ChioGovernor()
const approvals = new ApprovalQueue()
const attest = new AttestationManager()
const worktrees = new WorktreeManager()
const pty = new PtyManager()
let orchestrator: SwarmOrchestrator

function createWindow(): void {
  mainWindow = new BrowserWindow({
    width: 1440,
    height: 900,
    minWidth: 1024,
    minHeight: 680,
    show: false,
    backgroundColor: '#0a0b0e',
    titleBarStyle: process.platform === 'darwin' ? 'hiddenInset' : 'default',
    webPreferences: {
      preload: join(__dirname, '../preload/index.js'),
      sandbox: false,
      // <webview> is used to embed the OpenKnowledge intel UI.
      webviewTag: true,
    },
  })

  mainWindow.on('ready-to-show', () => mainWindow?.show())

  mainWindow.webContents.setWindowOpenHandler((details) => {
    void shell.openExternal(details.url)
    return { action: 'deny' }
  })

  if (process.env.ELECTRON_RENDERER_URL) {
    void mainWindow.loadURL(process.env.ELECTRON_RENDERER_URL)
  } else {
    void mainWindow.loadFile(join(__dirname, '../renderer/index.html'))
  }
}

app.whenReady().then(() => {
  electronApp.setAppUserModelId('dev.backbay.ambush')

  approvals.start()
  orchestrator = new SwarmOrchestrator(
    app.getPath('userData'),
    engine,
    governor,
    approvals,
    worktrees,
    pty,
  )
  const terminalGovernor = new TerminalGovernor({
    pty,
    getOperation: () => orchestrator.getOperation(),
    getSigningKey: () => governor.getSigningKey(),
  })
  registerIpc({ orchestrator, engine, governor, approvals, attest, terminalGovernor, pty })

  // Restore the last operation (vectors marked idle; agents are not re-spawned).
  const restored = orchestrator.loadPersisted()
  if (restored) bus.log('info', 'app', `Restored operation "${restored.name}"`)

  app.on('browser-window-created', (_e, win) => optimizer.watchWindowShortcuts(win))

  createWindow()

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow()
  })
})

app.on('window-all-closed', () => {
  pty.killAll()
  engine.stop()
  approvals.stop()
  if (process.platform !== 'darwin') app.quit()
})

app.on('before-quit', () => {
  pty.killAll()
  engine.stop()
  approvals.stop()
})
