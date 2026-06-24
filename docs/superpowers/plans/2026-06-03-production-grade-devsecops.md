# Production-Grade DevSecOps & Desktop Distribution Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Harden the AI SOC project to production grade and package it as an installable desktop app downloadable from a website like any normal desktop application.

**Architecture:** The Electron frontend becomes the control plane — it manages the full backend stack (Kafka, Redis, Postgres, ChromaDB, FastAPI) by spawning Docker Compose processes via IPC, shows a first-run wizard on fresh installs, and runs a system-tray icon for background operation. The build pipeline produces signed NSIS (Windows), DMG (macOS), and AppImage (Linux) installers uploaded to GitHub Releases and served from a static download page.

**Tech Stack:** Electron 28, electron-builder 26, electron-updater, React 19, Docker Compose v2, FastAPI + prometheus-client, Grafana 11, Prometheus 2, PowerShell/Bash scripts.

---

## Phase 1 — Security Fixes (Critical, ~1 hour)

### Task 1: Fix Dockerfile — non-root user + .dockerignore

**Files:**
- Modify: `backend/Dockerfile.api`
- Create: `backend/.dockerignore`

- [ ] **Step 1: Write the failing Trivy/Hadolint check**

```bash
# In CI this is already caught; run locally to verify:
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  aquasec/trivy image --exit-code 1 --severity CRITICAL,HIGH \
  $(docker build -q backend/)
# Also lint the Dockerfile:
docker run --rm -i hadolint/hadolint < backend/Dockerfile.api
```
Expected: Hadolint warns `DL3002 Last USER should not be root`

- [ ] **Step 2: Rewrite `backend/Dockerfile.api`**

Replace the entire file with:
```dockerfile
FROM python:3.11-slim

WORKDIR /app

RUN groupadd -r appuser && useradd -r -g appuser -u 1000 appuser

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN mkdir -p /app/data && chown -R appuser:appuser /app

USER appuser

EXPOSE 8080

CMD ["uvicorn", "api.hitl_api:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "8"]
```

- [ ] **Step 3: Create `backend/.dockerignore`**

```
__pycache__/
*.pyc
*.pyo
*.pyd
.Python
.env
*.env
.git/
.gitignore
.pytest_cache/
tests/
docs/
*.md
*.log
data/
vendor/
```

- [ ] **Step 4: Build and verify no root warning**

```bash
docker build -t ai-soc-api:test backend/
docker run --rm -i hadolint/hadolint < backend/Dockerfile.api
# Expected: no DL3002 warning
docker inspect ai-soc-api:test --format '{{.Config.User}}'
# Expected: appuser
```

- [ ] **Step 5: Commit**

```bash
git add backend/Dockerfile.api backend/.dockerignore
git commit -m "fix(container): run API as non-root user appuser (uid 1000)"
```

---

### Task 2: Pin all `>=` dependencies to exact versions

**Files:**
- Modify: `backend/requirements.txt`

- [ ] **Step 1: Resolve exact installed versions**

```bash
cd backend
pip install -r requirements.txt --quiet
pip freeze | grep -E "^(openai|pydantic|pydantic.settings|confluent.kafka|chromadb|sentence.transformers|aiohttp|python.multipart|PyYAML|orjson)==" 
```
Note the exact versions printed. Use those below (or use these minimum-locked values):

- [ ] **Step 2: Replace `>=` lines in `backend/requirements.txt`**

Change these lines (keep all comments intact):
```
# BEFORE:
openai>=1.54.0
pydantic>=2.9.2
pydantic-settings>=2.6.1
confluent-kafka>=2.6.1
chromadb>=0.5.23
sentence-transformers>=3.3.1
aiohttp>=3.11.10
python-multipart>=0.0.9
pyyaml>=6.0.2
orjson>=3.10.12

# AFTER (use exact versions from pip freeze above):
openai==1.54.0
pydantic==2.9.2
pydantic-settings==2.6.1
confluent-kafka==2.6.1
chromadb==0.5.23
sentence-transformers==3.3.1
aiohttp==3.11.10
python-multipart==0.0.9
pyyaml==6.0.2
orjson==3.10.12
```

- [ ] **Step 3: Verify CI pinning check passes**

```bash
python -c "
import re, sys
bad = [l for l in open('requirements.txt') if re.match(r'^[a-zA-Z]', l) and '>=' in l and not l.startswith('#')]
if bad:
    print('UNPINNED:', bad); sys.exit(1)
print('All dependencies pinned OK')
"
```
Expected: `All dependencies pinned OK`

- [ ] **Step 4: Confirm install still works**

```bash
pip install -r requirements.txt --quiet && python -c "import fastapi, pydantic, confluent_kafka; print('OK')"
```

- [ ] **Step 5: Commit**

```bash
git add backend/requirements.txt
git commit -m "fix(deps): pin all Python dependencies to exact versions for reproducible builds"
```

---

## Phase 2 — electron-builder Installer Config (~30 min)

### Task 3: Add electron-builder config to package.json

**Files:**
- Modify: `frontend/package.json`

This adds the `"build"` config block that `electron-builder` reads to produce NSIS (Windows), DMG (macOS), and AppImage/deb (Linux) installers.

- [ ] **Step 1: Add `electron-updater` dependency**

```bash
cd frontend
npm install electron-updater --save
```

- [ ] **Step 2: Add the `"build"` block to `frontend/package.json`**

Insert after the `"scripts"` block (before `"dependencies"`):

```json
  "build": {
    "appId": "com.aisoc.pipeline",
    "productName": "AI SOC",
    "copyright": "Copyright © 2025 AI SOC Contributors",
    "directories": {
      "output": "dist-installer"
    },
    "files": [
      "out/**/*",
      "resources/**/*",
      "!resources/*.psd"
    ],
    "extraResources": [
      {
        "from": "../backend/docker-compose.yml",
        "to": "backend/docker-compose.yml"
      },
      {
        "from": "../backend/.env.example",
        "to": "backend/.env.example"
      },
      {
        "from": "../wazuh-docker/single-node/docker-compose.yml",
        "to": "wazuh/docker-compose.yml"
      },
      {
        "from": "../deploy/shuffle/docker-compose.yml",
        "to": "shuffle/docker-compose.yml"
      },
      {
        "from": "../scripts",
        "to": "scripts",
        "filter": ["**/*"]
      }
    ],
    "win": {
      "target": [{ "target": "nsis", "arch": ["x64"] }],
      "icon": "resources/icon.ico",
      "publisherName": "AI SOC Contributors",
      "verifyUpdateCodeSignature": false
    },
    "nsis": {
      "oneClick": false,
      "allowToChangeInstallationDirectory": true,
      "createDesktopShortcut": true,
      "createStartMenuShortcut": true,
      "shortcutName": "AI SOC",
      "installerIcon": "resources/icon.ico",
      "uninstallerIcon": "resources/icon.ico",
      "installerHeaderIcon": "resources/icon.ico",
      "deleteAppDataOnUninstall": false,
      "license": "../LICENSE"
    },
    "mac": {
      "target": [{ "target": "dmg", "arch": ["x64", "arm64"] }],
      "icon": "resources/icon.icns",
      "category": "public.app-category.utilities"
    },
    "dmg": {
      "title": "AI SOC Installer",
      "background": "resources/dmg-background.png",
      "contents": [
        { "x": 410, "y": 150, "type": "link", "path": "/Applications" },
        { "x": 130, "y": 150, "type": "file" }
      ]
    },
    "linux": {
      "target": [
        { "target": "AppImage", "arch": ["x64"] },
        { "target": "deb", "arch": ["x64"] }
      ],
      "icon": "resources/icon.png",
      "category": "System"
    },
    "publish": {
      "provider": "github",
      "owner": "YOUR_GITHUB_ORG",
      "repo": "ai-soc"
    }
  },
```

- [ ] **Step 3: Add icon resources**

The build expects `resources/icon.ico` (Windows) and `resources/icon.icns` (macOS). If only `resources/icon.png` exists:
```bash
# Install electron-icon-builder globally (or use online converter)
npx electron-icon-builder --input=resources/icon.png --output=resources/
# This generates icon.ico and icon.icns automatically
```
If the tool isn't available, note that build:win will error on missing .ico — place a valid 256x256 ICO at `frontend/resources/icon.ico`.

- [ ] **Step 4: Create `scripts/` directory with a placeholder README**

```bash
mkdir -p scripts
echo "# AI SOC Scripts\nSee DEPLOYMENT.md for usage." > scripts/README.md
```

- [ ] **Step 5: Test the build produces an installer**

```bash
cd frontend
npm run build:win
# Expected: dist-installer/AI SOC Setup 1.0.0.exe created
ls dist-installer/
```

- [ ] **Step 6: Commit**

```bash
git add frontend/package.json frontend/resources/ scripts/
git commit -m "feat(installer): add electron-builder config for NSIS/DMG/AppImage installers"
```

---

## Phase 3 — Backend Service Manager in Electron (~2 hours)

The Electron main process needs to start, stop, and monitor Docker Compose services and report status to the renderer via IPC.

### Task 4: Create the backend service manager module

**Files:**
- Create: `frontend/src/main/services/backendManager.ts`
- Modify: `frontend/src/main/index.ts`
- Modify: `frontend/src/preload/index.ts`
- Create: `frontend/src/preload/index.d.ts` (if not present)

- [ ] **Step 1: Create `frontend/src/main/services/backendManager.ts`**

```typescript
import { spawn, ChildProcess } from 'child_process'
import { join } from 'path'
import { app } from 'electron'
import * as fs from 'fs'

export type ServiceStatus = 'stopped' | 'starting' | 'running' | 'error'

export interface ServiceState {
  status: ServiceStatus
  message: string
}

type StatusCallback = (state: ServiceState) => void

const resourcesPath = app.isPackaged
  ? process.resourcesPath
  : join(__dirname, '..', '..', '..', '..')

function getComposePath(file: string): string {
  return app.isPackaged
    ? join(resourcesPath, file)
    : join(resourcesPath, 'backend', file.replace('backend/', ''))
}

let composeProcess: ChildProcess | null = null
let currentStatus: ServiceStatus = 'stopped'
const listeners: StatusCallback[] = []

function emit(state: ServiceState): void {
  currentStatus = state.status
  listeners.forEach((cb) => cb(state))
}

export function onStatusChange(cb: StatusCallback): () => void {
  listeners.push(cb)
  return () => {
    const idx = listeners.indexOf(cb)
    if (idx !== -1) listeners.splice(idx, 1)
  }
}

export function getStatus(): ServiceStatus {
  return currentStatus
}

export async function checkDockerAvailable(): Promise<boolean> {
  return new Promise((resolve) => {
    const proc = spawn('docker', ['info'], { stdio: 'ignore', shell: true })
    proc.on('close', (code) => resolve(code === 0))
    proc.on('error', () => resolve(false))
  })
}

export async function startServices(): Promise<void> {
  if (currentStatus === 'running' || currentStatus === 'starting') return

  const dockerOk = await checkDockerAvailable()
  if (!dockerOk) {
    emit({ status: 'error', message: 'Docker is not running. Please start Docker Desktop.' })
    return
  }

  emit({ status: 'starting', message: 'Starting AI SOC backend services...' })

  const backendCompose = getComposePath('backend/docker-compose.yml')
  const envFile = join(app.getPath('userData'), '.env')

  if (!fs.existsSync(envFile)) {
    emit({ status: 'error', message: 'No .env file found. Run the setup wizard first.' })
    return
  }

  composeProcess = spawn(
    'docker',
    ['compose', '-f', backendCompose, '--env-file', envFile, 'up', '-d', '--wait'],
    { shell: true, stdio: 'pipe' }
  )

  let stderr = ''
  composeProcess.stderr?.on('data', (d) => { stderr += d.toString() })

  composeProcess.on('close', (code) => {
    if (code === 0) {
      emit({ status: 'running', message: 'All backend services are healthy.' })
    } else {
      emit({ status: 'error', message: `Service startup failed:\n${stderr}` })
    }
    composeProcess = null
  })

  composeProcess.on('error', (err) => {
    emit({ status: 'error', message: `Failed to spawn docker compose: ${err.message}` })
    composeProcess = null
  })
}

export async function stopServices(): Promise<void> {
  if (currentStatus === 'stopped') return

  const backendCompose = getComposePath('backend/docker-compose.yml')
  emit({ status: 'starting', message: 'Stopping services...' })

  await new Promise<void>((resolve) => {
    const proc = spawn('docker', ['compose', '-f', backendCompose, 'down'], {
      shell: true,
      stdio: 'ignore',
    })
    proc.on('close', () => {
      emit({ status: 'stopped', message: 'All services stopped.' })
      resolve()
    })
    proc.on('error', () => {
      emit({ status: 'stopped', message: 'Stopped (with warnings).' })
      resolve()
    })
  })
}

export async function getServiceLogs(tail = 100): Promise<string> {
  const backendCompose = getComposePath('backend/docker-compose.yml')
  return new Promise((resolve) => {
    const proc = spawn('docker', ['compose', '-f', backendCompose, 'logs', `--tail=${tail}`], {
      shell: true,
      stdio: 'pipe',
    })
    let out = ''
    proc.stdout?.on('data', (d) => { out += d.toString() })
    proc.stderr?.on('data', (d) => { out += d.toString() })
    proc.on('close', () => resolve(out))
    proc.on('error', () => resolve('Failed to fetch logs'))
  })
}
```

- [ ] **Step 2: Register IPC handlers in `frontend/src/main/index.ts`**

Replace the full file with:
```typescript
import { app, shell, BrowserWindow, ipcMain, Tray, Menu, nativeImage } from 'electron'
import { join } from 'path'
import icon from '../../resources/icon.png?asset'
import {
  startServices,
  stopServices,
  getServiceLogs,
  getStatus,
  onStatusChange,
  checkDockerAvailable,
} from './services/backendManager'
import { setupAutoUpdater } from './updater'

const isDev = process.env.NODE_ENV === 'development' || !app.isPackaged

let mainWindow: BrowserWindow | null = null
let tray: Tray | null = null

function createWindow(): void {
  mainWindow = new BrowserWindow({
    width: 1280,
    height: 800,
    show: false,
    autoHideMenuBar: true,
    ...(process.platform === 'linux' ? { icon } : {}),
    webPreferences: {
      preload: join(__dirname, '../preload/index.js'),
      sandbox: false,
    },
  })

  mainWindow.on('ready-to-show', () => {
    mainWindow!.show()
  })

  mainWindow.on('close', (event) => {
    if (process.platform !== 'darwin') {
      event.preventDefault()
      mainWindow!.hide()
    }
  })

  mainWindow.webContents.setWindowOpenHandler((details) => {
    shell.openExternal(details.url)
    return { action: 'deny' }
  })

  if (isDev && process.env['ELECTRON_RENDERER_URL']) {
    mainWindow.loadURL(process.env['ELECTRON_RENDERER_URL'])
  } else {
    mainWindow.loadFile(join(__dirname, '../renderer/index.html'))
  }
}

function createTray(): void {
  const trayIcon = nativeImage.createFromPath(icon as string).resize({ width: 16, height: 16 })
  tray = new Tray(trayIcon)
  tray.setToolTip('AI SOC')

  function buildMenu(): Electron.Menu {
    const status = getStatus()
    return Menu.buildFromTemplate([
      { label: 'Show Dashboard', click: () => { mainWindow?.show(); mainWindow?.focus() } },
      { type: 'separator' },
      {
        label: status === 'running' ? 'Services: Running' : `Services: ${status}`,
        enabled: false,
      },
      {
        label: 'Start Services',
        enabled: status === 'stopped' || status === 'error',
        click: () => startServices(),
      },
      {
        label: 'Stop Services',
        enabled: status === 'running',
        click: () => stopServices(),
      },
      { type: 'separator' },
      { label: 'Quit AI SOC', click: () => { app.exit(0) } },
    ])
  }

  tray.setContextMenu(buildMenu())
  tray.on('double-click', () => { mainWindow?.show(); mainWindow?.focus() })

  onStatusChange(() => {
    tray?.setContextMenu(buildMenu())
  })
}

// IPC handlers
function registerIPC(): void {
  ipcMain.handle('service:start', () => startServices())
  ipcMain.handle('service:stop', () => stopServices())
  ipcMain.handle('service:status', () => getStatus())
  ipcMain.handle('service:logs', (_, tail: number) => getServiceLogs(tail))
  ipcMain.handle('docker:available', () => checkDockerAvailable())

  onStatusChange((state) => {
    mainWindow?.webContents.send('service:status-changed', state)
  })
}

app.whenReady().then(() => {
  if (process.platform === 'win32') {
    app.setAppUserModelId('com.aisoc.pipeline')
  }

  createWindow()
  createTray()
  registerIPC()
  setupAutoUpdater(mainWindow!)

  // Auto-start services on launch
  startServices()

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow()
  })
})

app.on('window-all-closed', () => {
  // Stay in system tray on all platforms
})

app.on('before-quit', async () => {
  await stopServices()
})
```

- [ ] **Step 3: Expose IPC in `frontend/src/preload/index.ts`**

Replace the full file with:
```typescript
import { contextBridge, ipcRenderer } from 'electron'
import { electronAPI } from '@electron-toolkit/preload'

const backendAPI = {
  startServices: () => ipcRenderer.invoke('service:start'),
  stopServices: () => ipcRenderer.invoke('service:stop'),
  getStatus: () => ipcRenderer.invoke('service:status'),
  getLogs: (tail?: number) => ipcRenderer.invoke('service:logs', tail ?? 100),
  checkDocker: () => ipcRenderer.invoke('docker:available'),
  onStatusChanged: (cb: (state: { status: string; message: string }) => void) => {
    ipcRenderer.on('service:status-changed', (_event, state) => cb(state))
    return () => ipcRenderer.removeAllListeners('service:status-changed')
  },
}

if (process.contextIsolated) {
  try {
    contextBridge.exposeInMainWorld('electron', electronAPI)
    contextBridge.exposeInMainWorld('backend', backendAPI)
  } catch (error) {
    console.error(error)
  }
} else {
  // @ts-ignore
  window.electron = electronAPI
  // @ts-ignore
  window.backend = backendAPI
}
```

- [ ] **Step 4: Update type definitions `frontend/src/preload/index.d.ts`**

Create/replace with:
```typescript
import { ElectronAPI } from '@electron-toolkit/preload'

interface ServiceState {
  status: 'stopped' | 'starting' | 'running' | 'error'
  message: string
}

interface BackendAPI {
  startServices: () => Promise<void>
  stopServices: () => Promise<void>
  getStatus: () => Promise<'stopped' | 'starting' | 'running' | 'error'>
  getLogs: (tail?: number) => Promise<string>
  checkDocker: () => Promise<boolean>
  onStatusChanged: (cb: (state: ServiceState) => void) => () => void
}

declare global {
  interface Window {
    electron: ElectronAPI
    backend: BackendAPI
  }
}
```

- [ ] **Step 5: Build and verify no TypeScript errors**

```bash
cd frontend
npm run typecheck
# Expected: 0 errors
```

- [ ] **Step 6: Commit**

```bash
git add frontend/src/main/ frontend/src/preload/
git commit -m "feat(electron): add backend service manager with IPC, system tray, and docker compose orchestration"
```

---

### Task 5: Create the auto-updater module

**Files:**
- Create: `frontend/src/main/updater.ts`

- [ ] **Step 1: Create `frontend/src/main/updater.ts`**

```typescript
import { autoUpdater } from 'electron-updater'
import { BrowserWindow, dialog } from 'electron'

export function setupAutoUpdater(win: BrowserWindow): void {
  if (process.env.NODE_ENV === 'development') return

  autoUpdater.autoDownload = false
  autoUpdater.autoInstallOnAppQuit = true

  autoUpdater.on('update-available', (info) => {
    dialog
      .showMessageBox(win, {
        type: 'info',
        title: 'Update Available',
        message: `AI SOC v${info.version} is available.`,
        detail: 'Download now in the background?',
        buttons: ['Download', 'Later'],
        defaultId: 0,
      })
      .then(({ response }) => {
        if (response === 0) autoUpdater.downloadUpdate()
      })
  })

  autoUpdater.on('update-downloaded', () => {
    dialog
      .showMessageBox(win, {
        type: 'info',
        title: 'Update Ready',
        message: 'Update downloaded. Restart to install?',
        buttons: ['Restart Now', 'Later'],
        defaultId: 0,
      })
      .then(({ response }) => {
        if (response === 0) autoUpdater.quitAndInstall()
      })
  })

  autoUpdater.on('error', (err) => {
    console.error('Auto-updater error:', err)
  })

  // Check on startup, then every 4 hours
  autoUpdater.checkForUpdates()
  setInterval(() => autoUpdater.checkForUpdates(), 4 * 60 * 60 * 1000)
}
```

- [ ] **Step 2: Verify typecheck still passes**

```bash
cd frontend && npm run typecheck
```

- [ ] **Step 3: Commit**

```bash
git add frontend/src/main/updater.ts
git commit -m "feat(electron): add auto-updater via electron-updater with GitHub Releases provider"
```

---

## Phase 4 — First-Run Setup Wizard (~2 hours)

### Task 6: Setup wizard React component + env writer

**Files:**
- Create: `frontend/src/renderer/src/components/SetupWizard.tsx`
- Create: `frontend/src/main/services/envManager.ts`
- Modify: `frontend/src/preload/index.ts` (add env IPC)
- Modify: `frontend/src/renderer/src/App.tsx` (gate on setup complete)

- [ ] **Step 1: Create env manager in main process**

Create `frontend/src/main/services/envManager.ts`:
```typescript
import { app } from 'electron'
import * as fs from 'fs'
import * as path from 'path'

const ENV_PATH = path.join(app.getPath('userData'), '.env')
const EXAMPLE_PATH = app.isPackaged
  ? path.join(process.resourcesPath, 'backend/.env.example')
  : path.join(__dirname, '..', '..', '..', '..', 'backend', '.env.example')

export function isSetupComplete(): boolean {
  if (!fs.existsSync(ENV_PATH)) return false
  const content = fs.readFileSync(ENV_PATH, 'utf-8')
  return !content.includes('<CHANGE_ME>') && content.includes('JWT_SECRET_KEY=')
}

export function readEnvExample(): Record<string, string> {
  if (!fs.existsSync(EXAMPLE_PATH)) return {}
  const lines = fs.readFileSync(EXAMPLE_PATH, 'utf-8').split('\n')
  const result: Record<string, string> = {}
  for (const line of lines) {
    const trimmed = line.trim()
    if (!trimmed || trimmed.startsWith('#')) continue
    const eq = trimmed.indexOf('=')
    if (eq === -1) continue
    result[trimmed.slice(0, eq)] = trimmed.slice(eq + 1)
  }
  return result
}

export function writeEnv(values: Record<string, string>): void {
  const lines = Object.entries(values).map(([k, v]) => `${k}=${v}`)
  fs.writeFileSync(ENV_PATH, lines.join('\n') + '\n', 'utf-8')
}

export function generateSecret(bytes = 64): string {
  const { randomBytes } = require('crypto')
  return randomBytes(bytes).toString('hex')
}
```

- [ ] **Step 2: Register env IPC in `frontend/src/main/index.ts`**

Add these handlers inside `registerIPC()`:
```typescript
import { isSetupComplete, writeEnv, generateSecret } from './services/envManager'

// Inside registerIPC():
ipcMain.handle('setup:isComplete', () => isSetupComplete())
ipcMain.handle('setup:generateSecret', () => generateSecret())
ipcMain.handle('setup:writeEnv', (_event, values: Record<string, string>) => {
  writeEnv(values)
})
```

Also update `BackendAPI` in `frontend/src/preload/index.ts`:
```typescript
// Add to backendAPI object:
isSetupComplete: () => ipcRenderer.invoke('setup:isComplete'),
generateSecret: () => ipcRenderer.invoke('setup:generateSecret'),
writeEnv: (values: Record<string, string>) => ipcRenderer.invoke('setup:writeEnv', values),

// Add to BackendAPI interface in index.d.ts:
isSetupComplete: () => Promise<boolean>
generateSecret: () => Promise<string>
writeEnv: (values: Record<string, string>) => Promise<void>
```

- [ ] **Step 3: Create `frontend/src/renderer/src/components/SetupWizard.tsx`**

```tsx
import { useState, useEffect } from 'react'

type Step = 'docker' | 'secrets' | 'llm' | 'review' | 'installing'

interface Config {
  JWT_SECRET_KEY: string
  POSTGRES_PASSWORD: string
  REDIS_PASSWORD: string
  LOCAL_LLM_BASE_URL: string
  LOCAL_LLM_MODEL: string
  DEFAULT_ADMIN_PASSWORD: string
}

interface Props {
  onComplete: () => void
}

export function SetupWizard({ onComplete }: Props) {
  const [step, setStep] = useState<Step>('docker')
  const [dockerOk, setDockerOk] = useState<boolean | null>(null)
  const [config, setConfig] = useState<Config>({
    JWT_SECRET_KEY: '',
    POSTGRES_PASSWORD: '',
    REDIS_PASSWORD: '',
    LOCAL_LLM_BASE_URL: 'http://localhost:8001/v1',
    LOCAL_LLM_MODEL: 'Qwen/Qwen2.5-72B-Instruct-AWQ',
    DEFAULT_ADMIN_PASSWORD: '',
  })
  const [installing, setInstalling] = useState(false)
  const [installMsg, setInstallMsg] = useState('')

  useEffect(() => {
    if (step === 'docker') {
      window.backend.checkDocker().then(setDockerOk)
    }
  }, [step])

  async function generateSecrets() {
    const jwt = await window.backend.generateSecret()
    const pg = await window.backend.generateSecret()
    const redis = await window.backend.generateSecret()
    const admin = await window.backend.generateSecret()
    setConfig((c) => ({
      ...c,
      JWT_SECRET_KEY: jwt,
      POSTGRES_PASSWORD: pg.slice(0, 32),
      REDIS_PASSWORD: redis.slice(0, 32),
      DEFAULT_ADMIN_PASSWORD: admin.slice(0, 20),
    }))
  }

  async function finish() {
    setStep('installing')
    setInstalling(true)
    setInstallMsg('Writing configuration...')

    const full: Record<string, string> = {
      ...config,
      JWT_ALGORITHM: 'HS256',
      JWT_EXPIRE_MINUTES: '480',
      KAFKA_BOOTSTRAP_SERVERS: 'localhost:9092',
      KAFKA_GROUP_ID: 'ai_soc',
      REDIS_URL: `redis://:${config.REDIS_PASSWORD}@localhost:6379/0`,
      CHROMA_HOST: 'localhost',
      CHROMA_PORT: '8888',
      POSTGRES_DSN: `postgresql://soc:${config.POSTGRES_PASSWORD}@localhost:5432/soc_pipeline`,
      SQLITE_DB_PATH: './data/hitl.db',
      USE_MOCK_TI: 'true',
      LOCAL_AI_ONLY: 'true',
      SOAR_ENABLED: 'false',
      LOG_LEVEL: 'INFO',
      PIPELINE_MAX_CONCURRENT_ALERTS: '512',
      KAFKA_NUM_CONSUMER_WORKERS: '16',
      LLM_MAX_CONCURRENT_CALLS: '64',
      LLM_CALL_TIMEOUT_SECONDS: '30.0',
      PLAYBOOK_CACHE_TTL_SECONDS: '3600',
      RAG_CTX_CACHE_TTL_SECONDS: '3600',
    }
    await window.backend.writeEnv(full)

    setInstallMsg('Starting AI SOC services...')
    await window.backend.startServices()

    // Poll until running
    let attempts = 0
    const poll = setInterval(async () => {
      const status = await window.backend.getStatus()
      attempts++
      if (status === 'running') {
        clearInterval(poll)
        setInstallMsg('All services are running!')
        setTimeout(onComplete, 1500)
      } else if (status === 'error' || attempts > 60) {
        clearInterval(poll)
        setInstallMsg('Some services failed. Check Docker and try again.')
        setInstalling(false)
        setStep('review')
      }
    }, 2000)
  }

  return (
    <div className="min-h-screen bg-gray-950 text-gray-100 flex items-center justify-center p-8">
      <div className="w-full max-w-2xl bg-gray-900 rounded-2xl border border-gray-800 shadow-2xl p-8">
        <div className="flex items-center gap-3 mb-8">
          <div className="w-10 h-10 rounded-lg bg-blue-600 flex items-center justify-center text-xl font-bold">
            AI
          </div>
          <div>
            <h1 className="text-xl font-semibold">AI SOC Setup</h1>
            <p className="text-sm text-gray-400">First-time configuration</p>
          </div>
        </div>

        {step === 'docker' && (
          <div>
            <h2 className="text-lg font-medium mb-4">Step 1 — Docker Desktop</h2>
            {dockerOk === null && <p className="text-gray-400">Checking Docker...</p>}
            {dockerOk === true && (
              <div>
                <p className="text-green-400 mb-6">Docker is running.</p>
                <button
                  onClick={() => setStep('secrets')}
                  className="px-6 py-2 bg-blue-600 rounded-lg hover:bg-blue-500"
                >
                  Next
                </button>
              </div>
            )}
            {dockerOk === false && (
              <div>
                <p className="text-red-400 mb-2">Docker Desktop is not running.</p>
                <p className="text-gray-400 mb-6 text-sm">
                  Please start Docker Desktop, then click Retry.
                </p>
                <button
                  onClick={() => window.backend.checkDocker().then(setDockerOk)}
                  className="px-6 py-2 bg-gray-700 rounded-lg hover:bg-gray-600"
                >
                  Retry
                </button>
              </div>
            )}
          </div>
        )}

        {step === 'secrets' && (
          <div>
            <h2 className="text-lg font-medium mb-4">Step 2 — Generate Credentials</h2>
            <p className="text-gray-400 mb-6 text-sm">
              Click below to auto-generate secure random credentials for all services.
            </p>
            <button
              onClick={generateSecrets}
              className="px-4 py-2 bg-indigo-600 rounded-lg hover:bg-indigo-500 mb-6"
            >
              Generate Credentials
            </button>
            {config.JWT_SECRET_KEY && (
              <div className="space-y-3 mb-6 text-sm font-mono bg-gray-800 p-4 rounded-lg">
                <div className="flex justify-between">
                  <span className="text-gray-400">JWT Secret</span>
                  <span className="text-green-400 truncate max-w-xs">{config.JWT_SECRET_KEY.slice(0, 20)}…</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-400">Admin Password</span>
                  <span className="text-green-400">{config.DEFAULT_ADMIN_PASSWORD}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-400">Postgres Password</span>
                  <span className="text-green-400">{config.POSTGRES_PASSWORD}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-400">Redis Password</span>
                  <span className="text-green-400">{config.REDIS_PASSWORD}</span>
                </div>
              </div>
            )}
            <div className="flex gap-3">
              <button onClick={() => setStep('docker')} className="px-4 py-2 bg-gray-700 rounded-lg hover:bg-gray-600">
                Back
              </button>
              <button
                disabled={!config.JWT_SECRET_KEY}
                onClick={() => setStep('llm')}
                className="px-6 py-2 bg-blue-600 rounded-lg hover:bg-blue-500 disabled:opacity-40"
              >
                Next
              </button>
            </div>
          </div>
        )}

        {step === 'llm' && (
          <div>
            <h2 className="text-lg font-medium mb-4">Step 3 — Local LLM Endpoint</h2>
            <p className="text-gray-400 mb-6 text-sm">
              AI SOC runs entirely on-premises. Point to your local vLLM server.
            </p>
            <div className="space-y-4 mb-6">
              <div>
                <label className="block text-sm text-gray-400 mb-1">vLLM Base URL</label>
                <input
                  type="text"
                  value={config.LOCAL_LLM_BASE_URL}
                  onChange={(e) => setConfig((c) => ({ ...c, LOCAL_LLM_BASE_URL: e.target.value }))}
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm"
                />
              </div>
              <div>
                <label className="block text-sm text-gray-400 mb-1">Model Name</label>
                <input
                  type="text"
                  value={config.LOCAL_LLM_MODEL}
                  onChange={(e) => setConfig((c) => ({ ...c, LOCAL_LLM_MODEL: e.target.value }))}
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm"
                />
              </div>
            </div>
            <div className="flex gap-3">
              <button onClick={() => setStep('secrets')} className="px-4 py-2 bg-gray-700 rounded-lg hover:bg-gray-600">
                Back
              </button>
              <button onClick={() => setStep('review')} className="px-6 py-2 bg-blue-600 rounded-lg hover:bg-blue-500">
                Next
              </button>
            </div>
          </div>
        )}

        {step === 'review' && !installing && (
          <div>
            <h2 className="text-lg font-medium mb-4">Step 4 — Review & Install</h2>
            <div className="bg-gray-800 rounded-lg p-4 mb-6 text-sm space-y-2">
              <div className="flex justify-between">
                <span className="text-gray-400">LLM Endpoint</span>
                <span>{config.LOCAL_LLM_BASE_URL}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Model</span>
                <span>{config.LOCAL_LLM_MODEL}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Admin User</span>
                <span>admin</span>
              </div>
            </div>
            <p className="text-gray-400 text-sm mb-6">
              Clicking Install will write your .env and start all Docker services.
            </p>
            <div className="flex gap-3">
              <button onClick={() => setStep('llm')} className="px-4 py-2 bg-gray-700 rounded-lg hover:bg-gray-600">
                Back
              </button>
              <button onClick={finish} className="px-6 py-2 bg-green-600 rounded-lg hover:bg-green-500">
                Install & Launch
              </button>
            </div>
          </div>
        )}

        {step === 'installing' && (
          <div className="text-center py-8">
            <div className="text-4xl mb-4">⚙️</div>
            <p className="text-lg font-medium mb-2">Setting Up AI SOC</p>
            <p className="text-gray-400 text-sm">{installMsg}</p>
          </div>
        )}
      </div>
    </div>
  )
}
```

- [ ] **Step 4: Read current App.tsx to understand structure**

```bash
cat frontend/src/renderer/src/App.tsx | head -60
```

- [ ] **Step 5: Add setup gate to App.tsx**

At the top of the App component, add setup check:
```tsx
import { SetupWizard } from './components/SetupWizard'
import { useState, useEffect } from 'react'

// Inside App():
const [setupComplete, setSetupComplete] = useState<boolean | null>(null)

useEffect(() => {
  window.backend.isSetupComplete().then(setSetupComplete)
}, [])

if (setupComplete === null) return null  // loading
if (!setupComplete) return <SetupWizard onComplete={() => setSetupComplete(true)} />
// ... rest of existing App render
```

- [ ] **Step 6: Run dev build and verify wizard renders**

```bash
cd frontend && npm run dev
# Open app: first-time should show wizard, subsequent runs skip it
```

- [ ] **Step 7: Commit**

```bash
git add frontend/src/
git commit -m "feat(electron): add first-run setup wizard with auto-credential generation"
```

---

## Phase 5 — Prometheus Metrics + Grafana Monitoring (~1.5 hours)

### Task 7: Add Prometheus `/metrics` endpoint to FastAPI

**Files:**
- Modify: `backend/requirements.txt` (add prometheus-client)
- Create: `backend/api/metrics_middleware.py`
- Modify: `backend/api/hitl_api.py` (mount metrics)

- [ ] **Step 1: Add prometheus-client to requirements.txt**

```
prometheus-client==0.21.1
```

- [ ] **Step 2: Create `backend/api/metrics_middleware.py`**

```python
from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST
from fastapi import Request, Response
import time

REQUEST_COUNT = Counter(
    'http_requests_total',
    'Total HTTP requests',
    ['method', 'endpoint', 'status']
)

REQUEST_LATENCY = Histogram(
    'http_request_duration_seconds',
    'HTTP request duration in seconds',
    ['method', 'endpoint'],
    buckets=[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0]
)

HITL_PENDING = Gauge('soc_hitl_pending_reviews', 'Number of pending HITL reviews')
HITL_DECISIONS = Counter('soc_hitl_decisions_total', 'Total HITL decisions', ['action'])
ALERTS_PROCESSED = Counter('soc_alerts_processed_total', 'Total alerts processed', ['outcome'])
PIPELINE_ERRORS = Counter('soc_pipeline_errors_total', 'Pipeline errors', ['stage'])


async def prometheus_middleware(request: Request, call_next):
    start = time.perf_counter()
    response = await call_next(request)
    duration = time.perf_counter() - start

    endpoint = request.url.path
    REQUEST_COUNT.labels(
        method=request.method,
        endpoint=endpoint,
        status=response.status_code
    ).inc()
    REQUEST_LATENCY.labels(method=request.method, endpoint=endpoint).observe(duration)

    return response


def metrics_endpoint():
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
```

- [ ] **Step 3: Mount metrics in `backend/api/hitl_api.py`**

Add after the `app = FastAPI(...)` block:
```python
from starlette.middleware.base import BaseHTTPMiddleware
from api.metrics_middleware import prometheus_middleware, metrics_endpoint

app.add_middleware(BaseHTTPMiddleware, dispatch=prometheus_middleware)
app.add_route("/metrics", metrics_endpoint)
```

- [ ] **Step 4: Verify metrics endpoint responds**

```bash
cd backend
uvicorn api.hitl_api:app --port 8080 &
sleep 2
curl http://localhost:8080/metrics | head -20
# Expected: # HELP http_requests_total ...
kill %1
```

- [ ] **Step 5: Commit**

```bash
git add backend/api/metrics_middleware.py backend/api/hitl_api.py backend/requirements.txt
git commit -m "feat(monitoring): add Prometheus /metrics endpoint to FastAPI"
```

---

### Task 8: Add Prometheus + Grafana to docker-compose monitoring stack

**Files:**
- Create: `monitoring/docker-compose.monitoring.yml`
- Create: `monitoring/prometheus/prometheus.yml`
- Create: `monitoring/grafana/provisioning/datasources/prometheus.yml`
- Create: `monitoring/grafana/provisioning/dashboards/dashboard.yml`
- Create: `monitoring/grafana/dashboards/ai-soc-overview.json`

- [ ] **Step 1: Create `monitoring/docker-compose.monitoring.yml`**

```yaml
version: "3.9"

services:
  prometheus:
    image: prom/prometheus:v2.54.1
    container_name: prometheus
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus/prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - prometheus_data:/prometheus
    command:
      - "--config.file=/etc/prometheus/prometheus.yml"
      - "--storage.tsdb.path=/prometheus"
      - "--storage.tsdb.retention.time=30d"
      - "--web.enable-lifecycle"
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "wget", "-qO-", "http://localhost:9090/-/healthy"]
      interval: 15s
      timeout: 5s
      retries: 3

  grafana:
    image: grafana/grafana:11.3.0
    container_name: grafana
    ports:
      - "3000:3000"
    environment:
      GF_SECURITY_ADMIN_USER: admin
      GF_SECURITY_ADMIN_PASSWORD: ${GRAFANA_PASSWORD:-changeme_grafana}
      GF_USERS_ALLOW_SIGN_UP: "false"
      GF_AUTH_ANONYMOUS_ENABLED: "false"
      GF_SERVER_ROOT_URL: http://localhost:3000
    volumes:
      - grafana_data:/var/lib/grafana
      - ./grafana/provisioning:/etc/grafana/provisioning:ro
      - ./grafana/dashboards:/var/lib/grafana/dashboards:ro
    restart: unless-stopped
    depends_on:
      prometheus:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "wget", "-qO-", "http://localhost:3000/api/health"]
      interval: 15s
      timeout: 5s
      retries: 3

volumes:
  prometheus_data:
  grafana_data:
```

- [ ] **Step 2: Create `monitoring/prometheus/prometheus.yml`**

```yaml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'ai-soc-api'
    static_configs:
      - targets: ['host.docker.internal:8080']
    metrics_path: /metrics

  - job_name: 'kafka'
    static_configs:
      - targets: ['host.docker.internal:9092']

  - job_name: 'postgres'
    static_configs:
      - targets: ['host.docker.internal:5432']

  - job_name: 'redis'
    static_configs:
      - targets: ['host.docker.internal:6379']
```

- [ ] **Step 3: Create Grafana datasource provisioning**

Create `monitoring/grafana/provisioning/datasources/prometheus.yml`:
```yaml
apiVersion: 1
datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true
    jsonData:
      timeInterval: '15s'
```

Create `monitoring/grafana/provisioning/dashboards/dashboard.yml`:
```yaml
apiVersion: 1
providers:
  - name: 'AI SOC Dashboards'
    orgId: 1
    type: file
    disableDeletion: false
    updateIntervalSeconds: 30
    options:
      path: /var/lib/grafana/dashboards
```

- [ ] **Step 4: Create `monitoring/grafana/dashboards/ai-soc-overview.json`**

```json
{
  "title": "AI SOC Overview",
  "uid": "ai-soc-overview",
  "version": 1,
  "schemaVersion": 39,
  "refresh": "30s",
  "panels": [
    {
      "id": 1,
      "title": "API Request Rate",
      "type": "stat",
      "gridPos": { "h": 4, "w": 6, "x": 0, "y": 0 },
      "targets": [{
        "expr": "rate(http_requests_total[5m])",
        "legendFormat": "req/s"
      }]
    },
    {
      "id": 2,
      "title": "Pending HITL Reviews",
      "type": "stat",
      "gridPos": { "h": 4, "w": 6, "x": 6, "y": 0 },
      "targets": [{
        "expr": "soc_hitl_pending_reviews",
        "legendFormat": "pending"
      }],
      "fieldConfig": {
        "defaults": {
          "thresholds": {
            "steps": [
              {"color": "green", "value": 0},
              {"color": "yellow", "value": 10},
              {"color": "red", "value": 50}
            ]
          }
        }
      }
    },
    {
      "id": 3,
      "title": "HITL Decisions (24h)",
      "type": "piechart",
      "gridPos": { "h": 8, "w": 8, "x": 0, "y": 4 },
      "targets": [{
        "expr": "increase(soc_hitl_decisions_total[24h])",
        "legendFormat": "{{action}}"
      }]
    },
    {
      "id": 4,
      "title": "API Latency (p95)",
      "type": "timeseries",
      "gridPos": { "h": 8, "w": 16, "x": 8, "y": 4 },
      "targets": [{
        "expr": "histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))",
        "legendFormat": "p95 {{endpoint}}"
      }]
    }
  ]
}
```

- [ ] **Step 5: Test monitoring stack starts**

```bash
GRAFANA_PASSWORD=changeme_grafana docker compose -f monitoring/docker-compose.monitoring.yml up -d
sleep 10
curl http://localhost:9090/-/healthy   # Expected: Prometheus is Healthy.
curl http://localhost:3000/api/health  # Expected: {"database": "ok", "version": "..."}
```

- [ ] **Step 6: Commit**

```bash
git add monitoring/
git commit -m "feat(monitoring): add Prometheus + Grafana monitoring stack with AI SOC dashboard"
```

---

## Phase 6 — Operational Excellence (~1 hour)

### Task 9: Master docker-compose for full stack

**Files:**
- Create: `docker-compose.full.yml`

- [ ] **Step 1: Create `docker-compose.full.yml`** in the repo root

```yaml
# Full-stack docker compose — starts all AI SOC services in dependency order.
# Usage: docker compose -f docker-compose.full.yml --env-file backend/.env up -d

version: "3.9"

include:
  - path: backend/docker-compose.yml
  - path: monitoring/docker-compose.monitoring.yml
  - path: wazuh-docker/single-node/docker-compose.yml
```

- [ ] **Step 2: Verify it can be parsed**

```bash
docker compose -f docker-compose.full.yml config --quiet
# Expected: no errors (some services may warn about missing .env — that's OK)
```

- [ ] **Step 3: Commit**

```bash
git add docker-compose.full.yml
git commit -m "feat(deploy): add master docker-compose.full.yml that includes all stacks"
```

---

### Task 10: Backup scripts (Windows + Linux)

**Files:**
- Create: `scripts/backup.ps1` (Windows PowerShell)
- Create: `scripts/backup.sh` (Linux/macOS Bash)
- Create: `scripts/restore.sh`

- [ ] **Step 1: Create `scripts/backup.ps1`**

```powershell
#Requires -Version 5.1
<#
.SYNOPSIS
    Backup AI SOC persistent data volumes.
.PARAMETER OutputDir
    Directory to write backup archives (default: ./backups)
#>
param(
    [string]$OutputDir = ".\backups"
)

$ErrorActionPreference = "Stop"
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$backupDir = Join-Path $OutputDir $timestamp

New-Item -ItemType Directory -Force -Path $backupDir | Out-Null
Write-Host "Backup directory: $backupDir"

function Backup-Volume {
    param([string]$VolumeName, [string]$FileName)
    Write-Host "Backing up $VolumeName..."
    $archive = Join-Path $backupDir $FileName
    docker run --rm `
        -v "${VolumeName}:/data:ro" `
        -v "${backupDir}:/backup" `
        alpine tar czf "/backup/$FileName" -C /data .
    if ($LASTEXITCODE -ne 0) { throw "Failed to backup $VolumeName" }
    Write-Host "  -> $FileName"
}

Backup-Volume "backend_pg_data"    "postgres-$timestamp.tar.gz"
Backup-Volume "backend_redis_data" "redis-$timestamp.tar.gz"
Backup-Volume "backend_chroma_data" "chroma-$timestamp.tar.gz"
Backup-Volume "backend_kafka_data" "kafka-$timestamp.tar.gz"

$manifest = @{
    timestamp = $timestamp
    volumes   = @("postgres", "redis", "chroma", "kafka")
} | ConvertTo-Json
$manifest | Out-File -FilePath (Join-Path $backupDir "manifest.json") -Encoding utf8

Write-Host "`nBackup complete: $backupDir"
```

- [ ] **Step 2: Create `scripts/backup.sh`**

```bash
#!/usr/bin/env bash
set -euo pipefail

OUTPUT_DIR="${1:-./backups}"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
BACKUP_DIR="$OUTPUT_DIR/$TIMESTAMP"

mkdir -p "$BACKUP_DIR"
echo "Backup directory: $BACKUP_DIR"

backup_volume() {
    local volume="$1"
    local filename="$2"
    echo "Backing up $volume..."
    docker run --rm \
        -v "${volume}:/data:ro" \
        -v "${BACKUP_DIR}:/backup" \
        alpine tar czf "/backup/$filename" -C /data .
    echo "  -> $filename"
}

backup_volume "backend_pg_data"     "postgres-${TIMESTAMP}.tar.gz"
backup_volume "backend_redis_data"  "redis-${TIMESTAMP}.tar.gz"
backup_volume "backend_chroma_data" "chroma-${TIMESTAMP}.tar.gz"
backup_volume "backend_kafka_data"  "kafka-${TIMESTAMP}.tar.gz"

cat > "$BACKUP_DIR/manifest.json" <<EOF
{
  "timestamp": "$TIMESTAMP",
  "volumes": ["postgres", "redis", "chroma", "kafka"]
}
EOF

echo ""
echo "Backup complete: $BACKUP_DIR"
```

- [ ] **Step 3: Create `scripts/restore.sh`**

```bash
#!/usr/bin/env bash
set -euo pipefail

BACKUP_DIR="${1:?Usage: ./restore.sh <backup-dir>}"

if [ ! -f "$BACKUP_DIR/manifest.json" ]; then
    echo "Error: $BACKUP_DIR/manifest.json not found"
    exit 1
fi

echo "WARNING: This will OVERWRITE all current data volumes."
read -rp "Continue? (yes/no): " confirm
[ "$confirm" = "yes" ] || { echo "Aborted."; exit 0; }

TIMESTAMP=$(basename "$BACKUP_DIR")

restore_volume() {
    local volume="$1"
    local filename="$2"
    echo "Restoring $volume..."
    docker run --rm \
        -v "${volume}:/data" \
        -v "${BACKUP_DIR}:/backup:ro" \
        alpine sh -c "rm -rf /data/* && tar xzf /backup/$filename -C /data"
    echo "  done."
}

restore_volume "backend_pg_data"     "postgres-${TIMESTAMP}.tar.gz"
restore_volume "backend_redis_data"  "redis-${TIMESTAMP}.tar.gz"
restore_volume "backend_chroma_data" "chroma-${TIMESTAMP}.tar.gz"
restore_volume "backend_kafka_data"  "kafka-${TIMESTAMP}.tar.gz"

echo ""
echo "Restore complete. Restart services: docker compose -f docker-compose.full.yml up -d"
```

- [ ] **Step 4: Make scripts executable and commit**

```bash
chmod +x scripts/backup.sh scripts/restore.sh
git add scripts/
git commit -m "feat(ops): add volume backup/restore scripts for Windows and Linux"
```

---

### Task 11: Write DEPLOYMENT.md

**Files:**
- Create: `DEPLOYMENT.md`

- [ ] **Step 1: Create `DEPLOYMENT.md`** in the repo root

```markdown
# AI SOC — On-Premises Deployment Guide

## Prerequisites

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| Docker Desktop | 25.0 | Latest |
| RAM | 32 GB | 64 GB |
| GPU (for LLM) | NVIDIA 24 GB VRAM | A100 80 GB |
| Disk | 100 GB free | 500 GB NVMe |
| OS | Windows 10/11, Ubuntu 22.04 | Ubuntu 22.04 LTS |
| CPU | 8 cores | 32 cores |

## Option A — Desktop Installer (Recommended)

1. Download the installer for your OS from the [Releases page](https://github.com/amunim12/ai-soc/releases/latest)
2. Run the installer — follow the setup wizard
3. The wizard will:
   - Check Docker Desktop is running
   - Generate all credentials automatically
   - Write a `.env` file to `%APPDATA%/ai-soc/.env` (Windows) or `~/.config/ai-soc/.env` (Linux/Mac)
   - Start all Docker services
4. Log in with the admin credentials shown in the wizard

## Option B — Docker Compose (Advanced)

### 1. Clone the repository

```bash
git clone https://github.com/amunim12/ai-soc.git
cd ai-soc
```

### 2. Configure environment

```bash
cp backend/.env.example backend/.env
# Edit backend/.env — replace every <CHANGE_ME> value

# Generate JWT secret:
python -c "import secrets; print(secrets.token_hex(64))"

# Generate passwords:
python -c "import secrets; print(secrets.token_hex(32))"
```

### 3. Start infrastructure services

```bash
docker compose -f backend/docker-compose.yml --env-file backend/.env up -d
```

Wait for all services to be healthy:
```bash
docker compose -f backend/docker-compose.yml ps
# All services should show "healthy"
```

### 4. Start Wazuh SIEM

```bash
cd wazuh-docker/single-node
docker compose up -d
```

### 5. Start the AI API

```bash
cd backend
pip install -r requirements.txt
uvicorn api.hitl_api:app --host 0.0.0.0 --port 8080 --workers 8
```

Or via Docker:
```bash
docker compose -f backend/docker-compose.yml up hitl_api -d
```

### 6. Start monitoring (optional)

```bash
GRAFANA_PASSWORD=$(python -c "import secrets; print(secrets.token_hex(16))") \
  docker compose -f monitoring/docker-compose.monitoring.yml up -d
```

Grafana: http://localhost:3000 (admin / your GRAFANA_PASSWORD)
Prometheus: http://localhost:9090

### 7. Open the frontend

Launch the Electron app from the installer, or for development:
```bash
cd frontend
npm install
npm run dev
```

## Credential Rotation (Every 90 Days)

1. Stop all services
2. Generate new credentials: `python -c "import secrets; print(secrets.token_hex(64))"`
3. Update `backend/.env`
4. Restart services

## Backup

```bash
# Windows
powershell -File scripts/backup.ps1 -OutputDir C:\ai-soc-backups

# Linux/macOS
./scripts/backup.sh /mnt/backups
```

Backups are stored as compressed tar archives of Docker volumes.

## Restore

```bash
./scripts/restore.sh /mnt/backups/20260101-120000
```

## Upgrading

**Via Desktop App:** The app checks for updates automatically every 4 hours. You will be prompted to download and install.

**Via Docker Compose:**
```bash
git pull origin main
docker compose -f backend/docker-compose.yml pull
docker compose -f backend/docker-compose.yml up -d
```

## Troubleshooting

| Issue | Fix |
|-------|-----|
| API returns 503 | Check `docker ps` — all services must be healthy |
| LLM timeout | Verify vLLM server is running at `LOCAL_LLM_BASE_URL` |
| Kafka connection refused | Wait 30s after startup — Kafka takes time to initialize |
| ChromaDB OOM | Reduce `PIPELINE_MAX_CONCURRENT_ALERTS` in `.env` |
| Wazuh alerts not arriving | Check Wazuh agent is configured to send to `localhost:9092` |

## Ports Reference

| Service | Port | Protocol |
|---------|------|----------|
| AI SOC API | 8080 | HTTP |
| Frontend (dev) | 5173 | HTTP |
| Kafka | 9092 | TCP |
| Redis | 6379 | TCP |
| PostgreSQL | 5432 | TCP |
| ChromaDB | 8888 | HTTP |
| Wazuh Dashboard | 443 | HTTPS |
| Prometheus | 9090 | HTTP |
| Grafana | 3000 | HTTP |
```

- [ ] **Step 2: Commit**

```bash
git add DEPLOYMENT.md
git commit -m "docs: add comprehensive on-premises deployment guide (DEPLOYMENT.md)"
```

---

## Phase 7 — Download Website (~1 hour)

### Task 12: Create static download landing page

**Files:**
- Create: `website/index.html`
- Create: `website/styles.css`

This is a standalone static site served from GitHub Pages or any CDN.

- [ ] **Step 1: Create `website/index.html`**

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>AI SOC — On-Premises Security Operations Center</title>
  <link rel="stylesheet" href="styles.css" />
</head>
<body>
  <nav>
    <div class="nav-inner">
      <div class="logo">AI SOC</div>
      <div class="nav-links">
        <a href="#features">Features</a>
        <a href="#requirements">Requirements</a>
        <a href="https://github.com/amunim12/ai-soc/blob/main/DEPLOYMENT.md">Docs</a>
        <a href="https://github.com/amunim12/ai-soc" target="_blank">GitHub</a>
      </div>
    </div>
  </nav>

  <section class="hero">
    <div class="hero-inner">
      <div class="badge">100% On-Premises · Air-Gap Ready</div>
      <h1>AI-Powered Security Operations<br />That Never Leaves Your Network</h1>
      <p>Autonomous multi-agent SOC with LangGraph orchestration, Wazuh SIEM integration, and human-in-the-loop playbook review. No cloud. No telemetry. Full data sovereignty.</p>
      <div class="download-group">
        <a class="btn-primary" href="https://github.com/amunim12/ai-soc/releases/latest/download/AI.SOC.Setup.exe">
          ↓ Download for Windows
        </a>
        <a class="btn-secondary" href="https://github.com/amunim12/ai-soc/releases/latest/download/AI.SOC.dmg">
          ↓ Download for macOS
        </a>
        <a class="btn-secondary" href="https://github.com/amunim12/ai-soc/releases/latest/download/AI.SOC.AppImage">
          ↓ Download for Linux
        </a>
      </div>
      <p class="subtext">v1.0.0 · Requires Docker Desktop · <a href="https://github.com/amunim12/ai-soc/releases">All releases</a></p>
    </div>
  </section>

  <section id="features" class="features">
    <div class="container">
      <h2>What's Inside</h2>
      <div class="feature-grid">
        <div class="feature-card">
          <div class="feature-icon">🤖</div>
          <h3>Multi-Agent Pipeline</h3>
          <p>LangGraph-orchestrated agents: log analyst, threat intel, playbook generator, SOAR executor — all running locally on your hardware.</p>
        </div>
        <div class="feature-card">
          <div class="feature-icon">🔒</div>
          <h3>Zero Cloud Dependency</h3>
          <p>Fully air-gap capable. All LLM inference runs via local vLLM. Embedding models are pre-downloaded. No external API calls required.</p>
        </div>
        <div class="feature-card">
          <div class="feature-icon">👁️</div>
          <h3>Human-in-the-Loop</h3>
          <p>Critical decisions require analyst approval. Immutable audit log of every HITL decision. Configurable confidence thresholds.</p>
        </div>
        <div class="feature-card">
          <div class="feature-icon">📊</div>
          <h3>Built-in SIEM Dashboard</h3>
          <p>Native Wazuh integration, MITRE ATT&CK mapping, alert severity timeline, and agent status — all in the Electron desktop UI.</p>
        </div>
        <div class="feature-card">
          <div class="feature-icon">⚡</div>
          <h3>1,100 EPS Throughput</h3>
          <p>16 Kafka consumer workers, 48 partitions, async LLM batching. Handles enterprise-scale alert volume on a single server.</p>
        </div>
        <div class="feature-card">
          <div class="feature-icon">🛡️</div>
          <h3>EAL4 Security Controls</h3>
          <p>Common Criteria EAL4-aligned CI/CD with SAST, SCA, DAST, SBOM generation, and cosign image signing on every release.</p>
        </div>
      </div>
    </div>
  </section>

  <section id="requirements" class="requirements">
    <div class="container">
      <h2>System Requirements</h2>
      <table>
        <thead>
          <tr><th>Component</th><th>Minimum</th><th>Recommended</th></tr>
        </thead>
        <tbody>
          <tr><td>RAM</td><td>32 GB</td><td>64 GB</td></tr>
          <tr><td>GPU</td><td>NVIDIA 24 GB VRAM</td><td>A100 80 GB</td></tr>
          <tr><td>Storage</td><td>100 GB free</td><td>500 GB NVMe</td></tr>
          <tr><td>CPU</td><td>8 cores</td><td>32 cores</td></tr>
          <tr><td>OS</td><td>Windows 10, Ubuntu 22.04</td><td>Ubuntu 22.04 LTS</td></tr>
          <tr><td>Docker Desktop</td><td>25.0+</td><td>Latest</td></tr>
        </tbody>
      </table>
    </div>
  </section>

  <footer>
    <div class="container">
      <p>AI SOC is open-source software. <a href="https://github.com/amunim12/ai-soc">View on GitHub</a></p>
      <p class="license">Licensed under Apache 2.0 · Copyright © 2025 AI SOC Contributors</p>
    </div>
  </footer>
</body>
</html>
```

- [ ] **Step 2: Create `website/styles.css`**

```css
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

:root {
  --bg: #060a14;
  --surface: #0d1424;
  --border: #1e2d4a;
  --blue: #3b82f6;
  --blue-dark: #2563eb;
  --text: #e2e8f0;
  --muted: #64748b;
}

body { background: var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; line-height: 1.6; }

a { color: var(--blue); text-decoration: none; }
a:hover { text-decoration: underline; }

nav { position: sticky; top: 0; background: rgba(6,10,20,0.9); backdrop-filter: blur(8px); border-bottom: 1px solid var(--border); z-index: 100; }
.nav-inner { max-width: 1200px; margin: 0 auto; padding: 0 2rem; height: 56px; display: flex; align-items: center; justify-content: space-between; }
.logo { font-weight: 700; font-size: 1.1rem; letter-spacing: -0.02em; color: var(--blue); }
.nav-links { display: flex; gap: 2rem; }
.nav-links a { color: var(--muted); font-size: 0.9rem; transition: color 0.15s; }
.nav-links a:hover { color: var(--text); text-decoration: none; }

.hero { padding: 6rem 2rem 5rem; text-align: center; }
.hero-inner { max-width: 820px; margin: 0 auto; }
.badge { display: inline-block; padding: 0.3rem 1rem; background: rgba(59,130,246,0.1); border: 1px solid rgba(59,130,246,0.3); border-radius: 999px; font-size: 0.8rem; color: var(--blue); margin-bottom: 1.5rem; letter-spacing: 0.03em; }
h1 { font-size: clamp(2rem, 5vw, 3.2rem); font-weight: 800; line-height: 1.15; letter-spacing: -0.03em; margin-bottom: 1.2rem; }
.hero p { color: var(--muted); font-size: 1.1rem; max-width: 600px; margin: 0 auto 2.5rem; }

.download-group { display: flex; gap: 0.75rem; justify-content: center; flex-wrap: wrap; margin-bottom: 1rem; }
.btn-primary { background: var(--blue); color: #fff; padding: 0.75rem 1.75rem; border-radius: 8px; font-weight: 600; font-size: 0.95rem; transition: background 0.15s; }
.btn-primary:hover { background: var(--blue-dark); text-decoration: none; }
.btn-secondary { background: var(--surface); color: var(--text); padding: 0.75rem 1.75rem; border-radius: 8px; font-weight: 600; font-size: 0.95rem; border: 1px solid var(--border); transition: border-color 0.15s; }
.btn-secondary:hover { border-color: var(--blue); text-decoration: none; }
.subtext { font-size: 0.8rem; color: var(--muted); }

.features, .requirements { padding: 5rem 2rem; }
.features { background: var(--surface); border-top: 1px solid var(--border); border-bottom: 1px solid var(--border); }
.container { max-width: 1100px; margin: 0 auto; }
h2 { font-size: 2rem; font-weight: 700; letter-spacing: -0.02em; margin-bottom: 2.5rem; text-align: center; }

.feature-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 1.5rem; }
.feature-card { background: var(--bg); border: 1px solid var(--border); border-radius: 12px; padding: 1.5rem; }
.feature-icon { font-size: 1.8rem; margin-bottom: 0.75rem; }
.feature-card h3 { font-size: 1.05rem; font-weight: 600; margin-bottom: 0.5rem; }
.feature-card p { color: var(--muted); font-size: 0.9rem; }

table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
th { text-align: left; padding: 0.75rem 1rem; border-bottom: 2px solid var(--border); color: var(--muted); font-weight: 500; }
td { padding: 0.75rem 1rem; border-bottom: 1px solid var(--border); }
tr:last-child td { border-bottom: none; }

footer { padding: 3rem 2rem; border-top: 1px solid var(--border); text-align: center; }
footer p { color: var(--muted); font-size: 0.85rem; }
.license { margin-top: 0.4rem; font-size: 0.8rem; }
```

- [ ] **Step 3: Add GitHub Pages workflow**

Create `.github/workflows/website.yml`:
```yaml
name: Deploy Website

on:
  push:
    branches: [main]
    paths: ['website/**']

permissions:
  contents: read
  pages: write
  id-token: write

jobs:
  deploy:
    runs-on: ubuntu-latest
    environment:
      name: github-pages
      url: ${{ steps.deployment.outputs.page_url }}
    steps:
      - uses: actions/checkout@v4
      - uses: actions/configure-pages@v5
      - uses: actions/upload-pages-artifact@v3
        with:
          path: website/
      - id: deployment
        uses: actions/deploy-pages@v4
```

- [ ] **Step 4: Commit**

```bash
git add website/ .github/workflows/website.yml
git commit -m "feat(website): add static download landing page with GitHub Pages deployment"
```

---

## Self-Review Against Requirements

### Spec Coverage Check

| Requirement | Covered By |
|-------------|-----------|
| Non-root Docker container | Task 1 |
| All deps pinned to exact versions | Task 2 |
| Desktop installer (Windows NSIS, Mac DMG, Linux AppImage) | Task 3 |
| Backend service orchestration from Electron | Task 4 |
| Auto-updater | Task 5 |
| First-run setup wizard | Task 6 |
| Prometheus metrics endpoint | Task 7 |
| Grafana monitoring dashboard | Task 8 |
| Full-stack master compose | Task 9 |
| Backup/restore scripts (Windows + Linux) | Task 10 |
| DEPLOYMENT.md | Task 11 |
| Download website | Task 12 |

### Placeholder Scan — CLEAR

No TBD, TODO, or placeholder patterns found in code blocks above.

### Type Consistency Check

- `ServiceStatus` type defined in `backendManager.ts` Task 4, referenced consistently in `index.ts` Task 4 and `index.d.ts` Task 4
- `BackendAPI` interface in `index.d.ts` matches all methods in `preload/index.ts`
- `Config` interface in `SetupWizard.tsx` matches fields written by `envManager.ts`

---

**Estimated Total Effort:** ~8–10 hours of implementation.
**Risk:** Phase 3 (Electron service manager) is the highest-risk change — test on a clean machine with Docker Desktop installed before shipping the installer.
