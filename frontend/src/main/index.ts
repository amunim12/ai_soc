import { app, shell, BrowserWindow, ipcMain, Tray, Menu, nativeImage } from 'electron'
import { join } from 'path'
import icon from '../../resources/icon.png?asset'
import {
  startServices,
  stopServices,
  getServiceLogs,
  getStatus,
  onStatusChange,
  checkDockerAvailable
} from './services/backendManager'
import { isSetupComplete, writeEnv, generateSecret, getEnvPath } from './services/envManager'
import { setupAutoUpdater } from './updater'

const isDev = process.env.NODE_ENV === 'development' || !app.isPackaged

let mainWindow: BrowserWindow | null = null
let tray: Tray | null = null
let isQuitting = false

function createWindow(): void {
  mainWindow = new BrowserWindow({
    width: 1280,
    height: 800,
    show: false,
    autoHideMenuBar: true,
    ...(process.platform === 'linux' ? { icon } : {}),
    webPreferences: {
      preload: join(__dirname, '../preload/index.js'),
      sandbox: false
    }
  })

  mainWindow.on('ready-to-show', () => {
    mainWindow!.show()
  })

  // Hide to tray instead of closing (keep services running)
  mainWindow.on('close', (event) => {
    if (!isQuitting) {
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
  const trayImg = nativeImage.createFromPath(icon as string).resize({ width: 16, height: 16 })
  tray = new Tray(trayImg)
  tray.setToolTip('AI SOC')

  function buildMenu(): Electron.Menu {
    const status = getStatus()
    const statusLabel =
      status === 'running' ? '● Running' : status === 'starting' ? '◌ Starting…' : '○ Stopped'

    return Menu.buildFromTemplate([
      {
        label: 'Show Dashboard',
        click: () => {
          mainWindow?.show()
          mainWindow?.focus()
        }
      },
      { type: 'separator' },
      { label: statusLabel, enabled: false },
      {
        label: 'Start Services',
        enabled: status === 'stopped' || status === 'error',
        click: () => startServices()
      },
      {
        label: 'Stop Services',
        enabled: status === 'running',
        click: () => stopServices()
      },
      { type: 'separator' },
      {
        label: 'Quit AI SOC',
        click: () => {
          isQuitting = true
          app.quit()
        }
      }
    ])
  }

  tray.setContextMenu(buildMenu())
  tray.on('double-click', () => {
    mainWindow?.show()
    mainWindow?.focus()
  })

  onStatusChange(() => {
    tray?.setContextMenu(buildMenu())
  })
}

function registerIPC(): void {
  ipcMain.handle('service:start', () => startServices())
  ipcMain.handle('service:stop', () => stopServices())
  ipcMain.handle('service:status', () => getStatus())
  ipcMain.handle('service:logs', (_event, tail: number) => getServiceLogs(tail))
  ipcMain.handle('docker:available', () => checkDockerAvailable())

  ipcMain.handle('setup:isComplete', () => isSetupComplete())
  ipcMain.handle('setup:generateSecret', () => generateSecret())
  ipcMain.handle('setup:writeEnv', (_event, values: Record<string, string>) => writeEnv(values))
  ipcMain.handle('setup:envPath', () => getEnvPath())

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

  // Auto-start services on launch if already configured
  if (isSetupComplete()) {
    startServices()
  }

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow()
  })
})

app.on('window-all-closed', () => {
  // Keep running in system tray on all platforms
})

app.on('before-quit', async () => {
  await stopServices()
})
