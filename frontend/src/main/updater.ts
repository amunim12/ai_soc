import { autoUpdater } from 'electron-updater'
import { BrowserWindow, dialog, app } from 'electron'
import { execFileSync } from 'child_process'

function isAppSigned(): boolean {
  // On Windows, verify the running executable has a valid Authenticode signature.
  // Unsigned or dev builds must not offer auto-updates — electron-updater would
  // skip signature verification if the update payload is also unsigned, opening
  // a path for update-package substitution attacks.
  if (process.platform === 'win32') {
    try {
      // Pass the exe path via env var — never interpolated into the script string.
      // -LiteralPath prevents wildcard expansion on paths with brackets/globs.
      const result = execFileSync(
        'powershell',
        [
          '-NonInteractive',
          '-Command',
          '(Get-AuthenticodeSignature -LiteralPath $env:EXE_PATH).Status -eq "Valid"'
        ],
        { env: { ...process.env, EXE_PATH: app.getPath('exe') }, encoding: 'utf-8' }
      )
      return result.trim() === 'True'
    } catch {
      return false
    }
  }
  // On macOS, codesign --verify returns exit 0 only for valid signatures
  if (process.platform === 'darwin') {
    try {
      execFileSync('codesign', ['--verify', '--deep', app.getPath('exe')], { stdio: 'ignore' })
      return true
    } catch {
      return false
    }
  }
  // Linux: AppImage/deb signing is not enforced by the OS — allow updates
  return true
}

export function setupAutoUpdater(win: BrowserWindow): void {
  if (process.env.NODE_ENV === 'development' || !win) return

  // Do not enable auto-update on unsigned builds — an unsigned updater cannot
  // enforce the Authenticode chain and would silently accept any replacement package.
  if (!isAppSigned()) {
    console.warn('Auto-updater disabled: app is not code-signed.')
    return
  }

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
        defaultId: 0
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
        defaultId: 0
      })
      .then(({ response }) => {
        if (response === 0) autoUpdater.quitAndInstall()
      })
  })

  autoUpdater.on('error', (err) => {
    console.error('Auto-updater error:', err.message)
  })

  autoUpdater.checkForUpdates().catch(() => {})
  setInterval(() => autoUpdater.checkForUpdates().catch(() => {}), 4 * 60 * 60 * 1000)
}
