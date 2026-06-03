import { contextBridge, ipcRenderer } from 'electron'
import { electronAPI } from '@electron-toolkit/preload'

const backendAPI = {
  // Service orchestration
  startServices: () => ipcRenderer.invoke('service:start'),
  stopServices: () => ipcRenderer.invoke('service:stop'),
  getStatus: (): Promise<string> => ipcRenderer.invoke('service:status'),
  getLogs: (tail?: number) => ipcRenderer.invoke('service:logs', tail ?? 100),
  checkDocker: (): Promise<boolean> => ipcRenderer.invoke('docker:available'),
  onStatusChanged: (cb: (state: { status: string; message: string }) => void): (() => void) => {
    const handler = (
      _event: Electron.IpcRendererEvent,
      state: { status: string; message: string }
    ): void => cb(state)
    ipcRenderer.on('service:status-changed', handler)
    return () => ipcRenderer.removeListener('service:status-changed', handler)
  },
  // Setup wizard
  isSetupComplete: (): Promise<boolean> => ipcRenderer.invoke('setup:isComplete'),
  generateSecret: (): Promise<string> => ipcRenderer.invoke('setup:generateSecret'),
  writeEnv: (values: Record<string, string>): Promise<void> =>
    ipcRenderer.invoke('setup:writeEnv', values),
  getEnvPath: (): Promise<string> => ipcRenderer.invoke('setup:envPath')
}

if (process.contextIsolated) {
  try {
    contextBridge.exposeInMainWorld('electron', electronAPI)
    contextBridge.exposeInMainWorld('backend', backendAPI)
  } catch (error) {
    console.error(error)
  }
} else {
  // @ts-ignore -- context isolation is disabled; window augmentation is safe here
  window.electron = electronAPI
  // @ts-ignore -- context isolation is disabled; window augmentation is safe here
  window.backend = backendAPI
}
