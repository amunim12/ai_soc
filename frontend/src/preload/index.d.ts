import { ElectronAPI } from '@electron-toolkit/preload'

export type ServiceStatus = 'stopped' | 'starting' | 'running' | 'error'

export interface ServiceState {
  status: ServiceStatus
  message: string
}

export interface BackendAPI {
  // Service orchestration
  startServices: () => Promise<void>
  stopServices: () => Promise<void>
  getStatus: () => Promise<ServiceStatus>
  getLogs: (tail?: number) => Promise<string>
  checkDocker: () => Promise<boolean>
  onStatusChanged: (cb: (state: ServiceState) => void) => () => void
  // Setup wizard
  isSetupComplete: () => Promise<boolean>
  generateSecret: () => Promise<string>
  writeEnv: (values: Record<string, string>) => Promise<void>
  getEnvPath: () => Promise<string>
}

declare global {
  interface Window {
    electron: ElectronAPI
    backend: BackendAPI
  }
}
