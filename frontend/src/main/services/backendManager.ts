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

function getComposePath(relative: string): string {
  return app.isPackaged
    ? join(process.resourcesPath, relative)
    : join(__dirname, '..', '..', '..', '..', relative)
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
    emit({ status: 'error', message: 'Configuration not found. Run the setup wizard first.' })
    return
  }

  // docker-compose.yml's hitl_api service has `env_file: - .env`, which Compose
  // resolves relative to the compose file's own directory — NOT the --env-file
  // flag below (that only covers ${VAR} substitution within the YAML itself).
  // Mirror the generated credentials next to the compose file so hitl_api can
  // actually find them; without this, service startup fails every time.
  try {
    fs.copyFileSync(envFile, join(backendCompose, '..', '.env'))
  } catch (err) {
    emit({ status: 'error', message: `Failed to stage configuration: ${(err as Error).message}` })
    return
  }

  composeProcess = spawn(
    'docker',
    ['compose', '-f', backendCompose, '--env-file', envFile, 'up', '-d', '--wait'],
    { shell: true, stdio: 'pipe' }
  )

  let stderr = ''
  composeProcess.stderr?.on('data', (d) => {
    stderr += d.toString()
  })

  composeProcess.on('close', (code) => {
    if (code === 0) {
      emit({ status: 'running', message: 'All backend services are healthy.' })
    } else {
      emit({ status: 'error', message: `Service startup failed:\n${stderr.slice(-500)}` })
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
      stdio: 'ignore'
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
      stdio: 'pipe'
    })
    let out = ''
    proc.stdout?.on('data', (d) => {
      out += d.toString()
    })
    proc.stderr?.on('data', (d) => {
      out += d.toString()
    })
    proc.on('close', () => resolve(out))
    proc.on('error', () => resolve('Failed to fetch logs'))
  })
}
