import { app } from 'electron'
import { execFileSync } from 'child_process'
import * as fs from 'fs'
import * as path from 'path'
import { randomBytes } from 'crypto'

const ENV_PATH = path.join(app.getPath('userData'), '.env')

export function isSetupComplete(): boolean {
  if (!fs.existsSync(ENV_PATH)) return false
  const content = fs.readFileSync(ENV_PATH, 'utf-8')
  return !content.includes('<CHANGE_ME>') && content.includes('JWT_SECRET_KEY=')
}

export function getEnvPath(): string {
  return ENV_PATH
}

export function writeEnv(values: Record<string, string>): void {
  // Ensure the userData directory exists and is owner-only (0o700)
  fs.mkdirSync(path.dirname(ENV_PATH), { recursive: true, mode: 0o700 })
  const data =
    Object.entries(values)
      .map(([k, v]) => `${k}=${v}`)
      .join('\n') + '\n'
  // Write with owner-read/write only (0o600) — no group/other access
  fs.writeFileSync(ENV_PATH, data, { mode: 0o600, encoding: 'utf-8' })
  // On Windows, mode bits have no effect via Node — additionally restrict via icacls
  if (process.platform === 'win32') {
    try {
      // Remove inherited ACEs, grant current user Full Control only.
      // Using execFileSync with an array — no shell, no injection risk.
      execFileSync(
        'icacls',
        [ENV_PATH, '/inheritance:r', '/grant:r', `${process.env.USERNAME}:F`],
        {
          stdio: 'ignore'
        }
      )
    } catch {
      // Non-fatal: icacls unavailable in some sandbox/CI environments
    }
  }
}

export function generateSecret(bytes = 64): string {
  return randomBytes(bytes).toString('hex')
}
