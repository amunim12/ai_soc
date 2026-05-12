export interface AuthUser {
  username: string
  role: 'admin' | 'analyst'
  access_token: string
  expires_in: number
}

const KEY = 'soc_auth'

export function saveAuth(data: AuthUser): void {
  localStorage.setItem(KEY, JSON.stringify(data))
}

export function loadAuth(): AuthUser | null {
  try {
    const raw = localStorage.getItem(KEY)
    return raw ? (JSON.parse(raw) as AuthUser) : null
  } catch {
    return null
  }
}

export function clearAuth(): void {
  localStorage.removeItem(KEY)
}

export function getToken(): string | null {
  return loadAuth()?.access_token ?? null
}
