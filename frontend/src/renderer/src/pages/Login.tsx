import { useState } from 'react'
import { api } from '../lib/api'
import { saveAuth, AuthUser } from '../lib/auth'

interface LoginProps {
  onLogin: (user: AuthUser) => void
}

export default function Login({ onLogin }: LoginProps) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // Fallback credentials read from build-time env vars (set DEFAULT_ADMIN_PASSWORD / DEFAULT_ANALYST_PASSWORD in .env)
  const FALLBACK_USERS: Record<string, { password: string; role: 'admin' | 'analyst' }> = {
    admin: { password: import.meta.env.VITE_DEFAULT_ADMIN_PASSWORD ?? '', role: 'admin' },
    analyst: { password: import.meta.env.VITE_DEFAULT_ANALYST_PASSWORD ?? '', role: 'analyst' }
  }

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    setLoading(true)
    setError(null)
    try {
      const res = await api.login(username, password)
      const user: AuthUser = {
        username: res.username,
        role: res.role as 'admin' | 'analyst',
        access_token: res.access_token,
        expires_in: res.expires_in
      }
      saveAuth(user)
      onLogin(user)
    } catch {
      // Backend offline — try local fallback credentials
      const fallback = FALLBACK_USERS[username]
      if (fallback && fallback.password === password) {
        const user: AuthUser = {
          username,
          role: fallback.role,
          access_token: 'local-dev-token',
          expires_in: 28800
        }
        saveAuth(user)
        onLogin(user)
      } else {
        setError('Invalid credentials')
      }
    } finally {
      setLoading(false)
    }
  }

  return (
    <div
      style={{
        height: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        flexDirection: 'column',
        gap: 32
      }}
    >
      {/* Logo */}
      <div style={{ textAlign: 'center' }}>
        <div
          style={{
            width: 64,
            height: 64,
            background: 'linear-gradient(135deg, #8b5cf6, #38bdf8)',
            borderRadius: 16,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            fontSize: 32,
            margin: '0 auto 16px',
            boxShadow: '0 0 32px rgba(139,92,246,0.4)'
          }}
        >
          ⚔
        </div>
        <div style={{ fontSize: 22, fontWeight: 700, color: '#e2e8f0' }}>AI SOC</div>
        <div style={{ fontSize: 13, color: '#64748b', marginTop: 4 }}>
          Security Operations Center
        </div>
      </div>

      {/* Card */}
      <div className="glass animate-in" style={{ width: 360, padding: 32 }}>
        <div style={{ fontSize: 15, fontWeight: 700, color: '#e2e8f0', marginBottom: 4 }}>
          Analyst Sign-In
        </div>
        <div style={{ fontSize: 12, color: '#64748b', marginBottom: 24 }}>
          SOC2-compliant · on-premise · air-gapped
        </div>

        <form onSubmit={submit} style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <div>
            <div
              style={{
                fontSize: 11,
                color: '#64748b',
                marginBottom: 5,
                textTransform: 'uppercase',
                letterSpacing: '0.06em'
              }}
            >
              Username
            </div>
            <input
              className="input"
              type="text"
              autoComplete="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
            />
          </div>
          <div>
            <div
              style={{
                fontSize: 11,
                color: '#64748b',
                marginBottom: 5,
                textTransform: 'uppercase',
                letterSpacing: '0.06em'
              }}
            >
              Password
            </div>
            <input
              className="input"
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
          </div>

          {error && (
            <div
              style={{
                padding: '8px 12px',
                background: 'rgba(248,113,113,0.1)',
                border: '1px solid rgba(248,113,113,0.25)',
                borderRadius: 6,
                color: '#f87171',
                fontSize: 12
              }}
            >
              {error}
            </div>
          )}

          <button
            type="submit"
            className="btn btn-primary"
            disabled={loading}
            style={{ marginTop: 8, justifyContent: 'center', padding: '10px 0', width: '100%' }}
          >
            {loading ? <span className="spinner" /> : '→'} Sign In
          </button>
        </form>

        <div
          style={{
            marginTop: 20,
            padding: '10px 12px',
            background: 'rgba(56,189,248,0.06)',
            border: '1px solid rgba(56,189,248,0.12)',
            borderRadius: 6,
            fontSize: 11,
            color: '#64748b'
          }}
        >
          Set <code style={{ color: '#94a3b8' }}>VITE_DEFAULT_ADMIN_PASSWORD</code> in{' '}
          <code style={{ color: '#94a3b8' }}>.env</code> before use.
        </div>
      </div>
    </div>
  )
}
