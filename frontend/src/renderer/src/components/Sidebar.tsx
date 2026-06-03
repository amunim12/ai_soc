import { useEffect, useState } from 'react'
import { api } from '../lib/api'
import { AuthUser, clearAuth } from '../lib/auth'

interface SidebarProps {
  active: string
  onNavigate: (page: string) => void
  pendingCount: number
  user: AuthUser
  onLogout: () => void
}

export default function Sidebar({
  active,
  onNavigate,
  pendingCount,
  user,
  onLogout
}: SidebarProps) {
  const [backendOnline, setBackendOnline] = useState<boolean | null>(null)

  useEffect(() => {
    const check = async () => {
      try {
        await api.health()
        setBackendOnline(true)
      } catch {
        setBackendOnline(false)
      }
    }
    check()
    const t = setInterval(check, 500)
    return () => clearInterval(t)
  }, [])

  const isAdmin = user.role === 'admin'

  // Sections & items — admin-only items hidden for analyst role
  const navSections = [
    {
      label: 'Operations',
      items: [
        { id: 'dashboard', label: 'Overview', icon: '⬡' },
        { id: 'hitl', label: 'HITL Queue', icon: '◈', badge: pendingCount || undefined },
        { id: 'history', label: 'Execution History', icon: '◷' }
      ]
    },
    {
      label: 'Integrations',
      items: [
        { id: 'siem', label: 'SIEM', icon: '◉' },
        { id: 'shuffle', label: 'SOAR Dashboard', icon: '▷' },
        { id: 'logsources', label: 'Log Sources', icon: '⊕' }
      ]
    },
    ...(isAdmin
      ? [
          {
            label: 'Admin',
            items: [{ id: 'vectordb', label: 'Vector DB', icon: '⊞' }]
          }
        ]
      : [])
  ]

  function handleLogout() {
    clearAuth()
    onLogout()
  }

  return (
    <aside className="sidebar">
      {/* Logo */}
      <div className="sidebar-logo">
        <div className="sidebar-logo-icon">⚔</div>
        <div>
          <div className="sidebar-logo-text">AI SOC</div>
          <div className="sidebar-logo-sub">Security Operations</div>
        </div>
      </div>

      {navSections.map((section) => (
        <div key={section.label}>
          <div className="nav-section">{section.label}</div>
          {section.items.map((item) => (
            <button
              key={item.id}
              className={`nav-item${active === item.id ? ' active' : ''}`}
              onClick={() => onNavigate(item.id)}
              style={{ background: 'none', width: '100%', textAlign: 'left' }}
            >
              <span style={{ fontSize: 15 }}>{item.icon}</span>
              <span>{item.label}</span>
              {item.badge ? <span className="nav-pip">{item.badge}</span> : null}
            </button>
          ))}
        </div>
      ))}

      {/* Footer — user + status */}
      <div className="sidebar-footer">
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 8,
            padding: '8px 10px',
            background: 'rgba(255,255,255,0.03)',
            borderRadius: 6,
            marginBottom: 8
          }}
        >
          <div
            style={{
              width: 28,
              height: 28,
              background: isAdmin
                ? 'linear-gradient(135deg, #8b5cf6, #38bdf8)'
                : 'linear-gradient(135deg, #334155, #475569)',
              borderRadius: 6,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontSize: 13,
              flexShrink: 0
            }}
          >
            {isAdmin ? '★' : '◉'}
          </div>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div
              style={{
                fontSize: 12,
                fontWeight: 600,
                color: '#e2e8f0',
                overflow: 'hidden',
                textOverflow: 'ellipsis',
                whiteSpace: 'nowrap'
              }}
            >
              {user.username}
            </div>
            <div
              style={{
                fontSize: 10,
                color: isAdmin ? '#c4b5fd' : '#64748b',
                textTransform: 'uppercase',
                letterSpacing: '0.06em'
              }}
            >
              {user.role}
            </div>
          </div>
          <button
            onClick={handleLogout}
            style={{
              background: 'none',
              border: 'none',
              cursor: 'pointer',
              color: '#475569',
              fontSize: 14,
              padding: '2px 4px',
              borderRadius: 4,
              transition: 'color 0.15s'
            }}
            title="Sign out"
          >
            ⏏
          </button>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '4px 10px' }}>
          <span
            className={`status-dot ${backendOnline === null ? 'pending' : backendOnline ? 'online' : 'offline'}`}
          />
          <span style={{ fontSize: 11 }}>
            {backendOnline === null
              ? 'Connecting…'
              : backendOnline
                ? 'Backend online'
                : 'Backend offline'}
          </span>
        </div>
      </div>
    </aside>
  )
}
