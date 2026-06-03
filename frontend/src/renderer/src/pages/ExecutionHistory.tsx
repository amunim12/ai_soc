import { useEffect, useState, useCallback } from 'react'
import { api, SoarExecution } from '../lib/api'

function timeAgo(iso: string): string {
  if (!iso) return '—'
  const diff = Date.now() - new Date(iso).getTime()
  const m = Math.floor(diff / 60_000)
  if (m < 1) return 'just now'
  if (m < 60) return `${m}m ago`
  const h = Math.floor(m / 60)
  if (h < 24) return `${h}h ago`
  return `${Math.floor(h / 24)}d ago`
}

function StatusBadge({ status }: { status: string }) {
  const s = status?.toUpperCase()
  const map: Record<string, { cls: string; icon: string }> = {
    FINISHED: { cls: 'badge-low', icon: '✓' },
    COMPLETED: { cls: 'badge-low', icon: '✓' },
    EXECUTING: { cls: 'badge-medium', icon: '▶' },
    PENDING: { cls: 'badge-info', icon: '⏳' },
    ABORTED: { cls: 'badge-high', icon: '⏹' },
    FAILED: { cls: 'badge-critical', icon: '✕' }
  }
  const style = map[s] ?? { cls: 'badge-info', icon: '?' }
  return (
    <span className={`badge ${style.cls}`}>
      {style.icon} {s}
    </span>
  )
}

export default function ExecutionHistory() {
  const [executions, setExecutions] = useState<SoarExecution[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [selected, setSelected] = useState<SoarExecution | null>(null)

  const load = useCallback(async () => {
    try {
      const data = await api.executions(100)
      setExecutions(data)
      setError(null)
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    load()
    const t = setInterval(load, 500)
    return () => clearInterval(t)
  }, [load])

  return (
    <div
      className="page-content animate-in"
      style={{ display: 'flex', flexDirection: 'column', height: '100%', padding: 0 }}
    >
      {/* Header */}
      <div style={{ padding: '20px 20px 0' }}>
        <div
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'flex-start',
            marginBottom: 16
          }}
        >
          <div>
            <div style={{ fontSize: 18, fontWeight: 700, color: '#e2e8f0', marginBottom: 4 }}>
              Execution History
            </div>
            <div style={{ fontSize: 12, color: '#64748b' }}>
              SOAR workflow audit log · auto-refreshes every 10 s
            </div>
          </div>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            {loading && (
              <div className="spinner" style={{ width: 14, height: 14, borderWidth: 1.5 }} />
            )}
            <span
              style={{
                fontSize: 11,
                padding: '4px 10px',
                background: 'rgba(56,189,248,0.1)',
                color: '#38bdf8',
                borderRadius: 99,
                border: '1px solid rgba(56,189,248,0.2)',
                fontWeight: 700
              }}
            >
              {executions.length} records
            </span>
          </div>
        </div>

        {error && (
          <div
            style={{
              padding: '10px 14px',
              background: 'rgba(248,113,113,0.1)',
              border: '1px solid rgba(248,113,113,0.2)',
              borderRadius: 6,
              color: '#f87171',
              fontSize: 12,
              marginBottom: 12
            }}
          >
            ⚠ {error}
          </div>
        )}
      </div>

      {/* Two-panel layout */}
      <div style={{ flex: 1, display: 'flex', overflow: 'hidden', padding: 20, gap: 14 }}>
        {/* Table */}
        <div className="glass" style={{ flex: 1, overflow: 'auto' }}>
          {!loading && executions.length === 0 ? (
            <div className="empty-state">
              <div className="empty-state-icon">📜</div>
              <div>No executions recorded yet</div>
            </div>
          ) : (
            <table className="data-table">
              <thead>
                <tr>
                  <th>Execution ID</th>
                  <th>Workflow</th>
                  <th>Status</th>
                  <th>Received</th>
                </tr>
              </thead>
              <tbody>
                {executions.map((ex) => (
                  <tr
                    key={ex.execution_id}
                    onClick={() => setSelected(ex)}
                    style={{
                      background:
                        selected?.execution_id === ex.execution_id
                          ? 'rgba(139,92,246,0.08)'
                          : undefined
                    }}
                  >
                    <td>
                      <span
                        style={{
                          fontFamily: 'JetBrains Mono, monospace',
                          fontSize: 11,
                          color: '#94a3b8'
                        }}
                      >
                        {ex.execution_id?.slice(0, 20)}…
                      </span>
                    </td>
                    <td style={{ fontWeight: 600, color: '#c4b5fd', fontSize: 12 }}>
                      {ex.workflow ?? '—'}
                    </td>
                    <td>
                      <StatusBadge status={ex.status} />
                    </td>
                    <td style={{ color: '#64748b', fontSize: 11 }}>
                      {timeAgo(ex.received_at ?? '')}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        {/* Detail panel */}
        {selected && (
          <div
            className="glass animate-slide"
            style={{
              width: 320,
              flexShrink: 0,
              overflow: 'auto',
              padding: 16,
              display: 'flex',
              flexDirection: 'column',
              gap: 12
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div className="section-title" style={{ marginBottom: 0 }}>
                Execution Detail
              </div>
              <button
                className="btn btn-ghost"
                style={{ padding: '3px 8px', fontSize: 11 }}
                onClick={() => setSelected(null)}
              >
                ✕
              </button>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              {[
                ['Execution ID', selected.execution_id],
                ['Workflow', selected.workflow ?? '—'],
                ['Status', selected.status],
                ['Received', selected.received_at ?? '—']
              ].map(([k, v]) => (
                <div key={k}>
                  <div
                    style={{
                      fontSize: 10,
                      color: '#64748b',
                      textTransform: 'uppercase',
                      letterSpacing: '0.06em',
                      marginBottom: 2
                    }}
                  >
                    {k}
                  </div>
                  <div
                    style={{
                      fontSize: 12,
                      color: '#e2e8f0',
                      fontFamily: k === 'Execution ID' ? 'monospace' : undefined,
                      wordBreak: 'break-all'
                    }}
                  >
                    {v}
                  </div>
                </div>
              ))}
            </div>

            {selected.results && Object.keys(selected.results).length > 0 && (
              <>
                <div className="divider" />
                <div className="section-title">Results</div>
                <pre className="code-block" style={{ fontSize: 11 }}>
                  {JSON.stringify(selected.results, null, 2)}
                </pre>
              </>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
